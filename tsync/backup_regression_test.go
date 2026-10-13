package tsync

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tsyncv2 "github.com/abyii/t-sync-sdk-go/v2/gen/go/com/github/abyii/tsync/v2"
	"github.com/abyii/t-sync-sdk-go/v2/storage_clients"
	zip "github.com/abyii/zip-xxh3"
	"golang.org/x/crypto/nacl/box"
	"google.golang.org/protobuf/proto"
)

// ---------------------------------------------------------
// Test helpers
// ---------------------------------------------------------

// backupHookStorage wraps a Storage, counting calls and allowing per-call fault injection.
type backupHookStorage struct {
	Storage
	readHook       func(path string) error
	openWriterHook func(path string) error
	openWriters    sync.Map // path -> *int64
	readRanges     atomic.Int64
	writes         atomic.Int64
	deletes        atomic.Int64
}

func (h *backupHookStorage) Read(ctx context.Context, path string) ([]byte, error) {
	if h.readHook != nil {
		if err := h.readHook(path); err != nil {
			return nil, err
		}
	}
	return h.Storage.Read(ctx, path)
}

func (h *backupHookStorage) Write(ctx context.Context, path string, data []byte) error {
	h.writes.Add(1)
	return h.Storage.Write(ctx, path, data)
}

func (h *backupHookStorage) Delete(ctx context.Context, path string) error {
	h.deletes.Add(1)
	return h.Storage.Delete(ctx, path)
}

func (h *backupHookStorage) OpenWriter(ctx context.Context, path string) (io.WriteCloser, error) {
	c, _ := h.openWriters.LoadOrStore(path, new(int64))
	atomic.AddInt64(c.(*int64), 1)
	if h.openWriterHook != nil {
		if err := h.openWriterHook(path); err != nil {
			return nil, err
		}
	}
	return h.Storage.OpenWriter(ctx, path)
}

func (h *backupHookStorage) ReadRange(ctx context.Context, path string, offset, length int64) (io.ReadCloser, error) {
	h.readRanges.Add(1)
	return h.Storage.ReadRange(ctx, path, offset, length)
}

func (h *backupHookStorage) openWriterCount(path string) int64 {
	c, ok := h.openWriters.Load(path)
	if !ok {
		return 0
	}
	return atomic.LoadInt64(c.(*int64))
}

// backupFuncSource is a Source backed by a static entry list; it counts ListEntries calls and
// lets entries capture the run context.
type backupFuncSource struct {
	listCalls atomic.Int64
	build     func(ctx context.Context) []SourceEntry
}

func (s *backupFuncSource) ListEntries(ctx context.Context) ([]SourceEntry, error) {
	s.listCalls.Add(1)
	return s.build(ctx), nil
}

func staticSource(entries ...SourceEntry) *backupFuncSource {
	return &backupFuncSource{build: func(context.Context) []SourceEntry { return entries }}
}

func bytesEntry(path string, data []byte) SourceEntry {
	return SourceEntry{
		Path:         path,
		Size:         int64(len(data)),
		CRC32:        crc32.ChecksumIEEE(data),
		LastModified: time.Unix(1700000000, 0),
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(data)), nil
		},
	}
}

func newTestKeys(t *testing.T) (*[32]byte, *[32]byte) {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return pub, priv
}

func readStoreMetadata(t *testing.T, s Storage) *tsyncv2.BackupMetadata {
	t.Helper()
	b, err := s.Read(context.Background(), ".tsync")
	if err != nil {
		t.Fatalf("read .tsync: %v", err)
	}
	var md tsyncv2.BackupMetadata
	if err := proto.Unmarshal(b, &md); err != nil {
		t.Fatalf("unmarshal .tsync: %v", err)
	}
	return &md
}

func partKeys(m *MemStorage) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var keys []string
	for k := range m.files {
		if k != ".tsync" {
			keys = append(keys, k)
		}
	}
	return keys
}

// seedStore creates a store with one committed version and returns its .tsync bytes.
func seedStore(t *testing.T, dest Storage, pub *[32]byte, ts time.Time) []byte {
	t.Helper()
	_, err := RunBackup(context.Background(), staticSource(bytesEntry("seed.txt", []byte("seed content"))), dest, BackupOptions{
		PublicKeys:            map[string][]byte{"k": pub[:]},
		CustomBackupTimestamp: ts,
		CustomVersionID:       42,
	})
	if err != nil {
		t.Fatalf("seed backup: %v", err)
	}
	b, err := dest.Read(context.Background(), ".tsync")
	if err != nil {
		t.Fatalf("seed read: %v", err)
	}
	return b
}

// ---------------------------------------------------------
// Metadata load (findings 1, string table)
// ---------------------------------------------------------

func TestBackupTransientMetadataReadErrorDoesNotCreateNewStore(t *testing.T) {
	pub, _ := newTestKeys(t)
	mem := NewMemStorage()
	seed := seedStore(t, mem, pub, time.Now().Add(-time.Hour))
	before := len(partKeys(mem))

	transient := &storage_clients.StatusError{Op: "GetObject", StatusCode: 503}
	dest := &backupHookStorage{Storage: mem, readHook: func(p string) error {
		if p == ".tsync" {
			return transient
		}
		return nil
	}}
	src := staticSource(bytesEntry("new.txt", []byte("new content")))
	_, err := RunBackup(context.Background(), src, dest, BackupOptions{PublicKeys: map[string][]byte{"k": pub[:]}})
	if !errors.As(err, new(*storage_clients.StatusError)) {
		t.Fatalf("expected the transient read error to be returned, got %v", err)
	}
	if src.listCalls.Load() != 0 {
		t.Fatalf("source must not be listed when metadata cannot be read")
	}
	after, _ := mem.Read(context.Background(), ".tsync")
	if !bytes.Equal(after, seed) || len(partKeys(mem)) != before || dest.writes.Load() != 0 {
		t.Fatalf("store was modified after a transient .tsync read error")
	}
}

func TestBackupCorruptMetadataIsRejected(t *testing.T) {
	pub, _ := newTestKeys(t)
	mem := NewMemStorage()
	_ = mem.Write(context.Background(), ".tsync", []byte{0x0a, 0xff, 0xff}) // truncated length-delimited field
	src := staticSource(bytesEntry("a.txt", []byte("a")))
	_, err := RunBackup(context.Background(), src, mem, BackupOptions{PublicKeys: map[string][]byte{"k": pub[:]}})
	if !errors.Is(err, ErrCorruptMetadata) {
		t.Fatalf("expected ErrCorruptMetadata, got %v", err)
	}
	if src.listCalls.Load() != 0 {
		t.Fatalf("source listed despite corrupt metadata")
	}
}

func TestBackupUnsupportedSchema(t *testing.T) {
	pub, _ := newTestKeys(t)
	mem := NewMemStorage()
	b, _ := proto.Marshal(&tsyncv2.BackupMetadata{SchemaVersion: 7})
	_ = mem.Write(context.Background(), ".tsync", b)
	_, err := RunBackup(context.Background(), staticSource(), mem, BackupOptions{PublicKeys: map[string][]byte{"k": pub[:]}})
	var se *UnsupportedSchemaError
	if !errors.As(err, &se) || se.Version != 7 || !errors.Is(err, ErrUnsupportedSchema) {
		t.Fatalf("expected UnsupportedSchemaError{7}, got %v", err)
	}
}

func TestBackupNewStoreWithoutKeys(t *testing.T) {
	src := staticSource(bytesEntry("a.txt", []byte("a")))
	_, err := RunBackup(context.Background(), src, NewMemStorage(), BackupOptions{})
	if !errors.Is(err, ErrStoreNotInitialized) {
		t.Fatalf("expected ErrStoreNotInitialized, got %v", err)
	}
	if src.listCalls.Load() != 0 {
		t.Fatalf("source listed before store initialization check")
	}
}

func TestBackupTimestampAndVersionChecksBeforeListing(t *testing.T) {
	pub, _ := newTestKeys(t)
	mem := NewMemStorage()
	t1 := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	seedStore(t, mem, pub, t1)

	cases := []struct {
		name string
		opts BackupOptions
		want error
	}{
		{"equal", BackupOptions{CustomBackupTimestamp: t1.In(time.FixedZone("X", 3600))}, ErrTimestampEqualsLatest},
		{"before", BackupOptions{CustomBackupTimestamp: t1.Add(-time.Nanosecond)}, ErrTimestampBeforeLatest},
		{"future", BackupOptions{CustomBackupTimestamp: time.Now().Add(5 * time.Hour)}, ErrTimestampInFuture},
		{"id exists", BackupOptions{CustomVersionID: 42}, ErrVersionIDExists},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := staticSource(bytesEntry("a.txt", []byte("a")))
			_, err := RunBackup(context.Background(), src, mem, tc.opts)
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
			if src.listCalls.Load() != 0 {
				t.Fatalf("source was listed before the version checks")
			}
		})
	}
}

// ---------------------------------------------------------
// Worker lifecycle (findings 2, 11, 12)
// ---------------------------------------------------------

func TestBackupContextCancelMidRunCommitsNothing(t *testing.T) {
	pub, _ := newTestKeys(t)
	mem := NewMemStorage()
	seedStore(t, mem, pub, time.Now().Add(-time.Hour))
	seedParts := partKeys(mem)
	seedMeta, _ := mem.Read(context.Background(), ".tsync")
	dest := &backupHookStorage{Storage: mem}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var entries []SourceEntry
	for i := range 20 {
		data := []byte(fmt.Sprintf("file %d", i))
		e := bytesEntry(fmt.Sprintf("f%02d.txt", i), data)
		if i == 2 {
			e.Open = func() (io.ReadCloser, error) {
				cancel() // the caller gives up while the run is in progress
				return io.NopCloser(bytes.NewReader(data)), nil
			}
		}
		entries = append(entries, e)
	}

	_, err := RunBackup(ctx, staticSource(entries...), dest, BackupOptions{
		SingleVersionMode: true,
		Concurrency:       1,
	})
	if !errors.Is(err, ErrIncompleteRun) || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected ErrIncompleteRun wrapping context.Canceled, got %v", err)
	}
	after, _ := mem.Read(context.Background(), ".tsync")
	if !bytes.Equal(after, seedMeta) || dest.writes.Load() != 0 {
		t.Fatalf(".tsync was written by a cancelled run")
	}
	if dest.deletes.Load() != 0 {
		t.Fatalf("cancelled run deleted %d parts", dest.deletes.Load())
	}
	for _, k := range seedParts {
		if ok, _ := mem.Exists(context.Background(), k); !ok {
			t.Fatalf("seed part %s deleted", k)
		}
	}
}

func TestBackupFirstErrorStopsWorkersAndReturnsRootCause(t *testing.T) {
	pub, _ := newTestKeys(t)
	rootErr := errors.New("disk exploded")
	var active, started atomic.Int64

	src := &backupFuncSource{build: func(ctx context.Context) []SourceEntry {
		var entries []SourceEntry
		for i := range 3 {
			entries = append(entries, SourceEntry{
				Path: fmt.Sprintf("slow%d.txt", i), Size: 10, CRC32: 1,
				Open: func() (io.ReadCloser, error) {
					active.Add(1)
					defer active.Add(-1)
					started.Add(1)
					select {
					case <-ctx.Done(): // closure captured the run context
						return nil, context.Cause(ctx)
					case <-time.After(10 * time.Second):
						return nil, errors.New("run context was never cancelled")
					}
				},
			})
		}
		entries = append(entries, SourceEntry{
			Path: "bad.txt", Size: 10, CRC32: 2,
			Open: func() (io.ReadCloser, error) {
				deadline := time.Now().Add(5 * time.Second)
				for started.Load() < 3 && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				return nil, rootErr
			},
		})
		return entries
	}}

	_, err := RunBackup(context.Background(), src, NewMemStorage(), BackupOptions{
		PublicKeys:  map[string][]byte{"k": pub[:]},
		Concurrency: 4,
	})
	if n := active.Load(); n != 0 {
		t.Fatalf("RunBackup returned while %d workers were still running", n)
	}
	if !errors.Is(err, rootErr) {
		t.Fatalf("expected root cause %v, got %v", rootErr, err)
	}
	if errors.Is(err, ErrIncompleteRun) {
		t.Fatalf("worker failure must be reported as its root cause, got %v", err)
	}
}

// ---------------------------------------------------------
// Entry handling (findings 3, 4, 5, 10, 13)
// ---------------------------------------------------------

func preEncryptedOpts(t *testing.T, pub *[32]byte) BackupOptions {
	t.Helper()
	pass, _ := GenerateZipCryptoPassword()
	eph, enc, err := EncryptPassword(pass, pub[:])
	if err != nil {
		t.Fatal(err)
	}
	return BackupOptions{
		PublicKeys:        map[string][]byte{"k": pub[:]},
		EphPublicKey:      eph,
		EncryptedPassword: enc,
	}
}

func TestBackupEncryptedRawEntryWithZeroCRCDoesNotPanic(t *testing.T) {
	pub, _ := newTestKeys(t)
	raw := []byte("raw-encrypted-part-bytes")
	entry := SourceEntry{
		Path: "aes.bin", Size: 5, CompressedSize: int64(len(raw)), CRC32: 0,
		IsEncryptedRaw: true,
		OpenRaw:        func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil },
	}
	mem := NewMemStorage()
	if _, err := RunBackup(context.Background(), staticSource(entry), mem, preEncryptedOpts(t, pub)); err != nil {
		t.Fatalf("backup failed: %v", err)
	}
	if _, ok := readStoreMetadata(t, mem).Files[fileKeyFor(0, 5)]; !ok {
		t.Fatalf("expected record keyed by central-directory CRC/size")
	}

	entry.OpenRaw = nil
	_, err := RunBackup(context.Background(), staticSource(entry), NewMemStorage(), preEncryptedOpts(t, pub))
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("expected ErrInvalidOptions for nil OpenRaw, got %v", err)
	}
}

func TestBackupEntryWithoutOpenIsAnError(t *testing.T) {
	pub, _ := newTestKeys(t)
	_, err := RunBackup(context.Background(), staticSource(SourceEntry{Path: "x.txt", Size: 3}), NewMemStorage(),
		BackupOptions{PublicKeys: map[string][]byte{"k": pub[:]}})
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("expected ErrInvalidOptions, got %v", err)
	}
}

func TestBackupDuplicateKeysUploadedOnce(t *testing.T) {
	pub, _ := newTestKeys(t)
	content := []byte("identical content in many files")
	var entries []SourceEntry
	for i := range 40 {
		e := bytesEntry(fmt.Sprintf("dup%02d.txt", i), content)
		e.CRC32 = 0 // force the pre-read key path too
		entries = append(entries, e)
	}
	mem := NewMemStorage()
	dest := &backupHookStorage{Storage: mem}
	if _, err := RunBackup(context.Background(), staticSource(entries...), dest, BackupOptions{
		PublicKeys:  map[string][]byte{"k": pub[:]},
		Concurrency: 16,
	}); err != nil {
		t.Fatalf("backup failed: %v", err)
	}
	key := fileKeyFor(crc32.ChecksumIEEE(content), int64(len(content)))
	if n := dest.openWriterCount(partKeyFor(key)); n != 1 {
		t.Fatalf("expected exactly one upload of %s, got %d", key, n)
	}
}

type backupFailingReader struct {
	data []byte
	err  error
}

func (f *backupFailingReader) Read(p []byte) (int, error) {
	if len(f.data) == 0 {
		return 0, f.err
	}
	n := copy(p, f.data)
	f.data = f.data[n:]
	return n, nil
}

func TestBackupFailedSourceReadAbortsPartWriter(t *testing.T) {
	pub, _ := newTestKeys(t)
	readErr := errors.New("source I/O error")
	entry := SourceEntry{
		Path: "broken.bin", Size: 4096, CRC32: 0x12345678,
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(&backupFailingReader{data: bytes.Repeat([]byte("x"), 1000), err: readErr}), nil
		},
	}
	mem := NewMemStorage()
	_, err := RunBackup(context.Background(), staticSource(entry), mem, BackupOptions{PublicKeys: map[string][]byte{"k": pub[:]}})
	if !errors.Is(err, readErr) {
		t.Fatalf("expected source read error, got %v", err)
	}
	if keys := partKeys(mem); len(keys) != 0 {
		t.Fatalf("truncated part committed: %v", keys)
	}
}

func TestBackupKeyRecordMismatchIsSourceChanged(t *testing.T) {
	pub, _ := newTestKeys(t)
	cases := map[string]SourceEntry{
		"crc differs": {Path: "a.txt", Size: 5, CRC32: 0xdeadbeef, Open: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("hello")), nil
		}},
		"listed empty but grew": {Path: "b.txt", Size: 0, Open: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("not empty anymore")), nil
		}},
	}
	for name, e := range cases {
		t.Run(name, func(t *testing.T) {
			mem := NewMemStorage()
			_, err := RunBackup(context.Background(), staticSource(e), mem, BackupOptions{PublicKeys: map[string][]byte{"k": pub[:]}})
			if !errors.Is(err, ErrSourceChanged) {
				t.Fatalf("expected ErrSourceChanged, got %v", err)
			}
			if keys := partKeys(mem); len(keys) != 0 {
				t.Fatalf("mismatched part committed: %v", keys)
			}
		})
	}
}

func TestBackupRejectsPreEncryptedOptionsWithPlaintextEntries(t *testing.T) {
	pub, _ := newTestKeys(t)
	_, err := RunBackup(context.Background(), staticSource(bytesEntry("plain.txt", []byte("secret"))), NewMemStorage(), preEncryptedOpts(t, pub))
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("expected ErrInvalidOptions, got %v", err)
	}
}

// ---------------------------------------------------------
// OpenRawCompressed record size (finding 6)
// ---------------------------------------------------------

func TestBackupOpenRawCompressedRecordsEncryptedSize(t *testing.T) {
	pub, priv := newTestKeys(t)
	plain := bytes.Repeat([]byte("raw compressed payload "), 200)
	var comp bytes.Buffer
	fw, _ := flate.NewWriter(&comp, 5)
	fw.Write(plain)
	fw.Close()
	compBytes := comp.Bytes()

	entry := SourceEntry{
		Path: "dir/raw.txt", Size: int64(len(plain)), CompressedSize: int64(len(compBytes)),
		CRC32: crc32.ChecksumIEEE(plain), CompressionMethod: zip.Deflate, LastModified: time.Unix(1700000000, 0),
		OpenRawCompressed: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(compBytes)), nil },
	}
	mem := NewMemStorage()
	client := NewClient(mem)
	v, err := client.Backup(context.Background(), staticSource(entry), BackupOptions{PublicKeys: map[string][]byte{"k": pub[:]}})
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	rec := readStoreMetadata(t, mem).Files[fileKeyFor(entry.CRC32, entry.Size)]
	if rec == nil || rec.CompressedSize != int64(len(compBytes))+12 {
		t.Fatalf("expected compressed size %d (payload + 12-byte ZipCrypto header), got %+v", len(compBytes)+12, rec)
	}

	extract := t.TempDir()
	if err := client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{ExtractDir: extract, PrivateKey: priv[:]}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(extract, "dir", "raw.txt"))
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("restored content mismatch (err=%v)", err)
	}
}

// ---------------------------------------------------------
// Version IDs (finding 17), orphan cleanup (string table)
// ---------------------------------------------------------

func TestGeneratedVersionIDsFitInt64(t *testing.T) {
	existing := map[string]*tsyncv2.Version{}
	for range 10000 {
		id := generateVersionID(existing)
		if id == 0 || id > math.MaxInt64 {
			t.Fatalf("generated version ID %d out of range", id)
		}
	}
}

func TestSingleVersionCleanupSkipsMalformedKeys(t *testing.T) {
	pub, _ := newTestKeys(t)
	mem := NewMemStorage()
	seedStore(t, mem, pub, time.Now().Add(-time.Hour))
	md := readStoreMetadata(t, mem)
	md.Files["a"] = &tsyncv2.FileRecord{}
	md.Files["zz_bad/../x"] = &tsyncv2.FileRecord{}
	b, _ := proto.Marshal(md)
	_ = mem.Write(context.Background(), ".tsync", b)

	dest := &backupHookStorage{Storage: mem}
	if _, err := RunBackup(context.Background(), staticSource(bytesEntry("other.txt", []byte("other"))), dest, BackupOptions{SingleVersionMode: true}); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if n := dest.deletes.Load(); n != 1 {
		t.Fatalf("expected only the single valid orphan to be deleted, got %d deletes", n)
	}
	if !isValidFileKey("0123abcd_0") || isValidFileKey("0123ABCD_1") || isValidFileKey("0123abcd_") || isValidFileKey("a") {
		t.Fatalf("isValidFileKey mismatch")
	}
}

// ---------------------------------------------------------
// Object storage writer (findings 6/8/9, string table)
// ---------------------------------------------------------

func TestPartSizeGrowthCoversFiveTiB(t *testing.T) {
	var total int64
	prev := 0
	for n := 1; n <= maxMultipartParts; n++ {
		s := partSizeFor(n)
		if s < 5<<20 || s > maxPartSize || s < prev {
			t.Fatalf("part %d: invalid size %d (prev %d)", n, s, prev)
		}
		prev = s
		total += int64(s)
	}
	if total < 5<<40 {
		t.Fatalf("10,000 parts hold only %d bytes, need >= 5 TiB", total)
	}
	if partSizeFor(1) != initialPartSize || partSizeFor(1001) != 2*initialPartSize {
		t.Fatalf("unexpected growth schedule")
	}
}

type backupRecordingClient struct {
	mockObjectStorageClient
	mu         sync.Mutex
	parts      map[int][]byte
	put        []byte
	putCalled  bool
	abortCtxOK bool
	notFound   bool
}

func (c *backupRecordingClient) UploadPart(ctx context.Context, bucket, key, uploadID string, n int, data []byte) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.parts == nil {
		c.parts = map[int][]byte{}
	}
	c.parts[n] = bytes.Clone(data) // the writer reuses its buffer
	return fmt.Sprint(n), nil
}

func (c *backupRecordingClient) PutObject(ctx context.Context, bucket, key string, data []byte) error {
	c.put, c.putCalled = bytes.Clone(data), true
	return nil
}

func (c *backupRecordingClient) Abort(ctx context.Context, bucket, key, uploadID string) error {
	c.abortCtxOK = ctx.Err() == nil
	return nil
}

func (c *backupRecordingClient) GetObjectSize(ctx context.Context, bucket, key string) (int64, error) {
	return 0, fmt.Errorf("object %s: %w", key, storage_clients.ErrNotFound)
}

func (c *backupRecordingClient) DeleteObject(ctx context.Context, bucket, key string) error {
	return &storage_clients.StatusError{Op: "DeleteObject", StatusCode: 404}
}

func TestObjectStorageWriterPartsAndBufferReuse(t *testing.T) {
	c := &backupRecordingClient{}
	w := newObjectStorageWriter(context.Background(), c, "b", "k")
	data := make([]byte, 2*initialPartSize+12345)
	_, _ = rand.Read(data)
	for off := 0; off < len(data); off += 777777 {
		end := min(off+777777, len(data))
		if _, err := w.Write(data[off:end]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if len(c.parts) != 3 || len(c.parts[1]) != initialPartSize || len(c.parts[2]) != initialPartSize {
		t.Fatalf("unexpected parts layout: %d parts", len(c.parts))
	}
	got := append(append(append([]byte{}, c.parts[1]...), c.parts[2]...), c.parts[3]...)
	if !bytes.Equal(got, data) {
		t.Fatalf("reassembled multipart data mismatch")
	}

	// Exactly one part's worth goes through PutObject, not multipart.
	c2 := &backupRecordingClient{}
	w2 := newObjectStorageWriter(context.Background(), c2, "b", "k")
	_, _ = w2.Write(data[:initialPartSize])
	if err := w2.Close(); err != nil || !c2.putCalled || len(c2.parts) != 0 || !bytes.Equal(c2.put, data[:initialPartSize]) {
		t.Fatalf("expected single PutObject for an exactly-one-part object")
	}
}

func TestObjectStorageWriterAbortSurvivesCancelledContext(t *testing.T) {
	c := &backupRecordingClient{}
	ctx, cancel := context.WithCancel(context.Background())
	w := newObjectStorageWriter(ctx, c, "b", "k")
	_, _ = w.Write(make([]byte, initialPartSize+1)) // starts the multipart upload
	cancel()
	if err := w.Abort(); err != nil {
		t.Fatal(err)
	}
	if !c.abortCtxOK {
		t.Fatalf("multipart Abort ran on a cancelled context")
	}
	if c.putCalled {
		t.Fatalf("aborted writer committed an object")
	}
	if _, err := w.Write([]byte("x")); !errors.Is(err, ErrWriterClosed) {
		t.Fatalf("expected ErrWriterClosed, got %v", err)
	}
}

func TestObjectStorageNotFoundClassification(t *testing.T) {
	s := NewObjectStorage(&backupRecordingClient{}, "b", "p")
	ok, err := s.Exists(context.Background(), "missing")
	if ok || err != nil {
		t.Fatalf("Exists(missing) = %v, %v; want false, nil", ok, err)
	}
	if err := s.Delete(context.Background(), "missing"); err != nil {
		t.Fatalf("Delete(missing) = %v; want nil", err)
	}
}

// ---------------------------------------------------------
// LocalStorage (string table, atomic writes)
// ---------------------------------------------------------

func TestLocalStorageAtomicWriterAndNotFound(t *testing.T) {
	dir := t.TempDir()
	ls, _ := NewLocalStorage(dir)
	ctx := context.Background()

	if _, err := ls.Read(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Read: expected ErrNotFound, got %v", err)
	}
	if _, err := ls.Size(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Size: expected ErrNotFound, got %v", err)
	}
	if _, err := ls.OpenReader(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("OpenReader: expected ErrNotFound, got %v", err)
	}
	if _, err := ls.ReadRange(ctx, "nope", 0, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ReadRange: expected ErrNotFound, got %v", err)
	}

	if err := ls.Write(ctx, "ab/part", []byte("old")); err != nil {
		t.Fatal(err)
	}
	w, err := ls.OpenWriter(ctx, "ab/part")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("new but partial"))
	if got, _ := ls.Read(ctx, "ab/part"); string(got) != "old" {
		t.Fatalf("destination changed before Close: %q", got)
	}
	list, _ := ls.List(ctx, "")
	for _, f := range list {
		if strings.Contains(f.Name, localTempPrefix) {
			t.Fatalf("List exposed temp file %s", f.Name)
		}
	}
	if err := w.(AbortableWriter).Abort(); err != nil {
		t.Fatal(err)
	}
	if got, _ := ls.Read(ctx, "ab/part"); string(got) != "old" {
		t.Fatalf("aborted writer changed destination: %q", got)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "ab"))
	if len(entries) != 1 {
		t.Fatalf("expected only the destination file, found %d entries", len(entries))
	}

	// Simulated failure: the context dies before commit; nothing (partial) may appear.
	cctx, cancel := context.WithCancel(ctx)
	w2, _ := ls.OpenWriter(cctx, "ab/new")
	_, _ = w2.Write([]byte("partial"))
	cancel()
	if err := w2.Close(); err == nil {
		t.Fatalf("expected Close to fail on cancelled context")
	}
	if ok, _ := ls.Exists(ctx, "ab/new"); ok {
		t.Fatalf("partial file visible after failed Close")
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, "ab")); len(entries) != 1 {
		t.Fatalf("temp file leaked after failed Close")
	}
	if err := ls.Write(cctx, "ab/part", []byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Write ignored cancelled context: %v", err)
	}

	w3, _ := ls.OpenWriter(ctx, "ab/part")
	_, _ = w3.Write([]byte("committed"))
	if err := w3.Close(); err != nil {
		t.Fatal(err)
	}
	if got, _ := ls.Read(ctx, "ab/part"); string(got) != "committed" {
		t.Fatalf("Close did not commit: %q", got)
	}
}

// ---------------------------------------------------------
// Zip parsing (findings 14, 15)
// ---------------------------------------------------------

func buildPlainZip(t *testing.T, n int, comment string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := range n {
		w, err := zw.Create(fmt.Sprintf("dir/entry-%05d.txt", i), zip.Deflate, 5, zip.NoEncryption, "")
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(w, "content of entry %d", i)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	if comment != "" {
		// Patch an EOCD comment in (the writer does not support comments).
		b = append(b[:len(b)-2], byte(len(comment)), byte(len(comment)>>8))
		b = append(b, comment...)
	}
	return b
}

func TestZipCentralDirectoryReadIsConstantIO(t *testing.T) {
	const n = 5000
	mem := NewMemStorage()
	_ = mem.Write(context.Background(), "src.zip", buildPlainZip(t, n, ""))
	store := &backupHookStorage{Storage: mem}

	entries, err := NewZipFileSource(store, "src.zip", false).ListEntries(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != n {
		t.Fatalf("expected %d entries, got %d", n, len(entries))
	}
	if calls := store.readRanges.Load(); calls > 3 {
		t.Fatalf("listing %d entries issued %d ReadRange calls, want <= 3", n, calls)
	}

	// Reading one entry is a single ranged GET with verified content.
	store.readRanges.Store(0)
	rc, err := entries[1234].Open()
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil || string(got) != fmt.Sprintf("content of entry %d", 1234) {
		t.Fatalf("entry content mismatch: %q, %v", got, err)
	}
	if calls := store.readRanges.Load(); calls != 1 {
		t.Fatalf("reading one entry issued %d ReadRange calls, want 1", calls)
	}
}

func TestZipEOCDValidation(t *testing.T) {
	// Not a zip.
	junk := bytes.Repeat([]byte{0x42}, 4096)
	if _, err := GetZipPartRanges(bytes.NewReader(junk), int64(len(junk))); !errors.Is(err, ErrNotZip) {
		t.Fatalf("expected ErrNotZip, got %v", err)
	}

	// A fake EOCD signature inside the comment must not be picked.
	fake := "PK\x05\x06" + strings.Repeat("\x00", 18) + "trailing"
	z := buildPlainZip(t, 3, fake)
	off, err := FindEOCD(bytes.NewReader(z), int64(len(z)))
	if err != nil || off != int64(len(z)-22-len(fake)) {
		t.Fatalf("FindEOCD = %d, %v; want %d", off, err, len(z)-22-len(fake))
	}
	if r, err := GetZipPartRanges(bytes.NewReader(z), int64(len(z))); err != nil || len(r) != 3 {
		t.Fatalf("GetZipPartRanges with comment: %d ranges, %v", len(r), err)
	}

	// Zip64 sentinel offset without a zip64 record.
	bad := bytes.Clone(buildPlainZip(t, 2, ""))
	copy(bad[len(bad)-22+16:], []byte{0xff, 0xff, 0xff, 0xff})
	if _, err := GetCentralDirectoryOffset(bytes.NewReader(bad), int64(len(bad))); !errors.Is(err, ErrCorruptZip) {
		t.Fatalf("expected ErrCorruptZip for 0xFFFFFFFF offset without zip64, got %v", err)
	}
}

func TestZipSourceRejectsAE2Entries(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("secret.txt", zip.Deflate, 5, zip.AES256Encryption, "pw")
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("aes content"))
	zw.Close()
	mem := NewMemStorage()
	_ = mem.Write(context.Background(), "aes.zip", buf.Bytes())
	_, err = NewZipFileSource(mem, "aes.zip", true).ListEntries(context.Background())
	if !errors.Is(err, ErrUnsupportedEncryption) {
		t.Fatalf("expected ErrUnsupportedEncryption, got %v", err)
	}
}
