package tsync

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	tsyncv2 "github.com/abyii/t-sync-sdk-go/v2/gen/go/com/github/abyii/tsync/v2"
	zip "github.com/abyii/zip-xxh3"
	"golang.org/x/crypto/nacl/box"
	"google.golang.org/protobuf/proto"
)

var errInjected = errors.New("injected storage failure")

// hookStorage wraps a Storage and lets a test intercept Read and OpenReader.
type hookStorage struct {
	Storage
	read       func(ctx context.Context, path string) ([]byte, error)
	openReader func(ctx context.Context, path string, rc io.ReadCloser) (io.ReadCloser, error)
}

func (h *hookStorage) Read(ctx context.Context, path string) ([]byte, error) {
	if h.read != nil {
		return h.read(ctx, path)
	}
	return h.Storage.Read(ctx, path)
}

func (h *hookStorage) OpenReader(ctx context.Context, path string) (io.ReadCloser, error) {
	rc, err := h.Storage.OpenReader(ctx, path)
	if err != nil || h.openReader == nil {
		return rc, err
	}
	return h.openReader(ctx, path, rc)
}

// failAfterReader returns err once `after` bytes have been delivered.
type failAfterReader struct {
	io.ReadCloser
	after int
	err   error
}

func (f *failAfterReader) Read(p []byte) (int, error) {
	if f.after <= 0 {
		return 0, f.err
	}
	if len(p) > f.after {
		p = p[:f.after]
	}
	n, err := f.ReadCloser.Read(p)
	f.after -= n
	return n, err
}

type restoreFixture struct {
	store   *MemStorage
	version uint64
	pub     *[32]byte
	priv    *[32]byte
}

func newRestoreFixture(t *testing.T, files map[string][]byte, compressionLevel *int) *restoreFixture {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	src := NewMemStorage()
	for name, data := range files {
		if err := src.Write(context.Background(), name, data); err != nil {
			t.Fatalf("write source %s: %v", name, err)
		}
	}
	store := NewMemStorage()
	v, err := NewClient(store).Backup(context.Background(), NewFolderSource(src, ""), BackupOptions{
		Label:            "integrity",
		KeyID:            "key-1",
		PublicKeys:       map[string][]byte{"key-1": pub[:]},
		CompressionLevel: compressionLevel,
	})
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	return &restoreFixture{store: store, version: v.SnowflakeId, pub: pub, priv: priv}
}

func (f *restoreFixture) metadata(t *testing.T) *tsyncv2.BackupMetadata {
	t.Helper()
	md, err := loadMetadata(context.Background(), f.store)
	if err != nil {
		t.Fatalf("loadMetadata: %v", err)
	}
	return md
}

func (f *restoreFixture) saveMetadata(t *testing.T, md *tsyncv2.BackupMetadata) {
	t.Helper()
	b, err := proto.Marshal(md)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := f.store.Write(context.Background(), ".tsync", b); err != nil {
		t.Fatalf("write .tsync: %v", err)
	}
}

func (f *restoreFixture) fileKey(t *testing.T, path string) string {
	t.Helper()
	files, _, err := ResolveVersionTree(f.metadata(t), f.version, false)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	key, ok := files[path]
	if !ok {
		t.Fatalf("%s not in version", path)
	}
	return key
}

func (f *restoreFixture) partKey(t *testing.T, path string) string {
	key := f.fileKey(t, path)
	return key[0:2] + "/" + key
}

// tamperPart rewrites a stored part object.
func (f *restoreFixture) tamperPart(t *testing.T, path string, mutate func(part []byte) []byte) {
	t.Helper()
	pk := f.partKey(t, path)
	part, err := f.store.Read(context.Background(), pk)
	if err != nil {
		t.Fatalf("read part: %v", err)
	}
	if err := f.store.Write(context.Background(), pk, mutate(part)); err != nil {
		t.Fatalf("write part: %v", err)
	}
}

// payloadOffset returns the offset of the first byte after the local file header.
func payloadOffset(part []byte) int {
	nameLen := int(binary.LittleEndian.Uint16(part[26:28]))
	extraLen := int(binary.LittleEndian.Uint16(part[28:30]))
	return 30 + nameLen + extraLen
}

func storeLevel() *int { l := 0; return &l }

func testFiles() map[string][]byte {
	return map[string][]byte{
		"good.txt": bytes.Repeat([]byte("good content line\n"), 64),
		"bad.txt":  randomBytes(2048),
	}
}

func assertNoRestoreLeftovers(t *testing.T, dir string, absent ...string) {
	t.Helper()
	for _, p := range absent {
		if _, err := os.Stat(filepath.Join(dir, p)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("expected %s to be absent after failed restore, stat err = %v", p, err)
		}
	}
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && strings.HasPrefix(info.Name(), ".tsync-restore-tmp-") {
			t.Errorf("temp file left behind: %s", p)
		}
		return nil
	})
}

func TestRestoreContextCancelledMidRestoreReturnsError(t *testing.T) {
	files := map[string][]byte{}
	for i := range 8 {
		files[fmt.Sprintf("f%d.txt", i)] = []byte(fmt.Sprintf("content %d", i))
	}
	fx := newRestoreFixture(t, files, nil)

	for _, mode := range []string{"extract", "zip"} {
		for _, skip := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/skip=%v", mode, skip), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var once sync.Once
				// Like LocalStorage, the reader ignores ctx; cancellation happens between tasks.
				hs := &hookStorage{Storage: fx.store, openReader: func(_ context.Context, _ string, rc io.ReadCloser) (io.ReadCloser, error) {
					once.Do(cancel)
					return rc, nil
				}}
				opts := RestoreOptions{PrivateKey: fx.priv[:], Concurrency: 1, SkipDecryptionErrors: skip}
				var zipBuf bytes.Buffer
				if mode == "extract" {
					opts.ExtractDir = t.TempDir()
				} else {
					opts.ZipWriter = &zipBuf
				}
				err := RunRestore(ctx, hs, fx.version, opts)
				if err == nil {
					t.Fatal("expected error after context cancellation, got nil")
				}
				if !errors.Is(err, ErrIncompleteRun) || !errors.Is(err, context.Canceled) {
					t.Fatalf("expected ErrIncompleteRun wrapping context.Canceled, got %v", err)
				}
			})
		}
	}
}

func TestSkipDecryptionErrorsDoesNotHideIOErrors(t *testing.T) {
	fx := newRestoreFixture(t, testFiles(), nil)
	badPart := fx.partKey(t, "bad.txt")

	cases := map[string]func(ctx context.Context, path string, rc io.ReadCloser) (io.ReadCloser, error){
		"open": func(_ context.Context, path string, rc io.ReadCloser) (io.ReadCloser, error) {
			if path == badPart {
				rc.Close()
				return nil, errInjected
			}
			return rc, nil
		},
		"midstream": func(_ context.Context, path string, rc io.ReadCloser) (io.ReadCloser, error) {
			if path == badPart {
				return &failAfterReader{ReadCloser: rc, after: 100, err: errInjected}, nil
			}
			return rc, nil
		},
	}
	for name, hook := range cases {
		for _, mode := range []string{"extract", "zip"} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				hs := &hookStorage{Storage: fx.store, openReader: hook}
				opts := RestoreOptions{PrivateKey: fx.priv[:], SkipDecryptionErrors: true}
				var zipBuf bytes.Buffer
				if mode == "extract" {
					opts.ExtractDir = t.TempDir()
				} else {
					opts.ZipWriter = &zipBuf
				}
				err := RunRestore(context.Background(), hs, fx.version, opts)
				if !errors.Is(err, errInjected) {
					t.Fatalf("expected injected I/O error to be returned despite SkipDecryptionErrors, got %v", err)
				}
				if errors.Is(err, ErrCorruptPart) || errors.Is(err, ErrDecryptionFailed) {
					t.Fatalf("I/O error misclassified as part/decryption error: %v", err)
				}
				if mode == "extract" {
					assertNoRestoreLeftovers(t, opts.ExtractDir, "bad.txt")
				}
			})
		}
	}
}

func TestRestoreRejectsCorruptAndTruncatedParts(t *testing.T) {
	type tc struct {
		level  *int
		mutate func(part []byte) []byte
		zipToo bool // the raw-copy ZipWriter path can only detect length problems
	}
	cases := map[string]tc{
		"store-bitflip": {level: storeLevel(), mutate: func(p []byte) []byte {
			p[payloadOffset(p)+12+100] ^= 0xFF
			return p
		}},
		"store-truncated": {level: storeLevel(), zipToo: true, mutate: func(p []byte) []byte {
			return p[:payloadOffset(p)+12+5]
		}},
		"deflate-truncated": {level: nil, zipToo: true, mutate: func(p []byte) []byte {
			return p[:payloadOffset(p)+12+5]
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			fx := newRestoreFixture(t, testFiles(), c.level)
			fx.tamperPart(t, "bad.txt", c.mutate)

			dir := t.TempDir()
			err := RunRestore(context.Background(), fx.store, fx.version, RestoreOptions{ExtractDir: dir, PrivateKey: fx.priv[:]})
			if !errors.Is(err, ErrCorruptPart) {
				t.Fatalf("expected ErrCorruptPart, got %v", err)
			}
			assertNoRestoreLeftovers(t, dir, "bad.txt")

			// SkipDecryptionErrors skips the corrupt file but restores the rest.
			dir2 := t.TempDir()
			err = RunRestore(context.Background(), fx.store, fx.version, RestoreOptions{ExtractDir: dir2, PrivateKey: fx.priv[:], SkipDecryptionErrors: true})
			if err != nil {
				t.Fatalf("expected corrupt part to be skipped, got %v", err)
			}
			assertNoRestoreLeftovers(t, dir2, "bad.txt")
			if got, err := os.ReadFile(filepath.Join(dir2, "good.txt")); err != nil || !bytes.Equal(got, testFiles()["good.txt"]) {
				t.Fatalf("good.txt not restored correctly: %v", err)
			}

			if c.zipToo {
				var zipBuf bytes.Buffer
				err = RunRestore(context.Background(), fx.store, fx.version, RestoreOptions{ZipWriter: &zipBuf, PrivateKey: fx.priv[:], FilesToRestore: []string{"bad.txt"}})
				if !errors.Is(err, ErrCorruptPart) {
					t.Fatalf("zip mode: expected ErrCorruptPart, got %v", err)
				}
			}
		})
	}
}

func TestRestoreRejectsUnsupportedMethod(t *testing.T) {
	fx := newRestoreFixture(t, testFiles(), nil)
	fx.tamperPart(t, "bad.txt", func(p []byte) []byte {
		binary.LittleEndian.PutUint16(p[8:10], 93) // zstd
		return p
	})
	err := RunRestore(context.Background(), fx.store, fx.version, RestoreOptions{ExtractDir: t.TempDir(), PrivateKey: fx.priv[:]})
	if !errors.Is(err, ErrUnsupportedMethod) {
		t.Fatalf("extract: expected ErrUnsupportedMethod, got %v", err)
	}
	var zipBuf bytes.Buffer
	err = RunRestore(context.Background(), fx.store, fx.version, RestoreOptions{ZipWriter: &zipBuf, PrivateKey: fx.priv[:]})
	if !errors.Is(err, ErrUnsupportedMethod) {
		t.Fatalf("zip: expected ErrUnsupportedMethod, got %v", err)
	}
}

func TestRestoreWrongKeyIsDecryptionFailed(t *testing.T) {
	fx := newRestoreFixture(t, testFiles(), nil)
	_, otherPriv, _ := box.GenerateKey(rand.Reader)

	dir := t.TempDir()
	err := RunRestore(context.Background(), fx.store, fx.version, RestoreOptions{ExtractDir: dir, PrivateKey: otherPriv[:]})
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("extract: expected ErrDecryptionFailed, got %v", err)
	}
	assertNoRestoreLeftovers(t, dir, "good.txt", "bad.txt")

	var zipBuf bytes.Buffer
	err = RunRestore(context.Background(), fx.store, fx.version, RestoreOptions{ZipWriter: &zipBuf, PrivateKey: otherPriv[:]})
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("zip: expected ErrDecryptionFailed, got %v", err)
	}

	err = RunRestore(context.Background(), fx.store, fx.version, RestoreOptions{ExtractDir: t.TempDir()})
	if !errors.Is(err, ErrPrivateKeyRequired) {
		t.Fatalf("expected ErrPrivateKeyRequired without key, got %v", err)
	}
}

func TestRestoreWrongZipPassword(t *testing.T) {
	fx := newRestoreFixture(t, testFiles(), nil)
	md := fx.metadata(t)
	rec := md.Files[fx.fileKey(t, "bad.txt")]
	eph, enc, err := EncryptPassword("definitely-not-the-password", fx.pub[:])
	if err != nil {
		t.Fatalf("EncryptPassword: %v", err)
	}
	rec.EphemeralPublicKey, rec.EncryptedZipPassword = eph, enc
	fx.saveMetadata(t, md)

	dir := t.TempDir()
	err = RunRestore(context.Background(), fx.store, fx.version, RestoreOptions{ExtractDir: dir, PrivateKey: fx.priv[:]})
	// The ZipCrypto check byte rejects a wrong password with probability 255/256; the rare
	// pass-through is still caught by the CRC32 check.
	if !errors.Is(err, ErrDecryptionFailed) && !errors.Is(err, ErrCorruptPart) {
		t.Fatalf("expected ErrDecryptionFailed (or ErrCorruptPart), got %v", err)
	}
	assertNoRestoreLeftovers(t, dir, "bad.txt")
}

func TestRestoreZipSkipsBadPasswordBeforeWriting(t *testing.T) {
	fx := newRestoreFixture(t, testFiles(), nil)
	md := fx.metadata(t)
	rec := md.Files[fx.fileKey(t, "bad.txt")]
	rec.EncryptedZipPassword[len(rec.EncryptedZipPassword)-1] ^= 0xFF // breaks the NaCl box
	fx.saveMetadata(t, md)

	var zipBuf bytes.Buffer
	err := RunRestore(context.Background(), fx.store, fx.version, RestoreOptions{ZipWriter: &zipBuf, PrivateKey: fx.priv[:], SkipDecryptionErrors: true})
	if err != nil {
		t.Fatalf("expected skippable decryption error, got %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(zipBuf.Bytes()), int64(zipBuf.Len()))
	if err != nil {
		t.Fatalf("output zip is not valid: %v", err)
	}
	if len(zr.File) != 1 || zr.File[0].Name != "good.txt" {
		t.Fatalf("expected only good.txt in output, got %d entries", len(zr.File))
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatalf("open good.txt: %v", err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil || !bytes.Equal(got, testFiles()["good.txt"]) {
		t.Fatalf("good.txt content mismatch: %v", err)
	}
}

func TestRestoredFileModeNotWorldWritable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	fx := newRestoreFixture(t, testFiles(), nil)
	dir := t.TempDir()
	if err := RunRestore(context.Background(), fx.store, fx.version, RestoreOptions{ExtractDir: dir, PrivateKey: fx.priv[:]}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	for name := range testFiles() {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o644 {
			t.Errorf("%s: expected mode 0644, got %#o", name, perm)
		}
	}
}

func TestRestoreEmptyDirCreationErrorIsReturned(t *testing.T) {
	fx := newRestoreFixture(t, map[string][]byte{"f.txt": []byte("x"), "blocked/sub/": nil}, nil)
	dir := t.TempDir()
	// A regular file where a parent of the empty directory must go makes MkdirAll fail.
	if err := os.WriteFile(filepath.Join(dir, "blocked"), []byte("not a dir"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := RunRestore(context.Background(), fx.store, fx.version, RestoreOptions{ExtractDir: dir, PrivateKey: fx.priv[:]})
	if err == nil {
		t.Fatal("expected empty-directory creation failure to be returned")
	}
	err = RunRestore(context.Background(), fx.store, fx.version, RestoreOptions{ExtractDir: dir, PrivateKey: fx.priv[:], SkipValidationErrors: true})
	if err != nil {
		t.Fatalf("expected SkipValidationErrors to log and continue, got %v", err)
	}
}

func TestRestoreOptionAndVersionErrors(t *testing.T) {
	fx := newRestoreFixture(t, testFiles(), nil)
	if err := RunRestore(context.Background(), fx.store, fx.version, RestoreOptions{}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("expected ErrInvalidOptions, got %v", err)
	}
	if err := RunRestore(context.Background(), fx.store, fx.version, RestoreOptions{ExtractDir: t.TempDir(), PrivateKey: []byte("short")}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("expected ErrInvalidOptions for bad key length, got %v", err)
	}
	if err := RunRestore(context.Background(), fx.store, fx.version+1, RestoreOptions{ExtractDir: t.TempDir(), PrivateKey: fx.priv[:]}); !errors.Is(err, ErrVersionNotFound) {
		t.Fatalf("expected ErrVersionNotFound, got %v", err)
	}
	if err := RunRestore(context.Background(), NewMemStorage(), 1, RestoreOptions{ExtractDir: t.TempDir()}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing store, got %v", err)
	}
}
