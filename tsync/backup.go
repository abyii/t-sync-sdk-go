package tsync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"maps"
	"math"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tsyncv2 "github.com/abyii/t-sync-sdk-go/v2/gen/go/com/github/abyii/tsync/v2"

	zip "github.com/abyii/zip-xxh3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var globalVersionSeq uint64

// futureTimestampTolerance is the clock skew allowed for CustomBackupTimestamp.
const futureTimestampTolerance = time.Hour

// BackupOptions configures the backup operation.
type BackupOptions struct {
	Label             string
	SingleVersionMode bool
	FilterFunc        func(path string) (bool, error)
	Concurrency       int

	// Cryptographic settings for unencrypted source:
	KeyID      string            // Public key ID to use. If empty, the lexicographically first key in public_keys is used.
	PublicKeys map[string][]byte // Maps key ID -> public key. Required if creating a new store.

	// Cryptographic settings for pre-encrypted source. When set, every file entry of the
	// source must be IsEncryptedRaw (plaintext entries are rejected with ErrInvalidOptions).
	EphPublicKey      []byte
	EncryptedPassword []byte

	// OnProgress is an optional callback triggered as each file backup completes.
	OnProgress func(done, total int, path string)

	// CompressionLevel specifies the compression level to use (from -1 to 9).
	// If nil or -1, it defaults to Deflate with level 5.
	// If 0, it uses Store (no compression).
	// If 1 to 9, it uses Deflate with the specified level.
	CompressionLevel *int

	// GetCompressionLevel is an optional callback allowing clients to specify per-file compression levels.
	// The callback is passed the file path and returns the compression level to use (from -1 to 9).
	// If the callback returns nil, the engine falls back to CompressionLevel option, and then to default (5).
	GetCompressionLevel func(path string) *int

	// CustomVersionID specifies a custom Snowflake ID for this backup version (<= math.MaxInt64).
	// If 0, a new ID is generated automatically (also <= math.MaxInt64).
	CustomVersionID uint64

	// CustomBackupTimestamp specifies a custom timestamp for this backup version.
	// If zero, the current time is used. It must be strictly after the latest version's
	// timestamp and not more than one hour in the future.
	CustomBackupTimestamp time.Time
}

// validateName validates a single name component for directory or file entries.
// `/` is the only path separator in tree paths; `\` is an ordinary name byte so that
// archive names are preserved exactly as the source stores them.
func validateName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("%w: name cannot be empty", ErrInvalidName)
	}
	if len(name) > 255 {
		return fmt.Errorf("%w: name exceeds maximum length of 255 bytes: %q", ErrInvalidName, name)
	}
	for i := range len(name) {
		c := name[i]
		if c == '/' {
			return fmt.Errorf("%w: name contains path separator '/': %q", ErrInvalidName, name)
		}
		if c == 0 {
			return fmt.Errorf("%w: name contains null byte: %q", ErrInvalidName, name)
		}
	}
	if name == "." || name == ".." {
		return fmt.Errorf("%w: name cannot be directory traversal sentinel %q", ErrInvalidName, name)
	}
	return nil
}

type tempDirNode struct {
	files   map[string]*tsyncv2.FileLeaf
	subdirs map[string]*tempDirNode
}

func newTempDirNode() *tempDirNode {
	return &tempDirNode{
		files:   make(map[string]*tsyncv2.FileLeaf),
		subdirs: make(map[string]*tempDirNode),
	}
}

func (n *tempDirNode) buildAndHash(trees map[string]*tsyncv2.TreeNode) (string, error) {
	var entries []*tsyncv2.TreeEntry

	for name, fileLeaf := range n.files {
		entries = append(entries, &tsyncv2.TreeEntry{
			Name: name,
			Node: &tsyncv2.TreeEntry_File{
				File: fileLeaf,
			},
		})
	}

	for name, subdirNode := range n.subdirs {
		subHash, err := subdirNode.buildAndHash(trees)
		if err != nil {
			return "", err
		}
		entries = append(entries, &tsyncv2.TreeEntry{
			Name: name,
			Node: &tsyncv2.TreeEntry_SubtreeHash{
				SubtreeHash: subHash,
			},
		})
	}

	// 1. Sort entries by name - raw UTF-8 byte order, case-sensitive
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})

	// 2. Deterministic proto3 binary encoding
	treeNode := &tsyncv2.TreeNode{
		Entries: entries,
	}

	marshaled, err := proto.MarshalOptions{Deterministic: true}.Marshal(treeNode)
	if err != nil {
		return "", fmt.Errorf("failed to marshal tree node: %w", err)
	}

	// 3. Hash: SHA-256 over serialized bytes
	h := sha256.New()
	h.Write(marshaled)
	hashHex := hex.EncodeToString(h.Sum(nil))

	trees[hashHex] = treeNode
	return hashHex, nil
}

// fileKeyFor returns the content key "crc32hex_size" of a file part.
func fileKeyFor(crc uint32, size int64) string {
	return fmt.Sprintf("%08x_%d", crc, size)
}

// isValidFileKey reports whether k has the form ^[0-9a-f]{8}_[0-9]+$.
func isValidFileKey(k string) bool {
	if len(k) < 10 || k[8] != '_' {
		return false
	}
	for _, c := range []byte(k[:8]) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	for i := 9; i < len(k); i++ {
		if k[i] < '0' || k[i] > '9' {
			return false
		}
	}
	return true
}

// partKeyFor returns the storage path of the part with the given (valid) file key.
func partKeyFor(fileKey string) string {
	return fileKey[0:2] + "/" + fileKey
}

// resolveCompression maps a compression level option to a zip method and level.
func resolveCompression(lvl int) (uint16, int, error) {
	switch {
	case lvl == 0:
		return zip.Store, 0, nil
	case lvl >= -1 && lvl <= 9:
		return zip.Deflate, lvl, nil
	}
	return 0, 0, fmt.Errorf("%w: invalid compression level %d (must be between -1 and 9)", ErrInvalidOptions, lvl)
}

// latestVersion returns the version with the greatest timestamp (ties broken by ID), or nil.
func latestVersion(md *tsyncv2.BackupMetadata) *tsyncv2.Version {
	var latest *tsyncv2.Version
	var latestTS time.Time
	for _, v := range md.GetVersions() {
		ts := v.GetBackupTimestamp().AsTime()
		if latest == nil || ts.After(latestTS) || (ts.Equal(latestTS) && v.GetSnowflakeId() > latest.GetSnowflakeId()) {
			latest, latestTS = v, ts
		}
	}
	return latest
}

// generateVersionID returns a fresh non-zero version ID <= math.MaxInt64 not present in existing.
func generateVersionID(existing map[string]*tsyncv2.Version) uint64 {
	const mask = uint64(1) << 63
	id := hashStringToUint64(strconv.FormatInt(time.Now().UnixNano(), 10)) &^ mask
	for id == 0 || existing[strconv.FormatUint(id, 10)] != nil {
		seq := atomic.AddUint64(&globalVersionSeq, 1)
		id = hashStringToUint64(fmt.Sprintf("%d-%d", time.Now().UnixNano(), seq)) &^ mask
	}
	return id
}

func validateBackupOptions(opts *BackupOptions) error {
	for k, pk := range opts.PublicKeys {
		if len(pk) != 32 {
			return fmt.Errorf("%w: invalid public key length for key ID %q: expected 32 bytes (NaCl Curve25519), got %d (check if an RSA/PEM key was passed by mistake)", ErrInvalidOptions, k, len(pk))
		}
	}
	if len(opts.EphPublicKey) > 0 && len(opts.EphPublicKey) != 32 {
		return fmt.Errorf("%w: invalid EphPublicKey: expected 32 bytes (NaCl Curve25519), got %d", ErrInvalidOptions, len(opts.EphPublicKey))
	}
	if len(opts.EncryptedPassword) > 0 && len(opts.EncryptedPassword) < 40 {
		return fmt.Errorf("%w: invalid EncryptedPassword: must be at least 40 bytes (24-byte nonce + 16-byte Poly1305 tag), got %d", ErrInvalidOptions, len(opts.EncryptedPassword))
	}
	if opts.KeyID != "" && len(opts.PublicKeys) > 0 {
		if _, exists := opts.PublicKeys[opts.KeyID]; !exists {
			return fmt.Errorf("%w: selected key ID %q not in BackupOptions.PublicKeys", ErrKeyNotFound, opts.KeyID)
		}
	}
	if opts.CustomVersionID > math.MaxInt64 {
		return fmt.Errorf("%w: invalid custom version ID %d (must be <= %d)", ErrInvalidOptions, opts.CustomVersionID, int64(math.MaxInt64))
	}
	if !opts.CustomBackupTimestamp.IsZero() && opts.CustomBackupTimestamp.After(time.Now().Add(futureTimestampTolerance)) {
		return fmt.Errorf("%w: custom backup timestamp %v", ErrTimestampInFuture, opts.CustomBackupTimestamp)
	}
	if opts.CompressionLevel != nil {
		if _, _, err := resolveCompression(*opts.CompressionLevel); err != nil {
			return err
		}
	}
	return nil
}

// copyBufPool recycles copy buffers across the (many) files of a run.
var copyBufPool = sync.Pool{New: func() any {
	b := make([]byte, 256*1024)
	return &b
}}

func pooledCopy(dst io.Writer, src io.Reader) (int64, error) {
	bp := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bp)
	return io.CopyBuffer(dst, src, *bp)
}

// abortWriter discards a part writer after a failure. Writers that implement AbortableWriter
// are aborted so nothing is committed; others are closed (releasing their resources) — any
// object they commit is unreferenced by metadata.
func abortWriter(w io.WriteCloser) error {
	if a, ok := w.(AbortableWriter); ok {
		return a.Abort()
	}
	return w.Close()
}

// uploadFlight deduplicates concurrent uploads of the same file key within one run.
type uploadFlight struct {
	done chan struct{}
	rec  *tsyncv2.FileRecord
	err  error
}

// backupRun holds the shared, read-mostly state of one RunBackup call.
type backupRun struct {
	dest       Storage
	opts       *BackupOptions
	compMethod uint16
	compLevel  int

	ephPubKey        []byte
	encryptedZipPass []byte
	clearZipPass     string
	keyID            string

	existing map[string]*tsyncv2.FileRecord // file records of the loaded metadata (read-only)

	mu      sync.Mutex
	flights map[string]*uploadFlight
}

type backupResult struct {
	path   string
	isDir  bool
	key    string
	record *tsyncv2.FileRecord
	err    error
}

func isDirEntry(e *SourceEntry) bool {
	return e.IsDir || strings.HasSuffix(e.Path, "/")
}

// process handles one entry and always produces exactly one result.
func (r *backupRun) process(ctx context.Context, cancel context.CancelCauseFunc, entry SourceEntry) backupResult {
	if ctx.Err() != nil {
		return backupResult{path: entry.Path, err: context.Cause(ctx)}
	}
	if isDirEntry(&entry) {
		return backupResult{path: entry.Path, isDir: true}
	}
	key, rec, err := r.processFile(ctx, &entry)
	if err != nil {
		// Record the root cause before siblings observe the cancellation.
		cancel(err)
		return backupResult{path: entry.Path, err: err}
	}
	return backupResult{path: entry.Path, key: key, record: rec}
}

func (r *backupRun) processFile(ctx context.Context, entry *SourceEntry) (string, *tsyncv2.FileRecord, error) {
	var key string
	switch {
	case entry.IsEncryptedRaw:
		// Pre-encrypted parts cannot be read in plaintext: the central-directory CRC/size is authoritative.
		if entry.OpenRaw == nil {
			return "", nil, fmt.Errorf("%w: entry %q is IsEncryptedRaw but OpenRaw is nil", ErrInvalidOptions, entry.Path)
		}
		key = fileKeyFor(entry.CRC32, entry.Size)
	case entry.CRC32 != 0 || entry.Size == 0:
		key = fileKeyFor(entry.CRC32, entry.Size)
	default:
		// CRC unknown: read the content once to compute the key.
		if entry.Open == nil {
			return "", nil, fmt.Errorf("%w: entry %q has no CRC32 and Open is nil", ErrInvalidOptions, entry.Path)
		}
		rc, err := entry.Open()
		if err != nil {
			return "", nil, fmt.Errorf("failed to open source file %s: %w", entry.Path, err)
		}
		h := crc32.NewIEEE()
		size, err := pooledCopy(h, rc)
		rc.Close()
		if err != nil {
			return "", nil, fmt.Errorf("failed to read source file %s: %w", entry.Path, err)
		}
		key = fileKeyFor(h.Sum32(), size)
	}

	if rec := r.existing[key]; rec != nil {
		return key, rec, nil
	}
	rec, err := r.uploadOnce(ctx, key, entry)
	return key, rec, err
}

// uploadOnce uploads the part for key at most once per run; concurrent callers with the
// same key wait for the first upload and reuse its record.
func (r *backupRun) uploadOnce(ctx context.Context, key string, entry *SourceEntry) (*tsyncv2.FileRecord, error) {
	r.mu.Lock()
	if fl, ok := r.flights[key]; ok {
		r.mu.Unlock()
		select {
		case <-fl.done:
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
		if fl.err != nil {
			return nil, fl.err
		}
		return fl.rec, nil
	}
	fl := &uploadFlight{done: make(chan struct{})}
	r.flights[key] = fl
	r.mu.Unlock()

	fl.rec, fl.err = r.uploadPart(ctx, key, entry)
	close(fl.done)
	return fl.rec, fl.err
}

func (r *backupRun) compressionFor(p string) (uint16, int, error) {
	if r.opts.GetCompressionLevel != nil {
		if lvl := r.opts.GetCompressionLevel(p); lvl != nil {
			m, l, err := resolveCompression(*lvl)
			if err != nil {
				return 0, 0, fmt.Errorf("compression level callback for %s: %w", p, err)
			}
			return m, l, nil
		}
	}
	return r.compMethod, r.compLevel, nil
}

// uploadPart writes the part object for entry under key. The object is committed only if
// the content was fully produced and matches key; otherwise the writer is aborted.
func (r *backupRun) uploadPart(ctx context.Context, key string, entry *SourceEntry) (*tsyncv2.FileRecord, error) {
	compMethod, compLevel, err := r.compressionFor(entry.Path)
	if err != nil {
		return nil, err
	}

	var open func() (io.ReadCloser, error)
	switch {
	case entry.IsEncryptedRaw:
		open = entry.OpenRaw
	case entry.OpenRawCompressed != nil:
		open = entry.OpenRawCompressed
	case entry.Open != nil:
		open = entry.Open
	default:
		return nil, fmt.Errorf("%w: entry %q has neither Open nor OpenRawCompressed", ErrInvalidOptions, entry.Path)
	}
	rc, err := open()
	if err != nil {
		return nil, fmt.Errorf("failed to open source %s: %w", entry.Path, err)
	}
	defer rc.Close()

	partKey := partKeyFor(key)
	w, err := r.dest.OpenWriter(ctx, partKey)
	if err != nil {
		return nil, fmt.Errorf("failed to open writer for %s: %w", partKey, err)
	}

	var crc uint32
	var uncompSize, compSize int64
	switch {
	case entry.IsEncryptedRaw:
		crc, uncompSize, compSize = entry.CRC32, entry.Size, entry.CompressedSize
		err = copyRawPart(w, rc, entry)
	case entry.OpenRawCompressed != nil:
		crc, uncompSize = entry.CRC32, entry.Size
		compSize, err = r.writeRawCompressedPart(w, rc, entry)
	default:
		crc, uncompSize, compSize, err = r.writeCompressedPart(w, rc, entry, compMethod, compLevel)
	}
	if err == nil && fileKeyFor(crc, uncompSize) != key {
		err = fmt.Errorf("%w: %s was keyed as %s but its content is %s", ErrSourceChanged, entry.Path, key, fileKeyFor(crc, uncompSize))
	}
	if err != nil {
		return nil, errors.Join(err, abortWriter(w))
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("failed to commit part %s: %w", partKey, err)
	}

	rec := &tsyncv2.FileRecord{
		EphemeralPublicKey:   r.ephPubKey,
		EncryptedZipPassword: r.encryptedZipPass,
		Crc32:                crc,
		CompressedSize:       compSize,
		UncompressedSize:     uncompSize,
		LastModified:         timestamppb.New(entry.LastModified),
	}
	if r.keyID != "" {
		keyID := r.keyID
		rec.KeyId = &keyID
	}
	return rec, nil
}

// copyRawPart streams pre-encrypted part bytes (LFH + payload + data descriptor) verbatim.
func copyRawPart(w io.Writer, rc io.Reader, entry *SourceEntry) error {
	n, err := pooledCopy(w, rc)
	if err != nil {
		return fmt.Errorf("failed to copy raw part for %s: %w", entry.Path, err)
	}
	if n < entry.CompressedSize {
		return fmt.Errorf("%w: raw part for %s is %d bytes, shorter than its compressed size %d", ErrCorruptZip, entry.Path, n, entry.CompressedSize)
	}
	return nil
}

// writeRawCompressedPart wraps an already-compressed payload into a part, encrypting on the fly.
// It returns the payload size as written (including the 12-byte ZipCrypto header).
func (r *backupRun) writeRawCompressedPart(w io.Writer, rc io.Reader, entry *SourceEntry) (int64, error) {
	fh := &zip.FileHeader{
		Name:               path.Base(entry.Path),
		Method:             entry.CompressionMethod,
		CRC32:              entry.CRC32,
		CompressedSize64:   uint64(entry.CompressedSize),
		UncompressedSize64: uint64(entry.Size),
	}
	fh.SetModTime(entry.LastModified)
	if r.clearZipPass != "" {
		fh.SetEncryptionMethod(zip.StandardEncryption)
		fh.SetPassword(r.clearZipPass)
	}
	wPart, err := zip.NewWriter().CreateRawFileParts(fh, 0, w)
	if err != nil {
		return 0, fmt.Errorf("failed to create raw zip file part for %s: %w", entry.Path, err)
	}
	if _, err := pooledCopy(wPart, rc); err != nil {
		return 0, fmt.Errorf("failed to copy raw compressed bytes for %s: %w", entry.Path, err)
	}
	if err := wPart.Close(); err != nil {
		return 0, fmt.Errorf("failed to close raw part writer for %s: %w", entry.Path, err)
	}
	// The writer updates the header with the bytes it actually wrote (payload + encryption header).
	return int64(fh.CompressedSize64), nil
}

// writeCompressedPart compresses and encrypts plaintext content into a part.
// Sizes and CRC come from the zip writer's header after close, so they always match the
// bytes in the part (including zip64 data-descriptor handling inside the library).
func (r *backupRun) writeCompressedPart(w io.Writer, rc io.Reader, entry *SourceEntry, method uint16, level int) (uint32, int64, int64, error) {
	fh := &zip.FileHeader{
		Name:             path.Base(entry.Path),
		Method:           method,
		CompressionLevel: level,
	}
	if r.clearZipPass != "" {
		fh.SetEncryptionMethod(zip.StandardEncryption)
		fh.SetPassword(r.clearZipPass)
	}
	wPart, err := zip.NewWriter().CreateFileParts(fh, 0, w)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("failed to create zip file part for %s: %w", entry.Path, err)
	}
	if _, err := pooledCopy(wPart, rc); err != nil {
		return 0, 0, 0, fmt.Errorf("failed to compress/encrypt file %s: %w", entry.Path, err)
	}
	if err := wPart.Close(); err != nil {
		return 0, 0, 0, fmt.Errorf("failed to close zip part writer for %s: %w", entry.Path, err)
	}
	return fh.CRC32, int64(fh.UncompressedSize64), int64(fh.CompressedSize64), nil
}

// runError converts the end state of the worker phase into the error to return (nil if complete).
func runError(parent, runCtx context.Context, firstErr error, done, total int) error {
	cause := context.Cause(runCtx)
	if cause == nil {
		cause = firstErr
	}
	if cause != nil {
		if parent.Err() != nil {
			return fmt.Errorf("%w: %w", ErrIncompleteRun, cause)
		}
		return cause
	}
	if done != total {
		return fmt.Errorf("%w: processed %d of %d entries", ErrIncompleteRun, done, total)
	}
	return nil
}

func RunBackup(ctx context.Context, src Source, dest Storage, opts BackupOptions) (*tsyncv2.Version, error) {
	// 0. Validate input options upfront
	if err := validateBackupOptions(&opts); err != nil {
		return nil, err
	}
	compMethod, compLevel := uint16(zip.Deflate), -1
	if opts.CompressionLevel != nil {
		compMethod, compLevel, _ = resolveCompression(*opts.CompressionLevel)
	}

	// Clean up source if it implements io.Closer
	if closer, ok := src.(io.Closer); ok {
		defer closer.Close()
	}

	// 1. Load existing metadata. Only a missing .tsync means "new store"; any other read
	// failure must not be mistaken for an empty store.
	metadata, err := loadMetadata(ctx, dest)
	hasOldMetadata := err == nil
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		if len(opts.PublicKeys) == 0 {
			return nil, fmt.Errorf("%w: creating a new backup store requires at least one public key", ErrStoreNotInitialized)
		}
		metadata = &tsyncv2.BackupMetadata{
			Versions:      make(map[string]*tsyncv2.Version),
			Trees:         make(map[string]*tsyncv2.TreeNode),
			Files:         make(map[string]*tsyncv2.FileRecord),
			PublicKeys:    maps.Clone(opts.PublicKeys),
			SchemaVersion: 2,
		}
	}

	// 2. Version ID / timestamp ordering checks (before touching the source).
	latest := latestVersion(metadata)
	if opts.CustomVersionID != 0 {
		if _, exists := metadata.Versions[strconv.FormatUint(opts.CustomVersionID, 10)]; exists {
			return nil, fmt.Errorf("%w: %d", ErrVersionIDExists, opts.CustomVersionID)
		}
	}
	if !opts.CustomBackupTimestamp.IsZero() && latest != nil {
		latestTS := latest.GetBackupTimestamp().AsTime()
		if opts.CustomBackupTimestamp.Equal(latestTS) {
			return nil, fmt.Errorf("%w: %v (version %d)", ErrTimestampEqualsLatest, latestTS, latest.GetSnowflakeId())
		}
		if opts.CustomBackupTimestamp.Before(latestTS) {
			return nil, fmt.Errorf("%w: %v is before %v (version %d)", ErrTimestampBeforeLatest, opts.CustomBackupTimestamp, latestTS, latest.GetSnowflakeId())
		}
	}

	if hasOldMetadata {
		// Merge any new public keys into the existing ones
		if metadata.PublicKeys == nil {
			metadata.PublicKeys = make(map[string][]byte)
		}
		maps.Copy(metadata.PublicKeys, opts.PublicKeys)
	}

	// 3. List the source on a cancellable run context: entry closures capture it, so the
	// first failure (or a caller cancellation) stops all in-flight source and storage I/O.
	runCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	allEntries, err := src.ListEntries(runCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to list source entries: %w", err)
	}

	// Apply filter and validate path components upfront
	entries := make([]SourceEntry, 0, len(allEntries))
	for _, entry := range allEntries {
		if opts.FilterFunc != nil {
			keep, err := opts.FilterFunc(entry.Path)
			if err != nil {
				return nil, fmt.Errorf("filter callback failed for %s: %w", entry.Path, err)
			}
			if !keep {
				continue
			}
		}

		if entry.Path == "" {
			return nil, fmt.Errorf("%w: empty path entry", ErrInvalidName)
		}

		cleanPath := strings.TrimSuffix(entry.Path, "/")
		for _, part := range strings.Split(cleanPath, "/") {
			if err := validateName(part); err != nil {
				return nil, fmt.Errorf("invalid path component in %q: %w", entry.Path, err)
			}
		}

		entries = append(entries, entry)
	}

	// 4. Cryptographic keys and ZIP password for this pass
	run := &backupRun{
		dest:       dest,
		opts:       &opts,
		compMethod: compMethod,
		compLevel:  compLevel,
		existing:   metadata.Files,
		flights:    make(map[string]*uploadFlight),
	}

	hasRaw, hasPlain := false, false
	for i := range entries {
		if isDirEntry(&entries[i]) {
			continue
		}
		if entries[i].IsEncryptedRaw {
			hasRaw = true
		} else {
			hasPlain = true
		}
	}

	if hasRaw || len(opts.EncryptedPassword) > 0 || len(opts.EphPublicKey) > 0 {
		if len(opts.EphPublicKey) == 0 || len(opts.EncryptedPassword) == 0 {
			return nil, fmt.Errorf("%w: pre-encrypted source requires both EphPublicKey and EncryptedPassword", ErrInvalidOptions)
		}
		if hasPlain {
			// The pass password is unknown to us, so plaintext entries would be stored unencrypted.
			return nil, fmt.Errorf("%w: pre-encrypted options/entries cannot be combined with plaintext source entries", ErrInvalidOptions)
		}
		run.ephPubKey = opts.EphPublicKey
		run.encryptedZipPass = opts.EncryptedPassword
		run.keyID = opts.KeyID
	} else {
		if len(metadata.PublicKeys) == 0 {
			return nil, fmt.Errorf("%w: no public keys in the backup store metadata", ErrKeyNotFound)
		}
		selectedKeyID := opts.KeyID
		if selectedKeyID == "" {
			// Deterministic default: lexicographically first key ID.
			for k := range metadata.PublicKeys {
				if selectedKeyID == "" || k < selectedKeyID {
					selectedKeyID = k
				}
			}
		}
		vmPubKey, exists := metadata.PublicKeys[selectedKeyID]
		if !exists {
			return nil, fmt.Errorf("%w: %q not in store metadata", ErrKeyNotFound, selectedKeyID)
		}

		clearZipPass, err := GenerateZipCryptoPassword()
		if err != nil {
			return nil, fmt.Errorf("failed to generate random ZIP password: %w", err)
		}
		ephPubKey, encryptedZipPass, err := EncryptPassword(clearZipPass, vmPubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt ZIP password: %w", err)
		}
		run.clearZipPass = clearZipPass
		run.ephPubKey = ephPubKey
		run.encryptedZipPass = encryptedZipPass
		run.keyID = selectedKeyID
	}

	// 5. Parallel workers. Every task yields exactly one result; on the first failure the run
	// context is cancelled with that error as cause and all workers are drained before returning.
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 10
	}
	concurrency = min(concurrency, len(entries))

	taskChan := make(chan SourceEntry, len(entries))
	for _, entry := range entries {
		taskChan <- entry
	}
	close(taskChan)
	resultChan := make(chan backupResult, len(entries))

	var wg sync.WaitGroup
	wg.Add(concurrency)
	for range concurrency {
		go func() {
			defer wg.Done()
			for entry := range taskChan {
				resultChan <- run.process(runCtx, cancel, entry)
			}
		}()
	}
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 6. Gather results (drains until every worker has exited).
	newPathToFileKey := make(map[string]string)
	newFilesPool := make(map[string]*tsyncv2.FileRecord)
	dirPaths := make(map[string]bool)

	var firstErr error
	doneCount := 0
	for res := range resultChan {
		if res.err != nil {
			if firstErr == nil {
				firstErr = res.err
				cancel(res.err)
			}
			continue
		}
		if firstErr != nil {
			continue
		}
		if res.isDir {
			dirPaths[strings.TrimSuffix(res.path, "/")] = true
		} else {
			newPathToFileKey[res.path] = res.key
			newFilesPool[res.key] = res.record
		}

		doneCount++
		if opts.OnProgress != nil {
			opts.OnProgress(doneCount, len(entries), res.path)
		}
	}
	if err := runError(ctx, runCtx, firstErr, doneCount, len(entries)); err != nil {
		return nil, err
	}

	// Build the directory tree structure
	rootNode := newTempDirNode()

	// 1. Add directories (including empty ones)
	for dPath := range dirPaths {
		if dPath == "" {
			continue
		}
		curr := rootNode
		for _, part := range strings.Split(dPath, "/") {
			subdir, exists := curr.subdirs[part]
			if !exists {
				subdir = newTempDirNode()
				curr.subdirs[part] = subdir
			}
			curr = subdir
		}
	}

	// 2. Add files
	for p, fileKey := range newPathToFileKey {
		parts := strings.Split(p, "/")
		curr := rootNode
		for i, part := range parts {
			if i == len(parts)-1 {
				if _, exists := curr.subdirs[part]; exists {
					return nil, fmt.Errorf("%w: %q", ErrPathCollision, p)
				}
				rec := newFilesPool[fileKey]
				curr.files[part] = &tsyncv2.FileLeaf{
					Crc32:            rec.Crc32,
					UncompressedSize: rec.UncompressedSize,
				}
			} else {
				if _, exists := curr.files[part]; exists {
					return nil, fmt.Errorf("%w: %q", ErrPathCollision, p)
				}
				subdir, exists := curr.subdirs[part]
				if !exists {
					subdir = newTempDirNode()
					curr.subdirs[part] = subdir
				}
				curr = subdir
			}
		}
	}

	// Recursively build and hash TreeNodes bottom-up
	newTreesMap := make(map[string]*tsyncv2.TreeNode)
	rootHash, err := rootNode.buildAndHash(newTreesMap)
	if err != nil {
		return nil, fmt.Errorf("failed to build and hash directory tree: %w", err)
	}

	// 7. Create the new Version message
	versionID := opts.CustomVersionID
	if versionID == 0 {
		versionID = generateVersionID(metadata.Versions)
	}
	backupTime := time.Now()
	if !opts.CustomBackupTimestamp.IsZero() {
		backupTime = opts.CustomBackupTimestamp
	}

	var precedingID uint64
	if latest != nil {
		precedingID = latest.SnowflakeId
	}

	newVersion := &tsyncv2.Version{
		SnowflakeId:        versionID,
		BackupTimestamp:    timestamppb.New(backupTime),
		RootTreeHash:       rootHash,
		PrecedingVersionId: precedingID,
		Label:              opts.Label,
	}

	// 8. Prepare final metadata
	newMetadata := &tsyncv2.BackupMetadata{
		Versions:      make(map[string]*tsyncv2.Version),
		Trees:         make(map[string]*tsyncv2.TreeNode),
		Files:         make(map[string]*tsyncv2.FileRecord),
		PublicKeys:    metadata.PublicKeys,
		SchemaVersion: 2,
		LastUpdated:   timestamppb.New(time.Now()),
	}

	if !opts.SingleVersionMode {
		// Keep all old versions, trees, and files
		maps.Copy(newMetadata.Versions, metadata.Versions)
		maps.Copy(newMetadata.Trees, metadata.Trees)
		maps.Copy(newMetadata.Files, metadata.Files)
	}
	newMetadata.Versions[strconv.FormatUint(versionID, 10)] = newVersion
	maps.Copy(newMetadata.Trees, newTreesMap)
	maps.Copy(newMetadata.Files, newFilesPool)

	// 9. Commit: a single .tsync write, after every part has been committed.
	pbBytes, err := proto.Marshal(newMetadata)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize backup metadata: %w", err)
	}
	if err := dest.Write(ctx, ".tsync", pbBytes); err != nil {
		return nil, fmt.Errorf("failed to write .tsync file: %w", err)
	}

	// 10. Best-effort cleanup of parts no longer referenced (Single Version Mode), only
	// after the new metadata is durable. Malformed keys are skipped.
	if opts.SingleVersionMode && hasOldMetadata {
		for oldKey := range metadata.Files {
			if _, exists := newMetadata.Files[oldKey]; exists || !isValidFileKey(oldKey) {
				continue
			}
			_ = dest.Delete(ctx, partKeyFor(oldKey))
		}
	}

	return newVersion, nil
}
