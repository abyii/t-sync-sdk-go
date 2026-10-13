package tsync

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	tsyncv2 "github.com/abyii/t-sync-sdk-go/v2/gen/go/com/github/abyii/tsync/v2"

	zip "github.com/abyii/zip-xxh3"
	"google.golang.org/protobuf/proto"
)

// RestoreOptions configures the restoration operation.
type RestoreOptions struct {
	ZipWriter            io.Writer              // Writer for reconstructed ZIP
	ExtractDir           string                 // Local directory to extract to (if set, ZipWriter is ignored)
	PrivateKey           []byte                 // VM private key to decrypt ZIP passwords
	NewPassword          string                 // Password for the output ZIP (if empty, output ZIP is unencrypted)
	SkipDecryptionErrors bool                   // If true, bad keys/parts are skipped instead of failing the run
	SkipValidationErrors bool                   // If true, metadata validation errors are logged as warnings and skipped, rather than failing the run
	FilesToRestore       []string               // Optional list of specific files to restore
	FilterFunc           func(path string) bool // Optional callback filter
	Concurrency          int                    // Optional concurrency level for extraction (defaults to 10)
	NoOverwrite          bool                   // If true, existing files will be skipped rather than overwritten

	// OnProgress is an optional callback triggered as each file restoration completes.
	OnProgress func(done, total int, path string)
}

// ResolveVersionTree resolves a Version's file and empty directory mappings by walking the directory tree.
func ResolveVersionTree(metadata *tsyncv2.BackupMetadata, versionID uint64, skipValidationErrors bool) (files map[string]string, emptyDirs []string, err error) {
	vStr := strconv.FormatUint(versionID, 10)
	version, exists := metadata.Versions[vStr]
	if !exists {
		return nil, nil, fmt.Errorf("%w: version %d not found in backup metadata", ErrVersionNotFound, versionID)
	}

	filesResult := make(map[string]string)
	var dirsResult []string
	err = walkTree(version.RootTreeHash, "", metadata.Trees, skipValidationErrors, filesResult, &dirsResult)
	if err != nil {
		return nil, nil, err
	}
	return filesResult, dirsResult, nil
}

func walkTree(treeHash string, prefix string, trees map[string]*tsyncv2.TreeNode, skipValidationErrors bool, filesResult map[string]string, dirsResult *[]string) error {
	node, exists := trees[treeHash]
	if !exists {
		err := fmt.Errorf("%w: tree node %s not found in metadata trees map", ErrCorruptMetadata, treeHash)
		if skipValidationErrors {
			log.Printf("[RESTORE WARNING] Skipping missing tree node %s at path %q: %v", treeHash, prefix, err)
			return nil
		}
		return err
	}

	// 1. Verify tree node hash matches its key
	marshaled, err := proto.MarshalOptions{Deterministic: true}.Marshal(node)
	if err != nil {
		err2 := fmt.Errorf("%w: failed to marshal tree node for hash verification: %w", ErrCorruptMetadata, err)
		if skipValidationErrors {
			log.Printf("[RESTORE WARNING] Skipping unmarshalable tree node %s at path %q: %v", treeHash, prefix, err2)
			return nil
		}
		return err2
	}
	h := sha256.New()
	h.Write(marshaled)
	computedHash := hex.EncodeToString(h.Sum(nil))
	if computedHash != treeHash {
		err2 := fmt.Errorf("%w: tree node hash mismatch: map key is %s, but computed hash is %s", ErrCorruptMetadata, treeHash, computedHash)
		if skipValidationErrors {
			log.Printf("[RESTORE WARNING] Skipping hash-mismatched tree node %s at path %q: %v", treeHash, prefix, err2)
			return nil
		}
		return err2
	}

	// 2. Verify sorted order of entries
	var prevName string
	for i, entry := range node.Entries {
		if i > 0 && entry.Name <= prevName {
			err2 := fmt.Errorf("%w: tree node %s is not sorted: %q comes after %q", ErrCorruptMetadata, treeHash, entry.Name, prevName)
			if skipValidationErrors {
				log.Printf("[RESTORE WARNING] Tree node %s at path %q is not sorted: %v. Continuing...", treeHash, prefix, err2)
				break // stop order check, but continue walking entries anyway
			}
			return err2
		}
		prevName = entry.Name
	}

	// Empty tree node -> empty directory
	if len(node.Entries) == 0 && prefix != "" {
		*dirsResult = append(*dirsResult, prefix)
		return nil
	}

	// 3. Walk entries
	for _, entry := range node.Entries {
		if err := validateName(entry.Name); err != nil {
			if skipValidationErrors {
				log.Printf("[RESTORE WARNING] Skipping entry with invalid name in tree node %s: %v", treeHash, err)
				continue
			}
			return fmt.Errorf("%w: invalid name %q in tree entry: %w", ErrCorruptMetadata, entry.Name, err)
		}

		fullPath := entry.Name
		if prefix != "" {
			fullPath = prefix + "/" + entry.Name
		}

		switch n := entry.Node.(type) {
		case *tsyncv2.TreeEntry_File:
			if n.File == nil {
				err2 := fmt.Errorf("%w: file leaf is nil for entry %s", ErrCorruptMetadata, entry.Name)
				if skipValidationErrors {
					log.Printf("[RESTORE WARNING] Skipping entry %s in tree node %s: %v", entry.Name, treeHash, err2)
					continue
				}
				return err2
			}
			fileKey := fmt.Sprintf("%08x_%d", n.File.Crc32, n.File.UncompressedSize)
			filesResult[fullPath] = fileKey
		case *tsyncv2.TreeEntry_SubtreeHash:
			if n.SubtreeHash == "" {
				err2 := fmt.Errorf("%w: subtree hash is empty for entry %s", ErrCorruptMetadata, entry.Name)
				if skipValidationErrors {
					log.Printf("[RESTORE WARNING] Skipping entry %s in tree node %s: %v", entry.Name, treeHash, err2)
					continue
				}
				return err2
			}
			err := walkTree(n.SubtreeHash, fullPath, trees, skipValidationErrors, filesResult, dirsResult)
			if err != nil {
				return err
			}
		default:
			err2 := fmt.Errorf("%w: tree entry %s has no node type set", ErrCorruptMetadata, entry.Name)
			if skipValidationErrors {
				log.Printf("[RESTORE WARNING] Skipping entry %s in tree node %s: %v", entry.Name, treeHash, err2)
				continue
			}
			return err2
		}
	}
	return nil
}

// ErrUnsupportedMethod is returned when a stored part uses a ZIP compression or encryption
// method restore cannot decode (anything other than Store/Deflate, optionally ZipCrypto).
// RestoreOptions.SkipDecryptionErrors treats it like a decryption/corruption error.
var ErrUnsupportedMethod = errors.New("tsync: unsupported zip compression or encryption method in part")

// isSkippableRestoreError reports whether RestoreOptions.SkipDecryptionErrors may skip err:
// only key/password/part-integrity problems, never cancellation, I/O, disk or rename errors.
func isSkippableRestoreError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return errors.Is(err, ErrDecryptionFailed) ||
		errors.Is(err, ErrCorruptPart) ||
		errors.Is(err, ErrPrivateKeyRequired) ||
		errors.Is(err, ErrUnsupportedMethod)
}

// trackedReader counts bytes read and records the first non-EOF error of the wrapped reader,
// so failures of the underlying storage stream can be told apart from decode failures.
type trackedReader struct {
	r   io.Reader
	n   int64
	err error
}

func (t *trackedReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	t.n += int64(n)
	if err != nil && err != io.EOF && t.err == nil {
		t.err = err
	}
	return n, err
}

// trackedWriter records the first error of the wrapped writer.
type trackedWriter struct {
	w   io.Writer
	err error
}

func (t *trackedWriter) Write(p []byte) (int, error) {
	n, err := t.w.Write(p)
	if err != nil && t.err == nil {
		t.err = err
	}
	return n, err
}

// decryptPartPassword returns the clear ZipCrypto password of record ("" when unencrypted).
func decryptPartPassword(record *tsyncv2.FileRecord, privateKey []byte, fileKey string) (string, error) {
	if len(record.EncryptedZipPassword) == 0 {
		return "", nil
	}
	if len(privateKey) == 0 {
		return "", fmt.Errorf("%w: part %s", ErrPrivateKeyRequired, fileKey)
	}
	pass, err := DecryptPassword(record.EncryptedZipPassword, record.EphemeralPublicKey, privateKey)
	if err != nil {
		if errors.Is(err, ErrDecryptionFailed) {
			return "", fmt.Errorf("failed to decrypt ZIP password for part %s: %w", fileKey, err)
		}
		return "", fmt.Errorf("%w: failed to decrypt ZIP password for part %s: %w", ErrDecryptionFailed, fileKey, err)
	}
	return pass, nil
}

// checkPartHeader rejects parts restore cannot decode correctly.
func checkPartHeader(fh *zip.FileHeader, password, partKey string) error {
	if fh.Method != zip.Store && fh.Method != zip.Deflate {
		return fmt.Errorf("%w: part %s uses method %d", ErrUnsupportedMethod, partKey, fh.Method)
	}
	if fh.Flags&0x40 != 0 {
		return fmt.Errorf("%w: part %s uses strong encryption", ErrUnsupportedMethod, partKey)
	}
	if fh.Flags&0x1 != 0 && password == "" {
		return fmt.Errorf("%w: part %s is encrypted but its file record has no password", ErrDecryptionFailed, partKey)
	}
	return nil
}

// classifyPartError maps a failure while streaming a part to the right error class.
// Storage read and output write failures keep their cause (never skippable); a ZipCrypto
// check-byte mismatch is ErrDecryptionFailed; anything else is a malformed part.
func classifyPartError(err error, src *trackedReader, dst *trackedWriter, partKey string) error {
	switch {
	case dst != nil && dst.err != nil:
		return fmt.Errorf("failed to write restored data for part %s: %w", partKey, err)
	case src.err != nil:
		return fmt.Errorf("failed to read part %s: %w", partKey, err)
	case errors.Is(err, zip.ErrPassword):
		return fmt.Errorf("%w: wrong password for part %s: %w", ErrDecryptionFailed, partKey, err)
	default:
		return fmt.Errorf("%w: failed to decode part %s: %w", ErrCorruptPart, partKey, err)
	}
}

// safeJoin joins a slash-separated archive path onto base, rejecting traversal.
func safeJoin(base, archivePath string) (string, error) {
	cleanBase := filepath.Clean(base)
	cleanOut := filepath.Clean(filepath.Join(base, filepath.FromSlash(archivePath)))
	rel, err := filepath.Rel(cleanBase, cleanOut)
	if err != nil || rel == "." || relEscapesBase(rel) {
		return "", fmt.Errorf("%w: %s", ErrUnsafePath, archivePath)
	}
	return cleanOut, nil
}

// incompleteRunError reports a run that stopped before processing every entry.
func incompleteRunError(cause error, done, total int) error {
	if cause != nil {
		return fmt.Errorf("%w: restored %d of %d entries: %w", ErrIncompleteRun, done, total, cause)
	}
	return fmt.Errorf("%w: restored %d of %d entries", ErrIncompleteRun, done, total)
}

// RunRestore performs the ZIP reconstruction or extraction.
//
// Integrity: every extracted file is verified against its FileRecord (compressed length,
// uncompressed length and CRC32) before it is renamed into place; a mismatch returns
// ErrCorruptPart and leaves nothing at the destination path. Extracted files are fsynced
// before the rename and created with mode 0644 (the temp file starts as 0600 and is
// chmodded explicitly; the process umask is not applied).
//
// SkipDecryptionErrors only skips ErrDecryptionFailed, ErrCorruptPart, ErrPrivateKeyRequired
// and ErrUnsupportedMethod failures. In ZipWriter mode a part is verified (header, method and
// ZipCrypto password check byte) before anything is written to the output; a failure after
// writing to the output has started is always returned, and the output ZIP is then left
// unfinalized (no central directory) so it cannot be mistaken for a complete archive.
//
// A cancelled context or any unprocessed entry returns an error wrapping ErrIncompleteRun.
func RunRestore(ctx context.Context, dest Storage, versionID uint64, opts RestoreOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if opts.ExtractDir == "" && opts.ZipWriter == nil {
		return fmt.Errorf("%w: either ZipWriter or ExtractDir must be set in RestoreOptions", ErrInvalidOptions)
	}
	if len(opts.PrivateKey) > 0 && len(opts.PrivateKey) != 32 {
		return fmt.Errorf("%w: invalid PrivateKey in RestoreOptions: expected 32 bytes (NaCl Curve25519), got %d (check if an RSA/PEM key was passed by mistake)", ErrInvalidOptions, len(opts.PrivateKey))
	}

	// 1. Read metadata
	metadata, err := loadMetadata(ctx, dest)
	if err != nil {
		return err
	}

	// 2. Resolve the version file and empty directory map
	resolvedMap, rawEmptyDirs, err := ResolveVersionTree(metadata, versionID, opts.SkipValidationErrors)
	if err != nil {
		return fmt.Errorf("failed to resolve version map: %w", err)
	}

	// 3. Apply selective restore filters
	filteredMap := make(map[string]string)
	var emptyDirs []string
	if len(opts.FilesToRestore) > 0 {
		targets := make(map[string]bool)
		for _, f := range opts.FilesToRestore {
			targets[f] = true
			targets[strings.TrimSuffix(f, "/")] = true
		}
		for path, fileKey := range resolvedMap {
			if targets[path] {
				filteredMap[path] = fileKey
			}
		}
		for _, dPath := range rawEmptyDirs {
			if targets[dPath] || targets[dPath+"/"] {
				emptyDirs = append(emptyDirs, dPath)
			}
		}
	} else {
		for path, fileKey := range resolvedMap {
			if opts.FilterFunc != nil {
				if opts.FilterFunc(path) {
					filteredMap[path] = fileKey
				}
			} else {
				filteredMap[path] = fileKey
			}
		}
		for _, dPath := range rawEmptyDirs {
			if opts.FilterFunc != nil {
				if opts.FilterFunc(dPath) || opts.FilterFunc(dPath+"/") {
					emptyDirs = append(emptyDirs, dPath)
				}
			} else {
				emptyDirs = append(emptyDirs, dPath)
			}
		}
	}

	if opts.ExtractDir != "" {
		return restoreToDir(ctx, dest, metadata, filteredMap, emptyDirs, opts)
	}
	return restoreToZip(ctx, dest, metadata, filteredMap, emptyDirs, opts)
}

// restoreToDir streams every selected part directly into opts.ExtractDir (no temp zip file).
func restoreToDir(ctx context.Context, dest Storage, metadata *tsyncv2.BackupMetadata, filteredMap map[string]string, emptyDirs []string, opts RestoreOptions) error {
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 10
	}
	total := len(filteredMap)

	// Perform disk space pre-check
	ancestor := getExistingAncestor(opts.ExtractDir)
	freeSpace, err := getFreeSpace(ancestor)
	if err == nil {
		var totalUncompressedSize int64
		var maxUncompressedSize int64
		for _, fileKey := range filteredMap {
			if rec, ok := metadata.Files[fileKey]; ok {
				totalUncompressedSize += rec.UncompressedSize
				if rec.UncompressedSize > maxUncompressedSize {
					maxUncompressedSize = rec.UncompressedSize
				}
			}
		}

		if freeSpace < uint64(maxUncompressedSize) {
			return fmt.Errorf("%w: required at least %d bytes (for the largest file), but only %d bytes available at %s", ErrInsufficientDiskSpace, maxUncompressedSize, freeSpace, ancestor)
		}

		if freeSpace < uint64(totalUncompressedSize) {
			// Switch to sequential mode (concurrency = 1) to conserve space
			concurrency = 1
			log.Printf("[RESTORE] Insufficient space for parallel extraction (%d bytes available, %d bytes total required). Switching to sequential mode.", freeSpace, totalUncompressedSize)
		}
	}

	type restoreTask struct {
		path    string
		fileKey string
	}

	type restoreResult struct {
		path string
		err  error
		// cancelled marks results that only reflect workerCtx cancellation, not a root cause.
		cancelled bool
	}

	// Both channels hold every task, so neither feeding nor reporting can block.
	taskChan := make(chan restoreTask, total)
	resultChan := make(chan restoreResult, total)

	// Create a cancelable subcontext so we can abort early if a worker fails
	workerCtx, workerCancel := context.WithCancel(ctx)
	defer workerCancel()

	var progressMu sync.Mutex
	var progressDone int32

	// Parent directories of renamed files, fsynced once at the end so the renames are durable.
	var dirsMu sync.Mutex
	touchedDirs := make(map[string]struct{})

	extractOne := func(t restoreTask) error {
		cleanOutPath, err := safeJoin(opts.ExtractDir, t.path)
		if err != nil {
			return err
		}

		record, exists := metadata.Files[t.fileKey]
		if !exists {
			return fmt.Errorf("%w: file record %s for %q not found in metadata files pool", ErrCorruptMetadata, t.fileKey, t.path)
		}

		// Check if file exists and handle overwrite logic
		if fi, statErr := os.Stat(cleanOutPath); statErr == nil {
			if opts.NoOverwrite {
				// Skip extraction without error
				return nil
			}
			// Only calculate CRC32 if the size matches to optimize
			if fi.Mode().IsRegular() && fi.Size() == record.UncompressedSize {
				diskCrc, hashErr := calculateFileCRC32(cleanOutPath)
				if hashErr == nil && diskCrc == record.Crc32 {
					// Skip extraction since file is identical
					return nil
				}
			}
		}

		password, err := decryptPartPassword(record, opts.PrivateKey, t.fileKey)
		if err != nil {
			return fmt.Errorf("%s: %w", t.path, err)
		}

		// Open file part object stream
		partKey := fmt.Sprintf("%s/%s", t.fileKey[0:2], t.fileKey)
		rc, err := dest.OpenReader(workerCtx, partKey)
		if err != nil {
			return fmt.Errorf("failed to open file part %s: %w", partKey, err)
		}
		defer rc.Close()
		src := &trackedReader{r: rc}

		// Read local file header to find compression method & flags
		fh, err := zip.ReadLocalFileHeader(src)
		if err != nil {
			return fmt.Errorf("local file header of %s: %w", t.path, classifyPartError(err, src, nil, partKey))
		}
		if err := checkPartHeader(fh, password, partKey); err != nil {
			return fmt.Errorf("%s: %w", t.path, err)
		}

		tmpDir := filepath.Dir(cleanOutPath)
		if err := os.MkdirAll(tmpDir, 0755); err != nil {
			return fmt.Errorf("failed to create parent directory for %s: %w", cleanOutPath, err)
		}

		tmpFile, err := os.CreateTemp(tmpDir, ".tsync-restore-tmp-*")
		if err != nil {
			return fmt.Errorf("failed to create temp file: %w", err)
		}
		tmpName := tmpFile.Name()
		tmpClosed := false
		defer func() {
			if tmpName != "" {
				if !tmpClosed {
					tmpFile.Close()
				}
				_ = os.Remove(tmpName)
			}
		}()

		comp := &trackedReader{r: io.LimitReader(src, record.CompressedSize)}
		var payloadReader io.Reader = comp
		if fh.Flags&0x1 != 0 {
			payloadReader = zip.NewVerifiedZipCryptoDecryptReader(payloadReader, []byte(password), fh)
		}
		if fh.Method == zip.Deflate {
			fr := flate.NewReader(payloadReader)
			defer fr.Close()
			payloadReader = fr
		}

		crc := crc32.NewIEEE()
		dst := &trackedWriter{w: io.MultiWriter(tmpFile, crc)}
		written, err := io.Copy(dst, payloadReader)
		if err == nil {
			// Consume any compressed bytes the decoder did not need so the length check
			// below sees the whole stored payload (and detects truncation).
			_, err = io.Copy(io.Discard, comp)
		}
		if err != nil {
			return fmt.Errorf("failed to extract %s: %w", t.path, classifyPartError(err, src, dst, partKey))
		}
		if comp.n != record.CompressedSize {
			return fmt.Errorf("%w: part %s for %s has %d compressed bytes, expected %d", ErrCorruptPart, partKey, t.path, comp.n, record.CompressedSize)
		}
		if written != record.UncompressedSize || crc.Sum32() != record.Crc32 {
			return fmt.Errorf("%w: part %s for %s decoded to %d bytes with CRC32 %08x, expected %d bytes with CRC32 %08x", ErrCorruptPart, partKey, t.path, written, crc.Sum32(), record.UncompressedSize, record.Crc32)
		}

		if err := tmpFile.Chmod(0o644); err != nil {
			return fmt.Errorf("failed to chmod temp file for %s: %w", t.path, err)
		}
		if err := tmpFile.Sync(); err != nil {
			return fmt.Errorf("failed to sync temp file for %s: %w", t.path, err)
		}
		tmpClosed = true
		if err := tmpFile.Close(); err != nil {
			return fmt.Errorf("failed to close temp file for %s: %w", t.path, err)
		}

		if err := os.Rename(tmpName, cleanOutPath); err != nil {
			return fmt.Errorf("failed to rename temp file to %s: %w", cleanOutPath, err)
		}
		tmpName = "" // Prevent removal in defer

		dirsMu.Lock()
		touchedDirs[tmpDir] = struct{}{}
		dirsMu.Unlock()
		return nil
	}

	var wg sync.WaitGroup
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Every task produces exactly one result.
			for t := range taskChan {
				if err := workerCtx.Err(); err != nil {
					resultChan <- restoreResult{path: t.path, err: err, cancelled: true}
					continue
				}

				err := extractOne(t)
				if err != nil && opts.SkipDecryptionErrors && isSkippableRestoreError(err) {
					log.Printf("[RESTORE WARNING] Skipping extraction for %q: %v", t.path, err)
					err = nil
				}
				if err != nil {
					cancelled := workerCtx.Err() != nil && errors.Is(err, context.Canceled)
					workerCancel()
					resultChan <- restoreResult{path: t.path, err: err, cancelled: cancelled}
					continue
				}

				done := atomic.AddInt32(&progressDone, 1)
				if opts.OnProgress != nil {
					progressMu.Lock()
					opts.OnProgress(int(done), total, t.path)
					progressMu.Unlock()
				}
				resultChan <- restoreResult{path: t.path}
			}
		}()
	}

	// Feed tasks
	for path, fileKey := range filteredMap {
		taskChan <- restoreTask{path: path, fileKey: fileKey}
	}
	close(taskChan)

	// Wait for workers in a separate goroutine and close results channel
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Drain every result so no worker is still writing when we return.
	var firstErr error
	done := 0
	for res := range resultChan {
		if res.err == nil {
			done++
			continue
		}
		if firstErr == nil && !res.cancelled {
			firstErr = res.err
		}
	}

	if err := ctx.Err(); err != nil {
		return incompleteRunError(err, done, total)
	}
	if firstErr != nil {
		return firstErr
	}
	if done != total {
		return incompleteRunError(nil, done, total)
	}

	// Recreate empty directories on disk
	for _, dPath := range emptyDirs {
		cleanDirPath, err := safeJoin(opts.ExtractDir, dPath)
		if err == nil {
			err = os.MkdirAll(cleanDirPath, 0755)
		}
		if err != nil {
			if opts.SkipValidationErrors {
				log.Printf("[RESTORE WARNING] Skipping empty directory %q: %v", dPath, err)
				continue
			}
			return fmt.Errorf("failed to create empty directory %q: %w", dPath, err)
		}
	}

	for dir := range touchedDirs {
		if err := syncDir(dir); err != nil {
			return fmt.Errorf("failed to sync directory %s: %w", dir, err)
		}
	}

	return nil
}

// restoreToZip reconstructs the ZIP archive directly into opts.ZipWriter (no temp zip file).
func restoreToZip(ctx context.Context, dest Storage, metadata *tsyncv2.BackupMetadata, filteredMap map[string]string, emptyDirs []string, opts RestoreOptions) error {
	total := len(filteredMap)
	out := &trackedWriter{w: opts.ZipWriter}
	zipw := zip.NewWriter(out)

	// copyOne returns started=true once anything may have been written to the output ZIP;
	// such failures are never skippable because the entry would be left corrupt.
	copyOne := func(path, fileKey string) (started bool, err error) {
		record, exists := metadata.Files[fileKey]
		if !exists {
			return false, fmt.Errorf("%w: file record %s for %q not found in metadata files pool", ErrCorruptMetadata, fileKey, path)
		}

		password, err := decryptPartPassword(record, opts.PrivateKey, fileKey)
		if err != nil {
			return false, fmt.Errorf("%s: %w", path, err)
		}

		// Open file part object stream
		partKey := fmt.Sprintf("%s/%s", fileKey[0:2], fileKey)
		rc, err := dest.OpenReader(ctx, partKey)
		if err != nil {
			return false, fmt.Errorf("failed to open file part %s: %w", partKey, err)
		}
		defer rc.Close()
		src := &trackedReader{r: rc}

		// Pre-read and validate the local header (and ZipCrypto header) before writing anything.
		var header bytes.Buffer
		fh, err := zip.ReadLocalFileHeader(io.TeeReader(src, &header))
		if err != nil {
			return false, fmt.Errorf("local file header of %s: %w", path, classifyPartError(err, src, nil, partKey))
		}
		headerLen := int64(header.Len())
		if err := checkPartHeader(fh, password, partKey); err != nil {
			return false, fmt.Errorf("%s: %w", path, err)
		}
		prefix := io.Reader(&header)
		if fh.Flags&0x1 != 0 {
			encHeader := make([]byte, 12)
			if _, err := io.ReadFull(src, encHeader); err != nil {
				return false, fmt.Errorf("encryption header of %s: %w", path, classifyPartError(err, src, nil, partKey))
			}
			probe := zip.NewVerifiedZipCryptoDecryptReader(bytes.NewReader(encHeader), []byte(password), fh)
			if _, err := probe.Read(make([]byte, 1)); err != nil && err != io.EOF {
				return false, fmt.Errorf("encryption header of %s: %w", path, classifyPartError(err, src, nil, partKey))
			}
			prefix = io.MultiReader(&header, bytes.NewReader(encHeader))
		}

		// Re-key and copy raw ZIP part into output writer
		err = zipw.CopyRawPart(io.MultiReader(prefix, src), password, opts.NewPassword, func(override *zip.OverridableFileHeader) {
			override.Name = path
		})
		if err != nil {
			return true, fmt.Errorf("failed to copy and re-key part %s: %w", path, classifyPartError(err, src, out, partKey))
		}

		// CopyRawPart consumed the whole part object: header + payload (+ data descriptor).
		trailing := src.n - headerLen - record.CompressedSize
		validTrailing := trailing == 0
		if fh.Flags&0x8 != 0 {
			validTrailing = trailing == 12 || trailing == 16 || trailing == 20 || trailing == 24
		}
		if !validTrailing {
			return true, fmt.Errorf("%w: part %s for %s has %d payload bytes, expected %d", ErrCorruptPart, partKey, path, src.n-headerLen, record.CompressedSize)
		}
		return true, nil
	}

	doneCount := 0
	report := func(path string) {
		doneCount++
		if opts.OnProgress != nil {
			opts.OnProgress(doneCount, total, path)
		}
	}

	// On any returned error the ZIP is intentionally not closed: without a central directory
	// a partial output cannot be mistaken for a complete archive.
	for path, fileKey := range filteredMap {
		if err := ctx.Err(); err != nil {
			return incompleteRunError(err, doneCount, total)
		}
		started, err := copyOne(path, fileKey)
		if err != nil {
			if !started && opts.SkipDecryptionErrors && isSkippableRestoreError(err) {
				log.Printf("[RESTORE WARNING] Skipping file %q: %v", path, err)
				report(path)
				continue
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				return incompleteRunError(fmt.Errorf("%w (while restoring %q: %w)", ctxErr, path, err), doneCount, total)
			}
			return err
		}
		report(path)
	}
	if err := ctx.Err(); err != nil {
		return incompleteRunError(err, doneCount, total)
	}

	// Recreate empty directory headers in reconstructed ZIP
	for _, dPath := range emptyDirs {
		dirName := dPath
		if !strings.HasSuffix(dirName, "/") {
			dirName += "/"
		}
		wDir, err := zipw.Create(dirName, zip.Store, 0, zip.NoEncryption, "")
		if err != nil {
			return fmt.Errorf("failed to add empty directory %q to reconstructed zip: %w", dPath, err)
		}
		if c, ok := wDir.(io.Closer); ok {
			if err := c.Close(); err != nil {
				return fmt.Errorf("failed to add empty directory %q to reconstructed zip: %w", dPath, err)
			}
		}
	}

	if err := zipw.Close(); err != nil {
		return fmt.Errorf("failed to close reconstructed zip writer: %w", err)
	}

	return nil
}

func calculateFileCRC32(filePath string) (uint32, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	h := crc32.NewIEEE()
	if _, err := io.Copy(h, f); err != nil {
		return 0, err
	}
	return h.Sum32(), nil
}

// relEscapesBase reports whether a filepath.Rel result points outside its base.
// Names such as "..a" or "..cfg" are ordinary children, not traversal.
func relEscapesBase(rel string) bool {
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func getExistingAncestor(path string) string {
	for {
		if _, err := os.Stat(path); err == nil {
			return path
		}
		parent := filepath.Dir(path)
		if parent == path { // reached root
			return path
		}
		path = parent
	}
}

var getFreeSpace = osGetFreeSpace
