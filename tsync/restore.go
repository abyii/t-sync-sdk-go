package tsync

import (
	"compress/flate"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
		return nil, nil, fmt.Errorf("version %d not found in backup metadata", versionID)
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
		err := fmt.Errorf("tree node %s not found in metadata trees map", treeHash)
		if skipValidationErrors {
			log.Printf("[RESTORE WARNING] Skipping missing tree node %s at path %q: %v", treeHash, prefix, err)
			return nil
		}
		return err
	}

	// 1. Verify tree node hash matches its key
	marshaled, err := proto.MarshalOptions{Deterministic: true}.Marshal(node)
	if err != nil {
		err2 := fmt.Errorf("failed to marshal tree node for hash verification: %w", err)
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
		err2 := fmt.Errorf("tree node hash mismatch: map key is %s, but computed hash is %s", treeHash, computedHash)
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
			err2 := fmt.Errorf("tree node %s is not sorted: %q comes after %q", treeHash, entry.Name, prevName)
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
			return fmt.Errorf("invalid name %q in tree entry: %w", entry.Name, err)
		}

		fullPath := entry.Name
		if prefix != "" {
			fullPath = prefix + "/" + entry.Name
		}

		switch n := entry.Node.(type) {
		case *tsyncv2.TreeEntry_File:
			if n.File == nil {
				err2 := fmt.Errorf("file leaf is nil for entry %s", entry.Name)
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
				err2 := fmt.Errorf("subtree hash is empty for entry %s", entry.Name)
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
			err2 := fmt.Errorf("tree entry %s has no node type set", entry.Name)
			if skipValidationErrors {
				log.Printf("[RESTORE WARNING] Skipping entry %s in tree node %s: %v", entry.Name, treeHash, err2)
				continue
			}
			return err2
		}
	}
	return nil
}

// RunRestore performs the ZIP reconstruction or extraction.
func RunRestore(ctx context.Context, dest Storage, versionID uint64, opts RestoreOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if opts.ExtractDir == "" && opts.ZipWriter == nil {
		return fmt.Errorf("either ZipWriter or ExtractDir must be set in RestoreOptions")
	}
	if len(opts.PrivateKey) > 0 && len(opts.PrivateKey) != 32 {
		return fmt.Errorf("invalid PrivateKey in RestoreOptions: expected 32 bytes (NaCl Curve25519), got %d (check if an RSA/PEM key was passed by mistake)", len(opts.PrivateKey))
	}

	// 1. Read metadata
	metadataBytes, err := dest.Read(ctx, ".tsync")
	if err != nil {
		return fmt.Errorf("failed to read .tsync metadata file: %w", err)
	}

	var metadata tsyncv2.BackupMetadata
	if err := proto.Unmarshal(metadataBytes, &metadata); err != nil {
		return fmt.Errorf("failed to unmarshal .tsync metadata: %w", err)
	}

	if metadata.SchemaVersion != 2 {
		return fmt.Errorf("unsupported schema version %d (expected 2)", metadata.SchemaVersion)
	}

	// 2. Resolve the version file and empty directory map
	resolvedMap, rawEmptyDirs, err := ResolveVersionTree(&metadata, versionID, opts.SkipValidationErrors)
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

	// 4. If ExtractDir is set, perform direct streaming extraction (no temp zip file)
	if opts.ExtractDir != "" {
		concurrency := opts.Concurrency
		if concurrency <= 0 {
			concurrency = 10
		}

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

			if int64(freeSpace) < maxUncompressedSize {
				return fmt.Errorf("insufficient disk space: required at least %d bytes (for the largest file), but only %d bytes available", maxUncompressedSize, freeSpace)
			}

			if int64(freeSpace) < totalUncompressedSize {
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
		}

		taskChan := make(chan restoreTask, len(filteredMap))
		resultChan := make(chan restoreResult, len(filteredMap))

		// Create a cancelable subcontext so we can abort early if a worker fails
		workerCtx, workerCancel := context.WithCancel(ctx)
		defer workerCancel()

		var progressMu sync.Mutex
		var progressDone int32

		var wg sync.WaitGroup
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for t := range taskChan {
					if workerCtx.Err() != nil {
						continue
					}

					err := func() error {
						// Safe path validation first
						outPath := filepath.Join(opts.ExtractDir, filepath.FromSlash(t.path))
						cleanOutPath := filepath.Clean(outPath)
						cleanExtractDir := filepath.Clean(opts.ExtractDir)
						rel, err := filepath.Rel(cleanExtractDir, cleanOutPath)
						if err != nil || rel == "." || relEscapesBase(rel) {
							return fmt.Errorf("illegal file path (directory traversal): %s", t.path)
						}

						record, exists := metadata.Files[t.fileKey]
						if !exists {
							return fmt.Errorf("file record %s not found in metadata files pool", t.fileKey)
						}

						// Check if file exists and handle overwrite logic
						if fi, statErr := os.Stat(cleanOutPath); statErr == nil {
							if opts.NoOverwrite {
								// Skip extraction without error
								return nil
							}
							// Only calculate CRC32 if the size matches to optimize
							if fi.Size() == record.UncompressedSize {
								diskCrc, hashErr := calculateFileCRC32(cleanOutPath)
								if hashErr == nil && diskCrc == record.Crc32 {
									// Skip extraction since file is identical
									return nil
								}
							}
						}

						// Decrypt ZIP password
						decryptedPassword := ""
						if len(record.EncryptedZipPassword) > 0 {
							if len(opts.PrivateKey) == 0 {
								return fmt.Errorf("ZIP part %s is encrypted, but no PrivateKey was provided in options", t.fileKey)
							}
							pass, err := DecryptPassword(record.EncryptedZipPassword, record.EphemeralPublicKey, opts.PrivateKey)
							if err != nil {
								return fmt.Errorf("failed to decrypt ZIP password for %s: %w", t.path, err)
							}
							decryptedPassword = pass
						}

						// Open file part object stream
						partKey := fmt.Sprintf("%s/%s", t.fileKey[0:2], t.fileKey)
						rc, err := dest.OpenReader(workerCtx, partKey)
						if err != nil {
							return fmt.Errorf("failed to open file part %s: %w", partKey, err)
						}
						defer rc.Close()

						// Read local file header to find compression method & flags
						fh, err := zip.ReadLocalFileHeader(rc)
						if err != nil {
							return fmt.Errorf("failed to read local file header for %s: %w", t.path, err)
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
						defer func() {
							if tmpName != "" {
								tmpFile.Close()
								_ = os.Remove(tmpName)
							}
						}()

						var payloadReader io.Reader = io.LimitReader(rc, record.CompressedSize)

						if fh.Flags&1 != 0 {
							payloadReader = zip.NewZipCryptoDecryptReader(payloadReader, []byte(decryptedPassword))
						}

						if fh.Method == zip.Deflate {
							fr := flate.NewReader(payloadReader)
							defer fr.Close()
							payloadReader = fr
						}

						_, err = io.Copy(tmpFile, payloadReader)
						if err != nil {
							return fmt.Errorf("failed to extract file content for %s: %w", t.path, err)
						}

						if err := tmpFile.Close(); err != nil {
							return fmt.Errorf("failed to close temp file for %s: %w", t.path, err)
						}

						if err := os.Chmod(tmpName, fh.Mode()); err != nil {
							return fmt.Errorf("failed to chmod temp file for %s: %w", t.path, err)
						}

						if err := os.Rename(tmpName, cleanOutPath); err != nil {
							return fmt.Errorf("failed to rename temp file to %s: %w", cleanOutPath, err)
						}
						tmpName = "" // Prevent removal in defer

						return nil
					}()

					if err != nil {
						if opts.SkipDecryptionErrors {
							log.Printf("[RESTORE WARNING] Skipping extraction for %q: %v", t.path, err)
						} else {
							workerCancel()
							resultChan <- restoreResult{path: t.path, err: err}
							return
						}
					}

					done := atomic.AddInt32(&progressDone, 1)
					if opts.OnProgress != nil {
						progressMu.Lock()
						opts.OnProgress(int(done), len(filteredMap), t.path)
						progressMu.Unlock()
					}
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

		// Process results
		for res := range resultChan {
			if res.err != nil {
				return res.err
			}
		}

		// Recreate empty directories on disk
		for _, dPath := range emptyDirs {
			cleanDirPath := filepath.Clean(filepath.Join(opts.ExtractDir, filepath.FromSlash(dPath)))
			cleanExtractDir := filepath.Clean(opts.ExtractDir)
			rel, err := filepath.Rel(cleanExtractDir, cleanDirPath)
			if err == nil && !relEscapesBase(rel) {
				_ = os.MkdirAll(cleanDirPath, 0755)
			}
		}

		return nil
	}

	// 5. Reconstruct ZIP archive directly to ZipWriter (no temp zip file)
	if opts.ZipWriter == nil {
		return fmt.Errorf("either ZipWriter or ExtractDir must be set in RestoreOptions")
	}

	zipw := zip.NewWriter(opts.ZipWriter)
	doneCount := 0
	for path, fileKey := range filteredMap {
		err := func() error {
			record, exists := metadata.Files[fileKey]
			if !exists {
				return fmt.Errorf("file record %s not found in metadata files pool", fileKey)
			}

			// Decrypt ZIP password
			decryptedPassword := ""
			if len(record.EncryptedZipPassword) > 0 {
				if len(opts.PrivateKey) == 0 {
					return fmt.Errorf("ZIP part %s is encrypted, but no PrivateKey was provided in options", fileKey)
				}
				pass, err := DecryptPassword(record.EncryptedZipPassword, record.EphemeralPublicKey, opts.PrivateKey)
				if err != nil {
					return fmt.Errorf("failed to decrypt ZIP password for %s: %w", path, err)
				}
				decryptedPassword = pass
			}

			// Open file part object stream
			partKey := fmt.Sprintf("%s/%s", fileKey[0:2], fileKey)
			rc, err := dest.OpenReader(ctx, partKey)
			if err != nil {
				return fmt.Errorf("failed to open file part %s: %w", partKey, err)
			}
			defer rc.Close()

			// Re-key and copy raw ZIP part into output writer
			err = zipw.CopyRawPart(rc, decryptedPassword, opts.NewPassword, func(override *zip.OverridableFileHeader) {
				override.Name = path
			})
			if err != nil {
				return fmt.Errorf("failed to copy and re-key part %s: %w", path, err)
			}

			return nil
		}()

		if err != nil {
			if opts.SkipDecryptionErrors {
				log.Printf("[RESTORE WARNING] Skipping file %q: %v", path, err)
				doneCount++
				if opts.OnProgress != nil {
					opts.OnProgress(doneCount, len(filteredMap), path)
				}
				continue
			}
			zipw.Close()
			return err
		}

		doneCount++
		if opts.OnProgress != nil {
			opts.OnProgress(doneCount, len(filteredMap), path)
		}
	}

	// Recreate empty directory headers in reconstructed ZIP
	for _, dPath := range emptyDirs {
		dirName := dPath
		if !strings.HasSuffix(dirName, "/") {
			dirName += "/"
		}
		wDir, err := zipw.Create(dirName, zip.Store, 0, zip.NoEncryption, "")
		if err == nil && wDir != nil {
			if c, ok := wDir.(io.Closer); ok {
				_ = c.Close()
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
