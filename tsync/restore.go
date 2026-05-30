package tsync

import (
	"compress/flate"
	"context"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	tsyncv1 "t-sync-sdk-go/gen/go/com/github/abyii/tsync/v1"

	zip "github.com/abyii/zip-xxh3"
	"google.golang.org/protobuf/proto"
)

// RestoreOptions configures the restoration operation.
type RestoreOptions struct {
	ZipWriter            io.Writer // Writer for reconstructed ZIP
	ExtractDir           string    // Local directory to extract to (if set, ZipWriter is ignored)
	PrivateKey           []byte    // VM private key to decrypt ZIP passwords
	NewPassword          string    // Password for the output ZIP (if empty, output ZIP is unencrypted)
	SkipDecryptionErrors bool      // If true, bad keys/parts are skipped instead of failing the run
	FilesToRestore       []string  // Optional list of specific files to restore
	FilterFunc           func(path string) bool // Optional callback filter
	Concurrency          int       // Optional concurrency level for extraction (defaults to 10)
	NoOverwrite          bool      // If true, existing files will be skipped rather than overwritten
}

// ResolveVersionMap resolves a Version's path-to-key mapping by evaluating its full/delta definition.
func ResolveVersionMap(metadata *tsyncv1.BackupMetadata, versionID uint64) (map[string]string, error) {
	vStr := strconv.FormatUint(versionID, 10)
	version, exists := metadata.Versions[vStr]
	if !exists {
		return nil, fmt.Errorf("version %d not found in backup metadata", versionID)
	}

	if version.Kind == tsyncv1.VersionKind_VERSION_KIND_UNSPECIFIED {
		return nil, fmt.Errorf("version %d has unspecified kind", versionID)
	}

	if version.Kind == tsyncv1.VersionKind_VERSION_KIND_FULL {
		// Copy and return the full map
		res := make(map[string]string)
		for k, v := range version.PathToFileKey {
			res[k] = v
		}
		return res, nil
	}

	// DELTA version must resolve against parent (which must be FULL)
	parentStr := strconv.FormatUint(version.ParentId, 10)
	parent, exists := metadata.Versions[parentStr]
	if !exists {
		return nil, fmt.Errorf("parent version %d of delta version %d not found", version.ParentId, versionID)
	}

	if parent.Kind != tsyncv1.VersionKind_VERSION_KIND_FULL {
		return nil, fmt.Errorf("invalid delta parent: parent version %d must be FULL, but got kind %v", version.ParentId, parent.Kind)
	}

	// Start with parent map
	res := make(map[string]string)
	for k, v := range parent.PathToFileKey {
		res[k] = v
	}

	// Apply delta modifications
	for k, v := range version.DeltaChanges {
		res[k] = v
	}

	// Apply delta deletions
	for _, k := range version.DeltaDeleted {
		delete(res, k)
	}

	return res, nil
}

// RunRestore performs the ZIP reconstruction or extraction.
func RunRestore(ctx context.Context, dest Storage, versionID uint64, opts RestoreOptions) error {
	// 1. Read metadata
	metadataBytes, err := dest.Read(ctx, ".tsync")
	if err != nil {
		return fmt.Errorf("failed to read .tsync metadata file: %w", err)
	}

	var metadata tsyncv1.BackupMetadata
	if err := proto.Unmarshal(metadataBytes, &metadata); err != nil {
		return fmt.Errorf("failed to unmarshal .tsync metadata: %w", err)
	}

	// 2. Resolve the version file map
	resolvedMap, err := ResolveVersionMap(&metadata, versionID)
	if err != nil {
		return fmt.Errorf("failed to resolve version map: %w", err)
	}

	// 3. Apply selective restore filters
	filteredMap := make(map[string]string)
	if len(opts.FilesToRestore) > 0 {
		targets := make(map[string]bool)
		for _, f := range opts.FilesToRestore {
			targets[f] = true
		}
		for path, fileKey := range resolvedMap {
			if targets[path] {
				filteredMap[path] = fileKey
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
	}

	// 4. If ExtractDir is set, perform direct streaming extraction (no temp zip file)
	if opts.ExtractDir != "" {
		concurrency := opts.Concurrency
		if concurrency <= 0 {
			concurrency = 10
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
						if err != nil || strings.HasPrefix(rel, "..") {
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

		return nil
	}

	// 5. Reconstruct ZIP archive directly to ZipWriter (no temp zip file)
	if opts.ZipWriter == nil {
		return fmt.Errorf("either ZipWriter or ExtractDir must be set in RestoreOptions")
	}

	zipw := zip.NewWriter(opts.ZipWriter)
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
				continue
			}
			zipw.Close()
			return err
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
