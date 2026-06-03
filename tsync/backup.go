package tsync

import (
	"context"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"path"
	"strconv"
	"sync"
	"time"

	tsyncv1 "github.com/abyii/t-sync-sdk-go/gen/go/com/github/abyii/tsync/v1"

	zip "github.com/abyii/zip-xxh3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// BackupOptions configures the backup operation.
type BackupOptions struct {
	Label             string
	SingleVersionMode bool
	FilterFunc        func(path string) (bool, error)
	Concurrency       int

	// Cryptographic settings for unencrypted source:
	KeyID      string            // Public key ID to use. If empty, the first key in public_keys is used.
	PublicKeys map[string][]byte // Maps key ID -> public key. Required if creating a new store.

	// Cryptographic settings for pre-encrypted source:
	EphPublicKey      []byte
	EncryptedPassword []byte

	// OnProgress is an optional callback triggered as each file backup completes.
	OnProgress func(done, total int, path string)

	// CompressionLevel specifies the compression level to use (from -1 to 9).
	// If nil or -1, it defaults to Deflate with level 5.
	// If 0, it uses Store (no compression).
	// If 1 to 9, it uses Deflate with the specified level.
	CompressionLevel *int
}

type countingWriter struct {
	w io.Writer
	h hash.Hash32
	n int64
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	if n > 0 {
		cw.h.Write(p[:n])
		cw.n += int64(n)
	}
	return n, err
}

type trackingWriter struct {
	w     io.Writer
	count int64
}

func (tw *trackingWriter) Write(p []byte) (int, error) {
	n, err := tw.w.Write(p)
	tw.count += int64(n)
	return n, err
}

func RunBackup(ctx context.Context, src Source, dest Storage, opts BackupOptions) (*tsyncv1.Version, error) {
	// Resolve compression method and level
	compMethod := zip.Deflate
	compLevel := 5
	if opts.CompressionLevel != nil {
		lvl := *opts.CompressionLevel
		if lvl == -1 {
			compLevel = 5
		} else if lvl == 0 {
			compMethod = zip.Store
			compLevel = 0
		} else if lvl >= 1 && lvl <= 9 {
			compLevel = lvl
		} else {
			return nil, fmt.Errorf("invalid compression level: %d (must be between -1 and 9)", lvl)
		}
	}

	// Clean up source if it implements io.Closer
	if closer, ok := src.(io.Closer); ok {
		defer closer.Close()
	}

	// 1. List files from source
	allEntries, err := src.ListEntries(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list source entries: %w", err)
	}

	// Apply filter
	var entries []SourceEntry
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
		entries = append(entries, entry)
	}

	// 2. Load existing metadata or initialize new
	var metadata tsyncv1.BackupMetadata
	hasOldMetadata := false

	tsyncBytes, err := dest.Read(ctx, ".tsync")
	if err == nil {
		if err = proto.Unmarshal(tsyncBytes, &metadata); err == nil {
			hasOldMetadata = true
		}
	}

	if !hasOldMetadata {
		if len(opts.PublicKeys) == 0 {
			return nil, fmt.Errorf("creating a new backup store requires providing at least one public key in options")
		}
		metadata = tsyncv1.BackupMetadata{
			Versions:      make(map[string]*tsyncv1.Version),
			Files:         make(map[string]*tsyncv1.FileRecord),
			PublicKeys:    opts.PublicKeys,
			SchemaVersion: 1,
		}
	} else {
		// Merge any new public keys into the existing ones
		if metadata.PublicKeys == nil {
			metadata.PublicKeys = make(map[string][]byte)
		}
		for k, v := range opts.PublicKeys {
			metadata.PublicKeys[k] = v
		}
	}

	// 3. Manage cryptographic keys and ZIP passwords for this pass
	var ephPubKey []byte
	var encryptedZipPass []byte
	var clearZipPass string
	var selectedKeyID string

	// Determine if the source is already encrypted
	isSrcEncrypted := false
	if len(entries) > 0 && entries[0].IsEncryptedRaw {
		isSrcEncrypted = true
	}

	if isSrcEncrypted {
		if len(opts.EphPublicKey) == 0 || len(opts.EncryptedPassword) == 0 {
			return nil, fmt.Errorf("pre-encrypted source requires providing EphPublicKey and EncryptedPassword in options")
		}
		ephPubKey = opts.EphPublicKey
		encryptedZipPass = opts.EncryptedPassword
		// Retrieve key ID if provided, otherwise check metadata
		selectedKeyID = opts.KeyID
	} else {
		// Unencrypted source: generate throw-away password and encrypt it ONCE for this pass
		if len(metadata.PublicKeys) == 0 {
			return nil, fmt.Errorf("no public keys available in the backup store metadata for encryption")
		}

		// Select main public key
		if opts.KeyID != "" {
			selectedKeyID = opts.KeyID
		} else {
			// Choose first key in map
			for k := range metadata.PublicKeys {
				selectedKeyID = k
				break
			}
		}

		vmPubKey, exists := metadata.PublicKeys[selectedKeyID]
		if !exists {
			return nil, fmt.Errorf("selected public key ID %q not found in metadata", selectedKeyID)
		}

		// Generate random password
		clearZipPass, err = GenerateZipCryptoPassword()
		if err != nil {
			return nil, fmt.Errorf("failed to generate random ZIP password: %w", err)
		}

		// Encrypt password
		ephPubKey, encryptedZipPass, err = EncryptPassword(clearZipPass, vmPubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt ZIP password: %w", err)
		}
	}

	// 4. Parallel workers to process file parts
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 10
	}

	type task struct {
		entry SourceEntry
	}

	type result struct {
		path   string
		key    string
		record *tsyncv1.FileRecord
		err    error
	}

	taskChan := make(chan task, len(entries))
	resultChan := make(chan result, len(entries))

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range taskChan {
				if ctx.Err() != nil {
					continue
				}
				entry := t.entry

				// A. Check if the file part already exists in the metadata files pool
				var fileKey string
				var record *tsyncv1.FileRecord

				if entry.CRC32 != 0 || entry.Size == 0 {
					fileKey = fmt.Sprintf("%08x_%d", entry.CRC32, entry.Size)
				} else {
					// We need to read the file to compute the CRC32 and uncompressed size
					// Let's compute the CRC32 and size by reading it first.
					rc, err := entry.Open()
					if err != nil {
						cancel()
						resultChan <- result{err: fmt.Errorf("failed to open source file %s: %w", entry.Path, err)}
						continue
					}
					h := crc32.NewIEEE()
					size, err := io.Copy(h, rc)
					rc.Close()
					if err != nil {
						cancel()
						resultChan <- result{err: fmt.Errorf("failed to read source file %s: %w", entry.Path, err)}
						continue
					}
					fileKey = fmt.Sprintf("%08x_%d", h.Sum32(), size)
				}

				// Look up in existing metadata files
				if existingRec, exists := metadata.Files[fileKey]; exists {
					record = existingRec
				}

				if record == nil {
					// B. Create the file part object
					partKey := fmt.Sprintf("%s/%s", fileKey[0:2], fileKey)

					var compSize int64
					var uncompSize int64
					var finalCrc32 uint32

					if entry.IsEncryptedRaw {
						// Stream raw part bytes directly
						rc, err := entry.OpenRaw()
						if err != nil {
							cancel()
							resultChan <- result{err: fmt.Errorf("failed to open raw part for %s: %w", entry.Path, err)}
							continue
						}

						partWriter, err := dest.OpenWriter(ctx, partKey)
						if err != nil {
							rc.Close()
							cancel()
							resultChan <- result{err: fmt.Errorf("failed to open writer for %s: %w", partKey, err)}
							continue
						}

						_, err = io.Copy(partWriter, rc)
						rc.Close()
						closeErr := partWriter.Close()

						if err != nil {
							cancel()
							resultChan <- result{err: fmt.Errorf("failed to read raw part for %s: %w", entry.Path, err)}
							continue
						}
						if closeErr != nil {
							cancel()
							resultChan <- result{err: fmt.Errorf("failed to close destination part %s: %w", partKey, closeErr)}
							continue
						}

						uncompSize = entry.Size
						compSize = entry.CompressedSize
						finalCrc32 = entry.CRC32
					} else if entry.OpenRawCompressed != nil {
						// Stream raw compressed bytes from source and encrypt on-the-fly
						rc, err := entry.OpenRawCompressed()
						if err != nil {
							cancel()
							resultChan <- result{err: fmt.Errorf("failed to open raw compressed stream for %s: %w", entry.Path, err)}
							continue
						}

						partWriter, err := dest.OpenWriter(ctx, partKey)
						if err != nil {
							rc.Close()
							cancel()
							resultChan <- result{err: fmt.Errorf("failed to open writer for %s: %w", partKey, err)}
							continue
						}

						// Create FileHeader for CreateRawFileParts
						fh := &zip.FileHeader{
							Name:               path.Base(entry.Path),
							Method:             entry.CompressionMethod,
							CRC32:              entry.CRC32,
							CompressedSize64:   uint64(entry.CompressedSize),
							UncompressedSize64: uint64(entry.Size),
						}
						fh.SetModTime(entry.LastModified)
						if clearZipPass != "" {
							fh.SetEncryptionMethod(zip.StandardEncryption)
							fh.SetPassword(clearZipPass)
						}

						zipw := zip.NewWriter()
						wPart, err := zipw.CreateRawFileParts(fh, 0, partWriter)
						if err != nil {
							rc.Close()
							partWriter.Close()
							cancel()
							resultChan <- result{err: fmt.Errorf("failed to create raw zip file part for %s: %w", entry.Path, err)}
							continue
						}

						_, copyErr := io.Copy(wPart, rc)
						rc.Close()

						wPartCloseErr := wPart.Close()
						partWriterCloseErr := partWriter.Close()

						if copyErr != nil {
							cancel()
							resultChan <- result{err: fmt.Errorf("failed to copy raw compressed bytes for %s: %w", entry.Path, copyErr)}
							continue
						}
						if wPartCloseErr != nil {
							cancel()
							resultChan <- result{err: fmt.Errorf("failed to close raw part writer for %s: %w", entry.Path, wPartCloseErr)}
							continue
						}
						if partWriterCloseErr != nil {
							cancel()
							resultChan <- result{err: fmt.Errorf("failed to close storage writer for %s: %w", partKey, partWriterCloseErr)}
							continue
						}

						uncompSize = entry.Size
						compSize = entry.CompressedSize
						finalCrc32 = entry.CRC32
					} else {
						// Stream compressed/encrypted part directly to destination storage
						partWriter, err := dest.OpenWriter(ctx, partKey)
						if err != nil {
							cancel()
							resultChan <- result{err: fmt.Errorf("failed to open writer for %s: %w", partKey, err)}
							continue
						}

						tw := &trackingWriter{w: partWriter}
						zipw := zip.NewWriter()

						encMethod := zip.NoEncryption
						if clearZipPass != "" {
							encMethod = zip.StandardEncryption
						}

						wPart, err := zipw.CreateFilePartSimple(path.Base(entry.Path), compMethod, compLevel, encMethod, clearZipPass, 0, tw)
						if err != nil {
							zipw.Close()
							partWriter.Close()
							cancel()
							resultChan <- result{err: fmt.Errorf("failed to create zip file part for %s: %w", entry.Path, err)}
							continue
						}

						// Reset count to exclude the Local File Header (LFH) bytes that zipw just wrote to tw
						tw.count = 0

						// Write content and measure sizes
						cw := &countingWriter{
							w: wPart,
							h: crc32.NewIEEE(),
						}

						rc, err := entry.Open()
						if err != nil {
							wPart.Close()
							zipw.Close()
							partWriter.Close()
							cancel()
							resultChan <- result{err: fmt.Errorf("failed to open source file %s: %w", entry.Path, err)}
							continue
						}

						_, copyErr := io.Copy(cw, rc)
						rc.Close()

						wPartCloseErr := wPart.Close()
						zipwCloseErr := zipw.Close()
						partWriterCloseErr := partWriter.Close()

						if copyErr != nil {
							cancel()
							resultChan <- result{err: fmt.Errorf("failed to compress/encrypt file %s: %w", entry.Path, copyErr)}
							continue
						}
						if wPartCloseErr != nil {
							cancel()
							resultChan <- result{err: fmt.Errorf("failed to close zip part writer for %s: %w", entry.Path, wPartCloseErr)}
							continue
						}
						if zipwCloseErr != nil {
							cancel()
							resultChan <- result{err: fmt.Errorf("failed to close zip writer for %s: %w", entry.Path, zipwCloseErr)}
							continue
						}
						if partWriterCloseErr != nil {
							cancel()
							resultChan <- result{err: fmt.Errorf("failed to close storage writer for %s: %w", partKey, partWriterCloseErr)}
							continue
						}

						uncompSize = cw.n
						finalCrc32 = cw.h.Sum32()

						// Calculate compSize by subtracting Data Descriptor size from total bytes written after LFH
						ddSize := int64(16)
						if uncompSize >= 0xffffffff {
							ddSize = 24
						}
						compSize = tw.count - ddSize
						if compSize < 0 {
							compSize = 0
						}
					}

					record = &tsyncv1.FileRecord{
						EphemeralPublicKey:   ephPubKey,
						EncryptedZipPassword: encryptedZipPass,
						Crc32:                finalCrc32,
						CompressedSize:       compSize,
						UncompressedSize:     uncompSize,
						LastModified:         timestamppb.New(entry.LastModified),
					}
					if selectedKeyID != "" {
						record.KeyId = &selectedKeyID
					}
				}

				resultChan <- result{
					path:   entry.Path,
					key:    fileKey,
					record: record,
				}
			}
		}()
	}

	// Feed tasks
	for _, entry := range entries {
		taskChan <- task{entry: entry}
	}
	close(taskChan)

	// Wait for workers in a separate goroutine and close results
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 5. Gather results
	newPathToFileKey := make(map[string]string)
	newFilesPool := make(map[string]*tsyncv1.FileRecord)

	doneCount := 0
	for res := range resultChan {
		if res.err != nil {
			return nil, res.err
		}
		newPathToFileKey[res.path] = res.key
		newFilesPool[res.key] = res.record

		doneCount++
		if opts.OnProgress != nil {
			opts.OnProgress(doneCount, len(entries), res.path)
		}
	}

	// 6. Resolve version kind (FULL vs DELTA)
	var kind tsyncv1.VersionKind = tsyncv1.VersionKind_VERSION_KIND_FULL
	var parentID uint64 = 0
	var deltaChanges map[string]string
	var deltaDeleted []string

	if opts.SingleVersionMode {
		kind = tsyncv1.VersionKind_VERSION_KIND_FULL
	} else if hasOldMetadata && len(metadata.Versions) > 0 {
		// Find parent version (the latest version in the store)
		var parentV *tsyncv1.Version
		for _, v := range metadata.Versions {
			if parentV == nil || v.BackupTimestamp.AsTime().After(parentV.BackupTimestamp.AsTime()) {
				parentV = v
			}
		}

		// DELTA is only allowed if parent is FULL (no delta chains)
		if parentV != nil && parentV.Kind == tsyncv1.VersionKind_VERSION_KIND_FULL {
			parentID = parentV.SnowflakeId
			deltaChanges = make(map[string]string)
			deltaDeleted = make([]string, 0)

			// Calculate changes relative to parent
			for path, fileKey := range newPathToFileKey {
				parentKey, exists := parentV.PathToFileKey[path]
				if !exists || parentKey != fileKey {
					deltaChanges[path] = fileKey
				}
			}

			// Calculate deletions relative to parent
			for path := range parentV.PathToFileKey {
				if _, exists := newPathToFileKey[path]; !exists {
					deltaDeleted = append(deltaDeleted, path)
				}
			}

			deltaCost := len(deltaChanges) + len(deltaDeleted)
			fullCost := len(newPathToFileKey)

			if deltaCost < fullCost {
				kind = tsyncv1.VersionKind_VERSION_KIND_DELTA
			}
		}
	}

	// 7. Create the new Version message
	versionID := hashStringToUint64(strconv.FormatInt(time.Now().UnixNano(), 10))
	newVersion := &tsyncv1.Version{
		SnowflakeId:     versionID,
		BackupTimestamp: timestamppb.New(time.Now()),
		Kind:            kind,
		Label:           opts.Label,
	}

	if kind == tsyncv1.VersionKind_VERSION_KIND_FULL {
		newVersion.PathToFileKey = newPathToFileKey
	} else {
		newVersion.ParentId = parentID
		newVersion.DeltaChanges = deltaChanges
		newVersion.DeltaDeleted = deltaDeleted
	}

	// 8. Prepare final metadata updates
	newMetadata := &tsyncv1.BackupMetadata{
		Versions:      make(map[string]*tsyncv1.Version),
		Files:         make(map[string]*tsyncv1.FileRecord),
		PublicKeys:    metadata.PublicKeys,
		SchemaVersion: 1,
		LastUpdated:   timestamppb.New(time.Now()),
	}

	if opts.SingleVersionMode {
		// Single Version Mode: keep only the new FULL version
		newMetadata.Versions[strconv.FormatUint(versionID, 10)] = newVersion

		// In-memory files pool contains only files referenced by the new version
		for _, key := range newPathToFileKey {
			newMetadata.Files[key] = newFilesPool[key]
		}
	} else {
		// Multi Version Mode: keep all versions and files
		for k, v := range metadata.Versions {
			newMetadata.Versions[k] = v
		}
		newMetadata.Versions[strconv.FormatUint(versionID, 10)] = newVersion

		for k, v := range metadata.Files {
			newMetadata.Files[k] = v
		}
		for k, v := range newFilesPool {
			newMetadata.Files[k] = v
		}
	}

	// 9. Write .tsync file
	pbBytes, err := proto.Marshal(newMetadata)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize backup metadata: %w", err)
	}

	err = dest.Write(ctx, ".tsync", pbBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to write .tsync file: %w", err)
	}

	// 10. Clean up orphaned file parts if in Single Version Mode or if metadata changed
	if opts.SingleVersionMode && hasOldMetadata {
		for oldKey := range metadata.Files {
			if _, exists := newMetadata.Files[oldKey]; !exists {
				partKey := fmt.Sprintf("%s/%s", oldKey[0:2], oldKey)
				_ = dest.Delete(ctx, partKey)
			}
		}
	}

	return newVersion, nil
}
