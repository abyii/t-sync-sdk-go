package tsync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	tsyncv2 "github.com/abyii/t-sync-sdk-go/v2/gen/go/com/github/abyii/tsync/v2"

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

	// GetCompressionLevel is an optional callback allowing clients to specify per-file compression levels.
	// The callback is passed the file path and returns the compression level to use (from -1 to 9).
	// If the callback returns nil, the engine falls back to CompressionLevel option, and then to default (5).
	GetCompressionLevel func(path string) *int

	// CustomVersionID specifies a custom Snowflake ID for this backup version.
	// If 0, a new ID is generated automatically.
	CustomVersionID uint64

	// CustomBackupTimestamp specifies a custom timestamp for this backup version.
	// If zero, the current time is used.
	CustomBackupTimestamp time.Time
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

// validateName validates a single name component for directory or file entries.
func validateName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("name cannot be empty")
	}
	if len(name) > 255 {
		return fmt.Errorf("name exceeds maximum length of 255 bytes: %q", name)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '/' || c == '\\' {
			return fmt.Errorf("name contains illegal character %q: %q", c, name)
		}
		if c == 0 {
			return fmt.Errorf("name contains null byte: %q", name)
		}
	}
	if name == "." || name == ".." {
		return fmt.Errorf("name cannot be directory traversal sentinel %q", name)
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

func RunBackup(ctx context.Context, src Source, dest Storage, opts BackupOptions) (*tsyncv2.Version, error) {
	// 0. Validate custom options if passed
	if opts.CustomVersionID != 0 {
		if opts.CustomVersionID > 9223372036854775807 {
			return nil, fmt.Errorf("invalid custom version ID: %d (must be <= 9223372036854775807)", opts.CustomVersionID)
		}
	}
	if !opts.CustomBackupTimestamp.IsZero() {
		if opts.CustomBackupTimestamp.After(time.Now().Add(1 * time.Hour)) {
			return nil, fmt.Errorf("custom backup timestamp %v is in the future", opts.CustomBackupTimestamp)
		}
	}

	// Resolve global compression method and level
	globalCompMethod := zip.Deflate
	globalCompLevel := -1
	if opts.CompressionLevel != nil {
		lvl := *opts.CompressionLevel
		if lvl == 0 {
			globalCompMethod = zip.Store
			globalCompLevel = 0
		} else if lvl >= -1 && lvl <= 9 {
			globalCompLevel = lvl
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

	// Apply filter and validate path components upfront
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

		// Validate name components
		parts := strings.Split(entry.Path, "/")
		for _, part := range parts {
			if err := validateName(part); err != nil {
				return nil, fmt.Errorf("invalid path component in %q: %w", entry.Path, err)
			}
		}

		entries = append(entries, entry)
	}

	// 2. Load existing metadata or initialize new
	var metadata tsyncv2.BackupMetadata
	hasOldMetadata := false

	tsyncBytes, err := dest.Read(ctx, ".tsync")
	if err == nil {
		if err = proto.Unmarshal(tsyncBytes, &metadata); err == nil {
			if metadata.SchemaVersion != 2 {
				return nil, fmt.Errorf("unsupported schema version %d (expected 2)", metadata.SchemaVersion)
			}
			hasOldMetadata = true
		}
	}

	if hasOldMetadata {
		if opts.CustomVersionID != 0 {
			if _, exists := metadata.Versions[strconv.FormatUint(opts.CustomVersionID, 10)]; exists {
				return nil, fmt.Errorf("version ID %d already exists in the backup store", opts.CustomVersionID)
			}
		}
		if !opts.CustomBackupTimestamp.IsZero() && len(metadata.Versions) > 0 {
			var latestV *tsyncv2.Version
			for _, v := range metadata.Versions {
				if latestV == nil || v.BackupTimestamp.AsTime().After(latestV.BackupTimestamp.AsTime()) {
					latestV = v
				}
			}
			if latestV != nil && !opts.CustomBackupTimestamp.After(latestV.BackupTimestamp.AsTime()) {
				return nil, fmt.Errorf("custom backup timestamp %v must be after the latest version's backup timestamp %v", opts.CustomBackupTimestamp, latestV.BackupTimestamp.AsTime())
			}
		}
	}

	if !hasOldMetadata {
		if len(opts.PublicKeys) == 0 {
			return nil, fmt.Errorf("creating a new backup store requires providing at least one public key in options")
		}
		metadata = tsyncv2.BackupMetadata{
			Versions:      make(map[string]*tsyncv2.Version),
			Trees:         make(map[string]*tsyncv2.TreeNode),
			Files:         make(map[string]*tsyncv2.FileRecord),
			PublicKeys:    opts.PublicKeys,
			SchemaVersion: 2,
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
		record *tsyncv2.FileRecord
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
				var record *tsyncv2.FileRecord

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

					// Resolve compression method and level for this file
					compMethod := globalCompMethod
					compLevel := globalCompLevel
					if opts.GetCompressionLevel != nil {
						lvlPtr := opts.GetCompressionLevel(entry.Path)
						if lvlPtr != nil {
							lvl := *lvlPtr
							if lvl == 0 {
								compMethod = zip.Store
								compLevel = 0
							} else if lvl >= -1 && lvl <= 9 {
								compMethod = zip.Deflate
								compLevel = lvl
							} else {
								cancel()
								resultChan <- result{err: fmt.Errorf("invalid compression level returned by callback for %s: %d", entry.Path, lvl)}
								continue
							}
						}
					}

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

					record = &tsyncv2.FileRecord{
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
	newFilesPool := make(map[string]*tsyncv2.FileRecord)

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

	// Build the directory tree structure
	rootNode := newTempDirNode()
	for p, fileKey := range newPathToFileKey {
		parts := strings.Split(p, "/")
		curr := rootNode
		for i, part := range parts {
			if i == len(parts)-1 {
				// Path collision check: file vs directory
				if _, exists := curr.subdirs[part]; exists {
					return nil, fmt.Errorf("path collision: %q is both a directory and a file", p)
				}
				rec := newFilesPool[fileKey]
				curr.files[part] = &tsyncv2.FileLeaf{
					Crc32:            rec.Crc32,
					UncompressedSize: rec.UncompressedSize,
				}
			} else {
				// Path collision check: file vs directory
				if _, exists := curr.files[part]; exists {
					return nil, fmt.Errorf("path collision: %q is both a file and a directory", p)
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

	// 6. Create the new Version message
	versionID := opts.CustomVersionID
	if versionID == 0 {
		versionID = hashStringToUint64(strconv.FormatInt(time.Now().UnixNano(), 10))
	}
	backupTime := time.Now()
	if !opts.CustomBackupTimestamp.IsZero() {
		backupTime = opts.CustomBackupTimestamp
	}

	var precedingID uint64 = 0
	if hasOldMetadata && len(metadata.Versions) > 0 {
		var latestV *tsyncv2.Version
		for _, v := range metadata.Versions {
			if latestV == nil || v.BackupTimestamp.AsTime().After(latestV.BackupTimestamp.AsTime()) {
				latestV = v
			}
		}
		if latestV != nil {
			precedingID = latestV.SnowflakeId
		}
	}

	newVersion := &tsyncv2.Version{
		SnowflakeId:        versionID,
		BackupTimestamp:    timestamppb.New(backupTime),
		RootTreeHash:       rootHash,
		PrecedingVersionId: precedingID,
		Label:              opts.Label,
	}

	// 7. Prepare final metadata updates
	newMetadata := &tsyncv2.BackupMetadata{
		Versions:      make(map[string]*tsyncv2.Version),
		Trees:         make(map[string]*tsyncv2.TreeNode),
		Files:         make(map[string]*tsyncv2.FileRecord),
		PublicKeys:    metadata.PublicKeys,
		SchemaVersion: 2,
		LastUpdated:   timestamppb.New(time.Now()),
	}

	if opts.SingleVersionMode {
		newMetadata.Versions[strconv.FormatUint(versionID, 10)] = newVersion
		for k, v := range newTreesMap {
			newMetadata.Trees[k] = v
		}
		for k, v := range newFilesPool {
			newMetadata.Files[k] = v
		}
	} else {
		// Keep all old versions, trees, and files
		for k, v := range metadata.Versions {
			newMetadata.Versions[k] = v
		}
		newMetadata.Versions[strconv.FormatUint(versionID, 10)] = newVersion

		for k, v := range metadata.Trees {
			newMetadata.Trees[k] = v
		}
		for k, v := range newTreesMap {
			newMetadata.Trees[k] = v
		}

		for k, v := range metadata.Files {
			newMetadata.Files[k] = v
		}
		for k, v := range newFilesPool {
			newMetadata.Files[k] = v
		}
	}

	// 8. Write .tsync file
	pbBytes, err := proto.Marshal(newMetadata)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize backup metadata: %w", err)
	}

	err = dest.Write(ctx, ".tsync", pbBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to write .tsync file: %w", err)
	}

	// 9. Clean up orphaned file parts if in Single Version Mode
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
