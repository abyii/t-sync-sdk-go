package tsync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"time"

	tsyncv2 "github.com/abyii/t-sync-sdk-go/v2/gen/go/com/github/abyii/tsync/v2"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Client represents the high-level T-Sync SDK client.
type Client struct {
	store Storage
}

// NewClient creates a new T-Sync SDK client wrapping the given storage.
func NewClient(store Storage) *Client {
	return &Client{store: store}
}

// Backup creates a new backup version from the given source.
func (c *Client) Backup(ctx context.Context, src Source, opts BackupOptions) (*tsyncv2.Version, error) {
	return RunBackup(ctx, src, c.store, opts)
}

// Restore reconstructs or extracts a specific backup version.
func (c *Client) Restore(ctx context.Context, versionID uint64, opts RestoreOptions) error {
	return RunRestore(ctx, c.store, versionID, opts)
}

// ListVersions lists all backup versions in the store.
func (c *Client) ListVersions(ctx context.Context) ([]*tsyncv2.Version, error) {
	pbBytes, err := c.store.Read(ctx, ".tsync")
	if err != nil {
		// If store doesn't exist yet, return empty list
		return nil, nil
	}

	var metadata tsyncv2.BackupMetadata
	if err := proto.Unmarshal(pbBytes, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	if metadata.SchemaVersion != 2 {
		return nil, fmt.Errorf("unsupported schema version %d (expected 2)", metadata.SchemaVersion)
	}

	var versions []*tsyncv2.Version
	for _, v := range metadata.Versions {
		versions = append(versions, v)
	}
	return versions, nil
}

// ListFiles lists all file paths in a specific version.
func (c *Client) ListFiles(ctx context.Context, versionID uint64) ([]string, error) {
	pbBytes, err := c.store.Read(ctx, ".tsync")
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata: %w", err)
	}

	var metadata tsyncv2.BackupMetadata
	if err := proto.Unmarshal(pbBytes, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	if metadata.SchemaVersion != 2 {
		return nil, fmt.Errorf("unsupported schema version %d (expected 2)", metadata.SchemaVersion)
	}

	resolvedMap, err := ResolveVersionMap(&metadata, versionID)
	if err != nil {
		return nil, err
	}

	var paths []string
	for p := range resolvedMap {
		paths = append(paths, p)
	}
	return paths, nil
}

// DeleteVersion deletes a backup version from the store.
// Removes orphaned tree nodes and file records from the metadata, and deletes orphaned file parts from the storage.
func (c *Client) DeleteVersion(ctx context.Context, versionID uint64) error {
	pbBytes, err := c.store.Read(ctx, ".tsync")
	if err != nil {
		return fmt.Errorf("failed to read metadata: %w", err)
	}

	var metadata tsyncv2.BackupMetadata
	if err := proto.Unmarshal(pbBytes, &metadata); err != nil {
		return fmt.Errorf("failed to parse metadata: %w", err)
	}

	if metadata.SchemaVersion != 2 {
		return fmt.Errorf("unsupported schema version %d (expected 2)", metadata.SchemaVersion)
	}

	vStr := strconv.FormatUint(versionID, 10)
	_, exists := metadata.Versions[vStr]
	if !exists {
		return fmt.Errorf("version %d not found in store", versionID)
	}

	// 1. Remove the version
	delete(metadata.Versions, vStr)
	metadata.LastUpdated = timestamppb.New(time.Now())

	// 2. Collect the set of all live tree hashes and file keys by walking every remaining version's tree
	liveTreeHashes := make(map[string]bool)
	liveFileKeys := make(map[string]bool)

	for _, v := range metadata.Versions {
		err := walkCollect(v.RootTreeHash, metadata.Trees, liveTreeHashes, liveFileKeys)
		if err != nil {
			return fmt.Errorf("failed to collect live resources: %w", err)
		}
	}

	// 3. GC orphaned TreeNodes
	for treeHash := range metadata.Trees {
		if !liveTreeHashes[treeHash] {
			delete(metadata.Trees, treeHash)
		}
	}

	// 4. Identify orphaned file records to delete
	var keysToDelete []string
	for fileKey := range metadata.Files {
		if !liveFileKeys[fileKey] {
			keysToDelete = append(keysToDelete, fileKey)
		}
	}

	// Delete from metadata map
	for _, key := range keysToDelete {
		delete(metadata.Files, key)
	}

	// 5. Save updated metadata first (Atomic write guarantee)
	newPbBytes, err := proto.Marshal(&metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal updated metadata: %w", err)
	}

	err = c.store.Write(ctx, ".tsync", newPbBytes)
	if err != nil {
		return fmt.Errorf("failed to write updated .tsync metadata file: %w", err)
	}

	// 6. Delete the orphaned file-part objects from storage
	for _, key := range keysToDelete {
		partKey := fmt.Sprintf("%s/%s", key[0:2], key)
		_ = c.store.Delete(ctx, partKey)
	}

	return nil
}

// walkCollect recursively traverses the tree to collect live subtrees and file keys.
func walkCollect(treeHash string, trees map[string]*tsyncv2.TreeNode, liveTrees map[string]bool, liveFiles map[string]bool) error {
	if liveTrees[treeHash] {
		return nil // already visited (structural sharing)
	}
	liveTrees[treeHash] = true

	node, exists := trees[treeHash]
	if !exists {
		return fmt.Errorf("tree node %s not found in metadata trees map", treeHash)
	}

	// Verify tree node hash matches its key
	marshaled, err := proto.MarshalOptions{Deterministic: true}.Marshal(node)
	if err != nil {
		return fmt.Errorf("failed to marshal tree node: %w", err)
	}
	h := sha256.New()
	h.Write(marshaled)
	computedHash := hex.EncodeToString(h.Sum(nil))
	if computedHash != treeHash {
		return fmt.Errorf("tree node hash mismatch: map key is %s, but computed hash is %s", treeHash, computedHash)
	}

	// Verify entries sorting
	var prevName string
	for i, entry := range node.Entries {
		if i > 0 && entry.Name <= prevName {
			return fmt.Errorf("tree node %s is not sorted: %q comes after %q", treeHash, entry.Name, prevName)
		}
		prevName = entry.Name
	}

	for _, entry := range node.Entries {
		if err := validateName(entry.Name); err != nil {
			return fmt.Errorf("invalid name %q in tree entry: %w", entry.Name, err)
		}

		switch n := entry.Node.(type) {
		case *tsyncv2.TreeEntry_File:
			if n.File == nil {
				return fmt.Errorf("file leaf is nil in entry %s", entry.Name)
			}
			fileKey := fmt.Sprintf("%08x_%d", n.File.Crc32, n.File.UncompressedSize)
			liveFiles[fileKey] = true
		case *tsyncv2.TreeEntry_SubtreeHash:
			if n.SubtreeHash == "" {
				return fmt.Errorf("subtree hash is empty in entry %s", entry.Name)
			}
			err := walkCollect(n.SubtreeHash, trees, liveTrees, liveFiles)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("tree entry %s has no node type set", entry.Name)
		}
	}
	return nil
}

// GC performs storage-level garbage collection.
// It cleans up orphaned TreeNodes and FileRecords from the metadata file itself,
// and deletes any file-part objects in storage that are not referenced in the metadata.
func (c *Client) GC(ctx context.Context) error {
	pbBytes, err := c.store.Read(ctx, ".tsync")
	if err != nil {
		return fmt.Errorf("failed to read metadata: %w", err)
	}

	var metadata tsyncv2.BackupMetadata
	if err := proto.Unmarshal(pbBytes, &metadata); err != nil {
		return fmt.Errorf("failed to parse metadata: %w", err)
	}

	if metadata.SchemaVersion != 2 {
		return fmt.Errorf("unsupported schema version %d (expected 2)", metadata.SchemaVersion)
	}

	// 1. Collect all live trees and file keys
	liveTreeHashes := make(map[string]bool)
	liveFileKeys := make(map[string]bool)

	for _, v := range metadata.Versions {
		err := walkCollect(v.RootTreeHash, metadata.Trees, liveTreeHashes, liveFileKeys)
		if err != nil {
			return fmt.Errorf("failed to collect live resources: %w", err)
		}
	}

	// 2. GC orphaned TreeNodes from metadata
	metadataChanged := false
	for treeHash := range metadata.Trees {
		if !liveTreeHashes[treeHash] {
			delete(metadata.Trees, treeHash)
			metadataChanged = true
		}
	}

	// 3. GC orphaned FileRecords from metadata
	for fileKey := range metadata.Files {
		if !liveFileKeys[fileKey] {
			delete(metadata.Files, fileKey)
			metadataChanged = true
		}
	}

	// 4. Save updated metadata if any changes were made
	if metadataChanged {
		metadata.LastUpdated = timestamppb.New(time.Now())
		newPbBytes, err := proto.Marshal(&metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal updated metadata: %w", err)
		}

		err = c.store.Write(ctx, ".tsync", newPbBytes)
		if err != nil {
			return fmt.Errorf("failed to write updated .tsync metadata file: %w", err)
		}
	}

	// 5. List all files in the storage and delete orphans
	validParts := make(map[string]bool)
	for key := range metadata.Files {
		validParts[key] = true
	}

	// List all files in the storage
	allFiles, err := c.store.List(ctx, "")
	if err != nil {
		return fmt.Errorf("failed to list files in storage: %w", err)
	}

	// Compile regex to match sharded file part keys: e.g. "1a/1a2b3c4d_12345"
	partRegex := regexp.MustCompile(`^[a-f0-9]{2}/[a-f0-9]{8}_[0-9]+$`)

	for _, f := range allFiles {
		// Check if the path matches a T-Sync part structure
		if partRegex.MatchString(f.Name) {
			// Extract key (base name of the path)
			key := path.Base(f.Name)
			if !validParts[key] {
				// File is orphaned, delete it from storage
				_ = c.store.Delete(ctx, f.Name)
			}
		}
	}

	return nil
}

// Helper to hash string to uint64 (fnv-like hash, identical to main.go)
func hashStringToUint64(s string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h = h ^ uint64(s[i])
		h = h * 1099511628211
	}
	return h
}

// StoreMetadata represents the loaded store metadata at a point in time,
// and provides safe, up-to-date methods to query and reload the store info.
type StoreMetadata struct {
	client   *Client
	metadata *tsyncv2.BackupMetadata
}

// ReadMetadata reads and parses the .tsync metadata file from storage.
func (c *Client) ReadMetadata(ctx context.Context) (*StoreMetadata, error) {
	pbBytes, err := c.store.Read(ctx, ".tsync")
	if err != nil {
		return nil, fmt.Errorf("failed to read store metadata: %w", err)
	}

	var metadata tsyncv2.BackupMetadata
	if err := proto.Unmarshal(pbBytes, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse store metadata: %w", err)
	}

	if metadata.SchemaVersion != 2 {
		return nil, fmt.Errorf("unsupported schema version %d (expected 2)", metadata.SchemaVersion)
	}

	return &StoreMetadata{
		client:   c,
		metadata: &metadata,
	}, nil
}

// Reload refreshes the metadata from the underlying storage.
func (sm *StoreMetadata) Reload(ctx context.Context) error {
	pbBytes, err := sm.client.store.Read(ctx, ".tsync")
	if err != nil {
		return fmt.Errorf("failed to reload store metadata: %w", err)
	}

	var metadata tsyncv2.BackupMetadata
	if err := proto.Unmarshal(pbBytes, &metadata); err != nil {
		return fmt.Errorf("failed to parse reloaded store metadata: %w", err)
	}

	if metadata.SchemaVersion != 2 {
		return fmt.Errorf("unsupported schema version %d (expected 2)", metadata.SchemaVersion)
	}

	sm.metadata = &metadata
	return nil
}

// SchemaVersion returns the schema version.
func (sm *StoreMetadata) SchemaVersion() uint32 {
	return sm.metadata.SchemaVersion
}

// StoreLabel returns the store label.
func (sm *StoreMetadata) StoreLabel() string {
	return sm.metadata.GetStoreLabel()
}

// LastUpdated returns the timestamp of the last metadata update.
func (sm *StoreMetadata) LastUpdated() time.Time {
	if sm.metadata.LastUpdated == nil {
		return time.Time{}
	}
	return sm.metadata.LastUpdated.AsTime()
}

// PublicKeys returns the registered public keys in the store.
func (sm *StoreMetadata) PublicKeys() map[string][]byte {
	keys := make(map[string][]byte)
	for k, v := range sm.metadata.PublicKeys {
		valCopy := make([]byte, len(v))
		copy(valCopy, v)
		keys[k] = valCopy
	}
	return keys
}

// LatestVersion returns the details of the latest backup version.
func (sm *StoreMetadata) LatestVersion() *tsyncv2.Version {
	if len(sm.metadata.Versions) == 0 {
		return nil
	}
	var latest *tsyncv2.Version
	for _, v := range sm.metadata.Versions {
		if latest == nil || v.BackupTimestamp.AsTime().After(latest.BackupTimestamp.AsTime()) {
			latest = v
		}
	}
	return latest
}

// Versions returns list of all backup versions sorted by timestamp descending.
func (sm *StoreMetadata) Versions() []*tsyncv2.Version {
	var versions []*tsyncv2.Version
	for _, v := range sm.metadata.Versions {
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].BackupTimestamp.AsTime().After(versions[j].BackupTimestamp.AsTime())
	})
	return versions
}

// HasVersion checks if a specific version ID exists.
func (sm *StoreMetadata) HasVersion(versionID uint64) bool {
	vStr := strconv.FormatUint(versionID, 10)
	_, exists := sm.metadata.Versions[vStr]
	return exists
}

// Files returns a map of all files registered in the store (copy of internal map).
func (sm *StoreMetadata) Files() map[string]*tsyncv2.FileRecord {
	files := make(map[string]*tsyncv2.FileRecord)
	for k, v := range sm.metadata.Files {
		files[k] = v
	}
	return files
}

// GetFileRecord returns a specific file record by its compound key.
func (sm *StoreMetadata) GetFileRecord(fileKey string) *tsyncv2.FileRecord {
	return sm.metadata.Files[fileKey]
}
