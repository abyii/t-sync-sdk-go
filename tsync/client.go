package tsync

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"time"

	tsyncv1 "t-sync-sdk-go/gen/go/com/github/abyii/tsync/v1"

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
func (c *Client) Backup(ctx context.Context, src Source, opts BackupOptions) (*tsyncv1.Version, error) {
	return RunBackup(ctx, src, c.store, opts)
}

// Restore reconstructs or extracts a specific backup version.
func (c *Client) Restore(ctx context.Context, versionID uint64, opts RestoreOptions) error {
	return RunRestore(ctx, c.store, versionID, opts)
}

// ListVersions lists all backup versions in the store, sorted by timestamp descending.
func (c *Client) ListVersions(ctx context.Context) ([]*tsyncv1.Version, error) {
	pbBytes, err := c.store.Read(ctx, ".tsync")
	if err != nil {
		// If store doesn't exist yet, return empty list
		return nil, nil
	}

	var metadata tsyncv1.BackupMetadata
	if err := proto.Unmarshal(pbBytes, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	var versions []*tsyncv1.Version
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

	var metadata tsyncv1.BackupMetadata
	if err := proto.Unmarshal(pbBytes, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
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
// If any other versions are deltas depending on this version, they are promoted to FULL.
// Removes orphaned file parts from the storage.
func (c *Client) DeleteVersion(ctx context.Context, versionID uint64) error {
	pbBytes, err := c.store.Read(ctx, ".tsync")
	if err != nil {
		return fmt.Errorf("failed to read metadata: %w", err)
	}

	var metadata tsyncv1.BackupMetadata
	if err := proto.Unmarshal(pbBytes, &metadata); err != nil {
		return fmt.Errorf("failed to parse metadata: %w", err)
	}

	vStr := strconv.FormatUint(versionID, 10)
	_, exists := metadata.Versions[vStr]
	if !exists {
		return fmt.Errorf("version %d not found in store", versionID)
	}

	// 1. Promote any dependent delta versions to FULL
	for k, v := range metadata.Versions {
		if v.Kind == tsyncv1.VersionKind_VERSION_KIND_DELTA && v.ParentId == versionID {
			resolvedMap, err := ResolveVersionMap(&metadata, v.SnowflakeId)
			if err != nil {
				return fmt.Errorf("failed to resolve delta version %d for promotion: %w", v.SnowflakeId, err)
			}
			
			// Overwrite delta to full
			v.Kind = tsyncv1.VersionKind_VERSION_KIND_FULL
			v.PathToFileKey = resolvedMap
			v.ParentId = 0
			v.DeltaChanges = nil
			v.DeltaDeleted = nil

			metadata.Versions[k] = v
		}
	}

	// 2. Remove the version
	delete(metadata.Versions, vStr)
	metadata.LastUpdated = timestamppb.New(time.Now())

	// 3. Compile a list of referenced file keys across all remaining versions
	referencedKeys := make(map[string]bool)
	for _, v := range metadata.Versions {
		resolved, err := ResolveVersionMap(&metadata, v.SnowflakeId)
		if err == nil {
			for _, key := range resolved {
				referencedKeys[key] = true
			}
		}
	}

	// 4. Identify orphaned file records to delete
	var keysToDelete []string
	for key := range metadata.Files {
		if !referencedKeys[key] {
			keysToDelete = append(keysToDelete, key)
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

// GC performs storage-level garbage collection.
// It deletes any file-part objects in storage that are not present in the .tsync metadata.
func (c *Client) GC(ctx context.Context) error {
	pbBytes, err := c.store.Read(ctx, ".tsync")
	if err != nil {
		return fmt.Errorf("failed to read metadata: %w", err)
	}

	var metadata tsyncv1.BackupMetadata
	if err := proto.Unmarshal(pbBytes, &metadata); err != nil {
		return fmt.Errorf("failed to parse metadata: %w", err)
	}

	// Compile a list of all valid file parts in metadata
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
	metadata *tsyncv1.BackupMetadata
}

// ReadMetadata reads and parses the .tsync metadata file from storage.
func (c *Client) ReadMetadata(ctx context.Context) (*StoreMetadata, error) {
	pbBytes, err := c.store.Read(ctx, ".tsync")
	if err != nil {
		return nil, fmt.Errorf("failed to read store metadata: %w", err)
	}

	var metadata tsyncv1.BackupMetadata
	if err := proto.Unmarshal(pbBytes, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse store metadata: %w", err)
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

	var metadata tsyncv1.BackupMetadata
	if err := proto.Unmarshal(pbBytes, &metadata); err != nil {
		return fmt.Errorf("failed to parse reloaded store metadata: %w", err)
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
func (sm *StoreMetadata) LatestVersion() *tsyncv1.Version {
	if len(sm.metadata.Versions) == 0 {
		return nil
	}
	var latest *tsyncv1.Version
	for _, v := range sm.metadata.Versions {
		if latest == nil || v.BackupTimestamp.AsTime().After(latest.BackupTimestamp.AsTime()) {
			latest = v
		}
	}
	return latest
}

// Versions returns list of all backup versions sorted by timestamp descending.
func (sm *StoreMetadata) Versions() []*tsyncv1.Version {
	var versions []*tsyncv1.Version
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
func (sm *StoreMetadata) Files() map[string]*tsyncv1.FileRecord {
	files := make(map[string]*tsyncv1.FileRecord)
	for k, v := range sm.metadata.Files {
		files[k] = v
	}
	return files
}

// GetFileRecord returns a specific file record by its compound key.
func (sm *StoreMetadata) GetFileRecord(fileKey string) *tsyncv1.FileRecord {
	return sm.metadata.Files[fileKey]
}
