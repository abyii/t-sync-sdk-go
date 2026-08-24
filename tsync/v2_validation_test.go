package tsync

import (
	"context"
	"crypto/rand"
	"os"
	"strings"
	"testing"

	tsyncv2 "github.com/abyii/t-sync-sdk-go/v2/gen/go/com/github/abyii/tsync/v2"
	"golang.org/x/crypto/nacl/box"
	"google.golang.org/protobuf/proto"
)

func TestTsyncV2ValidationAndBestEffort(t *testing.T) {
	vmPub, vmPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	t.Run("Invalid File Names Rejected during Backup", func(t *testing.T) {
		invalidNames := []string{
			"foo/../bar",
			"foo/./bar",
			"foo//bar",
			"foo/bar\x00baz",
			"foo/bar\\baz",
			"",
			strings.Repeat("a", 256),
		}

		for _, name := range invalidNames {
			srcStore := NewMemStorage()
			_ = srcStore.Write(context.Background(), name, []byte("test content"))
			destStore := NewMemStorage()
			client := NewClient(destStore)

			_, err = client.Backup(context.Background(), NewFolderSource(srcStore, ""), BackupOptions{
				Label:      "invalid-run",
				KeyID:      "key-1",
				PublicKeys: map[string][]byte{"key-1": vmPub[:]},
			})
			if err == nil {
				t.Errorf("expected backup to fail for invalid name %q, but succeeded", name)
			}
		}
	})

	t.Run("Reject Schema Version != 2", func(t *testing.T) {
		destStore := NewMemStorage()
		client := NewClient(destStore)

		// Create metadata with schema version 1
		metadata := tsyncv2.BackupMetadata{
			Versions:      make(map[string]*tsyncv2.Version),
			SchemaVersion: 1,
		}
		pbBytes, _ := proto.Marshal(&metadata)
		_ = destStore.Write(context.Background(), ".tsync", pbBytes)

		// ListVersions should fail
		_, err = client.ListVersions(context.Background())
		if err == nil {
			t.Errorf("expected ListVersions to fail for schema version 1")
		}

		// Restore should fail
		err = client.Restore(context.Background(), 123, RestoreOptions{})
		if err == nil {
			t.Errorf("expected Restore to fail for schema version 1")
		}
	})

	t.Run("Tree Validation Failures and SkipValidationErrors", func(t *testing.T) {
		srcStore := NewMemStorage()
		_ = srcStore.Write(context.Background(), "a.txt", []byte("file a"))
		_ = srcStore.Write(context.Background(), "b.txt", []byte("file b"))
		_ = srcStore.Write(context.Background(), "c.txt", []byte("file c"))

		destStore := NewMemStorage()
		client := NewClient(destStore)

		v, err := client.Backup(context.Background(), NewFolderSource(srcStore, ""), BackupOptions{
			Label:      "valid-run",
			KeyID:      "key-1",
			PublicKeys: map[string][]byte{"key-1": vmPub[:]},
		})
		if err != nil {
			t.Fatalf("backup failed: %v", err)
		}

		// A. Validate normal restore succeeds
		tmpDir, err := os.MkdirTemp("", "tsync-validation-test-*")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
			ExtractDir: tmpDir,
			PrivateKey: vmPriv[:],
		})
		if err != nil {
			t.Fatalf("normal restore failed: %v", err)
		}

		// B. Test out-of-order entries in a TreeNode
		pbBytes, _ := destStore.Read(context.Background(), ".tsync")
		var metadata tsyncv2.BackupMetadata
		_ = proto.Unmarshal(pbBytes, &metadata)

		// Corrupt sorting of the root node
		var rootNode *tsyncv2.TreeNode
		for _, node := range metadata.Trees {
			rootNode = node
			break
		}
		if rootNode == nil || len(rootNode.Entries) < 2 {
			t.Fatalf("expected at least 2 entries in root node")
		}

		// Swap two entries to make it out-of-order
		rootNode.Entries[0], rootNode.Entries[1] = rootNode.Entries[1], rootNode.Entries[0]

		// Save back corrupted metadata
		corruptPb, _ := proto.Marshal(&metadata)
		_ = destStore.Write(context.Background(), ".tsync", corruptPb)

		// Restore should fail
		err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
			ExtractDir: tmpDir,
			PrivateKey: vmPriv[:],
		})
		if err == nil {
			t.Errorf("expected restore to fail due to unsorted tree node, but succeeded")
		}

		// Restore with SkipValidationErrors should succeed
		err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
			ExtractDir:           tmpDir,
			PrivateKey:           vmPriv[:],
			SkipValidationErrors: true,
		})
		if err != nil {
			t.Errorf("expected restore with SkipValidationErrors to succeed for unsorted tree, got: %v", err)
		}

		// C. Test incorrect tree node hash / missing tree node
		_ = proto.Unmarshal(pbBytes, &metadata)
		for k, v := range metadata.Versions {
			v.RootTreeHash = "invalidhash123456789012345678901234567890123456789012345678901234"
			metadata.Versions[k] = v
		}
		corruptPb, _ = proto.Marshal(&metadata)
		_ = destStore.Write(context.Background(), ".tsync", corruptPb)

		// Restore should fail
		err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
			ExtractDir: tmpDir,
			PrivateKey: vmPriv[:],
		})
		if err == nil {
			t.Errorf("expected restore to fail due to missing/invalid root tree hash, but succeeded")
		}

		// Restore with SkipValidationErrors should skip/return empty without failing
		err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
			ExtractDir:           tmpDir,
			PrivateKey:           vmPriv[:],
			SkipValidationErrors: true,
		})
		if err != nil {
			t.Errorf("expected restore with SkipValidationErrors to succeed for missing tree node, got: %v", err)
		}
	})

	t.Run("GC prunes metadata orphans", func(t *testing.T) {
		srcStore := NewMemStorage()
		_ = srcStore.Write(context.Background(), "a.txt", []byte("file a"))
		destStore := NewMemStorage()
		client := NewClient(destStore)

		_, err = client.Backup(context.Background(), NewFolderSource(srcStore, ""), BackupOptions{
			Label:      "valid-run",
			KeyID:      "key-1",
			PublicKeys: map[string][]byte{"key-1": vmPub[:]},
		})
		if err != nil {
			t.Fatalf("backup failed: %v", err)
		}

		// Inject orphaned tree node and file record
		pbBytes, _ := destStore.Read(context.Background(), ".tsync")
		var metadata tsyncv2.BackupMetadata
		_ = proto.Unmarshal(pbBytes, &metadata)

		metadata.Trees["orphanedtreehash123456789012345678901234567890123456789012345"] = &tsyncv2.TreeNode{
			Entries: []*tsyncv2.TreeEntry{
				{
					Name: "orphan.txt",
					Node: &tsyncv2.TreeEntry_File{
						File: &tsyncv2.FileLeaf{
							Crc32:            12345,
							UncompressedSize: 67890,
						},
					},
				},
			},
		}

		metadata.Files["00003039_67890"] = &tsyncv2.FileRecord{
			Crc32:            12345,
			UncompressedSize: 67890,
		}

		// Write a fake sharded file part to destStore
		fakeOrphanKey := "00/00003039_67890"
		_ = destStore.Write(context.Background(), fakeOrphanKey, []byte("fake part data"))

		corruptPb, _ := proto.Marshal(&metadata)
		_ = destStore.Write(context.Background(), ".tsync", corruptPb)

		// Run GC
		err = client.GC(context.Background())
		if err != nil {
			t.Fatalf("GC failed: %v", err)
		}

		// Read metadata back
		pbBytes2, _ := destStore.Read(context.Background(), ".tsync")
		var metadata2 tsyncv2.BackupMetadata
		_ = proto.Unmarshal(pbBytes2, &metadata2)

		// Verify orphans are gone from metadata
		if _, exists := metadata2.Trees["orphanedtreehash123456789012345678901234567890123456789012345"]; exists {
			t.Errorf("orphaned tree was not pruned by GC")
		}
		// Verify orphaned file part is gone from storage
		exists, _ := destStore.Exists(context.Background(), fakeOrphanKey)
		if exists {
			t.Errorf("orphaned storage part was not deleted by GC")
		}
	})
}
