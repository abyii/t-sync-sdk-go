package tsync

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	zip "github.com/abyii/zip-xxh3"
	"golang.org/x/crypto/nacl/box"
)

func TestTsyncCompressionLevels(t *testing.T) {
	vmPub, vmPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	testCases := []struct {
		name             string
		compressionLevel *int
		expectedMethod   uint16
	}{
		{
			name:             "DefaultFallback(-1)",
			compressionLevel: intPtr(-1),
			expectedMethod:   zip.Deflate,
		},
		{
			name:             "StoreMethod(0)",
			compressionLevel: intPtr(0),
			expectedMethod:   zip.Store,
		},
		{
			name:             "BestCompression(9)",
			compressionLevel: intPtr(9),
			expectedMethod:   zip.Deflate,
		},
		{
			name:             "UnsetNilDefault",
			compressionLevel: nil,
			expectedMethod:   zip.Deflate,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srcStore := NewMemStorage()
			content := []byte("compression level verification content that repeats to ensure compression actually compresses something meaningful. repeating repeating repeating")
			_ = srcStore.Write(context.Background(), "test.txt", content)

			destStore := NewMemStorage()
			client := NewClient(destStore)

			// Run Backup with options
			v, err := client.Backup(context.Background(), NewFolderSource(srcStore, ""), BackupOptions{
				Label:            "backup-run",
				KeyID:            "key-1",
				PublicKeys:       map[string][]byte{"key-1": vmPub[:]},
				CompressionLevel: tc.compressionLevel,
			})
			if err != nil {
				t.Fatalf("backup failed: %v", err)
			}

			// Verify underlying part uses expected method and has valid metadata
			sm, err := client.ReadMetadata(context.Background())
			if err != nil {
				t.Fatalf("failed to read metadata: %v", err)
			}

			// Retrieve the first file record's fileKey and locate its part in destStore
			var fileKey string
			for fk := range sm.Files() {
				fileKey = fk
				break
			}
			if fileKey == "" {
				t.Fatalf("no files found in backup metadata")
			}

			partKey := fmt.Sprintf("%s/%s", fileKey[0:2], fileKey)
			partData, err := destStore.Read(context.Background(), partKey)
			if err != nil {
				t.Fatalf("failed to read part data from store: %v", err)
			}

			if len(partData) < 10 {
				t.Fatalf("part data too short")
			}
			sig := binary.LittleEndian.Uint32(partData[0:4])
			if sig != 0x04034b50 {
				t.Fatalf("invalid local file header signature: 0x%08x", sig)
			}
			compMethod := binary.LittleEndian.Uint16(partData[8:10])
			if compMethod != tc.expectedMethod {
				t.Errorf("expected compression method %d, got %d", tc.expectedMethod, compMethod)
			}

			// Restore and verify content integrity
			tmpDir, err := os.MkdirTemp("", "tsync-restore-level-test-*")
			if err != nil {
				t.Fatalf("failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
				ExtractDir: tmpDir,
				PrivateKey: vmPriv[:],
			})
			if err != nil {
				t.Fatalf("restore failed: %v", err)
			}

			restoredContent, err := os.ReadFile(filepath.Join(tmpDir, "test.txt"))
			if err != nil {
				t.Fatalf("failed to read restored file: %v", err)
			}
			if !bytes.Equal(restoredContent, content) {
				t.Errorf("restored content does not match original")
			}
		})
	}
}

func TestTsyncCustomVersionAndTimestamp(t *testing.T) {
	vmPub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	srcStore := NewMemStorage()
	_ = srcStore.Write(context.Background(), "test.txt", []byte("custom version and timestamp test content"))

	destStore := NewMemStorage()
	client := NewClient(destStore)

	t1 := time.Now().Add(-2 * time.Hour).Truncate(time.Second)

	// 1. Test Valid Custom Version ID and Timestamp
	v1, err := client.Backup(context.Background(), NewFolderSource(srcStore, ""), BackupOptions{
		Label:                 "backup-v1",
		KeyID:                 "key-1",
		PublicKeys:            map[string][]byte{"key-1": vmPub[:]},
		CustomVersionID:       1000,
		CustomBackupTimestamp: t1,
	})
	if err != nil {
		t.Fatalf("backup failed: %v", err)
	}
	if v1.SnowflakeId != 1000 {
		t.Errorf("expected version ID 1000, got %d", v1.SnowflakeId)
	}
	if !v1.BackupTimestamp.AsTime().Equal(t1) {
		t.Errorf("expected backup timestamp %v, got %v", t1, v1.BackupTimestamp.AsTime())
	}

	// 2. Test Duplicate Version ID Error
	_, err = client.Backup(context.Background(), NewFolderSource(srcStore, ""), BackupOptions{
		Label:                 "backup-duplicate",
		KeyID:                 "key-1",
		PublicKeys:            map[string][]byte{"key-1": vmPub[:]},
		CustomVersionID:       1000,
		CustomBackupTimestamp: time.Now(),
	})
	if err == nil {
		t.Errorf("expected error due to duplicate version ID, but got nil")
	} else if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected 'already exists' error, got: %v", err)
	}

	// 3. Test Out-of-bounds Version ID Error
	_, err = client.Backup(context.Background(), NewFolderSource(srcStore, ""), BackupOptions{
		Label:                 "backup-invalid-id",
		KeyID:                 "key-1",
		PublicKeys:            map[string][]byte{"key-1": vmPub[:]},
		CustomVersionID:       9223372036854775808, // > 2^63 - 1
		CustomBackupTimestamp: time.Now(),
	})
	if err == nil {
		t.Errorf("expected error due to out-of-bounds version ID, but got nil")
	} else if !strings.Contains(err.Error(), "invalid custom version ID") {
		t.Errorf("expected 'invalid custom version ID' error, got: %v", err)
	}

	// 4. Test Future Custom Timestamp Error
	_, err = client.Backup(context.Background(), NewFolderSource(srcStore, ""), BackupOptions{
		Label:                 "backup-future-time",
		KeyID:                 "key-1",
		PublicKeys:            map[string][]byte{"key-1": vmPub[:]},
		CustomVersionID:       2000,
		CustomBackupTimestamp: time.Now().Add(5 * time.Hour),
	})
	if err == nil {
		t.Errorf("expected error due to future timestamp, but got nil")
	} else if !strings.Contains(err.Error(), "is in the future") {
		t.Errorf("expected 'is in the future' error, got: %v", err)
	}

	// 5. Test Custom Timestamp before Latest Version Error
	t2 := time.Now().Add(-3 * time.Hour).Truncate(time.Second) // earlier than t1
	_, err = client.Backup(context.Background(), NewFolderSource(srcStore, ""), BackupOptions{
		Label:                 "backup-past-time",
		KeyID:                 "key-1",
		PublicKeys:            map[string][]byte{"key-1": vmPub[:]},
		CustomVersionID:       3000,
		CustomBackupTimestamp: t2,
	})
	if err == nil {
		t.Errorf("expected error due to timestamp before latest version, but got nil")
	} else if !strings.Contains(err.Error(), "must be after the latest version's backup timestamp") {
		t.Errorf("expected 'must be after the latest version's' error, got: %v", err)
	}
}

func TestTsyncPerFileCompressionCallback(t *testing.T) {
	vmPub, vmPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	srcStore := NewMemStorage()
	contentTxt := []byte("compression callback txt content that repeats repeats repeats repeats")
	contentPng := []byte("compression callback png content that repeats repeats repeats repeats")
	contentDat := []byte("compression callback dat content that repeats repeats repeats repeats")

	_ = srcStore.Write(context.Background(), "a.txt", contentTxt)
	_ = srcStore.Write(context.Background(), "b.png", contentPng)
	_ = srcStore.Write(context.Background(), "c.dat", contentDat)

	destStore := NewMemStorage()
	client := NewClient(destStore)

	globalLvl := 1
	v, err := client.Backup(context.Background(), NewFolderSource(srcStore, ""), BackupOptions{
		Label:            "per-file-comp-run",
		KeyID:            "key-1",
		PublicKeys:       map[string][]byte{"key-1": vmPub[:]},
		CompressionLevel: &globalLvl,
		GetCompressionLevel: func(path string) *int {
			if strings.HasSuffix(path, ".png") {
				return intPtr(0)
			}
			if strings.HasSuffix(path, ".txt") {
				return intPtr(9)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("backup failed: %v", err)
	}

	// 1. Read metadata and verify files
	sm, err := client.ReadMetadata(context.Background())
	if err != nil {
		t.Fatalf("failed to read metadata: %v", err)
	}

	resolvedMap, _, err := ResolveVersionTree(sm.metadata, v.SnowflakeId, false)
	if err != nil {
		t.Fatalf("failed to resolve version map: %v", err)
	}

	// Helper to check compression method in stored part
	checkMethod := func(path string, expectedMethod uint16) {
		fileKey, ok := resolvedMap[path]
		if !ok {
			t.Fatalf("file %s not found in resolved map", path)
		}
		partKey := fmt.Sprintf("%s/%s", fileKey[0:2], fileKey)
		partData, err := destStore.Read(context.Background(), partKey)
		if err != nil {
			t.Fatalf("failed to read part data for %s: %v", path, err)
		}
		if len(partData) < 10 {
			t.Fatalf("part data too short for %s", path)
		}
		sig := binary.LittleEndian.Uint32(partData[0:4])
		if sig != 0x04034b50 {
			t.Fatalf("invalid local file header signature for %s: 0x%08x", path, sig)
		}
		compMethod := binary.LittleEndian.Uint16(partData[8:10])
		if compMethod != expectedMethod {
			t.Errorf("expected compression method %d for %s, got %d", expectedMethod, path, compMethod)
		}
	}

	// .png must be stored (0)
	checkMethod("b.png", zip.Store)
	// .txt must be deflated (8)
	checkMethod("a.txt", zip.Deflate)
	// .dat must be deflated (8)
	checkMethod("c.dat", zip.Deflate)

	// 2. Restore and verify content integrity
	tmpDir, err := os.MkdirTemp("", "tsync-per-file-restore-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
		ExtractDir: tmpDir,
		PrivateKey: vmPriv[:],
	})
	if err != nil {
		t.Fatalf("restore failed: %v", err)
	}

	restoredTxt, _ := os.ReadFile(filepath.Join(tmpDir, "a.txt"))
	restoredPng, _ := os.ReadFile(filepath.Join(tmpDir, "b.png"))
	restoredDat, _ := os.ReadFile(filepath.Join(tmpDir, "c.dat"))

	if !bytes.Equal(restoredTxt, contentTxt) {
		t.Errorf("restored txt content mismatch")
	}
	if !bytes.Equal(restoredPng, contentPng) {
		t.Errorf("restored png content mismatch")
	}
	if !bytes.Equal(restoredDat, contentDat) {
		t.Errorf("restored dat content mismatch")
	}
}
