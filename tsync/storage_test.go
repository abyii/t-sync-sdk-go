package tsync

import (
	"context"
	"crypto/rand"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

// ---------------------------------------------------------
// Storage Integration Tests
// ---------------------------------------------------------

func TestLocalStorageIntegration(t *testing.T) {
	// Create temp directories in workspace
	tmpRoot := filepath.Join(".", "tmp")
	_ = os.MkdirAll(tmpRoot, 0755)

	srcDir, err := os.MkdirTemp(tmpRoot, "tsync-local-src-*")
	if err != nil {
		t.Fatalf("failed to create temp src dir: %v", err)
	}
	defer os.RemoveAll(srcDir)

	destDir, err := os.MkdirTemp(tmpRoot, "tsync-local-dest-*")
	if err != nil {
		t.Fatalf("failed to create temp dest dir: %v", err)
	}
	defer os.RemoveAll(destDir)

	// Create a test file
	testFilePath := filepath.Join(srcDir, "test.txt")
	err = os.WriteFile(testFilePath, []byte("local filesystem test"), 0644)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	srcStore, err := NewLocalStorage(srcDir)
	if err != nil {
		t.Fatalf("failed to create LocalStorage source: %v", err)
	}

	destStore, err := NewLocalStorage(destDir)
	if err != nil {
		t.Fatalf("failed to create LocalStorage dest: %v", err)
	}

	client := NewClient(destStore)
	vmPub, _, _ := box.GenerateKey(rand.Reader)
	publicKeys := map[string][]byte{"key-1": vmPub[:]}

	srcFolder := NewFolderSource(srcStore, "")

	v, err := client.Backup(context.Background(), srcFolder, BackupOptions{
		Label:      "local-run",
		KeyID:      "key-1",
		PublicKeys: publicKeys,
	})
	if err != nil {
		t.Fatalf("backup failed: %v", err)
	}

	// Verify .tsync file exists on disk
	metadataPath := filepath.Join(destDir, ".tsync")
	if _, err := os.Stat(metadataPath); err != nil {
		t.Fatalf(".tsync metadata file was not written to disk: %v", err)
	}

	// Verify sharded file exists on disk
	fileKey := ""
	h := crc32.NewIEEE()
	_, _ = h.Write([]byte("local filesystem test"))
	fileKey = fmt.Sprintf("%08x_%d", h.Sum32(), len("local filesystem test"))

	// Let's log files on disk
	entries, _ := os.ReadDir(destDir)
	for _, entry := range entries {
		t.Logf("Root entry: %s, isDir: %v", entry.Name(), entry.IsDir())
		if entry.IsDir() {
			subEntries, _ := os.ReadDir(filepath.Join(destDir, entry.Name()))
			for _, sub := range subEntries {
				t.Logf("  Sub entry: %s", sub.Name())
			}
		}
	}

	t.Logf("Expected fileKey: %s", fileKey)
	t.Logf("Version path map: %v", v.PathToFileKey)

	partPath := filepath.Join(destDir, fileKey[0:2], fileKey)
	if _, err := os.Stat(partPath); err != nil {
		t.Fatalf("sharded file part %s was not written to disk: %v", fileKey, err)
	}

	// Test listing versions
	versions, err := client.ListVersions(context.Background())
	if err != nil {
		t.Fatalf("failed to list versions: %v", err)
	}
	if len(versions) != 1 || versions[0].SnowflakeId != v.SnowflakeId {
		t.Errorf("version listing mismatch")
	}

	// Test listing files
	files, err := client.ListFiles(context.Background(), v.SnowflakeId)
	if err != nil {
		t.Fatalf("failed to list files in version: %v", err)
	}
	if len(files) != 1 || files[0] != "test.txt" {
		t.Errorf("file listing mismatch: expected ['test.txt'], got %v", files)
	}
}
