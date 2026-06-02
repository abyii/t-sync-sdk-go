package tsync

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestProgressReportingAndDiskSpace(t *testing.T) {
	// Setup keys
	vmPub, vmPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	srcStore := NewMemStorage()
	_ = srcStore.Write(context.Background(), "file1.txt", []byte("Short file"))
	_ = srcStore.Write(context.Background(), "file2.txt", []byte("Another relatively short file"))
	_ = srcStore.Write(context.Background(), "file3.txt", []byte("Longest file in the archive to trigger threshold checks"))

	destStore := NewMemStorage()
	client := NewClient(destStore)

	// 1. Test Backup Progress
	var backupProgress []int
	var backupMu sync.Mutex
	v, err := client.Backup(context.Background(), NewFolderSource(srcStore, ""), BackupOptions{
		Label:      "v1",
		KeyID:      "key-1",
		PublicKeys: map[string][]byte{"key-1": vmPub[:]},
		OnProgress: func(done, total int, path string) {
			backupMu.Lock()
			backupProgress = append(backupProgress, done)
			backupMu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("backup failed: %v", err)
	}

	if len(backupProgress) != 3 {
		t.Errorf("expected 3 progress callbacks during backup, got %d", len(backupProgress))
	}
	for i, done := range backupProgress {
		if done != i+1 {
			t.Errorf("expected sequential progress %d, got %d", i+1, done)
		}
	}

	// 2. Test Restore ZipWriter Progress
	var restoreZipProgress []int
	var zipBuf bytes.Buffer
	err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
		ZipWriter:  &zipBuf,
		PrivateKey: vmPriv[:],
		OnProgress: func(done, total int, path string) {
			restoreZipProgress = append(restoreZipProgress, done)
		},
	})
	if err != nil {
		t.Fatalf("restore zip failed: %v", err)
	}
	if len(restoreZipProgress) != 3 {
		t.Errorf("expected 3 progress callbacks during zip restore, got %d", len(restoreZipProgress))
	}
	for i, done := range restoreZipProgress {
		if done != i+1 {
			t.Errorf("expected sequential progress %d, got %d", i+1, done)
		}
	}

	// 3. Test Restore ExtractDir Progress & Disk Space Check
	tmpDir, err := os.MkdirTemp("", "tsync-progress-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// A. Mock disk space: extremely small (should fail because max file size is larger)
	origGetFreeSpace := getFreeSpace
	defer func() { getFreeSpace = origGetFreeSpace }()

	getFreeSpace = func(path string) (uint64, error) {
		return 10, nil // only 10 bytes available
	}

	err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
		ExtractDir: tmpDir,
		PrivateKey: vmPriv[:],
	})
	if err == nil {
		t.Errorf("expected restore to fail due to insufficient disk space, but it succeeded")
	} else if !bytes.Contains([]byte(err.Error()), []byte("insufficient disk space")) {
		t.Errorf("expected insufficient disk space error, got: %v", err)
	}

	// B. Mock disk space: less than total uncompressed size but larger than max file size
	// Max file is "Longest file in the archive..." (~55 bytes)
	// Total uncompressed is ~94 bytes
	getFreeSpace = func(path string) (uint64, error) {
		return 70, nil // 70 bytes free: > 55 but < 94
	}

	var restoreDirProgress []int
	var restoreDirMu sync.Mutex

	err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
		ExtractDir:  tmpDir,
		PrivateKey:  vmPriv[:],
		Concurrency: 4, // requested parallel, but should fallback to sequential
		OnProgress: func(done, total int, path string) {
			restoreDirMu.Lock()
			restoreDirProgress = append(restoreDirProgress, done)
			restoreDirMu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("restore with disk space fallback failed: %v", err)
	}

	if len(restoreDirProgress) != 3 {
		t.Errorf("expected 3 progress callbacks during directory restore, got %d", len(restoreDirProgress))
	}

	// Ensure the extracted files exist and match the expected content
	content1, err := os.ReadFile(filepath.Join(tmpDir, "file1.txt"))
	if err != nil {
		t.Fatalf("failed to read extracted file1: %v", err)
	}
	if string(content1) != "Short file" {
		t.Errorf("expected 'Short file', got %q", string(content1))
	}
}

func TestGetExistingAncestor(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tsync-ancestor-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	nonExistentSubdir := filepath.Join(tmpDir, "sub1", "sub2", "sub3")
	ancestor := getExistingAncestor(nonExistentSubdir)

	cleanAncestor, _ := filepath.EvalSymlinks(ancestor)
	cleanTmpDir, _ := filepath.EvalSymlinks(tmpDir)

	if cleanAncestor != cleanTmpDir {
		t.Errorf("expected existing ancestor to be %q, got %q", cleanTmpDir, cleanAncestor)
	}
}
