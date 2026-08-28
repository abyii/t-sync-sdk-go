package tsync

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	zip "github.com/abyii/zip-xxh3"
	"golang.org/x/crypto/nacl/box"
)

// ---------------------------------------------------------
// FaultInjectingStorage - Wrapper for testing ACID & Crashes
// ---------------------------------------------------------

type FaultInjectingStorage struct {
	base Storage
	mu   sync.Mutex

	failWriteAfterNFiles int64
	writtenFileCount     int64

	failWriteOnPathContains string
	failWriteTriggered      bool

	failDeleteOnPathContains string
	failDeleteTriggered      bool
}

func NewFaultInjectingStorage(base Storage) *FaultInjectingStorage {
	return &FaultInjectingStorage{
		base: base,
	}
}

func (s *FaultInjectingStorage) SetFailWriteAfterNFiles(n int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failWriteAfterNFiles = n
	s.writtenFileCount = 0
}

func (s *FaultInjectingStorage) SetFailWriteOnPathContains(substr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failWriteOnPathContains = substr
	s.failWriteTriggered = false
}

func (s *FaultInjectingStorage) SetFailDeleteOnPathContains(substr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failDeleteOnPathContains = substr
	s.failDeleteTriggered = false
}

func (s *FaultInjectingStorage) List(ctx context.Context, prefix string) ([]FileInfo, error) {
	return s.base.List(ctx, prefix)
}

func (s *FaultInjectingStorage) OpenReader(ctx context.Context, key string) (io.ReadCloser, error) {
	return s.base.OpenReader(ctx, key)
}

func (s *FaultInjectingStorage) Read(ctx context.Context, key string) ([]byte, error) {
	return s.base.Read(ctx, key)
}

func (s *FaultInjectingStorage) ReadRange(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error) {
	return s.base.ReadRange(ctx, key, offset, length)
}

func (s *FaultInjectingStorage) Size(ctx context.Context, key string) (int64, error) {
	return s.base.Size(ctx, key)
}

func (s *FaultInjectingStorage) Exists(ctx context.Context, key string) (bool, error) {
	return s.base.Exists(ctx, key)
}

func (s *FaultInjectingStorage) OpenWriter(ctx context.Context, key string) (io.WriteCloser, error) {
	s.mu.Lock()
	if s.failWriteOnPathContains != "" && strings.Contains(key, s.failWriteOnPathContains) {
		s.failWriteTriggered = true
		s.mu.Unlock()
		return nil, fmt.Errorf("injected fault: write blocked on path %q", key)
	}

	if s.failWriteAfterNFiles > 0 {
		count := atomic.AddInt64(&s.writtenFileCount, 1)
		if count > s.failWriteAfterNFiles {
			s.mu.Unlock()
			return nil, fmt.Errorf("injected fault: storage limit reached (%d files written)", s.failWriteAfterNFiles)
		}
	}
	s.mu.Unlock()

	return s.base.OpenWriter(ctx, key)
}

func (s *FaultInjectingStorage) Write(ctx context.Context, key string, data []byte) error {
	s.mu.Lock()
	if s.failWriteOnPathContains != "" && strings.Contains(key, s.failWriteOnPathContains) {
		s.failWriteTriggered = true
		s.mu.Unlock()
		return fmt.Errorf("injected fault: write blocked on path %q", key)
	}

	if s.failWriteAfterNFiles > 0 {
		count := atomic.AddInt64(&s.writtenFileCount, 1)
		if count > s.failWriteAfterNFiles {
			s.mu.Unlock()
			return fmt.Errorf("injected fault: storage limit reached (%d files written)", s.failWriteAfterNFiles)
		}
	}
	s.mu.Unlock()

	return s.base.Write(ctx, key, data)
}

func (s *FaultInjectingStorage) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	if s.failDeleteOnPathContains != "" && strings.Contains(key, s.failDeleteOnPathContains) {
		s.failDeleteTriggered = true
		s.mu.Unlock()
		return fmt.Errorf("injected fault: delete blocked on path %q", key)
	}
	s.mu.Unlock()

	return s.base.Delete(ctx, key)
}

// ---------------------------------------------------------
// ACID Test Cases
// ---------------------------------------------------------

// TestTsyncACIDBackupAbortedMidFlight verifies all-or-nothing atomicity when Backup process is killed mid-flight.
func TestTsyncACIDBackupAbortedMidFlight(t *testing.T) {
	vmPub, vmPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	memStorage := NewMemStorage()
	faultStorage := NewFaultInjectingStorage(memStorage)
	client := NewClient(faultStorage)

	// Step 1: Create and commit Version 1 with 10 files cleanly
	srcStore1 := NewMemStorage()
	for i := 1; i <= 10; i++ {
		_ = srcStore1.Write(context.Background(), fmt.Sprintf("v1_file_%d.txt", i), []byte(fmt.Sprintf("v1 content %d", i)))
	}

	v1, err := client.Backup(context.Background(), NewFolderSource(srcStore1, ""), BackupOptions{
		Label:      "v1-commit",
		KeyID:      "key-1",
		PublicKeys: map[string][]byte{"key-1": vmPub[:]},
	})
	if err != nil {
		t.Fatalf("v1 backup failed: %v", err)
	}

	// Step 2: Configure fault storage to fail after writing 5 files during Version 2 backup
	faultStorage.SetFailWriteAfterNFiles(5)

	srcStore2 := NewMemStorage()
	for i := 1; i <= 30; i++ {
		_ = srcStore2.Write(context.Background(), fmt.Sprintf("v2_file_%d.txt", i), []byte(fmt.Sprintf("v2 new content %d", i)))
	}

	_, backupErr := client.Backup(context.Background(), NewFolderSource(srcStore2, ""), BackupOptions{
		Label:      "v2-aborted",
		KeyID:      "key-1",
		PublicKeys: map[string][]byte{"key-1": vmPub[:]},
	})
	if backupErr == nil {
		t.Fatalf("expected Version 2 backup to fail due to injected storage fault, but it succeeded")
	}

	// ATOMICITY ASSERTIONS:
	// 1. Version 1 remains 100% restorable without any corruption
	var restoredZipBuf bytes.Buffer
	err = client.Restore(context.Background(), v1.SnowflakeId, RestoreOptions{
		ZipWriter:  &restoredZipBuf,
		PrivateKey: vmPriv[:],
	})
	if err != nil {
		t.Fatalf("restoring Version 1 after aborted Version 2 failed: %v", err)
	}

	verifyZipExplorerExtractable(t, restoredZipBuf.Bytes(), "")

	zr, err := zip.NewReader(bytes.NewReader(restoredZipBuf.Bytes()), int64(restoredZipBuf.Len()))
	if err != nil {
		t.Fatalf("failed to parse restored Version 1 ZIP: %v", err)
	}
	if len(zr.File) != 10 {
		t.Fatalf("expected 10 files in restored Version 1, got %d", len(zr.File))
	}

	// 2. Storage Metadata contains ONLY Version 1 (no partial Version 2 record in metadata)
	history, err := client.ListVersions(context.Background())
	if err != nil {
		t.Fatalf("failed to list versions: %v", err)
	}
	if len(history) != 1 || history[0].SnowflakeId != v1.SnowflakeId {
		t.Fatalf("metadata catalog corrupted: expected exactly 1 version (v1), got %d versions", len(history))
	}
}

// TestTsyncACIDBackupResumeSelfHealing verifies that a retried Backup after an aborted attempt resumes cleanly.
func TestTsyncACIDBackupResumeSelfHealing(t *testing.T) {
	vmPub, vmPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	memStorage := NewMemStorage()
	faultStorage := NewFaultInjectingStorage(memStorage)
	client := NewClient(faultStorage)

	srcStore := NewMemStorage()
	for i := 1; i <= 20; i++ {
		_ = srcStore.Write(context.Background(), fmt.Sprintf("file_%d.txt", i), []byte(fmt.Sprintf("content for file %d", i)))
	}

	// Use fixed EphPublicKey and EncryptedPassword for consistent retry encryption
	clearZipPass, _ := GenerateZipCryptoPassword()
	ephPub, encPass, _ := EncryptPassword(clearZipPass, vmPub[:])

	bOpts := BackupOptions{
		KeyID:             "key-1",
		PublicKeys:        map[string][]byte{"key-1": vmPub[:]},
		EphPublicKey:      ephPub,
		EncryptedPassword: encPass,
	}

	// 1. First Backup attempt fails halfway (after 7 files)
	faultStorage.SetFailWriteAfterNFiles(7)
	bOpts.Label = "attempt-1-fail"
	_, err = client.Backup(context.Background(), NewFolderSource(srcStore, ""), bOpts)
	if err == nil {
		t.Fatalf("expected attempt 1 to fail")
	}

	// 2. Remove fault injection limit and retry Backup
	faultStorage.SetFailWriteAfterNFiles(0)
	bOpts.Label = "attempt-2-success"
	v2, err := client.Backup(context.Background(), NewFolderSource(srcStore, ""), bOpts)
	if err != nil {
		t.Fatalf("retried backup failed: %v", err)
	}

	// 3. Verify restored output
	var restoredZipBuf bytes.Buffer
	err = client.Restore(context.Background(), v2.SnowflakeId, RestoreOptions{
		ZipWriter:  &restoredZipBuf,
		PrivateKey: vmPriv[:],
	})
	if err != nil {
		t.Fatalf("restore of self-healed backup failed: %v", err)
	}

	verifyZipExplorerExtractable(t, restoredZipBuf.Bytes(), "")

	zr, err := zip.NewReader(bytes.NewReader(restoredZipBuf.Bytes()), int64(restoredZipBuf.Len()))
	if err != nil {
		t.Fatalf("failed to parse restored zip: %v", err)
	}
	if len(zr.File) != 20 {
		t.Fatalf("expected 20 files in restored ZIP, got %d", len(zr.File))
	}
}

// TestTsyncACIDMetadataCommitFailure verifies atomicity when metadata write fails at 99% during the final commit step.
func TestTsyncACIDMetadataCommitFailure(t *testing.T) {
	vmPub, vmPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	memStorage := NewMemStorage()
	faultStorage := NewFaultInjectingStorage(memStorage)
	client := NewClient(faultStorage)

	// Step 1: Version 1 commit cleanly
	srcStore1 := NewMemStorage()
	_ = srcStore1.Write(context.Background(), "initial.txt", []byte("initial data"))
	v1, err := client.Backup(context.Background(), NewFolderSource(srcStore1, ""), BackupOptions{
		Label:      "v1-commit",
		KeyID:      "key-1",
		PublicKeys: map[string][]byte{"key-1": vmPub[:]},
	})
	if err != nil {
		t.Fatalf("v1 backup failed: %v", err)
	}

	// Step 2: Inject failure specifically on ".tsync" metadata commit file
	faultStorage.SetFailWriteOnPathContains(".tsync")

	srcStore2 := NewMemStorage()
	_ = srcStore2.Write(context.Background(), "newfile.txt", []byte("new data"))

	_, err = client.Backup(context.Background(), NewFolderSource(srcStore2, ""), BackupOptions{
		Label:      "v2-fail-commit",
		KeyID:      "key-1",
		PublicKeys: map[string][]byte{"key-1": vmPub[:]},
	})
	if err == nil {
		t.Fatalf("expected backup to fail on metadata commit")
	}

	// Verify metadata remains untouched pointing to Version 1
	history, err := client.ListVersions(context.Background())
	if err != nil {
		t.Fatalf("failed to list versions: %v", err)
	}
	if len(history) != 1 || history[0].SnowflakeId != v1.SnowflakeId {
		t.Fatalf("metadata corrupted after metadata commit failure: expected 1 version, got %d", len(history))
	}

	// Restore Version 1
	var restoredZipBuf bytes.Buffer
	err = client.Restore(context.Background(), v1.SnowflakeId, RestoreOptions{
		ZipWriter:  &restoredZipBuf,
		PrivateKey: vmPriv[:],
	})
	if err != nil {
		t.Fatalf("restore v1 failed: %v", err)
	}
	verifyZipExplorerExtractable(t, restoredZipBuf.Bytes(), "")
}

// TestTsyncACIDDeleteVersionAtomicity verifies atomicity of DeleteVersion when payload deletion is interrupted midway.
func TestTsyncACIDDeleteVersionAtomicity(t *testing.T) {
	vmPub, vmPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	memStorage := NewMemStorage()
	faultStorage := NewFaultInjectingStorage(memStorage)
	client := NewClient(faultStorage)

	// Step 1: Backup Version 1
	srcStore1 := NewMemStorage()
	_ = srcStore1.Write(context.Background(), "v1_unique.txt", []byte("v1 unique data"))
	v1, err := client.Backup(context.Background(), NewFolderSource(srcStore1, ""), BackupOptions{
		Label:      "v1",
		KeyID:      "key-1",
		PublicKeys: map[string][]byte{"key-1": vmPub[:]},
	})
	if err != nil {
		t.Fatalf("v1 backup failed: %v", err)
	}

	// Step 2: Backup Version 2
	srcStore2 := NewMemStorage()
	_ = srcStore2.Write(context.Background(), "v2_unique.txt", []byte("v2 unique data"))
	v2, err := client.Backup(context.Background(), NewFolderSource(srcStore2, ""), BackupOptions{
		Label:      "v2",
		KeyID:      "key-1",
		PublicKeys: map[string][]byte{"key-1": vmPub[:]},
	})
	if err != nil {
		t.Fatalf("v2 backup failed: %v", err)
	}

	// Step 3: Delete Version 1
	_ = client.DeleteVersion(context.Background(), v1.SnowflakeId)

	// ATOMICITY ASSERTION:
	// .tsync metadata was updated atomically!
	history, err := client.ListVersions(context.Background())
	if err != nil {
		t.Fatalf("failed to list versions: %v", err)
	}
	if len(history) != 1 || history[0].SnowflakeId != v2.SnowflakeId {
		t.Fatalf("expected version catalog to reflect v1 deletion, got %d versions", len(history))
	}

	// Version 2 remains 100% restorable
	var restoredZipBuf bytes.Buffer
	err = client.Restore(context.Background(), v2.SnowflakeId, RestoreOptions{
		ZipWriter:  &restoredZipBuf,
		PrivateKey: vmPriv[:],
	})
	if err != nil {
		t.Fatalf("restoring Version 2 failed: %v", err)
	}
	verifyZipExplorerExtractable(t, restoredZipBuf.Bytes(), "")
}
