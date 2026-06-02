package tsync

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	tsyncv1 "github.com/abyii/t-sync-sdk-go/gen/go/com/github/abyii/tsync/v1"

	zip "github.com/abyii/zip-xxh3"
	"golang.org/x/crypto/nacl/box"
	"google.golang.org/protobuf/proto"
)

// ---------------------------------------------------------
// Integration / Full Lifecycle Tests
// ---------------------------------------------------------

func TestTsyncFullLifecycle(t *testing.T) {
	// A. Setup cryptographic key pairs
	vmPub, vmPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}
	publicKeys := map[string][]byte{
		"vm-key-1": vmPub[:],
	}

	// B. Create mock Source storage
	srcStore := NewMemStorage()
	_ = srcStore.Write(context.Background(), "file1.txt", []byte("Hello World, T-Sync Go SDK!"))
	_ = srcStore.Write(context.Background(), "folder/file2.bin", randomBytes(100))
	_ = srcStore.Write(context.Background(), "folder/subfolder/file3.dat", []byte("Deeply nested file"))
	_ = srcStore.Write(context.Background(), "extra1.txt", []byte("extra file 1"))
	_ = srcStore.Write(context.Background(), "extra2.txt", []byte("extra file 2"))
	_ = srcStore.Write(context.Background(), "extra3.txt", []byte("extra file 3"))
	_ = srcStore.Write(context.Background(), "extra4.txt", []byte("extra file 4"))

	folderSrc := NewFolderSource(srcStore, "")

	// Create mock Destination storage
	destStore := NewMemStorage()
	client := NewClient(destStore)

	// 1. Initial Backup (should create FULL version)
	v1, err := client.Backup(context.Background(), folderSrc, BackupOptions{
		Label:       "v1.0.0",
		Concurrency: 2,
		KeyID:       "vm-key-1",
		PublicKeys:  publicKeys,
	})
	if err != nil {
		t.Fatalf("v1 backup failed: %v", err)
	}

	if v1.Kind != tsyncv1.VersionKind_VERSION_KIND_FULL {
		t.Fatalf("expected v1 kind to be FULL, got %v", v1.Kind)
	}

	// Verify that .tsync is present
	exists, _ := destStore.Exists(context.Background(), ".tsync")
	if !exists {
		t.Fatalf(".tsync metadata file was not written to storage")
	}

	// 2. Incremental Backup (modify file1.txt, add file4.txt, delete file3.dat)
	_ = srcStore.Write(context.Background(), "file1.txt", []byte("Modified Hello World!"))
	_ = srcStore.Write(context.Background(), "file4.txt", []byte("Brand new file"))
	_ = srcStore.Delete(context.Background(), "folder/subfolder/file3.dat")

	v2, err := client.Backup(context.Background(), folderSrc, BackupOptions{
		Label:       "v1.1.0-delta",
		Concurrency: 2,
	})
	if err != nil {
		t.Fatalf("v2 incremental backup failed: %v", err)
	}

	if v2.Kind != tsyncv1.VersionKind_VERSION_KIND_DELTA {
		t.Fatalf("expected v2 to be DELTA, got %v", v2.Kind)
	}

	if v2.ParentId != v1.SnowflakeId {
		t.Fatalf("expected v2 parent ID to be %d, got %d", v1.SnowflakeId, v2.ParentId)
	}

	// Check delta contents
	if _, ok := v2.DeltaChanges["file1.txt"]; !ok {
		t.Errorf("expected file1.txt in delta changes")
	}
	if _, ok := v2.DeltaChanges["file4.txt"]; !ok {
		t.Errorf("expected file4.txt in delta changes")
	}
	if len(v2.DeltaDeleted) != 1 || v2.DeltaDeleted[0] != "folder/subfolder/file3.dat" {
		t.Errorf("expected folder/subfolder/file3.dat in delta deletions, got %v", v2.DeltaDeleted)
	}

	// 3. Reconstruct / Restore v2 ZIP File (Unencrypted output)
	var zipBuf bytes.Buffer
	err = client.Restore(context.Background(), v2.SnowflakeId, RestoreOptions{
		ZipWriter:  &zipBuf,
		PrivateKey: vmPriv[:],
	})
	if err != nil {
		t.Fatalf("failed to restore v2 zip: %v", err)
	}

	// Read restored ZIP structure and check contents
	restoredBytes := zipBuf.Bytes()
	zr, err := zip.NewReader(bytes.NewReader(restoredBytes), int64(len(restoredBytes)))
	if err != nil {
		t.Fatalf("failed to parse restored zip: %v", err)
	}

	restoredFiles := make(map[string][]byte)
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("failed to open file %s in restored zip: %v", f.Name, err)
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		restoredFiles[f.Name] = data
	}

	if string(restoredFiles["file1.txt"]) != "Modified Hello World!" {
		t.Errorf("restored file1 content mismatch: got %q", restoredFiles["file1.txt"])
	}
	if string(restoredFiles["file4.txt"]) != "Brand new file" {
		t.Errorf("restored file4 content mismatch")
	}
	if _, exists := restoredFiles["folder/subfolder/file3.dat"]; exists {
		t.Errorf("restored ZIP should not contain deleted file3.dat")
	}

	// 4. Restore v2 with On-the-fly Rekeying (to a new password "newPasswordSec")
	var encZipBuf bytes.Buffer
	err = client.Restore(context.Background(), v2.SnowflakeId, RestoreOptions{
		ZipWriter:   &encZipBuf,
		PrivateKey:  vmPriv[:],
		NewPassword: "newPasswordSec",
	})
	if err != nil {
		t.Fatalf("failed to restore and rekey v2: %v", err)
	}

	encRestoredBytes := encZipBuf.Bytes()
	zrEnc, err := zip.NewReader(bytes.NewReader(encRestoredBytes), int64(len(encRestoredBytes)))
	if err != nil {
		t.Fatalf("failed to parse rekeyed zip: %v", err)
	}

	// Verify that the file is encrypted
	if !zrEnc.File[0].IsEncrypted() {
		t.Fatalf("expected file to be encrypted")
	}

	// Open with password should succeed
	zrEnc.File[0].SetPassword("newPasswordSec")
	rc, err := zrEnc.File[0].Open()
	if err != nil {
		t.Fatalf("failed to open file with new password: %v", err)
	}
	rc.Close()

	// 5. Restore with skip decryption errors
	// Inject a corrupted FileRecord with bad keys to simulate a corruption
	metadataBytes, _ := destStore.Read(context.Background(), ".tsync")
	var corruptMetadata tsyncv1.BackupMetadata
	_ = proto.Unmarshal(metadataBytes, &corruptMetadata)

	// Corrupt file4.txt's record
	for k, r := range corruptMetadata.Files {
		// Find key for file4
		if r.UncompressedSize == int64(len("Brand new file")) {
			// Corrupt the encrypted zip password
			r.EncryptedZipPassword = []byte("corrupted password data")
			corruptMetadata.Files[k] = r
			break
		}
	}
	corruptBytes, _ := proto.Marshal(&corruptMetadata)
	_ = destStore.Write(context.Background(), ".tsync", corruptBytes)

	// Attempt restore without skip flag -> should fail
	var failedBuf bytes.Buffer
	err = client.Restore(context.Background(), v2.SnowflakeId, RestoreOptions{
		ZipWriter:            &failedBuf,
		PrivateKey:           vmPriv[:],
		SkipDecryptionErrors: false,
	})
	if err == nil {
		t.Fatalf("restore should have failed due to decryption error")
	}

	// Attempt restore with skip flag -> should succeed (skipping file4.txt)
	var skipBuf bytes.Buffer
	err = client.Restore(context.Background(), v2.SnowflakeId, RestoreOptions{
		ZipWriter:            &skipBuf,
		PrivateKey:           vmPriv[:],
		SkipDecryptionErrors: true,
	})
	if err != nil {
		t.Fatalf("restore with SkipDecryptionErrors failed: %v", err)
	}

	// 6. Delete Version (with delta promotion test)
	// Reset correct metadata
	_ = destStore.Write(context.Background(), ".tsync", metadataBytes)

	// Delete parent v1. Version v2 (which is delta) should be promoted to FULL.
	err = client.DeleteVersion(context.Background(), v1.SnowflakeId)
	if err != nil {
		t.Fatalf("failed to delete version v1: %v", err)
	}

	// Load updated metadata
	pbBytes, _ := destStore.Read(context.Background(), ".tsync")
	var updatedMetadata tsyncv1.BackupMetadata
	_ = proto.Unmarshal(pbBytes, &updatedMetadata)

	if _, exists := updatedMetadata.Versions[strconv.FormatUint(v1.SnowflakeId, 10)]; exists {
		t.Fatalf("version v1 was not deleted from metadata")
	}

	v2Updated := updatedMetadata.Versions[strconv.FormatUint(v2.SnowflakeId, 10)]
	if v2Updated == nil {
		t.Fatalf("version v2 was deleted unexpectedly")
	}

	if v2Updated.Kind != tsyncv1.VersionKind_VERSION_KIND_FULL {
		t.Fatalf("expected delta version v2 to be promoted to FULL, but got kind %v", v2Updated.Kind)
	}

	if len(v2Updated.PathToFileKey) == 0 {
		t.Fatalf("promoted version v2 path map is empty")
	}

	// 7. Single Version Mode Test
	// Add one more file to source
	_ = srcStore.Write(context.Background(), "file5.txt", []byte("Single version mode file"))

	// Record existing keys in destStore
	existingDestFiles, _ := destStore.List(context.Background(), "")
	existingPartCount := 0
	for _, f := range existingDestFiles {
		if f.Name != ".tsync" {
			existingPartCount++
		}
	}

	v3, err := client.Backup(context.Background(), folderSrc, BackupOptions{
		Label:             "single-version-run",
		SingleVersionMode: true,
	})
	if err != nil {
		t.Fatalf("single version backup failed: %v", err)
	}

	// Load updated metadata
	pbBytes, _ = destStore.Read(context.Background(), ".tsync")
	var singleMetadata tsyncv1.BackupMetadata
	_ = proto.Unmarshal(pbBytes, &singleMetadata)

	if len(singleMetadata.Versions) != 1 {
		t.Fatalf("expected exactly 1 version in single version mode, got %d", len(singleMetadata.Versions))
	}

	v3Metadata := singleMetadata.Versions[strconv.FormatUint(v3.SnowflakeId, 10)]
	if v3Metadata == nil {
		t.Fatalf("newly created version v3 was not found")
	}

	// Verify orphans are deleted from storage
	destFilesAfter, _ := destStore.List(context.Background(), "")
	partCountAfter := 0
	for _, f := range destFilesAfter {
		if f.Name != ".tsync" {
			partCountAfter++
		}
	}

	// The store should only contain part files referenced by v3
	expectedPartCount := len(v3Metadata.PathToFileKey)
	if partCountAfter != expectedPartCount {
		t.Fatalf("expected %d file parts in storage after single version run, got %d", expectedPartCount, partCountAfter)
	}

	// 8. Storage GC Test
	// Write a fake orphaned file part to destStore
	fakeOrphanKey := "aa/aabbccdd_555"
	_ = destStore.Write(context.Background(), fakeOrphanKey, []byte("fake part data"))

	// Verify orphan exists
	exists, _ = destStore.Exists(context.Background(), fakeOrphanKey)
	if !exists {
		t.Fatalf("fake orphan part was not written")
	}

	// Run GC
	err = client.GC(context.Background())
	if err != nil {
		t.Fatalf("GC run failed: %v", err)
	}

	// Verify orphan is gone
	exists, _ = destStore.Exists(context.Background(), fakeOrphanKey)
	if exists {
		t.Fatalf("orphaned part was not cleaned up by GC")
	}
}

func TestTsyncRestoreOptions(t *testing.T) {
	// Setup keys
	vmPub, vmPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	srcStore := NewMemStorage()
	_ = srcStore.Write(context.Background(), "file_to_restore.txt", []byte("Restore options verification content"))
	_ = srcStore.Write(context.Background(), "another.txt", []byte("second file content"))

	destStore := NewMemStorage()
	client := NewClient(destStore)

	// Backup
	v, err := client.Backup(context.Background(), NewFolderSource(srcStore, ""), BackupOptions{
		Label:      "v1",
		KeyID:      "key-1",
		PublicKeys: map[string][]byte{"key-1": vmPub[:]},
	})
	if err != nil {
		t.Fatalf("backup failed: %v", err)
	}

	// Create temp directory for extraction
	tmpDir, err := os.MkdirTemp("", "tsync-extract-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// 1. Test parallel extraction to directory (ExtractDir)
	err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
		ExtractDir:  tmpDir,
		PrivateKey:  vmPriv[:],
		Concurrency: 4,
	})
	if err != nil {
		t.Fatalf("restore with parallel extraction failed: %v", err)
	}

	restoredPath := filepath.Join(tmpDir, "file_to_restore.txt")
	content, err := os.ReadFile(restoredPath)
	if err != nil {
		t.Fatalf("failed to read restored file: %v", err)
	}
	if string(content) != "Restore options verification content" {
		t.Errorf("expected 'Restore options verification content', got %q", string(content))
	}

	// 2. Test incremental restore (no overwrite on identical files)
	fiBefore, err := os.Stat(restoredPath)
	if err != nil {
		t.Fatalf("failed to stat: %v", err)
	}
	modTimeBefore := fiBefore.ModTime()

	// Wait briefly to make sure mod time difference can be detected if modified
	time.Sleep(10 * time.Millisecond)

	// Restore again. Since files are identical (size and CRC32 match), it should skip and NOT update mod time.
	err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
		ExtractDir:  tmpDir,
		PrivateKey:  vmPriv[:],
		Concurrency: 2,
	})
	if err != nil {
		t.Fatalf("second restore failed: %v", err)
	}

	fiAfter, err := os.Stat(restoredPath)
	if err != nil {
		t.Fatalf("failed to stat after second restore: %v", err)
	}
	if !fiAfter.ModTime().Equal(modTimeBefore) {
		t.Errorf("expected identical file to not be rewritten, but mod time changed")
	}

	// 3. Modify a file at destination (change content but keep same size)
	// Changing content but keeping same size to verify CRC32 check works correctly
	_ = os.WriteFile(restoredPath, []byte("Restore options verif_cation content"), 0644)

	// Set a very old mod time to verify it actually gets updated/overwritten
	oldTime := time.Now().Add(-10 * time.Hour)
	_ = os.Chtimes(restoredPath, oldTime, oldTime)

	// Restore again. Since CRC32 differs, it must overwrite.
	err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
		ExtractDir: tmpDir,
		PrivateKey: vmPriv[:],
	})
	if err != nil {
		t.Fatalf("restore after CRC32 mismatch failed: %v", err)
	}

	fiCrcModified, err := os.Stat(restoredPath)
	if err != nil {
		t.Fatalf("failed to stat: %v", err)
	}
	if fiCrcModified.ModTime().Equal(oldTime) {
		t.Errorf("expected file with CRC32 mismatch to be overwritten, but it was skipped")
	}

	// Verify content was restored correctly
	newContent, _ := os.ReadFile(restoredPath)
	if string(newContent) != "Restore options verification content" {
		t.Errorf("content was not restored correctly: %q", string(newContent))
	}

	// 4. Test NoOverwrite = true
	// Modify content of the restored file again
	_ = os.WriteFile(restoredPath, []byte("manually modified content"), 0644)
	oldTime2 := time.Now().Add(-5 * time.Hour)
	_ = os.Chtimes(restoredPath, oldTime2, oldTime2)

	// Restore with NoOverwrite = true. It should skip the file even though it's modified.
	err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
		ExtractDir:  tmpDir,
		PrivateKey:  vmPriv[:],
		NoOverwrite: true,
	})
	if err != nil {
		t.Fatalf("restore with NoOverwrite failed: %v", err)
	}

	// Verify the manual modification is still there and mod time is not updated
	fiNoOverwrite, err := os.Stat(restoredPath)
	if err != nil {
		t.Fatalf("failed to stat: %v", err)
	}
	if !fiNoOverwrite.ModTime().Equal(oldTime2) {
		t.Errorf("expected file to be skipped by NoOverwrite, but mod time changed")
	}
	noOverwrittenContent, _ := os.ReadFile(restoredPath)
	if string(noOverwrittenContent) != "manually modified content" {
		t.Errorf("expected manual modification to remain, got %q", string(noOverwrittenContent))
	}
}

func TestTsyncEncryptedZipSource(t *testing.T) {
	// A. Setup key pairs
	vmPub, vmPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	// B. Create an encrypted ZIP file in srcStore using standard zip writer
	srcStore := NewMemStorage()
	var zipBuf bytes.Buffer
	zipw := zip.NewWriter(&zipBuf)

	// Generate random password
	clearZipPass, err := GenerateZipCryptoPassword()
	if err != nil {
		t.Fatalf("failed to generate password: %v", err)
	}

	// Create dynamic public ephemeral key for this backup pass
	ephPub, encPass, err := EncryptPassword(clearZipPass, vmPub[:])
	if err != nil {
		t.Fatalf("failed to encrypt password: %v", err)
	}

	// Add file to ZIP with encryption
	w, err := zipw.Create("secret.txt", zip.Deflate, -1, zip.StandardEncryption, clearZipPass)
	if err != nil {
		t.Fatalf("failed to create zip header: %v", err)
	}
	_, _ = w.Write([]byte("top secret data payload"))
	_ = zipw.Close()

	// Write ZIP file to source storage
	zipPath := "encrypted-archive.zip"
	_ = srcStore.Write(context.Background(), zipPath, zipBuf.Bytes())

	// Create ZipFileSource with isEncrypted = true (Case A)
	zipSrc := NewZipFileSource(srcStore, zipPath, true)

	// Backup
	destStore := NewMemStorage()
	client := NewClient(destStore)
	v, err := client.Backup(context.Background(), zipSrc, BackupOptions{
		Label:             "encrypted-zip-run",
		KeyID:             "key-1",
		PublicKeys:        map[string][]byte{"key-1": vmPub[:]},
		EphPublicKey:      ephPub,
		EncryptedPassword: encPass,
	})
	if err != nil {
		t.Fatalf("backup from encrypted zip source failed: %v", err)
	}

	// Restore and reconstruct to ZIP
	var restoreZipBuf bytes.Buffer
	err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
		ZipWriter:  &restoreZipBuf,
		PrivateKey: vmPriv[:],
	})
	if err != nil {
		t.Fatalf("restore failed: %v", err)
	}

	// Parse restored ZIP and verify content
	zr, err := zip.NewReader(bytes.NewReader(restoreZipBuf.Bytes()), int64(restoreZipBuf.Len()))
	if err != nil {
		t.Fatalf("failed to read restored zip: %v", err)
	}
	if len(zr.File) != 1 || zr.File[0].Name != "secret.txt" {
		t.Fatalf("restored zip file structure mismatch")
	}

	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatalf("failed to open restored file: %v", err)
	}
	data, _ := io.ReadAll(rc)
	rc.Close()

	if string(data) != "top secret data payload" {
		t.Errorf("expected 'top secret data payload', got %q", string(data))
	}
}
