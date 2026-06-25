package tsync

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	tsyncv2 "github.com/abyii/t-sync-sdk-go/v2/gen/go/com/github/abyii/tsync/v2"

	zip "github.com/abyii/zip-xxh3"
	"golang.org/x/crypto/nacl/box"
	"google.golang.org/protobuf/proto"
)

func intPtr(val int) *int {
	return &val
}

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
	_ = srcStore.Write(context.Background(), "folder/subfolder/.gitkeep", []byte(""))
	_ = srcStore.Write(context.Background(), "extra1.txt", []byte("extra file 1"))
	_ = srcStore.Write(context.Background(), "extra2.txt", []byte("extra file 2"))
	_ = srcStore.Write(context.Background(), "extra3.txt", []byte("extra file 3"))
	_ = srcStore.Write(context.Background(), "extra4.txt", []byte("extra file 4"))

	folderSrc := NewFolderSource(srcStore, "")

	// Create mock Destination storage
	destStore := NewMemStorage()
	client := NewClient(destStore)

	// 1. Initial Backup
	v1, err := client.Backup(context.Background(), folderSrc, BackupOptions{
		Label:       "v1.0.0",
		Concurrency: 2,
		KeyID:       "vm-key-1",
		PublicKeys:  publicKeys,
	})
	if err != nil {
		t.Fatalf("v1 backup failed: %v", err)
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
		t.Fatalf("v2 backup failed: %v", err)
	}

	if v2.PrecedingVersionId != v1.SnowflakeId {
		t.Fatalf("expected v2 preceding version ID to be %d, got %d", v1.SnowflakeId, v2.PrecedingVersionId)
	}

	// Read metadata to check v2 resolved map
	pbBytes, _ := destStore.Read(context.Background(), ".tsync")
	var metadata tsyncv2.BackupMetadata
	_ = proto.Unmarshal(pbBytes, &metadata)

	v2Map, err := ResolveVersionMap(&metadata, v2.SnowflakeId)
	if err != nil {
		t.Fatalf("failed to resolve v2 map: %v", err)
	}

	if _, ok := v2Map["file1.txt"]; !ok {
		t.Errorf("expected file1.txt in resolved v2 map")
	}
	if _, ok := v2Map["file4.txt"]; !ok {
		t.Errorf("expected file4.txt in resolved v2 map")
	}
	if _, exists := v2Map["folder/subfolder/file3.dat"]; exists {
		t.Errorf("resolved v2 map should not contain deleted file3.dat")
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

	// Open all files with password should succeed (including 0-byte .gitkeep)
	for _, ef := range zrEnc.File {
		if !ef.IsEncrypted() {
			t.Fatalf("expected all files in rekeyed zip to be encrypted, but %s was not", ef.Name)
		}
		ef.SetPassword("newPasswordSec")
		rc, err := ef.Open()
		if err != nil {
			t.Fatalf("failed to open file %s with new password: %v", ef.Name, err)
		}
		rc.Close()
	}

	// 5. Restore with skip decryption errors
	// Inject a corrupted FileRecord with bad keys to simulate a corruption
	metadataBytes, _ := destStore.Read(context.Background(), ".tsync")
	var corruptMetadata tsyncv2.BackupMetadata
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

	// 6. Delete Version
	// Reset correct metadata
	_ = destStore.Write(context.Background(), ".tsync", metadataBytes)

	// Delete version v1
	err = client.DeleteVersion(context.Background(), v1.SnowflakeId)
	if err != nil {
		t.Fatalf("failed to delete version v1: %v", err)
	}

	// Load updated metadata
	pbBytes, _ = destStore.Read(context.Background(), ".tsync")
	var updatedMetadata tsyncv2.BackupMetadata
	_ = proto.Unmarshal(pbBytes, &updatedMetadata)

	if _, exists := updatedMetadata.Versions[strconv.FormatUint(v1.SnowflakeId, 10)]; exists {
		t.Fatalf("version v1 was not deleted from metadata")
	}

	v2Updated := updatedMetadata.Versions[strconv.FormatUint(v2.SnowflakeId, 10)]
	if v2Updated == nil {
		t.Fatalf("version v2 was deleted unexpectedly")
	}

	// Verify we can still resolve v2 successfully
	v2MapAfterDelete, err := ResolveVersionMap(&updatedMetadata, v2.SnowflakeId)
	if err != nil {
		t.Fatalf("failed to resolve version v2 after deleting v1: %v", err)
	}
	if len(v2MapAfterDelete) == 0 {
		t.Fatalf("resolved version v2 map is empty")
	}

	// 7. Single Version Mode Test
	// Add one more file to source
	_ = srcStore.Write(context.Background(), "file5.txt", []byte("Single version mode file"))

	v3, err := client.Backup(context.Background(), folderSrc, BackupOptions{
		Label:             "single-version-run",
		SingleVersionMode: true,
	})
	if err != nil {
		t.Fatalf("single version backup failed: %v", err)
	}

	// Load updated metadata
	pbBytes, _ = destStore.Read(context.Background(), ".tsync")
	var singleMetadata tsyncv2.BackupMetadata
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
	v3Map, err := ResolveVersionMap(&singleMetadata, v3.SnowflakeId)
	if err != nil {
		t.Fatalf("failed to resolve v3 map: %v", err)
	}
	expectedPartCount := len(v3Map)
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

	// Create ZipFileSource with isEncrypted = true
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

	// Callback:
	// - Returns 0 (Store) for .png
	// - Returns 9 (Deflate Level 9) for .txt
	// - Returns nil (fallback) for .dat (which should fallback to global CompressionLevel = 1)
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

	resolvedMap, err := ResolveVersionMap(sm.metadata, v.SnowflakeId)
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

type mockSource struct {
	entries []SourceEntry
}

func (m *mockSource) ListEntries(ctx context.Context) ([]SourceEntry, error) {
	return m.entries, nil
}

func TestTsyncSkipDirectoryEntries(t *testing.T) {
	vmPub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	mockSrc := &mockSource{
		entries: []SourceEntry{
			{
				Path: "folder/", // explicit directory node
				Size: 0,
			},
			{
				Path: "folder/file.txt",
				Size: 12,
				Open: func() (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader("hello world!")), nil
				},
			},
		},
	}

	destStore := NewMemStorage()
	client := NewClient(destStore)

	v, err := client.Backup(context.Background(), mockSrc, BackupOptions{
		Label:      "skip-dirs-run",
		KeyID:      "key-1",
		PublicKeys: map[string][]byte{"key-1": vmPub[:]},
	})
	if err != nil {
		t.Fatalf("backup failed: %v", err)
	}

	// Verify that the backup succeeded and has version ID
	if v.SnowflakeId == 0 {
		t.Errorf("expected non-zero SnowflakeId")
	}

	// Verify only "folder/file.txt" is registered in metadata files pool
	sm, err := client.ReadMetadata(context.Background())
	if err != nil {
		t.Fatalf("failed to read metadata: %v", err)
	}

	filesMap := sm.Files()
	if len(filesMap) != 1 {
		t.Errorf("expected exactly 1 file record, got %d", len(filesMap))
	}
}

