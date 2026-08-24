package tsync

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

func verifyZipExplorerExtractable(t *testing.T, zipBytes []byte, password string) {
	t.Helper()

	if len(zipBytes) == 0 {
		t.Fatalf("verifyZipExplorerExtractable: zipBytes is empty")
	}

	// 1. Verify standard ZIP structure with Go abyii/zip-xxh3
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("verifyZipExplorerExtractable: failed to parse ZIP structure: %v", err)
	}

	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if password != "" {
			if !f.IsEncrypted() {
				t.Errorf("verifyZipExplorerExtractable: file %s expected to be encrypted, but is not", f.Name)
			}
			f.SetPassword(password)
		}
		rc, err := f.Open()
		if err != nil {
			t.Errorf("verifyZipExplorerExtractable: failed to open file %s: %v", f.Name, err)
			continue
		}
		data, readErr := io.ReadAll(rc)
		rc.Close()
		if readErr != nil {
			t.Errorf("verifyZipExplorerExtractable: failed to read/decompress file %s: %v", f.Name, readErr)
		} else if f.UncompressedSize64 > 0 && len(data) == 0 {
			t.Errorf("verifyZipExplorerExtractable: file %s extracted 0 bytes, expected %d", f.Name, f.UncompressedSize64)
		}
	}

	// 2. On Windows OS, execute native PowerShell Expand-Archive for unencrypted ZIPs in standard unit tests.
	// Skip external powershell.exe process spawning during high-frequency parallel fuzzing to avoid OS handle exhaustion.
	if runtime.GOOS == "windows" && password == "" && !strings.HasPrefix(t.Name(), "Fuzz") {
		tmpZip, err := os.CreateTemp("", "tsync-verify-win-*.zip")
		if err == nil {
			_, _ = tmpZip.Write(zipBytes)
			tmpZip.Close()
			defer os.Remove(tmpZip.Name())

			destDir, err := os.MkdirTemp("", "tsync-verify-win-extract-*")
			if err == nil {
				defer os.RemoveAll(destDir)

				psCmd := fmt.Sprintf("Expand-Archive -Path '%s' -DestinationPath '%s' -Force", tmpZip.Name(), destDir)
				cmd := exec.Command("powershell", "-Command", psCmd)
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Errorf("verifyZipExplorerExtractable: Windows PowerShell Expand-Archive failed: %v\nOutput: %s", err, string(out))
				}
			}
		}
	}
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

	v2Map, _, err := ResolveVersionTree(&metadata, v2.SnowflakeId, false)
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

	// Verify Windows Explorer extractability & ZIP validity
	verifyZipExplorerExtractable(t, zipBuf.Bytes(), "")

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

	verifyZipExplorerExtractable(t, encZipBuf.Bytes(), "newPasswordSec")

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
	rawMetadataBytes, _ := destStore.Read(context.Background(), ".tsync")
	metadataBytes := append([]byte(nil), rawMetadataBytes...)
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
	v2MapAfterDelete, _, err := ResolveVersionTree(&updatedMetadata, v2.SnowflakeId, false)
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
	v3Map, _, err := ResolveVersionTree(&singleMetadata, v3.SnowflakeId, false)
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
