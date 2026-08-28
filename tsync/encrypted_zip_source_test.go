package tsync

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	zip "github.com/abyii/zip-xxh3"
	"golang.org/x/crypto/nacl/box"
)

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

	verifyZipExplorerExtractable(t, restoreZipBuf.Bytes(), "")

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

func TestTsyncEncryptedZipSourceWithLeadingDirectory(t *testing.T) {
	vmPub, vmPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	srcStore := NewMemStorage()
	var zipBuf bytes.Buffer
	zipw := zip.NewWriter(&zipBuf)

	clearZipPass, err := GenerateZipCryptoPassword()
	if err != nil {
		t.Fatalf("failed to generate password: %v", err)
	}

	ephPub, encPass, err := EncryptPassword(clearZipPass, vmPub[:])
	if err != nil {
		t.Fatalf("failed to encrypt password: %v", err)
	}

	// 1. Add an empty directory FIRST in the ZIP archive
	_, err = zipw.Create("TestData/", zip.Store, 0, zip.NoEncryption, "")
	if err != nil {
		t.Fatalf("failed to create dir header: %v", err)
	}

	// 2. Add an encrypted file AFTER the directory
	w, err := zipw.Create("TestData/secret.txt", zip.Deflate, -1, zip.StandardEncryption, clearZipPass)
	if err != nil {
		t.Fatalf("failed to create zip header: %v", err)
	}
	_, _ = w.Write([]byte("encrypted data with leading dir"))
	_ = zipw.Close()

	zipPath := "encrypted-leading-dir.zip"
	_ = srcStore.Write(context.Background(), zipPath, zipBuf.Bytes())

	zipSrc := NewZipFileSource(srcStore, zipPath, true)
	destStore := NewMemStorage()
	client := NewClient(destStore)

	v, err := client.Backup(context.Background(), zipSrc, BackupOptions{
		Label:             "encrypted-leading-dir-run",
		KeyID:             "key-1",
		PublicKeys:        map[string][]byte{"key-1": vmPub[:]},
		EphPublicKey:      ephPub,
		EncryptedPassword: encPass,
	})
	if err != nil {
		t.Fatalf("backup failed: %v", err)
	}

	// Restore and reconstruct to ZIP with NewPassword = "restored_pass"
	var restoreZipBuf bytes.Buffer
	err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
		ZipWriter:   &restoreZipBuf,
		PrivateKey:  vmPriv[:],
		NewPassword: "restored_pass",
	})
	if err != nil {
		t.Fatalf("restore failed: %v", err)
	}

	verifyZipExplorerExtractable(t, restoreZipBuf.Bytes(), "restored_pass")

	zr, err := zip.NewReader(bytes.NewReader(restoreZipBuf.Bytes()), int64(restoreZipBuf.Len()))
	if err != nil {
		t.Fatalf("failed to read restored zip: %v", err)
	}

	foundFile := false
	for _, f := range zr.File {
		if f.Name == "TestData/secret.txt" {
			foundFile = true
			f.SetPassword("restored_pass")
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("failed to open restored file with restored_pass: %v", err)
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatalf("failed to read restored content: %v", err)
			}
			if string(data) != "encrypted data with leading dir" {
				t.Errorf("content mismatch: got %q", string(data))
			}
		}
	}
	if !foundFile {
		t.Fatalf("TestData/secret.txt not found in restored ZIP")
	}
}

func TestTsyncMultipleEncryptedZipSourcesWithDifferentPasswords(t *testing.T) {
	vmPub, vmPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	destStore := NewMemStorage()
	client := NewClient(destStore)

	// Track active files and directories at each incremental step
	currentFiles := make(map[string]string)
	currentDirs := make(map[string]bool)

	const totalSteps = 9
	for step := 1; step <= totalSteps; step++ {
		srcStore := NewMemStorage()
		var zipBuf bytes.Buffer
		zipw := zip.NewWriter(&zipBuf)

		// Each step uses a unique PKWARE password
		stepPass := fmt.Sprintf("pass_source_step_%d_%d", step, time.Now().UnixNano())
		ephPub, encPass, err := EncryptPassword(stepPass, vmPub[:])
		if err != nil {
			t.Fatalf("step %d: failed to encrypt password: %v", step, err)
		}

		// 1. ADD PERSISTENT FILE (added once at this step with stepPass, never deleted)
		persistentFile := fmt.Sprintf("persistent_file_step_%d.txt", step)
		currentFiles[persistentFile] = fmt.Sprintf("persistent data created at step %d with pass %s", step, stepPass)

		// 2. MODIFY SHARED FILE
		currentFiles["shared_mutated_file.txt"] = fmt.Sprintf("content of shared_mutated_file updated at step %d", step)

		// 3. ADD TEMPORARY FILE (added at this step, deleted at next step)
		tempFile := fmt.Sprintf("temp_file_step_%d.txt", step)
		currentFiles[tempFile] = fmt.Sprintf("temporary data for step %d", step)

		// 4. DELETE TEMPORARY FILE FROM PREVIOUS STEP
		if step > 1 {
			prevTempFile := fmt.Sprintf("temp_file_step_%d.txt", step-1)
			delete(currentFiles, prevTempFile)
		}

		// 5. ADD PERSISTENT & TEMPORARY EMPTY DIRECTORIES
		currentDirs[fmt.Sprintf("persistent_dir_step_%d/", step)] = true
		currentDirs[fmt.Sprintf("temp_dir_step_%d/", step)] = true
		if step > 1 {
			delete(currentDirs, fmt.Sprintf("temp_dir_step_%d/", step-1))
		}

		// Write empty directories into source ZIP first
		for dirName := range currentDirs {
			_, err = zipw.Create(dirName, zip.Store, 0, zip.NoEncryption, "")
			if err != nil {
				t.Fatalf("step %d: failed to create empty dir entry %s: %v", step, dirName, err)
			}
		}

		// Write all current active files into the source ZIP for this step
		for name, content := range currentFiles {
			w, err := zipw.Create(name, zip.Deflate, -1, zip.StandardEncryption, stepPass)
			if err != nil {
				t.Fatalf("step %d: failed to create zip entry %s: %v", step, name, err)
			}
			_, _ = w.Write([]byte(content))
		}
		_ = zipw.Close()

		zipPath := fmt.Sprintf("src_step_%d.zip", step)
		_ = srcStore.Write(context.Background(), zipPath, zipBuf.Bytes())

		// Perform Backup
		v, err := client.Backup(context.Background(), NewZipFileSource(srcStore, zipPath, true), BackupOptions{
			Label:             fmt.Sprintf("v-step-%d", step),
			KeyID:             "key-1",
			PublicKeys:        map[string][]byte{"key-1": vmPub[:]},
			EphPublicKey:      ephPub,
			EncryptedPassword: encPass,
		})
		if err != nil {
			t.Fatalf("step %d: backup failed: %v", step, err)
		}

		// Perform Restore to Rekeyed ZIP
		rekeyPass := fmt.Sprintf("rekey_pass_step_%d", step)
		var restoredZipBuf bytes.Buffer
		err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
			ZipWriter:   &restoredZipBuf,
			PrivateKey:  vmPriv[:],
			NewPassword: rekeyPass,
		})
		if err != nil {
			t.Fatalf("step %d: restore to rekeyed ZIP failed: %v", step, err)
		}

		// Verification 1: Windows Explorer Extractability Check
		verifyZipExplorerExtractable(t, restoredZipBuf.Bytes(), rekeyPass)

		// Verification 2: Programmatic Decryption & Content/Directory Assertion
		zr, err := zip.NewReader(bytes.NewReader(restoredZipBuf.Bytes()), int64(restoredZipBuf.Len()))
		if err != nil {
			t.Fatalf("step %d: failed to parse restored zip: %v", step, err)
		}

		restoredFiles := make(map[string]string)
		restoredDirs := make(map[string]bool)

		for _, f := range zr.File {
			if strings.HasSuffix(f.Name, "/") {
				restoredDirs[f.Name] = true
				continue
			}
			f.SetPassword(rekeyPass)
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("step %d: failed to open %s with rekeyed pass: %v", step, f.Name, err)
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatalf("step %d: failed to read content of %s: %v", step, f.Name, err)
			}
			restoredFiles[f.Name] = string(data)
		}

		// Assert file count and content
		if len(restoredFiles) != len(currentFiles) {
			t.Fatalf("step %d: file count mismatch: expected %d, got %d", step, len(currentFiles), len(restoredFiles))
		}
		for name, expectedContent := range currentFiles {
			gotContent, exists := restoredFiles[name]
			if !exists {
				t.Fatalf("step %d: expected file %s missing in restored ZIP", step, name)
			}
			if gotContent != expectedContent {
				t.Fatalf("step %d: content mismatch for %s: expected %q, got %q", step, name, expectedContent, gotContent)
			}
		}

		// Assert directory count and existence
		if len(restoredDirs) != len(currentDirs) {
			t.Fatalf("step %d: dir count mismatch: expected %d, got %d", step, len(currentDirs), len(restoredDirs))
		}
		for dirName := range currentDirs {
			if !restoredDirs[dirName] {
				t.Fatalf("step %d: expected directory %s missing in restored ZIP", step, dirName)
			}
		}
	}
}




