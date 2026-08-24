package tsync

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"testing"

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
