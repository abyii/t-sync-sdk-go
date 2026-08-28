package tsync

import (
	"bytes"
	"context"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestTsyncValidationOptions_RSA_PublicKey_Rejected(t *testing.T) {
	store := NewMemStorage()
	client := NewClient(store)

	srcStore := NewMemStorage()
	_ = srcStore.Write(context.Background(), "file.txt", []byte("hello"))

	// 256-byte dummy RSA key (2048-bit key)
	rsa2048PubKey := make([]byte, 256)
	_, _ = rand.Read(rsa2048PubKey)

	_, err := client.Backup(context.Background(), NewFolderSource(srcStore, ""), BackupOptions{
		Label:      "rsa-test",
		KeyID:      "key-1",
		PublicKeys: map[string][]byte{"key-1": rsa2048PubKey},
	})

	if err == nil {
		t.Fatalf("expected Backup to reject 256-byte RSA public key, but got nil error")
	}

	if !strings.Contains(err.Error(), "expected 32 bytes") {
		t.Fatalf("expected error message to mention 'expected 32 bytes', got: %v", err)
	}
}

func TestTsyncValidationOptions_RSA_EphPublicKey_Rejected(t *testing.T) {
	vmPub, _, _ := box.GenerateKey(rand.Reader)
	store := NewMemStorage()
	client := NewClient(store)

	srcStore := NewMemStorage()
	_ = srcStore.Write(context.Background(), "file.txt", []byte("hello"))

	rsa2048EphKey := make([]byte, 256)
	dummyEncPass := make([]byte, 48)

	_, err := client.Backup(context.Background(), NewFolderSource(srcStore, ""), BackupOptions{
		Label:             "rsa-eph-test",
		KeyID:             "key-1",
		PublicKeys:        map[string][]byte{"key-1": vmPub[:]},
		EphPublicKey:      rsa2048EphKey,
		EncryptedPassword: dummyEncPass,
	})

	if err == nil {
		t.Fatalf("expected Backup to reject 256-byte EphPublicKey, but got nil error")
	}

	if !strings.Contains(err.Error(), "expected 32 bytes") {
		t.Fatalf("expected error to mention 'expected 32 bytes', got: %v", err)
	}
}

func TestTsyncValidationOptions_Invalid_EncryptedPassword_Rejected(t *testing.T) {
	vmPub, _, _ := box.GenerateKey(rand.Reader)
	store := NewMemStorage()
	client := NewClient(store)

	srcStore := NewMemStorage()
	_ = srcStore.Write(context.Background(), "file.txt", []byte("hello"))

	validEphKey := make([]byte, 32)
	shortEncPass := make([]byte, 20) // < 40 bytes requirement

	_, err := client.Backup(context.Background(), NewFolderSource(srcStore, ""), BackupOptions{
		Label:             "short-pass-test",
		KeyID:             "key-1",
		PublicKeys:        map[string][]byte{"key-1": vmPub[:]},
		EphPublicKey:      validEphKey,
		EncryptedPassword: shortEncPass,
	})

	if err == nil {
		t.Fatalf("expected Backup to reject short EncryptedPassword (< 40 bytes), but got nil error")
	}

	if !strings.Contains(err.Error(), "at least 40 bytes") {
		t.Fatalf("expected error to mention 'at least 40 bytes', got: %v", err)
	}
}

func TestTsyncValidationOptions_Invalid_CompressionLevel_Rejected(t *testing.T) {
	vmPub, _, _ := box.GenerateKey(rand.Reader)
	store := NewMemStorage()
	client := NewClient(store)

	srcStore := NewMemStorage()
	_ = srcStore.Write(context.Background(), "file.txt", []byte("hello"))

	invalidLevel := 10
	_, err := client.Backup(context.Background(), NewFolderSource(srcStore, ""), BackupOptions{
		Label:            "invalid-comp-test",
		KeyID:            "key-1",
		PublicKeys:       map[string][]byte{"key-1": vmPub[:]},
		CompressionLevel: &invalidLevel,
	})

	if err == nil {
		t.Fatalf("expected Backup to reject invalid compression level 10, but got nil error")
	}

	if !strings.Contains(err.Error(), "between -1 and 9") {
		t.Fatalf("expected error to mention 'between -1 and 9', got: %v", err)
	}
}

func TestTsyncValidationOptions_RSA_PrivateKey_Rejected(t *testing.T) {
	store := NewMemStorage()
	client := NewClient(store)

	rsa2048PrivKey := make([]byte, 256)
	var restoredZipBuf bytes.Buffer

	err := client.Restore(context.Background(), 1000, RestoreOptions{
		ZipWriter:  &restoredZipBuf,
		PrivateKey: rsa2048PrivKey,
	})

	if err == nil {
		t.Fatalf("expected Restore to reject 256-byte RSA private key, but got nil error")
	}

	if !strings.Contains(err.Error(), "expected 32 bytes") {
		t.Fatalf("expected error to mention 'expected 32 bytes', got: %v", err)
	}
}

func TestTsyncValidationOptions_Missing_RestoreDestination_Rejected(t *testing.T) {
	store := NewMemStorage()
	client := NewClient(store)

	err := client.Restore(context.Background(), 1000, RestoreOptions{})

	if err == nil {
		t.Fatalf("expected Restore to fail when neither ZipWriter nor ExtractDir is set, but got nil error")
	}

	if !strings.Contains(err.Error(), "either ZipWriter or ExtractDir must be set") {
		t.Fatalf("expected error to mention 'either ZipWriter or ExtractDir must be set', got: %v", err)
	}
}
