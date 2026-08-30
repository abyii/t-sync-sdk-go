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

// ---------------------------------------------------------
// 1. Encrypted Zip64 Source Backup -> Encrypted Zip64 Restore Test
// ---------------------------------------------------------

func TestTsyncEncryptedZip64SourceToEncryptedZip64Restore(t *testing.T) {
	vmPub, vmPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	srcPass := "zip64_source_pass_123"
	ephPub, encPass, err := EncryptPassword(srcPass, vmPub[:])
	if err != nil {
		t.Fatalf("failed to encrypt password: %v", err)
	}

	// Construct an Encrypted Zip64 source containing 64-bit size headers
	var srcZipBuf bytes.Buffer
	zipw := zip.NewWriter(&srcZipBuf)

	fhZip64File := &zip.FileHeader{
		Name:               "large_encrypted_file.bin",
		Method:             zip.Deflate,
		UncompressedSize64: 4_500_000_000, // 4.5 GB (> 4GB Zip64 threshold)
		CompressedSize64:   100,            // Dummy compressed size marker
	}
	fhZip64File.SetEncryptionMethod(zip.StandardEncryption)
	fhZip64File.SetPassword(srcPass)

	w, err := zipw.CreateHeader(fhZip64File)
	if err != nil {
		t.Fatalf("failed to create encrypted zip64 header: %v", err)
	}
	_, _ = w.Write([]byte("zip64 encrypted file content payload"))
	_ = zipw.Close()

	srcStore := NewMemStorage()
	_ = srcStore.Write(context.Background(), "src_zip64_enc.zip", srcZipBuf.Bytes())

	destStore := NewMemStorage()
	client := NewClient(destStore)

	// Backup pre-encrypted Zip64 source
	v, err := client.Backup(context.Background(), NewZipFileSource(srcStore, "src_zip64_enc.zip", true), BackupOptions{
		Label:             "zip64-encrypted-backup",
		KeyID:             "key-1",
		PublicKeys:        map[string][]byte{"key-1": vmPub[:]},
		EphPublicKey:      ephPub,
		EncryptedPassword: encPass,
	})
	if err != nil {
		t.Fatalf("backup of encrypted Zip64 source failed: %v", err)
	}

	// Restore to Rekeyed Encrypted ZIP
	rekeyPass := "rekeyed_target_pass_456"
	var restoredZipBuf bytes.Buffer
	err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
		ZipWriter:   &restoredZipBuf,
		PrivateKey:  vmPriv[:],
		NewPassword: rekeyPass,
	})
	if err != nil {
		t.Fatalf("restore of encrypted Zip64 to rekeyed ZIP failed: %v", err)
	}

	// Verify Windows Explorer extractability natively
	verifyZipExplorerExtractable(t, restoredZipBuf.Bytes(), rekeyPass)

	// Programmatically verify Zip64 extraction and password re-keying
	zr, err := zip.NewReader(bytes.NewReader(restoredZipBuf.Bytes()), int64(restoredZipBuf.Len()))
	if err != nil {
		t.Fatalf("failed to parse restored zip64: %v", err)
	}

	if len(zr.File) != 1 {
		t.Fatalf("expected 1 file in restored zip64, got %d", len(zr.File))
	}

	f := zr.File[0]
	if f.Name != "large_encrypted_file.bin" {
		t.Fatalf("expected filename 'large_encrypted_file.bin', got %s", f.Name)
	}

	f.SetPassword(rekeyPass)
	rc, err := f.Open()
	if err != nil {
		t.Fatalf("failed to open restored zip64 file with rekeyed pass: %v", err)
	}
	data, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatalf("failed to read content of restored zip64 file: %v", err)
	}

	if string(data) != "zip64 encrypted file content payload" {
		t.Fatalf("content mismatch for restored zip64 file: expected %q, got %q", "zip64 encrypted file content payload", string(data))
	}
}

// ---------------------------------------------------------
// 2. Unencrypted Zip64 Source Backup -> Encrypted Zip64 Restore Test
// ---------------------------------------------------------

func TestTsyncUnencryptedZip64SourceToEncryptedZip64Restore(t *testing.T) {
	vmPub, vmPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	var srcZipBuf bytes.Buffer
	zipw := zip.NewWriter(&srcZipBuf)

	fhZip64 := &zip.FileHeader{
		Name:               "data_unencrypted_zip64.txt",
		Method:             zip.Deflate,
		UncompressedSize64: 4_300_000_000,
	}
	w, err := zipw.CreateHeader(fhZip64)
	if err != nil {
		t.Fatalf("failed to create zip64 header: %v", err)
	}
	_, _ = w.Write([]byte("unencrypted zip64 payload"))
	_ = zipw.Close()

	srcStore := NewMemStorage()
	_ = srcStore.Write(context.Background(), "src_unenc_zip64.zip", srcZipBuf.Bytes())

	destStore := NewMemStorage()
	client := NewClient(destStore)

	v, err := client.Backup(context.Background(), NewZipFileSource(srcStore, "src_unenc_zip64.zip", false), BackupOptions{
		Label:      "unenc-zip64-backup",
		KeyID:      "key-1",
		PublicKeys: map[string][]byte{"key-1": vmPub[:]},
	})
	if err != nil {
		t.Fatalf("backup of unencrypted zip64 source failed: %v", err)
	}

	// Restore to Encrypted output ZIP
	rekeyPass := "enc_zip64_output_pass"
	var restoredZipBuf bytes.Buffer
	err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
		ZipWriter:   &restoredZipBuf,
		PrivateKey:  vmPriv[:],
		NewPassword: rekeyPass,
	})
	if err != nil {
		t.Fatalf("restore of unencrypted zip64 source to encrypted ZIP failed: %v", err)
	}

	verifyZipExplorerExtractable(t, restoredZipBuf.Bytes(), rekeyPass)
}

// ---------------------------------------------------------
// 3. Zip64 with Data Descriptors Test (fh.Flags & 8 != 0)
// ---------------------------------------------------------

func TestTsyncZip64DataDescriptorsMatrix(t *testing.T) {
	vmPub, vmPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	var zipBuf bytes.Buffer
	zipw := zip.NewWriter(&zipBuf)

	fhDD := &zip.FileHeader{
		Name:               "dd_zip64_file.dat",
		Method:             zip.Deflate,
		Flags:              8, // Bit 3 set: Data Descriptor present
		UncompressedSize64: 4_200_000_000,
	}

	w, err := zipw.CreateHeader(fhDD)
	if err != nil {
		t.Fatalf("failed to create header with Data Descriptor: %v", err)
	}
	_, _ = w.Write([]byte("data descriptor payload test"))
	_ = zipw.Close()

	srcStore := NewMemStorage()
	_ = srcStore.Write(context.Background(), "src_dd_zip64.zip", zipBuf.Bytes())

	destStore := NewMemStorage()
	client := NewClient(destStore)

	v, err := client.Backup(context.Background(), NewZipFileSource(srcStore, "src_dd_zip64.zip", false), BackupOptions{
		Label:      "dd-zip64-backup",
		KeyID:      "key-1",
		PublicKeys: map[string][]byte{"key-1": vmPub[:]},
	})
	if err != nil {
		t.Fatalf("backup of Zip64 with Data Descriptor failed: %v", err)
	}

	var restoredZipBuf bytes.Buffer
	err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
		ZipWriter:  &restoredZipBuf,
		PrivateKey: vmPriv[:],
	})
	if err != nil {
		t.Fatalf("restore of Zip64 Data Descriptor backup failed: %v", err)
	}

	verifyZipExplorerExtractable(t, restoredZipBuf.Bytes(), "")
}

// ---------------------------------------------------------
// 4. Weird / Non-Standard ZIP Formats Test
// ---------------------------------------------------------

func TestTsyncWeirdZipFormatsMatrix(t *testing.T) {
	vmPub, vmPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	// Case A: Flat ZIP with 0 directory entries (only file paths)
	// Case B: Mixed 32-bit and 64-bit Zip64 extra field entries in same archive
	// Case C: Empty 0-byte directory headers ending in "/"
	var zipBuf bytes.Buffer
	zipw := zip.NewWriter(&zipBuf)

	// 1. Regular 32-bit entry
	w1, _ := zipw.Create("flat_file_1.txt", zip.Deflate, -1, zip.NoEncryption, "")
	_, _ = w1.Write([]byte("flat file 1"))

	// 2. Zip64 64-bit entry
	fh64 := &zip.FileHeader{
		Name:               "flat_file_64.dat",
		Method:             zip.Deflate,
		UncompressedSize64: 4_100_000_000,
	}
	w2, _ := zipw.CreateHeader(fh64)
	_, _ = w2.Write([]byte("flat file 64-bit zip64 payload"))

	// 3. Empty folder header ending in "/"
	fhDir := &zip.FileHeader{
		Name:   "empty_folder_header/",
		Method: zip.Store,
	}
	wDir, _ := zipw.CreateHeader(fhDir)
	if c, ok := wDir.(io.Closer); ok {
		_ = c.Close()
	}

	_ = zipw.Close()

	srcStore := NewMemStorage()
	_ = srcStore.Write(context.Background(), "weird_archive.zip", zipBuf.Bytes())

	destStore := NewMemStorage()
	client := NewClient(destStore)

	v, err := client.Backup(context.Background(), NewZipFileSource(srcStore, "weird_archive.zip", false), BackupOptions{
		Label:      "weird-zip-backup",
		KeyID:      "key-1",
		PublicKeys: map[string][]byte{"key-1": vmPub[:]},
	})
	if err != nil {
		t.Fatalf("backup of weird zip format failed: %v", err)
	}

	var restoredZipBuf bytes.Buffer
	err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
		ZipWriter:  &restoredZipBuf,
		PrivateKey: vmPriv[:],
	})
	if err != nil {
		t.Fatalf("restore of weird zip format failed: %v", err)
	}

	verifyZipExplorerExtractable(t, restoredZipBuf.Bytes(), "")

	zr, err := zip.NewReader(bytes.NewReader(restoredZipBuf.Bytes()), int64(restoredZipBuf.Len()))
	if err != nil {
		t.Fatalf("failed to parse restored weird zip: %v", err)
	}

	names := make(map[string]bool)
	for _, f := range zr.File {
		names[f.Name] = true
	}

	if !names["flat_file_1.txt"] || !names["flat_file_64.dat"] || !names["empty_folder_header/"] {
		t.Fatalf("expected all weird entries to be restored, got: %v", names)
	}
}
