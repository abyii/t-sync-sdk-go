package tsync

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abyii/t-sync-sdk-go/v2/storage_clients"
	zip "github.com/abyii/zip-xxh3"
	"golang.org/x/crypto/nacl/box"
	"google.golang.org/protobuf/proto"

	tsyncv2 "github.com/abyii/t-sync-sdk-go/v2/gen/go/com/github/abyii/tsync/v2"
)

// ---------------------------------------------------------
// 1. Restore Context Cancellation Test
// ---------------------------------------------------------

func TestTsyncRestoreContextCancellation(t *testing.T) {
	vmPub, vmPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	store := NewMemStorage()
	client := NewClient(store)

	srcStore := NewMemStorage()
	for i := 1; i <= 20; i++ {
		_ = srcStore.Write(context.Background(), fmt.Sprintf("file_%d.txt", i), []byte(fmt.Sprintf("large content block for file %d", i)))
	}

	v, err := client.Backup(context.Background(), NewFolderSource(srcStore, ""), BackupOptions{
		Label:      "v1",
		KeyID:      "key-1",
		PublicKeys: map[string][]byte{"key-1": vmPub[:]},
	})
	if err != nil {
		t.Fatalf("backup failed: %v", err)
	}

	// Create a context cancelled immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel context before restore executes

	tempExtractDir, err := os.MkdirTemp("", "tsync-cancel-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempExtractDir)

	err = client.Restore(ctx, v.SnowflakeId, RestoreOptions{
		ExtractDir: tempExtractDir,
		PrivateKey: vmPriv[:],
	})

	if err == nil {
		t.Fatalf("expected Restore to fail due to context cancellation, but got nil error")
	}

	// Verify no partial files or temp files leak in target dir
	entries, _ := os.ReadDir(tempExtractDir)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".tsync-restore-tmp") {
			t.Fatalf("leaked temporary restore file found: %s", entry.Name())
		}
	}
}

// ---------------------------------------------------------
// 2. UTF-8 Unicode Filenames Matrix Test
// ---------------------------------------------------------

func TestTsyncUnicodeAndSpecialFilenameMatrix(t *testing.T) {
	vmPub, vmPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	unicodeFiles := map[string]string{
		"Documents/报告_2026/数据.txt":               "Chinese characters payload",
		"folder_🚀/file_ñ_á_é.txt":                "Emoji and accented characters",
		"path with spaces/file (v1) [copy].txt": "Spaces and brackets in path",
		"empty_unicode_dir/":                    "",
	}

	srcStore := NewMemStorage()
	var zipBuf bytes.Buffer
	zipw := zip.NewWriter(&zipBuf)

	stepPass := "pass_unicode_123"
	ephPub, encPass, err := EncryptPassword(stepPass, vmPub[:])
	if err != nil {
		t.Fatalf("failed to encrypt password: %v", err)
	}

	for name, content := range unicodeFiles {
		if strings.HasSuffix(name, "/") {
			_, err = zipw.Create(name, zip.Store, 0, zip.NoEncryption, "")
			if err != nil {
				t.Fatalf("failed to create dir entry %s: %v", name, err)
			}
			continue
		}
		w, err := zipw.Create(name, zip.Deflate, -1, zip.StandardEncryption, stepPass)
		if err != nil {
			t.Fatalf("failed to create file entry %s: %v", name, err)
		}
		_, _ = w.Write([]byte(content))
	}
	_ = zipw.Close()

	_ = srcStore.Write(context.Background(), "src_unicode.zip", zipBuf.Bytes())

	destStore := NewMemStorage()
	client := NewClient(destStore)

	v, err := client.Backup(context.Background(), NewZipFileSource(srcStore, "src_unicode.zip", true), BackupOptions{
		Label:             "unicode-backup",
		KeyID:             "key-1",
		PublicKeys:        map[string][]byte{"key-1": vmPub[:]},
		EphPublicKey:      ephPub,
		EncryptedPassword: encPass,
	})
	if err != nil {
		t.Fatalf("backup with unicode filenames failed: %v", err)
	}

	// Restore to rekeyed ZIP
	rekeyPass := "rekey_unicode_pass"
	var restoredZipBuf bytes.Buffer
	err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
		ZipWriter:   &restoredZipBuf,
		PrivateKey:  vmPriv[:],
		NewPassword: rekeyPass,
	})
	if err != nil {
		t.Fatalf("restore with unicode filenames failed: %v", err)
	}

	// Windows Explorer extractability verification
	verifyZipExplorerExtractable(t, restoredZipBuf.Bytes(), rekeyPass)

	// Assert reconstructed filenames and contents
	zr, err := zip.NewReader(bytes.NewReader(restoredZipBuf.Bytes()), int64(restoredZipBuf.Len()))
	if err != nil {
		t.Fatalf("failed to parse restored zip: %v", err)
	}

	restoredEntries := make(map[string]string)
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/") {
			restoredEntries[f.Name] = ""
			continue
		}
		f.SetPassword(rekeyPass)
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("failed to open %s: %v", f.Name, err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("failed to read content of %s: %v", f.Name, err)
		}
		restoredEntries[f.Name] = string(data)
	}

	for name, expectedContent := range unicodeFiles {
		gotContent, exists := restoredEntries[name]
		if !exists {
			t.Fatalf("expected unicode entry %q missing in restored ZIP", name)
		}
		if gotContent != expectedContent {
			t.Fatalf("content mismatch for unicode entry %q: expected %q, got %q", name, expectedContent, gotContent)
		}
	}
}

// ---------------------------------------------------------
// 3. ObjectStorage Multipart Upload Fault Injection Test
// ---------------------------------------------------------

type mockObjectStorageClient struct {
	mu            sync.Mutex
	initiateCount int
	uploadCount   int
	completeCount int
	abortCount    int

	failUploadPartAt int
}

func (m *mockObjectStorageClient) SetRegion(region string) {}

func (m *mockObjectStorageClient) ListBuckets(ctx context.Context, prefix string) ([]string, error) {
	return []string{"test-bucket"}, nil
}

func (m *mockObjectStorageClient) GetObjectSize(ctx context.Context, bucket, key string) (int64, error) {
	return 0, os.ErrNotExist
}

func (m *mockObjectStorageClient) GetObjectRange(ctx context.Context, bucket, key string, offset, length int64) (io.ReadCloser, error) {
	return nil, os.ErrNotExist
}

func (m *mockObjectStorageClient) PutObject(ctx context.Context, bucket, key string, data []byte) error {
	return nil
}

func (m *mockObjectStorageClient) DeleteObject(ctx context.Context, bucket, key string) error {
	return nil
}

func (m *mockObjectStorageClient) ListObjects(ctx context.Context, bucket, prefix string) ([]storage_clients.ObjectInfo, error) {
	return nil, nil
}

func (m *mockObjectStorageClient) Initiate(ctx context.Context, bucket, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.initiateCount++
	return "mock-upload-id-123", nil
}

func (m *mockObjectStorageClient) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, data []byte) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.uploadCount++
	if m.failUploadPartAt > 0 && m.uploadCount >= m.failUploadPartAt {
		return "", fmt.Errorf("injected error on UploadPart %d", partNumber)
	}
	return fmt.Sprintf("etag-part-%d", partNumber), nil
}

func (m *mockObjectStorageClient) Complete(ctx context.Context, bucket, key, uploadID string, etags map[int]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.completeCount++
	return nil
}

func (m *mockObjectStorageClient) Abort(ctx context.Context, bucket, key, uploadID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.abortCount++
	return nil
}

func TestTsyncObjectStorageMultipartFaultInjection(t *testing.T) {
	mockClient := &mockObjectStorageClient{
		failUploadPartAt: 2, // Fail on 2nd 5MB multipart chunk
	}

	objStore := NewObjectStorage(mockClient, "test-bucket", "backup-prefix")
	writer, err := objStore.OpenWriter(context.Background(), "large_file_part.bin")
	if err != nil {
		t.Fatalf("failed to open writer: %v", err)
	}

	// Write 12MB of data to trigger multipart upload (5MB threshold per part)
	chunk := make([]byte, 1024*1024) // 1MB chunk
	var writeErr error
	for i := 0; i < 12; i++ {
		_, writeErr = writer.Write(chunk)
		if writeErr != nil {
			break
		}
	}

	closeErr := writer.Close()

	if writeErr == nil && closeErr == nil {
		t.Fatalf("expected multipart upload to fail, but it succeeded")
	}

	// Assert that Abort() was invoked on the mock client to clean up the multipart session
	mockClient.mu.Lock()
	abortCount := mockClient.abortCount
	mockClient.mu.Unlock()

	if abortCount == 0 {
		t.Fatalf("expected ObjectStorage writer to call Abort() on multipart failure, but abortCount is 0")
	}
}

// ---------------------------------------------------------
// 4. Zip64 Single-File Size Boundary Test (> 4.8 GB Single File)
// ---------------------------------------------------------

type zeroReader struct {
	remaining int64
}

func (z *zeroReader) Read(p []byte) (int, error) {
	if z.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > z.remaining {
		n = int(z.remaining)
	}
	for i := 0; i < n; i++ {
		p[i] = 0
	}
	z.remaining -= int64(n)
	return n, nil
}

type singleFileSource struct {
	name string
	size int64
}

func (s *singleFileSource) ListEntries(ctx context.Context) ([]SourceEntry, error) {
	return []SourceEntry{
		{
			Path:         s.name,
			Size:         s.size,
			LastModified: time.Now(),
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(&zeroReader{remaining: s.size}), nil
			},
		},
	}, nil
}

func TestTsyncZip64SingleLargeFileBoundary(t *testing.T) {
	const largeSize int64 = 4_800_000_000 // 4.8 GB (> 4GB Zip64 threshold)

	src := &singleFileSource{
		name: "large_4.8gb_file.dat",
		size: largeSize,
	}

	store := NewMemStorage()
	client := NewClient(store)

	vmPub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	storeCompression := 0
	v, err := client.Backup(context.Background(), src, BackupOptions{
		Label:            "zip64-large-file",
		KeyID:            "key-1",
		PublicKeys:       map[string][]byte{"key-1": vmPub[:]},
		CompressionLevel: &storeCompression, // Store method for ultra-fast generation
	})
	if err != nil {
		t.Fatalf("backup of 4.8GB single file failed: %v", err)
	}

	// Verify that FileRecord in metadata stored 4.8GB size accurately without 32-bit integer overflow
	files, err := client.ListFiles(context.Background(), v.SnowflakeId)
	if err != nil {
		t.Fatalf("failed to list files: %v", err)
	}

	if len(files) != 1 || files[0] != "large_4.8gb_file.dat" {
		t.Fatalf("expected file 'large_4.8gb_file.dat', got %v", files)
	}

	// Verify metadata file record size
	pbBytes, err := store.Read(context.Background(), ".tsync")
	if err != nil {
		t.Fatalf("failed to read .tsync metadata: %v", err)
	}

	var metadata tsyncv2.BackupMetadata
	if err := proto.Unmarshal(pbBytes, &metadata); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}

	var foundRecord bool
	for _, rec := range metadata.Files {
		if rec.UncompressedSize == largeSize {
			foundRecord = true
			break
		}
	}

	if !foundRecord {
		t.Fatalf("expected to find file record with UncompressedSize = %d (4.8GB), but none found", largeSize)
	}
}
