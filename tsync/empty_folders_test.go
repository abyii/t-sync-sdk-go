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
	"strings"
	"testing"

	zip "github.com/abyii/zip-xxh3"
	"golang.org/x/crypto/nacl/box"
)

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

func TestTsyncEmptyFoldersBackupAndRestore(t *testing.T) {
	vmPub, vmPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	t.Run("FileSystem Source -> Backup -> Restore ExtractDir & ZipWriter", func(t *testing.T) {
		srcStore := NewMemStorage()
		_ = srcStore.Write(context.Background(), "file1.txt", []byte("file1 content"))
		_ = srcStore.Write(context.Background(), "nested/file2.txt", []byte("file2 content"))
		_ = srcStore.Write(context.Background(), "empty_folder/", []byte(""))
		_ = srcStore.Write(context.Background(), "nested/empty_subfolder/", []byte(""))
		_ = srcStore.Write(context.Background(), "deeply/nested/empty_deep/", []byte(""))

		destStore := NewMemStorage()
		client := NewClient(destStore)

		v, err := client.Backup(context.Background(), NewFolderSource(srcStore, ""), BackupOptions{
			Label:      "fs-empty-folder-run",
			KeyID:      "key-1",
			PublicKeys: map[string][]byte{"key-1": vmPub[:]},
		})
		if err != nil {
			t.Fatalf("backup failed: %v", err)
		}

		// A. Restore to ExtractDir
		tmpDir, err := os.MkdirTemp("", "tsync-empty-dir-test-*")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
			ExtractDir: tmpDir,
			PrivateKey: vmPriv[:],
		})
		if err != nil {
			t.Fatalf("restore to ExtractDir failed: %v", err)
		}

		// Verify files
		if content, err := os.ReadFile(filepath.Join(tmpDir, "file1.txt")); err != nil || string(content) != "file1 content" {
			t.Errorf("file1.txt mismatch: %v, %s", err, string(content))
		}
		if content, err := os.ReadFile(filepath.Join(tmpDir, "nested", "file2.txt")); err != nil || string(content) != "file2 content" {
			t.Errorf("nested/file2.txt mismatch: %v, %s", err, string(content))
		}

		// Verify empty folders exist on disk and are directories
		emptyDirsToVerify := []string{
			filepath.Join(tmpDir, "empty_folder"),
			filepath.Join(tmpDir, "nested", "empty_subfolder"),
			filepath.Join(tmpDir, "deeply", "nested", "empty_deep"),
		}
		for _, d := range emptyDirsToVerify {
			fi, err := os.Stat(d)
			if err != nil {
				t.Errorf("expected empty folder %s to exist on disk, got error: %v", d, err)
			} else if !fi.IsDir() {
				t.Errorf("expected %s to be a directory", d)
			}
		}

		// B. Restore to ZipWriter
		var zipBuf bytes.Buffer
		err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
			ZipWriter:  &zipBuf,
			PrivateKey: vmPriv[:],
		})
		if err != nil {
			t.Fatalf("restore to ZipWriter failed: %v", err)
		}

		// Parse restored ZIP and verify empty folder headers exist
		zr, err := zip.NewReader(bytes.NewReader(zipBuf.Bytes()), int64(zipBuf.Len()))
		if err != nil {
			t.Fatalf("failed to parse restored ZIP: %v", err)
		}

		zipEntries := make(map[string]*zip.File)
		for _, f := range zr.File {
			zipEntries[f.Name] = f
		}

		expectedZipDirs := []string{"empty_folder/", "nested/empty_subfolder/", "deeply/nested/empty_deep/"}
		for _, zd := range expectedZipDirs {
			zf, ok := zipEntries[zd]
			if !ok {
				t.Errorf("expected zip entry %q in restored ZIP archive", zd)
			} else if !strings.HasSuffix(zf.Name, "/") {
				t.Errorf("expected zip entry %q to end with '/'", zd)
			}
		}
	})

	t.Run("ZipFileSource with Empty Folders -> Backup -> Restore", func(t *testing.T) {
		// Construct source ZIP containing empty folder entries
		var srcZipBuf bytes.Buffer
		zipw := zip.NewWriter(&srcZipBuf)

		w1, _ := zipw.Create("data.txt", zip.Store, 0, zip.NoEncryption, "")
		_, _ = w1.Write([]byte("zip file data"))
		if c, ok := w1.(io.Closer); ok {
			_ = c.Close()
		}

		wDir1, _ := zipw.Create("zip_empty_dir/", zip.Store, 0, zip.NoEncryption, "")
		if c, ok := wDir1.(io.Closer); ok {
			_ = c.Close()
		}

		wDir2, _ := zipw.Create("zip_nested/empty_sub/", zip.Store, 0, zip.NoEncryption, "")
		if c, ok := wDir2.(io.Closer); ok {
			_ = c.Close()
		}

		_ = zipw.Close()

		srcStore := NewMemStorage()
		_ = srcStore.Write(context.Background(), "source.zip", srcZipBuf.Bytes())

		zipSrc := NewZipFileSource(srcStore, "source.zip", false)

		destStore := NewMemStorage()
		client := NewClient(destStore)

		v, err := client.Backup(context.Background(), zipSrc, BackupOptions{
			Label:      "zip-src-empty-dirs-run",
			KeyID:      "key-1",
			PublicKeys: map[string][]byte{"key-1": vmPub[:]},
		})
		if err != nil {
			t.Fatalf("backup from ZipFileSource failed: %v", err)
		}

		// Restore to ExtractDir
		tmpDir, err := os.MkdirTemp("", "tsync-zip-src-extract-*")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
			ExtractDir: tmpDir,
			PrivateKey: vmPriv[:],
		})
		if err != nil {
			t.Fatalf("restore to ExtractDir failed: %v", err)
		}

		fi1, err1 := os.Stat(filepath.Join(tmpDir, "zip_empty_dir"))
		fi2, err2 := os.Stat(filepath.Join(tmpDir, "zip_nested", "empty_sub"))
		if err1 != nil || !fi1.IsDir() {
			t.Errorf("zip_empty_dir not restored properly: %v", err1)
		}
		if err2 != nil || !fi2.IsDir() {
			t.Errorf("zip_nested/empty_sub not restored properly: %v", err2)
		}

		// Restore to ZipWriter
		var outZipBuf bytes.Buffer
		err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
			ZipWriter:  &outZipBuf,
			PrivateKey: vmPriv[:],
		})
		if err != nil {
			t.Fatalf("restore to ZipWriter failed: %v", err)
		}

		zrOut, err := zip.NewReader(bytes.NewReader(outZipBuf.Bytes()), int64(outZipBuf.Len()))
		if err != nil {
			t.Fatalf("failed to parse output ZIP: %v", err)
		}

		outEntries := make(map[string]bool)
		for _, f := range zrOut.File {
			outEntries[f.Name] = true
		}

		if !outEntries["zip_empty_dir/"] {
			t.Errorf("expected zip_empty_dir/ in output ZIP")
		}
		if !outEntries["zip_nested/empty_sub/"] {
			t.Errorf("expected zip_nested/empty_sub/ in output ZIP")
		}
	})

	t.Run("Zip64 Source with Empty Folders -> Backup -> Restore", func(t *testing.T) {
		// Construct Zip64 archive containing empty directory headers
		var zip64Buf bytes.Buffer
		zipw := zip.NewWriter(&zip64Buf)

		// Force Zip64 extra field format on file header
		fhFile := &zip.FileHeader{
			Name:               "large_marker.txt",
			Method:             zip.Store,
			UncompressedSize64: 4294967296, // 4GB+ to trigger Zip64
			CompressedSize64:   4294967296,
		}
		wFile, err := zipw.CreateHeader(fhFile)
		if err == nil && wFile != nil {
			if c, ok := wFile.(io.Closer); ok {
				_ = c.Close()
			}
		}

		// Add empty directory in Zip64 archive
		fhDir := &zip.FileHeader{
			Name:   "zip64_empty_dir/",
			Method: zip.Store,
		}
		wDir, err := zipw.CreateHeader(fhDir)
		if err == nil && wDir != nil {
			if c, ok := wDir.(io.Closer); ok {
				_ = c.Close()
			}
		}

		_ = zipw.Close()

		srcStore := NewMemStorage()
		_ = srcStore.Write(context.Background(), "zip64_source.zip", zip64Buf.Bytes())

		zipSrc := NewZipFileSource(srcStore, "zip64_source.zip", false)

		destStore := NewMemStorage()
		client := NewClient(destStore)

		v, err := client.Backup(context.Background(), zipSrc, BackupOptions{
			Label:      "zip64-empty-dir-run",
			KeyID:      "key-1",
			PublicKeys: map[string][]byte{"key-1": vmPub[:]},
		})
		if err != nil {
			t.Fatalf("backup from Zip64 source with empty dir failed: %v", err)
		}

		// Restore to ExtractDir
		tmpDir, err := os.MkdirTemp("", "tsync-zip64-extract-*")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
			ExtractDir: tmpDir,
			PrivateKey: vmPriv[:],
		})
		if err != nil {
			t.Fatalf("restore from Zip64 backup failed: %v", err)
		}

		fiDir, err := os.Stat(filepath.Join(tmpDir, "zip64_empty_dir"))
		if err != nil || !fiDir.IsDir() {
			t.Errorf("zip64_empty_dir not restored as directory: %v", err)
		}

		// Restore to ZipWriter
		var zip64OutBuf bytes.Buffer
		err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
			ZipWriter:  &zip64OutBuf,
			PrivateKey: vmPriv[:],
		})
		if err != nil {
			t.Fatalf("restore Zip64 to ZipWriter failed: %v", err)
		}

		zr64Out, err := zip.NewReader(bytes.NewReader(zip64OutBuf.Bytes()), int64(zip64OutBuf.Len()))
		if err != nil {
			t.Fatalf("failed to parse Zip64 restored output ZIP: %v", err)
		}

		z64Entries := make(map[string]bool)
		for _, f := range zr64Out.File {
			z64Entries[f.Name] = true
		}
		if !z64Entries["zip64_empty_dir/"] {
			t.Errorf("expected zip64_empty_dir/ in output ZIP")
		}
	})

	t.Run("Rekeying and FilterFunc with Empty Folders", func(t *testing.T) {
		srcStore := NewMemStorage()
		_ = srcStore.Write(context.Background(), "keep_file.txt", []byte("keep content"))
		_ = srcStore.Write(context.Background(), "keep_empty/", []byte(""))
		_ = srcStore.Write(context.Background(), "ignore_empty/", []byte(""))

		destStore := NewMemStorage()
		client := NewClient(destStore)

		v, err := client.Backup(context.Background(), NewFolderSource(srcStore, ""), BackupOptions{
			Label:      "rekey-filter-empty-run",
			KeyID:      "key-1",
			PublicKeys: map[string][]byte{"key-1": vmPub[:]},
		})
		if err != nil {
			t.Fatalf("backup failed: %v", err)
		}

		// Restore with FilterFunc skipping ignore_empty
		var rekeyedZipBuf bytes.Buffer
		err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
			ZipWriter:   &rekeyedZipBuf,
			PrivateKey:  vmPriv[:],
			NewPassword: "rekeyedPassword123",
			FilterFunc: func(p string) bool {
				return !strings.HasPrefix(p, "ignore_empty")
			},
		})
		if err != nil {
			t.Fatalf("rekeyed restore failed: %v", err)
		}

		zrRekey, err := zip.NewReader(bytes.NewReader(rekeyedZipBuf.Bytes()), int64(rekeyedZipBuf.Len()))
		if err != nil {
			t.Fatalf("failed to parse rekeyed ZIP: %v", err)
		}

		rekeyedFiles := make(map[string]*zip.File)
		for _, f := range zrRekey.File {
			rekeyedFiles[f.Name] = f
		}

		if _, ok := rekeyedFiles["ignore_empty/"]; ok {
			t.Errorf("expected ignore_empty/ to be filtered out")
		}

		if zf, ok := rekeyedFiles["keep_empty/"]; !ok || !strings.HasSuffix(zf.Name, "/") {
			t.Errorf("expected keep_empty/ in rekeyed ZIP")
		}

		if zf, ok := rekeyedFiles["keep_file.txt"]; !ok || !zf.IsEncrypted() {
			t.Errorf("expected keep_file.txt to be present and encrypted with new password")
		}
	})

	t.Run("Only Empty Folders (0 files) -> Backup -> Restore", func(t *testing.T) {
		srcStore := NewMemStorage()
		_ = srcStore.Write(context.Background(), "sole_empty_dir/", []byte(""))

		destStore := NewMemStorage()
		client := NewClient(destStore)

		v, err := client.Backup(context.Background(), NewFolderSource(srcStore, ""), BackupOptions{
			Label:      "zero-files-empty-dir-run",
			KeyID:      "key-1",
			PublicKeys: map[string][]byte{"key-1": vmPub[:]},
		})
		if err != nil {
			t.Fatalf("backup of 0 files with empty folder failed: %v", err)
		}

		tmpDir, err := os.MkdirTemp("", "tsync-zero-files-extract-*")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
			ExtractDir: tmpDir,
			PrivateKey: vmPriv[:],
		})
		if err != nil {
			t.Fatalf("restore of 0-file empty dir failed: %v", err)
		}

		fi, err := os.Stat(filepath.Join(tmpDir, "sole_empty_dir"))
		if err != nil || !fi.IsDir() {
			t.Errorf("sole_empty_dir not restored properly: %v", err)
		}
	})

	t.Run("Empty Folder Path Traversal Protection Rejection", func(t *testing.T) {
		srcStore := NewMemStorage()
		_ = srcStore.Write(context.Background(), "../../../traversal_dir/", []byte(""))

		destStore := NewMemStorage()
		client := NewClient(destStore)

		_, err := client.Backup(context.Background(), NewFolderSource(srcStore, ""), BackupOptions{
			Label:      "traversal-empty-dir-run",
			KeyID:      "key-1",
			PublicKeys: map[string][]byte{"key-1": vmPub[:]},
		})
		if err == nil {
			t.Fatalf("expected backup to fail due to directory traversal '..', but it succeeded")
		}
		if !strings.Contains(err.Error(), "directory traversal sentinel \"..\"") {
			t.Errorf("expected error to mention traversal sentinel, got: %v", err)
		}
	})

	t.Run("Encrypted ZIP Source -> Backup -> Restore ExtractDir", func(t *testing.T) {
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

		w, err := zipw.Create("data/file1.txt", zip.Deflate, -1, zip.StandardEncryption, clearZipPass)
		if err != nil {
			t.Fatalf("failed to create zip file: %v", err)
		}
		_, _ = w.Write([]byte("extracted filesystem content"))
		_ = zipw.Close()

		zipPath := "enc-source.zip"
		_ = srcStore.Write(context.Background(), zipPath, zipBuf.Bytes())

		zipSrc := NewZipFileSource(srcStore, zipPath, true)
		destStore := NewMemStorage()
		client := NewClient(destStore)

		v, err := client.Backup(context.Background(), zipSrc, BackupOptions{
			Label:             "enc-zip-extractdir-run",
			KeyID:             "key-1",
			PublicKeys:        map[string][]byte{"key-1": vmPub[:]},
			EphPublicKey:      ephPub,
			EncryptedPassword: encPass,
		})
		if err != nil {
			t.Fatalf("backup failed: %v", err)
		}

		tmpDir, err := os.MkdirTemp("", "tsync-enc-extractdir-*")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
			ExtractDir: tmpDir,
			PrivateKey: vmPriv[:],
		})
		if err != nil {
			t.Fatalf("restore to ExtractDir failed: %v", err)
		}

		content, err := os.ReadFile(filepath.Join(tmpDir, "data", "file1.txt"))
		if err != nil || string(content) != "extracted filesystem content" {
			t.Errorf("extracted content mismatch: err=%v, content=%q", err, string(content))
		}
	})
}

func TestTsyncSkipNonRegularFiles(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tsync-nonregular-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a regular file and a directory
	regPath := filepath.Join(tmpDir, "regular.txt")
	_ = os.WriteFile(regPath, []byte("regular file content"), 0644)
	subDir := filepath.Join(tmpDir, "subdir")
	_ = os.MkdirAll(subDir, 0755)

	// Try creating a symlink (if OS permits)
	symPath := filepath.Join(tmpDir, "symlink.txt")
	_ = os.Symlink(regPath, symPath)

	localStore, err := NewLocalStorage(tmpDir)
	if err != nil {
		t.Fatalf("failed to create LocalStorage: %v", err)
	}

	files, err := localStore.List(context.Background(), "")
	if err != nil {
		t.Fatalf("failed to list LocalStorage: %v", err)
	}

	for _, f := range files {
		if strings.HasPrefix(f.Name, "symlink.txt") {
			t.Errorf("expected symlink.txt to be skipped by LocalStorage.List, but it was included")
		}
	}
}

func TestWindowsNativeExtractionCompliance(t *testing.T) {
	vmPub, vmPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	srcStore := NewMemStorage()
	_ = srcStore.Write(context.Background(), "file1.txt", []byte("Hello Windows Explorer!"))
	_ = srcStore.Write(context.Background(), "sub/file2.txt", []byte("Nested content for Windows extraction test."))
	_ = srcStore.Write(context.Background(), "empty_dir/", []byte(""))

	destStore := NewMemStorage()
	client := NewClient(destStore)

	v, err := client.Backup(context.Background(), NewFolderSource(srcStore, ""), BackupOptions{
		Label:      "win-test-run",
		KeyID:      "key-1",
		PublicKeys: map[string][]byte{"key-1": vmPub[:]},
	})
	if err != nil {
		t.Fatalf("backup failed: %v", err)
	}

	// 1. Restore to an unencrypted ZIP archive
	var unencZipBuf bytes.Buffer
	err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
		ZipWriter:  &unencZipBuf,
		PrivateKey: vmPriv[:],
	})
	if err != nil {
		t.Fatalf("restore unencrypted failed: %v", err)
	}

	// Verify with standard Go zip reader
	zrUnenc, err := zip.NewReader(bytes.NewReader(unencZipBuf.Bytes()), int64(unencZipBuf.Len()))
	if err != nil {
		t.Fatalf("failed to parse unencrypted restored ZIP: %v", err)
	}
	if len(zrUnenc.File) < 3 {
		t.Fatalf("expected at least 3 entries in restored ZIP, got %d", len(zrUnenc.File))
	}

	// Test extraction using native Windows PowerShell Expand-Archive (if running on Windows)
	if runtime.GOOS == "windows" {
		tmpUnencZip, err := os.CreateTemp("", "win-unenc-*.zip")
		if err == nil {
			_, _ = tmpUnencZip.Write(unencZipBuf.Bytes())
			tmpUnencZip.Close()
			defer os.Remove(tmpUnencZip.Name())

			destExtractDir, err := os.MkdirTemp("", "win-unenc-extract-*")
			if err == nil {
				defer os.RemoveAll(destExtractDir)

				psCmd := fmt.Sprintf("Expand-Archive -Path '%s' -DestinationPath '%s' -Force", tmpUnencZip.Name(), destExtractDir)
				cmd := exec.Command("powershell", "-Command", psCmd)
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("PowerShell Expand-Archive failed to extract restored ZIP: %v\nOutput: %s", err, string(out))
				}

				f1Data, err1 := os.ReadFile(filepath.Join(destExtractDir, "file1.txt"))
				f2Data, err2 := os.ReadFile(filepath.Join(destExtractDir, "sub", "file2.txt"))
				fiEmpty, errEmpty := os.Stat(filepath.Join(destExtractDir, "empty_dir"))

				if err1 != nil || string(f1Data) != "Hello Windows Explorer!" {
					t.Errorf("file1.txt extraction mismatch: err=%v, content=%q", err1, string(f1Data))
				}
				if err2 != nil || string(f2Data) != "Nested content for Windows extraction test." {
					t.Errorf("sub/file2.txt extraction mismatch: err=%v, content=%q", err2, string(f2Data))
				}
				if errEmpty != nil || !fiEmpty.IsDir() {
					t.Errorf("empty_dir not extracted as directory: %v", errEmpty)
				}
			}
		}
	}

	// 2. Restore to an encrypted ZIP archive with NewPassword = "winPassword123"
	var encZipBuf bytes.Buffer
	err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
		ZipWriter:   &encZipBuf,
		PrivateKey:  vmPriv[:],
		NewPassword: "winPassword123",
	})
	if err != nil {
		t.Fatalf("restore encrypted failed: %v", err)
	}

	zrEnc, err := zip.NewReader(bytes.NewReader(encZipBuf.Bytes()), int64(encZipBuf.Len()))
	if err != nil {
		t.Fatalf("failed to parse encrypted restored ZIP: %v", err)
	}

	for _, f := range zrEnc.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if !f.IsEncrypted() {
			t.Errorf("expected %s to be encrypted in re-keyed ZIP", f.Name)
		}
		f.SetPassword("winPassword123")
		rc, err := f.Open()
		if err != nil {
			t.Errorf("failed to open %s with password: %v", f.Name, err)
			continue
		}
		data, readErr := io.ReadAll(rc)
		rc.Close()
		if readErr != nil {
			t.Errorf("failed to read %s content: %v", f.Name, readErr)
		} else if len(data) == 0 {
			t.Errorf("%s extracted 0 bytes", f.Name)
		}
	}
}
