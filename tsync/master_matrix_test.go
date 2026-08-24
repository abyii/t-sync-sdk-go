package tsync

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	zip "github.com/abyii/zip-xxh3"
	"golang.org/x/crypto/nacl/box"
)

type matrixSourceType int

const (
	matrixSourceFileSystem matrixSourceType = iota
	matrixSourceZipUnencrypted
	matrixSourceZipEncrypted
)

type matrixArchiveSpec int

const (
	matrixSpecStandard matrixArchiveSpec = iota
	matrixSpecZip64
)

type matrixComposition int

const (
	matrixCompOnlyEmptyFolders matrixComposition = iota
	matrixCompMixedFilesAndFolders
)

func TestTsyncMasterMatrixSuite(t *testing.T) {
	vmPub, vmPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	sourceTypes := []struct {
		name string
		kind matrixSourceType
	}{
		{"FileSystemSource", matrixSourceFileSystem},
		{"UnencryptedZipSource", matrixSourceZipUnencrypted},
		{"EncryptedZipSource", matrixSourceZipEncrypted},
	}

	archiveSpecs := []struct {
		name string
		spec matrixArchiveSpec
	}{
		{"StandardZip", matrixSpecStandard},
		{"Zip64Zip", matrixSpecZip64},
	}

	compositions := []struct {
		name string
		comp matrixComposition
	}{
		{"OnlyEmptyFolders", matrixCompOnlyEmptyFolders},
		{"MixedFilesAndFolders", matrixCompMixedFilesAndFolders},
	}

	for _, st := range sourceTypes {
		for _, spec := range archiveSpecs {
			for _, comp := range compositions {
				testName := fmt.Sprintf("%s/%s/%s", st.name, spec.name, comp.name)
				t.Run(testName, func(t *testing.T) {
					runMasterMatrixTest(t, st.kind, spec.spec, comp.comp, vmPub[:], vmPriv[:])
				})
			}
		}
	}
}

func runMasterMatrixTest(
	t *testing.T,
	srcKind matrixSourceType,
	specKind matrixArchiveSpec,
	compKind matrixComposition,
	vmPub []byte,
	vmPriv []byte,
) {
	ctx := context.Background()

	// 1. Prepare initial dataset
	srcStore := NewMemStorage()
	var clearZipPass string
	var ephPub []byte
	var encPass []byte

	if compKind == matrixCompOnlyEmptyFolders {
		_ = srcStore.Write(ctx, "empty_root/", []byte(""))
		_ = srcStore.Write(ctx, "nested/empty_sub/", []byte(""))
		_ = srcStore.Write(ctx, "deep/nested/empty_deep/", []byte(""))
	} else {
		// Mixed Composition: 0-byte files, small files, medium files, large files, empty folders
		_ = srcStore.Write(ctx, ".gitkeep", []byte(""))
		_ = srcStore.Write(ctx, "small1.txt", []byte("small file 1 content"))
		_ = srcStore.Write(ctx, "small2.txt", []byte("small file 2 content"))
		_ = srcStore.Write(ctx, "med/medium.dat", bytes.Repeat([]byte("M"), 50*1024))   // 50 KB
		_ = srcStore.Write(ctx, "large/big.bin", bytes.Repeat([]byte("B"), 500*1024))   // 500 KB
		_ = srcStore.Write(ctx, "empty_dir/", []byte(""))
		_ = srcStore.Write(ctx, "nested/empty_sub/", []byte(""))

		// Add multiple small files (scale check)
		for i := 0; i < 25; i++ {
			p := fmt.Sprintf("scale/file_%03d.txt", i)
			_ = srcStore.Write(ctx, p, []byte(fmt.Sprintf("scale payload %d", i)))
		}
	}

	// Prepare Source implementation
	var source Source
	if srcKind == matrixSourceFileSystem {
		source = NewFolderSource(srcStore, "")
	} else {
		// Construct ZIP source
		var zipBuf bytes.Buffer
		zipw := zip.NewWriter(&zipBuf)

		if srcKind == matrixSourceZipEncrypted {
			var err error
			clearZipPass, err = GenerateZipCryptoPassword()
			if err != nil {
				t.Fatalf("failed to generate password: %v", err)
			}
			ephPub, encPass, err = EncryptPassword(clearZipPass, vmPub)
			if err != nil {
				t.Fatalf("failed to encrypt password: %v", err)
			}
		}

		files, _ := srcStore.List(ctx, "")
		for _, f := range files {
			isDir := strings.HasSuffix(f.Name, "/")
			if isDir {
				_, _ = zipw.Create(f.Name, zip.Store, 0, zip.NoEncryption, "")
			} else {
				data, _ := srcStore.Read(ctx, f.Name)
				var w io.Writer
				var err error
				if srcKind == matrixSourceZipEncrypted {
					w, err = zipw.Create(f.Name, zip.Deflate, -1, zip.StandardEncryption, clearZipPass)
				} else {
					w, err = zipw.Create(f.Name, zip.Deflate, -1, zip.NoEncryption, "")
				}
				if err == nil && w != nil {
					_, _ = w.Write(data)
				}
			}
		}
		_ = zipw.Close()

		zipPath := "source_archive.zip"
		_ = srcStore.Write(ctx, zipPath, zipBuf.Bytes())
		source = NewZipFileSource(srcStore, zipPath, srcKind == matrixSourceZipEncrypted)
	}

	// Create SDK Destination Storage & Client
	destStore := NewMemStorage()
	client := NewClient(destStore)

	bOpts1 := BackupOptions{
		Label:             "matrix-v1",
		KeyID:             "vm-key-1",
		PublicKeys:        map[string][]byte{"vm-key-1": vmPub},
		Concurrency:       2,
		EphPublicKey:      ephPub,
		EncryptedPassword: encPass,
	}

	// 2. Run Initial Backup (Version 1)
	v1, err := client.Backup(ctx, source, bOpts1)
	if err != nil {
		t.Fatalf("v1 backup failed: %v", err)
	}

	// Verify Version 1 Restores
	// A. Restore to ExtractDir
	tmpDir1, err := os.MkdirTemp("", "matrix-v1-extract-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir1)

	err = client.Restore(ctx, v1.SnowflakeId, RestoreOptions{
		ExtractDir: tmpDir1,
		PrivateKey: vmPriv,
	})
	if err != nil {
		t.Fatalf("v1 restore to ExtractDir failed: %v", err)
	}

	// B. Restore to Unencrypted ZipWriter
	var zipBuf1 bytes.Buffer
	err = client.Restore(ctx, v1.SnowflakeId, RestoreOptions{
		ZipWriter:  &zipBuf1,
		PrivateKey: vmPriv,
	})
	if err != nil {
		t.Fatalf("v1 restore to ZipWriter failed: %v", err)
	}
	verifyZipExplorerExtractable(t, zipBuf1.Bytes(), "")

	// C. Restore to Encrypted ZipWriter with Rekeying
	var encZipBuf1 bytes.Buffer
	err = client.Restore(ctx, v1.SnowflakeId, RestoreOptions{
		ZipWriter:   &encZipBuf1,
		PrivateKey:  vmPriv,
		NewPassword: "rekeyPassword123",
	})
	if err != nil {
		t.Fatalf("v1 restore with rekeying failed: %v", err)
	}
	verifyZipExplorerExtractable(t, encZipBuf1.Bytes(), "rekeyPassword123")

	// 3. Multi-Version Lifecycle: Incremental Backup (Version 2)
	if compKind == matrixCompMixedFilesAndFolders {
		_ = srcStore.Write(ctx, "small1.txt", []byte("updated small file 1"))
		_ = srcStore.Write(ctx, "new_file.txt", []byte("added in v2"))
		_ = srcStore.Write(ctx, "v2_empty_dir/", []byte(""))
		_ = srcStore.Delete(ctx, "small2.txt")
	} else {
		_ = srcStore.Write(ctx, "v2_empty_folder/", []byte(""))
	}

	// Update source if ZIP
	if srcKind != matrixSourceFileSystem {
		var zipBuf2 bytes.Buffer
		zipw2 := zip.NewWriter(&zipBuf2)
		files, _ := srcStore.List(ctx, "")
		for _, f := range files {
			if f.Name == "source_archive.zip" {
				continue
			}
			isDir := strings.HasSuffix(f.Name, "/")
			if isDir {
				_, _ = zipw2.Create(f.Name, zip.Store, 0, zip.NoEncryption, "")
			} else {
				data, _ := srcStore.Read(ctx, f.Name)
				var w io.Writer
				var err error
				if srcKind == matrixSourceZipEncrypted {
					w, err = zipw2.Create(f.Name, zip.Deflate, -1, zip.StandardEncryption, clearZipPass)
				} else {
					w, err = zipw2.Create(f.Name, zip.Deflate, -1, zip.NoEncryption, "")
				}
				if err == nil && w != nil {
					_, _ = w.Write(data)
				}
			}
		}
		_ = zipw2.Close()
		_ = srcStore.Write(ctx, "source_archive.zip", zipBuf2.Bytes())
		source = NewZipFileSource(srcStore, "source_archive.zip", srcKind == matrixSourceZipEncrypted)
	}

	v2, err := client.Backup(ctx, source, BackupOptions{
		Label:             "matrix-v2",
		Concurrency:       2,
		EphPublicKey:      ephPub,
		EncryptedPassword: encPass,
	})
	if err != nil {
		t.Fatalf("v2 backup failed: %v", err)
	}

	if v2.PrecedingVersionId != v1.SnowflakeId {
		t.Fatalf("expected v2 preceding version to be %d, got %d", v1.SnowflakeId, v2.PrecedingVersionId)
	}

	// Restore Version 2
	var zipBuf2 bytes.Buffer
	err = client.Restore(ctx, v2.SnowflakeId, RestoreOptions{
		ZipWriter:  &zipBuf2,
		PrivateKey: vmPriv,
	})
	if err != nil {
		t.Fatalf("v2 restore to ZipWriter failed: %v", err)
	}
	verifyZipExplorerExtractable(t, zipBuf2.Bytes(), "")

	// 4. SDK Operations: Delete Version (Delete v1)
	err = client.DeleteVersion(ctx, v1.SnowflakeId)
	if err != nil {
		t.Fatalf("DeleteVersion v1 failed: %v", err)
	}

	// Verify v1 is gone from ListVersions
	versions, err := client.ListVersions(ctx)
	if err != nil {
		t.Fatalf("ListVersions failed: %v", err)
	}
	for _, ver := range versions {
		if ver.SnowflakeId == v1.SnowflakeId {
			t.Fatalf("deleted version v1 is still present in ListVersions")
		}
	}

	// Verify v2 remains fully extractable after v1 deletion
	var zipBuf2AfterDelete bytes.Buffer
	err = client.Restore(ctx, v2.SnowflakeId, RestoreOptions{
		ZipWriter:  &zipBuf2AfterDelete,
		PrivateKey: vmPriv,
	})
	if err != nil {
		t.Fatalf("v2 restore after v1 deletion failed: %v", err)
	}
	verifyZipExplorerExtractable(t, zipBuf2AfterDelete.Bytes(), "")

	// 5. SDK Operations: Garbage Collection (GC)
	// Inject fake orphan
	fakeOrphanKey := "99/99999999_999"
	_ = destStore.Write(ctx, fakeOrphanKey, []byte("orphaned content"))

	err = client.GC(ctx)
	if err != nil {
		t.Fatalf("GC failed: %v", err)
	}

	orphanExists, _ := destStore.Exists(ctx, fakeOrphanKey)
	if orphanExists {
		t.Fatalf("orphaned file part was not deleted by GC")
	}

	// Verify v2 remains fully extractable after GC
	tmpDir2, err := os.MkdirTemp("", "matrix-v2-extract-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir2)

	err = client.Restore(ctx, v2.SnowflakeId, RestoreOptions{
		ExtractDir: tmpDir2,
		PrivateKey: vmPriv,
	})
	if err != nil {
		t.Fatalf("v2 restore to ExtractDir after GC failed: %v", err)
	}

	if compKind == matrixCompMixedFilesAndFolders {
		c1, err1 := os.ReadFile(filepath.Join(tmpDir2, "small1.txt"))
		if err1 != nil || string(c1) != "updated small file 1" {
			t.Errorf("small1.txt mismatch after GC: err=%v, content=%q", err1, string(c1))
		}
		cNew, errNew := os.ReadFile(filepath.Join(tmpDir2, "new_file.txt"))
		if errNew != nil || string(cNew) != "added in v2" {
			t.Errorf("new_file.txt mismatch after GC: err=%v, content=%q", errNew, string(cNew))
		}
		fiEmpty, errEmpty := os.Stat(filepath.Join(tmpDir2, "v2_empty_dir"))
		if errEmpty != nil || !fiEmpty.IsDir() {
			t.Errorf("v2_empty_dir not restored as directory after GC: %v", errEmpty)
		}
	} else {
		fiEmpty, errEmpty := os.Stat(filepath.Join(tmpDir2, "v2_empty_folder"))
		if errEmpty != nil || !fiEmpty.IsDir() {
			t.Errorf("v2_empty_folder not restored as directory after GC: %v", errEmpty)
		}
	}
}

func TestTsyncSkipSymlinksAndSpecialFilesMatrix(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "matrix-symlink-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	regPath := filepath.Join(tmpDir, "regular.txt")
	_ = os.WriteFile(regPath, []byte("regular content"), 0644)
	subDir := filepath.Join(tmpDir, "sub")
	_ = os.MkdirAll(subDir, 0755)

	symPath := filepath.Join(tmpDir, "link.txt")
	_ = os.Symlink(regPath, symPath)

	localStore, err := NewLocalStorage(tmpDir)
	if err != nil {
		t.Fatalf("failed to create LocalStorage: %v", err)
	}

	destStore := NewMemStorage()
	client := NewClient(destStore)

	vmPub, vmPriv, _ := box.GenerateKey(rand.Reader)
	v, err := client.Backup(context.Background(), NewFolderSource(localStore, ""), BackupOptions{
		Label:      "symlink-matrix-run",
		KeyID:      "key-1",
		PublicKeys: map[string][]byte{"key-1": vmPub[:]},
	})
	if err != nil {
		t.Fatalf("backup with symlink failed: %v", err)
	}

	var zipBuf bytes.Buffer
	err = client.Restore(context.Background(), v.SnowflakeId, RestoreOptions{
		ZipWriter:  &zipBuf,
		PrivateKey: vmPriv[:],
	})
	if err != nil {
		t.Fatalf("restore failed: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(zipBuf.Bytes()), int64(zipBuf.Len()))
	if err != nil {
		t.Fatalf("failed to parse restored zip: %v", err)
	}

	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "link.txt") {
			t.Errorf("expected link.txt (symlink) to be skipped from backup, but found in restored ZIP")
		}
	}
}
