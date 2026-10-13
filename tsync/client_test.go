package tsync

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strconv"
	"testing"
	"time"

	tsyncv2 "github.com/abyii/t-sync-sdk-go/v2/gen/go/com/github/abyii/tsync/v2"
	zip "github.com/abyii/zip-xxh3"
	"golang.org/x/crypto/nacl/box"
	"google.golang.org/protobuf/proto"
)

func TestZipFileSourceAndLoadStoreInfo(t *testing.T) {
	// Create a zip file in a mock Storage
	srcStore := NewMemStorage()

	// Create an unencrypted ZIP with some files
	var zipBuf bytes.Buffer
	zipw := zip.NewWriter(&zipBuf)

	w1, _ := zipw.Create("hello.txt", zip.Deflate, -1, zip.NoEncryption, "")
	_, _ = w1.Write([]byte("hello world"))
	w2, _ := zipw.Create("world.txt", zip.Deflate, -1, zip.NoEncryption, "")
	_, _ = w2.Write([]byte("world hello"))
	_ = zipw.Close()

	_ = srcStore.Write(context.Background(), "my-archive.zip", zipBuf.Bytes())

	// Open ZipFileSource
	zipSrc := NewZipFileSource(srcStore, "my-archive.zip", false)
	entries, err := zipSrc.ListEntries(context.Background())
	if err != nil {
		t.Fatalf("failed to list entries: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	// Verify we can read contents from entry without temp file
	for _, entry := range entries {
		rc, err := entry.Open()
		if err != nil {
			t.Fatalf("failed to open entry %s: %v", entry.Path, err)
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		if entry.Path == "hello.txt" && string(data) != "hello world" {
			t.Errorf("expected 'hello world', got %q", string(data))
		}
	}

	// Backup from ZipFileSource
	destStore := NewMemStorage()
	client := NewClient(destStore)
	vmPub, _, _ := box.GenerateKey(rand.Reader)

	_, err = client.Backup(context.Background(), zipSrc, BackupOptions{
		Label:      "zip-backup",
		KeyID:      "key-1",
		PublicKeys: map[string][]byte{"key-1": vmPub[:]},
	})
	if err != nil {
		t.Fatalf("backup failed: %v", err)
	}

	// Test ReadMetadata
	sm, err := client.ReadMetadata(context.Background())
	if err != nil {
		t.Fatalf("ReadMetadata failed: %v", err)
	}

	if sm.StoreLabel() != "" {
		t.Errorf("expected empty store label")
	}
	if len(sm.Versions()) != 1 {
		t.Errorf("expected 1 version, got %d", len(sm.Versions()))
	}
	if len(sm.Files()) != 2 {
		t.Errorf("expected 2 file records in pool, got %d", len(sm.Files()))
	}
}

func TestStoreMetadataWrapper(t *testing.T) {
	destStore := NewMemStorage()
	client := NewClient(destStore)
	vmPub, _, _ := box.GenerateKey(rand.Reader)

	// Create dynamic files to backup
	srcStore := NewMemStorage()
	_ = srcStore.Write(context.Background(), "a.txt", []byte("aaa"))
	folderSrc := NewFolderSource(srcStore, "")

	v, err := client.Backup(context.Background(), folderSrc, BackupOptions{
		Label:      "test-run",
		KeyID:      "my-key",
		PublicKeys: map[string][]byte{"my-key": vmPub[:]},
	})
	if err != nil {
		t.Fatalf("backup failed: %v", err)
	}

	// 1. Read store metadata
	sm, err := client.ReadMetadata(context.Background())
	if err != nil {
		t.Fatalf("ReadMetadata failed: %v", err)
	}

	// Verify metadata values
	if sm.SchemaVersion() != 2 {
		t.Errorf("expected SchemaVersion 2, got %d", sm.SchemaVersion())
	}
	if len(sm.PublicKeys()) != 1 || sm.PublicKeys()["my-key"] == nil {
		t.Errorf("missing public key")
	}

	latest := sm.LatestVersion()
	if latest == nil || latest.SnowflakeId != v.SnowflakeId {
		t.Errorf("latest version ID mismatch")
	}
	if latest.Label != "test-run" {
		t.Errorf("latest version label mismatch")
	}

	if !sm.HasVersion(v.SnowflakeId) {
		t.Errorf("expected version %d to exist", v.SnowflakeId)
	}

	if len(sm.Versions()) != 1 {
		t.Errorf("expected 1 version, got %d", len(sm.Versions()))
	}
	if len(sm.Files()) != 1 {
		t.Errorf("expected 1 file record, got %d", len(sm.Files()))
	}

	// 2. Perform another backup to verify Reload works
	_ = srcStore.Write(context.Background(), "b.txt", []byte("bbb"))
	time.Sleep(5 * time.Millisecond)
	_, err = client.Backup(context.Background(), folderSrc, BackupOptions{
		Label: "second-run",
	})
	if err != nil {
		t.Fatalf("second backup failed: %v", err)
	}

	// Before reload, sm should have stale data (1 version)
	if len(sm.Versions()) != 1 {
		t.Errorf("expected cached sm to still have 1 version, got %d", len(sm.Versions()))
	}

	// Reload sm
	err = sm.Reload(context.Background())
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	// After reload, sm should have the new version (2 versions)
	if len(sm.Versions()) != 2 {
		t.Errorf("expected reloaded sm to have 2 versions, got %d", len(sm.Versions()))
	}

	latest = sm.LatestVersion()
	if latest.Label != "second-run" {
		t.Errorf("expected reloaded latest label to be 'second-run', got %q", latest.Label)
	}
}

func TestListVersionsErrorClassification(t *testing.T) {
	ctx := context.Background()

	missing := &hookStorage{Storage: NewMemStorage(), read: func(context.Context, string) ([]byte, error) {
		return nil, fmt.Errorf("provider said: %w", ErrNotFound)
	}}
	if vs, err := NewClient(missing).ListVersions(ctx); err != nil || vs != nil {
		t.Fatalf("missing .tsync: expected nil, nil; got %v, %v", vs, err)
	}

	failing := &hookStorage{Storage: NewMemStorage(), read: func(context.Context, string) ([]byte, error) {
		return nil, errInjected
	}}
	if _, err := NewClient(failing).ListVersions(ctx); !errors.Is(err, errInjected) {
		t.Fatalf("expected read failure to propagate, got %v", err)
	}

	corrupt := NewMemStorage()
	_ = corrupt.Write(ctx, ".tsync", []byte{0xFF, 0xFF, 0xFF})
	if _, err := NewClient(corrupt).ListVersions(ctx); !errors.Is(err, ErrCorruptMetadata) {
		t.Fatalf("expected ErrCorruptMetadata, got %v", err)
	}

	future := NewMemStorage()
	b, _ := proto.Marshal(&tsyncv2.BackupMetadata{SchemaVersion: 3})
	_ = future.Write(ctx, ".tsync", b)
	_, err := NewClient(future).ListVersions(ctx)
	var schemaErr *UnsupportedSchemaError
	if !errors.Is(err, ErrUnsupportedSchema) || !errors.As(err, &schemaErr) || schemaErr.Version != 3 {
		t.Fatalf("expected *UnsupportedSchemaError{3}, got %v", err)
	}
}

func TestClientVersionAndTreeErrors(t *testing.T) {
	ctx := context.Background()
	fx := newRestoreFixture(t, testFiles(), nil)
	c := NewClient(fx.store)

	if _, err := c.ListFiles(ctx, fx.version+1); !errors.Is(err, ErrVersionNotFound) {
		t.Fatalf("ListFiles: expected ErrVersionNotFound, got %v", err)
	}
	if err := c.DeleteVersion(ctx, fx.version+1); !errors.Is(err, ErrVersionNotFound) {
		t.Fatalf("DeleteVersion: expected ErrVersionNotFound, got %v", err)
	}

	md := fx.metadata(t)
	root := md.Versions[strconv.FormatUint(fx.version, 10)].RootTreeHash
	delete(md.Trees, root)
	fx.saveMetadata(t, md)
	if _, err := c.ListFiles(ctx, fx.version); !errors.Is(err, ErrCorruptMetadata) {
		t.Fatalf("ListFiles: expected ErrCorruptMetadata for missing tree, got %v", err)
	}
	if err := c.GC(ctx); !errors.Is(err, ErrCorruptMetadata) {
		t.Fatalf("GC: expected ErrCorruptMetadata for missing tree, got %v", err)
	}
}

func TestDeleteVersionMalformedFileKeyDoesNotPanic(t *testing.T) {
	ctx := context.Background()
	fx := newRestoreFixture(t, testFiles(), nil)
	md := fx.metadata(t)
	md.Files["x"] = &tsyncv2.FileRecord{} // damaged, orphaned record with a too-short key
	fx.saveMetadata(t, md)

	if err := NewClient(fx.store).DeleteVersion(ctx, fx.version); err != nil {
		t.Fatalf("DeleteVersion: %v", err)
	}
	after := fx.metadata(t)
	if len(after.Versions) != 0 || len(after.Files) != 0 {
		t.Fatalf("expected empty store after deleting the only version, got %d versions, %d files", len(after.Versions), len(after.Files))
	}
}
