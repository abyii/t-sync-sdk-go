# t-sync Go SDK

The Go SDK for **t-sync**: a secure, incremental, and highly optimized backup format that shards files into compressed and encrypted parts, offering zero-I/O streaming, deduplication, and NaCl box cryptographic wrapping.

This SDK is a fairly optimised implementation of the t-sync spec: https://github.com/abyii/t-sync-proto/blob/main/docs/spec.md . Provides functionalities like Backup, Restore, Garbage Collection, Reconstruct ZIP, Query Metadata, etc. For different kinds of sources and destinations, e.g. compressed and encrypted/unencrypted zip source/destination, or local filesystem/object storage (s3, oci, etc.) source/destination.

Features:
* Zero temporary disk I/O: Operations run purely in memory using streaming pipelines.
* Bounded O(1) memory consumption: Uses direct, backpressured stream copies rather than loading entire files or part buffers into memory.
* Parallel worker engines: Parallel processing of file parts during backup uploads and concurrent extraction during restoration.
* Atomic Writes: Restorations write to a temporary file in the destination folder before renaming atomically (`os.Rename`), ensuring failures never leave half-written corrupt files on disk.
* Direct Protobuf presentation: Schema-driven representations (`tsyncv1.Version`, `tsyncv1.FileRecord`) are exposed directly to prevent drift.

---

## Installation

```bash
go get github.com/abyii/t-sync-sdk-go/tsync
```

---

## Quick Start Examples

### 1. Initialize Client & Storage Client
You can wrap standard filesystems or configure cloud-based object storages (such as AWS S3 or OCI Object Storage).

```go
package main

import (
	"context"
	"log"
	
	"github.com/abyii/t-sync-sdk-go/tsync"
)

func main() {
	ctx := context.Background()

	// Initialize Local Storage backend (acting as backup destination)
	destStore, err := tsync.NewLocalStorage("./backup-vault")
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}

	// Create the high-level T-Sync Client
	client := tsync.NewClient(destStore)
}
```

### 2. Run a Backup Pass (Unencrypted Source)
Generate a throw-away ZIP password per backup pass, encrypt it once using the VM's public key, and back up a local folder.

```go
// Setup cryptographic keys
publicKeys := map[string][]byte{
    "vm-key-1": vmPublicKeyBytes, // 32-byte Curve25519 public key
}

// Source acting as a file-system directory
srcStore, _ := tsync.NewLocalStorage("./my-local-data")
srcFolder := tsync.NewFolderSource(srcStore, "")

// Perform Backup
version, err := client.Backup(ctx, srcFolder, tsync.BackupOptions{
    Label:       "daily-backup-v1",
    Concurrency: 4,
    KeyID:       "vm-key-1",
    PublicKeys:  publicKeys,
})
if err != nil {
    log.Fatalf("Backup failed: %v", err)
}

log.Printf("Successfully created Backup Version: %d (%s)", version.SnowflakeId, version.Label)
```

### 3. Run a Backup Pass from a ZIP Source (Case A/B)
You can back up directly from a ZIP file without extracting it to disk first. Pre-compressed files will be encrypted on-the-fly, and already encrypted files will be backed up directly.

```go
// Source representing a ZIP file in local or object storage
srcStore, _ := tsync.NewLocalStorage("./my-zip-storage")

// Unencrypted ZIP source (Case B):
zipSrc := tsync.NewZipFileSource(srcStore, "my-archive.zip", false)

version, err := client.Backup(ctx, zipSrc, tsync.BackupOptions{
    Label:       "zip-backup-v1",
    Concurrency: 4,
    KeyID:       "vm-key-1",
    PublicKeys:  publicKeys,
})

// Already encrypted ZIP source (Case A):
// We must specify the EphPublicKey and EncryptedPassword that was used to encrypt the ZIP
encZipSrc := tsync.NewZipFileSource(srcStore, "encrypted-archive.zip", true)

version, err = client.Backup(ctx, encZipSrc, tsync.BackupOptions{
    Label:             "enc-zip-backup-v1",
    Concurrency:       4,
    KeyID:             "vm-key-1",
    PublicKeys:        publicKeys,
    EphPublicKey:      ephPublicKeyBytes,   // 32-byte ephemeral public key
    EncryptedPassword: encryptedPasswordBytes, // 40-byte encrypted zip password
})
```

### 4. Restore to Local Directory (Parallel & Incremental)
Restore files directly into a target folder using concurrent extraction workers and incremental size/CRC32 mismatch optimizations.

```go
err = client.Restore(ctx, version.SnowflakeId, tsync.RestoreOptions{
    ExtractDir:           "./restored-data",
    PrivateKey:           vmPrivateKeyBytes, // 32-byte Curve25519 private key
    Concurrency:          4,                 // Concurrently extract files
    NoOverwrite:          false,             // Set true to skip overwrite checks entirely
    SkipDecryptionErrors: false,
})
if err != nil {
    log.Fatalf("Restore failed: %v", err)
}
```

### 5. Reconstruct ZIP Archive (On-the-fly Rekeying)
Reconstruct a version directly into a ZIP stream, rekeying the files to a new password on-the-fly.

```go
zipFile, err := os.Create("restored.zip")
if err != nil {
    log.Fatal(err)
}
defer zipFile.Close()

err = client.Restore(ctx, version.SnowflakeId, tsync.RestoreOptions{
    ZipWriter:   zipFile,
    PrivateKey:  vmPrivateKeyBytes,
    NewPassword: "strongNewZipPassword", // Re-encrypt on-the-fly with standard zip password
})
if err != nil {
    log.Fatalf("ZIP reconstruction failed: %v", err)
}
```

---

## Detailed Core APIs

### The `Storage` Interface
The engine relies on a key-value/object-like store interface for reading and writing files:

```go
type Storage interface {
	Exists(ctx context.Context, path string) (bool, error)
	Read(ctx context.Context, path string) ([]byte, error)
	Write(ctx context.Context, path string, data []byte) error
	Delete(ctx context.Context, path string) error
	List(ctx context.Context, prefix string) ([]FileInfo, error)
	OpenReader(ctx context.Context, path string) (io.ReadCloser, error)
	OpenWriter(ctx context.Context, path string) (io.WriteCloser, error)
	Size(ctx context.Context, path string) (int64, error)
	ReadRange(ctx context.Context, path string, offset, length int64) (io.ReadCloser, error)
}
```

### The `Source` Interface
Represents the backing source being backed up (can be a folder on disk, S3 folder, or an existing ZIP file):

```go
type Source interface {
	ListEntries(ctx context.Context) ([]SourceEntry, error)
}
```

### Querying Backup Store Metadata
`StoreMetadata` is a presentation wrapper for querying backup versions, keys, and file records from the `.tsync` directory metadata.

```go
// Load metadata from destination
sm, err := client.ReadMetadata(ctx)
if err != nil {
    log.Fatal(err)
}

// Reload metadata in case of updates
_ = sm.Reload(ctx)

// Query structures directly
latestVersion := sm.LatestVersion() // Returns *tsyncv1.Version
registeredFiles := sm.Files()       // Returns map[string]*tsyncv1.FileRecord
versionsList := sm.Versions()       // Returns []*tsyncv1.Version sorted by time desc
```

---

## Garbage Collection (GC)
Prune unused file-part objects from destination storage (objects that are no longer referenced by any remaining version in the `.tsync` metadata file).

```go
err = client.GC(ctx)
if err != nil {
    log.Fatalf("GC failed: %v", err)
}
```

---

## Development and Testing

The SDK features comprehensive test coverage split into domain-specific test suites:
* `mem_storage_test.go`: Thread-safe mock in-memory store.
* `crypto_test.go`: Unit tests for Box encryption/decryption keys.
* `backup_restore_test.go`: Comprehensive lifecycle integration verification.
* `storage_test.go`: Local filesystem integration testing.
* `client_test.go`: Wrapped metadata checks.

To run all tests:
```bash
go test -count=1 -v ./...
```