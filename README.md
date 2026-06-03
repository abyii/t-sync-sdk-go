# t-sync Go SDK

The Go SDK for **t-sync**: a secure, incremental, and highly optimized backup format that shards files into compressed and encrypted parts, offering zero-I/O streaming, deduplication, and NaCl box cryptographic wrapping.

This SDK is a fairly optimised implementation of the t-sync spec: https://github.com/abyii/t-sync-proto/blob/main/docs/spec.md . Provides functionalities like Backup, Restore, Garbage Collection, Reconstruct ZIP, Query Metadata, etc. For different kinds of sources and destinations, e.g. compressed and encrypted/unencrypted zip source/destination, or local filesystem/object storage (s3, oci, etc.) source/destination.

Features:
* Zero temporary disk I/O: Operations run purely in memory using streaming pipelines.
* Bounded O(1) memory consumption: Uses direct, backpressured stream copies rather than loading entire files or part buffers into memory.
* Parallel worker engines: Parallel processing of file parts during backup uploads and concurrent extraction during restoration.
* Atomic Writes: Restorations write to a temporary file in the destination folder before renaming atomically (`os.Rename`), ensuring failures never leave half-written corrupt files on disk.
* Direct Protobuf presentation: Schema-driven representations (`tsyncv1.Version`, `tsyncv1.FileRecord`) are exposed directly to prevent drift.
* Done/Total Progress callbacks: Track backup and restore progress in real-time.
* Smart disk space checking: Verifies available space on the target path, auto-falling back to single-threaded sequential extraction when space is tight, or aborting early if the remaining space is less than the largest file in the backup.

---

## Installation

```bash
go get github.com/abyii/t-sync-sdk-go/tsync
```

### Selective Storage Providers (AWS S3 & OCI Object Storage)
To keep the core `tsync` library lightweight and free of heavy external dependencies, the AWS S3 and OCI Go SDK implementations are decoupled into sub-packages.

* **LocalStorage & MemStorage**: Supported out-of-the-box with **zero** external cloud SDK dependencies.
* **AWS S3 Backend**: To enable and download the S3 dependencies, add this import to your code (e.g. in `main.go`):
  ```go
  import _ "github.com/abyii/t-sync-sdk-go/storage_clients/s3"
  ```
* **OCI Object Storage Backend**: To enable and download the Oracle OCI dependencies, add this import to your code:
  ```go
  import _ "github.com/abyii/t-sync-sdk-go/storage_clients/oci"
  ```
* **Generic HTTP / CDN / S3-Origin Backend**: Supported out-of-the-box with **zero** external dependencies. Supports range requests for seeking, single PUT/DELETE operations, custom request headers (for authentication, tokens, etc.), and native S3-compatible REST API multipart uploads. To enable:
  ```go
  import _ "github.com/abyii/t-sync-sdk-go/storage_clients/http"
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

## Progress Reporting & Disk-Space Pre-Check

Both `Backup` and `Restore` support an optional progress callback (`OnProgress`) that provides the name of the file being processed, the current `done` count, and the `total` number of files.

### Backup Progress

To monitor progress during a backup pass:

```go
version, err := client.Backup(ctx, srcFolder, tsync.BackupOptions{
    Label:       "daily-backup-v1",
    Concurrency: 4,
    KeyID:       "vm-key-1",
    PublicKeys:  publicKeys,
    OnProgress: func(done, total int, path string) {
        log.Printf("[%d/%d] Backed up: %s (%.2f%%)", done, total, path, float64(done)/float64(total)*100)
    },
})
```

### Restore Progress & Disk-Space-Aware Fallback

During a restoration (either direct directory extraction or ZIP reconstruction), progress can be tracked similarly:

```go
err = client.Restore(ctx, version.SnowflakeId, tsync.RestoreOptions{
    ExtractDir:  "./restored-data",
    PrivateKey:  vmPrivateKeyBytes,
    Concurrency: 4,
    OnProgress: func(done, total int, path string) {
        log.Printf("[%d/%d] Restored: %s (%.2f%%)", done, total, path, float64(done)/float64(total)*100)
    },
})
```

#### Smart Disk Space Pre-Checks

Before performing directory extraction (`ExtractDir`), the restore engine automatically checks the available disk space on the target drive (traversing to the first existing parent folder if the path does not exist yet):
1. **Abort Early**: If the free space is less than the size of the single largest uncompressed file in the backup, the restoration is aborted immediately with an `insufficient disk space` error.
2. **Sequential Fallback**: If the free space is larger than the single largest file but smaller than the total required uncompressed space for all files, the engine automatically prints a warning and switches the concurrency level to `1` (sequential mode) to ensure that only a single file's space overhead is required on disk at any given time.

### Compression Configuration

By default, the backup engine uses the `Deflate` compression method with a level of `5` for unencrypted sources. You can customize this by setting the `CompressionLevel` option in `BackupOptions`:

* **`nil` (or `-1`)**: Defaults to `Deflate` method with level `5`.
* **`0`**: Uses `Store` method (no compression, raw pass-through).
* **`1` to `9`**: Uses `Deflate` method with the specified compression level (from `1` for fastest compression to `9` for best compression).

Example:

```go
// Create a pointer to the compression level
compLevel := 9 // Best compression

version, err := client.Backup(ctx, srcFolder, tsync.BackupOptions{
    Label:            "highly-compressed-backup",
    Concurrency:      4,
    KeyID:            "vm-key-1",
    PublicKeys:       publicKeys,
    CompressionLevel: &compLevel,
})
```

### Custom Version ID & Backup Timestamp

By default, the backup engine automatically generates a random 64-bit Snowflake ID for the version and uses the current system time as the backup timestamp. You can override these by setting the `CustomVersionID` and `CustomBackupTimestamp` fields in `BackupOptions`:

* **`CustomVersionID` (uint64)**: An optional custom version ID.
  * Must be a positive 64-bit integer $\le 9223372036854775807$ (signed 64-bit maximum).
  * Must be unique (does not already exist in the backup store).
* **`CustomBackupTimestamp` (time.Time)**: An optional custom timestamp.
  * Must not be in the future (allowing up to 1 hour clock skew).
  * Must be strictly after the latest existing backup version's timestamp in the store.

Example:

```go
customID := uint64(1234567890)
customTime := time.Now().Add(-24 * time.Hour) // 24 hours ago

version, err := client.Backup(ctx, srcFolder, tsync.BackupOptions{
    Label:                 "historical-backup",
    Concurrency:           4,
    KeyID:                 "vm-key-1",
    PublicKeys:            publicKeys,
    CustomVersionID:       customID,
    CustomBackupTimestamp: customTime,
})
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

## Best Practices

To ensure high performance, security, and resource efficiency when using the T-Sync SDK, adhere to the following best practices:

### 1. Selective Import of Storage Clients
Avoid importing all storage clients. External cloud SDKs (AWS SDK and OCI SDK) add significant size and memory footprints to your binary.
* For thin clients (e.g., restore agents run on VM instances), compile only with the required driver (e.g., `storage_clients/http` for static/CDN endpoints, or `storage_clients/s3` for AWS environments).
* Keep your imports localized to your entry point (usually `main.go`).

### 2. Tuning Backup and Restore Concurrency
* **Network-bound environments (S3/OCI)**: Scale concurrency (e.g., `Concurrency: 4` to `8`) to parallelize HTTP requests and optimize bandwidth utilization.
* **Local disk-bound environments**: Restrict concurrency to `2` or `4` to prevent I/O saturation.
* **Rate Limits**: Excessive concurrency against remote APIs can trigger HTTP `429 Too Many Requests` or `503 Service Unavailable`. If rate-limiting occurs, decrease the concurrency value.

### 3. Graceful Termination & Context Propagation
Always thread a cancelable `context.Context` (with appropriate timeouts) through all API calls:
* If a backup or restore is aborted (e.g., on `SIGTERM` or container termination), the SDK will immediately halt worker pools, abort active upload streams, and clean up temporary partial write artifacts from disk.

### 4. Key Management & Crypto Password Lifecycle
* Generate strong, cryptographically secure random passwords for each backup pass.
* Safely wrap the password using the public key of the targeted VM.
* Never hardcode public keys or keep private keys in plaintext config files. Use a secure vault system (e.g., AWS Secrets Manager or OCI Vault) to provision keys to your agent.

### 5. Memory Management
* The SDK operates in $O(1)$ memory by utilizing streaming writes directly to the target storage writer interface.
* Avoid loading file contents into custom memory buffers prior to feeding them to the `Source` interface. Instead, implement a streaming `io.Reader` implementation where possible.

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