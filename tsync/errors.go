package tsync

import (
	"errors"
	"fmt"

	"github.com/abyii/t-sync-sdk-go/v2/storage_clients"
)

// ErrNotFound is returned (wrapped) by Storage implementations when a path does not exist.
// It is the same value as storage_clients.ErrNotFound so callers can use either.
var ErrNotFound = storage_clients.ErrNotFound

var (
	// Backup timestamp / version ordering.
	ErrTimestampEqualsLatest = errors.New("tsync: backup timestamp equals the latest version's timestamp")
	ErrTimestampBeforeLatest = errors.New("tsync: backup timestamp is before the latest version's timestamp")
	ErrTimestampInFuture     = errors.New("tsync: backup timestamp is in the future")
	ErrVersionIDExists       = errors.New("tsync: version ID already exists")
	ErrVersionNotFound       = errors.New("tsync: version not found")

	// Store / metadata state.
	ErrStoreNotInitialized = errors.New("tsync: backup store not initialized (no .tsync and no public keys provided)")
	ErrCorruptMetadata     = errors.New("tsync: corrupt or inconsistent backup metadata")
	ErrUnsupportedSchema   = errors.New("tsync: unsupported metadata schema version")

	// Caller input.
	ErrInvalidOptions = errors.New("tsync: invalid options")
	ErrKeyNotFound    = errors.New("tsync: public key ID not found")
	ErrInvalidName    = errors.New("tsync: invalid path name")
	ErrPathCollision  = errors.New("tsync: path is both a file and a directory")
	ErrUnsafePath     = errors.New("tsync: unsafe path (directory traversal)")

	// Data integrity / crypto.
	ErrPrivateKeyRequired = errors.New("tsync: part is encrypted but no private key was provided")
	ErrDecryptionFailed   = errors.New("tsync: decryption failed")
	ErrCorruptPart        = errors.New("tsync: file part is corrupt (size/CRC mismatch)")
	ErrSourceChanged      = errors.New("tsync: source file changed during backup")
	ErrNotZip             = errors.New("tsync: not a valid zip archive")
	ErrCorruptZip         = errors.New("tsync: corrupt zip archive structure")
	// ErrUnsupportedEncryption is returned for pre-encrypted zip entries whose encryption scheme
	// cannot be backed up safely (WinZip AE-2 entries store no CRC32, so they cannot be keyed).
	ErrUnsupportedEncryption = errors.New("tsync: unsupported zip entry encryption")

	// Resources.
	ErrInsufficientDiskSpace = errors.New("tsync: insufficient disk space")
	ErrWriterClosed          = errors.New("tsync: writer is closed")

	// ErrIncompleteRun is returned when a backup/restore pass did not process every entry
	// (e.g. context cancelled between tasks). Nothing is committed when this is returned.
	ErrIncompleteRun = errors.New("tsync: run did not process all entries")
)

// UnsupportedSchemaError carries the schema version found. It matches ErrUnsupportedSchema.
type UnsupportedSchemaError struct {
	Version uint32
}

func (e *UnsupportedSchemaError) Error() string {
	return fmt.Sprintf("tsync: unsupported metadata schema version %d (expected 2)", e.Version)
}

func (e *UnsupportedSchemaError) Is(target error) bool { return target == ErrUnsupportedSchema }
