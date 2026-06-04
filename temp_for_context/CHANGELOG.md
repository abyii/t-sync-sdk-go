# T-Sync Changelog

All notable changes to the T-Sync schema are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

---

## [2.0.0] — Content-addressed hash tree

**Breaking change — new proto package `com.github.abyii.tsync.v2`.**
The v1 package (`com.github.abyii.tsync.v1`) remains published and frozen forever.
Both packages coexist on BSR; clients migrate on their own schedule.

### Added

**`metadata.proto`**
- `TreeNode` message — content-addressed directory node, keyed by SHA-256 of its canonical serialized bytes
- `TreeEntry` message — one item in a TreeNode: either a `FileLeaf` or a `subtree_hash`
- `FileLeaf` message — file reference carrying `crc32` + `uncompressed_size` to form the compound key
- `Version.root_tree_hash` — SHA-256 hash of the root TreeNode for this version
- `Version.preceding_version_id` — optional informational link to the previous version (not structural)
- `FileRecord.crc32` — CRC-32 restored for self-contained identity

**`t_sync.proto`**
- `BackupMetadata.trees` — content-addressed tree store (`map<string, TreeNode>`), shared across versions
- `BackupMetadata.schema_version` — always `2` for v2 messages

### Changed

**`metadata.proto`**
- `Version` no longer uses FULL/DELTA model — every version is a complete snapshot via its root tree hash
- `Version.parent_id` renamed to `Version.preceding_version_id` (informational only, not structural)
- Compound key separator remains `_` (unchanged from v1: `<crc32_hex>_<uncompressed_size>`)

**`t_sync.proto`**
- `BackupMetadata.versions` field number shifted from 1→1 (unchanged), `files` from 2→3, `public_keys` from 3→4, `schema_version` from 4→5, `store_label` from 5→6, `last_updated` from 6→7 (to accommodate new `trees` field at 2)

### Removed

**`metadata.proto`**
- `VersionKind` enum (`VERSION_KIND_UNSPECIFIED`, `VERSION_KIND_FULL`, `VERSION_KIND_DELTA`) — no longer needed; every version is a full snapshot
- `Version.kind` — removed with `VersionKind`
- `Version.path_to_file_key` — replaced by root tree hash + tree walk
- `Version.delta_changes` — eliminated by hash tree model
- `Version.delta_deleted` — eliminated by hash tree model

---

## [1.0.0] — Initial release

### Added

**`t_sync.proto`**
- `BackupMetadata.versions` — map of all backup versions keyed by snowflake_id (decimal string)
- `BackupMetadata.files` — content-addressable file records keyed by compound file key (`<crc32_hex>_<uncompressed_size>`)
- `BackupMetadata.public_keys` — VM long-lived public keys keyed by key_id
- `BackupMetadata.schema_version` — always `1` for v1 messages
- `BackupMetadata.store_label` — optional human-readable store name
- `BackupMetadata.last_updated` — timestamp of last metadata write

**`metadata.proto`**
- `VersionKind` enum: `VERSION_KIND_UNSPECIFIED (0)`, `VERSION_KIND_FULL (1)`, `VERSION_KIND_DELTA (2)`
- `Version.snowflake_id` — fixed64 unique version identifier
- `Version.backup_timestamp` — wall-clock time of snapshot
- `Version.kind` — VERSION_KIND_FULL or VERSION_KIND_DELTA
- `Version.path_to_file_key` — complete path→file_key map (VERSION_KIND_FULL only)
- `Version.parent_id` — parent snowflake_id (VERSION_KIND_DELTA only)
- `Version.delta_changes` — added/modified files (VERSION_KIND_DELTA only)
- `Version.delta_deleted` — deleted file paths (VERSION_KIND_DELTA only)
- `Version.label` — optional human-readable version label
- `FileRecord.ephemeral_public_key` — ephemeral public key used to encrypt ZIP password
- `FileRecord.encrypted_zip_password` — encrypted ZIP password
- `FileRecord.key_id` — reference to BackupMetadata.public_keys
- `FileRecord.crc32` — fixed32 content CRC32 checksum
- `FileRecord.compressed_size` — int64, bytes after compression
- `FileRecord.uncompressed_size` — int64, bytes before compression
- `FileRecord.last_modified` — source file modification time

---

<!-- versions below this line are future -->
<!-- [2.1.0] ... -->
<!-- [3.0.0] ... -->
