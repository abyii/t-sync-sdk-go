# T-Sync Changelog

All notable changes to the T-Sync schema are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Changed

**Name validation (spec §TreeEntry, §10) — SDK `tsync` package**

- `\` (0x5C) is now an ordinary byte in `TreeEntry.name`. Only `/` separates path
  components. ZIP sources whose entry names contain `\` (e.g. `dir/a\b.txt`, can now be backed up and are restored to a ZIP
  with byte-identical entry names. `a\b.txt` and `a/b.txt` are distinct entries.
- Error for a `/` inside a name component changed from
  `name contains illegal character '/': "<name>"` to
  `name contains path separator '/': "<name>"`.
- Still rejected: empty components, `.`, `..`, null bytes, components longer than 255 bytes.

**Restore to `ExtractDir`**

- On Linux/macOS a `\` in a name is written literally (`a\b.txt` is one file).
- On Windows the OS treats `\` as a separator, so `a\b.txt` is extracted as `a/b.txt`.
  Names that would land outside `ExtractDir` (e.g. `..\up.txt`) fail with
  `illegal file path (directory traversal)`. ZIP→ZIP restore is unaffected and exact.

### Fixed

- Restore to `ExtractDir` no longer rejects names that merely start with `..`
  (e.g. `..a.txt`, `..cfg/x.txt`) as directory traversal, and no longer skips such
  empty directories. Only paths that actually resolve outside `ExtractDir` are rejected.

### Compatibility with older SDK versions

- **Stores written by older SDKs:** fully readable by this version. Nothing in the
  `.tsync` format changed: no proto change, same tree hashing, `schema_version` stays `2`.
- **Stores written by this version, read by SDK v2.0.0–v2.0.11:** versions without `\`
  in any name are unaffected. Older SDKs still reject `\` when they validate tree entry
  names, so once any version in a store contains a name with `\`:
  - `Restore` / `ListFiles` of a version containing `\` fail with
    `name contains illegal character '\\'`. With `RestoreOptions.SkipValidationErrors`
    the entry is skipped with a warning instead; if the `\` is in a directory name, the
    whole subtree is skipped.
  - `DeleteVersion` and `GC` walk **every** version in the store, so a single version
    containing `\` makes them fail for the whole store, including unrelated versions.
  - `Backup` from an older SDK into such a store still succeeds (it does not walk existing
    trees), but a source containing `\` is still rejected by the older SDK.
- **Recommendation:** upgrade every reader/writer of a store (backup agents, restore
  agents, GC jobs) before backing up sources whose names contain `\`.
- **Known limitation (unchanged):** `TreeEntry.name` is a proto3 `string`, so names that
  are not valid UTF-8 (e.g. raw Shift-JIS/CP437 ZIP names) fail at backup with
  `failed to marshal tree node: string field contains invalid UTF-8`.

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
