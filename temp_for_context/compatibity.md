# T-Sync Compatibility Policy

## Versioning scheme

T-Sync uses **semver** for release tags (`v1.0.0`, `v2.0.0`, etc.) and
**proto package versioning** for breaking changes (`tsync.v1`, `tsync.v2`).

---

## Three-tier model

### Patch (e.g. v2.0.0 → v2.0.1)
- Comment or documentation fixes only
- No `.proto` file changes
- No BSR push required; tag the git repo

### Minor (e.g. v2.0 → v2.1)
- New **optional** fields added to existing messages
- New messages added
- New enum values added (readers must handle unknown enum values gracefully)
- Existing fields **deprecated** (marked with a comment, field number reserved)
- Wire-compatible: old readers silently ignore unknown fields (proto3 guarantee)
- Old writers produce messages that new readers handle correctly
- BSR push with new semver tag

### Major (e.g. v2 → v3)
- Any field removed, renamed, or type-changed
- Any field number reused
- Any message removed
- Any structural reorganisation
- **New proto package**: `com.github.abyii.tsync.v3`
- Old packages remain published and **frozen forever** — no further changes
- Clients migrate on their own schedule; all packages coexist on BSR

---

## Rules that are frozen for all time within v2

These rules may **never** be violated in a minor/patch release. Violation
requires a major version bump:

1. Field numbers are permanent. A removed field's number is tombstoned with `reserved`.
2. Field types are permanent.
3. The proto package name `com.github.abyii.tsync.v2` is permanent.
4. Enum value numbers are permanent.
5. The canonical serialization algorithm for `TreeNode` (sort-by-name, deterministic proto3, SHA-256) is permanent.

---

## v1 → v2 migration

The `com.github.abyii.tsync.v1` package remains published on BSR and frozen
forever. No further changes will be made to v1.

Key differences for migrators:
- The flat `path_to_file_key` map and FULL/DELTA model are replaced by a
  content-addressed hash tree (`TreeNode` / `TreeEntry` / `FileLeaf`).
- `Version.parent_id` (structural delta base in v1) is replaced by
  `Version.preceding_version_id` (informational history link in v2).
- `VersionKind` enum is removed — every version is a complete snapshot.
- The compound file key separator remains `_` (e.g. `"1a2b3c4d_12345"`).
  No change from v1.
- `FileRecord.crc32` is retained in v2 (field 4), same as v1.

Both v1 and v2 packages coexist. A single `.tsync` file uses exactly one
schema version — check `BackupMetadata.schema_version` (1 or 2) and decode
with the corresponding package.

---

## Deprecation process

When deprecating a field:

```protobuf
// Deprecated since v2.1.0 — use new_field instead.
// Field number 7 is reserved and must never be reused.
// string old_field = 7;
reserved 7;
reserved "old_field";
```

Deprecated fields are announced in CHANGELOG.md and removed from documentation,
but their field numbers and names are reserved permanently.

---

## How clients should handle unknown fields

Proto3 preserves unknown fields during decode→encode round-trips. Clients
should **not** strip unknown fields when re-serializing a `BackupMetadata`
they didn't originate. This ensures forward-compatibility: a v2.0 client
reading a v2.1 file and re-writing it doesn't lose the new fields.

---

## Breaking change detection in CI

The buf configuration enforces wire compatibility automatically:

```bash
# Run in CI on every PR against the main branch
buf breaking --against '.git#branch=main'
```

This will fail if any change would break existing generated code or wire format.
