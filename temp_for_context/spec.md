# T-Sync Specification — v2

## 1. Overview

A T-Sync backup store consists of two parts:

1. **A metadata file** (`.tsync`) — a single protobuf-serialized `BackupMetadata`
   message describing all versions, all directory trees, all unique file blobs,
   and encryption keys.

2. **File-part objects** — one encrypted binary object per unique compound file key,
   stored in any object store (S3, GCS, local disk, etc.). Each object contains:
   ```
   [ Local File Header (LFH) | compressed+encrypted content | Data Descriptor ]
   ```
   The LFH and Data Descriptor are **not** encrypted. Only the content is.

A conforming implementation can reconstruct any versioned ZIP archive from just
these two inputs plus the private key corresponding to the stored public key.

---

## 2. Content identity and compound key

T-Sync uses a compound file key derived from the **CRC32** and the **uncompressed size** of the raw (pre-compression, pre-encryption) file content as the primary content identifier.

- Compound key format: `<crc32_hex>_<uncompressed_size>` (e.g. `"1a2b3c4d_12345"`).
  - `<crc32_hex>`: 8-character lowercase hexadecimal representation of the 32-bit CRC32 checksum, zero-padded if necessary.
  - `<uncompressed_size>`: Decimal representation of the uncompressed file size in bytes.
- Encoding in proto map keys: String representation of the compound key (e.g. `"1a2b3c4d_12345"`).
- Encoding in `FileRecord.crc32` and `FileLeaf.crc32`: `fixed32` binary (representing the raw CRC32 value).
- The CRC32 checksum covers **file content only** — not filename, timestamps, or any metadata.
- CRC32 is already computed and stored in every standard ZIP file header/descriptor, removing the need for a separate custom hashing pass. Combining CRC32 with the uncompressed size practically eliminates the risk of collisions.

---

## 3. Version tree model

Every `Version` contains a `root_tree_hash` pointing to a `TreeNode` in the
content-addressed tree store (`BackupMetadata.trees`). The complete file listing
for a version is obtained by recursively walking the tree.

### TreeNode

A `TreeNode` represents one directory. It contains a sorted list of `TreeEntry`
items — each either a file leaf or a reference to a child `TreeNode` (subdirectory).

```
TreeNode {
  entries: [TreeEntry]   // sorted by name, lexicographic byte order
}
```

### TreeEntry

```
TreeEntry {
  name: string           // single path component (e.g. "main.go")
  oneof {
    file: FileLeaf       // this entry is a file
    subtree_hash: string  // this entry is a subdirectory (SHA-256 hex)
  }
}
```

**Name validation rules:**
- Must not be empty.
- Must not contain `/` or `\`.
- Must not contain null bytes (0x00).
- Must not be the literal name `.` or `..` (directory traversal entries).
  Dots within normal filenames (e.g. `main.go`) are valid.
- Should not exceed 255 bytes (common filesystem limit).

### FileLeaf

```
FileLeaf {
  crc32: fixed32          // CRC-32 of uncompressed content
  uncompressed_size: int64 // byte count of uncompressed content
}
```

The compound file key is derived: `sprintf("%08x_%d", crc32, uncompressed_size)`.
This key is used to look up the `FileRecord` in `BackupMetadata.files`.

### Structural sharing

Two versions whose subdirectory is identical (same files, same names, same
content) will reference the **exact same** `TreeNode` hash. That node is stored
once in `BackupMetadata.trees`, regardless of how many versions reference it.

This replaces v1's FULL/DELTA heuristic. Every version is always a complete,
self-sufficient snapshot — no parent resolution, no delta chains, no heuristic.
Space efficiency comes from structural sharing of unchanged subtrees.

---

## 4. Canonical serialization of TreeNodes

TreeNode hashes are the foundation of the content-addressed tree. Deterministic
serialization is **mandatory** — two implementations given the same logical
directory must produce the same hash.

### Rules

1. **Sort entries** by `name` — raw UTF-8 byte order, case-sensitive.
2. **Deterministic proto3 binary encoding:**
   - No unknown fields.
   - Fields at their default/zero value are elided (standard proto3 behaviour).
     A zero-byte file (`crc32=0`, `uncompressed_size=0`) produces a valid but
     empty `FileLeaf` sub-message.
   - Varints must use minimal-length encoding.
   - Map fields are not present in `TreeNode`, so map ordering is not relevant.
3. **Hash:** Compute SHA-256 over the serialized bytes. Encode as a 64-character
   lowercase hex string. This is the map key in `BackupMetadata.trees`.

### Reference implementation

Go: `proto.MarshalOptions{Deterministic: true}` — or the equivalent
deterministic serializer in your language.

### Empty directory sentinel

An empty directory has zero entries. Its canonical serialization is zero bytes,
producing the well-known SHA-256 of empty input:

```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

All empty directories across all versions share this one hash.

---

## 5. Version resolution

To resolve version V to a complete `path → file_key` map:

```
func resolve(V, trees, files):
    root = trees[V.root_tree_hash]
    return walk(root, "", trees)

func walk(node, prefix, trees):
    result = {}
    for entry in node.entries:
        full_path = prefix + entry.name
        if entry is file:
            file_key = sprintf("%08x_%d", entry.file.crc32, entry.file.uncompressed_size)
            result[full_path] = file_key
        else:  // subtree
            child = trees[entry.subtree_hash]
            result.merge(walk(child, full_path + "/", trees))
    return result
```

No parent lookups, no delta application. One recursive tree walk.

---

## 6. Encryption model

Each unique file blob is compressed and then encrypted using ZipCrypto. The ZipCrypto password (which acts as the symmetric key) is itself encrypted using **NaCl Box** (Curve25519 ECDH + XSalsa20-Poly1305).

```
plaintext content
    → compress (deflate or stored)
    → encrypt with ZipCrypto using password
    → store as file-part object

ZipCrypto password
    → encrypt with NaCl Box (ephemeral Curve25519 keypair + VM public key)
    → store as FileRecord.encrypted_zip_password
```

Decryption is derived via ECDH using the VM's private key and the stored `FileRecord.ephemeral_public_key`.

The VM public key is stored in `BackupMetadata.public_keys`, keyed by `key_id`.
The `FileRecord` references this key via `key_id`.

**Key rotation**: To rotate keys, decrypt each affected `encrypted_zip_password` with the old private key, re-encrypt with the new public key (using a fresh ephemeral keypair), update `FileRecord.encrypted_zip_password`, `FileRecord.ephemeral_public_key`, and `FileRecord.key_id`, and add the new public key to `BackupMetadata.public_keys`. The file-part objects themselves do not change.

---

## 7. ZIP reconstruction

To reconstruct a ZIP for version V:

1. Resolve V to a complete `path → file_key` map (see §5).
2. For each `(path, file_key)` pair:
   a. Look up `FileRecord` in `BackupMetadata.files[file_key]`.
   b. Decrypt `FileRecord.encrypted_zip_password` using the private key for `FileRecord.key_id` and the `FileRecord.ephemeral_public_key`.
   c. Fetch the file-part object for `file_key` from the object store.
   d. Decrypt and decompress the content using the decrypted ZIP password.
   e. The LFH and Data Descriptor in the file-part object are already well-formed
      ZIP structures. Use them directly.
3. Build the ZIP Central Directory:
   - For each file, write a Central Directory Header using:
     - File path from the resolved map key
     - `compressed_size`, `uncompressed_size` from `FileRecord` (or Data Descriptor)
     - `last_modified` from `FileRecord` → convert to DOS time/date
     - CRC-32 from `FileRecord.crc32` (or the Data Descriptor in the file-part object)
     - `relative_offset_of_local_header` → computed from sequential byte offsets
       as file-part objects are written
4. Write End of Central Directory record.

---

## 8. GC — removing a version

To delete version V:

1. Remove V from `BackupMetadata.versions`.
2. Collect the set of all live tree hashes and file keys by walking every
   remaining version's tree:

   ```
   live_tree_hashes = {}
   live_file_keys = {}

   for V in BackupMetadata.versions:
       walk_collect(V.root_tree_hash, live_tree_hashes, live_file_keys)

   func walk_collect(tree_hash, live_trees, live_files):
       if tree_hash in live_trees:
           return  // already visited (structural sharing)
       live_trees.add(tree_hash)
       node = BackupMetadata.trees[tree_hash]
       for entry in node.entries:
           if entry is file:
               file_key = sprintf("%08x_%d", entry.file.crc32, entry.file.uncompressed_size)
               live_files.add(file_key)
           else:
               walk_collect(entry.subtree_hash, live_trees, live_files)
   ```

3. GC orphaned `TreeNode`s:
   ```
   for tree_hash in BackupMetadata.trees:
       if tree_hash not in live_tree_hashes:
           delete BackupMetadata.trees[tree_hash]
   ```

4. GC orphaned `FileRecord`s:
   ```
   for file_key in BackupMetadata.files:
       if file_key not in live_file_keys:
           delete BackupMetadata.files[file_key]
           delete file-part object from object store
   ```

Note: the `walk_collect` function short-circuits on already-visited hashes. This
means the total work is proportional to the number of **distinct** tree nodes
across all live versions, not the sum of all versions' tree sizes. Structural
sharing makes this efficient even with many versions.

Unlike v1, there is no need to "promote" child versions when deleting a parent —
every version is self-sufficient via its root tree hash.

---

## 9. File-part object naming

File-part objects in the object store should be named by their compound file key:

```
<store_root>/<key[0:2]>/<key>
```

For example, if the key is `1a2b3c4d_12345`, the sharded path would be `<store_root>/1a/1a2b3c4d_12345`.
The two-character prefix sharding avoids filesystem/object-store hot spots when
there are many files (same convention as Git's object store).

---

## 10. Conformance

A conforming implementation must:

- Reject any `BackupMetadata` with `schema_version != 2`
- Reject any `TreeEntry` with an empty `name` or a `name` containing `/`, `\`, null bytes, or the literal `.` or `..`
- Reject any `TreeEntry` where neither `file` nor `subtree_hash` is set
- Reject any `TreeNode` whose entries are not sorted by `name` (byte-order)
- Correctly implement the canonical serialization algorithm in §4 and verify
  TreeNode hashes match their map keys
- Correctly resolve a version's file tree by recursive tree walk (§5)
- Correctly derive DOS time/date from `FileRecord.last_modified` for CD entries
- Correctly identify files using the compound file key (`<crc32_hex>_<uncompressed_size>`)

Test vectors are in `conformance/testdata/`. See that directory's README for
the format.
