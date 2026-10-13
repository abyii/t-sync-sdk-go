package tsync

import (
	"bufio"
	"compress/flate"
	"context"
	"encoding/binary"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"strings"
	"time"

	zip "github.com/abyii/zip-xxh3"
)

// SourceEntry represents an individual file in a backup source.
type SourceEntry struct {
	Path           string
	Size           int64 // Raw/uncompressed size in bytes
	CompressedSize int64 // Compressed size in bytes (if known, e.g. from zip source)
	LastModified   time.Time
	CRC32          uint32 // Original CRC32 (if known, e.g. from a zip file)
	IsDir          bool   // True if the entry represents a directory

	// Open returns a read closer for the raw, uncompressed, unencrypted content.
	// Used when IsEncryptedRaw is false.
	Open func() (io.ReadCloser, error)

	// IsEncryptedRaw is true if the source is already an encrypted zip.
	// CRC32, Size and CompressedSize must then be the central-directory values of the entry.
	IsEncryptedRaw bool
	// OpenRaw returns a read closer for the raw encrypted part bytes (LFH + payload + Data Descriptor).
	// Used when IsEncryptedRaw is true.
	OpenRaw func() (io.ReadCloser, error)

	// CompressionMethod is the zip compression method (if known, e.g. Deflate or Store)
	CompressionMethod uint16
	// OpenRawCompressed returns a read closer for the raw compressed payload (excluding LFH and DD).
	// Used when IsEncryptedRaw is false, but we want to copy the compressed payload directly and encrypt it on the fly.
	OpenRawCompressed func() (io.ReadCloser, error)
}

// Source represents a unified interface for iterating files in any backup source.
//
// The ctx passed to ListEntries is the context of the backup run; Open/OpenRaw/OpenRawCompressed
// closures should perform their I/O with it so cancelling the run stops in-flight reads.
type Source interface {
	ListEntries(ctx context.Context) ([]SourceEntry, error)
}

// ---------------------------------------------------------
// FolderSource Implementation
// ---------------------------------------------------------

type FolderSource struct {
	store  Storage
	prefix string
}

func NewFolderSource(store Storage, prefix string) *FolderSource {
	return &FolderSource{
		store:  store,
		prefix: prefix,
	}
}

func (s *FolderSource) ListEntries(ctx context.Context) ([]SourceEntry, error) {
	files, err := s.store.List(ctx, s.prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list files in source folder: %w", err)
	}

	entries := make([]SourceEntry, 0, len(files))
	for _, f := range files {
		name := f.Name
		isDir := strings.HasSuffix(name, "/")
		entry := SourceEntry{
			Path:         name,
			Size:         f.Size,
			LastModified: f.LastModified,
			IsDir:        isDir,
		}
		if !isDir {
			entry.Open = func() (io.ReadCloser, error) {
				return s.store.OpenReader(ctx, name)
			}
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// ---------------------------------------------------------
// ZipFileSource Implementation
// ---------------------------------------------------------

type ZipFileSource struct {
	store       Storage
	zipPath     string
	isEncrypted bool
}

func NewZipFileSource(store Storage, zipPath string, isEncrypted bool) *ZipFileSource {
	return &ZipFileSource{
		store:       store,
		zipPath:     zipPath,
		isEncrypted: isEncrypted,
	}
}

const (
	localFileHeaderLen = 30
	localFileHeaderSig = 0x04034b50
	winzipAESExtraID   = 0x9901
)

// isWinZipAE2 reports whether the entry carries a WinZip AES extra field of vendor version AE-2,
// whose CRC32 is always stored as 0.
func isWinZipAE2(f *zip.File) bool {
	b := f.Extra
	for len(b) >= 4 {
		tag := binary.LittleEndian.Uint16(b)
		size := int(binary.LittleEndian.Uint16(b[2:]))
		b = b[4:]
		if size > len(b) {
			return false
		}
		if tag == winzipAESExtraID && size >= 2 {
			return binary.LittleEndian.Uint16(b) == 2
		}
		b = b[size:]
	}
	return false
}

func (s *ZipFileSource) ListEntries(ctx context.Context) ([]SourceEntry, error) {
	size, err := s.store.Size(ctx, s.zipPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get source zip size: %w", err)
	}

	readerAt := NewStorageReaderAt(ctx, s.store, s.zipPath)
	ranges, err := GetZipPartRanges(readerAt, size)
	if err != nil {
		return nil, fmt.Errorf("failed to parse zip parts: %w", err)
	}

	entries := make([]SourceEntry, 0, len(ranges))
	for _, r := range ranges {
		partRange := r
		f := partRange.File

		isDir := strings.HasSuffix(partRange.Name, "/")
		entry := SourceEntry{
			Path:           partRange.Name,
			Size:           int64(f.UncompressedSize64),
			CompressedSize: int64(f.CompressedSize64),
			LastModified:   MSDosTimeToTime(f.ModifiedDate, f.ModifiedTime),
			CRC32:          f.CRC32,
			IsDir:          isDir,
		}

		if !isDir {
			if s.isEncrypted {
				if isWinZipAE2(f) {
					return nil, fmt.Errorf("%w: entry %q is WinZip AE-2 encrypted (no CRC32 to key it by)", ErrUnsupportedEncryption, partRange.Name)
				}
				entry.IsEncryptedRaw = true
				entry.OpenRaw = func() (io.ReadCloser, error) {
					// Read exactly the range of this part directly from storage
					return s.store.ReadRange(ctx, s.zipPath, partRange.StartOffset, partRange.EndOffset-partRange.StartOffset)
				}
			} else {
				entry.CompressionMethod = f.Method
				if f.Flags&0x1 == 0 && (f.Method == zip.Store || f.Method == zip.Deflate) {
					// Stream the whole entry with a single ranged read.
					entry.Open = func() (io.ReadCloser, error) {
						return openZipEntryStream(ctx, s.store, s.zipPath, partRange)
					}
				} else {
					entry.Open = f.Open
				}
			}
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// openZipEntryStream reads an unencrypted Store/Deflate entry with ONE ReadRange covering
// its local header and payload, decompresses it and verifies size and CRC32 at EOF.
// (zip.File.Open would issue one ranged read per 4 KiB buffer fill.)
func openZipEntryStream(ctx context.Context, store Storage, zipPath string, pr ZipPartRange) (io.ReadCloser, error) {
	f := pr.File
	rc, err := store.ReadRange(ctx, zipPath, pr.StartOffset, pr.EndOffset-pr.StartOffset)
	if err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(rc, 64*1024)
	var lfh [localFileHeaderLen]byte
	if _, err := io.ReadFull(br, lfh[:]); err != nil {
		rc.Close()
		return nil, fmt.Errorf("%w: reading local header of %q: %w", ErrCorruptZip, f.Name, err)
	}
	if binary.LittleEndian.Uint32(lfh[:]) != localFileHeaderSig {
		rc.Close()
		return nil, fmt.Errorf("%w: bad local header signature for %q", ErrCorruptZip, f.Name)
	}
	skip := int64(binary.LittleEndian.Uint16(lfh[26:])) + int64(binary.LittleEndian.Uint16(lfh[28:]))
	if _, err := br.Discard(int(skip)); err != nil {
		rc.Close()
		return nil, fmt.Errorf("%w: reading local header of %q: %w", ErrCorruptZip, f.Name, err)
	}
	body := io.LimitReader(br, int64(f.CompressedSize64))

	z := &zipEntryStream{src: rc, hash: crc32.NewIEEE(), f: f}
	if f.Method == zip.Deflate {
		fr := flate.NewReader(body)
		z.r, z.decomp = fr, fr
	} else {
		z.r = body
	}
	return z, nil
}

type zipEntryStream struct {
	r      io.Reader
	decomp io.Closer // flate reader, if any
	src    io.Closer
	hash   hash.Hash32
	n      uint64
	f      *zip.File
	err    error
}

func (z *zipEntryStream) Read(p []byte) (int, error) {
	if z.err != nil {
		return 0, z.err
	}
	n, err := z.r.Read(p)
	z.hash.Write(p[:n])
	z.n += uint64(n)
	if z.n > z.f.UncompressedSize64 {
		z.err = fmt.Errorf("%w: %q decompresses beyond its declared size %d", ErrCorruptZip, z.f.Name, z.f.UncompressedSize64)
		return n, z.err
	}
	if err == io.EOF {
		if z.n != z.f.UncompressedSize64 {
			err = fmt.Errorf("%w: %q has %d bytes, central directory declares %d: %w", ErrCorruptZip, z.f.Name, z.n, z.f.UncompressedSize64, io.ErrUnexpectedEOF)
		} else if z.hash.Sum32() != z.f.CRC32 {
			err = fmt.Errorf("%w: %q: %w", ErrCorruptZip, z.f.Name, zip.ErrChecksum)
		}
	}
	if err != nil {
		z.err = err
	}
	return n, err
}

func (z *zipEntryStream) Close() error {
	if z.decomp != nil {
		z.decomp.Close()
	}
	return z.src.Close()
}
