package tsync

import (
	"context"
	"fmt"
	"io"
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

	// Open returns a read closer for the raw, uncompressed, unencrypted content.
	// Used when IsEncryptedRaw is false.
	Open func() (io.ReadCloser, error)

	// IsEncryptedRaw is true if the source is already an encrypted zip.
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

	var entries []SourceEntry
	for _, f := range files {
		fileInfo := f
		entries = append(entries, SourceEntry{
			Path:         fileInfo.Name,
			Size:         fileInfo.Size,
			LastModified: fileInfo.LastModified,
			Open: func() (io.ReadCloser, error) {
				return s.store.OpenReader(context.Background(), fileInfo.Name)
			},
		})
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

	var entries []SourceEntry
	for _, r := range ranges {
		partRange := r

		entry := SourceEntry{
			Path:           partRange.Name,
			Size:           int64(partRange.File.UncompressedSize64),
			CompressedSize: int64(partRange.File.CompressedSize64),
			LastModified:   MSDosTimeToTime(partRange.File.ModifiedDate, partRange.File.ModifiedTime),
			CRC32:          partRange.File.CRC32,
		}

		if s.isEncrypted {
			entry.IsEncryptedRaw = true
			entry.OpenRaw = func() (io.ReadCloser, error) {
				// Read exactly the range of this part directly from storage
				return s.store.ReadRange(context.Background(), s.zipPath, partRange.StartOffset, partRange.EndOffset-partRange.StartOffset)
			}
		} else {
			entry.Open = func() (io.ReadCloser, error) {
				return partRange.File.Open()
			}
			entry.CompressionMethod = partRange.File.Method
			entry.OpenRawCompressed = func() (io.ReadCloser, error) {
				rc, err := s.store.ReadRange(context.Background(), s.zipPath, partRange.StartOffset, partRange.EndOffset-partRange.StartOffset)
				if err != nil {
					return nil, err
				}
				_, err = zip.ReadLocalFileHeader(rc)
				if err != nil {
					rc.Close()
					return nil, err
				}
				return &limitReadCloser{
					r: io.LimitReader(rc, int64(partRange.File.CompressedSize64)),
					c: rc,
				}, nil
			}
		}

		entries = append(entries, entry)
	}

	return entries, nil
}
