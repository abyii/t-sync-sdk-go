package tsync

import (
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"sort"
	"time"

	zip "github.com/abyii/zip-xxh3"
)

// ZipPartRange defines the byte offset range of a single file part inside a ZIP file.
type ZipPartRange struct {
	Name        string
	StartOffset int64
	EndOffset   int64
	File        *zip.File
}

// GetZipPartRanges parses the ZIP structure and returns the start and end offsets of all file parts.
func GetZipPartRanges(ra io.ReaderAt, size int64) ([]ZipPartRange, error) {
	cdOffset, err := GetCentralDirectoryOffset(ra, size)
	if err != nil {
		return nil, fmt.Errorf("failed to get central directory offset: %w", err)
	}

	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return nil, fmt.Errorf("failed to parse central directory: %w", err)
	}

	type fileWithOffset struct {
		file   *zip.File
		offset int64
	}

	files := make([]fileWithOffset, len(zr.File))
	for i, f := range zr.File {
		files[i] = fileWithOffset{
			file:   f,
			offset: GetHeaderOffset(f),
		}
	}

	// Sort files by their local header offset to determine contiguous ranges
	sort.Slice(files, func(i, j int) bool {
		return files[i].offset < files[j].offset
	})

	ranges := make([]ZipPartRange, len(files))
	for i, item := range files {
		start := item.offset
		var end int64
		if i < len(files)-1 {
			end = files[i+1].offset
		} else {
			end = cdOffset
		}

		ranges[i] = ZipPartRange{
			Name:        item.file.Name,
			StartOffset: start,
			EndOffset:   end,
			File:        item.file,
		}
	}

	return ranges, nil
}

// GetHeaderOffset extracts the private "headerOffset" field of a zip.File using reflection.
func GetHeaderOffset(f *zip.File) int64 {
	val := reflect.ValueOf(*f)
	field := val.FieldByName("headerOffset")
	if !field.IsValid() {
		return 0
	}
	return field.Int()
}

// FindEOCD locates the End of Central Directory record in a ZIP file reader.
func FindEOCD(r io.ReaderAt, size int64) (int64, error) {
	bufSize := int64(65557)
	if bufSize > size {
		bufSize = size
	}
	buf := make([]byte, bufSize)
	_, err := r.ReadAt(buf, size-bufSize)
	if err != nil && err != io.EOF {
		return 0, err
	}
	for i := len(buf) - 22; i >= 0; i-- {
		// Look for standard EOCD signature: 0x06054b50 (PK\x05\x06) in little endian
		if buf[i] == 0x50 && buf[i+1] == 0x4b && buf[i+2] == 0x05 && buf[i+3] == 0x06 {
			return size - bufSize + int64(i), nil
		}
	}
	return 0, fmt.Errorf("EOCD not found")
}

// GetCentralDirectoryOffset computes the start offset of the Central Directory in a ZIP file.
func GetCentralDirectoryOffset(r io.ReaderAt, size int64) (int64, error) {
	eocdOffset, err := FindEOCD(r, size)
	if err != nil {
		return 0, err
	}
	buf := make([]byte, 22)
	if _, err := r.ReadAt(buf, eocdOffset); err != nil {
		return 0, err
	}
	cdOffset := int64(binary.LittleEndian.Uint32(buf[16:20]))

	// Check if Zip64 EOCD locator is present (located 20 bytes before EOCD)
	if eocdOffset >= 20 {
		locBuf := make([]byte, 20)
		if _, err := r.ReadAt(locBuf, eocdOffset-20); err == nil {
			// Signature: 0x07064b50 (PK\x06\x07)
			if locBuf[0] == 0x50 && locBuf[1] == 0x4b && locBuf[2] == 0x06 && locBuf[3] == 0x07 {
				zip64EocdOffset := int64(binary.LittleEndian.Uint64(locBuf[8:16]))
				recBuf := make([]byte, 56)
				if _, err := r.ReadAt(recBuf, zip64EocdOffset); err == nil {
					// Signature: 0x06064b50 (PK\x06\x06)
					if recBuf[0] == 0x50 && recBuf[1] == 0x4b && recBuf[2] == 0x06 && recBuf[3] == 0x06 {
						return int64(binary.LittleEndian.Uint64(recBuf[48:56])), nil
					}
				}
			}
		}
	}
	return cdOffset, nil
}

// MSDosTimeToTime converts MS-DOS timestamp format to time.Time.
func MSDosTimeToTime(dosDate, dosTime uint16) time.Time {
	seconds := int((dosTime & 0x1F) * 2)
	minutes := int((dosTime >> 5) & 0x3F)
	hours := int((dosTime >> 11) & 0x1F)

	day := int(dosDate & 0x1F)
	month := time.Month((dosDate >> 5) & 0x0F)
	year := int((dosDate>>9)&0x7F) + 1980

	return time.Date(year, month, day, hours, minutes, seconds, 0, time.UTC)
}
