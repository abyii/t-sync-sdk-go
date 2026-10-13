package tsync

import (
	"encoding/binary"
	"fmt"
	"io"
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

const (
	eocdLen            = 22
	eocdSignature      = 0x06054b50
	zip64LocatorLen    = 20
	zip64LocatorSig    = 0x07064b50
	zip64EOCDLen       = 56
	zip64EOCDSignature = 0x06064b50
	maxEOCDCommentLen  = 0xffff
)

// zipDirectory describes where the central directory of an archive lives.
type zipDirectory struct {
	eocdOffset int64 // offset of the (32-bit) EOCD record
	cdOffset   int64 // offset of the first central directory header
	cdSize     int64 // size of the central directory in bytes
	records    uint64
	// tailOffset/tail cache the bytes [tailOffset, size) read while locating the EOCD.
	tailOffset int64
	tail       []byte
}

// readZipDirectory locates and validates the EOCD (and zip64 EOCD when present) with one
// read of the archive tail (plus at most one read of the zip64 record if it is not in the tail).
func readZipDirectory(r io.ReaderAt, size int64) (*zipDirectory, error) {
	if size < eocdLen {
		return nil, fmt.Errorf("%w: file too small (%d bytes)", ErrNotZip, size)
	}
	// Large enough for EOCD + max comment + zip64 locator, and for the 65 KiB window
	// zip.NewReader scans, so that window is served from the cache.
	tailLen := int64(66 * 1024)
	if tailLen > size {
		tailLen = size
	}
	tailOffset := size - tailLen
	tail := make([]byte, tailLen)
	if n, err := r.ReadAt(tail, tailOffset); err != nil && !(err == io.EOF && int64(n) == tailLen) {
		return nil, fmt.Errorf("failed to read zip tail: %w", err)
	}

	// Scan backwards for an EOCD whose comment exactly reaches the end of the file.
	pos := -1
	for i := len(tail) - eocdLen; i >= 0; i-- {
		if binary.LittleEndian.Uint32(tail[i:]) != eocdSignature {
			continue
		}
		commentLen := int(binary.LittleEndian.Uint16(tail[i+20:]))
		if i+eocdLen+commentLen == len(tail) {
			pos = i
			break
		}
	}
	if pos < 0 {
		return nil, fmt.Errorf("%w: end of central directory record not found", ErrNotZip)
	}

	eocd := tail[pos : pos+eocdLen]
	d := &zipDirectory{
		eocdOffset: tailOffset + int64(pos),
		tailOffset: tailOffset,
		tail:       tail,
	}
	records16 := binary.LittleEndian.Uint16(eocd[10:])
	cdSize32 := binary.LittleEndian.Uint32(eocd[12:])
	cdOffset32 := binary.LittleEndian.Uint32(eocd[16:])
	d.records = uint64(records16)
	d.cdSize = int64(cdSize32)
	d.cdOffset = int64(cdOffset32)
	dirEnd := d.eocdOffset

	// Zip64 locator sits immediately before the EOCD.
	if d.eocdOffset >= zip64LocatorLen {
		loc, err := readAtCached(r, d, d.eocdOffset-zip64LocatorLen, zip64LocatorLen)
		if err != nil {
			return nil, fmt.Errorf("failed to read zip64 locator: %w", err)
		}
		if binary.LittleEndian.Uint32(loc) == zip64LocatorSig {
			recOffset := int64(binary.LittleEndian.Uint64(loc[8:]))
			if recOffset < 0 || recOffset+zip64EOCDLen > d.eocdOffset-zip64LocatorLen {
				return nil, fmt.Errorf("%w: zip64 end of central directory offset %d out of range", ErrCorruptZip, recOffset)
			}
			rec, err := readAtCached(r, d, recOffset, zip64EOCDLen)
			if err != nil {
				return nil, fmt.Errorf("failed to read zip64 end of central directory: %w", err)
			}
			if binary.LittleEndian.Uint32(rec) != zip64EOCDSignature {
				return nil, fmt.Errorf("%w: bad zip64 end of central directory signature", ErrCorruptZip)
			}
			d.records = binary.LittleEndian.Uint64(rec[32:])
			d.cdSize = int64(binary.LittleEndian.Uint64(rec[40:]))
			d.cdOffset = int64(binary.LittleEndian.Uint64(rec[48:]))
			dirEnd = recOffset
		}
	}
	if d.cdOffset < 0 || d.cdSize < 0 || d.cdOffset+d.cdSize > dirEnd {
		return nil, fmt.Errorf("%w: central directory [%d,+%d) exceeds directory end %d", ErrCorruptZip, d.cdOffset, d.cdSize, dirEnd)
	}
	return d, nil
}

// readAtCached reads n bytes at off, serving them from d.tail when fully cached.
func readAtCached(r io.ReaderAt, d *zipDirectory, off int64, n int) ([]byte, error) {
	if off >= d.tailOffset && off+int64(n) <= d.tailOffset+int64(len(d.tail)) {
		s := off - d.tailOffset
		return d.tail[s : s+int64(n)], nil
	}
	buf := make([]byte, n)
	if _, err := r.ReadAt(buf, off); err != nil && err != io.EOF {
		return nil, err
	}
	return buf, nil
}

// cachedTailReaderAt serves [cacheOffset, size) from memory and everything else from r.
// It lets zip.NewReader parse the central directory without any further I/O.
type cachedTailReaderAt struct {
	r           io.ReaderAt
	cacheOffset int64
	cache       []byte
}

func (c *cachedTailReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("%w: negative offset %d", ErrCorruptZip, off)
	}
	end := c.cacheOffset + int64(len(c.cache))
	if off >= c.cacheOffset {
		if off >= end {
			return 0, io.EOF
		}
		n := copy(p, c.cache[off-c.cacheOffset:])
		if n < len(p) {
			return n, io.EOF
		}
		return n, nil
	}
	// Prefix outside the cache comes from the underlying reader.
	head := p
	if off+int64(len(p)) > c.cacheOffset {
		head = p[:c.cacheOffset-off]
	}
	n, err := c.r.ReadAt(head, off)
	if err != nil || n < len(head) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return n, err
	}
	if len(head) == len(p) {
		return n, nil
	}
	m, err := c.ReadAt(p[len(head):], c.cacheOffset)
	return n + m, err
}

// GetZipPartRanges parses the ZIP structure and returns the start and end offsets of all file parts,
// sorted by offset.
//
// I/O is O(1) in the number of entries: one read of the archive tail (EOCD/zip64 records),
// at most one read of the zip64 record, and one read of the whole central directory, which is
// then parsed from memory. Returned zip.File values read entry data through ra.
func GetZipPartRanges(ra io.ReaderAt, size int64) ([]ZipPartRange, error) {
	d, err := readZipDirectory(ra, size)
	if err != nil {
		return nil, err
	}

	// Cache [min(cdOffset, tailOffset), size): the CD, all end records and the tail window
	// zip.NewReader scans for the EOCD. The part below the tail is fetched with ONE read.
	cacheOffset := d.tailOffset
	cache := d.tail
	if d.cdOffset < d.tailOffset {
		cacheOffset = d.cdOffset
		cache = make([]byte, size-cacheOffset)
		head := cache[:d.tailOffset-cacheOffset]
		if n, err := ra.ReadAt(head, cacheOffset); err != nil && !(err == io.EOF && n == len(head)) {
			return nil, fmt.Errorf("failed to read central directory: %w", err)
		}
		copy(cache[len(head):], d.tail)
	}
	// Present the archive to the library as ending right after the validated EOCD with an
	// empty comment, so its (comment-length-agnostic) backward scan cannot pick a fake EOCD
	// signature embedded in the comment.
	eocdEnd := d.eocdOffset + eocdLen
	cache = cache[:eocdEnd-cacheOffset]
	binary.LittleEndian.PutUint16(cache[d.eocdOffset-cacheOffset+20:], 0)
	cra := &cachedTailReaderAt{r: ra, cacheOffset: cacheOffset, cache: cache}

	zr, err := zip.NewReader(cra, eocdEnd)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse central directory: %w", ErrCorruptZip, err)
	}
	// Like the library, compare only 16 bits: plain EOCD record counts are truncated.
	if uint16(len(zr.File)) != uint16(d.records) {
		return nil, fmt.Errorf("%w: central directory has %d entries, end record declares %d", ErrCorruptZip, len(zr.File), d.records)
	}

	type fileWithOffset struct {
		file   *zip.File
		offset int64
	}
	files := make([]fileWithOffset, len(zr.File))
	for i, f := range zr.File {
		off := f.HeaderOffset()
		if off < 0 || off >= d.cdOffset {
			return nil, fmt.Errorf("%w: local header offset %d of %q outside data area [0,%d)", ErrCorruptZip, off, f.Name, d.cdOffset)
		}
		files[i] = fileWithOffset{file: f, offset: off}
	}

	// Sort files by their local header offset to determine contiguous ranges
	sort.Slice(files, func(i, j int) bool {
		return files[i].offset < files[j].offset
	})

	ranges := make([]ZipPartRange, len(files))
	for i, item := range files {
		end := d.cdOffset
		if i < len(files)-1 {
			end = files[i+1].offset
		}
		if end <= item.offset {
			return nil, fmt.Errorf("%w: entries %q and %q share local header offset %d", ErrCorruptZip, item.file.Name, files[i+1].file.Name, item.offset)
		}
		ranges[i] = ZipPartRange{
			Name:        item.file.Name,
			StartOffset: item.offset,
			EndOffset:   end,
			File:        item.file,
		}
	}

	// Note: returned Files keep cra (and thus the cached CD bytes) alive for reads.
	return ranges, nil
}

// FindEOCD locates the End of Central Directory record in a ZIP file reader.
// The record must be followed by exactly its declared comment length.
func FindEOCD(r io.ReaderAt, size int64) (int64, error) {
	d, err := readZipDirectory(r, size)
	if err != nil {
		return 0, err
	}
	return d.eocdOffset, nil
}

// GetCentralDirectoryOffset computes the start offset of the Central Directory in a ZIP file,
// using the zip64 end record when present.
func GetCentralDirectoryOffset(r io.ReaderAt, size int64) (int64, error) {
	d, err := readZipDirectory(r, size)
	if err != nil {
		return 0, err
	}
	return d.cdOffset, nil
}

// ZipEntryCount returns the number of entries declared by the archive's end of central
// directory records (zip64-aware). It reads only the archive tail, never the central directory,
// so callers can cheaply size work (e.g. time budgets) before running a backup.
func ZipEntryCount(r io.ReaderAt, size int64) (uint64, error) {
	d, err := readZipDirectory(r, size)
	if err != nil {
		return 0, err
	}
	return d.records, nil
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
