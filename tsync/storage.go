package tsync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/abyii/t-sync-sdk-go/v2/storage_clients"
)

// FileInfo represents basic file metadata.
type FileInfo struct {
	Name         string
	Size         int64
	LastModified time.Time
}

// Storage abstracts read, write, list and delete operations for local or object storage.
//
// Implementations MUST return an error satisfying errors.Is(err, ErrNotFound) when a path
// does not exist (Read, OpenReader, Size, ReadRange). Delete of a missing path is not an error.
type Storage interface {
	Exists(ctx context.Context, path string) (bool, error)
	Read(ctx context.Context, path string) ([]byte, error)
	// Write stores data at path. It must be all-or-nothing: readers never observe a partial object.
	Write(ctx context.Context, path string, data []byte) error
	Delete(ctx context.Context, path string) error
	List(ctx context.Context, prefix string) ([]FileInfo, error)
	OpenReader(ctx context.Context, path string) (io.ReadCloser, error)
	// OpenWriter returns a writer whose data becomes visible at path only on a successful Close.
	// Writers SHOULD also implement AbortableWriter.
	OpenWriter(ctx context.Context, path string) (io.WriteCloser, error)

	// Size returns the file size in bytes.
	Size(ctx context.Context, path string) (int64, error)
	// ReadRange reads a range of bytes from the file.
	// If length is -1, it reads to the end of the file.
	ReadRange(ctx context.Context, path string, offset, length int64) (io.ReadCloser, error)
}

// AbortableWriter is an optional interface for writers returned by Storage.OpenWriter.
// Abort discards everything written so far without committing an object; the writer
// is unusable afterwards. RunBackup calls Abort instead of Close whenever producing
// the content failed, so truncated objects are never committed.
type AbortableWriter interface {
	io.WriteCloser
	Abort() error
}

// cleanupTimeout bounds abort/cleanup calls that must run even after the caller's
// context was cancelled or hit its deadline.
const cleanupTimeout = 30 * time.Second

// cleanupContext returns a context detached from ctx's cancellation (values kept)
// with a short timeout, for abort/cleanup work.
func cleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
}

// ---------------------------------------------------------
// Local Storage Implementation
// ---------------------------------------------------------

// localTempPrefix marks in-progress files written by LocalStorage. They are hidden from List.
const localTempPrefix = ".tsync-tmp-"

type LocalStorage struct {
	rootDir string
}

func NewLocalStorage(rootDir string) (*LocalStorage, error) {
	absDir, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, err
	}
	return &LocalStorage{rootDir: absDir}, nil
}

func (l *LocalStorage) resolvePath(path string) string {
	return filepath.Join(l.rootDir, filepath.FromSlash(path))
}

// localErr translates "does not exist" errors into ErrNotFound while keeping the OS error in the chain.
func localErr(path string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %s: %w", ErrNotFound, path, err)
	}
	return err
}

func (l *LocalStorage) Exists(ctx context.Context, path string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	_, err := os.Stat(l.resolvePath(path))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func (l *LocalStorage) Read(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(l.resolvePath(path))
	if err != nil {
		return nil, localErr(path, err)
	}
	return data, nil
}

// Write atomically replaces path with data: the bytes are written to a temp file in the
// same directory, fsynced, and renamed over the destination (followed by a best-effort
// directory fsync). Readers observe either the old or the new content, never a mix.
func (l *LocalStorage) Write(ctx context.Context, path string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	w, err := l.openAtomicWriter(ctx, path)
	if err != nil {
		return err
	}
	if _, err := w.f.Write(data); err != nil {
		_ = w.Abort()
		return err
	}
	return w.Close()
}

func (l *LocalStorage) Delete(ctx context.Context, path string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := os.Remove(l.resolvePath(path))
	if err != nil && errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func (l *LocalStorage) List(ctx context.Context, prefix string) ([]FileInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var files []FileInfo
	fullPrefix := l.resolvePath(prefix)

	// Determine the directory to read
	searchDir := fullPrefix
	if !strings.HasSuffix(prefix, "/") && prefix != "" {
		searchDir = filepath.Dir(fullPrefix)
	}

	err := filepath.WalkDir(searchDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}

		relPath, err := filepath.Rel(l.rootDir, path)
		if err != nil {
			return err
		}
		relSlash := filepath.ToSlash(relPath)
		if relSlash == "." || relSlash == "" {
			return nil
		}
		// Only process regular files and directories; ignore symlinks, sockets, pipes, devices, etc.
		mode := d.Type()
		if !mode.IsRegular() && !d.IsDir() {
			return nil
		}
		// Hide in-progress (or crash-leftover) temp files of atomic writes.
		if !d.IsDir() && strings.HasPrefix(d.Name(), localTempPrefix) {
			return nil
		}

		if d.IsDir() {
			relSlash += "/"
		}

		if strings.HasPrefix(relSlash, prefix) {
			info, err := d.Info()
			if err != nil {
				return err
			}
			size := info.Size()
			if d.IsDir() {
				size = 0
			}
			files = append(files, FileInfo{
				Name:         relSlash,
				Size:         size,
				LastModified: info.ModTime(),
			})
		}
		return nil
	})

	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return files, nil
}

func (l *LocalStorage) OpenReader(ctx context.Context, path string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open(l.resolvePath(path))
	if err != nil {
		return nil, localErr(path, err)
	}
	return &ctxReadCloser{ctx: ctx, r: f, c: f}, nil
}

// OpenWriter returns an AbortableWriter. Data is written to a temp file in the destination
// directory and atomically renamed onto path by Close; Abort removes the temp file.
func (l *LocalStorage) OpenWriter(ctx context.Context, path string) (io.WriteCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return l.openAtomicWriter(ctx, path)
}

func (l *LocalStorage) openAtomicWriter(ctx context.Context, path string) (*localAtomicWriter, error) {
	fullPath := l.resolvePath(path)
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, localTempPrefix+filepath.Base(fullPath)+"-*")
	if err != nil {
		return nil, err
	}
	return &localAtomicWriter{ctx: ctx, f: f, finalPath: fullPath}, nil
}

func (l *LocalStorage) Size(ctx context.Context, path string) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	info, err := os.Stat(l.resolvePath(path))
	if err != nil {
		return 0, localErr(path, err)
	}
	return info.Size(), nil
}

func (l *LocalStorage) ReadRange(ctx context.Context, path string, offset, length int64) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open(l.resolvePath(path))
	if err != nil {
		return nil, localErr(path, err)
	}
	if offset > 0 {
		if _, err = f.Seek(offset, io.SeekStart); err != nil {
			f.Close()
			return nil, err
		}
	}
	var r io.Reader = f
	if length >= 0 {
		r = io.LimitReader(f, length)
	}
	return &ctxReadCloser{ctx: ctx, r: r, c: f}, nil
}

// localAtomicWriter writes to a temp file and renames it onto finalPath on Close.
type localAtomicWriter struct {
	ctx       context.Context
	f         *os.File
	finalPath string
	done      bool
}

func (w *localAtomicWriter) Write(p []byte) (int, error) {
	if w.done {
		return 0, ErrWriterClosed
	}
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	return w.f.Write(p)
}

// Close fsyncs the temp file, renames it onto the destination and fsyncs the directory
// (best-effort; unsupported on some platforms). On any failure the temp file is removed.
func (w *localAtomicWriter) Close() error {
	if w.done {
		return nil
	}
	w.done = true
	tmp := w.f.Name()
	if err := w.ctx.Err(); err != nil {
		w.f.Close()
		os.Remove(tmp)
		return err
	}
	if err := w.f.Sync(); err != nil {
		w.f.Close()
		os.Remove(tmp)
		return err
	}
	if err := w.f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, w.finalPath); err != nil {
		os.Remove(tmp)
		return err
	}
	_ = syncDir(filepath.Dir(w.finalPath)) // best-effort: the rename itself already succeeded
	return nil
}

// Abort discards the temp file; the destination is left untouched.
func (w *localAtomicWriter) Abort() error {
	if w.done {
		return nil
	}
	w.done = true
	closeErr := w.f.Close()
	if err := os.Remove(w.f.Name()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return closeErr
}

// ctxReadCloser fails reads once ctx is done.
type ctxReadCloser struct {
	ctx context.Context
	r   io.Reader
	c   io.Closer
}

func (c *ctxReadCloser) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

func (c *ctxReadCloser) Close() error { return c.c.Close() }

// ---------------------------------------------------------
// Object Storage Implementation
// ---------------------------------------------------------

type ObjectStorage struct {
	client storage_clients.ObjectStorageClient
	bucket string
	prefix string
}

func NewObjectStorage(client storage_clients.ObjectStorageClient, bucket, prefix string) *ObjectStorage {
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return &ObjectStorage{
		client: client,
		bucket: bucket,
		prefix: prefix,
	}
}

func (o *ObjectStorage) resolveKey(path string) string {
	return o.prefix + strings.TrimPrefix(path, "/")
}

func (o *ObjectStorage) Exists(ctx context.Context, path string) (bool, error) {
	_, err := o.client.GetObjectSize(ctx, o.bucket, o.resolveKey(path))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return false, err
}

func (o *ObjectStorage) Read(ctx context.Context, path string) ([]byte, error) {
	rc, err := o.client.GetObjectRange(ctx, o.bucket, o.resolveKey(path), 0, -1)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// Write uploads data with a single PutObject, which object stores apply atomically.
func (o *ObjectStorage) Write(ctx context.Context, path string, data []byte) error {
	return o.client.PutObject(ctx, o.bucket, o.resolveKey(path), data)
}

func (o *ObjectStorage) Delete(ctx context.Context, path string) error {
	err := o.client.DeleteObject(ctx, o.bucket, o.resolveKey(path))
	if err != nil && errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

func (o *ObjectStorage) List(ctx context.Context, prefix string) ([]FileInfo, error) {
	objs, err := o.client.ListObjects(ctx, o.bucket, o.resolveKey(prefix))
	if err != nil {
		return nil, err
	}

	files := make([]FileInfo, 0, len(objs))
	now := time.Now()
	for _, obj := range objs {
		// Strip storage prefix to return relative paths
		files = append(files, FileInfo{
			Name:         strings.TrimPrefix(obj.Name, o.prefix),
			Size:         obj.Size,
			LastModified: now, // Default fallback for object storage
		})
	}
	return files, nil
}

func (o *ObjectStorage) OpenReader(ctx context.Context, path string) (io.ReadCloser, error) {
	return o.client.GetObjectRange(ctx, o.bucket, o.resolveKey(path), 0, -1)
}

// OpenWriter returns an AbortableWriter that uploads via PutObject (small objects) or multipart upload.
func (o *ObjectStorage) OpenWriter(ctx context.Context, path string) (io.WriteCloser, error) {
	return newObjectStorageWriter(ctx, o.client, o.bucket, o.resolveKey(path)), nil
}

func (o *ObjectStorage) Size(ctx context.Context, path string) (int64, error) {
	return o.client.GetObjectSize(ctx, o.bucket, o.resolveKey(path))
}

func (o *ObjectStorage) ReadRange(ctx context.Context, path string, offset, length int64) (io.ReadCloser, error) {
	if length == 0 {
		return io.NopCloser(bytes.NewReader(nil)), nil
	}
	endByte := int64(-1)
	if length > 0 {
		endByte = offset + length - 1
	}
	return o.client.GetObjectRange(ctx, o.bucket, o.resolveKey(path), offset, endByte)
}

// ---------------------------------------------------------
// Buffered Object Storage Writer
// ---------------------------------------------------------

const (
	// initialPartSize is the multipart part size for the first partSizeStep parts.
	initialPartSize = 8 << 20 // 8 MiB
	// maxPartSize is the provider limit for a single part (S3/OCI).
	maxPartSize = 5 << 30 // 5 GiB
	// partSizeStep is the number of parts after which the part size doubles.
	partSizeStep = 1000
	// maxMultipartParts is the provider limit on the number of parts (S3/OCI).
	maxMultipartParts = 10000
)

// partSizeFor returns the size of the 1-based multipart part number n.
// Sizes double every partSizeStep parts (8 MiB, 16 MiB, ... 4 GiB), capped at maxPartSize,
// so 10,000 parts hold ~7.8 TiB, above the 5 TiB single-object limit of S3/OCI.
func partSizeFor(n int) int {
	shift := (n - 1) / partSizeStep
	if shift < 0 {
		shift = 0
	}
	size := int64(initialPartSize)
	for ; shift > 0 && size < maxPartSize; shift-- {
		size <<= 1
	}
	if size > maxPartSize {
		size = maxPartSize
	}
	return int(size)
}

// partBufPool recycles initialPartSize buffers across writers so that many small
// objects do not each allocate (and grow) a fresh buffer.
var partBufPool = sync.Pool{New: func() any {
	b := make([]byte, 0, initialPartSize)
	return &b
}}

type objectStorageWriter struct {
	ctx        context.Context
	client     storage_clients.ObjectStorageClient
	bucket     string
	key        string
	uploadID   string
	partNumber int // number of the part currently being buffered (1-based)
	buf        []byte
	pooled     *[]byte // pool handle for buf when it came from partBufPool
	etags      map[int]string
	err        error
	closed     bool
}

func newObjectStorageWriter(ctx context.Context, client storage_clients.ObjectStorageClient, bucket, key string) *objectStorageWriter {
	return &objectStorageWriter{
		ctx:        ctx,
		client:     client,
		bucket:     bucket,
		key:        key,
		partNumber: 1,
	}
}

// ensureBuffer makes sure buf has capacity for the current part size. It is only
// called with an empty buffer.
func (w *objectStorageWriter) ensureBuffer(size int) {
	if cap(w.buf) >= size {
		return
	}
	w.releaseBuffer()
	if size == initialPartSize {
		w.pooled = partBufPool.Get().(*[]byte)
		w.buf = (*w.pooled)[:0]
		return
	}
	w.buf = make([]byte, 0, size)
}

func (w *objectStorageWriter) releaseBuffer() {
	if w.pooled != nil {
		*w.pooled = w.buf[:0]
		partBufPool.Put(w.pooled)
		w.pooled = nil
	}
	w.buf = nil
}

func (w *objectStorageWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, ErrWriterClosed
	}
	if w.err != nil {
		return 0, w.err
	}

	written := 0
	for len(p) > 0 {
		size := partSizeFor(w.partNumber)
		if len(w.buf) == size {
			// Buffer full and more data follows: ship it as a part.
			if err := w.uploadBufferedPart(); err != nil {
				w.err = err
				return written, err
			}
			size = partSizeFor(w.partNumber)
		}
		if len(w.buf) == 0 {
			w.ensureBuffer(size)
		}
		n := min(len(p), size-len(w.buf))
		w.buf = append(w.buf, p[:n]...)
		p = p[n:]
		written += n
	}
	return written, nil
}

func (w *objectStorageWriter) uploadBufferedPart() error {
	if w.partNumber > maxMultipartParts {
		return fmt.Errorf("object %s exceeds the maximum of %d multipart parts", w.key, maxMultipartParts)
	}
	if w.uploadID == "" {
		id, err := w.client.Initiate(w.ctx, w.bucket, w.key)
		if err != nil {
			return fmt.Errorf("failed to initiate multipart upload: %w", err)
		}
		w.uploadID = id
		w.etags = make(map[int]string)
	}

	etag, err := w.client.UploadPart(w.ctx, w.bucket, w.key, w.uploadID, w.partNumber, w.buf)
	if err != nil {
		return fmt.Errorf("failed to upload part %d: %w", w.partNumber, err)
	}
	w.etags[w.partNumber] = etag
	w.partNumber++
	w.buf = w.buf[:0]
	return nil
}

// abortUpload aborts the multipart upload (if any) on a context that survives
// cancellation of the writer's context.
func (w *objectStorageWriter) abortUpload() error {
	if w.uploadID == "" {
		return nil
	}
	ctx, cancel := cleanupContext(w.ctx)
	defer cancel()
	err := w.client.Abort(ctx, w.bucket, w.key, w.uploadID)
	if err != nil && errors.Is(err, storage_clients.ErrUploadNotFound) {
		err = nil
	}
	if err != nil {
		return fmt.Errorf("failed to abort multipart upload %s: %w", w.uploadID, err)
	}
	return nil
}

// Abort discards the object: buffered data is dropped and an in-progress multipart upload is aborted.
func (w *objectStorageWriter) Abort() error {
	if w.closed {
		return nil
	}
	w.closed = true
	w.releaseBuffer()
	return w.abortUpload()
}

func (w *objectStorageWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	defer w.releaseBuffer()

	if w.err != nil {
		return errors.Join(w.err, w.abortUpload())
	}

	if w.uploadID == "" {
		// Small object optimization: upload as a single PutObject
		return w.client.PutObject(w.ctx, w.bucket, w.key, w.buf)
	}

	// Final part upload if there's remaining data
	if len(w.buf) > 0 {
		if err := w.uploadBufferedPart(); err != nil {
			return errors.Join(fmt.Errorf("failed to upload final part: %w", err), w.abortUpload())
		}
	}

	if err := w.client.Complete(w.ctx, w.bucket, w.key, w.uploadID, w.etags); err != nil {
		return errors.Join(fmt.Errorf("failed to complete multipart upload: %w", err), w.abortUpload())
	}
	return nil
}

// StorageReaderAt implements io.ReaderAt on top of any Storage interface.
// Every ReadAt issues one ReadRange call.
type StorageReaderAt struct {
	ctx   context.Context
	store Storage
	path  string
}

func NewStorageReaderAt(ctx context.Context, store Storage, path string) *StorageReaderAt {
	return &StorageReaderAt{
		ctx:   ctx,
		store: store,
		path:  path,
	}
}

func (s *StorageReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	rc, err := s.store.ReadRange(s.ctx, s.path, off, int64(len(p)))
	if err != nil {
		return 0, err
	}
	defer rc.Close()
	n, err = io.ReadFull(rc, p)
	if err == io.ErrUnexpectedEOF {
		err = io.EOF // io.ReaderAt contract: short read at end of input reports io.EOF
	}
	return n, err
}
