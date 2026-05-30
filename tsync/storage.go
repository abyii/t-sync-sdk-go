package tsync

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"t-sync-sdk-go/storage_clients"
)

// FileInfo represents basic file metadata.
type FileInfo struct {
	Name         string
	Size         int64
	LastModified time.Time
}

// Storage abstracts read, write, list and delete operations for local or object storage.
type Storage interface {
	Exists(ctx context.Context, path string) (bool, error)
	Read(ctx context.Context, path string) ([]byte, error)
	Write(ctx context.Context, path string, data []byte) error
	Delete(ctx context.Context, path string) error
	List(ctx context.Context, prefix string) ([]FileInfo, error)
	OpenReader(ctx context.Context, path string) (io.ReadCloser, error)
	OpenWriter(ctx context.Context, path string) (io.WriteCloser, error)
	
	// Size returns the file size in bytes.
	Size(ctx context.Context, path string) (int64, error)
	// ReadRange reads a range of bytes from the file.
	// If length is -1, it reads to the end of the file.
	ReadRange(ctx context.Context, path string, offset, length int64) (io.ReadCloser, error)
}

// ---------------------------------------------------------
// Local Storage Implementation
// ---------------------------------------------------------

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

func (l *LocalStorage) Exists(ctx context.Context, path string) (bool, error) {
	fullPath := l.resolvePath(path)
	_, err := os.Stat(fullPath)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func (l *LocalStorage) Read(ctx context.Context, path string) ([]byte, error) {
	fullPath := l.resolvePath(path)
	return os.ReadFile(fullPath)
}

func (l *LocalStorage) Write(ctx context.Context, path string, data []byte) error {
	fullPath := l.resolvePath(path)
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(fullPath, data, 0644)
}

func (l *LocalStorage) Delete(ctx context.Context, path string) error {
	fullPath := l.resolvePath(path)
	err := os.Remove(fullPath)
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	return err
}

func (l *LocalStorage) List(ctx context.Context, prefix string) ([]FileInfo, error) {
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
		if d.IsDir() {
			return nil
		}
		
		// Match prefix
		relPath, err := filepath.Rel(l.rootDir, path)
		if err != nil {
			return err
		}
		relSlash := filepath.ToSlash(relPath)
		if strings.HasPrefix(relSlash, prefix) {
			info, err := d.Info()
			if err != nil {
				return err
			}
			files = append(files, FileInfo{
				Name:         relSlash,
				Size:         info.Size(),
				LastModified: info.ModTime(),
			})
		}
		return nil
	})

	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return files, nil
}

func (l *LocalStorage) OpenReader(ctx context.Context, path string) (io.ReadCloser, error) {
	fullPath := l.resolvePath(path)
	return os.Open(fullPath)
}

func (l *LocalStorage) OpenWriter(ctx context.Context, path string) (io.WriteCloser, error) {
	fullPath := l.resolvePath(path)
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	return os.Create(fullPath)
}

func (l *LocalStorage) Size(ctx context.Context, path string) (int64, error) {
	fullPath := l.resolvePath(path)
	info, err := os.Stat(fullPath)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func (l *LocalStorage) ReadRange(ctx context.Context, path string, offset, length int64) (io.ReadCloser, error) {
	fullPath := l.resolvePath(path)
	f, err := os.Open(fullPath)
	if err != nil {
		return nil, err
	}
	if offset > 0 {
		_, err = f.Seek(offset, io.SeekStart)
		if err != nil {
			f.Close()
			return nil, err
		}
	}
	if length >= 0 {
		return &limitReadCloser{
			r: io.LimitReader(f, length),
			c: f,
		}, nil
	}
	return f, nil
}

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
	key := o.resolveKey(path)
	_, err := o.client.GetObjectSize(ctx, o.bucket, key)
	if err == nil {
		return true, nil
	}
	// Many object storages return NoSuchKey or 404 in the error message
	if strings.Contains(err.Error(), "NoSuchKey") || strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "not found") {
		return false, nil
	}
	return false, err
}

func (o *ObjectStorage) Read(ctx context.Context, path string) ([]byte, error) {
	key := o.resolveKey(path)
	rc, err := o.client.GetObjectRange(ctx, o.bucket, key, 0, -1)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func (o *ObjectStorage) Write(ctx context.Context, path string, data []byte) error {
	key := o.resolveKey(path)
	return o.client.PutObject(ctx, o.bucket, key, data)
}

func (o *ObjectStorage) Delete(ctx context.Context, path string) error {
	key := o.resolveKey(path)
	err := o.client.DeleteObject(ctx, o.bucket, key)
	if err != nil && (strings.Contains(err.Error(), "NoSuchKey") || strings.Contains(err.Error(), "404")) {
		return nil
	}
	return err
}

func (o *ObjectStorage) List(ctx context.Context, prefix string) ([]FileInfo, error) {
	searchPrefix := o.resolveKey(prefix)
	objs, err := o.client.ListObjects(ctx, o.bucket, searchPrefix)
	if err != nil {
		return nil, err
	}
	
	var files []FileInfo
	for _, obj := range objs {
		// Strip storage prefix to return relative paths
		relName := strings.TrimPrefix(obj.Name, o.prefix)
		files = append(files, FileInfo{
			Name:         relName,
			Size:         obj.Size,
			LastModified: time.Now(), // Default fallback for object storage
		})
	}
	return files, nil
}

func (o *ObjectStorage) OpenReader(ctx context.Context, path string) (io.ReadCloser, error) {
	key := o.resolveKey(path)
	return o.client.GetObjectRange(ctx, o.bucket, key, 0, -1)
}

func (o *ObjectStorage) OpenWriter(ctx context.Context, path string) (io.WriteCloser, error) {
	key := o.resolveKey(path)
	return newObjectStorageWriter(ctx, o.client, o.bucket, key), nil
}

func (o *ObjectStorage) Size(ctx context.Context, path string) (int64, error) {
	key := o.resolveKey(path)
	return o.client.GetObjectSize(ctx, o.bucket, key)
}

func (o *ObjectStorage) ReadRange(ctx context.Context, path string, offset, length int64) (io.ReadCloser, error) {
	key := o.resolveKey(path)
	endByte := int64(-1)
	if length >= 0 {
		endByte = offset + length - 1
	}
	return o.client.GetObjectRange(ctx, o.bucket, key, offset, endByte)
}

// ---------------------------------------------------------
// Buffered Object Storage Writer
// ---------------------------------------------------------

type objectStorageWriter struct {
	ctx        context.Context
	client     storage_clients.ObjectStorageClient
	bucket     string
	key        string
	uploadID   string
	partSize   int
	partNumber int
	buffer     *bytes.Buffer
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
		partSize:   5 * 1024 * 1024, // 5MB minimum part size
		buffer:     &bytes.Buffer{},
		etags:      make(map[int]string),
		partNumber: 1,
	}
}

func (w *objectStorageWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, fmt.Errorf("writer is closed")
	}
	if w.err != nil {
		return 0, w.err
	}

	n, err := w.buffer.Write(p)
	if err != nil {
		return 0, err
	}

	// If we exceed part size, trigger upload
	for w.buffer.Len() >= w.partSize {
		if err := w.uploadBufferedPart(); err != nil {
			w.err = err
			return 0, err
		}
	}

	return n, nil
}

func (w *objectStorageWriter) uploadBufferedPart() error {
	if w.uploadID == "" {
		// Initialize multipart upload
		id, err := w.client.Initiate(w.ctx, w.bucket, w.key)
		if err != nil {
			return fmt.Errorf("failed to initiate multipart upload: %w", err)
		}
		w.uploadID = id
	}

	partData := make([]byte, w.partSize)
	_, err := w.buffer.Read(partData)
	if err != nil {
		return err
	}

	etag, err := w.client.UploadPart(w.ctx, w.bucket, w.key, w.uploadID, w.partNumber, partData)
	if err != nil {
		return fmt.Errorf("failed to upload part %d: %w", w.partNumber, err)
	}

	w.etags[w.partNumber] = etag
	w.partNumber++
	return nil
}

func (w *objectStorageWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true

	if w.err != nil {
		if w.uploadID != "" {
			_ = w.client.Abort(w.ctx, w.bucket, w.key, w.uploadID)
		}
		return w.err
	}

	if w.uploadID == "" {
		// Small object optimization: upload as a single PutObject
		err := w.client.PutObject(w.ctx, w.bucket, w.key, w.buffer.Bytes())
		w.buffer.Reset()
		return err
	}

	// Final part upload if there's remaining data
	if w.buffer.Len() > 0 {
		partData := w.buffer.Bytes()
		etag, err := w.client.UploadPart(w.ctx, w.bucket, w.key, w.uploadID, w.partNumber, partData)
		if err != nil {
			_ = w.client.Abort(w.ctx, w.bucket, w.key, w.uploadID)
			return fmt.Errorf("failed to upload final part %d: %w", w.partNumber, err)
		}
		w.etags[w.partNumber] = etag
	}
	w.buffer.Reset()

	// Complete multipart upload
	err := w.client.Complete(w.ctx, w.bucket, w.key, w.uploadID, w.etags)
	if err != nil {
		_ = w.client.Abort(w.ctx, w.bucket, w.key, w.uploadID)
		return fmt.Errorf("failed to complete multipart upload: %w", err)
	}

	return nil
}

// StorageReaderAt implements io.ReaderAt on top of any Storage interface.
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
	rc, err := s.store.ReadRange(s.ctx, s.path, off, int64(len(p)))
	if err != nil {
		return 0, err
	}
	defer rc.Close()
	return io.ReadFull(rc, p)
}

type limitReadCloser struct {
	r io.Reader
	c io.Closer
}

func (l *limitReadCloser) Read(p []byte) (int, error) {
	return l.r.Read(p)
}

func (l *limitReadCloser) Close() error {
	return l.c.Close()
}
