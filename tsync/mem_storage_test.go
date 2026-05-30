package tsync

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------
// Thread-safe Mock Memory Storage for Testing
// ---------------------------------------------------------

type MemStorage struct {
	mu    sync.RWMutex
	files map[string][]byte
}

func NewMemStorage() *MemStorage {
	return &MemStorage{
		files: make(map[string][]byte),
	}
}

func (m *MemStorage) Exists(ctx context.Context, path string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.files[path]
	return ok, nil
}

func (m *MemStorage) Read(ctx context.Context, path string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	data, ok := m.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	return cp, nil
}

func (m *MemStorage) Write(ctx context.Context, path string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	m.files[path] = cp
	return nil
}

func (m *MemStorage) Delete(ctx context.Context, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.files, path)
	return nil
}

func (m *MemStorage) List(ctx context.Context, prefix string) ([]FileInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var list []FileInfo
	for name, data := range m.files {
		if strings.HasPrefix(name, prefix) {
			list = append(list, FileInfo{
				Name:         name,
				Size:         int64(len(data)),
				LastModified: time.Now(),
			})
		}
	}
	return list, nil
}

func (m *MemStorage) OpenReader(ctx context.Context, path string) (io.ReadCloser, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	data, ok := m.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

type memWriter struct {
	buf bytes.Buffer
	cb  func([]byte) error
}

func (w *memWriter) Write(p []byte) (int, error) {
	return w.buf.Write(p)
}

func (w *memWriter) Close() error {
	return w.cb(w.buf.Bytes())
}

func (m *MemStorage) OpenWriter(ctx context.Context, path string) (io.WriteCloser, error) {
	return &memWriter{
		cb: func(data []byte) error {
			return m.Write(ctx, path, data)
		},
	}, nil
}

func (m *MemStorage) Size(ctx context.Context, path string) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	data, ok := m.files[path]
	if !ok {
		return 0, os.ErrNotExist
	}
	return int64(len(data)), nil
}

func (m *MemStorage) ReadRange(ctx context.Context, path string, offset, length int64) (io.ReadCloser, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	data, ok := m.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	
	if offset > int64(len(data)) {
		offset = int64(len(data))
	}
	
	end := int64(len(data))
	if length >= 0 && offset+length < end {
		end = offset + length
	}
	
	slice := data[offset:end]
	return io.NopCloser(bytes.NewReader(slice)), nil
}

// ---------------------------------------------------------
// Helper: generate random files content
// ---------------------------------------------------------

func randomBytes(size int) []byte {
	b := make([]byte, size)
	_, _ = rand.Read(b)
	return b
}

func generateRandomString(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, length)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		b[i] = chars[n.Int64()]
	}
	return string(b)
}
