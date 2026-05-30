package storage_clients

import (
	"context"
	"fmt"
	"io"
)

// ObjectInfo holds basic object metadata.
type ObjectInfo struct {
	Name string
	Size int64
}

// ObjectStorageClient provides unified access to read/write from object storage.
type ObjectStorageClient interface {
	ListBuckets(ctx context.Context, compartmentID string) ([]string, error)
	ListObjects(ctx context.Context, bucket, prefix string) ([]ObjectInfo, error)
	GetObjectSize(ctx context.Context, bucket, key string) (int64, error)
	// GetObjectRange returns a ReadCloser for the specified range.
	// If endByte is -1, it fetches to the end of the object.
	GetObjectRange(ctx context.Context, bucket, key string, startByte, endByte int64) (io.ReadCloser, error)

	Initiate(ctx context.Context, bucket, key string) (uploadID string, err error)
	UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, data []byte) (etag string, err error)
	Complete(ctx context.Context, bucket, key, uploadID string, etags map[int]string) error
	Abort(ctx context.Context, bucket, key, uploadID string) error
	PutObject(ctx context.Context, bucket, key string, data []byte) error
	DeleteObject(ctx context.Context, bucket, key string) error
	SetRegion(region string)
}

// ClientFactory is a function that creates a new client.
type ClientFactory func(authType, namespace string) (ObjectStorageClient, error)

var (
	registry = make(map[string]ClientFactory)
)

// RegisterClient registers a new client factory for a provider.
func RegisterClient(provider string, factory ClientFactory) {
	registry[provider] = factory
}

// GetClient returns a client for the given provider.
func GetClient(provider, authType, namespace string) (ObjectStorageClient, error) {
	if factory, ok := registry[provider]; ok {
		return factory(authType, namespace)
	}
	return nil, fmt.Errorf("provider '%s' is not supported in this build", provider)
}
