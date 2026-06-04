package oci

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/abyii/t-sync-sdk-go/v2/storage_clients"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

func init() {
	storage_clients.RegisterClient("oci", func(authType, namespace string) (storage_clients.ObjectStorageClient, error) {
		return NewOCIClient(namespace, authType)
	})
}

type OCIClient struct {
	client    objectstorage.ObjectStorageClient
	namespace string
}

func NewOCIClient(namespace, authType string) (*OCIClient, error) {
	if namespace == "" {
		return nil, fmt.Errorf("namespace is required")
	}

	var provider common.ConfigurationProvider
	var err error

	if strings.HasPrefix(authType, "OCI_CONFIG_FILE") {
		profile := "DEFAULT"
		if strings.Contains(authType, "[") && strings.Contains(authType, "]") {
			start := strings.Index(authType, "[")
			end := strings.Index(authType, "]")
			if start != -1 && end != -1 && end > start {
				profile = authType[start+1 : end]
			}
		}
		provider = common.CustomProfileConfigProvider("~/.oci/config", profile)
	} else if authType == "OKE_WORKLOAD_IDENTITY" {
		provider, err = auth.OkeWorkloadIdentityConfigurationProvider()
		if err != nil {
			return nil, fmt.Errorf("failed to create OKE workload identity provider: %v", err)
		}
	} else if authType == "INSTANCE_PRINCIPAL" {
		provider, err = auth.InstancePrincipalConfigurationProvider()
		if err != nil {
			return nil, fmt.Errorf("failed to create instance principal provider: %v", err)
		}
	} else if authType == "RESOURCE_PRINCIPAL" {
		provider, err = auth.ResourcePrincipalConfigurationProvider()
		if err != nil {
			return nil, fmt.Errorf("failed to create resource principal provider: %v", err)
		}
	} else {
		provider = common.DefaultConfigProvider()
	}

	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCI object storage client: %v", err)
	}

	// Remove default 60s timeout for large file streaming
	client.HTTPClient = &http.Client{
		Timeout: 0,
	}

	return &OCIClient{
		client:    client,
		namespace: namespace,
	}, nil
}

func (u *OCIClient) ListBuckets(ctx context.Context, compartmentID string) ([]string, error) {
	var buckets []string
	var nextStartWith *string

	for {
		req := objectstorage.ListBucketsRequest{
			NamespaceName: &u.namespace,
			CompartmentId: &compartmentID,
			Page:          nextStartWith,
			Limit:         common.Int(1000),
		}
		resp, err := u.client.ListBuckets(ctx, req)
		if err != nil {
			return nil, err
		}
		for _, b := range resp.Items {
			buckets = append(buckets, *b.Name)
		}
		if resp.OpcNextPage == nil {
			break
		}
		nextStartWith = resp.OpcNextPage
	}
	return buckets, nil
}

func (u *OCIClient) ListObjects(ctx context.Context, bucket, prefix string) ([]storage_clients.ObjectInfo, error) {
	var objects []storage_clients.ObjectInfo
	var nextStartWith *string

	fields := "name,size"

	for {
		req := objectstorage.ListObjectsRequest{
			NamespaceName: &u.namespace,
			BucketName:    &bucket,
			Prefix:        common.String(prefix),
			Fields:        &fields,
			Limit:         common.Int(1000),
			Start:         nextStartWith,
		}
		resp, err := u.client.ListObjects(ctx, req)
		if err != nil {
			return nil, err
		}
		for _, o := range resp.ListObjects.Objects {
			size := int64(0)
			if o.Size != nil {
				size = *o.Size
			}
			objects = append(objects, storage_clients.ObjectInfo{
				Name: *o.Name,
				Size: size,
			})
		}
		if resp.ListObjects.NextStartWith == nil {
			break
		}
		nextStartWith = resp.ListObjects.NextStartWith
	}
	return objects, nil
}

func (u *OCIClient) GetObjectSize(ctx context.Context, bucket, key string) (int64, error) {
	req := objectstorage.HeadObjectRequest{
		NamespaceName: &u.namespace,
		BucketName:    &bucket,
		ObjectName:    &key,
	}
	resp, err := u.client.HeadObject(ctx, req)
	if err != nil {
		return 0, fmt.Errorf("failed to head object: %w", err)
	}
	if resp.ContentLength == nil {
		return 0, fmt.Errorf("content length not returned")
	}
	return *resp.ContentLength, nil
}

func (u *OCIClient) GetObjectRange(ctx context.Context, bucket, key string, startByte, endByte int64) (io.ReadCloser, error) {
	if startByte < 0 {
		return nil, fmt.Errorf("start byte must be non-negative")
	}

	var rangeHeader string
	if endByte == -1 {
		rangeHeader = fmt.Sprintf("bytes=%d-", startByte)
	} else {
		if endByte < startByte {
			return nil, fmt.Errorf("end byte must be greater than or equal to start byte")
		}
		rangeHeader = fmt.Sprintf("bytes=%d-%d", startByte, endByte)
	}

	req := objectstorage.GetObjectRequest{
		NamespaceName: &u.namespace,
		BucketName:    &bucket,
		ObjectName:    &key,
		Range:         &rangeHeader,
	}

	resp, err := u.client.GetObject(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get object range: %w", err)
	}

	return resp.Content, nil
}

func (u *OCIClient) Initiate(ctx context.Context, bucket, key string) (string, error) {
	req := objectstorage.CreateMultipartUploadRequest{
		NamespaceName: &u.namespace,
		BucketName:    &bucket,
		CreateMultipartUploadDetails: objectstorage.CreateMultipartUploadDetails{
			Object: &key,
		},
	}

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		resp, err := u.client.CreateMultipartUpload(ctx, req)
		if err == nil {
			return *resp.UploadId, nil
		}
		lastErr = err
		time.Sleep(time.Duration(1<<attempt-1) * time.Second)
	}
	return "", fmt.Errorf("initiate upload failed: %w", lastErr)
}

func (u *OCIClient) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, data []byte) (string, error) {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		req := objectstorage.UploadPartRequest{
			NamespaceName:  &u.namespace,
			BucketName:     &bucket,
			ObjectName:     &key,
			UploadId:       &uploadID,
			UploadPartNum:  &partNumber,
			ContentLength:  common.Int64(int64(len(data))),
			UploadPartBody: io.NopCloser(bytes.NewReader(data)),
		}

		resp, err := u.client.UploadPart(ctx, req)
		req.UploadPartBody = nil
		if err == nil && resp.ETag != nil {
			etag := string([]byte(*resp.ETag))
			return etag, nil
		} else if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("no ETag returned")
		}
		time.Sleep(time.Duration(1<<attempt-1) * time.Second)
	}
	return "", fmt.Errorf("upload part failed: %w", lastErr)
}

func (u *OCIClient) Complete(ctx context.Context, bucket, key, uploadID string, etags map[int]string) error {
	parts := make([]objectstorage.CommitMultipartUploadPartDetails, 0, len(etags))
	for partNum, etag := range etags {
		parts = append(parts, objectstorage.CommitMultipartUploadPartDetails{
			PartNum: common.Int(partNum),
			Etag:    common.String(etag),
		})
	}

	req := objectstorage.CommitMultipartUploadRequest{
		NamespaceName: &u.namespace,
		BucketName:    &bucket,
		ObjectName:    &key,
		UploadId:      &uploadID,
		CommitMultipartUploadDetails: objectstorage.CommitMultipartUploadDetails{
			PartsToCommit: parts,
		},
	}

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		_, err := u.client.CommitMultipartUpload(ctx, req)
		if err == nil {
			return nil
		}
		lastErr = err
		time.Sleep(time.Duration(1<<attempt-1) * time.Second)
	}
	return fmt.Errorf("complete upload failed: %w", lastErr)
}

func (u *OCIClient) PutObject(ctx context.Context, bucket, key string, data []byte) error {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		req := objectstorage.PutObjectRequest{
			NamespaceName: &u.namespace,
			BucketName:    &bucket,
			ObjectName:    &key,
			ContentLength: common.Int64(int64(len(data))),
			PutObjectBody: io.NopCloser(bytes.NewReader(data)),
		}

		_, err := u.client.PutObject(ctx, req)
		req.PutObjectBody = nil
		if err == nil {
			return nil
		}
		lastErr = err
		time.Sleep(time.Duration(1<<attempt-1) * time.Second)
	}
	return fmt.Errorf("put object failed: %w", lastErr)
}

func (u *OCIClient) Abort(ctx context.Context, bucket, key, uploadID string) error {
	req := objectstorage.AbortMultipartUploadRequest{
		NamespaceName: &u.namespace,
		BucketName:    &bucket,
		ObjectName:    &key,
		UploadId:      &uploadID,
	}

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		_, err := u.client.AbortMultipartUpload(ctx, req)
		if err == nil || strings.Contains(err.Error(), "NoSuchUpload") || strings.Contains(err.Error(), "404") {
			return nil
		}
		lastErr = err
		time.Sleep(time.Duration(1<<attempt-1) * time.Second)
	}
	return fmt.Errorf("abort upload failed: %w", lastErr)
}

func (u *OCIClient) DeleteObject(ctx context.Context, bucket, key string) error {
	req := objectstorage.DeleteObjectRequest{
		NamespaceName: &u.namespace,
		BucketName:    &bucket,
		ObjectName:    &key,
	}
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		_, err := u.client.DeleteObject(ctx, req)
		if err == nil {
			return nil
		}
		lastErr = err
		time.Sleep(time.Duration(1<<attempt-1) * time.Second)
	}
	return fmt.Errorf("delete object failed: %w", lastErr)
}

func (u *OCIClient) SetRegion(region string) {
	u.client.SetRegion(region)
}
