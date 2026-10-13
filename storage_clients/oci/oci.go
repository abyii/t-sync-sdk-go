package oci

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"

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
	retry     storage_clients.RetryPolicy
}

// newConfigProvider resolves the base auth part of an auth string.
// Accepted: "" / "DEFAULT" (default ~/.oci/config chain), "OCI_CONFIG_FILE",
// "OCI_CONFIG_FILE[PROFILE]", "OKE_WORKLOAD_IDENTITY", "INSTANCE_PRINCIPAL",
// "RESOURCE_PRINCIPAL". Anything else is ErrInvalidConfig.
func newConfigProvider(baseAuth string) (common.ConfigurationProvider, error) {
	switch {
	case baseAuth == "" || baseAuth == "DEFAULT":
		return common.DefaultConfigProvider(), nil
	case baseAuth == "OCI_CONFIG_FILE":
		return common.CustomProfileConfigProvider("~/.oci/config", "DEFAULT"), nil
	case strings.HasPrefix(baseAuth, "OCI_CONFIG_FILE[") && strings.HasSuffix(baseAuth, "]"):
		profile := strings.TrimSpace(baseAuth[len("OCI_CONFIG_FILE[") : len(baseAuth)-1])
		if profile == "" {
			profile = "DEFAULT"
		}
		return common.CustomProfileConfigProvider("~/.oci/config", profile), nil
	case baseAuth == "OKE_WORKLOAD_IDENTITY":
		p, err := auth.OkeWorkloadIdentityConfigurationProvider()
		if err != nil {
			return nil, fmt.Errorf("failed to create OKE workload identity provider: %w", err)
		}
		return p, nil
	case baseAuth == "INSTANCE_PRINCIPAL":
		p, err := auth.InstancePrincipalConfigurationProvider()
		if err != nil {
			return nil, fmt.Errorf("failed to create instance principal provider: %w", err)
		}
		return p, nil
	case baseAuth == "RESOURCE_PRINCIPAL":
		p, err := auth.ResourcePrincipalConfigurationProvider()
		if err != nil {
			return nil, fmt.Errorf("failed to create resource principal provider: %w", err)
		}
		return p, nil
	default:
		return nil, fmt.Errorf("%w: unsupported OCI auth type %q (want DEFAULT, OCI_CONFIG_FILE[PROFILE], OKE_WORKLOAD_IDENTITY, INSTANCE_PRINCIPAL or RESOURCE_PRINCIPAL)", storage_clients.ErrInvalidConfig, baseAuth)
	}
}

// NewOCIClient creates an OCI Object Storage client. authType is
// "BASE[;region=REGION]" (options in any order; see newConfigProvider for BASE).
func NewOCIClient(namespace, authType string) (*OCIClient, error) {
	if namespace == "" {
		return nil, fmt.Errorf("%w: namespace is required", storage_clients.ErrInvalidConfig)
	}

	baseAuth, opts, err := storage_clients.ParseAuthString(authType, "region")
	if err != nil {
		return nil, err
	}
	provider, err := newConfigProvider(baseAuth)
	if err != nil {
		return nil, err
	}

	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCI object storage client: %w", err)
	}
	configureClient(&client)

	if region := opts["region"]; region != "" {
		client.SetRegion(region)
	}

	return &OCIClient{
		client:    client,
		namespace: namespace,
		retry:     storage_clients.DefaultRetryPolicy,
	}, nil
}

// configureClient keeps the SDK dispatcher (custom CA bundle, client certs,
// cert refresh) but removes the overall client timeout (unless the user set
// OCI_CUSTOM_CLIENT_TIMEOUT), adds dial/TLS/response-header timeouts on the
// transport, and disables SDK-internal retries (our RetryPolicy is the only
// retry layer).
func configureClient(client *objectstorage.ObjectStorageClient) {
	if hc, ok := client.HTTPClient.(*http.Client); ok {
		tuned := *hc
		if os.Getenv(common.CustomClientTimeoutEnvVar) == "" {
			tuned.Timeout = 0
		}
		if w, ok := hc.Transport.(*common.OciHTTPTransportWrapper); ok {
			w.TransportTemplate = func(tlsCfg *tls.Config) (http.RoundTripper, error) {
				tr, err := common.DefaultTransport(tlsCfg)
				if err != nil {
					return nil, err
				}
				storage_clients.TuneTransport(tr)
				return tr, nil
			}
		}
		client.HTTPClient = &tuned
	}
	noRetry := common.NoRetryPolicy()
	client.Configuration.RetryPolicy = &noRetry
}

// classifyError maps an OCI SDK error to the storage_clients error contract:
// service errors become *StatusError (404 matches ErrNotFound); for
// multipart-upload operations a 404 additionally matches ErrUploadNotFound.
func classifyError(op string, err error, uploadOp bool) error {
	if err == nil {
		return nil
	}
	var se common.ServiceError
	if errors.As(err, &se) {
		status := &storage_clients.StatusError{Op: op, StatusCode: se.GetHTTPStatusCode(), Err: err}
		if uploadOp && status.StatusCode == http.StatusNotFound {
			return fmt.Errorf("%w: %w", storage_clients.ErrUploadNotFound, status)
		}
		return status
	}
	return fmt.Errorf("%s: %w", op, err)
}

func (u *OCIClient) ListBuckets(ctx context.Context, compartmentID string) ([]string, error) {
	var buckets []string
	var page *string

	for {
		req := objectstorage.ListBucketsRequest{
			NamespaceName: &u.namespace,
			CompartmentId: &compartmentID,
			Page:          page,
			Limit:         common.Int(1000),
		}
		var resp objectstorage.ListBucketsResponse
		err := u.retry.Do(ctx, "oci list buckets", storage_clients.MetadataAttemptTimeout, func(ctx context.Context) error {
			var err error
			resp, err = u.client.ListBuckets(ctx, req)
			return classifyError("ListBuckets", err, false)
		})
		if err != nil {
			return nil, err
		}
		for _, b := range resp.Items {
			buckets = append(buckets, *b.Name)
		}
		if resp.OpcNextPage == nil {
			break
		}
		page = resp.OpcNextPage
	}
	return buckets, nil
}

func (u *OCIClient) ListObjects(ctx context.Context, bucket, prefix string) ([]storage_clients.ObjectInfo, error) {
	var objects []storage_clients.ObjectInfo
	var start *string
	fields := "name,size"

	for {
		req := objectstorage.ListObjectsRequest{
			NamespaceName: &u.namespace,
			BucketName:    &bucket,
			Prefix:        common.String(prefix),
			Fields:        &fields,
			Limit:         common.Int(1000),
			Start:         start,
		}
		var resp objectstorage.ListObjectsResponse
		err := u.retry.Do(ctx, "oci list objects", storage_clients.MetadataAttemptTimeout, func(ctx context.Context) error {
			var err error
			resp, err = u.client.ListObjects(ctx, req)
			return classifyError("ListObjects", err, false)
		})
		if err != nil {
			return nil, err
		}
		for _, o := range resp.ListObjects.Objects {
			size := int64(0)
			if o.Size != nil {
				size = *o.Size
			}
			objects = append(objects, storage_clients.ObjectInfo{Name: *o.Name, Size: size})
		}
		if resp.ListObjects.NextStartWith == nil {
			break
		}
		start = resp.ListObjects.NextStartWith
	}
	return objects, nil
}

func (u *OCIClient) GetObjectSize(ctx context.Context, bucket, key string) (int64, error) {
	req := objectstorage.HeadObjectRequest{
		NamespaceName: &u.namespace,
		BucketName:    &bucket,
		ObjectName:    &key,
	}
	var size int64
	err := u.retry.Do(ctx, "oci head object", storage_clients.MetadataAttemptTimeout, func(ctx context.Context) error {
		resp, err := u.client.HeadObject(ctx, req)
		if err != nil {
			return classifyError("HeadObject", err, false)
		}
		if resp.ContentLength == nil {
			return fmt.Errorf("%w: content length not returned", storage_clients.ErrInvalidResponse)
		}
		size = *resp.ContentLength
		return nil
	})
	return size, err
}

// rangeHeader returns the Range header for [startByte, endByte] (endByte -1 =
// to the end), or "" when the whole object is requested (so zero-byte objects
// can be read: "bytes=0-" on an empty object yields 416).
func rangeHeader(startByte, endByte int64) (string, error) {
	if startByte < 0 {
		return "", fmt.Errorf("%w: start byte %d must be non-negative", storage_clients.ErrInvalidRange, startByte)
	}
	if endByte == -1 {
		if startByte == 0 {
			return "", nil
		}
		return fmt.Sprintf("bytes=%d-", startByte), nil
	}
	if endByte < startByte {
		return "", fmt.Errorf("%w: end byte %d before start byte %d", storage_clients.ErrInvalidRange, endByte, startByte)
	}
	return fmt.Sprintf("bytes=%d-%d", startByte, endByte), nil
}

func (u *OCIClient) GetObjectRange(ctx context.Context, bucket, key string, startByte, endByte int64) (io.ReadCloser, error) {
	rng, err := rangeHeader(startByte, endByte)
	if err != nil {
		return nil, err
	}
	req := objectstorage.GetObjectRequest{
		NamespaceName: &u.namespace,
		BucketName:    &bucket,
		ObjectName:    &key,
	}
	if rng != "" {
		req.Range = &rng
	}

	var body io.ReadCloser
	// No per-attempt timeout: the body outlives the attempt. Header stalls are
	// bounded by the transport's ResponseHeaderTimeout.
	err = u.retry.Do(ctx, "oci get object", 0, func(ctx context.Context) error {
		resp, err := u.client.GetObject(ctx, req)
		if err != nil {
			return classifyError("GetObject", err, false)
		}
		body = resp.Content
		return nil
	})
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (u *OCIClient) Initiate(ctx context.Context, bucket, key string) (string, error) {
	req := objectstorage.CreateMultipartUploadRequest{
		NamespaceName: &u.namespace,
		BucketName:    &bucket,
		CreateMultipartUploadDetails: objectstorage.CreateMultipartUploadDetails{
			Object: &key,
		},
	}
	var uploadID string
	err := u.retry.Do(ctx, "oci initiate upload", storage_clients.MetadataAttemptTimeout, func(ctx context.Context) error {
		resp, err := u.client.CreateMultipartUpload(ctx, req)
		if err != nil {
			return classifyError("CreateMultipartUpload", err, false)
		}
		if resp.UploadId == nil || *resp.UploadId == "" {
			return fmt.Errorf("%w: no upload ID returned", storage_clients.ErrInvalidResponse)
		}
		uploadID = *resp.UploadId
		return nil
	})
	return uploadID, err
}

func (u *OCIClient) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, data []byte) (string, error) {
	var etag string
	err := u.retry.Do(ctx, "oci upload part", storage_clients.UploadAttemptTimeout(len(data)), func(ctx context.Context) error {
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
		if err != nil {
			return classifyError("UploadPart", err, true)
		}
		if resp.ETag == nil || *resp.ETag == "" {
			return fmt.Errorf("%w: no ETag returned", storage_clients.ErrInvalidResponse)
		}
		etag = *resp.ETag
		return nil
	})
	return etag, err
}

func (u *OCIClient) Complete(ctx context.Context, bucket, key, uploadID string, etags map[int]string) error {
	partNums := make([]int, 0, len(etags))
	for n := range etags {
		partNums = append(partNums, n)
	}
	slices.Sort(partNums)
	parts := make([]objectstorage.CommitMultipartUploadPartDetails, 0, len(partNums))
	for _, n := range partNums {
		parts = append(parts, objectstorage.CommitMultipartUploadPartDetails{
			PartNum: common.Int(n),
			Etag:    common.String(etags[n]),
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
	return u.retry.Do(ctx, "oci complete upload", storage_clients.CompleteAttemptTimeout, func(ctx context.Context) error {
		_, err := u.client.CommitMultipartUpload(ctx, req)
		classified := classifyError("CommitMultipartUpload", err, true)
		if errors.Is(classified, storage_clients.ErrUploadNotFound) {
			if _, headErr := u.GetObjectSize(ctx, bucket, key); headErr == nil {
				return nil
			}
		}
		return classified
	})
}

func (u *OCIClient) PutObject(ctx context.Context, bucket, key string, data []byte) error {
	return u.retry.Do(ctx, "oci put object", storage_clients.UploadAttemptTimeout(len(data)), func(ctx context.Context) error {
		req := objectstorage.PutObjectRequest{
			NamespaceName: &u.namespace,
			BucketName:    &bucket,
			ObjectName:    &key,
			ContentLength: common.Int64(int64(len(data))),
			PutObjectBody: io.NopCloser(bytes.NewReader(data)),
		}
		_, err := u.client.PutObject(ctx, req)
		return classifyError("PutObject", err, false)
	})
}

// Abort aborts a multipart upload. An upload that is already gone (unknown
// upload ID) is treated as success.
func (u *OCIClient) Abort(ctx context.Context, bucket, key, uploadID string) error {
	req := objectstorage.AbortMultipartUploadRequest{
		NamespaceName: &u.namespace,
		BucketName:    &bucket,
		ObjectName:    &key,
		UploadId:      &uploadID,
	}
	err := u.retry.Do(ctx, "oci abort upload", storage_clients.MetadataAttemptTimeout, func(ctx context.Context) error {
		_, err := u.client.AbortMultipartUpload(ctx, req)
		return classifyError("AbortMultipartUpload", err, true)
	})
	if errors.Is(err, storage_clients.ErrUploadNotFound) {
		return nil
	}
	return err
}

// DeleteObject deletes an object; a missing object yields an error matching
// storage_clients.ErrNotFound.
func (u *OCIClient) DeleteObject(ctx context.Context, bucket, key string) error {
	req := objectstorage.DeleteObjectRequest{
		NamespaceName: &u.namespace,
		BucketName:    &bucket,
		ObjectName:    &key,
	}
	return u.retry.Do(ctx, "oci delete object", storage_clients.MetadataAttemptTimeout, func(ctx context.Context) error {
		_, err := u.client.DeleteObject(ctx, req)
		return classifyError("DeleteObject", err, false)
	})
}

func (u *OCIClient) SetRegion(region string) {
	u.client.SetRegion(region)
}
