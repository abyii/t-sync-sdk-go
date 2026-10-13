package s3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/abyii/t-sync-sdk-go/v2/storage_clients"
	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

func init() {
	storage_clients.RegisterClient("s3", func(authType, namespace string) (storage_clients.ObjectStorageClient, error) {
		return NewS3Client(authType)
	})
}

type S3Client struct {
	mu     sync.RWMutex
	client *s3.Client
	cfg    aws.Config
	retry  storage_clients.RetryPolicy
}

// newHTTPClient returns the SDK's buildable client with no overall timeout and
// dial/TLS/response-header timeouts for stall protection.
func newHTTPClient() aws.HTTPClient {
	return awshttp.NewBuildableClient().
		WithTimeout(0).
		WithTransportOptions(storage_clients.TuneTransport)
}

// newS3 builds an S3 client with SDK-internal retries disabled; RetryPolicy is
// the only retry layer.
func newS3(cfg aws.Config, optFns ...func(*s3.Options)) *s3.Client {
	opts := append([]func(*s3.Options){func(o *s3.Options) {
		o.Retryer = aws.NopRetryer{}
		o.RetryMaxAttempts = 0
	}}, optFns...)
	return s3.NewFromConfig(cfg, opts...)
}

// NewS3Client creates an S3 client. authType is "BASE[;region=REGION]" with
// BASE one of DEFAULT, DEFAULT[roleARN], S3_ACCESS_KEYS[key:secret[:token]].
func NewS3Client(authType string) (*S3Client, error) {
	baseAuth, opts, err := storage_clients.ParseAuthString(authType, "region")
	if err != nil {
		return nil, err
	}

	region := opts["region"]
	if region == "" {
		region = os.Getenv("AWS_REGION")
	}
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}
	if region == "" {
		region = "ap-south-1"
	}

	var cfg aws.Config
	switch {
	case strings.HasPrefix(baseAuth, "S3_ACCESS_KEYS[") && strings.HasSuffix(baseAuth, "]"):
		keysStr := baseAuth[len("S3_ACCESS_KEYS[") : len(baseAuth)-1]
		parts := strings.Split(keysStr, ":")
		if len(parts) < 2 || len(parts) > 3 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("%w: invalid S3_ACCESS_KEYS format (want S3_ACCESS_KEYS[KEY:SECRET[:TOKEN]])", storage_clients.ErrInvalidConfig)
		}
		sessionToken := ""
		if len(parts) == 3 {
			sessionToken = parts[2]
		}
		cfg = aws.Config{
			Region:      region,
			Credentials: credentials.NewStaticCredentialsProvider(parts[0], parts[1], sessionToken),
		}
	case baseAuth == "DEFAULT" || (strings.HasPrefix(baseAuth, "DEFAULT[") && strings.HasSuffix(baseAuth, "]")):
		cfg, err = config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
		if err != nil {
			return nil, fmt.Errorf("failed to load default AWS config: %w", err)
		}
		if strings.HasPrefix(baseAuth, "DEFAULT[") {
			roleARN := strings.TrimSpace(baseAuth[len("DEFAULT[") : len(baseAuth)-1])
			if roleARN == "" {
				return nil, fmt.Errorf("%w: empty role ARN provided in DEFAULT[...] authType", storage_clients.ErrInvalidConfig)
			}
			stsClient := sts.NewFromConfig(cfg)
			cfg.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(stsClient, roleARN))
		}
	default:
		return nil, fmt.Errorf("%w: unsupported authType for S3 client: %q", storage_clients.ErrInvalidConfig, baseAuth)
	}
	if bc, ok := cfg.HTTPClient.(*awshttp.BuildableClient); ok {
		cfg.HTTPClient = bc.WithTimeout(0).WithTransportOptions(storage_clients.TuneTransport)
	} else if cfg.HTTPClient == nil {
		cfg.HTTPClient = newHTTPClient()
	}

	return &S3Client{
		client: newS3(cfg),
		cfg:    cfg,
		retry:  storage_clients.DefaultRetryPolicy,
	}, nil
}

// classifyError maps an AWS SDK error to the storage_clients error contract:
// HTTP responses become *StatusError (404 matches ErrNotFound), NoSuchKey /
// NotFound / NoSuchBucket match ErrNotFound, NoSuchUpload (or any 404 on a
// multipart-upload operation) matches ErrUploadNotFound. S3's 400
// "RequestTimeout" (client body too slow) is left unclassified so it is retried.
func classifyError(op string, err error, uploadOp bool) error {
	if err == nil {
		return nil
	}
	status := 0
	var re *awshttp.ResponseError
	if errors.As(err, &re) {
		status = re.HTTPStatusCode()
	}
	code := ""
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code = apiErr.ErrorCode()
	}

	var (
		noSuchKey    *types.NoSuchKey
		notFound     *types.NotFound
		noSuchBucket *types.NoSuchBucket
		noSuchUpload *types.NoSuchUpload
	)
	isNotFound := errors.As(err, &noSuchKey) || errors.As(err, &notFound) || errors.As(err, &noSuchBucket) ||
		code == "NoSuchKey" || code == "NotFound" || code == "NoSuchBucket"
	isUploadGone := errors.As(err, &noSuchUpload) || code == "NoSuchUpload" ||
		(uploadOp && status == http.StatusNotFound)

	var out error
	if status != 0 && code != "RequestTimeout" {
		out = &storage_clients.StatusError{Op: op, StatusCode: status, Err: err}
	} else {
		out = fmt.Errorf("%s: %w", op, err)
	}
	if isNotFound && !errors.Is(out, storage_clients.ErrNotFound) {
		out = fmt.Errorf("%w: %w", storage_clients.ErrNotFound, out)
	}
	if isUploadGone {
		out = fmt.Errorf("%w: %w", storage_clients.ErrUploadNotFound, out)
	}
	return out
}

func (u *S3Client) getClient() *s3.Client {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.client
}

func (u *S3Client) SetRegion(region string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.cfg.Region = region
	u.client = newS3(u.cfg)
}

func (u *S3Client) ListBuckets(ctx context.Context, compartmentID string) ([]string, error) {
	// For S3, compartmentID is ignored; list all buckets.
	var buckets []string
	var token *string
	for {
		input := &s3.ListBucketsInput{ContinuationToken: token}
		var resp *s3.ListBucketsOutput
		err := u.retry.Do(ctx, "s3 list buckets", storage_clients.MetadataAttemptTimeout, func(ctx context.Context) error {
			var err error
			resp, err = u.getClient().ListBuckets(ctx, input)
			return classifyError("ListBuckets", err, false)
		})
		if err != nil {
			return nil, err
		}
		for _, b := range resp.Buckets {
			buckets = append(buckets, aws.ToString(b.Name))
		}
		if aws.ToString(resp.ContinuationToken) == "" {
			break
		}
		token = resp.ContinuationToken
	}
	return buckets, nil
}

func (u *S3Client) ListObjects(ctx context.Context, bucket, prefix string) ([]storage_clients.ObjectInfo, error) {
	var objects []storage_clients.ObjectInfo
	var token *string

	for {
		input := &s3.ListObjectsV2Input{
			Bucket:            aws.String(bucket),
			Prefix:            aws.String(prefix),
			ContinuationToken: token,
		}
		var resp *s3.ListObjectsV2Output
		err := u.retry.Do(ctx, "s3 list objects", storage_clients.MetadataAttemptTimeout, func(ctx context.Context) error {
			var err error
			resp, err = u.getClient().ListObjectsV2(ctx, input)
			return classifyError("ListObjectsV2", err, false)
		})
		if err != nil {
			return nil, err
		}
		for _, o := range resp.Contents {
			objects = append(objects, storage_clients.ObjectInfo{
				Name: aws.ToString(o.Key),
				Size: aws.ToInt64(o.Size),
			})
		}
		if !aws.ToBool(resp.IsTruncated) {
			break
		}
		if aws.ToString(resp.NextContinuationToken) == "" {
			return nil, fmt.Errorf("%w: truncated listing without continuation token", storage_clients.ErrInvalidResponse)
		}
		token = resp.NextContinuationToken
	}
	return objects, nil
}

func (u *S3Client) GetObjectSize(ctx context.Context, bucket, key string) (int64, error) {
	input := &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}
	var size int64
	err := u.retry.Do(ctx, "s3 head object", storage_clients.MetadataAttemptTimeout, func(ctx context.Context) error {
		resp, err := u.getClient().HeadObject(ctx, input)
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

func (u *S3Client) GetObjectRange(ctx context.Context, bucket, key string, startByte, endByte int64) (io.ReadCloser, error) {
	rng, err := rangeHeader(startByte, endByte)
	if err != nil {
		return nil, err
	}
	input := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}
	if rng != "" {
		input.Range = aws.String(rng)
	}

	var body io.ReadCloser
	// No per-attempt timeout: the body outlives the attempt. Header stalls are
	// bounded by the transport's ResponseHeaderTimeout.
	err = u.retry.Do(ctx, "s3 get object", 0, func(ctx context.Context) error {
		resp, err := u.getClient().GetObject(ctx, input)
		if err != nil {
			return classifyError("GetObject", err, false)
		}
		body = resp.Body
		return nil
	})
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (u *S3Client) Initiate(ctx context.Context, bucket, key string) (string, error) {
	input := &s3.CreateMultipartUploadInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}
	var uploadID string
	err := u.retry.Do(ctx, "s3 initiate upload", storage_clients.MetadataAttemptTimeout, func(ctx context.Context) error {
		resp, err := u.getClient().CreateMultipartUpload(ctx, input)
		if err != nil {
			return classifyError("CreateMultipartUpload", err, false)
		}
		if aws.ToString(resp.UploadId) == "" {
			return fmt.Errorf("%w: no upload ID returned", storage_clients.ErrInvalidResponse)
		}
		uploadID = *resp.UploadId
		return nil
	})
	return uploadID, err
}

func (u *S3Client) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, data []byte) (string, error) {
	var etag string
	err := u.retry.Do(ctx, "s3 upload part", storage_clients.UploadAttemptTimeout(len(data)), func(ctx context.Context) error {
		input := &s3.UploadPartInput{
			Bucket:        aws.String(bucket),
			Key:           aws.String(key),
			UploadId:      aws.String(uploadID),
			PartNumber:    aws.Int32(int32(partNumber)),
			ContentLength: aws.Int64(int64(len(data))),
			Body:          bytes.NewReader(data),
		}
		resp, err := u.getClient().UploadPart(ctx, input)
		if err != nil {
			return classifyError("UploadPart", err, true)
		}
		if aws.ToString(resp.ETag) == "" {
			return fmt.Errorf("%w: no ETag returned", storage_clients.ErrInvalidResponse)
		}
		etag = *resp.ETag
		return nil
	})
	return etag, err
}

func (u *S3Client) Complete(ctx context.Context, bucket, key, uploadID string, etags map[int]string) error {
	partNums := make([]int, 0, len(etags))
	for n := range etags {
		partNums = append(partNums, n)
	}
	slices.Sort(partNums)

	completedParts := make([]types.CompletedPart, 0, len(partNums))
	for _, n := range partNums {
		completedParts = append(completedParts, types.CompletedPart{
			PartNumber: aws.Int32(int32(n)),
			ETag:       aws.String(etags[n]),
		})
	}

	input := &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: completedParts,
		},
	}
	return u.retry.Do(ctx, "s3 complete upload", storage_clients.CompleteAttemptTimeout, func(ctx context.Context) error {
		_, err := u.getClient().CompleteMultipartUpload(ctx, input)
		classified := classifyError("CompleteMultipartUpload", err, true)
		if errors.Is(classified, storage_clients.ErrUploadNotFound) {
			// A previous attempt may have succeeded while its response was lost.
			if _, headErr := u.GetObjectSize(ctx, bucket, key); headErr == nil {
				return nil
			}
		}
		return classified
	})
}

func (u *S3Client) PutObject(ctx context.Context, bucket, key string, data []byte) error {
	return u.retry.Do(ctx, "s3 put object", storage_clients.UploadAttemptTimeout(len(data)), func(ctx context.Context) error {
		input := &s3.PutObjectInput{
			Bucket:        aws.String(bucket),
			Key:           aws.String(key),
			ContentLength: aws.Int64(int64(len(data))),
			Body:          bytes.NewReader(data),
		}
		_, err := u.getClient().PutObject(ctx, input)
		return classifyError("PutObject", err, false)
	})
}

// Abort aborts a multipart upload. An upload that is already gone (unknown
// upload ID) is treated as success.
func (u *S3Client) Abort(ctx context.Context, bucket, key, uploadID string) error {
	input := &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
	}
	err := u.retry.Do(ctx, "s3 abort upload", storage_clients.MetadataAttemptTimeout, func(ctx context.Context) error {
		_, err := u.getClient().AbortMultipartUpload(ctx, input)
		return classifyError("AbortMultipartUpload", err, true)
	})
	if errors.Is(err, storage_clients.ErrUploadNotFound) {
		return nil
	}
	return err
}

// DeleteObject deletes an object. S3 itself reports success for missing keys;
// S3-compatible stores returning 404 yield an error matching ErrNotFound.
func (u *S3Client) DeleteObject(ctx context.Context, bucket, key string) error {
	input := &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}
	return u.retry.Do(ctx, "s3 delete object", storage_clients.MetadataAttemptTimeout, func(ctx context.Context) error {
		_, err := u.getClient().DeleteObject(ctx, input)
		return classifyError("DeleteObject", err, false)
	})
}
