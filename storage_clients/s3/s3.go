package s3

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/abyii/t-sync-sdk-go/v2/storage_clients"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func init() {
	storage_clients.RegisterClient("s3", func(authType, namespace string) (storage_clients.ObjectStorageClient, error) {
		return NewS3Client(authType)
	})
}

type S3Client struct {
	client *s3.Client
}

func NewS3Client(authType string) (*S3Client, error) {
	var credsProvider aws.CredentialsProvider
	if strings.HasPrefix(authType, "S3_ACCESS_KEYS[") && strings.HasSuffix(authType, "]") {
		keysStr := authType[len("S3_ACCESS_KEYS[") : len(authType)-1]
		parts := strings.Split(keysStr, ":")
		if len(parts) < 2 || len(parts) > 3 {
			return nil, fmt.Errorf("invalid S3_ACCESS_KEYS format")
		}

		accessKey := parts[0]
		secretKey := parts[1]
		sessionToken := ""
		if len(parts) == 3 {
			sessionToken = parts[2]
		}
		credsProvider = credentials.NewStaticCredentialsProvider(accessKey, secretKey, sessionToken)
	} else {
		return nil, fmt.Errorf("only S3_ACCESS_KEYS authentication is supported for S3")
	}

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
		if region == "" {
			region = "ap-south-1"
		}
	}

	client := s3.New(s3.Options{
		Region:      region,
		Credentials: credsProvider,
	})

	return &S3Client{
		client: client,
	}, nil
}

func (u *S3Client) ListBuckets(ctx context.Context, compartmentID string) ([]string, error) {
	// For S3, CompartmentID is ignored, list all buckets
	resp, err := u.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}
	var buckets []string
	for _, b := range resp.Buckets {
		buckets = append(buckets, *b.Name)
	}
	return buckets, nil
}

func (u *S3Client) ListObjects(ctx context.Context, bucket, prefix string) ([]storage_clients.ObjectInfo, error) {
	var objects []storage_clients.ObjectInfo
	var continuationToken *string

	for {
		req := &s3.ListObjectsV2Input{
			Bucket:            aws.String(bucket),
			Prefix:            aws.String(prefix),
			ContinuationToken: continuationToken,
		}
		resp, err := u.client.ListObjectsV2(ctx, req)
		if err != nil {
			return nil, err
		}
		for _, o := range resp.Contents {
			size := int64(0)
			if o.Size != nil {
				size = *o.Size
			}
			objects = append(objects, storage_clients.ObjectInfo{
				Name: *o.Key,
				Size: size,
			})
		}
		if resp.IsTruncated != nil && *resp.IsTruncated {
			continuationToken = resp.NextContinuationToken
		} else {
			break
		}
	}
	return objects, nil
}

func (u *S3Client) GetObjectSize(ctx context.Context, bucket, key string) (int64, error) {
	input := &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	resp, err := u.client.HeadObject(ctx, input)
	if err != nil {
		return 0, fmt.Errorf("failed to head object: %w", err)
	}

	if resp.ContentLength == nil {
		return 0, fmt.Errorf("content length not returned")
	}

	return *resp.ContentLength, nil
}

func (u *S3Client) GetObjectRange(ctx context.Context, bucket, key string, startByte, endByte int64) (io.ReadCloser, error) {
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

	input := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Range:  aws.String(rangeHeader),
	}

	resp, err := u.client.GetObject(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get object range: %w", err)
	}

	return resp.Body, nil
}

func (u *S3Client) Initiate(ctx context.Context, bucket, key string) (string, error) {
	input := &s3.CreateMultipartUploadInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		resp, err := u.client.CreateMultipartUpload(ctx, input)
		if err == nil {
			return *resp.UploadId, nil
		}
		lastErr = err
		time.Sleep(time.Duration(1<<attempt-1) * time.Second)
	}
	return "", fmt.Errorf("initiate upload failed: %w", lastErr)
}

func (u *S3Client) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, data []byte) (string, error) {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		input := &s3.UploadPartInput{
			Bucket:        aws.String(bucket),
			Key:           aws.String(key),
			UploadId:      aws.String(uploadID),
			PartNumber:    aws.Int32(int32(partNumber)),
			ContentLength: aws.Int64(int64(len(data))),
			Body:          bytes.NewReader(data),
		}

		resp, err := u.client.UploadPart(ctx, input)
		input.Body = nil
		if err == nil && resp.ETag != nil {
			etag := string([]byte(*resp.ETag))
			runtime.GC()
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

func (u *S3Client) Complete(ctx context.Context, bucket, key, uploadID string, etags map[int]string) error {
	var partNums []int
	for partNum := range etags {
		partNums = append(partNums, partNum)
	}
	sort.Ints(partNums)

	var completedParts []types.CompletedPart
	for _, partNum := range partNums {
		completedParts = append(completedParts, types.CompletedPart{
			PartNumber: aws.Int32(int32(partNum)),
			ETag:       aws.String(etags[partNum]),
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

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		_, err := u.client.CompleteMultipartUpload(ctx, input)
		if err == nil {
			return nil
		}
		lastErr = err
		time.Sleep(time.Duration(1<<attempt-1) * time.Second)
	}
	return fmt.Errorf("complete upload failed: %w", lastErr)
}

func (u *S3Client) PutObject(ctx context.Context, bucket, key string, data []byte) error {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		input := &s3.PutObjectInput{
			Bucket:        aws.String(bucket),
			Key:           aws.String(key),
			ContentLength: aws.Int64(int64(len(data))),
			Body:          bytes.NewReader(data),
		}
		_, err := u.client.PutObject(ctx, input)
		input.Body = nil
		if err == nil {
			return nil
		}
		lastErr = err
		time.Sleep(time.Duration(1<<attempt-1) * time.Second)
	}
	return fmt.Errorf("put object failed: %w", lastErr)
}

func (u *S3Client) Abort(ctx context.Context, bucket, key, uploadID string) error {
	input := &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
	}
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		_, err := u.client.AbortMultipartUpload(ctx, input)
		if err == nil || strings.Contains(err.Error(), "NoSuchUpload") || strings.Contains(err.Error(), "404") {
			return nil
		}
		lastErr = err
		time.Sleep(time.Duration(1<<attempt-1) * time.Second)
	}
	return fmt.Errorf("abort upload failed: %w", lastErr)
}

func (u *S3Client) DeleteObject(ctx context.Context, bucket, key string) error {
	input := &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		_, err := u.client.DeleteObject(ctx, input)
		if err == nil {
			return nil
		}
		lastErr = err
		time.Sleep(time.Duration(1<<attempt-1) * time.Second)
	}
	return fmt.Errorf("delete object failed: %w", lastErr)
}

func (u *S3Client) SetRegion(region string) {
	// S3 client region is configured during creation or environment variables.
	// This is a noop for general compatibility.
}
