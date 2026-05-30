package http

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/abyii/t-sync-sdk-go/storage_clients"
)

func init() {
	storage_clients.RegisterClient("http", func(authType, namespace string) (storage_clients.ObjectStorageClient, error) {
		// namespace is treated as the base endpoint URL
		// authType is parsed for custom headers if present in the format: HEADER[Key1: Val1, Key2: Val2]
		headers := make(map[string]string)
		if authType != "" && strings.HasPrefix(authType, "HEADER[") && strings.HasSuffix(authType, "]") {
			content := authType[len("HEADER[") : len(authType)-1]
			parts := strings.Split(content, ",")
			for _, p := range parts {
				kv := strings.SplitN(strings.TrimSpace(p), ":", 2)
				if len(kv) == 2 {
					headers[kv[0]] = strings.TrimSpace(kv[1])
				}
			}
		}
		return NewHTTPStorageClient(namespace, headers), nil
	})
}

// HTTPStorageClient implements ObjectStorageClient using raw HTTP/S3-compatible REST requests.
type HTTPStorageClient struct {
	endpoint string            // Base URL (e.g. "https://cdn.example.com" or "http://localhost:9000")
	headers  map[string]string // Custom headers applied to every request
	client   *http.Client
}

// NewHTTPStorageClient creates a new HTTP storage client.
func NewHTTPStorageClient(endpoint string, headers map[string]string) *HTTPStorageClient {
	return &HTTPStorageClient{
		endpoint: endpoint,
		headers:  headers,
		client:   &http.Client{},
	}
}

func (h *HTTPStorageClient) buildURL(bucket, key string) string {
	url := strings.TrimSuffix(h.endpoint, "/")
	if bucket != "" {
		url += "/" + strings.TrimPrefix(bucket, "/")
	}
	if key != "" {
		url += "/" + strings.TrimPrefix(key, "/")
	}
	return url
}

func (h *HTTPStorageClient) doRequest(ctx context.Context, method, url string, body io.Reader, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	// Apply default custom headers configured on client
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}

	// Apply request-specific headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return h.client.Do(req)
}

func isRetryable(err error, resp *http.Response) bool {
	if err != nil {
		return true // Network errors are always retryable
	}
	if resp != nil {
		// Server errors (5xx) and rate limiting (429) are retryable
		return resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests
	}
	return false
}

func (h *HTTPStorageClient) ListBuckets(ctx context.Context, compartmentID string) ([]string, error) {
	// Not applicable for generic HTTP/CDN endpoints
	return nil, nil
}

type ListBucketResult struct {
	XMLName  xml.Name `xml:"ListBucketResult"`
	Contents []struct {
		Key  string `xml:"Key"`
		Size int64  `xml:"Size"`
	} `xml:"Contents"`
}

func (h *HTTPStorageClient) ListObjects(ctx context.Context, bucket, prefix string) ([]storage_clients.ObjectInfo, error) {
	url := h.buildURL(bucket, "")
	if prefix != "" {
		url += "?prefix=" + prefix
	}

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		resp, err := h.doRequest(ctx, "GET", url, nil, nil)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				data, readErr := io.ReadAll(resp.Body)
				if readErr != nil {
					return nil, readErr
				}

				var result ListBucketResult
				if err := xml.Unmarshal(data, &result); err != nil {
					// If listing XML is not returned/supported, return empty list gracefully
					return nil, nil
				}

				var objects []storage_clients.ObjectInfo
				for _, c := range result.Contents {
					objects = append(objects, storage_clients.ObjectInfo{
						Name: c.Key,
						Size: c.Size,
					})
				}
				return objects, nil
			}
			lastErr = fmt.Errorf("failed to list objects: status code %d", resp.StatusCode)
		} else {
			lastErr = err
		}

		if !isRetryable(err, resp) {
			return nil, lastErr
		}

		time.Sleep(time.Duration(1<<attempt-1) * time.Second)
	}
	return nil, lastErr
}

func (h *HTTPStorageClient) GetObjectSize(ctx context.Context, bucket, key string) (int64, error) {
	url := h.buildURL(bucket, key)

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		resp, err := h.doRequest(ctx, "HEAD", url, nil, nil)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusNotFound {
				return 0, os.ErrNotExist
			}
			if resp.StatusCode == http.StatusOK {
				contentLength := resp.Header.Get("Content-Length")
				if contentLength == "" {
					return 0, fmt.Errorf("missing Content-Length header")
				}
				size, parseErr := strconv.ParseInt(contentLength, 10, 64)
				if parseErr != nil {
					return 0, fmt.Errorf("invalid Content-Length: %w", parseErr)
				}
				return size, nil
			}
			lastErr = fmt.Errorf("failed to head object: status code %d", resp.StatusCode)
		} else {
			lastErr = err
		}

		if !isRetryable(err, resp) {
			return 0, lastErr
		}

		time.Sleep(time.Duration(1<<attempt-1) * time.Second)
	}
	return 0, lastErr
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

func (h *HTTPStorageClient) GetObjectRange(ctx context.Context, bucket, key string, startByte, endByte int64) (io.ReadCloser, error) {
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

	url := h.buildURL(bucket, key)
	headers := map[string]string{
		"Range": rangeHeader,
	}

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		resp, err := h.doRequest(ctx, "GET", url, nil, headers)
		if err == nil {
			if resp.StatusCode == http.StatusPartialContent {
				return resp.Body, nil
			}

			// Fallback in case endpoint does not support HTTP range requests:
			// Read full content and manually seek to the range
			if resp.StatusCode == http.StatusOK {
				if startByte > 0 {
					if _, err := io.CopyN(io.Discard, resp.Body, startByte); err != nil {
						resp.Body.Close()
						return nil, fmt.Errorf("failed to seek: %w", err)
					}
				}
				if endByte == -1 {
					return resp.Body, nil
				}
				return &limitReadCloser{
					r: io.LimitReader(resp.Body, endByte-startByte+1),
					c: resp.Body,
				}, nil
			}
			resp.Body.Close()
			lastErr = fmt.Errorf("failed to get object range: status code %d", resp.StatusCode)
		} else {
			lastErr = err
		}

		if !isRetryable(err, resp) {
			return nil, lastErr
		}

		time.Sleep(time.Duration(1<<attempt-1) * time.Second)
	}
	return nil, lastErr
}

type InitiateMultipartUploadResult struct {
	XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
	UploadID string   `xml:"UploadId"`
}

func (h *HTTPStorageClient) Initiate(ctx context.Context, bucket, key string) (string, error) {
	url := h.buildURL(bucket, key) + "?uploads"

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		resp, err := h.doRequest(ctx, "POST", url, nil, nil)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				data, readErr := io.ReadAll(resp.Body)
				if readErr != nil {
					return "", readErr
				}

				var result InitiateMultipartUploadResult
				if err := xml.Unmarshal(data, &result); err != nil {
					return "", fmt.Errorf("failed to parse initiate XML response: %w", err)
				}
				return result.UploadID, nil
			}
			lastErr = fmt.Errorf("failed to initiate multipart upload: status code %d", resp.StatusCode)
		} else {
			lastErr = err
		}

		if !isRetryable(err, resp) {
			return "", lastErr
		}

		time.Sleep(time.Duration(1<<attempt-1) * time.Second)
	}
	return "", lastErr
}

func (h *HTTPStorageClient) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, data []byte) (string, error) {
	url := fmt.Sprintf("%s?uploadId=%s&partNumber=%d", h.buildURL(bucket, key), uploadID, partNumber)
	headers := map[string]string{
		"Content-Length": strconv.Itoa(len(data)),
	}

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		resp, err := h.doRequest(ctx, "PUT", url, bytes.NewReader(data), headers)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				etag := resp.Header.Get("ETag")
				if etag == "" {
					return "", fmt.Errorf("missing ETag in upload part response")
				}
				return etag, nil
			}
			lastErr = fmt.Errorf("failed to upload part: status code %d", resp.StatusCode)
		} else {
			lastErr = err
		}

		if !isRetryable(err, resp) {
			return "", lastErr
		}

		time.Sleep(time.Duration(1<<attempt-1) * time.Second)
	}
	return "", lastErr
}

type CompleteMultipartUpload struct {
	XMLName xml.Name              `xml:"CompleteMultipartUpload"`
	Parts   []CompleteMultipartPart `xml:"Part"`
}

type CompleteMultipartPart struct {
	PartNumber int    `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
}

func (h *HTTPStorageClient) Complete(ctx context.Context, bucket, key, uploadID string, etags map[int]string) error {
	var parts []CompleteMultipartPart
	for pNum, etag := range etags {
		parts = append(parts, CompleteMultipartPart{
			PartNumber: pNum,
			ETag:       etag,
		})
	}

	xmlData, err := xml.Marshal(CompleteMultipartUpload{Parts: parts})
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s?uploadId=%s", h.buildURL(bucket, key), uploadID)
	headers := map[string]string{
		"Content-Type":   "application/xml",
		"Content-Length": strconv.Itoa(len(xmlData)),
	}

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		resp, err := h.doRequest(ctx, "POST", url, bytes.NewReader(xmlData), headers)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			lastErr = fmt.Errorf("failed to complete multipart upload: status code %d", resp.StatusCode)
		} else {
			lastErr = err
		}

		if !isRetryable(err, resp) {
			return lastErr
		}

		time.Sleep(time.Duration(1<<attempt-1) * time.Second)
	}
	return lastErr
}

func (h *HTTPStorageClient) Abort(ctx context.Context, bucket, key, uploadID string) error {
	url := fmt.Sprintf("%s?uploadId=%s", h.buildURL(bucket, key), uploadID)

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		resp, err := h.doRequest(ctx, "DELETE", url, nil, nil)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
				return nil
			}
			lastErr = fmt.Errorf("failed to abort multipart upload: status code %d", resp.StatusCode)
		} else {
			lastErr = err
		}

		if !isRetryable(err, resp) {
			return lastErr
		}

		time.Sleep(time.Duration(1<<attempt-1) * time.Second)
	}
	return lastErr
}

func (h *HTTPStorageClient) PutObject(ctx context.Context, bucket, key string, data []byte) error {
	url := h.buildURL(bucket, key)
	headers := map[string]string{
		"Content-Length": strconv.Itoa(len(data)),
	}

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		resp, err := h.doRequest(ctx, "PUT", url, bytes.NewReader(data), headers)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusNoContent {
				return nil
			}
			lastErr = fmt.Errorf("failed to put object: status code %d", resp.StatusCode)
		} else {
			lastErr = err
		}

		if !isRetryable(err, resp) {
			return lastErr
		}

		time.Sleep(time.Duration(1<<attempt-1) * time.Second)
	}
	return lastErr
}

func (h *HTTPStorageClient) DeleteObject(ctx context.Context, bucket, key string) error {
	url := h.buildURL(bucket, key)

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		resp, err := h.doRequest(ctx, "DELETE", url, nil, nil)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
				return nil
			}
			lastErr = fmt.Errorf("failed to delete object: status code %d", resp.StatusCode)
		} else {
			lastErr = err
		}

		if !isRetryable(err, resp) {
			return lastErr
		}

		time.Sleep(time.Duration(1<<attempt-1) * time.Second)
	}
	return lastErr
}

func (h *HTTPStorageClient) SetRegion(region string) {
	// Noop for generic HTTP client
}
