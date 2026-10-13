package http

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/abyii/t-sync-sdk-go/v2/storage_clients"
)

func init() {
	storage_clients.RegisterClient("http", func(authType, namespace string) (storage_clients.ObjectStorageClient, error) {
		// namespace is the base endpoint URL. authType may carry custom headers:
		// HEADER[Key1: Val1, Key2: Val2]. Other auth strings are ignored.
		headers, err := parseHeaderAuth(authType)
		if err != nil {
			return nil, err
		}
		return NewHTTPStorageClient(namespace, headers), nil
	})
}

// parseHeaderAuth parses "HEADER[Key1: Val1, Key2: Val2]". A comma starts a new
// header only if the following text up to ':' is a valid header name, so values
// may contain commas (e.g. "Accept: a, b" or HTTP dates). Keys and values are
// trimmed. Auth strings without the HEADER[...] form yield no headers.
func parseHeaderAuth(authType string) (map[string]string, error) {
	headers := make(map[string]string)
	authType = strings.TrimSpace(authType)
	if !strings.HasPrefix(authType, "HEADER[") || !strings.HasSuffix(authType, "]") {
		return headers, nil
	}
	content := authType[len("HEADER[") : len(authType)-1]
	var lastKey string
	for _, seg := range strings.Split(content, ",") {
		if k, v, ok := strings.Cut(seg, ":"); ok && isToken(strings.TrimSpace(k)) {
			lastKey = http.CanonicalHeaderKey(strings.TrimSpace(k))
			headers[lastKey] = strings.TrimSpace(v)
			continue
		}
		if lastKey == "" {
			if strings.TrimSpace(seg) == "" {
				continue
			}
			return nil, fmt.Errorf("%w: malformed header entry %q (want Key: Value)", storage_clients.ErrInvalidConfig, strings.TrimSpace(seg))
		}
		headers[lastKey] += "," + seg
		headers[lastKey] = strings.TrimSpace(headers[lastKey])
	}
	return headers, nil
}

// isToken reports whether s is a valid HTTP header field name (RFC 7230 token).
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// HTTPStorageClient implements ObjectStorageClient using raw HTTP/S3-compatible REST requests.
type HTTPStorageClient struct {
	endpoint string            // Base URL (e.g. "https://cdn.example.com" or "http://localhost:9000")
	headers  map[string]string // Custom headers applied to every request
	client   *http.Client
	retry    storage_clients.RetryPolicy
}

// NewHTTPStorageClient creates a new HTTP storage client. The underlying
// transport has dial/TLS/response-header timeouts but no overall timeout;
// uploads use per-attempt deadlines scaled to the payload size.
func NewHTTPStorageClient(endpoint string, headers map[string]string) *HTTPStorageClient {
	return &HTTPStorageClient{
		endpoint: endpoint,
		headers:  headers,
		client:   storage_clients.NewHTTPClient(),
		retry:    storage_clients.DefaultRetryPolicy,
	}
}

func appendEscapedPath(b *strings.Builder, p string) {
	for _, seg := range strings.Split(strings.Trim(p, "/"), "/") {
		b.WriteByte('/')
		b.WriteString(url.PathEscape(seg))
	}
}

// buildURL joins endpoint, bucket and key, escaping each path segment, and
// appends the encoded query (if any).
func (h *HTTPStorageClient) buildURL(bucket, key string, query string) string {
	var b strings.Builder
	b.WriteString(strings.TrimSuffix(h.endpoint, "/"))
	if strings.Trim(bucket, "/") != "" {
		appendEscapedPath(&b, bucket)
	}
	if strings.Trim(key, "/") != "" {
		appendEscapedPath(&b, key)
	}
	if query != "" {
		b.WriteByte('?')
		b.WriteString(query)
	}
	return b.String()
}

func (h *HTTPStorageClient) doRequest(ctx context.Context, method, url string, body []byte, headers map[string]string) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", storage_clients.ErrInvalidConfig, err)
	}
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return h.client.Do(req)
}

// statusError builds the error for an unexpected status. For multipart-upload
// operations a 404 additionally matches ErrUploadNotFound.
func statusError(op string, resp *http.Response, uploadOp bool) error {
	se := &storage_clients.StatusError{Op: op, StatusCode: resp.StatusCode}
	if uploadOp && resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w: %w", storage_clients.ErrUploadNotFound, se)
	}
	return se
}

// closeBody drains (bounded) and closes a response body so the connection can be reused.
func closeBody(resp *http.Response) {
	_, _ = io.CopyN(io.Discard, resp.Body, 64<<10)
	_ = resp.Body.Close()
}

func (h *HTTPStorageClient) ListBuckets(ctx context.Context, compartmentID string) ([]string, error) {
	// Not applicable for generic HTTP/CDN endpoints
	return nil, nil
}

// ListBucketResult is an S3 ListObjects (V1 or V2) response.
type ListBucketResult struct {
	XMLName  xml.Name `xml:"ListBucketResult"`
	Contents []struct {
		Key  string `xml:"Key"`
		Size int64  `xml:"Size"`
	} `xml:"Contents"`
	IsTruncated           bool   `xml:"IsTruncated"`
	NextContinuationToken string `xml:"NextContinuationToken"`
	NextMarker            string `xml:"NextMarker"`
}

// ListObjects lists objects via the S3 ListObjectsV2 API (list-type=2), following
// continuation tokens; servers answering in V1 form are paged with marker
// (NextMarker or the last key). A 200 response that is not a ListBucketResult
// returns ErrInvalidResponse; a missing bucket (404) matches ErrNotFound.
func (h *HTTPStorageClient) ListObjects(ctx context.Context, bucket, prefix string) ([]storage_clients.ObjectInfo, error) {
	var objects []storage_clients.ObjectInfo
	var token, marker string

	for {
		q := url.Values{}
		q.Set("list-type", "2")
		if prefix != "" {
			q.Set("prefix", prefix)
		}
		if token != "" {
			q.Set("continuation-token", token)
		}
		if marker != "" {
			q.Set("marker", marker)
		}
		u := h.buildURL(bucket, "", q.Encode())

		var page ListBucketResult
		err := h.retry.Do(ctx, "http list objects", storage_clients.MetadataAttemptTimeout, func(ctx context.Context) error {
			resp, err := h.doRequest(ctx, http.MethodGet, u, nil, nil)
			if err != nil {
				return err
			}
			defer closeBody(resp)
			if resp.StatusCode != http.StatusOK {
				return statusError("ListObjects", resp, false)
			}
			data, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			page = ListBucketResult{}
			if err := xml.Unmarshal(data, &page); err != nil {
				return storage_clients.Permanent(fmt.Errorf("%w: listing is not an S3 ListBucketResult: %w", storage_clients.ErrInvalidResponse, err))
			}
			return nil
		})
		if err != nil {
			return nil, err
		}

		for _, c := range page.Contents {
			objects = append(objects, storage_clients.ObjectInfo{Name: c.Key, Size: c.Size})
		}
		if !page.IsTruncated {
			return objects, nil
		}
		switch {
		case page.NextContinuationToken != "":
			if page.NextContinuationToken == token {
				return nil, fmt.Errorf("%w: listing continuation token did not advance", storage_clients.ErrInvalidResponse)
			}
			token, marker = page.NextContinuationToken, ""
		default:
			next := page.NextMarker
			if next == "" && len(page.Contents) > 0 {
				next = page.Contents[len(page.Contents)-1].Key
			}
			if next == "" || next == marker {
				return nil, fmt.Errorf("%w: truncated listing without a usable marker", storage_clients.ErrInvalidResponse)
			}
			token, marker = "", next
		}
	}
}

func (h *HTTPStorageClient) GetObjectSize(ctx context.Context, bucket, key string) (int64, error) {
	u := h.buildURL(bucket, key, "")
	var size int64
	err := h.retry.Do(ctx, "http head object", storage_clients.MetadataAttemptTimeout, func(ctx context.Context) error {
		resp, err := h.doRequest(ctx, http.MethodHead, u, nil, nil)
		if err != nil {
			return err
		}
		closeBody(resp)
		if resp.StatusCode != http.StatusOK {
			return statusError("HeadObject", resp, false)
		}
		cl := strings.TrimSpace(resp.Header.Get("Content-Length"))
		if cl == "" {
			return storage_clients.Permanent(fmt.Errorf("%w: missing Content-Length header", storage_clients.ErrInvalidResponse))
		}
		n, err := strconv.ParseInt(cl, 10, 64)
		if err != nil || n < 0 {
			return storage_clients.Permanent(fmt.Errorf("%w: invalid Content-Length %q", storage_clients.ErrInvalidResponse, cl))
		}
		size = n
		return nil
	})
	if err != nil {
		return 0, err
	}
	return size, nil
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

// GetObjectRange fetches [startByte, endByte] (endByte -1 = to the end). The
// whole object is requested without a Range header so zero-byte objects work.
// Servers ignoring Range (200) are handled by skipping/limiting the body.
func (h *HTTPStorageClient) GetObjectRange(ctx context.Context, bucket, key string, startByte, endByte int64) (io.ReadCloser, error) {
	if startByte < 0 {
		return nil, fmt.Errorf("%w: start byte %d must be non-negative", storage_clients.ErrInvalidRange, startByte)
	}
	if endByte != -1 && endByte < startByte {
		return nil, fmt.Errorf("%w: end byte %d before start byte %d", storage_clients.ErrInvalidRange, endByte, startByte)
	}
	var headers map[string]string
	switch {
	case endByte != -1:
		headers = map[string]string{"Range": fmt.Sprintf("bytes=%d-%d", startByte, endByte)}
	case startByte > 0:
		headers = map[string]string{"Range": fmt.Sprintf("bytes=%d-", startByte)}
	}

	u := h.buildURL(bucket, key, "")
	var body io.ReadCloser
	// No per-attempt timeout: the body outlives the attempt. Header stalls are
	// bounded by the transport's ResponseHeaderTimeout.
	err := h.retry.Do(ctx, "http get object", 0, func(ctx context.Context) error {
		resp, err := h.doRequest(ctx, http.MethodGet, u, nil, headers)
		if err != nil {
			return err
		}
		switch {
		case resp.StatusCode == http.StatusPartialContent && headers != nil:
			body = resp.Body
			return nil
		case resp.StatusCode == http.StatusOK:
			if startByte > 0 {
				if _, err := io.CopyN(io.Discard, resp.Body, startByte); err != nil {
					_ = resp.Body.Close()
					return fmt.Errorf("failed to skip to range start: %w", err)
				}
			}
			if endByte == -1 {
				body = resp.Body
			} else {
				body = &limitReadCloser{r: io.LimitReader(resp.Body, endByte-startByte+1), c: resp.Body}
			}
			return nil
		default:
			closeBody(resp)
			return statusError("GetObject", resp, false)
		}
	})
	if err != nil {
		return nil, err
	}
	return body, nil
}

type InitiateMultipartUploadResult struct {
	XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
	UploadID string   `xml:"UploadId"`
}

func (h *HTTPStorageClient) Initiate(ctx context.Context, bucket, key string) (string, error) {
	u := h.buildURL(bucket, key, "uploads")
	var uploadID string
	err := h.retry.Do(ctx, "http initiate upload", storage_clients.MetadataAttemptTimeout, func(ctx context.Context) error {
		resp, err := h.doRequest(ctx, http.MethodPost, u, nil, nil)
		if err != nil {
			return err
		}
		defer closeBody(resp)
		if resp.StatusCode != http.StatusOK {
			return statusError("CreateMultipartUpload", resp, false)
		}
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		var result InitiateMultipartUploadResult
		if err := xml.Unmarshal(data, &result); err != nil {
			return storage_clients.Permanent(fmt.Errorf("%w: failed to parse initiate response: %w", storage_clients.ErrInvalidResponse, err))
		}
		if result.UploadID == "" {
			return storage_clients.Permanent(fmt.Errorf("%w: no upload ID returned", storage_clients.ErrInvalidResponse))
		}
		uploadID = result.UploadID
		return nil
	})
	if err != nil {
		return "", err
	}
	return uploadID, nil
}

func (h *HTTPStorageClient) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, data []byte) (string, error) {
	q := url.Values{}
	q.Set("partNumber", strconv.Itoa(partNumber))
	q.Set("uploadId", uploadID)
	u := h.buildURL(bucket, key, q.Encode())

	var etag string
	err := h.retry.Do(ctx, "http upload part", storage_clients.UploadAttemptTimeout(len(data)), func(ctx context.Context) error {
		resp, err := h.doRequest(ctx, http.MethodPut, u, data, nil)
		if err != nil {
			return err
		}
		defer closeBody(resp)
		if resp.StatusCode != http.StatusOK {
			return statusError("UploadPart", resp, true)
		}
		etag = strings.TrimSpace(resp.Header.Get("ETag"))
		if etag == "" {
			return fmt.Errorf("%w: missing ETag in upload part response", storage_clients.ErrInvalidResponse)
		}
		return nil
	})
	return etag, err
}

type CompleteMultipartUpload struct {
	XMLName xml.Name                `xml:"CompleteMultipartUpload"`
	Parts   []CompleteMultipartPart `xml:"Part"`
}

type CompleteMultipartPart struct {
	PartNumber int    `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
}

// s3Error is the S3 <Error> body; CompleteMultipartUpload may return it with 200 OK.
type s3Error struct {
	XMLName xml.Name `xml:"Error"`
	Code    string   `xml:"Code"`
	Message string   `xml:"Message"`
}

// Complete commits the upload with parts in ascending part-number order (S3
// rejects unsorted lists with InvalidPartOrder). An <Error> document in a 200
// response is reported as an error.
func (h *HTTPStorageClient) Complete(ctx context.Context, bucket, key, uploadID string, etags map[int]string) error {
	partNums := make([]int, 0, len(etags))
	for n := range etags {
		partNums = append(partNums, n)
	}
	slices.Sort(partNums)
	parts := make([]CompleteMultipartPart, 0, len(partNums))
	for _, n := range partNums {
		parts = append(parts, CompleteMultipartPart{PartNumber: n, ETag: etags[n]})
	}

	xmlData, err := xml.Marshal(CompleteMultipartUpload{Parts: parts})
	if err != nil {
		return fmt.Errorf("http complete upload: %w", err)
	}

	q := url.Values{}
	q.Set("uploadId", uploadID)
	u := h.buildURL(bucket, key, q.Encode())
	headers := map[string]string{"Content-Type": "application/xml"}

	return h.retry.Do(ctx, "http complete upload", storage_clients.CompleteAttemptTimeout, func(ctx context.Context) error {
		resp, err := h.doRequest(ctx, http.MethodPost, u, xmlData, headers)
		if err != nil {
			return err
		}
		defer closeBody(resp)
		if resp.StatusCode != http.StatusOK {
			return statusError("CompleteMultipartUpload", resp, true)
		}
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		var e s3Error
		if xml.Unmarshal(data, &e) == nil {
			err := fmt.Errorf("CompleteMultipartUpload: error %s: %s", e.Code, e.Message)
			if e.Code == "NoSuchUpload" {
				if _, headErr := h.GetObjectSize(ctx, bucket, key); headErr == nil {
					return nil
				}
				return fmt.Errorf("%w: %w", storage_clients.ErrUploadNotFound, err)
			}
			return err
		}
		return nil
	})
}

// Abort aborts a multipart upload; an unknown upload (404) is treated as success.
func (h *HTTPStorageClient) Abort(ctx context.Context, bucket, key, uploadID string) error {
	q := url.Values{}
	q.Set("uploadId", uploadID)
	u := h.buildURL(bucket, key, q.Encode())

	err := h.retry.Do(ctx, "http abort upload", storage_clients.MetadataAttemptTimeout, func(ctx context.Context) error {
		resp, err := h.doRequest(ctx, http.MethodDelete, u, nil, nil)
		if err != nil {
			return err
		}
		closeBody(resp)
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
			return nil
		}
		return statusError("AbortMultipartUpload", resp, true)
	})
	if errors.Is(err, storage_clients.ErrUploadNotFound) {
		return nil
	}
	return err
}

func (h *HTTPStorageClient) PutObject(ctx context.Context, bucket, key string, data []byte) error {
	u := h.buildURL(bucket, key, "")
	return h.retry.Do(ctx, "http put object", storage_clients.UploadAttemptTimeout(len(data)), func(ctx context.Context) error {
		resp, err := h.doRequest(ctx, http.MethodPut, u, data, nil)
		if err != nil {
			return err
		}
		closeBody(resp)
		switch resp.StatusCode {
		case http.StatusOK, http.StatusCreated, http.StatusNoContent:
			return nil
		}
		return statusError("PutObject", resp, false)
	})
}

// DeleteObject deletes an object; a missing object (404) yields an error
// matching storage_clients.ErrNotFound.
func (h *HTTPStorageClient) DeleteObject(ctx context.Context, bucket, key string) error {
	u := h.buildURL(bucket, key, "")
	return h.retry.Do(ctx, "http delete object", storage_clients.MetadataAttemptTimeout, func(ctx context.Context) error {
		resp, err := h.doRequest(ctx, http.MethodDelete, u, nil, nil)
		if err != nil {
			return err
		}
		closeBody(resp)
		switch resp.StatusCode {
		case http.StatusOK, http.StatusNoContent, http.StatusAccepted:
			return nil
		}
		return statusError("DeleteObject", resp, false)
	})
}

func (h *HTTPStorageClient) SetRegion(region string) {
	// Noop for generic HTTP client
}
