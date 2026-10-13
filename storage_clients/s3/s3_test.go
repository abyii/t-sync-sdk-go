package s3

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abyii/t-sync-sdk-go/v2/storage_clients"
	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

func respErr(status int, inner error) error {
	return &smithy.OperationError{
		ServiceID:     "S3",
		OperationName: "Op",
		Err: &awshttp.ResponseError{
			ResponseError: &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
				Err:      inner,
			},
			RequestID: "req-14045-404",
		},
	}
}

func TestClassifyError(t *testing.T) {
	cases := []struct {
		name                        string
		err                         error
		uploadOp                    bool
		notFound, uploadGone, retry bool
	}{
		{"head 404", respErr(404, &types.NotFound{}), false, true, false, false},
		{"get NoSuchKey", respErr(404, &types.NoSuchKey{}), false, true, false, false},
		{"list NoSuchBucket", respErr(404, &types.NoSuchBucket{}), false, true, false, false},
		{"generic NoSuchBucket code", respErr(404, &smithy.GenericAPIError{Code: "NoSuchBucket"}), false, true, false, false},
		{"abort NoSuchUpload", respErr(404, &types.NoSuchUpload{}), true, true, true, false},
		{"NoSuchUpload code", respErr(404, &smithy.GenericAPIError{Code: "NoSuchUpload"}), false, true, true, false},
		{"403 with 404 in request id", respErr(403, &smithy.GenericAPIError{Code: "AccessDenied"}), true, false, false, false},
		{"503 SlowDown", respErr(503, &smithy.GenericAPIError{Code: "SlowDown"}), false, false, false, true},
		{"500", respErr(500, &smithy.GenericAPIError{Code: "InternalError"}), false, false, false, true},
		{"400 RequestTimeout", respErr(400, &smithy.GenericAPIError{Code: "RequestTimeout"}), false, false, false, true},
		{"400 InvalidArgument", respErr(400, &smithy.GenericAPIError{Code: "InvalidArgument"}), false, false, false, false},
		{"network", errors.New("connection reset"), false, false, false, true},
		{"canceled", &smithy.OperationError{Err: context.Canceled}, false, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := classifyError("Op", tc.err, tc.uploadOp)
			if got := errors.Is(err, storage_clients.ErrNotFound); got != tc.notFound {
				t.Errorf("ErrNotFound = %v, want %v (%v)", got, tc.notFound, err)
			}
			if got := errors.Is(err, storage_clients.ErrUploadNotFound); got != tc.uploadGone {
				t.Errorf("ErrUploadNotFound = %v, want %v (%v)", got, tc.uploadGone, err)
			}
			if got := storage_clients.IsRetryable(err); got != tc.retry {
				t.Errorf("IsRetryable = %v, want %v (%v)", got, tc.retry, err)
			}
			if !errors.Is(err, tc.err) {
				t.Errorf("original error lost: %v", err)
			}
		})
	}
}

func TestNewS3ClientAuth(t *testing.T) {
	c, err := NewS3Client("S3_ACCESS_KEYS[ak:sk];region=eu-west-1")
	if err != nil {
		t.Fatal(err)
	}
	if c.cfg.Region != "eu-west-1" {
		t.Fatalf("region = %q", c.cfg.Region)
	}
	if n := c.getClient().Options().Retryer.MaxAttempts(); n != 1 {
		t.Fatalf("SDK retryer max attempts = %d, want 1", n)
	}
	if _, ok := c.cfg.HTTPClient.(*awshttp.BuildableClient); !ok {
		t.Fatalf("http client = %T", c.cfg.HTTPClient)
	}
	if c.cfg.HTTPClient.(*awshttp.BuildableClient).GetTimeout() != 0 {
		t.Fatal("overall timeout must be 0")
	}
	if rht := c.cfg.HTTPClient.(*awshttp.BuildableClient).GetTransport().ResponseHeaderTimeout; rht != storage_clients.ResponseHeaderTimeout {
		t.Fatalf("ResponseHeaderTimeout = %v", rht)
	}
	for _, bad := range []string{"BOGUS", "S3_ACCESS_KEYS[onlykey]", "S3_ACCESS_KEYS[a:b];foo=bar", "DEFAULT[]"} {
		if _, err := NewS3Client(bad); !errors.Is(err, storage_clients.ErrInvalidConfig) {
			t.Errorf("%q: want ErrInvalidConfig, got %v", bad, err)
		}
	}
}

const xmlErr = `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>m</Message><RequestId>r</RequestId></Error>`

func writeErr(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, strings.Replace(xmlErr, "%s", code, 1))
}

func newTestClient(t *testing.T, h http.HandlerFunc) *S3Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	cfg := aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("ak", "sk", ""),
		HTTPClient:  newHTTPClient(),
	}
	return &S3Client{
		client: newS3(cfg, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(srv.URL)
			o.UsePathStyle = true
		}),
		cfg:   cfg,
		retry: storage_clients.RetryPolicy{MaxAttempts: 4, BaseDelay: time.Millisecond},
	}
}

func TestS3AgainstFakeServer(t *testing.T) {
	var flakyHits, gets int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case r.URL.Path == "/b/missing" && r.Method == http.MethodHead:
			w.WriteHeader(http.StatusNotFound)
		case r.URL.Path == "/b/missing":
			writeErr(w, 404, "NoSuchKey")
		case r.URL.Path == "/nobucket":
			writeErr(w, 404, "NoSuchBucket")
		case q.Get("uploadId") == "gone":
			writeErr(w, 404, "NoSuchUpload")
		case q.Get("uploadId") == "forbidden":
			writeErr(w, 403, "AccessDenied")
		case r.URL.Path == "/b/flaky":
			atomic.AddInt32(&flakyHits, 1)
			_, _ = io.Copy(io.Discard, r.Body)
			writeErr(w, 503, "SlowDown")
		case r.URL.Path == "/b/empty":
			atomic.AddInt32(&gets, 1)
			if r.Header.Get("Range") != "" {
				writeErr(w, 416, "InvalidRange")
				return
			}
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	})
	ctx := context.Background()

	if _, err := c.GetObjectSize(ctx, "b", "missing"); !errors.Is(err, storage_clients.ErrNotFound) {
		t.Errorf("HEAD missing: %v", err)
	}
	if _, err := c.GetObjectRange(ctx, "b", "missing", 0, -1); !errors.Is(err, storage_clients.ErrNotFound) {
		t.Errorf("GET missing: %v", err)
	}
	if _, err := c.ListObjects(ctx, "nobucket", ""); !errors.Is(err, storage_clients.ErrNotFound) {
		t.Errorf("list missing bucket: %v", err)
	}
	if err := c.Abort(ctx, "b", "k", "gone"); err != nil {
		t.Errorf("abort unknown upload should succeed: %v", err)
	}
	if err := c.Abort(ctx, "b", "k", "forbidden"); err == nil {
		t.Error("403 abort must fail")
	}

	err := c.PutObject(ctx, "b", "flaky", []byte("data"))
	var se *storage_clients.StatusError
	if !errors.As(err, &se) || se.StatusCode != 503 {
		t.Errorf("want StatusError 503, got %v", err)
	}
	if flakyHits != 4 {
		t.Errorf("PUT attempts = %d, want 4 (SDK retries must not stack)", flakyHits)
	}

	rc, err := c.GetObjectRange(ctx, "b", "empty", 0, -1)
	if err != nil {
		t.Fatalf("zero-byte read: %v", err)
	}
	rc.Close()
}
