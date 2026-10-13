package oci

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/abyii/t-sync-sdk-go/v2/storage_clients"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// fakeServiceError implements common.ServiceError like the SDK's servicefailure.
type fakeServiceError struct {
	status int
	code   string
}

func (e fakeServiceError) Error() string {
	return fmt.Sprintf("Error returned by Object Storage Service. Http Status Code: %d. Error Code: %s. Opc request id: req-14045-404", e.status, e.code)
}
func (e fakeServiceError) GetHTTPStatusCode() int  { return e.status }
func (e fakeServiceError) GetMessage() string      { return "msg" }
func (e fakeServiceError) GetCode() string         { return e.code }
func (e fakeServiceError) GetOpcRequestID() string { return "req-14045-404" }

var _ common.ServiceError = fakeServiceError{}

func TestClassifyError(t *testing.T) {
	notFound := classifyError("HeadObject", fakeServiceError{404, "ObjectNotFound"}, false)
	if !errors.Is(notFound, storage_clients.ErrNotFound) || storage_clients.IsRetryable(notFound) {
		t.Fatalf("404: %v", notFound)
	}
	if errors.Is(notFound, storage_clients.ErrUploadNotFound) {
		t.Fatal("non-upload 404 must not be ErrUploadNotFound")
	}
	bucket := classifyError("ListObjects", fakeServiceError{404, "BucketNotFound"}, false)
	if !errors.Is(bucket, storage_clients.ErrNotFound) {
		t.Fatalf("bucket 404: %v", bucket)
	}
	upload := classifyError("AbortMultipartUpload", fakeServiceError{404, "NoSuchUpload"}, true)
	if !errors.Is(upload, storage_clients.ErrUploadNotFound) {
		t.Fatalf("upload 404: %v", upload)
	}
	// A 403 whose message happens to contain "404" must not look like not-found.
	forbidden := classifyError("AbortMultipartUpload", fakeServiceError{403, "NotAuthorized"}, true)
	if errors.Is(forbidden, storage_clients.ErrUploadNotFound) || errors.Is(forbidden, storage_clients.ErrNotFound) ||
		storage_clients.IsRetryable(forbidden) {
		t.Fatalf("403: %v", forbidden)
	}
	for _, s := range []int{429, 500, 503} {
		if err := classifyError("PutObject", fakeServiceError{s, "x"}, false); !storage_clients.IsRetryable(err) {
			t.Errorf("%d should be retryable: %v", s, err)
		}
	}
	var se *storage_clients.StatusError
	if err := classifyError("PutObject", fakeServiceError{503, "x"}, false); !errors.As(err, &se) || se.StatusCode != 503 {
		t.Fatalf("StatusError not exposed: %v", err)
	}
	netErr := errors.New("dial tcp: i/o timeout")
	if err := classifyError("PutObject", netErr, false); !errors.Is(err, netErr) || !storage_clients.IsRetryable(err) {
		t.Fatalf("network: %v", err)
	}
	if err := classifyError("PutObject", context.Canceled, false); storage_clients.IsRetryable(err) {
		t.Fatalf("canceled must not be retryable: %v", err)
	}
	if classifyError("x", nil, false) != nil {
		t.Fatal("nil must stay nil")
	}
}

func TestAuthParsing(t *testing.T) {
	for _, bad := range []string{"INSTANCE_PRINCIPLE", "OCI_CONFIG_FILEX", "bogus;region=x"} {
		if _, err := NewOCIClient("ns", bad); !errors.Is(err, storage_clients.ErrInvalidConfig) {
			t.Errorf("%q: want ErrInvalidConfig, got %v", bad, err)
		}
	}
	if _, err := NewOCIClient("ns", "OCI_CONFIG_FILE[DEFAULT];foo=bar"); !errors.Is(err, storage_clients.ErrInvalidConfig) {
		t.Errorf("unknown option: %v", err)
	}
	if _, err := NewOCIClient("", "DEFAULT"); !errors.Is(err, storage_clients.ErrInvalidConfig) {
		t.Errorf("empty namespace: %v", err)
	}
	for _, ok := range []string{"", "DEFAULT", "OCI_CONFIG_FILE", "OCI_CONFIG_FILE[PROD]"} {
		if _, err := newConfigProvider(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
}

func rawProvider(t *testing.T) common.ConfigurationProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return common.NewRawConfigurationProvider("ocid1.tenancy.oc1..x", "ocid1.user.oc1..x", "ap-mumbai-1", "aa:bb", string(pemKey), nil)
}

func TestConfigureClient(t *testing.T) {
	t.Setenv(common.CustomClientTimeoutEnvVar, "")
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(rawProvider(t))
	if err != nil {
		t.Fatal(err)
	}
	orig, ok := client.HTTPClient.(*http.Client)
	if !ok {
		t.Fatalf("unexpected dispatcher %T", client.HTTPClient)
	}
	if _, ok := orig.Transport.(*common.OciHTTPTransportWrapper); !ok {
		t.Fatalf("unexpected transport %T", orig.Transport)
	}
	configureClient(&client)

	hc := client.HTTPClient.(*http.Client)
	if hc.Timeout != 0 {
		t.Fatalf("overall timeout = %v, want 0", hc.Timeout)
	}
	w, ok := hc.Transport.(*common.OciHTTPTransportWrapper)
	if !ok {
		t.Fatalf("SDK transport wrapper (CA bundle support) lost: %T", hc.Transport)
	}
	rt, err := w.TransportTemplate.NewOrDefault(nil)
	if err != nil {
		t.Fatal(err)
	}
	if tr := rt.(*http.Transport); tr.ResponseHeaderTimeout != storage_clients.ResponseHeaderTimeout || tr.Proxy == nil {
		t.Fatalf("transport not tuned: rht=%v", tr.ResponseHeaderTimeout)
	}
	if p := client.RetryPolicy(); p == nil || p.MaximumNumberAttempts != 1 {
		t.Fatalf("SDK retries not disabled: %+v", p)
	}
}

func TestRangeHeader(t *testing.T) {
	for _, tc := range []struct {
		s, e int64
		want string
	}{{0, -1, ""}, {5, -1, "bytes=5-"}, {0, 9, "bytes=0-9"}, {3, 3, "bytes=3-3"}} {
		got, err := rangeHeader(tc.s, tc.e)
		if err != nil || got != tc.want {
			t.Errorf("rangeHeader(%d,%d) = %q, %v; want %q", tc.s, tc.e, got, err, tc.want)
		}
	}
	if _, err := rangeHeader(-1, 3); !errors.Is(err, storage_clients.ErrInvalidRange) {
		t.Errorf("negative start: %v", err)
	}
	if _, err := rangeHeader(5, 3); !errors.Is(err, storage_clients.ErrInvalidRange) {
		t.Errorf("end<start: %v", err)
	}
}
