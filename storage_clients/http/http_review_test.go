package http

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abyii/t-sync-sdk-go/v2/storage_clients"
)

func newFastClient(endpoint string) *HTTPStorageClient {
	c := NewHTTPStorageClient(endpoint, map[string]string{})
	c.retry = storage_clients.RetryPolicy{MaxAttempts: 4, BaseDelay: time.Millisecond}
	return c
}

func statusServer(status int, hits *int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		w.WriteHeader(status)
	}))
}

func TestHTTPRetryClassification(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		status int
		want   int32
	}{
		{http.StatusNotFound, 1},
		{http.StatusForbidden, 1},
		{http.StatusBadRequest, 1},
		{http.StatusServiceUnavailable, 4},
		{http.StatusTooManyRequests, 4},
		{http.StatusInternalServerError, 4},
	} {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			var hits int32
			srv := statusServer(tc.status, &hits)
			defer srv.Close()
			err := newFastClient(srv.URL).PutObject(ctx, "b", "k", []byte("x"))
			var se *storage_clients.StatusError
			if !errors.As(err, &se) || se.StatusCode != tc.status {
				t.Fatalf("want StatusError %d, got %v", tc.status, err)
			}
			if hits != tc.want {
				t.Fatalf("requests = %d, want %d", hits, tc.want)
			}
		})
	}

	t.Run("network error retried", func(t *testing.T) {
		var hits int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&hits, 1)
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close() // drop the connection without a response
			}
		}))
		defer srv.Close()
		_, err := newFastClient(srv.URL).GetObjectSize(ctx, "b", "k")
		if err == nil || hits != 4 {
			t.Fatalf("hits=%d err=%v", hits, err)
		}
	})

	t.Run("recovers after 503", func(t *testing.T) {
		var hits int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if atomic.AddInt32(&hits, 1) < 3 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		if err := newFastClient(srv.URL).PutObject(ctx, "b", "k", []byte("x")); err != nil || hits != 3 {
			t.Fatalf("hits=%d err=%v", hits, err)
		}
	})

	t.Run("context cancel not retried", func(t *testing.T) {
		var hits int32
		srv := statusServer(http.StatusServiceUnavailable, &hits)
		defer srv.Close()
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		err := newFastClient(srv.URL).PutObject(cctx, "b", "k", []byte("x"))
		if !errors.Is(err, context.Canceled) || hits != 0 {
			t.Fatalf("hits=%d err=%v", hits, err)
		}
	})

	t.Run("cancel aborts backoff promptly", func(t *testing.T) {
		var hits int32
		srv := statusServer(http.StatusServiceUnavailable, &hits)
		defer srv.Close()
		c := NewHTTPStorageClient(srv.URL, nil)
		c.retry = storage_clients.RetryPolicy{MaxAttempts: 4, BaseDelay: 10 * time.Second}
		cctx, cancel := context.WithCancel(ctx)
		time.AfterFunc(100*time.Millisecond, cancel)
		start := time.Now()
		err := c.DeleteObject(cctx, "b", "k")
		if el := time.Since(start); el > 3*time.Second {
			t.Fatalf("took %v", el)
		}
		if !errors.Is(err, context.Canceled) || hits != 1 {
			t.Fatalf("hits=%d err=%v", hits, err)
		}
	})
}

func TestHTTPErrNotFoundFromEachOp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := newFastClient(srv.URL)
	ctx := context.Background()

	_, err := c.GetObjectSize(ctx, "b", "k")
	if !errors.Is(err, storage_clients.ErrNotFound) {
		t.Errorf("GetObjectSize: %v", err)
	}
	_, err = c.GetObjectRange(ctx, "b", "k", 0, -1)
	if !errors.Is(err, storage_clients.ErrNotFound) {
		t.Errorf("GetObjectRange: %v", err)
	}
	_, err = c.GetObjectRange(ctx, "b", "k", 5, 9)
	if !errors.Is(err, storage_clients.ErrNotFound) {
		t.Errorf("GetObjectRange ranged: %v", err)
	}
	if err = c.DeleteObject(ctx, "b", "k"); !errors.Is(err, storage_clients.ErrNotFound) {
		t.Errorf("DeleteObject: %v", err)
	}
	if _, err = c.ListObjects(ctx, "missing-bucket", ""); !errors.Is(err, storage_clients.ErrNotFound) {
		t.Errorf("ListObjects: %v", err)
	}
	if err = c.PutObject(ctx, "missing-bucket", "k", nil); !errors.Is(err, storage_clients.ErrNotFound) {
		t.Errorf("PutObject: %v", err)
	}
	if _, err = c.Initiate(ctx, "missing-bucket", "k"); !errors.Is(err, storage_clients.ErrNotFound) {
		t.Errorf("Initiate: %v", err)
	}
	_, err = c.UploadPart(ctx, "b", "k", "u", 1, []byte("x"))
	if !errors.Is(err, storage_clients.ErrUploadNotFound) || !errors.Is(err, storage_clients.ErrNotFound) {
		t.Errorf("UploadPart: %v", err)
	}
	err = c.Complete(ctx, "b", "k", "u", map[int]string{1: "e"})
	if !errors.Is(err, storage_clients.ErrUploadNotFound) {
		t.Errorf("Complete: %v", err)
	}
	if err = c.Abort(ctx, "b", "k", "u"); err != nil {
		t.Errorf("Abort of unknown upload should succeed, got %v", err)
	}
}

func TestHTTPAbortRealFailureNotSwallowed(t *testing.T) {
	var hits int32
	srv := statusServer(http.StatusForbidden, &hits)
	defer srv.Close()
	err := newFastClient(srv.URL).Abort(context.Background(), "b", "k14045", "u404")
	if err == nil {
		t.Fatal("403 abort must fail")
	}
}

func TestHTTPCompleteSortsParts(t *testing.T) {
	var got []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body CompleteMultipartUpload
		data, _ := io.ReadAll(r.Body)
		if err := xml.Unmarshal(data, &body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for _, p := range body.Parts {
			got = append(got, p.PartNumber)
		}
		if !sort.IntsAreSorted(got) {
			w.WriteHeader(http.StatusBadRequest) // S3 InvalidPartOrder
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	etags := map[int]string{}
	for i := 1; i <= 50; i++ {
		etags[i] = fmt.Sprintf(`"e%d"`, i)
	}
	if err := newFastClient(srv.URL).Complete(context.Background(), "b", "k", "u", etags); err != nil {
		t.Fatalf("Complete: %v (order %v)", err, got)
	}
	if len(got) != 50 {
		t.Fatalf("parts = %d", len(got))
	}
}

func TestHTTPCompleteErrorIn200Body(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<?xml version="1.0"?><Error><Code>InternalError</Code><Message>retry</Message></Error>`))
	}))
	defer srv.Close()
	err := newFastClient(srv.URL).Complete(context.Background(), "b", "k", "u", map[int]string{1: "e"})
	if err == nil || hits != 4 {
		t.Fatalf("hits=%d err=%v", hits, err)
	}
}

// listServer serves keys k00000..k(n-1) 1000 per page, either S3 V2-style
// (continuation tokens) or V1-style (marker, no NextMarker).
func listServer(t *testing.T, n int, v1 bool, requests *int32) *httptest.Server {
	keys := make([]string, n)
	for i := range keys {
		keys[i] = fmt.Sprintf("k%05d", i)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(requests, 1)
		q := r.URL.Query()
		start := 0
		if v1 {
			if m := q.Get("marker"); m != "" {
				start = sort.SearchStrings(keys, m) + 1
			}
		} else {
			if q.Get("list-type") != "2" {
				t.Errorf("list-type=2 not sent")
			}
			if tok := q.Get("continuation-token"); tok != "" {
				start, _ = strconv.Atoi(strings.TrimPrefix(tok, "tok-"))
			}
		}
		end := min(start+1000, n)
		var b strings.Builder
		b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult>`)
		for _, k := range keys[start:end] {
			fmt.Fprintf(&b, "<Contents><Key>%s</Key><Size>1</Size></Contents>", k)
		}
		if end < n {
			b.WriteString("<IsTruncated>true</IsTruncated>")
			if !v1 {
				fmt.Fprintf(&b, "<NextContinuationToken>tok-%d</NextContinuationToken>", end)
			}
		} else {
			b.WriteString("<IsTruncated>false</IsTruncated>")
		}
		b.WriteString("</ListBucketResult>")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(b.String()))
	}))
}

func TestHTTPListObjectsPagination(t *testing.T) {
	for _, v1 := range []bool{false, true} {
		t.Run(fmt.Sprintf("v1=%v", v1), func(t *testing.T) {
			var reqs int32
			srv := listServer(t, 2500, v1, &reqs)
			defer srv.Close()
			objs, err := newFastClient(srv.URL).ListObjects(context.Background(), "b", "")
			if err != nil {
				t.Fatal(err)
			}
			if len(objs) != 2500 || reqs != 3 {
				t.Fatalf("got %d objects in %d requests, want 2500 in 3", len(objs), reqs)
			}
			seen := map[string]bool{}
			for _, o := range objs {
				if seen[o.Name] {
					t.Fatalf("duplicate %s", o.Name)
				}
				seen[o.Name] = true
			}
		})
	}
}

func TestHTTPListObjectsNonXML(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>Index of /</body></html>"))
	}))
	defer srv.Close()
	objs, err := newFastClient(srv.URL).ListObjects(context.Background(), "b", "p/")
	if !errors.Is(err, storage_clients.ErrInvalidResponse) || objs != nil {
		t.Fatalf("want ErrInvalidResponse, got objs=%v err=%v", objs, err)
	}
	if hits != 1 {
		t.Fatalf("deterministic parse failure retried: %d requests", hits)
	}
}

func TestHTTPEscaping(t *testing.T) {
	const key = "dir/a#b?c%d&e +f=g;h"
	const prefix = "p&x +y#z?%"
	const uploadID = "id+/=&?#%"

	var mu sync.Mutex
	store := map[string][]byte{}
	var seenPrefix, seenUpload string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		q := r.URL.Query()
		switch {
		case r.Method == http.MethodGet && q.Get("list-type") == "2":
			seenPrefix = q.Get("prefix")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<ListBucketResult></ListBucketResult>"))
		case q.Has("uploadId"):
			seenUpload = q.Get("uploadId")
			w.Header().Set("ETag", `"e"`)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPut:
			data, _ := io.ReadAll(r.Body)
			store[r.URL.Path] = data
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet:
			data, ok := store[r.URL.Path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(data)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()
	c := newFastClient(srv.URL)
	ctx := context.Background()

	if err := c.PutObject(ctx, "bucket", key, []byte("payload")); err != nil {
		t.Fatal(err)
	}
	if _, ok := store["/bucket/"+key]; !ok {
		t.Fatalf("server saw paths %v, want %q", keysOf(store), "/bucket/"+key)
	}
	rc, err := c.GetObjectRange(ctx, "bucket", key, 0, -1)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(rc)
	rc.Close()
	if string(data) != "payload" {
		t.Fatalf("got %q", data)
	}

	if _, err := c.ListObjects(ctx, "bucket", prefix); err != nil {
		t.Fatal(err)
	}
	if seenPrefix != prefix {
		t.Fatalf("prefix = %q, want %q", seenPrefix, prefix)
	}
	if _, err := c.UploadPart(ctx, "bucket", key, uploadID, 1, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if seenUpload != uploadID {
		t.Fatalf("uploadId = %q, want %q", seenUpload, uploadID)
	}

	if u := c.buildURL("b", key, ""); !strings.HasSuffix(u, "/b/dir/a%23b%3Fc%25d&e%20+f=g%3Bh") {
		t.Fatalf("buildURL = %s", u)
	}
	if _, err := url.Parse(c.buildURL("b", "100%zz", "")); err != nil {
		t.Fatalf("unescaped %%: %v", err)
	}
}

func keysOf(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestHTTPZeroByteReadOmitsRange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "" {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable) // S3/OCI on empty objects
			return
		}
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	rc, err := newFastClient(srv.URL).GetObjectRange(context.Background(), "b", "empty", 0, -1)
	if err != nil {
		t.Fatalf("zero-byte read: %v", err)
	}
	data, _ := io.ReadAll(rc)
	rc.Close()
	if len(data) != 0 {
		t.Fatalf("got %d bytes", len(data))
	}
}

func TestHTTPInvalidRange(t *testing.T) {
	c := newFastClient("http://127.0.0.1:1")
	if _, err := c.GetObjectRange(context.Background(), "b", "k", -1, 5); !errors.Is(err, storage_clients.ErrInvalidRange) {
		t.Fatalf("got %v", err)
	}
	if _, err := c.GetObjectRange(context.Background(), "b", "k", 5, 4); !errors.Is(err, storage_clients.ErrInvalidRange) {
		t.Fatalf("got %v", err)
	}
}

func TestParseHeaderAuth(t *testing.T) {
	h, err := parseHeaderAuth("HEADER[ x-api-key : v1, Accept: a, b, If-Modified-Since: Mon, 01 Jan 2024 10:00:00 GMT]")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"X-Api-Key":         "v1",
		"Accept":            "a, b",
		"If-Modified-Since": "Mon, 01 Jan 2024 10:00:00 GMT",
	}
	if len(h) != len(want) {
		t.Fatalf("got %v", h)
	}
	for k, v := range want {
		if h[k] != v {
			t.Errorf("%s = %q, want %q", k, h[k], v)
		}
	}
	if h, err := parseHeaderAuth("OCI_CONFIG_FILE[DEFAULT]"); err != nil || len(h) != 0 {
		t.Fatalf("non-header auth must be ignored: %v %v", h, err)
	}
	if _, err := parseHeaderAuth("HEADER[no colon here]"); !errors.Is(err, storage_clients.ErrInvalidConfig) {
		t.Fatalf("got %v", err)
	}
}

func TestHTTPClientHasStallProtection(t *testing.T) {
	c := NewHTTPStorageClient("http://x", nil)
	tr, ok := c.client.Transport.(*http.Transport)
	if !ok || tr.ResponseHeaderTimeout == 0 || c.client.Timeout != 0 {
		t.Fatalf("client not tuned: timeout=%v transport=%T", c.client.Timeout, c.client.Transport)
	}
}
