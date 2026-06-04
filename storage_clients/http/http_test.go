package http

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/abyii/t-sync-sdk-go/v2/storage_clients"
)

func TestHTTPStorageClient(t *testing.T) {
	// State for mock server
	uploadedData := make(map[string][]byte)
	multipartUploads := make(map[string]map[int][]byte) // uploadID -> partNumber -> data

	// Start local mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		query := r.URL.Query()

		_, ok := query["uploads"]
		if r.Method == "POST" && ok {
			uploadID := "mock-upload-id-123"
			multipartUploads[uploadID] = make(map[int][]byte)

			res := InitiateMultipartUploadResult{UploadID: uploadID}
			xmlBytes, _ := xml.Marshal(res)
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(xmlBytes)
			return
		}

		// 2. Upload part (PUT /path?uploadId=xxx&partNumber=yyy)
		if r.Method == "PUT" && query.Get("uploadId") != "" && query.Get("partNumber") != "" {
			uploadID := query.Get("uploadId")
			partNumStr := query.Get("partNumber")
			partNum, _ := strconv.Atoi(partNumStr)

			data, _ := io.ReadAll(r.Body)
			if parts, exists := multipartUploads[uploadID]; exists {
				parts[partNum] = data
				w.Header().Set("ETag", fmt.Sprintf(`"etag-part-%d"`, partNum))
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
			return
		}

		// 3. Complete multipart upload (POST /path?uploadId=xxx)
		if r.Method == "POST" && query.Get("uploadId") != "" {
			uploadID := query.Get("uploadId")
			parts, exists := multipartUploads[uploadID]
			if !exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			// Read complete XML body
			bodyBytes, _ := io.ReadAll(r.Body)
			var complete CompleteMultipartUpload
			_ = xml.Unmarshal(bodyBytes, &complete)

			// Merge parts sequentially
			var merged []byte
			for i := 1; i <= len(parts); i++ {
				merged = append(merged, parts[i]...)
			}

			uploadedData[path] = merged
			delete(multipartUploads, uploadID)

			w.WriteHeader(http.StatusOK)
			return
		}

		// 4. Abort multipart upload (DELETE /path?uploadId=xxx)
		if r.Method == "DELETE" && query.Get("uploadId") != "" {
			uploadID := query.Get("uploadId")
			delete(multipartUploads, uploadID)
			w.WriteHeader(http.StatusOK)
			return
		}

		// 5. Get Object Range (GET /path)
		if r.Method == "GET" {
			data, exists := uploadedData[path]
			if !exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			rangeHeader := r.Header.Get("Range")
			forceFull := r.Header.Get("X-Force-Full")

			if rangeHeader == "" || forceFull == "true" {
				// Return full content (to test client fallback logic!)
				w.Header().Set("Content-Length", strconv.Itoa(len(data)))
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(data)
				return
			}

			// Parse simple range format: bytes=start-end or bytes=start-
			if !strings.HasPrefix(rangeHeader, "bytes=") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			parts := strings.Split(rangeHeader[6:], "-")
			start, _ := strconv.Atoi(parts[0])
			end := len(data) - 1
			if parts[1] != "" {
				end, _ = strconv.Atoi(parts[1])
			}

			if start < 0 || start >= len(data) || end < start {
				w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
				return
			}
			if end >= len(data) {
				end = len(data) - 1
			}

			partialData := data[start : end+1]
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(data)))
			w.Header().Set("Content-Length", strconv.Itoa(len(partialData)))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(partialData)
			return
		}

		// 6. Get Object Size (HEAD /path)
		if r.Method == "HEAD" {
			data, exists := uploadedData[path]
			if !exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(data)))
			w.WriteHeader(http.StatusOK)
			return
		}

		// 7. Put Object (PUT /path)
		if r.Method == "PUT" {
			data, _ := io.ReadAll(r.Body)
			uploadedData[path] = data
			w.WriteHeader(http.StatusOK)
			return
		}

		// 8. Delete Object (DELETE /path)
		if r.Method == "DELETE" {
			if _, exists := uploadedData[path]; exists {
				delete(uploadedData, path)
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
			return
		}

		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer server.Close()

	// Initialize HTTP storage client pointing to local mock server
	headers := map[string]string{
		"Authorization": "Bearer test-mock-token",
	}
	httpClient := NewHTTPStorageClient(server.URL, headers)

	ctx := context.Background()

	// 1. Test PutObject
	testData := []byte("hello HTTP storage client")
	err := httpClient.PutObject(ctx, "test-bucket", "file.txt", testData)
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	// 2. Test GetObjectSize
	size, err := httpClient.GetObjectSize(ctx, "test-bucket", "file.txt")
	if err != nil {
		t.Fatalf("GetObjectSize failed: %v", err)
	}
	if size != int64(len(testData)) {
		t.Errorf("expected size %d, got %d", len(testData), size)
	}

	// 3. Test GetObjectSize for non-existent file
	_, err = httpClient.GetObjectSize(ctx, "test-bucket", "missing.txt")
	if err == nil || !os.IsNotExist(err) {
		t.Errorf("expected os.ErrNotExist, got %v", err)
	}

	// 4. Test GetObjectRange with Range Support (Partial Content)
	rc, err := httpClient.GetObjectRange(ctx, "test-bucket", "file.txt", 6, 9)
	if err != nil {
		t.Fatalf("GetObjectRange failed: %v", err)
	}
	rangeData, _ := io.ReadAll(rc)
	rc.Close()
	if string(rangeData) != "HTTP" {
		t.Errorf("expected 'HTTP', got %q", string(rangeData))
	}

	// 5. Test GetObjectRange Fallback (server returns 200 OK using X-Force-Full header)
	httpClient.headers["X-Force-Full"] = "true"
	rc, err = httpClient.GetObjectRange(ctx, "test-bucket", "file.txt", 6, 9)
	if err != nil {
		t.Fatalf("GetObjectRange fallback failed: %v", err)
	}
	rangeDataFallback, _ := io.ReadAll(rc)
	rc.Close()
	if string(rangeDataFallback) != "HTTP" {
		t.Errorf("expected fallback 'HTTP', got %q", string(rangeDataFallback))
	}
	delete(httpClient.headers, "X-Force-Full")

	// 6. Test Multipart Upload
	uploadID, err := httpClient.Initiate(ctx, "test-bucket", "large.txt")
	if err != nil {
		t.Fatalf("Initiate failed: %v", err)
	}
	if uploadID != "mock-upload-id-123" {
		t.Errorf("expected uploadID mock-upload-id-123, got %q", uploadID)
	}

	etag1, err := httpClient.UploadPart(ctx, "test-bucket", "large.txt", uploadID, 1, []byte("part-1-"))
	if err != nil {
		t.Fatalf("UploadPart 1 failed: %v", err)
	}
	etag2, err := httpClient.UploadPart(ctx, "test-bucket", "large.txt", uploadID, 2, []byte("part-2"))
	if err != nil {
		t.Fatalf("UploadPart 2 failed: %v", err)
	}

	etags := map[int]string{
		1: etag1,
		2: etag2,
	}
	err = httpClient.Complete(ctx, "test-bucket", "large.txt", uploadID, etags)
	if err != nil {
		t.Fatalf("Complete failed: %v", err)
	}

	// Verify complete upload content
	rc, err = httpClient.GetObjectRange(ctx, "test-bucket", "large.txt", 0, -1)
	if err != nil {
		t.Fatalf("GetObjectRange for large file failed: %v", err)
	}
	largeData, _ := io.ReadAll(rc)
	rc.Close()
	if string(largeData) != "part-1-part-2" {
		t.Errorf("expected 'part-1-part-2', got %q", string(largeData))
	}

	// 7. Test DeleteObject
	err = httpClient.DeleteObject(ctx, "test-bucket", "large.txt")
	if err != nil {
		t.Fatalf("DeleteObject failed: %v", err)
	}

	// 8. Test Factory Registry creation
	factoryClient, err := storage_clients.GetClient("http", "HEADER[Authorization: Bearer factory-token]", server.URL)
	if err != nil {
		t.Fatalf("GetClient factory failed: %v", err)
	}
	if factoryClient == nil {
		t.Fatalf("factory client is nil")
	}
}
