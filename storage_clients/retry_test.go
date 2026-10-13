package storage_clients

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func countingFn(errs ...error) (func(context.Context) error, *int32) {
	var n int32
	return func(context.Context) error {
		i := atomic.AddInt32(&n, 1) - 1
		if int(i) < len(errs) {
			return errs[i]
		}
		return errs[len(errs)-1]
	}, &n
}

var fast = RetryPolicy{MaxAttempts: 4, BaseDelay: time.Millisecond}

func TestRetryNoRetryOnPermanentErrors(t *testing.T) {
	cases := map[string]error{
		"404":        &StatusError{Op: "op", StatusCode: http.StatusNotFound},
		"403":        &StatusError{Op: "op", StatusCode: http.StatusForbidden},
		"400":        &StatusError{Op: "op", StatusCode: http.StatusBadRequest},
		"notfound":   fmt.Errorf("x: %w", ErrNotFound),
		"upload":     fmt.Errorf("x: %w", ErrUploadNotFound),
		"range":      ErrInvalidRange,
		"canceled":   context.Canceled,
		"deadline":   fmt.Errorf("wrapped: %w", context.DeadlineExceeded),
		"permanent":  Permanent(errors.New("parse failure")),
		"permanent2": Permanent(fmt.Errorf("%w: bad xml", ErrInvalidResponse)),
	}
	for name, e := range cases {
		t.Run(name, func(t *testing.T) {
			fn, n := countingFn(e)
			err := fast.Do(context.Background(), "op", 0, fn)
			if *n != 1 {
				t.Fatalf("attempts = %d, want 1", *n)
			}
			if !errors.Is(err, e) {
				t.Fatalf("error chain lost: %v", err)
			}
		})
	}
}

func TestRetryRetriesTransientErrors(t *testing.T) {
	cases := map[string]error{
		"503":     &StatusError{Op: "op", StatusCode: http.StatusServiceUnavailable},
		"429":     &StatusError{Op: "op", StatusCode: http.StatusTooManyRequests},
		"500":     &StatusError{Op: "op", StatusCode: http.StatusInternalServerError},
		"network": errors.New("connection reset by peer"),
		"invalid": fmt.Errorf("%w: missing ETag", ErrInvalidResponse),
	}
	for name, e := range cases {
		t.Run(name, func(t *testing.T) {
			fn, n := countingFn(e)
			err := fast.Do(context.Background(), "op", 0, fn)
			if *n != 4 {
				t.Fatalf("attempts = %d, want 4", *n)
			}
			if !errors.Is(err, e) {
				t.Fatalf("error chain lost: %v", err)
			}
		})
	}
	t.Run("succeeds after transient", func(t *testing.T) {
		fn, n := countingFn(&StatusError{StatusCode: 503}, &StatusError{StatusCode: 503}, nil)
		if err := fast.Do(context.Background(), "op", 0, fn); err != nil {
			t.Fatal(err)
		}
		if *n != 3 {
			t.Fatalf("attempts = %d, want 3", *n)
		}
	})
}

func TestRetryNoSleepAfterLastAttempt(t *testing.T) {
	p := RetryPolicy{MaxAttempts: 1, BaseDelay: 2 * time.Second}
	fn, n := countingFn(errors.New("transient"))
	start := time.Now()
	_ = p.Do(context.Background(), "op", 0, fn)
	if el := time.Since(start); el > 500*time.Millisecond {
		t.Fatalf("slept after final attempt: %v", el)
	}
	if *n != 1 {
		t.Fatalf("attempts = %d", *n)
	}

	// 2 attempts: exactly one backoff (~[50ms,150ms)), none after the last.
	p = RetryPolicy{MaxAttempts: 2, BaseDelay: 100 * time.Millisecond}
	fn, _ = countingFn(errors.New("transient"))
	start = time.Now()
	_ = p.Do(context.Background(), "op", 0, fn)
	if el := time.Since(start); el < 50*time.Millisecond || el > 1500*time.Millisecond {
		t.Fatalf("elapsed %v, want one backoff only", el)
	}
}

func TestRetryContextCancelAbortsBackoff(t *testing.T) {
	p := RetryPolicy{MaxAttempts: 4, BaseDelay: 10 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	last := errors.New("transient")
	fn, n := countingFn(last)
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	err := p.Do(ctx, "op", 0, fn)
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("backoff not aborted promptly: %v", el)
	}
	if *n != 1 {
		t.Fatalf("attempts = %d, want 1", *n)
	}
	if !errors.Is(err, context.Canceled) || !errors.Is(err, last) {
		t.Fatalf("want canceled + last error, got %v", err)
	}
	if IsRetryable(err) {
		t.Fatal("canceled result must not be retryable")
	}
}

func TestRetryCanceledBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var n int32
	err := fast.Do(ctx, "op", 0, func(ctx context.Context) error {
		atomic.AddInt32(&n, 1)
		return ctx.Err()
	})
	if n != 1 || !errors.Is(err, context.Canceled) {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestRetryAttemptTimeoutIsRetried(t *testing.T) {
	var n int32
	err := fast.Do(context.Background(), "op", 20*time.Millisecond, func(ctx context.Context) error {
		atomic.AddInt32(&n, 1)
		<-ctx.Done() // simulate a stalled request
		return ctx.Err()
	})
	if n != 4 {
		t.Fatalf("attempts = %d, want 4", n)
	}
	if !errors.Is(err, ErrAttemptTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}

	// Stall only on the first attempt: the second succeeds.
	n = 0
	err = fast.Do(context.Background(), "op", 20*time.Millisecond, func(ctx context.Context) error {
		if atomic.AddInt32(&n, 1) == 1 {
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	})
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestRetryParentDeadlineNotRetried(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	var n int32
	err := fast.Do(ctx, "op", time.Minute, func(ctx context.Context) error {
		atomic.AddInt32(&n, 1)
		<-ctx.Done()
		return ctx.Err()
	})
	if n != 1 || errors.Is(err, ErrAttemptTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestUploadAttemptTimeout(t *testing.T) {
	if got := UploadAttemptTimeout(0); got != 60*time.Second {
		t.Fatalf("0 bytes: %v", got)
	}
	if got := UploadAttemptTimeout(256 * 1024 * 10); got != 70*time.Second {
		t.Fatalf("2.5MiB: %v", got)
	}
	if got := UploadAttemptTimeout(64 << 20); got != 60*time.Second+256*time.Second {
		t.Fatalf("64MiB: %v", got)
	}
}

func TestParseAuthString(t *testing.T) {
	base, opts, err := ParseAuthString("DEFAULT[arn:aws:iam::1:role/x];region=ap-south-1", "region")
	if err != nil || base != "DEFAULT[arn:aws:iam::1:role/x]" || opts["region"] != "ap-south-1" {
		t.Fatalf("base=%q opts=%v err=%v", base, opts, err)
	}
	base, opts, err = ParseAuthString(" OKE_WORKLOAD_IDENTITY ; Region = us-ashburn-1 ;", "region")
	if err != nil || base != "OKE_WORKLOAD_IDENTITY" || opts["region"] != "us-ashburn-1" {
		t.Fatalf("base=%q opts=%v err=%v", base, opts, err)
	}
	// ';' inside brackets does not split.
	base, _, err = ParseAuthString("S3_ACCESS_KEYS[a;b:c]", "region")
	if err != nil || base != "S3_ACCESS_KEYS[a;b:c]" {
		t.Fatalf("base=%q err=%v", base, err)
	}
	base, opts, err = ParseAuthString("OCI_CONFIG_FILE[DEFAULT]")
	if err != nil || base != "OCI_CONFIG_FILE[DEFAULT]" || len(opts) != 0 {
		t.Fatalf("base=%q opts=%v err=%v", base, opts, err)
	}
	for _, bad := range []string{"DEFAULT;regionap-south-1", "DEFAULT;foo=bar", "DEFAULT;region=a;region=b", "DEFAULT;=x"} {
		if _, _, err := ParseAuthString(bad, "region"); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%q: want ErrInvalidConfig, got %v", bad, err)
		}
	}
}

func TestGetClientUnsupportedProvider(t *testing.T) {
	_, err := GetClient("no-such-provider", "", "")
	if !errors.Is(err, ErrUnsupportedProvider) {
		t.Fatalf("got %v", err)
	}
}

func TestNewHTTPClientStallProtection(t *testing.T) {
	c := NewHTTPClient()
	if c.Timeout != 0 {
		t.Fatalf("overall timeout must be 0 for large streams, got %v", c.Timeout)
	}
	tr := c.Transport.(*http.Transport)
	if tr.ResponseHeaderTimeout != ResponseHeaderTimeout || tr.TLSHandshakeTimeout == 0 || tr.DialContext == nil {
		t.Fatalf("transport not tuned: %+v", tr)
	}
}
