package storage_clients

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

var (
	// ErrNotFound is returned (wrapped) when the requested object or bucket does not exist.
	ErrNotFound = errors.New("storage: object not found")

	// ErrUploadNotFound is returned (wrapped) when a multipart upload ID is unknown to the provider.
	ErrUploadNotFound = errors.New("storage: multipart upload not found")

	// ErrUnsupportedProvider is returned by GetClient for an unregistered provider.
	ErrUnsupportedProvider = errors.New("storage: unsupported provider")

	// ErrInvalidConfig is returned when auth/config strings cannot be parsed or are not supported.
	ErrInvalidConfig = errors.New("storage: invalid client configuration")

	// ErrInvalidRange is returned for invalid byte ranges passed to GetObjectRange.
	ErrInvalidRange = errors.New("storage: invalid byte range")

	// ErrInvalidResponse is returned when a provider response is missing required data
	// (ETag, Content-Length, unparseable listing, ...).
	ErrInvalidResponse = errors.New("storage: invalid provider response")
)

// StatusError reports a non-success HTTP status from a provider operation.
// It matches ErrNotFound via errors.Is when StatusCode is 404.
type StatusError struct {
	Op         string
	StatusCode int
	Err        error // optional underlying provider error
	// RetryAfter is the server's Retry-After hint (0 if absent). RetryPolicy.Do
	// honours it (capped) for retryable statuses.
	RetryAfter time.Duration
}

func (e *StatusError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: status %d: %v", e.Op, e.StatusCode, e.Err)
	}
	return fmt.Sprintf("%s: status %d", e.Op, e.StatusCode)
}

func (e *StatusError) Unwrap() error { return e.Err }

func (e *StatusError) Is(target error) bool {
	return target == ErrNotFound && e.StatusCode == http.StatusNotFound
}

// Retryable reports whether the status is worth retrying (408, 429, 5xx).
func (e *StatusError) Retryable() bool {
	return e.StatusCode == http.StatusRequestTimeout ||
		e.StatusCode == http.StatusTooManyRequests ||
		e.StatusCode >= 500
}

// IsRetryable classifies an error returned by a provider call.
// Caller context cancellation/deadline, ErrNotFound, ErrUploadNotFound,
// ErrInvalidRange, ErrInvalidConfig and non-retryable StatusErrors are not
// retryable; everything else (network errors, transport timeouts such as
// "timeout awaiting response headers" or dial timeouts, unknown errors) is.
//
// Transport timeouts satisfy errors.Is(err, context.DeadlineExceeded) through
// their Is methods, so the context check below only matches the context
// sentinels themselves in the error chain. Callers that own a context must
// check ctx.Err() first (RetryPolicy.Do does).
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}
	if chainHasContextSentinel(err) {
		return false
	}
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrUploadNotFound) ||
		errors.Is(err, ErrInvalidRange) || errors.Is(err, ErrInvalidConfig) {
		return false
	}
	var se *StatusError
	if errors.As(err, &se) {
		return se.Retryable()
	}
	return true
}

// chainHasContextSentinel reports whether context.Canceled or
// context.DeadlineExceeded itself (by identity, not via Is methods) appears in
// err's chain.
func chainHasContextSentinel(err error) bool {
	for err != nil {
		if err == context.Canceled || err == context.DeadlineExceeded {
			return true
		}
		switch u := err.(type) {
		case interface{ Unwrap() error }:
			err = u.Unwrap()
		case interface{ Unwrap() []error }:
			for _, e := range u.Unwrap() {
				if chainHasContextSentinel(e) {
					return true
				}
			}
			return false
		default:
			return false
		}
	}
	return false
}

// ErrAttemptTimeout is returned (wrapped, alongside context.DeadlineExceeded) when a
// single attempt exceeded its per-attempt deadline while the caller's context was
// still live. Such attempts are retried by RetryPolicy.Do.
var ErrAttemptTimeout = errors.New("storage: request attempt timed out")
