package storage_clients

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// MetadataAttemptTimeout bounds a single attempt of a request without a
	// payload (HEAD, DELETE, list page, initiate, abort).
	MetadataAttemptTimeout = 2 * time.Minute

	// CompleteAttemptTimeout bounds a single multipart-complete attempt; providers
	// may take a while to assemble many parts (OCI only sends headers once the
	// commit is done).
	CompleteAttemptTimeout = 10 * time.Minute

	// GetHeaderTimeout bounds the header phase of a GetObjectRange attempt (see
	// OpenWithHeaderTimeout). Once headers arrive, the body may stream for as
	// long as the caller needs.
	GetHeaderTimeout = 2 * time.Minute

	uploadBaseTimeout   = 60 * time.Second
	uploadMinThroughput = 256 * 1024 // bytes per second
)

// UploadAttemptTimeout returns the per-attempt deadline for sending a payload of
// n bytes: 60s plus the time needed at a minimum throughput of 256 KiB/s.
// A stalled connection therefore fails the attempt (and is retried) instead of
// consuming the caller's entire deadline.
//
// The 256 KiB/s floor is a total-elapsed-time budget, not a progress check: an
// attempt that is still moving bytes but averages below the floor is cut off
// and retried. Examples: 8 MiB -> 92s (needs ~89 KiB/s), 64 MiB -> 316s (~207
// KiB/s), 5 GiB -> ~5h42m (~256 KiB/s). With several concurrent uploads sharing
// a link slower than roughly 8-10 Mbit/s, large parts can exhaust every attempt;
// such deployments need fewer concurrent uploads or smaller parts.
func UploadAttemptTimeout(n int) time.Duration {
	return uploadBaseTimeout + time.Duration(int64(n)*int64(time.Second)/uploadMinThroughput)
}

// RetryPolicy is the single retry layer used by all storage clients. Provider
// SDK internal retries are disabled so attempts do not stack.
//
// Attempt limits depend on the error class of the latest failure: retryable
// HTTP statuses (408, 429, 5xx — throttling and service blips that usually
// clear within tens of seconds) get MaxStatusAttempts; everything else that is
// retryable (network errors, transport and per-attempt timeouts, malformed
// responses) gets MaxAttempts, since repeating a stalled or broken connection
// many times mostly burns the caller's deadline.
type RetryPolicy struct {
	// MaxAttempts is the total number of attempts (including the first) for
	// non-status errors.
	MaxAttempts int
	// MaxStatusAttempts is the total number of attempts for retryable HTTP
	// statuses; 0 means MaxAttempts.
	MaxStatusAttempts int
	// BaseDelay is the backoff before the second attempt; it doubles for each
	// further attempt, is capped at MaxDelay (0 = uncapped) and jittered to
	// [0.5x, 1x].
	BaseDelay time.Duration
	MaxDelay  time.Duration
	// MaxRetryAfter caps a server Retry-After hint (StatusError.RetryAfter); the
	// wait is max(backoff, min(RetryAfter, MaxRetryAfter)). 0 ignores hints.
	MaxRetryAfter time.Duration
}

// DefaultRetryPolicy: up to 8 attempts for 408/429/5xx and 4 for other
// retryable errors; backoff ~500ms, 1s, 2s, 4s, 8s, 16s, 20s (jittered, capped
// at 20s, worst case ~52s of sleeping); Retry-After honoured up to 60s.
var DefaultRetryPolicy = RetryPolicy{
	MaxAttempts:       4,
	MaxStatusAttempts: 8,
	BaseDelay:         500 * time.Millisecond,
	MaxDelay:          20 * time.Second,
	MaxRetryAfter:     60 * time.Second,
}

func (p RetryPolicy) backoff(retry int) time.Duration {
	if p.BaseDelay <= 0 {
		return 0
	}
	d := p.MaxDelay
	if shift := retry - 1; shift < 32 {
		if v := p.BaseDelay << shift; v > 0 && (p.MaxDelay <= 0 || v < p.MaxDelay) {
			d = v
		}
	}
	if d <= 0 {
		return 0
	}
	return d/2 + rand.N(d/2+1)
}

// attemptLimit returns the attempt budget for the class of err.
func (p RetryPolicy) attemptLimit(err error) int {
	limit := p.MaxAttempts
	var se *StatusError
	if p.MaxStatusAttempts > 0 && errors.As(err, &se) && se.Retryable() {
		limit = p.MaxStatusAttempts
	}
	return max(limit, 1)
}

func (p RetryPolicy) wait(retry int, err error) time.Duration {
	d := p.backoff(retry)
	var se *StatusError
	if p.MaxRetryAfter > 0 && errors.As(err, &se) && se.RetryAfter > 0 {
		d = max(d, min(se.RetryAfter, p.MaxRetryAfter))
	}
	return d
}

// Do runs fn until it succeeds, returns a non-retryable error (see IsRetryable),
// ctx is done, or the attempt limit for the latest error's class is reached
// (see RetryPolicy). No sleep happens after the last attempt and backoff waits
// abort as soon as ctx is done.
//
// If attemptTimeout > 0, each attempt gets its own context.WithTimeout derived
// from ctx; an attempt that hits that deadline (while ctx itself is still live)
// is retried and reported via ErrAttemptTimeout. Do not use attemptTimeout for
// calls returning a body that outlives fn (the attempt context is canceled when
// fn returns); use OpenWithHeaderTimeout inside fn instead.
//
// The returned error is wrapped with op.
func (p RetryPolicy) Do(ctx context.Context, op string, attemptTimeout time.Duration, fn func(ctx context.Context) error) error {
	for attempt := 1; ; attempt++ {
		err := runAttempt(ctx, attemptTimeout, fn)
		if err == nil {
			return nil
		}

		if ctxErr := ctx.Err(); ctxErr != nil {
			if errors.Is(err, ctxErr) {
				return fmt.Errorf("%s: %w", op, err)
			}
			return fmt.Errorf("%s: %w; last error: %w", op, ctxErr, err)
		}
		if isPermanent(err) || (!errors.Is(err, ErrAttemptTimeout) && !IsRetryable(err)) {
			return fmt.Errorf("%s: %w", op, err)
		}
		if attempt >= p.attemptLimit(err) {
			return fmt.Errorf("%s: giving up after %d attempts: %w", op, attempt, err)
		}

		t := time.NewTimer(p.wait(attempt, err))
		select {
		case <-ctx.Done():
			t.Stop()
			return fmt.Errorf("%s: %w; last error: %w", op, ctx.Err(), err)
		case <-t.C:
		}
	}
}

func runAttempt(ctx context.Context, attemptTimeout time.Duration, fn func(ctx context.Context) error) error {
	if attemptTimeout <= 0 {
		return fn(ctx)
	}
	actx, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()
	err := fn(actx)
	if err != nil && ctx.Err() == nil && errors.Is(actx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w after %s: %w", ErrAttemptTimeout, attemptTimeout, err)
	}
	return err
}

// ParseRetryAfter parses a Retry-After header value (delay-seconds or an
// HTTP-date relative to now). It returns 0 for empty, invalid or past values.
func ParseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs <= 0 {
			return 0
		}
		if secs > int64(24*time.Hour/time.Second) {
			secs = int64(24 * time.Hour / time.Second)
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

// Permanent marks err so RetryPolicy.Do does not retry it even if IsRetryable
// would (e.g. a deterministic response-parse failure). The wrapper is
// transparent: its message is err's and errors.Is/As see through it.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &permanentError{err}
}

type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

func isPermanent(err error) bool {
	var p *permanentError
	return errors.As(err, &p)
}
