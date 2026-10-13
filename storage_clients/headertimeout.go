package storage_clients

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// OpenWithHeaderTimeout runs open (a request whose response body outlives the
// call, e.g. GetObject) with a context derived from ctx that is canceled if
// open has not returned within d — the header phase. Once open returns a body
// the timer is disarmed; the context stays alive while the body streams and is
// canceled when the returned body is closed (callers must Close it).
//
// If the header phase expires while ctx is still live, the error matches
// ErrAttemptTimeout (and not context.Canceled), so RetryPolicy.Do retries it.
// d <= 0 disables the timer.
func OpenWithHeaderTimeout(ctx context.Context, d time.Duration, open func(ctx context.Context) (io.ReadCloser, error)) (io.ReadCloser, error) {
	if d <= 0 {
		return open(ctx)
	}
	hctx, cancel := context.WithCancel(ctx)
	var fired atomic.Bool
	timer := time.AfterFunc(d, func() {
		fired.Store(true)
		cancel()
	})
	body, err := open(hctx)
	if timer.Stop() && err == nil {
		return &cancelOnClose{ReadCloser: body, cancel: cancel}, nil
	}
	// Failed, or the timer fired concurrently (body context already canceled).
	if body != nil {
		_ = body.Close()
	}
	cancel()
	if fired.Load() && ctx.Err() == nil {
		if err == nil {
			return nil, fmt.Errorf("%w: no response headers within %s", ErrAttemptTimeout, d)
		}
		return nil, fmt.Errorf("%w: no response headers within %s (%v)", ErrAttemptTimeout, d, err)
	}
	return nil, err
}

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}
