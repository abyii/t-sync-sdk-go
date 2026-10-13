package storage_clients

import (
	"net"
	"net/http"
	"time"
)

const (
	// ResponseHeaderTimeout is the transport-level backstop for the wait for
	// response headers after the request has been written. It is at least
	// CompleteAttemptTimeout so it never cuts a slow multipart commit short;
	// tighter bounds come from per-attempt deadlines (MetadataAttemptTimeout,
	// UploadAttemptTimeout) and OpenWithHeaderTimeout (GetHeaderTimeout).
	ResponseHeaderTimeout = CompleteAttemptTimeout
	dialTimeout           = 30 * time.Second
	tlsHandshakeTimeout   = 15 * time.Second
	maxIdleConnsPerHost   = 64
)

// TuneTransport applies stall protection to tr: dial, TLS-handshake and
// response-header timeouts. It deliberately sets no overall timeout so large
// streams are not cut off; payload requests use per-attempt deadlines instead
// (see UploadAttemptTimeout). It also raises the idle-connection pool per host
// so concurrent workers reuse connections.
func TuneTransport(tr *http.Transport) {
	tr.DialContext = (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext
	tr.TLSHandshakeTimeout = tlsHandshakeTimeout
	tr.ResponseHeaderTimeout = ResponseHeaderTimeout
	if tr.MaxIdleConnsPerHost < maxIdleConnsPerHost {
		tr.MaxIdleConnsPerHost = maxIdleConnsPerHost
	}
	if tr.IdleConnTimeout == 0 {
		tr.IdleConnTimeout = 90 * time.Second
	}
}

// NewHTTPClient returns an http.Client (no overall Timeout) using a clone of
// http.DefaultTransport tuned by TuneTransport.
func NewHTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	TuneTransport(tr)
	return &http.Client{Transport: tr}
}
