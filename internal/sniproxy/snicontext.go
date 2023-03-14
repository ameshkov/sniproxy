package sniproxy

import "sync/atomic"

var lastID uint64

// SNIContext represents a single tunnel connection context.
type SNIContext struct {
	// ID is a unique connection ID.
	ID uint64

	// RemoteHost is the hostname that was parsed from the connection's TLS
	// ClientHello.
	RemoteHost string

	// RemoteAddr is the address the proxy will connect to.  Basically, it is
	// just remoteHost:remotePort.
	RemoteAddr string
}

// NewSNIContext creates a new instance of *SNIContext.
func NewSNIContext(remoteHost string, remoteAddr string) (c *SNIContext) {
	return &SNIContext{
		ID:         atomic.AddUint64(&lastID, 1),
		RemoteHost: remoteHost,
		RemoteAddr: remoteAddr,
	}
}
