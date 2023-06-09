package sniproxy

import (
	"net"
)

// Config is the SNI proxy configuration.
type Config struct {
	// TLSListenAddr is the listen address the SNI proxy will be listening to
	// TLS connections.
	TLSListenAddr *net.TCPAddr

	// HTTPListenAddr is the listen address the SNI proxy will be listening to
	// plain HTTP connections.
	HTTPListenAddr *net.TCPAddr

	// ForwardProxy is the address of the SOCKS5 proxy that the connections will
	// be forwarded to according to ForwardRules.
	ForwardProxy string

	// ForwardRules is a list of wildcards that define what connections will be
	// forwarded to the proxy using ForwardProxy.  If the list is empty and
	// ForwardProxy is set, all connections will be forwarded.
	ForwardRules []string

	// BlockRules is a list of wildcards that define connections to which hosts
	// will be blocked.
	BlockRules []string

	// DropRules is a list of wildcards that define connections to which hosts
	// will be dropped. "Dropped" means that they will be delayed for a specific
	// period of time.
	DropRules []string

	// BandwidthRate is a number of bytes per second the connections speed will
	// be limited to.  If not set, there is no limit.
	BandwidthRate float64

	// BandwidthRules is a map that allows to define connection speed for
	// domains that match the wildcards.  Has higher priority than
	// BandwidthRate.
	BandwidthRules map[string]float64
}
