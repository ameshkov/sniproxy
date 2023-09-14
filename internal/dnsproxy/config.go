package dnsproxy

import (
	"net"
	"net/netip"
)

// Config is the DNS proxy configuration.
type Config struct {
	// ListenAddr is the address the DNS server is supposed to listen to.
	ListenAddr netip.AddrPort

	// Upstream is the upstream that the requests will be forwarded to.  The
	// format of an upstream is the one that can be consumed by
	// [proxy.ParseUpstreamsConfig].
	Upstream string

	// RedirectIPv4To is the IP address A queries will be redirected to.
	RedirectIPv4To net.IP

	// RedirectIPv6To is the IP address AAAA queries will be redirected to.
	RedirectIPv6To net.IP

	// RedirectRules is a list of wildcards that is used for checking which
	// domains should be redirected.
	RedirectRules []string

	// DropRules is a list of wildcards that define DNS queries to which
	// domains will be dropped. "Dropped" means that the DNS server will not
	// respond to these queries.
	DropRules []string
}
