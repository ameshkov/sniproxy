package cmd

import "encoding/json"

// Options represents console arguments.
type Options struct {
	// DNSListenAddress is the IP address the DNS proxy server will be
	// listening to.
	DNSListenAddress string `long:"dns-address" description:"IP address that the DNS proxy server will be listening to." default:"0.0.0.0"`

	// DNSPort is the port the DNS proxy server will be listening to.
	DNSPort int `long:"dns-port" description:"Port the DNS proxy server will be listening to." default:"53"`

	// DNSUpstream is the address of the DNS server the proxy will forward
	// queries that are not rewritten to the SNI proxy.
	DNSUpstream string `long:"dns-upstream" description:"The address of the DNS server the proxy will forward queries that are not rewritten by sniproxy." default:"8.8.8.8"`

	// DNSRedirectIPV4To is the IPv4 address of the SNI proxy domains will be
	// redirected to by rewriting responses to A queries.
	DNSRedirectIPV4To string `long:"dns-redirect-ipv4-to" description:"IPv4 address that will be used for redirecting type A DNS queries."`

	// DNSRedirectIPV6To is the IPv6 address of the SNI proxy domains will be
	// redirected to by rewriting responses to AAAA queries.  If not set, the
	// program will try to automatically choose the public address of the SNI
	// proxy.
	DNSRedirectIPV6To string `long:"dns-redirect-ipv6-to" description:"IPv6 address that will be used for redirecting type AAAA DNS queries." default:""`

	// DNSRedirectRules is a list of wildcards that defines which domains
	// should be redirected to the SNI proxy.  Can be specified multiple times.
	DNSRedirectRules []string `long:"dns-redirect-rule" description:"Wildcard that defines which domains should be redirected to the SNI proxy. Can be specified multiple times." default:"*"`

	// HTTPListenAddress is the IP address the HTTP proxy server will be
	// listening to.  Note, that the HTTP proxy will work pretty much the same
	// way the SNI proxy works, i.e. it will tunnel traffic to the hostname
	// that was specified in the "Host" header.
	HTTPListenAddress string `long:"http-address" description:"IP address the SNI proxy server will be listening for plain HTTP connections." default:"0.0.0.0"`

	// HTTPPort is the port the HTTP proxy server will be listening to.
	HTTPPort int `long:"http-port" description:"Port the SNI proxy server will be listening for plain HTTP connections." default:"80"`

	// TLSListenAddress is the IP address the SNI proxy server will be
	// listening to.
	TLSListenAddress string `long:"tls-address" description:"IP address the SNI proxy server will be listening for TLS connections." default:"0.0.0.0"`

	// TLSPort is the port the SNI proxy server will be listening to.
	TLSPort int `long:"tls-port" description:"Port the SNI proxy server will be listening for TLS connections." default:"443"`

	// BandwidthRate is a number of bytes per second the connections speed will
	// be limited to.  If not set, there is no limit.
	BandwidthRate float64 `long:"bandwidth-rate" description:"Bytes per second the connections speed will be limited to. If not set, there is no limit." default:"0"`

	// ForwardProxy is the address of a SOCKS/HTTP/HTTPS proxy that the connections will
	// be forwarded to according to ForwardRules.
	ForwardProxy string `long:"forward-proxy" description:"Address of a SOCKS/HTTP/HTTPS proxy that the connections will be forwarded to according to forward-rule."`

	// ForwardRules is a list of wildcards that define what connections will be
	// forwarded to ForwardProxy.  If the list is empty and ForwardProxy is set,
	// all connections will be forwarded.
	ForwardRules []string `long:"forward-rule" description:"Wildcard that defines what connections will be forwarded to forward-proxy. Can be specified multiple times. If no rules are specified, all connections will be forwarded to the proxy."`

	// BlockRules is a list of wildcards that define connections to which hosts
	// will be blocked.
	BlockRules []string `long:"block-rule" description:"Wildcard that defines what domains should be blocked. Can be specified multiple times."`

	// Log settings
	// --

	// Verbose defines whether we should write the DEBUG-level log or not.
	Verbose bool `long:"verbose" description:"Verbose output (optional)" optional:"yes" optional-value:"true"`

	// LogOutput is the optional path to the log file.
	LogOutput string `long:"output" description:"Path to the log file. If not set, write to stdout."`
}

// String implements fmt.Stringer interface for Options.
func (o *Options) String() (s string) {
	b, _ := json.MarshalIndent(o, "", "    ")
	return string(b)
}
