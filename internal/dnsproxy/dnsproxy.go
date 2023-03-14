// Package dnsproxy is responsible for the DNS proxy server that will redirect
// specified domains to the SNI proxy.
package dnsproxy

import (
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/AdguardTeam/golibs/log"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/IGLOU-EU/go-wildcard"
	"github.com/miekg/dns"
)

// defaultTTL is the default TTL for the rewritten records.
const defaultTTL = 60

// DNSProxy is a struct that manages the DNS proxy server.  This server's
// purpose is to redirect queries to a specified SNI proxy.
type DNSProxy struct {
	proxy          *proxy.Proxy
	redirectRules  []string
	redirectIPv4To net.IP
	redirectIPv6To net.IP
}

// type check
var _ io.Closer = (*DNSProxy)(nil)

// New creates an instance of a DNSProxy.
func New(cfg *Config) (d *DNSProxy, err error) {
	proxyConfig, err := createProxyConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("dnsproxy: invalid configuration: %w", err)
	}

	d = &DNSProxy{
		redirectRules:  cfg.RedirectRules,
		redirectIPv4To: cfg.RedirectIPv4To,
		redirectIPv6To: cfg.RedirectIPv6To,
	}
	d.proxy = &proxy.Proxy{
		Config: proxyConfig,
	}
	d.proxy.RequestHandler = d.requestHandler

	return d, nil
}

// Start starts the DNSProxy server.
func (d *DNSProxy) Start() (err error) {
	log.Info("dnsproxy: starting")

	err = d.proxy.Start()

	log.Info("dnsproxy: started successfully")

	return err
}

// Close implements the [io.Closer] interface for DNSProxy.
func (d *DNSProxy) Close() (err error) {
	log.Info("dnsproxy: stopping")

	err = d.proxy.Stop()

	log.Info("dnsproxy: stopped")

	return err
}

// requestHandler is a [proxy.RequestHandler] implementation which purpose is
// to implement the actual redirection logic.
func (d *DNSProxy) requestHandler(p *proxy.Proxy, ctx *proxy.DNSContext) (err error) {
	qName := strings.ToLower(ctx.Req.Question[0].Name)
	qType := ctx.Req.Question[0].Qtype
	if qType != dns.TypeA && qType != dns.TypeAAAA {
		// Doing nothing with the request
		return nil
	}

	domainName := strings.TrimSuffix(qName, ".")

	for _, r := range d.redirectRules {
		if wildcard.MatchSimple(r, domainName) {
			d.rewrite(qName, qType, ctx)

			return nil
		}
	}

	return p.Resolve(ctx)
}

// rewrite rewrites the specified query and redirects the response to the
// configured IP addresses.
func (d *DNSProxy) rewrite(qName string, qType uint16, ctx *proxy.DNSContext) {
	resp := &dns.Msg{}
	resp.SetReply(ctx.Req)

	hdr := dns.RR_Header{
		Name:   qName,
		Rrtype: qType,
		Class:  dns.ClassINET,
		Ttl:    defaultTTL,
	}

	switch {
	case qType == dns.TypeA && d.redirectIPv4To != nil:
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: hdr,
			A:   d.redirectIPv4To,
		})
	case qType == dns.TypeAAAA && d.redirectIPv6To != nil:
		resp.Answer = append(resp.Answer, &dns.AAAA{
			Hdr:  hdr,
			AAAA: d.redirectIPv6To,
		})
	}

	ctx.Res = resp
}

// createProxyConfig creates DNS proxy configuration.
func createProxyConfig(cfg *Config) (proxyConfig proxy.Config, err error) {
	upstreamCfg, err := proxy.ParseUpstreamsConfig([]string{cfg.Upstream}, nil)
	if err != nil {
		return proxyConfig, fmt.Errorf("failed to parse upstream %s: %w", cfg.Upstream, err)
	}

	ip := net.IP(cfg.ListenAddr.Addr().AsSlice())

	udpPort := &net.UDPAddr{
		IP:   ip,
		Port: int(cfg.ListenAddr.Port()),
	}
	tcpPort := &net.TCPAddr{
		IP:   ip,
		Port: int(cfg.ListenAddr.Port()),
	}

	proxyConfig.UDPListenAddr = []*net.UDPAddr{udpPort}
	proxyConfig.TCPListenAddr = []*net.TCPAddr{tcpPort}
	proxyConfig.UpstreamConfig = upstreamCfg

	return proxyConfig, nil
}
