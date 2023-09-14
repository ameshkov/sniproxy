package cmd

import (
	"net"
	"net/netip"

	"github.com/AdguardTeam/golibs/log"
	"github.com/ameshkov/sniproxy/internal/dnsproxy"
	"github.com/ameshkov/sniproxy/internal/sniproxy"
)

// toDNSProxyConfig converts command-line arguments to [*dnsproxy.Config] or
// panics if the arguments aren't valid.
func toDNSProxyConfig(options *Options) (cfg *dnsproxy.Config) {
	addr, err := netip.ParseAddr(options.DNSListenAddress)
	check(err)

	addrPort := netip.AddrPortFrom(addr, uint16(options.DNSPort))

	cfg = &dnsproxy.Config{
		ListenAddr:    addrPort,
		Upstream:      options.DNSUpstream,
		RedirectRules: options.DNSRedirectRules,
		DropRules:     options.DNSDropRules,
	}

	if options.DNSRedirectIPV4To != "" {
		ip := net.ParseIP(options.DNSRedirectIPV4To)

		if ip == nil {
			log.Fatalf(
				"cmd: failed to parse dns-redirect-ipv4-to %s: %v",
				options.DNSRedirectIPV4To,
				err,
			)
		}

		if ip.To4() == nil {
			log.Fatalf(
				"cmd: dns-redirect-ipv4-to must be an IPv4 address: %s",
				options.DNSRedirectIPV4To,
			)
		}

		cfg.RedirectIPv4To = ip
	}

	if options.DNSRedirectIPV6To != "" {
		ip := net.ParseIP(options.DNSRedirectIPV6To)

		if ip == nil {
			log.Fatalf(
				"cmd: failed to parse dns-redirect-ipv6-to %s: %v",
				options.DNSRedirectIPV6To,
				err,
			)
		}

		if ip.To16() == nil {
			log.Fatalf(
				"cmd: dns-redirect-ipv6-to must be an IPv6 address: %s",
				options.DNSRedirectIPV6To,
			)
		}

		cfg.RedirectIPv6To = ip
	}

	if cfg.RedirectIPv4To == nil && cfg.RedirectIPv6To == nil {
		log.Fatalf("cmd: either dns-redirect-ipv4-to or dns-redirect-ipv6-to must be specified")
	}

	return cfg
}

// toSNIProxyConfig converts command-line arguments to [*sniproxy.Config] or
// panics if the arguments aren't valid.
func toSNIProxyConfig(options *Options) (cfg *sniproxy.Config) {
	tlsIP := net.ParseIP(options.TLSListenAddress)
	if tlsIP == nil {
		log.Fatalf("cmd: failed to parse tls-address %s", options.TLSListenAddress)
	}

	plainIP := net.ParseIP(options.HTTPListenAddress)
	if plainIP == nil {
		log.Fatalf("cmd: failed to parse http-address %s", options.HTTPListenAddress)
	}

	cfg = &sniproxy.Config{
		TLSListenAddr: &net.TCPAddr{
			IP:   tlsIP,
			Port: options.TLSPort,
		},
		HTTPListenAddr: &net.TCPAddr{
			IP:   plainIP,
			Port: options.HTTPPort,
		},
		ForwardProxy:  options.ForwardProxy,
		ForwardRules:  options.ForwardRules,
		BlockRules:    options.BlockRules,
		DropRules:     options.DropRules,
		BandwidthRate: options.BandwidthRate,
	}

	return cfg
}
