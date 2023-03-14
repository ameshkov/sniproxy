// Package httpupstream extends proxy with HTTP and HTTPS proxies support.
package httpupstream

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/ameshkov/sniproxy/internal/version"
	"golang.org/x/net/proxy"
)

// HTTPProxyDialer implement proxy.Dialer and proxy.ContextDialer and adds
// HTTP and HTTPS proxies support.
type HTTPProxyDialer struct {
	address  string
	tls      bool
	userinfo *url.Userinfo
	next     proxy.ContextDialer
}

// type check
var _ proxy.Dialer = (*HTTPProxyDialer)(nil)
var _ proxy.ContextDialer = (*HTTPProxyDialer)(nil)

// init registers http and https schemes.
func init() {
	proxy.RegisterDialerType("http", HTTPProxyDialerFromURL)
	proxy.RegisterDialerType("https", HTTPProxyDialerFromURL)
}

// NewHTTPProxyDialer creates a new instance of *HTTPProxyDialer.
func NewHTTPProxyDialer(
	address string,
	tls bool,
	userinfo *url.Userinfo,
	next proxy.Dialer,
) (d *HTTPProxyDialer) {
	return &HTTPProxyDialer{
		address:  address,
		tls:      tls,
		next:     maybeWrapWithContextDialer(next),
		userinfo: userinfo,
	}
}

// HTTPProxyDialerFromURL creates an instance of proxy.Dialer from an http:// or
// https:// URL.
func HTTPProxyDialerFromURL(u *url.URL, next proxy.Dialer) (d proxy.Dialer, err error) {
	host := u.Hostname()
	port := u.Port()
	var https bool

	switch strings.ToLower(u.Scheme) {
	case "http":
		if port == "" {
			port = "80"
		}
	case "https":
		https = true
		if port == "" {
			port = "443"
		}
	default:
		return nil, fmt.Errorf("httpupstream: unsupported scheme %s", u.Scheme)
	}

	address := net.JoinHostPort(host, port)

	return NewHTTPProxyDialer(address, https, u.User, next), nil
}

// Dial implements the proxy.Dialer interface for *HTTPProxyDialer.
func (d *HTTPProxyDialer) Dial(network, address string) (conn net.Conn, err error) {
	return d.DialContext(context.Background(), network, address)
}

// DialContext implements the proxy.ContextDialer interface for
// *HTTPProxyDialer.
func (d *HTTPProxyDialer) DialContext(
	ctx context.Context,
	network string,
	address string,
) (conn net.Conn, err error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("httpupstream: unsupported network %s", network)
	}

	conn, err = d.next.DialContext(ctx, "tcp", d.address)
	if err != nil {
		return nil, fmt.Errorf("httpupstream: proxy dialer is unable to make connection: %w", err)
	}

	if d.tls {
		var hostname string
		hostname, err = netutil.SplitHost(d.address)
		if err != nil {
			hostname = address
		}

		conn = tls.Client(conn, &tls.Config{
			ServerName: hostname,
		})
	}

	stopGuardEvent := make(chan struct{})
	guardErr := make(chan error, 1)
	go func() {
		select {
		case <-stopGuardEvent:
			close(guardErr)
		case <-ctx.Done():
			_ = conn.Close()
			guardErr <- ctx.Err()
		}
	}()

	var stopGuardOnce sync.Once
	stopGuard := func() {
		stopGuardOnce.Do(func() {
			close(stopGuardEvent)
		})
	}
	defer stopGuard()

	var reqBuf bytes.Buffer
	_, _ = fmt.Fprintf(&reqBuf, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", address, address)
	if d.userinfo != nil {
		_, _ = fmt.Fprintf(&reqBuf, "Proxy-Authorization: %s\r\n", basicAuthHeader(d.userinfo))
	}
	_, _ = fmt.Fprintf(&reqBuf, "User-Agent: sniproxy/%s\r\n\r\n", version.VersionString)

	_, err = io.Copy(conn, &reqBuf)
	if err != nil {
		log.OnCloserError(conn, log.DEBUG)

		return nil,
			fmt.Errorf(
				"httpupstream: unable to write proxy request for remote connection: %w",
				err,
			)
	}

	resp, err := readResponse(conn)
	if err != nil {
		log.OnCloserError(conn, log.DEBUG)

		return nil, fmt.Errorf("httpupstream: reading proxy response failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		log.OnCloserError(conn, log.DEBUG)

		return nil, fmt.Errorf("httpupstream: bad status code from proxy: %d", resp.StatusCode)
	}

	stopGuard()

	if err = <-guardErr; err != nil {
		return nil, fmt.Errorf("httpupstream: context error: %w", err)
	}

	return conn, nil
}

var (
	responseTerminator = []byte("\r\n\r\n")
)

// readResponse reads HTTP response from the specified reader.
func readResponse(r io.Reader) (*http.Response, error) {
	var respBuf bytes.Buffer
	b := make([]byte, 1)

	// The response is read byte-by-byte in order to avoid wrapping a network
	// connection with bufio.Reader.
	for !bytes.HasSuffix(respBuf.Bytes(), responseTerminator) {
		n, err := r.Read(b)

		if err != nil {
			return nil, fmt.Errorf("httpupstream: unable to read HTTP response: %w", err)
		}

		if n == 0 {
			continue
		}

		_, err = respBuf.Write(b)
		if err != nil {
			return nil, fmt.Errorf("httpupstream: unable to store byte into buffer: %w", err)
		}
	}

	resp, err := http.ReadResponse(bufio.NewReader(&respBuf), nil)
	if err != nil {
		return nil, fmt.Errorf("httpupstream: unable to decode proxy response: %w", err)
	}

	return resp, nil
}

// basicAuthHeader creates Authorization header  with the specified user info.
func basicAuthHeader(userinfo *url.Userinfo) string {
	username := userinfo.Username()
	password, _ := userinfo.Password()
	return "Basic " + base64.StdEncoding.EncodeToString(
		[]byte(username+":"+password))
}

// wrappedDialer wraps proxy.Dialer and adds DialContext implementation when
// necessary.
type wrappedDialer struct {
	d proxy.Dialer
}

// type check
var _ proxy.Dialer = (*wrappedDialer)(nil)
var _ proxy.ContextDialer = (*wrappedDialer)(nil)

// Dial implements the proxy.Dialer interface for *wrappedDialer.
func (wd wrappedDialer) Dial(net, address string) (net.Conn, error) {
	return wd.d.Dial(net, address)
}

// DialContext implements the proxy.ContextDialer interface for *wrappedDialer.
func (wd wrappedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var (
		conn net.Conn
		done = make(chan struct{}, 1)
		err  error
	)

	go func() {
		conn, err = wd.d.Dial(network, address)
		close(done)

		if conn != nil && ctx.Err() != nil {
			log.OnCloserError(conn, log.DEBUG)
		}
	}()

	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-done:
	}

	return conn, err
}

// maybeWrapWithContextDialer wraps the specified proxy.Dialer and adds
// proxy.ContextDialer capabilities if they're missing.
func maybeWrapWithContextDialer(d proxy.Dialer) (cd proxy.ContextDialer) {
	if xd, ok := d.(proxy.ContextDialer); ok {
		return xd
	}
	return wrappedDialer{d}
}
