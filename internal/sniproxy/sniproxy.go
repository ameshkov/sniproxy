// Package sniproxy is responsible for the SNI and plain HTTP proxy that will
// listen for incoming TLS/HTTP connections, read the server name either from
// the SNI field of ClientHello or from the HTTP Host header, and tunnel traffic
// to the respective hosts.
package sniproxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/IGLOU-EU/go-wildcard"
	"github.com/fujiwara/shapeio"
	"golang.org/x/net/proxy"

	// Imported in order to register HTTP and HTTPS proxies.
	_ "github.com/ameshkov/sniproxy/internal/httpupstream"
)

const (
	// readTimeout is the default timeout for a connection read deadline.
	readTimeout = 10 * time.Second

	// connectionTimeout is a timeout for connecting to a remote host.
	connectionTimeout = 10 * time.Second

	// remotePortPlain is the port the proxy will be connecting for plain HTTP
	// connections.
	remotePortPlain = 80

	// remotePortTLS is the port the proxy will be connecting to for TLS
	// connection.
	remotePortTLS = 443
)

// SNIProxy is a struct that manages the SNI proxy server.  This server's
// purpose is to handle TLS connections and tunnel them to the respective
// hosts.  Also, it can handle plain HTTP connections, parse the target host
// and tunnel traffic there.
type SNIProxy struct {
	tlsListenAddr  *net.TCPAddr
	httpListenAddr *net.TCPAddr

	sniListener   net.Listener
	plainListener net.Listener

	dialer      *net.Dialer
	proxyDialer proxy.Dialer

	forwardRules []string
	blockRules   []string

	bandwidthRate float64
}

// type check
var _ io.Closer = (*SNIProxy)(nil)

// New creates a new instance of *SNIProxy.
func New(cfg *Config) (d *SNIProxy, err error) {
	dialer := &net.Dialer{
		Timeout:  connectionTimeout,
		Resolver: &net.Resolver{},
	}

	var proxyDialer proxy.Dialer
	if cfg.ForwardProxy != "" {
		var u *url.URL
		u, err = url.Parse(cfg.ForwardProxy)
		if err != nil {
			return nil, fmt.Errorf(
				"sniproxy: failed to parse forward-proxy %s: %w",
				cfg.ForwardProxy,
				err,
			)
		}

		proxyDialer, err = proxy.FromURL(u, dialer)
		if err != nil {
			return nil, fmt.Errorf(
				"sniproxy: failed to init forward-proxy %s: %w",
				cfg.ForwardProxy,
				err,
			)
		}
	}

	return &SNIProxy{
		tlsListenAddr:  cfg.TLSListenAddr,
		httpListenAddr: cfg.HTTPListenAddr,
		dialer:         dialer,
		proxyDialer:    proxyDialer,
		forwardRules:   cfg.ForwardRules,
		blockRules:     cfg.BlockRules,
		bandwidthRate:  cfg.BandwidthRate,
	}, nil
}

// Start starts the SNIProxy server.
func (p *SNIProxy) Start() (err error) {
	log.Info("sniproxy: starting")

	p.sniListener, err = net.ListenTCP("tcp", p.tlsListenAddr)
	if err != nil {
		return fmt.Errorf("sniproxy: failed to start SNIProxy: %w", err)
	}

	p.plainListener, err = net.ListenTCP("tcp", p.httpListenAddr)
	if err != nil {
		return fmt.Errorf("sniproxy: failed to start SNIProxy: %w", err)
	}

	go p.acceptLoop(p.sniListener, false)
	go p.acceptLoop(p.plainListener, true)

	log.Info("sniproxy: started successfully")

	return nil
}

// Close implements the [io.Closer] interface for SNIProxy.
//
// TODO(ameshkov): wait until all workers finish their work.
func (p *SNIProxy) Close() (err error) {
	log.Info("sniproxy: stopping")

	sniErr := p.sniListener.Close()
	plainErr := p.plainListener.Close()

	log.Info("sniproxy: stopped")

	return errors.Join(sniErr, plainErr)
}

// acceptLoop accepts incoming TCP connections and starts goroutines processing
// them.
func (p *SNIProxy) acceptLoop(l net.Listener, plainHTTP bool) {
	if plainHTTP {
		log.Info("sniproxy: listening for HTTP connections on %s", l.Addr())
	} else {
		log.Info("sniproxy: listening for TLS connections on %s", l.Addr())
	}

	for {
		conn, err := l.Accept()
		if err != nil && strings.Contains(err.Error(), "closed network connection") {
			log.Info("sniproxy: existing listener loop as it has been closed")

			return
		}
		go func() {
			cErr := p.handleConnection(conn, plainHTTP)
			if cErr != nil {
				log.Debug("sniproxy: error handling connection: %v", err)
			}
		}()
	}
}

// handleConnection handles a new incoming client connection, parses SNI or
// HTTP request and tunnels traffic to the specified upstream.
func (p *SNIProxy) handleConnection(clientConn net.Conn, plainHTTP bool) (err error) {
	defer log.OnCloserError(clientConn, log.DEBUG)

	if err = clientConn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		return fmt.Errorf("sniproxy: failed to set read deadline: %w", err)
	}

	serverName, clientReader, err := peekServerName(clientConn, plainHTTP)
	if err != nil {
		return fmt.Errorf("sniproxy: failed to peek server name: %w", err)
	}

	if err = clientConn.SetReadDeadline(time.Time{}); err != nil {
		return fmt.Errorf("sniproxy: failed to remove read deadline: %w", err)
	}

	// Sometimes, the server name may contain both host and port, consider this
	// case.
	hostname, remotePort, err := netutil.SplitHostPort(serverName)
	if err == nil {
		serverName = hostname
	} else if plainHTTP {
		remotePort = remotePortPlain
	} else {
		remotePort = remotePortTLS
	}

	remoteAddr := netutil.JoinHostPort(serverName, remotePort)
	ctx := NewSNIContext(serverName, remoteAddr)

	log.Info("sniproxy: [%d] start tunneling to %s", ctx.ID, ctx.RemoteAddr)

	for _, r := range p.blockRules {
		if wildcard.MatchSimple(r, ctx.RemoteHost) {
			log.Info("sniproxy: [%d] blocked connection to %s", ctx.ID, ctx.RemoteHost)

			return nil
		}
	}

	backendConn, err := p.dial(ctx)
	if err != nil {
		return fmt.Errorf("sniproxy: [%d] failed to connect to %s: %w", ctx.ID, ctx.RemoteAddr, err)
	}
	defer log.OnCloserError(backendConn, log.DEBUG)

	var wg sync.WaitGroup
	wg.Add(2)

	var bytesReceived, bytesSent int64

	go func() {
		defer wg.Done()

		bytesReceived = p.tunnel(ctx, clientConn, backendConn)
	}()
	go func() {
		defer wg.Done()

		bytesSent = p.tunnel(ctx, backendConn, clientReader)
	}()

	wg.Wait()

	log.Info(
		"sniproxy: [%d] finished tunneling to %s. received %d, sent %d",
		ctx.ID,
		remoteAddr,
		bytesReceived,
		bytesSent,
	)

	return nil
}

// dial opens a TCP connection to the remote address specified in the context.
// It also applies forward rules in the case if proxy dialer is specified.
//
// TODO(ameshkov): consider using DNSUpstream to resolve the specified hostname.
func (p *SNIProxy) dial(ctx *SNIContext) (conn net.Conn, err error) {
	if p.shouldForward(ctx) {
		return p.proxyDialer.Dial("tcp", ctx.RemoteAddr)
	}

	return p.dialer.Dial("tcp", ctx.RemoteAddr)
}

// shouldForward checks if the connection should be forwarded to the next proxy.
func (p *SNIProxy) shouldForward(ctx *SNIContext) (ok bool) {
	if p.proxyDialer == nil {
		return false
	}

	if len(p.forwardRules) == 0 {
		// forward all connections if there are no rules.
		return true
	}

	for _, r := range p.forwardRules {
		if wildcard.MatchSimple(r, ctx.RemoteHost) {
			return true
		}
	}

	return false
}

// closeWriter is a helper interface which only purpose is to check if the
// object has CloseWrite function or not and call it if it exists.
type closeWriter interface {
	CloseWrite() error
}

// copy copies data from src to dst and signals that the work is done via the
// wg wait group.
func (p *SNIProxy) tunnel(ctx *SNIContext, dst net.Conn, src io.Reader) (written int64) {
	defer func() {
		// In the case of *tcp.Conn and *tls.Conn we should call CloseWriter, so
		// we're using closeWriter interface to check for that function
		// presence.
		switch c := dst.(type) {
		case closeWriter:
			_ = c.CloseWrite()
		default:
			_ = c.Close()
		}
	}()

	reader := shapeio.NewReader(src)
	writer := shapeio.NewWriter(dst)
	if p.bandwidthRate > 0 {
		reader.SetRateLimit(p.bandwidthRate)
		writer.SetRateLimit(p.bandwidthRate)
	}

	written, err := io.Copy(writer, reader)

	if err != nil {
		log.Debug("sniproxy: [%d] finished copying due to %v", ctx.ID, err)
	}

	return written
}

// peekServerName peeks on the first bytes from the reader and tries to parse
// the remote server name.  Depending on whether this is a TLS or a plain HTTP
// connection it will use different ways of parsing.
func peekServerName(
	reader io.Reader,
	plainHTTP bool,
) (serverName string, newReader io.Reader, err error) {
	if plainHTTP {
		serverName, newReader, err = peekHTTPHost(reader)

		if err != nil {
			return "", nil, err
		}
	} else {
		var clientHello *tls.ClientHelloInfo
		clientHello, newReader, err = peekClientHello(reader)

		if err != nil {
			return "", nil, err
		}

		serverName = clientHello.ServerName
	}

	return serverName, newReader, nil
}

// peekHTTPHost peeks on the first bytes from the reader and tries to parse the
// HTTP Host header.  Once it's done, it returns the hostname and a new reader
// that contains unmodified data.
func peekHTTPHost(reader io.Reader) (host string, newReader io.Reader, err error) {
	peekedBytes := new(bytes.Buffer)
	teeReader := bufio.NewReader(io.TeeReader(reader, peekedBytes))

	r, err := http.ReadRequest(teeReader)
	if err != nil {
		return "", nil, fmt.Errorf("sniproxy: failed to read http request: %w", err)
	}

	return r.Host, io.MultiReader(peekedBytes, reader), nil
}

// peekClientHello peeks on the first bytes from the reader and tries to parse
// the TLS ClientHello.  Once it's done, it returns the client hello information
// and a new reader that contains unmodified data.
func peekClientHello(
	reader io.Reader,
) (hello *tls.ClientHelloInfo, newReader io.Reader, err error) {
	peekedBytes := new(bytes.Buffer)
	hello, err = readClientHello(io.TeeReader(reader, peekedBytes))
	if err != nil {
		return nil, nil, err
	}

	return hello, io.MultiReader(peekedBytes, reader), nil
}

// readClientHello reads client hello information from the specified reader.
func readClientHello(reader io.Reader) (hello *tls.ClientHelloInfo, err error) {
	err = tls.Server(readOnlyConn{reader: reader}, &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = new(tls.ClientHelloInfo)
			*hello = *argHello
			return nil, nil
		},
	}).Handshake()

	if hello == nil {
		return nil, err
	}

	return hello, nil
}

// readOnlyConn implements net.Conn but overrides all it's methods so that
// only reading could work.  The purpose is to make sure that the Handshake
// method of [tls.Server] does not write any data to the underlying connection.
type readOnlyConn struct {
	reader io.Reader
}

// type check
var _ net.Conn = (*readOnlyConn)(nil)

// Read implements the net.Conn interface for *readOnlyConn.
func (conn readOnlyConn) Read(p []byte) (int, error) { return conn.reader.Read(p) }

// Write implements the net.Conn interface for *readOnlyConn.
func (conn readOnlyConn) Write(_ []byte) (int, error) { return 0, io.ErrClosedPipe }

// Close implements the net.Conn interface for *readOnlyConn.
func (conn readOnlyConn) Close() error { return nil }

// LocalAddr implements the net.Conn interface for *readOnlyConn.
func (conn readOnlyConn) LocalAddr() net.Addr { return nil }

// RemoteAddr implements the net.Conn interface for *readOnlyConn.
func (conn readOnlyConn) RemoteAddr() net.Addr { return nil }

// SetDeadline implements the net.Conn interface for *readOnlyConn.
func (conn readOnlyConn) SetDeadline(_ time.Time) error { return nil }

// SetReadDeadline implements the net.Conn interface for *readOnlyConn.
func (conn readOnlyConn) SetReadDeadline(_ time.Time) error { return nil }

// SetWriteDeadline implements the net.Conn interface for *readOnlyConn.
func (conn readOnlyConn) SetWriteDeadline(_ time.Time) error { return nil }
