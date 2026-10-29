// Package transport defines the seam between tunnel users and the ways a
// tunnel can be carried (HTTP/2 CONNECT, HTTP/3 CONNECT, WebSocket over a CDN,
// WebTunnel, Snowflake).
//
// Client side: a Dialer turns an Endpoint into a Session; a Session opens
// byte streams to "host:port" authorities. Server side: each adapter exposes a
// handler that authenticates every stream through a Backend and splices it to
// the upstream the Backend dials. Callers never see the carrier.
package transport

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/payam-foundation/dotvpn-wire/mimic"
)

// Kind names a carrier.
type Kind string

// Carriers a node can offer. Clients try them in ladder order.
const (
	KindH2        Kind = "h2"
	KindH3        Kind = "h3"
	KindCDNWS     Kind = "cdnws"
	KindWebTunnel Kind = "webtunnel"
	KindSnowflake Kind = "snowflake"
)

// Endpoint is everything needed to reach one node by one carrier. It is
// serialised in the signed server list.
type Endpoint struct {
	Kind Kind `json:"kind" yaml:"kind"`
	// Name labels the endpoint in logs and status output.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Addr is the host:port actually dialled: the node, a CDN edge, or a relay.
	Addr string `json:"addr" yaml:"addr"`
	// Host is the TLS server name and HTTP Host (the node or CDN domain).
	Host string `json:"host,omitempty" yaml:"host,omitempty"`
	// Path is the WebSocket path for cdnws and webtunnel.
	Path string `json:"path,omitempty" yaml:"path,omitempty"`
	// Pin is the base64 SHA-256 of the server's SPKI. When set, the chain is
	// not validated and the pin alone authenticates the server (self-signed
	// nodes without a domain).
	Pin string `json:"pin,omitempty" yaml:"pin,omitempty"`
	// Params carries carrier specific settings (snowflake broker, front, ...).
	Params map[string]string `json:"params,omitempty" yaml:"params,omitempty"`
}

// ServerName is the name to use for SNI and certificate verification.
func (e Endpoint) ServerName() string {
	if e.Host != "" {
		return e.Host
	}
	h, _, err := net.SplitHostPort(e.Addr)
	if err != nil {
		return e.Addr
	}
	return h
}

// Label is a short human description for logs.
func (e Endpoint) Label() string {
	if e.Name != "" {
		return fmt.Sprintf("%s(%s)", e.Name, e.Kind)
	}
	return fmt.Sprintf("%s@%s", e.Kind, e.Addr)
}

// TokenSource returns the current bearer token; sessions call it per stream
// so refreshed tokens apply without reconnecting.
type TokenSource func() string

// Session is one live connection to a node that multiplexes streams.
type Session interface {
	// OpenStream opens a stream to authority ("host:port"). ctx bounds the
	// open only; the stream outlives it.
	OpenStream(ctx context.Context, authority string) (net.Conn, error)
	// Alive reports whether new streams can still be opened.
	Alive() bool
	Close() error
}

// UDPSession is a Session that can also carry UDP flows (ADR-018). OpenUDP
// returns a datagram-preserving conn: each Write is one datagram, each Read
// one datagram, like a connected UDP socket to authority ("host:port"). Only
// use it when the endpoint advertises it (Endpoint.UDP): an older node would
// mistake the flow for a TCP stream.
type UDPSession interface {
	Session
	OpenUDP(ctx context.Context, authority string) (net.Conn, error)
}

// UDPBackend is a Backend that can dial UDP egress. Server adapters offer the
// UDP stream kind only when their Backend implements it, and only after the
// bearer token has been checked.
type UDPBackend interface {
	Backend
	DialUDP(ctx context.Context, u User, authority string) (net.Conn, error)
}

// ParamUDP in Endpoint.Params is "1" when the node serves UDP flows.
const ParamUDP = "udp"

// UDP reports whether the node behind e advertises UDP flows.
func (e Endpoint) UDP() bool { return e.Params[ParamUDP] == "1" }

// HeaderNet marks a CONNECT request as a UDP flow on h2 and h3. It is read
// only after the bearer token authenticates, so unauthenticated probes never
// see anything but the decoy.
const (
	HeaderNet = "Dotvpn-Net"
	NetUDP    = "udp"
)

// UDPPrefix is put before the authority of a UDP flow in the muxstream auth
// frame ("udp://host:port"). A node without UDP support fails to parse it as
// host:port and refuses the stream, so the extension fails closed.
const UDPPrefix = "udp://"

// Dialer connects to an Endpoint.
type Dialer interface {
	Dial(ctx context.Context, ep Endpoint, tok TokenSource) (Session, error)
}

// Options are the client wide knobs every Dialer honours.
type Options struct {
	// RootCAs overrides the system roots (tests, private CAs).
	RootCAs *x509.CertPool
	// Control runs on every raw socket before connect. VPN clients use it to
	// bind sockets to the physical interface so they bypass the tunnel.
	Control func(network, address string, c syscall.RawConn) error
	// Resolver looks up hostnames of endpoints. VPN clients set it to a
	// resolver that bypasses the tunnel; nil means the system resolver.
	Resolver *net.Resolver
	// DialTimeout bounds TCP connect plus TLS handshake. Default 15s.
	DialTimeout time.Duration
	// DNS is the plain resolver ("host:port") used for ECH HTTPS record
	// lookups when every DoH server fails. Default 1.1.1.1:53.
	DNS string
	// DoH overrides the pinned-address DNS-over-HTTPS resolvers used for ECH
	// lookups. Nil means Cloudflare, Google and Quad9 by IP.
	DoH []DoHServer
	// Upstream routes every TCP carrier through a SOCKS5 or HTTP CONNECT
	// proxy ("socks5://user:pass@host:port", "http://host:port"). UDP carriers
	// (h3, DNS, Snowflake) cannot use it; the client drops them when it is set.
	Upstream string
	// Fragment splits the TLS ClientHello into small TCP writes to defeat
	// naive SNI matching.
	Fragment bool
}

// Timeout is the dial timeout, 15s when unset.
func (o Options) Timeout() time.Duration {
	if o.DialTimeout > 0 {
		return o.DialTimeout
	}
	return 15 * time.Second
}

// Errors shared by client adapters and the server Backend.
var (
	ErrUnauthorized = errors.New("transport: proxy authentication required")
	ErrForbidden    = errors.New("transport: destination not allowed")
	ErrBusy         = errors.New("transport: too many streams")
	ErrBadGateway   = errors.New("transport: upstream unreachable")
)

// StatusError is a non-success reply from the node.
type StatusError struct{ Code int }

// Error reports the node's status code.
func (e *StatusError) Error() string {
	return fmt.Sprintf("transport: node replied %d %s", e.Code, http.StatusText(e.Code))
}

// ErrorFromStatus converts a node reply code to an error (nil for 200).
func ErrorFromStatus(code int) error {
	switch code {
	case http.StatusOK:
		return nil
	case http.StatusProxyAuthRequired:
		return ErrUnauthorized
	case http.StatusForbidden:
		return ErrForbidden
	case http.StatusTooManyRequests:
		return ErrBusy
	case http.StatusBadGateway:
		return ErrBadGateway
	}
	return &StatusError{Code: code}
}

// StatusFromError is the inverse, used by server adapters.
func StatusFromError(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, ErrUnauthorized):
		return http.StatusProxyAuthRequired
	case errors.Is(err, ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, ErrBusy):
		return http.StatusTooManyRequests
	}
	return http.StatusBadGateway
}

// User identifies an authenticated client to the Backend.
type User struct {
	ID   string
	Conc int
	Mbps int
}

// Backend is what a node gives server adapters. Authenticate is offline and
// cheap; Dial enforces egress policy, limits and accounting, and returns the
// upstream connection whose Close releases those resources.
type Backend interface {
	Authenticate(token string) (User, error)
	Dial(ctx context.Context, u User, authority string) (net.Conn, error)
}

// DialTCP connects with the socket options in o.
func DialTCP(ctx context.Context, addr string, o Options) (net.Conn, error) {
	d := net.Dialer{Timeout: o.Timeout(), KeepAlive: 30 * time.Second, Control: o.Control, Resolver: o.Resolver}
	if o.Upstream != "" {
		return dialUpstream(ctx, &d, o.Upstream, addr)
	}
	return d.DialContext(ctx, "tcp", addr)
}

// CandidateAddrs returns the addresses to try for ep: the comma separated
// Params["ips"] (bare IPs, or ip:port) on ep.Addr's port, or ep.Addr itself.
// The TLS name and HTTP Host stay ep.ServerName(), so a clean IP found by
// scanning a CDN range keeps working with the right SNI.
func CandidateAddrs(ep Endpoint) []string {
	list := ep.Params["ips"]
	if list == "" {
		return []string{ep.Addr}
	}
	_, port, err := net.SplitHostPort(ep.Addr)
	if err != nil {
		return []string{ep.Addr}
	}
	var out []string
	for _, f := range strings.Split(list, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(f); err == nil {
			out = append(out, f)
		} else if net.ParseIP(f) != nil {
			out = append(out, net.JoinHostPort(f, port))
		}
	}
	if len(out) == 0 {
		return []string{ep.Addr}
	}
	return out
}

// DialTLS runs the client handshake over raw and returns the secured conn and
// the negotiated ALPN protocol. It is the single place where the TLS
// fingerprint of the client is decided: a Chrome ClientHello (uTLS), with
// ECH per Endpoint.Params["ech"] (see ECHAuto, ECHRequire; ADR-017).
//
// raw must be a fresh connection to ep.Addr: when the server rejects ECH and
// offers retry configs, DialTLS dials ep.Addr again and retries once.
func DialTLS(ctx context.Context, raw net.Conn, ep Endpoint, o Options, alpn ...string) (net.Conn, string, error) {
	pol, err := parseECH(ep.Params["ech"])
	if err != nil {
		_ = raw.Close()
		return nil, "", err
	}
	var ech []byte
	if pol.on {
		if ech, err = resolveECH(ctx, ep, o, pol); err != nil {
			_ = raw.Close()
			return nil, "", err
		}
	}
	c, proto, err := tlsHandshake(ctx, raw, ep, o, ech, alpn)
	var rej *utls.ECHRejectionError
	if !errors.As(err, &rej) {
		return c, proto, err
	}
	// The server could not decrypt our inner hello. Its retry configs arrive
	// over a connection whose certificate was verified for the public name,
	// so they are trustworthy; with none, the server does not do ECH at all.
	retry := rej.RetryConfigList
	if len(retry) == 0 && pol.require {
		return nil, "", fmt.Errorf("%w: server rejected ech without retry configs", ErrECHRequired)
	}
	if pol.static != nil && len(retry) == 0 {
		return nil, "", err
	}
	if host := ep.ServerName(); len(retry) > 0 {
		cachePut(host, retry, echMinTTL)
	} else {
		cachePut(host, nil, echMinTTL)
	}
	raw2, derr := DialTCP(ctx, ep.Addr, o)
	if derr != nil {
		return nil, "", derr
	}
	c, proto, err = tlsHandshake(ctx, raw2, ep, o, retry, alpn)
	if errors.As(err, &rej) {
		return nil, "", fmt.Errorf("%w: rejected again", ErrECHRequired)
	}
	return c, proto, err
}

// tlsHandshake is one uTLS client handshake offering ech (nil: none, the
// preset's GREASE extension stays).
func tlsHandshake(ctx context.Context, raw net.Conn, ep Endpoint, o Options, ech []byte, alpn []string) (net.Conn, string, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_133)
	if err != nil {
		_ = raw.Close()
		return nil, "", err
	}
	mimic.ChromeCurrent(&spec)
	if len(alpn) > 0 {
		for _, e := range spec.Extensions {
			if a, ok := e.(*utls.ALPNExtension); ok {
				a.AlpnProtocols = alpn
			}
		}
	}
	cfg := &utls.Config{
		ServerName:                     ep.ServerName(),
		RootCAs:                        o.RootCAs,
		EncryptedClientHelloConfigList: ech,
	}
	if ech != nil {
		cfg.MinVersion = utls.VersionTLS13
	}
	if ep.Pin != "" {
		cfg.InsecureSkipVerify = true // #nosec G402 -- replaced by an exact SPKI pin check in VerifyConnection
		// VerifyConnection also runs on resumed sessions, unlike
		// VerifyPeerCertificate.
		cfg.VerifyConnection = func(cs utls.ConnectionState) error { return pinCheck(ep.Pin, cs.PeerCertificates) }
	}
	var wire net.Conn = raw
	if o.Fragment {
		wire = &fragmentConn{Conn: raw}
	}
	c := utls.UClient(wire, cfg, utls.HelloCustom)
	if err := c.ApplyPreset(&spec); err != nil {
		_ = raw.Close()
		return nil, "", err
	}
	if err := c.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, "", err
	}
	if o.Fragment {
		wire.(*fragmentConn).done = true
	}
	return c, c.ConnectionState().NegotiatedProtocol, nil
}

// TLSConfig is the standard-library client config for carriers that cannot use
// uTLS (QUIC). Same trust rules as DialTLS.
func TLSConfig(ep Endpoint, o Options, alpn ...string) *tls.Config {
	cfg := &tls.Config{
		ServerName: ep.ServerName(),
		RootCAs:    o.RootCAs,
		MinVersion: tls.VersionTLS13,
		NextProtos: alpn,
	}
	if ep.Pin != "" {
		cfg.InsecureSkipVerify = true // #nosec G402 -- replaced by an exact SPKI pin check in VerifyConnection
		cfg.VerifyConnection = func(cs tls.ConnectionState) error { return pinCheck(ep.Pin, cs.PeerCertificates) }
	}
	return cfg
}

// SPKIPin computes the Endpoint.Pin value for a certificate.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func pinCheck(pin string, certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return errors.New("transport: no server certificate")
	}
	if SPKIPin(certs[0]) != pin {
		return errors.New("transport: server key does not match pin")
	}
	return nil
}

// fragmentConn writes the first TLS flight (the ClientHello) in small pieces.
type fragmentConn struct {
	net.Conn
	done bool
	sent bool
}

func (f *fragmentConn) Write(p []byte) (int, error) {
	if f.done || f.sent {
		return f.Conn.Write(p)
	}
	f.sent = true
	const chunk = 24
	total := 0
	for len(p) > 0 {
		n := min(chunk, len(p))
		w, err := f.Conn.Write(p[:n])
		total += w
		if err != nil {
			return total, err
		}
		p = p[n:]
		if len(p) > 0 {
			time.Sleep(2 * time.Millisecond)
		}
	}
	return total, nil
}

// Splice copies both directions until either ends, then closes both. It
// returns bytes sent a->b and b->a. Half-close is propagated when supported.
func Splice(a, b io.ReadWriteCloser) (ab, ba int64) {
	done := make(chan struct{}, 2)
	go func() {
		ab, _ = io.Copy(b, a)
		closeWrite(b)
		done <- struct{}{}
	}()
	go func() {
		ba, _ = io.Copy(a, b)
		closeWrite(a)
		done <- struct{}{}
	}()
	<-done
	<-done
	_ = a.Close()
	_ = b.Close()
	return ab, ba
}

func closeWrite(c io.Closer) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// ResolveUDP resolves addr ("host:port") with o.Resolver.
func ResolveUDP(ctx context.Context, addr string, o Options) (*net.UDPAddr, error) {
	if o.Resolver == nil {
		return net.ResolveUDPAddr("udp", addr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	p, err := net.LookupPort("udp", port)
	if err != nil {
		return nil, err
	}
	ips, err := o.Resolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("transport: resolve %s: %v", host, err)
	}
	return &net.UDPAddr{IP: ips[0].AsSlice(), Port: p}, nil
}

// Listener is the server side seam: it accepts carrier connections, and runs
// each stream through b. Serve blocks until ctx ends or the listener fails.
type Listener interface {
	Serve(ctx context.Context, b Backend) error
}
