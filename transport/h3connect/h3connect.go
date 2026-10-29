// Package h3connect is the HTTP/3 CONNECT carrier: the same data plane as
// h2connect over QUIC. It falls behind h2 in the client ladder because QUIC is
// often throttled; when it works it avoids TCP head-of-line blocking.
//
// ponytail: the QUIC handshake uses crypto/tls, not uTLS, so its ClientHello
// is the Go one. Revisit if QUIC fingerprinting is observed in practice.
package h3connect

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/payam-foundation/dotvpn-wire/transport"
)

// quicConfig: InitialPacketSize 1200 stops PMTU discovery probes from being
// dropped on restrictive networks (Firefox VPN learned this the hard way).
func quicConfig(timeout time.Duration) *quic.Config {
	return &quic.Config{
		// QUIC v2 (RFC 9369) first, v1 as fallback: its Initial keys differ, so
		// on-path DPI that only decrypts v1 Initials cannot read the SNI.
		Versions:             []quic.Version{quic.Version2, quic.Version1},
		InitialPacketSize:    1200,
		KeepAlivePeriod:      15 * time.Second,
		MaxIdleTimeout:       45 * time.Second,
		HandshakeIdleTimeout: timeout,
	}
}

// Dialer implements transport.Dialer for Kind h3.
type Dialer struct{ Opts transport.Options }

// Dial opens a session to ep using h3: HTTP/3 CONNECT over QUIC. The token is fetched per stream.
func (d Dialer) Dial(ctx context.Context, ep transport.Endpoint, tok transport.TokenSource) (transport.Session, error) {
	if d.Opts.Upstream != "" {
		return nil, errors.New("h3connect: QUIC cannot use an upstream proxy")
	}
	if transport.ECHRequired(ep) {
		// QUIC here uses crypto/tls without ECH; never dial it in the clear.
		return nil, transport.ErrECHRequired
	}
	dctx, cancel := context.WithTimeout(ctx, d.Opts.Timeout())
	defer cancel()
	addr, err := transport.ResolveUDP(dctx, ep.Addr, d.Opts)
	if err != nil {
		return nil, err
	}
	lc := net.ListenConfig{Control: d.Opts.Control}
	pc, err := lc.ListenPacket(dctx, "udp", ":0")
	if err != nil {
		return nil, err
	}
	qt := &quic.Transport{Conn: pc}
	qc, err := qt.Dial(dctx, addr, transport.TLSConfig(ep, d.Opts, http3.NextProtoH3), quicConfig(d.Opts.Timeout()))
	if err != nil {
		_ = qt.Close()
		return nil, err
	}
	h3 := &http3.Transport{}
	s := &session{cc: h3.NewClientConn(qc), qc: qc, qt: qt, tok: tok}
	s.alive.Store(true)
	return s, nil
}

type session struct {
	cc    *http3.ClientConn
	qc    *quic.Conn
	qt    *quic.Transport
	tok   transport.TokenSource
	alive atomic.Bool
}

func (s *session) RoundTrip(r *http.Request) (*http.Response, error) { return s.cc.RoundTrip(r) }

func (s *session) OpenStream(ctx context.Context, authority string) (net.Conn, error) {
	c, err := transport.OpenConnect(ctx, s, authority, s.tok(), &carrier{s.qc})
	if err != nil && s.qc.Context().Err() != nil {
		s.alive.Store(false)
	}
	return c, err
}

// OpenUDP opens a UDP flow to authority; see transport.UDPSession. The flow is
// a framed CONNECT stream, not a QUIC datagram, so it behaves the same on every carrier.
func (s *session) OpenUDP(ctx context.Context, authority string) (net.Conn, error) {
	c, err := transport.OpenConnectUDP(ctx, s, authority, s.tok(), &carrier{s.qc})
	if err != nil && s.qc.Context().Err() != nil {
		s.alive.Store(false)
	}
	return c, err
}

func (s *session) Alive() bool { return s.alive.Load() && s.qc.Context().Err() == nil }

func (s *session) Close() error {
	s.alive.Store(false)
	err := s.qc.CloseWithError(0, "")
	_ = s.qt.Close()
	return err
}

// carrier gives ClientStream the addresses of the QUIC connection.
type carrier struct{ c *quic.Conn }

func (c *carrier) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (c *carrier) Write([]byte) (int, error)        { return 0, net.ErrClosed }
func (c *carrier) Close() error                     { return nil }
func (c *carrier) LocalAddr() net.Addr              { return c.c.LocalAddr() }
func (c *carrier) RemoteAddr() net.Addr             { return c.c.RemoteAddr() }
func (c *carrier) SetDeadline(time.Time) error      { return nil }
func (c *carrier) SetReadDeadline(time.Time) error  { return nil }
func (c *carrier) SetWriteDeadline(time.Time) error { return nil }

// Serve runs an HTTP/3 server on the UDP port of addr until ctx ends. It
// matches node.Options.Extra.
func Serve(ctx context.Context, addr string, tlsCfg *tls.Config, h http.Handler) error {
	srv := &http3.Server{
		Addr:        addr,
		TLSConfig:   tlsCfg,
		Handler:     h,
		QUICConfig:  quicConfig(15 * time.Second),
		IdleTimeout: 5 * time.Minute,
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.ListenAndServe(); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}
