// Package h2connect is the HTTP/2 CONNECT carrier (the Firefox VPN data plane).
package h2connect

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"github.com/payam-foundation/dotvpn-wire/transport"
)

// Dialer implements transport.Dialer for Kind h2.
type Dialer struct{ Opts transport.Options }

// Dial opens a session to ep using h2: HTTP/2 CONNECT over a pinned TLS connection. The token is fetched per stream.
func (d Dialer) Dial(ctx context.Context, ep transport.Endpoint, tok transport.TokenSource) (transport.Session, error) {
	dctx, cancel := context.WithTimeout(ctx, d.Opts.Timeout())
	defer cancel()
	raw, err := transport.DialTCP(dctx, ep.Addr, d.Opts)
	if err != nil {
		return nil, err
	}
	conn, proto, err := transport.DialTLS(dctx, raw, ep, d.Opts, "h2", "http/1.1")
	if err != nil {
		return nil, err
	}
	if proto != "h2" {
		_ = conn.Close()
		return nil, errors.New("h2connect: node did not negotiate h2")
	}
	// ponytail: x/net http2.Transport is deprecated for http.Transport, but only it
	// wraps a pre-dialled conn with ping tuning; migrate when http.ClientConn covers it.
	t := &http2.Transport{
		StrictMaxConcurrentStreams: true,
		ReadIdleTimeout:            15 * time.Second,
		PingTimeout:                10 * time.Second,
		WriteByteTimeout:           30 * time.Second,
	}
	cc, err := t.NewClientConn(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	s := &session{cc: cc, conn: conn, tok: tok}
	s.alive.Store(true)
	return s, nil
}

type session struct {
	cc    *http2.ClientConn
	conn  net.Conn
	tok   transport.TokenSource
	alive atomic.Bool
}

// roundTripper adapts a single ClientConn to http.RoundTripper.
func (s *session) RoundTrip(r *http.Request) (*http.Response, error) { return s.cc.RoundTrip(r) }

func (s *session) OpenStream(ctx context.Context, authority string) (net.Conn, error) {
	c, err := transport.OpenConnect(ctx, s, authority, s.tok(), s.conn)
	if err != nil && s.cc.State().Closed {
		s.alive.Store(false)
	}
	return c, err
}

// OpenUDP opens a UDP flow to authority; see transport.UDPSession.
func (s *session) OpenUDP(ctx context.Context, authority string) (net.Conn, error) {
	c, err := transport.OpenConnectUDP(ctx, s, authority, s.tok(), s.conn)
	if err != nil && s.cc.State().Closed {
		s.alive.Store(false)
	}
	return c, err
}

func (s *session) Alive() bool {
	if !s.alive.Load() {
		return false
	}
	st := s.cc.State()
	return !st.Closed && !st.Closing
}

func (s *session) Close() error {
	s.alive.Store(false)
	return s.cc.Close()
}
