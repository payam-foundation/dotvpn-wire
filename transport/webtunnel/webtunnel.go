// Package webtunnel is the carrier that looks like an ordinary HTTPS
// WebSocket upgrade on a secret path of the decoy domain. The upgrade handshake
// is Tor's WebTunnel httpupgrade transport; once switched, smux carries
// streams (muxstream).
package webtunnel

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel/transport/httpupgrade"

	"github.com/payam-foundation/dotvpn-wire/transport"
	"github.com/payam-foundation/dotvpn-wire/transport/muxstream"
)

// Dialer implements transport.Dialer for Kind webtunnel.
type Dialer struct{ Opts transport.Options }

// Dial opens a session to ep using webtunnel: CONNECT hidden behind a secret URL path on a web server. The token is fetched per stream.
func (d Dialer) Dial(ctx context.Context, ep transport.Endpoint, tok transport.TokenSource) (transport.Session, error) {
	dctx, cancel := context.WithTimeout(ctx, d.Opts.Timeout())
	defer cancel()
	raw, err := transport.DialTCP(dctx, ep.Addr, d.Opts)
	if err != nil {
		return nil, err
	}
	// http/1.1 only: the upgrade needs a raw byte stream after the 101.
	c, _, err := transport.DialTLS(dctx, raw, ep, d.Opts, "http/1.1")
	if err != nil {
		return nil, err
	}
	// Unblock the handshake if the context ends first.
	stop := context.AfterFunc(dctx, func() { _ = c.Close() })
	defer stop()
	t, err := httpupgrade.NewHTTPUpgradeTransport(&httpupgrade.Config{
		Path: strings.TrimPrefix(ep.Path, "/"),
		Host: ep.ServerName(),
	})
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	up, err := t.Client(c)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	if !stop() {
		_ = c.Close()
		return nil, dctx.Err()
	}
	x, err := muxstream.Client(up)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return muxstream.NewSession(tok, x), nil
}

// Handler serves the carrier on its path. Requests that are not upgrades go to
// decoy, so the path answers like any other page to a casual visitor.
func Handler(b transport.Backend, decoy http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || r.ProtoMajor != 1 {
			decoy.ServeHTTP(w, r)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			decoy.ServeHTTP(w, r)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Time{})
		// Reply 101 ourselves; the request is already parsed by net/http.
		if _, err := buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n"); err != nil {
			return
		}
		if err := buf.Flush(); err != nil {
			return
		}
		muxstream.Serve(b, &bufConn{Conn: conn, r: buf.Reader})
	})
}

// bufConn reads through the hijacked bufio.Reader so bytes the client sent
// right behind the upgrade request are not lost.
type bufConn struct {
	net.Conn
	r interface{ Read([]byte) (int, error) }
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }
