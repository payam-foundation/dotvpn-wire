// Package cdnws is the CDN-friendly carrier: WebSocket over TLS to a path on
// the node or CDN hostname, with smux multiplexing streams over a small pool
// of sockets. CDNs forward WebSocket upgrades where they refuse CONNECT.
// Stream framing lives in muxstream.
package cdnws

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/xtaci/smux"

	"github.com/payam-foundation/dotvpn-wire/transport"
	"github.com/payam-foundation/dotvpn-wire/transport/muxstream"
)

// readLimit must exceed the largest smux frame (32 KiB payload + header).
const readLimit = 1 << 20

// Dialer implements transport.Dialer for Kind cdnws. Pool is the number of
// WebSocket sessions to open (default 2, capped at 4).
type Dialer struct {
	Opts transport.Options
	Pool int
}

// Dial opens a session to ep using cdnws: WebSocket carrier through a CDN, pooled over several sockets. The token is fetched per stream.
func (d Dialer) Dial(ctx context.Context, ep transport.Endpoint, tok transport.TokenSource) (transport.Session, error) {
	n := min(max(d.Pool, 2), 4)
	dctx, cancel := context.WithTimeout(ctx, d.Opts.Timeout())
	defer cancel()
	first, err := d.dialOne(dctx, ep)
	if err != nil {
		return nil, err
	}
	s := muxstream.NewSession(tok, first)
	// Extra sockets spread load over more CDN connections; they are best
	// effort and join the pool when ready.
	for i := 1; i < n; i++ {
		go func() {
			ectx, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.Opts.Timeout())
			defer cancel()
			if x, err := d.dialOne(ectx, ep); err == nil {
				s.Add(x)
			}
		}()
	}
	return s, nil
}

func (d Dialer) dialOne(ctx context.Context, ep transport.Endpoint) (*smux.Session, error) {
	hc := &http.Client{Transport: &http.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			raw, err := transport.DialTCP(ctx, ep.Addr, d.Opts)
			if err != nil {
				return nil, err
			}
			c, _, err := transport.DialTLS(ctx, raw, ep, d.Opts, "http/1.1")
			return c, err
		},
		ForceAttemptHTTP2: false,
	}}
	path := ep.Path
	if path == "" {
		path = "/"
	}
	ws, _, err := websocket.Dial(ctx, "https://"+ep.ServerName()+path, &websocket.DialOptions{HTTPClient: hc})
	if err != nil {
		return nil, err
	}
	ws.SetReadLimit(readLimit)
	return muxstream.Client(websocket.NetConn(context.WithoutCancel(ctx), ws, websocket.MessageBinary))
}

// Handler serves the carrier. Anything that is not a WebSocket upgrade goes to
// decoy; sockets that never present a valid token get their streams reset.
func Handler(b transport.Backend, decoy http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			decoy.ServeHTTP(w, r)
			return
		}
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		ws.SetReadLimit(readLimit)
		ctx, cancel := context.WithTimeout(r.Context(), 24*time.Hour)
		defer cancel()
		muxstream.Serve(b, websocket.NetConn(ctx, ws, websocket.MessageBinary))
	})
}
