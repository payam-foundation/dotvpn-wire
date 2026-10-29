package transport

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/payam-foundation/dotvpn-wire/auth"
	"github.com/payam-foundation/dotvpn-wire/transport/udpframe"
)

// ConnectHandler serves the Firefox-style data plane: an HTTP CONNECT request
// carrying "Proxy-Authorization: Bearer <jwt>". It is identical on HTTP/2 and
// HTTP/3, so both listeners share it.
//
// Probe resistance: a request that is not a CONNECT, or a CONNECT without any
// Proxy-Authorization header, is handed to decoy and looks like an ordinary
// website. Only a request that presents a bearer token gets proxy-specific
// replies (407, 403, 429, 502).
func ConnectHandler(b Backend, decoy http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Header.Get("Proxy-Authorization") == "" {
			decoy.ServeHTTP(w, r)
			return
		}
		user, err := b.Authenticate(auth.Bearer(r.Header.Get("Proxy-Authorization")))
		if err != nil {
			w.Header().Set("Proxy-Authenticate", "Bearer")
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		authority := r.Host
		if authority == "" {
			authority = r.URL.Host
		}
		udp := false
		switch r.Header.Get(HeaderNet) {
		case "":
		case NetUDP:
			udp = true
		default:
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var up net.Conn
		if udp {
			ub, ok := b.(UDPBackend)
			if !ok {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			up, err = ub.DialUDP(r.Context(), user, authority)
		} else {
			up, err = b.Dial(r.Context(), user, authority)
		}
		if err != nil {
			w.WriteHeader(StatusFromError(err))
			return
		}
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		_ = rc.Flush()
		if udp {
			udpframe.Relay(&serverStream{r: r.Body, w: w, rc: rc}, up)
			return
		}
		Splice(&serverStream{r: r.Body, w: w, rc: rc}, up)
	})
}

// serverStream adapts a CONNECT exchange to io.ReadWriteCloser.
type serverStream struct {
	r  io.ReadCloser
	w  http.ResponseWriter
	rc *http.ResponseController
	mu sync.Mutex
}

func (s *serverStream) Read(p []byte) (int, error) { return s.r.Read(p) }

func (s *serverStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.w.Write(p)
	if err == nil {
		err = s.rc.Flush()
	}
	return n, err
}

// Close ends the read side; the handler returning ends the write side.
func (s *serverStream) Close() error { return s.r.Close() }

// ClientStream is the client side of one CONNECT stream.
type ClientStream struct {
	body io.ReadCloser  // response body: bytes from the node
	pw   *io.PipeWriter // request body: bytes to the node
	conn net.Conn       // underlying carrier, for addresses only
	once sync.Once
}

// NewClientStream wraps the pieces of a successful CONNECT round trip.
func NewClientStream(body io.ReadCloser, pw *io.PipeWriter, carrier net.Conn) *ClientStream {
	return &ClientStream{body: body, pw: pw, conn: carrier}
}

// Read reads from the node's reply body.
func (c *ClientStream) Read(p []byte) (int, error) { return c.body.Read(p) }

// Write sends to the node through the request body pipe.
func (c *ClientStream) Write(p []byte) (int, error) { return c.pw.Write(p) }

// CloseWrite half-closes by ending the request body.
func (c *ClientStream) CloseWrite() error { return c.pw.Close() }

// Close tears down both directions; it is safe to call more than once.
func (c *ClientStream) Close() error {
	c.once.Do(func() {
		_ = c.pw.Close()
		_ = c.body.Close()
	})
	return nil
}

// LocalAddr reports the carrier connection's local address.
func (c *ClientStream) LocalAddr() net.Addr { return c.conn.LocalAddr() }

// RemoteAddr reports the carrier connection's remote address.
func (c *ClientStream) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// SetDeadline is a no-op: deadlines are unsupported on multiplexed streams;
// callers use contexts. The same holds for SetReadDeadline and SetWriteDeadline.
func (c *ClientStream) SetDeadline(time.Time) error { return nil }

// SetReadDeadline is a no-op, see SetDeadline.
func (c *ClientStream) SetReadDeadline(time.Time) error { return nil }

// SetWriteDeadline is a no-op, see SetDeadline.
func (c *ClientStream) SetWriteDeadline(time.Time) error { return nil }

// OpenConnect performs the CONNECT round trip over any http.RoundTripper that
// speaks HTTP/2 or HTTP/3, and returns the stream on a 200 reply.
func OpenConnect(ctx context.Context, rt http.RoundTripper, authority, token string, carrier net.Conn) (net.Conn, error) {
	return openConnect(ctx, rt, authority, token, carrier, false)
}

// OpenConnectUDP is OpenConnect for a UDP flow (Dotvpn-Net: udp); the result
// preserves datagram boundaries. Only call it for endpoints that advertise UDP.
func OpenConnectUDP(ctx context.Context, rt http.RoundTripper, authority, token string, carrier net.Conn) (net.Conn, error) {
	c, err := openConnect(ctx, rt, authority, token, carrier, true)
	if err != nil {
		return nil, err
	}
	return udpframe.NewConn(c), nil
}

func openConnect(ctx context.Context, rt http.RoundTripper, authority, token string, carrier net.Conn, udp bool) (net.Conn, error) {
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+authority, pr)
	if err != nil {
		return nil, err
	}
	req.Host = authority
	req.ContentLength = -1
	req.Header.Set("Proxy-Authorization", "Bearer "+token)
	if udp {
		req.Header.Set(HeaderNet, NetUDP)
	}

	// ctx bounds the open only. The request context also governs the stream's
	// lifetime in net/http, so run the round trip on a detached context and
	// cancel it ourselves if ctx expires before the headers arrive.
	rctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	req = req.WithContext(rctx)
	type result struct {
		resp *http.Response
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		resp, err := rt.RoundTrip(req)
		ch <- result{resp, err}
	}()
	select {
	case <-ctx.Done():
		cancel()
		_ = pw.Close()
		return nil, ctx.Err()
	case res := <-ch:
		if res.err != nil {
			cancel()
			_ = pw.Close()
			return nil, res.err
		}
		if err := ErrorFromStatus(res.resp.StatusCode); err != nil {
			_ = res.resp.Body.Close()
			cancel()
			_ = pw.Close()
			return nil, err
		}
		cs := NewClientStream(&cancelBody{ReadCloser: res.resp.Body, cancel: cancel}, pw, carrier)
		return cs, nil
	}
}

type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelBody) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}
