// Package muxstream is the stream layer shared by the byte-pipe carriers
// (cdnws, webtunnel, snowflake): smux over any net.Conn, with every stream
// opened by an auth frame so the token travels inside the encrypted carrier.
//
//	client -> node: u16 len | token | u16 len | authority
//	node -> client: u16 HTTP status (200 means the stream is spliced)
package muxstream

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"

	"github.com/payam-foundation/dotvpn-wire/auth"
	"github.com/payam-foundation/dotvpn-wire/transport"
	"github.com/payam-foundation/dotvpn-wire/transport/udpframe"
)

const (
	authWindow = 10 * time.Second
	maxField   = 4096
)

func config() *smux.Config {
	c := smux.DefaultConfig()
	c.KeepAliveInterval = 15 * time.Second
	c.KeepAliveTimeout = 45 * time.Second
	return c
}

// Client starts the client side of a smux session over conn.
func Client(conn net.Conn) (*smux.Session, error) { return smux.Client(conn, config()) }

// Session is a transport.Session over one or more smux sessions; streams are
// spread round-robin over the live ones.
type Session struct {
	tok  transport.TokenSource
	next atomic.Uint32

	mu   sync.Mutex
	sess []*smux.Session
}

// NewSession wraps already-negotiated smux sessions; tok supplies the bearer
// token for each opened stream.
func NewSession(tok transport.TokenSource, first *smux.Session) *Session {
	return &Session{tok: tok, sess: []*smux.Session{first}}
}

// Add joins another smux session to the pool.
func (s *Session) Add(x *smux.Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sess = append(s.sess, x)
}

func (s *Session) pick() *smux.Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	live := s.sess[:0]
	for _, x := range s.sess {
		if !x.IsClosed() {
			live = append(live, x)
		}
	}
	s.sess = live
	if len(live) == 0 {
		return nil
	}
	return live[int(s.next.Add(1))%len(live)]
}

// OpenStream opens a stream on the next live smux session (round robin) and
// asks the node to connect it to authority.
func (s *Session) OpenStream(ctx context.Context, authority string) (net.Conn, error) {
	return s.open(ctx, authority)
}

// OpenUDP opens a UDP flow to authority (transport.UDPSession). The auth frame
// carries it as "udp://authority".
func (s *Session) OpenUDP(ctx context.Context, authority string) (net.Conn, error) {
	st, err := s.open(ctx, transport.UDPPrefix+authority)
	if err != nil {
		return nil, err
	}
	return udpframe.NewConn(st), nil
}

func (s *Session) open(ctx context.Context, authority string) (net.Conn, error) {
	x := s.pick()
	if x == nil {
		return nil, errors.New("muxstream: session closed")
	}
	st, err := x.OpenStream()
	if err != nil {
		return nil, err
	}
	// ctx bounds the open only: abort the handshake by closing the stream.
	stop := context.AfterFunc(ctx, func() { _ = st.Close() })
	defer stop()
	if err := writeFrames(st, s.tok(), authority); err != nil {
		_ = st.Close()
		return nil, err
	}
	var code [2]byte
	if _, err := io.ReadFull(st, code[:]); err != nil {
		_ = st.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if err := transport.ErrorFromStatus(int(binary.BigEndian.Uint16(code[:]))); err != nil {
		_ = st.Close()
		return nil, err
	}
	if !stop() {
		_ = st.Close()
		return nil, ctx.Err()
	}
	return st, nil
}

// Alive reports whether any underlying session is still usable.
func (s *Session) Alive() bool { return s.pick() != nil }

// Close closes every underlying session.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.sess {
		_ = x.Close()
	}
	s.sess = nil
	return nil
}

func writeFrames(w io.Writer, token, authority string) error {
	buf := make([]byte, 0, 4+len(token)+len(authority))
	for _, f := range []string{token, authority} {
		if len(f) > math.MaxUint16 {
			return errors.New("muxstream: field too long")
		}
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(f)))
		buf = append(buf, f...)
	}
	_, err := w.Write(buf)
	return err
}

func readFrame(r io.Reader) (string, error) {
	var n [2]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return "", err
	}
	l := int(binary.BigEndian.Uint16(n[:]))
	if l > maxField {
		return "", errors.New("muxstream: oversized frame")
	}
	b := make([]byte, l)
	_, err := io.ReadFull(r, b)
	return string(b), err
}

// Serve runs the server side over conn until it ends. Streams that never
// present a valid token are answered 407 and closed, never tunnelled.
func Serve(b transport.Backend, conn net.Conn) {
	sess, err := smux.Server(conn, config())
	if err != nil {
		_ = conn.Close()
		return
	}
	defer sess.Close()
	for {
		st, err := sess.AcceptStream()
		if err != nil {
			return
		}
		go serveStream(b, st)
	}
}

func serveStream(b transport.Backend, st *smux.Stream) {
	defer st.Close()
	_ = st.SetReadDeadline(time.Now().Add(authWindow))
	token, err := readFrame(st)
	if err != nil {
		return
	}
	authority, err := readFrame(st)
	if err != nil {
		return
	}
	_ = st.SetReadDeadline(time.Time{})

	reply := func(code int) {
		var c [2]byte
		binary.BigEndian.PutUint16(c[:], uint16(code))
		_, _ = st.Write(c[:])
	}
	user, err := b.Authenticate(auth.Bearer("Bearer " + token))
	if err != nil {
		reply(http.StatusProxyAuthRequired)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if rest, udp := strings.CutPrefix(authority, transport.UDPPrefix); udp {
		ub, ok := b.(transport.UDPBackend)
		if !ok {
			reply(http.StatusForbidden)
			return
		}
		up, err := ub.DialUDP(ctx, user, rest)
		if err != nil {
			reply(transport.StatusFromError(err))
			return
		}
		reply(http.StatusOK)
		udpframe.Relay(st, up)
		return
	}
	up, err := b.Dial(ctx, user, authority)
	if err != nil {
		reply(transport.StatusFromError(err))
		return
	}
	reply(http.StatusOK)
	transport.Splice(st, up)
}
