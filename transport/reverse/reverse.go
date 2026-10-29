// Package reverse is the relay carrier. A relay in a restricted country only
// listens; the core node dials out to it and parks authenticated connections
// in a pool. A client that reaches the relay is spliced onto a pooled
// connection and runs the normal session handshake with the node through it,
// so the relay forwards ciphertext and never learns the node address, keys or
// the client's account.
//
//	node  -> relay: mimic knock hello (public pool key)
//	node <-> relay: handshake (relay identity pinned) + pool auth token
//	client-> relay: mimic knock hello (public per-node key)
//	client<-> node: handshake (node identity pinned) + muxstream
//
// Over UDP the client uses the DNS-shaped carrier and prefixes the stream with
// the node id, since there is no hello to carry a knock.
package reverse

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/payam-foundation/dotvpn-wire/auth"
	"github.com/payam-foundation/dotvpn-wire/dnscarrier"
	"github.com/payam-foundation/dotvpn-wire/frame"
	"github.com/payam-foundation/dotvpn-wire/handshake"
	"github.com/payam-foundation/dotvpn-wire/mimic"
	"github.com/payam-foundation/dotvpn-wire/transport"
	"github.com/payam-foundation/dotvpn-wire/transport/muxstream"
)

// Endpoint kinds and parameters.
const (
	KindReverse transport.Kind = "reverse" // TCP, mimic knock
	KindDNS     transport.Kind = "dns"     // UDP, DNS-shaped

	ParamKnock = "knock" // base64 client knock key (reverse)
	ParamID    = "id"    // base64 node identity public key
	ParamNode  = "node"  // node id (dns)
	ParamZone  = "zone"  // DNS zone (dns)
)

// DefaultIdle is the cover-traffic interval on pooled connections.
const DefaultIdle = 25 * time.Second

// PoolKnockKey is the knock key of node->relay pool connections.
func PoolKnockKey(relay ed25519.PublicKey) []byte { return mimic.KnockKey("pool", relay) }

// ClientKnockKey is the knock key of client->relay connections for a node.
// It derives from public values only: it keeps scanners out, authentication
// is the node handshake behind it.
func ClientKnockKey(relay ed25519.PublicKey, nodeID string) []byte {
	return mimic.KnockKey("client "+nodeID, relay)
}

// WriteAuth sends the pool auth token (u16 length | token) to the relay.
func WriteAuth(w io.Writer, token string) error {
	if len(token) > 4096 {
		return errors.New("reverse: token too long")
	}
	b := binary.BigEndian.AppendUint16(nil, uint16(len(token)))
	_, err := w.Write(append(b, token...))
	return err
}

// ReadAuth reads and verifies a pool auth token, returning the node id.
func ReadAuth(r io.Reader, v *auth.Verifier) (string, error) {
	var n [2]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return "", err
	}
	l := int(binary.BigEndian.Uint16(n[:]))
	if l == 0 || l > 4096 {
		return "", errors.New("reverse: bad auth length")
	}
	b := make([]byte, l)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	c, err := v.VerifyAud(string(b), auth.AudPool)
	if err != nil {
		return "", err
	}
	return c.Sub, nil
}

// WriteNodeID and ReadNodeID frame the node id at the start of a DNS stream.
func WriteNodeID(w io.Writer, id string) error {
	if len(id) == 0 || len(id) > 255 {
		return errors.New("reverse: bad node id")
	}
	_, err := w.Write(append([]byte{byte(len(id))}, id...))
	return err
}

// ReadNodeID reads the length-prefixed (1 byte) node id a core sends after
// auth. The prefix bounds the read to 255 bytes.
func ReadNodeID(r io.Reader) (string, error) {
	var n [1]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return "", err
	}
	if n[0] == 0 {
		return "", errors.New("reverse: empty node id")
	}
	b := make([]byte, n[0])
	_, err := io.ReadFull(r, b)
	return string(b), err
}

// Dialer is the client side for Kind reverse and Kind dns.
type Dialer struct {
	Opts  transport.Options
	Frame frame.Opts
}

// Dial opens a session through a relay's reverse pool to the node named by
// ep.Params[ParamID].
func (d Dialer) Dial(ctx context.Context, ep transport.Endpoint, tok transport.TokenSource) (transport.Session, error) {
	id, err := decodeKey(ep.Params[ParamID])
	if err != nil {
		return nil, err
	}
	var raw net.Conn
	switch ep.Kind {
	case KindReverse:
		knock, err := base64.StdEncoding.DecodeString(ep.Params[ParamKnock])
		if err != nil || len(knock) == 0 {
			return nil, errors.New("reverse: bad knock key")
		}
		dctx, cancel := context.WithTimeout(ctx, d.Opts.Timeout())
		defer cancel()
		if raw, err = transport.DialTCP(dctx, ep.Addr, d.Opts); err != nil {
			return nil, err
		}
		if err = mimic.Dial(raw, ep.ServerName(), knock); err != nil {
			_ = raw.Close()
			return nil, err
		}
	case KindDNS:
		nd := net.Dialer{Timeout: d.Opts.Timeout(), Control: d.Opts.Control, Resolver: d.Opts.Resolver}
		raw, err = dnscarrier.Dial(ep.Addr, ep.Params[ParamZone], func(n, a string) (net.Conn, error) {
			return nd.DialContext(ctx, n, a)
		})
		if err != nil {
			return nil, err
		}
		if err = WriteNodeID(raw, ep.Params[ParamNode]); err != nil {
			_ = raw.Close()
			return nil, err
		}
	default:
		return nil, errors.New("reverse: unsupported endpoint kind")
	}
	fc, err := handshake.Initiate(raw, id, d.frameOpts())
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	x, err := muxstream.Client(fc)
	if err != nil {
		_ = fc.Close()
		return nil, err
	}
	return muxstream.NewSession(tok, x), nil
}

func (d Dialer) frameOpts() frame.Opts {
	o := d.Frame
	if o.Idle == 0 {
		o.Idle = DefaultIdle
	}
	return o
}

func decodeKey(s string) (ed25519.PublicKey, error) { return auth.DecodePublicKey(s) }

// Relay is one relay a node keeps a pool to.
type Relay struct {
	ID   string
	Addr string
	SNI  string
	Key  ed25519.PublicKey
}

// Pool is the node side (a transport.Listener): it dials the relays, parks
// authenticated idle connections, and serves a client when one arrives.
type Pool struct {
	Relays   func() []Relay
	Identity ed25519.PrivateKey
	// Token returns the current pool token (auth.AudPool, minted by control).
	Token func() string
	// Size is idle connections kept per relay. Default 4.
	Size int
	// MaxIdle is the mean time an idle connection is kept before it is
	// replaced; each is uniform in [MaxIdle/2, 3*MaxIdle/2]. Default 5m.
	MaxIdle time.Duration
	Opts    transport.Options
	Frame   frame.Opts
	Log     *slog.Logger
}

// Serve keeps Size tunnels to the relay, redialing with jitter, and serves
// streams arriving on them from b until ctx ends.
func (p *Pool) Serve(ctx context.Context, b transport.Backend) error {
	if p.Size == 0 {
		p.Size = 4
	}
	if p.MaxIdle == 0 {
		p.MaxIdle = 5 * time.Minute
	}
	if p.Log == nil {
		p.Log = slog.Default()
	}
	running := map[string]context.CancelFunc{}
	var wg sync.WaitGroup
	defer wg.Wait()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		want := map[string]Relay{}
		for _, r := range p.Relays() {
			want[r.ID+"|"+r.Addr] = r
		}
		for k, cancel := range running {
			if _, ok := want[k]; !ok {
				cancel()
				delete(running, k)
			}
		}
		for k, r := range want {
			if _, ok := running[k]; ok {
				continue
			}
			rctx, cancel := context.WithCancel(ctx)
			running[k] = cancel
			for range p.Size {
				wg.Add(1)
				go func() { defer wg.Done(); p.slot(rctx, r, b, &wg) }()
			}
		}
		select {
		case <-ctx.Done():
			for _, c := range running {
				c()
			}
			return nil
		case <-t.C:
		}
	}
}

func jitter(d time.Duration) time.Duration {
	return d/2 + time.Duration(rand.Int64N(int64(d)+1))
}

func sleep(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// slot keeps one pooled connection alive for r: connect, wait, serve, repeat.
// Once a client takes the connection a replacement slot starts at once, so
// the idle pool stays full while sessions run; this slot then ends with its
// session.
func (p *Pool) slot(ctx context.Context, r Relay, b transport.Backend, wg *sync.WaitGroup) {
	backoff := time.Second
	taken := func() {
		wg.Add(1)
		go func() { defer wg.Done(); p.slot(ctx, r, b, wg) }()
	}
	for ctx.Err() == nil {
		served, err := p.once(ctx, r, b, taken)
		if err != nil && ctx.Err() == nil {
			p.Log.Debug("pool connection ended", "relay", r.ID, "err", err)
		}
		if served {
			return
		}
		if !sleep(ctx, jitter(backoff)) {
			return
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (p *Pool) once(ctx context.Context, r Relay, b transport.Backend, taken func()) (served bool, err error) {
	dctx, cancel := context.WithTimeout(ctx, p.Opts.Timeout())
	raw, err := transport.DialTCP(dctx, r.Addr, p.Opts)
	cancel()
	if err != nil {
		return false, err
	}
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	if err := mimic.Dial(raw, r.SNI, PoolKnockKey(r.Key)); err != nil {
		return false, err
	}
	o := p.Frame
	if o.Idle == 0 {
		o.Idle = DefaultIdle
	}
	outer, err := handshake.Initiate(raw, r.Key, o)
	if err != nil {
		return false, err
	}
	if err := WriteAuth(outer, p.Token()); err != nil {
		return false, err
	}
	// Idle connections are replaced on a random schedule; once a client
	// arrives the timer is cancelled.
	idle := time.AfterFunc(jitter(p.MaxIdle), func() { _ = raw.Close() })
	inner, err := handshake.Respond(outer, p.Identity, o)
	if !idle.Stop() {
		return false, errors.New("idle rotation")
	}
	if err != nil {
		return false, err
	}
	taken()
	muxstream.Serve(b, inner)
	return true, nil
}
