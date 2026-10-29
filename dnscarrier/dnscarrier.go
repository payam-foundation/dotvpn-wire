// Package dnscarrier shapes datagrams as DNS. Upstream, a payload becomes the
// base32 labels of a TXT query under Zone; downstream, the answer to that
// query is a TXT record holding the payload. A KCP session on top (Dial,
// Listen) gives a reliable byte stream for the frame layer, so the carrier is
// usable where only UDP/53-looking traffic passes. The server polls are driven
// by the client: it sends an empty query every PollEvery while idle.
//
// This is shaping, not a resolver chain: it talks to the carrier server
// directly. Statistically it is distinguishable from real DNS (see REPORT.md).
package dnscarrier

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/xtaci/kcp-go/v5"
)

// MaxUp is the largest upstream payload per query.
const MaxUp = 100

// MaxDown is the largest downstream payload per answer.
const MaxDown = 700

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// ErrNotCarrier marks a packet that is not carrier traffic; the DNS server
// answers it like an ordinary resolver would.
var ErrNotCarrier = errors.New("dnscarrier: not a carrier packet")

func nonce() string {
	var b [3]byte
	_, _ = rand.Read(b[:])
	return strings.ToLower(b32.EncodeToString(b[:]))
}

// EncodeQuery builds the wire bytes of a query carrying payload under zone.
func EncodeQuery(zone string, payload []byte) ([]byte, error) {
	if len(payload) > MaxUp {
		return nil, errors.New("dnscarrier: payload too large")
	}
	enc := strings.ToLower(b32.EncodeToString(payload))
	var labels []string
	for len(enc) > 0 {
		n := min(len(enc), 50)
		labels = append(labels, enc[:n])
		enc = enc[n:]
	}
	labels = append(labels, nonce())
	name := dns.Fqdn(strings.Join(labels, ".") + "." + zone)
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeTXT)
	m.RecursionDesired = true
	return m.Pack()
}

// DecodeQuery extracts the payload and message for the answer.
func DecodeQuery(zone string, b []byte) ([]byte, *dns.Msg, error) {
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil || m.Response || len(m.Question) != 1 || m.Question[0].Qtype != dns.TypeTXT {
		return nil, nil, ErrNotCarrier
	}
	name := strings.ToLower(m.Question[0].Name)
	suffix := "." + strings.ToLower(dns.Fqdn(zone))
	if !strings.HasSuffix(name, suffix) {
		return nil, nil, ErrNotCarrier
	}
	labels := strings.Split(strings.TrimSuffix(name, suffix), ".")
	if len(labels) < 1 {
		return nil, nil, ErrNotCarrier
	}
	data := strings.ToUpper(strings.Join(labels[:len(labels)-1], ""))
	p, err := b32.DecodeString(data)
	if err != nil {
		return nil, nil, ErrNotCarrier
	}
	return p, m, nil
}

// EncodeAnswer builds the response to q carrying payload.
func EncodeAnswer(q *dns.Msg, payload []byte) ([]byte, error) {
	if len(payload) > MaxDown {
		return nil, errors.New("dnscarrier: payload too large")
	}
	r := new(dns.Msg)
	r.SetReply(q)
	r.RecursionAvailable = true
	// TXT strings are escaped text in the DNS library, so ship base64.
	enc := base64.RawStdEncoding.EncodeToString(payload)
	var txt []string
	for i := 0; i < len(enc); i += 255 {
		txt = append(txt, enc[i:min(i+255, len(enc))])
	}
	if len(txt) == 0 {
		txt = []string{""}
	}
	r.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: txt}}
	return r.Pack()
}

// DecodeAnswer extracts the payload of a response.
func DecodeAnswer(b []byte) ([]byte, error) {
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil || !m.Response || len(m.Answer) != 1 {
		return nil, ErrNotCarrier
	}
	t, ok := m.Answer[0].(*dns.TXT)
	if !ok {
		return nil, ErrNotCarrier
	}
	p, err := base64.RawStdEncoding.DecodeString(strings.Join(t.Txt, ""))
	if err != nil {
		return nil, ErrNotCarrier
	}
	return p, nil
}

// fakeRemote is the address KCP believes it talks to; the real peer is the
// connected UDP socket, so any stable value works.
var fakeRemote = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}

// clientPC is the client's net.PacketConn: WriteTo wraps, ReadFrom unwraps.
type clientPC struct {
	conn net.Conn
	zone string
	poll time.Duration

	mu       sync.Mutex
	lastSent time.Time
	done     chan struct{}
	once     sync.Once
}

// PollEvery is the idle polling interval of a client.
var PollEvery = 40 * time.Millisecond

func newClientPC(conn net.Conn, zone string) *clientPC {
	c := &clientPC{conn: conn, zone: zone, poll: PollEvery, done: make(chan struct{})}
	go func() {
		for {
			select {
			case <-c.done:
				return
			case <-time.After(c.poll):
			}
			c.mu.Lock()
			idle := time.Since(c.lastSent) >= c.poll
			c.mu.Unlock()
			if idle {
				_, _ = c.WriteTo(nil, nil)
			}
		}
	}()
	return c
}

func (c *clientPC) WriteTo(p []byte, _ net.Addr) (int, error) {
	q, err := EncodeQuery(c.zone, p)
	if err != nil {
		return 0, err
	}
	c.mu.Lock()
	c.lastSent = time.Now()
	c.mu.Unlock()
	if _, err := c.conn.Write(q); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *clientPC) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, 2048)
	for {
		n, err := c.conn.Read(buf)
		if err != nil {
			return 0, nil, err
		}
		pl, err := DecodeAnswer(buf[:n])
		if err != nil || len(pl) == 0 {
			continue
		}
		return copy(p, pl), fakeRemote, nil
	}
}

func (c *clientPC) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.conn.Close()
}
func (c *clientPC) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *clientPC) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *clientPC) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *clientPC) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// serverPC is the server's net.PacketConn over a UDP socket.
type serverPC struct {
	pc   net.PacketConn
	zone string

	mu    sync.Mutex
	queue map[string][][]byte
}

func (s *serverPC) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, 2048)
	for {
		n, addr, err := s.pc.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		pl, q, err := DecodeQuery(s.zone, buf[:n])
		if err != nil {
			// Not ours: answer NXDOMAIN like a server that does not own the name.
			var m dns.Msg
			if m.Unpack(buf[:n]) == nil && !m.Response {
				r := new(dns.Msg)
				r.SetRcode(&m, dns.RcodeNameError)
				if b, e := r.Pack(); e == nil {
					_, _ = s.pc.WriteTo(b, addr)
				}
			}
			continue
		}
		var down []byte
		s.mu.Lock()
		if qq := s.queue[addr.String()]; len(qq) > 0 {
			down, s.queue[addr.String()] = qq[0], qq[1:]
		}
		s.mu.Unlock()
		if a, err := EncodeAnswer(q, down); err == nil {
			_, _ = s.pc.WriteTo(a, addr)
		}
		if len(pl) == 0 {
			continue
		}
		return copy(p, pl), addr, nil
	}
}

func (s *serverPC) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) > MaxDown {
		return 0, errors.New("dnscarrier: payload too large")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := addr.String()
	if len(s.queue[k]) > 256 {
		return len(p), nil // drop; KCP retransmits
	}
	s.queue[k] = append(s.queue[k], append([]byte(nil), p...))
	return len(p), nil
}

func (s *serverPC) Close() error                       { return s.pc.Close() }
func (s *serverPC) LocalAddr() net.Addr                { return s.pc.LocalAddr() }
func (s *serverPC) SetDeadline(t time.Time) error      { return s.pc.SetDeadline(t) }
func (s *serverPC) SetReadDeadline(t time.Time) error  { return s.pc.SetReadDeadline(t) }
func (s *serverPC) SetWriteDeadline(t time.Time) error { return s.pc.SetWriteDeadline(t) }

// tune sets KCP for one direction. mtu is the largest segment this side sends:
// a client sends in queries (MaxUp), a server in answers (MaxDown). A server
// capped at the query size moves one 96-byte segment per poll.
func tune(s *kcp.UDPSession, mtu int) {
	// KCP stream framing is part of the carrier wire format; deprecation is advisory.
	s.SetStreamMode(true)
	s.SetNoDelay(1, 20, 2, 1)
	s.SetMtu(mtu)
	s.SetWindowSize(128, 128)
}

// Dial opens a reliable stream to a carrier server at addr (host:port) over
// UDP. dial lets the caller bind the socket (bypass); nil uses net.Dial.
func Dial(addr, zone string, dial func(network, addr string) (net.Conn, error)) (net.Conn, error) {
	if dial == nil {
		dial = net.Dial
	}
	c, err := dial("udp", addr)
	if err != nil {
		return nil, err
	}
	pc := newClientPC(c, zone)
	s, err := kcp.NewConn2(fakeRemote, nil, 0, 0, pc)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	tune(s, MaxUp-4)
	return &closer{Conn: s, pc: pc}, nil
}

type closer struct {
	net.Conn
	pc net.PacketConn
}

func (c *closer) Close() error { _ = c.Conn.Close(); return c.pc.Close() }

// Listener accepts reliable streams from carrier clients.
type Listener struct{ l *kcp.Listener }

// Listen serves zone on pc.
func Listen(pc net.PacketConn, zone string) (*Listener, error) {
	l, err := kcp.ServeConn(nil, 0, 0, &serverPC{pc: pc, zone: zone, queue: map[string][][]byte{}})
	if err != nil {
		return nil, err
	}
	return &Listener{l}, nil
}

// Accept returns the next KCP session, tuned for the answer-size budget.
func (l *Listener) Accept() (net.Conn, error) {
	s, err := l.l.AcceptKCP()
	if err != nil {
		return nil, err
	}
	tune(s, MaxDown-4)
	return s, nil
}

// Close stops the listener.
func (l *Listener) Close() error { return l.l.Close() }

// Addr is the local UDP address.
func (l *Listener) Addr() net.Addr { return l.l.Addr() }
