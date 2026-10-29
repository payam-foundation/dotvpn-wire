// Package mimic is the carrier whose first bytes are a real Chrome ClientHello
// (uTLS) with the authentication "knock" hidden in the two fields that are
// random on the wire anyway: the 32 byte client random and the 32 byte legacy
// session ID.
//
//	random    = 32 random bytes
//	sessionID = HMAC-SHA256(knockKey, random | minute)
//
// A server that does not see a valid knock must treat the connection as an
// ordinary visitor and hand it to the decoy (Server.Fallback) with every byte
// read so far replayed, so probes see the real site. After a valid knock the
// two ends run package handshake on the same TCP stream.
package mimic

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// recordHead is the TLS record header (5), handshake header (4), version (2),
// random (32), session-id length (1) and session id (32).
const (
	helloPrefix = 5 + 4 + 2 + 32 + 1 + 32
	offRandom   = 11
	offSID      = 44
)

// KnockKey derives a knock key from a label and secret material.
func KnockKey(label string, material []byte) []byte {
	h := hmac.New(sha256.New, []byte("dotvpn-wire/1 knock "+label))
	h.Write(material)
	return h.Sum(nil)
}

func tag(key, random []byte, minute int64) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(random)
	_ = binary.Write(h, binary.BigEndian, minute)
	return h.Sum(nil)
}

// Hello returns the bytes of a Chrome ClientHello record for sni carrying a
// knock for key. alpn nil keeps Chrome's default (h2, http/1.1).
func Hello(c net.Conn, sni string, key []byte, now time.Time) ([]byte, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_133)
	if err != nil {
		return nil, err
	}
	ChromeCurrent(&spec)
	u := utls.UClient(c, &utls.Config{ServerName: sni}, utls.HelloCustom)
	if err := u.ApplyPreset(&spec); err != nil {
		return nil, err
	}
	random := make([]byte, 32)
	_, _ = rand.Read(random)
	u.HandshakeState.Hello.Random = random
	u.HandshakeState.Hello.SessionId = tag(key, random, now.Unix()/60)
	if err := u.MarshalClientHello(); err != nil {
		return nil, err
	}
	raw := u.HandshakeState.Hello.Raw
	rec := append([]byte{0x16, 0x03, 0x01, byte(len(raw) >> 8), byte(len(raw))}, raw...)
	return rec, nil
}

// ChromeCurrent brings the utls Chrome 133 preset up to what Chrome 156 sends
// (measured against the real browser with dotvpn-lab/cmd/fpcheck): extension
// 51764 with a constant body, and the three extra signature schemes
// 0x0904-0x0906. Without them the JA4 differs from every real Chrome.
// DialTLS applies it too, so every carrier presents the same hello.
// ponytail: tracks one Chrome release; re-measure and update when the preset
// or browsers move on (fpcheck prints both sides).
func ChromeCurrent(spec *utls.ClientHelloSpec) {
	have := false
	for _, e := range spec.Extensions {
		switch x := e.(type) {
		case *utls.GenericExtension:
			have = have || x.Id == 51764
		case *utls.SignatureAlgorithmsExtension:
			if !slices.Contains(x.SupportedSignatureAlgorithms, 0x0904) {
				x.SupportedSignatureAlgorithms = append([]utls.SignatureScheme{0x0904, 0x0905, 0x0906}, x.SupportedSignatureAlgorithms...)
			}
		}
	}
	if !have {
		spec.Extensions = append(spec.Extensions, &utls.GenericExtension{Id: 51764, Data: trustAnchors})
	}
}

// trustAnchors is the constant body Chrome 156 sends in extension 51764.
var trustAnchors = mustHex("00b80582df1302010582df1302060582df13020d0582df13020e0582df13020f0582df1302120582df1302130582df13021408839a648c9b2d010708839a648c9b2d010808839a648c9b2d010908839a648c9b2d010a08839a648c9b2d010b08839a648c9b2d010c08839a648c9b2d010d08839a648c9b2d011208839a648c9b2d011304d679090104d679090404d679090504d679090604d679090704d679090804d679090a04d679090b04d679090c04d679090d04d679090f")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Dial sends the knock hello on c. The caller continues with
// handshake.Initiate on c.
func Dial(c net.Conn, sni string, key []byte) error {
	h, err := Hello(c, sni, key, time.Now())
	if err != nil {
		return err
	}
	_, err = c.Write(h)
	return err
}

// ParseKnock reports whether prefix (at least helloPrefix bytes) is a
// ClientHello carrying a valid knock for key within one minute of now.
func ParseKnock(prefix, key []byte, now time.Time) (random []byte, ok bool) {
	if len(prefix) < helloPrefix || prefix[0] != 0x16 || prefix[1] != 0x03 || prefix[5] != 0x01 || prefix[43] != 32 {
		return nil, false
	}
	random = prefix[offRandom : offRandom+32]
	sid := prefix[offSID : offSID+32]
	m := now.Unix() / 60
	good := false
	for _, d := range []int64{0, -1, 1} { // constant work, no early exit
		if hmac.Equal(sid, tag(key, random, m+d)) {
			good = true
		}
	}
	return random, good
}

// plausible reports whether b can still be the start of a TLS handshake
// record, so junk (HTTP, SSH, random bytes) is sent to the decoy at once.
func plausible(b []byte) bool {
	if len(b) > 0 && b[0] != 0x16 {
		return false
	}
	if len(b) > 1 && b[1] != 0x03 {
		return false
	}
	if len(b) > 5 && b[5] != 0x01 {
		return false
	}
	return true
}

// Server classifies inbound connections.
type Server struct {
	// Keys are the accepted knock keys; the index of the matching key is
	// returned by Classify.
	Keys [][]byte
	// KeysFn, when set, supplies the accepted keys per connection instead of
	// Keys (a relay accepts a key per node that currently has a pool).
	KeysFn func() [][]byte
	// Wait is how long a slow, plausible hello is waited for before the bytes
	// are given to the decoy anyway. Default 3s.
	Wait time.Duration
	Now  func() time.Time

	mu   sync.Mutex
	seen map[[32]byte]time.Time
}

// PrefixConn replays buffered bytes before reading from the embedded conn.
type PrefixConn struct {
	net.Conn
	Buf []byte
}

// Read serves the bytes already consumed while parsing, then the connection.
func (p *PrefixConn) Read(b []byte) (int, error) {
	if len(p.Buf) > 0 {
		n := copy(b, p.Buf)
		p.Buf = p.Buf[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// replayed records random and reports whether it was already used. The cache
// is bounded: entries older than two minutes are dropped and growth is capped.
func (s *Server) replayed(random []byte, now time.Time) bool {
	var k [32]byte
	copy(k[:], random)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen == nil {
		s.seen = map[[32]byte]time.Time{}
	}
	if len(s.seen) > 1<<16 {
		for x, t := range s.seen {
			if now.Sub(t) > 2*time.Minute {
				delete(s.seen, x)
			}
		}
		if len(s.seen) > 1<<16 {
			return true // fail closed to the decoy under flood
		}
	}
	if _, ok := s.seen[k]; ok {
		return true
	}
	s.seen[k] = now
	return false
}

// Classify reads the start of c. If it is a fresh, valid knock for Keys[i] it
// returns i and a conn positioned right after the hello, with ok true. In
// every other case ok is false and the returned conn replays all bytes read,
// ready to be proxied to the decoy; the caller must not write to c first.
func (s *Server) Classify(c net.Conn) (idx int, out net.Conn, ok bool) {
	_, idx, out, ok = s.classify(c)
	return idx, out, ok
}

// ClassifyKey is Classify that returns the matching key itself, which stays
// meaningful when KeysFn changes between connections.
func (s *Server) ClassifyKey(c net.Conn) (key []byte, out net.Conn, ok bool) {
	key, _, out, ok = s.classify(c)
	return key, out, ok
}

func (s *Server) classify(c net.Conn) (key []byte, idx int, out net.Conn, ok bool) {
	keys := s.Keys
	if s.KeysFn != nil {
		keys = s.KeysFn()
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	wait := s.Wait
	if wait == 0 {
		wait = 3 * time.Second
	}
	buf := make([]byte, 0, 2048)
	deadline := time.Now().Add(wait)
	for len(buf) < helloPrefix {
		_ = c.SetReadDeadline(deadline)
		var tmp [helloPrefix]byte
		n, err := c.Read(tmp[:helloPrefix-len(buf)])
		buf = append(buf, tmp[:n]...)
		if !plausible(buf) || err != nil {
			_ = c.SetReadDeadline(time.Time{})
			return nil, -1, &PrefixConn{Conn: c, Buf: buf}, false
		}
	}
	_ = c.SetReadDeadline(time.Time{})
	t := now()
	for i, k := range keys {
		if random, good := ParseKnock(buf, k, t); good {
			if s.replayed(random, t) {
				break
			}
			// Consume the rest of the hello record; it is the Chrome hello.
			rl := int(binary.BigEndian.Uint16(buf[3:5]))
			rest := rl + 5 - len(buf)
			if rl > 1<<14 || rest < 0 {
				break
			}
			_ = c.SetReadDeadline(time.Now().Add(wait))
			if _, err := io.CopyN(io.Discard, c, int64(rest)); err != nil {
				return nil, -1, &PrefixConn{Conn: c, Buf: buf}, false
			}
			_ = c.SetReadDeadline(time.Time{})
			return k, i, c, true
		}
	}
	return nil, -1, &PrefixConn{Conn: c, Buf: buf}, false
}

// ErrNoKnock means the connection did not start with a valid knock; the
// caller hands it to the decoy instead of closing.
var ErrNoKnock = errors.New("mimic: no valid knock")
