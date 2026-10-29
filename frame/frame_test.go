package frame

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"
)

func pair(t *testing.T, o Opts) (*Conn, *Conn) {
	t.Helper()
	a, b := net.Pipe()
	var k Keys
	for i := range 32 {
		k.SendKey[i], k.RecvKey[i], k.SendMask[i], k.RecvMask[i] = byte(i), byte(100+i), byte(50+i), byte(150+i)
	}
	sw := Keys{SendKey: k.RecvKey, RecvKey: k.SendKey, SendMask: k.RecvMask, RecvMask: k.SendMask}
	return New(a, k, o), New(b, sw, o)
}

func TestRoundTripLarge(t *testing.T) {
	a, b := pair(t, Opts{})
	msg := bytes.Repeat([]byte("dotvpn"), 20000) // > MaxData, several records
	go func() { _, _ = a.Write(msg); _ = a.Close() }()
	got, err := io.ReadAll(b)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("round trip: err=%v len=%d want=%d", err, len(got), len(msg))
	}
}

// capture records what a carrier sees.
type capture struct {
	net.Conn
	buf bytes.Buffer
}

func (c *capture) Write(p []byte) (int, error) { c.buf.Write(p); return c.Conn.Write(p) }

func TestWireImage(t *testing.T) {
	// Fresh session keys per run: no header byte may be constant.
	var seen [2]map[byte]int
	seen[0], seen[1] = map[byte]int{}, map[byte]int{}
	for range 128 {
		x, y := net.Pipe()
		cap := &capture{Conn: x}
		var k Keys
		_, _ = rand.Read(k.SendKey[:])
		_, _ = rand.Read(k.SendMask[:])
		a := New(cap, k, Opts{})
		go io.Copy(io.Discard, y)
		_, _ = a.Write([]byte("hello"))
		w := cap.buf.Bytes()
		seen[0][w[0]]++
		seen[1][w[1]]++
	}
	for i, m := range seen {
		if len(m) < 16 {
			t.Fatalf("header byte %d has only %d distinct values over 128 sessions", i, len(m))
		}
	}
}

func TestTamperClosesConn(t *testing.T) {
	x, y := net.Pipe()
	var k Keys
	_, _ = rand.Read(k.SendKey[:])
	cap := &capture{Conn: x}
	a := New(cap, k, Opts{})
	b := New(y, Keys{RecvKey: k.SendKey, RecvMask: k.SendMask}, Opts{})
	go func() { _, _ = a.Write([]byte("secret")) }()
	buf := make([]byte, 64)
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := b.Read(buf); err != nil || string(buf[:n]) != "secret" {
		t.Fatalf("clean record: %v", err)
	}
	// Second record with one flipped ciphertext bit.
	x2, y2 := net.Pipe()
	cap2 := &capture{Conn: x2}
	a2 := New(cap2, k, Opts{})
	go io.Copy(io.Discard, y2)
	_, _ = a2.Write([]byte("secret"))
	w := append([]byte(nil), cap2.buf.Bytes()...)
	w[len(w)-1] ^= 1
	p, q := net.Pipe()
	b2 := New(q, Keys{RecvKey: k.SendKey, RecvMask: k.SendMask}, Opts{})
	go func() { _, _ = p.Write(w) }()
	_ = b2.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := b2.Read(buf); err == nil {
		t.Fatal("forged record accepted")
	}
}

func TestIdleCover(t *testing.T) {
	x, y := net.Pipe()
	cap := &capture{Conn: x}
	a := New(cap, Keys{}, Opts{Idle: 20 * time.Millisecond})
	go io.Copy(io.Discard, y)
	time.Sleep(300 * time.Millisecond)
	_ = a.Close()
	if cap.buf.Len() == 0 {
		t.Fatal("no cover records while idle")
	}
}

// Golden vector: the exact bytes of the first record for fixed keys. Every
// repo that vendors the wire runs this; changing it is a wire version bump.
func TestGoldenRecord(t *testing.T) {
	x, y := net.Pipe()
	cap := &capture{Conn: x}
	var k Keys
	for i := range 32 {
		k.SendKey[i], k.SendMask[i] = byte(i), byte(0xA0+i)
	}
	a := New(cap, k, Opts{Pad: func(int) int { return 5 }})
	go io.Copy(io.Discard, y)
	_, _ = a.Write([]byte("golden"))
	const want = "e9270ebcb3b9da40e7d866a8a935182c287238f79395aff983b152d5f2c61c88"
	got := hex.EncodeToString(cap.buf.Bytes())
	if got != want {
		t.Fatalf("wire image changed:\n got %s\nwant %s", got, want)
	}
}

func FuzzRead(f *testing.F) {
	f.Add([]byte{0, 30, 1, 2, 3})
	f.Fuzz(func(t *testing.T, b []byte) {
		x, y := net.Pipe()
		c := New(y, Keys{}, Opts{})
		go func() { _, _ = x.Write(b); _ = x.Close() }()
		_ = y.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = io.ReadAll(c)
	})
}
