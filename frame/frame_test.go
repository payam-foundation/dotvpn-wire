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

func TestQuantizeBuckets(t *testing.T) {
	ok := map[int]bool{}
	for _, b := range buckets {
		ok[b] = true
	}
	for n := 0; n <= MaxData; n++ {
		pad := Quantize(n)
		if pad < 0 || pad > maxPad {
			t.Fatalf("Quantize(%d) = %d out of range", n, pad)
		}
		if size := overhead + n + pad; !ok[size] {
			t.Fatalf("n=%d: wire size %d is not a bucket", n, size)
		}
	}
}

// A shaped writer's records are exactly bucket sized on the wire and an
// unshaped reader still recovers the data.
func TestQuantizeRoundTrip(t *testing.T) {
	x, y := net.Pipe()
	cap := &capture{Conn: x}
	var k Keys
	r := Keys{SendKey: k.RecvKey, RecvKey: k.SendKey}
	a, b := New(cap, k, Opts{Pad: Quantize}), New(y, r, Opts{})
	msg := bytes.Repeat([]byte("x"), 700)
	go func() { _, _ = a.Write(msg) }()
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(b, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("round trip: %v", err)
	}
	if n := cap.buf.Len(); n != 1400 {
		t.Fatalf("wire bytes = %d, want 1400", n)
	}
}

func FuzzQuantize(f *testing.F) {
	f.Add(0)
	f.Add(107)
	f.Add(MaxData)
	f.Fuzz(func(t *testing.T, n int) {
		n = min(max(n, 0), MaxData)
		if size := overhead + n + Quantize(n); size < overhead+n || size > buckets[len(buckets)-1] {
			t.Fatalf("n=%d size=%d", n, size)
		}
	})
}

// Measured wire cost of shaping against the default padding. Bulk writes fill
// records and cost almost nothing; interactive traffic pays for the buckets.
func TestShapingOverhead(t *testing.T) {
	wire := func(o Opts, sizes []int) (data, sent int) {
		x, y := net.Pipe()
		cap := &capture{Conn: x}
		var k Keys
		a := New(cap, k, o)
		go func() { _, _ = io.Copy(io.Discard, y) }()
		for _, n := range sizes {
			if _, err := a.Write(make([]byte, n)); err != nil {
				t.Fatal(err)
			}
			data += n
		}
		_ = a.Close()
		return data, cap.buf.Len()
	}
	bulk := make([]int, 200)
	for i := range bulk {
		bulk[i] = 64 << 10 // fills MaxData records, with a short tail each
	}
	var interactive []int
	for i := range 400 {
		interactive = append(interactive, []int{40, 90, 160, 300, 620, 1200}[i%6])
	}
	for _, c := range []struct {
		name  string
		sizes []int
		max   float64 // shaped wire bytes / default wire bytes
	}{{"bulk", bulk, 1.30}, {"interactive", interactive, 3.0}} {
		d, base := wire(Opts{}, c.sizes)
		_, shaped := wire(Opts{Pad: Quantize}, c.sizes)
		r := float64(shaped) / float64(base)
		t.Logf("%s: data %d, default wire %d (%.2fx data), shaped wire %d (%.2fx data), shaped/default %.2fx",
			c.name, d, base, float64(base)/float64(d), shaped, float64(shaped)/float64(d), r)
		if r > c.max {
			t.Errorf("%s: shaping costs %.2fx the default wire size, budget %.2fx", c.name, r, c.max)
		}
	}
}
