package dnscarrier

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCodec(t *testing.T) {
	p := bytes.Repeat([]byte{0xAB, 0x01}, 50)
	q, err := EncodeQuery("t.example.com", p)
	if err != nil {
		t.Fatal(err)
	}
	got, m, err := DecodeQuery("t.example.com", q)
	if err != nil || !bytes.Equal(got, p) {
		t.Fatal(err)
	}
	down := bytes.Repeat([]byte{7}, 700)
	a, err := EncodeAnswer(m, down)
	if err != nil {
		t.Fatal(err)
	}
	d, err := DecodeAnswer(a)
	if err != nil || !bytes.Equal(d, down) {
		t.Fatal(err)
	}
	// The query must be a plain, valid DNS message.
	var x dns.Msg
	if err := x.Unpack(q); err != nil || x.Question[0].Qtype != dns.TypeTXT {
		t.Fatal("not a TXT query")
	}
	if _, _, err := DecodeQuery("other.org", q); err == nil {
		t.Fatal("foreign zone accepted")
	}
}

func TestStream(t *testing.T) {
	PollEvery = 5 * time.Millisecond
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := Listen(pc, "t.example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		_, _ = io.Copy(c, c)
	}()
	c, err := Dial(pc.LocalAddr().String(), "t.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	msg := bytes.Repeat([]byte("dns!"), 500)
	go c.Write(msg)
	got := make([]byte, len(msg))
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("echo over DNS carrier: %v", err)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, b []byte) {
		DecodeQuery("z.example", b)
		DecodeAnswer(b)
	})
}

// TestDownstreamThroughput guards the server-side KCP MTU: answers carry up to
// MaxDown bytes, so a bulk download must not crawl at the query size.
func TestDownstreamThroughput(t *testing.T) {
	PollEvery = 5 * time.Millisecond
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := Listen(pc, "t.example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	const size = 100 << 10
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 1)
		_, _ = c.Read(buf) // wait for the client's first byte, then push
		_, _ = c.Write(bytes.Repeat([]byte{'x'}, size))
	}()
	c, err := Dial(pc.LocalAddr().String(), "t.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte{1})
	start := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.ReadFull(c, make([]byte, size)); err != nil {
		t.Fatal(err)
	}
	// 5 ms polls at 96 B per answer need about 5 s; at ~700 B well under 1.5 s.
	if d := time.Since(start); d > 2500*time.Millisecond {
		t.Fatalf("100 KiB download took %v", d)
	}
}
