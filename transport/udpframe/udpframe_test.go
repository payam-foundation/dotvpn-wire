package udpframe

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"
)

// Golden vector: the frame layout is part of the wire contract (ADR-018).
func TestGoldenFrame(t *testing.T) {
	got, err := Append(nil, []byte("hi!"))
	if err != nil {
		t.Fatal(err)
	}
	if h := hex.EncodeToString(got); h != "0003686921" {
		t.Fatalf("frame = %s", h)
	}
	if h := hex.EncodeToString(mustAppend(t, nil, nil)); h != "0000" {
		t.Fatalf("empty frame = %s", h)
	}
}

func mustAppend(t *testing.T, dst, p []byte) []byte {
	t.Helper()
	b, err := Append(dst, p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRoundTripAndLimits(t *testing.T) {
	var buf bytes.Buffer
	for _, p := range [][]byte{{}, []byte("a"), bytes.Repeat([]byte{7}, MaxPayload)} {
		buf.Write(mustAppend(t, nil, p))
	}
	b := make([]byte, MaxPayload)
	for _, want := range []int{0, 1, MaxPayload} {
		n, err := Read(&buf, b)
		if err != nil || n != want {
			t.Fatalf("read = %d, %v; want %d", n, err, want)
		}
	}
	if _, err := Read(&buf, b); err != io.EOF {
		t.Fatalf("end = %v", err)
	}
	if _, err := Append(nil, make([]byte, MaxPayload+1)); err != ErrTooLarge {
		t.Fatalf("oversize write = %v", err)
	}
	if _, err := Read(bytes.NewReader([]byte{0xff, 0xff}), b); err != ErrFrame {
		t.Fatalf("oversize frame = %v", err)
	}
	if _, err := Read(bytes.NewReader([]byte{0, 5, 1, 2}), b); err != io.ErrUnexpectedEOF {
		t.Fatalf("truncated = %v", err)
	}
}

// Conn keeps datagram boundaries across a stream.
func TestConnPreservesBoundaries(t *testing.T) {
	a, b := net.Pipe()
	ca, cb := NewConn(a), NewConn(b)
	defer ca.Close()
	defer cb.Close()
	go func() {
		_, _ = ca.Write([]byte("one"))
		_, _ = ca.Write([]byte("two22"))
	}()
	buf := make([]byte, 64)
	for _, want := range []string{"one", "two22"} {
		n, err := cb.Read(buf)
		if err != nil || string(buf[:n]) != want {
			t.Fatalf("got %q, %v; want %q", buf[:n], err, want)
		}
	}
	if _, err := ca.Write(make([]byte, MaxPayload+1)); err != ErrTooLarge {
		t.Fatalf("oversize = %v", err)
	}
}

// Relay moves datagrams both ways against a real UDP socket and ends when
// the stream closes.
func TestRelay(t *testing.T) {
	srv, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := srv.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = srv.WriteTo(append([]byte("echo:"), b[:n]...), from)
		}
	}()
	up, err := net.Dial("udp", srv.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	cs, ss := net.Pipe()
	finished := make(chan struct{})
	go func() { Relay(ss, up); close(finished) }()
	c := NewConn(cs)
	_ = cs.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "echo:ping" {
		t.Fatalf("got %q, %v", buf[:n], err)
	}
	_ = c.Close()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("Relay did not end after the stream closed")
	}
}

func FuzzUDPFrame(f *testing.F) {
	f.Add([]byte{0, 3, 'a', 'b', 'c'})
	f.Add([]byte{0xff, 0xff})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, in []byte) {
		r := bytes.NewReader(in)
		buf := make([]byte, MaxPayload)
		for {
			n, err := Read(r, buf)
			if err != nil {
				return
			}
			fr, err := Append(nil, buf[:n])
			if err != nil || len(fr) != n+2 {
				t.Fatalf("re-encode: %v len %d for %d", err, len(fr), n)
			}
		}
	})
}
