package mem

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/payam-foundation/dotvpn-wire/transport"
)

// udpBackend echoes each datagram with a prefix and records the authority.
type udpBackend struct {
	backend
	got chan string
}

func (b udpBackend) DialUDP(_ context.Context, _ transport.User, authority string) (net.Conn, error) {
	b.got <- authority
	a, c := net.Pipe()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := a.Read(buf)
			if err != nil {
				return
			}
			if _, err := a.Write(append([]byte("e:"), buf[:n]...)); err != nil {
				return
			}
		}
	}()
	return c, nil
}

func TestUDPFlowOverMux(t *testing.T) {
	n := New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := udpBackend{got: make(chan string, 1)}
	go n.Listener().Serve(ctx, b)
	s, err := n.Dialer().Dial(ctx, transport.Endpoint{}, func() string { return "good" })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	us, ok := s.(transport.UDPSession)
	if !ok {
		t.Fatal("mux session must implement UDPSession")
	}
	c, err := us.OpenUDP(ctx, "9.9.9.9:53")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if a := <-b.got; a != "9.9.9.9:53" {
		t.Fatalf("authority = %q", a)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second)) // mux streams honour it
	for _, m := range []string{"a", "bb"} {
		if _, err := c.Write([]byte(m)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		k, err := c.Read(buf)
		if err != nil || string(buf[:k]) != "e:"+m {
			t.Fatalf("got %q, %v", buf[:k], err)
		}
	}
}

// A node whose Backend has no UDP support refuses the flow instead of
// splicing it as TCP, and a bad token is still 407.
func TestUDPRefusedWithoutBackendSupport(t *testing.T) {
	n := New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Listener().Serve(ctx, backend{})
	for tok, want := range map[string]error{"good": transport.ErrForbidden, "bad": transport.ErrUnauthorized} {
		s, err := n.Dialer().Dial(ctx, transport.Endpoint{}, func() string { return tok })
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.(transport.UDPSession).OpenUDP(ctx, "9.9.9.9:53"); !errors.Is(err, want) {
			t.Fatalf("token %q: %v, want %v", tok, err, want)
		}
		_ = s.Close()
	}
}
