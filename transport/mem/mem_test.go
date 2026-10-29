package mem

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/payam-foundation/dotvpn-wire/transport"
)

type backend struct{}

func (backend) Authenticate(tok string) (transport.User, error) {
	if tok != "good" {
		return transport.User{}, transport.ErrUnauthorized
	}
	return transport.User{ID: "u"}, nil
}

func (backend) Dial(_ context.Context, _ transport.User, _ string) (net.Conn, error) {
	a, b := net.Pipe()
	go func() { _, _ = io.Copy(a, a) }()
	return b, nil
}

func TestSeam(t *testing.T) {
	n := New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Listener().Serve(ctx, backend{})
	for tok, wantErr := range map[string]bool{"good": false, "bad": true} {
		s, err := n.Dialer().Dial(ctx, transport.Endpoint{}, func() string { return tok })
		if err != nil {
			t.Fatal(err)
		}
		c, err := s.OpenStream(ctx, "example.com:443")
		if (err != nil) != wantErr {
			t.Fatalf("token %q: err=%v", tok, err)
		}
		if err == nil {
			_, _ = c.Write([]byte("x"))
			b := make([]byte, 1)
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := io.ReadFull(c, b); err != nil {
				t.Fatal(err)
			}
		}
		_ = s.Close()
	}
}
