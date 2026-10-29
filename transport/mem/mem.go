// Package mem is the in-memory carrier for tests: a Dialer and a Listener
// joined by net.Pipe, with the same stream layer (muxstream) as the real byte
// pipe carriers.
package mem

import (
	"context"
	"errors"
	"net"

	"github.com/payam-foundation/dotvpn-wire/transport"
	"github.com/payam-foundation/dotvpn-wire/transport/muxstream"
)

// Net is one in-memory network.
type Net struct{ ch chan net.Conn }

// New returns an empty in-memory network.
func New() *Net { return &Net{ch: make(chan net.Conn)} }

// Dialer implements transport.Dialer; the Endpoint is ignored.
func (n *Net) Dialer() transport.Dialer { return dialer{n} }

type dialer struct{ n *Net }

func (d dialer) Dial(ctx context.Context, _ transport.Endpoint, tok transport.TokenSource) (transport.Session, error) {
	a, b := net.Pipe()
	select {
	case d.n.ch <- b:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	x, err := muxstream.Client(a)
	if err != nil {
		return nil, err
	}
	return muxstream.NewSession(tok, x), nil
}

// Listener implements transport.Listener.
func (n *Net) Listener() transport.Listener { return listener{n} }

type listener struct{ n *Net }

func (l listener) Serve(ctx context.Context, b transport.Backend) error {
	for {
		select {
		case c := <-l.n.ch:
			go muxstream.Serve(b, c)
		case <-ctx.Done():
			return errors.Join(ctx.Err())
		}
	}
}
