// Package snowflake is the last-resort carrier for blackouts: the client
// reaches the node through WebRTC volunteer proxies matched by our own broker.
// The node embeds Tor's snowflake server; every accepted snowflake stream
// carries one muxstream session.
//
// Tor's public proxy pool only relays to Tor bridges, so capacity is whatever
// proxies we or supporters run (`dotvpn proxy`).
package snowflake

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"

	sfclient "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/client/lib"
	sfserver "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/server/lib"

	"github.com/payam-foundation/dotvpn-wire/transport"
	"github.com/payam-foundation/dotvpn-wire/transport/muxstream"
)

// DefaultICE is used when an endpoint does not list STUN servers.
const DefaultICE = "stun:stun.l.google.com:19302"

// Endpoint Params understood by the Dialer.
const (
	ParamBroker = "broker" // broker base URL (required)
	ParamFront  = "front"  // optional comma separated domain fronts for the broker
	ParamICE    = "ice"    // optional comma separated STUN URLs
	// ParamLocal ("1") keeps local addresses in SDP; for tests and LANs only.
	ParamLocal = "local"
)

// Dialer implements transport.Dialer for Kind snowflake.
type Dialer struct{ Opts transport.Options }

// Dial opens a session to ep using snowflake: reaches the node through a volunteer proxy found via the broker. The token is fetched per stream.
func (d Dialer) Dial(ctx context.Context, ep transport.Endpoint, tok transport.TokenSource) (transport.Session, error) {
	broker := ep.Params[ParamBroker]
	if broker == "" {
		return nil, errors.New("snowflake: endpoint has no broker")
	}
	cfg := sfclient.ClientConfig{
		BrokerURL:          broker,
		FrontDomains:       split(ep.Params[ParamFront]),
		ICEAddresses:       split(or(ep.Params[ParamICE], DefaultICE)),
		KeepLocalAddresses: ep.Params[ParamLocal] == "1",
		UTLSClientID:       "hellochrome_auto",
		Max:                1,
	}
	if cfg.KeepLocalAddresses && ep.Params[ParamICE] == "" {
		cfg.ICEAddresses = nil
	}
	t, err := sfclient.NewSnowflakeClient(cfg)
	if err != nil {
		return nil, err
	}
	dctx, cancel := context.WithTimeout(ctx, 2*d.Opts.Timeout())
	defer cancel()
	type result struct {
		c   net.Conn
		err error
	}
	res := make(chan result, 1)
	go func() {
		c, err := t.Dial() // gathers a proxy through the broker; has no ctx
		res <- result{c, err}
	}()
	var c net.Conn
	select {
	case r := <-res:
		if r.err != nil {
			return nil, r.err
		}
		c = r.c
	case <-dctx.Done():
		go func() {
			if r := <-res; r.c != nil {
				_ = r.c.Close()
			}
		}()
		return nil, dctx.Err()
	}
	x, err := muxstream.Client(c)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return muxstream.NewSession(tok, x), nil
}

// Serve runs the snowflake server on listen until ctx ends, handing every
// client stream to muxstream. With tlsCfg nil it listens in plain HTTP (put TLS
// in front; tests). Volunteer proxies connect here over wss.
func Serve(ctx context.Context, listen string, tlsCfg *tls.Config, b transport.Backend) error {
	addr, err := net.ResolveTCPAddr("tcp", listen)
	if err != nil {
		return err
	}
	var getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	if tlsCfg != nil {
		getCert = certGetter(tlsCfg)
	}
	ln, err := sfserver.NewSnowflakeServer(getCert).Listen(addr, 1)
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			wg.Wait()
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			muxstream.Serve(b, c)
		}()
	}
}

func certGetter(cfg *tls.Config) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if cfg.GetCertificate != nil {
			return cfg.GetCertificate(hi)
		}
		if len(cfg.Certificates) == 0 {
			return nil, errors.New("snowflake: no certificate")
		}
		return &cfg.Certificates[0], nil
	}
}

func split(s string) []string {
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
