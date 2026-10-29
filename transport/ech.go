package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ErrECHRequired is returned when Endpoint.Params["ech"] is "require" and the
// handshake cannot use ECH. The endpoint must not be dialled without it.
var ErrECHRequired = errors.New("transport: ech required but not available")

// ECH policy values for Endpoint.Params["ech"] (ADR-017).
const (
	// ECHAuto tries ECH when the HTTPS record has a config. Without one the
	// handshake continues with the ECH GREASE extension the Chrome preset
	// already sends, so the hello keeps its shape.
	ECHAuto = "auto"
	// ECHRequire fails closed: no config, or a server that rejects ECH, is a
	// dial error.
	ECHRequire = "require"
	// Any other non-empty value is a base64 ECHConfigList used as given.
)

type echPolicy struct {
	on      bool
	require bool
	static  []byte
}

func parseECH(p string) (echPolicy, error) {
	switch p {
	case "":
		return echPolicy{}, nil
	case ECHAuto:
		return echPolicy{on: true}, nil
	case ECHRequire:
		return echPolicy{on: true, require: true}, nil
	}
	b, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		return echPolicy{}, fmt.Errorf("transport: bad ech config: %w", err)
	}
	return echPolicy{on: true, require: true, static: b}, nil
}

// ECHRequired reports whether ep may only be dialled with ECH. Carriers that
// cannot do ECH (QUIC) refuse such endpoints so the ladder moves on.
func ECHRequired(ep Endpoint) bool {
	p, err := parseECH(ep.Params["ech"])
	return err == nil && p.require
}

// DoHServer is one DNS-over-HTTPS resolver reached at a pinned address, so
// finding it needs no DNS lookup a censor could tamper with.
type DoHServer struct {
	// URL is the RFC 8484 endpoint; its host is the TLS server name.
	URL string
	// Addr is the host:port dialled, normally the resolver's well-known IP.
	Addr string
}

// defaultDoH are public resolvers dialled by IP. Several, so one blocked
// provider does not disable ECH.
var defaultDoH = []DoHServer{
	{URL: "https://cloudflare-dns.com/dns-query", Addr: "1.1.1.1:443"},
	{URL: "https://dns.google/dns-query", Addr: "8.8.8.8:443"},
	{URL: "https://dns.quad9.net/dns-query", Addr: "9.9.9.9:443"},
}

const (
	echMaxTTL      = time.Hour
	echMinTTL      = time.Minute
	dohStagger     = time.Second
	dohTotalBudget = 8 * time.Second
)

// echCache remembers ECH configs per host until their DNS TTL ends. A nil cfg
// is a cached "no ECH published".
var echCache = struct {
	sync.Mutex
	m map[string]echEntry
}{m: map[string]echEntry{}}

type echEntry struct {
	cfg []byte
	exp time.Time
}

func cacheGet(host string) (cfg []byte, ok bool) {
	echCache.Lock()
	defer echCache.Unlock()
	e, ok := echCache.m[host]
	if !ok || time.Now().After(e.exp) {
		delete(echCache.m, host)
		return nil, false
	}
	return e.cfg, true
}

func cachePut(host string, cfg []byte, ttl time.Duration) {
	ttl = min(max(ttl, echMinTTL), echMaxTTL)
	echCache.Lock()
	echCache.m[host] = echEntry{cfg: cfg, exp: time.Now().Add(ttl)}
	echCache.Unlock()
}

// resolveECH returns the ECHConfigList to offer for ep, or nil for none. Under
// "require" every failure is ErrECHRequired.
func resolveECH(ctx context.Context, ep Endpoint, o Options, pol echPolicy) ([]byte, error) {
	if pol.static != nil {
		return pol.static, nil
	}
	cfg, err := lookupConfig(ctx, ep.ServerName(), o)
	if err != nil && pol.require {
		return nil, fmt.Errorf("%w: %v", ErrECHRequired, err)
	}
	return cfg, nil // auto: no config means plain hello with GREASE
}

func lookupConfig(ctx context.Context, host string, o Options) ([]byte, error) {
	if net.ParseIP(host) != nil {
		return nil, errors.New("ech needs a domain name")
	}
	if cfg, ok := cacheGet(host); ok {
		if cfg == nil {
			return nil, errors.New("no ech in HTTPS record (cached)")
		}
		return cfg, nil
	}
	servers := o.DoH
	if servers == nil {
		servers = defaultDoH
	}
	r, err := resolveDoH(ctx, host, servers, o)
	if err != nil {
		// DoH blocked: fall back to plain DNS. A poisoned answer can only
		// make the handshake fail or be corrected by the server's retry
		// configs; it cannot downgrade `require`.
		plain := o.DNS
		if plain == "" {
			plain = "1.1.1.1:53"
		}
		var perr error
		if r, perr = plainLookup(ctx, host, plain); perr != nil {
			return nil, errors.Join(err, perr)
		}
	}
	cfg, ttl := echFromAnswer(r)
	cachePut(host, cfg, ttl)
	if cfg == nil {
		return nil, errors.New("no ech in HTTPS record")
	}
	return cfg, nil
}

// LookupECH queries the HTTPS record of host at the plain DNS server
// ("ip:port") and returns its ECHConfigList. DialTLS prefers DoH; this is the
// fallback and a helper for tools.
func LookupECH(ctx context.Context, host, server string) ([]byte, error) {
	if net.ParseIP(host) != nil {
		return nil, errors.New("transport: ech needs a domain name")
	}
	r, err := plainLookup(ctx, host, server)
	if err != nil {
		return nil, err
	}
	if cfg, _ := echFromAnswer(r); cfg != nil {
		return cfg, nil
	}
	return nil, errors.New("transport: no ech in HTTPS record")
}

func httpsQuery(host string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeHTTPS)
	return m
}

func plainLookup(ctx context.Context, host, server string) (*dns.Msg, error) {
	m := httpsQuery(host)
	var r *dns.Msg
	var err error
	for _, network := range []string{"udp", "tcp"} {
		c := &dns.Client{Net: network}
		r, _, err = c.ExchangeContext(ctx, m, server)
		if err == nil && !r.Truncated {
			return r, nil
		}
	}
	return nil, err
}

// echFromAnswer extracts the first ECHConfigList and the smallest record TTL.
func echFromAnswer(r *dns.Msg) (cfg []byte, ttl time.Duration) {
	ttl = echMaxTTL
	for _, rr := range r.Answer {
		h, ok := rr.(*dns.HTTPS)
		if !ok {
			continue
		}
		for _, kv := range h.Value {
			if e, ok := kv.(*dns.SVCBECHConfig); ok && len(e.ECH) > 0 {
				return e.ECH, time.Duration(h.Hdr.Ttl) * time.Second
			}
		}
	}
	return nil, ttl
}

// resolveDoH asks the servers in order, starting the next one after
// dohStagger without an answer, and returns the first good reply.
func resolveDoH(ctx context.Context, host string, servers []DoHServer, o Options) (*dns.Msg, error) {
	if len(servers) == 0 {
		return nil, errors.New("no DoH servers")
	}
	ctx, cancel := context.WithTimeout(ctx, dohTotalBudget)
	defer cancel()
	type result struct {
		m   *dns.Msg
		err error
	}
	ch := make(chan result, len(servers))
	for i, s := range servers {
		go func() {
			if i > 0 {
				select {
				case <-time.After(time.Duration(i) * dohStagger):
				case <-ctx.Done():
					ch <- result{err: ctx.Err()}
					return
				}
			}
			m, err := dohQuery(ctx, host, s, o)
			ch <- result{m, err}
		}()
	}
	var errs []error
	for range servers {
		r := <-ch
		if r.err == nil {
			return r.m, nil
		}
		errs = append(errs, r.err)
	}
	return nil, errors.Join(errs...)
}

// dohQuery is one RFC 8484 POST of an HTTPS query.
func dohQuery(ctx context.Context, host string, s DoHServer, o Options) (*dns.Msg, error) {
	q := httpsQuery(host)
	q.Id = 0 // RFC 8484 section 4.1: keeps responses cacheable
	wire, err := q.Pack()
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{RootCAs: o.RootCAs, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 4 * time.Second, Control: o.Control}
			return d.DialContext(ctx, network, s.Addr)
		},
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh %s: status %d", s.URL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		return nil, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("doh %s: rcode %s", s.URL, dns.RcodeToString[r.Rcode])
	}
	return r, nil
}
