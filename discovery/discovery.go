// Package discovery gets a client from "I have an account key" to "I have a
// token and a verified list of endpoints", even when the control plane is
// blocked. The signed server list is the trust anchor: it can travel through
// any untrusted channel (relay, CDN, DoH TXT, embedded bootstrap, cache file).
//
// Interface: Signed lists (Sign, Open) and Client.Refresh.
package discovery

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/payam-foundation/dotvpn-wire/auth"
	"github.com/payam-foundation/dotvpn-wire/transport"
)

// ControlChannel is one way to reach the control plane.
type ControlChannel struct {
	URL string `yaml:"url" json:"url"`
	// Via is an optional CDN base URL fronting the control URL.
	Via string `yaml:"via,omitempty" json:"via,omitempty"`
	// Host overrides the Host header when Via is used.
	Host string `yaml:"host,omitempty" json:"host,omitempty"`
	// Relay names a relay endpoint; the request is tunnelled end to end to the
	// core through it, so the relay never sees the account key.
	Relay string `yaml:"relay,omitempty" json:"relay,omitempty"`
}

// List is the content of a server list.
type List struct {
	Issued    int64                `json:"issued"`
	Endpoints []transport.Endpoint `json:"endpoints"`
}

// Signed is a List with a detached signature, safe to relay or cache.
type Signed struct {
	Payload string `json:"payload"` // base64url JSON of List
	Sig     string `json:"sig"`
}

var b64 = base64.RawURLEncoding

// Sign produces a Signed list.
func Sign(s *auth.Signer, l List) (Signed, error) {
	raw, err := json.Marshal(l)
	if err != nil {
		return Signed{}, err
	}
	p := b64.EncodeToString(raw)
	return Signed{Payload: p, Sig: s.SignBlob([]byte(p))}, nil
}

// Open verifies and decodes a Signed list. Lists older than maxAge are
// rejected when maxAge > 0, which blunts replay of a stale list that points at
// burned nodes.
func Open(v *auth.Verifier, s Signed, maxAge time.Duration) (List, error) {
	var l List
	if err := v.VerifyBlob([]byte(s.Payload), s.Sig); err != nil {
		return l, err
	}
	raw, err := b64.DecodeString(s.Payload)
	if err != nil {
		return l, err
	}
	if err := json.Unmarshal(raw, &l); err != nil {
		return l, err
	}
	if maxAge > 0 && time.Since(time.Unix(l.Issued, 0)) > maxAge {
		return l, errors.New("discovery: server list too old")
	}
	return l, nil
}

// Encode and Decode move a Signed list through text channels (config, DNS TXT).
func (s Signed) Encode() string {
	b, _ := json.Marshal(s)
	return b64.EncodeToString(b)
}

// Decode parses the text form produced by Signed.Encode. It does not verify
// the signature; call Open with trusted keys before using the list.
func Decode(text string) (Signed, error) {
	var s Signed
	raw, err := b64.DecodeString(strings.TrimSpace(text))
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(raw, &s)
}

// TokenResponse is the control plane's reply to POST /v1/token.
type TokenResponse struct {
	Token   string `json:"token"`
	Expires int64  `json:"expires"`
	Now     int64  `json:"now"` // control plane clock, for skew anchoring
	Servers Signed `json:"servers"`
}

// Result is what a Refresh yields.
type Result struct {
	Token     string
	Expires   time.Time
	Endpoints []transport.Endpoint
	// Skew is control-plane time minus local time; clients with wrong clocks
	// use it to judge token expiry.
	Skew time.Duration
	// Source says which channel answered ("control", "cache", "bootstrap").
	Source string
	// Signed is the verified list as received, for caching and re-serving.
	Signed Signed
}

// Client talks to the control plane over an ordered list of channels.
type Client struct {
	Channels   []ControlChannel
	Verifier   *auth.Verifier
	AccountKey string
	// CachePath persists the last good Signed list so the next start works
	// with every channel blocked. Empty disables caching.
	CachePath string
	// Bootstrap is an embedded Signed list (Encode form) used as a last resort.
	Bootstrap string
	// HTTP is the HTTP client; the zero value uses a 15s timeout.
	HTTP *http.Client
	// ChannelHTTP, when set, returns the HTTP client for one channel (relay
	// tunnels). It wins over HTTP; nil or a nil result falls back to HTTP.
	ChannelHTTP func(ControlChannel) *http.Client
	// MaxListAge bounds list freshness for cache and bootstrap. Default 30 days.
	MaxListAge time.Duration
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// Refresh fetches a token and endpoints. Channels are tried in order; if all
// fail, the cached list and then the bootstrap list provide endpoints without
// a token, and the error says why the token is missing.
func (c *Client) Refresh(ctx context.Context) (Result, error) {
	var errs []error
	for _, ch := range c.Channels {
		res, err := c.viaChannel(ctx, ch)
		if err == nil {
			c.saveCache(res)
			return res, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", describe(ch), err))
		if ctx.Err() != nil {
			break
		}
	}
	if l, src, ok := c.offlineList(); ok {
		return Result{Endpoints: l.Endpoints, Source: src}, fmt.Errorf("control unreachable, using %s list: %w", src, errors.Join(errs...))
	}
	if len(errs) == 0 {
		return Result{}, errors.New("discovery: no control channels configured")
	}
	return Result{}, fmt.Errorf("discovery: all channels failed: %w", errors.Join(errs...))
}

func describe(ch ControlChannel) string {
	if ch.Via != "" {
		return ch.URL + " via " + ch.Via
	}
	return ch.URL
}

func (c *Client) viaChannel(ctx context.Context, ch ControlChannel) (Result, error) {
	base, host := strings.TrimSuffix(ch.URL, "/"), ""
	if ch.Via != "" {
		base = strings.TrimSuffix(ch.Via, "/")
		host = ch.Host
	}
	body, _ := json.Marshal(map[string]string{"account_key": c.AccountKey})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/token", bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if host != "" {
		req.Host = host
	}
	hc := c.http()
	if c.ChannelHTTP != nil {
		if x := c.ChannelHTTP(ch); x != nil {
			hc = x
		}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("control replied %d", resp.StatusCode)
	}
	var tr TokenResponse
	if err := json.Unmarshal(raw, &tr); err != nil {
		return Result{}, fmt.Errorf("bad control reply: %w", err)
	}
	// A relay or CDN is untrusted: the list must verify.
	l, err := Open(c.Verifier, tr.Servers, 0)
	if err != nil {
		return Result{}, fmt.Errorf("server list: %w", err)
	}
	return Result{
		Token:     tr.Token,
		Expires:   time.Unix(tr.Expires, 0),
		Endpoints: l.Endpoints,
		Skew:      time.Until(time.Unix(tr.Now, 0)),
		Source:    "control",
		Signed:    tr.Servers,
	}, nil
}

func (c *Client) maxAge() time.Duration {
	if c.MaxListAge > 0 {
		return c.MaxListAge
	}
	return 30 * 24 * time.Hour
}

func (c *Client) offlineList() (List, string, bool) {
	if c.CachePath != "" {
		if b, err := os.ReadFile(c.CachePath); err == nil {
			if s, err := Decode(string(b)); err == nil {
				if l, err := Open(c.Verifier, s, c.maxAge()); err == nil {
					return l, "cache", true
				}
			}
		}
	}
	if c.Bootstrap != "" {
		if s, err := Decode(c.Bootstrap); err == nil {
			if l, err := Open(c.Verifier, s, 0); err == nil {
				return l, "bootstrap", true
			}
		}
	}
	return List{}, "", false
}

func (c *Client) saveCache(r Result) {
	if c.CachePath == "" || r.Signed.Payload == "" {
		return
	}
	tmp := c.CachePath + ".tmp"
	if os.WriteFile(tmp, []byte(r.Signed.Encode()), 0o600) == nil {
		_ = os.Rename(tmp, c.CachePath)
	}
}
