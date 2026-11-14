// SPDX-License-Identifier: AGPL-3.0-only OR PolyForm-Noncommercial-1.0.0

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
	Issued     int64                `json:"issued"`
	Generation int64                `json:"generation,omitempty"`
	Policy     ServerListPolicy     `json:"policy,omitempty"`
	Endpoints  []transport.Endpoint `json:"endpoints"`
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
	Token      string   `json:"token"`
	Expires    int64    `json:"expires"`
	Now        int64    `json:"now"` // control plane clock, for skew anchoring
	Servers    Signed   `json:"servers"`
	FleetKey   string   `json:"fleet_key,omitempty"` // raw URL-safe key material
	FleetKeyID string   `json:"fleet_key_id,omitempty"`
	FleetURLs  []string `json:"fleet_urls,omitempty"` // S3/GH object URLs
}

// Result is what a Refresh yields.
type Result struct {
	Token     string
	Expires   time.Time
	Endpoints []transport.Endpoint
	// Skew is control-plane time minus local time; clients with wrong clocks
	// use it to judge token expiry.
	Skew time.Duration
	// Source says which channel answered ("control", "cache", "bootstrap", "fleet").
	Source string
	// Signed is the verified list as received, for caching and re-serving.
	Signed     Signed
	FleetKey   string
	FleetKeyID string
	FleetURLs  []string
	Generation int64
}

// Client talks to the control plane over an ordered list of channels.
type Client struct {
	Channels   []ControlChannel
	Verifier   *auth.Verifier
	AccountKey string
	// DeviceID is a stable per-install id used for concurrent-device seats.
	DeviceID string
	// Relays are private community (or private curated) relay ids the client
	// has opted into; control includes them in the signed list when minting.
	Relays []string
	// CachePath persists the last good Signed list so the next start works
	// with every channel blocked. Empty disables caching.
	CachePath string
	// Mirrors are HTTPS URLs for the clear bootstrap blob (Worker / CDN).
	Mirrors []string
	// Bootstrap is an embedded Signed list (Encode form) used as a last resort.
	Bootstrap string
	// FleetKey / FleetKeyID persist the last authenticated unwrap material.
	FleetKey   string
	FleetKeyID string
	// FleetURLs are encrypted fleet mirror URLs from the last token response.
	FleetURLs []string
	// HTTP is the HTTP client; the zero value uses a 15s timeout.
	HTTP *http.Client
	// ChannelHTTP, when set, returns the HTTP client for one channel (relay
	// tunnels). It wins over HTTP; nil or a nil result falls back to HTTP.
	ChannelHTTP func(ControlChannel) *http.Client
	// OnBootstrapEndpoints is called when a clear bootstrap list is loaded so
	// callers can feed reverse endpoints into ChannelHTTP before /v1/token.
	OnBootstrapEndpoints func([]transport.Endpoint)
	// MaxListAge bounds list freshness for cache and mirrors. Default 30 days.
	MaxListAge time.Duration

	bootstrapRelay string
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// Refresh fetches a token and endpoints.
//
// Stages: warm clear bootstrap (mirrors / embedded) → try control channels
// (auto-attaching ControlChannel.Relay from bootstrap when needed) → unwrap
// encrypted fleet mirrors with fleet_key → cache. Offline cache/bootstrap
// remain as last resort without a token.
func (c *Client) Refresh(ctx context.Context) (Result, error) {
	c.warmBootstrap(ctx)

	var errs []error
	for _, ch := range c.channelsForAttempt() {
		res, err := c.viaChannel(ctx, ch)
		if err == nil {
			res = c.enrichFleet(ctx, res)
			c.rememberFleet(res)
			c.saveCache(res)
			return res, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", describe(ch), err))
		if ctx.Err() != nil {
			break
		}
	}
	res, offlineErrs, ok := c.offlineList(ctx)
	errs = append(errs, offlineErrs...)
	if ok {
		cause := errors.Join(errs...)
		if cause == nil {
			cause = errors.New("discovery: no control channels configured")
		}
		return res, fmt.Errorf("control unreachable, using %s list: %w", res.Source, cause)
	}
	if len(errs) == 0 {
		return Result{}, errors.New("discovery: no control channels configured")
	}
	return Result{}, fmt.Errorf("discovery: all channels failed: %w", errors.Join(errs...))
}

func (c *Client) warmBootstrap(ctx context.Context) {
	res, _, ok := c.bootstrapSources(ctx)
	if !ok {
		return
	}
	c.bootstrapRelay = firstReverseAddr(res.Endpoints)
	if c.OnBootstrapEndpoints != nil && len(res.Endpoints) > 0 {
		c.OnBootstrapEndpoints(res.Endpoints)
	}
}

func (c *Client) channelsForAttempt() []ControlChannel {
	out := append([]ControlChannel(nil), c.Channels...)
	if c.bootstrapRelay == "" {
		return out
	}
	// After directs, retry channels that had no Relay using the bootstrap relay.
	for _, ch := range c.Channels {
		if ch.Relay == "" {
			cp := ch
			cp.Relay = c.bootstrapRelay
			out = append(out, cp)
		}
	}
	return out
}

func firstReverseAddr(eps []transport.Endpoint) string {
	for _, ep := range eps {
		if (ep.Kind == "reverse" || ep.Kind == "dns") && ep.Addr != "" {
			return ep.Addr
		}
	}
	return ""
}

func (c *Client) rememberFleet(r Result) {
	if r.FleetKey != "" {
		c.FleetKey = r.FleetKey
	}
	if r.FleetKeyID != "" {
		c.FleetKeyID = r.FleetKeyID
	}
	if len(r.FleetURLs) > 0 {
		c.FleetURLs = append([]string(nil), r.FleetURLs...)
	}
}

func (c *Client) enrichFleet(ctx context.Context, res Result) Result {
	key := res.FleetKey
	if key == "" {
		key = c.FleetKey
	}
	kid := res.FleetKeyID
	if kid == "" {
		kid = c.FleetKeyID
	}
	urls := res.FleetURLs
	if len(urls) == 0 {
		urls = c.FleetURLs
	}
	if key == "" || len(urls) == 0 || c.Verifier == nil {
		return res
	}
	rawKey, err := DecodeFleetKey(key)
	if err != nil {
		return res
	}
	for _, u := range urls {
		fb, err := c.fetchFleetBlob(ctx, u)
		if err != nil {
			continue
		}
		inner, err := OpenFleet(c.Verifier, kid, rawKey, fb)
		if err != nil {
			continue
		}
		list, err := Open(c.Verifier, inner, c.maxAge())
		if err != nil {
			continue
		}
		if res.Generation > 0 && list.Generation > 0 && list.Generation < res.Generation {
			continue // refuse older fleet than bootstrap/token generation
		}
		res.Endpoints = list.Endpoints
		res.Signed = inner
		res.Source = "fleet"
		res.Generation = list.Generation
		res.FleetKey = key
		res.FleetKeyID = kid
		res.FleetURLs = append([]string(nil), urls...)
		return res
	}
	return res
}

func (c *Client) fetchFleetBlob(ctx context.Context, mirror string) (FleetBlob, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mirror, nil)
	if err != nil {
		return FleetBlob{}, err
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return FleetBlob{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return FleetBlob{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return FleetBlob{}, fmt.Errorf("fleet mirror replied %d", resp.StatusCode)
	}
	text := strings.TrimSpace(string(raw))
	var fb FleetBlob
	if err := json.Unmarshal([]byte(text), &fb); err != nil {
		return FleetBlob{}, err
	}
	return fb, nil
}

func (c *Client) bootstrapSources(ctx context.Context) (Result, []error, bool) {
	var errs []error
	for _, mirror := range c.Mirrors {
		res, err := c.viaMirror(ctx, mirror)
		if err == nil {
			res.Source = "bootstrap"
			return res, errs, true
		}
		errs = append(errs, fmt.Errorf("mirror %s: %w", mirror, err))
		if ctx.Err() != nil {
			break
		}
	}
	if c.Bootstrap != "" {
		if s, err := Decode(c.Bootstrap); err == nil {
			if l, err := Open(c.Verifier, s, 0); err == nil {
				return Result{Endpoints: l.Endpoints, Source: "bootstrap", Signed: s, Generation: l.Generation}, errs, true
			}
		}
	}
	return Result{}, errs, false
}

func describe(ch ControlChannel) string {
	s := ch.URL
	if ch.Via != "" {
		s = ch.URL + " via " + ch.Via
	}
	if ch.Relay != "" {
		s += " relay " + ch.Relay
	}
	return s
}

func (c *Client) viaChannel(ctx context.Context, ch ControlChannel) (Result, error) {
	base, host := strings.TrimSuffix(ch.URL, "/"), ""
	if ch.Via != "" {
		base = strings.TrimSuffix(ch.Via, "/")
		host = ch.Host
	}
	payload := map[string]any{"account_key": c.AccountKey}
	if c.DeviceID != "" {
		payload["device_id"] = c.DeviceID
	}
	if len(c.Relays) > 0 {
		payload["relays"] = c.Relays
	}
	body, _ := json.Marshal(payload)
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
		Token:      tr.Token,
		Expires:    time.Unix(tr.Expires, 0),
		Endpoints:  l.Endpoints,
		Skew:       time.Until(time.Unix(tr.Now, 0)),
		Source:     "control",
		Signed:     tr.Servers,
		FleetKey:   tr.FleetKey,
		FleetKeyID: tr.FleetKeyID,
		FleetURLs:  append([]string(nil), tr.FleetURLs...),
		Generation: l.Generation,
	}, nil
}

func (c *Client) maxAge() time.Duration {
	if c.MaxListAge > 0 {
		return c.MaxListAge
	}
	return 30 * 24 * time.Hour
}

func (c *Client) offlineList(ctx context.Context) (Result, []error, bool) {
	if c.CachePath != "" {
		if b, err := os.ReadFile(c.CachePath); err == nil {
			if s, err := Decode(string(b)); err == nil {
				if l, err := Open(c.Verifier, s, c.maxAge()); err == nil {
					return Result{Endpoints: l.Endpoints, Source: "cache", Signed: s}, nil, true
				}
			}
		}
	}
	var errs []error
	for _, mirror := range c.Mirrors {
		res, err := c.viaMirror(ctx, mirror)
		if err == nil {
			return res, errs, true
		}
		errs = append(errs, fmt.Errorf("mirror %s: %w", mirror, err))
		if ctx.Err() != nil {
			break
		}
	}
	if c.Bootstrap != "" {
		if s, err := Decode(c.Bootstrap); err == nil {
			if l, err := Open(c.Verifier, s, 0); err == nil {
				return Result{Endpoints: l.Endpoints, Source: "bootstrap", Signed: s}, errs, true
			}
		}
	}
	return Result{}, errs, false
}

func (c *Client) viaMirror(ctx context.Context, mirror string) (Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mirror, nil)
	if err != nil {
		return Result{}, fmt.Errorf("create request: %w", err)
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("get: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Result{}, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("replied %d", resp.StatusCode)
	}
	s, err := decodeMirror(string(raw))
	if err != nil {
		return Result{}, fmt.Errorf("decode: %w", err)
	}
	l, err := Open(c.Verifier, s, c.maxAge())
	if err != nil {
		return Result{}, fmt.Errorf("server list: %w", err)
	}
	return Result{Endpoints: l.Endpoints, Source: "mirror", Signed: s}, nil
}

func decodeMirror(text string) (Signed, error) {
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "{") {
		var s Signed
		if err := json.Unmarshal([]byte(text), &s); err != nil {
			return Signed{}, fmt.Errorf("JSON signed list: %w", err)
		}
		return s, nil
	}
	s, err := Decode(text)
	if err != nil {
		return Signed{}, fmt.Errorf("encoded signed list: %w", err)
	}
	return s, nil
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
