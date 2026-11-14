// SPDX-License-Identifier: AGPL-3.0-only OR PolyForm-Noncommercial-1.0.0

// Package invite is the one-string onboarding blob a client pastes to join:
// endpoints, control channels and the keys that sign its server list. It holds
// no node secrets.
package invite

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"unicode"

	"github.com/payam-foundation/dotvpn-wire/discovery"
	"github.com/payam-foundation/dotvpn-wire/transport"
)

const InvitePrefix = "dv://"

// Invite is the one-string client onboarding blob printed by the installer
// and by `dotvpn invite`. It carries no node secrets.
type Invite struct {
	Endpoints  []transport.Endpoint       `json:"e,omitempty"`
	Control    []discovery.ControlChannel `json:"c,omitempty"`
	TrustedKey []string                   `json:"k"`
	// Account is the per-user account key used to fetch tokens from control.
	Account string `json:"a,omitempty"`
	// Token is a static bearer token for deployments without a control plane,
	// or a short-lived bootstrap JWT for cold-start muxstream auth.
	Token string `json:"t,omitempty"`
	// Bootstrap is an optional embedded signed list (Encode form) used as a
	// last-resort fallback when the Worker URL is unreachable.
	Bootstrap string `json:"b,omitempty"`
	// Mirrors are HTTPS URLs for the clear bootstrap blob (Cloudflare Worker
	// dvb first). Clients verify Ed25519; mirrors never carry the full fleet.
	Mirrors []string `json:"m,omitempty"`
}

// Encode renders the invite as one copy-pasteable string.
func (i Invite) Encode() string {
	b, _ := json.Marshal(i)
	return InvitePrefix + base64.RawURLEncoding.EncodeToString(b)
}

// DecodeInvite parses Encode output. Surrounding and internal whitespace
// (hard-wrapped TUI paste) is ignored. TUI chrome around the URI is stripped
// by extracting the first dv:// + base64url run and peeling trailing junk
// until the payload is valid JSON with a trusted key.
func DecodeInvite(s string) (Invite, error) {
	var i Invite
	s = extractPrefixed(s, InvitePrefix)
	if !strings.HasPrefix(s, InvitePrefix) {
		return i, errors.New("invite: missing dv:// prefix")
	}
	payload := strings.TrimPrefix(s, InvitePrefix)
	for len(payload) > 0 {
		raw, err := base64.RawURLEncoding.DecodeString(payload)
		if err == nil {
			var cand Invite
			if json.Unmarshal(raw, &cand) == nil && len(cand.TrustedKey) > 0 {
				return cand, nil
			}
		}
		payload = payload[:len(payload)-1]
	}
	return i, errors.New("invite: bad encoding")
}

// extractPrefixed keeps the first prefix… base64url token and drops prose.
func extractPrefixed(s, prefix string) string {
	start := strings.Index(s, prefix)
	if start < 0 {
		return stripSpace(s)
	}
	s = s[start:]
	payload := s[len(prefix):]
	var b strings.Builder
	b.Grow(len(prefix) + len(payload))
	b.WriteString(prefix)
	for _, r := range payload {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		if r > unicode.MaxASCII || !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_') {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

func stripSpace(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s)
}
