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

const invitePrefix = "dotvpn://"

// Invite is the one-string client onboarding blob printed by the installer
// and by `dotvpn invite`. It carries no node secrets.
type Invite struct {
	Endpoints  []transport.Endpoint       `json:"e,omitempty"`
	Control    []discovery.ControlChannel `json:"c,omitempty"`
	TrustedKey []string                   `json:"k"`
	// Account is the per-user account key used to fetch tokens from control.
	Account string `json:"a,omitempty"`
	// Token is a static bearer token for deployments without a control plane.
	Token string `json:"t,omitempty"`
	// Bootstrap is a signed server list for first contact when control is blocked.
	Bootstrap string `json:"b,omitempty"`
}

// Encode renders the invite as one copy-pasteable string.
func (i Invite) Encode() string {
	b, _ := json.Marshal(i)
	return invitePrefix + base64.RawURLEncoding.EncodeToString(b)
}

// DecodeInvite parses Encode output. Surrounding and internal whitespace
// (hard-wrapped TUI paste) is ignored. TUI chrome around the URI
// ("Invite for …", "(855 chars — select…)", "Copied!") is stripped by
// extracting the first dotvpn:// + base64url run and peeling trailing
// junk until the payload is valid JSON with a trusted key.
func DecodeInvite(s string) (Invite, error) {
	var i Invite
	s = extractInvite(s)
	if !strings.HasPrefix(s, invitePrefix) {
		return i, errors.New("invite: missing dotvpn:// prefix")
	}
	payload := strings.TrimPrefix(s, invitePrefix)
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

// extractInvite keeps the first dotvpn://… base64url token and drops any
// leading/trailing prose the operator TUI prints around it. Whitespace
// inside the payload is skipped (hard-wrapped pastes). Trailing letters
// that glued on (e.g. "Copied!") are peeled in DecodeInvite.
func extractInvite(s string) string {
	start := strings.Index(s, invitePrefix)
	if start < 0 {
		return stripSpace(s)
	}
	s = s[start:]
	payload := s[len(invitePrefix):]
	var b strings.Builder
	b.Grow(len(invitePrefix) + len(payload))
	b.WriteString(invitePrefix)
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
