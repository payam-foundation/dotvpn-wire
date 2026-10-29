// Package invite is the one-string onboarding blob a client pastes to join:
// endpoints, control channels and the keys that sign its server list. It holds
// no node secrets.
package invite

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

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

// DecodeInvite parses Encode output; surrounding whitespace is ignored.
func DecodeInvite(s string) (Invite, error) {
	var i Invite
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, invitePrefix) {
		return i, errors.New("invite: missing dotvpn:// prefix")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, invitePrefix))
	if err != nil {
		return i, errors.New("invite: bad encoding")
	}
	if err := json.Unmarshal(raw, &i); err != nil {
		return i, errors.New("invite: bad content")
	}
	if len(i.TrustedKey) == 0 {
		return i, errors.New("invite: no trusted key")
	}
	return i, nil
}
