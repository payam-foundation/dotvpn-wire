// SPDX-License-Identifier: AGPL-3.0-only OR PolyForm-Noncommercial-1.0.0

package invite

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/payam-foundation/dotvpn-wire/auth"
	"github.com/payam-foundation/dotvpn-wire/transport"
)

const RelayPrefix = "dvr://"

// RelayInvite is a shareable cold-start bypass blob: relay id plus dialable
// reverse/dns endpoints, signed by control so clients can verify before dial.
type RelayInvite struct {
	ID        string               `json:"id"`
	Endpoints []transport.Endpoint `json:"e,omitempty"`
	Sig       string               `json:"sig,omitempty"`
	KeyID     string               `json:"kid,omitempty"`
}

type relayInviteBody struct {
	ID        string               `json:"id"`
	Endpoints []transport.Endpoint `json:"e,omitempty"`
}

// signingPayload is the canonical bytes covered by Sig.
func (r RelayInvite) signingPayload() ([]byte, error) {
	return json.Marshal(relayInviteBody{ID: r.ID, Endpoints: r.Endpoints})
}

// Encode signs (when signer non-nil) and renders dvr://…
func (r RelayInvite) Encode(signer *auth.Signer) (string, error) {
	if strings.TrimSpace(r.ID) == "" {
		return "", errors.New("invite: relay id required")
	}
	out := r
	if signer != nil {
		payload, err := out.signingPayload()
		if err != nil {
			return "", err
		}
		out.Sig = signer.SignBlob(payload)
		out.KeyID = auth.KeyID(signer.Public())
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return RelayPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// DecodeRelayInvite parses a dvr:// URI without verifying the signature.
func DecodeRelayInvite(s string) (RelayInvite, error) {
	var r RelayInvite
	s = extractPrefixed(s, RelayPrefix)
	if !strings.HasPrefix(s, RelayPrefix) {
		return r, errors.New("invite: missing dvr:// prefix")
	}
	payload := strings.TrimPrefix(s, RelayPrefix)
	for len(payload) > 0 {
		raw, err := base64.RawURLEncoding.DecodeString(payload)
		if err == nil {
			var cand RelayInvite
			if json.Unmarshal(raw, &cand) == nil && strings.TrimSpace(cand.ID) != "" {
				return cand, nil
			}
		}
		payload = payload[:len(payload)-1]
	}
	return r, errors.New("invite: bad relay encoding")
}

// Verify checks Sig against trustedKeys (base64url Ed25519 public keys).
func (r RelayInvite) Verify(trustedKeys []string) error {
	if r.Sig == "" {
		return errors.New("invite: relay invite unsigned")
	}
	payload, err := r.signingPayload()
	if err != nil {
		return err
	}
	sig, err := base64.RawURLEncoding.DecodeString(r.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("invite: bad relay signature")
	}
	for _, enc := range trustedKeys {
		pub, err := auth.DecodePublicKey(enc)
		if err != nil {
			continue
		}
		if r.KeyID != "" && auth.KeyID(pub) != r.KeyID {
			continue
		}
		if ed25519.Verify(pub, payload, sig) {
			return nil
		}
	}
	return errors.New("invite: relay signature rejected")
}

// ParseRelayID returns the bare relay id from a dvr:// URI or a bare id.
func ParseRelayID(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("invite: empty relay id")
	}
	if strings.Contains(s, RelayPrefix) || strings.HasPrefix(s, RelayPrefix) {
		r, err := DecodeRelayInvite(s)
		if err == nil {
			return r.ID, nil
		}
		// Unsigned short form dvr://<id> (admin/debug); reject opaque garbage.
		rest := strings.TrimSpace(strings.TrimPrefix(extractPrefixed(s, RelayPrefix), RelayPrefix))
		if i := strings.IndexAny(rest, "/?#"); i >= 0 {
			rest = rest[:i]
		}
		if rest == "" || strings.ContainsAny(rest, "+/=") || len(rest) > 128 {
			return "", err
		}
		return rest, nil
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return s, nil
}
