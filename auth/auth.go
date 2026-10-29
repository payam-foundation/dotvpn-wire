// Package auth issues and verifies short-lived Ed25519 JWTs.
//
// Interface: Signer.Mint, Verifier.Verify, plus detached blob signatures used
// for the signed server list. A Verifier holds public keys only, so nodes
// verify tokens offline and keep serving while the control plane is down.
package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Token verification failures. Callers map all of them to one unauthorized
// reply so a prober cannot tell which check failed.
var (
	ErrMalformed    = errors.New("auth: malformed token")
	ErrUnknownKey   = errors.New("auth: unknown key id")
	ErrBadSignature = errors.New("auth: bad signature")
	ErrExpired      = errors.New("auth: token expired")
	ErrNotYetValid  = errors.New("auth: token not yet valid")
)

// Claims is the token payload. Times are Unix seconds.
type Claims struct {
	Sub string `json:"sub"`
	// Aud scopes the token. Empty is the data plane (Verify); other values
	// (AudControl, AudEnroll, AudPool) are only accepted by VerifyAud, so a
	// token minted for one purpose cannot be replayed for another.
	Aud string `json:"aud,omitempty"`
	// Jti makes single-use tokens (enrollment) trackable.
	Jti string `json:"jti,omitempty"`
	Iat int64  `json:"iat"`
	Nbf int64  `json:"nbf"`
	Exp int64  `json:"exp"`
	// Conc caps concurrent streams for the user on one node; 0 means node default.
	Conc int `json:"conc,omitempty"`
	// Mbps caps throughput for the user on one node; 0 means node default.
	Mbps int `json:"mbps,omitempty"`
}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

var b64 = base64.RawURLEncoding

// KeyID is a short stable identifier of a public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:6])
}

// GenerateKey returns a fresh signing key pair.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// EncodeKey and DecodeKey move keys through config files as base64url text.
func EncodeKey(k []byte) string { return b64.EncodeToString(k) }

// DecodePublicKey parses a base64url Ed25519 public key, rejecting any other length.
func DecodePublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := b64.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("auth: invalid public key")
	}
	return ed25519.PublicKey(raw), nil
}

// DecodePrivateKey parses a base64url Ed25519 private key, rejecting any other length.
func DecodePrivateKey(s string) (ed25519.PrivateKey, error) {
	raw, err := b64.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("auth: invalid private key")
	}
	return ed25519.PrivateKey(raw), nil
}

// Signer mints tokens and signs blobs. Only the control plane holds one.
type Signer struct {
	kid  string
	priv ed25519.PrivateKey
	now  func() time.Time
}

// NewSigner returns a Signer whose key id is derived from priv's public half.
func NewSigner(priv ed25519.PrivateKey) *Signer {
	return &Signer{kid: KeyID(priv.Public().(ed25519.PublicKey)), priv: priv, now: time.Now}
}

// KeyID is the id written into every token header; verifiers use it to pick a key.
func (s *Signer) KeyID() string { return s.kid }

// Public returns the verification key matching this signer.
func (s *Signer) Public() ed25519.PublicKey { return s.priv.Public().(ed25519.PublicKey) }

// Mint signs claims valid for ttl. Iat and Nbf default to now.
func (s *Signer) Mint(c Claims, ttl time.Duration) (string, error) {
	now := s.now()
	if c.Sub == "" {
		return "", errors.New("auth: empty subject")
	}
	if c.Iat == 0 {
		c.Iat = now.Unix()
	}
	if c.Nbf == 0 {
		c.Nbf = now.Unix()
	}
	c.Exp = now.Add(ttl).Unix()
	h, _ := json.Marshal(header{Alg: "EdDSA", Typ: "JWT", Kid: s.kid})
	p, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signing := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	sig := ed25519.Sign(s.priv, []byte(signing))
	return signing + "." + b64.EncodeToString(sig), nil
}

// SignBlob returns a detached signature over data.
func (s *Signer) SignBlob(data []byte) string {
	return b64.EncodeToString(ed25519.Sign(s.priv, data))
}

// Verifier checks tokens against a set of trusted public keys, which allows
// key rotation: publish the new key, switch the signer, drop the old key.
type Verifier struct {
	keys map[string]ed25519.PublicKey
	// Skew tolerates clock differences between control plane and node.
	Skew time.Duration
	now  func() time.Time
}

// NewVerifier trusts the given public keys, with a 30s clock skew allowance.
func NewVerifier(pubs ...ed25519.PublicKey) *Verifier {
	v := &Verifier{keys: map[string]ed25519.PublicKey{}, Skew: 30 * time.Second, now: time.Now}
	for _, p := range pubs {
		v.keys[KeyID(p)] = p
	}
	return v
}

// Token audiences besides the data plane.
const (
	AudControl = "control" // reach the control plane (also through a relay)
	AudEnroll  = "enroll"  // one-time relay enrollment
	AudPool    = "pool"    // a core proving itself to a relay
)

// ErrWrongAudience means a token is valid but meant for another audience
// (for example a pool token presented as a data-plane token).
var ErrWrongAudience = errors.New("auth: wrong token audience")

// Verify accepts data-plane tokens only (empty Aud).
func (v *Verifier) Verify(token string) (Claims, error) {
	return v.VerifyAud(token, "")
}

// VerifyAud checks signature, time window and that the token's audience is aud.
func (v *Verifier) VerifyAud(token, aud string) (Claims, error) {
	c, err := v.verify(token)
	if err != nil {
		return Claims{}, err
	}
	if c.Aud != aud {
		return Claims{}, ErrWrongAudience
	}
	return c, nil
}

func (v *Verifier) verify(token string) (Claims, error) {
	var c Claims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return c, ErrMalformed
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return c, ErrMalformed
	}
	var h header
	if json.Unmarshal(hb, &h) != nil || h.Alg != "EdDSA" {
		return c, ErrMalformed
	}
	pub, ok := v.keys[h.Kid]
	if !ok {
		return c, ErrUnknownKey
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return c, ErrBadSignature
	}
	pb, err := b64.DecodeString(parts[1])
	if err != nil || json.Unmarshal(pb, &c) != nil {
		return Claims{}, ErrMalformed
	}
	now := v.now().Unix()
	skew := int64(v.Skew / time.Second)
	if now > c.Exp+skew {
		return Claims{}, ErrExpired
	}
	if now+skew < c.Nbf {
		return Claims{}, ErrNotYetValid
	}
	return c, nil
}

// VerifyBlob checks a detached signature produced by Signer.SignBlob against
// any trusted key.
func (v *Verifier) VerifyBlob(data []byte, sig string) error {
	raw, err := b64.DecodeString(sig)
	if err != nil {
		return ErrMalformed
	}
	for _, pub := range v.keys {
		if ed25519.Verify(pub, data, raw) {
			return nil
		}
	}
	return ErrBadSignature
}

// Bearer extracts the token from an "Authorization"-style header value.
func Bearer(h string) string {
	const p = "Bearer "
	if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) {
		return strings.TrimSpace(h[len(p):])
	}
	return ""
}

// String implements fmt.Stringer for Claims in logs without leaking tokens.
func (c Claims) String() string {
	return fmt.Sprintf("sub=%s exp=%s", c.Sub, time.Unix(c.Exp, 0).UTC().Format(time.RFC3339))
}
