package discovery

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/payam-foundation/dotvpn-wire/auth"
)

const fleetBlobVersion = 1

// FleetBlob is an encrypted Signed server list for untrusted mirrors (S3/GitHub).
// Clients unwrap with fleet_key from an authenticated TokenResponse, then Open
// the inner Signed with trusted control keys.
type FleetBlob struct {
	Version    int    `json:"v"`
	KeyID      string `json:"kid"`
	Nonce      string `json:"n"`
	Ciphertext string `json:"ct"`
	Generation int64  `json:"g"`
	Sig        string `json:"sig"`
}

// SealFleet encrypts a Signed list's Encode() bytes with AES-256-GCM and
// attaches an Ed25519 signature over the envelope fields.
func SealFleet(s *auth.Signer, keyID string, fleetKey []byte, generation int64, signed Signed) (FleetBlob, error) {
	if s == nil {
		return FleetBlob{}, errors.New("discovery: nil signer")
	}
	if len(fleetKey) != 32 {
		return FleetBlob{}, errors.New("discovery: fleet key must be 32 bytes")
	}
	plain := []byte(signed.Encode())
	block, err := aes.NewCipher(fleetKey)
	if err != nil {
		return FleetBlob{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return FleetBlob{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return FleetBlob{}, err
	}
	ct := gcm.Seal(nil, nonce, plain, aadFleet(fleetBlobVersion, keyID, generation))
	fb := FleetBlob{
		Version:    fleetBlobVersion,
		KeyID:      keyID,
		Nonce:      b64.EncodeToString(nonce),
		Ciphertext: b64.EncodeToString(ct),
		Generation: generation,
	}
	fb.Sig = s.SignBlob(fb.signBytes())
	return fb, nil
}

// OpenFleet verifies the outer signature, decrypts with fleetKey, and returns
// the inner Signed list (still needs Open with the verifier).
func OpenFleet(v *auth.Verifier, keyID string, fleetKey []byte, fb FleetBlob) (Signed, error) {
	if v == nil {
		return Signed{}, errors.New("discovery: nil verifier")
	}
	if fb.Version != fleetBlobVersion {
		return Signed{}, fmt.Errorf("discovery: unsupported fleet blob version %d", fb.Version)
	}
	if keyID != "" && fb.KeyID != keyID {
		return Signed{}, errors.New("discovery: fleet key id mismatch")
	}
	if len(fleetKey) != 32 {
		return Signed{}, errors.New("discovery: fleet key must be 32 bytes")
	}
	if err := v.VerifyBlob(fb.signBytes(), fb.Sig); err != nil {
		return Signed{}, errors.New("discovery: fleet blob signature invalid")
	}
	nonce, err := b64.DecodeString(fb.Nonce)
	if err != nil {
		return Signed{}, errors.New("discovery: fleet blob nonce invalid")
	}
	ct, err := b64.DecodeString(fb.Ciphertext)
	if err != nil {
		return Signed{}, errors.New("discovery: fleet blob ciphertext invalid")
	}
	block, err := aes.NewCipher(fleetKey)
	if err != nil {
		return Signed{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Signed{}, err
	}
	if len(nonce) != gcm.NonceSize() {
		return Signed{}, errors.New("discovery: fleet blob nonce size")
	}
	plain, err := gcm.Open(nil, nonce, ct, aadFleet(fb.Version, fb.KeyID, fb.Generation))
	if err != nil {
		return Signed{}, errors.New("discovery: fleet blob decrypt failed")
	}
	return Decode(string(plain))
}

// EncodeFleetKey / DecodeFleetKey move 32-byte AES keys as URL-safe base64.
func EncodeFleetKey(key []byte) string {
	return b64.EncodeToString(key)
}

func DecodeFleetKey(s string) ([]byte, error) {
	raw, err := b64.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	if len(raw) != 32 {
		return nil, errors.New("discovery: fleet key must decode to 32 bytes")
	}
	return raw, nil
}

// NewFleetKey returns a fresh 32-byte AES-256 key.
func NewFleetKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

func (fb FleetBlob) signBytes() []byte {
	var b []byte
	b = append(b, byte(fb.Version))
	b = append(b, []byte(fb.KeyID)...)
	b = append(b, 0)
	b = append(b, []byte(fb.Nonce)...)
	b = append(b, 0)
	b = append(b, []byte(fb.Ciphertext)...)
	b = append(b, 0)
	var gen [8]byte
	binary.BigEndian.PutUint64(gen[:], uint64(fb.Generation))
	b = append(b, gen[:]...)
	return b
}

func aadFleet(version int, keyID string, generation int64) []byte {
	var gen [8]byte
	binary.BigEndian.PutUint64(gen[:], uint64(generation))
	return append([]byte{byte(version)}, append([]byte(keyID), gen[:]...)...)
}
