// Package handshake is the X25519 session setup of the wire protocol.
//
//	initiator -> responder: ephC(32) | padlen^ephC[31] (1) | pad
//	responder -> initiator: ephS(32) | padlen^ephS[31] (1) | pad | AEAD(sig)
//
// sig is the responder's Ed25519 signature over the transcript, which the
// initiator checks against a pinned key, so the responder is authenticated and
// both ends get forward secrecy from the ephemeral keys. The version is bound
// into the KDF: a version or algorithm mismatch yields different keys and the
// first record fails closed, so there is nothing to downgrade.
package handshake

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"time"

	"github.com/payam-foundation/dotvpn-wire/frame"
)

// Version is the wire protocol version bound into every session key.
const Version = "dotvpn-wire/1"

const maxPad = 64

// ErrAuth means the responder did not prove knowledge of the pinned key.
var ErrAuth = errors.New("handshake: responder authentication failed")

// DeriveKeys expands the DH secret into the four record keys, from the
// initiator's point of view; the responder swaps Send and Recv.
func DeriveKeys(shared, ephC, ephS []byte) (frame.Keys, error) {
	out, err := hkdf.Key(sha256.New, shared, append(append([]byte{}, ephC...), ephS...), Version, 128)
	if err != nil {
		return frame.Keys{}, err
	}
	var k frame.Keys
	copy(k.SendKey[:], out[0:32])
	copy(k.RecvKey[:], out[32:64])
	copy(k.SendMask[:], out[64:96])
	copy(k.RecvMask[:], out[96:128])
	return k, nil
}

func swap(k frame.Keys) frame.Keys {
	return frame.Keys{SendKey: k.RecvKey, RecvKey: k.SendKey, SendMask: k.RecvMask, RecvMask: k.SendMask}
}

func transcript(ephC, ephS []byte) []byte {
	return append(append([]byte(Version+" responder"), ephC...), ephS...)
}

func sigAEAD(shared []byte, ephC, ephS []byte) (cipher.AEAD, error) {
	k, err := hkdf.Key(sha256.New, shared, append(append([]byte{}, ephC...), ephS...), Version+" sig", 32)
	if err != nil {
		return nil, err
	}
	b, _ := aes.NewCipher(k)
	return cipher.NewGCM(b)
}

func randPad() []byte {
	var n [1]byte
	_, _ = rand.Read(n[:])
	p := make([]byte, int(n[0])%(maxPad+1))
	_, _ = rand.Read(p)
	return p
}

func hello(eph []byte) []byte {
	pad := randPad()
	out := append(append([]byte{}, eph...), byte(len(pad))^eph[31])
	return append(out, pad...)
}

func readHello(c net.Conn) ([]byte, error) {
	var h [33]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return nil, err
	}
	pl := int(h[32] ^ h[31])
	if pl > maxPad {
		return nil, errors.New("handshake: bad padding")
	}
	if _, err := io.CopyN(io.Discard, c, int64(pl)); err != nil {
		return nil, err
	}
	return h[:32], nil
}

// Timeout bounds each handshake.
const Timeout = 15 * time.Second

// Initiate runs the client side. serverKey is the pinned responder identity.
func Initiate(c net.Conn, serverKey ed25519.PublicKey, o frame.Opts) (*frame.Conn, error) {
	_ = c.SetDeadline(time.Now().Add(Timeout))
	defer c.SetDeadline(time.Time{})
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ephC := priv.PublicKey().Bytes()
	if _, err := c.Write(hello(ephC)); err != nil {
		return nil, err
	}
	ephS, err := readHello(c)
	if err != nil {
		return nil, err
	}
	pub, err := ecdh.X25519().NewPublicKey(ephS)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	aead, err := sigAEAD(shared, ephC, ephS)
	if err != nil {
		return nil, err
	}
	ct := make([]byte, ed25519.SignatureSize+aead.Overhead())
	if _, err := io.ReadFull(c, ct); err != nil {
		return nil, err
	}
	sig, err := aead.Open(nil, make([]byte, aead.NonceSize()), ct, nil)
	if err != nil || !ed25519.Verify(serverKey, transcript(ephC, ephS), sig) {
		return nil, ErrAuth
	}
	k, err := DeriveKeys(shared, ephC, ephS)
	if err != nil {
		return nil, err
	}
	return frame.New(c, k, o), nil
}

// Respond runs the server side with the long-term identity key id. It blocks
// until the initiator speaks, so a pooled idle connection can wait in it.
func Respond(c net.Conn, id ed25519.PrivateKey, o frame.Opts) (*frame.Conn, error) {
	ephC, err := readHello(c)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(Timeout))
	defer c.SetDeadline(time.Time{})
	pubC, err := ecdh.X25519().NewPublicKey(ephC)
	if err != nil {
		return nil, err
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ephS := priv.PublicKey().Bytes()
	shared, err := priv.ECDH(pubC)
	if err != nil {
		return nil, err
	}
	aead, err := sigAEAD(shared, ephC, ephS)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(id, transcript(ephC, ephS))
	// Zero nonce is safe: the AEAD key is derived from a fresh ephemeral
	// X25519 secret and encrypts exactly one message.
	sealed := aead.Seal(nil, make([]byte, aead.NonceSize()), sig, nil) // #nosec G407
	out := append(hello(ephS), sealed...)
	if _, err := c.Write(out); err != nil {
		return nil, err
	}
	k, err := DeriveKeys(shared, ephC, ephS)
	if err != nil {
		return nil, err
	}
	return frame.New(c, swap(k), o), nil
}
