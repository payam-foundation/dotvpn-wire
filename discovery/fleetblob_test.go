// SPDX-License-Identifier: AGPL-3.0-only OR PolyForm-Noncommercial-1.0.0

package discovery

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/payam-foundation/dotvpn-wire/auth"
	"github.com/payam-foundation/dotvpn-wire/transport"
)

func TestFleetBlobRoundTrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := auth.NewSigner(priv)
	signed, err := Sign(signer, List{
		Issued:     time.Now().Unix(),
		Generation: 7,
		Endpoints:  []transport.Endpoint{{Addr: "1.2.3.4:443", Host: "a.example"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewFleetKey()
	if err != nil {
		t.Fatal(err)
	}
	fb, err := SealFleet(signer, "k1", key, 7, signed)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(fb)
	if err != nil {
		t.Fatal(err)
	}
	var got FleetBlob
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	v := auth.NewVerifier(pub)
	inner, err := OpenFleet(v, "k1", key, got)
	if err != nil {
		t.Fatal(err)
	}
	list, err := Open(v, inner, 0)
	if err != nil {
		t.Fatal(err)
	}
	if list.Generation != 7 || len(list.Endpoints) != 1 || list.Endpoints[0].Addr != "1.2.3.4:443" {
		t.Fatalf("list: %+v", list)
	}
}

func TestFleetBlobTamper(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := auth.NewSigner(priv)
	signed, err := Sign(signer, List{Issued: time.Now().Unix(), Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewFleetKey()
	if err != nil {
		t.Fatal(err)
	}
	fb, err := SealFleet(signer, "k1", key, 1, signed)
	if err != nil {
		t.Fatal(err)
	}
	fb.Ciphertext = b64.EncodeToString([]byte("tampered"))
	v := auth.NewVerifier(priv.Public().(ed25519.PublicKey))
	if _, err := OpenFleet(v, "k1", key, fb); err == nil {
		t.Fatal("expected tamper failure")
	}
}

func TestFleetKeyCodec(t *testing.T) {
	key, err := NewFleetKey()
	if err != nil {
		t.Fatal(err)
	}
	enc := EncodeFleetKey(key)
	got, err := DecodeFleetKey(enc)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 32 || string(got) != string(key) {
		t.Fatalf("roundtrip mismatch")
	}
	if _, err := DecodeFleetKey("abc"); err == nil {
		t.Fatal("expected short key error")
	}
}
