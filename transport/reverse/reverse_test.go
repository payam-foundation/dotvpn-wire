package reverse

import (
	"bytes"
	"testing"
	"time"

	"github.com/payam-foundation/dotvpn-wire/auth"
)

func TestAuthRoundTrip(t *testing.T) {
	pub, priv, _ := auth.GenerateKey()
	s := auth.NewSigner(priv)
	v := auth.NewVerifier(pub)
	tok, _ := s.Mint(auth.Claims{Sub: "n1", Aud: auth.AudPool}, time.Minute)
	var b bytes.Buffer
	if err := WriteAuth(&b, tok); err != nil {
		t.Fatal(err)
	}
	if id, err := ReadAuth(&b, v); err != nil || id != "n1" {
		t.Fatalf("%q %v", id, err)
	}
	data, _ := s.Mint(auth.Claims{Sub: "n1"}, time.Minute)
	b.Reset()
	_ = WriteAuth(&b, data)
	if _, err := ReadAuth(&b, v); err == nil {
		t.Fatal("data-plane token accepted as pool token")
	}
}

func TestKnockKeysAreDomainSeparated(t *testing.T) {
	pub, _, _ := auth.GenerateKey()
	if bytes.Equal(PoolKnockKey(pub), ClientKnockKey(pub, "n1")) || bytes.Equal(ClientKnockKey(pub, "n1"), ClientKnockKey(pub, "n2")) {
		t.Fatal("knock keys collide")
	}
}

func FuzzReadAuth(f *testing.F) {
	pub, _, _ := auth.GenerateKey()
	v := auth.NewVerifier(pub)
	f.Add([]byte{0, 3, 'a', 'b', 'c'})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ReadAuth(bytes.NewReader(b), v) })
}
