package auth

import (
	"errors"
	"testing"
	"time"
)

func TestMintVerify(t *testing.T) {
	pub, priv, _ := GenerateKey()
	s := NewSigner(priv)
	v := NewVerifier(pub)

	tok, err := s.Mint(Claims{Sub: "alice", Conc: 7}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	c, err := v.Verify(tok)
	if err != nil || c.Sub != "alice" || c.Conc != 7 {
		t.Fatalf("verify: %v %+v", err, c)
	}

	v.now = func() time.Time { return time.Now().Add(time.Hour) }
	if _, err := v.Verify(tok); !errors.Is(err, ErrExpired) {
		t.Fatalf("want expired, got %v", err)
	}
	v.now = time.Now

	pub2, priv2, _ := GenerateKey()
	other, _ := NewSigner(priv2).Mint(Claims{Sub: "x"}, time.Minute)
	if _, err := v.Verify(other); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("want unknown key, got %v", err)
	}
	rot := NewVerifier(pub, pub2)
	if _, err := rot.Verify(other); err != nil {
		t.Fatalf("rotation: %v", err)
	}

	// tampered payload
	// Edit the middle: about 6% of signatures already end in "AA", which made
	// the old end-of-token edit a no-op.
	mid := len(tok) / 2
	repl := "A"
	if tok[mid] == 'A' {
		repl = "B"
	}
	bad := tok[:mid] + repl + tok[mid+1:]
	if _, err := v.Verify(bad); err == nil {
		t.Fatal("tampered token accepted")
	}
	if _, err := v.Verify("garbage"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("want malformed, got %v", err)
	}
}

func TestBlob(t *testing.T) {
	pub, priv, _ := GenerateKey()
	s := NewSigner(priv)
	v := NewVerifier(pub)
	sig := s.SignBlob([]byte("hello"))
	if v.VerifyBlob([]byte("hello"), sig) != nil || v.VerifyBlob([]byte("hellO"), sig) == nil {
		t.Fatal("blob signature check wrong")
	}
}

func TestBearer(t *testing.T) {
	if Bearer("Bearer abc") != "abc" || Bearer("bearer abc") != "abc" || Bearer("Basic abc") != "" || Bearer("") != "" {
		t.Fatal("bearer parse")
	}
}

func TestAudienceIsolation(t *testing.T) {
	pub, priv, _ := GenerateKey()
	s, v := NewSigner(priv), NewVerifier(pub)
	ctl, _ := s.Mint(Claims{Sub: "a", Aud: AudControl}, time.Minute)
	data, _ := s.Mint(Claims{Sub: "a"}, time.Minute)
	if _, err := v.Verify(ctl); err != ErrWrongAudience {
		t.Fatalf("control token accepted as data token: %v", err)
	}
	if _, err := v.VerifyAud(data, AudControl); err != ErrWrongAudience {
		t.Fatalf("data token accepted as control token: %v", err)
	}
	if _, err := v.VerifyAud(ctl, AudControl); err != nil {
		t.Fatal(err)
	}
}
