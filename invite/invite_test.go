package invite

import (
	"strings"
	"testing"

	"github.com/payam-foundation/dotvpn-wire/auth"
	"github.com/payam-foundation/dotvpn-wire/transport"
)

func hasPrefix(s, p string) bool { return strings.HasPrefix(s, p) }

func TestRoundTrip(t *testing.T) {
	in := Invite{TrustedKey: []string{"k"}, Account: "ak_1"}
	out, err := DecodeInvite(in.Encode())
	if err != nil || out.Account != "ak_1" || out.TrustedKey[0] != "k" {
		t.Fatal(err, out)
	}
	if _, err := DecodeInvite("dv://" + "e30"); err == nil {
		t.Fatal("invite without trusted key accepted")
	}
	if _, err := DecodeInvite("https://x"); err == nil {
		t.Fatal("wrong prefix accepted")
	}
	if _, err := DecodeInvite("dotvpn://e30"); err == nil {
		t.Fatal("legacy prefix accepted")
	}
	enc := in.Encode()
	if !hasPrefix(enc, "dv://") {
		t.Fatalf("prefix: %q", enc)
	}
	var wrapped string
	for i := 0; i < len(enc); i += 16 {
		if i > 0 {
			wrapped += "\n"
		}
		end := i + 16
		if end > len(enc) {
			end = len(enc)
		}
		wrapped += enc[i:end]
	}
	out, err = DecodeInvite(wrapped)
	if err != nil || out.Account != "ak_1" {
		t.Fatalf("hard-wrapped invite: %v %+v", err, out)
	}

	chrome := "Invite for davod (shown once, copy it now):\n\n" + wrapped +
		"\n\n(855 chars — select every line of the value above)"
	out, err = DecodeInvite(chrome)
	if err != nil || out.Account != "ak_1" {
		t.Fatalf("tui chrome paste: %v %+v", err, out)
	}

	glued := enc + "\n\nCopied!"
	out, err = DecodeInvite(glued)
	if err != nil || out.Account != "ak_1" {
		t.Fatalf("trailing prose paste: %v %+v", err, out)
	}
}

func TestRelayInviteRoundTrip(t *testing.T) {
	_, priv, err := auth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer := auth.NewSigner(priv)
	pub := auth.EncodeKey(signer.Public())
	in := RelayInvite{
		ID: "relay1",
		Endpoints: []transport.Endpoint{{
			Kind: "reverse",
			Addr: "1.2.3.4:443",
			Host: "cdn.example",
			Params: map[string]string{
				"node": "n1",
				"id":   "nodepub",
			},
		}},
	}
	uri, err := in.Encode(signer)
	if err != nil {
		t.Fatal(err)
	}
	if !hasPrefix(uri, "dvr://") {
		t.Fatalf("prefix: %q", uri)
	}
	out, err := DecodeRelayInvite(uri)
	if err != nil {
		t.Fatal(err)
	}
	if out.ID != "relay1" || len(out.Endpoints) != 1 {
		t.Fatalf("%+v", out)
	}
	if err := out.Verify([]string{pub}); err != nil {
		t.Fatal(err)
	}
	if err := out.Verify([]string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}); err == nil {
		t.Fatal("bad key accepted")
	}
	if _, err := DecodeRelayInvite("dotvpn-relay://relay1"); err == nil {
		t.Fatal("legacy relay prefix accepted")
	}
	id, err := ParseRelayID(uri)
	if err != nil || id != "relay1" {
		t.Fatal(err, id)
	}
	id, err = ParseRelayID("relay1")
	if err != nil || id != "relay1" {
		t.Fatal(err, id)
	}
}
