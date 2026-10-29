package invite

import "testing"

func TestRoundTrip(t *testing.T) {
	in := Invite{TrustedKey: []string{"k"}, Account: "ak_1"}
	out, err := DecodeInvite(in.Encode())
	if err != nil || out.Account != "ak_1" || out.TrustedKey[0] != "k" {
		t.Fatal(err, out)
	}
	if _, err := DecodeInvite("dotvpn://" + "e30"); err == nil {
		t.Fatal("invite without trusted key accepted")
	}
	if _, err := DecodeInvite("https://x"); err == nil {
		t.Fatal("wrong prefix accepted")
	}
}
