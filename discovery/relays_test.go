// SPDX-License-Identifier: AGPL-3.0-only OR PolyForm-Noncommercial-1.0.0

package discovery

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/payam-foundation/dotvpn-wire/auth"
)

func TestTokenRequestIncludesRelays(t *testing.T) {
	pub, priv, err := auth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer := auth.NewSigner(priv)
	list, err := Sign(signer, List{Issued: 1})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		_ = json.NewEncoder(w).Encode(TokenResponse{Token: "t", Expires: 2, Now: 1, Servers: list})
	}))
	t.Cleanup(srv.Close)

	c := &Client{
		Channels:   []ControlChannel{{URL: srv.URL}},
		Verifier:   auth.NewVerifier(pub),
		AccountKey: "ak_x",
		Relays:     []string{"r1", "r2"},
		HTTP:       srv.Client(),
	}
	if _, err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got["account_key"] != "ak_x" {
		t.Fatalf("key: %v", got["account_key"])
	}
	ids, _ := got["relays"].([]any)
	if len(ids) != 2 || ids[0] != "r1" || ids[1] != "r2" {
		t.Fatalf("relays: %#v", got["relays"])
	}
}
