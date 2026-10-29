package auth_test

import (
	"fmt"
	"time"

	"github.com/payam-foundation/dotvpn-wire/auth"
)

// Control mints a short-lived token; a node verifies it offline with the
// public key alone.
func Example() {
	pub, priv, _ := auth.GenerateKey()
	tok, _ := auth.NewSigner(priv).Mint(auth.Claims{Sub: "user-1"}, 15*time.Minute)

	c, err := auth.NewVerifier(pub).Verify(tok)
	fmt.Println(c.Sub, err)

	// A token for another audience is refused on the data plane.
	pool, _ := auth.NewSigner(priv).Mint(auth.Claims{Sub: "node-1", Aud: auth.AudPool}, time.Minute)
	_, err = auth.NewVerifier(pub).Verify(pool)
	fmt.Println(err)
	// Output:
	// user-1 <nil>
	// auth: wrong token audience
}
