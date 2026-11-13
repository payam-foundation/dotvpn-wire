package invite_test

import (
	"fmt"

	"github.com/payam-foundation/dotvpn-wire/invite"
)

func Example() {
	s := invite.Invite{TrustedKey: []string{"k1"}, Token: "t"}.Encode()
	got, err := invite.DecodeInvite(s)
	fmt.Println(s[:5], got.TrustedKey, got.Token, err)
	// Output: dv:// [k1] t <nil>
}
