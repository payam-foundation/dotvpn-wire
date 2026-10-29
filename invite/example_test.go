package invite_test

import (
	"fmt"

	"github.com/payam-foundation/dotvpn-wire/invite"
)

func Example() {
	s := invite.Invite{TrustedKey: []string{"k1"}, Token: "t"}.Encode()
	got, err := invite.DecodeInvite(s)
	fmt.Println(s[:9], got.TrustedKey, got.Token, err)
	// Output: dotvpn:// [k1] t <nil>
}
