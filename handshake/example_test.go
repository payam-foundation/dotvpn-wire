package handshake_test

import (
	"fmt"
	"io"
	"net"

	"github.com/payam-foundation/dotvpn-wire/auth"
	"github.com/payam-foundation/dotvpn-wire/frame"
	"github.com/payam-foundation/dotvpn-wire/handshake"
)

// The client pins the node's identity key; both sides then talk over an
// encrypted, padded frame.Conn.
func Example() {
	pub, priv, _ := auth.GenerateKey()
	a, b := net.Pipe()

	go func() {
		s, err := handshake.Respond(b, priv, frame.Opts{})
		if err != nil {
			return
		}
		buf := make([]byte, 5)
		_, _ = io.ReadFull(s, buf)
		_, _ = s.Write(buf)
	}()

	c, err := handshake.Initiate(a, pub, frame.Opts{})
	if err != nil {
		fmt.Println(err)
		return
	}
	_, _ = c.Write([]byte("hello"))
	buf := make([]byte, 5)
	_, _ = io.ReadFull(c, buf)
	fmt.Println(string(buf))
	// Output: hello
}
