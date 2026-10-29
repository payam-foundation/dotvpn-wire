package frame_test

import (
	"fmt"
	"io"
	"net"

	"github.com/payam-foundation/dotvpn-wire/frame"
)

// Two ends with mirrored keys exchange padded, authenticated records.
// handshake.DeriveKeys produces such a pair in real use.
func Example() {
	var k1, k2 frame.Keys
	k1.SendKey[0], k1.SendMask[0] = 1, 2
	k1.RecvKey[0], k1.RecvMask[0] = 3, 4
	k2.SendKey, k2.SendMask = k1.RecvKey, k1.RecvMask
	k2.RecvKey, k2.RecvMask = k1.SendKey, k1.SendMask

	a, b := net.Pipe()
	c, s := frame.New(a, k1, frame.Opts{}), frame.New(b, k2, frame.Opts{})
	go func() { _, _ = c.Write([]byte("ping")); _ = c.Close() }()

	got, _ := io.ReadAll(s)
	fmt.Println(string(got))
	// Output: ping
}
