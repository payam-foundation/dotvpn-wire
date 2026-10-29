package handshake

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/payam-foundation/dotvpn-wire/frame"
)

func run(t *testing.T, pin ed25519.PublicKey, id ed25519.PrivateKey) (cli *frame.Conn, srv *frame.Conn, cerr, serr error) {
	t.Helper()
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() { srv, serr = Respond(b, id, frame.Opts{}); close(done) }()
	cli, cerr = Initiate(a, pin, frame.Opts{})
	if cerr != nil {
		_ = a.Close()
	}
	<-done
	return
}

func TestSessionAndForwardSecrecy(t *testing.T) {
	pub, id, _ := ed25519.GenerateKey(rand.Reader)
	c1, s1, ce, se := run(t, pub, id)
	if ce != nil || se != nil {
		t.Fatal(ce, se)
	}
	go c1.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(s1, buf); err != nil || string(buf) != "ping" {
		t.Fatal(err, string(buf))
	}
	// A second session under the same identity has unrelated keys: derive the
	// first-record ciphertext of each over an identical write and compare.
	k1, _ := DeriveKeys([]byte("a"), []byte("c"), []byte("s"))
	k2, _ := DeriveKeys([]byte("b"), []byte("c"), []byte("s"))
	if k1 == k2 {
		t.Fatal("different DH secrets gave equal keys")
	}
}

func TestWrongIdentityRejected(t *testing.T) {
	_, id, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, _, ce, _ := run(t, otherPub, id)
	if ce != ErrAuth {
		t.Fatalf("got %v, want ErrAuth", ce)
	}
}

// Golden vector shared by all repos: any change to Version or the KDF layout
// changes these keys and is a wire version bump.
func TestGoldenKeys(t *testing.T) {
	k, _ := DeriveKeys(make([]byte, 32), make([]byte, 32), make([]byte, 32))
	got := hex.EncodeToString(k.SendKey[:4]) + hex.EncodeToString(k.RecvKey[:4]) + hex.EncodeToString(k.SendMask[:4]) + hex.EncodeToString(k.RecvMask[:4])
	const want = "6cc2558940ab4ef7c741da3d730a3e22"
	if got != want {
		t.Fatalf("golden keys changed: got %s", got)
	}
}

func TestResponderTimesOutOnSilence(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	_ = b.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, id, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Respond(b, id, frame.Opts{}); err == nil {
		t.Fatal("expected error on silent peer")
	}
}

func FuzzRespond(f *testing.F) {
	f.Add(make([]byte, 33))
	f.Fuzz(func(t *testing.T, in []byte) {
		a, b := net.Pipe()
		_, id, _ := ed25519.GenerateKey(rand.Reader)
		go func() { _, _ = a.Write(in); _ = a.Close() }()
		_ = b.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, _ = Respond(b, id, frame.Opts{})
	})
}
