package loopback

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestCheck(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:9100": true, "[::1]:9100": true, "localhost:1": true, "unix:/run/d.sock": true,
		":9100": false, "0.0.0.0:9100": false, "[::]:1": false, "10.0.0.1:1": false,
		"example.com:1": false, "unix:": false, "nonsense": false,
	} {
		if err := Check(addr); (err == nil) != ok {
			t.Errorf("%q: err=%v want ok=%v", addr, err, ok)
		}
	}
}

func TestListenRefusesPublicAndReplacesStaleSocket(t *testing.T) {
	if _, err := Listen("0.0.0.0:0"); err == nil {
		t.Fatal("wildcard bind accepted")
	}
	sock := "unix:" + filepath.Join(os.TempDir(), fmt.Sprintf("dvpn-%d.sock", os.Getpid()))
	t.Cleanup(func() { os.Remove(sock[5:]) })
	for range 2 { // second round replaces the stale socket file
		ln, err := Listen(sock)
		if err != nil {
			t.Fatal(err)
		}
		ln.Close()
	}
}

func TestIsHost(t *testing.T) {
	for h, want := range map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true, "10.0.0.1": false, "example.com": false, "": false} {
		if IsHost(h) != want {
			t.Errorf("%q: want %v", h, want)
		}
	}
}
