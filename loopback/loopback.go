// Package loopback keeps admin and metrics surfaces off the network: an
// address is accepted only if it is loopback or a unix socket.
package loopback

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
)

// IsHost reports whether host (no port) is "localhost" or a loopback IP.
func IsHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Check reports an error unless addr is a loopback host:port or "unix:/path".
func Check(addr string) error {
	if p, ok := strings.CutPrefix(addr, "unix:"); ok {
		if p == "" {
			return errors.New("empty unix socket path")
		}
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("bad listen address %q: %w", addr, err)
	}
	if IsHost(host) {
		return nil
	}
	return fmt.Errorf("%q is not loopback: admin surfaces listen on 127.0.0.1, ::1 or unix:/path only", addr)
}

// Listen opens addr after Check. A unix socket is created with mode 0600 and
// a stale socket file from a previous run is replaced.
func Listen(addr string) (net.Listener, error) {
	if err := Check(addr); err != nil {
		return nil, err
	}
	p, ok := strings.CutPrefix(addr, "unix:")
	if !ok {
		return net.Listen("tcp", addr)
	}
	if fi, err := os.Lstat(p); err == nil && fi.Mode()&os.ModeSocket != 0 {
		_ = os.Remove(p)
	}
	ln, err := net.Listen("unix", p)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(p, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

// Dialer returns the network and address to dial for an admin address.
func Dialer(addr string) (network, address string) {
	if p, ok := strings.CutPrefix(addr, "unix:"); ok {
		return "unix", p
	}
	return "tcp", addr
}
