package transport

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"reflect"
	"testing"
	"time"
)

func TestCandidateAddrs(t *testing.T) {
	for _, tc := range []struct {
		name string
		ep   Endpoint
		want []string
	}{
		{"none", Endpoint{Addr: "h:443"}, []string{"h:443"}},
		{"bare ips take the port", Endpoint{Addr: "h:8443", Params: map[string]string{"ips": "1.1.1.1, 2.2.2.2"}}, []string{"1.1.1.1:8443", "2.2.2.2:8443"}},
		{"explicit ports kept", Endpoint{Addr: "h:443", Params: map[string]string{"ips": "1.1.1.1:444"}}, []string{"1.1.1.1:444"}},
		{"junk falls back", Endpoint{Addr: "h:443", Params: map[string]string{"ips": "nope,,"}}, []string{"h:443"}},
	} {
		if got := CandidateAddrs(tc.ep); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// DialTCP with Options.Upstream tunnels through an HTTP CONNECT proxy and the
// proxy, not the client, sees the destination name.
func TestDialTCPThroughHTTPConnect(t *testing.T) {
	target, _ := net.Listen("tcp", "127.0.0.1:0")
	defer target.Close()
	go func() {
		c, err := target.Accept()
		if err == nil {
			_, _ = c.Write([]byte("hello"))
			_ = c.Close()
		}
	}()
	gotHost := make(chan string, 1)
	px, _ := net.Listen("tcp", "127.0.0.1:0")
	defer px.Close()
	go func() {
		c, err := px.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		req, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil || req.Method != http.MethodConnect {
			return
		}
		gotHost <- req.Host
		up, err := net.Dial("tcp", target.Addr().String())
		if err != nil {
			return
		}
		defer up.Close()
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
		_, _ = io.Copy(c, up)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := DialTCP(ctx, "node.invalid:443", Options{Upstream: "http://" + px.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	b, _ := io.ReadAll(c)
	if string(b) != "hello" || <-gotHost != "node.invalid:443" {
		t.Fatalf("read %q", b)
	}
	if _, err := DialTCP(ctx, "x:1", Options{Upstream: "ftp://127.0.0.1:1"}); err == nil {
		t.Fatal("unsupported scheme must fail")
	}
}
