package transport

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// dialUpstream reaches addr through the proxy at rawURL. The proxy hop itself
// is dialled with d, so Options.Control still pins it to the physical
// interface. addr is resolved by the proxy, not locally.
func dialUpstream(ctx context.Context, d *net.Dialer, rawURL, addr string) (net.Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("transport: bad upstream proxy %q", rawURL)
	}
	hostport := u.Host
	if u.Port() == "" {
		def := map[string]string{"socks5": "1080", "socks5h": "1080", "http": "8080"}[u.Scheme]
		hostport = net.JoinHostPort(u.Hostname(), def)
	}
	switch u.Scheme {
	case "socks5", "socks5h":
		var a *proxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			a = &proxy.Auth{User: u.User.Username(), Password: pw}
		}
		p, err := proxy.SOCKS5("tcp", hostport, a, d)
		if err != nil {
			return nil, err
		}
		return p.(proxy.ContextDialer).DialContext(ctx, "tcp", addr)
	case "http":
		return httpConnect(ctx, d, u, hostport, addr)
	}
	return nil, fmt.Errorf("transport: upstream scheme %q not supported (socks5, http)", u.Scheme)
}

func httpConnect(ctx context.Context, d *net.Dialer, u *url.URL, hostport, addr string) (net.Conn, error) {
	c, err := d.DialContext(ctx, "tcp", hostport)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	} else {
		_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	}
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: addr}, Host: addr, Header: http.Header{}}
	if u.User != nil {
		pw, _ := u.User.Password()
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+pw)))
	}
	if err := req.Write(c); err != nil {
		_ = c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = c.Close()
		return nil, fmt.Errorf("transport: upstream proxy refused CONNECT: %s", resp.Status)
	}
	_ = c.SetDeadline(time.Time{})
	if br.Buffered() > 0 { // bytes the server sent right behind the 200
		return &bufConn{Conn: c, r: br}, nil
	}
	return c, nil
}

// bufConn reads through br so nothing buffered past the CONNECT reply is lost.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }
