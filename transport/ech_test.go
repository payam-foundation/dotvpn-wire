package transport

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// testPKI is one certificate valid for every name the tests use.
type testPKI struct {
	cert tls.Certificate
	pool *x509.CertPool
}

func newPKI(t *testing.T) testPKI {
	t.Helper()
	// The ECH cache is process-wide; every test starts cold.
	echCache.Lock()
	clear(echCache.m)
	echCache.Unlock()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dotvpn test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"public.test", "inner.test", "doh.test"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return testPKI{cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool: pool}
}

// echKey is a server ECH key and its published ECHConfigList.
type echKey struct {
	key  tls.EncryptedClientHelloKey
	list []byte
}

// newECHKey builds an ECHConfig (draft-ietf-tls-esni) for public name
// "public.test" using X25519, HKDF-SHA256 and AES-128-GCM.
func newECHKey(t *testing.T, id byte) echKey {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u16 := func(v int) []byte { return binary.BigEndian.AppendUint16(nil, uint16(v)) }
	pub := priv.PublicKey().Bytes()
	contents := []byte{id}
	contents = append(contents, u16(0x0020)...) // DHKEM(X25519, HKDF-SHA256)
	contents = append(contents, u16(len(pub))...)
	contents = append(contents, pub...)
	contents = append(contents, u16(4)...)
	contents = append(contents, u16(0x0001)...) // HKDF-SHA256
	contents = append(contents, u16(0x0001)...) // AES-128-GCM
	contents = append(contents, 64)             // maximum name length
	contents = append(contents, byte(len("public.test")))
	contents = append(contents, "public.test"...)
	contents = append(contents, u16(0)...) // no extensions
	cfg := append(u16(0xfe0d), u16(len(contents))...)
	cfg = append(cfg, contents...)
	return echKey{
		key:  tls.EncryptedClientHelloKey{Config: cfg, PrivateKey: priv.Bytes(), SendAsRetry: true},
		list: append(u16(len(cfg)), cfg...),
	}
}

type serverSeen struct {
	sni  string
	ech  bool
	alpn string
}

// startTLSServer accepts TLS with the given ECH keys and reports every
// completed handshake.
func startTLSServer(t *testing.T, pki testPKI, keys ...echKey) (addr string, seen chan serverSeen, accepted *atomic.Int32) {
	t.Helper()
	var ks []tls.EncryptedClientHelloKey
	for _, k := range keys {
		ks = append(ks, k.key)
	}
	cfg := &tls.Config{
		Certificates:             []tls.Certificate{pki.cert},
		MinVersion:               tls.VersionTLS13,
		NextProtos:               []string{"h2", "http/1.1"},
		EncryptedClientHelloKeys: ks,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	seen = make(chan serverSeen, 8)
	accepted = new(atomic.Int32)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer c.Close()
				tc := c.(*tls.Conn)
				if tc.Handshake() != nil {
					return
				}
				cs := tc.ConnectionState()
				seen <- serverSeen{cs.ServerName, cs.ECHAccepted, cs.NegotiatedProtocol}
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln.Addr().String(), seen, accepted
}

// httpsRR is a DNS answer carrying list as the ECH parameter.
func httpsRR(name string, list []byte, ttl uint32) *dns.HTTPS {
	rr := &dns.HTTPS{}
	rr.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: ttl}
	rr.Priority = 1
	rr.Target = "."
	rr.Value = []dns.SVCBKeyValue{&dns.SVCBECHConfig{ECH: list}}
	return rr
}

// startDoH serves RFC 8484 POST queries; answer maps a name to its ECH list
// (nil list: empty answer). Hits counts requests.
func startDoH(t *testing.T, pki testPKI, answer func(name string) []byte) (DoHServer, *atomic.Int32) {
	t.Helper()
	hits := new(atomic.Int32)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if q.Unpack(body) != nil || len(q.Question) != 1 || q.Question[0].Qtype != dns.TypeHTTPS {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		m := new(dns.Msg)
		m.SetReply(q)
		if list := answer(q.Question[0].Name); list != nil {
			m.Answer = append(m.Answer, httpsRR(q.Question[0].Name, list, 300))
		}
		out, _ := m.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pki.cert}}
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return DoHServer{URL: "https://doh.test/dns-query", Addr: srv.Listener.Addr().String()}, hits
}

// startPlainDNS serves HTTPS queries over UDP at 127.0.0.1.
func startPlainDNS(t *testing.T, list []byte) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		if list != nil {
			m.Answer = append(m.Answer, httpsRR(q.Question[0].Name, list, 300))
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

var deadDoH = []DoHServer{{URL: "https://doh.test/dns-query", Addr: "127.0.0.1:1"}}

func echDial(t *testing.T, addr, host, policy string, o Options) (net.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ep := Endpoint{Kind: KindH2, Addr: addr, Host: host, Params: map[string]string{"ech": policy}}
	raw, err := DialTCP(ctx, addr, o)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := DialTLS(ctx, raw, ep, o, "h2")
	return c, err
}

func wantSeen(t *testing.T, seen chan serverSeen, sni string, ech bool) {
	t.Helper()
	select {
	case s := <-seen:
		if s.sni != sni || s.ech != ech {
			t.Fatalf("server saw sni=%q ech=%v, want sni=%q ech=%v", s.sni, s.ech, sni, ech)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server saw no completed handshake")
	}
}

func TestECHViaDoH(t *testing.T) {
	pki := newPKI(t)
	key := newECHKey(t, 7)
	addr, seen, _ := startTLSServer(t, pki, key)
	doh, hits := startDoH(t, pki, func(string) []byte { return key.list })
	o := Options{RootCAs: pki.pool, DoH: []DoHServer{doh}, DNS: "127.0.0.1:1"}

	// The outer SNI is "public.test"; the inner, hidden name is inner.test.
	c, err := echDial(t, addr, "inner.test", ECHAuto, o)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	wantSeen(t, seen, "inner.test", true)

	// A second dial inside the TTL is served from the cache.
	before := hits.Load()
	c2, err := echDial(t, addr, "inner.test", ECHAuto, o)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	wantSeen(t, seen, "inner.test", true)
	if hits.Load() != before {
		t.Errorf("DoH queried again within TTL: %d -> %d", before, hits.Load())
	}
}

func TestECHStaticConfig(t *testing.T) {
	pki := newPKI(t)
	key := newECHKey(t, 9)
	addr, seen, _ := startTLSServer(t, pki, key)
	o := Options{RootCAs: pki.pool, DoH: deadDoH, DNS: "127.0.0.1:1"}
	c, err := echDial(t, addr, "inner.test", base64.StdEncoding.EncodeToString(key.list), o)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	wantSeen(t, seen, "inner.test", true)
}

func TestECHAutoWithoutRecordProceedsPlain(t *testing.T) {
	pki := newPKI(t)
	addr, seen, _ := startTLSServer(t, pki, newECHKey(t, 1))
	doh, _ := startDoH(t, pki, func(string) []byte { return nil })
	o := Options{RootCAs: pki.pool, DoH: []DoHServer{doh}, DNS: "127.0.0.1:1"}
	c, err := echDial(t, addr, "plain-auto.test", ECHAuto, o)
	if err == nil {
		c.Close()
		t.Fatal("cert is not valid for plain-auto.test, handshake should fail on verify")
	}
	// Same, with a name the certificate covers: no record, so no ECH but connected.
	c, err = echDial(t, addr, "inner.test", ECHAuto, o)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	wantSeen(t, seen, "inner.test", false)
}

func TestECHRequireFailsClosed(t *testing.T) {
	pki := newPKI(t)
	addr, seen, _ := startTLSServer(t, pki, newECHKey(t, 1))
	t.Run("no HTTPS record", func(t *testing.T) {
		doh, _ := startDoH(t, pki, func(string) []byte { return nil })
		_, err := echDial(t, addr, "inner.test", ECHRequire, Options{RootCAs: pki.pool, DoH: []DoHServer{doh}, DNS: "127.0.0.1:1"})
		if !errors.Is(err, ErrECHRequired) {
			t.Fatalf("err = %v, want ErrECHRequired", err)
		}
	})
	t.Run("resolvers unreachable", func(t *testing.T) {
		_, err := echDial(t, addr, "inner.test", ECHRequire, Options{RootCAs: pki.pool, DoH: deadDoH, DNS: "127.0.0.1:1"})
		if !errors.Is(err, ErrECHRequired) {
			t.Fatalf("err = %v, want ErrECHRequired", err)
		}
	})
	t.Run("server without ECH keys", func(t *testing.T) {
		// A server that does not do ECH sends no retry configs: fail closed.
		plainAddr, _, _ := startTLSServer(t, pki)
		stale := newECHKey(t, 3)
		_, err := echDial(t, plainAddr, "inner.test", ECHRequire, Options{RootCAs: pki.pool, DoH: deadDoH, DNS: startPlainDNS(t, stale.list)})
		if !errors.Is(err, ErrECHRequired) {
			t.Fatalf("err = %v, want ErrECHRequired", err)
		}
	})
	// "server without ECH keys" ran against another server; this one must
	// never have completed a handshake.
	if n := len(seen); n != 0 {
		t.Errorf("require completed %d handshakes without ECH", n)
	}
}

func TestECHRetryConfigs(t *testing.T) {
	pki := newPKI(t)
	current := newECHKey(t, 2)
	stale := newECHKey(t, 1) // the server rotated keys; DNS still shows the old one
	addr, seen, _ := startTLSServer(t, pki, current)
	doh, _ := startDoH(t, pki, func(string) []byte { return stale.list })
	o := Options{RootCAs: pki.pool, DoH: []DoHServer{doh}, DNS: "127.0.0.1:1"}

	c, err := echDial(t, addr, "inner.test", ECHRequire, o)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	wantSeen(t, seen, "public.test", false) // the rejected first attempt, outer name only
	wantSeen(t, seen, "inner.test", true)

	// The retry config replaced the stale one in the cache.
	if cfg, ok := cacheGet("inner.test"); !ok || string(cfg) != string(current.list) {
		t.Error("retry config not cached")
	}
}

func TestECHFallsBackToPlainDNS(t *testing.T) {
	pki := newPKI(t)
	key := newECHKey(t, 5)
	addr, seen, _ := startTLSServer(t, pki, key)
	o := Options{RootCAs: pki.pool, DoH: deadDoH, DNS: startPlainDNS(t, key.list)}
	c, err := echDial(t, addr, "inner.test", ECHRequire, o)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	wantSeen(t, seen, "inner.test", true)
}

// A poisoned plain-DNS answer must not downgrade `require`: DoH is asked
// first, and a wrong config only makes the handshake fail or be corrected.
func TestECHPoisonedPlainDNSIgnoredWhenDoHWorks(t *testing.T) {
	pki := newPKI(t)
	key := newECHKey(t, 6)
	addr, seen, _ := startTLSServer(t, pki, key)
	doh, _ := startDoH(t, pki, func(string) []byte { return key.list })
	o := Options{RootCAs: pki.pool, DoH: []DoHServer{doh}, DNS: startPlainDNS(t, nil)}
	c, err := echDial(t, addr, "inner.test", ECHRequire, o)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	wantSeen(t, seen, "inner.test", true)
}

func TestECHBadParam(t *testing.T) {
	if _, err := parseECH("!!not-base64!!"); err == nil {
		t.Error("bad base64 accepted")
	}
	if !ECHRequired(Endpoint{Params: map[string]string{"ech": ECHRequire}}) || ECHRequired(Endpoint{Params: map[string]string{"ech": ECHAuto}}) {
		t.Error("ECHRequired wrong")
	}
}

func TestDoHFailover(t *testing.T) {
	pki := newPKI(t)
	key := newECHKey(t, 4)
	doh, hits := startDoH(t, pki, func(string) []byte { return key.list })
	servers := []DoHServer{{URL: "https://doh.test/dns-query", Addr: "127.0.0.1:1"}, doh}
	r, err := resolveDoH(context.Background(), "inner.test", servers, Options{RootCAs: pki.pool})
	if err != nil {
		t.Fatal(err)
	}
	if cfg, _ := echFromAnswer(r); string(cfg) != string(key.list) || hits.Load() != 1 {
		t.Errorf("failover answer wrong, hits=%d", hits.Load())
	}
}
