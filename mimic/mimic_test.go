package mimic

import (
	"bytes"
	"net"
	"slices"
	"testing"
	"time"
)

func hello(t *testing.T, key []byte, at time.Time) []byte {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	h, err := Hello(a, "example.com", key, at)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestKnockRoundTrip(t *testing.T) {
	key := KnockKey("pool", []byte("secret"))
	h := hello(t, key, time.Now())
	if len(h) < 300 {
		t.Fatalf("hello suspiciously small (%d): not a Chrome hello", len(h))
	}
	if _, ok := ParseKnock(h, key, time.Now()); !ok {
		t.Fatal("valid knock rejected")
	}
	if _, ok := ParseKnock(h, KnockKey("pool", []byte("other")), time.Now()); ok {
		t.Fatal("wrong key accepted")
	}
	if _, ok := ParseKnock(h, key, time.Now().Add(10*time.Minute)); ok {
		t.Fatal("stale knock accepted")
	}
}

func TestHelloIsUnique(t *testing.T) {
	key := KnockKey("pool", []byte("s"))
	a, b := hello(t, key, time.Now()), hello(t, key, time.Now())
	if bytes.Equal(a[11:76], b[11:76]) {
		t.Fatal("random/session id repeated")
	}
}

func serve(t *testing.T, s *Server, data []byte) (int, bool, []byte) {
	t.Helper()
	a, b := net.Pipe()
	go func() { _, _ = a.Write(data); _ = a.Close() }()
	idx, out, ok := s.Classify(b)
	var got []byte
	if !ok {
		pc := out.(*PrefixConn)
		got = pc.Buf
	}
	return idx, ok, got
}

func TestClassify(t *testing.T) {
	key := KnockKey("pool", []byte("secret"))
	s := &Server{Keys: [][]byte{key}, Wait: 200 * time.Millisecond}
	h := hello(t, key, time.Now())
	if idx, ok, _ := serve(t, s, h); !ok || idx != 0 {
		t.Fatal("valid knock not accepted")
	}
	if _, ok, _ := serve(t, s, h); ok {
		t.Fatal("replayed knock accepted")
	}
	bad := hello(t, KnockKey("pool", []byte("nope")), time.Now())
	if _, ok, buf := serve(t, s, bad); ok || !bytes.HasPrefix(bad, buf) || len(buf) == 0 {
		t.Fatal("bad knock must fall back with bytes preserved")
	}
	if _, ok, buf := serve(t, s, []byte("GET / HTTP/1.1\r\n")); ok || len(buf) == 0 {
		t.Fatal("http probe must fall back")
	}
}

func FuzzParseKnock(f *testing.F) {
	f.Add(make([]byte, 80))
	f.Fuzz(func(t *testing.T, b []byte) { ParseKnock(b, []byte("k"), time.Now()) })
}

// The hello must carry the extension set of the Chrome release it imitates
// (17 extensions incl. 51764 and the 0x0904-0x0906 signature schemes); a
// missing one gives a JA4 no real browser has.
func TestHelloMatchesMeasuredChrome(t *testing.T) {
	h := hello(t, KnockKey("pool", []byte("s")), time.Now())
	b := h[9+34:]
	b = b[1+int(b[0]):]
	cl := int(b[0])<<8 | int(b[1])
	b = b[2+cl:]
	b = b[1+int(b[0]):]
	el := int(b[0])<<8 | int(b[1])
	b = b[2 : 2+el]
	var ids []int
	var sigalgs []byte
	for len(b) >= 4 {
		id, l := int(b[0])<<8|int(b[1]), int(b[2])<<8|int(b[3])
		if id == 13 {
			sigalgs = b[6 : 4+l]
		}
		if id&0x0f0f != 0x0a0a {
			ids = append(ids, id)
		}
		b = b[4+l:]
	}
	if len(ids) != 17 {
		t.Fatalf("%d non-GREASE extensions, Chrome 156 sends 17: %v", len(ids), ids)
	}
	if !slices.Contains(ids, 51764) {
		t.Fatal("extension 51764 missing")
	}
	if !bytes.Contains(sigalgs, []byte{0x09, 0x04, 0x09, 0x05, 0x09, 0x06}) {
		t.Fatalf("signature schemes 0x0904-0x0906 missing: %x", sigalgs)
	}
}
