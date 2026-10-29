// Package frame is the record layer of the wire protocol. Every record is
//
//	mask(2) | AEAD(type(1) | n(2) | data(n) | padding)
//
// The two header bytes are the ciphertext length XOR a keystream word, so no
// byte of a record is constant or a visible counter. Records are padded to a
// caller-chosen size and an optional idle task emits cover records at jittered
// intervals. Keys come from package handshake (or any 128 byte KDF output).
package frame

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	typeData  = 0
	typePad   = 1
	typeClose = 3

	// MaxData is the largest payload of one record.
	MaxData = 16000
	tagLen  = 16
	maxSeq  = 1<<62 - 1
)

// Keys are the per-direction secrets. Send and Recv must be swapped between
// the two ends.
type Keys struct {
	SendKey, RecvKey   [32]byte
	SendMask, RecvMask [32]byte
}

// Opts shapes the wire image. The zero value pads every record by 0-31 random
// length bytes and sends no idle cover traffic.
type Opts struct {
	// Pad returns the padding bytes to add to a record carrying n data bytes.
	// Nil means uniform 0-31. It must not be negative or exceed 2048.
	Pad func(n int) int
	// Idle is the mean interval of cover records when the link is quiet; each
	// wait is uniform in [Idle/2, 3*Idle/2]. Zero disables cover traffic.
	Idle time.Duration
}

// ErrRecord means a record failed length or authentication checks. The
// connection is unusable afterwards.
var ErrRecord = errors.New("frame: malformed record")

// Conn is a framed, encrypted net.Conn.
type Conn struct {
	net.Conn
	o Opts

	wmu  sync.Mutex
	wseq uint64
	wa   cipher.AEAD
	wmk  [32]byte

	rmu  sync.Mutex
	rseq uint64
	ra   cipher.AEAD
	rmk  [32]byte
	rbuf []byte
	rerr error

	lastWrite atomic.Int64
	done      chan struct{}
	once      sync.Once
}

func gcm(key [32]byte) cipher.AEAD {
	b, _ := aes.NewCipher(key[:])
	a, _ := cipher.NewGCM(b)
	return a
}

// New wraps c. It starts the idle task when o.Idle > 0.
func New(c net.Conn, k Keys, o Opts) *Conn {
	f := &Conn{Conn: c, o: o, wa: gcm(k.SendKey), ra: gcm(k.RecvKey), wmk: k.SendMask, rmk: k.RecvMask, done: make(chan struct{})}
	f.lastWrite.Store(time.Now().UnixNano())
	if o.Idle > 0 {
		go f.idle()
	}
	return f
}

func nonce(seq uint64) []byte {
	var n [12]byte
	binary.BigEndian.PutUint64(n[4:], seq)
	return n[:]
}

func mask(key [32]byte, seq uint64) uint16 {
	var b [40]byte
	copy(b[:], key[:])
	binary.BigEndian.PutUint64(b[32:], seq)
	s := sha256.Sum256(b[:])
	return binary.BigEndian.Uint16(s[:2])
}

func randN(n int) int {
	if n <= 1 {
		return 0
	}
	v, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
	return int(v.Int64())
}

func (c *Conn) padFor(n int) int {
	if c.o.Pad != nil {
		return min(max(c.o.Pad(n), 0), 2048)
	}
	return randN(32)
}

func (c *Conn) writeRecord(t byte, data []byte, pad int) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.wseq >= maxSeq {
		return errors.New("frame: sequence exhausted, rekey")
	}
	seq := c.wseq
	c.wseq++
	plain := make([]byte, 3+len(data)+pad)
	plain[0] = t
	binary.BigEndian.PutUint16(plain[1:], uint16(len(data)))
	copy(plain[3:], data)
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(plain)+tagLen)^mask(c.wmk, seq))
	out := c.wa.Seal(append(make([]byte, 0, 2+len(plain)+tagLen), hdr[:]...), nonce(seq), plain, hdr[:])
	c.lastWrite.Store(time.Now().UnixNano())
	_, err := c.Conn.Write(out)
	return err
}

// Write sends p in records of at most MaxData bytes.
func (c *Conn) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		k := min(len(p), MaxData)
		if err := c.writeRecord(typeData, p[:k], c.padFor(k)); err != nil {
			return n, err
		}
		n += k
		p = p[k:]
	}
	return n, nil
}

func (c *Conn) readRecord() (byte, []byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]) ^ mask(c.rmk, c.rseq))
	if n < 3+tagLen {
		return 0, nil, ErrRecord
	}
	ct := make([]byte, n)
	if _, err := io.ReadFull(c.Conn, ct); err != nil {
		return 0, nil, err
	}
	plain, err := c.ra.Open(nil, nonce(c.rseq), ct, hdr[:])
	if err != nil {
		return 0, nil, ErrRecord
	}
	c.rseq++
	l := int(binary.BigEndian.Uint16(plain[1:3]))
	if 3+l > len(plain) {
		return 0, nil, ErrRecord
	}
	return plain[0], plain[3 : 3+l], nil
}

// Read returns data records; cover records are skipped, a close record is EOF.
// Any malformed or forged record is fatal for the connection.
func (c *Conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.rbuf) == 0 {
		if c.rerr != nil {
			return 0, c.rerr
		}
		t, d, err := c.readRecord()
		switch {
		case err != nil:
			c.rerr = err
		case t == typeClose:
			c.rerr = io.EOF
		case t == typeData:
			c.rbuf = d
		}
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

func (c *Conn) idle() {
	for {
		base := c.o.Idle
		wait := base/2 + time.Duration(randN(int(base)))
		select {
		case <-c.done:
			return
		case <-time.After(wait):
		}
		if time.Since(time.Unix(0, c.lastWrite.Load())) < wait/2 {
			continue
		}
		if c.writeRecord(typePad, make([]byte, randN(256)), randN(64)) != nil {
			return
		}
	}
}

// Close sends a close record (best effort) and closes the carrier.
func (c *Conn) Close() error {
	c.once.Do(func() {
		close(c.done)
		_ = c.Conn.SetWriteDeadline(time.Now().Add(time.Second))
		_ = c.writeRecord(typeClose, nil, c.padFor(0))
	})
	return c.Conn.Close()
}
