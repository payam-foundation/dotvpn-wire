// Package udpframe carries UDP datagrams over a byte stream: each datagram is
// "u16 length | payload". The stream is an ordinary authenticated tunnel
// stream, so UDP rides every carrier that can carry TCP.
//
//	client <-> node: u16 len | datagram | u16 len | datagram | ...
//
// Order and delivery are the stream's, not UDP's: a lost packet stalls the
// ones behind it (head-of-line blocking). That is the price of working on h2,
// cdnws and relay paths; real-time media tolerates it less than QUIC does.
package udpframe

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
)

// MaxPayload is the largest datagram a frame may carry. It covers a full
// 1500-byte Ethernet MTU (1472 for IPv4 UDP) with room for the 1252-byte
// QUIC datagrams browsers send.
const MaxPayload = 1472

var (
	// ErrTooLarge is returned for a datagram above MaxPayload; the datagram is
	// dropped and the stream stays usable.
	ErrTooLarge = errors.New("udpframe: datagram too large")
	// ErrFrame is a received length above MaxPayload: the peer is broken or
	// hostile and the stream cannot be resynchronised.
	ErrFrame = errors.New("udpframe: oversized frame")
)

// Append appends one frame for p to dst, or returns ErrTooLarge.
func Append(dst, p []byte) ([]byte, error) {
	if len(p) > MaxPayload {
		return dst, ErrTooLarge
	}
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(p)))
	return append(dst, p...), nil
}

// Read reads one frame into buf (len >= MaxPayload) and returns the payload
// length. A length above MaxPayload is ErrFrame; the stream is then unusable.
func Read(r io.Reader, buf []byte) (int, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n > MaxPayload || n > len(buf) {
		return 0, ErrFrame
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return 0, err
	}
	return n, nil
}

// Conn is the datagram view of a stream: every Write sends one datagram and
// every Read returns one, like a connected UDP socket.
type Conn struct {
	net.Conn
	br  *bufio.Reader
	rmu sync.Mutex
	wmu sync.Mutex
}

// NewConn wraps a stream. The stream's addresses and deadlines are passed
// through (multiplexed carrier streams ignore deadlines).
func NewConn(s net.Conn) *Conn { return &Conn{Conn: s, br: bufio.NewReaderSize(s, 2*(MaxPayload+2))} }

// Read returns the next datagram, truncated to len(p) like UDP does.
func (c *Conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	var buf [MaxPayload]byte
	n, err := Read(c.br, buf[:])
	if err != nil {
		return 0, err
	}
	return copy(p, buf[:n]), nil
}

// Write sends p as one datagram; above MaxPayload it fails with ErrTooLarge
// and sends nothing.
func (c *Conn) Write(p []byte) (int, error) {
	f, err := Append(make([]byte, 0, len(p)+2), p)
	if err != nil {
		return 0, err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if _, err := c.Conn.Write(f); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Relay joins a framed stream to a datagram socket until either side ends,
// then closes both. dgram must preserve datagram boundaries (a connected UDP
// socket). Datagrams above MaxPayload from dgram are dropped.
func Relay(stream io.ReadWriteCloser, dgram io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() { // stream -> socket
		defer func() { done <- struct{}{} }()
		br := bufio.NewReaderSize(stream, 2*(MaxPayload+2))
		var buf [MaxPayload]byte
		for {
			n, err := Read(br, buf[:])
			if err != nil {
				return
			}
			if _, err := dgram.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	go func() { // socket -> stream
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 65535)
		out := make([]byte, 0, MaxPayload+2)
		for {
			n, err := dgram.Read(buf)
			if err != nil {
				return
			}
			f, err := Append(out[:0], buf[:n])
			if err != nil {
				continue
			}
			if _, err := stream.Write(f); err != nil {
				return
			}
		}
	}()
	<-done
	_ = stream.Close()
	_ = dgram.Close()
	<-done
}
