// SPDX-License-Identifier: AGPL-3.0-only OR PolyForm-Noncommercial-1.0.0

package transport

import "time"

// Session liveness budgets shared by every carrier.
//
// Restricted networks and CGNAT commonly expire quiet UDP/TCP flows around
// 30s. Keepalives must land well under that, and the dead-peer timeout must
// tolerate several lost probes before tearing the session down. Carriers that
// invent their own shorter idle windows cause the 30–40s drops seen on H3.
const (
	// KeepAliveInterval is how often a quiet session probes the peer.
	KeepAliveInterval = 10 * time.Second
	// KeepAliveTimeout is how long without a keepalive response (or any
	// traffic) before the carrier treats the session as dead.
	KeepAliveTimeout = 2 * time.Minute
	// MaxIdleTimeout is the QUIC/HTTP idle bound. Must be >= KeepAliveTimeout
	// so keepalives can keep the connection alive.
	MaxIdleTimeout = 3 * time.Minute
	// PingTimeout is how long an HTTP/2 PING may wait for an ACK.
	PingTimeout = 15 * time.Second
	// WriteByteTimeout bounds a stalled HTTP/2 write.
	WriteByteTimeout = 30 * time.Second
)
