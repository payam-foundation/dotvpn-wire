# ADR-018: UDP over tunnel streams

Status: accepted

## Context

The TUN front dropped all UDP except DNS, so QUIC, STUN and VoIP leaked or failed. H3 datagrams would only work on one carrier; operators need UDP on h2, cdnws and relay paths too.

## Decision

UDP is a stream kind. After the normal token auth, the client opens a stream whose authority is a UDP target and exchanges length-framed datagrams (`transport/udpframe`): `u16 big-endian length | payload`, payload at most 1472 bytes. Frames preserve datagram boundaries over a byte stream. Golden vector: `"hi!"` frames as `0003686921` (`TestGoldenFrame`); `FuzzUDPFrame` covers decode.

Carriers:

- h2connect / h3connect: the CONNECT request carries `Dotvpn-Net: udp`. The header is read only after bearer validation, so unauthenticated probes still get the decoy.
- muxstream (cdnws, relay): the stream auth frame target is prefixed `udp://`.

Optional interfaces keep the seam small: `UDPSession` (`OpenUDP(ctx, authority) (net.Conn, error)`) on sessions, `UDPBackend` (`DialUDP(ctx, user, authority)`) on backends. A backend without it refuses the stream.

Capability: nodes advertise `Params["udp"]="1"` (`Endpoint.UDP()`) in the signed server list. The client calls `OpenUDP` only then, so an older node never mis-splices a datagram stream as TCP. Otherwise `Engine.DialPacket` returns `ErrNoUDP`.

Node policy (`Backend.DialUDP`): port allow-list (53, 123, 443, 3478 by default), resolved-IP SSRF guard shared with TCP, per-user concurrency slot shared with TCP, 256 flows per user, 30 s idle timeout, rate limit and byte metering. No new logging.

Client: TUN `onUDP` keeps DNS on fakedns, sends other UDP through `Engine.DialPacket` or, for router-direct destinations, the bypass dialer. Without `Packet` non-DNS UDP is dropped as before. The kill switch is unchanged: UDP leaves only through the tunnel.

## Consequences

- Wire VERSION is v0.2.0 (ADR-011); the handshake version is unchanged, old clients and nodes interoperate because of the capability flag.
- UDP over TCP carriers has head-of-line blocking; acceptable for DNS, STUN and QUIC handshakes.
- H3-only paths are intentionally not offered datagrams; a UDP-blocked network falls back to h2 and UDP rides h2.

## Rejected

QUIC datagrams only: single carrier, useless where QUIC is blocked. A separate UDP port on the node: new fingerprint and probe surface.
