# ADR-008: Signed server list and multi-channel discovery

Status: accepted (extended for dual-blob)

## Context

The server list survives hostile channels. A single cleartext full-fleet mirror
is scrapeable by censors.

## Decision

The list is signed by control, so it can travel over any untrusted channel.

Dual-blob discovery:

1. **Bootstrap** — clear `Signed` list of live system + public reverse relays
   only, served from a short Cloudflare Worker (`dvb`). Policy
   `ServerListPolicy=bootstrap`.
2. **Fleet** — `FleetBlob`: AES-256-GCM over a Signed full inventory, outer
   Ed25519 over the envelope. Served from S3/GitHub. Unwrap key
   (`fleet_key` / `fleet_key_id` / `fleet_urls`) arrives only in an
   authenticated `TokenResponse`. Policy `ServerListPolicy=fleet`.

Cold start (path A): fetch bootstrap → tunnel `/v1/token` via
`ControlChannel.Relay` → decrypt fleet → connect → refresh again after VPN.

Clients try, in order: control direct, control via CDN, control via relay,
Worker bootstrap, encrypted fleet mirrors (with key), cache, embedded
bootstrap. Verified decrypted lists are cached on disk. Generation counters
reject mixing bootstrap gen N with fleet gen N-1.

Invite field `m` carries the Worker bootstrap URL; `b` remains an optional
embedded fallback.

`GET /v1/servers` requires an account Bearer (no anonymous clear dump).

## Rejected

Single control URL: one block takes every client offline.
Cleartext full-fleet public mirrors.
