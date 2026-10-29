# ADR-017: ECH policy, DoH resolution and fail-closed mode

Status: accepted

## Context

ECH hides the real server name behind a public one. Until now `Params["ech"]="auto"` looked up the HTTPS record over plain UDP/TCP DNS, which a censor can block or poison, and any failure silently meant no ECH. An operator who chose ECH could not tell that it was off.

## Decision

`Endpoint.Params["ech"]` is a policy:

| Value | Behaviour |
| --- | --- |
| empty | No ECH config. The Chrome preset still sends its ECH GREASE extension (extension 65037), so the hello shape does not change. |
| `auto` | Look up the config; no config means continue without it (GREASE hello). |
| `require` | Fail closed. No config, resolver failure, or a server that rejects ECH without retry configs is `ErrECHRequired`; the endpoint goes to cooldown. Carriers that cannot do ECH (h3, QUIC through crypto/tls) refuse the endpoint so the ladder moves on. |
| base64 | A fixed ECHConfigList, treated as `require`. |

Resolution (`transport/ech.go`): DNS-over-HTTPS (RFC 8484 POST, `application/dns-message`) to resolvers dialled by pinned IP (Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9 9.9.9.9), the next one started after one second without an answer. Sockets use `Options.Control`/`Resolver`, so they bypass the tunnel. If every DoH server fails, plain DNS at `Options.DNS` is tried. A poisoned plain answer cannot downgrade `require`: a wrong config makes the handshake fail or be corrected by retry configs. Answers are cached for the record TTL, clamped to 1 minute to 1 hour.

Rejection: when the server cannot decrypt the inner hello, uTLS returns `ECHRejectionError`, and the outer certificate was verified for the public name. `DialTLS` redials once with the server's retry config list and caches it. Rejected again, or no retry configs under `require`, is `ErrECHRequired`.

GREASE: utls v1.8.2 `HelloChrome_133` includes `GREASEEncryptedClientHelloExtension`. The lab fingerprint suite (`TestECHHelloMatchesChrome`) asserts the Chrome 156 JA4 and extension set both with GREASE and with a real config.

## Consequences

- `ech=require` is the setting for endpoints behind a CDN that publishes ECH; `auto` stays the default for convenience.
- DoH resolvers are visible to the network as TLS to well-known IPs. A censor that blocks them forces the plain-DNS fallback (`auto`) or a dial error (`require`). Operators in that case ship the base64 config.
- `Options.DoH` replaces the resolver list for private deployments and tests.

## Rejected

DoH through the tunnel: the tunnel needs the config to be established. Pinning only one resolver: a single block disables ECH.
