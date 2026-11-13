# ADR-023: `dv://` and signed `dvr://` invite schemes

Status: accepted

## Context

Account onboarding used `dotvpn://` and relay sharing used
`dotvpn-relay://<id>`. A bare relay id cannot cold-start a blocked-path client:
it needs dialable reverse/DNS endpoints before the first control refresh.
Legacy prefixes also forced dual parsers across desktop, Android, and admin
scrubbers.

## Decision

- Emit and accept only `dv://` (account invite) and `dvr://` (relay invite).
  Parsers reject legacy prefixes.
- `dvr://` is a control-signed blob: expanded reverse/DNS endpoints for one
  relay plus Ed25519 `sig`/`kid` over the payload. Clients verify before dialing.
- Control mints `dvr://` via `MintRelayInvite` (ExpandReverse for that relay).
  Shareable strings are always full `dvr://`; bare ids remain admin-internal
  opt-in only.
- Account `dv://` may embed Worker mirrors, an optional clear bootstrap blob,
  and a short-lived bootstrap JWT (`t`) so muxstream auth succeeds before the
  first `/v1/token` refresh.
- ADR-019 opt-in still holds: `dvr://` is out-of-band share, not global catalog
  enumeration.

## Consequences

All clients, relays, and admin surfaces must cut over together. Old invites
stop working. Wire `invite` owns both schemes; callers must not concatenate
scheme strings ad hoc.
