# ADR-011: Wire library versioning and golden vectors

Status: accepted

## Decision

`dotvpn-wire` is semver. The wire contract is `handshake.Version` plus the golden vectors (`TestGoldenRecord`, `TestGoldenKeys`). Changing a vector is a wire break: a major version, or a new `handshake.Version` string while both are accepted. The version is bound into the handshake KDF, so a downgrade fails instead of negotiating silently.

Consumers pin an exact tag in `go.mod`. Their CI runs against the pinned tag and against wire `main` (compatibility matrix). Local development uses an untracked `go.work`; `go.mod` never carries a `replace`.

The version field also lets a fingerprinted carrier (mimic, DNS) be rotated without breaking clients that still speak the old one.

## Consequences

A wire major bump is a flag day for core, relay and client; rollbacks of one component past it need all three rolled back (see each README).
