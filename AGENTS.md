# dotvpn-wire

Shared protocol library for dotvpn. Module `github.com/payam-foundation/dotvpn-wire`. Imported by `dotvpn-core`, `dotvpn-relay`, `dotvpn-client` and `dotvpn-lab`; imports none of them.

Contents: frame codec, Ed25519 token/JWT, invite codec, X25519 handshake, Endpoint/Pin, Dialer/Listener seams, mimic (Chrome ClientHello, knock) and DNS carrier, reverse-pool carrier, muxstream, loopback check.

## Commands

```sh
go build ./... && go vet ./...
go test -race -count=1 ./...
go test -run '^$' -fuzz '^Name$' -fuzztime 30s ./pkg   # FuzzRead (frame), FuzzRespond (handshake), FuzzParseKnock (mimic), FuzzReadAuth (reverse), FuzzDecode (dnscarrier)
```

## Invariants

- Semver. `VERSION` (no `v` prefix) must match the release tag; release-please bumps both. The wire contract is `handshake.Version` plus the golden vectors (`TestGoldenRecord`, `TestGoldenKeys`). Change a vector deliberately and bump the version (ADR-011).
- Every length-prefixed reader has a size cap. Keep it when adding readers.
- TLS pins use `VerifyConnection` (survives session resumption). No new `InsecureSkipVerify` unless pinned or loopback-only.
- After a change run the three dependants (`dotvpn-core`, `dotvpn-relay`, `dotvpn-client`) and `dotvpn-lab`.

## Shared rules

- Static builds: `CGO_ENABLED=0`, `-trimpath`. Docker base images pinned by digest, distroless, non-root.
- Secrets never go in the repo, unit files, env files or CI. Keys are written 0600/0640.
- Go style: stdlib first, no new dependency for what a few lines do, no placeholder code. Mark deliberate shortcuts with a `ponytail:` comment naming the ceiling and the upgrade path.
- Each repo is its own git repo and Go module. Sibling repos live next to this one; do not import across core, relay and client. Anything two of them must agree on goes in `dotvpn-wire`.

## Docs

`docs/adr/`: ADR-003, 004, 007, 008, 011, 017, 018. Cross-repo index: `../dotvpn-lab/docs/adr/README.md`.

## Flow

Pull requests only, never push to `main`. PR title is a Conventional Commit, commits are signed off (`git commit -s`), merges are squash-only. Releases come from release-please. See `CONTRIBUTING.md`.
