# ADR-019: Account and relay client surface

Status: accepted

## Context

The desktop client needs a safe account view (name, quota, plan end) and a way
to opt into community relays without learning addresses or keys. Country labels
on nodes and relays need a non-breaking way into the signed endpoint list.

## Decision

- `GET /v1/account` (Bearer account key) returns a redacted account view.
- `GET /v1/relays?ids=` returns curated public relays plus opted-in ids with
  `id`, `name`, `country`, `tier`, coarse `health` only.
- `POST /v1/token` already accepted `"relays": []`; the discovery client now
  sends that field from `Client.Relays`.
- Endpoint country is carried as `Params["cc"]` (ISO-3166 alpha-2). Additive;
  no wire version bump.
- Plan `expires` refuses new tokens the same way as quota exhaustion; admin
  renews by PATCHing `expires`.

## Consequences

Older clients ignore unknown JSON and `cc`. New clients must pin a wire release
that includes the discovery `Relays` field.
