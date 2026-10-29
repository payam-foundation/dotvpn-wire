# ADR-007: Own-infrastructure Snowflake and WebTunnel

Status: accepted

## Context

Extra transports we run ourselves.

## Decision

WebTunnel is mounted on a secret path of the node's decoy domain and looks like an ordinary HTTPS WebSocket. Snowflake uses an embedded server, our own broker, and `dotvpn proxy` volunteers. Honest limit: Tor's public proxy pool only relays to Tor bridges, so capacity equals the proxies we or supporters run. Snowflake is the blackout tier, last in the ladder.

## Rejected

Relying on Tor's public Snowflake pool: not possible for non-Tor destinations.
