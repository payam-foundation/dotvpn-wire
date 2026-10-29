# ADR-004: CONNECT for direct, WebSocket + smux for CDN

Status: accepted

## Context

Two carriers for the same stream abstraction.

## Decision

Direct nodes speak HTTP/2 or HTTP/3 `CONNECT`. Cloudflare and Fastly do not reliably forward `CONNECT`, so the CDN adapter is a WebSocket on a path with smux over 2-4 pooled sockets and the JWT in the first frame. Both present the same `Session.OpenStream`.

## Rejected

WebSocket everywhere: loses HTTP/3 and adds framing cost on the direct path.
