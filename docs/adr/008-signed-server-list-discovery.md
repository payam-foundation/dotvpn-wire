# ADR-008: Signed server list and multi-channel discovery

Status: accepted

## Context

The server list survives hostile channels.

## Decision

The list is signed by control, so it can travel over any untrusted channel. Clients try, in order: control direct, control via CDN, control via relay, an embedded signed bootstrap list, DoH TXT, static mirrors. Verified lists are cached on disk.

## Rejected

Single control URL: one block takes every client offline.
