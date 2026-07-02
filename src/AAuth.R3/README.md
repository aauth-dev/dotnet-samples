# AAuth.R3 (preview)

Experimental helpers for **AAuth Rich Resource Requests (R3)** — resource-declared,
vocabulary-based authorization layered on the [AAuth](https://www.nuget.org/packages/AAuth)
protocol. Resources publish content-addressed R3 documents describing what a class
of access *means*; tokens carry `r3_uri`, `r3_s256`, `r3_granted`, and
`r3_conditional` alongside opaque scopes.

> **Preview.** R3 is an IETF Exploratory Draft (`draft-hardt-aauth-r3`). This package
> ships separately from `AAuth` and may change with the draft. It tracks the `AAuth`
> package version.

## What's inside

- R3 models (`R3Document`, `R3Operations`, `R3Grant`, `R3Operation`, `R3Display`,
  proposal document). Operations are **vocabulary-agnostic** — one self-describing
  `R3Operation` (`R3Operation.Mcp(tool)` / `R3Operation.OpenApi(operationId)` / …)
  serializes to the vocabulary's single-key shape and round-trips byte-stably.
- Content addressing (`R3Hash`) — SHA-256 over the verbatim served bytes, base64url
  (no canonicalization).
- Claim helpers (`R3AuthClaims`, `R3ClaimReader`) that ride the core token builders'
  `AdditionalClaims` seam.
- Server helpers: AS-only R3-document endpoint, AS-signed fetch + hash-verify,
  per-call proposal challenge + digest enforcement, and an audit sink.

## Status

Preview. The AAuth samples show a runnable end-to-end R3 flow (the **Bookings**
resource, guarded by a dedicated R3 Access Server, using the **OpenAPI** vocabulary).
