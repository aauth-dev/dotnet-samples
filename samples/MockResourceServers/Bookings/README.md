# Bookings — Rich Resource Requests (R3, four-party)

Aria's external **reservations provider** for dining & experiences (reserve a table,
book a tour). Bookings demonstrates [Rich Resource Requests](../../../docs/workflows/rich-resource-requests.md):
instead of opaque scopes, it publishes a content-addressed **R3 document** describing
what a class of access covers and its human consequences, and the auth token carries
`r3_granted` / `r3_conditional` operations. It is guarded by a **dedicated R3 Access
Server** (`:5501`).

> **Sample only — not part of the AAuth SDK.**

Port: `http://localhost:5005`. Federates to the R3 Access Server at
`http://localhost:5501` (override via `AAuth:AccessServer`); brokers through the
Person Server at `http://localhost:5100`.

## Vocabulary

Bookings is an ASP.NET HTTP API, so it advertises the **OpenAPI** vocabulary
(`urn:aauth:vocabulary:openapi`) in `r3_vocabularies`, pointing at its OpenAPI
document at [`/openapi.json`](http://localhost:5005/openapi.json). R3 operations are
OpenAPI `operationId`s.

## Endpoints

| Path | operationId | Grant | Notes |
|------|-------------|-------|-------|
| `/` | _(index)_ | — | Sample metadata |
| `/openapi.json` | — | — | OpenAPI discovery document (the OpenAPI vocabulary's discovery endpoint) |
| `/authorize` | — | — | Proactive R3 request: the agent posts `r3_operations`; Bookings returns a resource token (`aud` = R3 AS) referencing the R3 document |
| `/search_availability` | `searchAvailability` | `r3_granted` | Read availability — served immediately |
| `/hold_reservation` | `holdReservation` | `r3_granted` | Place a temporary hold — served immediately |
| `/confirm_reservation` | `confirmReservation` | `r3_conditional` | Charges a non-refundable deposit → **per-call proposal**: first call returns `401` + a resource token referencing a single-invocation R3 document carrying the concrete `parameters`; after AS approval the retry (same params) is served |
| `/r3/{hash}` | — | — | The class R3 document — served **only** to a trusted fetcher (the R3 AS / PS), never to agents |
| `/r3/proposals/{hash}` | — | — | Per-call proposal documents (same AS-only fetch gate) |
| `/.well-known/aauth-resource.json` | — | — | Resource metadata (via `MapAAuthWellKnown`), incl. `r3_vocabularies` and `mission_aware` |
| `/.well-known/jwks.json` | — | — | Resource signing JWKS |

`confirm_reservation` is where R3's per-call authorization earns its keep: the AS
authorizes it *in principle* (`r3_conditional`), but the concrete parameters (venue,
date, party size, deposit) are re-evaluated per call before a token is issued, and
the resource verifies the presented parameters match the approved proposal's digest.

## Configuration

| Key | Default | Purpose |
| --- | --- | --- |
| `AAuth:Issuer` | `http://localhost:5005` | Resource issuer / metadata host. |
| `AAuth:AccessServer` | `http://localhost:5501` | R3 Access Server this resource federates to (resource-token `aud`). |
| `AAuth:PersonServer` | `http://localhost:5100` | Person Server (added to the trusted R3-fetcher set for `display`). |
| `AAuth:SignatureWindow` | `60` | Max age (seconds) for inbound RFC 9421 signatures. |
| `Bookings:MissionAware` | `false` | Advertised in metadata only; Bookings does not read or enforce `AAuth-Mission`. |
| `Bookings:TrustedR3Fetchers` | `[AccessServer, PersonServer]` | Origins allowed to fetch R3 documents. |

## Running

```bash
dotnet run --project samples/MockResourceServers/Bookings
```

The four-party R3 flow needs the R3 Access Server (`:5501`) and the Person Server
(`:5100`). All are started together by `make demo`. The end-to-end R3 flow (proactive
authorize, granted vs conditional, per-call proposal + digest enforcement) is
exercised by the in-process [`AAuth.R3.Tests`](../../../tests/AAuth.R3.Tests/) suite.

## See also

- [Rich Resource Requests workflow](../../../docs/workflows/rich-resource-requests.md)
- [Mock Access Servers](../../MockAccessServers/README.md) (the R3 AS at `:5501`)
- [`AAuth.R3` package](../../../src/AAuth.R3/)
- [Mock Resource Servers](../README.md) — the suite overview
