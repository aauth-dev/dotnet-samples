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

Bookings also contains the Wave 6A AAuth Events waitlist sample. The ticket and
subscription store is deliberately in-memory and sample-only; it makes no
durability or production deployment claim.

## Vocabulary

Bookings is an ASP.NET HTTP API, so it advertises the **OpenAPI** vocabulary
(`urn:aauth:vocabulary:openapi`) in `r3_vocabularies`, pointing at its OpenAPI
document at [`/openapi.json`](http://localhost:5005/openapi.json). R3 operations are
OpenAPI `operationId`s.

The same caller-owned vocabulary map also advertises the AAuth Events
**AsyncAPI** vocabulary at [`/asyncapi.json`](http://localhost:5005/asyncapi.json).
The document is validated with `AsyncApiAAuthValidator` during startup. It uses
the draft's `action: receive`, a protected
`/waitlist/subscriptions/{subscriptionTicket}` channel, and a direct
`application/json` `slot.available` payload.

## Endpoints

| Path | operationId | Grant | Notes |
|------|-------------|-------|-------|
| `/` | _(index)_ | — | Sample metadata |
| `/openapi.json` | — | — | OpenAPI discovery document (the OpenAPI vocabulary's discovery endpoint) |
| `/authorize` | — | — | Proactive R3 request: the agent posts `r3_operations`; Bookings returns a resource token (`aud` = R3 AS) referencing the R3 document |
| `/search_availability` | `searchAvailability` | `r3_granted` | Read availability — served immediately |
| `/hold_reservation` | `holdReservation` | `r3_granted` | Place a temporary hold — served immediately |
| `/confirm_reservation` | `confirmReservation` | `r3_conditional` | Charges a non-refundable deposit → **per-call proposal**: first call returns `401` + a resource token referencing a single-invocation R3 document carrying the concrete `parameters`; the R3 AS requires **human approval** (`202` → consent screen) before minting the per-call token; the retry (same params) is then served |
| `/r3/{hash}` | — | — | The class R3 document — served **only** to a trusted fetcher (the R3 AS / PS), never to agents |
| `/r3/proposals/{hash}` | — | — | Per-call proposal documents (same AS-only fetch gate) |
| `/.well-known/aauth-resource.json` | — | — | Resource metadata (via `MapAAuthWellKnown`), incl. `r3_vocabularies` and `mission_aware` |
| `/.well-known/jwks.json` | — | — | Resource signing JWKS |
| `/waitlist/request` | — | `searchAvailability` | Authenticated unavailable response containing a short-lived, single-use subscription URL |
| `/waitlist/subscriptions/{subscriptionTicket}` | — | Events subscribe token | Protected registration for `slot.available`; the ticket is agent-bound and cannot be widened or reused |
| `/waitlist/subscriptions/{eid}/trigger` | — | authenticated | Deterministic bodyless trigger; sends the direct JSON event to the AP's discovered endpoint |

`confirm_reservation` is where R3's per-call authorization earns its keep: the AS
authorizes it *in principle* (`r3_conditional`), but the concrete parameters (venue,
date, party size, deposit) are surfaced to the user for **per-call consent** and
re-evaluated before a token is issued, and the resource verifies the presented
parameters match the approved proposal's digest.

## Configuration

| Key | Default | Purpose |
| --- | --- | --- |
| `AAuth:Issuer` | `http://localhost:5005` | Resource issuer / metadata host. |
| `AAuth:AccessServer` | `http://localhost:5501` | R3 Access Server this resource federates to (resource-token `aud`). |
| `AAuth:PersonServer` | `http://localhost:5100` | Person Server (added to the trusted R3-fetcher set for `display`). |
| `AAuth:SignatureWindow` | `60` | Max age (seconds) for inbound RFC 9421 signatures. |
| `Bookings:MissionAware` | `false` | Advertised in metadata only; Bookings does not read or enforce `AAuth-Mission`. |
| `Bookings:TrustedR3Fetchers` | `[AccessServer, PersonServer]` | Origins allowed to fetch R3 documents. |
| `Events:TicketLifetimeSeconds` | `300` | Sample-only ticket lifetime. |
| `Events:SubscriptionLifetimeSeconds` | `3600` | Application subscription expiry (not a wire claim). |
| `Events:EventLifetimeSeconds` | `300` | Sample event-token lifetime. |
| `Events:MaxBodyBytes` | `1048576` | Events registration/event body limit. |

## Running

```bash
dotnet run --project samples/MockResourceServers/Bookings
```

The four-party R3 flow needs the R3 Access Server (`:5501`) and the Person Server
(`:5100`). All are started together by `make demo`. The end-to-end R3 flow (proactive
authorize, granted vs conditional, per-call proposal + digest enforcement) is
exercised by the in-process [`AAuth.R3.Tests`](../../../tests/AAuth.R3.Tests/) suite.

For the waitlist flow, present an AAuth auth token with the existing
`searchAvailability` grant:

1. `POST /waitlist/request` to receive `waitlist.subscribe_url`.
2. Register the AP-issued Events subscribe token at that URL (the registration
   uses the agent confirmation key and may contain only `slot.available`).
3. `POST /waitlist/subscriptions/{eid}/trigger` with the same authenticated
   agent to deliver one deterministic event.

Events discovery and delivery use the package's no-redirect URL policy and
current AP metadata endpoint. AP polling and all persistence in this sample are
non-normative; production hosts must provide their own durable AP and agent
stores. The sample follows the draft deviations recorded by AAuth.Events:
direct JSON payloads, `action: receive`, application-owned `ExpiresAt`, and
sample-only authenticated transport.

## See also

- [Rich Resource Requests workflow](../../../docs/workflows/rich-resource-requests.md)
- [Mock Access Servers](../../MockAccessServers/README.md) (the R3 AS at `:5501`)
- [`AAuth.R3` package](../../../src/AAuth.R3/)
- [Mock Resource Servers](../README.md) — the suite overview
