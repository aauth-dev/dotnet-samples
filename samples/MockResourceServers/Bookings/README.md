# Bookings — R3 and AAuth Events sample

Bookings is the sample reservations resource at
`http://localhost:5005`. It demonstrates R3 authorization and a protected
AAuth Events waitlist. **Everything in this project is sample-only.**

## Events routes

| Method and route | Status | Purpose |
|---|---|---|
| `POST /waitlist/request` | AAuth-protected | Returns `waitlist.subscribe_url`, `event_types: ["slot.available"]`, and `offer_window_seconds`. |
| `POST /waitlist/subscriptions/{subscriptionTicket}` | Events protected channel | Presents the AP subscribe token as `Signature-Key`; accepts direct JSON preferences and returns `200 {"event_types":["slot.available"]}`. |
| `POST /waitlist/subscriptions/{eid}/trigger` | AAuth-protected | Sends one deterministic `slot.available` event to the AP's current discovered `event_endpoint`. |
| `GET /asyncapi.json` | Public discovery | AsyncAPI 3.0.0 document for the waitlist channel. |
| `/.well-known/aauth-resource.json` | Public discovery | Resource metadata, including the composed `r3_vocabularies` map. |

The `waitlist-subscriptions` channel is a protected
`SubscriptionChannel` with route value `subscriptionTicket`. Its opaque ticket
is short-lived, single-use, and bound to the authenticated agent. The
registration body is direct `application/json`; its event-type preference is
signature-unbound and cannot widen the channel's single allowed event type.

The resource uses `EventEndpointResolver` and `EventDeliveryClient`; the AP
endpoint is read from current `/.well-known/aauth-agent.json`, not copied from
the subscribe token.

## Configuration

The defaults are in `appsettings.json`:

| Key | Default | Meaning |
|---|---|---|
| `AAuth:Issuer` | `http://localhost:5005` | Resource issuer and metadata host. |
| `AAuth:AccessServer` | `http://localhost:5501` | R3 Access Server. |
| `AAuth:PersonServer` | `http://localhost:5100` | Person Server. |
| `AAuth:SignatureWindow` | `60` | Core signature age in seconds. |
| `Events:SignatureWindow` | `60` | Events registration signature age. |
| `Events:FutureSkew` | `5` | Allowed future signature skew in seconds. |
| `Events:MaxBodyBytes` | `1048576` | Events body limit (1 MiB). |
| `Events:TicketLifetimeSeconds` | `300` | Sample ticket lifetime. |
| `Events:SubscriptionLifetimeSeconds` | `3600` | Application `ExpiresAt` policy; not a wire claim. |
| `Events:EventLifetimeSeconds` | `300` | Event-token lifetime, bounded by subscription expiry. |

The event payload is a direct JSON object containing
`reservation_id`, `venue`, `date`, `party_size`, `available`, and
`offer_expires_at`. It is authenticated only on the resource-to-AP HTTP hop;
the event JWT does not authenticate payload bytes to the agent.

## Run

For the focused stack:

```bash
make events-stack
# in another terminal
make agent-events
```

To run Bookings by itself:

```bash
dotnet run --project samples/MockResourceServers/Bookings
```

The focused stack starts the Person Server (`:5100`), Mock Agent Provider
(`:5301`), R3 Access Server (`:5501`), and Bookings (`:5005`). The full
four-party R3 stack is also available through `make demo`.

## Normative boundary

The Events package's resource registration, token validation, direct JSON body,
HTTP signature profiles, current metadata resolution, and resource-to-AP
delivery are the protocol-facing pieces. The deterministic trigger, this
sample's in-memory ticket/subscription state, and the AP's polling/ACK
transport are **non-normative**. No sample storage is durable or production
conformant; production resources and APs must supply durable atomic storage.

See the [AAuth Events workflow](../../../docs/workflows/aauth-events.md) and
the [Mock Agent Provider](../../MockAgentProvider/README.md).
