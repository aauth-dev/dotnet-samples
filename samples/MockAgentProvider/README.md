# MockAgentProvider

> **Sample only — not part of the AAuth SDK.** The registry and Events inbox
> are in-memory and are lost when the process stops.

This ASP.NET sample AP listens at `http://localhost:5301` by default. It
implements bootstrap enrollment/refresh plus the protocol-facing Events
delivery endpoint. Its agent-to-AP acquisition, polling, and ACK routes are
**non-normative sample transport**.

## Routes

| Method and route | Boundary | Description |
|---|---|---|
| `GET /.well-known/aauth-agent.json` | bootstrap + Events discovery | Publishes `issuer`, `jwks_uri`, `enrol_endpoint`, `refresh_endpoint`, and `event_endpoint` (default `/events`). |
| `GET /.well-known/jwks.json` | bootstrap | AP signing JWKS. |
| `GET /agents/{agentId}/jwks.json` | bootstrap | Enrolled agent identity JWKS. |
| `POST /enrol` | bootstrap | JSON `{agent_id, jwk, ps?}`; returns `agent_token`, `key_id`, `jwks_uri`, `expires_in`. |
| `POST /refresh` | bootstrap | Signed refresh request; the sample requires `Signature-Key`, `Signature-Input`, and `Signature` and does not use a request body. |
| `GET /agents` | sample diagnostic | Lists enrolled agents. |
| `POST /events` | **Events-facing** | Verifies resource event JWT/signature and calls the durable-store contract. |
| `POST /agents/{agentId}/event-subscriptions/bookings` | **sample-only** | Signed bodyless acquisition of a Bookings subscribe token. |
| `GET /agents/{agentId}/events?limit=20` | **sample-only** | Signed, non-destructive batch polling (`limit` is 1–100; default 20). |
| `POST /agents/{agentId}/events/{receiptId}/ack` | **sample-only** | Signed bodyless receipt removal; returns `204` or `404`. |

`/events` is mapped with `MapAAuthEventEndpoint` and uses the
`IAAuthAgentProviderEventStore` contract. The sample implementation performs
atomic checks under a process lock, but it is not durable. Production APs must
provide durable subscription/inbox storage and document retention: the AP sees
the event token and the raw payload.

## Configuration

`appsettings.json` contains:

| Key | Default | Meaning |
|---|---|---|
| `AgentProvider:Issuer` | `http://localhost:5301` | AP issuer and metadata authority. |
| `AgentProvider:KeyId` | `ap-key-1` | AP signing key id. |
| `AgentProvider:Events:BookingsResourceUrl` | `http://localhost:5005` | Fixed resource audience for sample acquisition. |
| `AgentProvider:Events:SubscriptionLifetimeSeconds` | `3600` | Sample subscribe-token lifetime. |
| `AgentProvider:Events:SubscriptionMaxUses` | `3` | Sample `max_uses`; omit/`null` for unlimited. |
| `AgentProvider:Events:EventEndpointRoute` | `/events` | Route advertised as `event_endpoint`. |

The AP signing key is persisted under `~/.aauth/ap-keys`; the agent registry
and Events inbox are not persisted.

## Run

```bash
dotnet run --project samples/MockAgentProvider
```

For the complete sample flow:

```bash
make events-stack
# in another terminal
make agent-events
```

The AP acquisition, polling, and ACK endpoints are examples only. Polling and
ACK are not standardized by AAuth Events, and neither this in-memory inbox nor
the sample's transport should be used as a production design.
