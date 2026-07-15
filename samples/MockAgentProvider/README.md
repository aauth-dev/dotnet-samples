# MockAgentProvider

A minimal Agent Provider (AP) sample for development and testing.

> **Sample only — not part of the AAuth SDK.** This project is illustrative wiring built on top of the SDK. Do not depend on its types or HTTP surface in production code.

## What it does

Implements the AP endpoints from the AAuth bootstrap spec (§7):

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/aauth-agent.json` | GET | AP metadata |
| `/.well-known/jwks.json` | GET | AP's own signing key (for verifying agent token JWTs) |
| `/agents/{agentId}/jwks.json` | GET | Per-agent JWKS — the agent's public key for `sig=jwks_uri` identity-based access |
| `/enrol` | POST | Register an agent — accepts `{agent_id, jwk}`, returns `{agent_token, key_id, jwks_uri}` |
| `/refresh` | POST | Refresh an agent token — accepts `{agent_token}`, returns fresh token |
| `/agents` | GET | Dev tool — list registered agents |
| `/events` | POST | AAuth Events resource-to-AP delivery endpoint |
| `/agents/{agentId}/event-subscriptions/bookings` | POST | **Sample-only** signed subscribe-token acquisition |
| `/agents/{agentId}/events?limit=20` | GET | **Sample-only** signed, non-destructive event polling |
| `/agents/{agentId}/events/{receiptId}/ack` | POST | **Sample-only** signed event receipt ACK |

The Events acquisition, polling, and ACK routes are a non-normative sample
transport, not an AAuth Events protocol endpoint. The inbox is in-memory and
non-durable; it is for local demonstrations only and is not production-safe.
Production Agent Providers must use durable storage and choose their own
agent-to-AP transport.

## Running

```bash
dotnet run --project samples/MockAgentProvider
```

Defaults to `http://localhost:5301` (HTTP) / `https://localhost:5300` (HTTPS).

## Using with AgentConsole

```bash
dotnet run --project samples/AgentConsole -- http://localhost:5000/pseudonymous \
  --ap http://localhost:5301 \
  --sub "aauth:myagent@ap.example"
```

## Using with GuidedTour

Add to `samples/GuidedTour/appsettings.json`:

```json
{
  "GuidedTour": {
    "AgentProviderUrl": "http://localhost:5301"
  }
}
```

## Configuration

Settings in `appsettings.json`:

| Key | Default | Description |
|-----|---------|-------------|
| `AgentProvider:Issuer` | `http://localhost:5301` | AP issuer claim in tokens |
| `AgentProvider:KeyId` | `ap-key-1` | Key identifier for the AP signing key |
| `AgentProvider:Events:BookingsResourceUrl` | `http://localhost:5302` | Fixed `bookings` resource audience for sample token acquisition |
| `AgentProvider:Events:SubscriptionLifetimeSeconds` | `3600` | Sample subscribe-token lifetime |
| `AgentProvider:Events:SubscriptionMaxUses` | `3` | Sample event-use limit |
| `AgentProvider:Events:EventEndpointRoute` | `/events` | AP `event_endpoint` route |

The AP metadata document advertises the configured `event_endpoint`. The
bookings alias is fixed by configuration: the acquisition request has no body
or query parameters, so callers cannot substitute a resource URL.
