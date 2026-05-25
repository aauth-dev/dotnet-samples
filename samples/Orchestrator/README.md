# Orchestrator

Multi-agent call-chaining sample. The Orchestrator acts as both a **resource** (verifies incoming callers) and an **agent** (calls downstream WhoAmI with delegation).

## What It Demonstrates

- Intermediate service pattern: resource + agent in one process
- Proper 401 challenge with resource token when receiving agent tokens
- Token exchange with `upstream_token` for nested `act` delegation
- `UseJwt(string)` to present a pre-acquired auth token downstream
- Full issuer verification (`RequireIssuerVerification = true`)

## Flow

```
Agent A ──agent token──→ Orchestrator ──401 + resource_token──→ Agent A
Agent A ──auth token───→ Orchestrator ──agent token──→ WhoAmI ──401──→ Orchestrator
                         Orchestrator ──exchange(upstream_token)──→ PS
                         Orchestrator ──chained auth token──→ WhoAmI ──200──→ Orchestrator ──200──→ Agent A
```

The final response includes:

```json
{
  "chain": "Agent → Orchestrator → WhoAmI",
  "upstream": { "agent": "aauth:sample-app@ap.example" },
  "downstream": {
    "mode": "three-party",
    "act": {
      "sub": "aauth:orchestrator@ap.example",
      "act": { "sub": "aauth:sample-app@ap.example" }
    }
  }
}
```

## Running

```bash
make demo-sample   # starts all 5 services
```

Or standalone (requires WhoAmI, PS, and AP already running):

```bash
dotnet run --project samples/Orchestrator
# → http://localhost:5200
```

## Configuration

| Key | Default | Purpose |
|-----|---------|---------|
| `AAuth:Issuer` | `http://localhost:5200` | Orchestrator's resource identifier |
| `AAuth:Downstream` | `http://localhost:5000` | Downstream resource (WhoAmI) URL |
| `AAuth:AgentProvider` | `http://localhost:5301` | AP for enrollment |
| `AAuth:PersonServer` | `http://localhost:5100` | PS for token exchange |
| `AAuth:AgentId` | `aauth:orchestrator@ap.example` | Orchestrator's agent identity |

## Using with AgentConsole

```bash
# Pre-grant consent for both hops
curl -X POST http://localhost:5100/admin/consent \
  -H "Content-Type: application/json" \
  -d '{"agent":"aauth:demo@ap.example","resource":"http://localhost:5200"}'

curl -X POST http://localhost:5100/admin/consent \
  -H "Content-Type: application/json" \
  -d '{"agent":"aauth:orchestrator@ap.example","resource":"http://localhost:5000"}'

# Call through the chain
dotnet run --project samples/AgentConsole -- http://localhost:5200 \
  --ap http://localhost:5301 --ps http://localhost:5100
```

## Key Implementation Details

1. **Lazy enrollment**: The Orchestrator enrolls with the AP on first request (not at startup).
2. **Per-request consent grant**: Grants consent for itself at the PS before each downstream call (demo simplification).
3. **Fallback path**: If the caller used HWK/JWKS-URI (no upstream auth token), falls back to standard challenge handling without chaining.
