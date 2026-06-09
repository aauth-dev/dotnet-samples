# Orchestrator

Multi-agent call-chaining sample. The Orchestrator acts as both a **resource** (verifies incoming callers) and an **agent** (calls downstream Calendar with delegation).

## What It Demonstrates

- Intermediate service pattern: resource + agent in one process
- Proper 401 challenge with resource token when receiving agent tokens
- Token exchange with `upstream_token` for nested `act` delegation
- `UseJwt(string)` to present a pre-acquired auth token downstream
- Full issuer verification (`RequireIssuerVerification = true`)

## Flow

```
Agent A ──agent token──→ Orchestrator ──401 + resource_token──→ Agent A
Agent A ──auth token───→ Orchestrator ──agent token──→ Calendar ─┄01──→ Orchestrator
                         Orchestrator ──exchange(upstream_token)──→ PS
                         Orchestrator ──chained auth token──→ Calendar ──200──→ Orchestrator ──200──→ Agent A
```

The final response includes:

```json
{
  "chain": "Agent → Orchestrator → Calendar",
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

Or standalone (requires Calendar, PS, and AP already running):

```bash
dotnet run --project samples/Orchestrator
# → http://localhost:5200
```

## Configuration

| Key | Default | Purpose |
|-----|---------|---------|
| `AAuth:Issuer` | `http://localhost:5200` | Orchestrator's resource identifier |
| `AAuth:Downstream` | `http://localhost:5001` | Downstream resource (Calendar) URL for the plain chain |
| `AAuth:MissionDownstream` | `http://localhost:5002` | Downstream resource (Trips) URL for the mission chain |
| `AAuth:PersonServer` | `http://localhost:5100` | PS for token exchange |
| `AAuth:AgentId` | `aauth:orchestrator@localhost:5200` | Orchestrator's agent identity |

## Using with AgentConsole

```bash
# Pre-grant consent for both hops
curl -X POST http://localhost:5100/admin/consent \
  -H "Content-Type: application/json" \
  -d '{"agent":"aauth:demo@ap.example","resource":"http://localhost:5200"}'

curl -X POST http://localhost:5100/admin/consent \
  -H "Content-Type: application/json" \
  -d '{"agent":"aauth:orchestrator@localhost:5200","resource":"http://localhost:5001"}'

# Call through the chain
dotnet run --project samples/AgentConsole -- http://localhost:5200 \
  --ap http://localhost:5301 --ps http://localhost:5100
```

## Key Implementation Details

1. **Self-issued identity**: The Orchestrator acts as its own AP per spec §Self-Hosted Agents — it publishes agent metadata at `/.well-known/aauth-agent.json` and self-signs agent tokens with its published key.
2. **Per-request consent grant**: Grants consent for itself at the PS before each downstream call (demo simplification).
3. **Fallback path**: If the caller used HWK/JWKS-URI (no upstream auth token), falls back to standard challenge handling without chaining.
