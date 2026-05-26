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

## Running

```bash
dotnet run --project samples/MockAgentProvider
```

Defaults to `http://localhost:5301` (HTTP) / `https://localhost:5300` (HTTPS).

## Using with AgentConsole

```bash
dotnet run --project samples/AgentConsole -- http://localhost:5000/hwk \
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
