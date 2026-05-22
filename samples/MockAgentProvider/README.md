# MockAgentProvider

A minimal Agent Provider (AP) sample for development and testing.

## What it does

Implements the AP endpoints from the AAuth bootstrap spec (§7):

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/aauth-agent.json` | GET | AP metadata |
| `/.well-known/jwks.json` | GET | AP signing keys (JWKS) |
| `/enrol` | POST | Register an agent — accepts `{agent_id, jwk}`, returns signed agent token |
| `/refresh` | POST | Refresh an agent token — accepts `{agent_token}`, returns fresh token |
| `/agents` | GET | Dev tool — list registered agents |

## Running

```bash
dotnet run --project samples/MockAgentProvider
```

Defaults to `http://localhost:5301` (HTTP) / `https://localhost:5300` (HTTPS).

## Using with AgentConsole

```bash
dotnet run --project samples/AgentConsole -- http://localhost:5000 \
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
| `Issuer` | `http://localhost:5301` | AP issuer claim in tokens |
| `KeyId` | `ap-key-1` | Key identifier for the AP signing key |
