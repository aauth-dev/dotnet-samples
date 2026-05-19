# Mock Person Server

A minimal AAuth Person Server for end-to-end demos and integration tests.

## What it does

- Serves PS discovery metadata at `/.well-known/aauth-person.json` (with `token_endpoint`).
- Serves its signing JWKS at `/.well-known/jwks.json`.
- On `POST /token`, validates the incoming RFC 9421 signature, reads
  `resource_token` from the JSON body, and returns an `aa-auth+jwt` bound
  to the agent's confirmation key.

It does **not** verify the posted `resource_token` against the resource's
JWKS — sufficient for the demo flow, **not** a production PS.

## Run

```bash
dotnet run --project samples/MockPersonServer
# → http://localhost:5100
```

Pair it with `samples/WhoAmI` (configured with `AAuth:Issuer=http://localhost:5000`)
and exercise the three-party flow with `samples/AgentConsole`:

```bash
# Terminal 1
ASPNETCORE_URLS=http://localhost:5100 \
  dotnet run --project samples/MockPersonServer

# Terminal 2
ASPNETCORE_URLS=http://localhost:5000 \
  dotnet run --project samples/WhoAmI

# Terminal 3
dotnet run --project samples/AgentConsole -- \
  http://localhost:5000/ --ps http://localhost:5100
```

## Configuration

| Key | Default | Purpose |
|---|---|---|
| `AAuth:Issuer` | `http://localhost:5100` | PS issuer URL — must match what agents put in their agent token's `ps` claim |
| `AAuth:SignatureWindow` | `60` | RFC 9421 `created` freshness window, in seconds |
