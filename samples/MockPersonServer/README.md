# Mock Person Server

A minimal AAuth Person Server for end-to-end demos and integration tests.

## What it does

- Serves PS discovery metadata at `/.well-known/aauth-person.json` (with `token_endpoint`).
- Serves its signing JWKS at `/.well-known/jwks.json`.
- On `POST /token`, validates the incoming RFC 9421 signature, reads
  `resource_token` from the JSON body, and returns an `aa-auth+jwt` bound
  to the agent's confirmation key.
- When started with `RequireConsent=true`, defers the exchange instead:
  the first `POST /token` returns `202 Accepted` with
  `Location: /pending/{id}`, a `Retry-After`, and
  `AAuth-Requirement: requirement=interaction; url; code`. The agent then
  polls the signed `GET /pending/{id}` until the user makes a choice:
  - **Approve** (`POST /interaction/approve`, or `POST /admin/consent`
    from a script) → next poll returns `200` with the `auth_token`.
  - **Deny** (`POST /interaction/deny`) → next poll returns `403` with
    `{"error":"access_denied"}`.
  - No action → the agent's polling budget eventually expires.
- `GET /interaction` renders a tiny built-in consent page used by the
  `GuidedTour` "Open consent page" button.

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
  http://localhost:5000 --ap http://localhost:5301 --ps http://localhost:5100
```

## Configuration

| Key | Default | Purpose |
|---|---|---|
| `AAuth:Issuer` | `http://localhost:5100` | PS issuer URL — must match what agents put in their agent token's `ps` claim |
| `AAuth:SignatureWindow` | `60` | RFC 9421 `created` freshness window, in seconds |
| `MockPersonServer:RequireConsent` | `false` | When `true`, `POST /token` returns `202 + Location` and the user must approve or deny via `/interaction/{approve,deny}` before the poll resolves. `make demo` sets this to `true`. |
