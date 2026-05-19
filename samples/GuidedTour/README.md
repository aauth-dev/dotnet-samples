# AAuth Guided Tour

A Blazor Server walk-through of the AAuth three-party flow, aimed at folks
learning the spec for the first time. It runs the same SDK code that
`samples/AgentConsole` does, but pauses between each step so you can see
the signature base, the JWTs, and the request/response payloads at every
hop.

## What you'll see

Eight steps render as a swim-lane sequence diagram across three actors —
**Agent**, **Resource**, **Person Server** — with a payload inspector on
the right that decodes each JWT and shows the canonical RFC 9421 signature
base for every signed request.

1. Generate Ed25519 keypair
2. Build agent token (`aa-agent+jwt`)
3. Unsigned discovery → resource well-known
4. Signed `GET /` carrying the agent token
5. Parse the 401 `AAuth-Requirement` challenge + `resource_token`
6. Unsigned discovery → Person Server well-known
7. Signed `POST /token` (exchange) → `auth_token` returned
8. Signed `GET /` carrying the `auth_token` → 200 + claims

If `PersonServerUrl` is empty in `appsettings.json` the tour stops at step 4
in identity-based mode (200 directly).

## Run it

In three terminals from the repo root:

```bash
# Terminal 1 — Person Server (port 5100)
dotnet run --project samples/MockPersonServer

# Terminal 2 — Resource (port 5000)
dotnet run --project samples/WhoAmI

# Terminal 3 — Tour UI (port 5400)
dotnet run --project samples/GuidedTour
```

Then open <http://localhost:5400> and click **Run all** (or step through
with **Run step**).

## Configuration

`appsettings.json`:

| Key | Default | Meaning |
| --- | --- | --- |
| `GuidedTour:WhoAmIUrl` | `http://localhost:5000` | Resource server base URL. |
| `GuidedTour:PersonServerUrl` | `http://localhost:5100` | Set empty to demo the identity-based flow. |
| `GuidedTour:AgentId` | `aauth:tour-agent@ap.example` | Value placed in the agent token's `sub`. |
