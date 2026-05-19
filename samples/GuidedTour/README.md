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

### Deferred / user-consent mode (default)

When the PS requires user consent (`MockPersonServer__RequireConsent=true`,
which `make demo` sets automatically) the tour expands to 11 steps:

1–6. Same as above.
7. Signed `POST /token` → **`202 Accepted`** with `Location: /pending/{id}`
   and `AAuth-Requirement: requirement=interaction; url; code`.
8. Agent presents the user-facing `{url}?code={code}` link.
9. **User opens the PS's consent page.** The "Open consent page →" button
   opens `{url}?code={code}` in a new browser tab. The Person Server
   renders its own consent screen (agent + resource + scope), the user
   clicks **Approve** there, and the PS records consent via
   `POST /interaction/approve`. The agent is not on this channel.
10. Agent polls `Location` with a signed `GET` (`DeferredPoller`) → 200 +
    `auth_token`. The polling budget is 2 minutes to give the human
    time to click Approve in the other tab.
11. Signed `GET /` carrying the `auth_token` → 200 + claims.

Switch back to the original 8-step flow by setting `GuidedTour:Mode` to
`Autonomous` in `appsettings.json`.

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
