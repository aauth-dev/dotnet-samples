# Samples

Nine sample applications demonstrating AAuth flows end-to-end.

| Sample | Port | Description |
|--------|------|-------------|
| [WhoAmI](WhoAmI/) | 5000 | ASP.NET Core resource server — isolated per-mode pipelines (`/` index, `/hwk`, `/jkt-jwt`, `/jwks-uri`, `/jwt`, `/jwt/admin`, `/jwt/roles`, `/federated`) |
| [Orchestrator](Orchestrator/) | 5200 | Intermediate service — call chaining with nested `act` delegation |
| [MockPersonServer](MockPersonServer/) | 5100 | Reference Person Server — verifies exchanges, mints auth tokens, federates to an Access Server. **Sample only — not part of the AAuth SDK.** |
| [MockAgentProvider](MockAgentProvider/) | 5301 | Reference Agent Provider — issues agent tokens, hosts JWKS. **Sample only — not part of the AAuth SDK.** |
| [MockAccessServer](MockAccessServer/) | 5500 | Reference Access Server — the fourth party in federated access; evaluates policy (stub or Keycloak) and mints `aa-auth+jwt` (`dwk=aauth-access.json`). **Sample only — not part of the AAuth SDK.** |
| [GuidedTour](GuidedTour/) | 5400 | Blazor walk-through — visualises every AAuth flow step by step, including the four-party federated flow |
| [SampleApp](SampleApp/) | 5240 | Golden example — one page per signing mode (hwk, jwt, jwks_uri, call chain, federated four-party) |
| [AgentConsole](AgentConsole/) | — | CLI agent — signs requests, handles challenges, exchanges with a PS |
| [LiveWhoAmITest](LiveWhoAmITest/) | 5199 | Live interop test against `whoami.aauth.dev` + `person.hello.coop` — exercises all 3 protocol modes over a public tunnel |

## Quick Start

The fastest way to run all samples together:

```bash
make demo
```

This starts WhoAmI + Orchestrator + MockPersonServer + MockAgentProvider + MockAccessServer (stub) + GuidedTour + SampleApp in parallel, prints their URLs, and tears them down on `Ctrl+C`. Then open the **GuidedTour** at <http://localhost:5400> and click **Run all**, or the **SampleApp** at <http://localhost:5240>.

For the **four-party (federated)** flow with an Access Server, `make demo` already
includes a stub Access Server (no Docker). For the live Keycloak policy engine,
use the Keycloak variant:

```bash
make demo-keycloak   # both UIs + real Keycloak policy engine (Docker)
```

The Keycloak target boots the Access Server with the Keycloak policy engine; log
in as `demo`/`demo` (admin) or `guest`/`guest` (limited). See
[Federated Access](../docs/workflows/federated-access.md) and the
[Mock Access Server README](MockAccessServer/README.md).

## Running Individually

### WhoAmI (Resource Server)

```bash
dotnet run --project samples/WhoAmI
```

Each access mode has its own isolated verification pipeline. `GET /` is an unauthenticated index that lists the available flows:

| Path | Mode | Verification / Policy |
|------|------|-----------------------|
| `/` | _(index)_ | None — lists the available flows |
| `/hwk` | Pseudonymous | HTTP signature only — resource sees key thumbprint (`jkt`) |
| `/jkt-jwt` | Pseudonymous (key delegation) | Signature only — agent known by durable key thumbprint via naming JWT |
| `/jwks-uri` | Agent Identity | Signature verified via published JWKS (`AAuth.Identified`) |
| `/jwt` | Three-party JWT | Full issuer verification + `aud` + PoP, scope `whoami` |
| `/jwt/admin` | Three-party (step-up) | Elevated scope `whoami:admin` |
| `/jwt/roles` | Three-party (RBAC) | Role `whoami-admin` from the auth token's `roles` claim |

All paths serve `/.well-known/aauth-resource.json` and `/.well-known/jwks.json` without requiring a signature.

Override the issuer: `--AAuth:Issuer https://my-rs.example` (or env var `AAuth__Issuer`).

Browse discovery:

```bash
curl http://localhost:5000/.well-known/aauth-resource.json
curl http://localhost:5000/.well-known/jwks.json
```

### AgentConsole

When the target URL has no path (or just `/`), AgentConsole appends the path for the chosen signing mode: `hwk → /hwk`, `jkt-jwt → /jkt-jwt`, `jwks_uri → /jwks-uri`, and the default `jwt → /jwt`. To reach `/jwt/admin` or `/jwt/roles`, pass the explicit path. See [AgentConsole/README.md](AgentConsole/README.md) for the full mapping and the enrollment-cache note.

**Pseudonymous (HWK) access** — default when no `--ps` is provided:

```bash
dotnet run --project samples/AgentConsole -- http://localhost:5000/hwk --ap http://localhost:5301
```

**Pseudonymous with key delegation (JKT-JWT):**

```bash
dotnet run --project samples/AgentConsole -- http://localhost:5000 \
  --ap http://localhost:5301 --signing-mode jkt-jwt
```

**Agent Identity (JWKS-URI) access:**

```bash
dotnet run --project samples/AgentConsole -- http://localhost:5000 \
  --ap http://localhost:5301 --signing-mode jwks_uri
```

**Three-party flow** (agent advertises a PS; resource challenges; agent exchanges — grant consent first):

```bash
dotnet run --project samples/AgentConsole -- http://localhost:5000 \
  --ap http://localhost:5301 --ps http://localhost:5100
```

**Three-party with elevated scope (`/jwt/admin`)** — grant consent for scope `whoami:admin`:

```bash
dotnet run --project samples/AgentConsole -- http://localhost:5000/jwt/admin \
  --ap http://localhost:5301 --ps http://localhost:5100 --signing-mode jwt
```

**Three-party with RBAC (`/jwt/roles`)** — the PS asserts roles `whoami-admin` and groups `demo-users`:

```bash
dotnet run --project samples/AgentConsole -- http://localhost:5000/jwt/roles \
  --ap http://localhost:5301 --ps http://localhost:5100 --signing-mode jwt
```

> **Note:** `make demo` starts MockPersonServer with `RequireConsent=true`, so three-party flows (`jwt`, `jkt-jwt`) will print an interaction URL for user approval:
>
> ```
> [interaction] User approval required: http://localhost:5100/interaction?code=...
> ```
>
> Open that URL in a browser and click **Approve**, or pre-approve programmatically:
>
> ```bash
> curl -X POST http://localhost:5100/admin/consent \
>   -H "Content-Type: application/json" \
>   -d '{"agent":"aauth:demo@ap.example","resource":"http://localhost:5000","scope":"whoami"}'
> ```
>
> To skip consent entirely, start MockPersonServer separately without the flag: `dotnet run --project samples/MockPersonServer`

| Flag | Default | Purpose |
|------|---------|---------|
| `--ap <url>` | _(required)_ | Agent Provider URL (enrol + refresh endpoints) |
| `--sub <id>` | `aauth:demo@ap.example` | Agent subject identifier |
| `--ps <url>` | _(none)_ | Person Server URL — enables three-party flow |
| `--signing-mode <mode>` | `jwt` (with PS) / `hwk` (without) | One of `jwt`, `hwk`, `jwks_uri`, `jkt-jwt` |
| `--prefer-wait <seconds>` | _(none)_ | Long-poll hint for deferred PS responses |
| `--upstream-token <jwt>` | _(none)_ | Upstream auth token for call-chaining scenarios |

### MockPersonServer

```bash
dotnet run --project samples/MockPersonServer
```

Verifies the RFC 9421 signature on the exchange request, parses the `resource_token`, and mints an `aa-auth+jwt` bound to the agent's confirmation key. See [MockPersonServer/README.md](MockPersonServer/README.md) for consent mode and admin endpoints.

### MockAgentProvider

```bash
dotnet run --project samples/MockAgentProvider
```

Implements AP enrollment and JWKS hosting. See [MockAgentProvider/README.md](MockAgentProvider/README.md) for details.

### GuidedTour

```bash
dotnet run --project samples/GuidedTour
```

Requires WhoAmI, MockPersonServer, Orchestrator, and MockAgentProvider already running (or use `make demo`). See [GuidedTour/README.md](GuidedTour/README.md) for mode configuration.

### SampleApp

```bash
dotnet run --project samples/SampleApp
```

Simple Blazor app showing each signing mode as a separate page. Open <http://localhost:5240>. Requires WhoAmI, MockPersonServer, and Orchestrator running. MockAgentProvider is needed only for the JWKS-URI enrollment page.

### LiveWhoAmITest

```bash
dotnet run --project samples/LiveWhoAmITest
```

Live interop test that runs against the public reference servers (`whoami.aauth.dev` and `person.hello.coop`) instead of the local mocks. It generates an agent key, starts a local metadata + JWKS endpoint on port 5199, exposes it via a `cloudflared` quick tunnel, and exercises all three protocol modes:

- **Mode 1** — unsigned request returns `401` + `Accept-Signature`.
- **Mode 2** — `aa-agent+jwt` returns the agent identity (no scope) or a `401` + `AAuth-Requirement` resource token (scoped).
- **Mode 3** — full three-party flow: agent token → resource token → PS exchange → auth token → identity claims.

Requires `cloudflared` on the `PATH` (preinstalled in the dev container) and outbound network access. Mode 3 may prompt for user consent at `person.hello.coop`; the agent prints the interaction URL to approve in a browser.

## Make Targets

```bash
make help            # list available targets
make build           # dotnet build AAuth.slnx
make restore         # restore NuGet packages
make test            # run all tests (SDK + conformance)
make test-unit       # SDK unit + integration tests only
make test-conformance # spec conformance tests only
make demo            # start WhoAmI + Orchestrator + MockPersonServer + MockAgentProvider + GuidedTour
make whoami          # only the resource server (port 5000)
make ps              # MockPersonServer (port 5100)
make ps-consent      # MockPersonServer with RequireConsent=true
make ap              # MockAgentProvider (port 5301)
make tour            # GuidedTour (port 5400; expects other services running)
make sampleapp       # SampleApp (port 5240; expects other services running)
make agent           # AgentConsole against WhoAmI (override URL=…)
make live            # LiveWhoAmITest against whoami.aauth.dev (needs cloudflared + network)
make clean           # dotnet clean + remove bin/ obj/
```
