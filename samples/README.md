# Samples

Seven sample applications demonstrating AAuth flows end-to-end.

| Sample | Port | Description |
|--------|------|-------------|
| [WhoAmI](WhoAmI/) | 5000 | ASP.NET Core resource server — per-endpoint verification (`/hwk`, `/jwks-uri`, `/`) |
| [Orchestrator](Orchestrator/) | 5200 | Intermediate service — call chaining with nested `act` delegation |
| [MockPersonServer](MockPersonServer/) | 5100 | Reference Person Server — verifies exchanges, mints auth tokens |
| [MockAgentProvider](MockAgentProvider/) | 5301 | Reference Agent Provider — issues agent tokens, hosts JWKS |
| [GuidedTour](GuidedTour/) | 5400 | Blazor walk-through — visualises all four AAuth flows step by step |
| [SampleApp](SampleApp/) | 5240 | Golden example — one page per signing mode (hwk, jwt, jwks_uri, call chain) |
| [AgentConsole](AgentConsole/) | — | CLI agent — signs requests, handles challenges, exchanges with a PS |

## Quick Start

The fastest way to run all samples together:

```bash
make demo
```

This starts WhoAmI + Orchestrator + MockPersonServer + MockAgentProvider + GuidedTour in parallel, prints their URLs, and tears them down on `Ctrl+C`. Then open <http://localhost:5400> and click **Run all**.

## Running Individually

### WhoAmI (Resource Server)

```bash
dotnet run --project samples/WhoAmI
```

Exposes three endpoints, one per signing mode:

| Path | Mode | Verification |
|------|------|-------------|
| `/hwk` | Pseudonymous | HTTP signature only |
| `/jwks-uri` | Agent Identity | Signature verified via published JWKS |
| `/` | Three-party JWT | Full issuer verification + aud + PoP + act.sub |

All paths serve `/.well-known/aauth-resource.json` and `/.well-known/jwks.json` without requiring a signature.

Override the issuer: `--AAuth:Issuer https://my-rs.example` (or env var `AAuth__Issuer`).

Browse discovery:

```bash
curl http://localhost:5000/.well-known/aauth-resource.json
curl http://localhost:5000/.well-known/jwks.json
```

### AgentConsole

**Pseudonymous (HWK) access** — default when no `--ps` is provided:

```bash
dotnet run --project samples/AgentConsole -- http://localhost:5000/hwk --ap http://localhost:5301
```

**Agent Identity (JWKS-URI) access:**

```bash
dotnet run --project samples/AgentConsole -- http://localhost:5000/jwks-uri \
  --ap http://localhost:5301 --signing-mode jwks_uri
```

**Three-party flow** (agent advertises a PS; resource challenges; agent exchanges):

```bash
dotnet run --project samples/AgentConsole -- http://localhost:5000 \
  --ap http://localhost:5301 --ps http://localhost:5100
```

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

## Make Targets

```bash
make help            # list available targets
make build           # dotnet build AAuth.slnx
make restore         # restore NuGet packages
make test            # run all tests (SDK + conformance)
make test-unit       # SDK unit + integration tests only
make test-conformance # spec conformance tests only
make demo            # start WhoAmI + MockPersonServer + MockAgentProvider + GuidedTour
make whoami          # only the resource server (port 5000)
make ps              # MockPersonServer (port 5100)
make ps-consent      # MockPersonServer with RequireConsent=true
make ap              # MockAgentProvider (port 5301)
make tour            # GuidedTour (port 5400; expects other services running)
make sampleapp       # SampleApp (port 5240; expects other services running)
make agent           # AgentConsole against WhoAmI (override URL=…)
make clean           # dotnet clean + remove bin/ obj/
```
