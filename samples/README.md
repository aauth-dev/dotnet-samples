# Samples

Five sample applications demonstrating AAuth flows end-to-end.

| Sample | Port | Description |
|--------|------|-------------|
| [WhoAmI](WhoAmI/) | 5000 | ASP.NET Core resource server — verifies signatures, issues resource tokens |
| [AgentConsole](AgentConsole/) | — | CLI agent — signs requests, handles challenges, exchanges with a PS |
| [MockPersonServer](MockPersonServer/) | 5100 | Reference Person Server — verifies exchanges, mints auth tokens |
| [MockAgentProvider](MockAgentProvider/) | 5200 | Reference Agent Provider — issues agent tokens, hosts JWKS |
| [GuidedTour](GuidedTour/) | 5400 | Blazor walk-through — visualises the three-party flow step by step |

## Quick Start

The fastest way to run all samples together:

```bash
make demo
```

This starts WhoAmI + MockPersonServer + GuidedTour in parallel, prints their URLs, and tears them down on `Ctrl+C`. Then open <http://localhost:5400> and click **Run all**.

## Running Individually

### WhoAmI (Resource Server)

```bash
dotnet run --project samples/WhoAmI
```

- Serves `/.well-known/aauth-resource.json` and `/.well-known/jwks.json`
- Verifies RFC 9421 signature on every non-discovery request
- If agent token presented: mints a `resource_token` and replies `401 AAuth-Requirement: requirement=auth-token`
- If auth token presented: verifies against PS's JWKS and returns `200` with resolved claims

Override the issuer: `--AAuth:Issuer https://my-rs.example` (or env var `AAuth__Issuer`).

Browse discovery:

```bash
curl http://localhost:5000/.well-known/aauth-resource.json
curl http://localhost:5000/.well-known/jwks.json
```

### AgentConsole

```bash
dotnet run --project samples/AgentConsole -- http://localhost:5000
```

Generates (or loads) an Ed25519 key under `~/.aauth/keys/<kid>/`, builds an `aa-agent+jwt`, signs an HTTP `GET`, and prints the response.

**Three-party flow** (agent advertises a PS; resource challenges; agent exchanges):

```bash
dotnet run --project samples/AgentConsole -- http://localhost:5000 --ps http://localhost:5100
```

| Flag | Default | Purpose |
|------|---------|---------|
| `--iss <url>` | `https://ap.example` | Agent Provider issuer URL embedded in agent token |
| `--sub <id>` | `aauth:demo@ap.example` | Agent subject identifier |
| `--kid <name>` | `demo` | Key id under `~/.aauth/keys/` (generated on first use) |
| `--ps <url>` | _(none)_ | Person Server URL — enables three-party flow |

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

Requires WhoAmI and MockPersonServer already running. See [GuidedTour/README.md](GuidedTour/README.md) for mode configuration.

## Make Targets

```bash
make help          # list available targets
make build         # dotnet build AAuth.slnx
make test          # dotnet test AAuth.slnx
make demo          # start WhoAmI + MockPersonServer + GuidedTour together
make tour          # only the GuidedTour (expects WhoAmI + MockPS running)
make whoami        # only the resource server
make ps            # only the MockPersonServer
make clean         # dotnet clean + remove bin/ obj/
```
