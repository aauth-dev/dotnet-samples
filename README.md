# dotnet-samples

> **Status: Work in Progress** — Phase 3 of the .NET AAuth SDK is complete: Ed25519 keys, agent JWT, RFC 9421 outbound signing, signature verification middleware, resource & auth token builders, JWKS / metadata discovery clients, the working three-party challenge/exchange flow (autonomous **and** deferred user-consent), a reference `MockPersonServer` (with `403 access_denied` denial support), and the Blazor `GuidedTour` walk-through. CLI tool and full multi-agent demo land in later phases. See the [implementation plan](.agent/plans/2026-05-13-dotnet-aauth-sdk/implementation-plan.md) for phase status.

AAuth samples and SDK for .NET — demonstrating the [AAuth protocol](https://github.com/dickhardt/AAuth) for agent-to-resource authorization with cryptographic proof-of-possession.

## What is AAuth?

AAuth is a four-party authorization protocol for AI agents. Every HTTP request carries a cryptographic signature — there are no bearer tokens. See the [protocol spec](aauth-spec/draft-hardt-oauth-aauth-protocol.md) for full details.

The four parties are:

- **Agent Provider (AP)** — issues `aa-agent+jwt` tokens that identify an agent and bind its signing key.
- **Agent** — signs every outbound HTTP request (RFC 9421) and presents the agent token in the `Signature-Key` header.
- **Resource Server (RS)** — verifies the signature, optionally challenges with a `resource_token` to demand a person-scoped `auth_token`.
- **Person Server (PS)** — receives a signed exchange request from the agent and returns an `aa-auth+jwt` proving the person delegated the requested scope.

## Repository Layout

| Path | Description |
|------|-------------|
| [aauth-spec/](aauth-spec/) | Protocol specifications (draft-01) copied from [dickhardt/AAuth](https://github.com/dickhardt/AAuth) — see [SPEC-VERSION.md](aauth-spec/SPEC-VERSION.md) |
| [src/AAuth/](src/AAuth/) | AAuth SDK library |
| [samples/AgentConsole/](samples/AgentConsole/) | Console agent: signs requests, handles AAuth challenges, exchanges with a PS |
| [samples/WhoAmI/](samples/WhoAmI/) | ASP.NET Core resource server that verifies AAuth requests and issues resource tokens |
| [samples/MockPersonServer/](samples/MockPersonServer/) | Reference Person Server: verifies signed exchange requests and mints auth tokens |
| [samples/GuidedTour/](samples/GuidedTour/) | Blazor Server walk-through of the three-party flow with payloads, JWTs, and signature bases |
| [tests/AAuth.Tests/](tests/AAuth.Tests/) | Unit + integration tests for the SDK |
| [tests/AAuth.Conformance/](tests/AAuth.Conformance/) | Spec-traceable xUnit tests mirroring the AAuth spec section structure |
| [.agent/plans/](.agent/plans/) | Research and planning documents |

## SDK Components (`src/AAuth/`)

| Namespace | Type | Purpose |
|-----------|------|---------|
| `AAuth.Crypto` | `AAuthKey`, `KeyStore` | Ed25519 key generation, on-disk persistence, JWK import/export |
| `AAuth.Tokens` | `AgentTokenBuilder` | Builds `aa-agent+jwt` carrying agent identity, DWK, and optional PS pointer |
| `AAuth.Tokens` | `ResourceTokenBuilder` | Issues `aa-resource+jwt` for an RS to challenge an agent |
| `AAuth.Tokens` | `AuthTokenBuilder` | Issues `aa-auth+jwt` for a PS to attest a person's delegation |
| `AAuth.Tokens` | `TokenVerifier` | EdDSA JWT verification with full claim checks (`VerifyWithJwksAsync` for PS-issued tokens) |
| `AAuth.HttpSig` | `AAuthSigningHandler` | `DelegatingHandler` that signs outbound requests per RFC 9421 |
| `AAuth.HttpSig` | `SignatureKeyHeader`, `SignatureKeyParser` | Format/parse the `Signature-Key` header |
| `AAuth.HttpSig` | `AAuthVerifier`, `AAuthVerificationMiddleware` | Server-side signature verification (ASP.NET middleware) |
| `AAuth.Headers` | `AAuthRequirementHeader` | Format/parse the `AAuth-Requirement` challenge header |
| `AAuth.Discovery` | `MetadataClient`, `JwksClient` | Cached fetchers for `/.well-known/aauth-*` and JWKS |
| `AAuth.Server` | `WellKnownEndpoints` | `MapAAuthResourceWellKnown` for ASP.NET minimal APIs |
| `AAuth.Agent` | `AAuthTokenHolder`, `ChallengeHandler`, `TokenExchangeClient` | Client-side three-party flow: holds the current carrier token, intercepts 401s, exchanges with PS |

## Getting Started

### Prerequisites

- [Docker](https://www.docker.com/products/docker-desktop)
- [Visual Studio Code](https://code.visualstudio.com/) with the [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)

The dev container provides the .NET 10 SDK and `gh` CLI. Outside the dev container, install the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) directly.

### Build everything

```bash
dotnet build AAuth.slnx
```

## Running the Samples

### 1. WhoAmI resource server (`samples/WhoAmI/`)

An ASP.NET Core minimal API that:

- serves `/.well-known/aauth-resource.json` and `/.well-known/jwks.json`,
- verifies the RFC 9421 signature on every non-discovery request,
- if presented an agent token: mints a `resource_token` and replies `401 AAuth-Requirement: requirement=auth-token`,
- if presented a person-scoped auth token: verifies it against the PS's JWKS and returns `200` with the resolved claims.

Run it:

```bash
dotnet run --project samples/WhoAmI
```

By default it listens on `http://localhost:5000` and uses that as its issuer. Override with the `AAuth:Issuer` configuration key (env var `AAuth__Issuer` or `--AAuth:Issuer https://my-rs.example`).

Browse the discovery documents:

```bash
curl http://localhost:5000/.well-known/aauth-resource.json
curl http://localhost:5000/.well-known/jwks.json
```

### 2. AgentConsole (`samples/AgentConsole/`)

A console agent that generates (or loads) an Ed25519 key under `~/.aauth/keys/<kid>/`, builds an `aa-agent+jwt`, signs an HTTP `GET`, and prints the response.

**Identity-based call** (no person delegation; RS authorises off the agent identity alone):

```bash
dotnet run --project samples/AgentConsole -- http://localhost:5000
```

**Three-party flow** (the agent advertises a Person Server; RS challenges; agent exchanges with PS; RS returns claims):

```bash
dotnet run --project samples/AgentConsole -- http://localhost:5000 --ps https://your-ps.example
```

Flags:

| Flag | Default | Purpose |
|------|---------|---------|
| `--iss <url>`  | `https://ap.example`        | Agent Provider issuer URL embedded in the agent token |
| `--sub <id>`   | `aauth:demo@ap.example`     | Agent subject identifier |
| `--kid <name>` | `demo`                      | Key id under `~/.aauth/keys/` (generated on first use) |
| `--ps <url>`   | _(none)_                    | Person Server URL — when set, the agent token includes a `ps` claim and the agent will handle resource-token challenges by exchanging at the PS's `token_endpoint` |

### 3. MockPersonServer (`samples/MockPersonServer/`)

A reference Person Server. Verifies the RFC 9421 signature on the token-exchange request from the agent, parses the embedded `resource_token` (does **not** verify its signature against the RS's JWKS — demo-only), and mints an `aa-auth+jwt` bound to the agent's confirmation key.

```bash
dotnet run --project samples/MockPersonServer
```

Listens on `http://localhost:5100` by default.

### 4. GuidedTour (`samples/GuidedTour/`)

A Blazor Server walk-through of the three-party flow aimed at folks new to AAuth. Pauses between each step so you can see the RFC 9421 signature base, the decoded JWTs, and every request/response payload as the flow unfolds across a three-actor sequence diagram.

Run all three samples in separate terminals (or use `make demo` — see [Quick demo](#quick-demo) below):

```bash
dotnet run --project samples/MockPersonServer   # terminal 1, port 5100
dotnet run --project samples/WhoAmI             # terminal 2, port 5000
dotnet run --project samples/GuidedTour         # terminal 3, port 5400
```

Then open <http://localhost:5400> and click **Run all**.

### Quick demo

A `Makefile` at the repo root exposes one-line commands for the common workflows:

```bash
make help          # list available targets
make build         # dotnet build AAuth.slnx
make test          # dotnet test AAuth.slnx
make demo          # start WhoAmI + MockPersonServer + GuidedTour together
make tour          # only the GuidedTour Blazor app (expects WhoAmI + MockPS already running)
make whoami        # only the resource server
make ps            # only the MockPersonServer
make clean         # dotnet clean + remove bin/ obj/
```

`make demo` runs all three sample processes in parallel, prints their URLs, and tears them down on `Ctrl+C`.

The three-party flow is also exercised end-to-end in [tests/AAuth.Tests/Integration/WhoAmIFlowTests.cs](tests/AAuth.Tests/Integration/WhoAmIFlowTests.cs), which drives the shipped `MockPersonServer` via `WebApplicationFactory` and runs the full challenge → exchange → retry sequence in-process.

## Testing

Run the full suite (unit + integration + spec conformance):

```bash
dotnet test AAuth.slnx
```

Run a single project:

```bash
dotnet test tests/AAuth.Tests/AAuth.Tests.csproj              # SDK unit + integration tests
dotnet test tests/AAuth.Conformance/AAuth.Conformance.csproj  # Spec conformance suite
```

Run a single test by name:

```bash
dotnet test tests/AAuth.Tests/AAuth.Tests.csproj --filter "FullyQualifiedName~WhoAmIFlowTests"
```

### Test layout

- **`tests/AAuth.Tests/`** — xUnit unit tests organised by SDK namespace (`Crypto/`, `Tokens/`, `HttpSig/`, `Discovery/`, `Headers/`, `Agent/`) plus `Integration/WhoAmIFlowTests.cs`, which uses `WebApplicationFactory<Program>` to host both WhoAmI and a mock PS in-process and routes traffic between them with a host-based message handler.
- **`tests/AAuth.Conformance/`** — Each test file maps to a section of the AAuth spec; test display names quote the normative clause being verified. See [tests/AAuth.Conformance/README.md](tests/AAuth.Conformance/README.md) for the section→file map.

## Dev Container Details

The dev container is configured in `.devcontainer/`:

| File | Description |
|------|-------------|
| `Dockerfile` | Builds an image based on `mcr.microsoft.com/dotnet/sdk:10.0` |
| `devcontainer.json` | Configures VS Code extensions and the post-create command |
| `post-create.sh` | Runs on container create: prints `dotnet --info` and installs the GitHub CLI (`gh`) |

Included VS Code extensions:

- **C# Dev Kit** (`ms-dotnettools.csdevkit`)
- **C#** (`ms-dotnettools.csharp`)
- **.NET Runtime Install Tool** (`ms-dotnettools.vscode-dotnet-runtime`)
