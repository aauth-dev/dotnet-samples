# AAuth SDK for .NET

[![CI](https://github.com/aauth-dev/dotnet-samples/actions/workflows/ci.yml/badge.svg)](https://github.com/aauth-dev/dotnet-samples/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/vpre/AAuth)](https://www.nuget.org/packages/AAuth)
[![NuGet Downloads](https://img.shields.io/nuget/dt/AAuth)](https://www.nuget.org/packages/AAuth)


> 🚧 **Draft Specification** — The AAuth protocol is under active development. APIs and wire formats may change as the spec evolves. See [aauth-spec/](aauth-spec/) for the current draft.

The [AAuth protocol](https://github.com/dickhardt/AAuth) SDK for .NET — agent-to-resource authorization with cryptographic proof-of-possession.

The SDK supports all four signing modes (`hwk`, `jwks_uri`, `jwt`, `jkt-jwt`), the full three-party challenge/exchange flow (autonomous and deferred user-consent), signature verification middleware, resource & auth token builders, JWKS / metadata discovery, and a Blazor `GuidedTour` walk-through. See the [SDK documentation](docs/) for complete usage guides.

## What is AAuth?

AAuth is a four-party authorization protocol for AI agents. Every HTTP request carries a cryptographic signature — there are no bearer tokens. See the [protocol spec](aauth-spec/draft-hardt-oauth-aauth-protocol.md) for full details.

The four parties are:

- **Agent** — signs every outbound HTTP request (RFC 9421) and presents keying material in the `Signature-Key` header.
- **Resource** — verifies the signature, optionally challenges with a `resource_token` to demand a person-scoped `auth_token`.
- **Person Server (PS)** — represents the user; manages missions, federates to AS, issues `aa-auth+jwt` proving the person delegated access.
- **Access Server (AS)** — issues auth tokens; enforces resource access policy.

> **Agent Provider (AP)** is a supporting role that issues `aa-agent+jwt` tokens binding an agent's signing key to its identity.

## Quick Start

```bash
dotnet add package AAuth --prerelease
```

```csharp
using AAuth.Crypto;
using AAuth.HttpSig;

var key = AAuthKey.Generate();

using var client = new AAuthClientBuilder(key)
    .UseHwk()
    .Build();

var response = await client.GetAsync("https://resource.example/data");
// Every request is signed per RFC 9421 — no bearer tokens
```

See [Getting Started](docs/getting-started.md) for key persistence, DI integration, and all signing modes.

## Documentation

Full SDK documentation lives in the [`docs/`](docs/) directory:

| Section | Description |
|---------|-------------|
| [Getting Started](docs/getting-started.md) | Install, generate a key, make your first signed request |
| [Concepts](docs/concepts.md) | The four participants, three layers, and how the SDK maps to them |
| [Signing Modes](docs/signing-modes/overview.md) | Pseudonymous, Agent Identity, Agent Token, Key Rotation |
| [Workflows](docs/workflows/identity-based-access.md) | Identity-based, Resource-managed, PS-asserted, Federated access |
| [Server Implementation](docs/server/verification-middleware.md) | Verification middleware, metadata, token issuance, replay detection |
| [Advanced Topics](docs/advanced/key-management.md) | Key management, missions, platform attestation, error handling |
| [Configuration Reference](docs/reference/configuration.md) | All configuration options |

## Repository Layout

| Path | Description |
|------|-------------|
| [aauth-spec/](aauth-spec/) | Protocol specifications (draft-01) copied from [dickhardt/AAuth](https://github.com/dickhardt/AAuth) — see [SPEC-VERSION.md](aauth-spec/SPEC-VERSION.md) |
| [docs/](docs/) | SDK documentation — signing modes, workflows, server guides, and reference |
| [src/AAuth/](src/AAuth/) | AAuth SDK library |
| [samples/](samples/) | Sample applications — see [samples/README.md](samples/README.md) for details |
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

The quickest path:

```bash
make demo          # starts WhoAmI + MockPersonServer + GuidedTour together
```

Then open <http://localhost:5400> and click **Run all**.

See [samples/README.md](samples/README.md) for per-sample instructions, flags, and all Make targets.

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
