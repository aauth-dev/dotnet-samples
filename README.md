# AAuth SDK for .NET

[![CI](https://github.com/aauth-dev/dotnet-samples/actions/workflows/ci.yml/badge.svg)](https://github.com/aauth-dev/dotnet-samples/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/vpre/AAuth)](https://www.nuget.org/packages/AAuth)
[![NuGet Downloads](https://img.shields.io/nuget/dt/AAuth)](https://www.nuget.org/packages/AAuth)


> 🚧 **Draft Specification** — The AAuth protocol is under active development. APIs and wire formats may change as the spec evolves. See [aauth-spec/](aauth-spec/) for the current draft. This SDK is not yet spec-complete — [open an issue](https://github.com/aauth-dev/dotnet-samples/issues) to give feedback or report bugs.

The [AAuth protocol](https://aauth.dev) SDK for .NET — agent-to-resource authorization with cryptographic proof-of-possession. Visit [aauth.dev](https://aauth.dev) for the full protocol documentation, tutorials, and community resources.

## What is AAuth?

AAuth is a four-party authorization protocol for AI agents. Every HTTP request carries a cryptographic signature — there are no bearer tokens. See the [protocol spec](aauth-spec/draft-hardt-oauth-aauth-protocol.md) for full details.

The four parties are:

- **Agent** — signs every outbound HTTP request (RFC 9421) and presents keying material in the `Signature-Key` header.
- **Resource** — verifies the signature, optionally challenges with a `resource_token` to demand a person-scoped `auth_token`.
- **Person Server (PS)** — represents the user; manages missions, federates to AS, issues `aa-auth+jwt` proving the person delegated access.
- **Access Server (AS)** — issues auth tokens; enforces resource access policy.

> **Agent Provider (AP)** is a supporting role that issues `aa-agent+jwt` tokens binding an agent's signing key to its identity.

The SDK supports all four signing modes (`hwk`, `jwks_uri`, `jwt`, `jkt-jwt`), the full three-party challenge/exchange flow (autonomous and deferred user-consent), signature verification middleware, resource & auth token builders, JWKS / metadata discovery, and a Blazor `GuidedTour` walk-through. See the [SDK documentation](docs/) for complete usage guides.


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

### Three-Party Flow (Agent → Resource → Person Server)

Enrollment is a one-time provisioning step (like a DB migration). The durable signing key lives in a keystore and is referenced by ID — never extracted. The agent token is short-lived and refreshed automatically:

```csharp
using AAuth.Agent;
using AAuth.HttpSig;

// The key lives in the keystore; load it by the ID assigned during enrollment
var keyStore = KeyStore.Default(); // ~/.aauth/keys/ (or plug in HSM/TPM/Key Vault)
var key = await keyStore.LoadAsync("my-agent-key");

using var client = new AAuthClientBuilder(key!)
    .WithTokenRefresh(async (ctx, ct) =>
        await new AgentProviderClient(new HttpClient(), keyStore)
            .RefreshAsync("https://ap.example/refresh", ctx.KeyId, ct))
    .WithChallengeHandling("https://ps.example")
    .Build();

var response = await client.GetAsync("https://resource.example/protected");
```

See [Getting Started](docs/getting-started.md) for key persistence, DI integration, and all signing modes.

## Documentation

Full SDK documentation lives in [`docs/`](docs/):

- [Getting Started](docs/getting-started.md) — install, generate a key, first signed request
- [Concepts](docs/concepts.md) — the four participants and how the SDK maps to them
- [Signing Modes](docs/signing-modes/overview.md) — hwk, jwks_uri, jwt, jkt-jwt
- [Workflows](docs/workflows/identity-based-access.md) — identity-based, PS-asserted, federated
- [Server Guide](docs/server/verification-middleware.md) — verification middleware, token issuance
- [Configuration Reference](docs/reference/configuration.md)

## Running the Samples & Guided Tour

This repo includes sample services and an interactive Blazor walk-through.
The dev container gives you everything pre-configured, but you can also
run locally with the .NET 10 SDK.

### Sample App

Self-contained Blazor app with one page per AAuth flow (HWK, JWKS URI, JWT direct grant, Deferred user consent).

```bash
make demo-sample   # starts all servers + SampleApp on http://localhost:5240
```

![Sample App](samples/SampleApp/sample-app.png)

### Guided Tour

Step-by-step walk-through showing every HTTP exchange, header, and token claim across all protocol flows.

```bash
make demo          # starts all servers + GuidedTour on http://localhost:5400
```

![Guided Tour](samples/GuidedTour/tour-screenshot.png)

See [samples/README.md](samples/README.md) for the full list of sample projects and configuration options.

### Dev container (recommended)

Open this repo in VS Code → **Reopen in Container**. The container
provides .NET 10, the `gh` CLI, and the C# Dev Kit extensions.

### Local setup

Install the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0), then:

```bash
dotnet build AAuth.slnx
```

### Testing

```bash
dotnet test AAuth.slnx                # full suite (unit + conformance)
dotnet test tests/AAuth.Tests         # SDK unit + integration tests only
dotnet test tests/AAuth.Conformance   # spec conformance suite only
```

## Repository Layout

| Path | Description |
|------|-------------|
| [src/AAuth/](src/AAuth/) | AAuth SDK library (the NuGet package) |
| [docs/](docs/) | SDK documentation — signing modes, workflows, server guides |
| [samples/](samples/) | Sample applications — WhoAmI, AgentConsole, MockPersonServer, MockAgentProvider, GuidedTour, SampleApp |
| [tests/](tests/) | Unit, integration, and spec-conformance tests |
| [aauth-spec/](aauth-spec/) | Protocol specifications (draft-01) from [dickhardt/AAuth](https://github.com/dickhardt/AAuth) |

## Spec Compatibility

This SDK targets **draft-01** of the AAuth specifications:

| Spec | Draft |
|------|-------|
| [draft-hardt-oauth-aauth-protocol](aauth-spec/draft-hardt-oauth-aauth-protocol.md) | 01 |
| [draft-hardt-aauth-bootstrap](aauth-spec/draft-hardt-aauth-bootstrap.md) | 01 |
| [draft-hardt-aauth-r3](aauth-spec/draft-hardt-aauth-r3.md) | 01 |

Pinned to source commit [`c090879`](https://github.com/dickhardt/AAuth/commit/c090879ea2254d4af43a7253c7715f8d6530eb26) (2026-05-11). See [SPEC-VERSION.md](aauth-spec/SPEC-VERSION.md) for details.

## Contributing

1. Open this repo in the dev container (ensures consistent tooling).
2. Create a branch off `main`.
3. Make your changes — run `dotnet build AAuth.slnx` and `dotnet test AAuth.slnx` before submitting.
4. Open a pull request against `main`.
