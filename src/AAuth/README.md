# AAuth SDK for .NET

The [AAuth protocol](https://aauth.dev) SDK for .NET — agent-to-resource authorization with cryptographic proof-of-possession. Every HTTP request carries an RFC 9421 signature; there are no bearer tokens.

> 🚧 **Draft Specification** — The AAuth protocol is under active development. APIs and wire formats may change as the spec evolves.

## Install

```bash
dotnet add package AAuth --prerelease
```

## Quick Start

The simplest mode is **pseudonymous (HWK)** — the agent signs every request with an inline public key. No Agent Provider, no Person Server, no registration.

```csharp
using AAuth.Crypto;
using AAuth;

var key = AAuthKey.Generate(); // Ed25519 keypair

using var client = new AAuthClientBuilder(key)
    .UseHwk() // Pseudonymous mode: inline public key in Signature-Key header
    .Build();

var response = await client.GetAsync("https://resource.example/data");
// Request is signed per RFC 9421 — the resource verifies the signature
// using the public key from the Signature-Key: sig=hwk;jkt="...";jwk="..." header
```

## Access Modes

AAuth supports four resource access modes. Each adds parties and capabilities, and they build on one another — adoption is incremental.

| Mode | Parties | When to Use | Signing |
|------|---------|-------------|---------|
| **Identity-Based** | Agent + Resource | Replacing API keys with cryptographic identity | `hwk` / `jwks_uri` |
| **Resource-Managed** (two-party) | Agent + Resource | Resource manages authorization itself (interaction, OAuth/OIDC, internal policy) | Any |
| **PS-Asserted** (three-party) | Agent + Resource + PS | Resource accepts identity claims (`sub`, `email`, `tenant`, `groups`, `roles`) from any Person Server | `jwt` |
| **Federated** (four-party) | Agent + Resource + PS + AS | Cross-domain access with the resource's own Access Server enforcing policy | `jwt` |

## Three-Party Flow (Agent → Resource → Person Server)

The PS-Asserted flow is the primary authorization model. The resource delegates authorization to the agent's Person Server, which prompts the user for consent. Add `WithChallengeHandling` when building the client and the entire 401 → exchange → retry cycle becomes automatic:

```csharp
using AAuth.Crypto;
using AAuth;

var key = AAuthKey.Generate();

// A hosted service acts as its own Agent Provider (self-issuing).
using var client = AAuthClientBuilder.SelfIssuing(key)
    .As("https://my-service.example", "aauth:my-service@my-service.example")
    .WithKid("svc-key-1")
    .WithPersonServer("https://ps.example")
    .WithChallengeHandling() // automatic 401 → PS exchange → retry
    .Build();

var response = await client.GetAsync("https://resource.example/data");
// 1. Agent signs GET with agent token → Resource verifies, returns 401 + resource_token
// 2. ChallengeHandler POSTs resource_token to PS token endpoint
// 3. PS validates agent, prompts user for consent, issues auth_token
// 4. Agent retries GET signed with auth_token → Resource verifies → 200 OK
```

For CLI/desktop agents that enroll with an external Agent Provider, and for the
resource- and Person-Server-side code, see the
[full Getting Started guide](https://github.com/aauth-dev/dotnet-samples/blob/main/docs/getting-started.md).

## Features

- All four signing modes: `hwk`, `jwks_uri`, `jwt`, `jkt-jwt`
- Full three-party challenge/exchange flow (autonomous and deferred user-consent)
- Four-party federated access with an Access Server
- Signature verification middleware for resources
- Resource & auth token builders, JWKS / metadata discovery
- Self-hosted and enrolled (external Agent Provider) agent models

## Documentation

Full documentation, tutorials, samples, and an interactive protocol explorer:

- Protocol docs and tutorials: <https://aauth.dev>
- Interactive protocol explorer: <https://explorer.aauth.dev>
- Source, samples, and SDK guides: <https://github.com/aauth-dev/dotnet-samples>

## License

MIT
