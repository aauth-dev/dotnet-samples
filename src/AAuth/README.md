# AAuth SDK for .NET

The [AAuth protocol](https://aauth.dev) SDK for .NET — agent-to-resource authorization with cryptographic proof-of-possession. Every HTTP request carries an RFC 9421 signature; there are no bearer tokens.

> 🚧 **Draft Specification** — The AAuth protocol is under active development. APIs and wire formats may change as the spec evolves.

## Install

```bash
dotnet add package AAuth --prerelease
```

## Quick Start

Use an AP-issued agent JWT with the matching locally held key. The provider
assigns the enrolled identity; replace the HTTPS endpoints with your deployment.

```csharp
using AAuth.Crypto;
using AAuth;

var keyStore = FileKeyStore.Default();
var key = keyStore.LoadOrCreate("my-agent");
var enrollment = await AAuthClientBuilder.Bootstrap("https://ap.example/enrol")
    .WithKey(key).WithKeyStore(keyStore).EnrolAsync();
using var client = AAuthClientBuilder.Enrolled(key)
    .RefreshingFrom("https://ap.example/refresh", enrollment.LocalKeyHandle!)
    .WithKeyStore(keyStore)
    .Build();

var response = await client.GetAsync("https://resource.example/data");
// Signature-Key: sig=jwt;jwt="<aa-agent+jwt>"
```

## Access Modes

AAuth supports five resource access modes. Each adds parties and capabilities, and they build on one another — adoption is incremental.

| Mode | Parties | When to Use | Signing |
|------|---------|-------------|---------|
| **Identity-Based** | Agent + Resource | Resource authorizes verified agent identity | `jwt` |
| **Resource-Managed** (two-party) | Agent + Resource | Resource manages authorization itself | `jwt` plus opaque AAuth-Access |
| **Person Identity** | Agent + Resource + PS | Resource requires a PS-issued person token before issuing an auth-token challenge | `jwt` with a person token |
| **PS Authorization** (three-party) | Agent + Resource + PS | Resource accepts consent and identity claims (`sub`, `email`, `tenant`, `groups`, `roles`) from a trusted Person Server | `jwt` |
| **Federated** (four-party) | Agent + Resource + PS + AS | Cross-domain access with the resource's own Access Server enforcing policy | `jwt` |

## Three-Party Flow (Agent → Resource → Person Server)

The PS authorization flow is the primary authorization model. The resource first
asks for a person token, then issues a resource token bound to that presented
person token, and the agent exchanges both at the Person Server. Add
`WithChallengeHandling` when building the client and the entire
401 → person token → 401 → auth token → retry cycle becomes automatic:

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
// 1. Agent signs GET with agent token → Resource returns requirement=person-token
// 2. ChallengeHandler requests a person token and retries the resource
// 3. Resource returns requirement=auth-token + resource_token bound by presented_jti
// 4. ChallengeHandler POSTs resource_token + presented_token to the PS
// 5. PS validates the pair, prompts user for consent, issues auth_token
// 6. Agent retries GET signed with auth_token → Resource verifies → 200 OK
```

For CLI/desktop agents that enroll with an external Agent Provider, and for the
resource- and Person-Server-side code, see the
[full Getting Started guide](https://github.com/aauth-dev/dotnet-samples/blob/main/docs/getting-started.md).

## Features

Targets AAuth protocol draft-11 and HTTP Signature Keys draft-09. Companion
packages provide R3 and revised Events draft-00 as vendored with draft-11. Fully specified
Ed25519/ES256 keys and JWT headers are supported; old wire aliases are rejected.
X.509/cached carriers, third-party login hosting and platform attestation are
not implemented. Production persistence, user admission and transport policies
remain host responsibilities. Local test success is not universal external interop.

- Six Signature-Key schemes: `hwk`, `jkt-jwt`, `jwks_uri`, `jwks`, `jwt`, `self-jwt`; AAuth agent resource requests use `jwt`
- Two-party resource-managed access with opaque `AAuth-Access` tokens
- Full three-party challenge/exchange flow (person token, autonomous and deferred user-consent)
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
