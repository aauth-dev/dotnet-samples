# Token Issuance

> [Token Types](https://explorer.aauth.dev/foundations/tokens) | [Token Lifecycle](https://explorer.aauth.dev/tokens/lifecycle)

## Overview

The SDK provides builders for all three AAuth JWT token types. Each produces a compact JWT (`header.payload.signature`) signed with Ed25519.

## Resource Tokens (`aa-resource+jwt`)

Issued by a resource to challenge the agent. Contains the audience (Access Server URL) and the agent's key thumbprint.

```csharp
using AAuth.Tokens;

var resourceToken = new ResourceTokenBuilder
{
    Issuer = "https://resource.example",
    Audience = "https://as.example",          // where agent exchanges this
    Agent = "aauth:myapp@ap.example",         // agent identifier
    AgentJkt = keyInfo.Jkt!,                  // from parsed signature key
    Key = resourceSigningKey,                 // Ed25519 key
    KeyId = "resource-key-1",
    Scope = "read write",                     // requested scope
    Lifetime = TimeSpan.FromMinutes(5),       // default: 5 min
}.Build();

// Return as 401 challenge
context.Response.Headers["WWW-Authenticate"] = $"AAuth resource_token={resourceToken}";
return Results.Unauthorized();
```

### ResourceTokenBuilder Properties

| Property | Required | Default | Description |
|----------|:--------:|---------|-------------|
| `Issuer` | Yes | — | Resource URL (becomes `iss`) |
| `Audience` | Yes | — | AS/PS URL where agent exchanges (becomes `aud`) |
| `Agent` | Yes | — | Agent identifier (becomes `agent`) |
| `AgentJkt` | Yes | — | Agent's key thumbprint (for binding) |
| `Key` | Yes | — | Signing key |
| `KeyId` | Yes | — | Key ID (goes in JWT header `kid`) |
| `Scope` | No | — | Space-separated scopes |
| `Lifetime` | No | 5 min | Token validity duration |
| `IssuedAt` | No | Now | Override issuance time |
| `TokenId` | No | Auto | Custom `jti` (auto-generated UUID if omitted) |

## Auth Tokens (`aa-auth+jwt`)

Issued by a Person Server or Access Server to grant access. Bound to the agent's confirmation key.

```csharp
var authToken = new AuthTokenBuilder
{
    Issuer = "https://ps.example",
    Audience = "https://resource.example",    // resource that will accept this
    Agent = "aauth:myapp@ap.example",
    AgentConfirmationKey = agentPublicKey,    // binds token to agent's key
    Key = psSigningKey,
    KeyId = "ps-key-1",
    Dwk = AuthTokenBuilder.PersonDwk,        // "aauth-person.json" (or AccessDwk for AS)
    Scope = "read",
    Subject = "user@example.com",            // optional: person identifier
    Lifetime = TimeSpan.FromHours(1),
}.Build();
```

### AuthTokenBuilder Properties

| Property | Required | Default | Description |
|----------|:--------:|---------|-------------|
| `Issuer` | Yes | — | PS or AS URL (becomes `iss`) |
| `Audience` | Yes | — | Resource URL (becomes `aud`) |
| `Agent` | Yes | — | Agent identifier |
| `AgentConfirmationKey` | Yes | — | Agent's public key (bound via `cnf.jkt`) |
| `Key` | Yes | — | PS/AS signing key |
| `KeyId` | Yes | — | Key ID (JWT header `kid`) |
| `Dwk` | No | `"aauth-person.json"` | Discovery well-known path (`PersonDwk` or `AccessDwk`) |
| `Scope` | No | — | Granted scope |
| `Subject` | No | — | Person identifier |
| `Lifetime` | No | 1 hour | Token validity |
| `IssuedAt` | No | Now | Override issuance time |
| `TokenId` | No | Auto | Custom `jti` |

### Person Server vs Access Server

```csharp
// Person Server issues:
Dwk = AuthTokenBuilder.PersonDwk  // "aauth-person.json"

// Access Server issues:
Dwk = AuthTokenBuilder.AccessDwk  // "aauth-access.json"
```

The `Dwk` determines which `.well-known` document an agent fetches to find the issuer's public key for verification.

## Agent Tokens (`aa-agent+jwt`)

Issued by an Agent Provider to bind an agent's key to its identity.

```csharp
var agentToken = new AgentTokenBuilder
{
    Issuer = "https://ap.example",
    Subject = "aauth:myapp@ap.example",
    Key = apSigningKey,
    KeyId = "ap-key-1",
    ConfirmationKey = agentPublicKey,          // binds token to this key
    PersonServer = "https://ps.example",       // optional
    Lifetime = TimeSpan.FromHours(24),
}.Build();
```

## Token Verification

Use `TokenVerifier` to validate tokens received from other parties:

```csharp
var verifier = new TokenVerifier
{
    ClockSkew = TimeSpan.FromSeconds(30)
};

// Verify a resource token
var result = verifier.Verify(
    jwt: resourceTokenString,
    issuerKey: resourcePublicKey,
    expectedType: ResourceTokenBuilder.TokenType,
    expectedDwk: ResourceTokenBuilder.ResourceDwk,
    expectedAudience: "https://ps.example");

// Verify an auth token (also checks agent key binding)
var auth = verifier.VerifyAuthToken(
    jwt: authTokenString,
    issuerKey: psPublicKey,
    expectedAudience: "https://resource.example",
    httpSignatureKey: agentKey,
    expectedAgentId: "aauth:myapp@ap.example");
```

## Further Reading

- [Verification Middleware](verification-middleware.md) — signature verification before token logic
- [Replay Detection](replay-detection.md) — using `jti` to prevent reuse
