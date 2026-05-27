---
title: "ITokenRefresher Concrete Types — Research"
description: Research document for introducing built-in ITokenRefresher implementations to the AAuth SDK
ms.date: 2026-05-27
---

## Problem Statement

The SDK exposes `ITokenRefresher` (in `AAuth.Agent`) as a pluggable interface but ships no concrete implementations. Every documentation page, sample, and DI example re-implements the same 5-line `ApTokenRefresher` class that wraps `AgentProviderClient.RefreshAsync()`. This creates:

* Boilerplate in every agent application
* Inconsistency across docs (some call it `ApTokenRefresher`, others `AgentProviderRefresher`)
* A gap compared to `IKeyStore` which ships with `FileKeyStore` and `InMemoryKeyStore`

## Current SDK Surface

| Type | Namespace | Role |
|------|-----------|------|
| `ITokenRefresher` | `AAuth.Agent` | Interface — single method `RefreshAsync(TokenRefreshContext, CancellationToken)` |
| `TokenRefreshContext` | `AAuth.Agent` | Record with `CurrentToken`, `ApIssuer`, `AgentId`, `KeyId` |
| `DelegateTokenRefresher` | `AAuth.HttpSig` (internal) | Lambda-wrapping adapter used by `AAuthClientBuilder.WithTokenRefresh(Func<...>)` |
| `TokenRefreshHandler` | `AAuth.Agent` (internal) | `DelegatingHandler` that calls `ITokenRefresher` before expiry |
| `AgentProviderClient` | `AAuth.Agent` | Already has `RefreshAsync(endpoint, keyId, ct)` and `RefreshAsync(endpoint, currentToken, keyId, ct)` |
| `AgentTokenBuilder` | `AAuth.Tokens` | Builds self-issued agent tokens (JWT) |

## Refresh Patterns in Documentation

Three distinct patterns appear repeatedly:

### 1. Agent Provider Refresh (AP-enrolled agents)

Most common. The agent has a durable key enrolled with an AP. Refresh means signing a request to the AP's refresh endpoint.

```csharp
// Repeated in: ps-asserted-access.md, federated-access.md, dependency-injection.md
class ApTokenRefresher(IKeyStore keyStore, string apRefreshEndpoint) : ITokenRefresher
{
    public async Task<string> RefreshAsync(TokenRefreshContext ctx, CancellationToken ct)
    {
        var apClient = new AgentProviderClient(new HttpClient(), keyStore);
        return await apClient.RefreshAsync(apRefreshEndpoint, ctx.KeyId, ct);
    }
}
```

Problems with the sample pattern:
* Creates a new `HttpClient` per refresh (no pooling)
* Creates a new `AgentProviderClient` per refresh
* No retry/resilience

### 2. Self-Issued Refresh (hosted services)

Hosted services with stable URLs self-issue tokens via `AgentTokenBuilder`. No AP involved.

```csharp
// Repeated in: ps-asserted-access.md Code Example, self-issuance docs
.WithTokenRefresh(async (ctx, ct) => new AgentTokenBuilder
{
    Issuer = issuer,
    Subject = agentId,
    KeyId = keyId,
    Key = key,
    PersonServer = psUrl,
}.Build())
```

### 3. Delegate/Lambda (already handled)

`AAuthClientBuilder.WithTokenRefresh(Func<...>)` wraps in `DelegateTokenRefresher`. No SDK type needed — the builder already handles this.

## Proposed Concrete Types

### `AgentProviderTokenRefresher`

Covers pattern #1 — the AP refresh flow. Wraps `AgentProviderClient.RefreshAsync()`.

* Accepts `HttpClient` (or `IHttpClientFactory`) + `IKeyStore` + `refreshEndpoint`
* Reuses the client across calls (no per-call allocation)
* Calls `AgentProviderClient.RefreshAsync(endpoint, ctx.KeyId, ct)`

### `SelfIssuedTokenRefresher`

Covers pattern #2 — hosted services that mint their own agent tokens.

* Accepts `IAAuthKey` + `issuer` + `subject` + `keyId` + `personServer`
* Calls `AgentTokenBuilder.Build()` on each refresh
* Stateless — just builds a fresh JWT with updated `iat`/`exp`

## Namespace Placement

Both types belong in `AAuth.Agent` — they implement `ITokenRefresher` and compose agent-layer types (`AgentProviderClient`, `IKeyStore`). This parallels how `NoopAttestor` lives alongside `IPlatformAttestor`.

Exception: `SelfIssuedTokenRefresher` depends on `AgentTokenBuilder` (in `AAuth.Tokens`). Since `AAuth.Agent` already references `AAuth.Tokens` types transitively via the builder pipeline, this is fine.

## Spec References

* Agent Provider refresh flow: `draft-hardt-aauth-bootstrap.md` §8 (Token Refresh)
* Self-issued agent tokens: `draft-hardt-oauth-aauth-protocol.md` §Signature-Key header, scheme=jwt with self-issued tokens
* Token expiry/refresh timing: protocol spec §Agent Token Lifetime

## Naming Considerations

| Option | Pros | Cons |
|--------|------|------|
| `AgentProviderTokenRefresher` | Clear, specific | Long |
| `ApTokenRefresher` | Short, matches doc samples | `Ap` abbreviation unclear to newcomers |
| `AgentProviderRefresher` | Medium length | Might imply it refreshes the AP itself |

Recommendation: **`AgentProviderTokenRefresher`** — matches `AgentProviderClient` naming and is unambiguous. Alias via the shorter `ApTokenRefresher` name in docs if desired.

For self-issued: **`SelfIssuedTokenRefresher`** — matches `VerifySelfIssuedAgentToken` naming already in the SDK.

## Open Questions

1. Should `AgentProviderTokenRefresher` accept `HttpClient` directly or `IHttpClientFactory`? Direct `HttpClient` is simpler for `AAuthClientBuilder` usage; `IHttpClientFactory` is better for DI scenarios. **Resolution: Accept `HttpClient` in constructor (callers pass a pooled instance from DI or create one). This matches `AgentProviderClient`'s existing pattern.**

2. Should the refresh endpoint be part of the constructor or pulled from `TokenRefreshContext`? **Resolution: Constructor parameter — the endpoint is fixed per agent registration, not per-request.**

3. Should `SelfIssuedTokenRefresher` accept a custom lifetime or default to the SDK standard (e.g., 5 minutes)? **Resolution: Optional `TimeSpan? lifetime` constructor parameter, defaulting to `AgentTokenBuilder`'s default.**
