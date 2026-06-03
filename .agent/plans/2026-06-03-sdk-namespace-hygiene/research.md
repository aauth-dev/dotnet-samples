---
title: "SDK Namespace Hygiene — Research"
description: Research document for improving the AAuth SDK namespace layout and public type naming
ms.date: 2026-06-03
---

## Problem Statement

The AAuth SDK (`src/AAuth/`) organizes ~106 types across 11 namespaces. The
layout is conventional and structurally sound — feature/layer folders map 1:1
to namespaces — but four recurring friction points hurt discoverability and
ergonomics for consumers:

1. **DI extension methods are not in the conventional namespace.** Registration
   helpers live in `AAuth.DependencyInjection` rather than the .NET-idiomatic
   `Microsoft.Extensions.DependencyInjection` / `Microsoft.AspNetCore.Builder`,
   so consumers must add an extra `using` they would not expect.
2. **The `AAuth` type-name prefix stutters** against the `AAuth.*` namespaces
   (`AAuth.Crypto.AAuthKey`, `AAuth.Agent.AAuthMission`, etc.).
3. **The four-party Access-Server feature is split** across `AAuth.Tokens` and
   `AAuth.Server`, so a single feature spans two namespaces.
4. **The primary client builders hide in `AAuth.HttpSig`**, which reads like an
   internal transport concern rather than the headline entry point.

This document captures the current state and the trade-offs. It contains no
task lists — see [implementation-plan.md](implementation-plan.md).

## Current Namespace Inventory

| Namespace | Folder | Representative types |
|---|---|---|
| `AAuth` | `src/AAuth/` | `AAuthUrl`, `AAuthConstants`, `AAuthDiagnostics`, `AAuthTokenType` |
| `AAuth.Crypto` | `Crypto/` | `IAAuthKey`, `AAuthKey`, `EcdsaAAuthKey`, `IKeyStore`, `FileKeyStore`, `InMemoryKeyStore`, `KeyFactory` |
| `AAuth.HttpSig` | `HttpSig/` | `AAuthClientBuilder`, `SelfIssuingBuilder`, `EnrolledBuilder`, `BootstrapBuilder`, `AAuthVerifier`, `AAuthSigningHandler`, `ISignatureKeyProvider`/`Resolver` family |
| `AAuth.Tokens` | `Tokens/` | `AuthTokenBuilder`, `AgentTokenBuilder`, `ResourceTokenBuilder`, `TokenVerifier`, `AccessServerClient`, `AccessServerRequest`, `ActChainBuilder`/`Reader` |
| `AAuth.Server` | `Server/` | `AAuthVerificationMiddleware`, `AAuthChallengeMiddleware`, `IAccessPolicy`, `IAccessPendingStore`, `AAuthAccessServerEndpoints`, `IJtiStore`, `WellKnownEndpoints` |
| `AAuth.Agent` | `Agent/` | `AgentProviderClient`, `TokenExchangeClient`, `ChallengeHandler`, `ITokenRefresher` family, `AAuthMission`, `IInteractionPresenter` |
| `AAuth.Discovery` | `Discovery/` | `MetadataClient`, `JwksClient`, `ServerMetadata` |
| `AAuth.Headers` | `Headers/` | `AAuthInteraction`, `AAuthRequirementHeader`, `AAuthClaimsRequirement`, `AAuthClaimsResponse` |
| `AAuth.Errors` | `Errors/` | `AAuthTokenExchangeException`, `AAuthPaymentRequiredException`, `SignatureError`, `TokenError`, `PollingError` |
| `AAuth.Identifiers` | `Identifiers/` | `AAuthAgentId`, `AAuthServerId` |
| `AAuth.DependencyInjection` | `DependencyInjection/` | `AAuthResourceServiceCollectionExtensions`, `AAuthAgentServiceCollectionExtensions`, `AAuthDiscoveryServiceCollectionExtensions`, `AAuthApplicationBuilderExtensions`, plus options records |

## Issue 1 — DI Extensions in a Non-Conventional Namespace

### Current state

```csharp
namespace AAuth.DependencyInjection;

public static class AAuthResourceServiceCollectionExtensions
{
    public static IServiceCollection AddAAuthResource(this IServiceCollection services, ...) { ... }
}
```

Extension targets and their idiomatic homes:

| Extension class | Extends | Idiomatic namespace |
|---|---|---|
| `AAuthResourceServiceCollectionExtensions` | `IServiceCollection` | `Microsoft.Extensions.DependencyInjection` |
| `AAuthAgentServiceCollectionExtensions` | `IServiceCollection` | `Microsoft.Extensions.DependencyInjection` |
| `AAuthDiscoveryServiceCollectionExtensions` | `IServiceCollection` | `Microsoft.Extensions.DependencyInjection` |
| `AAuthApplicationBuilderExtensions` | `IApplicationBuilder` | `Microsoft.AspNetCore.Builder` |

### Why it matters

`Program.cs` in an ASP.NET Core app already has `Microsoft.Extensions.DependencyInjection`
and `Microsoft.AspNetCore.Builder` in scope via implicit usings. Placing the
extension methods there makes `services.AddAAuthResource(...)` and
`app.UseAAuth...()` appear in IntelliSense with **no extra `using`**. This is
the established convention used by EF Core, MediatR, Polly, Serilog, etc.

### Consumer impact (in-repo)

`using AAuth.DependencyInjection;` appears in test/sample files including
[ActivityDiagnosticsTests.cs](../../tests/AAuth.Conformance/Observability/ActivityDiagnosticsTests.cs),
[AAuthResourceDITests.cs](../../tests/AAuth.Tests/DependencyInjection/AAuthResourceDITests.cs),
[AAuthAgentDITests.cs](../../tests/AAuth.Tests/DependencyInjection/AAuthAgentDITests.cs),
[NamingJwtValidationTests.cs](../../tests/AAuth.Conformance/HttpSignatures/NamingJwtValidationTests.cs),
[ChallengeMiddlewareTests.cs](../../tests/AAuth.Conformance/HttpSignatures/ChallengeMiddlewareTests.cs),
[AAuthDiscoveryDITests.cs](../../tests/AAuth.Tests/DependencyInjection/AAuthDiscoveryDITests.cs).
The option records currently in `AAuth.DependencyInjection`
(`AAuthResourceOptions`, `AAuthAgentOptions`, `AAuthDiscoveryOptions`,
`AAuthResourcePipelineOptions`) are referenced by the `configure` lambdas, so
they need a stable home that does not force the same extra `using`.

### Design note

The extension *methods* should move to the Microsoft namespaces; the *options*
records they configure can either move with them or relocate to a feature
namespace (e.g. `AAuth` root or `AAuth.Server`/`AAuth.Agent`). The safest split
is: methods → Microsoft namespaces, options → `AAuth` root (single `using AAuth;`).

## Issue 2 — `AAuth` Type-Name Prefix Stutter

`AAuth`-prefixed public types include (non-exhaustive): `AAuthKey`,
`AAuthScopeRequirement`, `AAuthInteraction`, `AAuthAccessMode`,
`AAuthAgentMetadataOptions`, `AAuthAuthenticationHandler`,
`AAuthVerificationOptions`, `AAuthChallengeMiddleware`, `AAuthClaimsResponse`,
`AAuthHttpContextExtensions`, `AAuthLevel`, `AAuthAccessServerOptions`,
`AAuthResourceMetadataOptions`, `AAuthVerificationResult`, `AAuthConstants`,
`AAuthDiagnostics`, `AAuthClaimsRequirement`, `AAuthMission`, `AAuthAgentId`,
`AAuthServerId`, `AAuthVerifier`, `AAuthClientBuilder`.

### Guidance

.NET naming guidelines recommend prefixing types in the **root** namespace and
for **disambiguation** against BCL/common names, but not redundantly inside a
descriptive sub-namespace. Two buckets:

| Keep the prefix (collision/identity risk) | Candidate to drop the prefix |
|---|---|
| `AAuthKey` (vs `System.Security...Key`) | `AAuthMission` → `Mission` |
| `AAuthVerifier` | `AAuthAgentId` → `AgentId` |
| `AAuthClientBuilder` (headline brand) | `AAuthServerId` → `ServerId` |
| `AAuthConstants`, `AAuthDiagnostics` (root) | `AAuthInteraction` → `Interaction` (in `Headers`) |
| `AAuthLevel`, `AAuthAccessMode` (terse enums) | `AAuthVerificationResult` → `VerificationResult` |

This is a **breaking** change (public renames). It is best done as one
deliberate sweep, not piecemeal, and gated behind a major version bump.

## Issue 3 — Access-Server Feature Split Across Namespaces

The four-party federated feature spans:

| Type | Current namespace | Role |
|---|---|---|
| `AccessServerClient` | `AAuth.Tokens` | Client the PS uses to federate |
| `AccessServerRequest` | `AAuth.Tokens` | Request DTO |
| `IAccessPolicy`, `AccessDecision` | `AAuth.Server` | AS-side policy contract |
| `IAccessPendingStore`, `AccessPendingEntry` | `AAuth.Server` | AS-side deferred-decision store |
| `AAuthAccessServerEndpoints`, `AAuthAccessServerOptions` | `AAuth.Server` | AS host helper |

A consumer building federated access must import both `AAuth.Tokens` and
`AAuth.Server`. Options: introduce a cohesive `AAuth.Access` namespace, or at
minimum co-locate the client-side pair with the policy/store contracts. Note
the directional asymmetry: `AccessServerClient` is used by the *Person Server*
(client role), while the policy/store/endpoints are used by the *Access Server*
(host role) — a single namespace is still reasonable since both are "access"
domain concepts.

## Issue 4 — Client Builders Under `AAuth.HttpSig`

The headline consumer entry points — `AAuthClientBuilder`, `SelfIssuingBuilder`,
`EnrolledBuilder`, `BootstrapBuilder` — live in `AAuth.HttpSig`, alongside
internal signing machinery (`AAuthSigningHandler`, `ISignatureKeyProvider`,
`SignatureKeyParser`). A newcomer typing `new AAuthClientBuilder()` will not
guess "HttpSig". `using AAuth.HttpSig;` appears in many test files, confirming
it is currently load-bearing for consumers.

### Options

- **A:** Move the four builders to root `AAuth` (joins `AAuthUrl`,
  `AAuthConstants`). Surfaces the headline API with a single `using AAuth;`.
- **B:** Introduce `AAuth.Client` for the builder family, leaving signing
  internals in `HttpSig`.

Option A maximizes "one using" ergonomics; Option B keeps a clean client/
transport separation. Either is breaking for the `using AAuth.HttpSig;` sites.

## Risk & Compatibility Summary

> **Policy (2026-06-03):** SDK is in **alpha** — clean breaks are acceptable.
> No `[Obsolete]` shims or type-forwarders; renames/moves are applied directly
> and all in-repo callers are updated in the same change.

| Issue | Breaking? | Notes |
|---|---|---|
| 1 — DI namespace | Non-breaking for callers using implicit usings; explicit `using AAuth.DependencyInjection;` sites (all in-repo) updated | Largest ergonomic win; ship first |
| 2 — Type renames | Breaking (public API) | Clean break; update all in-repo references via language-server rename |
| 3 — Access namespace | Breaking (`AccessServerClient` namespace move) | Clean break; update sample/test usings |
| 4 — Builder namespace | Breaking (`AAuth.HttpSig` move) | Clean break; update sample/test usings |

## Open Questions

1. **Compat shims:** Do we ship `[Obsolete]` forwarding aliases for the
   breaking renames (Issues 2–4), or is a clean break acceptable given the SDK
   is pre-1.0 / draft-stage?
   > **Resolved (2026-06-03):** Clean break — **no** `[Obsolete]` shims or
   > type-forwarders. The SDK is in **alpha**; breaking changes are acceptable.
   > Old names are simply renamed/removed and all in-repo callers updated.
2. **Options placement (Issue 1):** Move option records to `AAuth` root, or
   leave them in a dedicated `AAuth.Configuration` namespace? **Pending.**
3. **Issue 3 namespace name:** `AAuth.Access` vs `AAuth.Federation`? The spec
   uses "federated access"; the host is the "Access Server". **Pending — lean
   `AAuth.Access` to match the type-name stems (`Access*`).**
4. **Sequencing:** Should Issue 1 ship independently (non-breaking, immediate)
   ahead of the breaking batch (2–4)?
   > **Resolved (2026-06-03):** Phase ordering kept for review clarity, but no
   > version gate is required — alpha permits landing the breaking phases as
   > soon as each is ready.

## References

- .NET namespace/type naming guidelines (Framework Design Guidelines):
  prefix types in the root namespace; avoid redundant prefixes in descriptive
  sub-namespaces.
- ASP.NET Core convention: DI/builder extension methods live in
  `Microsoft.Extensions.DependencyInjection` and `Microsoft.AspNetCore.Builder`.
- In-repo prior art: [2026-05-27-token-refresher-concrete-types/research.md](../2026-05-27-token-refresher-concrete-types/research.md)
  discusses namespace placement for `AAuth.Agent` additions.
