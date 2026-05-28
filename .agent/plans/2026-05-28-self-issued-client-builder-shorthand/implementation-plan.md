---
title: "Client Builder Fluent Shorthand — Implementation Plan"
description: Phased plan for fluent shorthand methods across the AAuth SDK builder surface
ms.date: 2026-05-28
---

> **Phases 1–4:** COMPLETE (self-issued shorthand)
> **Phases 5–10:** COMPLETE (fluent refactor + AP-enrolled + resource shorthand + constants/extensions + response helpers)

---

## Phase 1: Core API — `AAuthClientBuilder.SelfIssued()` + `WithSelfIssuedToken()` ✅

*(Completed — see git log)*

### Definition of Done

- [x] `AAuthClientBuilder.SelfIssued()` compiles and is public
- [x] `AAuthClientBuilder.WithSelfIssuedToken()` compiles and is public
- [x] `AAuthClientBuilder.WithPersonServer()` compiles and is public
- [x] Unit tests pass (17 test cases)
- [x] Existing test suite passes (no regressions)
- [x] IntelliSense XML docs present on all new public members

---

## Phase 2: Update Samples ✅

*(Completed — see git log)*

### Definition of Done

- [x] All samples compile (`dotnet build`)
- [x] No sample uses raw `AgentTokenBuilder` inside a `WithTokenRefresh` callback
- [x] Orchestrator sample removes the `SelfIssueAgentToken()` helper method

---

## Phase 3: Update Documentation ✅

*(Completed — see git log)*

### Definition of Done

- [x] All doc code examples use shorthand as primary pattern
- [x] Verbose form preserved in "Advanced" sections
- [x] `docs/README.md` API table updated

---

## Phase 4: Update GuidedTour ✅

*(Completed — see git log)*

### Definition of Done

- [x] GuidedTour compiles
- [x] Code snippets show the new shorthand

---

## Phase 5: Fluent Refactor — `SelfIssuing(key).As(iss, sub)` ✅

Replace the positional-params `SelfIssued(key, iss, sub, kid)` with a fluent sub-builder
that makes the self-issuing (refresh) behavior obvious.

### API Surface

```csharp
// New entry point (verb form signals ongoing token minting)
public static SelfIssuingBuilder SelfIssuing(IAAuthKey key)

// Sub-builder
public sealed class SelfIssuingBuilder
{
    public SelfIssuingBuilder As(string issuer, string subject)
    public SelfIssuingBuilder WithKid(string kid)

    // Delegation back to AAuthClientBuilder
    public AAuthClientBuilder WithPersonServer(string personServer)
    public AAuthClientBuilder WithChallengeHandling()
    public AAuthClientBuilder WithChallengeHandling(string personServer)
    public AAuthClientBuilder WithChallengeHandling(Action<ChallengeHandlingOptions> configure)
    public AAuthClientBuilder WithCallChaining(HttpContext ctx)
    public AAuthClientBuilder WithCallChaining(Func<string?> provider)
    public AAuthClientBuilder WithCallChaining(string upstreamToken)
    public HttpClient Build()               // terminal — delegates to inner builder
    public HttpMessageHandler BuildHandler() // terminal
}
```

### Usage

```csharp
// Golden path:
using var client = AAuthClientBuilder.SelfIssuing(key)
    .As(issuer, subject)
    .WithPersonServer(ps)
    .WithChallengeHandling()
    .Build();

// Custom kid:
using var client = AAuthClientBuilder.SelfIssuing(key)
    .As(issuer, subject)
    .WithKid("svc-key-1")
    .WithPersonServer(ps)
    .WithChallengeHandling()
    .Build();
```

### Backward Compatibility

- `SelfIssued(key, iss, sub, kid)` remains (marks as `[Obsolete]` pointing to `SelfIssuing`)
- `WithSelfIssuedToken(iss, sub, kid)` remains (used by DI/From scenarios)

### Files

| Action | Path |
|--------|------|
| Create | `src/AAuth/HttpSig/SelfIssuingBuilder.cs` |
| Modify | `src/AAuth/HttpSig/AAuthClientBuilder.cs` (add `SelfIssuing()` factory) |
| Create | `tests/AAuth.Tests/HttpSig/SelfIssuingBuilderTests.cs` |

### Definition of Done

- [x] `SelfIssuingBuilder` compiles and is public
- [x] `AAuthClientBuilder.SelfIssuing(key)` returns it
- [x] `.As(iss, sub)` → `.WithPersonServer()` → `.Build()` produces working client
- [x] Unit tests pass (builder validation, delegation, kid default/override)
- [x] All 615 existing tests still pass

---

## Phase 6: AP-Enrolled Client Shorthand — `AAuthClientBuilder.Enrolled(key)` ✅

The AP-enrolled pattern is verbose:

```csharp
// Current (7 lines, 3 constructor calls)
new AAuthClientBuilder(key)
    .WithTokenRefresh(AgentProviderTokenRefresher.Create(refreshEndpoint, localKeyHandle)
        .WithKeyStore(keyStore)
        .Build())
    .WithChallengeHandling("https://ps.example")
    .Build();
```

### Proposed Fluent API

```csharp
// New (reads naturally, refresh behavior obvious)
AAuthClientBuilder.Enrolled(key)
    .RefreshingFrom(refreshEndpoint, localKeyHandle)
    .WithKeyStore(keyStore)
    .WithPersonServer(ps)
    .WithChallengeHandling()
    .Build();
```

### API Surface

```csharp
public static EnrolledBuilder Enrolled(IAAuthKey key)

public sealed class EnrolledBuilder
{
    public EnrolledBuilder RefreshingFrom(string refreshEndpoint, string localKeyHandle)
    public EnrolledBuilder WithKeyStore(IKeyStore keyStore)
    public EnrolledBuilder WithRefreshMode(RefreshMode mode, string? apIssuer = null)

    // Delegation to AAuthClientBuilder
    public AAuthClientBuilder WithPersonServer(string personServer)
    public AAuthClientBuilder WithChallengeHandling()
    public AAuthClientBuilder WithChallengeHandling(string personServer)
    public AAuthClientBuilder WithChallengeHandling(Action<ChallengeHandlingOptions> configure)
    public AAuthClientBuilder WithInteractionHandling()
    public AAuthClientBuilder WithInteractionHandling(Action<InteractionHandlingOptions> configure)
    public HttpClient Build()
    public HttpMessageHandler BuildHandler()
}
```

### Usage Comparison

| Scenario | Before | After |
|----------|--------|-------|
| Basic AP JWT | 7 lines | 5 lines |
| AP + interaction | 12 lines | 7 lines |
| Two-key refresh | 9 lines | 6 lines |

### Files

| Action | Path |
|--------|------|
| Create | `src/AAuth/HttpSig/EnrolledBuilder.cs` |
| Modify | `src/AAuth/HttpSig/AAuthClientBuilder.cs` (add `Enrolled()` factory) |
| Create | `tests/AAuth.Tests/HttpSig/EnrolledBuilderTests.cs` |

### Definition of Done

- [x] `EnrolledBuilder` compiles and is public
- [x] `.Enrolled(key).RefreshingFrom(...).WithKeyStore(...).Build()` produces working client
- [x] Default keystore is `FileKeyStore.Default()` when `WithKeyStore` is omitted
- [x] Two-key mode via `.WithRefreshMode(RefreshMode.TwoKey, apIssuer)`
- [x] Unit tests pass
- [x] Existing tests pass

---

## Phase 7: Resource Setup Shorthand — Unified `app.UseAAuth()` ✅

Current resource setup requires 3 separate middleware calls + options repetition:

```csharp
// Current (verbose, issuer/key repeated across options)
app.MapAAuthResourceWellKnown(new AAuthResourceMetadataOptions
{
    Issuer = resourceUrl,
    SigningKeys = new Dictionary<string, AAuthKey> { [kid] = key },
    ScopeDescriptions = new() { ["read"] = "Read data" },
});

app.UseAAuthVerification(new AAuthVerificationOptions
{
    ResourceIdentifier = resourceUrl,  // repeated!
    RequireIssuerVerification = true,
});

app.UseAAuthChallenge(new ChallengeOptions
{
    ResourceSigningKey = key,          // repeated!
    ResourceKeyId = kid,               // repeated!
    ResourceIdentifier = resourceUrl,  // repeated!
    DefaultScopes = "read",
});
```

### Proposed: `app.UseAAuth(resource => ...)`

```csharp
app.UseAAuth(resource => resource
    .Issuer(resourceUrl)
    .SigningKey(kid, key)
    .Scopes(s => s.Add("read", "Read data"))
    .RequireAuthToken()
    .RequireIssuerVerification());
```

### Alternative (less magic, more explicit): Keep DI + streamlined middleware

```csharp
// DI registration (already good — AddAAuthResource is fine)
builder.Services.AddAAuthResource(options =>
{
    options.Issuer = resourceUrl;
    options.SigningKeys = new() { [kid] = key };
});

// Middleware: single call replaces MapWellKnown + UseVerification + UseChallenge
app.MapAAuthResource();  // uses registered options for all three
```

### Analysis

The resource-side verbosity is not as painful because:
1. It's write-once setup code (not per-request like client construction)
2. `AddAAuthResource(opts => ...)` already captures most config in one place
3. The 3 middleware calls serve distinct concerns (metadata / verification / challenge) and may be mixed differently per path

**Recommendation:** A lighter touch — add `app.MapAAuthResource()` no-arg that reads from DI-registered `AAuthResourceOptions` to do all three in one call. Keep the individual middleware for advanced per-path configurations.

### Files

| Action | Path |
|--------|------|
| Modify | `src/AAuth/DependencyInjection/AAuthResourceServiceCollectionExtensions.cs` |
| Modify | `src/AAuth/Server/WellKnownEndpoints.cs` (add `MapAAuthResource()` extension) |
| Create | `tests/AAuth.Conformance/Server/MapAAuthResourceTests.cs` |

### Definition of Done

- [x] `app.MapAAuthResource()` serves well-known + configures verification + challenge middleware
- [x] Uses DI-registered `AAuthResourceOptions` automatically
- [x] Optional `Action<AAuthResourcePipelineOptions>` overload for inline config without DI pre-registration
- [x] Existing per-path middleware untouched
- [x] Unit tests pass

---

## Phase 8: Update Samples & Docs for Phases 5–7 ✅

Update all samples and docs to use the new fluent APIs.

### Files to Update

| File | Change |
|------|--------|
| `samples/Orchestrator/Program.cs` | Use `SelfIssuing(key).As(...)` |
| `samples/SampleApp/Components/Pages/*.razor` | Same |
| `samples/AgentConsole/Program.cs` | AP-enrolled path uses `Enrolled(key).RefreshingFrom(...)` |
| `samples/WhoAmI/Program.cs` | Consider `MapAAuthResource()` consolidation |
| `docs/getting-started.md` | Update all code examples |
| `docs/signing-modes/agent-token-jwt.md` | Update examples |
| `docs/workflows/*.md` | Update relevant examples |
| `docs/reference/dependency-injection.md` | Update DI examples |
| `README.md` | Update quick-start |
| `samples/GuidedTour/CodeSnippets.cs` | Update snippets |

### Definition of Done

- [x] All samples compile
- [x] All docs use new fluent API as primary examples
- [x] Verbose forms preserved in "Advanced" expandable sections
- [x] All tests pass

---

## Phase 9: Constants & HttpContext Extension Methods ✅

Consolidate bare string literals into well-named constants and provide typed
extension methods so resource endpoints don't need manual casts from
`HttpContext.Items`.

### Problem

Resource endpoint handlers currently require boilerplate:

```csharp
var parsed = (SignatureKeyParser.ParsedSignatureKeyInfo)
    ctx.Items[AAuthVerificationMiddleware.ParsedInfoItemKey]!;
var typ = (string?)parsed.Header?["typ"];

if (typ == "aa-agent+jwt") { ... }

ctx.Response.Headers["AAuth-Requirement"] = ...;
```

Issues:
1. Casting from `object?` is error-prone and requires importing two types.
2. Token type, header name, and scheme strings are scattered as bare literals.
3. The `VerificationResult` in `Items` duplicates what `Features` already holds via `AAuthVerificationResult` — users don't know which to use.

### A. Protocol Constants — `AAuthConstants` static class

Centralize strings that appear in 3+ places and aren't already behind a named constant.

```csharp
namespace AAuth;

/// <summary>Well-known protocol constants for the AAuth SDK.</summary>
public static class AAuthConstants
{
    /// <summary>HTTP header names used by AAuth.</summary>
    public static class Headers
    {
        public const string Signature = "Signature";
        public const string SignatureInput = "Signature-Input";
        public const string SignatureKey = "Signature-Key";  // already SignatureKeyHeader.Name
        public const string AAuthError = "AAuth-Error";
        public const string AAuthRequirement = "AAuth-Requirement"; // already AAuthRequirementHeader.Name
        public const string AAuthMission = "AAuth-Mission";         // already AAuthMission.Name
        public const string AAuthCapabilities = "AAuth-Capabilities";
    }

    /// <summary>Signature-Key scheme identifiers.</summary>
    public static class Schemes
    {
        public const string Jwt = "jwt";
        public const string Hwk = "hwk";
        public const string JktJwt = "jkt-jwt";
        public const string JwksUri = "jwks_uri";
    }

    /// <summary>Token type (<c>typ</c> header) values.</summary>
    public static class TokenTypes
    {
        public const string AgentToken = "aa-agent+jwt";
        public const string AuthToken = "aa-auth+jwt";
        public const string ResourceToken = "aa-resource+jwt";
        public const string NamingJwt = "naming+jwt";
    }

    /// <summary>Well-known DWK file names.</summary>
    public static class DwkFiles
    {
        public const string Agent = "aauth-agent.json";
        public const string Person = "aauth-person.json";
        public const string Access = "aauth-access.json";
        public const string Resource = "aauth-resource.json";
    }
}
```

### B. HttpContext Extension Methods — `AAuthHttpContextExtensions`

Provide strongly-typed access so endpoints read:

```csharp
using AAuth.Server;

app.MapGet("/", (HttpContext ctx) =>
{
    var result = ctx.GetAAuthVerification();  // AAuthVerificationResult (from Features)
    var parsed = ctx.GetAAuthParsedKey();     // ParsedSignatureKeyInfo (from Items)

    if (result.TokenType == AAuthConstants.TokenTypes.AgentToken) { ... }
});
```

Proposed surface:

```csharp
namespace AAuth.Server;

public static class AAuthHttpContextExtensions
{
    /// <summary>
    /// Gets the <see cref="AAuthVerificationResult"/> from <c>HttpContext.Features</c>.
    /// Returns null if verification middleware has not run.
    /// </summary>
    public static AAuthVerificationResult? GetAAuthVerification(this HttpContext context)
        => context.Features.Get<AAuthVerificationResult>();

    /// <summary>
    /// Gets the <see cref="ParsedSignatureKeyInfo"/> from <c>HttpContext.Items</c>.
    /// Returns null if verification middleware has not run.
    /// </summary>
    public static SignatureKeyParser.ParsedSignatureKeyInfo? GetAAuthParsedKey(this HttpContext context)
        => context.Items.TryGetValue(AAuthVerificationMiddleware.ParsedInfoItemKey, out var obj)
            ? obj as SignatureKeyParser.ParsedSignatureKeyInfo
            : null;

    /// <summary>
    /// Gets the <see cref="VerificationResult"/> from <c>HttpContext.Items</c>.
    /// Prefer <see cref="GetAAuthVerification"/> which returns the richer typed result.
    /// </summary>
    public static VerificationResult? GetAAuthResult(this HttpContext context)
        => context.Items.TryGetValue(AAuthVerificationMiddleware.ContextItemKey, out var obj)
            ? obj as VerificationResult
            : null;
}
```

### C. Replace Bare Literals in SDK Source

| File | Before | After |
|------|--------|-------|
| `AAuthVerificationMiddleware.cs` L91-92 | `"Signature"`, `"Signature-Input"` | `AAuthConstants.Headers.Signature`, `.SignatureInput` |
| `AAuthVerificationMiddleware.cs` L173, 211 | `"AAuth-Error"` | `AAuthConstants.Headers.AAuthError` |
| `AAuthVerificationMiddleware.cs` L227 | `"jwt" or "jkt-jwt"` | `AAuthConstants.Schemes.Jwt or AAuthConstants.Schemes.JktJwt` |
| `AAuthSigningHandler.cs` L163-168 | `"Signature"`, `"Signature-Input"` | `AAuthConstants.Headers.Signature`, `.SignatureInput` |
| `ChallengeHandler.cs` L203 | `"Signature" or "Signature-Input" or "Signature-Key"` | constants |
| `AAuthChallengeMiddleware.cs` L75, 135 | `"AAuth-Error"` | `AAuthConstants.Headers.AAuthError` |
| `AAuthChallengeMiddleware.cs` L80 | `"hwk" or "jwks_uri"` | `AAuthConstants.Schemes.Hwk or AAuthConstants.Schemes.JwksUri` |
| `SignatureKeyParser.cs` L96-99 | `"jwt"`, `"hwk"`, `"jkt-jwt"`, `"jwks_uri"` | scheme constants |
| `DefaultSignatureKeyResolver.cs` L38-41 | same scheme strings | scheme constants |
| `NamingJwtBuilder.cs` L31 | `"naming+jwt"` | `AAuthConstants.TokenTypes.NamingJwt` |
| `ServerMetadata.cs` L101,110,119 | DWK file names inline | `AAuthConstants.DwkFiles.*` |

### D. Update Samples to Use Extension Methods

| File | Before | After |
|------|--------|-------|
| `WhoAmI/Program.cs` (4 occurrences) | `(ParsedSignatureKeyInfo)ctx.Items[ParsedInfoItemKey]!` | `ctx.GetAAuthParsedKey()!` |
| `MockPersonServer/Program.cs` (1 occurrence) | same cast | `ctx.GetAAuthParsedKey()!` |
| `CallChain.razor` (execution code) | same cast | `ctx.GetAAuthParsedKey()!` |
| `Hwk.razor`, `JwksUri.razor` | same cast | `ctx.GetAAuthParsedKey()!` |
| All inline `"aa-agent+jwt"` | string literal | `AgentTokenBuilder.TokenType` or `AAuthConstants.TokenTypes.AgentToken` |

### Files

| Action | Path |
|--------|------|
| Create | `src/AAuth/AAuthConstants.cs` |
| Create | `src/AAuth/Server/AAuthHttpContextExtensions.cs` |
| Modify | `src/AAuth/Server/AAuthVerificationMiddleware.cs` (use constants) |
| Modify | `src/AAuth/Server/AAuthChallengeMiddleware.cs` (use constants) |
| Modify | `src/AAuth/HttpSig/AAuthSigningHandler.cs` (use constants) |
| Modify | `src/AAuth/HttpSig/SignatureKeyParser.cs` (use constants) |
| Modify | `src/AAuth/HttpSig/DefaultSignatureKeyResolver.cs` (use constants) |
| Modify | `src/AAuth/Agent/ChallengeHandler.cs` (use constants) |
| Modify | `src/AAuth/Agent/NamingJwtBuilder.cs` (use constants) |
| Modify | `src/AAuth/Discovery/ServerMetadata.cs` (use DWK constants) |
| Modify | `samples/WhoAmI/Program.cs` (use extension methods) |
| Modify | `samples/MockPersonServer/Program.cs` (use extension methods) |
| Modify | `samples/SampleApp/Components/Pages/CallChain.razor` (use extension & constants) |
| Modify | `samples/SampleApp/Components/Pages/Hwk.razor` (use extension) |
| Modify | `samples/SampleApp/Components/Pages/JwksUri.razor` (use extension) |
| Create | `tests/AAuth.Tests/AAuthConstantsTests.cs` (verify values match existing) |
| Create | `tests/AAuth.Tests/Server/AAuthHttpContextExtensionsTests.cs` |

### Definition of Done

- [x] `AAuthConstants` class compiles with all constants
- [x] Existing token builder constants (`AgentTokenBuilder.TokenType` etc.) remain but delegate or cross-reference to `AAuthConstants`
- [x] `AAuthHttpContextExtensions` compiles; `GetAAuthVerification()`, `GetAAuthParsedKey()`, `GetAAuthResult()` accessible
- [x] All bare string literals in SDK source replaced with constants
- [x] All `ctx.Items[ParsedInfoItemKey]!` casts in samples replaced with extension method
- [x] All 615+ existing tests still pass
- [x] New tests verify constant values match protocol spec
- [x] New tests verify extension methods return null when middleware hasn't run

### E. Token Type Enum — `AAuthTokenType`

Replace `string?` token type comparisons with a type-safe enum. The raw string
is still needed for JWT serialization but the public-facing API should use the enum.

```csharp
namespace AAuth;

/// <summary>AAuth token types from the JWT <c>typ</c> header.</summary>
public enum AAuthTokenType
{
    /// <summary>Unknown or missing token type.</summary>
    Unknown = 0,

    /// <summary>Agent token (<c>aa-agent+jwt</c>).</summary>
    AgentToken,

    /// <summary>Auth token (<c>aa-auth+jwt</c>).</summary>
    AuthToken,

    /// <summary>Resource token (<c>aa-resource+jwt</c>).</summary>
    ResourceToken,

    /// <summary>Naming JWT for key delegation (<c>naming+jwt</c>).</summary>
    NamingJwt,
}
```

With a helper for string↔enum conversion:

```csharp
public static class AAuthTokenTypeExtensions
{
    public static string ToHeaderValue(this AAuthTokenType type) => type switch
    {
        AAuthTokenType.AgentToken => AAuthConstants.TokenTypes.AgentToken,
        AAuthTokenType.AuthToken => AAuthConstants.TokenTypes.AuthToken,
        AAuthTokenType.ResourceToken => AAuthConstants.TokenTypes.ResourceToken,
        AAuthTokenType.NamingJwt => AAuthConstants.TokenTypes.NamingJwt,
        _ => throw new ArgumentOutOfRangeException(nameof(type)),
    };

    public static AAuthTokenType ParseTokenType(string? typ) => typ switch
    {
        AAuthConstants.TokenTypes.AgentToken => AAuthTokenType.AgentToken,
        AAuthConstants.TokenTypes.AuthToken => AAuthTokenType.AuthToken,
        AAuthConstants.TokenTypes.ResourceToken => AAuthTokenType.ResourceToken,
        AAuthConstants.TokenTypes.NamingJwt => AAuthTokenType.NamingJwt,
        _ => AAuthTokenType.Unknown,
    };
}
```

Affected properties:
- `AAuthVerificationResult.TokenType` → change from `string?` to `AAuthTokenType`
- `VerificationResult.TokenType` → change from `string?` to `AAuthTokenType`
- Middleware switch/if statements use enum comparisons
- `AgentTokenBuilder.TokenType`, `AuthTokenBuilder.TokenType`, `ResourceTokenBuilder.TokenType` remain as `const string` for JWT serialization (non-breaking)

Additional DoD:
- [x] `AAuthTokenType` enum compiles
- [x] `AAuthTokenTypeExtensions` round-trips all values
- [x] `AAuthVerificationResult.TokenType` is `AAuthTokenType` (breaking — acceptable since enum is richer)
- [x] Middleware uses enum comparisons internally
- [x] Samples use enum for comparisons (e.g. `result.TokenType == AAuthTokenType.AgentToken`)

---

## Phase 10: Resource-Side Response Helpers ✅

Encapsulate first-class protocol behaviors (challenge, error, token type query)
as one-liner extension methods on `HttpContext` so resource endpoints don't need
to know header names, formatting rules, or status codes.

### Problem

Issuing an AAuth challenge currently requires:

```csharp
ctx.Response.Headers[AAuthConstants.Headers.AAuthRequirement] =
    AAuthRequirementHeader.FormatAuthToken(resourceToken);
return Results.Json(new { error = "auth_token_required" },
    statusCode: StatusCodes.Status401Unauthorized);
```

This is verbose and leaks formatting details into application code.

### Solution

Three new extension methods on `AAuthHttpContextExtensions`:

```csharp
// Challenge: sets header + returns 401
return ctx.ChallengeAAuth(resourceToken);

// Error: sets AAuth-Error response header
ctx.SetAAuthError("something went wrong");

// Token type: reads enum from verification result
var type = ctx.GetAAuthTokenType();
```

### Files

| Action | Path |
|--------|------|
| Modify | `src/AAuth/Server/AAuthHttpContextExtensions.cs` |
| Modify | `samples/WhoAmI/Program.cs` (use `ChallengeAAuth`) |
| Modify | `docs/workflows/call-chaining.md` (use `ChallengeAAuth`) |
| Modify | `tests/AAuth.Tests/Server/AAuthHttpContextExtensionsTests.cs` |

### Definition of Done

- [x] `ctx.ChallengeAAuth(resourceToken)` sets `AAuth-Requirement` header and returns 401 `IResult`
- [x] `ctx.SetAAuthError(message)` sets `AAuth-Error` response header
- [x] `ctx.GetAAuthTokenType()` returns `AAuthTokenType` from verification result (or `Unknown`)
- [x] WhoAmI sample uses `ChallengeAAuth` instead of manual header + Results.Json
- [x] call-chaining.md docs updated
- [x] New unit tests pass
- [x] Full test suite passes (644 tests)

---

## Out of Scope

| Item | Reason |
|------|--------|
| `AdditionalClaims` in self-issued shorthand | Rare; use `WithTokenRefresh(SelfIssuedTokenRefresher.Create(...))` |
| Custom lifetime in shorthand | Default (1h) covers >95%; escape to `WithTokenRefresh` |
| Deprecating `WithTokenRefresh()` | Must remain for custom refresher scenarios |
| Removing `AgentTokenBuilder` | Still needed for server-side issuance and tests |
| Fluent Person Server setup | PS metadata is simple (1 endpoint + key) — no shorthand needed |
| Fluent MockAgentProvider setup | Demo code, not SDK API surface |
| JWT claim name constants (`"iss"`, `"sub"`, `"aud"`) | Standard claims — idiomatic to use inline in .NET; only AAuth-specific claims (`"agent"`, `"dwk"`, `"ps"`) could be future work |
