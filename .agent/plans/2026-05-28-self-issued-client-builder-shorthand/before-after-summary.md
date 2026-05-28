---
title: "Before / After — Fluent API Migration Summary"
description: Side-by-side comparison of old vs new API patterns and affected files
ms.date: 2026-05-28
---

## Self-Issued Identity (Phases 1 + 5)

### Before

```csharp
AAuthClientBuilder.SelfIssued(key, issuer, subject, kid)
    .WithPersonServer(ps)
    .WithChallengeHandling()
    .Build();
```

### After

```csharp
AAuthClientBuilder.SelfIssuing(key)
    .As(issuer, subject)
    .WithKid(kid)
    .WithPersonServer(ps)
    .WithChallengeHandling()
    .Build();
```

### Files Modified

| File | Change |
|------|--------|
| [src/AAuth/HttpSig/AAuthClientBuilder.cs](../../../src/AAuth/HttpSig/AAuthClientBuilder.cs) | Added `SelfIssuing()` factory, marked `SelfIssued()` as `[Obsolete]` |
| [src/AAuth/HttpSig/SelfIssuingBuilder.cs](../../../src/AAuth/HttpSig/SelfIssuingBuilder.cs) | New file — fluent sub-builder with `.As()`, `.WithKid()`, delegation methods |
| [samples/Orchestrator/Program.cs](../../../samples/Orchestrator/Program.cs) | `SelfIssued(key, url, id, kid)` → `SelfIssuing(key).As(url, id).WithKid(kid)` |
| [samples/SampleApp/Components/Pages/Jwt.razor](../../../samples/SampleApp/Components/Pages/Jwt.razor) | Same pattern in both execution code and display snippet |
| [samples/SampleApp/Components/Pages/CallChain.razor](../../../samples/SampleApp/Components/Pages/CallChain.razor) | Same pattern + Orchestrator handler snippet |
| [samples/SampleApp/Components/Pages/Deferred.razor](../../../samples/SampleApp/Components/Pages/Deferred.razor) | Same pattern in execution code and display snippet |
| [samples/GuidedTour/CodeSnippets.cs](../../../samples/GuidedTour/CodeSnippets.cs) | `CallChainConvenience` snippet |
| [docs/README.md](../../../docs/README.md) | API table: added `SelfIssuing()` and `Enrolled()` |
| [docs/getting-started.md](../../../docs/getting-started.md) | Self-issued examples (2 occurrences) |
| [docs/signing-modes/agent-token-jwt.md](../../../docs/signing-modes/agent-token-jwt.md) | Primary example |
| [docs/workflows/ps-asserted-access.md](../../../docs/workflows/ps-asserted-access.md) | Self-issued code example |
| [docs/workflows/bootstrap-enrollment.md](../../../docs/workflows/bootstrap-enrollment.md) | Self-issued section |
| [README.md](../../../README.md) | Quick-start snippet |
| [tests/AAuth.Tests/HttpSig/SelfIssuingBuilderTests.cs](../../../tests/AAuth.Tests/HttpSig/SelfIssuingBuilderTests.cs) | New file — 12 tests |

---

## AP-Enrolled Client (Phase 6)

### Before

```csharp
new AAuthClientBuilder(key)
    .WithTokenRefresh(AgentProviderTokenRefresher.Create(refreshEndpoint, localKeyHandle)
        .WithKeyStore(keyStore)
        .Build())
    .WithChallengeHandling("https://ps.example")
    .Build();
```

### After

```csharp
AAuthClientBuilder.Enrolled(key)
    .RefreshingFrom(refreshEndpoint, localKeyHandle)
    .WithKeyStore(keyStore)
    .WithChallengeHandling("https://ps.example")
    .Build();
```

### Files Modified

| File | Change |
|------|--------|
| [src/AAuth/HttpSig/AAuthClientBuilder.cs](../../../src/AAuth/HttpSig/AAuthClientBuilder.cs) | Added `Enrolled()` factory |
| [src/AAuth/HttpSig/EnrolledBuilder.cs](../../../src/AAuth/HttpSig/EnrolledBuilder.cs) | New file — fluent sub-builder with `.RefreshingFrom()`, `.WithKeyStore()`, `.WithRefreshMode()` |
| [samples/GuidedTour/CodeSnippets.cs](../../../samples/GuidedTour/CodeSnippets.cs) | `SignedGetJwt`, `TokenExchangeDirect`, `FullAutomatic` snippets |
| [samples/SampleApp/Components/Pages/Jwt.razor](../../../samples/SampleApp/Components/Pages/Jwt.razor) | Display code panel |
| [samples/SampleApp/Components/Pages/CallChain.razor](../../../samples/SampleApp/Components/Pages/CallChain.razor) | Agent code panel |
| [samples/SampleApp/Components/Pages/Deferred.razor](../../../samples/SampleApp/Components/Pages/Deferred.razor) | Display code panel |
| [docs/getting-started.md](../../../docs/getting-started.md) | AP-enrolled examples (3 occurrences) |
| [docs/workflows/bootstrap-enrollment.md](../../../docs/workflows/bootstrap-enrollment.md) | Runtime, single-key refresh, two-key refresh sections |
| [tests/AAuth.Tests/HttpSig/EnrolledBuilderTests.cs](../../../tests/AAuth.Tests/HttpSig/EnrolledBuilderTests.cs) | New file — 10 tests |

---

## Two-Key Refresh (via Enrolled)

### Before

```csharp
new AAuthClientBuilder(key)
    .WithTokenRefresh(AgentProviderTokenRefresher.Create(refreshEndpoint, localKeyHandle)
        .WithKeyStore(keyStore)
        .WithRefreshMode(RefreshMode.TwoKey, apIssuer)
        .Build())
    .Build();
```

### After

```csharp
AAuthClientBuilder.Enrolled(key)
    .RefreshingFrom(refreshEndpoint, localKeyHandle)
    .WithKeyStore(keyStore)
    .WithRefreshMode(RefreshMode.TwoKey, apIssuer)
    .Build();
```

### Files Modified

| File | Change |
|------|--------|
| [docs/workflows/bootstrap-enrollment.md](../../../docs/workflows/bootstrap-enrollment.md) | Two-key refresh section |

---

## Unified Resource Pipeline (Phase 7)

### Before

```csharp
app.MapAAuthResourceWellKnown(new AAuthResourceMetadataOptions { ... });
app.UseAAuthVerification(new AAuthVerificationOptions { ... });
app.UseAAuthChallenge(new ChallengeOptions { ... });
```

### After

```csharp
// DI registration (existing — unchanged)
builder.Services.AddAAuthResource(options => { ... });

// Single call replaces all three middleware registrations
app.MapAAuthResource();

// Or with inline options:
app.MapAAuthResource(opts =>
{
    opts.RequireIssuerVerification = true;
    opts.AccessMode = AAuthAccessMode.RequireAuthToken;
    opts.TrustedAuthTokenIssuers = new HashSet<string> { "https://ps.example" };
});
```

### Files Created

| File | Change |
|------|--------|
| [src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs) | Added `MapAAuthResource()` extension method |
| [src/AAuth/DependencyInjection/AAuthResourcePipelineOptions.cs](../../../src/AAuth/DependencyInjection/AAuthResourcePipelineOptions.cs) | New file — options class for the unified pipeline |

---

## Call-Chaining (Intermediary)

### Before

```csharp
using var client = new AAuthClientBuilder(key)
    .WithTokenRefresh(refreshFunc)
    .WithCallChaining(ctx)
    .Build();
```

### After

```csharp
using var client = AAuthClientBuilder.SelfIssuing(key)
    .As(orchestratorUrl, agentId)
    .WithPersonServer(psUrl)
    .WithCallChaining(ctx)
    .Build();
```

### Files Modified

| File | Change |
|------|--------|
| [samples/Orchestrator/Program.cs](../../../samples/Orchestrator/Program.cs) | Handler code |
| [samples/SampleApp/Components/Pages/CallChain.razor](../../../samples/SampleApp/Components/Pages/CallChain.razor) | Orchestrator handler display snippet |
| [samples/GuidedTour/CodeSnippets.cs](../../../samples/GuidedTour/CodeSnippets.cs) | `CallChainConvenience` snippet |

---

## Summary of New Public API Surface

| Entry Point | Returns | Purpose |
|-------------|---------|---------|
| `AAuthClientBuilder.SelfIssuing(key)` | `SelfIssuingBuilder` | Self-issued identity (hosted services) |
| `AAuthClientBuilder.Enrolled(key)` | `EnrolledBuilder` | AP-enrolled agents |
| `app.MapAAuthResource()` | `WebApplication` | Unified resource middleware pipeline |

| Sub-Builder Method | On | Effect |
|---|---|---|
| `.As(issuer, subject)` | `SelfIssuingBuilder` | Sets iss/sub for the minted JWT |
| `.WithKid(kid)` | `SelfIssuingBuilder` | Custom key ID (defaults to JWK thumbprint) |
| `.RefreshingFrom(endpoint, handle)` | `EnrolledBuilder` | Sets AP refresh endpoint and local key handle |
| `.WithKeyStore(keyStore)` | `EnrolledBuilder` | Custom key store (defaults to `FileKeyStore.Default()`) |
| `.WithRefreshMode(mode, apIssuer)` | `EnrolledBuilder` | Single-key or two-key refresh |

Both sub-builders delegate to `AAuthClientBuilder` for terminal methods (`.WithPersonServer()`, `.WithChallengeHandling()`, `.WithCallChaining()`, `.Build()`).

---

## Backward Compatibility

- `AAuthClientBuilder.SelfIssued(key, iss, sub, kid)` remains but is marked `[Obsolete]`
- `WithTokenRefresh(ITokenRefresher)` is unchanged — escape hatch for custom refreshers
- `new AAuthClientBuilder(key).UseHwk()/.UseJwksUri()/.UseJktJwt()` unchanged (identity-based modes)
- Individual middleware (`UseAAuthVerification`, `UseAAuthChallenge`, `MapAAuthWellKnown`) unchanged for per-path customization

---

## Constants & Extension Methods (Phase 9)

### Before — Bare String Literals & Manual Casts

```csharp
// Resource endpoint — verbose, cast-heavy, magic strings
app.MapGet("/", (HttpContext ctx) =>
{
    var parsed = (SignatureKeyParser.ParsedSignatureKeyInfo)
        ctx.Items[AAuthVerificationMiddleware.ParsedInfoItemKey]!;
    var typ = (string?)parsed.Header?["typ"];

    if (typ == "aa-agent+jwt")
    {
        ctx.Response.Headers["AAuth-Requirement"] = ...;
        return Results.Unauthorized();
    }
});
```

### After — Extension Methods & Constants

```csharp
// Resource endpoint — typed access, discoverable constants
app.MapGet("/", (HttpContext ctx) =>
{
    var parsed = ctx.GetAAuthParsedKey()!;
    var typ = (string?)parsed.Header?["typ"];

    if (typ == AAuthConstants.TokenTypes.AgentToken)
    {
        ctx.Response.Headers[AAuthConstants.Headers.AAuthRequirement] = ...;
        return Results.Unauthorized();
    }

    // Or use the higher-level typed result:
    var result = ctx.GetAAuthVerification()!;
    if (result.TokenType == AAuthTokenType.AgentToken) { ... }
});
```

### Files Created

| File | Purpose |
|------|---------|
| [src/AAuth/AAuthConstants.cs](../../../src/AAuth/AAuthConstants.cs) | Centralized protocol constants (Headers, Schemes, TokenTypes, DwkFiles) |
| [src/AAuth/AAuthTokenType.cs](../../../src/AAuth/AAuthTokenType.cs) | Token type enum + string↔enum extensions |
| [src/AAuth/Server/AAuthHttpContextExtensions.cs](../../../src/AAuth/Server/AAuthHttpContextExtensions.cs) | `GetAAuthVerification()`, `GetAAuthParsedKey()`, `GetAAuthResult()` |

### SDK Files Updated (bare literals → constants)

| File | Change |
|------|--------|
| [src/AAuth/Server/AAuthVerificationMiddleware.cs](../../../src/AAuth/Server/AAuthVerificationMiddleware.cs) | `"Signature"` → `AAuthConstants.Headers.Signature`, scheme strings → `AAuthConstants.Schemes.*`, `"AAuth-Error"` → constant, `AAuthVerificationResult.TokenType` now `AAuthTokenType` enum |
| [src/AAuth/Server/AAuthChallengeMiddleware.cs](../../../src/AAuth/Server/AAuthChallengeMiddleware.cs) | `"AAuth-Error"` → constant, `"hwk" or "jwks_uri"` → scheme constants, token type comparisons use `AAuthTokenType` enum |
| [src/AAuth/HttpSig/AAuthSigningHandler.cs](../../../src/AAuth/HttpSig/AAuthSigningHandler.cs) | `"Signature"`, `"Signature-Input"` → `AAuthConstants.Headers.*` |
| [src/AAuth/HttpSig/SignatureKeyParser.cs](../../../src/AAuth/HttpSig/SignatureKeyParser.cs) | Switch arms use `AAuthConstants.Schemes.*` |
| [src/AAuth/HttpSig/DefaultSignatureKeyResolver.cs](../../../src/AAuth/HttpSig/DefaultSignatureKeyResolver.cs) | Switch arms use `AAuthConstants.Schemes.*` |
| [src/AAuth/Agent/ChallengeHandler.cs](../../../src/AAuth/Agent/ChallengeHandler.cs) | Header filtering uses `AAuthConstants.Headers.*` |
| [src/AAuth/Agent/NamingJwtBuilder.cs](../../../src/AAuth/Agent/NamingJwtBuilder.cs) | `"naming+jwt"` → `AAuthConstants.TokenTypes.NamingJwt` |
| [src/AAuth/Discovery/ServerMetadata.cs](../../../src/AAuth/Discovery/ServerMetadata.cs) | DWK paths → `AAuthConstants.DwkFiles.*` |

### Samples Updated (extension methods)

| File | Change |
|------|--------|
| [samples/WhoAmI/Program.cs](../../../samples/WhoAmI/Program.cs) | 4× `(ParsedSignatureKeyInfo)ctx.Items[...]!` → `ctx.GetAAuthParsedKey()!` |
| [samples/MockPersonServer/Program.cs](../../../samples/MockPersonServer/Program.cs) | 1× same pattern |
| [samples/SampleApp/Components/Pages/CallChain.razor](../../../samples/SampleApp/Components/Pages/CallChain.razor) | Display snippet uses extension + `AAuthConstants.TokenTypes.AgentToken` |
| [samples/SampleApp/Components/Pages/Hwk.razor](../../../samples/SampleApp/Components/Pages/Hwk.razor) | Display snippet uses `ctx.GetAAuthParsedKey()!` |
| [samples/SampleApp/Components/Pages/JwksUri.razor](../../../samples/SampleApp/Components/Pages/JwksUri.razor) | Display snippet uses `ctx.GetAAuthParsedKey()!` |

### Tests Added

| File | Tests |
|------|-------|
| [tests/AAuth.Tests/AAuthConstantsTests.cs](../../../tests/AAuth.Tests/AAuthConstantsTests.cs) | 10 tests — verify constants match existing builder fields |
| [tests/AAuth.Tests/AAuthTokenTypeTests.cs](../../../tests/AAuth.Tests/AAuthTokenTypeTests.cs) | 13 tests — enum parse/format round-trips |
| [tests/AAuth.Tests/Server/AAuthHttpContextExtensionsTests.cs](../../../tests/AAuth.Tests/Server/AAuthHttpContextExtensionsTests.cs) | 6 tests — null when middleware not run, correct when set |

---

## Full New Public API Surface (Phase 9)

| Type | Member | Purpose |
|------|--------|---------|
| `AAuthConstants.Headers` | `.Signature`, `.SignatureInput`, `.SignatureKey`, `.AAuthError`, `.AAuthRequirement`, `.AAuthMission`, `.AAuthCapabilities` | HTTP header name constants |
| `AAuthConstants.Schemes` | `.Jwt`, `.Hwk`, `.JktJwt`, `.JwksUri` | Signature-Key scheme identifiers |
| `AAuthConstants.TokenTypes` | `.AgentToken`, `.AuthToken`, `.ResourceToken`, `.NamingJwt` | JWT typ header values |
| `AAuthConstants.DwkFiles` | `.Agent`, `.Person`, `.Access`, `.Resource` | Well-known DWK file names |
| `AAuthTokenType` | enum | Type-safe token type (Unknown, AgentToken, AuthToken, ResourceToken, NamingJwt) |
| `AAuthTokenTypeExtensions` | `.ToHeaderValue()`, `.ParseTokenType(string?)` | String↔enum conversion |
| `AAuthHttpContextExtensions` | `.GetAAuthVerification()`, `.GetAAuthParsedKey()`, `.GetAAuthResult()` | Typed HttpContext access |
| `AAuthVerificationResult.TokenType` | `AAuthTokenType` | Changed from `string?` to enum |

---

## Phase 10: Resource-Side Response Helpers

### Before (challenge a caller)

```csharp
ctx.Response.Headers[AAuthConstants.Headers.AAuthRequirement] =
    AAuthRequirementHeader.FormatAuthToken(resourceToken);
return Results.Json(new { error = "auth_token_required" },
    statusCode: StatusCodes.Status401Unauthorized);
```

### After

```csharp
return ctx.ChallengeAAuth(resourceToken);
```

### Before (set error header)

```csharp
ctx.Response.Headers[AAuthConstants.Headers.AAuthError] = "something went wrong";
```

### After

```csharp
ctx.SetAAuthError("something went wrong");
```

### Before (read token type)

```csharp
var result = ctx.Features.Get<AAuthVerificationResult>();
var tokenType = result?.TokenType ?? AAuthTokenType.Unknown;
```

### After

```csharp
var tokenType = ctx.GetAAuthTokenType();
```

### New API Surface (Phase 10)

| Type | Member | Purpose |
|------|--------|---------|
| `AAuthHttpContextExtensions` | `.ChallengeAAuth(string resourceToken)` | Sets `AAuth-Requirement` header + returns 401 IResult |
| `AAuthHttpContextExtensions` | `.SetAAuthError(string message)` | Sets `AAuth-Error` response header |
| `AAuthHttpContextExtensions` | `.GetAAuthTokenType()` | Returns `AAuthTokenType` from verification result |
