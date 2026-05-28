---
title: "Self-Issued Client Builder Shorthand — Research"
description: Research for combining AgentTokenBuilder into the AAuthClientBuilder fluent API
ms.date: 2026-05-28
---

## Problem Statement

The most common self-issued pattern requires constructing an `AgentTokenBuilder` inside a `WithTokenRefresh` callback:

```csharp
using var client = new AAuthClientBuilder(key)
    .WithTokenRefresh(async (ctx, ct) => new AgentTokenBuilder
    {
        Issuer = issuer,
        Subject = "aauth:my-service@my-service.example",
        KeyId = Kid,
        Key = key,
        PersonServer = "https://ps.example",
    }.Build())
    .WithChallengeHandling("https://ps.example")
    .Build();
```

Problems:
1. **Repetition** — `key` is passed to both the constructor and the token builder. `PersonServer` is passed to both the token builder and `WithChallengeHandling()`.
2. **Ceremony** — The user must understand `AgentTokenBuilder`, `ITokenRefresher`, and the callback signature just to do the simplest self-issued call.
3. **Leaking internals** — `KeyId` is usually just the JWK thumbprint (which the SDK already computes internally for `SelfIssuedTokenRefresher`).

Even with the existing `SelfIssuedTokenRefresher` (added in the token-refresher-concrete-types plan), it's still multi-line:

```csharp
using var client = new AAuthClientBuilder(key)
    .WithTokenRefresh(SelfIssuedTokenRefresher.Create(key, issuer, subject)
        .WithKid(kid)
        .WithPersonServer(psUrl)
        .Build())
    .WithChallengeHandling(psUrl)
    .Build();
```

## What the SDK Already Knows at Build Time

When a user configures a self-issued client, the `AAuthClientBuilder` already has:

| Parameter | Source | Already available? |
|-----------|--------|-------------------|
| `key` | Constructor `new AAuthClientBuilder(key)` | Yes |
| `kid` | Defaults to key's JWK thumbprint | Yes (computed internally) |
| `issuer` | Unique to caller | No — must be provided |
| `subject` | Unique to caller | No — must be provided |
| `personServer` | Often same value passed to `WithChallengeHandling(ps)` | Partially (only if challenge configured) |
| `lifetime` | Usually default (1 hour) | Not needed |

**Only `issuer` and `subject` are truly new information.** Everything else is either already held by the builder or has sensible defaults.

## Spec References

- Agent token structure: `draft-hardt-oauth-aauth-protocol.md` §Agent Token Structure — Required claims: `iss`, `dwk`, `sub`, `jti`, `cnf`, `iat`, `exp`. Optional: `ps`.
- Self-issued identity: Same spec §Agent Token Acquisition — "The mechanism for proving identity is platform-dependent." Self-hosted services act as their own AP.
- Signature-Key header: `draft-hardt-httpbis-signature-key` — scheme=jwt carries the agent token on every request.
- Token lifetime: spec recommends ≤ 24 hours; SDK defaults to 1 hour.

## Existing SDK Surface (Relevant)

| Type | Role |
|------|------|
| `AAuthClientBuilder(key)` | Fluent builder, holds the signing key |
| `.WithTokenRefresh(ITokenRefresher)` | Plugs in refresh logic |
| `.WithTokenRefresh(Func<ctx, ct, Task<string>>)` | Lambda shorthand |
| `.WithChallengeHandling(personServer)` | Enables 401 exchange; needs PS URL |
| `SelfIssuedTokenRefresher` | Implements `ITokenRefresher` for self-issued tokens |
| `SelfIssuedTokenRefresher.Create(key, issuer, subject).WithKid().WithPersonServer().Build()` | Fluent builder for the refresher |
| `AgentTokenBuilder` | Low-level JWT builder with all claims |

## Proposed API Options

### Option A: `WithSelfIssuedToken(issuer, subject)` — Minimal Required Params

```csharp
using var client = new AAuthClientBuilder(key)
    .WithSelfIssuedToken("https://my-service.example", "aauth:my-service@my-service.example")
    .WithChallengeHandling("https://ps.example")
    .Build();
```

**Semantics:**
- Implicitly creates a `SelfIssuedTokenRefresher` using the builder's `key`
- `kid` defaults to the key's JWK thumbprint
- `PersonServer` inferred from `WithChallengeHandling(psUrl)` if configured (or null)
- Implicitly sets JWT signing mode (no need for `UseJwt()` or separate `WithTokenRefresh()`)
- Token lifetime defaults to 1 hour

**Optional overload for PS in token (when no challenge handling needed):**
```csharp
.WithSelfIssuedToken("https://my-service.example", "aauth:my-service@my-service.example", personServer: "https://ps.example")
```

**Pros:**
- Fewest parameters (only what the SDK can't infer)
- Reads naturally: "build a client with a self-issued token"
- PersonServer DRY: inferred from challenge handling config when possible
- Backward compatible — existing `WithTokenRefresh()` APIs unchanged

**Cons:**
- Magic: `PersonServer` inference from `WithChallengeHandling` is non-obvious
- No kid customization without falling back to longer form
- Two concepts (token identity + refresh lifecycle) collapsed into one call

---

### Option B: `WithSelfIssuedToken(Action<SelfIssuedTokenOptions>)` — Options Lambda

```csharp
using var client = new AAuthClientBuilder(key)
    .WithSelfIssuedToken(opts =>
    {
        opts.Issuer = "https://my-service.example";
        opts.Subject = "aauth:my-service@my-service.example";
        opts.PersonServer = "https://ps.example";
    })
    .WithChallengeHandling()  // PS auto-extracted from token's ps claim
    .Build();
```

**Semantics:**
- Same underlying behavior as Option A
- `SelfIssuedTokenOptions` class with: `Issuer` (required), `Subject` (required), `KeyId` (optional), `PersonServer` (optional), `Lifetime` (optional)
- When `PersonServer` is set in options, `WithChallengeHandling()` (no-arg) can read it from the token's `ps` claim automatically

**Pros:**
- Familiar .NET pattern (matches `WithChallengeHandling(Action<...>)`)
- All token parameters visible in one block
- Easy to add future options without API breaks
- PersonServer set once, used by both token and challenge handler

**Cons:**
- More verbose than Option A for the common case
- Required properties in an options class are slightly awkward (must throw at build time, not compile time)

---

### Option C: Static Factory `AAuthClientBuilder.SelfIssued(key, issuer, subject)` 

```csharp
using var client = AAuthClientBuilder.SelfIssued(key, issuer, subject)
    .WithPersonServer("https://ps.example")  // sets both token ps + challenge PS
    .WithChallengeHandling()
    .Build();
```

**Semantics:**
- Static factory pre-configures: signing key, self-issued token refresh, JWT signing mode
- New `WithPersonServer(string)` method sets PS for both the token AND the challenge handler
- The factory returns `AAuthClientBuilder` — all existing methods still work

**Pros:**
- Most concise for the self-issued use case
- `WithPersonServer()` DRYly configures both token and challenge
- Mirrors `AAuthClientBuilder.Bootstrap()` and `AAuthClientBuilder.From()` patterns already in SDK
- Strong "pit of success" — caller can't forget to configure token refresh

**Cons:**
- Static factory proliferation (already have `Bootstrap()` and `From()`)
- `WithPersonServer()` is new builder state that has dual meaning (token claim vs. exchange target)
- Naming: `SelfIssued` as a factory name is clear but slightly breaks from the `.Bootstrap()` / `.From()` naming pattern

---

### Option D: Extend `WithTokenRefresh` with Sub-Builder Overload

```csharp
using var client = new AAuthClientBuilder(key)
    .WithTokenRefresh(selfIssued => selfIssued
        .Issuer("https://my-service.example")
        .Subject("aauth:my-service@my-service.example")
        .PersonServer("https://ps.example"))
    .WithChallengeHandling()
    .Build();
```

**Semantics:**
- New overload: `WithTokenRefresh(Action<SelfIssuedRefreshBuilder>)`
- The sub-builder internally creates a `SelfIssuedTokenRefresher`
- Key and kid auto-inherited from the parent builder

**Pros:**
- Stays within the existing `WithTokenRefresh` concept
- No new top-level methods on the builder
- Builder-in-builder pattern makes the relationship explicit

**Cons:**
- Nested builder might confuse newcomers
- Method resolution ambiguity risk with existing `WithTokenRefresh(Func<...>)` overload
- Doesn't simplify as much as A or C — still 4-5 lines

---

## Recommendation Matrix

| Criterion | A | B | C | D |
|-----------|---|---|---|---|
| Conciseness (fewest chars for common case) | ★★★★ | ★★★ | ★★★★★ | ★★★ |
| Discoverability (IntelliSense) | ★★★★ | ★★★ | ★★★★★ | ★★★ |
| Extensibility (future options without breaks) | ★★★ | ★★★★★ | ★★★★ | ★★★★ |
| Consistency with existing API | ★★★★ | ★★★★ | ★★★★ | ★★★ |
| Avoids PersonServer duplication | ★★★ | ★★★★ | ★★★★★ | ★★★★ |
| Non-breaking (existing code untouched) | ★★★★★ | ★★★★★ | ★★★★★ | ★★★★ |

## Combination Strategy

Options A and C are not mutually exclusive. A recommended approach combines:

- **Option C** (`AAuthClientBuilder.SelfIssued(...)`) for the "golden path" self-hosted service scenario
- **Option A** (`WithSelfIssuedToken(issuer, subject)`) as an instance method for cases where the builder is already constructed (e.g., from DI or `From()`)

Both delegate to `SelfIssuedTokenRefresher` internally. Existing `WithTokenRefresh()` overloads remain for advanced/custom scenarios.

## Impact Analysis

### Files That Currently Use the Verbose Pattern

| File | Current Pattern |
|------|----------------|
| `samples/Orchestrator/Program.cs` | Inline `AgentTokenBuilder` in `WithTokenRefresh` callback |
| `samples/SampleApp/Components/Pages/Jwt.razor` | Inline `AgentTokenBuilder` in callback |
| `samples/SampleApp/Components/Pages/Deferred.razor` | Same |
| `samples/SampleApp/Components/Pages/CallChain.razor` | Same |
| `docs/signing-modes/agent-token-jwt.md` | Code example with inline builder |
| `docs/workflows/ps-asserted-access.md` | Code example |
| `docs/getting-started.md` | Multiple examples |
| `samples/GuidedTour/CodeSnippets.cs` | String constants with examples |

### Documentation Pages Affected

- `docs/getting-started.md` — Primary onboarding examples
- `docs/signing-modes/agent-token-jwt.md` — JWT mode reference
- `docs/workflows/ps-asserted-access.md` — Three-party workflow
- `docs/workflows/call-chaining.md` — Call chaining examples
- `docs/reference/dependency-injection.md` — DI registration examples
- `README.md` — Quick start snippet

## Open Questions

1. **Should `WithPersonServer()` (Option C) set the challenge handler's PS automatically?** Recommendation: Yes — if `WithChallengeHandling()` is called without an explicit PS after `WithPersonServer()` was set, use the stored PS. Explicit PS in `WithChallengeHandling(ps)` takes precedence.

2. **Should `WithSelfIssuedToken()` implicitly enable challenge handling?** Recommendation: No — keep concerns separate. Self-issued tokens can be used for two-party access (no PS/challenge) as well.

3. **Should `kid` be customizable in the shorthand?** Recommendation: Yes, via an optional parameter or overload: `.WithSelfIssuedToken(issuer, subject, kid: "custom-kid")`.

---

## Phase 9 Research: Constants & HttpContext Extensions

### Current State of String Literals

The SDK has **48+ public constants** already defined, but they're co-located with
their owning types (e.g., `AgentTokenBuilder.TokenType`, `SignatureError.HeaderName`).
Several frequently-used strings have **no constant at all**:

| Literal | Occurrences | Defined? |
|---------|-------------|----------|
| `"Signature"` | 6 (middleware, signing handler, challenge handler) | No |
| `"Signature-Input"` | 5 (same three files) | No |
| `"AAuth-Error"` | 4 (verification + challenge middleware) | No |
| `"jwt"` / `"hwk"` / `"jkt-jwt"` / `"jwks_uri"` | 20+ (parser, resolver, middleware) | No |
| `"naming+jwt"` | 1 (NamingJwtBuilder) | No |
| `"aauth-resource.json"` etc. | 3 (ServerMetadata uses inline, not builder constants) | Defined in builders but not referenced by all consumers |

### HttpContext Access Patterns

Two parallel systems exist for reading verification results:

| Mechanism | Stored By | Access Pattern | Typed? |
|-----------|-----------|----------------|--------|
| `HttpContext.Items[ParsedInfoItemKey]` | Verification middleware | Cast from `object?` | No — requires `(ParsedSignatureKeyInfo)items[key]!` |
| `HttpContext.Items[ContextItemKey]` | Verification middleware | Cast from `object?` | No — requires `(VerificationResult)items[key]!` |
| `HttpContext.Features.Get<AAuthVerificationResult>()` | Verification middleware | Generic typed accessor | Yes |
| `HttpContext.Features.Get<UpstreamAuthTokenFeature>()` | Verification middleware | Generic typed accessor | Yes |

**Problem:** Samples and user code use `Items[]` because `ParsedSignatureKeyInfo`
exposes raw JWT header/payload access (scheme, jkt, jwks_uri, kid) that
`AAuthVerificationResult` doesn't fully surface. The cast-from-Items pattern
is awkward and undiscoverable.

### Design Decisions

1. **Single centralized `AAuthConstants` class vs. keep co-located constants?**
   Recommendation: Add `AAuthConstants` as the canonical "one-stop" reference
   for all protocol strings. Existing per-type constants (e.g., `AgentTokenBuilder.TokenType`)
   remain as convenience aliases but should reference `AAuthConstants` internally to
   ensure consistency.

2. **Extension methods on `HttpContext` vs. a wrapper type?**
   Recommendation: Extension methods — idiomatic in ASP.NET Core, zero allocation,
   no new abstraction. Three methods cover all use cases:
   - `GetAAuthVerification()` → `AAuthVerificationResult?` (the rich typed result)
   - `GetAAuthParsedKey()` → `ParsedSignatureKeyInfo?` (raw parsed JWT access)
   - `GetAAuthResult()` → `VerificationResult?` (legacy Items-based result)

3. **Should we deprecate `VerificationResult`?**
   Not in this phase. It has a different shape from `AAuthVerificationResult` and is
   used by `AAuthChallengeMiddleware`. Mark as internal consideration for a future phase.

4. **Namespace for constants?**
   `AAuth` (root namespace) — ensures constants are always in scope when `using AAuth;`
   is present.

5. **Pattern matching with constants?**
   C# pattern matching (`is "jwt" or "jkt-jwt"`) doesn't work with non-const references.
   Since `const string` fields in a static class work fine in patterns, this is safe:
   ```csharp
   if (scheme is AAuthConstants.Schemes.Jwt or AAuthConstants.Schemes.JktJwt) { ... }
   ```

### Prior Art in .NET

- `Microsoft.Net.Http.Headers.HeaderNames` — centralized HTTP header constants
- `System.Net.Mime.MediaTypeNames` — centralized MIME type constants
- `Microsoft.AspNetCore.Http.HttpContext.Features` + extension methods pattern
  (e.g., `IHttpResponseFeature`, `IHttpActivityFeature`)
- `Microsoft.AspNetCore.Authentication.AuthenticationHttpContextExtensions` —
  `HttpContext.AuthenticateAsync()`, `.SignInAsync()`, etc.

4. **What about `AdditionalClaims`?** Recommendation: Not in the shorthand. Users with additional claims fall back to `WithTokenRefresh(SelfIssuedTokenRefresher.Create(...))` or the full `AgentTokenBuilder` lambda.
