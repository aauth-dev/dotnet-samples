# Call-Chaining SDK Surface — Implementation Plan

## Overview

Add a composable API layer for call-chaining (multi-hop resource access) so that
intermediary services can implement spec-compliant downstream delegation in ~5
lines instead of ~80. Replaces PR #18 (`copilot/analyze-call-chaining`) which
will be abandoned.

## Context

- **Spec:** `draft-hardt-oauth-aauth-protocol` — §Call Chaining, §Upstream Token
  Verification, §Interaction Chaining, §Call Chaining Identity.
- **Abandoned PR:** #18 — validated as mostly spec-correct but with interaction
  chaining gaps and missing edge-case tests.
- **Branch:** TBD (create from `feature/gap-remediation-round-2`).

---

## Phase 1: `CallChainingRouter` + `UpstreamAuthTokenFeature`

**Goal:** Extract the routing logic into a public, testable pure-function and
surface the verified upstream auth token via `HttpContext.Features`.

### Files

| File | Action |
|------|--------|
| `src/AAuth/Server/CallChainingRouter.cs` | **New** — static class with `ResolveDownstreamServer(string upstreamAuthToken)` |
| `src/AAuth/Server/UpstreamAuthTokenFeature.cs` | **New** — sealed record exposed on HttpContext.Features |
| `src/AAuth/Server/AAuthVerificationMiddleware.cs` | **Modify** — set `UpstreamAuthTokenFeature` after auth-token verification |
| `src/AAuth/Server/AAuthVerificationOptions.cs` | **Modify** — expose `MaxActDepth` and `ClockSkew` (threaded to `TokenVerifier`) |
| `tests/AAuth.Conformance/CallChaining/CallChainingRouterTests.cs` | **New** — routing edge cases |

### API Surface

```csharp
// Pure-function routing (no network):
public static class CallChainingRouter
{
    public static string ResolveDownstreamServer(string upstreamAuthToken);
}

// Feature set by middleware after aa-auth+jwt verification:
public sealed class UpstreamAuthTokenFeature
{
    public string Token { get; }
}
```

### Routing Logic (per §Call Chaining)

```
1. Decode upstream auth token payload (already verified — no sig check).
2. If payload["mission"]["approver"] is present:
   a. Validate https-or-loopback → return approver URL.
   b. If invalid → throw (MUST NOT fall through to iss).
3. Else: return payload["iss"] (validate https-or-loopback).
```

### Test Cases

| Test | Input | Expected |
|------|-------|----------|
| Mission approver present | `{ "iss": "https://ps.example", "mission": { "approver": "https://mission-ps.example" } }` | `https://mission-ps.example` |
| No mission, iss is PS | `{ "iss": "https://ps.example" }` | `https://ps.example` |
| No mission, iss is AS | `{ "iss": "https://as.resource.example" }` | `https://as.resource.example` |
| Invalid mission.approver (http non-loopback) | `{ "mission": { "approver": "http://evil.example" } }` | throw `InvalidOperationException` |
| Missing iss | `{ "aud": "..." }` | throw `InvalidOperationException` |
| Malformed JWT (not 3 segments) | `not.a.jwt.at.all` | throw `InvalidOperationException` |
| Loopback iss (dev scenario) | `{ "iss": "http://localhost:5000" }` | `http://localhost:5000` |
| Null/empty approver field | `{ "mission": { "approver": "" } }` | throw (fail-fast, not fallthrough) |

### Definition of Done

- [x] `CallChainingRouter.ResolveDownstreamServer` handles all 3 routing cases.
- [x] Invalid `mission.approver` throws (does NOT fall through to `iss`).
- [x] `UpstreamAuthTokenFeature` set by middleware only for `aa-auth+jwt`.
- [x] `AAuthVerificationOptions.MaxActDepth` and `ClockSkew` threaded to `TokenVerifier` in middleware.
- [x] All 8+ routing tests pass.
- [x] Existing middleware tests unchanged (no regression).

---

## Phase 2: `ChallengeHandler` Upstream Token Support

**Goal:** Allow the existing `ChallengeHandler` to perform call-chaining
exchanges by accepting an upstream token provider.

### Files

| File | Action |
|------|--------|
| `src/AAuth/Agent/ChallengeHandler.cs` | **Modify** — add `Func<string?>? upstreamTokenProvider` parameter; route via `CallChainingRouter` when upstream token present |
| `src/AAuth/Agent/TokenExchangeClient.cs` | **Modify** — send `Prefer: wait=N` on initial POST to PS token endpoint |
| `tests/AAuth.Tests/Agent/ChallengeHandlerTests.cs` | **Modify** — add call-chaining test cases |

### Behavior Change

```csharp
// In SendAsync, after detecting 401 challenge:
var upstreamToken = _upstreamTokenProvider?.Invoke();
var targetServer = upstreamToken is not null
    ? CallChainingRouter.ResolveDownstreamServer(upstreamToken)
    : _personServer
        ?? throw new InvalidOperationException("No personServer and upstream token is null.");

var authToken = await _exchange.ExchangeAsync(
    targetServer, requirement.ResourceToken!,
    _onInteractionRequired, _pollerOptions,
    upstreamToken: upstreamToken,
    cancellationToken);
```

### Constructor Signature

```csharp
public ChallengeHandler(
    TokenExchangeClient exchange,
    AAuthTokenHolder holder,
    string? personServer,                                      // nullable when using upstream routing
    Func<AAuthInteraction, CancellationToken, Task>? onInteractionRequired = null,
    DeferredPollerOptions? pollerOptions = null,
    Func<string?>? upstreamTokenProvider = null)               // NEW
```

### Validation

- At least one of `personServer` or `upstreamTokenProvider` MUST be supplied.
- When both are supplied, `upstreamTokenProvider` takes precedence (call-chaining
  routing overrides static PS).

### Definition of Done

- [x] `ChallengeHandler` accepts and uses `upstreamTokenProvider`.
- [x] When upstream token is present, routes via `CallChainingRouter`.
- [x] When upstream token is null and `personServer` is set, falls back to static PS.
- [x] Throws `ArgumentException` if both personServer and upstreamTokenProvider are null.
- [x] `TokenExchangeClient` sends `Prefer: wait=45` on initial POST (configurable via `DeferredPollerOptions.PreferWaitSeconds`).
- [x] Existing challenge-handling tests unchanged (backward compatible).
- [x] New test: upstream token with `mission.approver` routes correctly.
- [x] New test: upstream token without mission routes to `iss`.
- [x] New test: initial exchange POST includes `Prefer` header.

---

## Phase 3: `AAuthClientBuilder.WithCallChaining()` Overloads

**Goal:** Fluent builder API for intermediary clients.

### Files

| File | Action |
|------|--------|
| `src/AAuth/HttpSig/AAuthClientBuilder.cs` | **Modify** — add 3 `WithCallChaining` overloads |
| `tests/AAuth.Tests/HttpSig/AAuthClientBuilderTests.cs` | **Modify** — add builder integration tests |

### API Surface

```csharp
// 1. Delegate provider (most flexible):
builder.WithCallChaining(Func<string?> upstreamTokenProvider);

// 2. Fixed token (when captured early):
builder.WithCallChaining(string upstreamAuthToken);

// 3. HttpContext-based (reads UpstreamAuthTokenFeature):
builder.WithCallChaining(HttpContext httpContext);
```

### Behavior

- Stores `_upstreamTokenProvider` on the builder.
- Implicitly enables challenge handling (call chaining always requires it).
- `personServer` becomes optional — resolved from upstream token at runtime.
- Passes `_upstreamTokenProvider` to `ChallengeHandler` constructor.

### Pipeline Composition

```
InteractionHandler (optional)
  → TokenRefreshHandler
    → ChallengeHandler (with upstreamTokenProvider)
      → AAuthSigningHandler (signs with intermediary's agent key)
        → HttpClientHandler
```

### Definition of Done

- [x] Three `WithCallChaining` overloads compile and pass null guards.
- [x] `WithCallChaining` implicitly enables challenge handling.
- [x] `personServer` is not required when `upstreamTokenProvider` is set.
- [x] Built client signs requests with intermediary's own key.
- [x] Integration test: builder + mock 401 → exchange with upstream_token → retry.
- [x] HttpContext overload reads from `UpstreamAuthTokenFeature`.

---

## Phase 4: `UseAAuthIntermediary` Extension + `CallChainingHandler` Refactor

**Goal:** Server-side middleware composition and simplification of the existing
`CallChainingHandler`.

### Files

| File | Action |
|------|--------|
| `src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs` | **Modify** — add `UseAAuthIntermediary` extension |
| `src/AAuth/Server/CallChainingHandler.cs` | **Modify** — delegate routing to `CallChainingRouter`; add `onInteractionRequired` + `pollerOptions` parameters |
| `tests/AAuth.Conformance/CallChaining/CallChainingHandlerTests.cs` | **Modify** — update for new signature |

### `UseAAuthIntermediary` API

```csharp
public static IApplicationBuilder UseAAuthIntermediary(
    this IApplicationBuilder app,
    AAuthVerificationOptions verificationOptions,
    ChallengeOptions challengeOptions)
{
    app.UseAAuthVerification(verificationOptions);
    app.UseAAuthChallenge(challengeOptions);
    return app;
}
```

### `CallChainingHandler.ExchangeForDownstreamAsync` Updated Signature

```csharp
public async Task<string> ExchangeForDownstreamAsync(
    string upstreamAuthToken,
    string resourceToken,
    Func<AAuthInteraction, CancellationToken, Task>? onInteractionRequired = null,
    DeferredPollerOptions? pollerOptions = null,
    CancellationToken cancellationToken = default)
```

### Definition of Done

- [x] `UseAAuthIntermediary` composes verification + challenge in correct order.
- [x] `CallChainingHandler.ResolveDownstreamServer` delegates to `CallChainingRouter`.
- [x] `ExchangeForDownstreamAsync` accepts interaction/poller callbacks.
- [x] Existing conformance tests adapted to new signature.
- [x] New test: `UseAAuthIntermediary` rejects agent tokens with 401.
- [x] New test: `UseAAuthIntermediary` passes auth tokens through.

---

## Phase 5: Orchestrator Sample Simplification

**Goal:** Rewrite `samples/Orchestrator/Program.cs` using the new APIs.

### Files

| File | Action |
|------|--------|
| `samples/Orchestrator/Program.cs` | **Rewrite** — use `UseAAuthIntermediary` + `WithCallChaining(ctx)` |
| `docs/workflows/call-chaining.md` | **Update** — document new "Simplified" pattern alongside lower-level building blocks |

### Target Code (~20 lines for the endpoint)

```csharp
app.UseWhen(
    ctx => !ctx.Request.Path.StartsWithSegments("/.well-known"),
    branch => branch.UseAAuthIntermediary(verificationOpts, challengeOpts));

app.MapGet("/", async (HttpContext ctx) =>
{
    await EnsureEnrolledAsync();

    using var downstream = new AAuthClientBuilder(enrolledKey!)
        .WithTokenRefresh(refreshFunc)
        .WithChallengeHandling()
        .WithCallChaining(ctx)
        .Build();

    var response = await downstream.GetAsync(downstreamUrl);
    var body = await response.Content.ReadAsStringAsync();
    // ... return result
});
```

### Definition of Done

- [x] Orchestrator endpoint ≤ 25 lines (down from ~80).
- [x] Sample still passes end-to-end with running servers (`make demo`).
- [x] Doc shows both simplified and lower-level patterns.
- [x] No behavioral change: same wire-format, same token exchanges.

---

## Phase 6: Interaction Chaining Documentation + Callback Wiring

**Goal:** Document and demonstrate the interaction-chaining path (202
propagation) without implementing automatic propagation middleware.

### Files

| File | Action |
|------|--------|
| `docs/advanced/interaction-chaining.md` | **New** — advanced guide for 202 propagation in intermediaries |
| `samples/Orchestrator/Program.cs` | **Modify** — add commented-out interaction-chaining example |

### Scope

This phase does NOT implement automatic 202 propagation (would require pending
URL management, background polling, response rewriting). Instead:

- Document the spec requirement (§Interaction Chaining).
- Show the `onInteractionRequired` callback pattern.
- Provide a code sample showing manual 202 return to caller.
- Identify automatic propagation as a future enhancement.

### Definition of Done

- [x] `docs/advanced/interaction-chaining.md` exists with spec-correct guidance.
- [x] Sample shows `onInteractionRequired` callback usage.
- [x] Open question documented: automatic propagation middleware (future).

---

## Phase 7: `AAuth-Mission` Auto-Forwarding on Downstream Requests

**Goal:** When the upstream auth token contains `mission.approver` and
`mission.s256`, the SDK automatically emits the `AAuth-Mission` header on
outbound downstream requests (per §Call Chaining — intermediaries operating in
mission context MUST include the header).

### Files

| File | Action |
|------|--------|
| `src/AAuth/Agent/MissionForwardingHandler.cs` | **New** — `DelegatingHandler` that emits `AAuth-Mission` header when upstream token has mission claims |
| `src/AAuth/Headers/AAuthMissionHeader.cs` | **Modify** — add `FormatStructured(string approver, string s256)` for spec-correct structured header format |
| `src/AAuth/HttpSig/AAuthClientBuilder.cs` | **Modify** — wire `MissionForwardingHandler` into pipeline when `WithCallChaining` is used |
| `tests/AAuth.Tests/Agent/MissionForwardingHandlerTests.cs` | **New** — verify header emission and format |

### Behavior

- When `WithCallChaining` is configured and the upstream token contains
  `mission.approver`, automatically insert `AAuth-Mission` on ALL downstream
  requests from that client.
- Header format: `AAuth-Mission: approver="https://ps.example"; s256="dBjf..."`
- Always forward when present — no opt-in flag needed.
- If no mission in upstream token, no header emitted (no-op).

### Pipeline Position

```
MissionForwardingHandler (reads upstream token, emits header)
  → InteractionHandler (optional)
    → TokenRefreshHandler
      → ChallengeHandler (with upstreamTokenProvider)
        → AAuthSigningHandler
          → HttpClientHandler
```

### Definition of Done

- [x] `AAuthMissionHeader.FormatStructured()` produces spec-correct structured header.
- [x] `MissionForwardingHandler` emits header when mission.approver present.
- [x] No header emitted when upstream token has no mission claims.
- [x] `WithCallChaining` auto-wires the handler (no extra builder call needed).
- [x] Test: mission present → header emitted with correct approver + s256.
- [x] Test: no mission → no header.

---

## Phase 8: Metadata Publishing Helpers (All Four Roles)

**Goal:** Provide `MapAAuth*WellKnown()` extension methods for all four metadata
endpoints so servers never hand-code well-known JSON responses.

### Files

| File | Action |
|------|--------|
| `src/AAuth/Server/WellKnownEndpoints.cs` | **Refactor** — extract shared JWKS mapping; add agent/PS/AS metadata builders |
| `src/AAuth/Server/AAuthAgentMetadataOptions.cs` | **New** — options for `/.well-known/aauth-agent.json` |
| `src/AAuth/Server/AAuthPersonServerMetadataOptions.cs` | **New** — options for `/.well-known/aauth-person.json` |
| `src/AAuth/Server/AAuthAccessServerMetadataOptions.cs` | **New** — options for `/.well-known/aauth-access.json` |
| `src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs` | **Modify** — add `MapAAuthAgentWellKnown`, `MapAAuthPersonServerWellKnown`, `MapAAuthAccessServerWellKnown` |
| `samples/Orchestrator/Program.cs` | **Modify** — replace hand-coded agent metadata with `MapAAuthAgentWellKnown` |
| `samples/MockPersonServer/Program.cs` | **Modify** — replace hand-coded PS metadata with `MapAAuthPersonServerWellKnown` |
| `tests/AAuth.Conformance/Server/WellKnownEndpointTests.cs` | **New** — verify all four metadata responses |

### API Surface

```csharp
// Agent/AP metadata (REQUIRED fields: issuer, jwks_uri):
app.MapAAuthAgentWellKnown(new AAuthAgentMetadataOptions
{
    Issuer = "https://orchestrator.example",
    SigningKeys = new() { ["key-1"] = myKey },
    // Optional: ClientName, LogoUri, CallbackEndpoint, LoginEndpoint
});

// Person Server metadata (REQUIRED fields: issuer, token_endpoint, jwks_uri):
app.MapAAuthPersonServerWellKnown(new AAuthPersonServerMetadataOptions
{
    Issuer = "https://ps.example",
    TokenEndpoint = "https://ps.example/token",
    SigningKeys = new() { ["ps-1"] = psKey },
    // Optional: MissionEndpoint, PermissionEndpoint, AuditEndpoint,
    //           InteractionEndpoint, RevocationEndpoint, ScopesSupported
});

// Access Server metadata (REQUIRED fields: issuer, token_endpoint, jwks_uri):
app.MapAAuthAccessServerWellKnown(new AAuthAccessServerMetadataOptions
{
    Issuer = "https://as.example",
    TokenEndpoint = "https://as.example/token",
    SigningKeys = new() { ["as-1"] = asKey },
    // Optional: RevocationEndpoint
});

// Resource metadata (EXISTING — no change to public API):
app.MapAAuthResourceWellKnown(new AAuthResourceMetadataOptions { ... });
```

### Shared JWKS Behavior

All four helpers share the same JWKS mapping pattern:
- Maps `/.well-known/jwks.json` with all keys from `SigningKeys`.
- If multiple helpers are registered on the same app, JWKS keys are merged.
- Uses `TryAdd` semantics — first registration wins for JWKS if conflict.

### Spec Field Mapping

| Helper | Endpoint | Required Fields |
|--------|----------|----------------|
| `MapAAuthAgentWellKnown` | `/.well-known/aauth-agent.json` | `issuer`, `jwks_uri` |
| `MapAAuthPersonServerWellKnown` | `/.well-known/aauth-person.json` | `issuer`, `token_endpoint`, `jwks_uri` |
| `MapAAuthAccessServerWellKnown` | `/.well-known/aauth-access.json` | `issuer`, `token_endpoint`, `jwks_uri` |
| `MapAAuthResourceWellKnown` | `/.well-known/aauth-resource.json` | `issuer`, `jwks_uri` |

### Definition of Done

- [x] `MapAAuthAgentWellKnown` serves correct JSON with required fields.
- [x] `MapAAuthPersonServerWellKnown` serves correct JSON with required fields.
- [x] `MapAAuthAccessServerWellKnown` serves correct JSON with required fields.
- [x] Existing `MapAAuthResourceWellKnown` unchanged (backward compatible).
- [x] JWKS endpoint includes keys from all registered helpers.
- [x] Orchestrator sample uses `MapAAuthAgentWellKnown` (no hand-coded JSON).
- [x] MockPersonServer sample uses `MapAAuthPersonServerWellKnown`.
- [x] Conformance tests verify all four metadata responses match spec fields.

---

## Phase 9: Cosmetic — `SupportedAlgorithms` Error Message Fix

**Goal:** Fix misleading error message that claims only EdDSA is supported when
the SDK actually accepts ES256 (P-256) as well. Spec says ES256 is a SHOULD.

### Files

| File | Action |
|------|--------|
| `src/AAuth/Server/AAuthVerificationMiddleware.cs` | **Modify** — update `SupportedAlgorithms` array to `["EdDSA", "ES256"]` |

### Definition of Done

- [ ] `SupportedAlgorithms` includes `"ES256"`.
- [ ] Error messages accurately reflect supported algorithms.
- [ ] No behavioral change (ES256 already works functionally).

---

## Phase 11: Configuration Surface Audit — Expose All Tunable Settings

**Goal:** Ensure all behavioral settings are configurable from the fluent builder
API, DI options classes, and middleware options — no hardcoded defaults that
consumers cannot override.

### Files

| File | Action |
|------|--------|
| `src/AAuth/Server/AAuthVerificationOptions.cs` | **Modify** — add `MaxActDepth`, `ClockSkew`, `MaxFutureSkew`, `Clock` |
| `src/AAuth/Server/AAuthVerificationMiddleware.cs` | **Modify** — thread options into `TokenVerifier` and `AAuthVerifier` construction |
| `src/AAuth/DependencyInjection/AAuthResourceOptions.cs` | **Modify** — add `MaxActDepth`, `ClockSkew`, `MaxFutureSkew` |
| `src/AAuth/DependencyInjection/AAuthAgentOptions.cs` | **Modify** — add `MinPollInterval`, `OnPoll` callback |
| `src/AAuth/HttpSig/ChallengeHandlingOptions.cs` | **Modify** — add `MinPollInterval` |
| `src/AAuth/HttpSig/InteractionHandlingOptions.cs` | **Modify** — add all `DeferredPollerOptions` fields (parity with `ChallengeHandlingOptions`) |
| `src/AAuth/DependencyInjection/AAuthDiscoveryOptions.cs` | **Modify** — add `Clock` (for testing) |
| `tests/AAuth.Tests/Configuration/OptionsThreadingTests.cs` | **New** — verify options flow to underlying components |

### Settings to Expose

#### Middleware / Server-Side (`AAuthVerificationOptions`)

| Setting | Type | Default | Source |
|---------|------|---------|--------|
| `MaxActDepth` | `int` | `10` | `TokenVerifier` |
| `ClockSkew` | `TimeSpan` | `30s` | `TokenVerifier` |
| `MaxFutureSkew` | `TimeSpan` | `5s` | `AAuthVerifier` |
| `Clock` | `Func<DateTimeOffset>?` | `null` (= UtcNow) | Both verifiers |

#### Client-Side (`ChallengeHandlingOptions` + `InteractionHandlingOptions`)

| Setting | Type | Default | Source |
|---------|------|---------|--------|
| `MinPollInterval` | `TimeSpan` | `100ms` | `DeferredPoller` |
| `OnPoll` | `Func<int, TimeSpan, Task>?` | `null` | `DeferredPoller` (observability) |

#### InteractionHandlingOptions Parity

Currently missing from `InteractionHandlingOptions` (but present in
`ChallengeHandlingOptions`):

| Setting | Type | Default |
|---------|------|---------|
| `PollingTimeout` | `TimeSpan` | `5min` |
| `DefaultPollInterval` | `TimeSpan` | `5s` |
| `PreferWaitSeconds` | `int?` | `null` |
| `MinPollInterval` | `TimeSpan` | `100ms` |

#### DI-Level (`AAuthResourceOptions` / `AAuthAgentOptions`)

| Setting | Type | Default | Target |
|---------|------|---------|--------|
| `MaxActDepth` | `int` | `10` | Resource DI path |
| `ClockSkew` | `TimeSpan` | `30s` | Resource DI path |
| `Clock` | `Func<DateTimeOffset>?` | `null` | All (shared clock for testing) |

### Threading Strategy

```text
AAuthVerificationOptions
    ├── MaxActDepth ──────→ TokenVerifier { MaxActDepth = ... }
    ├── ClockSkew ────────→ TokenVerifier { ClockSkew = ... }
    ├── MaxFutureSkew ────→ AAuthVerifier(maxFutureSkew: ...)
    └── Clock ────────────→ TokenVerifier.Clock + AAuthVerifier.Clock

ChallengeHandlingOptions
    ├── MinPollInterval ──→ DeferredPollerOptions.MinPollInterval
    └── OnPoll ───────────→ DeferredPollerOptions.OnPoll

InteractionHandlingOptions (add full parity)
    ├── PollingTimeout ───→ DeferredPollerOptions.MaxTotalWait
    ├── DefaultPollInterval → DeferredPollerOptions.DefaultPollInterval
    ├── PreferWaitSeconds ─→ DeferredPollerOptions.PreferWaitSeconds
    ├── MinPollInterval ──→ DeferredPollerOptions.MinPollInterval
    └── OnPoll ───────────→ DeferredPollerOptions.OnPoll
```

### Definition of Done

- [ ] `AAuthVerificationOptions` exposes `MaxActDepth`, `ClockSkew`, `MaxFutureSkew`, `Clock`.
- [ ] Middleware threads all options to `TokenVerifier` and `AAuthVerifier`.
- [ ] `ChallengeHandlingOptions` exposes `MinPollInterval` and `OnPoll`.
- [ ] `InteractionHandlingOptions` has full parity with `ChallengeHandlingOptions` for poller settings.
- [ ] `AAuthResourceOptions` and `AAuthAgentOptions` expose relevant subset.
- [ ] Clock injection works across all components (enables deterministic tests).
- [ ] Tests verify options threading (set non-default → assert inner component uses it).
- [ ] Existing tests unchanged (all defaults preserved).
- [ ] `docs/reference/configuration.md` updated with all new options.

---

## Phase 10: PS-Side Upstream Token Verification + Act Chain Utilities

**Goal:** Provide helpers for PS implementers to validate `upstream_token` per
§Upstream Token Verification, utilities to walk/extract the `act` delegation
chain, and multi-hop conformance tests proving end-to-end correctness.

### Files

| File | Action |
|------|--------|
| `src/AAuth/Tokens/UpstreamTokenValidator.cs` | **New** — validates upstream_token per spec 5-step process |
| `src/AAuth/Tokens/ActChainReader.cs` | **New** — utility to walk and extract the full delegation chain from nested `act` |
| `src/AAuth/Tokens/ActChainBuilder.cs` | **New** — PS-side helper to construct the nested `act` claim from a validated upstream token |
| `src/AAuth/Tokens/AuthTokenBuilder.cs` | **Modify** — add `BuildWithUpstreamAct(string upstreamToken)` convenience |
| `tests/AAuth.Conformance/AuthTokens/UpstreamTokenValidationTests.cs` | **New** — upstream token verification test cases |
| `tests/AAuth.Conformance/AuthTokens/ActChainReaderTests.cs` | **New** — multi-hop chain extraction tests |
| `tests/AAuth.Conformance/AuthTokens/ActChainBuilderTests.cs` | **New** — PS act-construction correctness tests |
| `tests/AAuth.Conformance/AuthTokens/MultiHopVerificationTests.cs` | **New** — end-to-end multi-hop token verification (resource-side) |

### `UpstreamTokenValidator` API

```csharp
public class UpstreamTokenValidator
{
    /// <summary>
    /// Validates an upstream_token per §Upstream Token Verification.
    /// Steps 1–3 are enforced; steps 4–5 (act construction, policy)
    /// are the caller's responsibility.
    /// </summary>
    public async Task<UpstreamTokenValidationResult> ValidateAsync(
        string upstreamToken,
        string expectedAudience,         // intermediary resource's own URL
        IReadOnlySet<string> trustedIssuers, // trusted ASes
        CancellationToken ct = default);
}

public record UpstreamTokenValidationResult
{
    public bool IsValid { get; init; }
    public string? Error { get; init; }
    public JsonObject? UpstreamAct { get; init; }  // ready to nest into downstream token
    public string? Issuer { get; init; }
    public string? Agent { get; init; }
    public string? Subject { get; init; }
}
```

### Validation Steps (per spec)

| Step | Spec Requirement | Implementation |
|------|-----------------|----------------|
| 1 | Auth Token Verification on upstream token | Delegate to existing `TokenVerifier.Verify()` |
| 2 | Verify `iss` is a trusted AS | Check against `trustedIssuers` set |
| 3 | Verify `aud` matches intermediary resource | Compare `aud` claim to `expectedAudience` |
| 4 | Construct nested `act` claim | Return `UpstreamAct` for caller to pass to `ActChainBuilder` or `AuthTokenBuilder` |
| 5 | Evaluate mission/governance policy | Out of scope (PS business logic) |

### `ActChainBuilder` API (PS-side)

```csharp
public static class ActChainBuilder
{
    /// <summary>
    /// Construct the nested act claim for a downstream auth token per
    /// §Upstream Token Verification step 4: wraps the upstream token's
    /// act inside a new act identifying the intermediary.
    /// </summary>
    /// <param name="intermediaryAgentId">The intermediary resource's agent identifier.</param>
    /// <param name="upstreamAct">The act claim from the validated upstream token.</param>
    /// <returns>A new JsonObject suitable for AuthTokenBuilder.Act.</returns>
    public static JsonObject BuildNestedAct(string intermediaryAgentId, JsonObject upstreamAct);

    /// <summary>
    /// Validate that a constructed act chain is semantically consistent:
    /// each level has a sub, nested levels don't exceed max depth.
    /// </summary>
    public static bool ValidateChain(JsonObject act, int maxDepth = 10);
}
```

### `ActChainReader` API

```csharp
public static class ActChainReader
{
    /// <summary>
    /// Extract the full delegation chain from a token's act claim.
    /// Returns agents in order from outermost (immediate caller) to
    /// innermost (original requester).
    /// </summary>
    public static IReadOnlyList<string> GetDelegationChain(JsonObject payload);

    /// <summary>Get the immediate actor (act.sub).</summary>
    public static string? GetImmediateActor(JsonObject payload);

    /// <summary>Get the original requester (innermost act.sub).</summary>
    public static string? GetOriginalActor(JsonObject payload);

    /// <summary>Get the chain depth (1 = direct, 2+ = chained).</summary>
    public static int GetChainDepth(JsonObject payload);
}
```

### Test Cases — UpstreamTokenValidator

| Test | Scenario | Expected |
|------|----------|----------|
| Valid upstream token | Correct iss, aud, act | `IsValid = true`, `UpstreamAct` populated |
| Untrusted issuer | `iss` not in trusted set | `IsValid = false`, error = "untrusted_issuer" |
| Audience mismatch | `aud` ≠ intermediary URL | `IsValid = false`, error = "audience_mismatch" |
| Missing act | No act claim in upstream | `IsValid = false`, error = "missing_act" |
| Expired upstream | `exp` in the past | `IsValid = false`, error from TokenVerifier |
| Invalid signature | Tampered payload | `IsValid = false`, error from TokenVerifier |

### Test Cases — ActChainBuilder (PS construction)

| Test | Scenario | Expected |
|------|----------|----------|
| Direct → 2-hop | Agent act + intermediary ID | `{ "sub": "intermediary", "act": { "sub": "agent" } }` |
| 2-hop → 3-hop | Nested act + new intermediary | `{ "sub": "r2", "act": { "sub": "r1", "act": { "sub": "agent" } } }` |
| Validate valid chain | Well-formed 3-level | `true` |
| Validate too deep | 11-level chain | `false` |
| Validate missing sub | act without sub field | `false` |

### Test Cases — Multi-Hop Resource-Side Verification

| Test | Scenario | Expected |
|------|----------|----------|
| 2-hop token accepted | Token with `act: { sub: "orch", act: { sub: "agent" } }` verified by downstream resource | Pass — `act.sub` = signer |
| 3-hop token accepted | Token with 3-level nested act, `act.sub` matches signer | Pass |
| act.sub mismatch rejected | Token's `act.sub` ≠ HTTP signer agent ID | Rejected |
| 10-level chain accepted | Maximum allowed depth | Pass |
| 11-level chain rejected | Exceeds max depth | Rejected |
| Valid chain with mixed issuers | Different PS/AS at each hop (realistic multi-org scenario) | Pass — resource only checks outermost act.sub |

### Test Cases — ActChainReader

| Test | Scenario | Expected |
|------|----------|----------|
| Valid 2-hop chain | Agent → Orchestrator → Resource | `["orchestrator-id", "agent-id"]` |
| Valid 3-hop chain | Agent → R1 → R2 → Resource | `["r2-id", "r1-id", "agent-id"]` |
| Direct (no nesting) | Single `act.sub` | `["agent-id"]` |
| GetOriginalActor 3-hop | 3-level chain | `"agent-id"` |
| GetChainDepth | Various depths | Correct integer |
| Depth exceeded | 11-level chain | Throws or returns error |

### Definition of Done

- [ ] `UpstreamTokenValidator.ValidateAsync` implements spec steps 1–3.
- [ ] Returns `UpstreamAct` ready for nesting into `AuthTokenBuilder`.
- [ ] `ActChainBuilder.BuildNestedAct` correctly wraps upstream act inside new intermediary act.
- [ ] `ActChainBuilder.ValidateChain` checks sub presence + depth.
- [ ] `ActChainReader.GetDelegationChain` walks full nested `act` chain.
- [ ] `ActChainReader.GetOriginalActor` returns innermost `act.sub`.
- [ ] Multi-hop resource-side verification tests pass (2-hop, 3-hop, 10-hop).
- [ ] Multi-hop PS construction tests pass (direct→2-hop, 2-hop→3-hop).
- [ ] Untrusted issuer and audience mismatch correctly rejected.
- [ ] Existing `TokenVerifier` depth logic reused (not duplicated).
- [ ] All new tests added to `AAuth.Conformance` project.

---

## Phase 12: Update Samples & Documentation

**Goal:** Update all sample applications and documentation to adopt the new SDK
APIs introduced in Phases 1–11, ensuring they serve as accurate living
references for consumers.

### Samples

#### Orchestrator (P0 — primary call-chaining reference)

| File | Change |
|------|--------|
| `samples/Orchestrator/Program.cs` | Replace manual agent-token challenge logic (~35 LOC) with `UseAAuthIntermediary()` |
| `samples/Orchestrator/Program.cs` | Replace manual 401→parse→exchange→retry loop (~25 LOC) with `WithCallChaining(ctx)` |
| `samples/Orchestrator/Program.cs` | Replace hand-coded `MapGet("/.well-known/aauth-agent.json")` with `MapAAuthAgentWellKnown()` |
| `samples/Orchestrator/Program.cs` | Use `UpstreamAuthTokenFeature` instead of manual `SignatureKeyParser` extraction |
| `samples/Orchestrator/Program.cs` | Add `AAuthVerificationOptions` Phase 11 fields (`MaxActDepth`, `ClockSkew`, `MaxFutureSkew`) |
| `samples/Orchestrator/README.md` | Update walkthrough to reflect simplified API |

**Estimated reduction:** ~72 LOC (20% of file)

#### MockPersonServer (P1 — PS-side helpers showcase)

| File | Change |
|------|--------|
| `samples/MockPersonServer/Program.cs` | Replace manual `upstream_token` validation (~50 LOC) with `UpstreamTokenValidator` |
| `samples/MockPersonServer/Program.cs` | Replace hand-coded `MapGet("/.well-known/aauth-person.json")` with `MapAAuthPersonServerWellKnown()` |
| `samples/MockPersonServer/Program.cs` | Optionally show `ActChainReader` for chain inspection |
| `samples/MockPersonServer/README.md` | Update to reference new helpers |

**Estimated reduction:** ~40 LOC

#### AgentConsole (P1 — call-chaining client demo)

| File | Change |
|------|--------|
| `samples/AgentConsole/Program.cs` | Wire `--upstream-token` CLI arg through `WithCallChaining(upstreamToken)` (currently parsed but unused) |
| `samples/AgentConsole/Program.cs` | Add `WithMissionForwarding()` when upstream token present |
| `samples/AgentConsole/Program.cs` | Add `OnPoll` callback for console progress output |
| `samples/AgentConsole/Program.cs` | Add `MinPollInterval` to `ChallengeHandlingOptions` |

#### SampleApp (P1 — Blazor call-chain page)

| File | Change |
|------|--------|
| `samples/SampleApp/Components/Pages/CallChain.razor` | Replace manual exchange flow with `.WithCallChaining(httpContext)` |
| `samples/SampleApp/Components/Pages/Deferred.razor` | Add `OnPoll` for progress UI feedback |

**Estimated reduction:** ~50 LOC in CallChain component

#### MockAgentProvider (P2 — metadata helper)

| File | Change |
|------|--------|
| `samples/MockAgentProvider/Program.cs` | Replace manual `MapGet("/.well-known/aauth-agent.json")` with `MapAAuthAgentWellKnown()` |

**Estimated reduction:** ~8 LOC

#### GuidedTour (P2 — educational snippets)

| File | Change |
|------|--------|
| `samples/GuidedTour/CodeSnippets.cs` | Update call-chain snippet to show `WithCallChaining()` convenience |
| `samples/GuidedTour/TourSession.cs` | Keep low-level manual steps (educational value) but add note about convenience alternative |

#### WhoAmI (P3 — minimal)

| File | Change |
|------|--------|
| `samples/WhoAmI/Program.cs` | Optionally add Phase 11 `AAuthVerificationOptions` fields to demonstrate tuning |

**Estimated change:** ~3 LOC (non-blocking, enhancement only)

### Documentation

#### High Priority

| File | Changes |
|------|---------|
| `docs/workflows/call-chaining.md` | Add `WithCallChaining()` section; add `UseAAuthIntermediary()` pattern; add `CallChainingRouter` helper; expand PS-side helpers subsection; add Phase 7 mission forwarding subsection; update code examples |
| `docs/reference/configuration.md` | Add Phase 11 settings tables (`MaxActDepth`, `ClockSkew`, `MaxFutureSkew`, `Clock`, `MinPollInterval`, `OnPoll`); add "Call Chaining Configuration" section; add "Metadata Endpoint Configuration" section |
| `docs/reference/dependency-injection.md` | Document `WithCallChaining()` overloads; document `WithMissionForwarding()`; add "Call Chaining DI Setup" section; expand `ChallengeHandlingOptions` / `InteractionHandlingOptions` tables |
| `docs/server/verification-middleware.md` | Document `MaxActDepth`, `ClockSkew`, `MaxFutureSkew`, `Clock` options; add "Call Chaining Verification" section showing `UpstreamAuthTokenFeature`; add nested act depth validation behavior |
| `docs/advanced/missions.md` | Add "Auto-Forwarding" section for Phase 7 `MissionForwardingHandler`; document mission propagation through intermediary chains; show `WithMissionForwarding()` registration |

#### Medium Priority

| File | Changes |
|------|---------|
| `docs/server/challenge-middleware.md` | Add note referencing `UseAAuthIntermediary()` as convenience alternative |
| `docs/server/resource-metadata.md` | Expand to reference all four `MapAAuth*WellKnown()` helpers |
| `docs/workflows/deferred-consent.md` | Expand `DeferredPollerOptions` table with `MinPollInterval`; document `OnPoll` callback |
| `docs/workflows/ps-asserted-access.md` | Update `ChallengeHandlingOptions` example with new fields |
| `docs/workflows/federated-access.md` | Verify polling options alignment; note clock skew config |
| `docs/signing-modes/overview.md` | Verify challenge handling description aligns with updated options |

#### Low Priority (informational only)

| File | Changes |
|------|---------|
| `docs/concepts.md` | Add `CallChainingRouter`, `UpstreamAuthTokenFeature` to API map |
| `docs/workflows/bootstrap-enrollment.md` | Add "See Also" link to clock/skew configuration |
| `samples/README.md` | Update samples table to note which demonstrate call-chaining |

### Definition of Done

- [ ] Orchestrator sample uses `UseAAuthIntermediary()` + `WithCallChaining(ctx)` — no manual exchange loop.
- [ ] Orchestrator sample uses `MapAAuthAgentWellKnown()` — no hand-coded JSON endpoint.
- [ ] MockPersonServer uses `UpstreamTokenValidator` + `MapAAuthPersonServerWellKnown()`.
- [ ] AgentConsole wires `--upstream-token` through `WithCallChaining()`.
- [ ] SampleApp CallChain.razor uses `WithCallChaining(httpContext)`.
- [ ] MockAgentProvider uses `MapAAuthAgentWellKnown()`.
- [ ] GuidedTour CodeSnippets updated with new convenience patterns.
- [ ] `docs/workflows/call-chaining.md` covers all new APIs with examples.
- [ ] `docs/reference/configuration.md` lists all Phase 11 settings.
- [ ] `docs/reference/dependency-injection.md` documents all new builder methods.
- [ ] `docs/server/verification-middleware.md` documents new verification options.
- [ ] `docs/advanced/missions.md` documents Phase 7 auto-forwarding.
- [ ] All code examples in docs compile (verified via GuidedTour or build).
- [ ] No sample references deprecated or removed API surfaces.

---

## Out of Scope

| Item | Reason |
|------|--------|
| Automatic 202 propagation middleware | High complexity; requires pending-URL store, background polling, response rewriting. Future work. |
| Four-party AS flow differences | Routing is identical; AS-specific behavior is handled by `TokenExchangeClient` metadata resolution. |
