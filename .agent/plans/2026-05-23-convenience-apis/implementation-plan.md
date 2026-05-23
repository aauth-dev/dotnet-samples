# Convenience APIs — Implementation Plan

## Overview

Add fluent builder methods and DI extensions so each AAuth workflow is
achievable in 3–5 lines. Low-level types remain available for advanced use.

## Pre-Phase: Spec Compliance Fix

**Goal**: Fix existing SDK violation before adding convenience APIs.

**Files**:

| File | Action |
|------|--------|
| `src/AAuth/Agent/DeferredPoller.cs` | Change `DefaultPollInterval` from 1s to 5s |
| `tests/AAuth.Tests/Agent/DeferredPollerTests.cs` | Update any tests asserting 1s default |

**Rationale**: Spec §Deferred Responses: "If a `Retry-After` header is not
present, the default polling interval is 5 seconds." Current value of 1s
violates a MUST-level requirement.

### Definition of Done

- [x] `DeferredPollerOptions.DefaultPollInterval` = 5 seconds.
- [x] Existing tests updated/passing.
- [x] No change to behavior when `Retry-After` is present (already correct).

---

## Phase 1: `WithChallengeHandling()` on `AAuthClientBuilder`

**Goal**: PS-asserted and federated flows in ~4 lines via the builder.

**Files**:

| File | Action |
|------|--------|
| `src/AAuth/HttpSig/AAuthClientBuilder.cs` | Add `WithChallengeHandling` overloads |
| `src/AAuth/HttpSig/ChallengeHandlingOptions.cs` | New — options record |
| `tests/AAuth.Tests/HttpSig/AAuthClientBuilderTests.cs` | Add 3-party builder tests |

**API Surface**:

```csharp
// Minimal (PS extracted from agent token):
new AAuthClientBuilder(key)
    .UseJwt(agentToken)
    .WithChallengeHandling()
    .Build();

// Explicit PS:
new AAuthClientBuilder(key)
    .UseJwt(agentToken)
    .WithChallengeHandling(personServer: "https://ps.example")
    .Build();

// With deferred-consent callback:
new AAuthClientBuilder(key)
    .UseJwt(agentToken)
    .WithChallengeHandling("https://ps.example", options =>
    {
        options.OnInteractionRequired = (interaction, ct) => ...;
        options.PollingTimeout = TimeSpan.FromMinutes(3);
    })
    .Build();

// With token refresh hook (custom implementation):
new AAuthClientBuilder(key)
    .UseJwt(agentToken)
    .WithChallengeHandling("https://ps.example")
    .WithTokenRefresh(myRefresher)        // ITokenRefresher
    .Build();

// With default AP refresher (just provide the refresh endpoint URL):
new AAuthClientBuilder(key)
    .UseJwt(agentToken)
    .WithChallengeHandling("https://ps.example")
    .WithTokenRefresh(refreshEndpoint: "https://ap.example/refresh")
    .Build();

// Or inline for custom logic:
new AAuthClientBuilder(key)
    .UseJwt(agentToken)
    .WithChallengeHandling("https://ps.example")
    .WithTokenRefresh(async (context, ct) =>
        await apClient.RefreshAsync($"{context.ApIssuer}/refresh", context.CurrentToken, context.KeyId, ct))
    .Build();
```

**Token refresh design**:

```csharp
/// <summary>
/// Consumer-implemented token refresh strategy. The SDK calls this when the
/// current token's exp claim is within the refresh threshold. The SDK takes
/// the returned token and updates the pipeline (AAuthTokenHolder) automatically.
/// </summary>
public interface ITokenRefresher
{
    Task<string> RefreshAsync(TokenRefreshContext context, CancellationToken ct);
}

/// <summary>
/// Context passed to the refresher — contains everything needed to refresh
/// without the consumer tracking AP details externally.
/// </summary>
public sealed record TokenRefreshContext
{
    /// <summary>The current (expiring) agent token.</summary>
    public required string CurrentToken { get; init; }

    /// <summary>AP issuer URL (extracted from the token's iss claim).</summary>
    public required string ApIssuer { get; init; }

    /// <summary>Agent identifier (extracted from the token's sub claim).</summary>
    public required string AgentId { get; init; }

    /// <summary>Key ID used for signing.</summary>
    public required string KeyId { get; init; }
}
```

- SDK checks `exp` before each request (configurable threshold, default 60s).
- If within threshold, SDK extracts `iss`, `sub`, `kid` from current token,
  builds `TokenRefreshContext`, calls `ITokenRefresher.RefreshAsync()`.
- SDK updates `AAuthTokenHolder` with the result.
- Concurrency: SDK uses a semaphore — only one refresh runs at a time;
  concurrent requests wait for the in-flight refresh.
- **Default implementation**: `AgentProviderRefresher` wraps the existing
  `AgentProviderClient.RefreshAsync()`. Consumer only provides the refresh
  endpoint URL. SDK has the key and key store from builder context — it
  constructs the signed refresh request internally.
- Refresh endpoint is NOT discoverable from AP metadata (spec says it's
  "AP-internal"). Must be provided explicitly.

**Spec note**: The bootstrap spec (§Refresh Patterns) describes refresh as
"informational guidance" — not normative. The refresh endpoint path (e.g.
`/refresh`) is AP-specific. The SDK's default refresher handles both two-key
(`jkt-jwt`) and single-key (`hwk`) refresh patterns based on how the builder
was configured.

**Internal wiring** (done by `Build()`):
1. Create `AAuthTokenHolder(agentToken)`.
2. Create exchange `HttpClient` with a signing handler pinned to the agent token.
3. Create `MetadataClient` + `TokenExchangeClient`.
4. Create `ChallengeHandler` wrapping the signing handler.
5. If `WithInteractionHandling()` also called, wire deferred-consent callback.

**Spec-mandated behavior**:
- Exchange pipeline MUST sign with agent token, never auth token (§PS-Asserted).
- PS `token_endpoint` discovered from `/.well-known/aauth-person.json` via
  `MetadataClient` (already implemented in `TokenExchangeClient`).
- When challenge handling is enabled, builder SHOULD auto-add
  `AAuth-Capabilities: auth-token` (signals to resources that 401 challenges
  are supported).

### Definition of Done

- [x] `WithChallengeHandling()` (no args) reads `ps` claim from agent token.
- [x] `WithChallengeHandling(string personServer)` uses explicit PS.
- [x] `WithChallengeHandling(string, Action<ChallengeHandlingOptions>)` supports callbacks.
- [x] `Build()` wires the full pipeline (exchange client, holder, challenge handler).
- [x] `WithTokenRefresh(ITokenRefresher)` and `WithTokenRefresh(Func)` overloads.
- [x] Refresh checks `exp` claim, uses semaphore for concurrency.
- [x] Unit tests verify handler chain order and option propagation.
- [x] Unit tests verify refresh is called when token nears expiry.
- [x] Existing builder tests still pass.

---

## Phase 2: `WithInteractionHandling()` for Resource-Managed and Deferred Flows

**Goal**: Handle `requirement=interaction` and `requirement=approval` (202
responses) automatically via the builder.

**Spec references**: §Requirement Responses, §Deferred Responses, §Approval
Pending.

**Files**:

| File | Action |
|------|--------|
| `src/AAuth/Agent/InteractionHandler.cs` | New — `DelegatingHandler` for 202 + interaction/approval |
| `src/AAuth/HttpSig/AAuthClientBuilder.cs` | Add `WithInteractionHandling` |
| `src/AAuth/HttpSig/InteractionHandlingOptions.cs` | New — options record |
| `tests/AAuth.Tests/HttpSig/AAuthClientBuilderTests.cs` | Add interaction tests |

**API Surface**:

```csharp
new AAuthClientBuilder(key)
    .UseHwk()
    .WithInteractionHandling(options =>
    {
        // Called for requirement=interaction (user must visit URL)
        options.OnInteractionRequired = (url, code, ct) => ShowUser(url, code);
        // Called for requirement=approval (no user URL, just waiting)
        options.OnApprovalPending = (ct) => LogWaitingForApproval();
        // Polling uses spec default of 5s unless Retry-After is present
    })
    .Build();
```

**Spec-mandated behavior**:
- On 202 + `requirement=interaction`: extract `url` and `code` params,
  construct `{url}?code={code}`, invoke callback, poll `Location`.
- On 202 + `requirement=approval`: invoke approval callback (no URL), poll
  `Location`. `Retry-After` MUST be present per spec.
- Default poll interval: 5s (from Pre-Phase fix).
- On 429: linear backoff (+5s per RFC 8628 §3.5).
- `Prefer: wait=N` sent on poll requests (opt-in).
- Agent SHOULD declare `AAuth-Capabilities: interaction` when this handler
  is attached (signals to servers that 202 responses are supported).

### Definition of Done

- [x] `InteractionHandler` intercepts 202 + `requirement=interaction`.
- [x] `InteractionHandler` intercepts 202 + `requirement=approval`.
- [x] Polls `Location` URL with signed GETs at spec-mandated intervals.
- [x] Respects `Retry-After` header; implements 429 linear backoff (+5s).
- [x] Builder auto-adds `AAuth-Capabilities: interaction` when handler is attached.
- [x] Tests with mock 202 → poll → 200 sequence for both interaction and approval.
- [x] Tests verify 429 backoff behavior.

---

## Phase 3: `AddAAuthAgent()` DI Extension

**Goal**: Register named AAuth agents with `IHttpClientFactory`.

**Files**:

| File | Action |
|------|--------|
| `src/AAuth/DependencyInjection/AAuthAgentOptions.cs` | New — options class |
| `src/AAuth/DependencyInjection/AAuthAgentServiceCollectionExtensions.cs` | New — `AddAAuthAgent` |
| `tests/AAuth.Tests/DependencyInjection/AAuthAgentDITests.cs` | New — DI tests |

**API Surface**:

```csharp
builder.Services.AddAAuthAgent("my-agent", options =>
{
    options.Key = key;
    options.AgentToken = agentToken;
    options.PersonServer = "https://ps.example";  // enables challenge handling
    options.OnInteractionRequired = ...;          // optional
});

// Inject:
public class MyService(IHttpClientFactory factory)
{
    private readonly HttpClient _client = factory.CreateClient("my-agent");
}
```

### Definition of Done

- [x] `AddAAuthAgent` registers named `HttpClient` with signing + challenge handlers.
- [x] Without `PersonServer`, registers signing-only client.
- [x] With `PersonServer`, registers full 3-party pipeline.
- [x] Tests resolve client from DI and verify handler chain.

---

## Phase 4: `AddAAuthResource()` + `UseAAuthVerification()` Server-Side DI

**Goal**: One-call server setup for resources.

**Files**:

| File | Action |
|------|--------|
| `src/AAuth/DependencyInjection/AAuthResourceOptions.cs` | New — options class |
| `src/AAuth/DependencyInjection/AAuthResourceServiceCollectionExtensions.cs` | New |
| `src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs` | New — `UseAAuthVerification` |
| `tests/AAuth.Tests/DependencyInjection/AAuthResourceDITests.cs` | New |

**API Surface**:

```csharp
builder.Services.AddAAuthResource(options =>
{
    options.Issuer = "https://resource.example";
    options.SigningKeys = [("kid1", key)];
    options.MaxSignatureAge = TimeSpan.FromSeconds(60);
    options.EnableReplayDetection = true;
});

app.UseAAuthVerification();
app.MapAAuthWellKnown();  // reads from registered options
```

### Definition of Done

- [x] `AddAAuthResource` registers `AAuthVerifier`, `DefaultSignatureKeyResolver`, `JwksClient`, `IJtiStore`.
- [x] `UseAAuthVerification()` adds middleware reading from DI.
- [x] `MapAAuthWellKnown()` maps metadata endpoints from options.
- [x] Tests verify DI registration and service resolution.

---

## Phase 5: `Bootstrap().EnrolAndBuildAsync()` Shorthand

**Goal**: One-shot AP enrol → ready-to-use client.

**Spec constraint**: AP metadata (`aauth-agent.json`) does NOT define an
`enrol_endpoint` field. Enrollment is "AP-internal" (§Bootstrap spec). The SDK
must take an explicit enrollment endpoint URL — it cannot be discovered from
metadata.

**Files**:

| File | Action |
|------|--------|
| `src/AAuth/HttpSig/AAuthClientBuilder.cs` | Add `Bootstrap` static method |
| `src/AAuth/HttpSig/BootstrapOptions.cs` | New — options record |
| `tests/AAuth.Tests/HttpSig/AAuthClientBuilderBootstrapTests.cs` | New |

**API Surface**:

```csharp
// Enrollment endpoint MUST be provided explicitly (not discoverable from metadata)
var (client, enrolResult) = await AAuthClientBuilder
    .Bootstrap(
        enrollEndpoint: "https://ap.example/enrol",
        agentId: "aauth:myagent@example.com")
    .WithPersonServer("https://ps.example")
    .WithChallengeHandling()
    .EnrolAndBuildAsync();
```

**Why not discover `enrol_endpoint`?** The AAuth spec deliberately leaves
enrollment as an AP-internal concern. Different APs may use different
mechanisms (platform attestation, OAuth redirect, manual provisioning). The
SDK accepts the endpoint as given.

### Definition of Done

- [x] `Bootstrap(enrollEndpoint, agentId)` takes explicit endpoint (not metadata-discovered).
- [x] Enrols, returns builder + `EnrolResult` with key and agent token.
- [x] Supports `IKeyStore` override (defaults to `InMemoryKeyStore`).
- [x] Supports `IPlatformAttestor` override.
- [x] Configuration tests for bootstrap builder.

---

## Phase 6: `AddAAuthDiscovery()` Shared Clients

**Goal**: Shared singleton `MetadataClient` + `JwksClient` in DI.

**Spec compliance note**: `JwksClient` already meets spec requirements:
- Rate-limits to 1 fetch/min per `jwks_uri` (spec: "no more than once per minute").
- Refreshes on unknown `kid` (spec: "SHOULD refresh on unknown kid").
- Default cache TTL is 1 hour; max configurable.
No changes needed to `JwksClient` internals — only DI registration.

**Files**:

| File | Action |
|------|--------|
| `src/AAuth/DependencyInjection/AAuthDiscoveryServiceCollectionExtensions.cs` | New |
| `src/AAuth/DependencyInjection/AAuthDiscoveryOptions.cs` | New |
| `tests/AAuth.Tests/DependencyInjection/AAuthDiscoveryDITests.cs` | New |

**API Surface**:

```csharp
builder.Services.AddAAuthDiscovery(options =>
{
    options.MetadataCacheTtl = TimeSpan.FromMinutes(5);
    options.JwksCacheTtl = TimeSpan.FromHours(1);
    options.JwksMinRefreshInterval = TimeSpan.FromMinutes(1); // spec minimum
});
```

### Definition of Done

- [x] Registers `MetadataClient` and `JwksClient` as singletons.
- [x] Other DI extensions (`AddAAuthAgent`, `AddAAuthResource`) consume them if registered.
- [x] Tests verify shared instance across multiple agent registrations.
- [x] Default `JwksMinRefreshInterval` remains 1 minute (spec requirement).

---

## Phase 7: Update Samples to Use Convenience APIs

**Goal**: Refactor `AgentConsole` and `GuidedTour` to demonstrate the new
fluent/DI APIs, serving as living documentation.

**Files**:

| File | Action |
|------|--------|
| `samples/AgentConsole/Program.cs` | Replace manual handler wiring with `AAuthClientBuilder` + `WithChallengeHandling()` |
| `samples/GuidedTour/TourSession.cs` | Use `AAuthClientBuilder` for pipeline construction |
| `samples/GuidedTour/Program.cs` | Use `AddAAuthAgent()` DI registration if applicable |
| `docs/getting-started.md` | Update three-party example to use new builder API |
| `README.md` | Update Quick Start three-party example |

**AgentConsole refactor** (before → after):

```csharp
// Before (~20 lines of manual handler construction)
var signingHandler = new AAuthSigningHandler(key, BuildProvider(...)) { InnerHandler = ... };
var exchangeHttp = new HttpClient(BuildSigningPipeline(() => agentToken));
var exchange = new TokenExchangeClient(exchangeHttp, metadata);
var pipeline = new ChallengeHandler(exchange, tokenHolder, personServer) { InnerHandler = ... };
using var client = new HttpClient(pipeline);

// After (~4 lines)
using var client = new AAuthClientBuilder(key)
    .UseJwt(agentToken)
    .WithChallengeHandling(personServer)
    .Build();
```

**GuidedTour refactor**:
- Replace manual `DelegatingHandler` chain with builder.
- If using DI, switch to `AddAAuthAgent("tour-agent", opts => ...)`.
- Keep the `CapturingMessageHandler` observation hook via
  `OnSignatureBase()` or `WithInnerHandler()`.

### Definition of Done

- [ ] `AgentConsole/Program.cs` uses `AAuthClientBuilder.WithChallengeHandling()`.
- [ ] `GuidedTour` uses builder or DI extension for pipeline construction.
- [ ] `make demo` still works end-to-end (WhoAmI + MockPS + GuidedTour).
- [ ] README and getting-started examples match the new API.
- [ ] All 333 tests still pass.

---

## Phase 8: Update Documentation

**Goal**: Update all docs to show convenience APIs as primary examples, with
low-level wiring as "Advanced" alternative where applicable.

**Files**:

| File | Update Needed |
|------|---------------|
| `docs/workflows/ps-asserted-access.md` | Replace manual ChallengeHandler wiring with `WithChallengeHandling()` |
| `docs/workflows/federated-access.md` | Same as ps-asserted |
| `docs/workflows/resource-managed-access.md` | Add `WithInteractionHandling()` example |
| `docs/workflows/deferred-consent.md` | Show builder with interaction callback |
| `docs/workflows/bootstrap-enrollment.md` | Show `Bootstrap().EnrolAndBuildAsync()` |
| `docs/workflows/identity-based-access.md` | Verify uses builder (may already be fine) |
| `docs/signing-modes/overview.md` | Add builder equivalents alongside raw provider construction |
| `docs/signing-modes/pseudonymous-hwk.md` | Add `AAuthClientBuilder.UseHwk()` as primary |
| `docs/signing-modes/agent-identity-jwks-uri.md` | Add `AAuthClientBuilder.UseJwksUri()` as primary |
| `docs/signing-modes/agent-token-jwt.md` | Add `AAuthClientBuilder.UseJwt()` as primary |
| `docs/signing-modes/key-rotation-jkt-jwt.md` | Add `AAuthClientBuilder.UseJktJwt()` as primary |
| `docs/server/verification-middleware.md` | Show `UseAAuthVerification()` DI extension |
| `docs/server/resource-metadata.md` | Show `AddAAuthResource()` registration |
| `docs/server/replay-detection.md` | Show DI registration of `IJtiStore` via `AddAAuthResource` |
| `docs/server/multi-scheme-verification.md` | Show resolver config via `AddAAuthResource` options |
| `docs/advanced/key-management.md` | Show `IKeyStore` DI registration |
| `docs/advanced/platform-attestation.md` | Show attestor in `Bootstrap()` options |
| `docs/reference/configuration.md` | Add DI options reference alongside constructor docs |
| `docs/getting-started.md` | Update three-party example (from Phase 7) |
| `README.md` | Update Quick Start (from Phase 7) |

**Not updated** (no convenience API applicable):
- `docs/concepts.md` — conceptual, no code
- `docs/advanced/error-handling.md` — error patterns, not construction
- `docs/advanced/missions.md` — mission types are standalone, no builder needed
- `docs/server/token-issuance.md` — token builders already have good init-only pattern

### Definition of Done

- [ ] Each signing-modes doc shows builder API as primary, raw construction as "Manual Setup".
- [ ] Each workflow doc shows convenience API as primary code example.
- [ ] Server docs show DI extension as primary, manual middleware as "Advanced".
- [ ] `docs/reference/configuration.md` includes DI options alongside constructor params.
- [ ] Examples compile (verified by inclusion in a test or doc-test project).

---

## Out of Scope

| Item | Reason |
|------|--------|
| Token builder fluent extensions | Already use init-only properties — pattern is good |
| `AAuthTokenHolder` DI lifecycle | Too workflow-specific; builder creates internally |
| Multi-tenant agent management | Beyond SDK scope — application concern |
| Background token refresh timer | Consumer owns refresh logic via `ITokenRefresher`; SDK provides the hook, not the scheduler |
