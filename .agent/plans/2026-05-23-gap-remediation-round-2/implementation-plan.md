# Gap Remediation Round 2 – Implementation Plan

> **Created:** 2026-05-23
> **Validated against code:** 2026-05-23
> **Re-validated:** 2026-05-25 (all 12 gaps confirmed active; spec deep-read refinements added; interaction chaining added as Gap 12)
> **Gaps document:** [gaps.md](gaps.md)
> **Research:** [research.md](research.md)

---

## Phase 1: Integrated Verification Middleware (Gaps 1–2)

**Goal:** Create a higher-level middleware (or opt-in mode) that performs BOTH HTTP signature PoP verification AND JWT issuer signature verification in a single pass. This closes the critical gap where the existing middleware only verifies PoP.

**Architectural note:** The current `AAuthVerificationMiddleware` is intentionally "policy-free" — it verifies HTTP signatures and projects parsed info. The new middleware layers on top (or replaces it with an opt-in flag) to also verify the JWT signature against the issuer's JWKS.

### Files to create/modify

| File | Change |
|------|--------|
| `src/AAuth/Server/AAuthFullVerificationMiddleware.cs` | **New** — chains HTTP sig + JWT issuer verification |
| `src/AAuth/Server/FullVerificationOptions.cs` | **New** — configuration (trusted issuers, audience, etc.) |
| `src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs` | Add `UseAAuthFullVerification()` extension |
| `src/AAuth/Tokens/TokenVerifier.cs` | Extract issuer-verification into reusable helper |

### Implementation steps

1. Create `FullVerificationOptions`:
   - `TrustedAgentProviderIssuers` (optional allow-list; if null, any resolvable issuer accepted)
   - `TrustedPersonServerIssuers` (optional allow-list for auth token issuers)
   - `ResourceIdentifier` (this resource's identifier — for `aud` validation on auth tokens)
   - `RequireIssuerVerification` (default: `true`)
2. Create `AAuthFullVerificationMiddleware`:
   - Step 1: Parse `Signature-Key` header (reuses `SignatureKeyParser.ParseAny()`)
   - Step 2: Resolve public key (reuses `ISignatureKeyResolver`)
   - Step 3: Verify HTTP signature (reuses `AAuthVerifier.Verify()`)
   - Step 4: **NEW** — detect token type from `typ` claim in parsed payload
   - Step 5: **NEW** — for `aa-agent+jwt`: call `TokenVerifier.VerifyWithJwksAsync()` to verify JWT signature against AP JWKS
   - Step 6: **NEW** — for `aa-auth+jwt`: call `TokenVerifier.VerifyAuthTokenWithJwksAsync()` to verify against PS JWKS + validate aud + verify PoP binding
   - Step 7: Store verified result in `HttpContext.Items` / `HttpContext.Features`
3. Handle caching: JWKS fetched via existing `JwksClient` (already has TTL cache)
4. Handle errors: return 401 with `Signature-Error` header and appropriate code (`invalid_jwt`, `unknown_key`)

### Implementation Decisions (2026-05-25)

> Added after deep spec read — these pin design choices before coding begins.

- **Token type dispatch:** Use `typ` JWT header claim (`aa-agent+jwt` / `aa-auth+jwt`) for routing verification logic. See research.md §8.7 for the full `typ`→`dwk` mapping.
- **`act` claim enforcement:** Spec requires `act` in ALL auth tokens (not just call-chaining). The middleware should reject auth tokens missing `act.sub`. `AuthTokenBuilder` should also emit `act: { sub: <agent> }` always.
- **Covered components for RFC 9421:** `@method`, `@authority`, `@path`, `signature-key` (matches current SDK — no change needed).
- **JWKS resolution reuse:** The middleware reuses existing `JwksClient` (already has TTL caching + rate limiting). No new HTTP client needed.
- **`dwk`→well-known URL mapping:** `aauth-agent.json` → AP, `aauth-person.json` → PS, `aauth-access.json` → AS. Construct base URL from `iss` claim.

### Definition of Done

- [x] `aa-agent+jwt` signature verified against AP JWKS before PoP is trusted
- [x] `aa-auth+jwt` signature verified against PS/AS JWKS + `aud` validated
- [x] Auth token `act.sub` validated (reject if missing)
- [x] `AuthTokenBuilder` emits `act: { sub: agent }` by default
- [x] Forged token with valid PoP but unknown/untrusted issuer → 401 `invalid_jwt`
- [x] `TrustedIssuers` allow-list restricts accepted issuers when configured
- [x] Existing `AAuthVerificationMiddleware` unchanged (non-breaking)
- [x] Unit tests: forged token rejected, valid token accepted, missing act rejected
- [x] Integration test: end-to-end with MockPersonServer

---

## Phase 2: Auto-Challenge Middleware + Access Mode (Gaps 3–4)

**Goal:** Reusable middleware that automatically issues 401 challenges with resource tokens when the resource requires an auth token but only an agent token is presented. Configurable per-resource access mode.

**Existing building blocks:**
- `ResourceTokenBuilder` — FULLY implemented, builds valid `aa-resource+jwt`
- `ChallengeHandler` (agent-side) — already handles 401 + resource token extraction + retry
- WhoAmI sample — demonstrates the complete pattern manually

### Files to create/modify

| File | Change |
|------|--------|
| `src/AAuth/Server/AAuthChallengeMiddleware.cs` | **New** — auto-challenge when auth token required |
| `src/AAuth/Server/AAuthAccessMode.cs` | **New** — enum: `IdentityOnly`, `RequireAuthToken` |
| `src/AAuth/Server/ChallengeOptions.cs` | **New** — resource signing key, scopes, mode |
| `src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs` | Add `UseAAuthChallenge()` extension |

### Implementation steps

1. Create `AAuthAccessMode` enum: `IdentityOnly` | `RequireAuthToken`
2. Create `ChallengeOptions`:
   - `AccessMode` (default: `IdentityOnly` — no challenge)
   - `ResourceSigningKey` + `ResourceKeyId`
   - `ResourceIdentifier` (issuer claim)
   - `PersonServerAudience` (audience claim)
   - `DefaultScopes` (scopes to include in resource token)
   - `AllowedSignatureKeySchemes` (optional filter)
3. Create `AAuthChallengeMiddleware`:
   - Runs AFTER `AAuthFullVerificationMiddleware`
   - If `AccessMode == RequireAuthToken` AND verified token type is `aa-agent+jwt`:
     - Extract `agent` and `agent_jkt` from verified claims
     - Resolve audience for resource token (see §8.2 in research.md):
       - If resource has own AS → `aud` = AS URL
       - Else if agent token contains `ps` claim → `aud` = PS URL
       - Else → resource handles authorization itself (no challenge needed)
     - Mint `aa-resource+jwt` via `ResourceTokenBuilder`
     - Return 401 with `AAuth-Requirement: requirement=auth-token; resource-token="<jwt>"`
   - If `aa-auth+jwt` is present → pass through
   - If `AccessMode == IdentityOnly` → pass through regardless of token type
4. Scheme filtering: reject disallowed schemes with 401 early

### Definition of Done

- [x] Resource returns 401 + `AAuth-Requirement` header with valid `aa-resource+jwt`
- [x] `IdentityOnly` mode passes through after identity verification
- [x] `RequireAuthToken` mode challenges when only agent token present
- [x] Agent-side `ChallengeHandler` successfully retries after challenge
- [x] `AllowedSignatureKeySchemes` rejects unlisted schemes
- [x] Unit tests: challenge issued, identity-only passthrough
- [x] Integration test: full challenge → exchange → retry flow

---

## Phase 3: Authorization Integration (Gaps 5–6)

**Goal:** Typed verification result + ASP.NET authorization policies so AAuth claims are consumable by standard .NET authorization patterns.

**Existing building blocks:**
- `ParsedSignatureKeyInfo` already in `HttpContext.Items` (raw data available)
- `TokenVerifier.VerifyAuthToken()` already validates scope narrowing

### Files to create/modify

| File | Change |
|------|--------|
| `src/AAuth/Server/AAuthVerificationResult.cs` | **New** — typed verification result |
| `src/AAuth/Server/AAuthLevel.cs` | **New** — enum: Pseudonymous, Identified, Authorized |
| `src/AAuth/Server/AAuthAuthenticationHandler.cs` | **New** — maps result to ClaimsPrincipal |
| `src/AAuth/Server/AAuthScopeRequirement.cs` | **New** — IAuthorizationRequirement for scopes |
| `src/AAuth/Server/AAuthScopeHandler.cs` | **New** — IAuthorizationHandler checking scope |
| `src/AAuth/DependencyInjection/AAuthResourceServiceCollectionExtensions.cs` | Register auth services |

### Implementation steps

1. Create `AAuthVerificationResult`:
   ```csharp
   public sealed class AAuthVerificationResult
   {
       public AAuthLevel Level { get; init; }
       public string Scheme { get; init; }
       public string? TokenType { get; init; }
       public string? Issuer { get; init; }
       public string? Agent { get; init; }
       public string? Subject { get; init; }
       public IReadOnlySet<string> Scopes { get; init; }
       public string? ActorSubject { get; init; }
       public string? Jkt { get; init; }
   }
   ```
2. Populate `AAuthVerificationResult` after Phase 1 middleware verification
3. Create `AAuthAuthenticationHandler` (implements `IAuthenticationHandler`):
   - Reads `AAuthVerificationResult` from `HttpContext.Features`
   - Creates `ClaimsPrincipal` with mapped claims
4. Create scope-based authorization:
   - `[RequireAAuthScope("data:read")]` → `AAuthScopeRequirement` + `AAuthScopeHandler`
   - Handler reads verified scopes from result, checks subset relationship
5. Register: `services.AddAAuthAuthentication()` + `services.AddAAuthAuthorization()`

### Definition of Done

- [x] `AAuthVerificationResult` stored in `HttpContext.Features` after verification
- [x] `HttpContext.User` populated with AAuth claims
- [x] `[Authorize(Policy = "AAuth.Authorized")]` requires auth-token level
- [x] `[RequireAAuthScope("x")]` rejects requests without scope (403)
- [x] Standard `User.HasClaim()` works with AAuth claims
- [x] Unit tests for each authorization requirement

---

## Phase 4: jkt-jwt + ECDSA Pipeline (Gaps 9–10)

**Goal:** Complete the jkt-jwt naming JWT signature verification (currently has a TODO) and wire ECDSA P-256 through the pipeline.

**Existing building blocks:**
- `DefaultSignatureKeyResolver.ResolveJktJwt()` — validates structural binding (jkt ↔ cnf.jwk) but skips JWT signature verification
- `EcdsaAAuthKey` — full P-256/ES256 implementation exists
- `IAAuthKey` interface — algorithm abstraction ready
- `JwksClient` — has explicit skip comment for non-Ed25519 keys

### Files to modify

| File | Change |
|------|--------|
| `src/AAuth/HttpSig/DefaultSignatureKeyResolver.cs` | Add naming JWT signature verification in `ResolveJktJwt()` |
| `src/AAuth/Discovery/JwksClient.cs` | Dispatch on `kty`/`crv` to handle EC/P-256 keys |
| `src/AAuth/Tokens/TokenVerifier.cs` | Dispatch on `alg` claim (EdDSA → AAuthKey, ES256 → EcdsaAAuthKey) |
| `src/AAuth/HttpSig/AAuthVerifier.cs` | Accept `IAAuthKey` for multi-algorithm sig verification |
| `src/AAuth/Crypto/KeyFactory.cs` | **New** — factory creating IAAuthKey from JWK based on kty/crv |

### Implementation steps

1. **jkt-jwt fix:** In `ResolveJktJwt()` (see research.md §8.6 for spec detail):
   - Read `iss` from naming JWT payload
   - Fetch `{iss}/.well-known/aauth-agent.json` → extract `jwks_uri`
   - Fetch JWKS → find durable key (by `kid` from naming JWT header)
   - Verify naming JWT signature (`typ: jkt-s256+jwt`) against durable key
   - Only then trust the delegation to ephemeral key (cnf.jwk)
2. **KeyFactory:** Create `IAAuthKey FromJwk(JsonObject jwk)` that dispatches:
   - `kty=OKP, crv=Ed25519` → `AAuthKey.FromJwk()`
   - `kty=EC, crv=P-256` → `EcdsaAAuthKey.FromJwk()`
   - Unknown → throw
3. **JwksClient:** Replace Ed25519-only filter with `KeyFactory.FromJwk()` call
4. **TokenVerifier:** Replace `if (alg != AAuthKey.Algorithm)` with multi-algorithm dispatch
5. **AAuthVerifier:** Verify signature using `IAAuthKey.Verify()` (check if interface already covers this)

### Definition of Done

- [x] jkt-jwt naming JWT signature verified against issuer JWKS
- [x] Forged jkt-jwt naming JWT rejected
- [x] `JwksClient` resolves both Ed25519 and P-256 keys from JWKS documents
- [x] `TokenVerifier` accepts both EdDSA and ES256 tokens
- [x] HTTP signature verification works with P-256 keys
- [x] Existing Ed25519 flows unaffected (backward compatible)
- [x] Unit tests: ES256 key round-trip, mixed JWKS, jkt-jwt verification

---

## Phase 5: Call Chaining (Gap 11)

**Goal:** Enable resources to act as agents for downstream resource access (multi-hop delegation).

**Existing building blocks:**
- `TokenVerifier` validates nested `act` claims (max depth 10)
- `TokenExchangeClient` handles token exchange (needs `upstream_token` parameter)

### Files to create/modify

| File | Change |
|------|--------|
| `src/AAuth/Agent/TokenExchangeClient.cs` | Add `upstream_token` parameter to exchange |
| `src/AAuth/Server/CallChainingHandler.cs` | **New** — DelegatingHandler for resource-as-agent |
| `src/AAuth/Server/CallChainingOptions.cs` | **New** — downstream resource config |

### Implementation steps

1. Extend `TokenExchangeClient.ExchangeAsync()` with optional `upstreamToken` parameter:
   - When provided, include `upstream_token` in POST body alongside `resource_token`
2. Create `CallChainingHandler` (DelegatingHandler):
   - Extracts incoming auth token from current request context
   - Routes downstream token request based on upstream auth token (see research.md §8.5):
     - `mission.approver` present → PS at approver URL
     - No mission, `iss` is PS → PS at `iss` URL
     - No mission, `iss` is AS → AS at `iss` URL
   - Signs downstream requests with resource's own agent identity
3. Create `CallChainingOptions`:
   - `DownstreamResources` — map of resource identifiers to PS endpoints
   - Resource's own agent key + agent token (for signing downstream requests)
4. Resource-as-agent metadata: support publishing `/.well-known/aauth-agent.json` alongside `aauth-resource.json`

### Definition of Done

- [x] `upstream_token` parameter sent in token exchange when provided
- [x] Resource can request auth tokens for downstream resources
- [x] Downstream auth tokens contain nested `act` chain (caller → resource → downstream)
- [x] `TokenVerifier` validates the chained `act` claims correctly
- [x] Unit tests: upstream_token exchange, act chain construction
- [x] Integration test: Agent → Resource 1 → Resource 2 flow

---

## Phase 6: DX and Observability (Gaps 7–8)

**Goal:** Prefer: wait=N long-poll support and OpenTelemetry trace enrichment.

### Files to modify

| File | Change |
|------|--------|
| `src/AAuth/Agent/DeferredPoller.cs` | Add `Prefer: wait=N` header when configured |
| `src/AAuth/Agent/DeferredPollerOptions.cs` | Add `PreferWaitSeconds` option |
| `src/AAuth/Server/AAuthFullVerificationMiddleware.cs` | Add Activity tags |
| `src/AAuth/Agent/ChallengeHandler.cs` | Create child span |
| `src/AAuth/Agent/TokenExchangeClient.cs` | Create child span |

### Implementation steps

1. **Prefer: wait=N:**
   - Add `PreferWaitSeconds` to `DeferredPollerOptions` (default: `null` = disabled)
   - When set, add `Prefer: wait={N}` header on poll requests
2. **OpenTelemetry:**
   - Create `AAuthDiagnostics` static class with `ActivitySource`
   - Server middleware: set tags on `Activity.Current` after verification (`aauth.scheme`, `aauth.level`, `aauth.agent`, `aauth.scope`)
   - Client: wrap challenge retry, token exchange, polling in child activities
   - No hard dependency on OTel SDK — pure `System.Diagnostics`

### Definition of Done

- [x] `Prefer: wait=30` sent on poll requests when configured
- [x] Activity tags populated after server-side verification
- [x] Client spans created for token exchange and polling
- [x] No external OTel package dependency
- [x] Smoke test: verify Activity tags present

---

## Phase 7: Samples and Documentation Updates (All Gaps)

**Goal:** Update the three sample applications and documentation to reflect all new SDK features from Phases 1–6. Samples become the canonical demonstration of gap remediation features; docs become the authoritative reference.

### Scope Summary

| Target | Role | Primary Gaps Affected |
|--------|------|----------------------|
| `samples/GuidedTour/` | Agent-side educational walkthrough | 9 (jkt-jwt mode), 10 (ECDSA), 11 (call chaining), 7 (Prefer) |
| `samples/AgentConsole/` | CLI agent client | 9 (jkt-jwt mode), 7 (Prefer), 11 (upstream_token) |
| `samples/SampleApp/` | Blazor app (agent + mini resource) | 1–6 (server-side demos), 7–8 (polling + OTel), 9–10 (ECDSA) |
| `docs/` | Reference documentation | All gaps |

---

### 7A. GuidedTour Updates

**Context:** Agent-side tour showing protocol flows. Server-side features (Gaps 1–6) do NOT apply directly — those are demonstrated by WhoAmI/SampleApp.

| File | Change | Gap |
|------|--------|-----|
| `samples/GuidedTour/TourSession.cs` | Add `jkt-jwt` case in `BuildSigningHandler()` | 9 |
| `samples/GuidedTour/TourSession.cs` | Update `StepPollPendingAsync()` to send `Prefer: wait=N` | 7 |
| `samples/GuidedTour/CodeSnippets.cs` | Add `SignedGetJktJwt` snippet | 9 |
| `samples/GuidedTour/CodeSnippets.cs` | Update polling snippet to show Prefer header | 7 |
| `samples/GuidedTour/TourOptions.cs` | Add optional `KeyType` enum (Ed25519/P-256) | 10 |
| `samples/GuidedTour/TourSession.cs` | Optional: ECDSA P-256 key generation in bootstrap step | 10 |

**Not changing:** Protocol flow structure, existing signing mode demos, server-side patterns.

---

### 7B. AgentConsole Updates

**Context:** CLI agent tool. Purely client-side — no middleware needed.

| File | Change | Gap |
|------|--------|-----|
| `samples/AgentConsole/Program.cs` | Add `--signing-mode jkt-jwt` option + builder case | 9 |
| `samples/AgentConsole/Program.cs` | Add `--prefer-wait <seconds>` flag for deferred polling | 7 |
| `samples/AgentConsole/Program.cs` | Add `--upstream-token <jwt>` flag for call chaining demo | 11 |

**Not changing:** Core enrollment logic, existing signing modes, ChallengeHandler integration.

---

### 7C. SampleApp Updates

**Context:** Blazor Server app — currently agent-only. Extend to also demonstrate server-side features by adding a mini resource endpoint.

| File | Change | Gap |
|------|--------|-----|
| `samples/SampleApp/Program.cs` | Add middleware stack: `UseAAuthFullVerification()` + `UseAAuthChallenge()` + auth policies | 1–6 |
| `samples/SampleApp/ResourceEndpoints.cs` | **New** — mini resource server demonstrating full verification + challenge + authorization | 1–4, 5–6 |
| `samples/SampleApp/Components/Pages/FullVerification.razor` | **New** — demonstrates JWT issuer verification middleware | 1–2 |
| `samples/SampleApp/Components/Pages/ScopeAuthorization.razor` | **New** — demonstrates `[Authorize]` + scope policies | 5–6 |
| `samples/SampleApp/Components/Pages/AdvancedFeatures.razor` | **New** — tabs for jkt-jwt, ECDSA, call chaining, OTel | 7–11 |
| `samples/SampleApp/Components/Pages/Deferred.razor` | Update to use `PreferWait` option on poller | 7 |
| `samples/SampleApp/EnrollmentService.cs` | Add optional ECDSA key generation path | 10 |
| `samples/SampleApp/Components/Layout/NavMenu.razor` | Add navigation for new pages | — |

---

### 7D. Documentation Updates

#### New Files to Create

| File | Purpose | Gap |
|------|---------|-----|
| `docs/server/full-verification-middleware.md` | Replaces/extends current verification-middleware.md — documents JWT issuer verification | 1–2 |
| `docs/server/challenge-middleware.md` | Auto-challenge via `UseAAuthChallenge()` + `AAuthAccessMode` | 3–4 |
| `docs/server/authentication-handler.md` | `AAuthAuthenticationHandler`, `AAuthVerificationResult`, `AAuthLevel` | 5–6 |
| `docs/server/authorization-policies.md` | `AAuthScopeRequirement`/`AAuthScopeHandler`, `[Authorize]` integration | 5–6 |
| `docs/workflows/call-chaining.md` | Multi-hop delegation with `upstream_token` + `act` claim | 11 |
| `docs/advanced/observability.md` | OpenTelemetry Activity tags + `AAuthDiagnostics` | 8 |

#### Existing Files to Update

| File | Change | Gap |
|------|--------|-----|
| `docs/server/verification-middleware.md` | Add migration note pointing to full-verification-middleware.md | 1–2 |
| `docs/server/token-issuance.md` | Document `act` claim as required for auth tokens in `AuthTokenBuilder` | 1–2 |
| `docs/server/multi-scheme-verification.md` | Note ECDSA P-256 support in key resolution | 9–10 |
| `docs/signing-modes/key-rotation-jkt-jwt.md` | Note P-256 keys supported for naming JWT delegation | 9–10 |
| `docs/advanced/key-management.md` | Add ECDSA (P-256) section alongside Ed25519 | 10 |
| `docs/workflows/deferred-consent.md` | Document `PreferWait` option in `DeferredPollerOptions` | 7 |
| `docs/workflows/resource-managed-access.md` | Document `Prefer: wait=N` server-side behavior | 7 |
| `docs/workflows/identity-based-access.md` | Update server-side to use new middleware APIs | 3–4 |
| `docs/workflows/ps-asserted-access.md` | Update challenge section to reference auto-challenge middleware | 3–4 |
| `docs/reference/configuration.md` | Add sections for all new middleware/handler options | 1–8 |
| `docs/reference/dependency-injection.md` | Add registration examples for new services | 1–6 |
| `docs/concepts.md` | Add `act` claim, auth levels, call chaining concepts | 1–2, 5–6, 11 |
| `docs/README.md` | Update API map with new types; link new doc pages | All |

---

### Definition of Done

- [ ] GuidedTour: jkt-jwt signing mode selectable and demonstrated
- [ ] AgentConsole: `--signing-mode jkt-jwt` works end-to-end
- [ ] SampleApp: mini resource endpoint demonstrates full verification + challenge + authorization
- [ ] SampleApp: new Blazor pages render and demonstrate each gap feature
- [ ] All new doc files created with correct structure and code examples
- [ ] Existing docs updated to reference new middleware APIs
- [ ] `docs/README.md` API map covers all new public types
- [ ] Code examples in docs compile against updated SDK
- [ ] Sample README.md files updated where applicable

---

## Phase 8: Interaction Chaining (Gap 12)

**Goal:** Enable consent requirements from downstream resources to propagate back through the call chain to the original agent (where the user is), so the user can approve downstream access requests.

**Spec reference:** §Interaction Chaining — MUST-level requirement for resources acting as agents.

**Scenario:** Agent A → Resource B → Resource C → PS returns `202 interaction` — consent bubbles back to Agent A.

### Existing building blocks

- `DeferredPoller` — resource can poll downstream PS after consent
- `AAuthInteraction` — parse and format interaction requirements
- `TokenExchangeClient.onInteractionRequired` — callback receives downstream 202
- `CallChainingHandler` — routes downstream token requests (currently throws on 202)
- `InMemoryJtiStore` pattern — ConcurrentDictionary reusable for pending store

### Files to create/modify

| File | Change |
|------|--------|
| `src/AAuth/Server/IPendingRequestStore.cs` | **New** — interface for parking requests awaiting downstream consent |
| `src/AAuth/Server/InMemoryPendingRequestStore.cs` | **New** — in-memory implementation with TTL expiry |
| `src/AAuth/Server/PendingRequest.cs` | **New** — model: id, downstream interaction, completion state, result |
| `src/AAuth/Server/InteractionChainingMiddleware.cs` | **New** — middleware that exposes `/aauth/pending/{id}` poll + `/aauth/interaction/{id}` proxy |
| `src/AAuth/Server/CallChainingHandler.cs` | Modify — accept `onInteractionRequired` callback; propagate 202 |
| `src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs` | Add `UseAAuthInteractionChaining()` extension |

### Implementation steps

1. **Define `IPendingRequestStore`:**
   - `CreateAsync(downstreamInteraction, originalRequestContext)` → returns pending ID
   - `GetAsync(id)` → returns status + result when complete
   - `CompleteAsync(id, result)` — called when downstream auth token obtained and request fulfilled
   - `ExpireAsync()` — cleanup for abandoned requests (TTL-based)

2. **Create `InMemoryPendingRequestStore`:**
   - `ConcurrentDictionary<string, PendingRequest>`
   - Configurable TTL (default 10 min)
   - Background cleanup via `IHostedService` or lazy eviction

3. **Create `InteractionChainingMiddleware`:**
   - Maps two endpoints:
     - `GET /aauth/pending/{id}` — returns `202 { "status": "pending" }` or `200 + result`
     - `GET /aauth/interaction/{id}` — redirects user browser to downstream PS interaction URL
   - Pending poll endpoint is signed (standard AAuth verification) to prevent unauthorized polling
   - Interaction proxy endpoint is browser-accessible (no signature — user navigates here)

4. **Extend `CallChainingHandler.ExchangeForDownstreamAsync`:**
   - Accept optional `Func<AAuthInteraction, CancellationToken, Task<string>>` callback
   - When downstream PS returns 202:
     - Park the original request via `IPendingRequestStore`
     - Return a `PendingExchangeResult` containing the pending ID + interaction info
   - When callback is null and 202 received → throw (current behavior, backward compatible)

5. **Propagation flow in middleware:**
   - Resource receives request from upstream caller
   - Resource needs to call downstream → uses `CallChainingHandler`
   - Downstream PS returns 202
   - Resource creates pending entry in store
   - Resource returns 202 to upstream caller with:
     - `Location: /aauth/pending/{id}`
     - `AAuth-Requirement: requirement=interaction; url="/aauth/interaction/{id}"; code="{code}"`
   - User (via Agent A) navigates to B's interaction URL
   - B redirects to PS interaction URL
   - User approves at PS
   - B polls PS → gets auth token → calls C → gets result → stores result at pending ID
   - Agent A polls B's pending URL → gets 200 + result

6. **Optional: DelegatingHandler integration:**
   - For resources using `HttpClient` pipelines, provide a `CallChainingDelegatingHandler`
   - Automatically handles 401 → challenge → exchange → 202 → park → poll cycle

### Definition of Done

- [ ] `IPendingRequestStore` interface defined with create/get/complete/expire
- [ ] `InMemoryPendingRequestStore` stores and expires pending requests
- [ ] `/aauth/pending/{id}` returns 202/200 based on completion state
- [ ] `/aauth/interaction/{id}` redirects to downstream PS interaction URL
- [ ] `CallChainingHandler` propagates 202 instead of throwing
- [ ] Resource returns 202 + own interaction code to upstream caller
- [ ] End-to-end test: Agent → Resource → PS (consent) → propagation → completion
- [ ] TTL expiry cleans up abandoned pending requests
- [ ] Backward compatible — existing `CallChainingHandler` callers unaffected

---

## Out of Scope

| Item | Reason |
|------|--------|
| Missions / governance (spec §10–11) | Separate initiative |
| R3 (Rich Resource Requests) | Separate initiative |
| PS/AS federation (4-party flow) | Requires AS implementation |
| Gateway/proxy integration (ExtAuthz gRPC) | Platform-specific |
| `AAuthSigningHandler` emitting non-jwt schemes | Agent-side scheme selection is a separate feature |
| Payment Required (402) flow | Not demonstrated in blog |
| `AAuth-Mission` header format mismatch (`approver`+`s256` structured dict) | See research.md §8.3 — missions are a separate initiative |
