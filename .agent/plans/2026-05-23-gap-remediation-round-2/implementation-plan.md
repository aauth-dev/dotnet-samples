# Gap Remediation Round 2 – Implementation Plan

> **Created:** 2026-05-23
> **Validated against code:** 2026-05-23
> **Re-validated:** 2026-05-25 (all 11 gaps confirmed active; spec deep-read refinements added)
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

- [ ] `aa-agent+jwt` signature verified against AP JWKS before PoP is trusted
- [ ] `aa-auth+jwt` signature verified against PS/AS JWKS + `aud` validated
- [ ] Auth token `act.sub` validated (reject if missing)
- [ ] `AuthTokenBuilder` emits `act: { sub: agent }` by default
- [ ] Forged token with valid PoP but unknown/untrusted issuer → 401 `invalid_jwt`
- [ ] `TrustedIssuers` allow-list restricts accepted issuers when configured
- [ ] Existing `AAuthVerificationMiddleware` unchanged (non-breaking)
- [ ] Unit tests: forged token rejected, valid token accepted, missing act rejected
- [ ] Integration test: end-to-end with MockPersonServer

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

- [ ] Resource returns 401 + `AAuth-Requirement` header with valid `aa-resource+jwt`
- [ ] `IdentityOnly` mode passes through after identity verification
- [ ] `RequireAuthToken` mode challenges when only agent token present
- [ ] Agent-side `ChallengeHandler` successfully retries after challenge
- [ ] `AllowedSignatureKeySchemes` rejects unlisted schemes
- [ ] Unit tests: challenge issued, identity-only passthrough
- [ ] Integration test: full challenge → exchange → retry flow

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

- [ ] `AAuthVerificationResult` stored in `HttpContext.Features` after verification
- [ ] `HttpContext.User` populated with AAuth claims
- [ ] `[Authorize(Policy = "AAuth.Authorized")]` requires auth-token level
- [ ] `[RequireAAuthScope("x")]` rejects requests without scope (403)
- [ ] Standard `User.HasClaim()` works with AAuth claims
- [ ] Unit tests for each authorization requirement

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

- [ ] jkt-jwt naming JWT signature verified against issuer JWKS
- [ ] Forged jkt-jwt naming JWT rejected
- [ ] `JwksClient` resolves both Ed25519 and P-256 keys from JWKS documents
- [ ] `TokenVerifier` accepts both EdDSA and ES256 tokens
- [ ] HTTP signature verification works with P-256 keys
- [ ] Existing Ed25519 flows unaffected (backward compatible)
- [ ] Unit tests: ES256 key round-trip, mixed JWKS, jkt-jwt verification

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

- [ ] `upstream_token` parameter sent in token exchange when provided
- [ ] Resource can request auth tokens for downstream resources
- [ ] Downstream auth tokens contain nested `act` chain (caller → resource → downstream)
- [ ] `TokenVerifier` validates the chained `act` claims correctly
- [ ] Unit tests: upstream_token exchange, act chain construction
- [ ] Integration test: Agent → Resource 1 → Resource 2 flow

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

- [ ] `Prefer: wait=30` sent on poll requests when configured
- [ ] Activity tags populated after server-side verification
- [ ] Client spans created for token exchange and polling
- [ ] No external OTel package dependency
- [ ] Smoke test: verify Activity tags present

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
