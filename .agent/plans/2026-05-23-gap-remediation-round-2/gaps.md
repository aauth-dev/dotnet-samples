# Gap Remediation Round 2 – Gaps Analysis

> **Created:** 2026-05-23
> **Validated:** 2026-05-23 (against actual SDK source code)
> **Source:** Comparison of [Christian Posta AAuth Full Demo](https://blog.christianposta.com/aauth-full-demo/) against our .NET SDK
> **Spec:** `draft-hardt-oauth-aauth-protocol` (2026-05-06)
> **SDK path:** `src/AAuth/`

This document identifies gaps validated by reading SDK source code directly. Prior analysis from blog comparison and round 1 carry-forwards has been verified against actual implementation state. Gaps that were found to already be implemented have been removed or reclassified.

---

## Summary

| # | Gap | Severity | Spec Gap? | Status |
|---|-----|----------|:---:|:---:|
| 1 | Middleware-level JWT issuer verification (agent token) | Critical | **YES — MUST** | Confirmed |
| 2 | Middleware-level JWT issuer verification (auth token) | Critical | **YES — MUST** | Confirmed |
| 3 | Auto-challenge middleware (401 + resource token) | Medium | **YES — MUST** | Partially implemented |
| 4 | Configurable access mode | Medium | No — impl pattern | Confirmed |
| 5 | Typed verification result (structured claims) | Low | No — impl pattern | Partially implemented |
| 6 | ASP.NET authorization policy integration | Medium | No — platform | Confirmed |
| 7 | Prefer: wait=N long-poll support | Low | No — MAY | Confirmed |
| 8 | OpenTelemetry trace enrichment | Low | No — not in spec | Confirmed |
| 9 | jkt-jwt naming JWT signature verification | Medium | **Conditional MUST** | Confirmed (TODO in code) |
| 10 | ECDSA P-256 pipeline wiring | Low | SHOULD | Confirmed |
| 11 | Call chaining (resource as agent) | Medium | **MUST (conditional)** | Confirmed |

> **Spec gaps: 5** (Gaps 1, 2, 3, 9, 11)
> **SHOULD: 1** (Gap 10)
> **Implementation/DX: 5** (Gaps 4, 5, 6, 7, 8)

---

## Invalidated Gaps (Previously Listed, Now Confirmed Implemented)

The following gaps from the initial analysis were found to be **already implemented** in the SDK:

| Original # | Claimed Gap | Actual Code Finding |
|:---:|---|---|
| 9 (old) | Signed polling requests | `DeferredPoller` uses `_signedClient` — constructor takes `HttpClient signedClient` documented as "pre-wired with the agent's signing handler" ([DeferredPoller.cs](../../src/AAuth/Agent/DeferredPoller.cs#L65)) |
| 10 (old) | Terminal polling status differentiation | `PollingErrorCode` enum has 6 codes (Denied, Abandoned, Expired, InvalidCode, SlowDown, ServerError). `DeferredPoller` special-cases SlowDown (backoff+continue) and throws typed `PollingErrorException` for all others ([PollingError.cs](../../src/AAuth/Errors/PollingError.cs)) |
| 6 (old) | Scope enforcement | `TokenVerifier.VerifyAuthToken()` implements full scope narrowing via `expectedMaxScope` parameter — iterates granted scopes and throws if any exceeds the allowed set ([TokenVerifier.cs](../../src/AAuth/Tokens/TokenVerifier.cs#L249-L258)) |
| 13 (old, partial) | Signature-Key scheme resolution | `DefaultSignatureKeyResolver` resolves ALL 4 schemes: jwt (cnf.jwk), hwk (inline key), jwks_uri (fetches via JwksClient), jkt-jwt (validates thumbprint match) ([DefaultSignatureKeyResolver.cs](../../src/AAuth/HttpSig/DefaultSignatureKeyResolver.cs#L28-L40)) |

---

## Gap Details

### Gap 1: Middleware-Level JWT Issuer Verification (Agent Token)

**Severity:** Critical | **Spec gap: YES — MUST**
**Spec:** §Agent Token Verification step 2: *"Discover the issuer's JWKS via `{iss}/.well-known/{dwk}`... Locate the key matching the JWT header `kid` and verify the JWT signature."*

**Code evidence:**
- `AAuthVerificationMiddleware.InvokeAsync()` ([AAuthVerificationMiddleware.cs](../../src/AAuth/HttpSig/AAuthVerificationMiddleware.cs#L60-L105)): calls `_verifier.Verify()` which is `AAuthVerifier` (HTTP signature only). Does NOT call `TokenVerifier`.
- Middleware source comment (line 30): *"Token-level verification (JWKS lookup, aud/scope checks) is the responsibility of route handlers via TokenVerifier"*
- `TokenVerifier.VerifyWithJwksAsync()` EXISTS ([TokenVerifier.cs](../../src/AAuth/Tokens/TokenVerifier.cs#L371-L410)) — fetches issuer metadata, resolves JWKS, verifies JWT signature. But never called from middleware.
- WhoAmI sample manually calls `verifier.VerifyWithJwksAsync()` in endpoint handler ([WhoAmI/Program.cs](../../samples/WhoAmI/Program.cs#L153)).

**Architectural context:** This is an explicit design choice — middleware does HTTP sig verification (PoP), endpoint handlers do JWT verification (identity trust). The risk is that developers who only use middleware without calling `TokenVerifier` are vulnerable to forged tokens.

**Risk:** An attacker forges an `aa-agent+jwt` with arbitrary claims, signs HTTP request with their own key (placed in `cnf.jwk`). Middleware accepts it because PoP passes. Without JWT issuer verification in each handler, the token is trusted.

**Required:**
- Option A: Higher-level middleware that chains HTTP sig + JWT verification (recommended)
- Option B: Extension method / endpoint filter that calls `TokenVerifier.VerifyWithJwksAsync()` automatically
- Either way: verify JWT signature against AP JWKS before trusting claims

---

### Gap 2: Middleware-Level JWT Issuer Verification (Auth Token)

**Severity:** Critical | **Spec gap: YES — MUST**
**Spec:** §Auth Token Verification step 2: *"Verify `dwk` is `aauth-access.json` or `aauth-person.json`. Discover the issuer's JWKS and verify the JWT signature."*

**Code evidence:**
- `TokenVerifier.VerifyAuthTokenWithJwksAsync()` EXISTS ([TokenVerifier.cs](../../src/AAuth/Tokens/TokenVerifier.cs#L269-L330)) — performs full PoP binding + JWT issuer verification.
- Middleware does NOT distinguish between `aa-agent+jwt` and `aa-auth+jwt` — treats both as "a JWT carrying cnf.jwk" for HTTP sig verification only.
- WhoAmI sample calls `verifier.VerifyWithJwksAsync(...AuthTokenBuilder.TokenType...)` manually ([WhoAmI/Program.cs](../../samples/WhoAmI/Program.cs#L206)).

**Same architectural pattern as Gap 1.** The verification capability is fully implemented but requires explicit invocation.

**Required:** Same solution as Gap 1 — an integrated middleware or filter that auto-detects token type (`typ` claim) and invokes the appropriate `TokenVerifier` method.

---

### Gap 3: Auto-Challenge Middleware (401 + Resource Token)

**Severity:** Medium | **Spec gap: YES — MUST**
**Spec:** §requirement-auth-token: *"A resource MUST respond with `401 Unauthorized` and `AAuth-Requirement: requirement=auth-token; resource-token="..."` when an auth token is required."*

**Code evidence:**
- `ResourceTokenBuilder` is FULLY IMPLEMENTED ([ResourceTokenBuilder.cs](../../src/AAuth/Tokens/ResourceTokenBuilder.cs)) — builds and signs `aa-resource+jwt` with proper claims (iss, aud, agent, agent_jkt, scope).
- WhoAmI sample shows the complete flow: builds resource token → returns 401 with `AAuth-Requirement` header ([WhoAmI/Program.cs](../../samples/WhoAmI/Program.cs#L179-L193)).
- Agent-side `ChallengeHandler` processes 401 challenges automatically ([ChallengeHandler.cs](../../src/AAuth/Agent/ChallengeHandler.cs#L60-L110)).
- Middleware comment (line 66): *"Surface missing-signature as 401 with no body so the resource can attach AAuth-Requirement from its own handler. This keeps the middleware policy-free."*

**What EXISTS:** Token building, agent-side challenge processing, sample showing the pattern.
**What's MISSING:** A reusable middleware/filter that automatically issues the 401+resource-token challenge when identity is verified but auth token is required. Currently each endpoint must implement this manually.

**Downgraded from High to Medium** because all building blocks exist and the pattern is demonstrated; the gap is a reusable integration layer.

**Required:**
- A middleware or endpoint filter: when `ParsedSignatureKeyInfo.Payload["typ"] == "aa-agent+jwt"` AND the endpoint requires an auth token → mint resource token → return 401 with `AAuth-Requirement` header.
- Configurable per-endpoint (some endpoints accept agent tokens directly).

---

### Gap 4: Configurable Access Mode

**Severity:** Medium | **Spec gap: No — implementation pattern**

**Code evidence:**
- `AAuthResourceOptions` ([DependencyInjection/](../../src/AAuth/DependencyInjection/)) configures metadata (scopes, JWKS) but has no access mode enum.
- WhoAmI sample manually dispatches on scheme (`parsed.Scheme == "hwk"` / `"jwks_uri"` / `"jwt"`).
- No enum like `AccessMode.IdentityOnly | RequireAuthToken` exists.
- No `AllowedSignatureKeySchemes` or `AllowedJwtTypes` configuration.

**Required:**
- Extend options with: `AllowedSchemes`, `RequiredTokenType`, `PersonServerIssuer`
- Middleware can reject disallowed schemes early (before endpoint code runs)

---

### Gap 5: Typed Verification Result (Structured Claims)

**Severity:** Low | **Spec gap: No — DX improvement**

**Code evidence:**
- Middleware stores `ParsedSignatureKeyInfo` in `HttpContext.Items["AAuth.ParsedSignatureKey"]` ([AAuthVerificationMiddleware.cs](../../src/AAuth/HttpSig/AAuthVerificationMiddleware.cs#L136)).
- `ParsedSignatureKeyInfo` includes `Scheme`, `Payload` (raw JsonObject), `ConfirmationKey`, `JwksUri`, `Kid`, `Jkt`.
- WhoAmI sample reads it: `(SignatureKeyParser.ParsedSignatureKeyInfo)ctx.Items[AAuthVerificationMiddleware.ContextItemKey]!`
- Raw data IS available — gap is the absence of a higher-level typed result object with ergonomic properties like `.Agent`, `.Scope`, `.Level`.

**Required:**
- `AAuthVerificationResult` class with typed properties (Level, Scheme, TokenType, Agent, Scope, ActorChain)
- Populated after full verification (Gap 1/2), stored in `HttpContext.Features<IAAuthVerificationResult>`

---

### Gap 6: ASP.NET Authorization Policy Integration

**Severity:** Medium | **Spec gap: No — platform integration**

**Code evidence:**
- No `IAuthorizationHandler` implementations anywhere in `src/AAuth/`.
- No `AuthorizationPolicy` builders or `[Authorize]` attribute support.
- Verified AAuth identity is NOT mapped to a `ClaimsPrincipal`.
- All authorization logic is manual in endpoint handlers.

**Required:**
- `AAuthAuthenticationHandler` that populates `HttpContext.User` with AAuth claims
- Policy builders: `[Authorize(Policy = "AAuth:RequireAuthToken")]`, `[RequireAAuthScope("data:read")]`
- Or `IAuthorizationHandler` reading from `HttpContext.Features`

---

### Gap 7: Prefer: wait=N Long-Poll Support

**Severity:** Low | **Spec gap: No — MAY**
**Spec:** §Polling with GET: *"The agent MAY include `Prefer: wait=N`."*

**Code evidence:**
- No "Prefer" header references anywhere in `src/AAuth/`.
- `DeferredPoller` uses `Retry-After` header for delay computation but never sends `Prefer`.
- `TokenExchangeClient` does not include preference headers.

**Required:**
- Add optional `PreferWait` property to `DeferredPollerOptions`
- Send `Prefer: wait=N` header on poll requests when configured

---

### Gap 8: OpenTelemetry Trace Enrichment

**Severity:** Low | **Spec gap: No — not in spec**

**Code evidence:**
- No `System.Diagnostics.Activity`, `DiagnosticSource`, `Meter`, or OpenTelemetry references in `src/AAuth/`.
- No span tags, no trace context propagation.

**Required:**
- Server middleware: add tags to current Activity (`aauth.scheme`, `aauth.agent`, `aauth.scope`)
- Client handlers: child spans for token exchange, polling cycles

---

### Gap 9: jkt-jwt Naming JWT Signature Verification

**Severity:** Medium | **Spec gap: Conditional MUST**
**Spec:** §Signature-Key jkt-jwt: The naming JWT's signature MUST be verified against the durable key's issuer JWKS.

**Code evidence:**
- `DefaultSignatureKeyResolver.ResolveJktJwt()` ([DefaultSignatureKeyResolver.cs](../../src/AAuth/HttpSig/DefaultSignatureKeyResolver.cs#L88-L107)):
  - ✅ Validates `jkt` parameter matches `cnf.jwk` thumbprint
  - ✅ Extracts ephemeral key from cnf.jwk for HTTP sig verification
  - ❌ Source comment (line 98): *"TODO: Full verification of the naming JWT signature against the durable key (requires JWKS lookup of the durable key's issuer). For now, we trust the structural binding."*
- The naming JWT's signature is NOT verified. Only the structural binding (jkt↔cnf.jwk) is checked.

**Impact:** An attacker can forge a jkt-jwt naming JWT with arbitrary identity claims, and the resolver will accept it as long as the thumbprint matches.

**Required:**
- Fetch the durable key's issuer JWKS (from the naming JWT's `iss` claim)
- Verify the naming JWT signature against that JWKS
- Then trust the delegation to the ephemeral key

---

### Gap 10: ECDSA P-256 Pipeline Wiring

**Severity:** Low | **Spec gap: SHOULD**
**Spec:** §Signature Algorithms: *"Agents and resources SHOULD support ECDSA using P-256."*

**Code evidence:**
- `EcdsaAAuthKey` exists with full implementation ([EcdsaAAuthKey.cs](../../src/AAuth/Crypto/EcdsaAAuthKey.cs)) — generation, signing, verification, JWK serialization.
- `JwksClient.FetchAsync()` ([JwksClient.cs](../../src/AAuth/Discovery/JwksClient.cs#L88-L93)): explicitly skips non-Ed25519 keys with comment: *"Skip non-Ed25519 keys silently; future support lands when ES256/RS256 are added."*
- `TokenVerifier` line 59: `if (alg != AAuthKey.Algorithm)` — hardcoded to `"EdDSA"`.
- `AAuthVerifier`: signature verification hardcoded to Ed25519.

**Required:**
- `JwksClient`: dispatch on `kty`/`crv` to create `EcdsaAAuthKey` for EC/P-256 keys
- `TokenVerifier`: dispatch on `alg` claim (EdDSA → AAuthKey, ES256 → EcdsaAAuthKey)
- `AAuthVerifier`: accept `IAAuthKey` (already interface-based? needs check)

---

### Gap 11: Call Chaining (Resource as Agent)

**Severity:** Medium | **Spec gap: MUST (for resources accessing downstream resources)**
**Spec:** §Call Chaining: *"The resource MUST have its own agent identity."*

**Code evidence:**
- No `upstream_token` parameter anywhere in `src/AAuth/`.
- `TokenExchangeClient` POST body only contains `resource_token` ([TokenExchangeClient.cs](../../src/AAuth/Agent/TokenExchangeClient.cs#L118)).
- `TokenVerifier` validates nested `act` claims (depth ≤ 10) — foundation for verifying chained tokens EXISTS.
- No `CallChainingHandler` or resource-as-agent pattern.

**Required:**
- `TokenExchangeClient`: accept optional `upstream_token` parameter
- `CallChainingHandler` (DelegatingHandler): extracts incoming auth token, requests new auth token with `upstream_token` for downstream resource
- Resource-as-agent metadata at `/.well-known/aauth-agent.json`

---

## Implementation Priority

### Phase 1: Critical Security — Integrated Verification Middleware (Gaps 1–2)

Create a higher-level middleware (or opt-in mode on existing middleware) that performs BOTH HTTP signature verification AND JWT issuer verification in one pass. This closes the security gap where developers might rely on middleware alone.

### Phase 2: Auto-Challenge and Access Mode (Gaps 3–4)

Reusable challenge filter + configurable access mode so resources can declaratively require auth tokens.

### Phase 3: Authorization Integration (Gaps 5–6)

Typed verification result + ASP.NET authorization policies. Makes AAuth consumable by standard .NET patterns.

### Phase 4: jkt-jwt and ECDSA (Gaps 9–10)

Complete the naming JWT signature verification TODO and wire ECDSA through the pipeline.

### Phase 5: Call Chaining (Gap 11)

Enable resource-as-agent pattern for multi-hop flows.

### Phase 6: DX and Observability (Gaps 7–8)

Prefer: wait=N, OpenTelemetry. Nice-to-have improvements.
