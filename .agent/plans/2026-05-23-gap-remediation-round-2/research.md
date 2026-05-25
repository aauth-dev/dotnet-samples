# Gap Remediation Round 2 – Research

> **Created:** 2026-05-23
> **Validated against code:** 2026-05-23
> **Re-validated:** 2026-05-25 (deep spec read of all 3 drafts + per-gap subagent code analysis)
> **Source:** [Christian Posta AAuth Full Demo](https://blog.christianposta.com/aauth-full-demo/)
> **Reference implementations:** Python AAuth Library, Go AAuth Library, AAuth Person Server, ExtAuthz AAuth Resource
> **Spec:** `draft-hardt-oauth-aauth-protocol` (2026-05-06, commit c090879)

---

## 1. Demo Architecture Overview

The blog demo is a multi-service architecture demonstrating end-to-end AAuth flows:

| Component | Role | Implementation |
|-----------|------|----------------|
| Person Server / Agent Provider | Issues `aa-agent+jwt`, manages consent, issues `aa-auth+jwt` | Python ([aauth-person-server](https://github.com/christian-posta/aauth-person-server)) |
| Agentgateway | Gateway / PEP for LLM/MCP/A2A traffic | Rust ([agentgateway](https://github.com/agentgateway/agentgateway)) |
| aauth-service (ExtAuthz) | AAuth verification + resource token issuance | Go ([extauth-aauth-resource](https://github.com/christian-posta/extauth-aauth-resource)) |
| Backend agent | Calling agent (initiates requests) | Python |
| Supply-chain-agent | Resource agent (receives requests) | Python |
| Market-analysis-agent | Downstream resource agent | Python |

### Key Observations

1. **Agentgateway is not an AAuth component** — it delegates verification entirely to `aauth-service` via Envoy ExtAuthz gRPC. The gateway only applies CEL policy on metadata returned by the verifier.
2. **aauth-service is the resource-side verifier** — it handles all `aa-agent+jwt` validation, HTTP signature PoP verification, resource token issuance (401 challenge), and auth token verification.
3. **The Python AAuth library** (`aauth>=0.3.4`) provides agent-side capabilities: request signing, 401 challenge handling, token exchange with PS, deferred polling, and interaction forwarding.
4. **The Go AAuth library** provides server-side verification: JWT validation, JWKS resolution, PoP binding check, and scope/policy evaluation.

---

## 2. Demo Capabilities Analyzed

### 2.1 Agent Identity (Bootstrap + Two-Key Model)

**What the demo does:**
- Agents generate a **stable key** (Ed25519, persisted to disk) and a new **ephemeral key** (Ed25519, rotated per refresh)
- On startup, agent calls `POST /register` at the AP with stable public key and ephemeral public key
- AP requires **person approval** (one-time) before issuing `aa-agent+jwt`
- `aa-agent+jwt` binds the ephemeral key via `cnf.jwk`
- Token refresh: stable key signs a delegation JWT (`typ: jkt-s256+jwt`) containing `cnf.jwk` pointing to a new ephemeral key; sent to `POST /refresh`
- AP discovery at `{iss}/.well-known/aauth-agent.json`

**SDK comparison:**
- ✅ `AgentProviderClient` handles bootstrap enrollment
- ✅ `TokenRefreshHandler` monitors expiry and triggers refresh
- ✅ `AAuthKey` supports Ed25519 key generation/persistence
- ✅ `KeyStore` provides file-based persistence with Unix permissions
- ✅ `MetadataClient` discovers AP metadata
- ❌ No `POST /refresh` endpoint implementation (only the handler triggers it)
- ❌ No person-approval UI/callback mechanism
- ❌ No stable key → ephemeral key delegation JWT builder (only `JktJwtSignatureKeyProvider` format)

### 2.2 Identity-Based Resource Access (Mode 1)

**What the demo does:**
- Agent signs HTTP request with ephemeral key
- Presents `aa-agent+jwt` in `Signature-Key` header with `scheme=jwt`
- Resource (via aauth-service) verifies:
  1. Decodes `aa-agent+jwt` from `Signature-Key`
  2. Fetches AP JWKS at `{iss}/.well-known/aauth-agent.json`
  3. Verifies JWT signature against AP's public key
  4. Confirms `cnf.jwk` matches the HTTP request signing key (PoP)
  5. Applies local policy (no 401 challenge needed)

**SDK comparison:**
- ✅ `AAuthSigningHandler` signs requests with ephemeral key + `aa-agent+jwt` in `Signature-Key`
- ✅ `AAuthVerificationMiddleware` verifies signatures
- ✅ `SignatureKeyParser` extracts `cnf.jwk` from JWT tokens
- ✅ `DefaultSignatureKeyResolver` resolves public keys
- ⚠️ Middleware verifies HTTP signature against `cnf.jwk` but does NOT verify the `aa-agent+jwt` signature against the AP's JWKS — it only verifies PoP (the key that signed the HTTP request matches the key in the token)
- ❌ No AP JWKS fetch for **JWT issuer signature verification** in the middleware pipeline
- ❌ No configurable policy layer (allow/deny based on identity)

### 2.3 PS-Asserted Authorization (Mode 3 – Autonomous)

**What the demo does:**
- Resource configured with `access: require: auth-token`
- On first request (with `aa-agent+jwt` only), resource:
  1. Verifies identity (same as Mode 1)
  2. Issues `401 Unauthorized` with `AAuth-Requirement: requirement=auth-token; resource-token="eyJ..."`
  3. Resource token contains: `iss` (resource), `aud` (PS), `agent`, `agent_jkt`, `scope`, `exp`, `jti`
- Agent extracts resource token, signs `POST /token` at PS with `aa-agent+jwt`
- PS verifies agent identity, evaluates policy, issues `aa-auth+jwt`
- Agent retries with `aa-auth+jwt` in `Signature-Key` header
- Resource verifies auth token against PS JWKS (via `dwk: aauth-person.json`)

**SDK comparison:**
- ✅ `ChallengeHandler` automatically handles 401 + resource token extraction + retry
- ✅ `TokenExchangeClient` exchanges resource token at PS token endpoint
- ✅ `ResourceTokenBuilder` builds compliant resource tokens
- ✅ `AuthTokenBuilder` builds compliant auth tokens
- ❌ **No server-side resource token issuance** — middleware returns bare 401; no code to attach `AAuth-Requirement` header with a freshly minted resource token
- ❌ **No configurable `access: require: auth-token` mode** on the resource server
- ❌ **No auth token verification on the resource side** (verifying PS-issued `aa-auth+jwt` against PS JWKS, checking `aud`, `scope`, `cnf.jwk` PoP binding)
- ❌ **No scope evaluation** — resource has no way to compare granted scope against required scope for an endpoint

### 2.4 PS-Asserted Authorization (User Consent / Deferred)

**What the demo does:**
- Same as Mode 3 but resource token scope includes `require:user`
- PS sees `require:user`, returns `202 Accepted` instead of immediate `aa-auth+jwt`
- Headers: `Location` (pending URL), `Retry-After`, `Cache-Control: no-store`, `AAuth-Requirement: requirement=interaction; url="..."; code="..."`
- Agent polls pending URL with signed GET requests
- PS responds with `202 + {"status": "pending"}` or `{"status": "interacting"}` until user approves
- On approval, poll returns `200 OK` with auth token
- On denial: `403`; on timeout: `408`; on consumed code: `410`

**SDK comparison:**
- ✅ `DeferredPoller` handles `202 Accepted` + `Location` polling with `Retry-After` support
- ✅ `InteractionHandler` handles `requirement=interaction` / `requirement=approval`
- ✅ `AAuthInteraction` projects user URL + code with QR/redirect support
- ✅ `AAuthRequirementHeader` parses all requirement types
- ✅ Poller uses `_signedClient` (constructor takes `HttpClient signedClient` documented as "pre-wired with the agent's signing handler") — **polling IS signed**
- ✅ `PollingErrorCode` enum differentiates all terminal states: Denied, Abandoned, Expired, InvalidCode, SlowDown, ServerError — throws typed `PollingErrorException`
- ❌ No `require:user` scope handling on the resource/PS side
- ❌ No `Prefer: wait=N` long-poll header support

### 2.5 Policy Enforcement via Gateway (CEL on ExtAuthz Metadata)

**What the demo does:**
- After `aauth-service` allows, it returns `dynamic_metadata` to the gateway
- Metadata fields: `level`, `scheme`, `token_type`, `issuer`, `key_id`, `jkt`, `agent_server`, `agent`, `scope`, `txn`, `act`, `sub`
- Gateway evaluates CEL rules on `extauthz.*` (e.g., `extauthz.agent.endsWith("...")`)
- Two-layer enforcement: verifier (is it valid?) + gateway (is it allowed?)

**SDK comparison:**
- ⚠️ **Partial verification result projection** — middleware sets `HttpContext.Items["AAuth.ParsedSignatureKey"]` with `ParsedSignatureKeyInfo` (includes Scheme, Payload JsonObject, ConfirmationKey, JwksUri, Kid, Jkt) — raw data available but no typed verification result class
- ❌ **No ASP.NET Core authorization policy integration** — no `IAuthorizationHandler` that maps AAuth claims to .NET authorization policies
- ❌ **No claims principal enrichment** — verified agent identity, scope, act chain not mapped to `ClaimsPrincipal`

### 2.6 Observability (Tracing + Structured Logging)

**What the demo does:**
- Agentgateway enriches access logs and OTLP traces with AAuth fields: `aauth.scheme`, `aauth.agent`, `sig_key`
- Full distributed tracing through Jaeger shows the token exchange flow

**SDK comparison:**
- ❌ No OpenTelemetry Activity/span enrichment for AAuth flows
- ❌ No structured logging of AAuth verification results
- ❌ No trace propagation through token exchange

---

## 3. Spec Sections Referenced by Demo

| Section | Topic | Demo Coverage | SDK Coverage |
|---------|-------|:---:|:---:|
| §4.1.1 | Identity-based access | ✅ Mode 1 | ⚠️ Partial (no issuer JWT verification) |
| §4.1.3 | PS-Asserted (3-party) | ✅ Mode 3 | ⚠️ Client-only (no server-side) |
| §5.2 | Agent tokens | ✅ Bootstrap | ✅ |
| §5.2.2 | Agent token structure | ✅ Claims shown | ✅ |
| §7.1.4 | Deferred responses | ✅ 202 flow | ✅ |
| §7.2 | User interaction | ✅ Consent UI | ✅ |
| §9.4.1 | Auth token structure | ✅ Claims shown | ✅ |
| §12.3.3 | Interaction requirement | ✅ Header parsing | ✅ |
| §12.4.2 | Deferred response body | ✅ Full | ⚠️ Partial |
| §12.4.3 | Polling with signed requests | ✅ | ✅ (via `_signedClient`) |
| §12.4.4 | Terminal status codes | ✅ 200/403/408/410 | ✅ (`PollingErrorCode` enum) |
| §14.1 | Proof-of-possession (cnf.jwk) | ✅ Full | ⚠️ Structural only |
| RFC 9421 | HTTP Message Signatures | ✅ Full | ✅ |

---

## 4. Patterns the Demo Validates That Our SDK Lacks

### 4.1 Server-Side Resource Token Issuance Pipeline

The demo's `aauth-service` shows the full server-side flow:
1. Receive request → parse `Signature-Key` → extract `aa-agent+jwt`
2. Fetch AP JWKS at `{iss}/.well-known/aauth-agent.json` → verify JWT signature
3. Extract `cnf.jwk` → verify HTTP signature matches (PoP)
4. Check resource config: does this resource require `auth-token`?
5. If yes and no `aa-auth+jwt` present → mint `aa-resource+jwt` → return 401 + `AAuth-Requirement` header
6. If `aa-auth+jwt` present → fetch PS JWKS (via `dwk` → `aauth-person.json`) → verify auth token → verify PoP → check scope → allow

Our middleware (step 3) stops after PoP verification and doesn't do steps 4–6.

### 4.2 Configurable Verification Levels

The demo's `aauth-config.yaml` supports per-resource configuration:
- `allowed_signature_key_schemes: [jwt]`
- `allowed_jwt_types: [aa-agent+jwt, aa-auth+jwt]`
- `access: require: auth-token`
- `supported_scopes` / `default_resource_token_scopes`
- `person_server: issuer: ...`

Our SDK has `AAuthResourceOptions` but it only configures metadata publication, not runtime verification behavior.

### 4.3 Token Issuer Verification (JWKS Chain)

The demo verifies the full trust chain:
1. `aa-agent+jwt.iss` → fetch `{iss}/.well-known/aauth-agent.json` → get `jwks_uri` → verify agent token signature
2. `aa-auth+jwt.iss` → fetch `{iss}/.well-known/aauth-person.json` → get `jwks_uri` → verify auth token signature

Our middleware only verifies the HTTP signature against the `cnf.jwk` from the token. It does NOT verify that the token itself was signed by a trusted issuer. This is a **critical gap** — an attacker could forge an `aa-agent+jwt` with their own key pair and pass PoP verification.

### 4.4 ~~Signed Polling Requests~~ (VALIDATED — Already Implemented)

~~Spec §12.4.3 requires that polling requests to the pending URL MUST be signed with the agent's key and carry the `aa-agent+jwt`. The demo's Python library signs every poll.~~

**Code validation (2026-05-23):** `DeferredPoller` constructor takes `HttpClient signedClient` (line 65, comment: "HttpClient pre-wired with the agent's signing handler"). All polling requests go through `_signedClient.SendAsync()`. This gap does NOT exist.

---

## 5. Reference Implementation Details

### Python AAuth Library (`aauth>=0.3.4`)

Key capabilities observed in the demo:
- `aauth.tokens.exchange_resource_token()` — handles 401 extraction, PS exchange, 202 deferred, polling, and interaction forwarding in a single call
- `aauth.agent.poller` — signed polling with `Prefer: wait=N` header for long-poll (our SDK has signed polling but lacks `Prefer: wait=N`)
- `aauth_interceptor` — DelegatingHandler equivalent that auto-signs requests and handles 401/202
- `AgentTokenService` — manages bootstrap, refresh, and token lifecycle

### Go AAuth Library (in aauth-service)

Key capabilities:
- Full JWT verification chain (issuer JWKS → token signature → cnf.jwk → PoP)
- Per-resource configuration: schemes, JWT types, access mode, scope lists, PS config
- Resource token minting with configurable scopes
- Dynamic metadata emission (ExtAuthz CheckResponse)
- Policy evaluation with named policies

---

## 6. Additional Spec Details for Implementation

### AAuth-Requirement Header Format (RFC 8941 Dictionary)

```
AAuth-Requirement: requirement=auth-token; resource-token="eyJ..."
AAuth-Requirement: requirement=interaction; url="https://ps.example/consent"; code="abc123"
```

### Resource Token Structure (§7.1.2)

```json
{
  "typ": "aa-resource+jwt",
  "alg": "EdDSA",
  "kid": "resource-key-1"
}
{
  "iss": "https://resource.example",
  "dwk": "aauth-resource.json",
  "aud": "https://ps.example",
  "agent": "aauth:uuid@agent-server.example",
  "agent_jkt": "sha-256-thumbprint-of-agent-ephemeral-key",
  "scope": "data:read data:write",
  "iat": 1778718322,
  "exp": 1778718622,
  "jti": "unique-id"
}
```

### Auth Token Verification Steps (Resource Side)

1. Extract `aa-auth+jwt` from `Signature-Key` header
2. Decode JWT header → check `typ: aa-auth+jwt`
3. Read `dwk` claim → resolve well-known document (e.g., `{iss}/.well-known/aauth-person.json`)
4. Fetch `jwks_uri` from well-known document
5. Verify JWT signature against PS/AS public key (by `kid`)
6. Check `aud` matches this resource's identifier
7. Check `exp` / `iat` temporal validity
8. Extract `cnf.jwk` → verify the HTTP request signature was made with this key
9. Check `scope` contains required scope for this endpoint
10. Extract `agent`, `act`, `sub` for policy/audit

### ExtAuthz Metadata Projection (for ASP.NET equivalent)

The Go implementation projects these fields after verification:

```
level: "identified" | "authorized"
scheme: "hwk" | "jwks_uri" | "jwt"
token_type: "aa-agent+jwt" | "aa-auth+jwt"
issuer: string (jwt iss claim)
key_id: string (kid from jwt header)
jkt: string (RFC 7638 thumbprint)
agent_server: string (agent token issuer)
agent: string (agent identifier from aa-auth+jwt)
scope: string (space-separated)
act: { sub: string } (actor chain)
sub: string (user subject)
txn: string (transaction id)
```

---

## 7. Code Validation Results (2026-05-23)

After reading SDK source code directly (not relying on docs or prior assumptions), the following corrections apply:

### 7.1 Features Found to Be Already Implemented

| Feature | Evidence (file:line) | Prior Claim |
|---------|---------------------|-------------|
| Signed polling | `DeferredPoller._signedClient.SendAsync()` — constructor requires signed client | Claimed unsigned |
| Terminal polling status | `PollingErrorCode` enum: Denied, Abandoned, Expired, InvalidCode, SlowDown, ServerError; `PollingErrorException` thrown with typed code | Claimed undifferentiated |
| Scope narrowing enforcement | `TokenVerifier.VerifyAuthToken()` lines 249–258: iterates granted scopes, throws if any exceeds `expectedMaxScope` | Claimed missing |
| All 4 Signature-Key scheme resolution | `DefaultSignatureKeyResolver` switch on scheme (jwt/hwk/jwks_uri/jkt-jwt) — all 4 resolve public key | Claimed jwt-only |
| Verification result projection | `context.Items[ContextItemKey] = parsedInfo` stores full `ParsedSignatureKeyInfo` (Scheme, Payload, ConfirmationKey, JwksUri, Kid, Jkt) | Claimed nothing projected |

### 7.2 Design Decisions Clarified

The middleware source comment (line 30) explicitly states:

> *"Token-level verification (JWKS lookup, aud/scope checks) is the responsibility of route handlers via TokenVerifier — this middleware only ensures the request is signed by the key resolved from the Signature-Key header."*

This means:
- **Middleware = HTTP signature PoP verification** (RFC 9421 compliance)
- **Endpoint handlers = JWT issuer verification** (trust establishment)

This is an intentional layered architecture. The `TokenVerifier` class has full JWT verification capability (`VerifyWithJwksAsync()`, `VerifyAuthTokenWithJwksAsync()`) but must be called explicitly. The WhoAmI sample demonstrates this pattern correctly.

### 7.3 Remaining Actual Gaps (Code-Confirmed)

| Gap | Code Evidence |
|-----|---------------|
| No integrated middleware calling `TokenVerifier` | `AAuthVerificationMiddleware.InvokeAsync()` only calls `_verifier.Verify()` (AAuthVerifier = HTTP sig only) |
| No auto-challenge middleware | Middleware returns bare 401; comment says "policy-free" — no `AAuth-Requirement` header attachment |
| No access mode configuration | `AAuthResourceOptions` has metadata fields only, no `AccessMode` enum |
| No `IAuthorizationHandler` | Zero matches for `IAuthorizationHandler` in `src/AAuth/` |
| No `Prefer: wait=N` | Zero matches for "Prefer" in `src/AAuth/` |
| No OpenTelemetry | Zero matches for `Activity`, `DiagnosticSource`, `Meter` (excluding BouncyCastle crypto params) |
| jkt-jwt naming JWT not signature-verified | `DefaultSignatureKeyResolver.ResolveJktJwt()` line 98: "TODO: Full verification of the naming JWT signature" |
| ECDSA skipped in JwksClient | `JwksClient.FetchAsync()` line 90: `if (kty != AAuthKey.KeyType \|\| crv != AAuthKey.Curve) continue;` |
| No `upstream_token` | Zero matches in `src/AAuth/` |
| No interaction chaining | Zero matches for "interaction chaining" or pending-request propagation in `src/AAuth/` |

### 7.4 Revised SDK Coverage Table

| §Spec Section | Topic | SDK Coverage | Notes |
|---------------|-------|:---:|-------|
| §4.1.1 | Identity-based access | ⚠️ Partial | HTTP sig verified; JWT issuer verification available but not middleware-automatic |
| §4.1.3 | PS-Asserted (3-party) | ⚠️ Client-side only | Agent-side complete; resource-side building blocks exist but no integrated middleware |
| §5.2 | Agent tokens | ✅ | Bootstrap, refresh, token building |
| §7.1.4 | Deferred responses | ✅ | Full polling + interaction + signed requests |
| §9.4.1 | Auth token structure | ✅ | Building + verification (manual call) |
| §12.4.2 | Deferred response body | ✅ | Full parsing |
| §12.4.3 | Signed polling | ✅ | `_signedClient` pattern |
| §12.4.4 | Terminal status codes | ✅ | Typed `PollingErrorCode` enum |
| §14.1 | PoP (cnf.jwk) | ✅ | Full binding in `TokenVerifier.VerifyAuthToken()` |
| RFC 9421 | HTTP Message Signatures | ✅ | Ed25519 end-to-end |

---

## 8. Spec-Level Observations from Deep Read (2026-05-25)

> **Update (2026-05-25):** The following observations come from a complete read of all three spec drafts (protocol, bootstrap, R3) and are relevant to prioritizing implementation work.

### 8.1 Auth Token `act` Claim Is Always Required

The spec §Auth Token Structure lists `act` as a Required payload claim:

> *"In direct authorization, `act.sub` is the agent identifier. In call chaining, `act` nests to record the full delegation chain."*

Our `AuthTokenBuilder` currently does NOT emit an `act` claim. This is a conformance gap (not listed in the original 11 because the builder works — but auth tokens without `act` are non-conformant). The `TokenVerifier.VerifyAuthToken()` does validate `act.sub` when present (step 8), but would need updating if `act` becomes mandatory for all auth tokens.

**Action:** `AuthTokenBuilder` should always emit `act: { sub: <agent identifier> }`. This is a minor change to add to Phase 1.

### 8.2 Resource Token Audience Logic (Spec §Resource Tokens)

The spec defines clear priority for resource token audience:

1. If resource has its own AS → `aud` = AS URL (four-party)
2. If resource has no AS but agent has PS (`ps` claim) → `aud` = PS URL (three-party)
3. If neither → resource handles authorization itself (two-party)

The auto-challenge middleware (Phase 2) needs to resolve the audience dynamically based on configuration. This is not a simple hardcoded value — it depends on whether the resource has an AS configured and whether the agent token contains a `ps` claim.

### 8.3 `AAuth-Mission` Header Format Mismatch

The spec defines `AAuth-Mission` as:

```http
AAuth-Mission: approver="https://ps.example"; s256="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
```

But the SDK's `AAuthMissionHeader.Format(string missionId)` takes a plain string ID — it does NOT format the `approver` + `s256` structured dictionary. This is a conformance gap in the mission model, but since missions are out of scope for this round (noted in the plan's Out of Scope table), it is documented here for future reference.

### 8.4 ECDSA Is SHOULD, Not MUST — Prioritize Correctly

Spec §Signature Algorithms:

> *"Agents and resources MUST support EdDSA using Ed25519. Agents and resources SHOULD support ECDSA using P-256 with deterministic signatures (RFC 6979)."*

Gap 10 is a **SHOULD**. The Ed25519-only pipeline is fully conformant. ECDSA wiring can be deferred below all MUST gaps.

### 8.5 Call Chaining Routing Logic (Gap 11 Detail)

The spec §Call Chaining defines routing based on the upstream auth token:

| Condition | Route downstream to | Rationale |
|---|---|---|
| `mission.approver` present in upstream auth token | PS at `mission.approver` URL | Governed path — PS has mission context |
| No mission, `iss` is a PS (three-party upstream) | PS at `iss` URL | PS evaluates without mission context |
| No mission, `iss` is an AS (four-party upstream) | AS at `iss` URL | No PS involved — AS evaluates |

The `upstream_token` is passed alongside `resource_token` in the POST body. The PS/AS constructs nested `act` claims preserving the delegation chain.

### 8.6 Spec Reference for jkt-jwt (Gap 9)

The jkt-jwt scheme is defined in the companion spec `draft-hardt-httpbis-signature-key`, not in the main AAuth protocol spec. The main spec references it normatively. The naming JWT (`typ: jkt-s256+jwt`) contains:
- `iss`: AP issuer URL (same as agent token issuer)
- `cnf.jwk`: ephemeral public key
- Signature: made by the durable key (AP-bound)

Verification requires fetching `{iss}/.well-known/aauth-agent.json` → `jwks_uri` → JWKS containing the durable key → verify naming JWT signature.

### 8.7 Token Type Values

For reference in Phase 1 middleware dispatch:

| Token | `typ` header value | `dwk` payload claim |
|---|---|---|
| Agent token | `aa-agent+jwt` | `aauth-agent.json` |
| Resource token | `aa-resource+jwt` | `aauth-resource.json` |
| Auth token | `aa-auth+jwt` | `aauth-person.json` (PS) or `aauth-access.json` (AS) |

### 8.8 Interaction Chaining (Gap 12 Detail)

**Spec reference:** §Interaction Chaining (line 1662–1666 of `draft-hardt-oauth-aauth-protocol.md`)

**Normative requirement (MUST-level):**

> When a resource acting as an agent receives a `202 Accepted` response with `AAuth-Requirement: requirement=interaction`, and the resource needs to propagate this interaction requirement to its caller, it MUST return a `202 Accepted` response to the original agent with its own `AAuth-Requirement` header containing `requirement=interaction` and its own interaction code. The resource MUST provide its own `Location` URL for the original agent to poll. When the user completes interaction and the resource obtains the downstream auth token, the resource completes the original request and returns the result at its pending URL.

**Scenario: Agent A → Resource B → Resource C → PS (consent required)**

```
User      Agent A     Resource B      Resource C    PS
  |         |              |               |          |
  |         | HTTPSig req  |               |          |
  |         |------------->|               |          |
  |         |              | HTTPSig req   |          |
  |         |              | (as agent)    |          |
  |         |              |-------------->|          |
  |         |              |               |          |
  |         |              | 401 + res_tok |          |
  |         |              |<--------------|          |
  |         |              |               |          |
  |         |              | POST token_ep |          |
  |         |              | (res_tok +    |          |
  |         |              |  upstream_tok)|          |
  |         |              |------------------------->|
  |         |              |               |          |
  |         |              | 202 Accepted  |          |
  |         |              | interaction   |          |
  |         |              | code="WXYZ"   |          |
  |         |              |<-------------------------|
  |         |              |               |          |
  |         | 202 Accepted |               |          |
  |         | interaction  |               |          |
  |         | code="MNOP"  |               |          |
  |         | Location:    |               |          |
  |         |  /pending/x  |               |          |
  |         |<-------------|               |          |
  |         |              |               |          |
  | direct user to B's URL |               |          |
  |<--------|              |               |          |
  |         |              |               |          |
  | B redirects to PS interaction          |          |
  |----------------------------------------------->  |
  |         |              |               |          |
  | user approves at PS    |               |          |
  |----------------------------------------------->  |
  |         |              |               |          |
  |         |         [B polls PS,         |          |
  |         |          gets auth_token,    |          |
  |         |          calls C,            |          |
  |         |          completes /pending/x]          |
  |         |              |               |          |
  |         | polls /pending/x             |          |
  |         |------------->|               |          |
  |         |              |               |          |
  |         | 200 OK       |               |          |
  |         |<-------------|               |          |
```

**Key architectural requirements for the SDK:**

1. **Pending Request Store** — Each intermediate resource must park the original incoming request while awaiting downstream consent. Needs a store (in-memory or distributed) keyed by a unique pending ID.

2. **Interaction Proxy Endpoint** — Each resource publishes a URL (e.g., `/aauth/interaction/{id}`) that:
   - Accepts the user browser redirect
   - Redirects the user to the actual downstream PS interaction URL
   - This creates the chain: user → B's URL → PS URL

3. **Pending Poll Endpoint** — Each resource exposes `Location: /aauth/pending/{id}` that:
   - Returns `202 { "status": "pending" }` while downstream consent is incomplete
   - Returns `200 + result` once downstream consent completes and the original request is fulfilled

4. **Propagation in CallChainingHandler** — When the downstream PS returns 202:
   - Resource parks its caller's request
   - Returns 202 with its own interaction code + pending URL to caller
   - Begins polling downstream or subscribing to completion signal

5. **Completion Callback** — When the downstream auth token arrives:
   - Resource uses it to call the downstream resource
   - Gets the response
   - Stores the response at its pending URL
   - Caller's next poll returns 200

**Existing SDK building blocks:**

| Component | Exists? | Reusable for interaction chaining? |
|-----------|---------|-----------------------------------|
| `DeferredPoller` | ✅ | Yes — resource can poll downstream PS |
| `AAuthInteraction` parser | ✅ | Yes — parse downstream 202 response |
| `AAuthInteraction.Format()` | ✅ | Yes — format resource's own 202 |
| `TokenExchangeClient` + `onInteractionRequired` | ✅ | Yes — receives the 202 from PS |
| `InMemoryJtiStore` pattern | ✅ | Pattern reusable for pending store (ConcurrentDictionary) |
| `AAuthChallengeMiddleware` | ✅ | Pattern reusable for interaction chaining middleware |
| Pending request parking | ❌ | Needs new `IPendingRequestStore` |
| Interaction proxy endpoint | ❌ | Needs new mapped endpoint |
| Pending poll endpoint | ❌ | Needs new mapped endpoint |
| `CallChainingHandler` propagation | ❌ | Currently passes `onInteractionRequired: null` |

**Complexity assessment:** HIGH. This is a stateful middleware pattern requiring:
- Request parking (storing context while awaiting async consent)
- Two new HTTP endpoints per resource (interaction proxy + pending poll)
- Integration with `CallChainingHandler`
- Proper cleanup/timeout for abandoned pending requests
