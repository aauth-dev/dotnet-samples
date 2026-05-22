# AAuth .NET SDK – Gaps Analysis

> **Generated:** 2026-05-20
> **Spec versions analysed:** `draft-hardt-oauth-aauth-protocol`, `draft-hardt-aauth-bootstrap`, `draft-hardt-aauth-r3`
> **SDK path:** `src/AAuth/`

This document identifies features defined in the AAuth specification that are **not yet implemented** in the .NET SDK or covered by conformance tests.

---

## Summary

| Category | Spec Features | Implemented | Gap Count |
|----------|:---:|:---:|:---:|
| Protocol Flows | 4 access modes | 2 (identity, 3-party PS-asserted) | 2 |
| Endpoints | ~15 distinct | 3 (resource well-known, PS token, polling) | ~12 |
| Token Types | 3 | 3 (agent, resource, auth) | 0 (structure only) |
| Token Building | Required claims per type | Partial (`act` missing from builder) | 1 |
| Signature-Key Schemes | 4 | 1 (`jwt`) | 3 |
| Cryptographic Algorithms | 2 | 1 (EdDSA/Ed25519) | 1 |
| Governance (Missions) | Full lifecycle | None | Full |
| R3 (Rich Resource Requests) | Full lifecycle | None | Full |
| Bootstrap / Refresh | Full lifecycle | None | Full |
| Error Handling | Detailed error model | Partial | Significant |
| Replay Detection | JTI uniqueness per token | None | 1 |
| Agent Capabilities | `AAuth-Capabilities` header | None | 1 |
| Conformance Tests | All phases | Phase 2 only | Phases 1, 3+ |

---

## 1. Protocol Flows Not Implemented

### 1.1 Resource-Managed Access (2-Party)
**Spec:** Agent sends signed request → Resource returns 202 with `requirement=interaction` → User completes interaction → Agent polls Location → Resource returns 200 with optional `AAuth-Access` opaque token.

**Gap:** No SDK support for:
- Issuing/handling `AAuth-Access` opaque tokens (non-JWT bearer)
- Resource-side interaction initiation flow
- Agent-side handling of resource-managed 202 responses (distinct from PS 202)

### 1.2 Federated Access (4-Party: Agent ↔ Resource ↔ PS ↔ AS)
**Spec:** Resource token has `aud` = AS URL → PS federates with AS → AS may require interaction/claims/payment → AS returns auth token → PS passes to agent.

**Gap:** No SDK support for:
- `AuthTokenBuilder` with `Dwk = "aauth-access.json"` is present but **untested**
- AS metadata discovery (`aauth-access.json`)
- PS→AS federation request construction
- PS→AS token exchange with `agent_token` + `resource_token` + optional `upstream_token`
- AS-side token endpoint handling
- Payment Required (402) flow handling

---

## 2. Endpoints Not Implemented

| Endpoint | Role | Status |
|----------|------|--------|
| `POST /authorize` | Resource authorization endpoint | ❌ Not implemented |
| `POST /token` (AS) | Access Server token endpoint | ❌ Not implemented |
| `POST /refresh` | AP token refresh | ❌ Not implemented |
| `POST /permission` | PS permission endpoint (tool calls) | ❌ Not implemented |
| `POST /audit` | PS audit endpoint (mission logs) | ❌ Not implemented |
| `POST /interaction` | PS interaction relay | ❌ Not implemented |
| `POST /mission` | PS mission creation | ❌ Not implemented |
| `POST /login` | Third-party login endpoint | ❌ Not implemented |
| `POST /revoke` | Token revocation (all servers) | ❌ Not implemented |
| `GET /.well-known/aauth-agent.json` | AP metadata | ❌ Not implemented (client fetches but no server-side mapping) |
| `GET /.well-known/aauth-person.json` | PS metadata | ❌ Server-side mapping not implemented (client discovery works) |
| `GET /.well-known/aauth-access.json` | AS metadata | ❌ Not implemented |
| `GET /r3/{id}` | R3 document fetch | ❌ Not implemented |

**Implemented:**
- ✅ `GET /.well-known/aauth-resource.json` (server-side via `WellKnownEndpoints`)
- ✅ `GET /.well-known/jwks.json` (server-side via `WellKnownEndpoints`)
- ✅ `POST /token` (PS) – client-side via `TokenExchangeClient`
- ✅ Deferred polling via `DeferredPoller`

---

## 3. Signature-Key Schemes

| Scheme | Purpose | Status |
|--------|---------|--------|
| `jwt` | Carry agent/auth token directly | ✅ Implemented |
| `jkt-jwt` | Two-key delegation (durable→ephemeral) | ❌ Not implemented |
| `hwk` | Inline hardware-bound key (enrollment) | ❌ Not implemented |
| `jwks_uri` | Key at endpoint (self-hosted agents) | ❌ Not implemented |

**Impact:** Without `jkt-jwt`, the SDK cannot support token refresh or the two-key pattern defined in the bootstrap spec.

---

## 4. Cryptographic Algorithm Support

| Algorithm | Spec Requirement | Status |
|-----------|-----------------|--------|
| EdDSA (Ed25519) | MUST support | ✅ Implemented |
| ECDSA (P-256, deterministic RFC 6979) | SHOULD support | ❌ Not implemented |

**Impact:** Interoperability with implementations that prefer P-256 is not possible. `JwksClient` silently skips non-Ed25519 keys.

---

## 5. Governance Features (Missions)

The entire mission lifecycle is unimplemented:

| Feature | Status |
|---------|--------|
| Mission creation (`POST /mission`) | ❌ |
| Mission blob structure (`approver`, `s256`, `approved_tools`, `capabilities`) | ❌ |
| `AAuth-Mission` request header | ❌ |
| Mission claim in resource/auth tokens | ❌ |
| Permission requests (`POST /permission`) for tool calls | ❌ |
| Audit logging (`POST /audit`) | ❌ |
| Mission termination (`mission_terminated` 403) | ❌ |
| Clarification chat loop (202 with `requirement=clarification`) | ❌ |
| Clarification response posting | ❌ |
| Approval requirement (`requirement=approval`) handling | ❌ |

---

## 6. R3 (Rich Resource Requests)

The entire R3 extension is unimplemented:

| Feature | Status |
|---------|--------|
| R3 document model (`version`, `vocabulary`, `operations`, `display`) | ❌ |
| `r3_uri` / `r3_s256` claims in resource tokens | ❌ |
| `r3_granted` / `r3_conditional` claims in auth tokens | ❌ |
| R3 document SHA-256 content addressing (RFC 8785 canonical JSON) | ❌ |
| Authorization endpoint with `r3_operations` parameter | ❌ |
| AS-side R3 document fetch and hash verification | ❌ |
| Resource-side R3 grant enforcement (granted vs conditional) | ❌ |
| Per-call approval flow for conditional operations | ❌ |
| Vocabulary support (MCP, OpenAPI, gRPC, GraphQL, etc.) | ❌ |
| Resource metadata `r3_vocabularies` field | ❌ |

---

## 7. Bootstrap / Token Refresh

The entire bootstrap and refresh lifecycle is unimplemented:

| Feature | Status |
|---------|--------|
| Two-key pattern (durable + ephemeral) | ❌ |
| `jkt-jwt` Signature-Key scheme | ❌ |
| Naming JWT construction (signed by durable key) | ❌ |
| AP enrollment endpoint client | ❌ |
| AP refresh endpoint client | ❌ |
| Self-hosted agent (self-issue tokens, publish JWKS as AP) | ❌ |
| Platform attestation integration (WebAuthn, App Attest, Play Integrity) | ❌ |
| Hardware-backed key storage abstraction | ❌ |

---

## 8. Error Handling Gaps

### 8.1 Signature-Error Header (Authentication Errors)
**Spec:** Resources MUST return `Signature-Error` header on 401 responses with structured error codes.

**Gap:** The SDK's `AAuthVerificationMiddleware` returns bare 401 without `Signature-Error` header. No model for:
- `invalid_request`, `invalid_signature`, `invalid_key`, `unknown_key`
- `invalid_jwt`, `expired_jwt`, `unsupported_algorithm`, `invalid_input`

### 8.2 Token Endpoint Error Model
**Spec:** Structured JSON errors with `error` + `error_description`.

**Gap:** `TokenExchangeClient` handles `access_denied` but does not parse/expose:
- `invalid_request`, `invalid_agent_token`, `expired_agent_token`
- `invalid_resource_token`, `expired_resource_token`
- `interaction_required`, `server_error`

### 8.3 Polling Error Codes
**Spec:** Specific error semantics for polling responses.

**Gap:** `DeferredPoller` handles 202/200 and generic non-success, but does not differentiate:
- `denied` (403) vs `abandoned` (403)
- `expired` (408) vs timeout
- `invalid_code` (410) – must NOT retry
- `slow_down` (429) – increase interval by 5 seconds

### 8.4 Payment Required (402)
**Spec:** AS may return 402 with payment instructions; agent polls Location.

**Gap:** Not handled anywhere in the SDK.

### 8.5 JTI Replay Detection (distinct from Revocation)
**Spec:** All token types carry `jti` (unique token identifier). Receivers SHOULD detect replayed tokens by tracking seen `jti` values within the token's validity window.

**Gap:** Neither `TokenVerifier` nor `AAuthVerificationMiddleware` tracks seen JTI values. A replayed token with a valid signature and unexpired `exp` is accepted every time. This is distinct from §14's token *revocation* (issuer invalidates by JTI before natural expiry):
- **Replay detection** = receiver rejects a `jti` it has seen before within the token's `exp` window (prevents replay attacks)
- **Revocation** = issuer pushes a `jti` into a denylist before its natural expiry (handles compromised tokens)

Both require server-side state (`IJtiStore`), but they serve different threat models and operate at different points in the flow.

---

## 9. Token Verification Gaps

| Verification Step | Status |
|-------------------|--------|
| Verify `typ` matches | ✅ |
| Verify `dwk` matches | ✅ |
| Verify signature via JWKS | ✅ |
| Verify `exp`/`iat` with skew | ✅ |
| Verify `iss` HTTPS | ✅ |
| Verify `aud` matches recipient | ✅ |
| Verify `cnf.jwk` matches HTTP signature key | ❌ Not enforced by SDK (left to caller) |
| Verify `agent_jkt` matches HTTP signature key thumbprint | ❌ Not enforced by SDK |
| Verify `act` claim structure and `act.sub` matches agent | ❌ Not implemented |
| Verify at least one of `sub` or `scope` in auth token | ❌ Not enforced in verifier |
| Verify auth token `scope` ⊆ resource token `scope` (narrowing) | ❌ Not enforced |
| Verify `mission` claim structure | ❌ Not implemented |
| Actor-chain (`act`) walking for delegation depth | ❌ Not implemented |
| Accept `dwk` = either `aauth-person.json` or `aauth-access.json` for auth tokens | ❌ Caller must specify expected `dwk` |

### 9.1 Auth Token Building Gap (`act` claim)

**Spec:** Auth token verification step 8 requires `act` MUST be present and `act.sub` MUST match the agent identifier from the signing context. This is an unconditional MUST.

**Gap:** `AuthTokenBuilder` has **no `Act` property**. Auth tokens built by the SDK (including `MockPersonServer`) are emitted without `act`, making them non-conformant. This is both a **building** and a **verification** gap:
- Building: `AuthTokenBuilder` should require `Act` (with at minimum `sub` = agent identifier)
- Verification: `TokenVerifier` should reject auth tokens missing `act`

### 9.2 Scope Narrowing Enforcement

**Spec:** "Auth token's scope MUST NOT be broader than resource token's scope."

**Gap:** Neither `AuthTokenBuilder` nor `TokenVerifier` enforce that the granted scope is a subset of the requested scope. This is primarily a resource-side obligation (the resource issued the resource token and can compare), but the verifier could optionally accept the original resource-token scope for comparison.

### 9.3 Dual-`dwk` Acceptance for Auth Tokens

**Spec:** Auth tokens may carry `dwk` = `aauth-person.json` (PS-issued) or `dwk` = `aauth-access.json` (AS-issued). Both are valid.

**Gap:** `TokenVerifier.VerifyWithJwksAsync` takes a single `expectedDwk` parameter. When verifying an auth token, the caller must know in advance whether the issuer is a PS or AS. For the 4-party flow, the resource receives an auth token and needs to accept either `dwk` value, discovering the issuer's JWKS via the appropriate well-known path.

---

## 10. Discovery & Metadata Gaps

| Feature | Status |
|---------|--------|
| Resource metadata server (`aauth-resource.json`) | ✅ |
| Resource JWKS server | ✅ |
| PS metadata server (`aauth-person.json`) | ❌ Server-side not implemented |
| AP metadata server (`aauth-agent.json`) | ❌ Server-side not implemented |
| AS metadata server (`aauth-access.json`) | ❌ Server-side not implemented |
| `signature_window` metadata field | ✅ (optional in resource metadata) |
| `scope_descriptions` metadata field | ✅ (optional in resource metadata) |
| `r3_vocabularies` metadata field | ❌ |
| `identity_scopes` in PS metadata | ❌ |
| `login_endpoint` in PS metadata | ❌ |
| `token_endpoint` client resolution | ✅ (via MetadataClient) |
| Metadata HTTPS validation on fetch | ❌ (MetadataClient does not validate URL scheme) |

---

## 11. Agent Identifier Validation

**Spec:** `aauth:local@domain` format with strict character rules.

**Gap:** No SDK utility for:
- Parsing agent identifiers (`aauth:` prefix, `local@domain` split)
- Validating local-part characters (lowercase ASCII letters, digits, `-`, `_`, `+`, `.`)
- Validating max length (255 chars for local part)
- Normalizing/comparing agent identifiers

---

## 12. Server Identifier Validation

**Spec:** Strict rules for server URLs: `https` only, host-only (no port/path/query/fragment), no trailing slash, lowercase, ACE form for IDN.

**Gap:** `AAuthUrl.IsHttpsOrLoopback` validates scheme but does **not** enforce:
- Host-only (rejects path/query/fragment)
- No trailing slash
- Lowercase normalization
- ACE form for internationalized domain names
- No port in production URLs

**Loopback port caveat:** The spec's "no port" rule applies to *server identifiers* (issuer URLs). However, the existing samples (`WhoAmI` on `:5000`, `MockPersonServer` on `:5100`, `GuidedTour` on `:5400`) use `http://localhost:<port>` as issuer URLs during development. The new `AAuthServerId` validator must carve out port allowance for loopback addresses — otherwise all existing samples and integration tests break. The spec is silent on whether loopback issuers may include ports; this is a pragmatic dev-mode exemption that MUST NOT extend to non-loopback hosts.

---

## 13. Conformance Test Gaps

### Root Cause

The conformance suite covers **protocol machinery** (agent-token structure, resource-token structure, HTTP signatures, discovery) but misses **semantic verification requirements** (act chains, scope narrowing, binding enforcement, capabilities). This happened because:
- The original plan's Phase 2 §2.9 scoped conformance to receiver-side agent-token and resource-token tests only.
- Auth-token conformance was implicitly deferred — `AuthTokenBuilder` and `TokenVerifier` shipped without corresponding spec-traceable tests.
- Features like `act` walking, scope narrowing, `AAuth-Capabilities`, and JTI replay were never implemented, so there was nothing to test.

### Currently Covered (47 tests, Phases 1–3 of original plan):
- ✅ Agent token structure (17 tests) — header, required/optional claims, lifetime
- ✅ Agent token verification (7 tests) — sig, alg=none, expired, typ, dwk, wrong key
- ✅ Resource token structure (11 tests) — header, required claims, lifetime ≤ 5min
- ✅ HTTP signature profile (4 tests) — covered components, created parameter, verifier rejection
- ✅ Signature-Key header (5 tests) — jwt format, cnf.jwk extraction, control chars
- ✅ Discovery (7 tests) — metadata fields, JWKS key structure

### Not Covered (by remediation phase):

**Phase 1 (verification hardening):**
- ❌ Auth token structure conformance (header, required claims, lifetime)
- ❌ Auth token verification conformance (`act` required, `act.sub` match, binding, dual-`dwk`)
- ❌ Scope narrowing conformance (auth scope ⊆ resource scope)
- ❌ Error response format conformance (`Signature-Error` header, JSON error body)
- ❌ Agent identifier format conformance
- ❌ Server identifier format conformance

**Phase 2 (4-party + replay):**
- ❌ Federated (4-party) flow conformance
- ❌ JTI replay detection conformance
- ❌ Authorization endpoint conformance
- ❌ Token revocation conformance

**Phases 3–7 (features):**
- ❌ ECDSA P-256 algorithm conformance
- ❌ Bootstrap/refresh conformance
- ❌ Mission lifecycle conformance
- ❌ R3 flow conformance
- ❌ Resource-managed access flow conformance
- ❌ Third-party login flow conformance
- ❌ Call-chaining (resource-to-resource delegation) conformance
- ❌ `AAuth-Capabilities` header conformance

---

## 14. Miscellaneous Gaps

| Feature | Spec Reference | Status |
|---------|---------------|--------|
| `Authorization: AAuth <opaque-token>` header (resource-managed) | Protocol §Resource-Managed | ❌ |
| `AAuth-Capabilities` request header (`interaction`, `clarification`, `payment`) | Protocol §Capabilities | ❌ |
| `AAuth-Mission` request header | Protocol §Missions | ❌ |
| Third-party login flow | Protocol §Third-Party Login | ❌ |
| Call chaining (resource acts as agent) | Protocol §Call Chaining | ❌ |
| `upstream_token` parameter in PS→AS federation | Protocol §Federated | ❌ |
| `tenant` claim in auth tokens | Protocol §Auth Token | ❌ |
| `login_hint` parameter at PS token endpoint | Protocol §PS Token | ❌ |
| `justification` parameter at PS token endpoint | Protocol §PS Token | ❌ |
| `platform` / `device` parameters | Protocol §PS Token | ❌ |
| Token revocation by JTI | Protocol §Revocation | ❌ |
| JTI replay detection (receiver-side) | Protocol §Verification | ❌ |
| Scope description validation against PS identity scopes | Protocol §Scopes | ❌ |
| `claims` requirement type (identity claims request) | Protocol §Requirements | ❌ |

### 14.1 `AAuth-Capabilities` Header

**Spec:** Agents SHOULD include `AAuth-Capabilities` header listing supported interaction modes: `interaction` (can direct user to URL), `clarification` (can engage in chat), `payment` (can handle 402 flows).

**Gap:** The SDK's `AAuthSigningHandler` never emits this header. Servers that check capabilities before offering deferred paths may fall back to denial rather than offering the interaction/clarification flow. Neither builder, handler, nor any configuration surface exposes capability advertisement.

**Impact:** Without this header, a compliant server cannot know whether to return `requirement=interaction` (useless if the agent cannot present a URL to the user) or simply deny access.

---

## Priority Recommendations

### High Priority (Core protocol completeness)
1. **Authorization endpoint** – Enables resource-initiated flows without relying on 401 challenge
2. **`act` claim verification** – Security-critical for delegation chain validation
3. **`cnf.jwk` binding enforcement** – Proof-of-possession must be verified, not optional
4. **Signature-Error header** – Spec-mandated error reporting on 401
5. **Agent/Server identifier validation** – Prevents security issues from malformed identifiers
6. **4-party federated flow** – Required for AS-mediated authorization

### Medium Priority (Ecosystem enablement)
7. **Token refresh / `jkt-jwt` scheme** – Needed for long-running agents
8. **ECDSA P-256 support** – Interoperability with non-EdDSA implementations
9. **Mission lifecycle** – Governance for autonomous agents
10. **R3 support** – Structured operation-level authorization
11. **Token revocation** – Security hygiene for compromised tokens
12. **Auth token conformance tests** – Verify PS implementation correctness

### Lower Priority (Specialized flows)
13. **Resource-managed access (2-party)** – Simpler deployments without PS
14. **Third-party login** – Enterprise SSO integration
15. **Call chaining** – Multi-resource orchestration
16. **Platform attestation** – Mobile/hardware security
17. **Payment (402) flow** – Commercial API access

---

## Appendix: SDK Module Coverage Map

```
src/AAuth/
├── Agent/                  ← Partial (3-party only, no mission/permission)
│   ├── ChallengeHandler    ✅ 3-party token exchange
│   ├── DeferredPoller      ✅ Polling with retry
│   ├── TokenExchangeClient ✅ PS token endpoint
│   └── AAuthTokenHolder    ✅ Token state
├── Crypto/                 ← Complete for Ed25519
│   ├── AAuthKey            ✅ Ed25519 only
│   └── KeyStore            ✅ File-based storage
├── Discovery/              ← Client-side complete, server-side partial
│   ├── MetadataClient      ✅ Fetch + cache
│   └── JwksClient          ✅ Resolve + cache
├── Headers/                ← Partial
│   ├── AAuthInteraction    ✅ Interaction requirement
│   └── AAuthRequirement    ✅ Auth-token requirement (others parsed but unused)
├── HttpSig/                ← Complete for jwt scheme
│   ├── AAuthSigningHandler ✅ Request signing
│   ├── AAuthVerifier       ✅ Signature verification
│   ├── SignatureKeyHeader   ✅ jwt scheme only
│   ├── SignatureKeyParser   ✅ JWT extraction
│   └── Middleware          ✅ ASP.NET Core integration
├── Server/                 ← Resource only
│   └── WellKnownEndpoints  ✅ Resource metadata + JWKS
└── Tokens/                 ← Builders complete, verification partial
    ├── AgentTokenBuilder   ✅
    ├── ResourceTokenBuilder✅
    ├── AuthTokenBuilder    ✅ (untested for 4-party)
    ├── TokenVerifier       ✅ (missing cnf/act/agent_jkt binding)
    └── JwtWriter           ✅ (internal)
```
