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
| Signature-Key Schemes | 4 | 1 (`jwt`) | 3 |
| Cryptographic Algorithms | 2 | 1 (EdDSA/Ed25519) | 1 |
| Governance (Missions) | Full lifecycle | None | Full |
| R3 (Rich Resource Requests) | Full lifecycle | None | Full |
| Bootstrap / Refresh | Full lifecycle | None | Full |
| Error Handling | Detailed error model | Partial | Significant |
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
| Verify `mission` claim structure | ❌ Not implemented |
| Actor-chain (`act`) walking for delegation depth | ❌ Not implemented |

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

---

## 13. Conformance Test Gaps

### Currently Covered (Phase 2):
- ✅ Agent token structure & verification
- ✅ Resource token structure
- ✅ HTTP signature profile (covered components, Signature-Key header)
- ✅ Discovery (resource metadata, JWKS)

### Not Covered:
- ❌ Auth token structure conformance tests
- ❌ Auth token verification conformance tests
- ❌ Resource-managed access flow conformance
- ❌ Federated (4-party) flow conformance
- ❌ Authorization endpoint conformance
- ❌ Token revocation conformance
- ❌ Mission lifecycle conformance
- ❌ R3 flow conformance
- ❌ Bootstrap/refresh conformance
- ❌ Error response format conformance (`Signature-Error` header, JSON error body)
- ❌ Agent identifier format conformance
- ❌ Server identifier format conformance
- ❌ Third-party login flow conformance
- ❌ Call-chaining (resource-to-resource delegation) conformance
- ❌ ECDSA P-256 algorithm conformance

---

## 14. Miscellaneous Gaps

| Feature | Spec Reference | Status |
|---------|---------------|--------|
| `Authorization: AAuth <opaque-token>` header (resource-managed) | Protocol §Resource-Managed | ❌ |
| `AAuth-Mission` request header | Protocol §Missions | ❌ |
| Third-party login flow | Protocol §Third-Party Login | ❌ |
| Call chaining (resource acts as agent) | Protocol §Call Chaining | ❌ |
| `upstream_token` parameter in PS→AS federation | Protocol §Federated | ❌ |
| `tenant` claim in auth tokens | Protocol §Auth Token | ❌ |
| `login_hint` parameter at PS token endpoint | Protocol §PS Token | ❌ |
| `justification` parameter at PS token endpoint | Protocol §PS Token | ❌ |
| `platform` / `device` parameters | Protocol §PS Token | ❌ |
| Token revocation by JTI | Protocol §Revocation | ❌ |
| Scope description validation against PS identity scopes | Protocol §Scopes | ❌ |
| `claims` requirement type (identity claims request) | Protocol §Requirements | ❌ |

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
