# Post-Implementation Report: AAuth .NET SDK Gap Remediation

> Completed 2026-05-22.  
> Branch: `feat/gap-remediation-plan-updates`  
> Commits: `4b48c04` (Phase 1), `4341db9` (Phases 2–7)

## Summary

This implementation closed the spec-conformance gaps catalogued in
[`gaps.md`](./gaps.md) for agent-side and resource-side functionality.
The Access Server (AS) and Agent Provider (AP) are not implemented as
hosted server roles in the SDK — the AS is an external service, and the
PS is kept only as a sample (`samples/MockPersonServer/`).

**Final test counts**: 130 unit tests + 176 conformance tests = 306 total, all passing.

---

## What was done

### Phase 1 — Verification & error-reporting hardening

| Item | Status | Deliverable |
|------|--------|-------------|
| PoP binding enforcement (§9) | Done | `TokenVerifier.VerifyAuthToken()` enforces `cnf.jwk` binding, `act` chain validation |
| Structured errors — signature (§8.1) | Done | `SignatureError` enum + `Signature-Error` header in middleware |
| Structured errors — token endpoint (§8.2) | Done | `TokenError` enum |
| Structured errors — polling (§8.3) | Done | `PollingError` enum + `PollingErrorException`, `slow_down` adds 5s |
| Identifier validation (§11, §12) | Done | `AAuthServerId`, `AAuthAgentId` with loopback carve-out |
| Auth token verification completeness (§9.2, §9.3) | Done | Dual-`dwk` acceptance, scope narrowing, `act.sub` equality |
| Conformance suite expansion | Done | Auth token structure/verification tests, error tests, identifier tests |

### Phase 2 — Resource-side discovery + replay detection

| Item | Status | Deliverable |
|------|--------|-------------|
| JTI replay detection (§8.5) | Done | `IJtiStore` + `InMemoryJtiStore`, wired into `AAuthVerificationMiddleware` |
| Token revocation endpoint | Done | `RevocationEndpoint` (POST /revoke) |
| Resource metadata extensions | Done | `authorization_endpoint`, `revocation_endpoint` fields in `AAuthResourceMetadataOptions` |
| Agent-side typed discovery | Done | `ServerMetadata`, `ResourceMetadata`, `MetadataClientExtensions` |

### Phase 3 — Signature-Key scheme expansion + ECDSA

| Item | Status | Deliverable |
|------|--------|-------------|
| `IAAuthKey` interface | Done | Extracted from `AAuthKey`; enables pluggable key types |
| ECDSA P-256 (ES256) | Done | `EcdsaAAuthKey` using BouncyCastle `HMacDsaKCalculator` (RFC 6979) |
| `hwk` scheme | Done | `SignatureKeyHeader.FormatHwk()`, `SignatureKeyParser.ParseAny()` |
| `jwks_uri` scheme | Done | `SignatureKeyHeader.FormatJwksUri()`, parser extracts `uri` + `kid` |
| `jkt-jwt` scheme | Done | `SignatureKeyHeader.FormatJktJwt()`, parser extracts `jkt` + JWT payload |
| `ParsedSignatureKeyInfo` model | Done | Unified parse result for all 4 schemes |

### Phase 4 — Bootstrap & refresh

| Item | Status | Deliverable |
|------|--------|-------------|
| `IKeyStore` + `InMemoryKeyStore` | Done | Key persistence abstraction for agents |
| `IPlatformAttestor` + `NoopAttestor` | Done | Extensibility seam for WebAuthn/App Attest/Play Integrity |
| `AgentProviderClient` | Done | `EnrolAsync()` and `RefreshAsync()` for agent↔AP communication |

### Phase 5 — Missions (governance)

| Item | Status | Deliverable |
|------|--------|-------------|
| `AAuthMission` model | Done | Parsed from PS/AS JSON responses |
| `AAuthMissionHeader` | Done | Header formatting for outbound agent requests |

### Phase 7 — Resource-managed + specialised flows

| Item | Status | Deliverable |
|------|--------|-------------|
| `AAuth-Capabilities` header (§14.1) | Done | `AAuthCapabilitiesHeader` + emission in `AAuthSigningHandler` |
| `IOpaqueTokenStore` + `InMemoryOpaqueTokenStore` | Done | 2-party resource-managed access token store |
| `IInteractionPresenter` + `ConsoleInteractionPresenter` | Done | Extensibility seam for user interaction presentation |

---

## What was not done (and why)

### Access Server (AS) hosted implementation

**Reason**: The user clarified that an existing external AS can be reused.
The SDK provides the agent-side client for interacting with any conformant
AS (discovery, token exchange) but does not host the AS role itself. The
`AuthTokenBuilder` with `Dwk = AccessDwk` remains available for testing.

### Person Server (PS) as SDK infrastructure

**Reason**: The user clarified the PS is kept only as a sample
(`samples/MockPersonServer/`). No PS-hosting infrastructure ships in the
SDK library. The MockPersonServer sample is fully functional for
development and testing.

### Agent Provider (AP) hosted endpoints

**Reason**: Same as AS — the AP is an external service. The SDK provides
`AgentProviderClient` for agents to enrol and refresh with any conformant AP.

### Phase 6 — R3 (Rich Resource Requests)

**Reason**: R3 requires a new NuGet dependency (`JsonCanonicalizer` for
RFC 8785 JCS canonicalisation), vocabulary parsers (MCP, OpenAPI), and
content-addressed document storage. This represents a significant new
subsystem with its own complexity. Deferred because:

1. No immediate consumer need was identified in the current samples.
2. Adds an external dependency (policy requires `research.md` justification).
3. The extensibility seam (`IR3Vocabulary`) is documented in the plan for
   when demand materialises.

### Full mission lifecycle endpoints (POST /mission, /permission, /audit)

**Reason**: These are server-side PS endpoints. Since PS is sample-only,
the mission *model* and *header* (agent-side) were implemented, but the
server-side endpoints for hosting mission flows were not. The
`DeferredPoller` already handles `requirement=clarification` and
`requirement=approval` from Phase 1.

### Third-party login, call chaining, payment (§14)

**Reason**: These are specialised protocol extensions. The foundational
pieces are in place (`AAuth-Capabilities` header declares support,
`IInteractionPresenter` handles interaction URLs, `DeferredPoller` handles
polling states), but the full protocol flows for login hints, upstream
token federation, and 402 payment handling are deferred as they require
integration with external identity and payment providers.

### Platform attestation implementations

**Reason**: WebAuthn/App Attest/Play Integrity are platform-specific and
each is a project in its own right. The `IPlatformAttestor` seam ships;
implementations are consumer-provided.

### `JwksClient` dispatching on `IAAuthKey` for multi-algorithm

**Reason**: `JwksClient` currently handles Ed25519 keys. Full
multi-algorithm dispatch (resolving ES256 keys from JWKS, routing to the
correct `IAAuthKey` implementation) requires updating the verification
pipeline to be algorithm-polymorphic. The `IAAuthKey` interface and
`EcdsaAAuthKey` are ready; the wiring through `JwksClient` → `TokenVerifier`
→ `AAuthVerifier` is an incremental follow-up.

---

## Architecture decisions made

| Decision | Rationale |
|----------|-----------|
| No AS/AP server hosting in SDK | Existing external services; SDK focuses on agent + resource roles |
| BouncyCastle for ECDSA P-256 signing | RFC 6979 deterministic-K required; BCL `ECDsa` doesn't expose it |
| `IAAuthKey` interface (not abstract class) | Extensible for hardware keys, cloud KMS, future algorithms |
| In-memory defaults for all stores | Ship working defaults; consumers plug in Redis/SQL/KMS via DI |
| `ParsedSignatureKeyInfo` over scheme-specific types | Single parse method handles all 4 schemes; callers switch on `Scheme` |
| PS stays as sample only | User direction; keeps SDK library focused |

---

## Test coverage summary

| Suite | Before | After | Delta |
|-------|--------|-------|-------|
| `AAuth.Tests` (unit) | 130 | 130 | +0 |
| `AAuth.Conformance` | 135 | 176 | +41 |
| **Total** | **265** | **306** | **+41** |

New conformance test files:
- `AgentTokens/AgentBootstrapTests.cs` — key store, platform attestor
- `Discovery/JtiStoreAndRevocationTests.cs` — replay detection, revocation endpoint
- `HttpSignatures/EcdsaKeyTests.cs` — P-256 key operations, RFC 6979 determinism
- `HttpSignatures/SignatureKeySchemesTests.cs` — all 4 Signature-Key scheme formats
- `HttpSignatures/CapabilitiesHeaderTests.cs` — capabilities header + signing handler emission
- `ResourceTokens/OpaqueTokenStoreTests.cs` — 2-party opaque token lifecycle
