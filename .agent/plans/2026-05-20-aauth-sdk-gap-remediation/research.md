# Gap Remediation: Research Document

> Research-only. No implementation.
> Created 2026-05-20 as part of plan `2026-05-20-aauth-sdk-gap-remediation`.
> Companion to [`implementation-plan.md`](./implementation-plan.md) and
> [`gaps.md`](./gaps.md).

This document extends the plan's recommendations with deeper analysis:
library options, spec-text citations, reference-implementation precedents,
and trade-off matrices. Where research reveals a better path than the plan
currently states, the plan is amended and the change is noted here.

---

## 1. Proof-of-Possession Binding (Plan §1.1)

### 1.1 What the spec mandates

The protocol spec (§Verification, steps 5–6) requires the server to "obtain
the public key from the `Signature-Key` header" and "verify the HTTP Message
Signature using the obtained public key". Token verification then requires
the signed key to match the binding claim:

- Agent/auth tokens: `cnf.jwk` must equal the HTTP signature key.
- Resource tokens: `agent_jkt` must equal the JWK thumbprint of the HTTP
  signature key.

There is no opt-out language — these are unconditional MUSTs.

### 1.2 Reference implementations

| SDK | How binding is enforced |
|---|---|
| **packages-js** `mcp-server/verify.ts` | Immediately after signature verification, compares `payload.cnf.jwk` to the key extracted from `Signature-Key`. Hard-fails if mismatch. |
| **aauth-go-library** | Calls `VerifyTokenBinding(token, sigKey)` inline during ExtAuthz `Check()`. No option to skip. |
| **aauth-python-library** | `verify_aauth_request()` raises `TokenBindingError` if `cnf.jwk` thumbprint ≠ HTTP sig key thumbprint. |

### 1.3 Recommendation (unchanged from plan)

Enforce inside `TokenVerifier` as a mandatory step, not caller-opt-in.
The reference implementations unanimously hard-wire this check.

### 1.4 `act` chain depth

The spec defines `act` (actor chain) without prescribing a maximum depth.
However, unbounded recursion is a denial-of-service vector.

**Reference behaviour**: the Go library caps at depth 5 (`MAX_ACT_DEPTH`);
the JS SDK does not implement `act` walking yet.

**Recommendation**: default `MaxActDepth = 10` (generous for any real-world
delegation), configurable via `TokenVerifierOptions`. Document that exceeding
the limit returns `invalid_jwt` error code.

---

## 2. Structured Error Model (Plan §1.2)

### 2.1 Signature-Error header

The spec references `[@!I-D.hardt-httpbis-signature-key]` for the error
header format. From the verification section (§Verification step-by-step),
the following error codes are normative:

| Condition | Code |
|---|---|
| Missing headers | `invalid_request` |
| Required components not covered | `invalid_input` (with `required_input`) |
| Created outside window | `invalid_signature` |
| Unsupported algorithm | `unsupported_algorithm` |
| Key parse failure | `invalid_key` |
| Key not found at `jwks_uri` | `unknown_key` |
| JWT scheme fails verification | `invalid_jwt` |
| JWT expired | `expired_jwt` |
| Signature verification fails | `invalid_signature` |

The header format (per Signature-Key draft) is a structured Dictionary with
a string value: `Signature-Error: sig="invalid_signature"`.

### 2.2 Token endpoint errors

The spec's table (§Token Endpoint Error Codes) enumerates seven codes. Each
is paired with an HTTP status.

### 2.3 Polling errors

Five polling codes (§Polling Error Codes), each paired with a status.

### 2.4 Design options for .NET modelling

| Option | Description | Pros | Cons |
|---|---|---|---|
| **A: Three enums** | `SignatureErrorCode`, `TokenErrorCode`, `PollingErrorCode` | Exhaustive match; compile-time safety | More types; consumer confusion about which to catch |
| **B: Single enum with [Category]** | `AAuthErrorCode` with metadata attribute | One type; simpler discovery | Allows nonsense combos; can't pattern-match by surface |
| **C: Hierarchy of result types** | `Result<T, TError>` pattern per surface | Functional; no exceptions on expected paths | Diverges from idiomatic .NET for HTTP operations |

**Recommendation**: Option A (three enums). Aligns with the spec's disjoint
code sets. The `Signature-Error` surface is server-only (emitted by
middleware); the token and polling surfaces are client-only (parsed by
`TokenExchangeClient` and `DeferredPoller`). No caller ever needs to handle
all three.

### 2.5 DeferredPoller `slow_down` behaviour

Spec: "increase interval by 5 seconds" on 429. Implementation: when
`DeferredPoller` receives 429, it adds 5 s to the *current* interval
(not the default), and never resets until the terminal response. This
matches the RFC 8628 device-code `slow_down` semantics the spec echoes.

### 2.6 `invalid_code` semantics

Spec: 410 Gone → code already consumed. Implementation: poller MUST abort
without retry, surface a typed `PollingDeniedException` (not a generic
`HttpRequestException`). The plan already covers this but does not call out
that 410 *also* means the resource should not be cached (RFC 9110 §15.4.11),
so the poller must NOT cache the polling URL for reuse.

---

## 3. Identifier Validation (Plan §1.3)

### 3.1 Server identifiers — spec rules

From §Server Identifiers:

1. MUST use `https` scheme.
2. MUST contain only scheme and host (no port, path, query, or fragment).
3. MUST NOT include a trailing slash.
4. MUST be lowercase.
5. IDN MUST use ACE form (A-labels, RFC 5890).
6. Comparison: exact string match.

### 3.2 Gap vs. current `AAuthUrl.IsHttpsOrLoopback`

Current code (`src/AAuth/AAuthUrl.cs:23-34`) only validates scheme +
loopback. It does **not** check:

- No path/query/fragment (allows `https://example.com/path`)
- No port (allows `https://example.com:8443`)
- No trailing slash (allows `https://example.com/`)
- Lowercase (allows `https://Example.COM`)
- ACE form (does not normalise IDN)

### 3.3 Proposed `AAuthServerId` design

```
readonly record struct AAuthServerId : IEquatable<AAuthServerId>, ISpanParsable<AAuthServerId>
{
    public string Value { get; }  // Canonical form: "https://lowercase-ace-host"
    public static AAuthServerId Parse(string input);
    public static bool TryParse(string? input, out AAuthServerId result);
}
```

Parse normalises: lowercase the host, apply `IdnMapping.GetAscii` for IDN,
reject if any of the six rules fail. `ToString()` returns the canonical form.
Equality is ordinal string comparison on `Value`.

**Loopback exemption for dev**: add a static `AAuthServerId.AllowLoopback`
flag (defaults to `false`). When `true`, `http://localhost` and
`http://127.0.0.1` pass rule 1. This preserves dev ergonomics from the
original `AAuthUrl` helper. Production code must not set this flag; the
README will document this.

### 3.4 Agent identifiers — spec rules

From §Agent Identifiers:

- URI scheme `aauth:`.
- Format: `aauth:local@domain`.
- Local part: `[a-z0-9\-_+.]+`, non-empty, ≤ 255 chars.
- Domain: valid domain name per server-identifier rules (without scheme).
- Comparison: case-sensitive exact string match (local is lowercase by
  construction; domain is already ACE).

### 3.5 Proposed `AAuthAgentId` design

```
readonly record struct AAuthAgentId : IEquatable<AAuthAgentId>, ISpanParsable<AAuthAgentId>
{
    public string LocalPart { get; }
    public string Domain { get; }       // ACE-normalised
    public string Value { get; }        // "aauth:local@domain"
    public static AAuthAgentId Parse(string input);
    public static bool TryParse(string? input, out AAuthAgentId result);
}
```

### 3.6 Where to hook validation

| Call site | Current input | New validator |
|---|---|---|
| `AgentTokenBuilder.Issuer` | `string` | `AAuthServerId.Parse(value)` |
| `AgentTokenBuilder.PersonServer` | `string` | `AAuthServerId.Parse(value)` |
| `ResourceTokenBuilder.Issuer` | `string` | `AAuthServerId.Parse(value)` |
| `AuthTokenBuilder.Issuer` | `string` | `AAuthServerId.Parse(value)` |
| `MetadataClient.FetchAsync(url)` | `string` | `AAuthServerId.Parse(url)` |
| `TokenExchangeClient` PS URL | `string` | `AAuthServerId.Parse(url)` |
| Agent identifier claims (`agent`, `sub`) | `string` | `AAuthAgentId.Parse(value)` |

### 3.7 Alternative: URI type wrapper instead of struct

Could use `class AAuthServerId` to allow null-ref without `?` boxing.
Rejected: the struct approach matches `IPAddress`, `Guid`, `DateOnly` — all
BCL identity types that represent small validated values. The `?` suffix is
explicit enough.

---

## 4. ECDSA P-256 with Deterministic Signatures (Plan §3.3)

### 4.1 Spec requirement

> "Agents and resources SHOULD support ECDSA using P-256 with deterministic
> signatures ([@!RFC6979])."

This is a SHOULD — not a MUST — but interop with non-EdDSA peers fails
without it.

### 4.2 .NET crypto landscape for RFC 6979

| Library | RFC 6979 support | Notes |
|---|---|---|
| BCL `ECDsa` | **No** — always random-K | API is sealed; cannot inject K-generation |
| BouncyCastle `ECDsaSigner` + `HMacDsaKCalculator` | **Yes** — RFC 6979 built-in | Already a direct dependency (`2.6.2`) |
| `NSec.Cryptography` | No ECDSA at all | Ed25519 only |

### 4.3 Recommendation

Use BouncyCastle for **signing** (deterministic), BCL for **verification**
(deterministic-K is irrelevant for verifiers — they just check the (r, s)
pair against the message and public key). This avoids BouncyCastle's heavier
`ECPoint` math on the hot verification path and reuses the BCL's
hardware-accelerated implementation.

### 4.4 JWK `alg` value

The spec says "See the IANA JSON Web Signature and Encryption Algorithms
registry". For P-256 deterministic, the standard `alg` value is `ES256` —
RFC 6979 does not change the algorithm identifier, only the nonce generation.

### 4.5 Impact on `AAuthKey`

`AAuthKey` currently wraps BouncyCastle `Ed25519PrivateKeyParameters` /
`Ed25519PublicKeyParameters`. Options:

| Option | Description | Pros | Cons |
|---|---|---|---|
| **A: Discriminated union** | `AAuthKey` holds either `Ed25519*` or `ECPrivateKeyParameters` / BCL `ECDsa` | Simple dispatch; single type | Growing match arms |
| **B: Interface + two implementations** | `IAAuthKey { Algorithm, Sign, PublicJwk }` + `Ed25519AAuthKey`, `EcdsaAAuthKey` | Open for extension; testable | More types; factory needed |
| **C: Keep struct, add `Algorithm` property** | Internal union pattern (tagged field) | Minimal API change; backward compat | Internal complexity |

**Recommendation**: Option B (interface + implementations). Reason: future
algorithms (e.g. Ed448, dilithium-ML-DSA for PQC) are plausible, and the
interface pattern lets consumers bring their own (hardware-backed keys for
example) without patching the SDK.

**Plan amendment**: the plan states "AAuthKey becomes algorithm-polymorphic"
— this research confirms the design shape should be an interface (`IAAuthKey`)
rather than extending the existing struct. The plan's text is amended to note
this.

---

## 5. Signature-Key Scheme Expansion (Plan §3.1, §3.2)

### 5.1 Scheme inventory (from spec §Keying Material)

| Scheme | When used | Key source |
|---|---|---|
| `jwt` | Identity-based, PS-asserted, federated | Decode JWT → `cnf.jwk` |
| `hwk` | Pseudonym (direct public key) | Inline JWK in header |
| `jkt-jwt` | Two-key delegation (refresh, bootstrap) | Decode naming JWT → ephemeral key |
| `jwks_uri` | Self-hosted agents (publish own JWKS) | Fetch JWKS → match by `kid` |

### 5.2 `hwk` parsing

Format: `sig=hwk;jwk={...}` — the JWK is a bare JSON object (not
quoted-string). RFC 8941 models this as an Inner List with parameters.

Implementation: parse the `jwk` parameter value as a JSON object, construct
an `IAAuthKey` (public-only). No network fetch needed.

### 5.3 `jwks_uri` verification flow

1. Extract `jwks_uri` URL from header.
2. Validate URL against `AAuthServerId` rules (HTTPS, host-only... wait — 
   `jwks_uri` may include a path like `/.well-known/jwks.json`). The spec's
   server-identifier rules apply to *issuer URLs*, not endpoint URLs. The
   `jwks_uri` is an *endpoint URL* — the spec's §Endpoint URLs section says
   MUST use `https`, MUST NOT contain fragment. Paths and ports are allowed.
3. Delegate to `JwksClient.ResolveAsync(jwksUri, kid)`.
4. Match `kid` from the `Signature` (or from the JWT's `kid` header if the
   naming JWT is present).

**Finding**: `JwksClient` currently takes a `Uri` and resolves by `kid`.
This is already the right shape for `jwks_uri`. The only gap is that
`JwksClient` currently only parses Ed25519 keys — Phase 3's ECDSA work fixes
that.

### 5.4 `jkt-jwt` verification flow (two-key)

1. Extract the naming JWT from `Signature-Key`.
2. Decode the naming JWT header → `kid` (thumbprint of durable key).
3. Fetch the durable key from the AP's JWKS (via `JwksClient`, using the
   AP URL from the naming JWT's `iss`).
4. Verify the naming JWT signature against the durable key.
5. Extract the ephemeral public key from the naming JWT payload (e.g.
   `cnf.jwk`).
6. Verify the HTTP message signature against the ephemeral key.

This is two verification layers, both of which the SDK already knows how to
do individually. The orchestration is new.

### 5.5 Caching considerations for `jwks_uri`

The existing `JwksClient` already:
- Caches per-URI with a 1-hour TTL.
- Rate-limits refreshes to once per minute.
- Supports `kid`-miss triggered refresh.

This is sufficient. No new caching infrastructure needed.

---

## 6. Bootstrap & Refresh (Plan §4)

### 6.1 Two-key model spec digest

From `draft-hardt-aauth-bootstrap` §Two-Key Refresh:

1. Agent generates fresh ephemeral key pair.
2. Agent constructs naming JWT **signed by durable key** naming the ephemeral
   public key (via `cnf.jwk`).
3. Agent signs the refresh POST with **ephemeral key** under `scheme=jkt-jwt`.
4. AP verifies: durable-key sig on naming JWT, looks up enrolment by durable
   JKT, verifies HTTP sig against ephemeral key, applies policy.
5. AP returns new agent token with `cnf.jwk` = ephemeral public key.
6. Agent discards old ephemeral key, uses new token + new ephemeral key until
   next refresh.

### 6.2 KeyStore schema evolution

Current `KeyStore` persists a single JWK file per agent under
`~/.aauth/keys/{thumbprint}.json`. The two-key model needs:

| Item | Storage |
|---|---|
| Durable key | Persisted long-term (file or future HSM) |
| Current ephemeral key | Persisted transiently (lost on crash is acceptable — triggers re-enrol) |
| Agent token (current) | Persisted alongside ephemeral key |

Proposal: extend the store to a directory structure:

```
~/.aauth/keys/
├── {durable-jkt}/
│   ├── durable.jwk       (the durable private key)
│   ├── ephemeral.jwk     (current ephemeral private key)
│   └── agent-token.jwt   (current agent token, text file)
```

A `version` field in a `meta.json` alongside the key files signals the store
format. Old single-file stores are migrated on first load by creating the
directory and moving the file to `durable.jwk`.

### 6.3 Platform attestation seam

From the bootstrap spec, attestation is "optional" and AP-policy-dependent.
The SDK needs only to provide a hook where the refresh request can include
platform-specific evidence. Shape:

```csharp
public interface IPlatformAttestor
{
    /// Produce attestation evidence for the given server nonce.
    /// Returns null if attestation is not available/required.
    Task<byte[]?> AttestAsync(byte[] serverNonce, CancellationToken ct);
}
```

The `NoopAttestor` returns null. A future WebAuthn or App Attest implementor
fills the byte array with the platform assertion. The refresh client
serialises non-null evidence into the refresh POST body per AP contract.

---

## 7. Mission System (Plan §5)

### 7.1 Spec structure (protocol §Missions)

- `POST /mission` at PS: propose mission (JSON body with `description`,
  `approved_tools`, `capabilities`, `justification`).
- PS may return 202 with `requirement=clarification` or
  `requirement=approval`.
- On approval, PS returns the mission blob (includes `s256` of canonical
  mission).
- Agent carries `AAuth-Mission: s256="<hash>"` on subsequent requests.
- `POST /permission` for per-call tool-use consent.
- `POST /audit` for mission event logging.
- 403 `mission_terminated` if PS revokes the mission.

### 7.2 In-memory store design

```csharp
public interface IMissionStore
{
    Task<Mission> CreateAsync(MissionProposal proposal, CancellationToken ct);
    Task<Mission?> GetAsync(string s256, CancellationToken ct);
    Task TerminateAsync(string s256, string reason, CancellationToken ct);
}
```

An `InMemoryMissionStore` backed by `ConcurrentDictionary<string, Mission>`
is the default. Production consumers swap in their own durable
implementation.

### 7.3 Clarification loop

The spec uses the standard deferred-response pattern (202 + Location +
Retry-After). `DeferredPoller` already handles this; the only new work is
teaching the agent-side `MissionClient` to detect
`requirement=clarification`, present the clarification prompt to the caller,
post the clarification response to the interaction URI, and re-poll.

This is a state-machine on the client: propose → (loop: clarify) → approved
/ denied.

### 7.4 `AAuth-Mission` header format

Structured Dictionary: `AAuth-Mission: s256="<base64url-hash>"`.

Implementation: add a static formatter/parser in `Headers/AAuthMissionHeader.cs`
analogous to the existing `AAuthRequirementHeader`.

---

## 8. R3 (Rich Resource Requests) (Plan §6)

### 8.1 JCS (RFC 8785) in .NET

The plan notes "no maintained .NET JCS package was identified". Research
update:

| Package | NuGet | Status | Notes |
|---|---|---|---|
| `JsonCanonicalizer` | [link](https://www.nuget.org/packages/JsonCanonicalizer/) | Maintained (v1.0.4, 2024) | By Anders Rundgren, the RFC 8785 author. Reference implementation. MIT. |
| `Stratumn.CanonicalJson` | [link](https://www.nuget.org/packages/Stratumn.CanonicalJson/) | Last update 2020 | Thin wrapper; may lack edge-case coverage. |

**Finding**: `JsonCanonicalizer` **is** maintained and is the official
reference port. The plan's statement that "no maintained .NET JCS package was
identified" is incorrect.

**Plan amendment**: Phase 6.1 should use `JsonCanonicalizer` (NuGet) instead
of hand-rolling JCS. This eliminates a class of canonicalisation bugs and
avoids reinventing the wheel. The dependency is small (single file, MIT,
zero transitive deps).

### 8.2 R3 document model

From `draft-hardt-aauth-r3` §R3 Document §Fields:

```json
{
  "version": "1.0",
  "vocabulary": "urn:aauth:vocabulary:mcp",
  "operations": [ { "tool": "create_calendar_event" } ],
  "display": { "name": "Calendar Access", "description": "..." }
}
```

Content addressing: `SHA-256(JCS(document))` → base64url → `r3_s256`.

### 8.3 Vocabulary abstraction

The spec defines seven vocabularies (MCP, OpenAPI, gRPC, GraphQL, AsyncAPI,
WSDL, OData). Each has the same outer shape; they differ only in the
operation-entry fields.

Design:

```csharp
public interface IR3Vocabulary
{
    string VocabularyUri { get; }              // e.g. "urn:aauth:vocabulary:mcp"
    bool ValidateOperation(JsonObject op);     // schema check
    string GetOperationId(JsonObject op);      // extract canonical ID for display
}
```

Ship `McpVocabulary` and `OpenApiVocabulary` in-box. Others are trivial to
add later (each is ~10 lines).

### 8.4 Auth-token R3 claims

From `draft-hardt-aauth-r3` §Auth Token Extensions:

- `r3_granted`: array of operation IDs unconditionally granted.
- `r3_conditional`: array of operation IDs requiring per-call approval.

These land as optional claims in `AuthTokenBuilder` and are verified by
`TokenVerifier` (structural presence only; enforcement is resource-side).

---

## 9. Resource-Managed (2-Party) Flow (Plan §7.1)

### 9.1 Protocol recap

1. Agent sends signed request (agent token in `Signature-Key`).
2. Resource returns `202` with `requirement=interaction` + `Location` +
   opaque interaction code.
3. User completes interaction (e.g. consent screen).
4. Agent polls Location.
5. Resource returns `200` with optional `AAuth-Access: <opaque-token>`.
6. Agent includes `Authorization: AAuth <opaque-token>` on subsequent
   requests to skip re-authorization.

### 9.2 SDK design

Agent-side:
- `ChallengeHandler` already handles the 202 → poll → retry loop.
- New: detect `AAuth-Access` in the terminal 200 response, store it in
  `AAuthTokenHolder` alongside the auth-token slot.
- New: when `AAuthTokenHolder` has an opaque token for a resource, emit
  `Authorization: AAuth <token>` instead of the `Signature-Key` auth-token
  path.

Resource-side:
- New: `OpaqueTokenStore` abstraction (`IOpaqueTokenStore`) — issue and
  validate opaque tokens. In-memory default.
- New: middleware path that accepts `Authorization: AAuth <token>` as an
  alternative to re-running the full verification flow.

### 9.3 Interaction with the existing 3-party path

The agent must distinguish which 202 pattern it's in:
- `requirement=auth-token` → 3-party (exchange at PS).
- `requirement=interaction` → 2-party (resource-managed).

`ChallengeHandler` already parses `AAuth-Requirement`; the switch is on the
requirement type.

---

## 10. Call Chaining (Plan §7.3)

### 10.1 Spec design

When a resource acts as an agent toward another resource, it presents:
- Its *own* agent token (or auth token from the original caller's flow).
- The `upstream_token` parameter in the PS→AS federation request so the AS
  can verify the full delegation chain.
- The resulting auth token carries an extended `act` chain.

### 10.2 Impact on `act` verification

Each hop adds one `act` layer. The verifier must walk the full chain (Phase
1.1's `act` walker) and confirm each actor matches the previous token's
subject. The `MaxActDepth` limit from §1.4 of this document bounds the
recursion.

### 10.3 SDK helper

New `CallChainingHandler` (a `DelegatingHandler`) that:
1. Accepts an "upstream" auth token from the caller's verification context.
2. Performs a token exchange at its own PS/AS including `upstream_token`.
3. Signs the outbound request with the resulting chained auth token.

This is a thin orchestration layer over existing primitives
(`TokenExchangeClient`, `AAuthSigningHandler`).

---

## 11. NuGet Dependency Assessment

### 11.1 Current dependencies (post original plan Phase 2)

| Package | Version | Purpose |
|---|---|---|
| `BouncyCastle.Cryptography` | 2.6.2 | Ed25519 sign/verify, ECDSA RFC 6979 (Phase 3) |
| `Microsoft.IdentityModel.Tokens` | 8.18.0 | JWK serialisation, thumbprint |
| `Microsoft.AspNetCore.App` (framework ref) | — | ASP.NET Core middleware |

### 11.2 Proposed additions

| Package | Version | Phase | Purpose | Justification |
|---|---|---|---|---|
| `JsonCanonicalizer` | 1.0.4 | 6 | RFC 8785 JCS | Reference impl by spec author; avoids re-inventing canonicalisation |

### 11.3 Packages explicitly NOT added

| Package | Reason for exclusion |
|---|---|
| `NSign.*` | Original plan removed it; hand-rolled signer/verifier is simpler for fixed AAuth covered-component set |
| `StructuredFieldValues` | Considered for RFC 8941 parsing but header formats are simple enough to hand-parse; avoids a dep for 3 headers |
| `ScottBrady.IdentityModel.EdDsa` | BouncyCastle already covers Ed25519; no need for a second EdDSA path |
| `jose-jwt` | Same rationale as above |
| `WireMock.Net` | Integration tests already use `WebApplicationFactory<T>` + hand-crafted test servers; no need for a mocking framework |

### 11.4 Security advisory check

Before adding `JsonCanonicalizer`, run `runtime-tools-gh-advisory-database`
against `{ ecosystem: "nuget", name: "JsonCanonicalizer", version: "1.0.4" }`
in the implementation PR.

---

## 12. Conformance Suite Strategy

### 12.1 Section coverage map (target state after all phases)

| Spec section | Test file | Phase |
|---|---|---|
| §Agent Identifiers | `Identifiers/AgentIdTests.cs` | 1 |
| §Server Identifiers | `Identifiers/ServerIdTests.cs` | 1 |
| §Signature Algorithms | `HttpSig/AlgorithmTests.cs` | 3 |
| §Verification | `HttpSig/VerificationTests.cs` | 1 |
| §Authentication Errors | `Errors/SignatureErrorTests.cs` | 1 |
| §Token Endpoint Errors | `Errors/TokenErrorTests.cs` | 1 |
| §Polling Errors | `Errors/PollingErrorTests.cs` | 1 |
| §Agent Token | `AgentTokens/` (existing) | — |
| §Resource Token | `ResourceTokens/` (existing) | — |
| §Auth Token | `AuthTokens/AuthTokenTests.cs` | 2 |
| §Federated flow | `Federated/FederatedFlowTests.cs` | 2 |
| §Bootstrap / Refresh | `Bootstrap/RefreshTests.cs` | 4 |
| §Missions | `Missions/MissionLifecycleTests.cs` | 5 |
| §R3 | `R3/R3FlowTests.cs` | 6 |
| §Resource-Managed | `ResourceManaged/TwoPartyTests.cs` | 7 |
| §Call Chaining | `CallChaining/ChainTests.cs` | 7 |

### 12.2 Negative-case priority (Phase 1)

| Test | Asserts |
|---|---|
| `alg=none` token | Rejected with `unsupported_algorithm` |
| Missing `cnf` | Rejected with `invalid_jwt` |
| `cnf.jwk` ≠ HTTP sig key | Rejected with `invalid_jwt` |
| Expired token | Rejected with `expired_jwt` |
| Wrong audience | Rejected at `TokenVerifier` level |
| Agent ID with uppercase | `AAuthAgentId.TryParse` returns false |
| Server URL with path | `AAuthServerId.TryParse` returns false |
| Server URL with port | `AAuthServerId.TryParse` returns false |

---

## 13. Findings Requiring Plan Amendments

| # | Finding | Plan section affected | Amendment |
|---|---|---|---|
| 1 | `JsonCanonicalizer` NuGet exists and is maintained | Phase 6.1 | Use the package instead of hand-rolling JCS. |
| 2 | `AAuthKey` should become an interface (`IAAuthKey`) for ECDSA + future algorithms | Phase 3.3 | Changed from "AAuthKey becomes polymorphic" to "introduce `IAAuthKey` interface with `Ed25519AAuthKey` and `EcdsaAAuthKey` implementations". |
| 3 | Spec does NOT mandate deterministic signatures for *verifiers* — only for *signers* | Phase 3.3 | Use BouncyCastle (RFC 6979) for signing, BCL `ECDsa` for verification. Plan text clarified. |

These amendments are applied to `implementation-plan.md` in the same commit
as this file.

---

## 14. Open Questions (for spec clarification or future research)

1. **`Signature-Error` header format**: the Signature-Key draft is referenced
   but not yet published as an RFC. If the format changes, the SDK's emitter
   must track it. Monitor `draft-hardt-httpbis-signature-key`.

2. **`act` chain interop**: no reference implementation exercises chains
   deeper than 1. Until a multi-hop demo exists, the `MaxActDepth = 10`
   default is speculative.

3. **`jwks_uri` latency budget**: the spec says "MUST NOT fetch more
   frequently than once per minute" but does not define a timeout for the
   fetch itself. The SDK should use a 10 s HTTP timeout (matching
   `MetadataClient`) and document it.

4. **RFC 6979 test vectors**: BouncyCastle's `HMacDsaKCalculator`
   implementation should be validated against the RFC 6979 §A.2.5 test
   vectors (P-256 / SHA-256) in the conformance suite to confirm
   deterministic-K correctness.

5. **Payment (402) flow**: the spec is thin on the Location URL semantics
   for payment. Monitor spec updates before implementing Phase 7.4.
