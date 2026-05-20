# Implementation Plan: AAuth .NET SDK Gap Remediation

> Created 2026-05-20. Companion to [`/GAPS.md`](../../../GAPS.md) (same PR).
> Builds on (but does not extend the phase numbering of) the prior plan
> [`2026-05-13-dotnet-aauth-sdk`](../2026-05-13-dotnet-aauth-sdk/implementation-plan.md),
> which delivered Phases 1–2 of the SDK (core crypto, agent token, signed
> request, 3-party PS-asserted flow). This plan is a standalone roadmap to
> close the spec-conformance gaps catalogued in `GAPS.md`; its phases are
> numbered from 1 and stand on their own.

This plan describes **what** to build and **why**, plus the alternatives
considered for each major decision and the implications of each choice. It
does not prescribe code shape — that belongs in the per-phase PRs.

## Principles (carried over from the prior plan)

- Single solution, single library project. New surface area lands inside
  `src/AAuth/` unless a phase explicitly justifies a sub-package.
- Every new production type ships with xUnit coverage in the same PR.
- Every phase that changes runnable artifacts updates `README.md`.
- Conformance assertions land in `tests/AAuth.Conformance/`, mirroring the
  spec section structure with `[Fact(DisplayName = "§<section> — <clause>")]`.
- Each phase ends in a `dotnet test`-green checkpoint; no "we'll fix it next
  phase" half-merges.

## Source of truth

Every phase below cites the section in [`GAPS.md`](../../../GAPS.md) it
closes. When the spec changes, update `GAPS.md` first, then re-sequence
this plan.

---

## Phase ordering rationale

The phases are ordered so each one (a) unblocks the next and (b) leaves the
SDK in a strictly more spec-conformant state than it found it. Security and
verification gaps come first because they alter behaviour of *already-shipped*
APIs; net-new features (missions, R3, bootstrap) come later because they only
add surface area.

| Phase | Theme | Closes |
|---|---|---|
| 1 | Verification & error-reporting hardening | GAPS §8, §9, §11, §12 |
| 2 | Server-side discovery + four-party flow | GAPS §1.2, §2, §10 |
| 3 | Signature-Key scheme expansion + ECDSA | GAPS §3, §4 |
| 4 | Bootstrap & refresh | GAPS §7 |
| 5 | Missions (governance) | GAPS §5 |
| 6 | R3 (Rich Resource Requests) | GAPS §6 |
| 7 | Resource-managed (2-party) + specialised flows | GAPS §1.1, §8.4, §14 |

---

## Phase 1: Verification & error-reporting hardening

**Goal**: Make `AAuthVerifier`/`AAuthVerificationMiddleware`/`TokenVerifier`/
`DeferredPoller` fully spec-conformant on the *paths they already cover*, so
later phases inherit a trustworthy verification core.

### 1.1 Proof-of-possession binding enforcement (GAPS §9)

**Fix**: Enforce `cnf.jwk` (agent/auth tokens) and `agent_jkt` (resource
tokens) bindings *inside* `TokenVerifier` against the HTTP signature key
recovered by `AAuthVerifier`, rather than leaving it as a caller obligation.
Add an `act`-chain walk that validates each link's `sub` against the next
link's actor and enforces a configurable max depth.

**Alternatives considered**:

1. *Keep binding as caller-opt-in* (status quo). Rejected — every consumer
   that forgets the check ships a confused-deputy vulnerability. The whole
   value proposition of AAuth is PoP; making it optional is a footgun.
2. *Verify binding only in middleware, not in `TokenVerifier`*. Rejected —
   non-middleware callers (CLI tools, conformance tests) need the same
   guarantee, and duplicating logic is how bypasses creep in.
3. *Add a separate `BoundTokenVerifier` decorator*. Rejected for v1 — extra
   type without a clear second implementation. Revisit if a future caller
   genuinely needs to verify tokens without a paired HTTP signature (e.g.
   offline audit log replay).

**Implications**:

- Breaking behaviour change: tokens that previously verified without binding
  enforcement will now fail. Documented in `README.md` and release notes;
  conformance suite gains negative-case tests for each mismatch class.
- `TokenVerifier` now needs the verified HTTP signature key as input, which
  threads through `AAuthVerificationMiddleware` and `ChallengeHandler`.
- `act` walking introduces a recursive structure to the verifier; the depth
  limit must be enforced or a malicious AP can DoS verification.

### 1.2 Structured authentication errors (GAPS §8.1, §8.2, §8.3)

**Fix**: Introduce typed error enums for the three error surfaces (signature
auth, token endpoint, polling), emit them as `Signature-Error` header /
RFC 6749-style JSON / polling status mapping, and surface them on the client
side as discriminated exception types.

**Alternatives considered**:

1. *String error codes throughout*. Rejected — stringly-typed errors lose
   exhaustiveness checks and make the conformance suite brittle.
2. *Single shared `AAuthErrorCode` enum across all three surfaces*. Rejected —
   the spec defines disjoint code sets per surface; merging them invites
   senders to emit invalid combinations (e.g. `slow_down` on a 401).
3. *Wrap every error in an `Exception`*. Rejected for the server side —
   middleware shouldn't throw to set a header. Client side keeps exceptions
   for ergonomic `try/catch` over `Result<T>`-style code.

**Implications**:

- Public API additions only; no behaviour change for callers that don't
  inspect the new types.
- `DeferredPoller` gains polling-loop changes (`slow_down` adds 5 s,
  `invalid_code` aborts without retry). Existing call sites should keep
  working, but anyone overriding the retry policy needs to be aware.

### 1.3 Identifier validation utilities (GAPS §11, §12)

**Fix**: Add `AAuthAgentId` and tighten `AAuthUrl` to enforce the spec's
strict server-identifier rules (host-only, no trailing slash, lowercase,
ACE/Punycode for IDN, scheme `https` except loopback in dev). Hook these into
`MetadataClient`, every token builder, and every endpoint that accepts a
server or agent identifier from the wire.

**Alternatives considered**:

1. *Validate only at the edges (HTTP boundary)*. Rejected — defence-in-depth
   matters here; invalid identifiers leaking into token builders cause
   downstream verification failures that are hard to diagnose.
2. *Use a third-party URL/IDN library*. Rejected for now — BCL covers IDN via
   `IdnMapping`, and the rules are small enough that a focused parser is
   easier to audit than wrapping a general-purpose URL crate.
3. *Treat the existing `AAuthUrl.IsHttpsOrLoopback` as sufficient*. Rejected —
   the spec is explicit that host-only, trailing-slash, and case rules are
   normative; we already have a stored memory citing this validator, so any
   change here needs that memory upvoted/updated.

**Implications**:

- Behaviour change: previously accepted "lenient" URLs (with paths, trailing
  slashes, mixed case) now throw. Phase notes will call this out; existing
  samples are audited and updated where needed.
- New public type `AAuthAgentId` becomes part of the API surface, so its
  shape needs care (immutable struct, parse/tryparse, equality).

### 1.4 Token verifier completeness (GAPS §9, residual)

**Fix**: Enforce the remaining structural rules — at least one of `sub` or
`scope` in auth tokens, `act.sub` equality with token subject, `mission`
claim shape (parsed but not yet evaluated — full mission semantics land in
Phase 5).

**Alternatives**: minor; the trade-offs are about *where* to fail (parse
time vs. verify time). Decision: fail at verify time, so token builders
remain permissive for tests that intentionally produce malformed tokens.

**Implications**: more negative-path conformance tests; no API surface
change.

### 1.5 Conformance suite expansion

Add the negative cases (`alg=none`, missing/mismatched `cnf`, expired, bad
audience, identifier-rule violations) and the auth-token structure tests
that GAPS §13 calls out.

### Phase 1 Definition of Done

- `dotnet test` green, including new negative cases.
- `Signature-Error` emitted by middleware for every documented failure mode.
- Stored memory `URL validation uses AAuthUrl.IsHttpsOrLoopback ...` either
  upvoted (still correct) or replaced with a memory describing the new
  strict validator.
- `GAPS.md` checkboxes for §8, §9, §11, §12 flipped to ✅ (or downgraded with
  a note for any item explicitly deferred).

---

## Phase 2: Server-side discovery + four-party federated flow

**Goal**: Bring the SDK from "client can do 3-party" to "SDK can host any of
the three server roles for the 4-party flow end-to-end".

### 2.1 Server-side metadata endpoints (GAPS §2, §10)

**Fix**: Generalise `WellKnownEndpoints` from resource-only to a role-aware
hoster that can serve `aauth-resource.json`, `aauth-person.json`,
`aauth-agent.json`, `aauth-access.json` and their JWKS counterparts from a
shared registration helper.

**Alternatives considered**:

1. *One endpoint hoster per role (`ResourceMetadataEndpoints`,
   `PersonMetadataEndpoints`, …)*. Rejected for v1 — 80% of the code is
   identical (JWKS serving, content-type, caching headers). A single hoster
   with role-specific options is easier to maintain. Revisit if the roles
   diverge significantly.
2. *Generate endpoints from a `[AAuthRole]`-style attribute on the host
   class*. Rejected — too much magic for one-line registration savings.
3. *Defer PS/AS endpoint hosting to consumers*. Rejected — without server-side
   metadata helpers, the conformance suite cannot run end-to-end 4-party
   tests against the SDK itself.

**Implications**:

- New DI registration surface (`AddAAuthPersonServer`,
  `AddAAuthAccessServer`, `AddAAuthAgentProvider`). Naming needs to be stable
  before Phase 3.
- The metadata client (GAPS §10, "Metadata HTTPS validation on fetch") gets
  the strict URL validator from Phase 1.3.

### 2.2 Resource `/authorize` endpoint (GAPS §2)

**Fix**: Add a resource-side authorization endpoint helper that lets a
resource explicitly *initiate* authorization (instead of relying on the 401
challenge path).

**Alternatives**: the spec allows either entry path; the SDK already covers
the 401 challenge, so adding `/authorize` is purely additive.

**Implications**: new test fixture and a sample showing the explicit entry
flow.

### 2.3 Access Server (AS) implementation (GAPS §1.2)

**Fix**: Implement `AS Token Endpoint` + AS-side verification of the
`agent_token` + `resource_token` pair, returning an auth token whose
`cnf.jwk` matches the agent. Add the `aud=AS_URL` path through
`ResourceTokenBuilder` and the PS→AS federation client.

**Alternatives considered**:

1. *Skip AS, treat 4-party as "out of scope for the SDK"*. Rejected — without
   AS support, the SDK can never demonstrate the spec's flagship federated
   flow. The whole point of the samples repo is to show every mode.
2. *Embed AS inside the PS sample only*. Rejected — AS is a distinct server
   role with its own metadata, key set, and audit obligations. Co-hosting is
   fine for demos but the library boundary must keep them separate.
3. *Build AS as a separate solution*. Rejected per the single-solution
   principle. Revisit only if the AS surface area grows to dwarf the rest.

**Implications**:

- New `tests/AAuth.Conformance/Federated/` section with end-to-end fixtures
  using TestServer for AP, PS, AS, and Resource.
- `AuthTokenBuilder` exits "untested" status (called out in `GAPS.md` §1.2).
- New sample (`samples/FederatedDemo/`) — README updated to reference it.

### 2.4 Token revocation + refresh-endpoint scaffolding (GAPS §2, §14)

**Fix**: Add `POST /revoke` and `POST /refresh` endpoint helpers on AP/PS/AS
roles and a `RevocationClient`. Refresh semantics are minimal here; the
two-key refresh flow lands in Phase 4.

**Alternatives**: revocation could be punted to Phase 5 (it pairs naturally
with missions). Rejected — revocation is a *security hygiene* primitive that
should ship before any of the long-lived flows that need it.

**Implications**: revocation introduces server-side state (JTI denylist). The
SDK ships an in-memory default implementation and an abstraction (`IJtiStore`)
for consumers to plug their own. Documented as "in-memory only — not
production-grade" in README.

### Phase 2 Definition of Done

- Full 4-party flow runs in conformance tests, end-to-end, with all four
  server roles hosted by SDK code.
- `samples/FederatedDemo/` runnable via `dotnet run`.
- GAPS §1.2, §2 (except R3-specific endpoints), §10 closed.

---

## Phase 3: Signature-Key scheme expansion + ECDSA

**Goal**: Cover the rest of the `Signature-Key` schemes and the second
mandatory signing algorithm so the SDK can talk to any conformant peer.

### 3.1 `hwk` and `jwks_uri` schemes (GAPS §3)

**Fix**: Extend `SignatureKeyHeader` + `SignatureKeyParser` to format and
parse `hwk` (inline JWK) and `jwks_uri` (URL reference); have `AAuthVerifier`
dispatch on the scheme to recover the verifier key.

**Alternatives considered**:

1. *Only add `jkt-jwt` (defer `hwk`/`jwks_uri` to a later phase)*. Rejected —
   `jwks_uri` is the only path for self-hosted agents (no AP), which the
   bootstrap spec relies on; adding it together with `jkt-jwt` keeps Phase 4
   focused on the two-key model rather than the wire format.
2. *Treat `jwks_uri` as a special case of `MetadataClient`*. Partially
   accepted — implementation reuses `JwksClient` caching; the *parser* is
   still scheme-aware.

**Implications**: new caching behaviour (`jwks_uri` fetches must respect
`Cache-Control`) — already covered by `JwksClient`, just needs reuse.

### 3.2 `jkt-jwt` (two-key naming) wire format (GAPS §3)

This phase ships the *parser/formatter* for `jkt-jwt`; Phase 4 wires it into
the bootstrap key model.

### 3.3 ECDSA P-256 (RFC 6979 deterministic) (GAPS §4)

**Fix**: Add ECDSA P-256 alongside Ed25519 in `AAuthKey`, `JwtWriter`,
`AAuthVerifier`, and `JwksClient` (currently silently skips non-Ed25519).

**Alternatives considered**:

1. *Use BCL `ECDsa` directly*. Preferred for verification and non-
   deterministic signing.
2. *Use BCL `ECDsa` with a deterministic-K shim*. Rejected — BCL does not
   expose RFC 6979 deterministic-K; we need BouncyCastle (already a direct
   dependency post Phase 2 self-review of the original plan). Recorded as
   the chosen path.
3. *Skip RFC 6979 and use the BCL random-K signer*. Rejected — the spec
   mandates deterministic signatures for reproducibility and PoP equality.

**Implications**:

- `AAuthKey` becomes algorithm-polymorphic; the JWK serialiser learns the
  `EC` key type alongside `OKP`.
- Public API: `AAuthKey.Generate` grows an algorithm parameter. Keep the
  Ed25519 overload as the default to preserve binary compatibility.

### Phase 3 Definition of Done

- Conformance suite has fixtures for each scheme × each algorithm.
- `JwksClient` no longer silently drops keys; logs at debug for unsupported.
- GAPS §3 (except `jkt-jwt` semantics, deferred to Phase 4), §4 closed.

---

## Phase 4: Bootstrap & token refresh

**Goal**: Long-running agents — durable key enrolment, ephemeral key
issuance, refresh.

### 4.1 Two-key model (GAPS §7)

**Fix**: Add a `DurableKey`/`EphemeralKey` distinction in `KeyStore`, the
naming-JWT construction (durable signs over ephemeral JWK + thumbprint), and
the `jkt-jwt` Signature-Key payload that names the chain.

**Alternatives considered**:

1. *Single-key model with re-issuance*. Rejected — that's just the original
   plan over again and does not match the bootstrap spec.
2. *Three-key model (durable + intermediate + ephemeral)*. Rejected — the
   spec defines two layers; adding a third without a concrete use case is
   speculative.

**Implications**:

- `KeyStore` schema bump. A `version` field is added and old stores are
  migrated forward on load. Old stores remain readable; new fields are
  optional.
- New sample showing enrolment + refresh loop.

### 4.2 AP enrolment and refresh endpoint clients (GAPS §7)

**Fix**: `AgentProviderClient.EnrolAsync` and `RefreshAsync`.

**Alternatives**: client vs. server hosting — server-side AP hosting is
already scaffolded in Phase 2.1; this phase only adds the client.

### 4.3 Platform attestation abstraction (GAPS §7)

**Fix**: Define an `IPlatformAttestor` abstraction with a `NoopAttestor`
default. WebAuthn / App Attest / Play Integrity implementations are
explicitly out of scope; we ship the seam only.

**Alternatives considered**:

1. *Ship a WebAuthn implementation*. Rejected — WebAuthn ceremonies belong
   in a browser; the .NET SDK can only ship the relying-party side, which is
   a project of its own.
2. *No abstraction; consumers patch us later*. Rejected — without the
   abstraction, every consumer reinvents the integration point.

**Implications**: small API surface addition; documented as
"extensibility seam, no built-in providers".

### Phase 4 Definition of Done

- Refresh sample runnable end-to-end against the Phase 2 AP server.
- GAPS §7 closed (except platform attestation implementations, deferred
  indefinitely per the rationale above).

---

## Phase 5: Missions (governance)

**Goal**: Mission lifecycle — proposal, clarification, approval, audit,
termination.

### 5.1 Mission model + header (GAPS §5)

**Fix**: `Mission` domain type (`approver`, `s256`, `approved_tools`,
`capabilities`), `AAuth-Mission` header parser/formatter, `mission` claim
shape in tokens.

### 5.2 Endpoints (GAPS §2, §5)

`POST /mission`, `POST /permission`, `POST /audit`, `POST /interaction` —
server-side hosters with `IMissionStore`, `IAuditSink`, `IInteractionRelay`
seams. In-memory defaults only.

### 5.3 Flow handling (GAPS §5)

- `requirement=clarification` 202 loop in `DeferredPoller`.
- `requirement=approval` handling.
- `mission_terminated` 403 → typed exception.

**Alternatives considered**:

1. *Push missions out to a separate package*. Rejected for v1 per the
   single-project principle; revisit if mission-only consumers exist.
2. *Combine permission + audit into one endpoint*. Rejected — the spec
   separates them, and audit volumes can dwarf permission volumes; co-
   hosting would couple their scaling.

**Implications**:

- The `IMissionStore`/`IAuditSink` abstractions land before any real backing
  store; documented as "in-memory only".
- Mission claim now flows through `TokenVerifier` (Phase 1.4 parsed it; this
  phase evaluates it).

### Phase 5 Definition of Done

- Mission lifecycle conformance section in `tests/AAuth.Conformance/`.
- Sample showing propose → clarify → approve → execute → audit.

---

## Phase 6: R3 (Rich Resource Requests)

**Goal**: Operation-level authorization with content-addressed R3 documents.

### 6.1 R3 document model + canonicalisation (GAPS §6)

**Fix**: R3 document type (`version`, `vocabulary`, `operations`, `display`),
RFC 8785 JCS canonicaliser, SHA-256 content addressing.

**Alternatives considered**:

1. *Use an existing JCS library*. Rejected for the SDK: no maintained .NET
   JCS package was identified in research; we ship a small focused
   implementation. Revisit when one matures.
2. *Skip canonicalisation and hash raw bytes*. Rejected — that breaks
   interop with any peer that round-trips the JSON.

### 6.2 R3 endpoints + claims (GAPS §2, §6)

`GET /r3/{id}`, `r3_uri`/`r3_s256` resource-token claims,
`r3_granted`/`r3_conditional` auth-token claims, `r3_vocabularies` in
resource metadata, AS-side hash verification, per-call approval for
conditional operations.

### 6.3 Vocabulary support (GAPS §6)

Ship MCP and OpenAPI vocabulary parsers as the two reference cases; expose
an `IR3Vocabulary` seam for the rest. gRPC and GraphQL deferred.

**Alternatives**: ship all five vocabularies up-front (rejected — most of the
work is the abstraction; adding more parsers is consumer-driven).

### Phase 6 Definition of Done

- R3 flow conformance section.
- Sample demonstrating an MCP tool call gated by an R3 grant.
- GAPS §6 closed (with deferred vocabularies documented).

---

## Phase 7: Resource-managed (2-party) + specialised flows

**Goal**: The remaining flows in GAPS §1.1, §8.4, and §14.

### 7.1 Resource-managed 2-party (GAPS §1.1)

`AAuth-Access` opaque token, `Authorization: AAuth <token>` header,
resource-side interaction initiation, agent-side 202 handling distinct from
PS-asserted 202.

### 7.2 Third-party login (GAPS §14)

`POST /login` endpoint, `login_hint`, `login_endpoint` in PS metadata.

### 7.3 Call chaining (GAPS §14)

Resource-acts-as-agent — `upstream_token` parameter in PS→AS federation,
`act` chain extension.

### 7.4 Payment Required (402) (GAPS §8.4)

Typed handling of 402 + Location polling for AS payment flows.

### 7.5 Misc claims (GAPS §14)

`tenant`, `justification`, `platform`, `device`, `claims` requirement.

### Phase 7 Definition of Done

- GAPS §1.1, §8.4, §14 closed.
- `GAPS.md` reduced to an empty "Gaps" table (any survivors moved to a new
  "Deferred" section with explicit rationale).

---

## Cross-cutting concerns

### Versioning and breaking changes

Phase 1 introduces verification behaviour that breaks consumers who relied on
the lax defaults. Until the SDK reaches `1.0.0`, this is acceptable; each
breaking phase ships with:

- Release notes calling out the change.
- README updates.
- A clear migration paragraph in the PR description.

Alternative considered: keep lax mode behind an opt-out flag. Rejected — the
flag would survive long after consumers stop reading release notes and would
quietly re-open the security hole.

### Conformance suite as the contract

Every phase adds spec-traceable `[Fact(DisplayName = "§<section>")]` tests.
The conformance suite is the single source of truth for "is the SDK
spec-conformant?"; `GAPS.md` is updated from the test list, not the other
way around.

### Dependency policy

No new NuGet packages without an entry in a `research.md` (next to this
file) explaining why the BCL or an existing dependency is insufficient.
Current phases anticipate **no** new dependencies beyond what the prior plan
already established (BouncyCastle, Microsoft.IdentityModel.Tokens).

### Stored-memory upkeep

Any phase that invalidates a stored repository memory must, in the same PR:

1. Downvote the stale memory (cite the file/line that changed).
2. Store the replacement memory describing the new reality.

Phase 1.3 in particular will touch the existing
`URL validation uses AAuthUrl.IsHttpsOrLoopback` memory.

---

## Out of scope (recorded, not deferred)

- Production-grade key storage (HSM/KMS integration) — explicit non-goal of
  the samples repo.
- Persistent backing stores for missions, audit, JTI denylists — abstractions
  ship; persistence is consumer responsibility.
- WebAuthn / App Attest / Play Integrity attestor implementations — see
  Phase 4.3.
- gRPC and GraphQL R3 vocabularies — see Phase 6.3.

If any of these become in scope later, they get their own dated plan folder
under `.agent/plans/` rather than being smuggled into one of the phases above.
