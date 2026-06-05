# Missions & PS Governance — Research

## Problem Statement

The AAuth protocol defines **missions** (scoped authorization contexts for agent
governance) and positions the **Person Server (PS)** as the *contextual* policy
evaluation point — distinct from the deterministic policy enforced by resources
and access servers. The .NET SDK (`src/AAuth/`), samples (`samples/`), and docs
(`docs/`) implement only fragments of this surface, and the central `Mission`
model is materially divergent from the specification.

This document captures the spec model, the current SDK/sample/doc state, and the
gap inventory. It contains **no** implementation steps — those live in
[implementation-plan.md](implementation-plan.md).

## Source Documents

| Document | Location | Relevant Sections |
|----------|----------|-------------------|
| AAuth Protocol | `aauth-spec/draft-hardt-oauth-aauth-protocol.md` | §Policy Evaluation Points; §Agent Governance; §Missions (overview + normative); §PS Governance Endpoints; §Person Server; §PS Token Endpoint; §Clarification Chat; §Permission Endpoint; §Audit Endpoint; §Interaction Endpoint; §Resource Token; §Auth Token; §Upstream Token Verification; §Call Chaining; §Person Server Metadata; rationale (Why Missions Are Not a Policy Language / Two States) |
| AAuth Bootstrap | `aauth-spec/draft-hardt-aauth-bootstrap.md` | PS lazy user-binding on first interaction; `ps` claim |
| Upcoming changes | `aauth-spec/upcoming-changes-02.md` | `capabilities` in PS token body; `prompt`/`provider_hint` params |

> Spec section anchors are cited by `{#anchor}` name and approximate line where a
> stable anchor is absent. Line numbers reference the current revision of
> `draft-hardt-oauth-aauth-protocol.md` and may drift on spec updates.

---

## Part 1 — Spec Model

### 1.1 Policy Evaluation Points (§Policy Evaluation Points, ~L380)

Policy is **distributed**; no single party is the decision point. Each of the
four server roles re-evaluates the agent's activity from its own vantage point,
and token lifetimes provide a natural re-evaluation cadence:

- **Agent Provider** — issues/refuses agent tokens (device posture, attestation).
- **Person Server** — decides whether to issue an auth token for a resource/scope
  based on **user consent** and, under a mission, the **mission intent + log**
  against the PS governance policy.
- **Access Server** — decides issuance on behalf of the resource (resource policy,
  PS-provided claims, deferred requirements).
- **Resource** — *decides what is required* when issuing a resource token, and
  *enforces* the auth token at access time.

### 1.2 The Mission as Contextual Governance (§Why Missions Are Not a Policy Language, ~L2789)

The spec deliberately separates two authorization kinds:

- **Deterministic policy** — scopes, resource tokens, AS policy. Machine-evaluable.
- **Contextual governance** — missions, justifications, clarification at the PS.
  *Not* machine-evaluable; concentrated at the PS, the only party with the mission
  content, the user relationship, and the full action history.

Consequence: mission **content never leaves the PS**. Only the mission **hash**
(`s256`) travels in tokens/headers. Distributing mission content would be "a
privacy leak and a false promise of enforcement."

### 1.3 Mission Object & Identity (§Mission Approval, ~L1259)

The approved **mission blob** is JSON:

| Field | Req? | Meaning |
|-------|------|---------|
| `approver` | MUST | HTTPS URL of approving entity (currently always the PS) |
| `agent` | MUST | Agent identifier `aauth:local@domain` |
| `approved_at` | MUST | ISO 8601 approval timestamp (makes `s256` globally unique) |
| `description` | MUST | Markdown describing approved scope |
| `approved_tools` | MAY | `[{name, description}]` usable without per-call permission |
| `capabilities` | MAY | e.g. `["interaction","payment"]` the PS can provide; agent unions into `AAuth-Capabilities` |

**Identity** — `s256` = base64url(SHA-256(**exact approved response body bytes**)).
The agent MUST store the body bytes verbatim — *no re-serialization* — and
verifies by recomputing over those bytes (§Mission Approval, ~L1275).

### 1.4 Mission Lifecycle

- **Creation** (§Mission Creation, ~L1228): agent POSTs `{description, tools}` to
  the PS `mission_endpoint` (signed, agent token via `Signature-Key: sig=jwt`).
  PS MAY return `202` for human review + clarification; approved blob MAY differ
  from the proposal.
- **States** (§Mission Management, ~L1322): exactly **two** — `active`,
  `terminated`. No suspended state (§Why Missions Have Only Two States, ~L2805).
- **Errors** (§Mission Status Errors, ~L1331): a request referencing a
  non-active mission → `403` `{error:"mission_terminated", mission_status:"terminated"}`.
- **Completion** (§Mission Completion, ~L1318): agent sends `type=completion`
  to the interaction endpoint with a summary; user accepts (terminate) or
  follows up (continues).
- **Mission Log** (§Mission Log, ~L1310): ordered record of *all* agent↔PS
  interactions (token requests + justifications, permission req/resp, audit
  records, interaction requests, clarification chats). PS-maintained.

### 1.5 Cryptographic Binding Chain

Mission binding is **by hash reference**, layered on top of **key-bound
proof-of-possession** and the **`act` delegation chain**:

1. Agent in mission context adds `aauth-mission` to the **signed** HTTPSig
   covered components (§Authorization Endpoint Request, ~L619). The `s256`
   reference is thus covered by the agent's signature.
2. Mission-aware **resource** embeds `{approver, s256}` as the `mission` claim in
   the **resource token** it signs (§Resource Token Structure, ~L780). Resource
   token also binds `agent_jkt` (RFC 7638 thumbprint).
3. PS/AS embeds `{approver, s256}` as the `mission` claim in the **auth token**
   it signs (§Auth Token Structure, ~L1560). Auth token binds `cnf.jwk` (PoP)
   and `act` (RFC 8693 actor chain).
4. **Delegation**: in call chaining the PS nests the upstream `act` inside a new
   `act` identifying the intermediary (§Upstream Token Verification, ~L1621),
   preserving the full chain for downstream authorization decisions.

**Integrity & provenance are cryptographic; appropriateness is a PS policy
decision** — the resource embeds the mission reference it received but does not
re-evaluate mission fitness. Only the PS resolves `s256` → content against the
mission log.

### 1.6 PS Endpoints (§Person Server, ~L810)

| Endpoint | Spec | Purpose | Mission? |
|----------|------|---------|----------|
| `token_endpoint` | §PS Token Endpoint ~L814 | Exchange resource token → auth token; consent; three/four-party | optional |
| `mission_endpoint` | §Mission Creation ~L1228 | Propose/approve missions | — |
| `permission_endpoint` | §Permission Endpoint ~L1013 | Pre-action governance for non-resource actions (tool calls) | optional |
| `audit_endpoint` | §Audit Endpoint ~L1077 | Fire-and-forget action logging (`201`) | **required** |
| `interaction_endpoint` | §Interaction Endpoint ~L1131 | Relay interaction/payment/question/completion to user | optional |

**Token request params** (§Agent Token Request, ~L830): `resource_token` (req),
`upstream_token`, `justification`, `login_hint`, `tenant`, `domain_hint`,
`platform`, `device`. `capabilities`/`prompt` per upcoming-changes-02.

**Clarification chat** (§Clarification Chat, ~L906): PS returns `202`
`requirement=clarification` with `{clarification, timeout?, options?}`. Agent
responds with one of: `clarification_response` POST, updated `resource_token`
POST, or `DELETE` to cancel. Round limit recommended ≤5; agent responses are
untrusted and MUST be sanitized by the PS before display.

**Permission** (§Permission Endpoint): POST `{action, description?, parameters?,
mission?}` → `{permission: granted|denied, reason?}` or deferred. `approved_tools`
short-circuit the call. **Audit** (§Audit Endpoint): POST `{mission(req),
action, description?, parameters?, result?}` → `201`. **Interaction**
(§Interaction Endpoint): POST `{type, description?, url?, code?, question?,
summary?, mission?}`; `question` → `{answer}`, `completion` → terminate/continue.

**PS Metadata** (§Person Server Metadata, ~L2199): publishes the optional
`mission_endpoint`, `permission_endpoint`, `audit_endpoint`,
`interaction_endpoint`.

---

## Part 2 — Current SDK State

### 2.1 What works (keep)

| Capability | Evidence | Spec |
|------------|----------|------|
| `AAuth-Mission` structured header format | `AAuthMissionHeader.FormatStructured` ([Agent/Mission.cs](../../../src/AAuth/Agent/Mission.cs)) | §AAuth-Mission Header |
| Mission forwarding on downstream calls | [Agent/MissionForwardingHandler.cs](../../../src/AAuth/Agent/MissionForwardingHandler.cs); wired in [AAuthClientBuilder.cs](../../../src/AAuth/AAuthClientBuilder.cs) L556 | §Call Chaining |
| `act` chain build/read/validate | `AuthTokenBuilder.UpstreamAct`, [Tokens/ActChainBuilder.cs](../../../src/AAuth/Tokens/ActChainBuilder.cs), [Tokens/ActChainReader.cs](../../../src/AAuth/Tokens/ActChainReader.cs), [Tokens/UpstreamTokenValidator.cs](../../../src/AAuth/Tokens/UpstreamTokenValidator.cs); depth limit in [Tokens/TokenVerifier.cs](../../../src/AAuth/Tokens/TokenVerifier.cs) | §Upstream Token Verification |
| Deferred `202` loop, interaction, Retry-After/Prefer, `402`, polling errors | [Agent/DeferredPoller.cs](../../../src/AAuth/Agent/DeferredPoller.cs), [Agent/TokenExchangeClient.cs](../../../src/AAuth/Agent/TokenExchangeClient.cs) | §User Interaction; §Deferred Responses |
| `mission.approver` constraint on resource token | `TokenVerifier.VerifyResourceToken` (~L512) when `expectedApprover` supplied | §Resource Token Verification step 7 |
| Call-chaining router (mission.approver → PS) | [Server/CallChaining/CallChainingRouter.cs](../../../src/AAuth/Server/CallChaining/CallChainingRouter.cs) | §Call Chaining |
| PS metadata **emission** of all 4 governance endpoints | [Server/Metadata/AAuthPersonServerMetadataOptions.cs](../../../src/AAuth/Server/Metadata/AAuthPersonServerMetadataOptions.cs), [Server/Metadata/WellKnownEndpoints.cs](../../../src/AAuth/Server/Metadata/WellKnownEndpoints.cs) L178-184 | §Person Server Metadata |

### 2.2 Gap Inventory

Severity: **C** critical (incorrect/non-compliant behavior), **H** high (missing
core capability), **M** medium (missing convenience / ecosystem coverage).

| # | Sev | Gap | Spec | Current state |
|---|-----|-----|------|---------------|
| G1 | C | `Mission` model uses 4 states `pending/approved/denied/completed` | §Mission Management (2 states) | [Agent/Mission.cs](../../../src/AAuth/Agent/Mission.cs) L17 |
| G2 | C | `Mission` missing required blob fields `approver`,`agent`,`approved_at`; carries non-spec `Id`,`Requirements`,`StatusUrl`,`InteractionUrl` | §Mission Approval | Agent/Mission.cs L12-44 |
| G3 | C | `Mission.FromJson` parses `mission_id` (throws if absent), wrong keys | §Mission Approval | Agent/Mission.cs L32-43 |
| G4 | C | No `s256` compute over exact body bytes; no verbatim byte storage; no verify | §Mission Approval ~L1275 | absent |
| G5 | H | No `mission_endpoint` client (propose/approve, 202 review) | §Mission Creation | absent |
| G6 | H | No `permission_endpoint` client | §Permission Endpoint | absent |
| G7 | H | No `audit_endpoint` client (fire-and-forget) | §Audit Endpoint | absent |
| G8 | H | No `interaction_endpoint` client (relay/question/completion) | §Interaction Endpoint | absent |
| G9 | H | `ResourceTokenBuilder` cannot emit `mission` claim | §Resource Token Structure ~L780 | [Tokens/ResourceTokenBuilder.cs](../../../src/AAuth/Tokens/ResourceTokenBuilder.cs) |
| G10 | H | `AuthTokenBuilder` cannot emit `mission` claim (only `AdditionalClaims`) | §Auth Token Structure ~L1560 | [Tokens/AuthTokenBuilder.cs](../../../src/AAuth/Tokens/AuthTokenBuilder.cs) |
| G11 | H | `TokenVerifier.VerifyAuthToken` does not surface `mission` claim | §Auth Token | TokenVerifier.cs L161-268 |
| G12 | H | HTTPSig does not auto-cover `aauth-mission` when header present | §Authorization Endpoint Request ~L619 | [HttpSig/AAuthSigningHandler.cs](../../../src/AAuth/HttpSig/AAuthSigningHandler.cs) L40 (fixed base components) |
| G13 | H | Clarification chat fully absent (parse, response POST, updated-request POST, DELETE cancel, round limit) | §Clarification Chat | DeferredPoller is GET-only |
| G14 | H | Token request missing params `justification`,`login_hint`,`tenant`,`domain_hint`,`platform`,`device` | §Agent Token Request ~L830 | [Agent/TokenExchangeRequest.cs](../../../src/AAuth/Agent/TokenExchangeRequest.cs) |
| G15 | H | `ServerMetadata` does not parse `permission_endpoint`/`audit_endpoint` | §Person Server Metadata | [Discovery/ServerMetadata.cs](../../../src/AAuth/Discovery/ServerMetadata.cs) L43-44 |
| G16 | H | No `mission_terminated` error code / typed exception / handling | §Mission Status Errors | not in [Errors/TokenError.cs](../../../src/AAuth/Errors/TokenError.cs) |
| G17 | M | No `capabilities` union (mission blob ∪ agent) into `AAuth-Capabilities` | §Mission Approval; §AAuth-Capabilities | [Agent/AAuthCapabilitiesHeader.cs](../../../src/AAuth/Agent/AAuthCapabilitiesHeader.cs) format/parse only |
| G18 | M | No PS-side governance handlers (mission/permission/audit/interaction) or DI seams | §PS Governance Endpoints | absent; MockPersonServer hand-rolls partial flows |
| G19 | M | No governance DTOs (Permission/Audit/Interaction/MissionCreate req+resp) | §PS Governance Endpoints | absent |
| G20 | M | No mission-log abstraction (store seam) | §Mission Log | absent |

### 2.3 SDK role scope (context for plan)

The SDK is **client/agent + resource-verification** focused; it ships token
**builders** but not full PS/AS servers. [samples/MockPersonServer/Program.cs](../../../samples/MockPersonServer/Program.cs)
hand-rolls token issuance and consent UI (`GET /interaction`, `POST
/interaction/{approve,deny}`) but no spec governance endpoints, no mission
extraction, no `s256`, no mission claim in issued tokens. Server-side governance
helpers (G18/G19/G20) should follow the existing pattern: thin SDK primitives
(DTOs + parse/format + optional minimal endpoint mappers / DI seams) that the
mock servers consume, rather than a full PS implementation.

---

## Part 3 — Samples & Docs State

### 3.1 Samples

0 of 9 samples demonstrate mission creation, permission, audit, interaction
relay, or completion. Orchestrator forwards the `AAuth-Mission` header only.

| Sample | Mission-aware | Governance demo |
|--------|---------------|-----------------|
| WhoAmI (resource) | no | no |
| Orchestrator (call chain) | header forward only | no |
| MockPersonServer | no mission claim/s256 | consent UI only |
| MockAgentProvider / MockAccessServer | n/a | no |
| GuidedTour / SampleApp / AgentConsole / LiveWhoAmITest | no | no |

### 3.2 Docs

| File | Status |
|------|--------|
| [docs/advanced/missions.md](../../../docs/advanced/missions.md) | **STALE** — mirrors broken model (4 states, `mission_id`/`status_url`/`interaction_url`); no `s256`, no blob fields, no governance endpoints |
| [docs/workflows/call-chaining.md](../../../docs/workflows/call-chaining.md) | partial — mentions forwarding, no mission blob/governance |
| [docs/workflows/ps-asserted-access.md](../../../docs/workflows/ps-asserted-access.md) | aligned for consent; no mission context |
| [docs/workflows/deferred-consent.md](../../../docs/workflows/deferred-consent.md) | aligned; no mission/permission context |
| [docs/workflows/federated-access.md](../../../docs/workflows/federated-access.md) | partial; no mission governance |
| [docs/server/token-issuance.md](../../../docs/server/token-issuance.md) | mentions `mission.approver`; no `s256`/lifecycle |
| docs/server/{permission,audit,interaction} | **absent** |

Docs index: [docs/README.md](../../../docs/README.md) (slot new governance docs
under `docs/server/` + refresh `docs/advanced/missions.md` + add a
`docs/workflows/` mission-governance walkthrough).

---

## Part 4 — Gaps & Open Questions

1. **`s256` over which bytes?** Spec: exact response body bytes of the mission
   approval. SDK must retain the raw `byte[]`/`string` from the `mission_endpoint`
   response (and any persisted blob) — model must expose a verbatim-bytes
   accessor, not a re-serialized `JsonObject`. (§Mission Approval ~L1275)
2. **Auto-signing `aauth-mission`.** Should `AAuthSigningHandler` auto-detect the
   `AAuth-Mission` request header and add `aauth-mission` to covered components,
   or should the mission-aware client layer set `AdditionalComponentsKey`?
   Leaning auto-detect for correctness (G12), but must confirm it does not
   double-add when callers also set it. (§Authorization Endpoint Request ~L619)
3. **Backward compatibility of `Mission`.** Replacing the model is a breaking
   change. Confirm whether to rename (e.g. `ApprovedMission`) + keep a
   `[Obsolete]` shim, or replace outright. (Affects docs + any sample usage.)
4. **Server governance depth.** How much PS-side to put in the SDK vs. the mock?
   Proposed: DTOs + serialization + minimal endpoint mappers + store/relay
   interfaces (`IMissionStore`, `IPermissionDecider`, `IAuditSink`,
   `IInteractionRelay`); full policy lives in MockPersonServer. (§PS Governance)
5. **Clarification scope.** Implement the full agent-side three-action loop
   (respond / update / cancel) plus a server-side helper, or agent-side only in
   round one? (§Clarification Chat)
6. **`mission_terminated` propagation.** Where to surface — `TokenExchangeClient`,
   governance clients, or a shared error mapper consumed by all PS calls?
   (§Mission Status Errors)

> **Update (2026-06):** Initial research complete. Open questions above to be
> resolved as Implementation Decisions per phase before coding.

## Part 5 — Phase Findings

### Phase 1 — Mission model & `s256` (2026-06-05, complete)

- **Decisions resolved.** Q1 (verbatim bytes): `Mission.RawBytes`
  (`ReadOnlyMemory<byte>`) stores the exact approval body; `FromApprovalBytes`
  hashes those bytes directly (no `JsonNode` re-serialization). Q3 (compat):
  given draft status + no back-compat constraint, the old `Mission` model was
  **replaced in place** — no rename, no `[Obsolete]` shim.
- **Old model had zero external references.** `Mission` (with `Id`/`Status`/
  `Requirements`/`StatusUrl`/`InteractionUrl`) and `Mission.FromJson` were not
  referenced anywhere in `src/`, `tests/`, or `samples/`. The rewrite therefore
  broke no callers — confirmed by a full-solution build (0 warnings/errors).
- **`AAuthMissionHeader` kept as-is.** `FormatStructured(approver, s256)` already
  matched spec; only the dead `Format(string missionId)` overload was removed.
  `MissionForwardingHandler` (the sole consumer) is unaffected.
- **`s256` is byte-sensitive.** A test confirms pretty-printed vs compact JSON of
  the same logical content produce **different** `s256` — reinforcing the
  "store verbatim, never re-serialize" requirement (§Mission Approval).
- **Capabilities union** added as `AAuthCapabilitiesHeader.Union(mission, agent)`
  (mission-first, order-preserving, case-sensitive dedupe).
- **New files:** `Mission.cs` (rewritten), `MissionState.cs`, `MissionTool.cs`.
  **Tests:** `Missions/MissionModelTests.cs`, `Missions/MissionS256Tests.cs`,
  plus `Union` cases in `CapabilitiesHeaderTests.cs`.
- **Validation:** 364 conformance + 371 unit tests green; full solution builds.
- **No new open questions or design choices for Phase 1.** `VerifyS256` uses a
  fixed-time comparison (defensive; the value is not secret but the helper is
  cheap and avoids early-exit surprises).

### Phase 2 — Mission binding through the token chain (2026-06-05, complete)

- **Mission claim shape.** Introduced `MissionClaim(string Approver, string
  S256)` (`src/AAuth/Tokens/MissionClaim.cs`) as the `{approver, s256}` value
  carried in tokens. `ResourceTokenBuilder` and `AuthTokenBuilder` gained an
  optional `Mission` property; the `mission` claim is emitted **only when set**
  (§Resource Token Structure, §Auth Token Structure).
- **Verification surface.** `TokenVerifier.VerifiedToken` exposes a computed
  `Mission` property (parses `payload.mission`; `null` when absent/malformed).
  The existing `expectedApprover` constraint in `VerifyResourceTokenAsync`
  (step 7) is unchanged.
- **DISCOVERY (mid-phase, surfaced to user).** Adding `aauth-mission` on the
  signing side alone would **break** every mission-context request: the
  production verifier `AAuthVerifier.Verify` rigidly rejected any covered
  component beyond the base 4 + optional `authorization` (threw when
  `components.Count > 5`). This required extending the verifier +
  `AAuthVerificationMiddleware`, two files **not** in the original Phase 2 file
  list. **User approved** adding them (design decision D5).
- **Covered-component ordering (D6, resolved per spec).** Spec
  §Authorization Endpoint Request shows mission context as
  `("@method" "@authority" "@path" "signature-key" "aauth-mission")` — i.e.
  `aauth-mission` is the **last** component, after `signature-key`. The signer
  appends it after the (pre-existing) `authorization` block, so the verifier
  accepts the optional trailing pair `authorization` then `aauth-mission`.
  **Pre-existing deviation noted:** the spec's §AAuth-Access example places
  `authorization` *before* `signature-key`, but the SDK appends it *after*;
  re-aligning that is out of Phase 2 scope (would churn existing tests).
- **No double-cover.** `aauth-mission` is added to the signer's `seen` set so an
  explicit `AdditionalComponentsKey` request for it is ignored (covered once via
  header auto-detection). Test asserts a single occurrence.
- **Header value consistency.** Signer covers the verbatim `AAuth-Mission` header
  value (`approver="..."; s256="..."` via `AAuthMissionHeader.FormatStructured`).
  Middleware passes `req.Headers["AAuth-Mission"].FirstOrDefault()`; single-valued
  in practice so producer and verifier see identical bytes.
- **Files:** `MissionClaim.cs` (new); modified `ResourceTokenBuilder.cs`,
  `AuthTokenBuilder.cs`, `TokenVerifier.cs`, `AAuthSigningHandler.cs`,
  `AAuthVerifier.cs`, `AAuthVerificationMiddleware.cs`. **Tests:**
  `Missions/MissionClaimTests.cs` (6), `HttpSignatures/MissionSignedComponentTests.cs`
  (5) — note `MissionClaimTests` placed under `Missions/` (no `Tokens/` folder
  exists in the conformance project).
- **Validation:** 375 conformance (+11) + 371 unit tests green; full solution
  builds 0/0.
