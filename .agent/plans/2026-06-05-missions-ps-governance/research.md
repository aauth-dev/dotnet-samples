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

### Phase 3 — PS token-request params, clarification chat, mission errors (2026-06-05, complete)

- **Token-request params (§Agent Token Request).** Added six optional `string?`
  properties to `TokenExchangeRequest` — `Justification`, `LoginHint`, `Tenant`,
  `DomainHint`, `Platform`, `Device` — serialized into the POST body as
  `justification`, `login_hint`, `tenant`, `domain_hint`, `platform`, `device`
  via a new `AddIfPresent` helper that omits unset/empty values.
- **Clarification model (§Clarification Chat).** `ClarificationRequirement`
  (`src/AAuth/Headers/ClarificationRequirement.cs`) parses the `202` body
  `{clarification, timeout?, options?}` for `requirement=clarification`,
  modeled on the existing `ClaimsRequirement`. Throws `FormatException` when the
  `clarification` string is missing.
- **Clarification API design (D7, user-approved).** The agent supplies a
  callback `OnClarificationRequired` on `TokenExchangeRequest` (mirrors
  `OnInteractionRequired`) that returns a `ClarificationResponse` *decision*
  object. `ExchangeAsync`'s response handling was rewritten into a
  `while (StatusCode == 202)` loop that resolves the requirement, dispatches
  interaction vs. clarification, applies the decision, and re-polls.
- **ClarificationResponse + ClarificationExchange.** `ClarificationResponse`
  (nested `Kind { Respond, Update, Cancel }`) carries the agent's choice; the
  factories are `Respond(markdown)`, `Update(resourceToken, justification?)`,
  `Cancel()`. `ClarificationExchange` performs the wire calls against the pending
  URL: `clarification_response` POST, updated `resource_token` POST, and `DELETE`
  cancel (which surfaces `AAuthClarificationCancelledException`).
- **Round limit (§Clarification Limits).** Default `MaxRounds = 5` (configurable
  via `TokenExchangeRequest.MaxClarificationRounds`); `Respond`/`Update` consume a
  round, `Cancel` does not. Exceeding the limit throws
  `AAuthClarificationLimitException`.
- **DEVIATION FROM PLAN FILE LIST.** The plan listed `DeferredPoller.cs` as
  **Modify — allow POST/DELETE to pending URL**. In implementation the POST/DELETE
  calls live entirely in `ClarificationExchange` (using its own `HttpClient`),
  and the clarification-stop during polling reuses the **existing**
  `DeferredPollerOptions.StopWhenAccepted` predicate (composed via
  `ComposePollerOptions`). `DeferredPoller.cs` was therefore **not** modified.
- **Mission-terminated (§Mission Status Errors).** Added `TokenErrorCode.
  MissionTerminated` (`mission_terminated`, round-trips through `TokenErrorResponse`)
  and `AAuthMissionTerminatedException` (with `MissionStatus`). `ExchangeAsync`
  classifies a terminal `403` body `{error:"mission_terminated", mission_status}`
  via `TryReadMissionTerminatedAsync` — both on the direct token response and on a
  `403` surfaced during polling (the poller returns the unrecognized `403` rather
  than throwing, so the client classifies it). A shared `BufferBodyAsync` lets the
  `access_denied`, `mission_terminated`, and auth-token readers all re-read the body.
- **Files:** new `Headers/ClarificationRequirement.cs`, `Agent/ClarificationExchange.cs`
  (holds `ClarificationResponse` + `ClarificationExchange`),
  `Errors/AAuthMissionTerminatedException.cs`; modified `Agent/TokenExchangeRequest.cs`,
  `Agent/TokenExchangeClient.cs`, `Agent/AAuthInteractionExceptions.cs` (added
  `AAuthClarificationCancelledException`, `AAuthClarificationLimitException`),
  `Errors/TokenError.cs`. **Tests:** `Missions/ClarificationChatTests.cs` (8),
  `Missions/MissionTerminatedTests.cs` (3), and an **added** (not in original plan
  list) `Missions/TokenRequestParamsTests.cs` (2) covering the six params.
- **Validation:** 388 conformance (+13) + 371 unit tests green; full solution
  builds 0/0.

### Phase 4 — PS governance clients + metadata discovery (2026-06-05, complete)

- **Metadata (§Person Server Metadata, ~L2199).** `ServerMetadata.FromJson`
  already parsed `mission_endpoint` + `interaction_endpoint`; added
  `permission_endpoint` and `audit_endpoint`, so all four governance endpoints
  (all OPTIONAL in spec) are now surfaced. The clients resolve an endpoint by
  fetching the PS `aauth-person.json`, validating https-or-loopback, and
  origin-pinning the returned URL to the PS authority.
- **Shared exchange (DEVIATION — added beyond plan file list).** A new
  `Agent/Governance/GovernanceExchange.cs` holds the common signed-POST +
  deferred-`202` loop + `mission_terminated` classification + endpoint
  origin-pinning, plus a public `GovernanceOptions`
  (`OnInteractionRequired`, `OnClarificationRequired`, `MaxClarificationRounds`,
  `PollerOptions`). This mirrors `TokenExchangeClient`'s deferred/clarification
  loop. **Design note for user:** `GovernanceExchange` duplicates some
  `TokenExchangeClient` logic; `TokenExchangeClient` was deliberately left
  untouched (zero regression risk). A future shared-helper refactor is possible
  if desired.
- **MissionClient (§Mission Creation ~L399/L1228, §Mission Approval ~L1265).**
  `ProposeAsync(personServer, MissionProposal, options?, ct)` posts
  `{description, tools?}` to `mission_endpoint`, handles the `202` review/
  clarification loop, then reads the approval body **verbatim** and calls
  `Mission.FromApprovalBytes`. It parses the `AAuth-Mission` header's `s256` and
  verifies it against the recomputed blob hash (throws on mismatch/missing).
- **PermissionClient (§Permission Endpoint ~L1013).** `RequestAsync` posts
  `{action, description?, parameters?, mission?}` → `200 {permission, reason?}`.
  An overload taking a `Mission` short-circuits to `Granted`
  ("Pre-approved tool on the active mission.") when the action matches
  `mission.ApprovedTools`, **without** calling the PS (spec `approved_tools`).
- **AuditClient (§Audit Endpoint ~L1077).** `RecordAsync` posts
  `{mission, action, description?, parameters?, result?}` (mission REQUIRED),
  returns on `201`/`200`/`204` (fire-and-forget); `mission_terminated` surfaces
  via `GovernanceExchange`.
- **InteractionClient (§Interaction Endpoint ~L1131).** `SendAsync` posts
  `{type, ...}` for all four `type` values; `question` → `Answer` from
  `body["answer"]`, `completion` → `Terminated` when `mission_status != "active"`.
  Convenience helpers: `RelayInteractionAsync`, `RelayPaymentAsync`,
  `AskQuestionAsync`, `ProposeCompletionAsync`. (DEVIATION — added
  `InteractionResult.cs` DTO not explicitly in plan list.)
- **DTOs.** `MissionProposal`, `PermissionRequest`/`PermissionResult`
  (`PermissionGrant` enum), `AuditRecord`, `InteractionRequest`
  (`InteractionType` enum)/`InteractionResult`. Each request DTO has an
  `internal ToJsonObject()`; `PermissionResult.FromJson` maps granted/denied.
- **Layering decision.** Agent DTOs own serialization (`ToJsonObject`); the
  server side owns parsing (Phase 5 `GovernanceEndpoints.Parse*`). Agent
  governance clients are constructed directly (like `TokenExchangeClient`) and
  are **not** DI-registered.
- **Files:** modified `Discovery/ServerMetadata.cs`; new
  `Agent/Governance/{GovernanceExchange,MissionProposal,MissionClient,
  PermissionRequest,PermissionResult,PermissionClient,AuditRecord,AuditClient,
  InteractionRequest,InteractionResult,InteractionClient}.cs`. **Tests:**
  `Missions/GovernanceClientTests.cs` (12) against a stub PS.
- **Validation:** 399 conformance (+11) + 371 unit green; SDK + full solution
  build 0/0.

### Phase 5 — PS server-side governance seams + mission log (2026-06-05, complete)

- **Decision boundary (D3).** The SDK ships thin server-side seams — request
  parsers, a `mission_terminated` helper, storage interfaces + in-memory
  defaults, and the policy/relay interfaces — so a PS can serve the governance
  endpoints without hand-rolling parsing. Policy and UI live in the PS
  (MockPersonServer, Phase 6).
- **Request parsers (§PS Governance Endpoints ~L463).**
  `GovernanceEndpoints.Parse{Permission,Audit,Interaction,MissionProposal}`
  map a `JsonObject` to the Phase 4 DTOs, throwing `FormatException` on missing
  required fields (`action`; `mission`+`action`; `type`; `description`) and on
  unknown interaction `type`. Mission objects are read via
  `MissionClaim.FromPayload`. This keeps parsing **server-side** rather than
  adding `FromJson` to the agent DTOs (clean agent-serializes / server-parses
  split).
- **Mission-terminated helper (§Mission Status Errors ~L1331).**
  `MissionTerminatedStatus = 403`; `MissionTerminatedBody(missionStatus =
  "terminated")` emits `{error:"mission_terminated", mission_status}` (error code
  from `AAuthMissionTerminatedException.ErrorCode`); `MissionTerminated(...)`
  returns an `IResult` via `Results.Json(..., statusCode: 403)`.
- **Mission store (§Mission Approval — verbatim bytes).** `IMissionStore` +
  `StoredMission(S256, Approver, Agent, Blob)` with `MissionState State`
  (default `Active`). `InMemoryMissionStore` (DEVIATION — added in-memory default,
  mirrors `InMemoryJtiStore`) stores the blob bytes verbatim and transitions
  state via `existing with { State = state }`.
- **Mission log (§Mission Log ~L1310, §Agent Token Request ~L784).** `IMissionLog`
  + `MissionLogEntry(S256, Kind, Timestamp)` with `MissionLogEntryKind`
  {Token, Permission, Audit, Interaction, Clarification} and optional
  Resource/Scope/Action/Granted/Detail. `InMemoryMissionLog` (DEVIATION — added)
  appends in order, `ReadAsync` preserves order, and `HasPriorConsentAsync(s256,
  resource, scope)` returns true only for `Token` entries with `Granted == true`
  matching `(s256, resource, scope)` — the prior-consent context a PS uses to
  skip re-prompting.
- **Decider seam (§Person Server ~L385, §Permission ~L1017).**
  `IPermissionDecider.DecideAsync(PermissionDecisionContext, ct)` is invoked with
  the request + resolved `StoredMission` + ordered log, and returns a
  `PermissionDecision(Outcome, Reason, Message?)` where `PermissionOutcome`
  {Granted, Denied, Prompt} and `PermissionDecisionReason` {InScope, PriorConsent,
  ApprovedTool, OutOfScope}. The SDK supplies the inputs + reason taxonomy; the
  PS owns the policy. `IAuditSink` and `IInteractionRelay` are the audit/relay
  seams.
- **DI.** `AddAAuthGovernance` (`Microsoft.Extensions.DependencyInjection`
  namespace) `TryAddSingleton`s `IMissionStore`→`InMemoryMissionStore` and
  `IMissionLog`→`InMemoryMissionLog`; the policy seams (decider/sink/relay) are
  left for the PS to register.
- **Files:** new `Server/Governance/{IMissionStore,InMemoryMissionStore,
  IMissionLog,InMemoryMissionLog,IPermissionDecider,IAuditSink,IInteractionRelay,
  GovernanceEndpoints}.cs` and
  `DependencyInjection/AAuthGovernanceServiceCollectionExtensions.cs`. **Tests:**
  `Missions/GovernanceServerTests.cs` (17).
- **Validation:** 417 conformance (+18 across Phases 4+5) + 371 unit green; SDK +
  full solution build 0/0.
