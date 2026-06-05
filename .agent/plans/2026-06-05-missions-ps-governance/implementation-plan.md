# Missions & PS Governance — Implementation Plan

## Overview

Bring the .NET SDK, samples, and docs into alignment with the AAuth spec's
**mission** model and the **Person Server as the contextual policy evaluation
point**. Fix the divergent `Mission` model, add the mission cryptographic
binding through the token chain, implement the PS governance endpoints
(client + minimal server seams), then update samples and docs to showcase the
end-to-end mission flow, with a final multi-subagent review.

See [research.md](research.md) for the full spec model and gap inventory
(G1–G20). Every phase below cites the governing spec section in
`aauth-spec/draft-hardt-oauth-aauth-protocol.md`.

## Context

- **Spec:** `draft-hardt-oauth-aauth-protocol` — §Missions, §Mission Approval,
  §Mission Management, §Mission Status Errors, §Resource Token, §Auth Token,
  §Authorization Endpoint Request (signed `aauth-mission`), §PS Token Endpoint,
  §Clarification Chat, §Permission/Audit/Interaction Endpoints, §Person Server
  Metadata, §Policy Evaluation Points, §Why Missions Are Not a Policy Language.
- **Branch:** TBD.
- **Sequencing:** Phases 1→5 are SDK; Phase 6 samples; Phase 7 docs; Phase 8 review.
  Samples (6) and docs (7) are intentionally separate phases per the agreed
  workflow.

## Cross-Cutting Decisions

The spec and SDK are both still in **draft** and backward compatibility is **not**
a concern. Breaking changes to existing types, method signatures, DI registration,
and the HTTP-signature covered-components contract are acceptable; callers are
updated in place. This resolves prior open questions Q2 and Q3 directly:

- **D1 — `Mission` replacement (resolved):** Replace `Mission` in place with the
  spec blob. No rename, no `[Obsolete]` shim, no dual model — update all callers.
- **D2 — `aauth-mission` signing (resolved):** Auto-cover `aauth-mission` in
  `AAuthSigningHandler` when the header is present. No explicit
  `AdditionalComponentsKey` fallback path is required.
- **D3 — Server governance depth** (research Q4): SDK ships DTOs + serialization
  + minimal endpoint mappers + store/relay interfaces; full policy stays in
  MockPersonServer. (Scope choice, unaffected by compat.)
- **D4 — Verbatim mission bytes** (research Q1): model retains raw approval body
  bytes for `s256`; no re-serialization. (Correctness requirement for `s256`.)

---

## Phase 1 — Mission model & `s256` identity

**Goal:** Replace the stale `Mission` model with the spec mission blob, store the
verbatim approval bytes, and compute/verify `s256`. Fixes G1–G4, G17.

**Spec:** §Mission Approval (blob fields; `s256` = base64url(SHA-256(exact body
bytes)), store bytes "no re-serialization"); §Mission Management (states
`active`/`terminated`); §Mission Approval (`capabilities` union into
`AAuth-Capabilities`).

### Files

| File | Action |
|------|--------|
| `src/AAuth/Agent/Mission.cs` | **Rewrite** — spec blob fields + raw bytes + `s256` |
| `src/AAuth/Agent/MissionState.cs` | **New** — `active`/`terminated` |
| `src/AAuth/Agent/MissionTool.cs` | **New** — `{name, description}` record |
| `src/AAuth/Crypto/` (existing hash util) or `Agent/Mission.cs` | **Modify/Use** — SHA-256 + base64url over raw bytes |
| `src/AAuth/Agent/AAuthCapabilitiesHeader.cs` | **Modify** — `Union(missionCapabilities, agentCapabilities)` |
| `tests/AAuth.Conformance/Missions/MissionModelTests.cs` | **New** |
| `tests/AAuth.Conformance/Missions/MissionS256Tests.cs` | **New** |

### API Surface (illustrative)

```csharp
public sealed class Mission
{
    public required string Approver { get; init; }
    public required string Agent { get; init; }
    public required DateTimeOffset ApprovedAt { get; init; }
    public required string Description { get; init; }       // Markdown
    public IReadOnlyList<MissionTool> ApprovedTools { get; init; }
    public IReadOnlyList<string> Capabilities { get; init; }
    public required string S256 { get; init; }              // computed identity
    public ReadOnlyMemory<byte> RawBytes { get; }           // verbatim approval body

    public static Mission FromApprovalBytes(ReadOnlySpan<byte> body); // parse + compute s256
    public bool VerifyS256(string expected);
}
```

### Implementation Decisions

- D1: replace `Mission` in place; update all callers (no shim).
- D4 byte source: parse from the `mission_endpoint` response body bytes.

### Definition of Done

- [x] `Mission` exposes spec blob fields; non-spec fields removed.
- [x] States limited to `active`/`terminated` (§Mission Management).
- [x] `s256` computed as base64url(SHA-256(raw bytes)); raw bytes stored verbatim.
- [x] `VerifyS256` round-trips against a known-good blob fixture.
- [x] `AAuthCapabilitiesHeader.Union` merges mission ∪ agent capabilities (deduped).
- [x] Model + `s256` tests pass; no re-serialization in the hash path.
- [x] All existing callers updated to the new model (no shim).

---

## Phase 2 — Mission binding through the token chain

**Goal:** Carry `{approver, s256}` as the `mission` claim in resource and auth
tokens, surface it on verification, and ensure `aauth-mission` is covered by the
HTTP signature. Fixes G9–G12.

**Spec:** §Resource Token Structure (`mission` claim when `AAuth-Mission`
present; `agent_jkt`); §Resource Token Verification step 7; §Auth Token
Structure (`mission` claim); §Auth Token Verification; §Authorization Endpoint
Request (~L619, add `aauth-mission` to signed components).

### Files

| File | Action |
|------|--------|
| `src/AAuth/Tokens/ResourceTokenBuilder.cs` | **Modify** — first-class `Mission` ({approver,s256}) claim |
| `src/AAuth/Tokens/AuthTokenBuilder.cs` | **Modify** — first-class `Mission` claim |
| `src/AAuth/Tokens/TokenVerifier.cs` | **Modify** — surface `mission` on auth-token verify result |
| `src/AAuth/Tokens/VerifiedToken*.cs` | **Modify** — expose parsed `mission` |
| `src/AAuth/HttpSig/AAuthSigningHandler.cs` | **Modify** — auto-cover `aauth-mission` when header present (D2) |
| `tests/AAuth.Conformance/Tokens/MissionClaimTests.cs` | **New** |
| `tests/AAuth.Conformance/HttpSignatures/MissionSignedComponentTests.cs` | **New** |

### Implementation Decisions

- D2 (resolved): auto-cover `aauth-mission` in `AAuthSigningHandler` when the
  header is present; signing method signatures may change as needed.

### Definition of Done

- [ ] `ResourceTokenBuilder` emits `mission` claim when a mission is present (§Resource Token).
- [ ] `AuthTokenBuilder` emits `mission` claim when a mission is present (§Auth Token).
- [ ] `TokenVerifier` exposes the verified `mission` claim on auth tokens.
- [ ] When `AAuth-Mission` header present, `aauth-mission` appears in
      `Signature-Input` covered components (§Authorization Endpoint Request).
- [ ] Covered-components contract updated; token/signature tests adjusted to match.

---

## Phase 3 — PS token-request params, clarification chat, mission errors

**Goal:** Complete the PS token endpoint client surface: missing request
parameters, the clarification chat loop, and `mission_terminated` handling.
Fixes G13, G14, G16.

**Spec:** §Agent Token Request (params `justification`, `login_hint`, `tenant`,
`domain_hint`, `platform`, `device`); §Clarification Chat (`requirement=
clarification`; agent responses: `clarification_response` POST / updated
`resource_token` POST / `DELETE` cancel; round limit; sanitization is PS-side);
§Mission Status Errors (`403 mission_terminated`).

### Files

| File | Action |
|------|--------|
| `src/AAuth/Agent/TokenExchangeRequest.cs` | **Modify** — add `Justification`, `LoginHint`, `Tenant`, `DomainHint`, `Platform`, `Device` |
| `src/AAuth/Agent/TokenExchangeClient.cs` | **Modify** — emit new params; detect `requirement=clarification` |
| `src/AAuth/Agent/DeferredPoller.cs` | **Modify** — allow POST/DELETE to pending URL |
| `src/AAuth/Agent/ClarificationExchange.cs` | **New** — respond / update / cancel actions + round tracking |
| `src/AAuth/Headers/ClarificationRequirement.cs` | **New** — parse `{clarification, timeout?, options?}` |
| `src/AAuth/Errors/TokenError.cs` | **Modify** — add `mission_terminated` |
| `src/AAuth/Errors/AAuthMissionTerminatedException.cs` | **New** |
| `tests/AAuth.Conformance/Missions/ClarificationChatTests.cs` | **New** |
| `tests/AAuth.Conformance/Missions/MissionTerminatedTests.cs` | **New** |

### Definition of Done

- [ ] All six token-request params serialized into the POST body (§Agent Token Request).
- [ ] `requirement=clarification` parsed into a typed model (question/timeout/options).
- [ ] Agent can `clarification_response` POST, updated-`resource_token` POST, and
      `DELETE`-cancel against the pending URL (§Agent Response to Clarification).
- [ ] Clarification round limit enforced (default 5) (§Clarification Limits).
- [ ] `403 mission_terminated` → `AAuthMissionTerminatedException` across PS calls
      (§Mission Status Errors).
- [ ] New tests pass; existing deferred/interaction tests unaffected.

---

## Phase 4 — PS governance clients + metadata discovery

**Goal:** Add agent-side clients for `mission_endpoint`, `permission_endpoint`,
`audit_endpoint`, `interaction_endpoint`, with DTOs, and parse the missing
metadata endpoints. Fixes G5–G8, G15, G19.

**Spec:** §Mission Creation; §Permission Endpoint; §Audit Endpoint;
§Interaction Endpoint; §Person Server Metadata. Audit **requires** a mission;
permission/interaction optional. Reuse the deferred/`202` loop from Phase 3.

### Files

| File | Action |
|------|--------|
| `src/AAuth/Discovery/ServerMetadata.cs` | **Modify** — parse `permission_endpoint`, `audit_endpoint` |
| `src/AAuth/Agent/Governance/MissionClient.cs` | **New** — propose/approve (handles `202` review) |
| `src/AAuth/Agent/Governance/PermissionClient.cs` | **New** — `{action,description?,parameters?,mission?}` → granted/denied |
| `src/AAuth/Agent/Governance/AuditClient.cs` | **New** — fire-and-forget `201` (requires mission) |
| `src/AAuth/Agent/Governance/InteractionClient.cs` | **New** — interaction/payment/question/completion |
| `src/AAuth/Agent/Governance/*Request.cs` / `*Response.cs` | **New** — DTOs |
| `tests/AAuth.Conformance/Missions/GovernanceClientTests.cs` | **New** |

### Definition of Done

- [ ] `ServerMetadata` parses all four governance endpoints (§Person Server Metadata).
- [ ] `MissionClient.ProposeAsync` returns an approved `Mission` (verifies `s256`,
      handles `202` review/clarification) (§Mission Creation).
- [ ] `PermissionClient.RequestAsync` returns granted/denied, honoring
      `approved_tools` short-circuit and deferred responses (§Permission Endpoint).
- [ ] `AuditClient.RecordAsync` is fire-and-forget, requires a mission, expects
      `201` (§Audit Endpoint).
- [ ] `InteractionClient` supports all four `type` values incl. `completion`
      terminate/continue (§Interaction Endpoint).
- [ ] `mission_terminated` surfaces from each client (Phase 3 exception).
- [ ] Client tests pass against a stub PS.

---

## Phase 5 — PS server-side governance seams + mission log

**Goal:** Provide minimal SDK primitives so a PS (e.g. MockPersonServer) can
serve the governance endpoints without hand-rolling parsing: request parsing,
response helpers, store/relay interfaces, and a mission-log seam. Fixes G18, G20
(per decision D3 — thin seams, not a full PS).

**Spec:** §PS Governance Endpoints; §Mission Log; §Mission Status Errors;
§Policy Evaluation Points (PS evaluates against mission intent + log).

### Files

| File | Action |
|------|--------|
| `src/AAuth/Server/Governance/IMissionStore.cs` | **New** — persist blob bytes + state |
| `src/AAuth/Server/Governance/IPermissionDecider.cs` | **New** |
| `src/AAuth/Server/Governance/IAuditSink.cs` | **New** |
| `src/AAuth/Server/Governance/IInteractionRelay.cs` | **New** |
| `src/AAuth/Server/Governance/IMissionLog.cs` | **New** — ordered append; read |
| `src/AAuth/Server/Governance/GovernanceEndpoints.cs` | **New** — minimal request parse + `mission_terminated` helper (optional minimal-API mappers) |
| `src/AAuth/DependencyInjection/*` | **Modify** — register governance seams |
| `tests/AAuth.Conformance/Missions/GovernanceServerTests.cs` | **New** |

### Implementation Decisions

- D3 boundary: SDK = DTO parse + helpers + interfaces; policy/UI in mock.
- `IPermissionDecider` returns a typed decision **with a reason** (in-scope /
  prior consent / `approved_tools` / out-of-scope → prompt) so a PS can both act
  on it and surface it to UIs; the SDK provides the inputs + reason enum, the PS
  owns the policy (§Agent Token Request L385/L784/L828, §Permission L1017).

### Definition of Done

- [ ] Request parsers for permission/audit/interaction/mission-create map to DTOs.
- [ ] `mission_terminated` helper emits spec `403` body (§Mission Status Errors).
- [ ] `IMissionStore` stores verbatim blob bytes + `active`/`terminated` state.
- [ ] `IMissionLog` appends token/permission/audit/interaction/clarification
      entries in order, and supports a prior-consent read keyed by
      `(s256, resource, scope)` (§Mission Log, §Agent Token Request L784).
- [ ] `IPermissionDecider` is invoked with mission + log context for the consent
      decision (§Person Server L385).
- [ ] DI registration wires the seams.
- [ ] Server-seam tests pass.

---

## Phase 6 — Samples

**Goal:** Showcase the end-to-end mission flow across actors. Update
MockPersonServer to a real governance PS and add an agent-side mission demo.

**Spec:** §Missions; §PS Governance Endpoints; §Call Chaining (mission context);
§Agent Token Request (consent decision: L385, L784, L828); §Permission Endpoint
(`approved_tools`: L1017); the three worked flows in research (single-resource,
multi-resource + permission/audit/interaction, multi-hop chaining).

Missions are an **optional, orthogonal** governance layer (§Overview L141, L201;
§Missions L397). Existing samples demonstrate valid no-mission flows and are
**not** spec-incorrect; the mission flow is **added alongside** them, not a
rewrite of existing flows.

### Files

| File | Action |
|------|--------|
| `samples/MockPersonServer/Program.cs` | **Modify** — serve `mission_endpoint`, `permission_endpoint`, `audit_endpoint`, `interaction_endpoint`; embed `mission` claim in issued auth tokens; compute `s256`; implement the three-gate consent decision and record a decision reason (in-scope / prior consent / `approved_tools` / out-of-scope) in the mission log so samples can display it; expose a minimal "terminate mission" demo hook; maintain mission log via Phase 5 seams |
| `samples/MockPersonServer/README.md` | **Modify** |
| `samples/MissionAgent/` | **New** — dedicated CLI agent: propose mission → operate under it → permission + audit + interaction → completion |
| `samples/Orchestrator/Program.cs` | **Modify** — show mission-governed downstream hop (call chaining) |
| `samples/SampleApp/Components/Pages/Mission.razor` | **New** — golden one-page mission example; visualizes all three consent gates, each labelled **prompt** vs **silent (in scope)** |
| `samples/SampleApp/Components/Pages/Home.razor` | **Modify** — add mission page link/card |
| `samples/GuidedTour/TourOptions.cs` | **Modify** — add `TourMode.Mission` |
| `samples/GuidedTour/TourSession.cs` | **Modify** — multi-step mission plan that drives each gate through **both** outcomes: (1) mission approval prompt; (2) in-scope token request that resolves **silently**; (3) out-of-scope token request that **prompts**; (4) `approved_tools` permission that resolves **silently**; (5) non-pre-approved permission that **prompts**; then audit / interaction / complete |
| `samples/GuidedTour/CodeSnippets.cs` | **Modify** — mission client snippets |
| `samples/GuidedTour/Components/SequenceDiagram.razor` (+ `EntityHighlighter`) | **Modify** — render mission interactions; mark each step **prompt** vs **silent** and show the decision reason (in-scope / prior consent / `approved_tools`) |
| `samples/GuidedTour/playwright-tests/mission.spec.ts` | **New** — drives `TourMode.Mission`; asserts each gate's **prompt** vs **silent** outcome + decision reason |
| `samples/SampleApp/playwright-tests/mission.spec.ts` | **New** — exercises `Mission.razor`; asserts prompt vs silent gate labels |
| `tests/e2e/playwright.config.ts` | **Modify (if needed)** — mission specs reuse existing `guided-tour`/`sample-app` projects + booted backends; add a PS env/policy toggle only if the silent-vs-prompt scenario needs pre-seeded `approved_tools` |
| `tests/e2e/README.md` | **Modify** — document the mission specs |
| `tests/AAuth.Tests/Integration/MissionAgentFlowTests.cs` (or a dedicated integration test project) | **New** — **.NET integration test**: boot MockPersonServer + WhoAmI + MockAgentProvider, run `samples/MissionAgent`, and assert **every consent permutation** (see Consent Test Matrix) plus the `mission_terminated` path |
| `Makefile` | **Modify** — add `demo-mission` target and an `e2e-mission` target |
| `tests/e2e/package.json` | **Modify** — add `test:mission` script (Blazor mission specs) |
| `samples/README.md` | **Modify** — index the mission demo |

### Implementation Decisions

- **Test split:** Blazor apps (GuidedTour, SampleApp) are covered by **Playwright
  e2e** in `tests/e2e/`; the `MissionAgent` CLI is covered by a **.NET
  integration test** under `tests/` (spawns servers + CLI), run via `dotnet test`.
- **Sample shape:** new dedicated `samples/MissionAgent/` (not extending
  AgentConsole) for a legible showcase; SampleApp gets a new `Mission.razor`
  page; GuidedTour gets a new `TourMode.Mission` with a multi-step plan
  (mirroring the federated multi-step style). Existing flows untouched.
- **`make demo` integration:** separate `make demo-mission` target (like
  `demo-keycloak`) to keep the default `make demo` bundle uncluttered.
- **Consent decision (three gates)** — the PS prompts the user only when needed,
  not on every deferred point (§Agent Token Request L385/L784/L828, §Permission
  L1017):
  1. **Mission approval** — always prompt once at mission proposal
     (§Mission Creation).
  2. **Token request** — silent when the resource+scope is within the approved
     mission intent or matches a remembered prior consent in the mission log;
     otherwise prompt (L385, L784, L828).
  3. **Permission request** — silent when the action matches `approved_tools`;
     otherwise prompt (L1017).
  Prior-consent memory keyed by `(mission s256, resource, scope)`. The decision
  is mock PS policy implemented over the Phase 5 `IPermissionDecider` /
  `IMissionStore` / mission-log seams — not SDK behavior.

#### Consent Test Matrix (CLI integration test)

The `MissionAgent` integration test MUST cover **all** permutations of the three
gates — both decision outcomes (approve/deny) and both PS paths (prompt/silent):

| # | Gate | Scenario | Expected |
|---|------|----------|----------|
| 1 | Mission approval | user **approves** the proposed mission | `active` mission, `s256` bound |
| 2 | Mission approval | user **denies** the proposed mission | no mission; agent aborts cleanly |
| 3 | Token request | resource+scope **within** approved mission intent | **silent**, reason = in-scope |
| 4 | Token request | resubmit same `(s256, resource, scope)` after prior consent | **silent**, reason = prior consent |
| 5 | Token request | **out-of-scope** resource/scope → user **approves** | prompt → auth token issued |
| 6 | Token request | **out-of-scope** resource/scope → user **denies** | prompt → access denied |
| 7 | Token request (clarification) | user asks a question; agent responds; user approves | clarification round then issue |
| 8 | Token request (clarification) | agent **cancels** via `DELETE` | pending `410 Gone`; no token |
| 9 | Permission | action **in** `approved_tools` | **silent**, reason = approved_tools |
| 10 | Permission | action **not** pre-approved → user **approves** | prompt → granted |
| 11 | Permission | action **not** pre-approved → user **denies** | prompt → denied |
| 12 | Termination | mission terminated mid-flow, agent retries | `403 mission_terminated` surfaced |

The PS consent decisions are driven deterministically in the test (scripted
approve/deny + pre-seeded `approved_tools` / prior-consent state) so each row is
reproducible without manual interaction. Each row also asserts the recorded
mission-log **decision reason**.

### Definition of Done

- [ ] MockPersonServer serves all four governance endpoints (§PS Governance).
- [ ] MockPersonServer embeds `{approver, s256}` in issued auth tokens (§Auth Token).
- [ ] MockPersonServer implements the three-gate consent decision: mission approved
      once, then resource/tool access proceeds without re-prompting unless outside
      approved scope / `approved_tools` (§Agent Token Request, §Permission Endpoint).
- [ ] MockPersonServer exposes a minimal "terminate mission" hook so the
      `mission_terminated` path is exercised end-to-end (§Mission Status Errors).
- [ ] `samples/MissionAgent/` proposes a mission, accesses ≥1 resource under it,
      requests a permission, records an audit entry, relays an interaction, and
      completes it.
- [ ] SampleApp `Mission.razor` page renders the flow and labels each consent gate
      as **prompt** or **silent (in scope)**; Home links to it; existing pages
      unchanged.
- [ ] GuidedTour `TourMode.Mission` drives every gate through **both** outcomes
      (mission approval prompt; in-scope token silent vs out-of-scope token prompt;
      `approved_tools` permission silent vs non-pre-approved permission prompt) and
      surfaces the PS decision reason for each; existing modes unchanged.
- [ ] The PS decision reason (in-scope / prior consent / `approved_tools` /
      out-of-scope) is visible in both samples so the contrast between prompted
      and silent gates is observable.
- [ ] Orchestrator demonstrates a mission-governed downstream hop (§Call Chaining).
- [ ] `make demo-mission` boots the mission demo; existing `make demo` unchanged.
- [ ] New GuidedTour + SampleApp mission Playwright **e2e** specs pass under the
      existing `guided-tour`/`sample-app` projects; existing specs still pass.
- [ ] **.NET integration test** for the `MissionAgent` CLI covers **all 12 rows**
      of the Consent Test Matrix (every gate × approve/deny × prompt/silent),
      including clarification and `mission_terminated`, each asserting the
      recorded decision reason.
- [ ] `make e2e` (Blazor) and `dotnet test` (CLI integration) green locally and in CI.
- [ ] Sample READMEs updated.

---

## Phase 7 — Docs

**Goal:** Rewrite the stale missions doc and add PS-governance docs reflecting the
implemented surface. Separate phase from samples per the agreed workflow.

**Spec:** §Missions; §Mission Approval; §Mission Log; §Policy Evaluation Points;
§Why Missions Are Not a Policy Language; §Permission/Audit/Interaction Endpoints;
§Clarification Chat.

### Files

| File | Action |
|------|--------|
| `docs/advanced/missions.md` | **Rewrite** — spec blob, `s256`, two states, lifecycle, binding chain |
| `docs/server/mission-governance.md` | **New** — PS as contextual policy point; permission/audit/interaction; mission log |
| `docs/workflows/mission-governed-access.md` | **New** — end-to-end walkthrough (the three research flows) |
| `docs/server/token-issuance.md` | **Modify** — add `s256` verify + mission claim emission |
| `docs/workflows/call-chaining.md` | **Modify** — mission forwarding + governance |
| `docs/concepts.md` / `docs/README.md` | **Modify** — index + concept of PS policy enforcement |

### Definition of Done

- [ ] `docs/advanced/missions.md` matches the implemented model (no stale fields/states).
- [ ] New governance doc explains the deterministic-vs-contextual split
      (§Why Missions Are Not a Policy Language).
- [ ] Walkthrough doc covers create → operate → permission → audit → interaction →
      completion, with the binding chain.
- [ ] All doc code samples compile against the Phase 1–5 API.
- [ ] docs index/README updated; cross-links valid.

---

## Phase 8 — Review

**Goal:** Validate each logical change set against the spec and the plan with a
dedicated subagent per set, then remediate findings.

### Review subagents (one per change set)

| # | Change set | Scope |
|---|------------|-------|
| R1 | Mission model + `s256` (Phase 1) | spec §Mission Approval/Management fidelity |
| R2 | Token binding + HTTPSig (Phase 2) | §Resource/Auth Token, §signed `aauth-mission` |
| R3 | Token params + clarification + errors (Phase 3) | §Agent Token Request, §Clarification Chat, §Mission Status Errors |
| R4 | Governance clients + metadata (Phase 4) | §Permission/Audit/Interaction, §PS Metadata |
| R5 | Server seams + mission log (Phase 5) | §PS Governance, §Mission Log |
| R6 | Samples (Phase 6) | flows run end-to-end; spec-faithful |
| R7 | Docs (Phase 7) | accuracy vs implemented API + spec |

### Definition of Done

- [ ] Each review subagent produces severity-graded findings with spec citations.
- [ ] All critical/high findings remediated or explicitly deferred (with rationale).
- [ ] Full solution builds; `AAuth.Tests` + `AAuth.Conformance` green.
- [ ] e2e mission flow green.
- [ ] research.md updated with any spec/behavior corrections discovered.

---

## Out of Scope

| Item | Reason |
|------|--------|
| Full AS implementation in SDK | SDK ships builders + verification; AS stays in mock/Keycloak |
| Mission revocation / delegation-tree queries / admin APIs | Spec defers to a companion specification (§Mission Management) |
| Payment settlement (x402/MPP) beyond surfacing `402` | Out of AAuth core scope; already surfaced as exception |
| Cross-PS agent correlation / multi-device regrouping | PS-side concern per bootstrap spec; not SDK |
| Pairwise `sub` directed-identifier generation strategy | Existing PS-asserted work; not mission-specific. Mock reuses its existing `sub` generation as-is; the `mission` claim is additive alongside it |
