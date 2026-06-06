# Mission API Refactor — Implementation Plan

## Overview

Streamline the AAuth .NET SDK's mission/governance surface into an API that can be
constructed three ways — **static factories**, **fluent builders**, and
**DI registration** — for both agent (client) and resource (PS) sides, update every
mission sample and doc to the new surface, add a combined **clarification +
mission + call-chain** SampleApp example, and land two small spec-hardening fixes.

The API surface is built in **two passes**: a first pass (Phase 1) that gets a
working end-to-end surface, then a consistency pass (Phase 2) that learns from the
first and fine-tunes naming/shape to match the conventions already used elsewhere in
the SDK. The closing phases independently audit samples, docs, and spec compliance.

See [research.md](research.md) for the full current-state, pain-point, and gap
inventory (Parts A–G) and the recorded design decisions (Open Design Choices).
Significant issues and spec deviations are logged in
[issues-and-deviations.md](issues-and-deviations.md). Every phase below cites the
governing spec section.

> **R3 (Rich Resource Requests)** is out of scope here — tracked in its own
> initiative, `.agent/plans/2026-06-06-r3-rich-resource-requests/`.

## Working Agreement (2026-06-06)

Directives captured from the user for this initiative:

- **Two-pass API design.** Phase 1 does a first pass at the surface; Phase 2 learns
  from it and fine-tunes for consistency with existing SDK patterns.
- **Construction triad.** Support **static factories**, **fluent builders**, and
  **DI-friendly** registration for the mission/governance API.
- **No regressions.** None of the existing flows may break — old behavior is
  preserved; only the API shape changes.
- **New sample has an e2e spec.** The combined SampleApp page ships with a Playwright
  spec.
- **Closing audits use subagents.** The final sample and doc validation phases each
  use a dedicated subagent to surface inconsistencies and readability issues
  (especially docs, GuidedTour code snippets, and SampleApp).
- **Independent spec reviewer is the last phase.** A separate reviewer subagent
  validates every change against the AAuth spec for 100% compliance. Fix the SDK
  where it is not spec compliant.
- **Deviation tracking.** Significant issues/deviations are recorded in
  [issues-and-deviations.md](issues-and-deviations.md); research is always updated
  with new findings.
- **Gated execution.** Ask the user for permission before starting each phase. Do
  **not** commit until the user says so. Surface major decisions at the end for
  input; refactoring afterward is acceptable.

## Context

- **Spec:** `aauth-spec/draft-hardt-oauth-aauth-protocol.md` — §Agent Governance,
  §Mission Creation/Approval, §Permission Endpoint, §Audit Endpoint, §Interaction
  Endpoint, §Clarification Chat, §Call Chaining, §AAuth-Capabilities, §Person Server
  Metadata, §Agent Token Request.
- **Upcoming:** `aauth-spec/upcoming-changes-02.md` (F1 capabilities body — already
  correct; F5/F6 wait on draft-02).
- **Branch:** `feat/missions-ps-governance` (continue).
- **Sequencing:** Phase 1 API first pass (agent + resource) → Phase 2 API
  consistency pass → Phase 3 spec hardening → Phase 4 sample migration → Phase 5 new
  combined sample + e2e → Phase 6 docs → Phase 7 samples audit (subagent) → Phase 8
  docs audit (subagent) → Phase 9 independent spec-compliance review (subagent).

## Cross-Cutting Decisions

The SDK is pre-1.0 and backward compatibility is **not** a concern (confirmed
2026-06-06). The mission API is a **breaking refactor**: low-level signatures change
and all call-sites are updated in place — no `[Obsolete]` shim, no dual surface.

- **DC1 — Breaking refactor (no shim).** Replace the low-level mission client/
  resource surface; migrate all callers (research Part C inventory).
- **DC2 — Both client + resource ergonomics.** Address agent pain points
  (PT-A1…A6) and resource pain points (PT-R1…R4).
- **DC3 — Align with existing conventions.** Fluent builder like
  `AAuthClientBuilder`; DI like `AddAAuthDiscovery`; app-builder mapper like
  `MapAAuthResource` (research Part B).
- **DC4 — One combined sample page.** Clarification + mission + call-chain in a
  single SampleApp page reusing Orchestrator + WhoAmI as hops.
- **DC5 — Construction triad.** Every primary entry point is reachable via a static
  factory, a fluent builder, and DI registration, mirroring how `AAuthClient`,
  `AddAAuthAgent`, and `MapAAuthResource` already coexist (research Part B).
- **DC6 — No regressions.** All existing mission/clarification/call-chain flows keep
  working; the four mission e2e specs stay green throughout.
- **DC7 — Independent closing review.** Sample audit, doc audit, and spec-compliance
  review are separate final phases, each driven by a dedicated subagent; findings
  are adjudicated against spec text and logged in `issues-and-deviations.md`.

---

## Phase 1 — API surface: first pass (agent + resource)

**Goal:** Get a working end-to-end mission/governance surface across **both** the
agent (client) and resource (PS) sides in one pass. Naming and shape need not be
final here — Phase 2 refines them. Fixes the agent pain points (PT-A1…A6) and the
resource pain points (PT-R1…R4), and lands the construction triad (DC5).

**Spec:** §Agent Governance (governance clients call PS endpoints); §Mission
Creation/Approval (mission carried as `{approver, s256}`); §Permission/Audit/
Interaction Endpoints (per-call mission claim, request/response shapes,
`mission_terminated` 403); §Clarification Chat (deferred 202 handling); §Person
Server Metadata (endpoint advertisement).

### Approach — agent side

- **Bind the PS once.** `AAuthClientBuilder.WithPersonServer(...)` already exists;
  `BuildGovernance()` returns an `AAuthGovernanceClient` bound to that PS so
  per-call `personServer` params are removed (PT-A2).
- **Mission session auto-threads the claim.** `Mission.ProposeAsync(...)` returns a
  `MissionSession` that wraps the approved `Mission` + the bound client and exposes
  `Permission`/`Audit`/`Interaction` calls that inject `{approver, s256}`
  automatically (PT-A1, PT-A5).
- **Construction triad (DC5).** Static factory (`AAuthGovernanceClient.Create(...)`),
  fluent builder (`AAuthClientBuilder…BuildGovernance(...)`), and DI
  (`AddAAuthGovernanceClient(name, Action<options>)` mirroring `AddAAuthAgent`)
  (PT-A4).
- **Default callbacks.** Bound `GovernanceOptions` defaults set once on the builder,
  overridable per call (PT-A6).

### Approach — resource side

- **`MapAAuthGovernance(...)`** app-builder mapper (mirrors `MapAAuthResource`) maps
  `/mission`, `/permission`, `/audit`, `/mission-interaction` and their pending/poll
  routes, using `GovernanceEndpoints` parsers + the registered seams (PT-R1, PT-R2).
- **Default no-op seams** registered via `TryAdd` in `AddAAuthGovernance(configure?)`
  so a PS overrides only what it needs (PT-R3).
- **Resource governance builder** for mission-aware challenge config, replacing the
  bare `ChallengeOptions.MissionAware` bool (PT-R4).

### Files

| File | Action |
|------|--------|
| `src/AAuth/Agent/Governance/AAuthGovernanceClient.cs` | **Modify** — bind PS URL + default `GovernanceOptions`; drop per-call PS param; add `Create(...)` factory |
| `src/AAuth/Agent/Governance/MissionSession.cs` | **New** — mission-scoped facade auto-threading the claim |
| `src/AAuth/Agent/Governance/MissionClient.cs` | **Modify** — `ProposeAsync(proposal, options?)` → `MissionSession` |
| `src/AAuth/Agent/Governance/PermissionClient.cs` | **Modify** — drop PS param; mission injected by session |
| `src/AAuth/Agent/Governance/AuditClient.cs` | **Modify** — drop PS param; mission injected |
| `src/AAuth/Agent/Governance/InteractionClient.cs` | **Modify** — drop PS param; mission injected |
| `src/AAuth/AAuthClientBuilder.cs` | **Modify** — `BuildGovernance()` binds PS + default options |
| `src/AAuth/DependencyInjection/AAuthGovernanceClientServiceCollectionExtensions.cs` | **New** — `AddAAuthGovernanceClient(...)` |
| `src/AAuth/DependencyInjection/AAuthGovernanceApplicationBuilderExtensions.cs` | **New** — `MapAAuthGovernance(Action<AAuthGovernancePipelineOptions>?)` |
| `src/AAuth/DependencyInjection/AAuthGovernanceServiceCollectionExtensions.cs` | **Modify** — `AddAAuthGovernance(configure?)` + default no-op `IPermissionDecider`/`IAuditSink`/`IInteractionRelay` |
| `src/AAuth/Server/Governance/GovernanceEndpoints.cs` | **Modify** — promote per-endpoint handlers (carrier-token check, parse, mission lookup, state check) |
| `src/AAuth/Server/Governance/AAuthGovernancePipelineOptions.cs` | **New** — route prefix + deferred/pending config |
| `src/AAuth/Server/Challenge/ChallengeOptions.cs` | **Modify** — keep `MissionAware`; surface via resource builder |
| `tests/AAuth.Conformance/Missions/GovernanceClientBuilderTests.cs` | **New** |
| `tests/AAuth.Conformance/Missions/GovernanceEndpointMapperTests.cs` | **New** |
| `tests/AAuth.Tests/Governance/MissionSessionTests.cs` | **New** |

### API Surface (illustrative)

```csharp
// Agent — fluent builder + bound PS + mission session
AAuthGovernanceClient governance = AAuthClientBuilder
    .SelfIssuing(key).As(issuer, agentId)
    .WithPersonServer(ps)                 // PS bound once
    .WithChallengeHandling()
    .BuildGovernance(o => o.MaxClarificationRounds = 3);

MissionSession mission = await governance.Mission.ProposeAsync(
    new MissionProposal("Keep the inbox under control") { Tools = [...] });

// claim + PS auto-threaded:
PermissionResult r = await mission.Permission.RequestAsync("send_email");
await mission.Audit.RecordAsync("send_email", result: ...);
bool done = await mission.ProposeCompletionAsync("Inbox triaged.");

// Resource — DI + mapper
builder.Services.AddAAuthGovernance(o => o.UseInMemoryStores());
builder.Services.AddSingleton<IPermissionDecider, SamplePermissionDecider>();
app.MapAAuthGovernance();   // maps the 4 endpoints + pending polls
```

### Implementation Decisions

- DC1: no shim; `MissionSession` replaces manual `MissionClaim` extraction.
- DC3: mapper follows the `MapAAuthResource` precedent; seams keep policy in the PS.
- The bound `AAuthGovernanceClient` remains usable mission-lessly for permission
  requests that carry no mission (§Permission Endpoint — mission optional).
- Default `IInteractionRelay` returns `Pending` (no user channel) so a bare PS still
  compiles and behaves predictably.

### Definition of Done

- [x] `BuildGovernance()` binds the PS URL and default `GovernanceOptions`.
- [x] `MissionSession` injects `{approver, s256}` into permission/audit/interaction.
- [x] Per-call `personServer` parameters removed from the governance clients. _(done in Phase 2, D1 — bound client is the only path)_
- [x] Client reachable via static factory, fluent builder, and `AddAAuthGovernanceClient(...)`.
- [x] `MapAAuthGovernance()` maps mission/permission/audit/interaction + poll routes. _(mission-creation via `IMissionApprover`; deferred 202 + poll via `IDeferredConsentStore`, Phase 2 D3)_
- [x] `AddAAuthGovernance(configure?)` registers default no-op seams via `TryAdd`.
- [~] `mission_terminated` 403 + carrier-token checks centralized in the mapper. _(403 termination centralized; carrier-token checks pending Phase 2)_
- [x] New unit + conformance tests pass; full suite green (build 0/0).


---

## Phase 2 — API surface: consistency pass

**Goal:** Learn from the Phase 1 first pass and fine-tune the surface so it reads
consistently with the conventions already used elsewhere in the SDK. No new
capability — naming, shape, and ergonomics only. Confirms the construction triad
(DC5) behaves uniformly across agent and resource sides.

**Spec:** as cited in Phase 1 (no new spec surface; shape alignment only).

### Approach

- **Convention diff.** Compare the Phase 1 surface against `AAuthClientBuilder`,
  `AddAAuthDiscovery`/`AddAAuthAgent`, and `MapAAuthResource` (research Part B);
  list naming/return-type/option-pattern divergences before changing anything.
- **Normalize the triad.** Ensure the static factory, fluent builder, and DI
  registration share parameter names, option types, and defaults so the three paths
  are interchangeable and predictable (DC5).
- **Tighten names/return types.** Align method names, async suffixes, option-bag
  shapes (`Action<TOptions>` vs records), and nullability with the rest of the SDK.
- **Symmetry check.** Agent-side and resource-side builders/options use the same
  vocabulary (e.g. `With…` / `Use…` / `Map…`) as their non-mission counterparts.
- **D1 — remove the transitional dual surface.** Drop the per-call `personServer`
  parameters from `MissionClient` / `PermissionClient` / `AuditClient` /
  `InteractionClient`; the bound client + `MissionSession` become the only path
  (with sample migration completing in Phase 4). Reaches DC1's no-shim end state.
- **D2 — keep `MissionSession` flat.** Confirm flat methods
  (`RequestPermissionAsync`, `RecordAuditAsync`, `AskQuestionAsync`,
  `ProposeCompletionAsync`); no nested facades.
- **D4 — typed action POCO (replace bare strings).** Introduce a small
  `MissionAction` POCO for the invoked action so callers pass a value object
  instead of a `string`. Today `action` is a bare `string` on `PermissionRequest`,
  `AuditRecord`, `MissionSession.RequestPermissionAsync/RecordAuditAsync`, and
  `PermissionClient`. **Decision (2026-06-06):** model the *invocation* as a
  distinct `MissionAction` rather than reusing `MissionTool` — the spec's `action`
  is broader than a tool (covers file writes, message sends), and a dedicated type
  avoids the redundant `MissionTool.Description` on the invocation path. Named
  `MissionAction` (not bare `Action`) to avoid the `System.Action` clash. Keep
  `MissionTool` as the *catalog* entry (proposal / `approved_tools`); `MissionAction`
  is the *specific invocation*. Serialize the wire `action` field from
  `MissionAction.Name`; add an implicit `string → MissionAction` conversion so terse
  call sites (`"WebSearch"`) still compile. Update the `DefaultPermissionDecider`
  match to compare `MissionAction.Name` against `ApprovedTools[].Name`.
- **D3 — promote PS mission machinery into the SDK (closes DEV-1/DEV-2).** Move the
  approval-blob builder out of the sample into the SDK and add an
  `IMissionApprover` seam so `MapAAuthGovernance` can map mission creation; add a
  deferred/pending consent abstraction so a `Prompt` outcome returns a 202 deferred
  response instead of a denial. `DefaultPermissionDecider`/relay remain conservative
  no-ops but the deferred path becomes available to PS implementers.

### Files

| File | Action |
|------|--------|
| Phase 1 source files | **Modify** — rename/reshape per the convention diff |
| `src/AAuth/Agent/Governance/*Client.cs` | **Modify** — remove per-call `personServer` params (D1) |
| `src/AAuth/Agent/MissionAction.cs` (new) + `PermissionRequest`/`AuditRecord`/`MissionSession`/`PermissionClient` | **Add/Modify** — accept `MissionAction`; implicit `string` conversion (D4) |
| `src/AAuth/Server/Governance/*` (approval builder, `IMissionApprover`, pending/deferred seam) | **Add/Modify** — promote from sample (D3) |
| `src/AAuth/.../MapAAuthGovernance` | **Modify** — map mission creation + deferred 202 (D3) |
| `samples/MockPersonServer/*` | **Modify** — consume promoted SDK pieces where it reduces sample-local code |
| `tests/AAuth.Conformance/Missions/*` | **Modify** — update to the finalized names; cover mission-create + deferred |
| `tests/AAuth.Tests/Governance/*` | **Modify** — update to the finalized names |

### Implementation Decisions

- DC5: the finalized names from this pass are the public contract migrated in
  Phases 4–6; record any rename decisions in research before applying.
- **D1/D2/D3 confirmed by the user (2026-06-06):** additive-then-remove, flat
  `MissionSession`, and promote the mission machinery + deferred consent into the
  SDK. See [issues-and-deviations.md](issues-and-deviations.md).
- Divergences that cannot be reconciled with existing conventions are logged in
  [issues-and-deviations.md](issues-and-deviations.md) with rationale.

### Definition of Done

- [ ] Convention diff recorded in research (Part B / Open Design Choices).
- [ ] Factory, builder, and DI paths share names/options/defaults across both sides.
- [ ] Public names align with `AAuthClientBuilder` / `AddAAuth*` / `MapAAuth*`.
- [x] Per-call `personServer` params removed; bound client is the only path (D1).
- [x] Action passed as a `MissionAction` POCO (implicit `string` for terse call sites) (D4).
- [x] Mission creation mapped by `MapAAuthGovernance` via `IMissionApprover` (D3, DEV-2).
- [x] `Prompt` outcome returns a deferred 202 via the pending-consent seam (D3, DEV-1).
- [x] All Phase 1 tests updated and green; full suite green (build 0/0).


---

## Phase 3 — Spec hardening (F3 + F4)

**Goal:** Tighten audit response handling and add `device` validation.

**Spec:** §Audit Endpoint (PS returns `201 Created`); §Agent Token Request
(`device` MUST be UTF-8 printable, ≤64 chars).

### Files

| File | Action |
|------|--------|
| `src/AAuth/Agent/Governance/AuditClient.cs` | **Modify** — accept only `201 Created` (F3) |
| `src/AAuth/Agent/TokenExchangeRequest.cs` | **Modify** — validate `device` (printable ASCII 32–126, ≤64) (F4) |
| `tests/AAuth.Conformance/Missions/AuditResponseTests.cs` | **New/Modify** |
| `tests/AAuth.Conformance/TokenExchange/DeviceValidationTests.cs` | **New** |

### Definition of Done

- [ ] `AuditClient` rejects non-201 acknowledgments.
- [ ] `device` rejects control chars and lengths > 64 with a clear exception.
- [ ] Tests cover boundary cases; full suite green.

---

## Phase 4 — Migrate mission samples to the new API

**Goal:** Update all mission sample call-sites (research Part C) to the Phase 1–2
surface. No behavior change; API shape only.

**Spec:** as cited in Phases 1–2.

### Files

| File | Action |
|------|--------|
| `samples/MissionAgent/Program.cs` | **Modify** — `MissionSession`, bound PS, no manual `MissionClaim` |
| `samples/MockPersonServer/Program.cs` | **Modify** — `AddAAuthGovernance(...)` + `MapAAuthGovernance()`; remove hand-wired endpoints |
| `samples/MockPersonServer/MissionGovernance.cs` | **Modify** — seams unchanged or trimmed to new defaults |
| `samples/SampleApp/Components/Pages/Mission.razor` | **Modify** — new client surface |
| `samples/GuidedTour/TourSession.cs` | **Modify** — new client surface; step plan preserved |
| `samples/WhoAmI/Program.cs` | **Modify** — resource governance builder for mission-aware challenge |

### Definition of Done

- [ ] All mission samples build and run against the new API.
- [ ] Mission e2e specs (4) pass unchanged in behavior.
- [ ] No leftover manual `MissionClaim`/PS-URL threading in samples.

---

## Phase 5 — New combined SampleApp example (clarification + mission + call-chain)

**Goal:** Add one SampleApp page demonstrating a clarification round during mission
approval, then a mission-governed multi-hop call chain. Fills the two sample gaps
(research Part D).

**Spec:** §Clarification Chat (202 + `AAuth-Requirement: clarification`; bounded
rounds; untrusted text → sanitize); §Call Chaining (mission present → forward
`AAuth-Mission` each hop; per-hop PS re-evaluation; `act` nesting).

### Files

| File | Action |
|------|--------|
| `samples/SampleApp/Components/Pages/MissionCallChain.razor` | **New** — combined flow page |
| `samples/SampleApp/Components/Pages/Home.razor` | **Modify** — add card/link |
| `samples/MockPersonServer/MissionGovernance.cs` | **Modify** — script a clarification round during mission approval |
| `samples/Orchestrator/Program.cs` | **Modify (if needed)** — ensure mission forwarding hop is exercised |
| `tests/e2e/` (Playwright spec) | **New** — combined-flow spec |

### Implementation Decisions

- DC4: single page; Orchestrator + WhoAmI as downstream hops.
- Clarification text is rendered only after sanitization (untrusted input).

### Definition of Done

- [ ] Page shows a clarification round (respond/update/cancel) during mission approval.
- [ ] Mission is forwarded through the orchestrator; downstream hop is governed.
- [ ] Mission log/trail surfaced in the UI.
- [ ] New Playwright spec passes; full backend stack boots via webServer array.

---

## Phase 6 — Docs update

**Goal:** Bring mission docs to the new API.

**Spec:** as cited above.

### Files

| File | Action |
|------|--------|
| `docs/advanced/missions.md` | **Modify** — new surface |
| `docs/advanced/mission-governance-clients.md` | **Modify** — `MissionSession` lifecycle |
| `docs/advanced/clarification-chat.md` | **Modify** — link the new combined sample |
| `docs/server/mission-governance.md` | **Modify** — `MapAAuthGovernance()` + default seams |
| `docs/server/challenge-middleware.md` | **Modify** — resource governance builder |
| `docs/workflows/mission-governed-access.md` | **Modify** — updated walkthrough |

### Definition of Done

- [ ] All mission docs reflect the new API; code blocks compile against the surface.

---

## Phase 7 — Samples consistency audit (subagent)

**Goal:** With fresh eyes, validate that **every** sample uses the new API surface
and reads cleanly. A dedicated subagent surfaces inconsistencies, leftover old-API
usage, and readability problems across the sample projects; findings are adjudicated
and remediated.

**Spec:** as cited in Phases 1–5 (the audit confirms samples match those citations).

### Approach

- **Subagent sweep.** Launch an exploration subagent scoped to `samples/**` to list
  every mission/clarification/call-chain call-site, flag any that still use the old
  surface, manual `MissionClaim` threading, repeated PS URLs, or inconsistent
  construction styles, and rank readability issues.
- **Adjudicate + remediate.** Triage findings against the finalized Phase 2 surface;
  fix in place. Log anything that turns out to be a genuine SDK gap or deviation in
  [issues-and-deviations.md](issues-and-deviations.md).

### Definition of Done

- [ ] Subagent report captured; each finding marked fixed / deferred / not-an-issue.
- [ ] No sample retains old-API mission usage or manual claim/PS threading.
- [ ] Significant issues logged in `issues-and-deviations.md`; research updated.
- [ ] All samples build/run; mission + combined e2e specs green.

---

## Phase 8 — Docs & code-snippet consistency audit (subagent)

**Goal:** Validate that all docs and embedded code snippets — especially GuidedTour
snippets and SampleApp walkthroughs — use the new API and read cleanly. A dedicated
subagent surfaces inconsistencies; findings are adjudicated and remediated.

**Spec:** as cited in Phases 1–6 (the audit confirms docs match those citations).

### Approach

- **Subagent sweep.** Launch an exploration subagent scoped to `docs/**` plus
  GuidedTour/SampleApp snippet sources to flag old-API code blocks, stale prose,
  broken cross-links, and readability issues.
- **Adjudicate + remediate.** Update docs/snippets to the finalized surface; verify
  code blocks compile against it. Log SDK gaps/deviations in
  [issues-and-deviations.md](issues-and-deviations.md).

### Definition of Done

- [ ] Subagent report captured; each finding marked fixed / deferred / not-an-issue.
- [ ] All mission docs + GuidedTour/SampleApp snippets reflect the new API.
- [ ] Code blocks compile against the surface; cross-links resolve.
- [ ] Significant issues logged in `issues-and-deviations.md`; research updated.

---

## Phase 9 — Independent spec-compliance review (subagent)

**Goal:** A separate reviewer subagent independently validates **each change** in
this initiative against the AAuth spec to confirm 100% compliance. Where the SDK is
found non-compliant, fix it (DC6 still holds — fixes must not break existing flows).

**Spec:** `aauth-spec/draft-hardt-oauth-aauth-protocol.md` (all cited sections);
`aauth-spec/upcoming-changes-02.md` for F1/F5/F6 context.

### Approach

- **Independent review.** Launch a reviewer subagent that walks the diff of this
  initiative phase by phase and checks every behavior against the governing spec
  section, with no assumption that prior phases were correct.
- **Adjudicate against spec text.** Each flagged item is confirmed against the spec
  before any change; genuine non-compliance is fixed in the SDK, deviations that are
  intentional or pending draft-02 are documented.
- **Final ledger.** All significant findings recorded in
  [issues-and-deviations.md](issues-and-deviations.md); research updated with the
  closing compliance summary.

### Definition of Done

- [ ] Reviewer subagent report captured; every finding adjudicated against spec text.
- [ ] SDK non-compliance fixed without breaking existing flows (DC6).
- [ ] `dotnet build AAuth.slnx` 0/0; unit + conformance + mission/combined e2e green.
- [ ] `issues-and-deviations.md` finalized; research updated; plan DoD ticked.
- [ ] Major open decisions surfaced to the user for input.

---

## Out of Scope

| Item | Reason |
|------|--------|
| R3 (Rich Resource Requests) — models, RFC 8785 hasher, `r3_*` token claims, AS/MM fetch, resource enforcement | Split into its own initiative — `.agent/plans/2026-06-06-r3-rich-resource-requests/` |
| Implementing AS or MM as production SDK roles | Out of scope per mission research; mock servers only |
| Mission lifecycle beyond active/terminated (suspend/resume/revoke) | Deferred to companion spec (§Mission Management) |
| `user_unreachable` (F5) and `prompt` finalization (F6) | Pending draft-02 publication |
| Payment settlement protocols (x402/MPP) | External; SDK only surfaces 402 + details |
