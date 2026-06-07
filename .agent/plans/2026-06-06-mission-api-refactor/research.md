# Mission API Refactor — Research

## Problem Statement

The AAuth .NET SDK (`src/AAuth/`) has a **functionally complete** mission/governance
surface — `MissionClient`, `PermissionClient`, `AuditClient`, `InteractionClient`
on the agent side; `IMissionStore`/`IMissionLog`/`IPermissionDecider`/`IAuditSink`/
`IInteractionRelay` seams plus `GovernanceEndpoints` parsers on the server side.
What it lacks is **ergonomic polish**: missions are threaded by hand through every
call, the Person Server (PS) URL is repeated on every method, there is no DI- or
fluent-builder surface for either client or resource, and the PS must hand-wire
~310+ lines of endpoint boilerplate.

This document captures the current state, the spec models, the gap inventories,
and the open design choices for three work streams:

1. **Streamline mission APIs** for both client and resource — DI-friendly, fluent
   builders, aligned with existing SDK conventions.
   1.1 **Update mission code samples** (docs, GuidedTour, SampleApp, MissionAgent,
   MockPersonServer, WhoAmI) to the new surface.
2. **New SampleApp example** combining **clarification chat** + **call chain with
   mission**.

It contains **no** implementation steps or task lists — those live in
[implementation-plan.md](implementation-plan.md) once design choices are settled.

> **R3 (Rich Resource Requests)** was originally scoped here as a third work
> stream and has been split into its own initiative —
> `.agent/plans/2026-06-06-r3-rich-resource-requests/`.

> **Update (2026-06):** The user refined the delivery approach. The API surface is
> now built in **two passes** — Phase 1 first pass (agent + resource), Phase 2
> consistency pass that aligns naming/shape with existing SDK conventions. The
> surface must support **static factories, fluent builders, and DI registration**
> (construction triad). No existing flow may break. The closing phases are
> independent audits driven by subagents: a samples audit, a docs/code-snippet
> audit (especially GuidedTour + SampleApp), and a final independent
> spec-compliance review that validates every change against the AAuth spec and
> fixes the SDK where non-compliant. Significant issues/deviations are logged in
> [issues-and-deviations.md](issues-and-deviations.md). Execution is gated:
> permission is requested before each phase, nothing is committed until the user
> approves, and major decisions are surfaced at the end. See
> [implementation-plan.md](implementation-plan.md) "Working Agreement".

> **Update (2026-06) — Phase 1 first-pass landed (additive).** New SDK surface,
> all additive so the solution stays green (build 0/0; unit 387, conformance 440):
> - **Agent:** `MissionSession` ([../../../src/AAuth/Agent/Governance/MissionSession.cs](../../../src/AAuth/Agent/Governance/MissionSession.cs))
>   auto-threads the mission claim + bound PS; `AAuthGovernanceClient` gains a
>   bound variant, a `Create(...)` factory, a `PersonServer` property, and
>   `ProposeMissionAsync(...) → MissionSession`; `AAuthClientBuilder.BuildGovernance(GovernanceOptions?)`
>   binds the `WithPersonServer` URL; DI via `AddAAuthGovernanceClient(...)`.
> - **Resource:** `AddAAuthGovernance()` now also registers conservative default
>   seams (`DefaultPermissionDecider`/`DefaultAuditSink`/`DefaultInteractionRelay`)
>   via `TryAdd`; new `MapAAuthGovernance(...)` maps permission/audit/interaction
>   from the seams; `AAuthGovernancePipelineOptions` controls routes.
> - **Construction triad (DC5)** satisfied: static factory + fluent builder + DI.
> - **Phase 2 D3 (closes DEV-1/DEV-2):** `MissionApprovalBuilder` + an
>   `IMissionApprover`/`DefaultMissionApprover` seam promoted into the SDK so
>   `MapAAuthGovernance` maps mission creation (persists the `StoredMission` and
>   emits the `AAuth-Mission` header). An opt-in `IDeferredConsentStore` seam
>   (`AddAAuthDeferredConsent()`) lets the mapper park a `Prompt` outcome and
>   answer 202 + poll route; the interactive browser page stays a sample concern.
> - **Open items** logged in [issues-and-deviations.md](issues-and-deviations.md):
>   DEV-3 (no-op relay) remains intentional; DEV-1 and DEV-2 are resolved in
>   Phase 2 D3.

## Source Documents

| Document | Location | Relevant Sections |
|----------|----------|-------------------|
| AAuth Protocol | `aauth-spec/draft-hardt-oauth-aauth-protocol.md` | §Agent Governance; §Mission Creation/Approval; §Permission Endpoint; §Audit Endpoint; §Interaction Endpoint; §Clarification Chat; §Call Chaining; §AAuth-Capabilities; §Resource Token; §Auth Token; §Person Server Metadata |
| Upcoming changes | `aauth-spec/upcoming-changes-02.md` | `capabilities` in PS token body; `user_unreachable` terminal error; `prompt` param |

---

## Part A — Current Mission/Governance Surface & Ergonomic Friction

### A.1 Agent-side clients (verified signatures)

| Type | File | Shape |
|------|------|-------|
| `AAuthGovernanceClient` | [src/AAuth/Agent/Governance/AAuthGovernanceClient.cs](../../../src/AAuth/Agent/Governance/AAuthGovernanceClient.cs) | Facade: `Mission`/`Permission`/`Audit`/`Interaction`; ctor `(HttpClient signedClient, MetadataClient metadata)` |
| `MissionClient` | [src/AAuth/Agent/Governance/MissionClient.cs](../../../src/AAuth/Agent/Governance/MissionClient.cs) | `ProposeAsync(personServer, MissionProposal, GovernanceOptions?, CT)` |
| `PermissionClient` | [src/AAuth/Agent/Governance/PermissionClient.cs](../../../src/AAuth/Agent/Governance/PermissionClient.cs) | `RequestAsync(personServer, PermissionRequest, [Mission?], GovernanceOptions?, CT)` |
| `AuditClient` | [src/AAuth/Agent/Governance/AuditClient.cs](../../../src/AAuth/Agent/Governance/AuditClient.cs) | `RecordAsync(personServer, AuditRecord, CT)` |
| `InteractionClient` | [src/AAuth/Agent/Governance/InteractionClient.cs](../../../src/AAuth/Agent/Governance/InteractionClient.cs) | `SendAsync`/`RelayInteractionAsync`/`RelayPaymentAsync`/`AskQuestionAsync`/`ProposeCompletionAsync` |
| Builder entry | [src/AAuth/AAuthClientBuilder.cs](../../../src/AAuth/AAuthClientBuilder.cs) | `.BuildGovernance()` → `AAuthGovernanceClient` (one-shot; requires explicit signing mode) |

### A.2 Agent-side pain points

- **PT-A1 — Manual mission threading.** After `ProposeAsync` returns a `Mission`,
  the caller must hand-extract `new MissionClaim(mission.Approver, mission.S256)`
  and set it on every `PermissionRequest.Mission` / `AuditRecord` (positional) /
  `InteractionRequest.Mission`. Spec ref: mission travels as `{approver, s256}`
  only (§Mission Approval; §AAuth-Mission Request Header).
- **PT-A2 — Repeated `personServer` URL.** Every `*Async` method re-takes the PS
  URL; nothing binds it to the governance client.
- **PT-A3 — No fluent governance builder.** `BuildGovernance()` is a terminal
  one-shot. No way to chain default PS, default `GovernanceOptions`, or callbacks
  the way `AAuthClientBuilder` does for the main client.
- **PT-A4 — No DI registration.** `AddAAuthAgent(...)` exists for plain clients,
  but there is no `AddAAuthGovernanceClient(...)`. Callers wire a factory by hand.
- **PT-A5 — Inconsistent request construction.** `AuditRecord(mission, action)`
  positional vs. `PermissionRequest(action){ Mission = ... }` init vs.
  `InteractionRequest(type){ Mission = ... }` — no common factory/builder.
- **PT-A6 — Callbacks lack mission context.** `GovernanceOptions.OnInteractionRequired`
  / `OnClarificationRequired` receive only the requirement, not the mission; the
  caller must close over it.
- **PT-A7 — Resource access still hand-rolls the mission header + challenge cycle.**
  Even after the governance gates collapsed to one-liners (`ProposeMissionAsync`,
  `RequestPermissionAsync`, `RecordAuditAsync`), the *resource-access* leg an agent
  runs **between** gates is still fully manual: it sets the `AAuth-Mission` header on
  every outbound request by hand (`AAuthMissionHeader.FormatStructured(...)`), then
  drives the 401→`AAuth-Requirement` parse→token-exchange→retry-with-auth-token
  cycle itself (~30 lines in [samples/MissionAgent/Program.cs](../../../samples/MissionAgent/Program.cs)
  `AccessMissionResourceAsync`). The challenge cycle already has a convenience layer
  (`WithChallengeHandling()` + `WithInteractionHandling()` →
  [ChallengeHandler](../../../src/AAuth/Agent/ChallengeHandler.cs)), but **nothing**
  emits the agent's *own* mission header from a directly-held `Mission`. The existing
  [MissionForwardingHandler](../../../src/AAuth/Agent/MissionForwardingHandler.cs)
  only re-emits a mission **extracted from an upstream auth token** (call-chaining,
  §Call Chaining) — it cannot help an agent that proposed the mission itself.

> **Update (2026-06-06) — PT-A7 seam confirmed spec-backed.** The agent operating in
> a mission context is **required** to attach the mission to outbound resource
> requests: §Mission Context at Resources — "The agent includes the `AAuth-Mission`
> header when sending requests to resources, unless the mission is already conveyed
> in an auth token" — and the HTTP Message Signatures section — "When the agent is
> operating in a mission context, it includes the `AAuth-Mission` header and adds
> `aauth-mission` to the signed components." The SDK already auto-covers the
> `aauth-mission` component whenever the header is present
> ([AAuthSigningHandler](../../../src/AAuth/HttpSig/AAuthSigningHandler.cs) lines
> ~221–226, 294–331), so a builder seam that emits the header from a held `Mission`
> is sufficient and spec-correct: the signing handler beneath it covers the
> component automatically. **Decision (2026-06-06):** add an
> `AAuthClientBuilder.WithMission(Mission)` seam (a small `DelegatingHandler` that
> sets `AAuth-Mission` from `{approver, s256}`, mirroring `MissionForwardingHandler`
> but sourcing the mission directly) so a mission-holding agent composes
> `WithMission(...) + WithChallengeHandling() + WithInteractionHandling()` and the
> whole resource-access leg collapses to a single signed `SendAsync`. The "unless
> already conveyed in an auth token" carve-out stays the agent's call: call-chaining
> intermediaries keep using `MissionForwardingHandler`; `WithMission(...)` is for the
> originating agent that holds its own approved `Mission`. Tracked as **Phase 6** in
> [implementation-plan.md](implementation-plan.md).

### A.3 Resource/PS-side surface (verified)

- DI: [AddAAuthGovernance()](../../../src/AAuth/DependencyInjection/AAuthGovernanceServiceCollectionExtensions.cs)
  registers only `IMissionStore`/`IMissionLog` (in-memory, via `TryAddSingleton`).
- Seams (PS implements): `IPermissionDecider`, `IAuditSink`, `IInteractionRelay`.
- Parsers: [GovernanceEndpoints](../../../src/AAuth/Server/Governance/GovernanceEndpoints.cs)
  static `ParsePermission`/`ParseAudit`/`ParseInteraction`/`ParseMissionProposal`
  + `MissionTerminated()` 403 helper.
- Mission-aware resource: [ChallengeOptions.MissionAware](../../../src/AAuth/Server/Challenge/ChallengeOptions.cs)
  copies the `AAuth-Mission` header claim into the resource token.

### A.4 Resource/PS-side pain points

- **PT-R1 — ~310+ lines of endpoint boilerplate.** MockPersonServer hand-wires
  `/mission` (~127), `/permission` (~84), `/audit` (~33), `/mission-interaction`
  (~66), plus pending/poll endpoints (+200). No `MapAAuthGovernance()` mapper.
- **PT-R2 — Duplicated per-endpoint plumbing.** Each handler re-checks agent-token
  carrier type, parses JSON, extracts agent id, handles `FormatException`, looks up
  the mission, checks `MissionState`, and selects status codes.
- **PT-R3 — Scattered seam registration.** `AddAAuthGovernance()` registers storage
  only; the three policy/relay seams are registered separately with no defaults
  (no no-op fallback).
- **PT-R4 — No resource-side fluent builder.** `ChallengeOptions.MissionAware` is a
  bare bool; there is no fluent equivalent to the agent's `AAuthClientBuilder`.

---

## Part B — DI & Fluent-Builder Conventions to Align With

The refactor must mirror existing SDK conventions, not invent new ones.

### B.1 Fluent builder pattern ([AAuthClientBuilder.cs](../../../src/AAuth/AAuthClientBuilder.cs))

- Static factories: `Bootstrap`, `From`, `SelfIssuing`, `Enrolled`.
- Signing modes: `.UseHwk()`, `.UseJwt(...)`, `.UseJwksUri(...)`, `.UseJktJwt(...)`,
  `.UseProvider(...)`.
- Config chain: `.WithCapabilities()`, `.WithChallengeHandling(...)`,
  `.WithCallChaining(...)`, `.WithPersonServer(...)`, `.WithTokenRefresh(...)`,
  `.WithInteractionHandling(...)`.
- Terminals: `.Build()` → `HttpClient`; `.BuildHandler()` → `HttpMessageHandler`;
  `.BuildGovernance()` → `AAuthGovernanceClient`.
- Sub-builders (`SelfIssuingBuilder`, `EnrolledBuilder`, `BootstrapBuilder`) bridge
  back to the main builder via an internal `ToBuilder()` seam.

### B.2 DI extension conventions

- All in `Microsoft.Extensions.DependencyInjection` namespace, under
  `src/AAuth/DependencyInjection/`.
- Shape: `AddXxx(Action<TOptions> configure)` → new options → `configure?.Invoke` →
  register. DI options are **mutable** (`get; set;`, sealed).
- Seams registered with `TryAdd*` so consumers can override.
- App-builder extensions (`UseAAuthVerification`, `UseAAuthChallenge`,
  `MapAAuthWellKnown`, `MapAAuthResource`, `UseAAuthIntermediary`) live in the
  `Microsoft.AspNetCore.Builder` namespace, same folder.

### B.3 Options conventions

- **DI options** (mutable `get; set;`): `AAuthAgentOptions`, `AAuthResourceOptions`,
  `AAuthDiscoveryOptions`, `AAuthResourcePipelineOptions`.
- **Middleware options** (init-only `get; init;`): `AAuthVerificationOptions`,
  `ChallengeOptions`, `GovernanceOptions`.
- Public-facing types are `sealed`; interfaces `I*`; public SDK classes `AAuth*`;
  records for immutable DTOs.

### B.4 Existing precedent to extend

`MapAAuthResource(Action<AAuthResourcePipelineOptions>?)` already bundles
well-known + verification + challenge in one call — the natural template for a new
`MapAAuthGovernance(...)` PS mapper (PT-R1). `AddAAuthDiscovery(configure?)` is the
template for an optional-callback DI registration (PT-A4).

### B.5 — Phase 2 convention diff (verified 2026-06)

> **Update (2026-06) — Phase 1 surface vs. SDK conventions.** Comparing the
> committed Phase 1 surface against B.1–B.4:
>
> | Divergence | Phase 1 state | Convention | Phase 2 action |
> |---|---|---|---|
> | Per-call `personServer` | Every governed method takes `string personServer` as its first arg | Builder binds context once (`.WithPersonServer`); other clients don't re-take it per call | **D1** — bind the PS into `AAuthGovernanceClient` + sub-clients at construction; drop the param. Bound client becomes the only path. |
> | Bare `string action` | `PermissionRequest`/`AuditRecord`/`MissionSession`/`PermissionClient` pass `action` as `string` | DTOs are records/POCOs (`MissionTool`, `MissionClaim`) | **D4** — new `MissionAction` record + implicit `string` conversion. |
> | Unbound construction allowed | `AAuthGovernanceClient` has an unbound ctor + nullable `PersonServer` | `BuildGovernance()`/`Create()` are the blessed entry points | Make PS required on the bound path; keep `Create(...)` factory + `BuildGovernance(...)` + `AddAAuthGovernanceClient(...)` as the triad. |
> | Mapper coverage | Maps permission/audit/interaction only | `MapAAuthResource` bundles the whole pipeline | **D3** — add mission-creation (`IMissionApprover`) + deferred-consent (Prompt→202) so `MapAAuthGovernance` is a complete PS pipeline. |
>
> **Sequencing note:** D1 removes a surface consumed by `MissionAgent/Program.cs`,
> `GuidedTour/CodeSnippets.cs`, and the conformance tests. To honor DC6 (build 0/0
> after every phase), those governance call sites are migrated to the bound
> `MissionSession` surface **within Phase 2** (the structural sample work remains
> Phase 4/5). Names already match conventions (`With*`/`Create`/`Add*`/`Map*`); no
> renames of the Phase 1 public entry points are required.
>
> **Closure (2026-06-06) — all four divergences resolved.** D1, D3, and D4 landed;
> the unbound `AAuthGovernanceClient` ctor was removed so `BuildGovernance(...)`,
> `Create(..., personServer)`, and `AddAAuthGovernanceClient(...)` are the only
> construction paths and they share parameter names, the bound `GovernanceOptions`
> default shape, and the `Action<TOptions>` configure pattern across both the agent
> (`AddAAuthGovernanceClient`) and resource (`AddAAuthGovernance` + `MapAAuthGovernance`)
> sides. No public entry-point renames were needed — the Phase 1 names already
> matched the `With*`/`Create`/`Add*`/`Map*` vocabulary used by `AAuthClientBuilder`,
> `AddAAuthAgent`/`AddAAuthDiscovery`, and `MapAAuthResource`. The triad and naming
> DoD items are therefore satisfied by verification rather than further change.

---

## Part C — Mission Sample/Doc Call-Site Inventory (Work Stream 1.1)

Files that exercise the mission/governance surface and would change under an API
refactor. Full per-line table is preserved in the call-site appendix below.

| File | Role | Notable call-sites |
|------|------|--------------------|
| [samples/MissionAgent/Program.cs](../../../samples/MissionAgent/Program.cs) | Console walkthrough | `Mission.ProposeAsync`, `Permission.RequestAsync`, `Audit.RecordAsync`, `Interaction.AskQuestionAsync`/`ProposeCompletionAsync`, manual `MissionClaim` + `AAuthMissionHeader.FormatStructured` |
| [samples/MockPersonServer/Program.cs](../../../samples/MockPersonServer/Program.cs) | PS endpoints | `AddAAuthGovernance()` + 6 seam registrations; `/mission`, `/mission-create-pending/{id}`, `/permission`, `/permission-pending/{id}`, `/audit`, `/mission-interaction`; mission gate in `/token` |
| [samples/MockPersonServer/MissionGovernance.cs](../../../samples/MockPersonServer/MissionGovernance.cs) | Seam impls | `SamplePermissionDecider`, `SampleAuditSink`, `SampleInteractionRelay`, `MissionPolicyStore`, `MissionConsentScript` |
| [samples/SampleApp/Components/Pages/Mission.razor](../../../samples/SampleApp/Components/Pages/Mission.razor) | Browser 5-gate demo | `ProposeAsync`, two `RequestAsync` variants, `RecordAsync`; `ChallengeForMission` |
| [samples/SampleApp/Components/Pages/CallChain.razor](../../../samples/SampleApp/Components/Pages/CallChain.razor) | Call chain (no mission) | Currently mission-free by design; target for Work Stream 2 |
| [samples/GuidedTour/TourSession.cs](../../../samples/GuidedTour/TourSession.cs) | 20-step mission plan | `MissionPlan`, mission state tracking fields |
| [samples/GuidedTour/Components/Pages/Tour.razor](../../../samples/GuidedTour/Components/Pages/Tour.razor) | Tour UI | Mission mode picker + description |
| [samples/WhoAmI/Program.cs](../../../samples/WhoAmI/Program.cs) | Mission-aware resource | `ChallengeForMission(scope)` with `MissionAware = true`; `/jwt/mission`, `/jwt/mission/elevated` |
| docs/advanced/missions.md | Doc | `Mission`, `MissionClaim`, `AAuthMissionHeader` |
| docs/advanced/mission-governance-clients.md | Doc | Four-client facade + full lifecycle |
| docs/advanced/clarification-chat.md | Doc | `GovernanceOptions.OnClarificationRequired` |
| docs/server/mission-governance.md | Doc | `AddAAuthGovernance()`, seams, parsers |
| docs/server/token-issuance.md | Doc | `MissionClaim`, `AuthTokenBuilder` |
| docs/server/challenge-middleware.md | Doc | `ChallengeOptions.MissionAware` |
| docs/workflows/mission-governed-access.md | Doc | End-to-end walkthrough |

> Any new convenience surface should be **additive** where possible so these
> call-sites can migrate incrementally; whether to keep the low-level API public is
> an open design choice (see D1 in the original plan — "no shim" was the prior
> decision and may or may not carry forward).

---

## Part D — New SampleApp Example: Clarification Chat + Call-Chain-with-Mission (Work Stream 2)

### D.1 Current gaps

- **No end-to-end clarification-chat sample.** `ClarificationExchange` /
  `ClarificationResponse.Respond/Update/Cancel` exist and are documented, but no
  sample exercises a real multi-round clarification UI. MockPersonServer only
  toggles a scripted `RequireTokenClarification` flag.
- **Call chain explicitly omits missions.** [CallChain.razor](../../../samples/SampleApp/Components/Pages/CallChain.razor)
  states mission governance is "optional and orthogonal … intentionally left out
  of this demo" (added in commit `47ce1ef`). Multi-hop uses `upstream_token` only.

### D.2 Spec basis for the combined example

- **Clarification Chat** (§Clarification Chat): server returns 202 +
  `AAuth-Requirement: clarification`; agent responds via respond/update/cancel; the
  PS/resource MUST bound rounds (SDK default `MaxClarificationRounds = 5`). The
  clarification text is **untrusted** and must be sanitized before display.
- **Call Chaining with mission** (§Call Chaining): when a mission is present, the
  intermediary MUST forward the `AAuth-Mission` header on every downstream hop
  ([MissionForwardingHandler](../../../src/AAuth/Agent/MissionForwardingHandler.cs),
  auto-wired by `.WithCallChaining()`); the PS re-evaluates each hop against the
  mission scope + log; the nested delegation is carried in the auth token `act`
  claim.

### D.3 Candidate example shape (to confirm with user)

A new SampleApp page (e.g. `MissionCallChain.razor`) demonstrating:
1. Agent proposes a mission; PS asks a **clarification question** during approval;
   agent responds; mission approved with refined intent (clarification round
   surfaced in the UI).
2. Agent calls the Orchestrator with the mission; `AAuth-Mission` is forwarded.
3. Orchestrator's downstream hop to WhoAmI is governed by the mission (in-scope =
   silent; out-of-mission = 202 prompt), each hop's token carrying the mission
   claim with `act` nesting.
4. Mission log shows the full multi-hop trail.

> Open: whether this is one combined page or two (clarification-only +
> mission-call-chain). See [Open Design Choices](#open-design-choices).

> **Update (2026-06-06) — Phase 5 landed (single combined page).** Shipped as one
> `MissionCallChain.razor` page (DC4) with `mission-call-chain.spec.ts`. The flow is:
> **(1)** propose mission (PROMPT) → **(2)** access an out-of-mission elevated scope
> that triggers a **clarification round** (the SDK surfaces the untrusted question
> via `OnClarificationRequired`; Blazor `@`-encodes it before display; the agent
> answers and the user approves the PROMPT) → **(3)** carry the same mission with
> `WithMission(...)` to the Orchestrator `/mission` endpoint, which forwards
> `AAuth-Mission` to the WhoAmI `/jwt/mission` hop (SILENT, both hops seeded
> in-scope) → fetch + render the PS-held mission log. Three things surfaced while
> getting the spec green (all logged in
> [issues-and-deviations.md](issues-and-deviations.md)):
>
> - **SDK clarification→interaction escalation bugs (DEV-6, fixed in `DeferredExchange.cs`).**
>   The poller did not stop on a post-clarification interaction `202`
>   (`stopOnInteraction` not threaded through `PollAsync`/`ComposePollerOptions`),
>   and `ResolveLocation` dropped the interaction URL when a polled `202` omitted the
>   `Location` header. Covered by `ChallengeClarificationSeamTests` (4/4).
> - **Blazor render-batch stall (DEV-7, sample-only).** A per-second poll-counter
>   `Task.Run`/`PeriodicTimer` calling `StateHasChanged` while the approval popup
>   backgrounded the main tab filled the circuit's unacked-render-batch buffer and
>   froze rendering ~120 s. Removed the cosmetic timer; a single `StateHasChanged`
>   plus a static spinner conveys the polling state.
> - **Racy exact-transient-count assertion (DEV-8, e2e-only).** Step 3 is silent and
>   final, so the step-2/step-3 `StateHasChanged` calls coalesce into one render
>   batch (DOM 1→3, never 2). The helper now waits for the just-approved step's card
>   (`expect(stepCard(page, expectedCards)).toBeVisible()`, i.e. ≥ N) instead of an
>   exact `toHaveCount(N)`; the strict final `toHaveCount(3)` is unchanged.
>
> Result: `sample-app` suite green — 15 passed + 1 pre-existing skip across two
> consecutive clean CI runs; `mission.spec.ts` and `call-chain.spec.ts` unaffected.

---

## Part F — Spec-Alignment Findings (verified)

| ID | Finding | Status | Spec ref |
|----|---------|--------|----------|
| F1 | `capabilities` in PS **token-request body** | ✅ **Correct** — confirmed spec-standard by spec lead (`upcoming-changes-02.md` §1, 2026-05-30). No action. | §AAuth-Capabilities + upcoming-changes-02 §1 |
| F2 | `ServerMetadata` parses `mission`/`permission`/`audit`/`interaction` endpoints | ✅ **Complete** — all four parsed in [ServerMetadata.FromJson](../../../src/AAuth/Discovery/ServerMetadata.cs). (Earlier "not parsed" claim was wrong.) | §Person Server Metadata |
| F3 | `AuditClient` accepts 200/204 in addition to 201 | ⚠️ Over-permissive; spec wants only `201 Created`. Candidate hardening. | §Audit Endpoint response |
| F4 | `device` param: no UTF-8-printable / ≤64-char validation | ⚠️ Missing boundary validation. Candidate hardening. | §Agent Token Request |
| F5 | `user_unreachable` (400, terminal) distinct from `interaction_required` (202) | ⏳ Not yet modeled; pending draft-02. | upcoming-changes-02 §2 |
| F6 | `prompt` token-endpoint body param | ✅ Present on `TokenExchangeRequest`; pending draft-02 finalization. | upcoming-changes-02 §3 |

> F1/F2 resolve two previously-open questions: the capabilities-body behavior is
> **correct**, and metadata parsing is **already complete**. F3/F4/F5 are small,
> independent spec-hardening candidates that could ride along with this initiative
> or be deferred.

---

## Part G — Anything Else to Include in Research (recommendations)

Beyond the three work streams, the research/plan should also cover:

- **Back-compat / migration strategy** for the mission API refactor: additive
  convenience layer vs. breaking change to the low-level clients; how the 15+
  call-sites in Part C migrate; conformance/test impact (currently 383 unit + 425
  conformance + 4 mission e2e specs).
- **Testing strategy**: unit coverage for new builder/DI surface; conformance
  vectors for the new governance surface; Playwright specs for the new combined
  sample (the harness boots the full backend stack via the webServer array).
- **Spec-citation discipline**: every plan phase/change cites a spec section, per
  the standing directive.

> **R3 (Rich Resource Requests)** is tracked in its own initiative —
> `.agent/plans/2026-06-06-r3-rich-resource-requests/` — including its RFC 8785
> hashing prerequisite, R3↔mission interplay, and security invariants.

---

## Open Design Choices

> **Decisions (2026-06-06):** 1 → **Breaking refactor** of the low-level mission
> surface (no shim; call-sites updated to the new API). 2 → **Both client +
> resource** ergonomics (incl. `MapAAuthGovernance(...)` PS mapper). 3 → **One
> combined** SampleApp page (clarification + mission + call-chain). 4 → **Include
> both** spec-hardening fixes (F3 audit 201-only, F4 device validation). 5 →
> **Continue on `feat/missions-ps-governance`**. (R3 was split into its own
> initiative.)

These required user input **before** authoring `implementation-plan.md`.

1. **Mission API back-compat.** Additive convenience layer over the existing
   clients, or a breaking refactor of the low-level surface? (Prior initiative used
   a "no shim" stance — confirm whether that carries forward.)
2. **Combined sample shape.** One SampleApp page (clarification + mission +
   call-chain) or two separate pages? Reuse Orchestrator/WhoAmI as the downstream
   hops?
3. **Resource-side fluent builder.** Introduce a `MapAAuthGovernance(...)` PS
   mapper + a resource governance builder (addressing PT-R1…R4), or keep the
   refactor agent-side only this round?
4. **Spec-hardening ride-alongs.** Include F3 (audit 201-only) and F4 (device
   validation) in this initiative, or defer? F5/F6 wait on draft-02 regardless.
5. **Branch & workflow.** Continue on `feat/missions-ps-governance`, or cut a new
   branch for this initiative? (Standing directive: branch per initiative, ask
   before commit/push, cite spec per change.)

---

## Out of Scope (unless decided otherwise)

| Item | Reason |
|------|--------|
| R3 (Rich Resource Requests) — models, RFC 8785 hasher, `r3_*` claims, AS/MM fetch, enforcement | Split into its own initiative — `.agent/plans/2026-06-06-r3-rich-resource-requests/` |
| Implementing an AS or MM as production SDK roles | Out of scope per prior mission research; only mock servers demonstrate these |
| Mission lifecycle beyond active/terminated (suspend/resume/revoke) | Deferred to a companion spec (§Mission Management) |
| Payment settlement protocols (x402/MPP) | External; SDK only surfaces 402 + details |

---

## Call-Site Appendix (per-line detail)

Detailed line references for the refactor (source: read-only exploration,
2026-06-06). These are stable enough to plan against but should be re-verified at
edit time.

- **MissionAgent/Program.cs**: governance client + `MissionClaim` (105–119);
  `ProposeAsync` (133–142); mission-aware exchange (155–195); `Permission.RequestAsync`
  (205–217); `Audit.RecordAsync` (223–228); `AskQuestionAsync` (233–240);
  `ProposeCompletionAsync` (246–251); `AAuthMissionHeader.FormatStructured` (355–356).
- **MockPersonServer/Program.cs**: DI (102–108); metadata (179–182); `/mission`
  (699–777); `/mission-create-pending/{id}` (779–813); `/permission` (815–897);
  `/permission-pending/{id}` (1017–1041); `/audit` (945–965); `/mission-interaction`
  (967–1009); mission gate in `/token` (510–570).
- **MockPersonServer/MissionGovernance.cs**: `SamplePermissionDecider` (131–153);
  `SampleAuditSink` (156–167); `SampleInteractionRelay` (170–183); `MissionPolicyStore`
  (109–129); `MissionConsentScript` (24–94).
- **SampleApp/Components/Pages/Mission.razor**: `ProposeAsync` (59–67, 388–398);
  `RequestAsync` (110–120, 461–485); `RecordAsync` (191–198).
- **GuidedTour/TourSession.cs**: mission state fields (59–75); `TotalSteps` (199–203);
  `MissionPlan` (256–275).
- **GuidedTour/Components/Pages/Tour.razor**: mission picker + description (~3–65);
  polling display (177–190); mission lanes (~274).
- **WhoAmI/Program.cs**: `ChallengeForMission` (132–140); mission endpoints with
  `UseWhen` (195–213); scope descriptions (48–61).

---

> **Update (2026-06-06) — Phase 10 independent spec-compliance review.** An
> independent reviewer walked the whole mission/governance surface against
> `draft-hardt-oauth-aauth-protocol.md` (no assumption that earlier phases were
> correct). Verdict: spec-compliant across all six areas — `AAuth-Mission` header
> structure + signed-component coverage (§Authorization Endpoint Request L632), the
> mission claim shape and verbatim-bytes SHA-256 (§Mission Approval), the four
> endpoint request/response shapes incl. the audit `201`-only rule (§Audit
> Endpoint), the deferred-consent `202`/poll flow incl. the DEV-6 fixes (§Deferred
> Responses), the clarification round-trip + 5-round limit (§Clarification), the
> `mission_terminated` `403` surfacing (§Mission Status Errors), and the
> originator-vs-intermediary header rules (§Call Chaining). DEV-5 (resource seam via
> `ChallengeOptions.MissionAware`, no resource governance builder) reconfirmed
> intentional.
>
> One genuine non-compliance was found and fixed — **NC-1 / DEV-9**: the governance
> mapper's `interaction`/`payment` branch returned `200 {status:"ok"}`
> unconditionally and never read `InteractionRelayResult.Pending`, so a relay that
> signalled `Pending = true` could not drive the spec-mandated `202` + poll loop
> (§Interaction Response L1199: *"the PS … returns a deferred response. The agent
> polls until the user completes the interaction."*). The handler now parks the
> interaction on the deferred-consent store (new `DeferredConsentKind.Interaction`)
> and answers `202` + poll `Location` when a store is registered, degrading to a
> synchronous `200` otherwise — mirroring the permission `Prompt` path. The agent
> side already polled `202`s correctly via `DeferredExchange`, so no client change
> was needed. Covered by 4 new `GovernanceDeferredConsentMapperTests` (12/12).
> A secondary observation — completion review resolves synchronously rather than
> deferring (§Interaction Response L1212) — is logged as **DEV-10** (intentional:
> the completion relay contract is synchronous, no dropped `Pending` signal).
