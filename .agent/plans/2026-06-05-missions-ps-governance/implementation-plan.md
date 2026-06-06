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
| `src/AAuth/HttpSig/AAuthVerifier.cs` | **Modify** (added) — accept `mission` param + validate `aauth-mission` covered component |
| `src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs` | **Modify** (added) — pass `AAuth-Mission` header into the verifier |
| `src/AAuth/Tokens/MissionClaim.cs` | **New** (added) — `{approver, s256}` value carried in tokens |
| `tests/AAuth.Conformance/Missions/MissionClaimTests.cs` | **New** (placed under `Missions/`) |
| `tests/AAuth.Conformance/HttpSignatures/MissionSignedComponentTests.cs` | **New** |

### Implementation Decisions

- D2 (resolved): auto-cover `aauth-mission` in `AAuthSigningHandler` when the
  header is present; signing method signatures may change as needed.
- D5 (resolved, user-approved): the verifier side (`AAuthVerifier` +
  `AAuthVerificationMiddleware`) is extended in Phase 2 so signed mission
  requests round-trip; without it every mission-context request would fail
  HTTP-signature verification.
- D6 — covered-component ordering (resolved per spec): `aauth-mission` is the
  **last** covered component, after `signature-key` (spec §Authorization
  Endpoint Request example, mission context). The pre-existing `authorization`
  handling (appended after `signature-key`) is left unchanged — re-aligning it
  to the spec's `authorization`-before-`signature-key` example is out of Phase 2
  scope. Verifier accepts the optional trailing pair `authorization` then
  `aauth-mission`, in that order.

### Definition of Done

- [x] `ResourceTokenBuilder` emits `mission` claim when a mission is present (§Resource Token).
- [x] `AuthTokenBuilder` emits `mission` claim when a mission is present (§Auth Token).
- [x] `TokenVerifier` exposes the verified `mission` claim on auth tokens.
- [x] When `AAuth-Mission` header present, `aauth-mission` appears in
      `Signature-Input` covered components (§Authorization Endpoint Request).
- [x] Covered-components contract updated; token/signature tests adjusted to match.

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
| `src/AAuth/Agent/TokenExchangeRequest.cs` | **Modify** — add `Justification`, `LoginHint`, `Tenant`, `DomainHint`, `Platform`, `Device`, `OnClarificationRequired`, `MaxClarificationRounds` |
| `src/AAuth/Agent/TokenExchangeClient.cs` | **Modify** — emit new params; clarification loop; `mission_terminated` classification |
| `src/AAuth/Agent/ClarificationExchange.cs` | **New** — `ClarificationResponse` decision object + respond / update / cancel actions + round tracking |
| `src/AAuth/Agent/AAuthInteractionExceptions.cs` | **Modify** — add `AAuthClarificationCancelledException`, `AAuthClarificationLimitException` |
| `src/AAuth/Headers/ClarificationRequirement.cs` | **New** — parse `{clarification, timeout?, options?}` |
| `src/AAuth/Errors/TokenError.cs` | **Modify** — add `mission_terminated` |
| `src/AAuth/Errors/AAuthMissionTerminatedException.cs` | **New** |
| `tests/AAuth.Conformance/Missions/ClarificationChatTests.cs` | **New** |
| `tests/AAuth.Conformance/Missions/MissionTerminatedTests.cs` | **New** |
| `tests/AAuth.Conformance/Missions/TokenRequestParamsTests.cs` | **New** — covers the six token-request params |

> **Deviation:** `DeferredPoller.cs` was **not** modified. POST/DELETE to the
> pending URL live in `ClarificationExchange` (its own `HttpClient`), and the
> clarification stop reuses the existing `DeferredPollerOptions.StopWhenAccepted`
> predicate (composed via `ComposePollerOptions`) — see research Part 5, Phase 3.

### Definition of Done

- [x] All six token-request params serialized into the POST body (§Agent Token Request).
- [x] `requirement=clarification` parsed into a typed model (question/timeout/options).
- [x] Agent can `clarification_response` POST, updated-`resource_token` POST, and
      `DELETE`-cancel against the pending URL (§Agent Response to Clarification).
- [x] Clarification round limit enforced (default 5) (§Clarification Limits).
- [x] `403 mission_terminated` → `AAuthMissionTerminatedException` across PS calls
      (§Mission Status Errors).
- [x] New tests pass; existing deferred/interaction tests unaffected.

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
| `src/AAuth/Agent/Governance/*Request.cs` / `*Response.cs` | **New** — DTOs (MissionProposal, PermissionRequest/Result, AuditRecord, InteractionRequest/Result) |
| `src/AAuth/Agent/Governance/GovernanceExchange.cs` | **New (deviation)** — shared signed-POST + deferred-`202` loop + endpoint origin-pinning; `GovernanceOptions` |
| `tests/AAuth.Conformance/Missions/GovernanceClientTests.cs` | **New** (12 tests) |

### Definition of Done

- [x] `ServerMetadata` parses all four governance endpoints (§Person Server Metadata).
- [x] `MissionClient.ProposeAsync` returns an approved `Mission` (verifies `s256`,
      handles `202` review/clarification) (§Mission Creation).
- [x] `PermissionClient.RequestAsync` returns granted/denied, honoring
      `approved_tools` short-circuit and deferred responses (§Permission Endpoint).
- [x] `AuditClient.RecordAsync` is fire-and-forget, requires a mission, expects
      `201` (§Audit Endpoint).
- [x] `InteractionClient` supports all four `type` values incl. `completion`
      terminate/continue (§Interaction Endpoint).
- [x] `mission_terminated` surfaces from each client (Phase 3 exception).
- [x] Client tests pass against a stub PS.

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
| `src/AAuth/Server/Governance/IMissionStore.cs` | **New** — persist blob bytes + state; `StoredMission` record |
| `src/AAuth/Server/Governance/InMemoryMissionStore.cs` | **New (deviation)** — default in-memory store (mirrors `InMemoryJtiStore`) |
| `src/AAuth/Server/Governance/IPermissionDecider.cs` | **New** — `PermissionDecision` + reason enum + context |
| `src/AAuth/Server/Governance/IAuditSink.cs` | **New** |
| `src/AAuth/Server/Governance/IInteractionRelay.cs` | **New** |
| `src/AAuth/Server/Governance/IMissionLog.cs` | **New** — ordered append; read; prior-consent lookup |
| `src/AAuth/Server/Governance/InMemoryMissionLog.cs` | **New (deviation)** — default in-memory log |
| `src/AAuth/Server/Governance/GovernanceEndpoints.cs` | **New** — request parsers + `mission_terminated` helper |
| `src/AAuth/DependencyInjection/AAuthGovernanceServiceCollectionExtensions.cs` | **New** — `AddAAuthGovernance` registers storage seams |
| `tests/AAuth.Conformance/Missions/GovernanceServerTests.cs` | **New** (17 tests) |

### Implementation Decisions

- D3 boundary: SDK = DTO parse + helpers + interfaces; policy/UI in mock.
- `IPermissionDecider` returns a typed decision **with a reason** (in-scope /
  prior consent / `approved_tools` / out-of-scope → prompt) so a PS can both act
  on it and surface it to UIs; the SDK provides the inputs + reason enum, the PS
  owns the policy (§Agent Token Request L385/L784/L828, §Permission L1017).

### Definition of Done

- [x] Request parsers for permission/audit/interaction/mission-create map to DTOs.
- [x] `mission_terminated` helper emits spec `403` body (§Mission Status Errors).
- [x] `IMissionStore` stores verbatim blob bytes + `active`/`terminated` state.
- [x] `IMissionLog` appends token/permission/audit/interaction/clarification
      entries in order, and supports a prior-consent read keyed by
      `(s256, resource, scope)` (§Mission Log, §Agent Token Request L784).
- [x] `IPermissionDecider` is invoked with mission + log context for the consent
      decision (§Person Server L385).
- [x] DI registration wires the seams.
- [x] Server-seam tests pass.

---

## Phase 5.5 — Shared deferred transport + governance facade

**Goal:** Remove the duplication between `TokenExchangeClient` and the Phase 4
`GovernanceExchange` by extracting a single internal deferred-HTTP transport
(T1 + T2), and hide governance-client construction behind a public facade and a
builder factory so callers don't hand-wire the signed `HttpClient` + four
clients (A + B). No behavioural change — the existing 417 conformance + 371 unit
tests are the regression gate.

**Spec:** §User Interaction; §Clarification Chat; §Mission Status Errors;
§PS Governance Endpoints; §Person Server Metadata. (Pure refactor — same wire
behaviour, same spec citations as Phases 3–5.)

**Rationale (from feasibility review):** `GovernanceExchange` and
`TokenExchangeClient` share ~120 lines of identical logic — endpoint origin-pin,
the `202` deferred loop (interaction + clarification), `ComposePollerOptions`,
`BufferBodyAsync` / `ReadJsonBodyAsync` / `ExtractRequirement` / `ResolveLocation`,
the `mission_terminated` reader, and `AddIfPresent`. `TokenExchangeClient` is
never exposed — `AAuthClientBuilder` constructs it internally and runs it behind
a `ChallengeHandler` (`AAuthClientBuilder.cs` ~L495). Governance operations are
*deliberate* (not challenge-driven) so they can't hide behind a handler, but
their construction can be hidden the same way the builder already hides the
token client's `(signedClient, metadata)` pair.

### Implementation Decisions

- **D8 (T1+T2 — single transport):** Introduce `internal sealed class
  DeferredExchange` (in `AAuth.Agent`) as the one transport: `ResolveEndpointAsync`
  + `PostAsync(endpoint, body, DeferredExchangeOptions, ct)` returning the
  terminal `HttpResponseMessage` (caller parses + disposes), throwing
  `AAuthMissionTerminatedException` on a terminal `403 mission_terminated`. It owns
  all the shared helpers and the `AAuth.DeferredPoll` activity. `GovernanceExchange`
  is **deleted**; governance clients use `DeferredExchange` directly, adapting
  `GovernanceOptions` → `DeferredExchangeOptions`. `TokenExchangeClient.ExchangeAsync`
  keeps its token-specific concerns (body builder + capability inference + the
  `AAuth.TokenExchange` activity + `access_denied` classification + `auth_token` /
  token-error reading) and delegates the transport to `DeferredExchange.PostAsync`.
  `access_denied` moves from inside the poll loop to a post-`PostAsync` 403
  classifier (a `403 access_denied` body is not `mission_terminated`, so
  `PostAsync` returns it unthrown — order preserved). `TokenExchangeRequest` and
  the public `TokenExchangeClient` API are **unchanged**.
- **D9 (A+B — facade + factory):** Add public `AAuthGovernanceClient` bundling
  `Mission` / `Permission` / `Audit` / `Interaction` over one signed `HttpClient`
  + `MetadataClient` (ctor `(HttpClient signedClient, MetadataClient metadata)`;
  the four sub-clients stay public for advanced use). Add
  `AAuthClientBuilder.BuildGovernance()` returning an `AAuthGovernanceClient`
  built from the **same** exchange pipeline the builder already constructs
  (`AAuthClientBuilder.cs` ~L480–L495); factor that `(HttpClient signed,
  MetadataClient metadata)` construction into a private helper shared by
  `BuildHandler` and `BuildGovernance`. DI (`AddAAuthAgentGovernance`) is
  **out of scope** here — deferred until a sample needs it (Phase 6).

### Files

| File | Action |
|------|--------|
| `src/AAuth/Agent/DeferredExchange.cs` | **New** — shared transport + `DeferredExchangeOptions` + all shared helpers (absorbs `GovernanceExchange`) |
| `src/AAuth/Agent/Governance/GovernanceExchange.cs` | **Delete** — replaced by `DeferredExchange`; `GovernanceOptions` moves to its own file |
| `src/AAuth/Agent/Governance/GovernanceOptions.cs` | **New** — public `GovernanceOptions` (moved out of the deleted file) |
| `src/AAuth/Agent/TokenExchangeClient.cs` | **Modify** — delegate transport to `DeferredExchange`; keep token-specific body/error/diagnostics |
| `src/AAuth/Agent/Governance/{Mission,Permission,Audit,Interaction}Client.cs` | **Modify** — use `DeferredExchange`; adapt `GovernanceOptions` → `DeferredExchangeOptions` |
| `src/AAuth/Agent/Governance/AAuthGovernanceClient.cs` | **New** — public facade bundling the four clients |
| `src/AAuth/AAuthClientBuilder.cs` | **Modify** — extract shared `(signed HttpClient, MetadataClient)` build helper; add `BuildGovernance()` |
| `tests/AAuth.Conformance/Missions/GovernanceFacadeTests.cs` | **New** — facade construction + `BuildGovernance()` wiring |

### Definition of Done

- [x] Single `DeferredExchange` transport; `GovernanceExchange.cs` deleted; no
      duplicated deferred-loop / buffer / requirement helpers remain.
- [x] `TokenExchangeClient` delegates transport to `DeferredExchange`; its public
      API and wire behaviour are unchanged (`access_denied`, `mission_terminated`,
      token-error codes, diagnostics activities all preserved).
- [x] `AAuthGovernanceClient` facade exposes mission/permission/audit/interaction
      over one signed client; sub-clients remain public.
- [x] `AAuthClientBuilder.BuildGovernance()` returns a facade wired from the same
      signed exchange pipeline as `BuildHandler()` (shared private helper).
- [x] Full conformance (417 → **422** with new facade tests) + unit (371) suites
      pass unchanged; new facade tests pass; SDK + full solution build 0/0.

**Deviations (as built):**

- The token-only `access_denied` classification and the token-only
  fail-fast-without-callback behaviour are preserved through two
  `DeferredExchangeOptions` seams rather than living in `TokenExchangeClient`:
  `RequireInteractionCallback` (token = `true`, governance = `false`) reproduces
  the token-exact "no onInteractionRequired callback" message, and
  `OnPolledResponse` (token only) runs the `403 access_denied` classifier *after*
  an interaction-branch poll (not after a clarification poll or the
  initial/direct response), matching the original placement.
- `ResolveEndpointAsync(personServer, field, ct)` emits generic `'{field}'`
  error text that is byte-identical to the original `'token_endpoint'` messages
  when `field == "token_endpoint"`.
- The shared signed-channel helper is `BuildSignedChannel(provider, innerHandler)`.
  `BuildHandler` passes `new HttpClientHandler()` (preserving the prior exchange
  signer's exact inner handler); `BuildGovernance` passes
  `_innerHandler ?? new HttpClientHandler()` so tests can inject a stub.
- `BuildGovernance()` requires an explicit signing mode (`_provider`); it does
  **not** reconstruct the lazy-refresh token-holder pipeline (that path stays
  exclusive to `BuildHandler`). Throws `InvalidOperationException` otherwise.
- `AAuth.DeferredPoll` now also fires for governance polls (additive
  observability via the shared `DeferredExchange`, not a wire change).
- DI (`AddAAuthAgentGovernance`) remains out of scope — deferred to Phase 6.

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
- **Sub-phasing (agreed 2026-06-05):** Phase 6 executes in three committable
  sub-phases, each independently buildable + tested:
  - **6a — Backend foundation (DONE):** MockPersonServer governance endpoints + `s256`
    / mission claim emission + three-gate consent + terminate hook; new
    `samples/MissionAgent/` CLI; the 12-row Consent-Matrix .NET integration test.
  - **6b — Blazor + e2e (DONE):** SampleApp `Mission.razor` (+ Home link); GuidedTour
    `TourMode.Mission` (+ snippets, sequence diagram); the two Playwright specs.
  - **6c — Glue (PENDING):** Orchestrator mission hop; `make demo-mission` / `e2e-mission`;
    READMEs + `tests/e2e/package.json` script.
- **Deterministic consent scripting (agreed 2026-06-05 — option A):** the
  integration test drives mission-approval / token / permission outcomes by
  extending the existing unsigned `/admin/*` demo pattern (e.g.
  `/admin/mission-decision`, `/admin/permission-decision`, plus pre-seeding
  `approved_tools` / prior-consent), mirroring today's `/admin/consent`. No
  config/convention-encoded policy.


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

- [x] MockPersonServer serves all four governance endpoints (§PS Governance). _(6a)_
- [x] MockPersonServer embeds `{approver, s256}` in issued auth tokens (§Auth Token). _(6a)_
- [x] MockPersonServer implements the three-gate consent decision: mission approved
      once, then resource/tool access proceeds without re-prompting unless outside
      approved scope / `approved_tools` (§Agent Token Request, §Permission Endpoint). _(6a)_
- [x] MockPersonServer exposes a minimal "terminate mission" hook so the
      `mission_terminated` path is exercised end-to-end (§Mission Status Errors). _(6a)_
- [x] `samples/MissionAgent/` proposes a mission, accesses ≥1 resource under it,
      requests a permission, records an audit entry, relays an interaction, and
      completes it. _(6a)_
- [x] SampleApp `Mission.razor` page renders the flow and labels each consent gate
      as **prompt** or **silent (in scope)**; Home links to it; existing pages
      unchanged. _(6b)_
- [x] GuidedTour `TourMode.Mission` drives every gate through **both** outcomes
      (mission approval prompt; in-scope token silent vs out-of-scope token prompt;
      `approved_tools` permission silent vs non-pre-approved permission prompt) and
      surfaces the PS decision reason for each; existing modes unchanged. _(6b)_
- [x] The PS decision reason (in-scope / prior consent / `approved_tools` /
      out-of-scope) is visible in both samples so the contrast between prompted
      and silent gates is observable. _(6b)_
- [ ] Orchestrator demonstrates a mission-governed downstream hop (§Call Chaining). _(6c)_
- [x] `make demo-mission` boots the mission demo; existing `make demo` unchanged.
      _(pulled forward from 6c; also added `agent-mission` runner)_
- [x] New GuidedTour + SampleApp mission Playwright **e2e** specs pass under the
      existing `guided-tour`/`sample-app` projects; existing specs still pass.
      _(6b — full suite 29 passed / 1 skipped locally)_
- [x] **.NET integration test** for the `MissionAgent` CLI covers **all 12 rows**
      of the Consent Test Matrix (every gate × approve/deny × prompt/silent),
      including clarification and `mission_terminated`, each asserting the
      recorded decision reason. _(6a — `MissionAgentFlowTests`, 12/12)_
- [x] `make e2e` (Blazor) and `dotnet test` (CLI integration) green locally.
      _(CLI integration 12/12; Blazor e2e full suite 29 passed / 1 skipped locally; CI not separately run)_
- [ ] Sample READMEs updated. _(MissionAgent + MockPersonServer done in 6a; others in 6c)_

#### Phase 6a additions (spec-driven, beyond the original file list)

- **Mission-aware resource (SDK):** `AAuthMissionHeader.TryParseStructured`,
  `ChallengeOptions.MissionAware`, and `AAuthChallengeMiddleware` copying the
  parsed `{approver, s256}` into `ResourceTokenBuilder.Mission` so a resource can
  surface the mission claim in the resource token it issues (§Terminology,
  §Auth Token). Demonstrated by WhoAmI `/jwt/mission`. Covered by +3 conformance
  tests (`ChallengeMiddlewareTests`, total 425).
- **Interactive mission-creation consent screen:** `/mission` defers (202 +
  interaction) to a real browser consent screen when running interactively
  (`MissionConsentScript.InteractiveBrowser`), via the same deferred path the
  token/permission gates use (SDK `MissionClient.ProposeAsync` already routes
  through `DeferredExchange`). The PS `/interaction` page now renders all three
  consent screens — mission creation (description + tools), out-of-scope token
  (mission + tools + resource/scope), and out-of-tool permission (mission +
  tools + action) — keeping the demo faithful to §Mission Creation /
  §Permission Endpoint (`action` per-call vs mission `approved_tools`).
  Scripted mode (the 12-row test) is unaffected (`InteractiveBrowser = false`).

#### Phase 6b amendments (2026-06-06, spec-driven, added mid-phase)

These refine the consent UX and **add the missing out-of-mission scope gate**.
The original Phase 6 plan (file list, line "out-of-scope token request that
**prompts**") always intended a prompted **token/scope** gate, but 6b shipped
only the prompted **tool** gate (`delete_inbox`). These steps close that gap so
both halves of the spec's gate model — a prompted *scope* (§Agent Token Request
gate 3) **and** a prompted *tool* (§Permission Endpoint) — are demonstrated.

**Spec grounding:**

- **Tools are declared; scopes are evaluated** (§Mission Creation L1233 — proposal
  is `description` + optional `tools` only, no scopes; §Mission Approval L1299–1303
  — blob carries `approved_tools`, never scopes). The mission proposal lists no
  scopes; the PS determines required scopes **per request, over the mission's
  whole life** (§Scopes L1793 "The PS evaluates requested scopes against mission
  context"; §Concurrent Token Requests L828 "some requests may be resolved
  without user interaction … while others may require consent").
- **Out-of-mission scope ⇒ prompt, not auto-deny** (§Agent Token Request gate 3;
  §Scopes L1793). Only an explicit user deny (or `mission_terminated`, gate 1)
  yields `access_denied`.

**Decisions (agreed 2026-06-06 via interview):**

- **D6 — New mission-aware endpoint + new scope (not reuse `whoami:admin`).**
  WhoAmI gains a second mission-aware endpoint guarded by a **new** resource
  scope so the out-of-mission scenario is clearly distinct from the existing
  non-mission `/jwt/admin` step-up demo. Proposed: scope `whoami:history`
  ("See your full account/profile history") at endpoint `/jwt/history`, wired
  with `ChallengeForMission(ScopeWhoamiHistory)`. Under the seeded inbox mission
  (in-scope = `whoami` only), requesting `whoami:history` falls outside the
  mission → PS prompts (gate 3). _(final names confirmed at implementation.)_
- **D7 — Add as a NEW gate (5 gates total), existing gates unchanged.** Final
  order: (1) mission approval **PROMPT** → (2) `whoami` token **SILENT** (in
  scope) → (3) `whoami:history` token **PROMPT** (out-of-mission scope) → (4)
  `send_email` tool **SILENT** (pre-approved) → (5) `delete_inbox` tool
  **PROMPT** (not pre-approved).
- **D8 — "Agent console app" = `samples/MissionAgent/`** (the CLI), not
  `samples/AgentConsole/` (which has no mission support and no mermaid). Its
  README sequence diagram gains the new out-of-mission scope consent block.
- **D9 — Consent-screen UX refinements (already applied in 6b):** PS
  `/interaction` shows **scopes and tools as separate lists**; a spec-grounded
  **tool (local) vs scope (remote)** definition box; the **creation screen lists
  no scopes** (only a note that the PS determines them per-request from the
  mission description); post-creation gates relabel the scope list **"Granted so
  far"** (accrual), with empty state "nothing yet — this is the first request".

### Amendment files

| File | Action |
|------|--------|
| `samples/WhoAmI/Program.cs` | **Modify** — add scope `whoami:history` (+ `scope_descriptions` entry, scope policy) and a mission-aware endpoint `/jwt/history` via `ChallengeForMission`; exclude `/jwt/history` from the baseline `/jwt` branch; list it in the index payload |
| `samples/WhoAmI/README.md` | **Modify** — document the new scope + endpoint |
| `samples/SampleApp/Components/Pages/Mission.razor` | **Modify** — insert the out-of-mission **scope** gate (gate 3) between the silent `whoami` token and the tool gates; client + resource panels show `/protected_endpoint` requesting the elevated scope; 5-gate narrative |
| `samples/GuidedTour/TourSession.cs` | **Modify** — extend `MissionPlan` with an out-of-mission scope token cycle (challenge → 202 PROMPT → approve → poll → exchange); renumber steps + approval/poll constants |
| `samples/GuidedTour/CodeSnippets.cs` | **Modify** — add the out-of-mission scope snippet |
| `samples/GuidedTour/Components/Pages/Tour.razor` | **Modify** — mission lane/flow text reflects the new scope gate |
| `samples/MockPersonServer/Program.cs` | **Modify (done in 6b amendments)** — separate scope/tool lists, definition box, creation screen drops scopes + adds determined-per-request note, "Granted so far" relabel |
| `samples/MissionAgent/Program.cs` | **Modify** — add a step that requests the out-of-mission scope under the mission (prompted token gate) |
| `samples/MissionAgent/README.md` | **Modify** — add the out-of-mission scope consent block to the mermaid sequence diagram + the gate table / "Scope (remote) vs tool (local)" prose |
| `docs/concepts.md` | **Modify (done)** — tools declared vs scopes evaluated; per-request, lifetime-long scope determination |
| `samples/SampleApp/playwright-tests/mission.spec.ts` | **New/Modify** — assert the 5th gate (out-of-mission scope **prompt**) |
| `samples/GuidedTour/playwright-tests/mission.spec.ts` | **New/Modify** — assert the out-of-mission scope **prompt** step |

### Amendment Definition of Done

- [x] WhoAmI exposes a new resource scope (`whoami:elevated_scope`) on a
      mission-aware endpoint (`/jwt/mission/elevated`); `scope_descriptions` +
      scope policy updated; baseline `/jwt/mission` branch excludes it
      (§Resource Metadata, §Scopes). _(6b — final names landed as
      `whoami:elevated_scope` / `/jwt/mission/elevated`, not the proposed
      `whoami:history` / `/jwt/history`; D6 deferred names to implementation)_
- [x] Under the seeded inbox mission, requesting the new scope is **out of
      mission** → PS **prompts** (gate 3), and on approval issues the auth token;
      the granted scope then shows under "Granted so far" on later screens
      (§Agent Token Request, §Scopes L1793). _(6b)_
- [x] SampleApp `Mission.razor` shows **5 gates** incl. the out-of-mission scope
      prompt, distinct from the out-of-tool permission prompt. _(6b)_
- [x] GuidedTour `TourMode.Mission` drives the out-of-mission scope cycle
      (challenge → prompt → approve → exchange) with the decision reason visible.
      _(6b)_
- [x] `samples/MissionAgent/` requests the out-of-mission scope under the mission;
      its README mermaid diagram + gate prose include the new consent block. _(6b)_
- [x] Consent-screen UX refinements (D9) reflected and live-verified. _(6b)_
- [x] Playwright specs assert the new prompted-scope gate; existing specs pass.
      _(6b)_

---

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
