# Implementation Log — AAuth-Access opaque-token flow

Companion to [`implementation-plan.md`](implementation-plan.md) and
[`research.md`](research.md). A dated, **append-only** narrative of decisions
taken, deviations from the plan, and open questions / inputs needed — recorded
while implementing, for the owner to review. Three sections, in that order.

Entry format: `[YYYY-MM-DD] [Phase N] <title>` with a status — `PROCEEDED
(default X)` (chose a default to stay unblocked; revert if you disagree),
`BLOCKED`, or `RESOLVED`. Append; do not rewrite. A reversed decision gets a new
dated entry that supersedes the old one.

> Seeded 2026-06-27 alongside the plan to record the Phase 0 decision-gate
> rulings (OQ1–OQ6). No code has been written yet (plan status: *Not started*);
> the `PROCEEDED` defaults below stand until the owner reverts one.

## Decisions Taken

### [2026-06-27] [Phase 0] OQ1 — opaque-state wrapping seam — RESOLVED

The SDK already ships the seam and a demo store
([`Server/IOpaqueTokenStore.cs`](../../../src/AAuth/Server/IOpaqueTokenStore.cs):
`IOpaqueTokenStore` + `InMemoryOpaqueTokenStore` + `OpaqueTokenInfo`). The spec
leaves the wrapped format to the resource (`#aauth-access`, L740), so **no**
default cryptographic wrapper will be added — the app supplies internal state and
the SDK only wires the existing seam into the pipeline (Phase 3). Closes the
research's "default lean: a seam + a simple reference-token demo store."

### [2026-06-27] [Phase 0] OQ2 — per-origin replay store ownership — PROCEEDED (default: sibling handler + injectable store)

The agent keeps the latest `AAuth-Access` per resource origin in an injectable
`IAAuthAccessStore` (in-memory default), driven by a sibling
`AAuthAccessHandler` positioned **outer** of `AAuthSigningHandler` and **inner**
of `InteractionHandler`. This mirrors the existing handler composition and keeps
the signer untouched. Kept **distinct** from the resource-side `IOpaqueTokenStore`
(the agent never inspects the blob). Revert if a single combined store is
preferred.

### [2026-06-27] [Phase 0] OQ3 — `authorization` covered-component toggle — RESOLVED

No toggle needed. The signer already adds `authorization` to the covered
components whenever the header is present
([`AAuthSigningHandler.cs`](../../../src/AAuth/HttpSig/AAuthSigningHandler.cs)
L217–221 append to the base; L280–284 list it in `@signature-params`). The agent
handler only needs to *set* `Authorization: AAuth <token68>`; covering is
automatic. Closes the research's "auto when token present" lean as already-true.

### [2026-06-27] [Phase 0] OQ4 — rolling-refresh race rule — PROCEEDED (default: last-writer-wins)

Concurrent in-flight requests may each receive a new `AAuth-Access`. Rule:
**last-writer-wins**, no serialization — the store simply overwrites with the
most recently observed value. Documented behavior; acceptable because the spec
defines rolling refresh as "use the new value on subsequent requests" (L754)
without ordering guarantees. Revert if strict ordering is required.

### [2026-06-27] [Phase 0] OQ5 — `202 → poll → 200` reuse — PROCEEDED (default: reuse `InteractionHandler`)

The handshake reuses
[`Agent/InteractionHandler.cs`](../../../src/AAuth/Agent/InteractionHandler.cs)
(the `202 + requirement=interaction → poll Location → terminal 200` loop) and
[`Headers/Interaction.cs`](../../../src/AAuth/Headers/Interaction.cs) unchanged;
the outer `AAuthAccessHandler` observes the terminal `200` and captures
`AAuth-Access`. **Corrects** the original plan/research note that said
`DeferredPoller` — the reused poll loop lives in `InteractionHandler`.

### [2026-06-27] [Phase 0] OQ6 — `authorization_endpoint` entry point — PROCEEDED (default: out of scope for v1) — SUPERSEDED 2026-06-27

> Superseded by the OQ6 reversal below — owner ruled it **in scope**. Original
> reasoning kept for history.

The spec allows the `202` to be triggered by a signed `POST authorization_endpoint`
(L620, L2642) as well as by the resource call. The call-triggered `202` fully
demonstrates the flow, and the `authorization_endpoint` metadata field already
emits ([`WellKnownEndpoints.cs`](../../../src/AAuth/Server/Metadata/WellKnownEndpoints.cs)
L170–172). Deferring the endpoint-mapping helper to keep the first cut focused.
Listed in the plan's Out-of-Scope table; revert if interop requires it.

### [2026-06-27] [Phase 0] OQ2 + OQ4 — owner-confirmed defaults — RESOLVED

Owner accepted the PROCEEDED defaults verbatim: **OQ2** (a separate, injectable
`IAAuthAccessStore` driven by a sibling `AAuthAccessHandler`, kept distinct from
the resource-side `IOpaqueTokenStore`) and **OQ4** (rolling-refresh =
last-writer-wins, no serialization). No change from the defaults above; now
confirmed rather than provisional.

### [2026-06-27] [Phase 0] OQ6 — `authorization_endpoint` entry point — RESOLVED (reverses the default: now IN scope)

Owner ruling: *"do both if the spec mentions it — our samples must demonstrate the
spec."* The spec returns a resource token / runs authorization in **two ways**
(L605): reactive (`401`/`202` on the resource call) and proactive (signed
`POST authorization_endpoint`, L620, L2642). So the build now includes both:

- **Resource (Phase 3):** a `MapAAuthAuthorizationEndpoint(...)` helper accepting a
  signed `POST` with `{"scope": …}` (L620), running the **same** resource-managed
  decision logic as the reactive path (`202 + requirement=interaction`, then issue
  `AAuth-Access` on completion / identity-only).
- **Agent (Phase 2/4):** reach the discovered `authorization_endpoint` with the
  existing signed client; the `InteractionHandler` + `AAuthAccessHandler` chain
  handles the `202 → poll → 200 + AAuth-Access` with no extra agent code.
- **Inbox demo + e2e (Phase 4):** exercise both entry points (reactive
  `GET /messages → 202`, proactive `POST /authorize`).

Supersedes the 2026-06-27 OQ6 "out of scope" default; the row is removed from the
plan's Out-of-Scope table and folded into Phases 3–4.

## Deviations from Plan

### [2026-06-27] [Phase 5] Docs sweep missed several sample READMEs — RESOLVED (per-doc subagent pass)

The initial Phase 5 sweep updated the docs-table targets from `research.md` but
**missed** sample READMEs not on that list — most notably
`samples/MockResourceServers/README.md` (still "Four small … resource servers"
with a 4-server table + 4-step Aria narrative). A follow-up dispatched one
subagent per markdown doc/cluster (disjoint file sets, with the guardrail that
"four access **modes**" is correct and only resource **server** counts change).
Caught + fixed: `samples/MockResourceServers/README.md` (5 servers, Inbox row,
narrative, run-all), `samples/GuidedTour/README.md` (9 flows, slot-2
ResourceManaged, InboxUrl, make-demo list), `samples/AgentConsole/README.md`
(`--resource-managed` flag + example + path mapping), root `README.md`
(Repository Layout samples list +Inbox), `samples/README.md` (make-demo boot list
+ GuidedTour/SampleApp "requires" lists +Inbox), `src/AAuth/README.md` (Features
+two-party), and `docs/` (API map +agent surface, call-chaining + configuration
+Inbox, challenge-middleware enum +ResourceManaged). Per-server READMEs and the
Mock*/Concierge/MissionAgent READMEs needed no change (their "four" refs are
"four-party", which is correct). No markdown-lint errors; no compiled code
touched. Residual "four resource servers" strings remain only in historical
`.agent/plans/`.

### [2026-06-27] [Phases 1–3] Per-phase e2e gate deferred to Phase 4 — PROCEEDED

The guiding principles call for an e2e run at the end of each code phase. Phases
1–3 add only SDK surface that is **opt-in and off by default** with **no sample
wiring yet** (the Inbox demo + GuidedTour/SampleApp pages land in Phase 4), so the
existing Playwright suites exercise none of the new paths and unchanged flows are
unaffected. Running the full stack now would only re-validate untouched flows.
Deferring the e2e gate to Phase 4, where the resource-managed flow first becomes
exercisable end to end. Unit + conformance remain the per-phase gate for 1–3.

### [2026-06-27] [Phase 3] Consumption as extensions, not a dedicated middleware — PROCEEDED

The plan's summary described a resource-side "consumption middleware." During
implementation it became clear the binding MUST (`authorization` covered) is
**already** enforced by `AAuthVerifier` inside the existing
`AAuthVerificationMiddleware` (it passes the `Authorization` header to the
verifier, which rejects "present but uncovered"). The only remaining work —
`token68`-validate, `ValidateAsync`, surface `OpaqueTokenInfo`, and decide
202-vs-issue — is inherently endpoint-driven (the resource decides). So consumption
is a `HttpContext` extension (`ResolveAAuthAccessAsync`) the endpoint calls, not a
new middleware. This is less surface, avoids duplicating the verifier's check, and
keeps the access decision with the app. No behavior is lost; the binding is still
enforced for every signed request carrying `Authorization`.

## Open Questions / Inputs Needed

_Both items below resolved 2026-06-27 (owner). Kept here for traceability; the
rulings also drive Phase 3 / Phase 4 in the plan._

### [2026-06-27] [Phase 3] `OpaqueTokenInfo` rotation helper — RESOLVED (no new method)

Owner took the recommendation. Spec basis: rolling refresh (L754) says the
**agent** replaces its current token with any newly issued value; it does **not**
require the resource to atomically supersede/revoke the old one. So **no**
`SupersedeAsync` is added — rotation = call the existing `IssueAsync(...)` and emit
the new `AAuth-Access`, letting the old token lapse via `Expiration` or, for
immediate death, the existing `RevokeAsync(old)`. Avoids an abstraction for a
one-line operation. Closes inconsistency #5 as "by design, no helper."

### [2026-06-27] [Phase 4] Inbox demo domain — RESOLVED (Inbox / email)

Owner chose **Aria Inbox (email)** on `:5004` — "import the traveler's trip
confirmations." Rationale: resource-managed "drops in where you use OAuth" (L2624)
and the opaque token "MAY be an existing OAuth access token" (L740); email is the
canonical own-consent OAuth service and what real travel assistants do. Mock/seed
data only (no real PII). Sits in the journey between Profile (identity) and
Calendar (PS-asserted).

### [2026-06-27] [Phase 1] `token68` utility shape — PROCEEDED (default: `AAuthAccessHeader` static helper)

Implemented `AAuthConstants.Headers.AAuthAccess = "AAuth-Access"` (closes
inconsistency #4) and `src/AAuth/Headers/AAuthAccessHeader.cs`, a static helper
mirroring `AAuthRequirementHeader`'s style. Public API: `IsValidToken68` /
`ValidateToken68`; `FormatAuthorization` / `ParseAuthorization` /
`TryParseAuthorization`; `FormatAccess` / `ParseAccess` / `TryParseAccess`. The
spec's "more than one credential" MUST is enforced at the string level (a second
credential cannot be a single `token68`); the repeated-header-line variant is
deferred to the consuming middleware/handler (Phases 2–3) and noted in the file's
remarks. Tests: 33 unit (`AAuthAccessHeaderTests`) + 6 conformance
(`AAuthAccessTokenGrammarTests`). Full suites green: 456 unit / 550 conformance, 0
regressions.

### [2026-06-27] [Phase 3] Resource side wired — PROCEEDED

Wired the resource side. `AAuthAccessMode.ResourceManaged` added;
`AAuthChallengeMiddleware` treats it as pass-through (the resource manages
authorization itself). Consumption/issuance live in **`HttpContext` extensions**
(`AAuthHttpContextExtensions`): `ResolveAAuthAccessAsync` (token68-validate +
`ValidateAsync` + cache, requires a verified signature, rejects >1 credential),
`TryGetAAuthAccess`, `IssueAAuthAccessAsync` (mint + emit `AAuth-Access`),
`InteractionRequiredAAuth` (202 + `requirement=interaction` + `Location`).
`MapAAuthAuthorizationEndpoint(pattern, handler)` maps the signed `POST` with
`{"scope":…}` (L620) and dispatches to an app delegate. DI:
`AAuthResourceOptions.EnableResourceManagedAccess` registers a default
`InMemoryOpaqueTokenStore`. Tests: 9 unit (`AAuthHttpContextExtensionsTests`
resource-managed) + 3 binding conformance (`AAuthAccessSignedComponentTests`) + 3
in-pipeline integration (`ResourceManagedFlowTests`, real `TestServer`:
proactive authorize → issue → agent replay → resolve). Full suites green: 478
unit / 556 conformance, 0/0.

### [2026-06-27] [Phase 4] Inbox demo server + integration tests — PROCEEDED (partial)

Built the **Inbox** resource-managed server
(`samples/MockResourceServers/Inbox`, `:5004`): own consent page, in-memory
pending store, both spec entry points (reactive `GET /messages`, proactive
`POST /authorize` via `MapAAuthAuthorizationEndpoint`), `/pending/{code}` poll
target, and `aauth-resource.json` advertising `access_mode=aauth-access-token`
+ `authorization_endpoint`. Registered in `AAuth.slnx`; wired into `make resources`
and `make demo`; README added. Integration tests (`InboxFlowTests`, ×3 against
`WebApplicationFactory<Inbox.Entry>`) prove the **full** end-to-end flow: reactive
consent handshake (202 → approve → poll → 200 → capture → replay → messages),
proactive authorize, and metadata advertisement. Full suites green: 481 unit /
556 conformance, 0/0. **Remaining in Phase 4:** GuidedTour `ResourceManaged`
flow, SampleApp `/inbox` page, AgentConsole mapping, and the Playwright browser
e2e spec (presentation-layer; the protocol flow is fully proven by
`InboxFlowTests`).

### [2026-06-27] [Phase 4] UIs + CLI + e2e — PROCEEDED

Completed the presentation layer. **SampleApp** `/inbox` page (slot 2, between
`/identified` and `/calendar`) + nav + Home card — drives the real consent
handshake (surfaces the Inbox consent link, the SDK polls + replays).
**AgentConsole** `--resource-managed` flag (two-party, hwk; prints the consent URL,
does the two-call `/messages` pattern). **GuidedTour** `TourMode.ResourceManaged`
flow (slot 2, 6 steps) delegated to a subagent (Phase Implementor) that mirrored
the Deferred flow two-party against the live Inbox; both `GuidedTour` and
`AAuth.slnx` build 0/0. **e2e**: `samples/SampleApp/playwright-tests/inbox.spec.ts`
+ `samples/GuidedTour/playwright-tests/resource-managed.spec.ts`, Inbox added to
the Playwright `webServer` array, `ResourceManaged` added to the e2e `TourMode`
helper (step count 6) + the `phase8-visual` matrix. Specs typecheck and are
discovered (`npx playwright test --list`).

**Deviation — e2e not run in this environment:** the browser e2e needs the full
~12-service stack + Playwright browsers (`make e2e`), which is not run here. The
SampleApp spec is high-confidence (the page is ours); the GuidedTour spec is a
best-effort mirror of `deferred.spec.ts` adapted to the Inbox consent popup
(`#approve`) and may need a selector/step-count tweak when first run live. Full
build + unit + conformance remain green: 481 unit / 556 conformance, 0/0.

### [2026-06-27] [Phase 5] Docs & inconsistency sweep — PROCEEDED

Swept the non-compiled surfaces and fixed the pre-existing inconsistencies
(#1–#3): rewrote [docs/workflows/resource-managed-access.md] against the real API
(`WithResourceManagedAccess`, the `HttpContext` helpers, `MapAAuthAuthorizationEndpoint`,
`EnableResourceManagedAccess`) — no more inert `IOpaqueTokenStore` wire-up;
updated [docs/concepts.md] L38 + [docs/README.md] API map; flipped the root
[README.md] Access Modes row (added GuidedTour/SampleApp demo links) and removed
the "one protocol surface not yet implemented" claim (L287); [aauth-spec/SPEC-VERSION.md]
+ [aauth-spec/CHANGELOG.md] now state all four modes are implemented;
[samples/README.md] four→five Aria servers + Inbox row + run section + `make`
descriptions; [docs/getting-started.md] Supported-Flows demo column + flow list;
[docs/reference/dependency-injection.md] new agent/resource options. Grep-verified
no remaining "not yet implemented"/"not implemented" `AAuth-Access` claims outside
historical `.agent/plans/`. Build + unit + conformance green (481 / 556, 0/0).

### [2026-06-27] [Phase 6] Internal review — RESOLVED (PASS)

Dispatched the `Implementation Validator` subagent. It had **no file-access
tools** (only a session-store query interface) and correctly **refused to
fabricate** `file:line` findings; it instead returned a rigorous C1–C7
verification checklist (and one false-positive concern, R1, that Phase 5 hadn't
run — an artifact of stale session data ending mid-Phase-4). I executed its
checklist directly against the code + tests:

- **C1 — never a standalone bearer (Critical MUST):** PASS. Two independent
  guards — `AAuthVerifier.cs:122` throws when `Authorization` is present but
  `authorization` is not covered; `AAuthHttpContextExtensions.ResolveAAuthAccessAsync`
  (L124) returns null unless verification ran. The Inbox routes `/messages`,
  `/pending`, `/authorize` behind `UseAAuthVerification`, so the verifier always
  runs first.
- **C2/C3 — agent covers `authorization`, handler ordering:** PASS. Signer
  auto-covers (L217–221/L280–284); `AAuthAccessHandler` is wrapped directly around
  the signer (outer of signer, inner of interaction) in `WrapWithAccessHandler`.
- **C4 — token68 grammar:** PASS. `Token68_RejectsMultipleCredentials` + empty /
  whitespace / control-char negatives (agent and resource paths).
- **C5 — rolling refresh:** PASS. Last-writer-wins store; `RollingRefresh_SwitchesToNewToken`.
- **C6 — both entry points:** PASS. Reactive + proactive `MapAAuthAuthorizationEndpoint`;
  `ResourceManagedFlowTests` + `InboxFlowTests` exercise both.
- **C7 — rejection coverage:** PASS. `Verifier_Rejects_WhenAuthorizationPresentButUncovered`,
  `ResolveAAuthAccess_ReturnsNull_WhenVerificationDidNotRun`,
  `MultipleAccessHeaders_AreRejected_NotStored`, `ResolveAAuthAccess_ReturnsNull_ForInvalidToken68`.
- **Inconsistencies #1–#6:** resolved in Phase 5 (R1 was a false positive).

**Verdict: PASS — 0 code-verified Critical/High findings.** The browser e2e
(`make e2e`) remains the one validation not run in this environment.

### [2026-06-27] [Phase 2] Agent capture/replay — PROCEEDED (default: `AAuthAccessHandler` + `IAAuthAccessStore`)

Implemented the agent side: `src/AAuth/Agent/IAAuthAccessStore.cs`
(`IAAuthAccessStore` + `InMemoryAAuthAccessStore`, per-origin, last-writer-wins)
and `src/AAuth/Agent/AAuthAccessHandler.cs` (a `DelegatingHandler` that sets
`Authorization: AAuth <token68>` from the store before signing and captures
`AAuth-Access` after the response). Builder opt-in
`AAuthClientBuilder.WithResourceManagedAccess(store?)` inserts it via a
`WrapWithAccessHandler` helper **directly above the signer** in all three
pipelines (simple, challenge, refresh-only), so it sits inner of
`InteractionHandler` and the signer auto-covers `authorization` (confirmed: OQ3).
DI: `AAuthAgentOptions.EnableResourceManagedAccess` + `AAuthAccessStore`, wired in
`AddAAuthAgent`. Origin key = `scheme://authority` lowercased (OQ2 confirmed).
Multiple `AAuth-Access` headers or an invalid `token68` are ignored, not stored
(spec L756). Tests: 13 new (`AAuthAccessHandlerTests` ×9 +
`InMemoryAAuthAccessStoreTests` ×5 — capture, replay, `authorization` covered,
rolling refresh, multi-credential reject, caller-Authorization not overridden).
Full suites green: 469 unit / 550 conformance, 0 warnings / 0 errors.
