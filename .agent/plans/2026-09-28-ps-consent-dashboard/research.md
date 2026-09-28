# PS Consent Dashboard — Research

Research for a complementary **Person Server (PS) consent dashboard** mode in the
samples: the agent's back end raises the consent request, the agent moves
straight into its asynchronous poll, and the person decides every PS-hosted
consent request from one signed-in dashboard that also shows history, grouped by
mission or agent. The existing per-request interaction link keeps working.

This initiative is isolated from the draft-11 migration
([2026-09-11-aauth-v11-spec-migration](../2026-09-11-aauth-v11-spec-migration/research.md)),
but it is built on the same branch (`wip/aauth-draft-11`). See
[Baseline](#baseline-branch-and-build).

## Method

- Three read-only subagents surveyed the consent UX in parallel: SampleApp;
  GuidedTour; and CapabilitySupport, EventSupport, MissionAgent, AgentConsole,
  Concierge, the Access Server/Inbox consent UI, `tests/e2e`, and the Makefile.
- A fourth earlier subagent mapped PS hosting, clients, tests and docs.
- **Re-verified directly against source:** every spec citation below (vendored
  v10 and v11), the SDK pending/interaction mechanics, MockPersonServer
  endpoints, GuidedTour's click-to-poll and "Run all" logic, and the consent link
  surfaces (file:line re-grepped on 2026-09-28).
- **Reported by subagents, spot-checked only:** Playwright helper call sites and
  per-page narrative text. Re-check the line numbers before editing.

## Spec basis

Target text is draft-11 ([`aauth-spec/v11`](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md)),
because the branch is cutting over to it. The draft-10 counterparts are noted
where they differ.

| Topic | Rule | Citation |
|---|---|---|
| Out-of-band completion | "The server hosting the interaction URL MAY instead complete the interaction over a channel it already controls … without the person visiting `url` or presenting `code`; the code is consumed at that completion, and the pending URL returns the terminal response … Only the host of `url` can complete an interaction this way." | (#user-interaction, v11 L1011). Not present in v10. |
| Code is correlation only | The code is not an authorisation credential. The decision MUST be recorded via an authenticated channel at the PS, and the code alone MUST NOT authorise it. | (#interaction-code-format, v11 L2394; v10 L2136) |
| Single use | A code consumed by out-of-band completion MUST later be rejected with `invalid_code`, the same as a consumed code. | (#interaction-code-format, v11 L2396) |
| Interaction wire shape | `202` + `AAuth-Requirement: requirement=interaction; url; code` + `Location` + `Retry-After` | (#interaction-required, v11 L2358) |
| Approval pending | `202` + `requirement=approval` + `Location` + `Retry-After`. No user direction by the agent; same terminal codes. | (#approval-pending, v11 L2443–L2454; v10 L2191) |
| Misdirection defence | Show the full request context. `requirement=approval` via an existing session is the *stronger* mitigation. | Interaction Code Misdirection (v11 L2852–L2854; v10 L2837) |
| Approver authentication | Beyond a single-user local deployment, the PS MUST authenticate the approving party (e.g. operator session cookie). | (#ps-approval-endpoint-auth, v11 L2906–L2908; v10 L2859) |
| PS direct channel | "A PS MAY also maintain a direct channel to the person … for out-of-band approvals". | (#person-server, v11 L799; v10 L530) |
| Recording | "The PS SHOULD record all interaction requests and responses; within a mission it records them in the mission log." | (#interaction-response-poll-authority, v11 L1181) |

**Conclusion.** A dashboard is an out-of-band completion channel hosted by the
same server that hosts `url`, which is allowed. The PS keeps answering
`requirement=interaction` (link still valid) and *also* lists the pending
request on the dashboard. Whichever path decides first wins. A dashboard
decision must consume the code so that a later link visit returns
`invalid_code`. `requirement=approval` (no link at all) is a separate, optional
hardening and is not required here.

**Host constraint.** The PS can only complete interactions whose `url` it hosts.
Access Server consent relayed through the PS in the four-party flow (`url` on the
AS), R3 per-call consent and resource-hosted consent (Inbox, Documents) cannot be
completed from the PS dashboard.

## SDK mechanics (current branch)

- **The agent polls right after the callback.**
  [`DeferredExchange.PostAsync`](../../../src/AAuth/Agent/DeferredExchange.cs)
  invokes `OnInteractionRequired`, records the handled URL, and polls the
  `Location` at once. The poller stops early only on a *different*
  interaction/clarification requirement (`ComposePollerOptions`). A dashboard
  decision therefore reaches the agent without any agent-side change.
- **`requirement=approval` already polls silently** in the PS exchange. It
  matches neither the interaction nor the clarification branch. It is not
  emitted by the PS mapper: [`Pending202`](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs)
  (L1424) always formats `requirement=interaction` with
  `entry.InteractionCode ?? entry.Browser.Code` (L1434).
- **PS pending store.**
  [`IPersonPendingStore`](../../../src/AAuth/Person/IPersonPendingStore.cs)
  exposes `Add/Get/GetByCode/MarkAllowed/MarkDenied`, with **no enumeration**.
  `Add` now takes `string? missionS256` (the draft-11 migration replaced
  `MissionClaim`). Entries carry `ConsentAgentId`, `ResourceUrl`, `Scope`,
  `Account`, `MissionS256`, `MissionGate`, `Status`, `Lifecycle` (DeferredState)
  and `Browser` (BrowserInteraction). The in-memory store evicts roughly 1 h
  after its 10 min TTL.
- **Browser code lifecycle.**
  [`BrowserInteraction`](../../../src/AAuth/Server/BrowserConsentSessions.cs):
  - `Consumed` is `internal` (L18) and set on first entry (L196).
  - `Renew()` (L22) issues a fresh code and bumps `Generation`. That invalidates
    the old code and any in-flight `BrowserConsentDecision`.
  - `BrowserConsentSessions` (L78) provides the cookie session, CSRF and
    isolated demo sign-in (loopback-only by default, L108), and accepts an
    authenticated `HttpContext.User` identity when `authorizePerson` allows it.
- **Concierge relays.** It throws `AAuthInteractionChainedException` from
  `OnInteractionRequired` and re-emits the PS `url`/`code` upstream. It stays
  valid, because the link is unchanged.

## MockPersonServer today

- **Wiring.** `MapAAuthPersonServer`, with `/admin` unsigned
  ([Program.cs](../../../samples/MockPersonServer/Program.cs) L157, L170). One
  `BrowserConsentSessions("AAuth.Person.Consent", isolated-person-demo)` (L155).
- **Two pending stores:**
  - The SDK token pending entries go through
    [`ConsentBridgePersonPendingStore`](../../../samples/MockPersonServer/ConsentBridgePersonPendingStore.cs)
    (`Add` L32, `Get` L40). They cover three-party consent, the out-of-scope
    mission token gate, the four-party PS consent step and resource-interaction
    hops.
  - Mission creation and tool-permission requests use the sample-owned
    [`MissionPendingStore`](../../../samples/MockPersonServer/MissionGovernance.cs)
    (`MissionPendingEntry` L257, `Decision` L329, store L336). These are only
    parked (202) when `MissionConsentScript.InteractiveBrowser` is set.
- **Decision surfaces.**
  - `/interaction` (L712) renders a mission or token page per code.
  - `/interaction/approve` (L909) and `/interaction/deny` (L993) mutate either
    store under `BrowserConsentDecision.ApplyAsync`. Approve re-runs the
    asserter and writes identity fields and `FederationConsent` directly.
  - `/admin/consent` grants standing consent that the bridge store picks up on
    the next `Get`.
  - `/admin/reset` (L612) clears the consent store, mission-pending store and
    script only.
- **Identity.** A single demo person (`SampleIdentityClaimsAsserter`,
  `isolated-person-demo`). Every request belongs to that person.
- **No history.** Decided entries vanish with the TTL. The mission log
  (`IMissionLog`, `/admin/mission-log/{s256}`) records governed steps per
  mission only.

## Consent surfaces in the samples

"PS-hosted" means the dashboard can decide it. "AS-/resource-hosted" means it is
out of scope.

### SampleApp (`samples/SampleApp/Components/Pages`)

| Page | PS-hosted consent | Capture → render |
|---|---|---|
| [Deferred](../../../samples/SampleApp/Components/Pages/Deferred.razor) | Three-party token | `BuildUserUrl()` L195 → button L124 |
| [CallChain](../../../samples/SampleApp/Components/Pages/CallChain.razor) | Hop 1 + chained hop 2 | L282 → L158 |
| [Mission](../../../samples/SampleApp/Components/Pages/Mission.razor) | Mission creation, elevated scope, tool permission | L606 → L295 |
| [MissionCallChain](../../../samples/SampleApp/Components/Pages/MissionCallChain.razor) | Mission creation, clarified elevated scope | L519 → L189 |
| [Bookings](../../../samples/SampleApp/Components/Pages/Bookings.razor) | PS account consent (R3 per-call is AS-hosted) | L294 → L159; `IsPersonConsent` L190 |
| [Federated](../../../samples/SampleApp/Components/Pages/Federated.razor) | PS consent step (AS login is AS-hosted) | L209 → L130; `IsPersonConsent` L170 |
| [SubAgent](../../../samples/SampleApp/Components/Pages/SubAgent.razor) | PS rounds (AS round is AS-hosted) | L215 → L133 |
| [Inbox](../../../samples/SampleApp/Components/Pages/Inbox.razor) | — resource-hosted | out of scope |

- Every page polls in the background while the button is shown (SDK loop plus a
  UI `PeriodicTimer`).
- [`ConsentProgress.razor`](../../../samples/SampleApp/Components/ConsentProgress.razor)
  documents the per-code browser flow and needs a dashboard variant.

### GuidedTour (`samples/GuidedTour`)

- **Tracks with PS-hosted consent:** Deferred, CallChain, Mission,
  MissionCallChain, and the PS rounds of SubAgent. AS-hosted: Federated,
  RichRequests (R3), SubAgent AS round. Resource-hosted: ResourceManaged.
- **Polling starts on click.** The "Open consent page" link
  ([Tour.razor](../../../samples/GuidedTour/Components/Pages/Tour.razor) L93–L94)
  calls `MarkInteractionOpenedAsync` (L580). That records the approval-opened
  step and only then calls `StartPendingPollAsync` (L592,
  [TourSession.cs](../../../samples/GuidedTour/TourSession.cs) L2552).
- **"Run all" stops at consent.** `RunAllAsync` (Tour.razor L602) breaks on
  `AwaitingUserApproval` (TourSession L652) with a "Stopped: … click the green
  link" error. `StepUserApprovesPlaceholder` (L2151) throws if the user step is
  reached without a click.
- **Its own wire-level poll.** The tour replays the wire steps with
  `RunPendingPollAsync` rather than the SDK loop. Its URL/code live in
  `_interactionUrl`/`_interactionCode` (`UserInteractionUrl` L659), and
  sub-agent rounds use `WorkerConsentUrl` (L2482, L3766).
- **Hard-coded snippets.** [CodeSnippets.cs](../../../samples/GuidedTour/CodeSnippets.cs)
  (L150, L162) teach "direct the user to the interaction URL".

### Shared walkthroughs (embedded by both apps)

| Component | PS consent | Link |
|---|---|---|
| [CatalogDemoSession](../../../samples/CapabilitySupport/CatalogDemoSession.cs) | Yes | L74 → CatalogWalkthrough L39 |
| [DocumentDemoSession](../../../samples/CapabilitySupport/DocumentDemoSession.cs) | Yes (PS step) | L63 → DocumentWalkthrough L33 |
| [WalletDemoSession](../../../samples/CapabilitySupport/WalletDemoSession.cs) | Yes | L119 → WalletWalkthrough L54 |
| [EventDemoSession](../../../samples/EventSupport/EventDemoSession.cs) | Yes | L85 → EventWalkthrough L55 |

Project graph: SampleApp and GuidedTour reference CapabilitySupport and
EventSupport. CapabilitySupport references EventSupport. EventSupport is the
lowest shared Razor library.

### CLIs and intermediaries

- [MissionAgent](../../../samples/MissionAgent/Program.cs) `PromptUserAsync`
  (L348) prints the URL and opens a browser per prompt (L357).
- [AgentConsole](../../../samples/AgentConsole/Program.cs) prints the URL (L227).
- Concierge relays the link unchanged.

### Tests

- **Integration.** `tests/AAuth.Tests/Integration/MockPersonServerTests.cs`
  hosts the PS in-process (`WebApplicationFactory<MockPersonServer.Entry>`,
  `UseIsolatedDemoConsent()`, `ConsentFactory` with `RequireConsent=true`).
- **Playwright helpers.** [`tests/e2e/helpers/consent.ts`](../../../tests/e2e/helpers/consent.ts)
  provides `approveInPopup`, `denyInPopup`, `authenticateConsent`,
  `approvePersonConsent`, `grantConsent`, `resetConsent`, `decideAccessConsent`
  and `keycloakLogin`. `worker-consent.ts` provides `completeWorkerConsent`.
  Fixtures call `resetConsent()` before each test.
- **Boot.** `playwright.config.ts` boots PS `:5100` with `RequireConsent=true`,
  plus the SampleApp `:5240`, GuidedTour `:5400` and the backends.

## Baseline (branch and build)

- The branch is `wip/aauth-draft-11`, with the draft-11 SDK cutover committed
  (`05ea90c`) plus 26 uncommitted changes.
- `dotnet build AAuth.slnx` currently **fails** (2026-09-28): 23 errors across
  Concierge, Federated AS, MockPersonServer (`IPersonPendingStore.Add`
  signature, `MissionClaim` removed), Documents, Trips, AAuth.R3,
  AAuth.Conformance and AAuth.Events.Tests. SampleApp and GuidedTour fail only
  through AAuth.R3.
- The dashboard therefore cannot be compiled or verified until the draft-11
  migration restores those projects. The work here is written against the
  post-cutover shapes (`missionS256`).

## Design options considered

| Option | Verdict |
|---|---|
| Keep `requirement=interaction`; dashboard completes out-of-band (v11 L1011) | **Chosen.** No wire or SDK change; the link and Concierge relay still work. |
| Switch to `requirement=approval` in dashboard mode | Deferred. Needs an SDK mapper option and drops the link; stronger misdirection defence (v11 L2854). |
| Enumerate SDK entries via a new `IPersonPendingStore.List` | Not needed. The sample's bridge store already sees every `Add`. |
| Consume the code via `Browser.Renew()` | Viable with no SDK change. The old code then fails lookup (`invalid_code`) and counts as a failed attempt. |
| Consume the code via a new public `BrowserInteraction.Consume()` | Cleaner semantics, but is an SDK change. Fallback if `Renew()` proves inadequate. |
| Live dashboard via SSE or SignalR | Heavier. JSON polling from vanilla JS is enough for a sample. |

## Gaps and open questions

Rulings live in [implementation-log.md](implementation-log.md).

| # | Question |
|---|---|
| Q1 | Base branch |
| Q2 | Waiting-step UI (dashboard button vs link) |
| Q3 | Sequencing against the red build |
| Q4 | Wire response in dashboard mode |
| Q5 | Dashboard authentication and availability |
| Q6 | How a dashboard decision consumes the code |
| Q7 | Dashboard live-update mechanism |
| Q8 | History scope and retention |
| Q9 | Which request kinds the dashboard lists, and which it can decide |
| Q10 | Scripted (non-interactive) mission decisions in history |
| Q11 | Where the shared agent-side prompt component lives |
| Q12 | Deep-link parameter |
| Q13 | Playwright strategy |
| Q14 | CLI behaviour |
| Q15 | Decision-logic sharing between `/interaction/*` and the dashboard |
