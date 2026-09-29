# PS Consent Dashboard — Implementation Plan

Research: [research.md](research.md). Decisions and rulings:
[implementation-log.md](implementation-log.md).

> **Update (2026-09):**
>
> - **Sequencing.** This initiative runs **next**, before
>   [2026-09-29-sdk-api-surface-consistency](../2026-09-29-sdk-api-surface-consistency/implementation-plan.md).
>   That plan (its Q16) rebases onto this one afterwards.
> - **Build.** The draft-11 migration has closed and the full solution
>   build is green, so Q3 is superseded.
> - **Scope.** GuidedTour capability modes are added to Phase 4.
> - **Forward compatibility.** This plan now carries rules so the SDK
>   refactor can absorb its wiring; see Guiding principles.

## Goal

Add a complementary **dashboard mode** to the samples' Person Server (PS)
consent:

1. **Request.** The agent's back end sends its token or mission request. The PS
   parks it (`202`, `requirement=interaction` unchanged).
2. **Wait.** The agent goes straight into its asynchronous poll. "Run all"
   continues into the wait instead of stopping.
3. **Prompt.** Only the waiting step shows a button. It opens the PS dashboard,
   which is optional to click because the person may already have it open. A
   small secondary link opens the per-request page directly.
4. **Decide.** The signed-in person approves or denies on the dashboard. The
   dashboard shows every pending and historical PS consent request, grouped by
   mission or by agent. The agent's next poll returns the terminal response.

## Guiding principles

- **Spec conformance is paramount; backwards compatibility is not a goal.** The
  dashboard is out-of-band completion by the host of `url` (#user-interaction,
  v11 L1011).
  - A dashboard decision MUST consume the code (#interaction-code-format, v11
    L2396).
  - The dashboard MUST authenticate the approver (#ps-approval-endpoint-auth,
    v11 L2908).
  - The code MUST NOT authorise anything on its own (v11 L2394).
- **No SDK or wire change** (Q4, Q6). Any SDK touch is a logged deviation.
- **Complementary, not a replacement.** The per-request `/interaction?code=`
  flow, `/admin/consent`, the Concierge relay, and Access Server and resource
  consent keep working unchanged.
- **One decision path.** The link and dashboard share `PersonConsentDecisions`
  (Q15), so they cannot drift.
- **The dashboard decides only what the PS hosts** (Q9).
- **Forward-compatible with the SDK API surface plan** (Q16). The next
  initiative replaces MockPersonServer's hand wiring:
  - `AddAAuthPersonServer(...)` builder, named options, `IAAuthServerIdentity`;
  - the extensibility ladder (R0);
  - `Interaction.Source`;
  - `IAAuthAgentFactory`.

  To keep that rebase mechanical:
  - Register every new sample service (`PersonConsentDecisions`,
    `ConsentRegistry`) through DI, resolved by interface or type, never
    `new`ed inline in endpoint lambdas.
  - Read the PS issuer and URLs from the one existing configuration value.
    Add no new `psIssuer`/`$"{psIssuer}/..."` restatements beyond what an
    endpoint strictly needs.
  - The agent-side prompt takes the SDK `Interaction` record (not a URL
    string) plus the PS URL, so a later `Source` discriminator slots in.
  - New code adds no per-request `AAuthClientBuilder(...).Build()`, no
    `new RevocationClient(`, and no manual seam `AddSingleton` beyond the
    services above.
  - Add no public SDK types. The no-SDK-change rule (Q4, Q6) still
    applies.

## Verification strategy

| Layer | Command |
|---|---|
| Build (solution, gate) | `dotnet build AAuth.slnx -c Release -v q -nologo 2>&1 \| grep -E ' error \|warn'` (expect nothing) |
| Unit + integration | `dotnet test tests/AAuth.Tests -c Release --no-build` (plus Conformance, R3, Events at phase end) |
| PS integration | `dotnet test tests/AAuth.Tests --filter "FullyQualifiedName~MockPersonServer"` |
| Browser E2E | `cd tests/e2e && npx playwright test <spec>` (the stack boots via `webServer`); full suite with `--retries=0` at phase end |

> **Update (2026-09):** the solution build is green (Q3 superseded). The full
> build is the gate for every phase.

## Phase 0 — Decision gate and baseline

- Record rulings Q1–Q15 in the log. Q1–Q2 were ruled by the owner; the rest are
  defaults.
- Record the build baseline: which of the touched projects compile.

**Definition of Done**

- [x] Every open question (Q1–Q15) has a ruling in `implementation-log.md`.
- [x] Owner has reviewed the default rulings Q3–Q15 (accepted 2026-09-29; Q3
      superseded by the green build).
- [x] MockPersonServer, SampleApp and GuidedTour compile on the branch (Q3 gate).
      The full solution is green at `1045186` (2026-09-29).
- [x] Research line citations re-derived after `e2154a1` (research.md
      §Baseline update).

## Phase 1 — PS decision service and consent registry (no UI)

Refactor MockPersonServer so every PS consent request is tracked and every
decision flows through one service. There is no user-visible change.

**Files**

- `samples/MockPersonServer/PersonConsentDecisions.cs` (new).
  - `ApproveAsync(id)` and `DenyAsync(id)` for both SDK entries
    (`PersonPendingEntry`) and `MissionPendingEntry`.
  - Moves the bodies of `/interaction/approve` and `/interaction/deny`: the
    standing-consent grant, the asserter re-run, identity fields,
    `FederationConsent`, and `Status`/`Decision`.
  - Takes the entry lifecycle gate, then checks status, expiry and delivered
    state. Returns a typed outcome (`Applied`, `AlreadyDecided`, `Expired`,
    `Unknown`, `NotDecidable`).
- `samples/MockPersonServer/ConsentRegistry.cs` (new). An in-memory, capped
  (500) list of `ConsentRecord`:
  - `Id`, `Kind` (Token / MissionToken / MissionCreation / Permission /
    FederatedConsent / AccessServerInteraction), `AgentId`, `MissionS256`,
    mission description, `Resource`, `Scope`, `Account`, `CreatedAt`.
  - `Code()`, so the current code resolves on demand.
  - A derived `Status` (Pending / Approved / Denied / Expired / Withdrawn /
    Delivered), plus `DecidedAt` and `DecidedBy` (Dashboard / Link / Admin /
    Script).
- [ConsentBridgePersonPendingStore.cs](../../../samples/MockPersonServer/ConsentBridgePersonPendingStore.cs):
  on `Add`, register the entry with the registry.
- [MissionGovernance.cs](../../../samples/MockPersonServer/MissionGovernance.cs):
  on `MissionPendingStore.Add`, register the entry. Scripted resolutions record
  `DecidedBy = Script` (Q10).
- [Program.cs](../../../samples/MockPersonServer/Program.cs):
  - `/interaction/approve` and `/interaction/deny` call `PersonConsentDecisions`
    inside `BrowserConsentDecision.ApplyAsync`.
  - `/admin/consent` records `DecidedBy = Admin` when it resolves a parked entry.
  - `/admin/reset` also clears the registry.

**Tests** (`tests/AAuth.Tests/Integration/MockPersonServerTests.cs` or a new
`MockPersonServerConsentRegistryTests.cs`)

- The existing deferred, approve, deny and account-consent tests pass unchanged.
- A parked three-party request appears in the registry as `Pending`, then
  `Approved (Link)` after `/interaction/approve`, then `Delivered` after the
  poll returns 200.
- A mission-creation or permission park (interactive script) appears with its
  mission s256.
- `/admin/reset` empties the registry.

**Definition of Done**

- [x] `PersonConsentDecisions` owns every PS consent mutation. `/interaction/*`
      contain no mutation logic.
- [x] The registry records every PS-parked request with a derived status.
- [x] Existing MockPersonServer integration tests are green. The new registry
      tests are green.

## Phase 2 — PS dashboard

**Endpoints (MockPersonServer, under the unsigned `/dashboard` prefix)**

| Route | Purpose |
|---|---|
| `GET /dashboard` | Sign-in page if needed (isolated demo identity, loopback guard, Q5), then the dashboard HTML shell |
| `POST /dashboard/sign-in` | CSRF-protected demo sign-in. Sets the dashboard session cookie. |
| `GET /dashboard/requests?group=mission\|agent` | JSON: pending and history records, grouped. Requires the session. |
| `POST /dashboard/requests/{id}/approve` | Session + CSRF. `PersonConsentDecisions.ApproveAsync`, then consume the code (Q6). |
| `POST /dashboard/requests/{id}/deny` | Session + CSRF. `DenyAsync`, then consume the code. |

**Behaviour**

- The dashboard shell polls `/dashboard/requests` every ~1 s (Q7).
- It shows a **Pending** section on top and a **History** section below, with a
  group-by toggle for Mission, Agent, or none.
- Each record shows the full request context — agent, resource, scope, account,
  and the mission description and s256 — as the misdirection defence (v11
  L2854).
- Mission groups link to `/admin/mission-log/{s256}`.
- `?code=` highlights the matching pending record without consuming the code
  (Q12).
- Access Server interactions are read-only with a "complete at the Access
  Server" link (Q9).
- Races: a dashboard decision and a link decision on the same entry resolve
  exactly once, because both take the lifecycle gate. The loser gets
  `invalid_code` or "already decided".
- Add `/dashboard` to `UnsignedPathPrefixes`.

**Tests (integration, in-process)**

- Unauthenticated `GET /dashboard/requests` returns `401`. A missing or wrong
  CSRF token on approve returns `403`.
- A three-party request is approved on the dashboard, and the agent's poll
  returns `200 auth_token`. A later `/interaction?code=<old>` returns
  `invalid_code`.
- Dashboard deny makes the agent's poll return `403 denied`.
- Mission creation and tool permission (interactive script) approved on the
  dashboard resolve their `/mission-create-pending` and `/permission-pending`
  polls.
- Grouping JSON groups records by mission s256 and by agent id.
- Race: a link decision and a dashboard decision are applied once only.

**E2E helpers** ([`tests/e2e/helpers`](../../../tests/e2e/helpers))

- `dashboard.ts`: `openDashboard(context)` (signs in once per context),
  `approveOnDashboard(context, match)`, `denyOnDashboard(context, match)`.
  `match` selects by agent, resource, scope or mission.

**Definition of Done**

- [x] Dashboard endpoints are implemented, authenticated and CSRF-protected.
- [x] A dashboard decision resolves the agent's poll and consumes the code.
- [x] Pending and history lists with mission/agent grouping and deep-link
      highlight.
- [x] Integration tests above are green. E2E dashboard helpers exist.
- [x] If Q6 `Renew()` shows side effects, a deviation is logged and resolved.

## Phase 3 — Agent-side prompt: SampleApp and shared walkthroughs

**Files**

- `samples/ConsentSupport/` (new Razor library, Q11). Add it to
  [AAuth.slnx](../../../AAuth.slnx) and reference it from EventSupport,
  CapabilitySupport, SampleApp and GuidedTour.
  - `PersonServerConsent`: `DashboardUrl(personServer, code?)` and
    `IsPersonServerHosted(personServer, interactionUrl)`.
  - `PersonServerApprovalPrompt.razor`: primary "Open Person Server dashboard"
    button, a secondary "or open this request directly" link, a waiting spinner
    and a poll count. Parameters: `PersonServer`, `Interaction`, `PollCount`.
    Falls back to the direct link as primary when the interaction is not
    PS-hosted.
- SampleApp pages: replace the inline consent `<a>` with
  `PersonServerApprovalPrompt` in Deferred, CallChain (both hops), Mission,
  MissionCallChain, Bookings (PS branch), Federated (PS branch) and SubAgent (PS
  rounds). Store the `Interaction`, not just the built URL.
- [ConsentProgress.razor](../../../samples/SampleApp/Components/ConsentProgress.razor):
  describe the dashboard flow, with the per-code flow as the alternative.
- CapabilitySupport (Catalog, Document, Wallet walkthroughs) and EventSupport
  (EventWalkthrough): use the same component for the PS consent link.
- In-page code snippets that show `OnInteractionRequired`: add the dashboard
  line.

**Tests (E2E)**

- Migrate the SampleApp PS-consent specs to `approveOnDashboard`/
  `denyOnDashboard`: deferred, call-chain, call-chain-deferred, mission,
  mission-call-chain, bookings (PS path), federated(-deferred) (PS step),
  sub-agent (PS rounds), catalog, documents (PS step), events, wallet-protocol.
- Keep `deferred.spec.ts` covering the secondary direct link. Add one spec
  asserting the old link shows `invalid_code` after a dashboard approval.
- Assert the dashboard button is visible only at the waiting step, and that
  polling is already running before any click.

**Definition of Done**

- [x] `ConsentSupport` builds and is referenced by the four projects.
- [x] Every PS-hosted consent surface in SampleApp and the shared walkthroughs
      uses the prompt component. AS- and resource-hosted surfaces are unchanged.
- [x] Migrated SampleApp E2E specs are green, plus direct-link and
      stale-link specs.

## Phase 4 — GuidedTour: poll on arrival, "Run all" continues

**Files**

- [TourSession.cs](../../../samples/GuidedTour/TourSession.cs):
  - On reaching the user-approval step, record a "Waiting for approval on the PS
    dashboard" step and start `StartPendingPollAsync` immediately. Do not wait
    for a click.
  - Replace `StepUserApprovesPlaceholder`'s throw with a wait on the in-flight
    poll for PS-hosted interactions.
  - Keep the click-driven path for AS- and resource-hosted tracks (Federated,
    RichRequests, ResourceManaged, SubAgent AS round).
  - Expose the `Interaction` and `PersonServerUrl` for the prompt.
- [Tour.razor](../../../samples/GuidedTour/Components/Pages/Tour.razor):
  - At the waiting step, render `PersonServerApprovalPrompt` for PS-hosted
    interactions. `MarkInteractionOpenedAsync` no longer starts polling.
  - In `RunAllAsync`, for a PS-hosted interaction, await the background poll and
    continue. Stop only for AS- or resource-hosted consent (existing messages).
- [CodeSnippets.cs](../../../samples/GuidedTour/CodeSnippets.cs) and the step
  narratives: teach "poll immediately; the person decides on the PS dashboard
  (or via the link)".
- [TourSession.Capabilities.cs](../../../samples/GuidedTour/TourSession.Capabilities.cs)
  covers the capability modes: Events, Wallet Protocol, Documents, Catalog.
  - When `CapAuthority` (L670-L684) classifies the waiting interaction as
    PS-hosted, apply the same poll-on-arrival, prompt, and "Run all"
    behaviour.
  - Resource-first Documents consent (`/interaction/resource`) and AS-hosted
    steps keep the click-driven path.

**Tests (E2E)**

- GuidedTour deferred, call-chain, mission, mission-call-chain and sub-agent
  (PS rounds), plus the PS-hosted steps of the capability modes (events,
  wallet protocol, documents PS step, catalog):
  - "Run all" reaches the waiting step without an error.
  - `approveOnDashboard` resolves it, and the tour completes.
- Assert polling is live (poll count increases) before any dashboard action.
- Federated, richrequests and resource-managed specs are unchanged and still
  green.

**Definition of Done**

- [x] Polling starts on arrival at the waiting step for PS-hosted interactions,
      including the capability modes.
- [x] "Run all" runs through PS-hosted consent without stopping.
- [x] GuidedTour E2E specs green, including the unchanged AS/resource specs.

## Phase 5 — CLIs and Makefile

- [MissionAgent](../../../samples/MissionAgent/Program.cs): open the dashboard
  once in interactive mode. For each prompt, print the dashboard URL and the
  direct link (Q14).
- [AgentConsole](../../../samples/AgentConsole/Program.cs): print both URLs.
- [Makefile](../../../Makefile) `demo*` banners: list `PS dashboard:
  $(PS_URL)/dashboard`.

**Definition of Done**

- [x] Both CLIs print the dashboard URL. MissionAgent opens it once.
- [x] `MissionAgentFlowTests` is green. Banners are updated.

## Phase 6 — Samples, snippets and docs sweep

Run after the code surface is frozen.

- [MockPersonServer README](../../../samples/MockPersonServer/README.md): a
  dashboard section covering endpoints, sign-in, code consumption, grouping and
  history.
- [samples/README.md](../../../samples/README.md), the SampleApp and GuidedTour
  READMEs, [AgentConsole README](../../../samples/AgentConsole/README.md) and
  the MissionAgent README.
- `docs/workflows/ps-asserted-access.md` and `docs/server/mission-governance.md`:
  a note on out-of-band completion (v11 L1011) and the sample dashboard.
- Grep for stale strings: "Open consent page", "Open Person Server consent
  page", "click the green link", "Open mission approval page".
- `tests/e2e/README.md`: document the dashboard helpers.

**Definition of Done**

- [ ] No stale consent-button copy remains in README files, snippets or
      in-page code.
- [ ] Docs cite the spec sections by anchor and line.

## Phase 7 — Independent internal review

A fresh `code-review` subagent validates the diff against
[research.md](research.md), this plan and the cited spec lines. Focus areas:

- approver authentication and CSRF;
- code consumption and single-use;
- decision races;
- no drift from the link path;
- Access Server and resource consent untouched.

Findings are severity-graded and recorded in the log. The review also checks
the forward-compatibility rules in Guiding principles (Q16), and records
for the SDK API surface plan:

- every new hand-wired seam or restated PS identity;
- where it will fold into `AddAAuthPersonServer`.

**Definition of Done**

- [ ] Review completed. Every High or Medium finding is fixed or logged as a
      ruling.
- [ ] Final build and test status recorded in the log.

## Out of scope

| Item | Reason |
|---|---|
| `requirement=approval` (no link) mode | Optional hardening (v11 L2854). Needs an SDK mapper option (Q4). |
| Deciding Access Server / R3 consent on the PS dashboard | Only the host of `url` can complete out-of-band (v11 L1011). |
| Resource-hosted consent (Inbox, Documents) | Not PS consent. |
| Multi-user dashboard and agent-to-person mapping | The sample has one demo person. |
| Real authentication (passkey, OIDC) and persistence | Deployment concern. Demo sign-in only. |
| Push, email or other notifications | Not needed for the dashboard channel. |
| ~~Fixing draft-11 compile errors~~ | Resolved: the draft-11 migration closed (`ecc71e7`), and the build is green. |
| SDK API surface refactor (PS role builder, trust/callback seams, async signing) | Owned by 2026-09-29-sdk-api-surface-consistency, which runs after this plan. |
