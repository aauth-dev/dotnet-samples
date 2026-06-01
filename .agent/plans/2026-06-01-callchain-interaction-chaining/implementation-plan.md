# Call-Chain Interaction Chaining (multi-actor + human approval) — Implementation Plan

ms.date: 2026-06-01

Companion research: [research.md](research.md). Golden rule: **spec compliance**
(`aauth-spec/draft-hardt-oauth-aauth-protocol.md`, esp. `## Interaction Chaining`).
Backward compatibility with the auto-grant demo shortcut is waived (alpha).
Validate with the e2e suite as work proceeds. New findings → `research.md` with a
dated `> **Update**` callout. Design changes → ask maintainer.

## Scope summary

Demonstrate genuine **Interaction Chaining** in the interactive call-chain demo
(SampleApp → Orchestrator → WhoAmI) with `RequireConsent=true`:

- **Hop 1** (SampleApp ⇄ PS, scope `orchestrate`): plain Interaction Required —
  SampleApp relays the user to the PS consent page and resumes.
- **Hop 2** (Orchestrator ⇄ PS for WhoAmI, scope `whoami`): the Orchestrator
  (no user) re-emits its **own** `202 requirement=interaction` to SampleApp,
  exposes its own pending URL, and completes the original request once the
  downstream auth token resolves.

Out: changing real-PS behaviour; production-grade pending GC/persistence;
payment/clarification capabilities.

---

## Phase 1: Verify SDK control flow + lock the chaining mechanism (G1) ✅

Spec basis: `## Interaction Chaining` — intermediary MUST return its own `202`
without blocking on human approval.

Verified (read-only) and recorded in `research.md` G1 update:
- The PS-exchange `202` is handled **inside** `TokenExchangeClient.ExchangeAsync`
  via `challengeOptions.OnInteractionRequired`, **not** the top-level
  `InteractionHandler` (the exchange uses its own un-wrapped `HttpClient`).
- `ExchangeAsync` wraps the callback in `try { … } finally { Dispose() }` with **no
  `catch`**; `ChallengeHandler` does not catch around the exchange. A callback
  exception therefore propagates cleanly out of `GetAsync` **before** the blocking
  `DeferredPoller.PollAsync` runs.

### Implementation Decisions

- [x] **Mechanism: Option A (abort-via-callback exception).** The Orchestrator's
  `OnInteractionRequired` throws `AAuthInteractionChainedException(interaction)`;
  the endpoint catches it and re-emits its own `202`. Option B (probe helper)
  rejected as far more invasive (would bypass or rewrite `ChallengeHandler`).
- [x] **New SDK type:** `AAuthInteractionChainedException` (carries the
  `AAuthInteraction`) under `src/AAuth/Agent/`. This is the **only** SDK delta.
- [x] **Resume strategy: re-drive, not stored `Location`.** On each inbound
  `GET /pending/{id}` the Orchestrator re-runs the hop-2 chained call with the
  **stored upstream auth token** (`WithCallChaining(storedUpstreamToken)`).
  Idempotent; mirrors `MockPersonServer`'s per-poll consent re-check. The
  Orchestrator never needs the downstream poll `Location`.
- [x] **url/code mapping (G3):** pass through the PS `url`+`code`, swap only
  `Location`.

### Definition of Done

- [x] `research.md` updated with the verified control flow + chosen mechanism.
- [x] Implementation Decisions above completed and agreed with maintainer.

---

## Phase 2: SDK — `AAuthInteractionChainedException` (G1, Option A)

Files:
- `src/AAuth/Agent/AAuthInteractionChainedException.cs` (new) — exception carrying
  the `AAuthInteraction` (url + code), thrown by an intermediary's
  `OnInteractionRequired` to abort the in-flight exchange and surface the
  interaction to the endpoint for re-emission. Mirror the existing
  `AAuthInteractionDeniedException` / `AAuthInteractionTimeoutException` shape.
- No change to `TokenExchangeClient`, `ChallengeHandler`, `InteractionHandler`, or
  the builder — the existing `try/finally` (no `catch`) already propagates it.

Tests:
- `tests/AAuth.Tests/Agent/InteractionChainingTests.cs` — a callback that throws
  `AAuthInteractionChainedException` aborts the exchange **before** any poll
  (assert `DeferredPoller` is never invoked, e.g. via a one-shot 202 stub that
  would 200 only on a second call) and the exception (with its `AAuthInteraction`)
  surfaces out of the call. Regression: direct-interaction (callback returns
  normally) still blocking-polls; no-callback still throws the existing error.

### Definition of Done

- [x] `AAuthInteractionChainedException` added and XML-documented.
- [x] Throwing it from `OnInteractionRequired` aborts before polling and surfaces
  the interaction; direct-interaction and no-callback paths unchanged.
- [x] `dotnet build` clean; unit + conformance suites pass.

---

## Phase 3: Orchestrator — pending store, `/pending`, re-emit `202` (G2, G3)

Files:
- `samples/Orchestrator/Program.cs` — build the downstream client with
  `WithChallengeHandling(opts => opts.OnInteractionRequired = (i, ct) => throw new
  AAuthInteractionChainedException(i))` + `WithCallChaining(...)`. Wrap
  `GetAsync($"{downstream}/jwt")` in `try/catch (AAuthInteractionChainedException ex)`:
  on catch, persist a pending entry (id + the **upstream auth token** captured from
  the request + the PS interaction `url`/`code`) and write a `202` with
  `Location=/pending/{id}`, `Retry-After`, `Cache-Control: no-store`, and
  `AAuth-Requirement: requirement=interaction; url="{ps url}"; code="{code}"`
  (pass-through url+code). Remove the hop-2 auto-grant (`/admin/consent`).
- New `samples/Orchestrator/PendingStore.cs` (mirror `MockPersonServer`'s shape):
  signed `GET /pending/{id}` → **re-drive** the hop-2 chained call using the stored
  upstream token. If it throws `AAuthInteractionChainedException` again → `202`
  (re-emit the requirement). If it returns the downstream `200` → `200` (combined
  chain result). `403`/`404` for denied/unknown.

Tests:
- Validated via the Phase 5 e2e deferred spec (real 3-server flow) instead of a
  conformance contract test. A 3-server `WebApplicationFactory` harness was judged
  too heavy and duplicative of the e2e coverage; the layered choice is recorded in
  `research.md`.

### Definition of Done

- [x] Orchestrator re-emits its own `202 requirement=interaction` on hop-2 deferral
  (own `Location`, pass-through PS `url`/`code`).
- [x] `GET /pending/{id}` re-drives and returns `202`→`200` (consent) / `403` (deny).
- [x] Hop-2 auto-grant removed; chain result still shows full `act` delegation.
- [x] `/.well-known/aauth-agent.json` still published.

---

## Phase 4: SampleApp — wire interaction relay in `CallChain.razor` (G4, G6)

Files:
- `samples/SampleApp/Components/Pages/CallChain.razor` — build the client with
  `.WithChallengeHandling(opts => opts.OnInteractionRequired = ...)` so both the
  hop-1 PS `202` and the hop-2 Orchestrator `202` surface a user-facing URL.
  Render the `{url}?code={code}` as a button / new-tab link (and optionally QR);
  resume on poll. Remove the wrong-scope `GrantConsentAsync(orchestratorUrl)`
  pre-grant (or gate it behind an "autonomous" toggle). Extend `GrantConsentAsync`
  to accept an optional `scope` if any pre-grant remains.
- UI state to show pending / "waiting for your approval" and the final chain result.

### Definition of Done

- [x] Clicking "Send chained request" with no standing consent surfaces a consent
  URL (hop 1), and after approval surfaces the hop-2 chained consent URL, then the
  final `Agent → Orchestrator → WhoAmI` result.
- [x] No `onInteractionRequired`-missing exception path remains in the happy flow.
- [x] Pre-grant path still works: consent is controlled externally (tests/demo);
  the page no longer resets consent, so the pre-grant spec fast-paths to `200`
  (interaction callbacks wired via `WithChallengeHandling` + `WithInteractionHandling`
  but never fire when consent is already standing).

---

## Phase 5: e2e + docs

Files:
- `samples/SampleApp/playwright-tests/call-chain-deferred.spec.ts` (new) — mirror
  `GuidedTour/playwright-tests/deferred.spec.ts`: start with empty consent, drive
  the consent page for both hops, assert the final combined result. Keep the
  existing `call-chain.spec.ts` (pre-grant happy path) green.
- `docs/advanced/interaction-chaining.md` — update the SDK pattern to match the
  Phase 2 mechanism (replace the broken "write 202 inside callback then continue"
  example with the real abort/probe pattern).
- `docs/workflows/call-chaining.md` / `deferred-consent.md` — cross-link the new
  multi-actor human-approval walkthrough.

### Definition of Done

- [x] New deferred call-chain e2e spec passes; existing call-chain spec still passes.
- [x] `make e2e` green (no regressions in the broader suite — 22/22 passed).
- [x] `docs/advanced/interaction-chaining.md` example matches the new API
  (`AAuthInteractionChainedException` abort + endpoint re-emit; agent-side
  `WithInteractionHandling` for the chained `202`); call-chaining.md and
  deferred-consent.md cross-linked.

---

## Out of Scope

| Item | Reason |
|---|---|
| Production pending-entry persistence / TTL GC on the Orchestrator | Demo uses in-memory store like `MockPersonServer`. |
| `payment` / `clarification` capabilities | Only `interaction` is in scope. |
| Real-PS interaction relay (`/interaction` push to user) for the intermediary | Demo passes through the PS interaction URL; intermediary-via-own-PS relay deferred. |
| Changing GuidedTour call-chain to the deferred path | GuidedTour stays the pre-grant reference; SampleApp demonstrates deferral. |
| `user_unreachable` (upcoming-02) terminal handling | Current draft `interaction_required` semantics only. |
