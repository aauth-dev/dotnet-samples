# Call-Chain Interaction Chaining (multi-actor + human approval) — Research

ms.date: 2026-06-01

Research-only document. No task lists here (see `implementation-plan.md`).

## Goal

Make the interactive **call-chain** demo (SampleApp → Orchestrator → WhoAmI)
demonstrate the spec's **Interaction Chaining** behaviour end-to-end: when a hop
requires human consent that is not yet granted, the requirement is surfaced to a
real user (browser) and propagates back up the chain — instead of the SDK
throwing because no interaction callback is wired. Spec compliance is the golden
rule; backward compatibility with the current auto-grant demo shortcut is waived.

This is the "option 2" chosen by the maintainer after the deferred-consent
regression analysis (see the companion `whoami-flow-isolation-scopes` plan's
final discussion): wire genuine interaction relay + interaction chaining rather
than papering over the 202 by pre-granting consent.

## Spec grounding

All references are to `aauth-spec/draft-hardt-oauth-aauth-protocol.md` unless noted.

| Design area | Spec section | Key requirement |
|---|---|---|
| Deferred responses | `## Deferred Responses {#deferred-responses}` | Any endpoint MAY return `202`; agents MUST handle `202` by switching to GET-polling the `Location`. `Location` (same origin), `Retry-After`, `Cache-Control: no-store` REQUIRED. |
| Interaction required | `### Interaction Required` | `202` + `AAuth-Requirement: requirement=interaction; url=...; code=...` + `Location`. Agent builds `{url}?code={code}`, directs the user (redirect / display / QR), then polls `Location`. Terminal: `200` ok, `403` denied, `408` timeout. |
| Interaction chaining | `## Interaction Chaining {#interaction-chaining}` | A resource **acting as agent** that receives a `202 requirement=interaction` and must propagate it **MUST** return its **own** `202` to its caller with its **own** `requirement=interaction`, its **own** interaction `code`, and its **own** `Location`. When the user completes interaction and the resource obtains the downstream auth token, it completes the original request and returns the result at its pending URL. |
| Call chaining routing | `## Call Chaining {#call-chaining}` | Resource-as-agent routes the downstream exchange by upstream token: mission → `mission.approver` PS; no mission + PS `iss` → that PS; no mission + AS `iss` → that AS. Downstream scope need not subset upstream. Resource MUST publish `/.well-known/aauth-agent.json`. |
| Upstream token verification | `## Upstream Token Verification {#upstream-token-verification}` | PS nests upstream `act` inside a new `act` for the intermediary, preserving the full delegation chain. |
| Interaction endpoint | `## Interaction Endpoint {#interaction-endpoint}` | The PS interaction endpoint lets an agent relay an interaction to the user; for `type=interaction`/`payment` the PS relays and returns a deferred (202). If the PS cannot reach the user and the agent lacks the `interaction` capability → `interaction_required`. |
| Capabilities | `## AAuth-Capabilities Request Header {#aauth-capabilities}` | Agents declare `interaction`/`clarification`/`payment`. SDK infers `interaction` automatically when an interaction callback is wired (see `ChallengeHandler.Capabilities`). |
| Terminal "can't reach user" | `### Interaction Required` error / `upcoming-changes-02.md` | Current draft: `interaction_required` (403). Upcoming-02 splits into `interaction_required` (202, non-terminal, "direct the user") vs `user_unreachable` (400, terminal). |

## Two distinct interaction points in this demo

The chain has **two** exchanges, and they hit the consent gate differently:

1. **Hop 1 — SampleApp agent ⇄ its PS (audience = Orchestrator, scope `orchestrate`).**
   The agent talks to the PS **directly**. A `202` here is plain
   **Interaction Required**, *not* chaining — the agent (SampleApp) has the user
   and relays them straight to the PS interaction URL. Fix surface: wire
   `onInteractionRequired` in `CallChain.razor`; stop pre-granting the wrong scope.

2. **Hop 2 — Orchestrator (acting as agent) ⇄ PS (audience = WhoAmI, scope `whoami`, with `upstream_token`).**
   The Orchestrator has **no user**. A `202` here MUST be **chained**: the
   Orchestrator returns its **own** `202 requirement=interaction` to SampleApp
   (its caller), with its own `Location` (a pending URL on the Orchestrator) and
   an interaction `code`. SampleApp polls the Orchestrator's pending URL and
   relays the user to the interaction URL. This is the genuine multi-actor
   human-approval case the maintainer asked about. Today the Orchestrator
   **auto-grants** hop-2 consent (`/admin/consent`) to dodge this entirely.

A complete demo should exercise **both**: hop-1 direct interaction and hop-2
interaction chaining.

## Current state (as-is)

### Samples
- `samples/SampleApp/Components/Pages/CallChain.razor` — `SendChainedRequest()`
  calls `GrantConsentAsync(orchestratorUrl)` (no scope ⇒ PS defaults `whoami`,
  but Orchestrator challenge demands `orchestrate`), builds a client with
  `.WithChallengeHandling()` and **no** `onInteractionRequired`, then
  `GetAsync(orchestratorUrl)`. With `RequireConsent=true` the hop-1 exchange
  202s and the SDK throws at `TokenExchangeClient` (no callback). `GrantConsentAsync`
  posts `{ agent, resource }` only (no `scope`), and never grants hop-2.
- `samples/Orchestrator/Program.cs` — `MapGet("/")` **auto-grants** hop-2 consent
  via `POST {ps}/admin/consent { agent=orchestratorAgentId, resource=WhoAmI }`,
  then builds `AAuthClientBuilder.SelfIssuing(...).WithCallChaining(ctx).Build()`
  (note: **no** `WithChallengeHandling`/interaction callback in the live code) and
  `GetAsync($"{downstream}/jwt")`. No pending store, no `/pending` endpoint, no
  re-emit of a `202`.
- `samples/MockPersonServer/Program.cs` — already implements the full deferred
  flow: `POST /token` 202s with `Location=/pending/{id}` + `AAuth-Requirement`
  interaction header + `Retry-After`/`Cache-Control`; `GET /pending/{id}` returns
  202 while unconsented, 200 `{auth_token}` once consented, 403 `access_denied`
  when denied; `GET /interaction?code=` renders a consent page;
  `/interaction/approve` + `/interaction/deny`; demo-only `/admin/consent`,
  `/admin/revoke`, `/admin/reset`. Consent is keyed by `(agent, resource, scope)`.

### GuidedTour (reference, NOT the target)
`samples/GuidedTour/TourSession.cs` call-chain mode **pre-grants both hops**
(`orchestrate` for hop-1 at `OrchestratorUrl`; Orchestrator self-grants hop-2),
so it never receives a 202. It is the working reference for the *scope plumbing*
but does **not** demonstrate deferred interaction for call chaining.

## SDK capability inventory (what already exists)

- `src/AAuth/Agent/InteractionHandler.cs` — `DelegatingHandler` that, on
  `202 requirement=interaction`, invokes `onInteractionRequired(userUrl, code, ct)`
  then **blocking-polls** `Location` to a terminal response; throws
  `AAuthInteractionDeniedException` if no callback is configured. Also handles
  `requirement=approval`.
- `src/AAuth/Agent/ChallengeHandler.cs` — on `401 requirement=auth-token`, runs the
  embedded exchange via `TokenExchangeClient.ExchangeAsync`, forwarding
  `OnInteractionRequired` (`Func<AAuthInteraction, CancellationToken, Task>`),
  `PollerOptions`, `UpstreamToken`, `Capabilities`, `Prompt`. Supports
  call-chaining routing via `CallChainingRouter.ResolveDownstreamServer`.
- `src/AAuth/Agent/TokenExchangeClient.cs` — on exchange `202`, if
  `OnInteractionRequired` set: extract interaction, invoke callback, resolve
  `Location`, then `DeferredPoller.PollAsync` (**blocking** until terminal). No
  callback ⇒ throws.
- `src/AAuth/HttpSig/AAuthClientBuilder.cs` — `WithCallChaining(HttpContext|string|Func)`,
  `WithChallengeHandling(...)` (wires `InteractionHandlingOptions.OnInteractionRequired`),
  `SelfIssuing(...)`.
- `src/AAuth/Server/UpstreamAuthTokenFeature.cs` + `AAuthVerificationMiddleware.cs` —
  set the upstream auth token feature so `WithCallChaining(ctx)` can route hop-2.
- `docs/advanced/interaction-chaining.md` — documents the intended intermediary
  pattern (callback writes a `202` to `ctx.Response` and returns; manual
  `CallChainingHandler` pattern). **See gap G1 — the documented pattern does not
  work against the current blocking-poll behaviour.**

## Gaps & open questions

- **G1 (RESOLVED 2026-06-01) — intermediary cannot return 202 without blocking.**
  The documented chaining pattern in `docs/advanced/interaction-chaining.md`
  writes a `202` to `ctx.Response` *inside* `OnInteractionRequired` and expects
  the outer `GetAsync` to stop there. But the exchange **continues to
  blocking-poll** `Location` after the callback returns and then resolves the auth
  token and completes the original request — which would (a) block the inbound
  request for the full human-approval duration and (b) attempt to write a second
  response after `202` already started.

  > **Update 2026-06-01 (verified control flow + recommendation):** Read the
  > exact handler composition and exchange flow. Findings:
  >
  > - The PS-exchange `202` is handled **inside**
  >   `TokenExchangeClient.ExchangeAsync` (`src/AAuth/Agent/TokenExchangeClient.cs`
  >   lines ~154-207), invoking `challengeOptions.OnInteractionRequired` — **not**
  >   the top-level `InteractionHandler`. `AAuthClientBuilder.BuildHandler`
  >   (lines ~478-516) gives the exchange its **own** `HttpClient(exchangeSigner)`
  >   with **no** `InteractionHandler` wrapping it, so the top-level interaction
  >   handler only sees `202`s on **resource** responses, never the PS exchange.
  > - `ExchangeAsync` wraps the callback in `try { … } finally { response.Dispose(); }`
  >   with **no `catch`**. `ChallengeHandler.SendAsync` does **not** catch around
  >   `_exchange.ExchangeAsync`. So an exception thrown by `OnInteractionRequired`
  >   propagates cleanly out of `GetAsync` (response disposed in the `finally`,
  >   no double-write, no blocking poll).
  >
  > **Recommended: Option A — abort-via-callback exception.** The Orchestrator
  > sets `OnInteractionRequired` to `throw new AAuthInteractionChainedException(interaction)`.
  > The exception unwinds the in-flight exchange before `DeferredPoller.PollAsync`
  > is reached, propagates through `ChallengeHandler` → `GetAsync`, and the
  > Orchestrator endpoint catches it, persists pending state, and re-emits its own
  > `202`. Rationale:
  >
  > - **Minimal SDK surface:** one new exception type. No change to the
  >   exchange/poll logic, the builder, or `ChallengeHandler`. Fits the existing
  >   exception taxonomy (no-callback, `AAuthInteractionDeniedException`,
  >   `AAuthInteractionTimeoutException` already throw).
  > - **Keeps the full stack automatic:** the 401 challenge, resource-token
  >   extraction, and call-chaining routing (`CallChainingRouter`) all still run —
  >   the Orchestrator keeps using `GetAsync($"{downstream}/jwt")`.
  > - **Resume by re-drive, not by stored `Location`:** on each inbound
  >   `GET /pending/{id}`, the Orchestrator **re-runs** the hop-2 chained call
  >   using the **stored upstream auth token** (`WithCallChaining(storedUpstreamToken)`).
  >   While unconsented the callback throws again → re-emit `202`; once the user
  >   has consented at the PS, the re-run's exchange returns `200` (no `202`, no
  >   callback) → Orchestrator calls WhoAmI → combined `200`. This is idempotent
  >   and mirrors how `MockPersonServer`'s `/pending` re-checks consent per poll,
  >   so the callback never receives (and the Orchestrator never needs) the
  >   downstream poll `Location`.
  >
  > **Option B (probe helper) rejected:** a non-blocking `TryExchangeAsync`
  > returning *token-or-interaction* would either bypass `ChallengeHandler`
  > (forcing the Orchestrator to re-implement the 401 challenge + call-chaining
  > routing) or require threading a "probe mode" through `ChallengeHandler` **and**
  > `TokenExchangeClient` that changes the return contract — far more invasive for
  > no behavioural gain over Option A.
  >
  > **SDK change required:** add `AAuthInteractionChainedException` (carrying the
  > `AAuthInteraction`) under `src/AAuth/Agent/`. That is the entire Phase 2 SDK
  > delta.

- **G2 — Orchestrator has no pending store / `/pending` endpoint / `/interaction` relay.**
  To chain, the Orchestrator needs: a pending store keyed by its own id; a signed
  `GET /pending/{id}` that returns `202` (re-emitting the interaction requirement)
  while downstream is unconsented and `200` (final combined result) once the
  downstream auth token resolves; and a way to drive downstream polling to
  completion (background task or poll-on-demand when SampleApp polls). Mirror
  `MockPersonServer`'s `/pending` semantics.

- **G3 (RESOLVED 2026-06-01) — interaction URL/code identity across hops.**
  Spec says the intermediary returns *its own* code and *its own* `Location`, but
  the **interaction `url`** the user visits is still the **downstream PS's**
  interaction page (only the PS can record the user's consent).

  > **Update 2026-06-01 (maintainer decision):** The demo re-emits the PS's
  > `url` **and** `code` unchanged (pass-through) and swaps **only** `Location`
  > for the Orchestrator's own pending URL. The spec's "its own interaction code"
  > permits a remapped code, but pass-through is the simplest spec-correct mapping
  > and lets the user reach the PS consent page directly. No code remapping table
  > on the Orchestrator.

- **G4 — SampleApp must poll the Orchestrator's 202 and relay the user.**
  SampleApp's top-level `GetAsync(orchestrator)` already flows through
  `InteractionHandler` (via `WithChallengeHandling`), so a `202 requirement=interaction`
  from the Orchestrator is handled the same as one from a PS: invoke
  `onInteractionRequired` (open `{url}?code={code}` for the user) then poll the
  Orchestrator's `Location`. So once hop-1 wiring exists, hop-2 chaining is
  consumed for free **provided** the SampleApp client is built with the callback.
  Verify the Blazor UI can surface the user URL (new tab / button) and resume.

  > **Update 2026-06-01 (implementation correction):** G4 above was **wrong** that
  > `WithChallengeHandling` alone routes the Orchestrator's `202` through
  > `InteractionHandler`. `ChallengeHandler` only acts on `401` challenges (it
  > early-returns on any non-`401`). The top-level `InteractionHandler` — which
  > handles a *resource* `202 requirement=interaction` (the Orchestrator's chained
  > 202) — is **only** inserted when `WithInteractionHandling(...)` is configured.
  > So the SampleApp client must wire **both**: `WithChallengeHandling` (hop-1 PS
  > exchange `202`, callback `Func<AAuthInteraction, ct, Task>`) **and**
  > `WithInteractionHandling` (hop-2 chained `202`, callback
  > `Func<string userUrl, string code, ct, Task>`). Both funnel to one shared
  > "surface interaction to user" handler in `CallChain.razor`. Validated by the
  > new `call-chain-deferred.spec.ts` driving two real consent popups to a final
  > nested-`act` `200`.

  > **Update 2026-06-01 (Phase 3 test layering):** The planned
  > `tests/AAuth.Conformance/**` interaction-chaining contract test (a 3-server
  > `WebApplicationFactory` harness) was **not** added — it would have been heavy
  > to stand up and largely duplicative of the end-to-end coverage. The
  > intermediary re-emit (`202` own `Location` + pass-through PS `url`/`code`),
  > the `/pending/{id}` re-drive to `200` on consent, and the `403` on denial are
  > all exercised by `call-chain-deferred.spec.ts` against the real 5-server
  > stack. Unit coverage for the SDK abort mechanism lives in
  > `tests/AAuth.Tests/Agent/InteractionChainingTests.cs` (3 tests).

- **G5 — capabilities declaration.**
  When SampleApp wires `onInteractionRequired`, `ChallengeHandler` infers the
  `interaction` capability automatically. Confirm the Orchestrator (as agent on
  hop-2) should NOT declare `interaction` (it has no user) so the PS knows to
  return a chainable interaction requirement rather than expecting the
  Orchestrator to relay — or confirm the demo PS ignores capabilities. Document
  the actual MockPersonServer behaviour (it currently 202s regardless).

- **G6 — demo orchestration / RequireConsent.**
  `make demo-sample` runs PS with `RequireConsent=true`. Decide how the demo
  starts each run: no pre-grant (forces the full interaction for both hops), or a
  toggle. The e2e `call-chain.spec.ts` currently pre-grants both hops; a new
  spec is needed for the deferred path (mirror `GuidedTour/playwright-tests/deferred.spec.ts`).

## Validation surfaces

- Unit: `tests/AAuth.Tests/**` (SDK behaviour for the chosen G1 mechanism).
- Conformance: `tests/AAuth.Conformance/**` (interaction-chaining contract).
- e2e: `samples/SampleApp/playwright-tests/call-chain.spec.ts` (existing, pre-grant
  happy path) + a new deferred/interaction-chaining spec. `make e2e` / `make demo-sample`.
