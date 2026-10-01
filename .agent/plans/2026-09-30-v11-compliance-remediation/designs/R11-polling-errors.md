# R11 — Deferred polling and error codes

Findings: SDK-11, SDK-12, SDK-13, A19-HIGH-003, A19-HIGH-004, A14-MED-004; samples S08-02, S08-03, S09-01, S05-002; docs D07-05. Spec: #deferred-auth-token L643-L664; #deferred-responses L2478-L2564; #error-response-format L2571-L2579; #token-endpoint-error-codes L2580-L2616; #polling-error-codes L2617-L2640. Files read: `src/AAuth/Agent/ChallengeHandler.cs`, `src/AAuth/Agent/DeferredPoller.cs`, `src/AAuth/Server/DeferredState.cs`, `src/AAuth/Server/HeldInvocations.cs`, `src/AAuth/Errors/PollingError.cs`, `src/AAuth/Errors/TokenError.cs`, `src/AAuth/Errors/AAuthTokenExchangeException.cs`, `src/AAuth/Server/AAuthProblemDetails.cs`, `src/AAuth/AAuthConstants.cs`, `src/AAuth/Access/AAuthAccessServerEndpoints.cs`, `src/AAuth/Person/AAuthPersonServerEndpoints.cs`, `src/AAuth/Server/ResourceManaged/AAuthInteractionEndpointExtensions.cs`, `src/AAuth/DependencyInjection/AAuthGovernanceApplicationBuilderExtensions.cs`, `samples/GuidedTour/TourSession.cs`, `samples/GuidedTour/TourSession.Capabilities.cs`, `samples/Concierge/Program.cs`, `samples/MockPersonServer/Program.cs`, `samples/MockPersonServer/README.md`, `samples/MockResourceServers/Inbox/Program.cs`, `samples/MockAccessServers/Federated/Program.cs`, `samples/MockResourceServers/Documents/Program.cs`, `docs/advanced/interaction-chaining.md`, `docs/workflows/deferred-consent.md`, `docs/reference/configuration.md`, relevant audit findings, API-surface consistency notes, and existing tests named below.

## Problem restated (verified)

- SDK-11 / A14-HIGH-001 is still present. The auth-token deferred path records a `pendingLocation` for `202 requirement=auth-token` (`ChallengeHandler.cs:198`, `:212-218`), obtains the auth token, then immediately builds `PollRequest` and calls `SendWithAdaptiveSigningAsync` (`:300-303`). It never feeds the initial response's `Retry-After` into the poll cadence, and a later `429` is returned as an ordinary terminal response by the top-of-loop non-`202`/non-`401` branch (`:201-204`). This violates #deferred-auth-token L654-L656 and #deferred-responses L2527-L2532.
- SDK-12 / A14-HIGH-002 is still present. `DeferredState` emits `unknown_pending`/404 for malformed missing IDs (`DeferredState.cs:10-13`) and emits `invalid_code` as 400 (`:36-40`), while #polling-error-codes L2622-L2629 registers no `unknown_*` code and requires `invalid_code` to be 410.
- SDK-13 / A14-HIGH-003 is still present. `HeldInvocations.PollAsync` returns `Expired()` when an unauthenticated or post-auth poll first observes `PendingExpiresAt <= now` (`HeldInvocations.cs:321`, `:329`, `:350`), and `Expired()` is hard-coded to `expired`/410 (`:363`). #deferred-responses L2553-L2558 makes 408 the first timeout state and reserves 410 for gone/no retry.
- A19-HIGH-003 is still present. Token paths emit unregistered token-endpoint codes: `untrusted_person_server` in AS token/pending authorization (`AAuthAccessServerEndpoints.cs:191`, `:197`, `:205`, `:261`, `:266`), `untrusted_access_server` in PS federation (`AAuthPersonServerEndpoints.cs:1191`, `:1196`), and `policy_error` for invalid policy outputs (`AAuthAccessServerEndpoints.cs:370`, `:399`, `:472`, `:621`, `:712`). #token-endpoint-error-codes L2583-L2603 has no trust or policy codes, and #error-response-format L2574 says `error` must be defined by the endpoint returning it.
- A19-HIGH-004 is still present. Polling paths emit `unknown_pending`/404 (`DeferredState.cs:13`; `HeldInvocations.cs:313`; `AAuthGovernanceApplicationBuilderExtensions.cs:351`, `:365`; `AAuthInteractionEndpointExtensions.cs:41`), `unknown_interaction`/404 (`AAuthPersonServerEndpoints.cs:616`, `:699`, `:791`), `request_withdrawn`/410 (`AAuthPersonServerEndpoints.cs:705`, `:871`), and `invalid_code`/400 in browser/resource interaction helpers (`BrowserConsentSessions.cs:108` et al.; `PersonResourceInteraction.cs:64`, `:78`, `:99`, `:111`). None fit the #polling-error-codes table L2622-L2629.
- A14-MED-004 is still present in the generic poller. `DeferredPollerOptions.MinPollInterval` defaults to 100 ms (`DeferredPoller.cs:37`) and `ComputeDelay` clamps `Retry-After: 0` to that floor (`:281`), despite #deferred-responses L2516-L2518 saying `0` means retry immediately.
- The sample/doc findings are still present. Guided Tour overrides the poller fallback to 500 ms (`TourSession.cs:2691`) and text says unknown/expired pending IDs would be 404 (`:2887`); capability polling clamps `Retry-After` to 5 s and hand-rolls a 500 ms clarification loop (`TourSession.Capabilities.cs:812`, `:860-872`); Concierge returns `status="interaction_required"` for pending and `unknown_pending`/404 for missing pending entries (`Program.cs:220-224`, `:310-317`); `docs/advanced/interaction-chaining.md:135` uses `unknown_pending`/404.

## Candidate fixes

| # | Approach | Pros | Cons | Spec fit | API-surface fit (C1–C13) |
|---|---|---|---|---|---|
| 1 | Patch only the flagged literals and add ad hoc sleeps in `ChallengeHandler`. | Small diff. | Leaves two poll state machines, future emitters can reintroduce unregistered strings, samples continue to teach custom loops. | Partial; fixes visible rows but not the invariant from #deferred-responses L2533-L2564. | Weak C6/C7/C8; SDK does not own mechanics. |
| 2 | Reuse public `DeferredPoller` in `ChallengeHandler` by constructing a nested `HttpClient`. | Shares delay/backoff behavior. | Hard to preserve `HttpRequestMessage.Options`, carrier holder, adaptive signing, diagnostics, and per-request overrides; risks double pipelines. | Good for cadence, risky for auth-token presentation. | Medium C2/C3; awkward layering. |
| 3 | Extract a single internal deferred-poll core behind `DeferredPoller`, add typed problem helpers for closed error tables, and make every server/sample path use them. | One state machine; fail-closed status/code mapping; keeps public poller API while letting `ChallengeHandler` supply its request factory/send delegate. | Requires touching several emitters and public enum cleanup. | Strong: directly implements #deferred-responses, #token-endpoint-error-codes, and #polling-error-codes. | Strong C1, C6, C7, C8, C10. |

## Recommendation

Use approach 3. Treat deferred polling as SDK mechanics, not per-call policy: `DeferredPoller` remains the public facade, but its loop moves to an internal core that accepts `(pendingUrl, initialRetryAfter/not-before, requestFactory, sendAsync)`. The public `DeferredPoller` supplies the existing signed-GET factory; `ChallengeHandler` supplies `PollRequest(source, location)` and `SendWithAdaptiveSigningAsync`, so auth-token deferred delivery respects the same `Retry-After`, `429 slow_down`, timeout, `Prefer`, and typed polling errors as every other deferred path.

Centralize error emission with closed-table helpers: `AAuthProblemDetails.Polling(PollingErrorCode, ...)` and `AAuthProblemDetails.TokenEndpoint(TokenErrorCode, ...)` (names illustrative). The helper owns the normative status for each code and refuses mismatches in tests. Use raw `Signature-Error` for Signature-Key authentication/trust failures because #error-responses L2567-L2569 says 401 machine-readable errors are headers, not token JSON bodies.

For unknown pending IDs, choose `410 invalid_code`, not `404 unknown_pending` and not a 404 without an AAuth body. The spec has no 404 polling code (#polling-error-codes L2622-L2629), while the state machine gives 410 as the terminal "gone / MUST NOT retry" bucket (#deferred-responses L2557). Reusing `invalid_code` is the closest registered terminal code for an unrecognized or already-consumed polling handle, and avoids pending-ID enumeration. Use `408 expired` exactly once for a recognized request timing out; later polls of the consumed/terminal handle return `410 invalid_code`.

Map invented token codes to registered outcomes:

- Untrusted or wrong-role `Signature-Key` caller at AS/PS endpoints: bodyless `401 Signature-Error`, default `issuer_mismatch` (open question below), because the signing identity is not acceptable for this endpoint role.
- PS rejecting a resource token whose `aud` is syntactically invalid or names an untrusted AS: `400 invalid_resource_token`; the resource token is not usable at this PS as presented.
- Local policy bugs such as protocol-owned projected claims or missing payment `Location`: `500 server_error`; policy service outages may remain `503` only if handled by an area that defines a registered retry shape.
- Pending withdrawal/cancel without explicit denial: `403 abandoned`; explicit deny remains `403 denied`; token dependency revocation remains `403 revoked`.

Adversarial closure: a malicious peer can still omit `Retry-After`, send `Retry-After: 0`, flood `429`, or poll another user's pending URL. The shared core falls back to the spec default 5 s when absent, honors zero immediately, accumulates linear +5 s backoff for 429, enforces `MaxTotalWait`, and maps mismatched handles to the same `410 invalid_code` as missing handles so no existence or owner signal leaks.

## Public API delta

- Yes. `DeferredPollerOptions.MinPollInterval` default changes from 100 ms to `TimeSpan.Zero`; the property remains for hosts that deliberately choose a local safety floor, but the SDK default must honor `Retry-After: 0`.
- Yes. Prune token-endpoint typed values to the registered #token-endpoint-error-codes table: remove `TokenErrorCode.InvalidAgentToken`, `ExpiredAgentToken`, and `MissionTerminated` from the token-endpoint enum/wire map. `AAuthTokenExchangeException.ErrorCode` already remains a string for unrecognized/extension peer responses, so inbound compatibility is fail-closed without treating unregistered values as SDK-emitted constants. If R09 needs typed mission endpoint errors, it should define a mission-specific type, not a token-endpoint value.
- No new public poller methods are required. The reusable poll core and problem helpers can be internal. `PollingErrorCode` already matches the registered table and should remain unchanged.
- ApiSurface impact: enum member removals plus default-value documentation changes; no overload shims (C1).

## Wire effect

- Auth-token deferred `202` handling waits according to the initial `Retry-After` before the first signed `GET` of `Location`; absent header uses 5 s; `Retry-After: 0` polls immediately.
- `429 {"error":"slow_down"}` during the auth-token deferred path is no longer terminal; the next poll waits current interval + 5 s, and repeated 429s add another 5 s each.
- `invalid_code` changes from 400 to 410 everywhere it is a polling error.
- First recognized pending timeout changes from `410 expired` to `408 expired`; subsequent polls of the same terminal/missing/consumed handle return `410 invalid_code`.
- `unknown_pending`, `unknown_interaction`, and `request_withdrawn` disappear from AAuth polling bodies. No AAuth endpoint emits 404 with an AAuth polling error body.
- `untrusted_person_server`, `untrusted_access_server`, and `policy_error` disappear from token endpoint bodies. Replacement wire outcomes are `401 Signature-Error`, `400 invalid_resource_token`, or `500 server_error` as described above.
- Pending success bodies stay `{"status":"pending"}` for waiting 202s, with `Location`, `Retry-After`, and `Cache-Control: no-store` preserved.

## Implementation sketch

1. Add internal status maps next to `PollingErrorCode` / `TokenErrorCode` or in `AAuthProblemDetails`: `PollingStatus(PollingErrorCode)` and `TokenEndpointStatus(TokenErrorCode)`. Require emitters to call these helpers rather than `Create("literal")`; tests should assert no `src/AAuth` emitter contains removed strings.
2. Refactor `DeferredPoller` without changing its public shape:
   - Set `MinPollInterval = TimeSpan.Zero` and reject negative intervals in option validation/constructor use.
   - Move `PollCoreAsync` to an internal method that accepts a request factory and send delegate. Preserve `OnPoll`, `StopWhenAccepted`, `PreferWaitSeconds`, `MaxTotalWait`, `DelayAsync`, and the existing `PollingErrorException` parse path.
   - Represent the first delay as a not-before instant or `RetryConditionHeaderValue` captured from the initial 202. Do not poll before it; if elapsed work already exceeded it, poll immediately.
3. Update `ChallengeHandler.HandleAuthChallengesAsync`:
   - On `202 requirement=auth-token`, validate and store same-origin pending `Location` as today, plus the response's `Retry-After` and receipt time.
   - After obtaining the auth token, call the shared poll core with `PollRequest(request, pendingLocation)` and `SendWithAdaptiveSigningAsync` instead of manually looping through `SendWithAdaptiveSigningAsync(retry)`.
   - Keep copying the updated `PresentedToken` option back to the original request so diagnostics and subsequent challenge verification remain intact.
4. Update `DeferredState`:
   - `Missing(id)` returns `410 invalid_code` for both malformed and syntactically plausible unknown handles.
   - `InvalidCode` returns `410 invalid_code`.
   - First expiry remains `408 expired` and marks delivered; delivered/cancelled/replayed state returns `410 invalid_code`, not `410 expired`.
5. Update `HeldInvocations` to use a serializable terminal marker in `IAAuthHeldInvocationStore` (C10). A first poll of a known unexecuted entry after `PendingExpiresAt` atomically records terminal expired and returns `408 expired`; later polls, wrong-key polls, consumed-by-other-token polls, or missing entries return `410 invalid_code`. Retained successful results keyed by auth-token `jti` remain unchanged.
6. Replace polling literals across server endpoints:
   - `unknown_pending` / `unknown_interaction` / wrong owner / malformed code: `PollingErrorCode.InvalidCode` (410).
   - `request_withdrawn` and browser cancel without apply: `PollingErrorCode.Abandoned` (403).
   - Explicit user denial: `PollingErrorCode.Denied` (403); dependency revocation: `PollingErrorCode.Revoked` (403); server exception: `PollingErrorCode.ServerError` (500).
7. Replace token endpoint literals:
   - AS caller trust failures in `AAuthAccessServerEndpoints.AuthorizePsCallerAsync` and initial token handling become bodyless `Signature-Error` 401.
   - PS AS-audience trust failures in `AAuthPersonServerEndpoints` become `invalid_resource_token` 400.
   - `policy_error` branches become `server_error` 500 and log the internal reason without exposing policy internals in a new protocol code.
8. Update samples to call SDK poll machinery:
   - `TourSession.RunPendingPollAsync` removes `DefaultPollInterval = 500ms` and `MinPollInterval = 0` overrides; it relies on the new defaults and keeps `OnPoll` only for UI capture.
   - `TourSession.Capabilities.cs` replaces both hand-coded `Task.Delay(500ms)` / clamp loops with the same `DeferredPoller`-based helper, using `StopWhenAccepted` to surface a new requirement.
   - `Concierge` sample uses `status="pending"` for its waiting body and the typed polling helpers for its pending endpoint.
9. Update docs and generated configuration/reference tables for the new `MinPollInterval` default and the removal of unregistered error codes.

## Tests

- `tests/AAuth.Tests/Agent/ChallengeHandlerTests.cs`: extend the existing `DeferredAuthToken_PollsPendingUrlWithoutResendingBody` fixture with `DeferredAuthToken_RespectsInitialRetryAfterAndSlowDown`. Negative control: initial 202 has `Retry-After: 30`, first pending GET returns `429 {"error":"slow_down"}`, second returns 200. Assert no pending GET occurs before the captured delay, 429 is not returned to the caller, and the request remains a signed GET without the original body.
- `tests/AAuth.Tests/Agent/DeferredPollerTests.cs`: add `RetryAfterZero_IsImmediateByDefault` with `DelayAsync` capturing `TimeSpan.Zero`; add option validation for negative `MinPollInterval`; keep `DefaultPollInterval_Is5Seconds`.
- `tests/AAuth.Conformance/Errors/PollingErrorTests.cs`: keep the all-codes table, add `UnknownPollingCodes_AreNotParsed`, and add status validation that `invalid_code` only succeeds at 410 and `expired` only at 408.
- `tests/AAuth.Tests/Server/DeferredStateTests.cs`: add `InvalidCode_Is410`, `MissingMalformedAndUnknown_Are410InvalidCode`, and `ExpiredFirstPollIs408ThenReplayIs410InvalidCode`.
- `tests/AAuth.Tests/Server/HeldInvocationsTests.cs` (new or extend `SingleUseGateTests` with a minimal endpoint host): negative control reproduces SDK-13 by expiring a held invocation before auth-token presentation; assert first poll is `408 expired`, second is `410 invalid_code`, and no operation executes.
- `tests/AAuth.Tests/Server/AAuthProblemDetailsTests.cs`: assert `Polling` and `TokenEndpoint` helpers produce only registered code/status pairs and reject mismatched overrides.
- `tests/AAuth.Tests/Agent/ChallengeHandlerTests.cs` / token exchange tests: remove `interaction_required`, `expired_agent_token`, and other unregistered values from "published token" expectations; add a fail-closed peer-unknown test at the `AAuthTokenExchangeException` string layer.
- `tests/AAuth.Conformance/Errors/TokenEndpointErrorTests.cs` (new or extend existing conformance errors): grep-backed test over SDK token emitters, or direct endpoint tests, proving `untrusted_*` and `policy_error` no longer appear and replacements are `Signature-Error`, `invalid_resource_token`, or `server_error`.
- `tests/e2e` / GuidedTour Playwright deferred and capability specs: assert the UI still progresses while using the shared poller; negative control uses a mocked `Retry-After: 30` / `429 slow_down` authority and verifies the tour does not clamp or abort.

## Samples and docs to update

- `samples/GuidedTour/TourSession.cs`: remove sub-second default polling override; fix denial narrative that says unknown/expired pending IDs are 404.
- `samples/GuidedTour/TourSession.Capabilities.cs`: replace hand-rolled polling and `Retry-After` clamping with the SDK poller; keep educational capture hooks.
- `samples/Concierge/Program.cs`: emit `status="pending"`; replace `unknown_pending`/404 with `invalid_code`/410.
- Additional sample grep hits that must be corrected for consistency: `samples/MockPersonServer/Program.cs`, `samples/MockPersonServer/README.md`, `samples/MockResourceServers/Inbox/Program.cs`, `samples/MockAccessServers/Federated/Program.cs`, `samples/MockResourceServers/Documents/Program.cs`. `samples/LiveWhoAmITest/Program.cs` and `samples/AgentConsole/Program.cs` may keep explicit non-zero `MinPollInterval` if documented as local demo throttling, but should not claim it is the SDK/spec default.
- `docs/advanced/interaction-chaining.md`: replace `unknown_pending`/404 sample with typed `invalid_code`/410 and body `status="pending"` while waiting.
- `docs/workflows/deferred-consent.md` and `docs/reference/configuration.md`: change `MinPollInterval` default from 100 ms to zero and state that `Retry-After: 0` is honored verbatim unless an app explicitly opts into a floor.
- `docs/advanced/error-handling.md`: remove unregistered token-endpoint enum members from token-error examples; keep mission errors in a separate mission section if R09 retains them.

## Dependencies and conflicts with other Rnn

- R15 owns broader agent-client behavior. Coordinate the `ChallengeHandler` refactor so its auth-token verification and interaction-relay fixes do not fork the poll state machine again.
- R03 / R12 may touch authorization/governance deferred endpoints that currently emit `unknown_pending`; use the same polling helper rather than area-local strings.
- R09 owns mission endpoint errors. If `mission_terminated` remains registered for mission/governance endpoints, keep it out of `TokenErrorCode` and document a separate typed mission error.
- R18 / R19 own broad sample/docs cleanup. The implementation should still update directly coupled sample/doc lines above to avoid shipping examples that reintroduce forbidden wire codes.
- A19-HIGH-001 (401 body vs `Signature-Error`) is adjacent: the replacement for untrusted Signature-Key callers should use whatever final helper that area creates for bodyless 401 errors.

## Open questions (with proposed default)

1. Exact `Signature-Error` value for a verified but untrusted `jwks_uri` PS caller: use `issuer_mismatch` by default because the endpoint rejects the issuer/role, not the cryptographic signature.
2. Unknown pending ID semantics: use `410 invalid_code` by default. A bare 404 would avoid an invented AAuth body but would fall outside #polling-error-codes and force every poller to special-case non-AAuth errors.
3. `TokenErrorCode` values kept for AAuth #199 / missions: remove them from the token-endpoint enum by default; if another area proves they are registered for a different endpoint, introduce endpoint-specific types there.
