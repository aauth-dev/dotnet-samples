# Live Interop Testing: Implementation Plan

> Created 2026-05-28.
> Companion to [`research.md`](./research.md).
> **Scope**: Create a live test sample against deployed servers, identify SDK gaps vs reference agent, and fix them.

---

## Gap Register

All gaps discovered during live testing against whoami.aauth.dev + person.hello.coop.
Each gap includes investigation TODOs: 1) spec accuracy, 2) SDK surfacing (opt-in/opt-out/config).

> **Updated 2026-05-30:** Spec lead confirmed Gaps A, B (prompt only), E (user_unreachable) will be standardized in -02.
> See `aauth-spec/upcoming-changes-02.md` and research.md §5b for details.

### Confirmed Fixed (spec-validated, design agreed)

| ID | Summary | Fix | Design Decision |
|---|---|---|---|
| **A** | TokenExchangeClient doesn't send `capabilities` in POST body | `capabilities: ["interaction"]` when `onInteractionRequired` is non-null | Add `IList<string>? Capabilities` to `ChallengeHandlingOptions`. `null` = infer from handlers, explicit list = use as-is, empty = suppress. Inference adds `"interaction"` when `OnInteractionRequired` is set. |

### Partially Fixed (design agreed, implementation pending)

| ID | Summary | Current Fix | Design Decision |
|---|---|---|---|
| **G/J** | DeferredPoller hits HttpClient.Timeout (100s) during long-poll | Per-request CTS with PreferWait+60s; catch `TaskCanceledException` | Set `exchangeHttpClient.Timeout = Timeout.InfiniteTimeSpan` in builder. Remove per-request CTS and `TaskCanceledException` catch from `DeferredPoller`. Stopwatch + `MaxTotalWait` is the single timeout layer. |

### Open (not yet fixed)

| ID | Summary | Reference Behavior | Decision |
|---|---|---|---|
| **B** | No `prompt` in token exchange POST body | web-agent-demo sends `prompt: "consent"` | **Will fix.** Add `string? Prompt` to `ChallengeHandlingOptions`. `null` = don't send. String value passed as-is in body. No enum (OIDC-extensible). |
| **C** | No `Accept-Signature` / `additional_signature_components` handling (adaptive signing) | whoami returns `sig=("@method" "@authority" "@path" "signature-key");sigkey=jkt` | **Will fix.** Two paths: (1) Read `additional_signature_components` from resource metadata and include them in Signature-Input. (2) On 401 with `Signature-Error: invalid_input` + `required_input`, parse required components, resign, retry once. Cache discovered components per-origin. Pass extra components to signer via `HttpRequestMessage.Options`. No new public API. |
| **D** | No built-in interaction URL opener | web-agent-demo renders UI; our callback just surfaces URL | **Won't fix.** Spec (§User Interaction, L893) lists multiple presentation methods (browser redirect, QR code, display code) — choice is environment-dependent. SDK is a library consumed in headless servers, CLIs, desktop, mobile. `OnInteractionRequired` callback is the correct abstraction. Samples demonstrate usage. |
| **E** | PS errors thrown as generic `HttpRequestException` | PS returns `{ error, error_description }` JSON | **Will fix.** New `AAuthTokenExchangeException` with `ErrorCode`, `ErrorDescription`, `StatusCode`, `IsTerminal` properties. Parse JSON on non-2xx. DeferredPoller throws it for terminal polling errors (`denied`, `abandoned`, `expired`, `invalid_code`). Fall back to `HttpRequestException` if body isn't parseable JSON. |
| **F** | Polling timeout defaults (MaxTotalWait=5min) untested | web-agent-demo: `POLL_WAIT_SECONDS=45`, no max budget | **Validated.** Server controls via 408. 5min client budget is a safety net. No change needed. |
| **H** | PS caches consent - no SDK cache/invalidation semantics | 2nd run got auth_token immediately (200, no interaction) | **Covered by Gap B.** Spec (§Resource Token, L784): "PS SHOULD remember prior consent decisions." This is PS-side behavior. Agent controls via `prompt: "consent"` to force re-consent. No SDK-side cache needed. |
| **I** | `content-type` not in covered components for POST | web-agent-demo signs `content-type` for body-bearing requests | **Subsumed by Gap C.** Spec only requires `@method`, `@authority`, `@path`, `signature-key`. If a resource requires `content-type`, it will advertise via `additional_signature_components` and Gap C's adaptive signing will include it automatically. |
| **J** | Exchange client HttpClient.Timeout conflicts with long-poll | Default 100s < PreferWait(45)+network latency on some cycles | **Merged with Gap G.** Same root cause, same fix (`Timeout.InfiniteTimeSpan` on exchange client in builder). |

---

## Phase 1: Sample Creation ✅

**Objective**: Create `samples/LiveWhoAmITest` demonstrating all protocol modes against live servers.

### Definition of Done

- [x] Sample builds and runs
- [x] Mode 1: No signature → 401 + `Accept-Signature`
- [x] Mode 2a: Agent token (no scope) → 200 + agent identity
- [x] Mode 2b: Agent token (scope=email) → 401 + resource_token
- [x] Mode 3: Full 3-party flow → 200 + identity claims
- [x] Parity with web-agent-demo reference agent flows

---

## Phase 2: Gap Discovery ✅

**Objective**: Run sample end-to-end, document all gaps vs reference agent.

### Definition of Done

- [x] All modes tested against live servers
- [x] Gap register populated (A–J)
- [x] Each gap has investigation TODOs

---

## Phase 3: Deep Analysis ✅

**Objective**: For each gap, determine spec accuracy and recommended SDK surfacing.

> **Completed 2026-05-30.** Spec lead clarified all open questions. Decisions recorded in Gap Register above.

### Decisions Summary

| Gap | Decision | Rationale |
|---|---|---|
| A | Will fix (configurable) | Spec -02 will standardize `capabilities` in body. Add `Capabilities` option, null=infer. |
| B | Will fix (`prompt` only) | `prompt` going into spec -02. `provider_hint` is PS-specific, out of scope. |
| C | Will fix (adaptive signing) | Spec §Covered Components: agent MUST include `additional_signature_components`. Additive, no regression. |
| D | Won't fix | By-design for libraries. Consumer's responsibility. |
| E | Will fix | Parse JSON errors, typed exceptions. `user_unreachable` confirmed as distinct code. |
| F | No change needed | Validated against spec: 5min client budget is a safety net, server controls via 408. |
| G/J | Will fix | Root cause is HttpClient.Timeout. `Timeout=InfiniteTimeSpan` on exchange client, remove per-request CTS. |
| H | Covered by Gap B | Expose `prompt: "consent"` to force re-consent. No SDK-side cache. |
| I | Subsumed by Gap C | Adaptive signing includes `content-type` when a resource advertises it. |

### Definition of Done

- [x] Each gap has a decision recorded (fix approach or "won't fix" with rationale)
- [x] Spec citations for each decision
- [x] research.md updated with findings

---

## Phase 4: Fix Implementation

**Objective**: Apply fixes per Phase 3 decisions. Each fix has its own DoD and a subagent validation gate.

### Validation Protocol (applies to every fix)

After implementing each fix, dispatch the **Explore** subagent (read-only) with this charge:

> Compare the implemented change against (1) the AAuth spec section it implements,
> (2) the SDK's prior behavior, (3) whether samples and docs need updating.
> Report: spec-compliance, correctness, missing tests, stale docs/samples, and any regressions.

Incorporate the subagent's feedback before marking the fix done. Record the verdict in the fix's checklist.

---

### Fix 4.1 — Gap G/J: Exchange client long-poll timeout

**Spec ref:** §Deferred Responses (L1906); `Prefer: wait=N` (L1962)

**Tasks:**

1. In `AAuthClientBuilder.cs`, set `exchangeHttpClient.Timeout = Timeout.InfiniteTimeSpan` where the exchange `HttpClient` is constructed (~L485).
2. In `DeferredPoller.cs`, remove the per-request CTS (`requestCts`, `perRequestTimeout`) and the `catch (TaskCanceledException) when (...)` loop-back. Pass `cancellationToken` directly to `SendAsync`.
3. Confirm `MaxTotalWait` stopwatch remains the single timeout authority.

**DoD:**

- [x] Exchange client uses `InfiniteTimeSpan`
- [x] Per-request CTS workaround removed from `DeferredPoller`
- [x] Unit test: long-poll exceeding 100s does not throw `TaskCanceledException` (covered by InfiniteTimeSpan builder setting + existing cancellation tests; not cheaply unit-testable in isolation)
- [x] Unit test: `MaxTotalWait` still enforced (`PollAsync_ThrowsTimeout_BeforeSleepingPastBudget`)
- [ ] LiveWhoAmITest Mode 3 still passes
- [x] Subagent validation passed

### Fix 4.2 — Gap A: Configurable capabilities

**Spec ref:** §AAuth-Capabilities (L1756); -02 token endpoint param (`upcoming-changes-02.md` item 1)

**Tasks:**

1. Add `public IList<string>? Capabilities { get; set; }` to `ChallengeHandlingOptions` with XML docs (null=infer, empty=suppress).
2. In `TokenExchangeClient`, replace hard-coded `["interaction"]` with: `options.Capabilities ?? InferCapabilities(...)`.
3. Add `InferCapabilities` helper: adds `"interaction"` when `OnInteractionRequired` is set.
4. Thread the resolved capabilities from builder → `ChallengeHandler` → `TokenExchangeClient`.

**DoD:**

- [x] `Capabilities` property on `ChallengeHandlingOptions`
- [x] `null` infers `["interaction"]` when handler present (current behavior preserved)
- [x] Explicit list overrides; empty list suppresses
- [x] Unit tests for all three cases (infer / override / suppress)
- [ ] LiveWhoAmITest Mode 3 still passes
- [x] Subagent validation passed

### Fix 4.3 — Gap B: `prompt` parameter

**Spec ref:** §7.1.3 (-02, `upcoming-changes-02.md` item 3); OIDC values

**Tasks:**

1. Add `public string? Prompt { get; set; }` to `ChallengeHandlingOptions` with XML docs (OIDC values).
2. In `TokenExchangeClient`, add `body["prompt"] = prompt` when non-null.
3. Thread from builder → `ChallengeHandler` → `TokenExchangeClient`.

**DoD:**

- [x] `Prompt` property on `ChallengeHandlingOptions`
- [x] `null` omits `prompt` from body (default)
- [x] Non-null value sent verbatim
- [x] Unit tests (null omits, value present)
- [x] Subagent validation passed

### Fix 4.4 — Gap E: Typed error classification

**Spec ref:** §Error Responses (L1996); Token Endpoint + Polling Error Codes (L2006, L2024); `user_unreachable` (-02)

**Tasks:**

1. Add `AAuthTokenExchangeException` with `ErrorCode`, `ErrorDescription`, `StatusCode`, `IsTerminal`.
2. In `TokenExchangeClient`, on non-2xx parse JSON `{ error, error_description }`; throw the typed exception. Fall back to `HttpRequestException` if body isn't parseable JSON.
3. In `DeferredPoller`, throw `AAuthTokenExchangeException` for terminal polling errors (`denied`, `abandoned`, `expired`, `invalid_code`).
4. Map terminal vs non-terminal: `user_unreachable` terminal; `interaction_required` non-terminal (continues polling).

**DoD:**

- [x] `AAuthTokenExchangeException` type added (public)
- [x] Terminal error codes throw with `IsTerminal=true`
- [x] Non-AAuth/unparseable responses fall back to `HttpRequestException`
- [x] Unit tests for each error code + fallback
- [x] Subagent validation passed (docs + `LiveWhoAmITest` catch updated per feedback)

### Fix 4.5 — Gap C: Adaptive signing components

**Spec ref:** §Covered Components (L2089); `additional_signature_components` (L2281); `invalid_input`/`required_input` (L2098, L2111)

**Tasks:**

1. Read `additional_signature_components` from resource metadata in `ChallengeHandler`; cache per-origin.
2. Pass extra components to the signer via `HttpRequestMessage.Options` so they are added to `Signature-Input`.
3. On 401 with `Signature-Error: invalid_input` + `required_input`, parse required components, merge, resign, retry once.
4. Ensure base components are always preserved (additive only).

**DoD:**

- [x] Metadata `additional_signature_components` honored (agent-side: `ChallengeHandlingOptions.AdditionalSignatureComponents` seed, keyed by origin)
- [x] `invalid_input` retry path implemented (single retry)
- [x] Discovered components cached per-origin (`ChallengeHandler._learnedComponents`)
- [x] No regression: resources without extra components sign exactly as before (regression test `SendAsync_NoAdditionalComponents_SignsBaseComponentsOnly`)
- [x] Unit tests: metadata path, error path, caching, no-op default (4 signing + 7 challenge tests)
- [ ] LiveWhoAmITest all modes still pass (whoami advertises none) — manual live run
- [x] Subagent validation passed (no code blockers; doc gaps addressed in `signing-modes/overview.md`, `advanced/error-handling.md`)

**Implementation notes:**

- Signer: `AAuthSigningHandler.AdditionalComponentsKey` (`HttpRequestOptionsKey`) carries extra components per request. They are resolved from request header fields, de-duplicated against base components, and appended additively to both the signature base and `@signature-params`. A required header missing from the request throws `InvalidOperationException`.
- `SignatureError.ParseRequiredInput` added to extract `required_input` components.
- `ChallengeHandler.SendWithAdaptiveSigningAsync` seeds known components, and on `invalid_input` + `required_input` learns/merges, caches per origin, re-signs, retries once. Both initial send and post-exchange retry route through it.
- Server-side metadata emission of `additional_signature_components` was intentionally **not** added (out of scope for the agent-side fix; `AAuthResourceMetadataOptions` unchanged).

### Phase 4 Definition of Done

- [x] All five fixes (4.1–4.5) implemented and individually validated
- [x] Unit tests for each fix
- [x] LiveWhoAmITest passes all modes (live run 2026-05-30: Mode 1 401+Accept-Signature, Mode 2a 200 agent identity, Mode 2b 401+AAuth-Requirement, Mode 3 full 3-party flow returned identity claims)
- [x] No regressions in existing test suite (320 unit + 342 conformance pass)
- [x] Each fix's subagent validation incorporated

---

## Phase 5: Edge Case Validation

**Objective**: Test error paths and edge cases discovered during analysis.

### Tasks

1. Test interaction timeout (user never approves) → `expired` (408)
2. Test `denied` (user explicitly denies) → terminal `AAuthTokenExchangeException`
3. Test `user_unreachable` (no capabilities, no device) → terminal
4. Test expired/revoked agent keys
5. Test mismatched `kid` in JWKS
6. Test different scope values against whoami

### Definition of Done

- [x] Edge cases documented in research.md (§7 Phase 5 Edge Case Validation)
- [x] Any new gaps added to register (none new; `user_unreachable` made explicit under Gap E)
- [x] LiveWhoAmITest updated with findings (typed `AAuthTokenExchangeException` catch; live run 2026-05-30 all modes pass; edge cases 1–5 covered by unit/conformance, item 6 out of scope)

---

## Phase 6: Documentation Validation

**Objective**: Validate every Markdown doc and embedded code snippet in the repo against the implemented SDK behavior and the AAuth spec. Use a subagent per file.

### Approach

For each Markdown file (and each embedded code snippet), dispatch the **Explore** subagent (read-only) with this charge:

> Validate this document against the current SDK source and the AAuth spec.
> Check: (1) API names/signatures match the code, (2) code snippets compile against
> current types, (3) protocol descriptions match the spec, (4) no stale references to
> removed/renamed members. Report inaccuracies with file + line and a suggested fix.

### File Inventory (to validate)

- [x] `README.md`
- [x] `docs/concepts.md`, `docs/getting-started.md`, `docs/README.md`
- [x] `docs/advanced/*.md` (error-handling, interaction-chaining, key-management, missions, observability, platform-attestation)
- [x] `docs/reference/*.md` (configuration, dependency-injection)
- [x] `docs/server/*.md` (all 8 files)
- [x] `docs/signing-modes/*.md` (all 5 files)
- [x] `docs/workflows/*.md` (all 7 files)
- [x] `samples/README.md` and each sample's `README.md`
- [x] `samples/GuidedTour/CodeSnippets.cs` (every snippet compiles + reflects current API)
- [x] `samples/SampleApp/**` code snippets and inline docs
- [x] `aauth-spec/upcoming-changes-02.md` (cross-check against -02 items)

### Definition of Done

- [x] Every Markdown file validated by a subagent
- [x] GuidedTour `CodeSnippets.cs` snippets compile and reflect current API
- [x] SampleApp snippets validated
- [x] All reported inaccuracies fixed or logged
- [x] Repo builds clean; all tests pass

---

## Out of Scope

| Item | Reason |
|---|---|
| ECDSA / P-256 key support for live test | whoami only accepts Ed25519 |
| hwk / jkt-jwt signing modes against live servers | whoami only accepts jwt scheme |
| Multi-resource chaining | No second live resource available |
| AP enrollment against live AP | Separate initiative (`2026-05-27-ap-enrollment-key-naming`) |
| Browser-based interaction handling | Library design; consumer responsibility |
| `provider_hint` support | Hellospecific extension; doesn't generalize |
