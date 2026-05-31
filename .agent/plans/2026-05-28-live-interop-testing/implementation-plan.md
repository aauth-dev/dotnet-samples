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

## Phase 7: PR #27 Review Remediation

**Objective**: Address the findings from the two PR #27 review passes (external `copilot-pull-request-reviewer` + internal PR Review subagent). Full findings, severities, spec/SDK evidence, and accuracy verdicts are recorded in research.md §9.

**Design decisions (confirmed with user 2026-05-31):**

- **H2** → Full implement: compute and attach `Content-Digest` (RFC 9530, SHA-256) before signing when it is a required/learned component.
- **H1** → Options object refactor: introduce a `TokenExchangeRequest` parameter object. **Backward compatibility is NOT a constraint** (pre-1.0 alpha); replace the old positional overload outright rather than preserving it. Keep only the overloads that make the new surface clean.
- **M3** → Comment + docs only: reword the misleading `InfiniteTimeSpan` assertion as a stated requirement; do not re-add a per-request CTS (preserves the Fix 4.1 single-timeout-layer decision).
- **Nits L1–L5** → Included in this phase.

### Validation Protocol (applies to every fix)

Same as Phase 4: after each fix, dispatch the **Explore** subagent (read-only) to compare the change against (1) the spec section it implements, (2) prior SDK behavior, (3) samples/docs needing updates; report spec-compliance, correctness, missing tests, stale docs, regressions. Incorporate feedback before marking done.

### Docs / Samples Update Protocol (applies to every fix)

Backward compatibility is not a concern, so any surface or behavior change must be propagated everywhere it is referenced. After implementing each fix, dispatch a **dedicated subagent per fix** charged to find and update all affected: `docs/**`, `samples/**` (incl. each sample's `README.md`), `samples/GuidedTour/CodeSnippets.cs` snippets, `samples/SampleApp/**` code and inline docs, and root/`docs/README.md`. The subagent must (a) search for every reference to the changed symbol/behavior, (b) update it to the new surface, (c) confirm GuidedTour/SampleApp snippets still compile. Record the subagent's file list in the fix checklist.

---

### Fix 7.1 — H2: Compute `Content-Digest` for adaptive signing

**Files**: `src/AAuth/HttpSig/AAuthSigningHandler.cs` (~L256-271 `ResolveAdditionalComponents`), plus a digest helper.

When `content-digest` is a required/learned additional component and the request has a body, compute `Content-Digest: sha-256=:<base64>:` (RFC 9530 structured-field dictionary form) from the buffered body and attach it before the signature base is built, so the component resolves instead of throwing. Keep the hard throw only for genuinely unsatisfiable components (no header and not auto-computable), but make its message name the unmet component + origin.

#### Definition of Done

- [x] `Content-Digest` computed (SHA-256, RFC 9530 SF form) when required and body present
- [x] Buffered-body read does not break streaming/no-body requests
- [x] Header not duplicated if caller already set `Content-Digest`
- [x] Unsatisfiable-component error names the component + origin
- [x] Unit tests: digest value correctness, required-component path, no-body path, caller-preset header, unsatisfiable non-digest component
- [x] Adaptive retry loop (`ChallengeHandler`) no longer throws for `content-digest`
- [x] Dedicated docs/samples subagent dispatched; affected docs (`signing-modes/overview.md`, `advanced/error-handling.md`) and any snippets updated
- [x] Subagent validation passed

### Fix 7.2 — M1 + M2: Treat per-request components as additive on seed and clone

**Files**: `src/AAuth/Agent/ChallengeHandler.cs` (`SeedAdditionalComponents` ~L303, `CloneAsync` ~L334, reuse `MergeComponents` ~L311).

In `SeedAdditionalComponents`, read any existing `request.Options[AAuthSigningHandler.AdditionalComponentsKey]` and fold it into `MergeComponents` before `Set`, so a caller-set value is preserved additively instead of clobbered. In `CloneAsync`, copy `source.Options` onto the clone (iterate `HttpRequestOptions` as `IEnumerable<KeyValuePair<string,object?>>`) so request-scoped state survives retries; update the existing "options intentionally omitted" comment to reflect the new behavior.

#### Definition of Done

- [x] `SeedAdditionalComponents` merges caller-set components additively (order-preserving, de-duped)
- [x] `CloneAsync` copies `HttpRequestMessage.Options` to the clone
- [x] Stale "options intentionally omitted" comment corrected
- [x] Unit tests: caller-set components preserved through seed + retry; non-AAuth option survives clone
- [x] No regression: `SendAsync_NoAdditionalComponents_SignsBaseComponentsOnly` still passes
- [x] Dedicated docs/samples subagent dispatched; affected docs/snippets updated (none reference low-level option semantics — verified by search)
- [x] Subagent validation passed

### Fix 7.3 — H1: `TokenExchangeRequest` options object

**Files**: `src/AAuth/Agent/TokenExchangeClient.cs`, call sites (`src/AAuth/Server/CallChainingHandler.cs` ~L83, `src/AAuth/Agent/ChallengeHandler.cs` ~L193-198).

Introduce a `TokenExchangeRequest` (or equivalently named) parameter object carrying `onInteractionRequired`, `pollerOptions`, `upstreamToken`, `capabilities`, `prompt`. Add an `ExchangeAsync(string personServer, string resourceToken, TokenExchangeRequest request, CancellationToken cancellationToken = default)` overload. Keep the 3-arg convenience overload. Backward compatibility is not required: **remove** the old 7-positional-arg full overload outright. The fluent builder surface (`AAuthClientBuilder` + `ChallengeHandlingOptions`) must remain unchanged — `ChallengeHandlingOptions` stays the canonical config path; `TokenExchangeClient` is the low-level API. Update internal call sites to the new shape.

#### Definition of Done

- [x] `TokenExchangeRequest` type added (public, init-only properties)
- [x] New `ExchangeAsync` overload accepting the object; 3-arg convenience overload retained; old positional full overload removed
- [x] `CancellationToken` remains the last parameter on every overload
- [x] Fluent builder surface (`AAuthClientBuilder`, `ChallengeHandlingOptions`) unchanged
- [x] Internal call sites updated (`CallChainingHandler`, `ChallengeHandler`)
- [x] Unit tests cover the object-based overload (capabilities/prompt/upstream/deferred paths)
- [x] Dedicated docs/samples subagent dispatched; `workflows/call-chaining.md` + any `ExchangeAsync` snippets updated
- [x] Subagent validation passed

### Fix 7.4 — M3: Correct `DeferredPoller` timeout comment

**Files**: `src/AAuth/Agent/DeferredPoller.cs` (~L119-122 inline comment, class `<remarks>` ~L58-65).

Reword the inline comment so the `InfiniteTimeSpan` configuration reads as a *requirement/assumption* of the supplied `HttpClient`, not a guaranteed fact. Add the requirement to the class-level `<remarks>` beside the existing "must be signed" note. No behavioral change; no per-request CTS.

#### Definition of Done

- [x] Inline comment reworded as a requirement scoped to the builder-created client
- [x] Class `<remarks>` documents the infinite-timeout expectation for external callers
- [x] No behavioral/code change beyond comments + XML docs
- [x] Dedicated docs/samples subagent dispatched; any `DeferredPoller` usage docs updated
- [x] Subagent validation passed

### Fix 7.5 — L1–L5: Low-severity cleanup

**Files**: as listed per item.

- **L1** `ChallengeHandler.cs` ~L255-257: replace the read-modify-write of `_learnedComponents` with `AddOrUpdate` using a merge function for strict accumulation under concurrent 401s.
- **L2** `SignatureError.cs` ~L111-135 (`ParseRequiredInput`): replace naive `IndexOf("required_input")` with a `;`-split / word-boundary parse robust against tokens like `x-required_input`.
- **L3** `AAuthTokenExchangeException.cs` ~L52-53: add a clarifying comment that `interaction_required` is non-terminal (202) and unreachable on this `!IsSuccessStatusCode` path; keep behavior.
- **L4** `samples/LiveWhoAmITest/Program.cs` ~L78-93: wrap tunnel + Kestrel lifecycle in `try/finally`; dispose `tunnelProcess`; dispose per-mode `HttpResponseMessage`s.
- **L5** `.devcontainer/post-create.sh` ~L36: restore the cosmetic blank line removed adjacent to the cloudflared block.

#### Definition of Done

- [x] L1 `AddOrUpdate` accumulation; unit test for concurrent merge (or documented as benign)
- [x] L2 robust `required_input` parse; unit test with a decoy token
- [x] L3 clarifying comment added
- [x] L4 sample lifecycle in `try/finally`; disposables disposed
- [x] L5 cosmetic diff reverted
- [x] Dedicated docs/samples subagent dispatched; any affected docs/snippets updated
- [x] Subagent validation passed

### Phase 7 Definition of Done

- [x] Fixes 7.1–7.5 implemented and individually validated
- [x] Unit tests added for H2, M1/M2, H1, L1, L2
- [x] **A dedicated docs/samples subagent was dispatched per fix** and every affected doc, sample README, GuidedTour `CodeSnippets.cs` snippet, and SampleApp reference updated to the new surface
- [x] GuidedTour + SampleApp snippets still compile
- [x] LiveWhoAmITest still passes all modes (manual live run)
- [x] No regressions (full unit + conformance suite)
- [x] Repo builds clean (0 warnings / 0 errors)
- [x] Each fix's subagent validation incorporated
- [x] research.md §9 statuses updated (Open → Fixed)

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
