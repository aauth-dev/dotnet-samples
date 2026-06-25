# Implementation Log — Decisions, Deviations & Open Questions

> Living log for the AAuth protocol **draft-08** migration. Maintained by the
> implementing agent while the owner reviews at the end. See
> [implementation-plan.md](implementation-plan.md) and [research.md](research.md)
> for the agreed design.

## How to read this

- **Decisions taken** — choices made to keep moving, with rationale. Revert if you disagree.
- **Deviations from plan** — where reality differed from the plan/research.
- **Open questions / inputs needed** — things wanting an owner ruling.

Each entry: `[YYYY-MM-DD] [Phase N] <title>` with status
`PROCEEDED (default X)` / `BLOCKED` / `RESOLVED`.

---

## Decisions taken
### [2026-06-25] [Phase 10] Internal review (independent subagent) + triage landed
- **Review:** an independent subagent reviewed the shipped work cold against draft-08,
  `research.md`, and the plan with severity-graded findings. Result: **zero Critical,
  zero High.** Verdict: substantially conformant — the hard parts (optional `act` with
  `act.agent` = upstream delegator, the ordered `cnf.jwk` classification, the four-party
  mission gate, `scheme=jwt`, `name`/`documentation_uri`, fail-closed interaction-callback
  mapping, correlation-only interaction code, rate-limited silent re-keying) are correct.
  (The first attempt via the **Implementation Validator** agent was BLOCKED — its sandbox
  had no file-read tools — so the review ran in a general subagent with full file access.)
- **Triaged 4 Medium + 1 Low; all addressed:**
  - **M1 (fixed):** `UpstreamTokenValidator.ValidateAsync` now rejects an upstream token
    with no `agent` (was accepted with `Agent == null`, then crashed the PS at
    `BuildNestedAct` → HTTP 500). Clean `invalid_upstream_token` now.
  - **M2 (fixed):** the validator now rejects an upstream `dwk ∉ {aauth-person.json,
    aauth-access.json}` — the four-party gate classifies AS vs PS from `dwk`, so an
    out-of-set value must not pass. Test added. (The reviewer confirmed the
    signature-verified-`dwk` discriminator is **sound** vs a metadata probe.)
  - **M3 (fixed):** `MissionClaim.FromPayload` now enforces the §Mission Reference
    syntax (`approver` via `ServerId.TryParse`; `s256` unpadded base64url of 32 bytes),
    dropping a malformed reference so it can't govern a token request server-side. 7
    theory cases added.
  - **M4 (fixed):** the no-`ResourceIdentifier` auth-token branch in
    `AAuthVerificationMiddleware` now mirrors `VerifyAuthToken` — ordered `cnf.jwk`
    classification (shared `TokenVerifier.IsStructurallyCompleteJwk`, now `internal`),
    act-chain depth validation, and the `sub`-or-`scope` check — with a comment that
    `aud` cannot be bound without `ResourceIdentifier` (resources accepting auth tokens
    SHOULD set it). Did **not** fail-closed, to avoid breaking identity-only configs.
  - **L1 (disposition):** the surviving `UpstreamAct` members
    (`UpstreamTokenValidationResult.UpstreamAct`, local `upstreamAct`) are **legitimate**
    — they name the *upstream token's own* act chain, distinct from the removed
    `AuthTokenBuilder.UpstreamAct` (renamed to `Act`). Kept the names (a public-API
    rename buys little); corrected the Phase 8 grep-clean claim instead.
- **Two demo bugs (reported by owner) fixed alongside:** (1) the call-chain `upstream.tokenType`
  rendered as the enum's integer (`2`) — `samples/Concierge/Program.cs` now emits
  `.ToHeaderValue()` (`aa-auth+jwt`); (2) the SampleApp call-chain skipped hop-2 consent
  when the Concierge→Calendar consent already existed (e.g. after the Guided Tour, since
  that hop's consent is keyed by the Concierge, not the calling agent) — `CallChain.razor`
  now POSTs `/admin/reset` before the run, mirroring the Guided Tour's per-flow reset.
  The SampleApp `call-chain.spec.ts` was repurposed to assert the reset overrides standing
  consent (both hops still prompt) + the `tokenType` text.
- Verified after triage: build 0/0, **544 conformance + 423 unit** green; e2e 41
  passed / 1 skipped.

### [2026-06-25] [Phase 9] AAuth-Access opaque-token flow spun off (research + plan only)
- Created [`.agent/plans/2026-06-25-aauth-access-token-flow/`](../2026-06-25-aauth-access-token-flow/implementation-plan.md)
  with `research.md` (draft-08 `#aauth-access` L738, `#resource-managed-auth` L758,
  **AAuth-Access Security** L2712 — the `token68` grammar/rejection rules, the
  `202→poll→200` handshake, rolling refresh, and the `authorization` covered-component
  MUST, plus an SDK touch-point inventory and OQ1–OQ5) and a phased
  `implementation-plan.md` (Phase 0 decision gate → token68 utility → agent capture/
  replay/binding → resource issue/validate/unwrap → samples/docs → internal review).
  **No `src/` code** written for the flow — the migration stays scoped. Linked from
  this migration's Phase 3 `AAuth-Access` N/A deviation.

### [2026-06-25] [Phase 8] Samples / snippets / docs sweep landed
- **Compiled drift fixed (real bug):** `samples/GuidedTour/TourSession.cs` read
  `act["sub"]`/`act.act.sub` in the call-chain summary + narrative \u2014 a latent
  display bug under draft-08 (the act node carries `agent`, not `sub`, so it rendered
  null). Rewrote to `act["agent"]` with corrected draft-08 framing (top-level `agent`
  = presenter; `act.agent` = upstream delegator; no self-reference) and fixed the
  federated summary's `act["sub"]`. e2e still green (the spec only asserts the
  summary header, but the content is now correct).
- **draft-04 \u2192 draft-05 sweep** across the non-compiled sample surfaces:
  `CodeSnippets.cs`, `JktJwt.razor`, `MockAgentProvider/Program.cs`,
  `MockResourceServers/Profile/{Program.cs,README.md}`.
- **Docs sweep:** `call-chaining.md` rewritten to draft-08 \u2014 `act.agent` semantics,
  `AuthTokenBuilder.Act` (was `UpstreamAct`), correct `ActChainBuilder.BuildNestedAct`
  / `UpstreamTokenValidator.ValidateAsync` signatures, and corrected
  verification/validator bullets (no `act.sub`, no self-ref consistency check).
  `verification-middleware.md` act bullets \u2192 `act.agent` (optional). `client_name`/
  `ClientName` \u2192 `name`/`Name` across `resource-metadata.md`, `dependency-injection.md`,
  `configuration.md`, with `documentation_uri`/`DocumentationUri` surfaced.
- **Grep-clean confirmed:** no `client_name`/`ClientName`/`act.sub`/
  `signature-key-04`/`draft-04`/\u201conly secret guarding\u201d residue in `src/`, `samples/`,
  `docs/`, or `README.md`. Remaining hits are only the historical `aauth-spec/v02`
  snapshots, `aauth-spec/CHANGELOG.md`, and this migration's plan/log (all expected).
  (Note: the `UpstreamAct` token is *not* fully removed \u2014 see the Phase 10 L1
  disposition \u2014 the surviving members name the upstream token's own act chain, which
  is distinct from the removed `AuthTokenBuilder.UpstreamAct`.)
- **Interop profile S1\u2013S5:** `aauth-spec/v08/interop-demo-profile.md` is already
  draft-08-accurate (S5 documents `act.agent` = parent). Sample coverage: S1\u2013S4 are
  exercised by the runnable samples + e2e; the **runnable S5 (sub-agent) demo stays
  deferred per Q9** (Out of Scope) \u2014 the conformance-tested parent-mediated path
  (`PersonServerMapperTests`) proves the model.
- **PsApprovalGuard not wired into the loopback-only sample consent endpoints**
  (recorded as a deviation below): the sample PSes are loopback-only demos, which the
  spec's loopback exemption covers, so they don't enforce the guard. The primitive +
  conformance tests (Phase 7) satisfy the requirement; a production PS supplies an
  authenticator.
  Verified: build 0/0, **536 conformance + 423 unit** green; e2e 41 passed / 1 skipped.

### [2026-06-25] [Phase 7] PS approval-endpoint auth + JWKS refresh-on-failure landed; replay confirmed
- **Approval-endpoint auth (5a / Q8):** new `Person/PsApprovalGuard.cs` —
  `IsAuthorizedAsync(HttpContext, authenticator)` with a built-in **loopback
  exemption** (`IsLoopback`: remote IP is loopback or equals the server's local IP)
  and **default-deny** when a non-loopback request has no app-supplied authenticator
  (§PS Approval Endpoint Authentication, L2724). Provided as a **primitive**, not an
  endpoint guard: the SDK never maps the browser consent page — the host owns it and
  records the verdict via `IPersonPendingStore`/the governance deferred-consent store
  — so the host calls `PsApprovalGuard.IsAuthorizedAsync` before recording an
  approve/deny. 5 conformance cases (loopback v4/v6 exempt; external+no-auth denied;
  external defers to the delegate true/false; no-remote-IP fails closed). Wiring the
  guard into the sample consent endpoints is a Phase 8 item (recorded below).
- **JWKS refresh-on-verify-failure (5e):** added `JwksClient.ForceRefreshKeyAsync`
  (forces one fetch, still honouring the once-per-minute floor) and wired a
  **rate-limited retry** into both JWKS verify paths in `TokenVerifier`
  (`VerifyWithJwksAsync`, `VerifyAuthTokenWithJwksAsync`): on a verify failure, force
  one refresh and retry **only if the resolved key's JWK thumbprint changed** (silent
  re-keying under an unchanged `kid`); otherwise re-throw. The thumbprint guard makes
  the retry a no-op for the common no-rotation failure (and within-window refreshes
  return the cached key), so **no existing verify test regressed** — confirmed across
  the full 423-unit / 536-conformance runs. New `JwksClientTests` case proves
  silent re-keying surfaces the new material once past the floor and fails closed
  within it.
- **Freshness/replay (5g / Q6):** confirmed existing machinery suffices —
  `AAuthVerifier.MaxAge` enforces the `created` window and `InMemoryJtiStore.TryRecordAsync`
  provides `jti` replay detection (+ `RevokeAsync`). The spec replay cache is OPTIONAL
  (`MAY`); no opt-in resource needs the `(thumbprint, created, @method, @authority,
  @path)` cache key, so docs-only — no code change.
  Verified: build 0/0, **536 conformance + 423 unit** green; e2e 41 passed / 1 skipped.

### [2026-06-25] [Phase 6] Interaction callback errors + interaction-code framing landed
- **Audit (Q4 precondition):** the SDK has **no live `?error=` callback consumer** to
  wire into. The agent surfaces interaction outcomes by **polling** — `DeferredPoller`
  already parses `denied`/`abandoned`/`expired`/`invalid_code`/`slow_down`/`server_error`
  from non-202 poll responses and throws `PollingErrorException`. `Interaction.BuildUserUrl`
  *constructs* a browser `&callback=` URL and agent metadata advertises `callback_endpoint`,
  but no SDK code *receives* that redirect; and there is no PS resource-initiated
  interaction flow (no resource-token `interaction` claim handling). So both the
  agent-side callback receiver and the PS callback→polling mapping have no flow to
  attach to in the SDK today — analogous to the Phase 3 `AAuth-Access` situation.
- **Delivered the shared mapping utility (Q4 “shared utility code either way”):**
  new `Errors/InteractionCallbackError.cs` with the five callback codes
  (`access_denied`, `user_abandoned`, `server_error`, `temporarily_unavailable`,
  `interaction_expired`) and the normative mapping — `access_denied`→`denied`,
  `user_abandoned`→`abandoned`, `interaction_expired`→`expired`,
  `server_error`/`temporarily_unavailable`→`server_error`. `ToPollingError` fails
  closed (unknown→`server_error`); `TryGetPollingError` returns false for a
  missing/empty `error` (a success redirect). 11 conformance theory cases.
- **Framing:** reframed the `Headers/InteractionCode.cs` summary from “the only secret
  guarding the interaction URL” to “correlation identifier, not an authorization
  credential; the code alone MUST NOT authorize the decision” (§Interaction Relay,
  spec L2078). Pure-function behavior unchanged; existing `InteractionCodeTests` green.
- **Wiring deferred:** when an agent `callback_endpoint` receiver or a PS
  resource-initiated flow is built, it MUST call `InteractionCallbackError` to surface
  `?error=` (never completable). Recorded as a deviation below. The doc Crockford-citation
  refresh is folded into the Phase 8 docs sweep (two-tier principle).
  Verified: build 0/0, **531 conformance + 422 unit** green; e2e 41 passed / 1 skipped.

### [2026-06-25] [Phase 5] Four-party call-chaining PS mission gate landed
- **Gate:** in `AAuthPersonServerEndpoints.HandleThreePartyAsync`, after upstream-token
  validation, a call-chaining request (`upstream_token` present) whose upstream token
  was AS-issued **and** carries no mission is rejected with `invalid_request` (Q5). A
  three-party upstream (PS-issued) without a mission stays allowed, and an AS-issued
  upstream **with** a mission stays allowed (the `mission.approver` anchors the chain
  to a PS). §Call Chaining L1765.
- **PS-vs-AS via `dwk`, not a probe — DEVIATION from Q3 (PROCEEDED, revert to probe if
  you disagree).** The upstream token's `dwk` claim authoritatively identifies its
  issuer role — `aauth-access.json` ⇒ AS, `aauth-person.json` ⇒ PS (spec L1676) — and
  the `UpstreamTokenValidator` already resolved the issuer's signing key at
  `{iss}/.well-known/{dwk}` and verified the signature, so `dwk` is authenticated, not
  merely asserted. Using it is exactly what Q3's `{iss}/.well-known/aauth-access.json`
  probe would determine, but with zero extra network round-trips, no TOCTOU window, and
  immunity to network-level metadata poisoning. Exposed `IssuerDwk` + `MissionApprover`
  on `UpstreamTokenValidationResult`. To revert to the probe, swap the `IssuerDwk ==
  AccessDwk` check for a cached `MetadataClient` fetch of `aauth-access.json`.
- **Trust expansion (corrects a research mis-statement).** Research change-set-2 claimed
  the PS "accepts an `upstream_token` when the upstream `iss` is an AS"; in fact the
  endpoint trusted only its own issuer (`new HashSet<string> { issuer }`), so an
  AS-issued upstream was rejected as `untrusted_issuer` before any mission gate — and a
  legitimate four-party-**with**-mission chain could never validate. Expanded the
  upstream trust set to `TrustedAccessServers ∪ { own issuer }` (§Upstream Token
  Verification step 2). No regression: PS-self-issued upstreams stay trusted.
- **Tests:** `PersonServerMapperTests` gained 3 integration cases (four-party/no-mission
  → 400 `invalid_request`; three-party/no-mission → 200 + `act.agent`; four-party/with-
  mission → 200), with the stub handler extended to serve upstream-issuer person/access
  metadata. `UpstreamTokenValidationTests` gained `IssuerDwk`/`MissionApprover` coverage.
  Verified: build 0/0, **520 conformance + 422 unit** green; e2e 41 passed / 1 skipped.

### [2026-06-25] [Phase 4] Auth-token `act` rework + verification split landed
- **Field + optionality:** `act.sub` → `act.agent`; `act` is now OPTIONAL (omitted
  for direct authorization). `act.agent` names the immediate upstream agent (the
  delegator); the presenter stays in the top-level `agent` claim, never repeated in
  `act`. Touched `ActChainBuilder` (`BuildNestedAct(upstreamAgentId, upstreamChain?)`,
  `ValidateChain` on `agent`), `ActChainReader`, `AuthTokenBuilder`
  (`UpstreamAct` → **`Act`**, emitted verbatim, null ⇒ no act),
  `UpstreamTokenValidator` (act optional, no self-ref check),
  `TokenVerifier.VerifyAuthToken` (act optional + valid `act.agent`; ordered
  `cnf.jwk` failure classification — structurally-incomplete before decode, then
  invalid-key-material, then PoP mismatch), `AuthTokenResponseValidator`, the PS
  endpoint (composes the node via `BuildNestedAct`), and the no-`ResourceIdentifier`
  fallback path in `AAuthVerificationMiddleware`.
- **Rename (no back-compat, Q1):** `AAuthVerificationResult.ActorSubject` →
  **`ActorAgent`**; `AAuthAuthenticationHandler.ActorSubjectClaimType` (`aauth:act_sub`)
  → **`ActorAgentClaimType`** (`aauth:act_agent`).
- **Tests:** the ~14 affected test files (act fixtures, `act.sub` asserts, the
  `UpstreamAct`→`Act` helpers, the `act.sub`-claim and `act-must-be-present`
  semantic tests) were migrated to draft-08 by a delegated implementation subagent,
  then re-verified locally: build 0/0, **422 unit + 516 conformance** green.
- **Caught in review:** the subagent's pass left a second `act.sub` check in the
  middleware's no-`ResourceIdentifier` fallback branch; fixed directly (optional
  `act.agent` + ordered cnf.jwk) and re-verified. `src/*.cs` is grep-clean of
  `act.sub`/`ActorSubject`.
- **Flake note:** `ActivityDiagnosticsTests.DeferredPoll_CreatesActivitySpan` failed
  once in a full run but passes in isolation and on rerun — process-global
  `ActivityListener` state under parallel execution, not a regression.
### [2026-06-25] [Phase 3] Validation tightening — scheme=jwt guard + mission reference; AAuth-Access N/A
- **scheme=jwt (5c):** added a guard in `AAuthVerificationMiddleware` — a credential
  whose JWT header `typ` is `aa-agent+jwt` or `aa-auth+jwt` MUST be presented via
  Signature-Key `scheme=jwt`. This closes a real (if exotic) confusion vector: a
  self-anchored `jkt-jwt` naming JWT can be crafted with `typ=aa-agent+jwt` (it
  self-anchors on `iss==thumbprint` regardless of `typ`), so without the guard it
  could masquerade as an externally-vouched agent token. Negative + positive tests
  added (`VerificationMiddlewareTests`).
- **Mission reference (5b):** `AAuthMissionHeader.TryParseStructured` now rejects a
  non-conformant reference — `approver` must pass `ServerId.TryParse` (https,
  scheme+host only), `s256` must be unpadded base64url of exactly 32 bytes. 11 new
  theory cases (`MissionReferenceValidationTests`). Existing fixtures already used
  conformant values, so no regressions.
- **AAuth-Access token68 (5d) — N/A, recorded as a deviation below.** The SDK has
  no `Authorization: AAuth` / `AAuth-Access` consumption path, so there is nothing
  to validate. The `AAuth-Requirement` (unknown params kept in a dict) and
  `AAuth-Capabilities` (unknown values returned, not rejected) parsers are already
  forward-compatible. Verified: 422 unit + 515 conformance green.

### [2026-06-25] [Phase 2] Implemented the full common-fields table, not just `name`+`documentation_uri`
- The draft-03 change is the common-fields *table* defined identically across all
  four documents. Rather than add only the two headline fields, added the whole
  optional common set — `name`, `logo_uri`, `logo_dark_uri`, `documentation_uri`,
  `tos_uri`, `policy_uri` — to the client models (`ServerMetadata`,
  `ResourceMetadata`), all four server options, and a shared
  `AddCommonMetadataFields` builder helper. Spec-accurate and low-risk (trivial
  optional pass-throughs); avoids a second pass when the other fields are needed.
- `client_name` → `name` is a clean rename (no fallback) per Q1/Q2. Renamed the
  compiled samples in-phase to keep the build green; the two manual `["client_name"]`
  JsonObject literals (LiveWhoAmITest, MockAgentProvider) were switched to `["name"]`.
- **Docs deferred:** the `ClientName`/`client_name` references in `docs/reference/*`
  and `docs/server/resource-metadata.md` are non-compiled and left for the Phase 8
  sweep (per the two-tier principle). Verified: 422 unit + 502 conformance green.

### [2026-06-25] [Phase 1] HTTP Signature Keys draft-04 → draft-05 reference sweep
- Comment/doc-only: bumped all `signature-key-04`/`draft-04` citations to `-05`,
  pointed the doc links at the `v08/...-05.txt` snapshot, and added an SSRF/egress
  admission checklist (draft-05 §6.3) to `docs/server/verification-middleware.md`.
  No behavioral code change; build + 422 unit + 500 conformance green.

### [2026-06-25] [Phase 0] Decision gate closed — Q1–Q9 ruled
- All nine open questions resolved as `PROCEEDED (default X)` using the defaults
  framed in [`research.md`](research.md) and the plan; see the Open-questions
  section below, each flipped to `RESOLVED`. Rulings favor spec accuracy and the
  no-back-compat posture (Q1). Revert any you disagree with before the affected
  phase runs.
- Grounding for Q1: the 2026-06-09 draft-02 migration and the prior jkt-jwt work
  established the owner principle *“this repo is a spec-accurate alpha SDK; do
  whatever is needed to be spec-accurate.”* Carried forward unchanged.

---

## Deviations from plan

### [2026-06-25] [Phase 8] PsApprovalGuard left unwired in the loopback-only sample PSes (PROCEEDED)
- Phase 7 folded “wire `PsApprovalGuard` into the sample PS consent endpoints” into
  Phase 8. The sample PSes are loopback-only demos — exactly the case the spec's
  loopback exemption (§PS Approval Endpoint Authentication) covers — and the e2e
  Playwright browser drives the consent page over localhost. Enforcing the guard
  there would be a no-op at best and an e2e-fragility risk at worst (if the
  container's browser origin is not detected as loopback). Left the demos unguarded
  and documented the loopback exemption; the `PsApprovalGuard` primitive + 5
  conformance cases already satisfy the spec MUST. Reverse by supplying an
  authenticator to the sample consent endpoints (and confirming loopback detection).

### [2026-06-25] [Phase 7] PS approval guard is a primitive; sample consent-endpoint wiring is Phase 8 (PROCEEDED)
- Plan 5a says “add an authentication guard before consent/denial in
  `AAuthPersonServerEndpoints.cs`.” The SDK does **not** map the browser consent/
  approval endpoint (the host does — it calls `MarkAllowed`/`MarkDenied` /
  `IDeferredConsentStore.ResolveAsync`), so there is no SDK endpoint to gate. Shipped
  the guard as the `PsApprovalGuard` primitive (loopback exemption + app-supplied
  authenticator + default-deny) for the host to call at its consent endpoint. Wiring
  it into the sample PS consent endpoints (so the e2e loopback flows exercise the
  exemption end-to-end) is folded into the Phase 8 samples sweep. Reverse by mapping
  an SDK approval endpoint that enforces the guard directly.

### [2026-06-25] [Phase 6] `?error=` callback wiring is utility-only — no live flow to attach to (PROCEEDED)
- Phase 6's scope wires `?error=` parsing into `DeferredPoller`/`DeferredExchange`
  and/or the PS resource-initiated flow. The Phase-6 audit found neither flow exists
  in the SDK: the agent has no `callback_endpoint` *receiver* (only URL construction +
  metadata advertisement) and the PS has no resource-token `interaction` claim handling.
  Implementing the parsing inside a non-existent receiver would mean building those
  flows — out of scope for this phase (mirrors the Phase 3 `AAuth-Access` N/A). Delivered
  the normative mapping as the standalone `InteractionCallbackError` utility (with tests)
  so a future receiver wires it in one line. Reverse by building the agent callback
  receiver / PS resource-initiated flow and calling the utility there.

### [2026-06-25] [Phase 3] `AAuth-Access` token68 validation not implemented — N/A (no consumption path)
- Phase 3's plan scope/DoD calls for rejecting empty/whitespace/multi-credential
  `AAuth-Access` (`token68`). The SDK does **not** implement the resource-managed
  opaque-token flow — there is no code that reads `Authorization: AAuth` or the
  `AAuth-Access` response header — so there is nothing to tighten. Implementing the
  validation would mean building that flow, which is out of scope for a
  validation-tightening phase. If the AAuth-Access opaque-token flow is added later,
  it MUST enforce token68 (reject empty / embedded whitespace / control chars /
  multiple credentials) at that point.
- **Spun off (Phase 9):** this flow is now scoped as its own initiative \u2014
  [`.agent/plans/2026-06-25-aauth-access-token-flow/`](../2026-06-25-aauth-access-token-flow/implementation-plan.md)
  (research + plan only; no `src/` code in this migration). Its Phase 1 carries the
  `token68` validation that is N/A here.

### [2026-06-25] [Phase 2] Phase 2 docs work deferred to Phase 8 — PROCEEDED (default: defer)
- The plan's Phase 2 **Scope** lists a docs touch ("note the RFC 9728 divergences
  and the unprefixed common-field names"), but Phase 2's **DoD** has no docs
  checkbox. Deferred all Phase 2 doc edits — the RFC 9728 note *and* the stale
  `ClientName`/`client_name` references in `docs/reference/*` and
  `docs/server/resource-metadata.md` — to the Phase 8 samples/snippets/docs sweep,
  per the two-tier principle (non-compiled surfaces are swept once at the end).
  Net effect: those docs are temporarily stale until Phase 8. Reverse by doing the
  docs in Phase 2 if you'd rather not carry stale references.

### [2026-06-25] [Phase 2] Scope widened to the full common-fields table — PROCEEDED (default: spec-complete)
- The plan's Summary row names `name` + `documentation_uri` (and the scope text
  adds `logo_dark_uri`/`tos_uri`/`policy_uri`). I additionally added `logo_uri` to
  the **PS, AS, and resource** options/builders so all four documents implement
  the draft-03 common-fields table identically (agent already had `logo_uri`).
  Trivial optional pass-throughs; spec-accurate. Trim the extra fields if you want
  the minimal `name`+`documentation_uri` diff instead.

---

## Open questions / inputs needed

> Mirrors [`research.md`](research.md) "Gaps & open questions" and the plan's
> Phase 0. All **RESOLVED** 2026-06-25 as `PROCEEDED (default X)` — revert any you
> disagree with.

### [2026-06-25] [Phase 0] Q1 — No-back-compat posture for draft-08 — RESOLVED
- **Ruling: confirmed.** Spec-accurate alpha SDK; breaking renames/removals are
  acceptable for spec accuracy; single coordinated cutover; no dual-format shims.
  Gates the `act.sub`→`act.agent` and `client_name`→`name` renames.

### [2026-06-25] [Phase 0] Q2 — `ResourceMetadata` `name` fallback — RESOLVED
- **Ruling: spec-accurate `name` only, no `client_name` fallback.** Follows Q1;
  the SDK emits `name` on every document, so reading the legacy form buys nothing.
  Revisit only if a live older resource fails interop.

### [2026-06-25] [Phase 0] Q3 — PS-vs-AS determination for the four-party gate — RESOLVED
- **Ruling: metadata probe, cached.** Decide PS-vs-AS by probing
  `{iss}/.well-known/aauth-access.json` (present ⇒ AS) via the cached
  `MetadataClient`; no new configuration surface. Add an optional configured
  trusted-AS override later only if probe latency proves a problem.

### [2026-06-25] [Phase 0] Q4 — Owner of interaction `?error=` callback parsing — RESOLVED
- **Ruling: agent-side surfacing now; PS mapping where the flow exists.** The
  agent poller parses the `?error=` callback and surfaces it (never completable);
  the normative PS callback→polling mapping (spec `#interaction-callback-errors`,
  L987) is wired into the PS resource-initiated flow **iff** that flow is present
  in the SDK — confirmed by an audit at the start of Phase 6. The mapping table
  itself is shared utility code either way.

### [2026-06-25] [Phase 0] Q5 — Four-party "mission required" error code — RESOLVED
- **Ruling: `invalid_request`** with a distinct `error_description`. No new code
  is defined by the spec; fits the existing taxonomy.

### [2026-06-25] [Phase 0] Q6 — Freshness/replay machinery sufficiency — RESOLVED
- **Ruling: existing machinery suffices; treat as docs-only.** The spec replay
  cache is `MAY` (OPTIONAL); the `created` window is the primary defense and the
  `jti` store already covers replay. Verify
  [InMemoryJtiStore](../../../src/AAuth/Server/InMemoryJtiStore.cs) +
  [AAuthVerifier](../../../src/AAuth/HttpSig/AAuthVerifier.cs) in Phase 7; align
  the optional cache key only if a resource opts in.

### [2026-06-25] [Phase 0] Q7 — Egress-admission / SSRF ownership — RESOLVED
- **Ruling: deployment-level + docs.** SSRF/egress admission (draft-05 §6.3) is an
  infrastructure concern (HttpClient transport + network policy); document a
  checklist, defer any SDK hook unless a concrete gap appears.

### [2026-06-25] [Phase 0] Q8 — Approval-endpoint authentication shape — RESOLVED
- **Ruling: app-supplied verifier + built-in loopback exemption.** The PS approval
  endpoint takes an application-provided authentication delegate; a loopback-only
  deployment is exempt (OS-level access control). Default-deny when externally
  reachable and unauthenticated.

### [2026-06-25] [Phase 0] Q9 — Sub-agent (S5) interop sample — RESOLVED
- **Ruling: defer (Out of Scope).** Matches the 2026-06-09 migration, which also
  deferred a live sub-agent sample; the conformance-tested code paths prove the
  model. Revisit if interop testing needs a runnable S5 demo.
