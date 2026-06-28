# Server-Side API Surface — Implementation Log

Dated, append-only record of decisions, deviations, and open inputs made while
implementing. Append; do not rewrite. A reversed decision gets a new entry that
supersedes the old one.

## Decisions

### [2026-06-27] [Phase 0] Endpoint style — per-endpoint `RequireAAuth` — RESOLVED

Chosen in the decision interview. Per-route `.RequireAAuth(scope:…, role:…)` /
`.RequireAAuthSignature()` over a route-group DSL. Idiomatic Minimal API,
composes with `RequireAuthorization`, and retires the magic-string scope
policies. Spike-validated end-to-end (9/9 `CalendarFlowTests`).

### [2026-06-27] [Phase 0] Interaction module scope — full opt-in module — RESOLVED

Chosen in the interview. The SDK owns codegen + pending store + poll endpoint +
approve hook; payload endpoints opt in via `RequireAAuthInteraction`. The
resource keeps only its consent page (presentation + user auth the spec leaves
out, L2078).

### [2026-06-27] [Phase 0] Role mappers — migrate now — RESOLVED

Chosen in the interview (diverges from the research lean to defer). G6 showed
`MapAAuthPersonServer` already covers the behaviors; the work is migrating
MockPersonServer onto it via a `SampleIdentityClaimsAsserter` and adding seams
only for micro-gaps found during migration.

### [2026-06-27] [Phase 0] DI — extend `AddAAuthResource` + fold in discovery — RESOLVED

Chosen in the interview. Extend to parity (`SignatureWindow`, `AccessMode`,
`AuthorizationEndpoint`, discovery hook) and adopt in samples rather than add a
builder type.

### [2026-06-27] [Phase 0] Cutover posture — clean cutover — RESOLVED

Chosen in the interview. Replace diverged helpers and migrate consumers in one
change set; no back-compat shims (matches the repo's spec-accurate-alpha stance).

### [2026-06-27] [Phase 0] G1 — challenge in a post-routing middleware — RESOLVED

Spike confirmed a single middleware after `UseRouting` reads
`AAuthEndpointRequirement` metadata and runs verification + the
`requirement=auth-token` challenge correctly, composing the existing middleware.
Mitigation required for the discovered footgun: missing `UseRouting` makes
`GetEndpoint()` null and silently passes protected endpoints unverified — Phase 3
must fail-closed or ship a single ordered entry-point.

### [2026-06-27] [Phase 0] G2 — Crockford generator is safe — RESOLVED

No test depends on the Inbox hex code format. Phase 2 swaps in a shared
spec-conformant generator as a free conformance fix.

### [2026-06-27] [Phase 0] G3 — `UseAAuth` defaults from DI metadata — PROCEEDED (default)

`UseAAuth` defaults resource signing key / issuer / identifier from the
DI-registered `AAuthResourceMetadataOptions`; per-call config is limited to trust
(`TrustedAuthTokenIssuers`). Metadata ownership moves into the extended
`AAuthResourceOptions`. Revert if metadata should stay a separate sub-object.

### [2026-06-27] [Phase 0] G4 — keep discovery clients overridable — RESOLVED

Corrected: the integration harness overrides discovery via
`RemoveAll<MetadataClient/JwksClient>()` + re-add, not the named clients
([CalendarFlowTests.cs](../../../tests/AAuth.Tests/Integration/CalendarFlowTests.cs#L59-L99)).
Phase 1 must keep these as overridable singletons (`AddAAuthResource` already
does).

### [2026-06-27] [Phase 0] G5 — interaction park/poll primitive, no PS unification — PROCEEDED (default)

Build the interaction module on a small shared park/poll primitive but keep RS
opaque-token issuance distinct from PS auth-token minting. A full
PS-governance/`IDeferredConsentStore` unification is out of scope this round.
Revert if a single engine across all three roles is wanted now.

### [2026-06-27] [Phase 2] Interaction-code rate-limiting is deployment-level — PROCEEDED (default)

The interaction module's `AAuthInteractionCode` + `InMemoryInteractionPendingStore`
enforce the code-level spec MUSTs: Crockford base32, >= 40 bits from a CSPRNG,
single-use (poll removes the entry), and expiry. The spec's "rate-limit
 code-validation attempts at the interaction URL" is treated as a deployment
control (gateway / the resource's own consent handler), consistent with how the
SDK already treats other deployment-level controls (SSRF egress, draft-05 §6.3) —
rather than a store-global counter (which would itself be a lockout DoS vector).
Documented in `InMemoryInteractionPendingStore`. Revert if an in-SDK limiter is
wanted.

### [2026-06-27] [Phase 3] Per-route surface + 5-server migration — RESOLVED

Shipped `AAuthEndpointRequirement` + `RequireAAuth`/`RequireAAuthSignature` +
`UseAAuth` (defaults signing key/issuer/identifier from DI metadata; per-call
config is trust + federated AS audience). Migrated all five resource servers
(Profile/Calendar/Trips/Wallet/Inbox) to `AddAAuthResource` + `MapAAuthWellKnown`
+ `UseRouting`/`UseAAuth` + per-route `.RequireAAuth(...)`. The fail-closed guard
throws when `UseRouting` has not run; the middleware test asserts an unsigned
request to a protected endpoint never returns 200 (whether via the guard or
verification rejection). Trimmed now-unused usings in the five servers. Invariant
greps over `samples/MockResourceServers` return zero matches for
`AddAAuthScopePolicy` / `RequireAuthorization("AAuth.` / `AddHttpClient("aauth-` /
`new MetadataClient`/`new JwksClient` / `UseWhen`. Suites: AAuth.Tests 500,
AAuth.Conformance 556 — all green.

### [2026-06-27] [Phase 4] AddAAuthFederation seam + sample wiring — RESOLVED

Added `AddAAuthFederation(psKey, psIssuer, psKid)` (the one genuine SDK gap the
analysis found) and migrated MockPersonServer's hand-built federation block
(named `AddHttpClient` + `AccessServerClient` + `AuthTokenResponseValidator` via
`AAuthClientBuilder`) onto it — removing the last manual-HttpClient-in-DI on the
PS side (consumer invariant 2). The named transport client is exposed as
`AAuthFederationServiceCollectionExtensions.FederationHttpClientName` so the
federation test redirects in process without a duplicated literal.
`MockPersonServer*` tests: 17 green.

### [2026-06-27] [Phase 5] Docs / snippets / sample sweep — RESOLVED

Migrated the remaining samples off old surfaces: `Concierge` (manual discovery →
`AddAAuthResource` + `MapAAuthWellKnown`; kept the legitimate `UseAAuthIntermediary`
call-chaining helper) and `MockAccessServer`/`MockPersonServer` discovery blocks →
`AddAAuthDiscovery()`. Updated the docs (server/*, reference/*, README,
getting-started, concepts, workflows, signing-modes, resource-managed) and the six
SampleApp tour-page teaching snippets to the new API via update-subagents. Two
read-only verification subagents (docs; SampleApp + GuidedTour) confirmed clean —
the only residual old-surface mentions are the legitimately-allowed contexts: the
MVC `[Authorize]` named-policy path, explicitly-labeled low-level/building-block
sections (`UseAAuthVerification`/`MapAAuthResourceWellKnown`/`IJtiStore` override),
and the `UseAAuthIntermediary` intermediary pattern. Invariant greps over
`docs/` + `samples/` for manual discovery wiring and magic-string policies return
zero. Full build + AAuth.Tests 500 + AAuth.Conformance 556 green.

### [2026-06-27] [Phase 6] Internal review + fixes — RESOLVED

A file-reading reviewer validated the new SDK code against the spec + invariants.
Verified-correct: `AAuthInteractionCode` (Crockford alphabet, >=8 symbols, `b & 0x1F`
unbiased since 256 = 8x32, I/L->1 O->0 fold, hyphen strip); the `UseAAuth`
fail-closed guard (IEndpointFeature null -> throw); SignatureOnly skips the
challenge; signing key/issuer default from DI metadata with null-safe handling;
`InMemoryInteractionPendingStore` ConcurrentDictionary + volatile flag; pooled
singleton discovery clients; `AddAAuthFederation`; and the five migrated resource
servers (invariant greps clean). Two findings fixed:

- **[Critical] poll single-use race** (`MapAAuthInteractionPoll` get-then-remove
  could double-issue under concurrent polls). Fixed: added
  `IInteractionPendingStore.TryConsume` (atomic `TryRemove`-if-approved); the poll
  now claims atomically so an approved interaction issues at most one token.
  Regression test `InteractionPendingStoreTests` (incl. a 50-way concurrent race
  asserting exactly one winner).
- **[Medium] missing `Cache-Control: no-store`** on the poll's pending `202`
  (§Deferred Responses). Fixed.

Final: build 0/0, AAuth.Tests 504 + AAuth.Conformance 556 green. (Playwright e2e
not run — requires a full-stack boot; wire behavior is covered by the
WebApplicationFactory integration suites.)

### [2026-06-28] [Phase 7] Migrate MockPersonServer `/token` onto the mapper — EVALUATED → DECLINED (supersedes the Phase 4 BLOCKED issue)

Owner approved attempting the migration ("keep existing UX blocks unchanged, make
the UX pluggable"). On investigation the migration was **declined** — it cannot
preserve the PS's tested mission-governance contract. The PS `/token` stays
hand-rolled, consistent with prior
[DEV-4](../2026-06-06-mission-api-refactor/issues-and-deviations.md).

Decisive evidence — [MissionAgentFlowTests](../../../tests/AAuth.Tests/Integration/MissionAgentFlowTests.cs)
(12-row Consent Matrix) is coupled to behavior the mapper's `IIdentityClaimsAsserter`
+ `IPersonPendingStore` seam cannot reproduce:

- **Row 5** (out-of-scope → prompt → issue): asserts `OnInteractionRequired` fires
  AND the mission-log reason is `OutOfScope`. The mapper's asserter `Assert` fires
  no prompt and logs `InScope`; its `NeedsConsent`→park→poll logs `Consent`. No path
  yields a prompt + `OutOfScope`.
- **Row 6** (out-of-scope → prompt → deny): expects a prompt then
  `AAuthInteractionDenied`; the asserter `Deny` is a silent `403`.
- **Rows 7–8**: a **live clarification chat** (`OnClarificationRequired`, with
  `Clarification` mission-log entries). The mapper has no clarification sub-protocol.

**Correction to an earlier note in this effort:** `RequireTokenClarification` is
NOT dead code. The earlier grep (`RequireTokenClarification\s*=\s*true`) missed the
real assignment — `/admin/mission-script` sets it from `requireClarification` via
`script.RequireTokenClarification = rc.GetValue<bool>()`
([Program.cs L1224](../../../samples/MockPersonServer/Program.cs)), and Rows 7–8
exercise it. The "delete the clarification branch" plan was withdrawn. (Lesson
recorded: when judging code dead, grep ALL assignments + readers + the tests/admin
endpoints that drive it through config, not just literal `= true`.)

Spec context still holds (admin/consent is out of spec — L2078/L2724/L3226), but
that only means the SDK should not *host* the consent surface; it does not make the
demo's governance state machine expressible through the identity-claims asserter
(proven by
[PersonServerMapperTests](../../../tests/AAuth.Conformance/Person/PersonServerMapperTests.cs),
which covers the simpler 3-party/4-party identity model, not the mission matrix).

A speculative SDK option (`AAuthPersonServerOptions.UnsignedPathPrefixes`, to let the
mapper skip the demo's unsigned `/admin` surface) was prototyped and **reverted** —
with the migration declined it had no consumer.

**Net:** no code shipped for Phase 7. The PS already benefits from the Phase 0–6
convenience DI (`AddAAuthDiscovery` + `AddAAuthFederation`); the hand-rolled
`/token` remains the deliberate governance showcase. Build + AAuth.Tests +
AAuth.Conformance remain green (unchanged from the Phase 6 final).

### [2026-06-28] [Phase 7] Migrate PS via a faithful mission/clarification seam — APPROVED (supersedes the DECLINED entry above)

Owner pushed back on declining-by-precedent ("things change; analyze and make the
correct call aligned to our invariants"). Re-analyzed from the spec + the layering
invariant rather than DEV-4. Conclusion reversed: **migrate**, by closing a real
tier-3 conformance gap.

The gap (spec-measured, not precedent): the mapper routes the out-of-scope mission
decision through `IIdentityClaimsAsserter`, which cannot emit the **normative**
`requirement=clarification` round-trip
([spec L989/L995](../../../aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md),
MUST-level) nor log the spec mission-log reasons (`OutOfScope`/`Clarification`,
#mission-log). The agent half of clarification already ships in the SDK
(`OnClarificationRequired`/`ClarificationResponse`); the server-side asymmetry is
the bug. Invariant basis: spec conformance is paramount, and tier-3 already commits
to missions (PersonServerMapperTests), so it must handle them faithfully — a lossy
mission gate is a conformance liability whether or not a sample exercises it.

Owner refinement: the SDK owns only the **protocol** bits; a consumer seam owns
**how** clarification/consent is decided (LLM, human screen, scripted test). Spec
backs this — the PS "does not prescribe how the decision is made" (L3226).

Design: new `IMissionTokenConsent.ReviewAsync(ctx) → Grant | Deny | Clarify(q) |
Defer` in `AAuth.Server.Governance` (default ships the spec three-gate's
interactive resolution; registered by `AddAAuthGovernance`). Identity claims on
`Grant` still come from `IIdentityClaimsAsserter` — governance decision and
identity stay separate seams. The mapper owns the `requirement=clarification` 202
+ the pending-URL `GET`/`POST`/`DELETE` round-trip + `IMissionLog` reasons.
Migration replaces the sample's hand-rolled `/token` + `/pending` +
`/federated-pending` + `/mission-pending` with the mapper plus a sample
`ScriptMissionTokenConsent` over the existing `MissionConsentScript`; governance
endpoints + `/admin/*` + `ConsentStore` stay. This expands scope beyond the
original "sample-side only" framing — accepted by the owner.

The speculative `UnsignedPathPrefixes` option remains reverted; the mapper will
instead exclude the demo's unsigned `/admin` via the same seam-driven approach
decided during implementation.

### [2026-06-28] [Phase 7] SDK seam shipped + conformance-proven; sample-migration scope finding

SDK work for Option A is **complete and green**:

- New `IMissionTokenConsent` (`ReviewAsync → Grant | Deny | Clarify | Interact`) +
  `DefaultMissionTokenConsent` (conservative `Interact`), registered via
  `AddAAuthGovernance` (`TryAdd`).
- `MapAAuthPersonServer` mission gate rewritten: gate 2a/2c routes through the
  consent seam; the mapper owns the normative `requirement=clarification` 202 +
  the pending-URL `GET`/`POST`/`DELETE` round-trip; mission-log reasons are now
  `InScope`/`PriorConsent`/`OutOfScope`/`Clarification` per spec. `PersonPendingEntry`
  gained `MissionGate`/clarification state; identity on a grant still comes from
  `IIdentityClaimsAsserter`.
- `AAuthPersonServerOptions` gained `InteractionEndpoint`/`MissionEndpoint`/
  `PermissionEndpoint`/`AuditEndpoint` (metadata advertising) + `UnsignedPathPrefixes`
  (re-added, now load-bearing: lets the PS exclude its unsigned `/admin`).
- Conformance: `PersonServerMapperTests` +3 rows (clarify→grant logs `OutOfScope`,
  out-of-scope deny, withdraw→410+cancelled). Full conformance **559** green;
  AAuth.Tests **504** green; no regression against the unchanged sample.

**Scope finding on the sample migration (`MockPersonServer/Program.cs`, ~1640 lines):**
migrating `/token` moves the 3-party-consent and mission-token pending entries into
the SDK's `IPersonPendingStore`, but the demo's **interactive browser consent UI**
(`GET /interaction` + `/interaction/approve` + `/interaction/deny`, ~350 lines of
HTML) reads the old `PendingStore`/`MissionPendingStore` and sets `entry.Decision`.
Re-pointing that UI across two stores is required for the CLI/e2e interactive path —
and those browser flows run only under Playwright e2e, which **cannot boot in this
dev container**. The scripted integration paths (the 12 `MissionAgentFlowTests`
rows + `MockPersonServerConsentTests` via `/admin/consent`) do not touch that UI and
remain fully verifiable here.

### [2026-06-28] [Phase 7] Migration complete — green

MockPersonServer `/token` + the deferred polls now come from `MapAAuthPersonServer`.

- Deleted the hand-rolled `POST /token`, `GET /pending`, `GET /federated-pending`,
  and the `GET/POST/DELETE /mission-pending` clarification handlers + the
  `PendingStore`/`FederatedPendingStore` classes + the `IssueAuthToken`/
  `PeekJwtAudience`/`Base64UrlDecode` helpers.
- Added three sample adapters: `SampleIdentityClaimsAsserter` (identity + the
  non-mission `ConsentStore` gate), `ScriptMissionTokenConsent` (the out-of-scope
  mission decision over `MissionConsentScript`/`MissionPolicyStore`), and
  `ConsentBridgePersonPendingStore` (flips a parked three-party entry to allowed
  when `ConsentStore` records consent). Governance endpoints (`/mission`,
  `/permission`, `/audit`, `/mission-interaction`, `/permission-pending`,
  `/mission-create-pending`), `/admin/*`, and `ConsentStore` are unchanged; the
  browser `/interaction` page + approve/deny were re-pointed onto
  `IPersonPendingStore` (3-party + interactive mission) while keeping
  `MissionPendingStore` for permission/creation.
- All deferred polls now unify under `/pending/{id}` (the agent follows the
  `Location` header); updated the one stale `MockPersonServerFederationTests`
  assertion that pinned `/federated-pending/`.
- `PersonServerMapperTests` +3 rows (clarify→grant, out-of-scope deny, withdraw).

Validated: `dotnet build AAuth.slnx` 0/0; **AAuth.Tests 504**; **AAuth.Conformance
559**; the 12-row `MissionAgentFlowTests` + `MockPersonServer*` + consent-path
`CalendarFlowTests` all green. Playwright e2e (the interactive browser consent
flows) not runnable in this dev container; the re-pointed `/interaction` handlers
preserve the prior behavior over the new store.

### [2026-06-28] [Phase 8] Docs sweep + internal review

**Docs:** updated [MockPersonServer/README.md](../../../samples/MockPersonServer/README.md)
(adopts `MapAAuthPersonServer` + the three seams; governance/clarification now
mapper-owned), [token-issuance.md](../../../docs/server/token-issuance.md) (mission
gate via `IMissionTokenConsent`, new options, MockPersonServer no longer
hand-rolled), [mission-governance.md](../../../docs/server/mission-governance.md)
(seam table +`IMissionTokenConsent`), [clarification-chat.md](../../../docs/advanced/clarification-chat.md)
(new "Server side: emitting a clarification" section), and the
[docs/README.md](../../../docs/README.md) API map.

**Verification subagent (read-only):** migration is clean — no sample/test boots
or HTTP-calls the MockPersonServer's removed surfaces (GuidedTour/SampleApp/
MissionAgent touch only `/admin/*`); Concierge's own `/mission-pending` is an
intermediary route (legitimate); no stale docs references. Known minor: the
GuidedTour *narration* names the deferred poll "the mission-pending URL" — now
unified to `/pending/{id}`; functionally correct (it follows the `Location`
header), left as a narration-only follow-up to avoid churning its golden-text.

**Review subagent (read-only):** no CRITICAL; spec-conformance + seam design
confirmed. One **HIGH** fixed — the clarification `POST`/`DELETE` on `/pending/{id}`
did not verify the requesting agent owns the entry; added `RequesterMatches`
(verified carrier `sub` must equal `entry.AgentId`, else `404`) on both, plus a
`400` when the POST body carries neither `clarification_response` nor
`resource_token`. Locked with a new conformance test
(`Mission_Clarification_RejectsForeignAgent`). MEDIUM "updated `resource_token`
not re-applied" is pre-existing sample behavior preserved verbatim — and safe (the
new token is ignored, so no scope escalation); noted, not changed.

**Final:** `dotnet build AAuth.slnx` 0/0; **AAuth.Tests 504**; **AAuth.Conformance
560** (+1 security test). Phase 7 + Phase 8 complete.

### [2026-06-28] [Phase 9] Replay keyed on the carrier `jti` makes auth tokens single-use — APPROVED

**Finding (from the e2e call-chain regression).** All three `call-chain*` specs
broke after the migration. Root cause traced end-to-end with live PS + Concierge
diagnostics: the agent reuses **one** auth token across `GET /` and the Concierge's
`GET /pending/{id}` poll; the second presentation returns `401 invalid_jwt`. The
Concierge's `GET /pending/{id}` **re-drives** the chained call on every poll
(deferred interaction chaining), so the upstream auth token is *legitimately*
presented many times. `AAuthVerificationMiddleware` records the **carrier token's
`jti`** in the `IJtiStore` and rejects the duplicate → it treats a reusable auth
token as single-use.

Proven by stash-diffing HEAD vs the working tree with a boot probe:
- **HEAD (OLD):** Concierge hand-registered services, **no `IJtiStore`** →
  `DIAGBOOT IJtiStore=NULL`; same `jti` reused on `GET /` then `/pending` → **200**.
- **Working tree (NEW):** Concierge on `AddAAuthResource` → `IJtiStore=InMemoryJtiStore`;
  same `jti` reused → `/pending` → **401 `invalid_jwt`** (`aauthErr=-`, i.e. the
  replay branch, not issuer verification).

**Ruling.** The auth token **is** reusable; the bug is in the SDK, not the sample
or the test. Per §Freshness and Replay (L2376/L2378) replay is defended by the
signature: `created` (60 s window) plus an optional cache keyed on
`(signing-key-thumbprint, created, @method, @authority, @path)` — explicitly **not**
the token `jti`, and "this profile defines no nonce mechanism". `jti` is for audit
+ revocation (L567/L2274). Fix the middleware to key the replay record on the
signature tuple; keep `IsRevokedAsync(jti)` on the real `jti`. Rejected the
shortcut `EnableReplayDetection = false` on the Concierge — it hides the bug and
leaves every other resource single-using auth tokens. Tracked as **Phase 9**
(fix) + **Phase 10** (docs sweep + review).

### [2026-06-28] [Phase 9] Replay fix implemented — keyed on the signature, refined from the literal tuple

Implemented the replay record key in `AAuthVerificationMiddleware` and removed all
temporary diagnostics (the PS-mapper `DIAG*` logs + the Concierge request/boot
probes).

**Deviation from the planned key.** The plan first specified the spec's literal
example tuple `(key-thumbprint, created, @method, @authority, @path)`. Building it
that way broke 6 tests under the fixed test clock: the tuple omits the carrier, so
the challenge→retry hop (agent token then auth token — same key/created/method/path)
and the conformance row "§jkt-jwt — different jti values both succeed" false-collided
(`CalendarFlowTests` ×5 + `NamingJwtValidationTests.DifferentJti_BothSucceed`).
Refined to key on the **verified signature value** (`key-thumbprint | <Signature>`),
which subsumes the spec tuple *and* binds the covered `signature-key` (carrier), so
distinct carriers/paths never collide while a verbatim captured-signature replay
still does. Revocation stays keyed on the real carrier `jti`.

**Validation.** New `ReplayDetectionMiddlewareTests` (3 rows: reuse-allowed,
exact-replay-rejected, revocation-by-jti). `dotnet build AAuth.slnx` 0/0;
**AAuth.Tests 504**; **AAuth.Conformance 563** (+3); all `call-chain*` e2e specs
pass; full e2e **44 passed / 1 skipped / 0 failed**.

### [2026-06-28] [Phase 10] Docs sweep + internal review (replay fix)

**Docs:** rewrote [replay-detection.md](../../../docs/server/replay-detection.md)
to the signature-keyed model and corrected three cross-refs
([glossary.md](../../../docs/glossary.md), the [docs/README.md](../../../docs/README.md)
API map, [token-issuance.md](../../../docs/server/token-issuance.md)). Swept the
samples: corrected 5 stale "fresh `jti` so replay doesn't trip" comments in
[MissionAgent](../../../samples/MissionAgent/Program.cs) and
[GuidedTour](../../../samples/GuidedTour/TourSession.cs) (behaviour unchanged — the
token refresh now reads as realistic rotation, which is what it always was). Final
invariant greps over `docs/` + `samples/` clean.

**Review subagent (read-only):** APPROVED — no CRITICAL/HIGH. Confirmed the
signature key is a conformant, stronger realization of the spec tuple; exact-replay
still rejected; revocation precedes the replay check and uses the real `jti`; the 3
tests isolate their claims. One **MEDIUM** applied — cross-linked the lightweight
`ParseSignatureCreated` extract to the authoritative `AAuthVerifier.ParseSignatureInput`
so they stay in sync. Two **LOW** notes (the `InMemoryJtiStore` `_seen`/`_revoked`
dictionaries need periodic `Cleanup()` / a TTL store in production) are pre-existing
characteristics of the dev-only in-memory store, already documented — no change.

## Deviations from plan

### [2026-06-27] [Phase 1] Sample DI migration folded into Phase 3 — PROCEEDED (default)

Phase 1 delivers the SDK capability (`AddAAuthResource` now folds in discovery via
`AddAAuthDiscovery`, registers `MetadataClient` + `JwksClient` with a pooled
`SocketsHttpHandler`, and stores complete metadata incl.
`SignatureWindow`/`AccessMode`/`AuthorizationEndpoint`) plus focused DI tests
(`AAuthResourceDITests`: discovery registration, new metadata fields, override
seam). The **sample** DI migration (removing the manual `MetadataClient`/`JwksClient`
/ named-`AddHttpClient` blocks) is deferred to Phase 3, where each of the 5
resource servers is migrated comprehensively (DI + middleware + endpoints) in one
pass — avoiding double-touching the same files. Consequence: the DoD item about
the discovery strings no longer appearing in samples is verified in the Phase 3
migration and the final invariant audit, not in Phase 1. Revert if you want the
sample DI cut over in isolation first.

## Open questions / inputs needed

### [2026-06-27] [Phase 4] Full MockPersonServer `/token` → `MapAAuthPersonServer` migration — BLOCKED (needs your review)

Deferred the hand-rolled `/token` replacement with the mapper. The mapper is
proven adoptable (it already passes `tests/AAuth.Conformance/Person/PersonServerMapperTests.cs`
with `InMemoryPersonPendingStore`), and the gap analysis produced a concrete
`SampleIdentityClaimsAsserter` mapping. I did **not** execute it while you are AFK
because the sample's consent UX is deeply bespoke and intertwined in ways that are
risky to rewrite blind without leaving the suite red (the paramount constraint):

- Three distinct consent/poll surfaces would have to be re-pointed at the mapper's
  `IPersonPendingStore` model: the three-party `/interaction` + `/admin/consent` +
  `/pending` (keyed on `ConsentStore`), the four-party `/federated-pending` relay
  (`FederatedPendingStore`), and the interactive **mission-approval** parking
  (`MissionPendingStore` / `MissionConsentScript` / `MissionPolicyStore`).
- The mission three-gate's in-scope decision (`MissionPolicyStore.IsInScope`) must
  move inside `SampleIdentityClaimsAsserter` (returning `Assert` in-scope vs
  `NeedsConsent` out-of-scope), and the browser consent pages must switch to
  `IPersonPendingStore.MarkAllowed(subject, roles, groups, claims)` / `MarkDenied`.
- This is a large refactor of user-facing consent behavior best validated with you
  able to review the UX, not completed unattended.

What is delivered: the `AddAAuthFederation` seam + sample wiring (above). The
Access Server sample already uses `MapAAuthAccessServer`, so no AS work remains.

**Decision needed:** approve doing the full `/token` migration in a follow-up
(I have the step-by-step plan), or keep the sample's hand-rolled `/token` as the
reference for the bespoke consent UX while the mapper remains the SDK happy-path.

## Open questions / inputs needed (resolved)
</content>
