---
description: Phased plan to fix the draft-11 compliance audit findings, aligned with the SDK API surface consistency conventions.
---

# Implementation plan — draft-11 compliance remediation

- Research, design constraints C1–C13 and collated designs: [research.md](research.md).
- Per-area designs and red-team reviews: [designs/](designs/).
- Rulings Q1–Q32: [implementation-log.md](implementation-log.md).
- Findings being fixed: [2026-09-30-v11-compliance-audit](../2026-09-30-v11-compliance-audit/research.md).
- Conventions this plan must keep:
  [2026-09-29-sdk-api-surface-consistency](../2026-09-29-sdk-api-surface-consistency/implementation-plan.md).

## Goal

Close every confirmed audit finding graded MEDIUM or above:

- SDK: 1 CRITICAL, 15 HIGH, 54 MEDIUM;
- samples: 4 HIGH, 11 MEDIUM;
- docs: 7 HIGH, 30 MEDIUM.

LOW items are fixed where they sit in the same files. Each fix must be
spec-accurate against draft-11 and follow the API-surface conventions. After
this work, the README and `SPEC-VERSION.md` claims are true, and each fixed
finding has a negative-control test that reproduces the audit's adversarial
scenario.

## Guiding principles

- **Spec conformance is paramount; backwards compatibility is not a goal.**
  - Each change is a single coordinated cutover: breaking renames, removals and
    signature changes are expected.
  - There are no `[Obsolete]` bridges, dual overloads or compatibility shims.
  - Deliberate spec exceptions (Q2, Q19) are logged as `PROCEEDED` in
    `implementation-log.md`.
- **API-surface conventions C1–C13 are binding** (see research.md):
  - layered 80/20;
  - R0 ladder;
  - identity once per role;
  - SDK owns mechanics, consumers own policy;
  - typed constants;
  - no consumer HTTP plumbing;
  - async trust policy;
  - serializable stores that warn outside Development.

  A design choice that contradicts a prior API-surface ruling is re-ruled
  explicitly in the log (for example Q1 and Q8), never silently.
- **Fail closed by default.** The SDK enforces MUSTs on its default paths.
  Relaxations are explicit, data- or policy-driven, and logged.
- **Every finding gets a negative control.** The audit's adversarial scenario
  becomes a failing test before the fix and a passing test after, in
  `tests/AAuth.Conformance` unless stated otherwise.
- **Order by risk and dependency.** Cheap and isolated changes come first, the
  highest blast radius mid-stream, and samples and docs trail. Designs that
  share files land in the same phase (research.md, *Cross-design
  constraints*).

## Verification gates (every phase)

These are the API-surface gates (C13), unchanged:

```bash
dotnet build AAuth.slnx -c Release -v q -nologo 2>&1 | grep -E ' error |warn'   # expect nothing
for p in AAuth.Tests AAuth.Conformance AAuth.R3.Tests AAuth.Events.Tests; do
  dotnet test tests/$p -c Release --no-build; done
dotnet run --project tools/ApiSurface -c Release -- . --write                  # review the diff
AAUTH_UPDATE_DOCS_INVENTORY=1 dotnet test tests/AAuth.Tests -c Release --no-build \
  --filter FullyQualifiedName~Documentation_FrozenSurface
dotnet test tests/AAuth.Tests -c Release --no-build \
  --filter "FullyQualifiedName~SnippetCompilationTests|FullyQualifiedName~DocumentationLinkTests"
npm --prefix tests/e2e run typecheck
cd tests/e2e && CI=1 NODE_PATH=./node_modules npx playwright test --reporter=line --retries=0
```

Phases 3, 5, 7, 9 and 13 also run the Keycloak profile (see the
[v11 migration plan](../2026-09-11-aauth-v11-spec-migration/implementation-plan.md)).
Every public API change is reviewed in the `ApiSurface` diff, and every removal
is listed in the phase's log entry.

## Phase 0 — Decision gate and baseline

**Definition of Done**

- [x] Every open question from the 19 designs and 5 red-team reports has a
      ruling (Q1–Q32) in `implementation-log.md`.
- [x] Both UNSOUND red-team verdicts are resolved (Q2 for R16 A04-05, Q10 for
      R11 SDK-11).
- [x] Owner review of Q1 (throughput of the `created` wait) and Q2 (Development
      loopback identifiers) is recorded (owner rulings, 2026-09-30).
- [ ] The upstream issue on the replay tuple and `created` is sent to the spec
      author through the AAuth connector, and the reply is logged. This does
      not block Phase 1.
- [x] The baseline gates are green on the starting commit, and test counts are
      recorded in the log.
- [x] An `ApiSurface` snapshot of the starting commit is recorded for the final
      diff review.

## Phase 1 — Critical and immediate safety fixes (R01, SMP-01, claims)

The CRITICAL finding and the unsafe copy-and-paste guidance land first. The
blast radius is small.

- **R01 (SDK-01, A09-MED-001, A10-02).**
  - Change `AddAAuthResource` to post-configure
    `AAuthVerificationOptions.ResourceIdentifier` from `Issuer`.
  - Delete the token-`aud` fallback in `AAuthVerificationMiddleware`, so
    auth and person JWTs are rejected when no identifier is known.
  - Update the XML docs.
- **DOC-03.** Fix `docs/server/multi-scheme-verification.md:36-44`. Also fix
  `docs/reference/configuration.md:35-43`, which says audience validation is
  skipped.
- **SMP-01 (Q29).** Match the demo admin grant on the exact subject and key
  thumbprint.
- **Claims (Q28).** Correct the README and `SPEC-VERSION.md` pessimistically.
  Put a warning on the unsafe doc patterns that later phases replace: DOC-04
  (Inbox `/authorize`), DOC-06 (R3 without the single-use gate) and DOC-05
  (pass-through interaction codes).

**Definition of Done**

- [x] A negative control shows an auth or person token whose `aud` is resource
      A is rejected at resource B under a bare `UseAAuthVerification()` (401
      `invalid_jwt`).
- [x] A negative control shows that with no identifier configured, an auth or
      person JWT is rejected (401 `invalid_request`).
- [x] Agent-token and generic-scheme verification still pass without an
      identifier.
- [x] A sample test shows `aauth:demo@attacker.example` gets no admin claims.
- [x] The README and `SPEC-VERSION.md` claims match the audit status.
- [x] The gates are green.

## Phase 2 — Signing producer, metadata and identifiers (R13, R16, R17)

These are isolated from PS token issuance. They settle the metadata shape that
later phases consume.

- **R13 (SDK-16, Q1).**
  - `created` is never in the future. On an exact-tuple collision the signer
    waits for the next free second, honouring cancellation. The API-surface
    ASL L933-L939 mechanism is superseded.
  - Emit the `aauth.signing.created_wait` debug log and counter, and document
    the one-identical-request-per-second-per-key behaviour (Q1 owner ruling).
  - A body without `Content-Type` fails closed (A02-HIGH-002).
  - The provider label must match the handler label (A01-M01).
  - Add a typed `AdditionalSignatureComponents` on resource metadata that
    seeds first-request signing (A04-04).
- **R16.**
  - One `UrlKind` validator serves producer option validation (sync at start)
    and the consumer `MetadataClient` (A04-02, A04-03, A07-002 fragments).
  - Strict `AgentId` structure: `+` only as the sub-agent delimiter, with a
    non-empty discriminator (A04-01).
  - Lock down the Development-only loopback exception (Q2 owner ruling):
    - explicit loopback origins only;
    - startup fails when a loopback policy is used in a Production host
      environment;
    - a startup warning lists the admitted origins;
    - a strict-default conformance test.
  - Add AP `EventEndpoint` and `LocalhostCallbackAllowed` (A04-06).
  - The reserved-field validator knows R13's field (Q26).
- **R17.**
  - A typed event-store outcome replaces status codes from stores: 404 on
    exhaustion (A24-03).
  - Body components are required only when a body is present (A24-02).
  - The subscription body is optional (A24-01).
  - Update `samples/EventSupport/SqliteEventStore.cs` (S06-01).
  - The `tests/AAuth.Events.Tests/EventHttpTests.cs` assertion pinned to 429
    changes to 404.

**Implementation Decisions:** Q1, Q2, Q26, Q27 (log).

**Definition of Done**

- [x] A test shows 62 identical-target requests in one second all carry
      `created ≤ now`, and a strict tuple-cache verifier accepts every one.
      Cancellation during the wait sends no request.
- [x] Metadata with an `http`, query or fragment endpoint, or an `http`
      `logo_uri`, fails at startup (producer) and at fetch (consumer).
- [x] `aauth:parent+@ap.example` and a top-level `a+b` are rejected.
- [x] Production egress policy rejects loopback issuers. Development admits only
      the listed loopback origins, with a logged warning. A loopback policy in a
      Production host environment fails at startup. A wildcard or non-loopback
      entry is rejected when the policy is built.
- [x] A delayed signature emits the `aauth.signing.created_wait` counter and a
      debug log. Requests to a different path, host or method are not
      delayed.
- [x] A resource publishing `additional_signature_components` gets them on the
      agent's first request, with no `invalid_input` round trip.
- [x] Events: exhausted → 404, bodyless delivery accepted, empty subscription
      body accepted.
- [x] The gates are green.

## Phase 3 — Verification and challenge core (R14, R02, R03)

These share `AAuthVerificationMiddleware`, `AAuthChallengeMiddleware`,
`TokenVerifier`, `DefaultSignatureKeyResolver` and the composition helpers, so
they land together after R01.

- **R14 (Q22–Q24).**
  - Reject `crit` (SDK-17).
  - Add issuer-key resolution to `ISignatureTokenVerifier` for JWTs without
    `iss`/`dwk` (A01-H01).
  - Zero `exp` skew (A01-M02).
  - Remove `ChallengeOptions.AllowedSignatureKeySchemes` (A03-HIGH-001).
  - One internal `Signature-Error` writer for every 401 (A19-HIGH-001).
  - Pin TLS 1.2/1.3 (A21-TLS-01).
  - Update the Events companion verifier.
- **R02 (Q4; SDK-02 / A09-HIGH-001).**
  - `AAuthResourceOptions.AccessServer` declares four-party, deriving AS-only
    trust plus `dwk=aauth-access.json`. Three-party pins
    `aauth-person.json`.
  - Mixed mode is explicit. `AAuthTrust.Any` combined with `AccessServer`
    fails at startup unless mixed mode is declared.
  - AS responses at the PS are pinned to the AS issuer and access metadata
    (A17-002).
  - Add `AAuthTrustContext.TokenDwk`.
  - Fix docs D09-01 and D10-05 (open trust presented as the default without the
    four-party caveat).
- **R03 (Q25, Q3).**
  - Add a `PersonTokenRequired` gate for `MapAAuthAuthorizationEndpoint`, with
    `requirement=person-token` when the token is missing (SDK-08).
  - Typed request with an R3 extension seam (SDK-18).
  - `AgentTokenRequired` accepts only agent tokens (A07-001, A09-MED-002).
  - Non-JSON → 400 (A09-HIGH-003).
  - `BuildResourceTokenAsync` rejects agent assertions (A08-03).
  - Untrusted issuer → 401 `invalid_key` (A03-HIGH-002, Q3).
  - Inbox drops `/authorize` (SMP-04); fix DOC-04.

**Implementation Decisions:** Q3, Q4, Q22–Q25.

**Definition of Done**

- [x] A JWT with `crit:["x"]` is rejected for every token type.
- [x] A companion `jwt` without `iss`/`dwk` verifies through the new seam.
      An expired companion token is rejected with zero skew.
- [x] Every SDK 401 carries `Signature-Error`. An unsupported scheme also
      carries `Accept-Signature-Scheme`. No 403 carries either.
- [x] Four-party: a PS-issued auth token (`dwk=aauth-person.json`) with valid
      `aud`/`scope` is rejected, and an AS-issued one is accepted.
      Three-party: an AS-`dwk` token from an unrelated AS is rejected.
- [x] The PS rejects an AS response token verified through `aauth-person.json`.
- [x] The authorization endpoint challenges agent-token and auth-token callers
      with `requirement=person-token`. An R3 `r3_operations` body without
      `scope` is routed to the extension.
- [x] An `AgentTokenRequired` endpoint challenges person-token and auth-token
      callers.
- [x] An untrusted issuer gets 401 `invalid_key`.
- [x] The TLS 1.2/1.3 pin is asserted on the SDK handler.
- [x] The gates, including Keycloak, are green.

## Phase 4 — Deferred polling and error tables (R11)

- An internal poll core is shared by `DeferredPoller` and `ChallengeHandler`.
  It honours `Retry-After`, the default interval, and `429 slow_down` +5 s
  (SDK-11).
- It returns requirement-bearing responses so `ChallengeHandler` can
  re-exchange and resume the same `Location` (Q10).
- Closed-table helpers for polling and token-endpoint errors (Q9):
  - `invalid_code` → 410 (SDK-12);
  - held `expired` → 408, then 410 (SDK-13);
  - unknown pending id → 410 `invalid_code`;
  - remove the invented codes (A19-HIGH-003, A19-HIGH-004);
  - handle `Retry-After: 0` (A14-MED-004).
- Fix doc D07-05 (a sample pending endpoint that uses `unknown_pending` 404).
- Update the emitters in the PS, the AS, `HeldInvocations` and
  `ResourceManaged`.
- Queue the D10-02 claim fix (202 delivery and polling) for restoration in
  Phase 12.

**Implementation Decisions:** Q9, Q10.

**Definition of Done**

- [x] Deferred auth-token polling waits for `Retry-After`, backs off on 429,
      and never treats 429 as terminal.
- [x] A regression test covers a pending GET that returns a fresh
      `requirement=auth-token` resource token: the agent re-exchanges and
      finishes at the same `Location`.
- [x] A test enumerates every SDK emitter and finds only registered codes with
      their registered statuses. `grep` finds none of `unknown_pending`,
      `unknown_interaction`, `request_withdrawn`, `untrusted_person_server`,
      `untrusted_access_server` or `policy_error` in `src/`.
- [x] The gates are green.

## Phase 5 — Token inventory, revocation guard, provenance and chaining (R06, R05)

This phase has the highest blast radius. It defines the single inventory model
(Q5) that Phases 6, 7 and 9 build on.

- **R06.**
  - Add typed source dependencies, replacing the `SourceTokens` break (C1).
  - Add a guarded outbound primitive (Q7) around the four-party
    `FederateAsync` and the local mint (SDK-05).
  - A pending request whose dependency is revoked ends with `revoked` and a
    `detail` (A20-002).
  - A revoked auth token's 401 adds `requirement=person-token` (A20-003).
  - Scope step-up: `RequireAAuth(scope:)` answers `401 requirement=auth-token`
    with a new resource token (Q8, closing ASL L954-L959).
- **R05.**
  - Provenance records in `IJtiStore`, written atomically, pruned at
    `exp + skew`, with per-agent quotas.
  - A PS upstream step-4 primitive inside `AgentIssuanceContext` that fails
    closed on a missing record (SDK-04).
  - Every PS-issued and federated auth token records provenance.
  - A call-chaining interaction module lets intermediaries mint their own code
    and `Location` (A18-003).
  - Reshape `AAuthInteractionChainedException`.
  - Concierge (SMP-03), `SampleApp` `CallChain.razor`, and docs DOC-05 and
    D07-02.
- Docs D03-02 (the `replay-detection.md` re-check claim) and D10-01 (the
  revocation cascade claim) become true here and are restored in Phase 12.

**Implementation Decisions:** Q5, Q7, Q8.

**Definition of Done**

- [ ] A person token revoked while a four-party request is pending is never
      sent to the AS (spy AS). The agent then sees `403 revoked` with a
      detail.
- [ ] A revocation that races the send is cancelled through the linked token.
- [ ] An upstream AS auth token with no PS provenance record is rejected with
      `invalid_upstream_token`. A matching record plus a revoked
      binding/agent token is rejected with `revoked_upstream_token`.
- [ ] Provenance is pruned at `exp + skew`, and a quota breach answers 429
      before minting.
- [ ] An intermediary re-emits `202 requirement=interaction` with its own code
      and `Location`, then completes the original request.
- [ ] Insufficient scope on a valid auth token gets 401 with a new resource
      token. The agent steps up and retries.
- [ ] The gates, including Keycloak, are green.

## Phase 6 — R3 single use, audit and entitlement (R04)

- `R3Enforcement` returns an execute-once `SingleUse` handle keyed by
  `(iss, jti)`, shared with the 202 held path (Q6, SDK-03).
- `R3TokenIssuanceAuditRecord` gains `ps`, `sub` and `agent_jkt` (SDK-19).
  Update the `SqliteR3AuditSink` schema.
- Per-token, expiring, URI-bound document entitlement for both the AS and the
  PS (A23-003, API-surface Q12).
- Authoritative operation validation before minting (A23-004).
- Duplicate bare operation ids are rejected (A22-MED-001).
- Fix DOC-06 and D07-04 (R3 document shape: `vocabulary` is required), the R3
  README, and the Bookings and Catalog samples. The D10-04 claim is restored
  in Phase 12.

**Implementation Decisions:** Q6.

**Definition of Done**

- [ ] Replaying a per-call auth token with identical parameters returns the
      retained result without re-executing. The 202 and 401 paths share the
      key.
- [ ] A missing gate, `jti` or `exp` yields `single_use_required`.
- [ ] The audit record contains `ps`, `sub` and `agent_jkt`.
- [ ] A configured AS cannot fetch an R3 document not named by a resource
      token it received.
- [ ] Minting fails for an operation absent from the authoritative definition,
      and for ambiguous bare ids across merged definitions.
- [ ] The gates are green.

## Phase 7 — PS identity, missions and clarification (R10, R09, R08)

These share the PS core and the pending lifecycle gate, so they are applied as
one critical-section design (RT-3 conflict 3).

- **R10 (Q14, Q15).**
  - Add `AAuthPersonKey`.
  - Add `IAgentPersonBindingStore` with an atomic bind-or-verify (SDK-07).
  - Add the HMAC pairwise-`sub` key ring (A11-03).
  - First-issuance enrollment with a metadata fetch (A11-04).
  - Governance `ps` check, scoped to governance only (A15-002).
  - The sample asserter adds the issuer to SMP-01.
- **R09 (Q13).**
  - Key `IMissionStore` by `(PS, s256)`.
  - Add `TerminateAsync(reason)`.
  - One `MissionStatusEvaluator` on every path, including pending and
    federated ones (SDK-14, A16-001, A16-003).
  - Uniform `mission_not_found` (A16-004).
  - Update the `MissionGovernance.cs` sample and docs D04-002, D05-02, D08-05
    and D10-03.
- **R08 (Q11, Q12).**
  - One `ApplyUpdatedRequestAsync` recomputes bounds and sources (SDK-06).
  - A shared platform/device/capabilities validator, with capability
    constants moved to `AAuthConstants` (A12-02, A12-03, A13-05).
  - A central clarification round counter, including triage (A12-04).
  - An agent-side `timeout` deadline (A13-02).
  - Local pre-validation of the replacement pair (A13-03).

**Implementation Decisions:** Q11–Q15.

**Definition of Done**

- [ ] A second person key for the same agent is denied until the binding is
      revoked. A binding-store failure denies the request with no token or
      claims emitted.
- [ ] The default `sub` differs across two resources and stays stable across
      signing-key rotation. HMAC key rotation keeps existing subjects.
- [ ] A mission past `expires_at` gets `403 mission_terminated` with
      `termination_reason=expired` on the pending, federated, person and
      governance paths.
- [ ] Completion records `completed`.
- [ ] Absent, foreign-agent and foreign-PS missions produce identical
      responses (spy-store contract test).
- [ ] An `updated_request` with a shorter-lived or revoked replacement bounds
      or denies the grant. A longer-lived replacement recomputes the ceiling.
- [ ] Triage rounds count toward the cap.
- [ ] `platform:"evil-os"`, a control character in `device`, and
      `capabilities:"x"` all get 400.
- [ ] The agent suppresses a late clarification POST.
- [ ] The gates, including Keycloak, are green.

## Phase 8 — Governance endpoints (R12)

- `.WithGovernance()` declares the paths once, and `MapAAuthPersonServer()`
  auto-maps them. The primitive `MapAAuthGovernance()` fails fast on
  conflicts (SDK-10, Q16).
- Relay results are mutually exclusive: 202 + `Location` or 424. The default
  relay is `Unavailable` (SDK-09).
- Strict JSON objects for `parameters` and `result` (A15-004).
- The audit log keeps `parameters` and `result` (A15-005).
- Replace the sample `/mission-interaction` handler with the SDK mapper
  (SMP-02).
- Update DOC-07, D05-01 and D05-03.

**Implementation Decisions:** Q16.

**Definition of Done**

- [ ] PS metadata `interaction_endpoint` equals the mapped governance relay
      route, and is omitted when governance is off.
- [ ] The default relay answers 424 `interaction_unavailable` for
      `interaction`, `payment` and `question`. A relay returning `Pending`
      answers 202 with `Location`, `Retry-After` and `no-store`.
- [ ] Non-object `parameters`/`result` (including `null`) get 400. Audit
      entries keep both objects.
- [ ] A conflicting manual `MapAAuthGovernance` path fails at startup.
- [ ] The gates are green.

## Phase 9 — Federation: collapse and payment (R07)

- An explicit PS-AS collapse declaration runs internal AS policy evaluation and
  mints `dwk=aauth-access.json`. A misconfiguration fails closed (A17-001).
- An `IAAuthPaymentSettler` seam and a billing cache drive a 402 loop composed
  with 202 steps, wrapped by the Phase 5 guard (A17-003, A19-HIGH-005). With
  no settler, the result is `403 denied` (Q17).
- Enforce the claims `sub` rule on the AS and the PS (S04-01).
- Update D06-02 and the Keycloak and stub policies.

**Implementation Decisions:** Q17.

**Definition of Done**

- [ ] A declared collapse produces an AS-verdict token with
      `dwk=aauth-access.json`. A declared collapse with its linked AS missing
      fails closed.
- [ ] 402 → settle → poll → 202 claims → 200 completes. With no settler, the
      result is 403 `denied` with a detail. The settler never receives a JWT.
- [ ] An AS requesting `sub` in `requirement=claims` is rejected, and the PS
      never sends `sub`.
- [ ] The gates, including Keycloak, are green.

## Phase 10 — Agent client behaviour (R15)

This comes after Phases 2–4 and 7–8.

- Remove automatic two-key refresh (Q18, SDK-15).
- Pass `login_hint` through unchanged (A08-02, A13-01).
- Verify returned auth tokens by default, through the shared `JwksClient`
  (Q20, A10-01).
- Apply the five-minute margin to cached person and auth tokens (A06-02).
- Cap producer lifetimes at 24 h (Q19, A05-02, A06-03).
- PS-first relay of resource-response interactions (Q21, A13-04, A07-004).
- Strict `AAuth-Access` handling (A07-003).
- Union mission capabilities and serialize capabilities as an SF List
  (A07-005, A07-007).
- Add `AAuth-Capabilities` on tour requests (S09-02, via Phase 11).

**Implementation Decisions:** Q18–Q21.

**Definition of Done**

- [ ] The `TwoKey` refresher mode is gone from the API surface. The
      `RefreshTwoKeyAsync` rebuild example compiles in a snippet test.
- [ ] The resource-token `login_hint` reaches the PS body byte-for-byte.
- [ ] A PS returning an auth token with the wrong `typ` or a bad signature is
      rejected by default.
- [ ] A cached carrier within five minutes of `exp` is refreshed, not
      presented.
- [ ] `WithLifetime(25h)` throws, and a 25 h AP token logs a warning.
- [ ] A resource interaction is POSTed to the PS first. On 424 the agent falls
      back to the user.
- [ ] Two `AAuth-Access` headers reject the response.
- [ ] The gates are green.

## Phase 11 — Samples sweep (R18)

Sample-only fixes, plus sample rows owned by earlier phases that were not
already landed:

- the tour's generic Signature-Key lessons are labelled and limited to
  `RequireGenericSignature()` (S07-01, Q31);
- same-origin pending `Location` via the SDK (S08-01);
- the tour and Concierge use the SDK poller (S08-02, S08-03, S09-01);
- the Concierge pending shape (S05-002);
- resource revocation surfaces (S03-02, S03-03);
- Keycloak `sub` filtering (S04-01);
- `AAuth-Capabilities` in the tour (S09-02);
- credential redaction (Q32);
- all sample LOW prose.

**Definition of Done**

- [ ] Every Phase 3 samples finding in the audit is either closed here or
      closed by its owning phase (checklist in the log).
- [ ] No sample hand-rolls polling, and none signs requests to a cross-origin
      `Location`.
- [ ] The e2e specs are updated for the changed wire behaviour: 424 relay,
      step-up, person-token authorization and 404 events.
- [ ] The gates, including full Playwright `--retries=0`, are green.

## Phase 12 — Docs sweep and claim restoration (R19)

- Rewrite `docs/getting-started.md` to the draft-11 flow (DOC-01). The
  sequence is:
  1. agent token;
  2. `requirement=person-token`;
  3. person token;
  4. resource token with `presented_jti`;
  5. PS request carrying `resource_token` and `presented_token`;
  6. auth token.
- Signing-modes docs: jwt-only for AAuth agents. Generic schemes are labelled,
  and `jkt-jwt` is described as the AP refresh ceremony (DOC-02, D02-02, Q31).
- The five access modes and current terminology (D01-01, D02-03, D10-06).
- Doc MEDIUM and LOW items: D01-04, D03-03, D03-04, D04-001, D06-04, D06-05,
  D08-01, D08-02, D08-03, D10-07 and D06-03.
- Every "update after Rnn lands" row in R19.
- Regenerate the docs inventory. Every rewritten fence is compilable
  (`SnippetCompilationTests`).
- Restore the positive README and `SPEC-VERSION.md` claims only for areas whose
  owning phase DoD is ticked (Q28). The remaining deliberate deviations, Q2 and
  Q19, are listed in `SPEC-VERSION.md`. The Q1 same-second limitation is
  documented there too, with a link to the upstream issue once it is filed.

**Definition of Done**

- [ ] Every Phase 4 docs finding in the audit is closed (checklist in the
      log).
- [ ] The snippet, link and docs-inventory gates pass.
- [ ] Every README and `SPEC-VERSION.md` claim cites a passing conformance test
      class.

## Phase 13 — Independent internal review and re-audit

- A fresh `rubber-duck` agent reviews the work against research.md, this plan,
  C1–C13 and the spec rows each phase cites. Findings are graded P0–P3.
- Re-run the adversarial audit agents for the areas with CRITICAL or HIGH
  findings: A02, A05, A06, A09, A11, A12, A14, A15, A16, A18, A20, A22, A23.
  Each runs against the new code, with its original brief.

**Definition of Done**

- [ ] The review report is recorded in the log, and every P0/P1 is fixed or
      ruled.
- [ ] The re-audit finds no CRITICAL or HIGH in the re-run areas.
- [ ] The final gate run is green, including Keycloak and full Playwright
      `--retries=0`.
- [ ] The `ApiSurface` diff has been reviewed against the Phase 0 snapshot, and
      every removal is intentional and listed.

## Out of scope

| Item | Reason |
|---|---|
| Local TLS / host-alias topology for samples and e2e | Q2 keeps the Development-only loopback exception; a strict local topology is a separate initiative |
| Payment protocol implementations (x402, etc.) | Only the `IAAuthPaymentSettler` seam and the 402 loop are in scope (Q17) |
| Durable store implementations (EF Core, Redis) for new seams (binding, provenance, retained results) | Seams only; in-memory defaults warn outside Development (C12) |
| Budgets draft, `accept_signature_algs`, x509/cached schemes, `aauth-resource` link relation | Still not implemented; claims stay accurate (`SPEC-VERSION.md`) |
| Upstream spec changes (a nonce for replay, a payment polling code) | Q1 and Q17 rulings work within draft-11. Upstream issues may be filed separately |
| Agent Provider server endpoints | Out of scope per API-surface Q17 |
| AAuth #199 agent-token error codes | Upstream decision; unchanged |
