---
description: Phased implementation and verification of the AAuth v10 migration.
---

# Implementation Plan - AAuth v10 repository migration

Companion to [research.md](research.md), created 2026-09-08. This plan covers the
current SDK, R3, the missing Events capability, runnable examples, tests, and
documentation. The owner approved autonomous implementation on 2026-09-08;
decisions and deviations are recorded in [implementation-log.md](implementation-log.md).
Historical v09 plans remain unchanged; this initiative
reassesses their exclusions rather than treating them as current scope rulings.

## Guiding principles

- Spec conformance over backward compatibility: one coordinated alpha cutover,
  no old-wire fallbacks, obsolete aliases, or dual-format parsers.
- Requirement strength matters. Optional capability exclusions are explicit;
  enabled capabilities satisfy their conditional MUSTs. Spec ambiguities receive
  recorded rulings rather than invented requirements.
- Verification results represent checks actually performed. Parsed claims are
  not authenticated identities; proof of key possession is not issuer trust.
- Preserve working controls: byte-exact hashes, key/audience binding, scope
  narrowing, per-signature replay, and fail-before-release audit behavior.
- Every code phase updates its compiled sample callers and directly coupled
  fixtures, keeping the solution buildable. The final docs sweep also checks
  string-literal snippets, Razor explanations, diagrams, and browser assertions.
- SampleApp and GuidedTour are primary migration deliverables. When a phase
  changes an auth flow, update both apps' affected numbered steps, sequence
  visuals, embedded C#/JSON/HTTP snippets and step-dependent tests in that phase.
  Navigation, approval/polling indices, payload selection and completion counts
  must remain synchronized. Phase 13 checks the finished apps; it does not defer
  fixes to their executable walkthrough behavior.
- Every new user-facing capability needs a runnable scenario in both apps,
  either a clearly identified extension of an existing flow or a new selectable
  flow when none fits. A console example, SDK test or documentation paragraph
  alone does not satisfy this requirement. Each new flow needs Playwright tests
  in both app projects using the existing harness and helpers.
- Sample resource code is instructional too. Prefer a small, single-purpose
  resource with one clear use case; reuse an existing resource only when the new
  behavior belongs naturally to that purpose. Add a resource selectively when
  reuse would turn a focused example into a collection of unrelated features.
  Follow the existing resource projects; avoid one server per test variation,
  unnecessary services, or abstractions that hide the protocol being taught.
- Recheck cited lines against the pinned v10 snapshot before implementation.
  Research findings marked R receive direct reproduction before a fix is designed.
- Decisions, deviations, and scope rulings are appended to the implementation
  log when work begins. No package upgrade, branch merge, or commit is implicit.

## Verification strategy

Each phase starts with a focused failing regression for its confirmed defects,
then checks positive behavior. Existing passing tests are not independent v10
evidence when their fixtures reproduce the old contract. Use real HTTP handlers
and captured-wire assertions where producer/consumer agreement could hide a bug.

At phase boundaries run the touched test classes and `make build`. At shared
contract boundaries run the complete affected test projects. Final release gates:

```bash
make build
make test-unit
make test-conformance
dotnet test tests/AAuth.R3.Tests/AAuth.R3.Tests.csproj
dotnet test AAuth.slnx -c Release
make e2e
```

After the Events project exists, add it to the solution and run its test project
explicitly as well. The current `test-unit` and `test-conformance` targets do not
include R3 or Events. CI already uses solution tests; retain that wider gate.
Run Playwright with fresh services (`CI=1` for no service reuse), and exercise
both stub and Keycloak policy modes. The Keycloak job needs its configured
container/realm and `KEYCLOAK_E2E=1`; the ordinary stub run does not establish it.
Live external interop needs reachable HTTPS metadata and external availability;
record an unavailable environment as unverified, never a pass.

## Phase 0 - decisions and baseline gate

Resolve Q1-Q10 in [research.md](research.md#gaps-and-open-questions) before code.
Create the implementation log at that point with Decisions Taken, Deviations
from Plan, and Open Questions sections; record dated `PROCEEDED (default ...)`,
`RESOLVED`, or `BLOCKED` entries. Proposed defaults are not pre-approved rulings.

Phase rule: exact v10 contracts, no compatibility shims. Any exception requires
an explicit logged decision.

### Responsibilities

- Q1: confirm optional capability scope. Default includes account binding, all
  eight R3 vocabulary models, AS clarification, Events, self-jwt, and direct jwks.
  X.509/cached remain explicit exclusions unless the owner selects them.
- Q2-Q5: settle PS-AS signing, strict production/development separation, R3 PS
  readership, and Events recurring-event/payload ambiguities using cited clauses.
- Q6: decide durable store contracts and a transactional sample backend. Inspect
  existing branch work before selecting/pinning a persistence package.
- Q7-Q8: approve authenticated consent/session design and agent-expiry/context
  propagation without inventing an associated-token lookup at resources.
- Q9: read existing Events work from `feat/aauth-events-implementation` without
  checkout/merge; inventory reusable files/tests. No wholesale merge is implied.
- Q10: evaluate a maintained structured-fields/signature parser against labels,
  escaping, parameter types, and extra covered components; document exact package
  choice or a justified retained implementation. Keep crypto packages unless a
  demonstrated blocker requires changing them.
- Record the implementation baseline commit and tree state, source hashes,
  discovered projects, and full current test/e2e results. Make a requirement-to-
  test ledger covering the research's unreviewed policy boundaries as well.

### Definition of Done

- [x] Every Q1-Q10 has a recorded ruling in the implementation log.
- [x] Optional capabilities and ambiguous clauses have explicit dispositions.
- [x] Every research finding has a phase and a planned discriminating check.
- [x] Baseline failures and unavailable environments are recorded separately.
- [x] The implementation scope and plan are approved before SDK edits.

Phase 12 reconciliation (2026-09-09): Q1-Q10 and execution authorization were
already recorded on 2026-09-08; the finding-to-phase table and discriminating
checks are present. These checkboxes now reflect that evidence. A complete
pre-edit full-suite/browser baseline cannot be reconstructed from later passing
gates, so the baseline item remains open as a historical evidence limitation.
Later Phase 11/12 verification does not rewrite the original baseline.

Final evidence reconciliation (2026-09-09): the baseline item above requires
separate recording of failures and unavailable environments, not reconstruction
of a run that never happened. The log records the 1129-test pre-edit solution
gate and explicitly identifies the unavailable pre-edit browser baseline. The
item is closed on that recording basis; no missing browser run is claimed.

## Phase 1 - shared problem-details cutover

Findings: F11, the error portion of F30/F31. No code-phase dependencies.
Target: protocol [L2304](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2304)
(`#error-response-format`).

Phase rule: `detail` only, no `error_description` fallback or public alias.

### Implementation Decisions

- [x] Shared result/writer and breaking `Detail` rename approved; preserve status,
  headers, success contracts, and callbacks. Normalize application-defined AP
  errors for consistency. See the dated Phase 1 decision in
  [implementation-log.md](implementation-log.md).

### Responsibilities and files

- Introduce a common AAuth problem-details result/serialization contract under
  [src/AAuth/Server](../../../src/AAuth/Server/) with required `error`, optional
  `detail`, correct media type, and supported extension members.
- Update [TokenExchangeClient](../../../src/AAuth/Agent/TokenExchangeClient.cs),
  [AccessServerClient](../../../src/AAuth/Access/AccessServerClient.cs), and
  [errors](../../../src/AAuth/Errors/) public description properties.
- Migrate every actual producer discovered by pattern, including PS/AS endpoints,
  DI middleware, governance, revocation, resource-managed interactions, and R3
  helper/results. Do not change success media types or conflate signature errors
  with AAuth problem `type` values.
- Update compiled MockAgentProvider/LiveWhoAmITest/other consumers under the
  approved consistency ruling. Bootstrap's application-defined HTTP errors are
  not misreported as a normative Bootstrap protocol.

### Definition of Done

- [x] Real endpoint tests assert status, media type, `error`, `detail`, and
  endpoint extensions for representative PS/AS/R3/governance/revocation errors.
- [x] Clients use `error` for behavior regardless of RFC 9457 `type`.
- [x] No old wire/API description remains in migrated producers/consumers.
- [x] Success responses, auth challenges, and callbacks remain correct.
- [x] Focused tests, affected test projects, and solution build pass.

## Phase 2 - issuance bounds and reserved claims

Findings: F10, reserved-claim part of F19. Depends on Phase 1.
Target: protocol [L1344](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1344)
(Agent Token Lifecycle) and [L1708](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1708)
(Auth Token Structure).

Phase rule: exact validated issuance inputs, no legacy unbounded overload.

### Implementation Decisions

- [x] Required validated agent-expiry input, conservative delegation ceilings,
  and shared reserved-claim guard approved for this alpha cutover. See the dated
  Phase 2 decision in [implementation-log.md](implementation-log.md).

### Responsibilities and files

- Extend [AuthTokenBuilder](../../../src/AAuth/Tokens/AuthTokenBuilder.cs) and
  relevant verified-token/request contracts to retain source expiry ceilings;
  keep positive lifetime and one-hour validation independently testable.
- Carry verified agent expiration through [PS endpoints](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs),
  [AS endpoints](../../../src/AAuth/Access/AAuthAccessServerEndpoints.cs), both
  pending stores, R3 minting, and response delivery. Bind sub-agent issuance to
  the correct verified child context and the Phase 0 ruling on parent/upstream
  ceilings. Reject expiry reached during consent rather than minting a fresh hour.
- Derive `expires_in` from the issued token, not a hard-coded 3600.
- Validate reserved claim names independent of which optional claims were
  populated. Apply the same rule to requested claims and projected AS responses.
- Fix compiled builders and sample issuance at the same time.

### Definition of Done

- [x] Immediate and deferred two-minute-agent tests never yield a later auth exp.
- [x] Already-expired, zero/negative lifetime, and parent/child boundary cases fail.
- [x] `expires_in` matches actual expiry in direct and deferred responses.
- [x] AdditionalClaims cannot inject unset protocol-owned claims; legitimate
  identity extensions still work.
- [x] Core/conformance/R3 tests and solution build pass.

## Phase 3 - signature carriers and typed verification

Findings: F01-F07, F28 self-jwt/jwks, signing part of F31. Depends on Phases 1-2.
Target: protocol [L2409](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2409)
(`#signature-algorithms`), [L2478](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2478)
(`#verification`), Signature Keys [L641](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L641)
(3.4), [L964](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L964)
(3.6), and [L1222](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L1222)
(3.9).

Phase rule: old carrier encodings and `EdDSA` are rejected, not supported in parallel.

### Implementation Decisions

- [x] Autonomous Phase 3 only, no compatibility, delegation, commits or branch
  changes. Probe StructuredFieldValues 0.7.7 before runtime integration; retain
  current crypto. See the Phase 3 entry in [implementation-log.md](implementation-log.md).

### Responsibilities and files

- Update [Crypto](../../../src/AAuth/Crypto/) export/import validation and key
  factory dispatch. Require fully specified `alg`, key-type/curve consistency,
  public-only wire material, and correct unsupported-versus-invalid errors.
  Preserve RFC 7638 thumbprints and current Ed25519/ES256 cryptographic operations.
- Update [SignatureKeyHeader](../../../src/AAuth/HttpSig/SignatureKeyHeader.cs),
  [SignatureKeyParser](../../../src/AAuth/HttpSig/SignatureKeyParser.cs), providers,
  signer/verifier, and resolver: standard hwk members; jwks_uri id/dwk/kid;
  separate direct jwks; self-jwt without cnf. Use selected dictionary labels and
  a structured-fields model capable of required parameter types.
- Use `IAAuthKey` throughout JWT confirmation parsing and affected endpoint
  contracts. Test every advertised algorithm across supported schemes.
- Separate untrusted parsing, admitted key resolution, JWT validation, HTTP
  verification, and endpoint authorization. Report issuer verification only
  after the correct token-type verifier succeeds. Reject unsupported types by
  default; add explicit companion-verifier registration for Events later.
- Enforce naming-JWT header algorithm, required iat/exp, future/expired checks,
  and durable-to-ephemeral binding in one shared path used by MockAgentProvider.
- Honor signature expires/keyid rules, ignore signature alg on verification and
  omit it on signing. Support negotiated additional covered components without
  treating optional content-digest as a universal AAuth mandate.
- Replace exception-message classification with typed errors. Emit
  Accept-Signature-Scheme/Alg correctly; reject unknown schemes deterministically,
  including malformed parser input. Enforce AAuth versus generic signing policy.
- Apply Q2 to PS/AS server signers and R3 document fetchers; do not copy the stale
  protocol jwks_uri example. Fix compiled sample providers and fixtures in-phase.

### Definition of Done

- [x] Independent wire vectors for jwt, hwk, jkt-jwt, jwks_uri, jwks, self-jwt
  pass with Ed25519 and supported ES256 combinations.
- [x] Missing/polymorphic/symmetric/prohibited alg and alg/kty/crv mismatch fail;
  a valid selected JWKS member survives unrelated unsupported members.
- [x] Wrong typ, forged issuer with a valid PoP signature, forbidden self-jwt cnf,
  missing/future/expired naming claims, and expired signature expires fail.
- [x] Matching labels, additional signatures, escaping, malformed members, and
  unknown schemes produce the required result, not an uncaught exception.
- [x] AAuth failures use 401; authorization 403 has no signature error/negotiation
  headers. Generic Signature Keys status policy remains separately tested.
- [x] Old hwk/jwks_uri shapes and removed error members are absent from active
  producers/consumers and rejected by negative fixtures.
- [x] Core/conformance/R3 tests and build pass with all compiled consumers updated.

## Phase 4 - admitted discovery and cache behavior

Findings: F08-F09, fetch part of F26. Depends on Phase 3.
Target: protocol [L2517](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2517)
(`#jwks-discovery`) and Signature Keys
[L2372](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L2372) (7.3).

Phase rule: strict production admission; explicit narrow development policy only.

### Implementation Decisions

- [x] Autonomous implementation with pinned connections, explicit injected
  transport contracts, and configured loopback origins approved. Convenience
  builders remain in scope; new contracts are logged for Phase 11 inventory.
  No delegation, commits, checkouts, or specification snapshot edits.

### Responsibilities and files

- Put reusable URL/egress policy under [Discovery](../../../src/AAuth/Discovery/)
  and apply it before metadata/JWKS/R3/pending fetches and interaction redirects
  where the spec requires admission. Validate DNS results and the actual connected
  destination; account for redirects, response size/time, and cross-origin JWKS.
- Update [MetadataClient](../../../src/AAuth/Discovery/MetadataClient.cs),
  [JwksClient](../../../src/AAuth/Discovery/JwksClient.cs),
  [AAuthUrl](../../../src/AAuth/AAuthUrl.cs), DI HTTP handlers and R3 fetches.
  Validate identifier syntax before canonicalizing URI APIs can hide differences;
  return distinct issuer_missing/issuer_mismatch results.
- Enforce one fetch-attempt floor per URI across cold/expired/unknown-kid/same-kid
  and failed requests, with concurrency coordination and bounded caches.
  Retain valid stale fallback/backoff and maximum-age behavior per policy.
- Thread explicit loopback development configuration through every sample host
  and TestHost fixture; never globally disable network admission to get tests green.

### Definition of Done

- [x] DNS/private/link-local/loopback, redirect-to-private, mixed-address,
  cross-origin, oversized-body and timeout tests exercise real handler boundaries.
- [x] Missing/mismatched issuer and invalid identifier syntax fail before trust.
- [x] Parallel cold fetches and failed fetches honor the same one-minute floor.
- [x] Unknown-kid/same-kid rotation still succeeds after the allowed interval.
- [x] Explicit dev fixtures pass; production defaults reject their HTTP URLs.
- [x] Discovery/R3 targeted tests, affected projects, and build pass.

## Phase 5 - consent and deferred state machines

Findings: F12-F15, AS clarification capability. Depends on Phases 1-4.
Target: protocol [L1054](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1054)
(`#agent-response-to-clarification`), [L2136](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2136)
(Interaction Code Format), [L2825](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2825)
(Deferred Response Security).

Phase rule: explicit action and verified owner context, never legacy payload inference.

### Implementation Decisions

- [x] Autonomous full Phase 5 authorized, including AS clarification and both
  primary apps. Separate single-use correlation from authenticated, CSRF-protected
  decisions under Q7; preserve fluent API work for Phase 11 and inventory new
  contracts here. No delegation, commits, branch changes, or compatibility paths.

### Responsibilities and files

- Fix [Person endpoints](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs),
  [Access endpoints](../../../src/AAuth/Access/AAuthAccessServerEndpoints.cs),
  pending stores, and resource-managed interactions to require authenticated
  owner/key context on every poll, clarification update, and cancellation.
- Separate browser correlation-code state from the authenticated decision
  session. Normalize Crockford input, consume atomically, bound attempts, retain
  expired/consumed/terminal tombstones long enough to return the required errors.
  Choose abuse keys for malformed codes without enabling arbitrary interaction
  lockout; record that operational policy.
- Make terminal delivery atomic and one-time; subsequent polls return 410.
  Do not revoke reusable auth tokens or consume a legitimate decision session
  merely because the browser used its correlation code.
- Add action-based dispatch to [ClarificationExchange](../../../src/AAuth/Agent/ClarificationExchange.cs)
  and both enabled receivers. Validate replacement iss/agent/key against stored
  originals and replace scope/request context before re-consent. Preserve DELETE.
- Complete AS clarification production, PS triage/relay, resumption and
  cancellation using existing claims/deferred abstractions without conflating
  ordinary claims POSTs with clarification actions.
- Protect browser decisions in MockPersonServer, Federated AS and R3 consent.
  Make stub-only approval unavailable in Keycloak mode; authenticate the user,
  bind pending requests to the decision session, and enforce CSRF protection.
- Update TourSession, SampleApp, consent helpers, and directly affected e2e
  assertions alongside the state machine.

### Definition of Done

- [x] Foreign-owner GET/POST/DELETE and forged same-sub/different-key attempts fail.
- [x] Missing/unknown/mismatched action returns 400; malformed or differently bound
  replacement tokens fail; valid narrowed replacements affect the issued token.
- [x] Code aliases, reuse, expiry, attempt limits, concurrent approval, denial
  reversal, terminal replay, and cancellation have end-to-end HTTP tests.
- [x] Keycloak cannot be bypassed through stub approve/deny endpoints.
- [x] AS clarification works through the PS to the agent and back, with bounded
  polling, timeout, denial and cancellation behavior.
- [x] Relevant integration/conformance/e2e suites and solution build pass.

Available gates passed: `make build`, Release solution tests (1412/1412), and
fresh-service no-retry browser tests (49 passed, one Keycloak-only skip).
The final gate remains open for live Keycloak mode: the configured realm at
localhost:18080 was unreachable. In-process Keycloak flow and bypass tests
passed 7/7; they do not replace live IdP validation. See
[implementation-log.md](implementation-log.md) for exact evidence and failures.

Adversarial repair gate (2026-09-09): the reported GET lockout, mixed 202
dispatch, re-consent/code generation, operation-failure lifecycle, identity
binding and demo/retention boundaries have local tested dispositions in the
log. Final Release tests pass 1573/1573 (817 core, 703 conformance, 53 R3);
fresh-service no-retry browsers pass 49 with one Keycloak-only skip and no
failures/flaky tests. The full-environment gate remains open for live Keycloak,
an environment setup follow-up. Phase 6's historical record below is unchanged.

Phase 13 reconciliation (2026-09-09): the preceding paragraphs describe the
original Phase 5 gate, not a current blocker. Phase 12's 2069 Release tests and
68 live/67 stub browser gates, repeated in Phase 13, supersede the unavailable
localhost:18080 environment. Current live verification uses the configured
localhost:8080 realm. Historical log entries remain unchanged.

## Phase 6 - federation and delegation trust

Findings: F17-F19, F20. Depends on Phases 2-5.
Target: protocol [L934](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L934),
[L1511](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1511)
(PS-to-AS Token Request), [L1574](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1574)
(Auth Token Delivery), [L1809](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1809)
(Directed Identifiers Across a Chain), [L2041](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2041)
(`#scopes`).

Phase rule: preserve authenticated context end to end; no placeholder consent grant.

### Implementation Decisions

- [x] Autonomous alpha cutover authorized. Evaluate PS consent independently of
  AS claims negotiation, resume through Phase 5 sessions, preserve verified child
  and upstream context, and validate scopes against published definitions.
  Update both primary apps in-phase; record API additions for Phase 11. No
  delegation, commits, branch changes, or compatibility paths.

### Responsibilities and files

- Evaluate PS consent independently of AS claims negotiation, including immediate
  AS 200 and interaction-only 202-to-200 paths. Existing prior consent may satisfy
  policy; a claims callback must not be the only place the PS makes that decision.
- Gate PS claims release and final grant delivery on Assert/Deny/NeedsConsent.
  Suspend/resume federation through Phase 5; never substitute pairwise-sub as
  authorization. Derive downstream directed identities from authenticated context.
- Carry subagent_token and upstream_token through [AccessServerClient](../../../src/AAuth/Access/AccessServerClient.cs),
  PS/AS endpoint models, pending state and minting. Verify parent relationship,
  child resource/key binding, upstream issuer/audience/mission constraints and
  actor nesting for combined flows.
- Complete [UpstreamTokenValidator](../../../src/AAuth/Tokens/UpstreamTokenValidator.cs)
  structural validation without incorrectly equating the original upstream PoP
  key to the intermediary's current request key.
- Tighten [ActChainBuilder](../../../src/AAuth/Tokens/ActChainBuilder.cs), readers,
  and [AuthTokenResponseValidator](../../../src/AAuth/Tokens/AuthTokenResponseValidator.cs):
  immediate actor, nested context, no person identifiers, independently asserted
  downstream sub. Extend agent delivery checks as well as PS-side checks.
- Validate scope vocabularies before resource-token issuance, with resource
  scope definitions and the applicable PS identity-scope metadata. Keep AS scope
  narrowing and existing legitimate resource binding unchanged.
- Add a runnable four-party parent-mediated sub-agent scenario, including the
  combined upstream chain, rather than treating the three-party fixture as S5.

### Definition of Done

- [x] Deny/NeedsConsent never releases claims or returns a grant prematurely.
- [x] Immediate AS 200 and interaction-only 202-to-200 tests prove PS policy is
  evaluated even without a claims request; deny/consent-needed withhold the grant.
- [x] Three-party, four-party, chained and combined sub-agent cases bind the
  right key/agent and exact actor chain, with distinct actors/keys in fixtures.
- [x] Invalid upstream structure, trust, audience, mission or person-in-act fails.
- [x] Wrong immediate actor is rejected even when nested context matches.
- [x] Unadvertised resource/identity scopes fail; legitimate narrowed scope works.
- [x] Core/conformance/integration tests, compiled interop scenario and build pass.

Available final gates passed: `make build`, 1539/1539 Release solution tests
(core 791, conformance 696, R3 52), and the full fresh-service browser suite
(49 passed, one Keycloak-only skip, zero failures/flaky tests). Both primary
apps execute live distinct-key combined four-party flows. The final gate remains
open for live Keycloak validation: the configured localhost:18080 realm is
unreachable. No gate was moved to a later phase. See the Phase 6 implementation
log for test evidence, failures, repairs, and the Phase 11 API inventory.

Phase 13 reconciliation (2026-09-09): the original live-Keycloak blocker above
is superseded by Phase 12's complete live policy matrix and Phase 13's repeated
68-case live gate, including both distinct-key parent/worker scenarios. This
does not reconstruct Phase 0's missing pre-edit baseline or claim external interop.

## Phase 7 - issuer-qualified revocation

Finding: F16. Depends on Phases 2-6.
Target: protocol [L2361](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2361)
(`#token-revocation`) and [L2390](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2390)
(AP-to-PS revocation).

Phase rule: `(iss,jti)` only; no bare-jti API or wire fallback.

### Implementation Decisions

- [x] Typed token identity, separate request replay, bounded known-token inventory,
  and caller-to-target authorization approved for the alpha cutover. Source-token
  denial and recipient cascade require lifecycle integration, not helper-only
  evidence. See the Phase 7 decision in [implementation-log.md](implementation-log.md).

### Responsibilities and files

- Update [IJtiStore](../../../src/AAuth/Server/IJtiStore.cs), its in-memory
  implementation, [RevocationEndpoint](../../../src/AAuth/Server/RevocationEndpoint.cs),
  verification consumers, clients and sample callers with an explicit token key.
  Keep request replay state conceptually separate.
- Authorize against verified caller and token issuer, or an explicitly trusted
  PS; preserve deny-by-default configuration. Distinguish unknown pairs from
  already-invalid known tokens and validate both required members.
- Store issuance/recipient associations needed for AP-to-PS denial and PS/AS
  resource cascade. Expose PS revocation metadata; bound persistence/cleanup and
  make repeat revocation idempotent. Document unreachable-resource lifetime limits.

### Definition of Done

- [x] Same jti from two issuers remains isolated in store and real middleware.
- [x] Unauthorized cross-issuer requests fail; authorized issuer/trusted PS works.
- [x] Missing members fail, unknown pairs return 404, repeated known revocation 200.
- [x] AP-to-PS revoke blocks reuse and cascades to tracked resource grants.
- [x] Legitimate token reuse remains possible with fresh signatures.
- [x] Targeted revocation/integration suites and build pass.

Final Phase 7 gates: `make build` (zero warnings/errors), 1593/1593 Release
solution tests (818 core, 721 conformance, 54 R3), and 49 fresh-service browser
passes with one live-Keycloak skip, zero failures/flaky tests, and zero retries.
Live Keycloak was explicitly excluded by the current owner request. Real signed
multi-host tests cover PS-issued and AS-provided cascade, original-source denial
after deferred consent, unknown recipients, and two-issuer collisions. See the
Phase 7 completion record in [implementation-log.md](implementation-log.md).

## Phase 8 - account-aware authorization

Finding: F21. Depends on Phases 2, 5-7.
Target: protocol [L2055](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2055)
(`#account-binding`), R3 [L378](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L378).

Phase rule: one typed account contract; absent means absent, not an inferred default.

### Implementation Decisions

- [x] Phase 8 only authorized on 2026-09-09. Optional `string? Account` carries
  the resource's opaque identifier without normalization; exact nullable equality
  partitions authorization state. Resource-owned selection and verification
  expectations control enforcement. See [implementation-log.md](implementation-log.md).

### Responsibilities and files

- Add account to authorization requests, resource/auth builders/readers,
  verification expectations, PS/AS pending state and federation contracts.
- Include account in auth-token caches, prior-consent/grant lookup, refresh,
  mission consent and execution policies. Keep resource namespaces opaque.
- Add R3 document/proposal carriage, account-aware display and grant issuance.
  Never reuse an accountless cache entry for an account-selected request.
- Demonstrate two accounts for one person/resource using Bookings or another
  existing sample, including denial and a switch after prior consent.

### Definition of Done

- [x] Request/resource-token/auth-token/R3 account values remain identical.
- [x] Wrong-account execution, cache reuse and prior-consent reuse fail.
- [x] Accountless access still works without inventing an account claim.
- [x] Deferred, chained, refreshed and R3 flows preserve isolation.
- [x] Compiled samples, tests and build pass.

Final Phase 8 gates: `make build` and explicit Release solution build passed
with zero warnings/errors; 1667/1667 Release solution tests passed (864 core,
741 conformance, 62 R3); TypeScript checking passed. The full fresh-service
browser suite passed 51 tests, skipped one Keycloak-only test, and had zero
failures, flaky tests, or retries. Both apps exercise Personal/Work selection,
old-account grant rejection, fresh consent after denial, and account-bound R3
per-call approval. Live Keycloak remains unverified, not a claimed pass.
See [implementation-log.md](implementation-log.md) for APIs, deviations, and
final evidence. Phase 9 and later remain untouched.

Adversarial repair gate (2026-09-09): the four reviewed Phase 6-8 findings now
have reproduced failures and tested dispositions for shared federated mission
consent, exact upstream-context cache isolation, upstream revocation dependencies,
and direct no-mission AS chaining. Both primary apps' affected flow descriptions
and snippets are aligned. `make build` and Release build pass with zero warnings
or errors; all 1704 Release tests pass (865 core, 777 conformance, 62 R3).
Fresh-service browsers pass 51 with one Keycloak-only skip, zero failures/flaky
tests, and zero retries. Live Keycloak remains unverified because the configured
localhost:8080 realm was unreachable. Existing Phase 9 work was preserved, not
implemented or overwritten in this repair. The [implementation log](implementation-log.md)
records exact proofs, public contract inventory for Phase 11, and remaining
environment validation. The historical Phase 6-8 results above are unchanged.

## Phase 9 - R3 models, grants, audit and policy variants

Findings: F22-F26. Depends on Phases 3-8.
Target: R3 [L161](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L161)
(`#openapi-gateway-vocabulary`), [L590](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L590)
(`#per-call-proposals`), [L616](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L616)
(Audit Log Integrity), [L624](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L624)
(Grant Enforcement).

Phase rule: vocabulary-correct operation identity, no legacy bare-id alias.

### Implementation Decisions

- [x] Autonomous Phase 9 only; preserve partial work and preceding phases. No
  compatibility paths, delegation, commits or branch changes. Use qualified
  operation identities, explicit custom schemas, designated-AS readership by
  default, and mandatory fail-before-release audit persistence. SQLite provider
  10.0.11 is approved subject to availability verification. Record new contracts
  for Phase 11 and leave Events implementation to Phase 10.

### Responsibilities and files

- Replace single-member assumptions in [Model](../../../src/AAuth.R3/Model/)
  with validated shapes for all eight vocabularies and third-party extension
  support. Add structured Gateway discovery; retain optional-member semantics.
- Use complete vocabulary-qualified operation identity in R3Metadata,
  R3AuthClaims, R3ClaimReader, R3Grant, proposal matching and enforcement.
- Validate requested vocabulary/fields against advertised authoritative
  definitions in [Bookings](../../../samples/MockResourceServers/Bookings/Program.cs).
  Exercise unconditional and conditional policy variants for every sample endpoint.
- Retain served-byte hashes and approved-parameter checks. Require explicit
  audit persistence instead of a silent no-op; test fail-before-release and
  recovery semantics. Apply Q4 to R3 document readership and custom fetch contracts.
- Prepare the AsyncAPI handoff contract for Phase 10, without advertising a
  working subscription flow before its implementation.

### Definition of Done

- [x] All standard vocabulary shapes round-trip; required/optional/malformed
  fields and two Gateway services sharing an operationId are tested.
- [x] Wrong vocabulary/member/service cannot gain a same-id grant.
- [x] Granted/conditional/rejected behavior matches policy across Bookings routes.
- [x] Tampered document/proposal/parameters fail; custom fetch contracts are explicit.
- [x] Audit cannot silently disappear; failure/concurrency/restart tests verify
  token release and audit association under the selected storage model.
- [x] Dedicated R3 tests, integrated core tests, Bookings e2e and build pass.

Final evidence (2026-09-09): Release solution 1784/1784 tests (core 865,
conformance 777, R3 142), zero failures/skips. Release build and `make build`
pass with zero warnings/errors. Both R3 browser specs pass 6/6 with fresh
services, isolated HOME, retries=0 and full traces, including account-switch
screenshots at desktop/mobile sizes. Browser TypeScript checking passes.
The earlier 51-browser baseline is not claimed as a newly executed full-browser
gate. See the Phase 9 completion entry in [implementation-log.md](implementation-log.md)
for artifact paths, failures repaired, storage limits and Phase 10/11 handoff.

### Adversarial repair follow-up

- [x] Independently reproduce and repair PS-role authorization, OData method
  coverage, custom vocabulary member ordering, empty proposal parameters, and
  malformed credential value types. Preserve current Phase 10 Events code.
- [x] Add signed HTTP role/type/parameter tests and reordered matching tests
  across all vocabularies. Focused Release R3 suite: 206 passed, zero failed/skipped.
- [x] Record breaking custom-schema identity API and directional grant coverage
  in the Phase 9 adversarial entry in [implementation-log.md](implementation-log.md).
- [x] Rerun full Release solution tests/build and fresh-service R3 browser tests;
  record final review dispositions and remaining limits before closing repairs.

Repair evidence (2026-09-09): 1907 Release tests pass (core 865, conformance 777,
R3 206, Events 59), zero failed/skipped; Release build has zero warnings/errors.
Fresh R3 browser run passes 6/6 with no skips or flakes. Final scoped self-review
leaves none of the five reported findings open. The Phase 10 Events implementation
is unchanged; its earlier full-browser ledger is not claimed as newly rerun.
See the appended adversarial final-review entry in
[implementation-log.md](implementation-log.md) for artifacts and API handoff.

## Phase 10 - complete Events companion flow

Findings: F27, Events portion of F28/F31. Depends on Phases 3-9.
Target: Events [L277](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L277)
(`#subscribe-token`), [L368](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L368)
(`#event-token`), [L424](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L424)
(`#event-delivery`), [L447](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L447)
(`#ap-to-agent`), and [L603](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L603)
(Pre-Authorized Subscription URL Security).

Phase rule: exact subscribe/event wire types and self-jwt; no draft-09 delivery shim.

### Implementation Decisions

- [x] Autonomous Phase 10 implementation approved, with no compatibility, delegates,
  commits or branch changes. Use shared SDK verification and admitted discovery;
  require explicit companion registration. SQLite 10.0.11 remains sample-owned.
  Apply Q5 raw-body and issuer/eid deduplication literally; demonstrate single-shot
  delivery and label authenticated polling as a local transport profile.

### Responsibilities and files

- Add or selectively adapt the Events source/test/sample projects identified
  in Phase 0; add them to [AAuth.slnx](../../../AAuth.slnx), CI/test gates and
  package docs. Re-audit reused code instead of assuming another branch is v10-ready.
- Implement AP metadata, subscribe issuance/verification, resource registration,
  bound expiring single-use tickets, and subscription/context persistence.
- Implement self-jwt event issuance and AP validation of typ/dwk/issuer/audience/
  expiry/subscription, using the same discovered key for JWT and HTTP signature.
  Preserve and verify the actual payload bytes under the chosen digest profile.
- Atomically validate quota, persist the delivery/outbox and update uses before
  202. Include remaining_uses when required; implement specified errors and
  restart-safe delivery under Q5/Q6. Do not count a failed durable write as success.
- Implement agent-side issuer signature/audience/expiry/context validation and
  deduplication under the recorded interpretation. Provide one explicit local
  AP-agent transport; do not label it a standardized endpoint.
- Connect Bookings protected AsyncAPI ticket issuance, resource subscription,
  MockAgentProvider routing and a runnable EventAgent. Add a public-subscription
  case and bounded/unlimited quota tests even if the primary demo is single-shot.
- Also expose the Events lifecycle as a discoverable runnable scenario in both
  GuidedTour and SampleApp, with corresponding Playwright specs. Review whether
  the resource's Events behavior serves its single purpose clearly; retaining
  Bookings is a deliberate teaching/design choice, not a requirement to keep
  adding every future capability to that resource. Phase 12 checks this choice
  and the completeness of the scenarios against the capability inventory.

### Definition of Done

- [x] No EventToken cnf; unknown typ, wrong AP/resource/agent, expired/future claims,
  missing eid, mismatched HTTP key and tampered payload fail as appropriate.
- [x] Ticket reuse, wrong-agent redemption and concurrent redemption fail safely.
- [x] Concurrent max_uses cannot overrun; persistence failure never yields 202;
  restart preserves accepted events and quotas.
- [x] Agent never acts on expired/mismatched/unverified events; duplicate behavior
  follows the recorded spec interpretation without invented wire fields.
- [x] Public and protected AsyncAPI/R3 flows work end to end with captured headers.
- [x] New Events tests run in the solution and CI; complete sample/e2e and build pass.

Final evidence (2026-09-09): Release solution 1843/1843 tests (core 865,
conformance 777, R3 142, Events 59), zero failures/skips. Release and `make build`
pass with zero warnings/errors; Events NuGet packing succeeds. Fresh-service
full browser suite passes 55 tests, with one environment-gated Keycloak test
skipped and no failures/flakiness. Both Events pages pass public desktop and
protected work-account mobile flows. Standalone EventAgent completes all six
actual HTTP steps. See the Phase 10 completion ledger in
[implementation-log.md](implementation-log.md) for paths, provider obligations,
recurring-event ambiguity, local transport and remaining environmental limits.

## Phase 11 - public API alignment and fluent convenience builders

Depends on Phases 1-10, so the complete new runtime surface is available to
review. Runs before security closure and the frozen-surface sample/docs sweep.
The owner requested this phase after the resource-managed Inbox changed from
pseudonymous hwk to agent JWTs and its examples exposed manual refresher wiring.
See the implementation log's resource-managed revisit entry; the sample flow
decision is not closed merely because Phase 3 tests passed.

Target: protocol [L2420](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2420)
and [L2422](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2422)
(`#keying-material`), [L2055](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2055)
(`#account-binding`), Signature Keys
[L957](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L957)
(JWKS URI Discovery) and
[L1021](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L1021)
(Direct JWKS). These name protocol concepts, not required .NET method names.

Phase rule: restore the established fluent/convenience style without restoring
obsolete wire formats, compatibility aliases, implicit trust bypasses or hidden
authorization parties. A simpler API must preserve validation and explicit policy.

### Implementation Decisions

- [x] Autonomous full Phase 11 alignment authorized on 2026-09-09, preserving
  the 1920-test baseline and all 56 browser cases. No delegates, commits or
  branch changes. Retain JWT resource-managed access, expose enrollment setup,
  and audit the complete public delta against ba768f1. See the implementation log.

### Events Hardening Verification

- [x] Bind subscribe subjects to the issuing AP before public/ticket registration.
- [x] Persist AP enrollment ownership, require body-bound proof, and make the
  sample namespace provider-assigned with signed idempotent reenrollment.
- [x] Bound serialized inbox pages to 1 MiB with indexed SQL and owner-scoped ack.
- [x] Recover completed notify retries from durable owner/account-bound receipts;
  prove EventDemoSession recovery after a lost successful HTTP response.
- [x] Final Release build/tests and fresh no-retry browser gates, including the
  separately configured live Keycloak case, recorded in the implementation log.

### Responsibilities and files

- Rescan the complete migration diff against implementation baseline `ba768f1`,
  including added/changed public methods, overloads, constructors, option types,
  DI registrations, endpoint mappers and required context inputs. Extend the
  inventory after later fixes; do not limit it to the three phases already done.
  Record `spec concept | existing entry point | new low-level contract | chosen
  fluent API | ownership/defaults | callers/snippets | validation` in this folder.
- Map the new behavior onto [AAuthClientBuilder](../../../src/AAuth/AAuthClientBuilder.cs),
  [EnrolledBuilder](../../../src/AAuth/EnrolledBuilder.cs),
  [SelfIssuingBuilder](../../../src/AAuth/SelfIssuingBuilder.cs) and
  [BootstrapBuilder](../../../src/AAuth/BootstrapBuilder.cs), plus server/DI and
  companion entry points. Reuse suitable APIs; add a layer or forwarding method
  only where it removes necessary caller plumbing or fills a real composition gap.
  Start from the directly checked resource-managed API map under research F29;
  its current EnrolledBuilder can reach flow options via WithInteractionHandling
  but lacks a direct WithResourceManagedAccess forwarder. Review composition
  intentionally rather than forcing callers to reorder unrelated options.
- Separate Signature-Key schemes (`hwk`, `jkt-jwt`, `jwks_uri`, `jwks`, `jwt`,
  `self-jwt`) from the four resource access modes (identity-based,
  resource-managed, PS-asserted, federated). Distinguish agent enrollment/key
  refresh, agent/auth/subscribe/event tokens and opaque AAuth-Access credentials.
  A scheme choice must not silently select an authorization topology.
- Revisit the Inbox example in both primary apps. Record whether it demonstrates
  conformant AAuth resource-managed access with an agent token or a separately
  labeled generic pseudonymous signing example; do not silently call them the
  same flow. Show where the agent token comes from, whether enrollment is setup
  or an on-demand call, and which network parties participate at each stage.
  No PS/AS token exchange should be introduced into the two-party resource flow.
- Replace manual refresher/HttpClient construction in ordinary enrolled-client
  examples with the established Enrolled/RefreshingFrom/WithKeyStore style where
  appropriate. Ensure resource-managed access and interaction options compose
  through that builder, with correct key/token lifetime and disposable ownership.
  Keep an explicit fixed-token low-level path for already-held valid credentials;
  do not invent a builder name in a snippet before it exists and is tested.
- Review `From(EnrollResult)` defaults and overrides: it currently selects jwks
  when a key URL is available although its comment still says jwks_uri. Decide
  the default from the intended agent use case and actual enrollment/token data,
  not merely the presence of a URL. Test explicit scheme overrides after refresh
  configuration and prevent ambiguous or surprising precedence.
- Map verified issuance/expiry and reserved-claim contracts, admitted discovery,
  consent/pending APIs, delegation/sub-agents, issuer-qualified revocation,
  account selection, R3 vocabulary/proposal/audit and Events subscription/delivery
  contracts into ergonomic public entry points. Preserve mandatory verified
  context; do not make new required inputs optional simply to shorten examples.
- Align public naming, XML comments, diagnostics and capability terminology with
  the spec. Avoid describing self-issued agent-token provisioning as self-jwt
  signing, direct jwks as metadata discovery, or opaque access tokens as JWTs.
- Update all compiled callers and both samples' embedded code, explanatory
  text, numbered steps and visuals together. Use equivalent intent expressed
  through one consistent high-level builder style; retain low-level examples only
  when their explicit purpose is teaching that layer.
- Run an adversarial API review for naming, defaults, builder composition,
  disposal/lifetime, hidden network calls and security-policy equivalence. Resolve
  findings and repeat before freezing the surface for Phases 12-13.

### Definition of Done

- [x] The complete public-API inventory maps every migration-introduced layer
  to an existing convenience method, tested new method, or justified low-level API.
- [x] The Inbox agent-token/pseudonymous distinction has an explicit recorded
  ruling and both apps show credential provenance and actual parties accurately.
- [x] Enrolled and self-issued builders compose the supported flow options;
  client setup does not require avoidable manual service/handler construction.
- [x] Scheme/default/override tests verify emitted carriers and no unintended
  PS/AS call; lifecycle tests verify refresh, cancellation and resource ownership.
- [x] Simplified APIs retain required trust, expiry, key/account and consent checks.
- [x] Public names, comments, snippets and sample flow labels use spec terminology;
  obsolete aliases and misleading From/enrollment defaults are gone.
- [x] Updated snippets compile/run and both apps' flow/browser checks pass.
- [x] Full solution tests/build pass and the last API review has no unresolved
  in-scope findings; decisions and deviations are logged.

Verified 2026-09-09: Release 1967/1967 tests (core 913, conformance 777,
R3 206, Events 71), no skips/failures; Release and `make build` zero warnings
or errors. Final fresh-service browser gate: 55 stub cases plus the separately
configured live Keycloak case, all 56 executed successfully with retries=0 and
no flakiness. Exact snippet compilation covers 17 templates. The complete
[API map](api-surface-map.md) inventories 182 changed public-source files
(154 SDK, 28 sample runtime), +697/-143 declarations against ba768f1, with no
unmapped files. The [log](implementation-log.md) records failed checks/repairs,
ownership and two-key rulings, screenshots and phase boundaries. This does not
mark Phase 12 security closure or Phase 13 documentation finalization complete.

## Phase 12 - cross-cutting security and conformance closure

Findings: all P1/P2 findings plus the research coverage limits. Depends on Phases
1-11. Target: protocol [L1488](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1488)
(mission presentation), [L1490](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1490)
(no mission dereference), and [L2507](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2507)
(`#freshness-and-replay`), plus each finding's canonical references.

Phase rule: satisfy the normative baseline; do not invent hardening MUSTs.

### Implementation Decisions

- [x] Full Phase 12 authorized on 2026-09-09, including retrospective runnable
  capability coverage in both apps, selective single-purpose resources and
  requirement ledgers. Preserve prior migration work and fluent APIs; no
  commits, branch changes, nested delegation or vendor edits. Decisions and
  verification are appended to the implementation log as they occur.

### Responsibilities and files

- Independently sweep MUST/MUST NOT/reject requirements across core, R3 and
  Events, recording implemented, inapplicable, unsupported-optional, ambiguous,
  and unresolved cases in the requirement-to-test ledger.
- Close remaining governance coverage: permission/audit/interaction ownership,
  unknown/terminated missions, consent association, exact mission bytes and echo,
  no resource/AS mission dereference, and account-aware prior approvals.
- Exercise mixed challenge sequences: claims, clarification, approval, payment,
  user interaction, cancellation, expiry, slow_down and retry-after. Test redirect
  admission and new-token replacement, not only final 200 responses.
- Validate resource-managed agent/key/account binding, token refresh, replay
  isolation, secret-safe diagnostics, untrusted metadata/display sanitization,
  and real sample configuration rather than helper-only tests.
- Review the configured durable stores and injected HTTP/policy callbacks against
  their contracts. Record missing guarantees instead of claiming SDK control of
  arbitrary application implementations.

### Capability scenarios and resource simplicity

This is an implementation gate before Phase 13, not only a documentation audit.
Apply the owner's 2026-09-09 scenario requirement retrospectively to capabilities
already implemented in Phases 1-11 as well as any additions from review repairs.

- Build a capability-to-scenario matrix from the migration diff, the research
  findings, and [api-surface-map.md](api-surface-map.md):
  `capability | existing/new flow | GuidedTour entry | SampleApp entry | resource
  purpose | Playwright specs | evidence/gap`. Name the actual pages/flow selectors
  and assertions; do not treat unrelated success tests as coverage.
- Include Events public/protected subscriptions and delivery, account selection,
  direct and parent-mediated/chained authorization, AS clarification, and other
  new user-facing capabilities. Record internal hardening separately with its
  negative tests; it does not need an artificial new UI scenario. Optional
  capabilities excluded by the approved scope remain explicitly excluded.
- Extend an existing flow if it already teaches the capability without confusing
  its actors or purpose. Otherwise add the simplest discoverable scenario to
  both apps, with actual SDK/network behavior, setup, expected outcome and a
  meaningful rejection or recovery case. Do not substitute simulated output
  or a standalone EventAgent run for either app's scenario.
- Review [existing resource examples](../../../samples/MockResourceServers/)
  before choosing a backend. Record one sentence describing the resource's
  single purpose and why reuse or a new resource best preserves that example.
  Keep endpoint handlers, metadata, authorization and domain state easy to read;
  move reusable protocol mechanics into existing SDK facilities rather than
  copying them into the example. Supporting operations may belong to one use
  case; single-purpose does not mean one endpoint or one signing scheme.
- When a new resource is justified, add a minimal project alongside the existing
  resources. Wire its project into [AAuth.slnx](../../../AAuth.slnx), shared sample
  configuration/explicit loopback policy, [Makefile](../../../Makefile), and the
  [Playwright webServer setup](../../../tests/e2e/playwright.config.ts).
  Follow existing lifecycle, deterministic reset and isolated-state patterns.
  Do not provision a new external service unless the capability requires it.
- Add specs under [GuidedTour tests](../../../samples/GuidedTour/playwright-tests/)
  and [SampleApp tests](../../../samples/SampleApp/playwright-tests/), reusing
  [shared helpers](../../../tests/e2e/helpers/). Assert the new flow is reachable,
  executes its actual protocol steps, exposes the expected claims/headers or
  events, and handles the selected failure/recovery branch. Check numbered-step,
  sequence-visual and embedded-snippet associations and reset/repeated execution.
  Add narrowly scoped API tests for concurrency or crash cases not suited to UI.
- Validate affected flows at desktop and narrow viewports, then run both full
  browser projects on fresh services. Ensure the existing CI entry point picks
  up all new specs. Append resource-selection decisions and each gap's resolution
  to the implementation log; repeat this matrix check after adversarial repairs.

### Definition of Done

- [x] Every normative area has an explicit ledger disposition and test evidence
  or documented deployment responsibility; no unexplained MUST gap remains.
- [x] Every in-scope new user-facing capability maps to a real scenario in both
  apps, with uncovered capabilities implemented rather than silently deferred.
- [x] Resource choices are documented, selective and single-purpose; new resource
  source remains a comprehensible example following existing project patterns.
- [x] Every new flow has passing Playwright coverage in both app projects,
  including meaningful protocol assertions and a failure or recovery branch.
- [x] New resources/scenarios start, reset and run through the existing demo,
  solution, test harness and CI entry points without extra manual setup.
- [x] High-stakes R findings are directly reproduced/rechecked and resolved.
- [x] Threat-oriented tests pass without breaking existing positive controls.
- [x] Core/R3/Events/solution tests and both policy-mode e2e runs pass.

Final evidence (2026-09-09): 2069 Release tests; clean Release build; 21 exact
snippet templates; full fresh stub browsers 67 passed/one live-only skip; full
fresh live Keycloak browsers 68 passed/no skips. Both browser gates have zero
unexpected/flaky results and retries=0. The eight owner-supplied findings and
the callback/recovery gate have no remaining open in-scope finding. Historical
failed/interrupted runs remain in the append-only log. Deployment obligations
and unsupported optional capabilities remain explicit in the ledger; Phase 13
is not closed by this evidence.

## Phase 13 - frozen-surface samples, snippets and docs sweep

Findings: F29-F31 and every user-facing change. Depends on Phase 12; compiled
consumer fixes have already happened in their owning phases.
Target: protocol [L2420](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2420)
(`#keying-material`) and interop profile
[L9](../../../aauth-spec/v10/interop-demo-profile.md#L9) through its five surfaces.

Phase rule: describe only the final v10 API and supported capabilities, not legacy aliases.

### Implementation Decisions

- [x] Full Phase 13 writes authorized 2026-09-09. Exhaustive discovered snippet
  coverage replaces the representative-only requirement below. Reuse Roslyn;
  classify external templates explicitly; preserve useful instructional content.
  No commits/branch changes. No delegation is this worker's constraint, not an
  owner prohibition on the separate Phase 14 review. See the append-only log.

### Responsibilities and files

- Inventory every surface in the research ownership map. Cover root/package/
  sample READMEs, docs index/concepts/glossary, all signing/server/workflow/
  advanced/reference docs, GuidedTour CodeSnippets/TourSession/Razor content,
  SampleApp pages and both Playwright suites. Record `file | finding | edit | check`.
- Use the completed Phase 12 capability-to-scenario matrix to check every new
  page/flow, any new resource's README and code examples, navigation entries,
  numbered steps, sequence visuals and embedded snippets. The sweep must not
  declare coverage complete while either app lacks a required runnable scenario.
- Separate generic HTTP Signature Keys demos from four AAuth access modes in
  routes, policy, headings and diagrams. Ensure getting-started teaches a valid
  agent-token path and labels generic signing examples accurately.
- Replace old algorithm/error/action/revocation/carrier snippets. Add account,
  EventAgent/AsyncAPI, AS clarification, strict egress, consent session and
  supported-capability guidance. Keep hardware-attestation claims honest.
- Compile or explicitly classify every discovered fenced and string-literal example through
  the existing sample/test infrastructure. Compare displayed exchanges against
  captured runtime wire output, including negative responses.
- Prioritize both [SampleApp](../../../samples/SampleApp/) and
  [GuidedTour](../../../samples/GuidedTour/). For every changed flow, record
  `flow | changed step | SampleApp surface | GuidedTour surface | validation`.
  Reconcile numbered instructions and cross-references, actor lanes, arrows,
  decision branches, polling loops, highlights and navigation with runtime order.
  Show local checks as local decisions rather than invented network requests.
- Inventory embedded snippets in [CodeSnippets.cs](../../../samples/GuidedTour/CodeSnippets.cs),
  [TourSession.cs](../../../samples/GuidedTour/TourSession.cs),
  [GuidedTour Razor components](../../../samples/GuidedTour/Components/) and
  [SampleApp pages](../../../samples/SampleApp/Components/Pages/). Include raw,
  interpolated and multiline strings; inline pre/code blocks; displayed C#,
  JSON, JWT and HTTP examples; and copy/download variants where present.
  Update signatures, parameters, headers, claims, comments and step references,
  not only the live calls. Each snippet must describe the same flow and public
  API as its associated step and payload inspector.
- Compile/run complete C# snippets through focused tests or sample harnesses;
  wrap fragments with their declared imports/setup. Parse and assert JSON/HTTP
  examples against the current contract and captured wire output. For intentional
  placeholders or pseudocode, record that classification and check the surrounding
  contract explicitly. A successful sample build does not validate code in strings.
- Run five interop surfaces, including a real four-party sub-agent flow with
  distinct parent/child keys. Add local hermetic checks; distinguish externally
  unavailable live endpoints from failure/success.
- Only after runtime gates pass, update SDK-target wording in root/package docs,
  [SPEC-VERSION](../../../aauth-spec/SPEC-VERSION.md) and
  [CHANGELOG](../../../aauth-spec/CHANGELOG.md). Preserve historical entries and
  all vendored snapshot bytes. Explicitly document remaining optional exclusions.

### Definition of Done

- [x] Every ownership-map surface has a recorded disposition, not only grep hits.
- [x] Every scenario/resource introduced for capability coverage has aligned
  instructional content and links to the existing demo/test setup.
- [x] No stale executable wire shape remains except deliberate rejection fixtures.
- [x] Snippets compile/run; displayed bodies/headers match actual v10 behavior.
- [x] Every affected embedded snippet in both apps has a recorded validation
  result or an explicit illustrative-placeholder classification; no stale API,
  wire shape, comment or numbered-step reference remains.
- [x] Both apps' numbered steps, sequence visuals, displayed/copied snippets and
  payloads agree with the implemented flow, including consent, clarification,
  immediate grants, retries, denial and cancellation where applicable.
- [x] Both Playwright suites check affected step navigation, approval/polling
  transitions and displayed snippet/payload associations, not only final success.
  Desktop and narrow-viewport visual checks cover labels, arrows, loops,
  highlights, clipping and overlap.
- [x] Docs links and anchors resolve; examples do not mislabel generic signing as AAuth.
- [x] Full-stack fresh-server e2e and all interop surfaces have recorded results.
- [x] Version/capability claims match the implemented and verified scope.

Completed 2026-09-09. [Surface inventory](docs-surface-map.md): 161 files,
615 blocks, including 261 exact compiled C# blocks, 33 source-checked API
excerpts, five explicit external templates, 32 dynamic displays and 162 inline
Razor labels/expressions. The remaining blocks have individual format/runtime
dispositions; they are not all described as compiled programs. All 80 docs
test cases pass. Final Release: 2128 tests, zero failed/skipped, build zero
warnings/errors. Full fresh stub browsers: 67 passed/one live-only skip;
live Keycloak: 68 passed/no skips; retries=0 and no unexpected/flaky results.
Local S1-S5 evidence and partial external LiveWhoAmITest results are recorded in
the [ledger](conformance-ledger.md) and append-only log. External scoped
authorization returned person_token_required and is not claimed as a pass.
All 26 vendored snapshot files match HEAD byte-for-byte. Phases 14 and 15 remain
open; this phase is not an independent adversarial review.

Final authorization-repair checkpoint (2026-09-09): seven source-review findings
have code/regression evidence in the append-only log. Release passes 2160 tests;
full browsers pass 71 stub plus one live-only skip and 72 live with no skips,
retries=0. The four added Documents cases execute resource permission before PS
consent in both apps. Current inventories cover 169 files/617 documentation
blocks and 197 public-source files (+777/-149 declarations). This continuation
is implementation, not the independent review below; its checkboxes stay open.

## Phase 14 - independent internal review

Depends on Phase 13. Give a fresh read-only subagent the final diff, immutable
v10 sources, research, this plan, implementation log and requirement-to-test
ledger. Require severity-graded findings with reverified source lines, including
negative requirements, optional-capability boundaries, samples and docs.

Phase rule: no compatibility exception or spec interpretation is implicit.

### Implementation Decisions

- [x] 2026-09-09: Repair confirmed review findings using independently signed
  malformed-token tests and shared structural validation before trusted contexts.
  Apply required payload claims to built-in AAuth profiles, not arbitrary JWT
  types; registered companion verifiers retain their policy hook. Require the
  verified PS metadata role before core AS exchange or pending policy evaluation.
  Preserve previous repairs; no delegation, commits, or branch changes. Repeat
  Release, documentation inventories, and zero-retry stub/live browser gates.
  Independent review remains pending; these repairs do not close Phase 14.

- [x] 2026-09-09: Reject duplicate JWT members structurally; use policy-aware
  host-only agent-domain validation throughout actor contexts; preserve live
  factories in refresh-only clients and cancellation before token publication;
  support explicit R3 JSON null values without treating missing values as null.
  Correct per-agent JWKS/DI documentation and sample identities/consent mappings.
  Final implementation evidence: 2637 Release tests, clean build, 93 snippet
  checks, full fresh browsers (71 stub plus one live-only skip; 72 live),
  retries=0. Retain failed gate history and the optional bootstrap convenience
  limitation. This is not an independent pass; all Phase 14 DoD boxes stay open.

- [x] 2026-09-09: Complete the remaining guarded body/JWT parsing and typed
  credential-error repairs from the 2637-test checkpoint. PS/core AS/R3 AS
  reject malformed credentials before policy, audit, or document fetch; pending
  replacement and claims paths reject invalid shapes without changing state.
  Correct cached issuer discovery and conditional IAAuthKey resource-key docs;
  compare every property/constructor-parameter table row in both reference pages
  against source. Release passes 2859 tests, snippets/source checks pass 96,
  fresh full stub passes 71 plus one live-only skip, and live passes 72, all
  with zero retries. Only the parent is authorized to commit/push after final
  gates and fresh review; this worker performs neither. Independent review and
  all Phase 14 DoD checkboxes remain open.

- [x] 2026-09-09: Repair the 2859-checkpoint claims regression with strict raw
  JSON parsing shared across contexts and credential validation only for token
  requests or matching clarification updated_request actions. Trusted pending
  status controls dispatch; policy-requested action and credential-like names
  remain ordinary claims. Preserve reserved-name and invalid-shape guards.
  Correct adjacent replay, proactive endpoint and IAAuthKey documentation/XML;
  extend the source table checker to token-issuance PS options. Focused HTTP
  tests pass 286; snippets/source/link tests pass 103. Full Release passes 2911
  tests with a clean build; fresh browsers pass 71 stub plus one live-only skip
  and 72 live, all with zero retries or unexpected/flaky results. API and docs
  inventories are current. Parent-only commit/push authorization does not close
  independent review; no delegation or branch changes are authorized.

### Definition of Done

- [x] Every review finding has a recorded disposition and supporting evidence.
- [x] Approved fixes have focused regression tests and rerun affected gates.
- [x] Material architectural changes receive another independent review.
- [x] Independent review checks the capability-to-scenario matrix, both apps'
  new-flow Playwright coverage, and resource purpose/readability, not only SDK code.
- [x] Release solution tests, explicit R3/Events suites, stub/Keycloak e2e,
  snippet checks, links, and the requirement ledger are complete.
- [x] Unavailable external live interop is explicitly reported, with local
  captured-wire evidence; no blanket full-conformance claim hides it.
- [x] All changes remain uncommitted for owner inspection unless requested otherwise.

Closed 2026-09-09 after fresh read-only acceptance of signing/discovery/API,
authorization/claims dispatch, R3/Events/storage and instructional surfaces.
Reported findings were repaired and their affected sets reviewed again; the
last applicable independent passes have zero unresolved in-scope findings.
This is a bounded source-review result, not proof of correctness of arbitrary
host policies, stores or transports. The owner authorized commit/push after
completion; the premature worker publication is recorded as a deviation.

## Phase 15 - final documentation alignment gate

After all adversarial review repairs, repeat the Phase 13 inventory against the
final code, with SampleApp and GuidedTour as primary acceptance surfaces. Recheck
embedded snippets, numbered steps, sequence visuals, copied examples, API docs,
configuration, README version/capability claims and all affected browser tests.
Record results in the implementation log. Any behavior-changing correction
reopens the affected tests and logical area's independent review.

### Definition of Done

- [x] Final code and all instructional surfaces agree; no stale step or snippet remains.
- [x] The final capability matrix has no uncovered in-scope user-facing feature
  in either app, including additions from review fixes.
- [x] Links, snippet checks and both apps' visual/browser checks pass.
- [x] Every logical area's last adversarial pass has zero unresolved in-scope findings.
- [x] Runtime and documentation validation results and limitations are recorded honestly.

Final verification: 2913 Release tests (1469 core, 1079 conformance, 290 R3,
75 Events), zero failed/skipped; clean make build; explicit make unit/conformance
and R3/Events gates pass. All 105 documentation/source/link checks pass, with
current API and documentation inventories. The final runtime's fresh browser
reports contain 71 stub passes plus the expected live-only skip and 72 live
Keycloak passes, zero unexpected/flaky/global errors and retries=0. Subsequent
changes are documentation, XML comments and two documentation regressions only;
the browser evidence remains applicable and is not claimed as newly rerun.
The parent inspected saved Documents/Events desktop/mobile captures. All
vendored snapshot directories remain identical to the migration baseline.

External full authorization still returns `person_token_required`; local S1-S5
checks and successful Keycloak tests do not establish external interoperability.
Other declared optional and production-provider limitations remain in the
conformance ledger. No unresolved in-scope finding is hidden by those limits.

## Finding-to-phase traceability

| Findings | Owning phases |
|---|---|
| F01-F07 | 3; discovery dependencies in 4; API alignment in 11; cross-cutting review in 12 |
| F08-F09 | 4 |
| F10 | 2; context propagation checked in 5-6 |
| F11 | 1 |
| F12-F15 | 5 |
| F16 | 7 |
| F17-F18 | 6 |
| F19 | 2 (reserved claims), 6 (upstream and actor checks) |
| F20 | 6 |
| F21 | 8; R3 and Events integration in 9-10 |
| F22-F26 | 9; fetch admission in 4; Q4 in 0 |
| F27 | 10 |
| F28 | 0 (dispositions), 3 (self-jwt/jwks), 10 (Events consumer) |
| F29-F30 | Compiled consumers in owning phases; API/flow alignment in 11; final sweep in 13 |
| F31 | 1/3 (bootstrap shared behavior), 10 (AP integration), 11 (API), 13 (documentation) |
| Owner-requested API simplification and Inbox flow revisit | 11, with documentation gates in 13/15 |
| New-capability scenarios, selective single-purpose resources and Playwright | Owning feature phases; coverage implementation in 12; docs/review gates in 13-15 |
| Coverage limits and all negative requirements | 12 and independent review 14 |

## Out of scope

These are proposed dispositions subject to Phase 0, not silent omissions.

| Item | Reason and required boundary |
|---|---|
| Compatibility aliases, old-wire fallbacks | Explicit alpha/spec-accuracy constraint |
| SDK implementation during this documentation task | Research and planning only; approval gate precedes code |
| Rewriting old plans or vendored source | Historical records and immutable citation baseline |
| X.509 and cached-assertion implementations | Optional under Q1; reject/advertise accurately and document exclusion, not partial stubs |
| New JOSE algorithm families beyond supported Ed25519/ES256 | Algorithm agility does not require implementing every registered algorithm; unknown selected keys fail cleanly |
| Platform-native attestors and all AP-agent push transports | Bootstrap guidance and Events transport are implementation-specific; retain hooks and one complete local transport |
| Payment settlement engine | External protocol/provider responsibility; payment challenge/control-flow handling remains in scope |
| General recurring-event semantics invented beyond the draft | Q5 requires a ruling; support only what can be described/tested without inventing standard wire fields |
| Production-specific identity provider and database deployment | Supply explicit contracts and runnable sample providers; operational deployment remains application-owned |
| Automatic branch merge, package publication, git commit | Requires separate owner authorization |