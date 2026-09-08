# Implementation Plan - AAuth v10 repository migration

Companion to [research.md](research.md), created 2026-09-08. This plan covers the
current SDK, R3, the missing Events capability, runnable examples, tests, and
documentation. No implementation phase is complete or authorized by the creation
of these documents. Historical v09 plans remain unchanged; this initiative
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
  must remain synchronized. Phase 12 checks the finished apps; it does not defer
  fixes to their executable walkthrough behavior.
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

- [ ] Every Q1-Q10 has a recorded ruling in the implementation log.
- [ ] Optional capabilities and ambiguous clauses have explicit dispositions.
- [ ] Every research finding has a phase and a planned discriminating check.
- [ ] Baseline failures and unavailable environments are recorded separately.
- [ ] The implementation scope and plan are approved before SDK edits.

## Phase 1 - shared problem-details cutover

Findings: F11, the error portion of F30/F31. No code-phase dependencies.
Target: protocol [L2304](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2304)
(`#error-response-format`).

Phase rule: `detail` only, no `error_description` fallback or public alias.

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

- [ ] Real endpoint tests assert status, media type, `error`, `detail`, and
  endpoint extensions for representative PS/AS/R3/governance/revocation errors.
- [ ] Clients use `error` for behavior regardless of RFC 9457 `type`.
- [ ] No old wire/API description remains in migrated producers/consumers.
- [ ] Success responses, auth challenges, and callbacks remain correct.
- [ ] Focused tests, affected test projects, and solution build pass.

## Phase 2 - issuance bounds and reserved claims

Findings: F10, reserved-claim part of F19. Depends on Phase 1.
Target: protocol [L1344](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1344)
(Agent Token Lifecycle) and [L1708](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1708)
(Auth Token Structure).

Phase rule: exact validated issuance inputs, no legacy unbounded overload.

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

- [ ] Immediate and deferred two-minute-agent tests never yield a later auth exp.
- [ ] Already-expired, zero/negative lifetime, and parent/child boundary cases fail.
- [ ] `expires_in` matches actual expiry in direct and deferred responses.
- [ ] AdditionalClaims cannot inject unset protocol-owned claims; legitimate
  identity extensions still work.
- [ ] Core/conformance/R3 tests and solution build pass.

## Phase 3 - signature carriers and typed verification

Findings: F01-F07, F28 self-jwt/jwks, signing part of F31. Depends on Phases 1-2.
Target: protocol [L2409](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2409)
(`#signature-algorithms`), [L2478](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2478)
(`#verification`), Signature Keys [L641](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L641)
(3.4), [L964](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L964)
(3.6), and [L1222](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L1222)
(3.9).

Phase rule: old carrier encodings and `EdDSA` are rejected, not supported in parallel.

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

- [ ] Independent wire vectors for jwt, hwk, jkt-jwt, jwks_uri, jwks, self-jwt
  pass with Ed25519 and supported ES256 combinations.
- [ ] Missing/polymorphic/symmetric/prohibited alg and alg/kty/crv mismatch fail;
  a valid selected JWKS member survives unrelated unsupported members.
- [ ] Wrong typ, forged issuer with a valid PoP signature, forbidden self-jwt cnf,
  missing/future/expired naming claims, and expired signature expires fail.
- [ ] Matching labels, additional signatures, escaping, malformed members, and
  unknown schemes produce the required result, not an uncaught exception.
- [ ] AAuth failures use 401; authorization 403 has no signature error/negotiation
  headers. Generic Signature Keys status policy remains separately tested.
- [ ] Old hwk/jwks_uri shapes and removed error members are absent from active
  producers/consumers and rejected by negative fixtures.
- [ ] Core/conformance/R3 tests and build pass with all compiled consumers updated.

## Phase 4 - admitted discovery and cache behavior

Findings: F08-F09, fetch part of F26. Depends on Phase 3.
Target: protocol [L2517](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2517)
(`#jwks-discovery`) and Signature Keys
[L2372](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L2372) (7.3).

Phase rule: strict production admission; explicit narrow development policy only.

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

- [ ] DNS/private/link-local/loopback, redirect-to-private, mixed-address,
  cross-origin, oversized-body and timeout tests exercise real handler boundaries.
- [ ] Missing/mismatched issuer and invalid identifier syntax fail before trust.
- [ ] Parallel cold fetches and failed fetches honor the same one-minute floor.
- [ ] Unknown-kid/same-kid rotation still succeeds after the allowed interval.
- [ ] Explicit dev fixtures pass; production defaults reject their HTTP URLs.
- [ ] Discovery/R3 targeted tests, affected projects, and build pass.

## Phase 5 - consent and deferred state machines

Findings: F12-F15, AS clarification capability. Depends on Phases 1-4.
Target: protocol [L1054](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1054)
(`#agent-response-to-clarification`), [L2136](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2136)
(Interaction Code Format), [L2825](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2825)
(Deferred Response Security).

Phase rule: explicit action and verified owner context, never legacy payload inference.

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

- [ ] Foreign-owner GET/POST/DELETE and forged same-sub/different-key attempts fail.
- [ ] Missing/unknown/mismatched action returns 400; malformed or differently bound
  replacement tokens fail; valid narrowed replacements affect the issued token.
- [ ] Code aliases, reuse, expiry, attempt limits, concurrent approval, denial
  reversal, terminal replay, and cancellation have end-to-end HTTP tests.
- [ ] Keycloak cannot be bypassed through stub approve/deny endpoints.
- [ ] AS clarification works through the PS to the agent and back, with bounded
  polling, timeout, denial and cancellation behavior.
- [ ] Relevant integration/conformance/e2e suites and solution build pass.

## Phase 6 - federation and delegation trust

Findings: F17-F19, F20. Depends on Phases 2-5.
Target: protocol [L934](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L934),
[L1511](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1511)
(PS-to-AS Token Request), [L1574](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1574)
(Auth Token Delivery), [L1809](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1809)
(Directed Identifiers Across a Chain), [L2041](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2041)
(`#scopes`).

Phase rule: preserve authenticated context end to end; no placeholder consent grant.

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

- [ ] Deny/NeedsConsent never releases claims or returns a grant prematurely.
- [ ] Immediate AS 200 and interaction-only 202-to-200 tests prove PS policy is
  evaluated even without a claims request; deny/consent-needed withhold the grant.
- [ ] Three-party, four-party, chained and combined sub-agent cases bind the
  right key/agent and exact actor chain, with distinct actors/keys in fixtures.
- [ ] Invalid upstream structure, trust, audience, mission or person-in-act fails.
- [ ] Wrong immediate actor is rejected even when nested context matches.
- [ ] Unadvertised resource/identity scopes fail; legitimate narrowed scope works.
- [ ] Core/conformance/integration tests, compiled interop scenario and build pass.

## Phase 7 - issuer-qualified revocation

Finding: F16. Depends on Phases 2-6.
Target: protocol [L2361](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2361)
(`#token-revocation`) and [L2390](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2390)
(AP-to-PS revocation).

Phase rule: `(iss,jti)` only; no bare-jti API or wire fallback.

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

- [ ] Same jti from two issuers remains isolated in store and real middleware.
- [ ] Unauthorized cross-issuer requests fail; authorized issuer/trusted PS works.
- [ ] Missing members fail, unknown pairs return 404, repeated known revocation 200.
- [ ] AP-to-PS revoke blocks reuse and cascades to tracked resource grants.
- [ ] Legitimate token reuse remains possible with fresh signatures.
- [ ] Targeted revocation/integration suites and build pass.

## Phase 8 - account-aware authorization

Finding: F21. Depends on Phases 2, 5-7.
Target: protocol [L2055](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2055)
(`#account-binding`), R3 [L378](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L378).

Phase rule: one typed account contract; absent means absent, not an inferred default.

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

- [ ] Request/resource-token/auth-token/R3 account values remain identical.
- [ ] Wrong-account execution, cache reuse and prior-consent reuse fail.
- [ ] Accountless access still works without inventing an account claim.
- [ ] Deferred, chained, refreshed and R3 flows preserve isolation.
- [ ] Compiled samples, tests and build pass.

## Phase 9 - R3 models, grants, audit and policy variants

Findings: F22-F26. Depends on Phases 3-8.
Target: R3 [L161](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L161)
(`#openapi-gateway-vocabulary`), [L590](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L590)
(`#per-call-proposals`), [L616](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L616)
(Audit Log Integrity), [L624](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L624)
(Grant Enforcement).

Phase rule: vocabulary-correct operation identity, no legacy bare-id alias.

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

- [ ] All standard vocabulary shapes round-trip; required/optional/malformed
  fields and two Gateway services sharing an operationId are tested.
- [ ] Wrong vocabulary/member/service cannot gain a same-id grant.
- [ ] Granted/conditional/rejected behavior matches policy across Bookings routes.
- [ ] Tampered document/proposal/parameters fail; custom fetch contracts are explicit.
- [ ] Audit cannot silently disappear; failure/concurrency/restart tests verify
  token release and audit association under the selected storage model.
- [ ] Dedicated R3 tests, integrated core tests, Bookings e2e and build pass.

## Phase 10 - complete Events companion flow

Findings: F27, Events portion of F28/F31. Depends on Phases 3-9.
Target: Events [L277](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L277)
(`#subscribe-token`), [L368](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L368)
(`#event-token`), [L424](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L424)
(`#event-delivery`), [L447](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L447)
(`#ap-to-agent`), and [L603](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L603)
(Pre-Authorized Subscription URL Security).

Phase rule: exact subscribe/event wire types and self-jwt; no draft-09 delivery shim.

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

### Definition of Done

- [ ] No EventToken cnf; unknown typ, wrong AP/resource/agent, expired/future claims,
  missing eid, mismatched HTTP key and tampered payload fail as appropriate.
- [ ] Ticket reuse, wrong-agent redemption and concurrent redemption fail safely.
- [ ] Concurrent max_uses cannot overrun; persistence failure never yields 202;
  restart preserves accepted events and quotas.
- [ ] Agent never acts on expired/mismatched/unverified events; duplicate behavior
  follows the recorded spec interpretation without invented wire fields.
- [ ] Public and protected AsyncAPI/R3 flows work end to end with captured headers.
- [ ] New Events tests run in the solution and CI; complete sample/e2e and build pass.

## Phase 11 - cross-cutting security and conformance closure

Findings: all P1/P2 findings plus the research coverage limits. Depends on Phases
1-10. Target: protocol [L1488](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1488)
(mission presentation), [L1490](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1490)
(no mission dereference), and [L2507](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2507)
(`#freshness-and-replay`), plus each finding's canonical references.

Phase rule: satisfy the normative baseline; do not invent hardening MUSTs.

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

### Definition of Done

- [ ] Every normative area has an explicit ledger disposition and test evidence
  or documented deployment responsibility; no unexplained MUST gap remains.
- [ ] High-stakes R findings are directly reproduced/rechecked and resolved.
- [ ] Threat-oriented tests pass without breaking existing positive controls.
- [ ] Core/R3/Events/solution tests and both policy-mode e2e runs pass.

## Phase 12 - frozen-surface samples, snippets and docs sweep

Findings: F29-F31 and every user-facing change. Depends on Phase 11; compiled
consumer fixes have already happened in their owning phases.
Target: protocol [L2420](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2420)
(`#keying-material`) and interop profile
[L9](../../../aauth-spec/v10/interop-demo-profile.md#L9) through its five surfaces.

Phase rule: describe only the final v10 API and supported capabilities, not legacy aliases.

### Responsibilities and files

- Inventory every surface in the research ownership map. Cover root/package/
  sample READMEs, docs index/concepts/glossary, all signing/server/workflow/
  advanced/reference docs, GuidedTour CodeSnippets/TourSession/Razor content,
  SampleApp pages and both Playwright suites. Record `file | finding | edit | check`.
- Separate generic HTTP Signature Keys demos from four AAuth access modes in
  routes, policy, headings and diagrams. Ensure getting-started teaches a valid
  agent-token path and labels generic signing examples accurately.
- Replace old algorithm/error/action/revocation/carrier snippets. Add account,
  EventAgent/AsyncAPI, AS clarification, strict egress, consent session and
  supported-capability guidance. Keep hardware-attestation claims honest.
- Compile or execute representative fenced and string-literal examples through
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

- [ ] Every ownership-map surface has a recorded disposition, not only grep hits.
- [ ] No stale executable wire shape remains except deliberate rejection fixtures.
- [ ] Snippets compile/run; displayed bodies/headers match actual v10 behavior.
- [ ] Every affected embedded snippet in both apps has a recorded validation
  result or an explicit illustrative-placeholder classification; no stale API,
  wire shape, comment or numbered-step reference remains.
- [ ] Both apps' numbered steps, sequence visuals, displayed/copied snippets and
  payloads agree with the implemented flow, including consent, clarification,
  immediate grants, retries, denial and cancellation where applicable.
- [ ] Both Playwright suites check affected step navigation, approval/polling
  transitions and displayed snippet/payload associations, not only final success.
  Desktop and narrow-viewport visual checks cover labels, arrows, loops,
  highlights, clipping and overlap.
- [ ] Docs links and anchors resolve; examples do not mislabel generic signing as AAuth.
- [ ] Full-stack fresh-server e2e and all interop surfaces have recorded results.
- [ ] Version/capability claims match the implemented and verified scope.

## Phase 13 - independent internal review

Depends on Phase 12. Give a fresh read-only subagent the final diff, immutable
v10 sources, research, this plan, implementation log and requirement-to-test
ledger. Require severity-graded findings with reverified source lines, including
negative requirements, optional-capability boundaries, samples and docs.

Phase rule: no compatibility exception or spec interpretation is implicit.

### Definition of Done

- [ ] Every review finding has a recorded disposition and supporting evidence.
- [ ] Approved fixes have focused regression tests and rerun affected gates.
- [ ] Material architectural changes receive another independent review.
- [ ] Release solution tests, explicit R3/Events suites, stub/Keycloak e2e,
  snippet checks, links, and the requirement ledger are complete.
- [ ] Unavailable external live interop is explicitly reported, with local
  captured-wire evidence; no blanket full-conformance claim hides it.
- [ ] All changes remain uncommitted for owner inspection unless requested otherwise.

## Finding-to-phase traceability

| Findings | Owning phases |
|---|---|
| F01-F07 | 3; discovery dependencies in 4; cross-cutting review in 11 |
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
| F29-F30 | Compiled consumers in owning phases; final sweep in 12 |
| F31 | 1/3 (bootstrap shared behavior), 10 (AP integration), 12 (documentation) |
| Coverage limits and all negative requirements | 11 and independent review 13 |

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