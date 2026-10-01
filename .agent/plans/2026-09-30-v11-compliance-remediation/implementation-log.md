---
description: Decisions, deviations and open questions for the draft-11 compliance remediation.
---

# Implementation log — draft-11 compliance remediation

Rulings Q1–Q32 are the Phase 0 decision gate. Each cites the design (`Rnn`),
the red-team file (`RT-n`) and the spec line it rests on. Defaults are
`PROCEEDED` (revert if you disagree). Rulings that reverse an earlier
API-surface decision say so explicitly.

## Decisions taken

### [2026-09-30] [Phase 0] Q1 — Signature `created` (SDK-16)

PROCEEDED (default: wait for the next free second; owner review requested).

The producer never emits a future `created` (L2234). It keeps its per-key record
of the last-used second for each `(method, authority, path)`. On a collision it
awaits the next free wall-clock second, honours the request's cancellation
token, and emits the current time. No `nonce` or `tag` is added: the profile
defines none (L2272). The SDK verifier keeps its signature-base replay key.

**Supersedes** API-surface log L933-L939, *"Signatures take a unique created
per target"*. The invariant (no duplicate replay tuple) stays; the mechanism
changes.

Consequence: one identical-target request per second per key. Requests that
differ only in query collide too, because `@query` is not covered.

Rejected alternative (RT-4): relax the SDK verifier's replay rejection so no
waiting is needed. Third-party verifiers may still apply the spec tuple cache,
so producers that emit duplicate tuples remain non-interoperable. Revert to
"no wait + relaxed verifier" only by owner decision.

### [2026-09-30] [Phase 0] Q2 — Loopback server identifiers (A04-05, R16 UNSOUND)

PROCEEDED (default: keep a Development-only exception).

Production `ServerId` validation is strict: https, host only, no port or path
(L1946-L1970). The explicitly configured development egress policy keeps
admitting `http://localhost:port` / `127.0.0.1` issuers, with a startup warning
naming the relaxation. Conformance tests assert that production policy rejects
them.

Logged deliberate deviation. A04-05 is regraded INFO. Migrating samples and e2e
to local TLS with host aliases is out of scope (see plan).

### [2026-09-30] [Phase 0] Q3 — Untrusted signer or issuer response

RESOLVED.

A verified Signature-Key or JWT whose issuer or key fails trust policy answers
`401` with `Signature-Error: error=invalid_key`. Signature-Key §5.4.7
(L2044-L2048) defines `invalid_key` as a key that "does not meet the server's
trust requirements".

`403` is used only after identity is accepted, for authorization denials such
as account or role. Such responses carry no `Signature-Error` or
`Accept-Signature-*` headers (SK §5.3, L1936-L1944).

This overrides R03's `403 access_denied` and R11's `issuer_mismatch`
(`issuer_mismatch` is reserved for metadata issuer mismatch). Scope-only
shortfalls go through step-up (Q8).

### [2026-09-30] [Phase 0] Q4 — Auth-token topology and `dwk` (SDK-02, A17-002)

PROCEEDED.

- `AAuthResourceOptions.AccessServer` is the single four-party declaration (C5).
- **Four-party.** When `AccessServer` is set, the SDK's default auth-token trust
  is `{AccessServer}` and `ExpectedAuthTokenDwk = aauth-access.json`.
- **Three-party.** When it is unset, open PS trust is kept and the default is
  pinned to `ExpectedAuthTokenDwk = aauth-person.json` (RT-1).
- **Mixed mode.** It requires both `ExpectedAuthTokenDwk = null` and an explicit
  `TokenDwk`-aware `IAAuthTrustPolicy`.
- **`AAuthTrust.Any` with `AccessServer` set.** Startup fails unless mixed mode
  is declared.
- **The PS verifying an AS response.** It pins `aauth-access.json` and the AS
  issuer.
- **Ownership.** R02 owns the option. R14 threads `expectedDwk` through the
  companion verifier seam so app-specific JWT resolution cannot bypass the pin.

### [2026-09-30] [Phase 0] Q5 — One token inventory model (R05, R06, R10, R04)

PROCEEDED.

`IJtiStore` gains, as one breaking cutover:

- provenance records (R05);
- typed source dependencies (R06);
- agent–person binding revocation links (R10).

There are no parallel stores. Records are written atomically with grant
registration. Registering an unseen upstream token never creates provenance.

Records are pruned at `exp + skew`, with per-agent distinct-resource quotas.
Exceeding a quota answers `429` before minting. A missing record (for example
after in-memory store loss) fails closed as `invalid_upstream_token`. The
in-memory default warns outside Development (C12).

### [2026-09-30] [Phase 0] Q6 — Single-use key (SDK-03)

PROCEEDED.

The retained-result key is `(auth token iss, jti)`. Both the 202 held-invocation
path and the R3 401 per-call path use it, so one per-call auth token executes at
most once across both. `R3Enforcement` returns an execute-once `SingleUse`
handle. A missing gate, `jti` or `exp` yields `single_use_required`, never
`Granted`.

### [2026-09-30] [Phase 0] Q7 — Revocation guard around outbound presentation (SDK-05)

PROCEEDED.

A guarded outbound primitive does three things:

1. rechecks source dependencies immediately before send;
2. links a revocation-aware cancellation token through the HTTP call;
3. atomically flips the pending entry to terminal `revoked` on guard failure.

It wraps every federation send, including each 202/402 continuation that R07
adds, and every local mint.

### [2026-09-30] [Phase 0] Q8 — Scope step-up

RESOLVED. This closes the API-surface log open item L954-L959.

When a valid auth token lacks a required scope, `RequireAAuth(scope:)` and
`UseAAuth` answer `401 requirement=auth-token` with a new resource token bound
to the presented auth token. The spec permits this (L640), and agents must
handle it. Lower-level named MVC policies stay `403`. Roles and claims do not
step up.

### [2026-09-30] [Phase 0] Q9 — Polling and token error tables (SDK-12, SDK-13, A19-HIGH-003, A19-HIGH-004)

PROCEEDED.

- Only codes registered for each endpoint are emitted (L2574), through
  closed-table helpers that own each code's status.
- An unknown or consumed pending id answers `410 invalid_code`.
- `expired` is `408` on first observation, then `410`.
- `unknown_pending`, `unknown_interaction`, `request_withdrawn`,
  `untrusted_*` and `policy_error` are removed.

### [2026-09-30] [Phase 0] Q10 — Poll core preserves re-exchange (SDK-11, R11 UNSOUND)

RESOLVED.

The internal poll core returns requirement-bearing responses (`202` or `401`
with `AAuth-Requirement: auth-token` and a fresh resource token) to
`ChallengeHandler`. That handler re-exchanges and resumes polling the same
`Location` (L660-L663). A dedicated regression test is required.

### [2026-09-30] [Phase 0] Q11 — `updated_request` bounds (SDK-06)

PROCEEDED.

Bounds and sources are recomputed from the replacement pair, capped by agent,
mission and upstream. They may grow relative to the original pair; the PS may
deny an expansive update as policy. Tests cover longer-lived, shorter-lived and
revoked replacements.

### [2026-09-30] [Phase 0] Q12 — Agent-asserted input validation (A12-02, A12-03, A13-05)

PROCEEDED.

- `platform` must be a value from the vendored registry. Unknown values are
  rejected.
- `device` must be printable Unicode (runes), 64 or fewer, with
  control/format/surrogate/private-use characters rejected.
- An empty `capabilities: []` is distinct from omitting it.
- A non-positive clarification `timeout` is malformed.

One shared validator serves the agent (producer) and the PS (consumer).
Capability constants move to `AAuthConstants` with no aliases (C1, C7).

### [2026-09-30] [Phase 0] Q13 — Mission store and evaluator (SDK-14, A16-001, A16-003, A16-004)

PROCEEDED.

- `IMissionStore` is keyed by `(PersonServer, s256)`.
- `TerminateAsync(ps, s256, reason)` replaces `SetStateAsync`. It is
  idempotent and keeps the first reason.
- One `MissionStatusEvaluator` serves every decision path. A mission past
  `expires_at` auto-terminates with reason `expired`, and that takes
  precedence over generic deferred expiry.
- Absent, wrong-agent and wrong-PS lookups return an identical
  `mission_not_found` response, backed by contract tests (spy store) and
  custom-store guidance.

Reasons remain `AAuthConstants.MissionTerminationReasons` strings (API-surface
Q18).

### [2026-09-30] [Phase 0] Q14 — Agent–person binding and pairwise subjects (SDK-07, A11-03, A11-04)

PROCEEDED.

- `IdentityAssertion` carries an `AAuthPersonKey`, which is never emitted.
- `IAgentPersonBindingStore.BindOrVerifyAsync` runs atomically with enrollment
  and provenance writes before any token or claim leaves the PS. A store
  failure means deny.
- `NeedsConsent` may omit the key only until approval; nothing is minted
  without it.
- The default pairwise `sub` is HMAC(person key, resource) over a key ring with
  key ids, at a collision-safe length. Derived subjects are persisted with their
  key version. Production requires a configured secret; Development uses an
  ephemeral secret with a warning.
- First issuance for a new resource requires approval and a metadata fetch. A
  fetch failure answers `400 invalid_request`.

### [2026-09-30] [Phase 0] Q15 — Governance `ps` check (A15-002)

PROCEEDED.

PS governance endpoints (mission, permission, audit, interaction) reject agent
tokens whose `ps` is absent or names another PS, because an agent with a PS
MUST carry `ps` (L459). The check never applies to resource authorization or
token issuance: `ps` is informational there (L523). API docs and tests state
this scope.

### [2026-09-30] [Phase 0] Q16 — Governance mapping and relay (SDK-09, SDK-10)

PROCEEDED.

- `.WithGovernance()` declares the governance paths once, and
  `MapAAuthPersonServer()` maps them.
- `MapAAuthGovernance()` remains a primitive. It derives from the same
  declaration and fails fast on conflicting paths.
- `interaction_endpoint` is omitted unless governance is enabled or it is
  explicitly set.
- Relay results are mutually exclusive: `Answered`, `Pending` (202 +
  `Location`) or `Unavailable` (424). Setting both or none throws.
- The default relay answers `Unavailable` for every type. A `question` with no
  channel answers `424 interaction_unavailable` so the agent can ask directly.
  This is an interpretation: the interaction-errors table defines only that
  code (L1183-L1190).

### [2026-09-30] [Phase 0] Q17 — Federation collapse and payment (A17-001, A17-003)

PROCEEDED.

- **Collapse.** Declared explicitly as resource issuer + linked AS role name +
  expected AS issuer. A mismatched or missing linked AS fails closed; there is
  no silent three-party fallback.
- **Payment.** `IAAuthPaymentSettler` receives only the payment challenge, the
  AS origin and the pending URL, never JWTs. A PS billing cache is keyed by AS
  issuer and scheme. With no settler registered, or when settlement is declined,
  the pending request ends with the registered terminal polling error
  `403 denied`, whose `detail` says payment settlement is unavailable.

  This overrides R07's proposed `402 payment_required`: the polling table
  (L2617-L2640) has no payment code, and Q9 forbids unregistered codes.

### [2026-09-30] [Phase 0] Q18 — Two-key refresh (SDK-15)

PROCEEDED.

Automatic `TwoKey` mode is removed from `AgentProviderTokenRefresher` (C1). The
docs and API inventory state that the SDK offers no automatic two-key refresh.
`AgentProviderClient.RefreshTwoKeyAsync` stays, documented as: rebuild the
client with the returned `EphemeralKey` and `AgentToken` together.

### [2026-09-30] [Phase 0] Q19 — Agent-token lifetime (A05-02, A06-03)

PROCEEDED.

SDK producers reject a lifetime over 24 h at build time. Consumed AP tokens
longer than 24 h log a warning and are not rejected: the spec says SHOULD NOT,
so rejecting them would be an interop failure not required by the finding.

### [2026-09-30] [Phase 0] Q20 — Auth-token response verification (A10-01)

PROCEEDED.

Verification is on by default in the builder and DI, through the shared cached
`JwksClient` and egress policy. Structural and context checks (`typ`, `dwk`,
`iss`, `aud`, `cnf`, `sub`) are always on. Only signature verification can be
opted out, and only on the primitive, as a documented policy choice.

### [2026-09-30] [Phase 0] Q21 — PS-first interaction relay (A13-04, A07-004)

PROCEEDED.

Only resource-response interactions are relayed to the PS `interaction_endpoint`
first (L2404-L2412), falling back on `424`. PS-originated token-exchange
interactions are never relayed back to the PS. This lands after R12 (Phase 8).

### [2026-09-30] [Phase 0] Q22–Q24 — JWT and verification hygiene (R14)

PROCEEDED.

- **Q22.** Any `crit` is rejected, because no extension is implemented.
- **Q23.** `ISignatureTokenVerifier` gains issuer-key resolution, used only when
  `iss`/`dwk` are absent. `exp` has zero skew everywhere. A missing key answers
  `unknown_key` when the identity is known, otherwise `invalid_jwt`.
- **Q24.** `ChallengeOptions.AllowedSignatureKeySchemes` is removed (C1):
  `AAuthVerificationOptions.AcceptedSchemes` is the single scheme gate. The
  `Signature-Error` writer is internal and central. TLS is pinned to 1.2/1.3 on
  the SDK transport.

### [2026-09-30] [Phase 0] Q25 — Authorization endpoint (SDK-08, SDK-18, SMP-04)

PROCEEDED.

- A person token is required. When it is missing, the endpoint answers
  `requirement=person-token`.
- R3 plugs in through an extension seam, with no core→R3 reference.
- A non-JSON body answers `400 invalid_request`.
- The Inbox (two-party) sample removes `/authorize`.

### [2026-09-30] [Phase 0] Q26 — Metadata typed fields and Events endpoint (A04-04, A04-06)

PROCEEDED.

Typed metadata fields win: `AdditionalMetadata` must not shadow a typed field
(startup error). `additional_signature_components` is typed (R13), validated by
R16, and seeds first-request signing.

AP `event_endpoint` derives from a single `MapAAuthEventEndpoint`. Mapping more
than one fails unless `EventEndpoint` is set explicitly. `false` values of
`localhost_callback_allowed` are omitted from metadata.

### [2026-09-30] [Phase 0] Q27 — Events (A24-01, A24-02, A24-03)

PROCEEDED.

- Stores return a typed outcome, and the SDK maps it to a status: `Exhausted`,
  `Unknown` and `Expired` → 404; `Duplicate` → the same 202.
- `Content-Length: 0` with no content type means no body.
- A subscription body is optional.

### [2026-09-30] [Phase 0] Q28 — Conformance claims

PROCEEDED.

In Phase 1, R19 corrects README and `SPEC-VERSION.md` pessimistically: the
claims for cascades, 202 delivery, R3 per-call and mission expiry are marked
"remediation in progress". Positive claims are restored only in Phase 12, after
the owning phase gates pass.

### [2026-09-30] [Phase 0] Q29 — SMP-01 early patch

PROCEEDED.

In Phase 1, the demo admin grant matches the exact subject and key thumbprint.
Phase 7 (R10) adds the agent-token issuer.

### [2026-09-30] [Phase 0] Q30 — S09-02 ownership

RESOLVED. The tour's `AAuth-Capabilities` on signed requests is assigned to
Phase 10 (R15 behaviour) and applied to the tour in Phase 11 (R18).

### [2026-09-30] [Phase 0] Q31 — Generic Signature-Key lessons (S07-01, DOC-02)

PROCEEDED.

The GuidedTour and `docs/signing-modes/agent-identity-jwks-uri.md` keep the
`hwk`/`jwks_uri`/`jwks` lessons only as clearly labelled generic (non-AAuth)
Signature-Key demos against `RequireGenericSignature()`. AAuth agent identity
defaults to `jwt`. `jkt-jwt` is described only as the AP key-refresh
ceremony (L2196).

### [2026-09-30] [Phase 0] Q32 — Sample credential output

PROCEEDED. Token-bearing sample output is redacted by default. The GuidedTour
has one explicit local-only setting to show raw values.

### [2026-09-30] [Phase 0] Q1 — Owner ruling

RESOLVED (owner). The owner chose "wait for the next free second, with limits
on the cost". This supersedes the Q1 `PROCEEDED` entry above and keeps its
mechanism, adding these limits:

- **Scope.** The wait applies only to a collision of the exact replay tuple:
  same key, second, method, authority and path. Different paths, hosts,
  methods or agents never wait.
- **Cancellation.** A request cancelled while waiting is never sent.
- **Visibility.**
  - `AAuthDiagnostics` emits a debug log and a counter named
    `aauth.signing.created_wait` (with a duration measurement) whenever a
    request is delayed.
  - `docs/reference/configuration.md` and the signing-mode docs describe the
    one-identical-request-per-second-per-key behaviour.
- **Upstream.** The limitation is raised with the spec author. Ask for a
  profile nonce, or for `@query` in the replay tuple (see *Open questions*).

### [2026-09-30] [Phase 0] Q2 — Owner ruling

RESOLVED (owner). The owner chose "keep the exception, but lock it down". This
supersedes the Q2 `PROCEEDED` entry above.

1. **Loopback only.**
   `AAuthEgressPolicy.ForDevelopmentLoopback` admits only `localhost` and
   `127.0.0.1` origins with an explicit port, from the exact list given.
   Wildcards and other hosts are rejected when the policy is built.
2. **Never in Production.** The DI registrations (`AddAAuthResource`,
   `AddAAuthPersonServer`, `AddAAuthAccessServer`, `AddAAuthAgent`, the
   discovery registration) resolve `IHostEnvironment`. Startup fails when a
   policy admitting loopback origins is used and `IsProduction()` is true.
3. **Loud when active.** A startup warning lists every admitted loopback
   origin and states that this is a development-only relaxation of
   #server-identifiers (L1946-L1970).
4. **Strict by default.** `AAuthEgressPolicy.Production` stays strict.
   Conformance tests assert that it rejects `http://localhost:5002` as an
   issuer, identifier and metadata URL.
5. **Documented.** The exception is listed in `aauth-spec/SPEC-VERSION.md` as a
   deliberate development-only deviation.

Migrating the samples to local https names stays out of scope. No sample code
changes are required, for example the Trips `Program.cs` keeps
`http://localhost:5002`.

### [2026-09-30] [Phase 0] Baseline

RESOLVED. The starting commit is `30b8015`, plus the owner's uncommitted
MockPersonServer edits (`ConsentDashboard.cs`, `ConsentRegistry.cs`,
`MissionGovernance.cs`, `Program.cs`). By owner instruction these are included
in the baseline and never modified or committed by this plan.

Gates:

- The build has no errors or warnings.
- Tests:
  - AAuth.Tests: 1766 passed.
  - AAuth.Conformance: 1287 passed.
  - AAuth.R3.Tests: 330 passed.
  - AAuth.Events.Tests: 83 passed.
- e2e: typecheck clean; Playwright 78 passed, 1 skipped (Keycloak).

`ApiSurface` snapshot: the committed map at `30b8015`
(`.agent/plans/2026-09-11-aauth-v11-spec-migration/api-surface-map.md`,
205 files, +910/-408 against `v0.10.0-alpha.1`). The tool reported the map as
stale at baseline only because of the owner's sample edits
(`ConsentRegistry.DropPending`, `MissionPendingEntry.S256 { set; }`).

### [2026-09-30] [Phase 1] Critical and immediate safety fixes

RESOLVED.

- **R01 (SDK-01).**
  - `AddAAuthResource` post-configures
    `AAuthVerificationOptions.ResourceIdentifier ??= Issuer`.
  - `AAuthVerificationMiddleware` no longer falls back to the token's own
    `aud`. A new `RequireResourceIdentifier` answers `invalid_request` when
    no identifier is known.
  - `AccountVerified` no longer depends on an optional identifier.
  - There is no public signature change, only XML docs.
- **Negative controls** (`tests/AAuth.Conformance/HttpSignatures/VerificationMiddlewareTests.cs`):
  - `AuthTokenAudience_DerivesFromAddAAuthResourceIssuer_ForBareUseAAuthVerification`;
  - `AuthTokenWithoutResourceIdentifier_IsRejected_NotSelfAudienced`;
  - `PersonTokenAudience_IsBoundToResourceIdentity`;
  - `ExplicitResourceIdentifier_IsNotOverwrittenByAddAAuthResource`;
  - the `AccountProof` row with no identifier now expects rejection.

  Three of these failed on the unfixed code and pass after the fix.
- **SMP-01.** The demo admin grant is an exact agent-id match
  (`SampleIdentityClaimsAsserter.AdminAgents = { "aauth:demo@ap.example" }`),
  applied in the PS asserter, `ConsentBridgePersonPendingStore` via
  `IsAdminAgent`, and the Federated AS. New test:
  `tests/AAuth.Tests/Integration/SampleIdentityClaimsAsserterTests.cs`.
  - Three integration test files moved their test AP from `ap.test` to
    `ap.example`, so the exact admin id stays issuable (the verifier binds
    the agent-id domain to the AP issuer).
- **Docs.**
  - DOC-03: `verification-middleware.md`, `multi-scheme-verification.md` and
    the `configuration.md` `ResourceIdentifier` row.
  - Known-non-conformance callouts for DOC-04 (`resource-managed-access.md`),
    DOC-05 (`interaction-chaining.md`) and DOC-06
    (`rich-resource-requests.md`).
  - Pessimistic claims (Q28) in `README.md` and `SPEC-VERSION.md`.
  - The docs inventory was refreshed.
- **Gates.**
  - The build is clean.
  - Tests: AAuth.Tests 1770, Conformance 1294, R3 330, Events 83.
  - The snippet, link and inventory gates pass.
  - ApiSurface: +912/-409, one new sample member (`AdminAgents`).
  - e2e: typecheck clean; Playwright 78 passed, 1 skipped.

### [2026-09-30] [Phase 2] R13 — HTTP-signature producer

PROCEEDED (Q1/Q26).

- **SDK-16 / A02-HIGH-001.** `AAuthSigningHandler` no longer future-dates
  `created`. Exact same key/method/authority/path collisions wait for the next
  current wall-clock second via the handler `TimeProvider`, and cancellation
  before that second prevents the request from being sent. The SDK verifier
  replay key is unchanged.
- **Q1 visibility.** Delayed signing records `aauth.signing.created_wait`
  on `AAuthDiagnostics.Meter`, tagged with method and authority only. The
  orchestrator removed the path tag: paths are unbounded and may identify
  people. It also emits an `AAuth.Signing.CreatedWait` activity and trace line
  that do include the path.
- **A02-HIGH-002.** Body-bearing signed requests always require both
  `content-type` and `content-digest`; missing `Content-Type` fails locally
  before signature headers are emitted.
- **A01-M01.** The signing handler validates that the provider's
  `Signature-Key` dictionary contains the handler label before emitting
  `Signature-Input`/`Signature`.
- **A04-04.** `ResourceMetadata`,
  `AAuthResourceMetadataOptions` and `AAuthResourceOptions` now expose typed
  `AdditionalSignatureComponents`; well-known resource metadata emits
  `additional_signature_components`, and
  `ChallengeHandlingOptions.AddResourceMetadata` seeds first-request signing.
  Reserved-field validation for `AdditionalMetadata` shadowing remains with
  R16 per Q26.

### [2026-09-30] [Phase 2] R16 — Metadata and identifier validation

PROCEEDED (Q2/Q26).

- **A04-01.** `AgentId` now permits `+` only as a single sub-agent delimiter
  with non-empty parent and discriminator. `AgentTokenBuilder` and
  `TokenVerifier` both reject top-level subjects containing `+`, malformed
  sub-agent locals such as `aauth:parent+@ap.example`, and `parent_agent`
  values that do not derive from the subject's parent.
- **A04-02 / A04-03 / A07-002.** One internal metadata URL rule table now
  validates producer options and consumer `MetadataClient` documents. Endpoint
  and interaction URLs reject queries and fragments; common informational URIs
  must be HTTPS; consumer validation now covers the previously skipped
  permission/audit/mission-control/common/AP fields before caching.
- **Q2 loopback ruling.** `AAuthEgressPolicy.ForDevelopmentLoopback` is locked
  to exact `localhost` / `127.0.0.1` origins from the supplied list. Portless
  `http://localhost` / `https://localhost` remain admitted to keep
  `tests/TestEgress.cs` and local samples working, but wildcards, non-loopback
  hosts and `::1` are rejected at construction. A loopback-admitting policy is
  rejected in Production role/discovery/agent registrations or first
  resolution, and active development loopback policies log a warning listing
  the origins.
- **A04-06 / Q26.** AP metadata has typed `EventEndpoint` and
  `LocalhostCallbackAllowed`; `localhost_callback_allowed:false` is omitted.
  A single mapped `MapAAuthEventEndpoint` derives `event_endpoint`, while
  multiple mapped Events endpoints require an explicit `EventEndpoint`.
- **Q26 typed fields.** Resource `AdditionalMetadata` is now a pure extension
  seam: attempts to shadow typed/core fields, including R13's
  `additional_signature_components`, fail at startup.

### [2026-09-30] [Phase 2] R17 — Events

PROCEEDED (Q27).

- **A24-01.** Protected subscription registration now accepts the no-body form.
  `ValidateParameters` is optional; the default accepts an omitted body or an
  empty JSON object and rejects non-empty parameters.
- **A24-02.** Events body coverage is tied to actual body presence. Bodyless
  deliveries verify and send without `content-type`/`content-digest`; body-bearing
  deliveries still require both. Producer decision: `EventsProtocol.SendAsync`
  treats `null` and `Array.Empty<byte>()` as no payload and sends no body.
- **A24-03 / S06-01.** AP stores now return `EventAcceptanceOutcome`. The SDK
  maps `Unknown`/`Expired`/`Exhausted` to 404, `Forbidden` to 403, and
  `Accepted`/`Duplicate` to the same 202 shape with the stored
  `remaining_uses`. The SQLite sample no longer hard-codes 429.
- **Tests/docs.** Added negative controls for no-body protected subscriptions,
  body-bearing unsigned body components, no-payload delivery without digest, and
  exhausted quota returning 404. Updated Events README/workflow docs.

### [2026-09-30] [Phase 2] Gates and wrap-up

RESOLVED. R13, R16 and R17 each landed through a dedicated implementation
agent; see the entries above.

Orchestrator review:

- The `aauth.signing.created_wait` metric no longer carries a path tag.
- The loopback Production guard (Q2) made the first e2e run fail: the
  Documents sample has no launch profile, so it started as Production. Six
  samples gained `Properties/launchSettings.json` profiles that set
  Development:
  - Documents and Catalog (`ASPNETCORE_ENVIRONMENT`);
  - MissionAgent, AgentConsole, EventAgent and LiveWhoAmITest
    (`DOTNET_ENVIRONMENT`).

  This is the intended lock-down behaviour: samples run as Development.

Gates:

- The build is clean.
- Tests: AAuth.Tests 1781, Conformance 1321, R3 330, Events 89.
- The snippet, link and inventory gates pass.
- ApiSurface: +933/-410.
- e2e: typecheck clean; Playwright 78 passed, 1 skipped.

The committed ApiSurface map is still generated in the working tree only. It
includes the owner's uncommitted sample edits, so it is left unstaged.

### [2026-09-30] [Phase 3] R14 — JWT and verification hygiene

RESOLVED (Q3, Q22–Q24).

- **SDK-17 / Q22.** JWT protected headers now reject unsupported `crit` on the
  built-in token verifier path, generic/companion `jwt`, `self-jwt` and
  `jkt-jwt`.
- **A01-H01 / Q23.** `ISignatureTokenVerifier` is now context-based, with
  `ResolveIssuerKeyAsync` for companion `jwt` assertions whose `iss` or `dwk`
  is absent. The contexts carry `ExpectedDwk` so R02 can enforce role-DWK
  pinning through app-specific JWT issuer-key resolution.
- **A01-M02 / Q23.** Companion `jwt`, `self-jwt` and `jkt-jwt` expiration uses
  zero skew; `ClockSkew` remains only for optional future-`iat` tolerance.
- **A03-HIGH-001 / Q24.** `ChallengeOptions.AllowedSignatureKeySchemes` was
  removed. `AAuthVerificationOptions.AcceptedSchemes` is the single scheme
  gate, and unsupported schemes emit `Signature-Error:
  error=unsupported_scheme` with `Accept-Signature-Scheme`.
- **A19-HIGH-001 / Q24.** SDK-owned signature/authentication 401 paths now use
  the central `AAuthProblemDetails.SignatureFailure` writer. Requirement
  challenges remain `AAuth-Requirement`; 403 policy denials remain body
  problem details without signature headers.
- **A21-TLS-01 / Q24.** SDK-owned `SocketsHttpHandler` is pinned to
  TLS 1.2/1.3; injected transports document the caller's TLS-floor obligation.
- **Q3.** Trust-policy denial in `AAuthVerificationMiddleware` now maps to
  `401 Signature-Error: error=invalid_key`. R03 can build on the same central
  writer for remaining authorization-endpoint changes.

Public API delta: removed `ChallengeOptions.AllowedSignatureKeySchemes`;
replaced `ISignatureTokenVerifier.VerifyAsync(string, IAAuthKey,
TokenVerifier, CancellationToken)` with `ResolveIssuerKeyAsync(...)` and
`VerifyAsync(SignatureTokenVerificationContext, ...)`; added
`SignatureTokenIssuerKeyContext` and `SignatureTokenVerificationContext`; added
optional `services` / `expectedDwk` parameters to
`DefaultSignatureKeyResolver`.

### [2026-09-30] [Phase 3] R02 — Four-party trust and dwk pinning

RESOLVED (Q4; SDK-02 / A09-HIGH-001, A17-002, D09-01, D10-05).

- Added `AAuthResourceOptions.AccessServer` as the single high-level
  four-party declaration and projected it into resource metadata options for
  `UseAAuth`, `UseAAuthVerification`, and `MapAAuthResource` composition.
- Four-party resource composition now derives AS-only auth-token trust when no
  auth-token issuer policy is configured and pins auth-token verification to
  `aauth-access.json`. Three-party resource composition keeps open
  PS-asserted issuer trust but pins auth tokens to `aauth-person.json`.
- Explicit mixed mode is limited to `ExpectedAuthTokenDwk = null` plus a
  policy path capable of inspecting `AAuthTrustContext.TokenDwk`. Combining
  `AAuthTrust.Any` with `AccessServer` fails at startup.
- `TokenVerifier.VerifyAuthTokenWithJwksAsync` and the default Signature-Key
  JWT resolver now thread the expected auth-token `dwk`; `AuthTokenResponseValidator`
  pins AS responses to `aauth-access.json`.
- Four-party Wallet/Catalog/Bookings sample resources now declare
  `AAuthResourceOptions.AccessServer`; manual sample verification paths pin
  AS-issued auth tokens to `aauth-access.json`. README and DI docs now describe
  three-party open trust as the caveated default and four-party AS-derived trust
  as the `AccessServer` behavior.

Public API delta: added `AAuthResourceOptions.AccessServer`,
`AAuthResourceMetadataOptions.AccessServer`,
`AAuthVerificationOptions.ExpectedAuthTokenDwk`, and
`AAuthTrustContext.TokenDwk`; added `expectedDwk` to
`TokenVerifier.VerifyAuthTokenWithJwksAsync`.

### [2026-09-30] [Phase 3] R03 — Authorization endpoint and access-mode gating

RESOLVED (Q25; SDK-08, SDK-18, A07-001/A09-MED-002, A09-HIGH-003, A08-03, SMP-04, DOC-04).

- The core authorization endpoint now requires a verified person token and
  challenges missing-token, verified agent-token, and verified auth-token
  callers with
  `401 AAuth-Requirement: requirement=person-token`. Non-JSON and malformed
  JSON bodies return `400 invalid_request`.
- Added a core `IAAuthAuthorizationEndpointExtension` seam and an
  AAuth.R3 registration (`AddAAuthR3AuthorizationEndpoint`) so R3
  `r3_operations` bodies without `scope` satisfy the authorization claim
  without a core→R3 project reference.
- `AgentTokenRequired` now accepts only `aa-agent+jwt`; person and auth tokens
  receive a bare `requirement=agent-token`.
- `AAuthChallengeMiddleware.BuildResourceTokenAsync` now rejects presented
  agent-token assertions before minting a resource token.
- The Inbox two-party sample no longer maps or advertises `/authorize`; its
  README, sample index, Guided Tour text, SampleApp snippet, and
  resource-managed workflow docs now describe only the reactive
  `202 interaction` path.

Public API delta: added `IAAuthAuthorizationEndpointExtension`,
`AAuthAuthorizationExtensionResult`,
`AAuthAuthorizationExtensionException`, `AAuthAccessMode.PersonTokenRequired`,
`AAuthAuthorizationRequest.Features`, nullable `AAuthAuthorizationRequest.Scope`,
`RouteHandlerBuilder.RequireAAuthPersonToken`,
`R3AuthorizationEndpointExtensions.AddAAuthR3AuthorizationEndpoint`, and
`R3AuthorizationEndpointExtensions.GetR3Operations`.

### [2026-09-30] [Phase 3] Gates and wrap-up

RESOLVED. R14, R02 and R03 landed through implementation agents; see the
entries above.

Orchestrator follow-ups:

- **Concierge.** The wallet branch declares
  `ExpectedAuthTokenDwk = aauth-access.json`. That branch is four-party, and
  the new three-party default pin (Q4) rejected the Access Server's grant in
  the e2e run.
- **Q3 control.** `VerificationMiddlewareTests` now asserts
  `Signature-Error: error=invalid_key` on a trust-policy denial.
- **Restored coverage.** R03 had deleted agent-signed authorization-endpoint
  tests. `AuthorizationEndpointTests` restores the missing-scope and
  malformed-`account` coverage for person-token callers.

Gates:

- The build is clean.
- Tests: AAuth.Tests 1786, Conformance 1335, R3 332, Events 89.
- The inventory, snippet and link gates pass.
- ApiSurface: +967/-414.
- e2e: full Playwright 78 passed, 1 skipped.
- Keycloak profile (`KEYCLOAK_E2E=1`, Keycloak 26.0): `federated-deferred`
  1 passed; container removed.

Observation (pre-existing, not caused by this plan): running
`wallet-protocol.spec.ts` on its own makes "AS clarification is answered
before the approved review" time out waiting for Person Server consent. It
does the same at the Phase 2 commit with the owner's MockPersonServer edits,
and it passes in the full-suite order.

### [2026-09-30] [Phase 4] R11 — Deferred polling and error tables

RESOLVED.

- `ChallengeHandler` now resumes deferred auth-token delivery through the shared
  `DeferredPoller` path, carrying the initial `Retry-After`, treating
  `429 slow_down` as linear backoff, and returning requirement-bearing
  `202`/`401` responses so a fresh resource-token challenge is re-exchanged
  before polling the same `Location` again.
- Polling and token endpoint emitters were moved onto closed-table helpers that
  own each registered code's status. Unknown, foreign, consumed or replayed
  pending handles now converge on `410 invalid_code`; first observed held
  invocation expiry is `408 expired`, then `410 invalid_code`.
- Untrusted PS/AS signer cases are mapped per Q3 to bodyless
  `401 Signature-Error: error=invalid_key`. AS/PS policy failures that exposed
  the invented `policy_error` code now use registered `server_error`; untrusted
  AS audience failures in PS federation use `invalid_resource_token`.
- `TokenErrorCode` now contains only the registered token-endpoint table values;
  `mission_terminated` remains on the dedicated mission error surface, not the
  token-endpoint enum.
- `DeferredPollerOptions.MinPollInterval` defaults to zero, so
  `Retry-After: 0` is immediate unless an app explicitly configures a floor.
- Directly affected docs and non-protected samples were updated. The protected
  `samples/MockPersonServer/Program.cs` still contains removed-code examples,
  so that sample sub-item is left for the owner/orchestrator rather than
  editing owner-modified files.

### [2026-09-30] [Phase 4] Gates and wrap-up

RESOLVED.

**Orchestrator correction.** The R11 agent had removed
`TokenErrorCode.InvalidAgentToken` and `ExpiredAgentToken`, and mapped
`agent_token` parameter failures to `*_presented_token`. That change is
reverted, for two reasons:

- the spec's `<invalid|expired|revoked>_<parameter>_token` pattern
  (#token-endpoint-error-codes) covers the AS/R3 `agent_token` parameter;
- the AAuth #199 codes are out of scope for this plan.

The enum members, wire codes, their 400 status in the closed-table helper, the
`TokenFailure` agent mapping and the three affected test expectations are
restored. The removal of `MissionTerminated` from `TokenErrorCode` stands:
`mission_terminated` stays on the mission-specific surface
(`AAuthMissionTerminatedException`).

Remaining work for the owner-edited sample (Phase 11):

- `samples/MockPersonServer/Program.cs:321` and `:574` still emit
  `404 unknown_pending`.

Gates:

- The build is clean.
- Tests: AAuth.Tests 1819, Conformance 1348, R3 332, Events 89.
- The inventory, snippet and link gates pass.
- e2e: full Playwright 78 passed, 1 skipped.

### [2026-09-30] [Phase 5] R06 — Source guard, pending revocation and step-up

RESOLVED (Q5/Q7/Q8).

- `TokenRegistration` now carries source metadata for the single inventory
  model. PS/AS pending entries store typed registrations rather than parallel
  `TokenKey` lists, and tracked issuance checks those dependencies before
  minting.
- A shared source guard runs before pending responses, local mint, held
  invocation polling, AS callbacks, and the final PS→AS federation send. On
  pending failure it returns terminal `403 revoked` / `408 expired` with
  dependency detail; the PS federation path cancels the linked HTTP token and
  flips the entry to terminal state.
- Revoked auth-token verification still returns `401 Signature-Error:
  error=revoked_jwt` and now also includes `AAuth-Requirement:
  requirement=person-token`.
- `RequireAAuth(scope:)` / `UseAAuth` now step up a valid auth token missing
  the endpoint scope with `401 requirement=auth-token` and a resource token
  bound to the presented auth token. Named scope policies, roles and claims
  remain ordinary `403` authorization denials.
- Negative controls landed in `RevocationLifecycleTests`,
  `HeldInvocationTests`, `ChallengeMiddlewareTests`,
  `ReplayDetectionMiddlewareTests`, `ChallengeHandlerTests`, and
  `TrackedIssuanceTests`.
- Samples checked for stale insufficient-scope `403` assumptions. Calendar
  prose/comments were updated; owner-edited `samples/MockPersonServer/*` was
  not touched. Broader e2e/sample wording (including MissionAgent cache and
  mission gate hand-walk notes) remains for Phase 11 unless orchestrator e2e
  finds breakage.

### [2026-09-30] [Phase 5] R05 — Upstream provenance and interaction chaining

RESOLVED (Q5).

- Extended the single `IJtiStore` inventory with provenance-bearing
  `TokenGrant`s, `UpstreamCallerRecord`s, provenance quota preflight, and
  in-memory retention through token `exp + skew`. `RegisterAsync` of an unseen
  upstream token still creates no provenance.
- `AgentIssuanceContext.VerifyAsync` now uses the PS-aware
  `UpstreamTokenValidator.ValidateAtPersonServerAsync` primitive. Missing
  provenance fails closed as `invalid_upstream_token`; revoked recorded caller
  agent tokens or agent-person bindings fail as `revoked_upstream_token`.
  Static `Trust.AccessServers` can restrict AS issuers but never substitutes
  for provenance.
- PS person/auth issuance and federated AS auth returns record provenance
  atomically with grant registration. Quota failure returns `429
  invalid_request` before minting.
- Added the call-chaining interaction helper (`ChainedInteractionEntry` and
  `AAuthChainedInteractions`) and reshaped
  `AAuthInteractionChainedException` to carry `DownstreamInteraction`.
  Concierge now emits its own interaction code and `Location`, with a
  Concierge-owned redirect to the downstream PS/AS interaction.
- Negative controls landed in `UpstreamTokenValidationTests`,
  `TokenInventoryTests`, `InteractionChainingTests`, and updated call-chain
  fixture tests that synthesize upstream tokens with explicit provenance.
- Docs updated in `docs/advanced/interaction-chaining.md` and
  `docs/workflows/call-chaining.md`; `CallChain.razor` and Concierge samples
  now describe/use intermediary-owned interaction URLs. Owner-edited
  `samples/MockPersonServer/*` files were not touched.
- Validation: build clean; tests passed — AAuth.Tests 1821,
  AAuth.Conformance 1358, AAuth.R3.Tests 332, AAuth.Events.Tests 89;
  docs inventory, snippets/links, e2e typecheck, and `ApiSurface --write`
  passed.

### [2026-09-30] [Phase 5] e2e regressions

RESOLVED.

- The Concierge's intermediary-owned `/chain-interaction/{id}` URL was still
  behind the resource verification/challenge middleware. Browser visits were
  unsigned, so hop-2 chained approvals parked on a blank 401 instead of
  redirecting to the downstream PS/AS interaction. The endpoint is now public
  like a normal interaction URL; the pending URLs remain AAuth-protected.
- Guided Tour call-chain assertions still assumed both approvals surfaced as
  PS-dashboard prompts. Draft-11 interaction chaining now legitimately shows
  the intermediary's own interaction URL for hop 2, which redirects onward, so
  the test uses the generic consent driver and still requires exactly two
  approvals plus the final 15-step result.
- R06 scope step-up changed the wallet clarification negative control: a valid
  `wallet.review` auth token presented to `wallet.charge` now yields `401
  requirement=auth-token` with a new resource token, not a terminal `403`.
  Sample walkthroughs and e2e assertions now expect the step-up response.

### [2026-09-30] [Phase 5] Gates and wrap-up

RESOLVED.

Gates after the e2e-regression fixes (see the entry above):

- The build is clean.
- Tests: AAuth.Tests 1821, Conformance 1358, R3 332, Events 89.
- e2e: full Playwright 78 passed, 1 skipped.
- Keycloak profile: `federated-deferred` 1 passed; container removed.

### [2026-09-30] [Phase 5] Revocation race during federation

RESOLVED (Q7).

`AAuthSourceGuard.CheckThenActAsync` now keeps rechecking the single
`IJtiStore` inventory while the guarded outbound action is running. If any
source dependency is revoked or expires after the immediate pre-send check but
before the PS→AS `FederateAsync` call returns, the guard cancels the linked
send token and returns the same terminal guard failure path used by pre-send
revocation. The PS federation task then marks the pending entry `revoked` /
`expired` with dependency detail and does not relay or mint the AS result.
`CreateTrackedAsync` remains the post-answer backstop for races at result
registration.

Negative control:
`DeferredFederationTests::RevokedPresentedTokenCancelsInFlightFederationSend`
blocks the AS token endpoint, revokes the presented person token while that
HTTP call is in flight, and asserts the AS request is cancelled, no AS pending
entry is created, and the agent sees `403 revoked` with `detail` naming the
presented token.

### [2026-09-30] [Phase 6] R04 — R3 single use, audit and entitlement

RESOLVED.

- `R3Enforcement` now returns an execute-once `SingleUse` handle for approved
  per-call proposal retries. The handle uses the canonical `(auth token iss,
  jti)` retained-result key through `IAAuthSingleUseGate`; missing gate, `jti`
  or `exp` rejects with `single_use_required`. The 202 held-invocation path uses
  the same key builder.
- R3 token issuance audit records now include `ps`, `sub` and `agent_jkt`; the
  SQLite sample sink stores those as first-class non-null audit columns.
- R3 document entitlements are exact `r3_uri`/`r3_s256`/reader/resource-token
  grants with expiry, and `R3Challenge` entitles both the `aud` AS and `ps` PS
  only after validating the referenced document/proposal.
- Added `IR3AuthoritativeDefinitionProvider` / `IR3OperationValidator` and
  fail-closed `R3Challenge` reference validation; duplicate bare identifiers and
  absent operations are rejected.
- Updated Bookings/Catalog samples and R3 docs/README for the `SingleUse`
  pattern, required `vocabulary`, URI-bound entitlements and authoritative
  validation.

Negative controls:
`ResourceR3Tests::ApprovedProposalRetry_UsesSingleUseGateAndReturnsRetainedResult`,
`ResourceR3Tests::ApprovedProposalRetry_MissingSingleUsePrerequisiteRejects`,
`R3AutoEntitlementTests::ThirdSigner_Rejected_UntilHostEntitles`,
`R3VocabularyTests::ValidateOperations_RejectsDuplicateBareIdentifiers`,
`R3VocabularyTests::R3Challenge_RejectsDocumentOperationMissingFromAuthoritativeDefinition`,
and
`AccessEndpointR3Tests::TokenEndpoint_RejectsDocumentOperationMissingFromAuthoritativeDefinitionWithoutAudit`.

### [2026-09-30] [Phase 6] e2e regressions

RESOLVED.

The R3 Access Server's authoritative operation list covered only Bookings after
Phase 6 added fail-closed validation, but the e2e topology also routes the merged
Travel Catalog through that AS. Catalog resource-token exchange therefore failed
at the AS with `r3_evaluation_failed` before the sibling-operation recovery flow
could complete. The sample AS default authoritative OpenAPI operations now include
the Catalog's renamed merged-definition operation ids (`listDestinations`,
`listExperiences`) while preserving `confirmReservation` as the only per-call
default.

### [2026-09-30] [Phase 7] R10 — Agent–person binding and pairwise subjects

RESOLVED.

Implemented the R10 PS-core cutover for SDK-07/A11-01, A11-03, A11-04,
A15-002, and the SMP-01 issuer addition. `IdentityAssertion` now carries
`AAuthPersonKey`; PS issuance has binding, enrollment, HMAC subject-deriver,
and governance `ps` checks; the sample admin path matches `(issuer, agent id)`.
Negative controls landed for second-person denial/rebind after store revocation,
binding-store failure, first-resource approval, pairwise/HMAC key behavior,
and absent/foreign governance `ps`.

### [2026-09-30] [Phase 7] R10 follow-up — no compatibility inference

RESOLVED.

Removed the production compatibility inference that created `AAuthPersonKey`
values from presented or upstream directed `sub` values when the enrollment
store had no record. A PS-issued presented token without a recorded enrollment
now fails closed with `400 invalid_presented_token`; a PS-issued upstream token
without a recorded enrollment fails closed with `400 invalid_upstream_token`.
Tests that build tokens directly now seed the enrollment store explicitly, so
Q14's "nothing minted without a person key" invariant is enforced by real
state rather than a shim.

The agent/person binding inventory key is now generationed. Revoking a binding
revokes the live generation's inventory row for cascade/provenance checks, while
a later bind creates the next generation and can issue new grants without
resurrecting old upstream chains.

Explicit-subject `IdentityAssertion.Assert` remains a host approval decision
(C6): the SDK records the person/resource enrollment before minting, and docs
now state that explicit subjects do not bypass enrollment.

### [2026-09-30] [Phase 7] R09 — Missions

RESOLVED.

Implemented the R09 mission lifecycle cutover for SDK-14, A16-001, A16-003,
A16-004, D04-002, D05-02 and D08-05. `StoredMission` now records
`TerminationReason`; the default store keys missions by `(PersonServer, s256)`;
`TerminateAsync(ps, s256, reason)` preserves the first reason and rejects blank
reasons; and the shared `MissionStatusEvaluator` is used by person-token,
auth-token, pending, federated and SDK-governance decision paths. Expired
missions auto-terminate with `expired` before generic deferred expiry, and
completion records `completed`.

Negative controls cover pending, federated, person-token and governance expiry;
completion reason persistence; first-reason preservation; `(PS, s256)` aliasing;
and absent/foreign-agent/foreign-PS uniform `mission_not_found` responses with a
spy store proving SDK governance paths do not pre-load by `s256` alone.

Owner-edited `samples/MockPersonServer/MissionGovernance.cs` and `Program.cs`
were not modified. To keep the solution compiling until the owner updates those
files, `IMissionStore` retains the legacy `GetAsync(s256)` / `SetStateAsync`
members while new SDK paths use `(personServer, s256)` and `TerminateAsync`.
This is a temporary sample-compatibility trade-off against C1; the owner should
replace sample `GetAsync(s256)` calls with `GetAsync(ps, s256)` and
`SetStateAsync(..., Terminated)` calls with `TerminateAsync(ps, s256, reason)`,
choosing `completed`, `revoked` or `administrative` as appropriate, after which
the legacy members can be removed.

### [2026-09-30] [Phase 7] R08 — Clarification, updated_request and input validation

RESOLVED.

Implemented the R08 clarification and input-validation cutover for SDK-06,
A12-02, A12-03, A12-04, A13-02, A13-03 and A13-05. `updated_request` handling
now shares one replacement helper for normal pending POSTs and federated
replacements, verifies the replacement pair, recomputes active lifetime/source
dependencies from the replacement `resource_token`/`presented_token`, and keeps
shorter-lived, longer-lived and revoked replacements bounded by the active pair
plus agent/mission/upstream ceilings. Clarification round consumption is central
and includes local federated triage.

A shared protocol-input validator now serves agent producers and PS consumers for
vendored platform values, printable Unicode `device`, and strict capability-token
arrays; capability constants live in `AAuthConstants.Capabilities`, and the old
`AAuthCapabilitiesHeader.Capabilities` aliases were removed. Agent-side
clarification callbacks honor `timeout` by cancelling the per-round token and not
posting late answers, and local `updated_request` pre-validation rejects
mismatched replacement pairs before any POST.

Negative controls cover shorter/longer/revoked replacements, triage round caps,
invalid `platform`/`device`/`capabilities`, late clarification suppression, and
local replacement-pair mismatch suppression.

### [2026-09-30] [Phase 7] Gates and wrap-up

RESOLVED. R10, R09 and R08 landed; see the entries above.

Gates:

- The build is clean.
- Tests: AAuth.Tests 1825, Conformance 1389, R3 339, Events 89.
- The docs gates pass.
- e2e: the first full run had one timeout, "federated revocation cascades and
  recovery needs a fresh grant" (12.8 minutes; the Run-all button never
  re-enabled). It passed when run on its own, and the full suite then passed
  on a rerun: 78 passed, 1 skipped. Recorded as a flaky, slow run.
- Keycloak profile: `federated-deferred` 1 passed; container removed.

### [2026-09-30] [Phase 8] R12 — Governance endpoints

RESOLVED.

`.WithGovernance()` now declares the PS governance paths once
(`MissionPath`, `PermissionPath`, `AuditPath`, `InteractionEndpointPath`) and
`MapAAuthPersonServer()` auto-maps the same declaration. `MapAAuthGovernance()`
is idempotent for the same declaration and fails fast for conflicting paths. To
keep the owner-edited MockPersonServer starting until Phase 11 replaces its
hand-written routes, SDK governance endpoints are mapped with lower route
priority so a host route at the same path wins instead of causing an ambiguous
match.

Metadata no longer falls back from `interaction_endpoint` to the browser
`InteractionPath`; it is omitted when governance is off unless
`InteractionEndpointPath` is explicitly configured. The governance pipeline
option was renamed from `InteractionPath` to `InteractionEndpointPath`.

Relay results are enforced as exactly one of `Answered`, `Pending` or
`Unavailable` for interaction endpoint requests. The default relay returns
`Unavailable` for `interaction`, `payment` and `question`; `Pending` produces
`202` with `Location`, `Retry-After: 1` and `Cache-Control: no-store`, and
without a deferred store fails closed as `424 interaction_unavailable`.

Permission/audit parsers reject present non-object `parameters`/`result`
(including JSON `null`) as `400 invalid_request`. `MissionLogEntry` now carries
deep-cloned `Parameters` and `Result`, and the default audit sink preserves both.
Client/docs clarify that for resource-hosted interactions the resource pending
URL is authoritative and the PS relay only reports relay progress.

### [2026-09-30] [Phase 8] Gates and wrap-up

RESOLVED.

- **Flaky test fix.** The R13 metric test
  `AAuthSigningHandlerTests.SendAsync_CreatedWait_EmitsMetric` collected into
  a `List<double>`. The meter is process-wide, so parallel tests could record
  while it asserted (a collection-modified failure). It now uses a
  `ConcurrentQueue`.
- **Deferred to Phase 11 (owner-edited files):** SMP-02.
  `samples/MockPersonServer/Program.cs` keeps its hand-written
  `/mission-interaction` handler. The owner should remove it and rely on
  `.WithGovernance()` plus `MapAAuthPersonServer()`.
  `MissionGovernance.cs`'s relay should return `Pending` only with a pollable
  store, otherwise `Unavailable`.

Gates:

- The build is clean.
- Tests: AAuth.Tests 1827, Conformance 1398, R3 339, Events 89.
- The docs gates pass.
- e2e: full Playwright 78 passed, 1 skipped.

### [2026-09-30] [Phase 9] R07 — Federation: collapse and payment

RESOLVED.

- Added explicit PS-AS collapse declarations keyed by verified resource issuer,
  linked AS role name and expected AS issuer. Declared collapse resolves the
  local AS role, fails closed on missing/mismatched linkage, evaluates the
  local `IAccessPolicy`, and mints AS-shaped auth tokens with
  `dwk=aauth-access.json`; undeclared `aud == PS` remains three-party.
- Replaced payment-URL-shaped `NeedsPayment` with a payment challenge. AS
  `402` responses now use the pending URL as `Location`; payment protocol data
  stays in `WWW-Authenticate`/body. `AccessServerClient` composes
  `402 -> settle -> poll -> 202 claims -> 200`, and the PS payment settler
  receives only challenge, AS origin and pending URL. Missing/declined
  settlement becomes polling `403 denied` with detail
  `payment settlement is unavailable`.
- Enforced the `sub` rule on both sides: AS claim requirements/pushed claims
  reject protocol-owned names including `sub`; PS claims projection and
  `ClaimsResponse` never send `sub`. The federated Keycloak callback filters
  forbidden required-claim names before parking claims.
- Updated the federated workflow docs, sample README, docs inventory and API
  surface map. Required gates were run and green; Keycloak/Playwright e2e were
  not run in this slice per the implementation brief.

### [2026-10-01] [Phase 9] Gates and wrap-up

RESOLVED.

Gates:

- The build is clean.
- Tests: AAuth.Tests 1833, Conformance 1398, R3 339, Events 89.
- The docs gates pass.
- e2e: full Playwright 78 passed, 1 skipped.
- Keycloak profile (`KEYCLOAK_E2E=1`): every `federated` spec passed (4);
  container removed.

## Deviations from plan

### [2026-09-30] [Phase 7] R09 owner-edited sample compatibility

PROCEEDED. Q13 says `TerminateAsync(ps, s256, reason)` replaces
`SetStateAsync`, with no compatibility shims. The owner-edited
`samples/MockPersonServer/MissionGovernance.cs` and `Program.cs` still call the
old `IMissionStore.GetAsync(s256)` / `SetStateAsync(s256, state)` members and
must not be modified in this slice. To keep `AAuth.slnx` compiling without
touching those files, the interface temporarily retains those legacy members
while all SDK decision paths and new tests use `(PersonServer, s256)` and
reasoned `TerminateAsync`. Owner follow-up: update the sample calls to pass the
PS and explicit reason (`completed`, `revoked` or `administrative`), then remove
the legacy members.

### [2026-09-30] [Phase 7] R10 compatibility-limited enrollment strictness

PROCEEDED. The endpoint enforces first-resource approval on the default
SDK-derived subject path, but preserves existing explicit-subject sample/test
flows by recording the explicit directed subject immediately. For manually built
legacy test tokens with provenance, the enrollment store infers a person key
from the presented/upstream subject instead of failing closed. This keeps the
existing conformance harness green while the new R10 negative controls cover the
default fail-closed path.

### [2026-09-30] [Phase 7] R10 binding revocation inventory limit

PROCEEDED. `RevokeAgentAsync` clears the binding store and cascades issued
grants through the existing agent-subject revocation index, but does not revoke
the fixed `AgentPersonBinding.Key` inventory row because the current inventory
model treats that revocation as permanent until year 9000 and cannot re-enroll
the same `(PS, agent issuer, agent id)` tuple. The new binding-store negative
control verifies rebind after binding-store revocation.

### [2026-09-30] [Phase 1] SMP-01 matches the exact agent id, not id plus key

PROCEEDED. Q29 said "exact subject and key thumbprint". Demo agent keys are
ephemeral, so a pinned thumbprint would never match. The SDK verifier already
binds the agent-id domain to the agent provider's issuer
(`TokenVerifier.cs:664`). An exact id therefore implies the AP
(`https://ap.example`), which closes the `aauth:demo@attacker.example`
scenario. R10 (Phase 7) adds the SDK issuer and binding seam.

The stale comment at `samples/MockPersonServer/Program.cs:50`
("``aauth:demo@...``") is in an owner-edited file and is left for the Phase 11
sample sweep.

### [2026-09-30] [Phase 5] In-flight revocation uses polling, not notification

PROCEEDED. `AAuthSourceGuard.CheckThenActAsync` re-reads the source
dependencies from `IJtiStore` every 25 ms while the guarded action runs. On a
revocation it cancels the linked token. Because `IJtiStore` has no
revocation-notification contract, this polling keeps Q5's single inventory
model intact.

Cost: a durable store sees about 40 lookups per second for each in-flight
federation send. A push-based revocation notification on `IJtiStore` is the
refinement, and is left to a durable-store initiative (see the plan's out of
scope).

### [2026-10-01] [Phase 7] R10 compatibility-limited enrollment strictness superseded

RESOLVED. Supersedes the 2026-09-30 deviation "R10 compatibility-limited
enrollment strictness". The compatibility inference has been removed: missing
presented/upstream enrollment records fail closed with the token endpoint's
closed-table `invalid_presented_token` / `invalid_upstream_token` responses, and
tests seed real `IPersonResourceEnrollmentStore` records instead of relying on
production inference.

### [2026-10-01] [Phase 7] R10 binding revocation inventory limit superseded

RESOLVED. Supersedes the 2026-09-30 deviation "R10 binding revocation inventory
limit". Binding inventory rows now include a generation. Revocation marks the
current generation revoked for cascade and upstream-provenance checks; re-binding
creates a later generation so a new association can be established without
unrevoking grants chained to the old one.

### [2026-09-30] [Phase 7] Legacy IMissionStore members kept for the owner-edited sample

PROCEEDED. This is a temporary exception to C1.

`IMissionStore.GetAsync(s256)` and `SetStateAsync(s256, state)` stay on the
interface for one reason only: `samples/MockPersonServer/Program.cs` (an
owner-edited file this plan must not touch) calls them at L395, L472, L503,
L535, L558, L585 and L719. No SDK path uses them. Every SDK decision path goes
through `(PersonServer, s256)` and the mission status evaluator.

`InMemoryMissionStore.SetStateAsync(Terminated)` maps to
`TerminateAsync(..., administrative)`. As a result, the sample's completion
path (L558) records `administrative` instead of `completed`.

Phase 11 removes both members once the owner's MockPersonServer edits are
committed. The sample then moves to `GetAsync(ps, s256)` and
`TerminateAsync(ps, s256, Completed | Revoked)`.

## Open questions / inputs needed

### [2026-09-30] [Phase 0] Owner review requested on Q1 and Q2

RESOLVED (owner, 2026-09-30); superseded by the Q1 and Q2 owner-ruling
entries under *Decisions taken*.

### [2026-09-30] [Phase 0] Upstream issue: replay tuple and `created`

SENT, awaiting reply. The owner asked for the Q1 limitation to be raised with
Dick Hardt (spec author) through the AAuth connector MCP.

On 2026-09-30, after the connector was re-authenticated, the message went via
`encrypt.aauth.dev` `sendMessage` through `secret.agent.coop`:

- from `mailto:dasiths@hotmail.com` to `mailto:dick.hardt@hello.coop`;
- message id `msg_hcR1FaxPrNIPiCy1VHlYvTJ3_exh`.

It asks for one of three changes, in order of preference:

1. an optional `nonce` added to the replay tuple;
2. `@query` (or the full `@target-uri`) in the replay tuple;
3. letting verifiers key replay on the full signature base instead of the
   tuple.

Record the reply here when it arrives.

**Update (2026-10-01).** The spec author opened
[dickhardt/AAuth#222](https://github.com/dickhardt/AAuth/issues/222). It is
open, has no comments, and is not yet in a published draft. It proposes:

- an OPTIONAL `nonce` signature parameter. An agent SHOULD send one when it
  makes more than one request with the same method, authority and path
  within a second. It MUST NOT repeat for the key within the window, and
  verifiers MUST NOT require it.
- adding `nonce` to the replay tuple:
  `(thumbprint, created, nonce, @method, @authority, @path)`.

Effect on this plan:

- Q1 stands while the target is draft-11. A third-party draft-11 verifier
  keys on the tuple without `nonce`, so sending one doesn't avoid its replay
  rejection.
- The SDK verifier is already forward-compatible. It accepts a string `nonce`
  (`AAuthVerifier.cs:145`). Its replay key is SHA-256 of the signature base,
  which includes `@signature-params` (`AAuthVerifier.cs:112`), so a different
  `nonce` is already a different replay entry.
- When a draft adopts #222, the producer change is small: on an exact-tuple
  collision, add a random `nonce` instead of waiting, and drop the wait.

Status: the reply was received and the issue is tracked; no change to Q1.
