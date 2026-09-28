---
description: Seeded decision gate for the AAuth draft-11 migration; implementation has not begun.
---

# Implementation log - AAuth draft-11

Append-only log. Research defaults do not grant implementation authorization.
No SDK runtime gates have been run for this initiative. Prior plans and existing
vendoring changes remain intact.

## Decisions taken

### [2026-09-11] [Phase 0] Research-only scope

RESOLVED. The user requested breaking-change and SDK/API/Samples/Docs analysis
following the draft-10 migration folder. This package records research, maps,
scenarios, a ledger and a proposed implementation plan. SDK baseline:
`94576a3ebcba8cd1d167923e50c8796132057600`; current target remains draft-10.
The reference is unpublished draft-11 WIP with pins in [research.md](research.md).
No SDK implementation or deployment is authorized by the analysis request.

### [2026-09-11] [Phase 0] Publish the research branch

RESOLVED. The follow-up request authorizes pushing `wip/aauth-draft-11` after
finishing the analysis. Commit and push the vendored WIP snapshot and this
research package; keep SDK implementation separate. This authorizes Git branch
publication, not package publication, runtime deployment or a conformance claim.

### [2026-09-11] [Phase 0] Research validation and review

RESOLVED for the research deliverable only. Five read-only area audits were
collated; a fresh reviewer checked the seven-document package, then rechecked
the identified repairs. The follow-up found no remaining P1/P2 document issues.
Repairs included owning-phase snippet updates, minimum client/Events dependencies
at the identity cutover, atomic clarification-pair replacement, and corrected
source citations. Q13 and Q14 retain newly identified upstream uncertainties.

The local reference check validated 464 file/line links with no missing files
or empty cited lines; both heading-fragment links resolved. Markdown diagnostics
and tracked-document whitespace checks were clear. These are documentation
checks, not SDK tests. No build, unit, conformance, browser or external interop
pass is claimed, and all implementation definitions of done remain unchecked.

### [2026-09-25] [Phase 0] Retarget to published draft-11

RESOLVED. Draft-11 was published at AAuth tag `draft-hardt-oauth-aauth-protocol-11`
(commit `178e9e6`) with HTTP Signature Keys -09. Both are vendored in
[`aauth-spec/v11/`](../../../aauth-spec/v11/), along with the per-role
[upgrade checklists](../../../aauth-spec/v11/upgrade-10-to-11/README.md) from
commit `180bc95`. The WIP snapshot remains readable at `e6d18a3`. The
[implementation plan](implementation-plan.md#target-pins) now targets the
published text. Its upstream rulings table gives the governing line for each Q.
This is a planning change. It does not authorize SDK implementation.

### [2026-09-28] [Phase 0] Implementation authorized

RESOLVED. The user asked to start implementing the plan. This authorizes SDK,
sample, test and docs changes on `wip/aauth-draft-11` in phase order. It does
not authorize package publication, deployment, PR creation or pushing.

### [2026-09-28] [Phase 0] Q1-Q14 rulings

RESOLVED (by spec) for Q1-Q5, Q7-Q11, Q13 and Q14, per the governing lines in
[the plan's upstream rulings](implementation-plan.md#upstream-rulings). The SDK
design choices those leave open are decided in their owning phases and logged
there: consent caches (Q4, Phase 6), retained-result storage (Q8, Phases 5
and 8) and revocation delivery (Q9, Phase 7).

PROCEEDED (default: core migration plus existing R3 and Events) for Q6. Full
Budgets, hosted child provisioning, supervision protocol and delayed artifacts
stay out of scope. Result-release execution stays disabled with explicit
unsupported handling. Optional checklist items are not selected yet; each
owning phase records its selection before implementing one.

PROCEEDED (default: reuse current abstractions; isolated or versioned sample
storage) for Q12. No destructive reset of user data. Public API changes are a
single alpha cutover, tracked by the regenerated API map.

### [2026-09-28] [Phase 0] Baseline

RESOLVED. `origin/main` (`f44587f`, tag `v0.10.0-alpha.1`) was merged into the
branch as `eef4175` before implementation. .NET SDK 10.0.300, Node 20.20.2.
Release build clean. Baseline tests: Events 75, R3 290, Conformance 1079, core
1496, all passing. e2e TypeScript typecheck passes. Browser suites were not
run for this baseline and are not claimed.

### [2026-09-28] [Phase 1] Tooling retarget

RESOLVED. `tools/ApiSurface` defaults to the v11 API map and baseline
`v0.10.0-alpha.1`, with `--map` and `--baseline` overrides. The docs inventory
test writes the v11 docs map. The v10 maps are unchanged. The `jti` implies
`iss` heuristic is replaced by an explicit table of HTTP examples carrying a
`jti` body; the only entry is the revocation request, whose member set Phase 7
cuts over.

### [2026-09-28] [Phase 1] Signature error codes and the `created` window

RESOLVED. Signature Keys -09 `revoked_jwt` and `clock_skew` are typed.
Missing or malformed `Signature` / `Signature-Input` is `invalid_signature`
(-09 section 5.4.4); a malformed `Signature-Key` is `invalid_key` (5.4.7).
The `created` window is symmetric (#verification, L2246): older is
`invalid_signature`, further ahead is `clock_skew`. `MaxFutureSkew` (5 s)
rejected in-window requests, so it is removed from `AAuthVerifier`,
`AAuthResourceOptions` and `AAuthVerificationOptions` (where it was never read).
Future `iat` handling moves in Phase 2 with temporal trust.

### [2026-09-28] [Phase 1] Metadata vocabulary

RESOLVED. `token_endpoint` is `auth_token_endpoint` on PS and AS metadata,
clients and the C# options (`AuthTokenEndpoint`). Agents parse
`person_token_endpoint`; the PS publishes it in Phase 2. `access_mode` values
are `agent-token`, `person-token`, `session-token` and `auth-token`;
`aauth-access-token` is rejected at configuration, and agents treat any
unrecognized value as no declaration (AG-02). `login_endpoint` is removed
(RS-02, AP-04). GuidedTour executable reads and snippets moved with it.

### [2026-09-28] [Phase 1] Token, polling and revocation error vocabulary

PROCEEDED (default: keep `invalid_agent_token` and `expired_agent_token` until
Phase 4). The published token table removes them, but the PS, AS and Bookings
emitters still send them for failures that become `revoked_presented_token`
and `expired_presented_token` only after the exchange cutover. Removing the
client codes first would misclassify our own servers. Phase 4 removes both
codes and their emitters together. All other published token codes, polling
`revoked`, and revocation errors and downstream outcomes are typed. The unused
`interaction_required` token code is removed.

### [2026-09-28] [Phase 1] Agent identifiers and Ed25519

RESOLVED. `AgentId` accepts `A-Z` in the local part and compares ordinally, so
case variants are distinct identities (#agent-identifiers, L488). The domain
stays lowercase. Ed25519 needed no code change: `AAuthKey.Generate()` is
Ed25519, and the PS, AS, resource, R3 and Events endpoints all verify through
`AAuthVerificationMiddleware`. Existing suites sign with Ed25519 at each role:
MockPersonServer and MockAccessServer integration, `DeferredFederationTests`,
`AccessServerClientTests`, and `EnrolledBuilderTests` against MockAgentProvider's
refresh endpoint.

### [2026-09-28] [Phase 1] Gates

RESOLVED. Release build clean. Tests: Events 75, R3 290, Conformance 1112, core
1499, all passing. API map regenerated: 26 changed public-source files, +35/-9
declarations, 0 unmapped, current on rerun. Docs inventory regenerated and
current on rerun. e2e typecheck passes. Browser suites not run.

### [2026-09-28] [Phase 2-6] Single identity-model cutover

PROCEEDED (default: one coordinated cutover; revisit at review). Owner
direction: no backwards compatibility, but consumer-facing API, DI and helpers
stay usable without hand-built tokens. Auth and resource tokens carry `ps`,
`sub`, optional `tenant` and `mission_s256`; `agent`, `act` and `mission` are
removed and reserved in `AdditionalClaims`. The PS issues person tokens at
`person_token_endpoint` (`/person`). Token requests carry `resource_token` and
`presented_token`, and servers verify the pair with
`TokenVerifier.VerifyPresentedTokenAsync`. Removed: `ActChainBuilder`,
`ActChainReader`, `MaxActDepth`, `MissionClaim`, `AAuthMissionHeader`, the
`aauth-mission` signature component, `AccessDecision.Subject`, and the R3
`Subject` option.

### [2026-09-28] [Phase 4] Consumer helpers kept for the new flow

RESOLVED. The two-leg flow runs without callers building tokens:

- `ChallengeHandler` answers `requirement=person-token` itself.
- `TokenExchangeClient.RequestPersonTokenAsync(ps, resource)` and
  `ExchangeAsync(ps, resourceToken, presentedToken)` cover explicit use.
- `ctx.GetAAuthVerifiedAssertion()` exposes the presented token and signing key.
- `AAuthChallengeMiddleware.BuildResourceToken(..., interaction?, loginHint?)`
  and `R3Challenge.Challenge(ctx, uri, s256)` build challenges; the R3 one gives
  agent tokens the person-token requirement.
- `R3Challenge.BuildResourceToken(verifiedAuthToken, uri, s256)` names an
  already-presented auth token for per-call proposals.

### [2026-09-28] [Phase 4] Access Server accepts only PS callers

PROCEEDED (default: remove direct agent mode). Draft-11 gives the AS a
`jwks_uri`-signed PS caller with `agent_token`, `resource_token` and
`presented_token`. The direct-agent path and its conformance tests were removed,
and `DirectAsDeferredSourceRevocationAndClarification` now goes through the PS.
`agent_token` keeps the draft-10 `invalid_agent_token`/`expired_agent_token`
codes pending AAuth issue #199 (see Open questions).

### [2026-09-28] [Phase 3] Mission errors and actions

RESOLVED. Unknown or foreign missions return 404 `mission_not_found`; terminated
or expired missions return 403 `mission_terminated` (previously 403
`invalid_mission`). Approval returns the `{s256, mission}` envelope. Update and
completion are `POST {mission_endpoint}/{s256}` (`MissionClient.UpdateAsync` and
`CompleteAsync`); the interaction endpoint rejects `completion`.

### [2026-09-28] [Phase 8] Events tickets bind to the key thumbprint (Q5)

RESOLVED. Draft-11 auth tokens name no agent, so `SubscriptionTicket.Agent`
became `KeyThumbprint`, taken from the auth token's `cnf.jwk`.
`ResourceSubscription.KeyThumbprint` records the subscribe request's HTTP
signing key, and redemption requires the two to match. Tickets persisted with
the old shape no longer redeem; the sample SQLite store is disposable.

### [2026-09-28] [Phase 7] Revoked source tokens on a first request

RESOLVED. `TokenRegistration` now records the request parameter that carried
each source token. A revoked parameter token returns 400
`revoked_<parameter>_token` (#token-revocation, L2765; `revoked_upstream_token`
L2593). A revoked `Signature-Key` agent token returns 401
`Signature-Error: error=revoked_jwt` (L2764). Polling `403 revoked` stays for
revocation while a request is pending (L2624). The helper is
`AAuthProblemDetails.SourceRevoked`.

### [2026-09-28] [Phase 7] Revocation wire cutover to `{jti, exp}`

RESOLVED. Single cutover, no draft-10 shim (#token-revocation, L2666-L2768):

- Request `{jti, exp}`, both required; the issuer is the verified server
  signer (`jwks_uri`/`jwks`/`self-jwt`), never a body member (L2690). Body `iss`
  is ignored. Malformed body, `jti` or `exp` is `400 invalid_request`.
- `IJtiStore.RevokeAsync(TokenKey, DateTimeOffset expiresAt)` records unseen
  tokens (retained until `exp` plus retention, bounded capacity). There is no
  404 (L2703). A full inventory is `500 server_error`.
- `AAuthRevocationOptions.IsAcceptedIssuer` replaces
  `AllowTokenIssuer`/`TrustedPersonServers`/`IsTrustedPersonServer`. Unset
  means deny, answered `403 unsupported_iss` (L2745). `MapAAuthIssuerRevocation`
  defaults to `AAuthTrust.Any`. `MaxTokenLifetime` (24 h + 5 min skew) rejects
  a far-future `exp` (L2690 MAY).
- The endpoint records first, cascades, then answers `200` with a `downstream`
  report (L2703, L2710). `revocation_incomplete`/502 is gone. The PS sets
  `ReportDownstream = false`, so it answers the AP with an empty body.
  `RevocationClient.RevokeAsync(Uri, jti, exp)` returns `RevocationResult`
  (status, error, downstream, `Failure`).
- Cascade: a grant the recipient issued is revoked at its resource. For a grant
  another server (an AS) issued against one of its own tokens, it revokes that
  token at the AS instead (L2751), so AP revocation still ends federated access.
- `RevocationClient` covers `content-type`/`content-digest` (L2672). PS/AS/R3
  issuer endpoints require them. The generic resource endpoint behind
  `UseAAuth` does not yet enforce coverage.
- Wallet sample: the PS revokes the person token it presented at the AS, and
  the AS cascades to Wallet. Resource samples accept only the issuers of their
  tokens.
- Not implemented: `202` deferred revocation, `rate_limited`, per-issuer
  entry bounds, and records of every AS a person token was presented to.

### [2026-09-28] [Phase 7] `downstream` lists every recipient

PROCEEDED (default: spec text). The owner brief suggested listing only failed
downstream calls. L2710 says one entry per resource, with `error` absent on
success, so every recipient is listed and `error` appears only on failure. The
body is empty when nothing was downstream.

### [2026-09-28] [Phase 5] Fresh token requests name the expired source

RESOLVED. Direct PS, AS and R3 responses no longer return polling `408
expired`. `AuthTokenResponse.CreateTrackedAsync` has an overload that takes the
source `TokenRegistration`s, and `AAuthProblemDetails.SourceExpired` maps the
earliest-expired source to one of:

- a parameter token: 400 `expired_<parameter>_token` (#token-endpoint-error-codes);
- the `Signature-Key` token: 401 `Signature-Error: expired_jwt`;
- a ceiling set by a mission's `expires_at`: 403 `mission_terminated`.

Pending polls keep `408 expired`. At the AS and R3 the agent token is
registered as the `agent_token` parameter, so it reports `expired_agent_token`
and `revoked_agent_token`. That follows the interim issue #199 ruling.

### [2026-09-28] [Phase 6] Step 4 agent-token half already enforced

RESOLVED (test added). The PS records every person or auth token it issues as a
grant of the agent token, so an upstream token issued from a later-revoked agent
token has a revoked ancestor. The intermediary's request then gets 400
`revoked_upstream_token` (L1835, L2593). `UpstreamFromRevokedCallingAgent_IsRevokedUpstreamToken`
pins it in three- and four-party. The "person binding" half has no SDK concept:
bindings live in the host's `IIdentityClaimsAsserter`, which can refuse to
assert.

### [2026-09-28] [Phase 3] Mission approval issues `person_tokens`

RESOLVED. When the governance and PS endpoints share an app, an approval, direct
or on the deferred poll, mints a mission-bound person token for each proposed
resource the identity asserter asserts (#mission-approval). The seam is
`IMissionPersonTokenIssuer`.

- Tokens bind the agent key, carry `mission_s256`, and expire by the earliest
  of the agent token, the mission `expires_at` and one hour.
- Each is a tracked grant of the agent token, so revocation cascades.
- The member is present, possibly empty, whenever the PS issued for named
  resources.
- Governance hosted without a PS omits it.
- The deferred path mints at poll time from the poll's agent token rather than
  storing key material at park time.

Not done: MockPersonServer's own `/mission` handler still omits
`person_tokens`, no sample proposes `resources`, and agents do not yet reuse
`Mission.PersonTokens` before calling `/person`.

### [2026-09-28] [Phase 10] E2E isolates demo server state

RESOLVED. Playwright-started servers get a scratch `HOME`
(`$TMPDIR/aauth-e2e-home`, wiped per run; `AAUTH_E2E_HOME` keeps one) with the
real NuGet and dotnet caches, so `~/.aauth` no longer affects runs.
`FileKeyStore` names the offending key file. The R3 sample creates its data
folder instead of writing `r3-audit.sqlite` into the project. A plain
`npx playwright test` now passes against the stale `~/.aauth`.

### [2026-09-28] [Phase 10] Docs spec links on v11

RESOLVED.

- `document-release.md` now cites v11 L993/L994.
- The jkt-jwt and verification-middleware docs cite `signature-key-09`.
- Their `§6.3` citations were wrong in `-08` too. They now cite §7.3 (egress
  admission) and §8.1 (pseudonymity).
- Draft-11 R3 removed the OpenAPI Gateway vocabulary (operation identifier
  scope, L154). The Catalog page says so and keeps its v10 link until the
  Phase 8 redesign.

### [2026-09-28] [Phase 10] Sample resources echo person identity

RESOLVED. Calendar and Wallet responses return `ps` and `sub` instead of
`agent` and `act`. `userKey` is `{ps}|{sub}`, because in four-party the `iss` is
the AS, not the person's PS. Profile's `/identified` keeps `agent`, because it
accepts agent tokens only.

### [2026-09-28] [Phase 7] Resource middleware reports revoked tokens as `revoked_jwt`

RESOLVED (bug fix). `AAuthVerificationMiddleware` answered a revoked
`Signature-Key` token with `Signature-Error: invalid_jwt`. It now returns
`revoked_jwt` (#token-revocation, L2764). An inventory conflict on a live token
stays `invalid_jwt`. The docs sweep found this; the conformance test
`RevokedAuthToken_Rejected` now pins the exact header.

### [2026-09-28] [Phase 3] Mission `Approver` members renamed to `PersonServer`

PROCEEDED (default: rename, no alias). Draft-11 missions have no approver
field. The renamed members are `StoredMission.PersonServer`,
`AAuthGovernancePipelineOptions.PersonServer` and the deferred-consent entry's
`PersonServer`, matching `Mission.PersonServer` and `MissionApprovalContext`.
`IMissionApprover` keeps its name, because it is the PS component that decides
a proposal, not a token field.

### [2026-09-28] [Phase 10] `mission_aware` metadata removed

RESOLVED. Draft-11 defines no `mission_aware` resource metadata and no
`AAuth-Mission` header; a mission reaches a resource as `mission_s256`. Bookings
no longer advertises or configures the flag, and the SDK doc comments no longer
cite it.

### [2026-09-28] [Phase 10] Docs sweep

RESOLVED for `docs/`. 27 files were rewritten to the draft-11 model by a worker,
and the highest-stakes claims were spot-checked against source (revocation
error rules, pair verification). `Documentation_ResourceRecipientsAndGenericRoutesUseCorrectContext`
now asserts draft-11 wording (`expectedPersonServer`, `VerifyPresentedTokenAsync`,
no `expectedApprover`). The docs inventory is regenerated after the GuidedTour
snippets compile.

### [2026-09-28] [Phase 5] Holder dropped cached person tokens for account requests

RESOLVED (bug fix, found by e2e). `AAuthTokenHolder.SelectForRequest` required
the carrier token's `account` to match the request's account. A person token
MUST NOT carry `account` (#person-tokens, L898), so every account-scoped request
fell back to the agent token and looped on `person_token_required` (Bookings,
protected Events). Person tokens now skip the account check; the resource token
and the auth token still bind the account.

### [2026-09-28] [Phase 4] Person-token issuer trust separated from auth-token trust

PROCEEDED (default: new `TrustedPersonServers` / `IsTrustedPersonServer`,
falling back to the auth-token issuer policy when unset). The verification
middleware checked person-token issuers against `TrustedAuthTokenIssuers`. In
four-party the AS issues auth tokens and the PS issues person tokens, so a
resource had to list the PS as an auth-token issuer too, which widens what it
accepts. The options are on `AAuthVerificationOptions`,
`AAuthResourcePipelineOptions` (`UseAAuth`) and `AAuthServerOptions`
(`RequireAAuth`). Wallet, Catalog and the Concierge `/wallet` branch use them.
Conformance `PersonTokenIssuerTrustIsIndependent` covers four-party, untrusted,
and the three-party fallback.

### [2026-09-28] [Phase 10] Downstream `sub` is directed per resource

RESOLVED. The downstream auth token in a call chain keeps the upstream `ps`,
but `sub` is directed at the downstream resource, and the issuer must not copy
the upstream `sub` (§Call Chaining, directed identifiers). The e2e specs assert
a directed downstream `sub`, not equality with the upstream one.

### [2026-09-28] [Phase 10] GuidedTour and SampleApp migrated; step counts grew

RESOLVED. Every PS-governed tour flow now shows the person-token leg, and plan
lengths grew to match:

| Flow | Steps |
|---|---|
| Autonomous | 6 → 8 |
| Deferred | 9 → 11 |
| CallChain | 7/13 → 9/15 |
| Federated | 7/10 → 9/12 |
| RichRequests | 14 → 16 |
| Mission | 20 → 21 |
| MissionCallChain | 14 → 15 |
| SubAgent | 7 → 8 |

The elevated `/trips/book` step presents the mission person token again rather
than stepping up from the `/trips` auth token; the spec allows either. Two e2e
checks became weaker because the echoed `agent` no longer exists: the
RichRequests account switch compares `ps`, and the sub-agent step 8 checks the
four-party result, while step 6 still binds the auth token `cnf` to the worker
key. The worker also fixed the MockPersonServer `/local/wallet/revoke` route: it
passed the agent id as the scope limit, a draft-10 argument order.

### [2026-09-28] [Phase 9] `MissionHeaderHandler` renamed; ApiSurface gate restored

RESOLVED. The handler only tags requests with `mission_s256`, so it is now
`MissionContextHandler`. The ApiSurface tool failed on the new
`AAuthTokenType.PersonToken` because `AAuthTokenType.cs` had no grouping rule.
It now maps to server contracts, and the API map is regenerated and current
(116 changed public-source files, +198/-117 declarations).

### [2026-09-28] [Phase 10] Gates at `be7211c`

RESOLVED. Release build: 0 errors, 0 warnings. Tests: core 1651,
Conformance 1124, R3 319, Events 75, all passing. The API map and docs inventory
are current on rerun, and the e2e typecheck is clean. Full Playwright run
(isolated `HOME`): 76 passed, 1 skipped. The skip is the Keycloak-gated
`federated-deferred` spec, which needs `KEYCLOAK_E2E=1`.

## Deviations from plan

None. Implementation has not started. The package follows the seven-document
draft-10 pattern without inheriting completed checkboxes, historical API counts,
defect verdicts or test results. Its upstream-question section is part of the
research, not a new specification or modification of vendored bytes.

### [2026-09-25] [Phase 0] Research citations still point at WIP lines

PROCEEDED (default: callouts now, full re-derivation in Phase 0). The v11 line
citations in `research.md`, the ledger and the maps refer to the WIP capture.
The plan's new citations were checked against the published files. Phase 0 now
includes re-deriving the rest before implementation.

### [2026-09-28] [Phase 0] Merged `origin/main` instead of rebasing

PROCEEDED (default: keep the merge). The plan said rebase. The branch owner
merged `origin/main` (`eef4175`) instead. The published branch history is
preserved, and the API baseline uses the release tag directly.

### [2026-09-28] [Phase 1] Started before Phase 0 documentation re-derivation

PROCEEDED (default: finish before Phase 2). Phase 1 depends only on published
vocabulary, which was read from the published text directly. Re-deriving the
research, ledger and map citations, and assigning each upgrade-checklist ID to a
phase in the ledger, are still open Phase 0 items. Phase 2 does not start until
they are done.

### [2026-09-28] [Phase 2-6] Cutover landed as one commit

PROCEEDED (default: accept). Person tokens, the presented-token pair, `ps`/`sub`
and the `mission_s256` reference change the same wire contracts at every role,
so Phases 2-6 could not be split and still build. The Events ticket binding and
later fixes are separate commits. The Phase 0 documentation re-derivation was
not finished first; it moves to Phase 10.

### [2026-09-28] [Phase 10] GuidedTour and snippets still show draft-10 flows

PROCEEDED (default: sweep in Phase 10). `TourSession.cs` was only changed to
compile; its steps and `CodeSnippets` still describe agent-to-auth flows. The
snippet-compilation, frozen-surface and reference-table tests fail until the
sweep, along with the SampleApp `Mission.razor` snippets, the Documents step 2
snippet, and the v10 plan links to deleted files.

### [2026-09-28] [Phase 2-6] Bugs found and fixed during the cutover

RESOLVED.

- **The PS fetched its own metadata over HTTP** to verify the tokens it had
  issued. It now verifies them with its configured keys, via
  `TokenVerifier.WithLocalIssuer`.
- **`AuthTokenResponse` left `StatusCode` null**, which broke callers checking
  for 200 (federation, mission log). It now returns an explicit 200.
- **A Bookings call silently rebound an argument.** After the
  `VerifyAuthTokenWithJwksAsync` signature change, the agent id bound to
  `expectedMaxScope` with no compile error. The argument was removed.
- **The Calendar consent-deny fixture** did not trust the test PS. This only
  surfaced once the resource verified a PS-issued person token before consent.
- **First requests with a revoked upstream token returned 403 `revoked`**
  (Conformance `RevocationLifecycleTests`). Fixed in "Revoked source tokens on a
  first request" above.

### [2026-09-28] [Phase 3, 5-10] Post-cutover items folded into the plan

PROCEEDED (default: assign each to its owning phase). A gap review after the
revocation cutover found 12 remaining items. Eleven are now responsibilities
and Definition of Done boxes in their owning phases:

- Phase 3: deferred-approval expiry (item 8); MockPersonServer `person_tokens` and a resource-naming proposal (10).
- Phase 5: agent reuse of `Mission.PersonTokens` (11); MockAgentProvider `401` Signature-Error (4).
- Phase 6: agent-person binding revocation at step 4 (3).
- Phase 7: revocation digest coverage at every endpoint (2); per-issuer bounds and `rate_limited` (5); deferred `202` revocation (6); AS presentation records (9).
- Phase 8: R3 draft-11 wire names (1); event dedup on `(iss, jti)` (7).
- Phase 10: Wallet `DirectAs` label (12).

AAuth issue #199 is excluded and stays an open upstream question. Boxes were
ticked only where a named, passing test backs them; 29 are ticked and 57 are
open. The plan gained a closing-out section for when every box is ticked.

### [2026-09-28] [Phase 3, 5-10] Correction: all 12 items are in the plan

CORRECTED. The previous entry says "Eleven". The gap review listed 12 items,
with AAuth issue #199 listed separately, and all 12 were folded in as the list
above shows. No plan change was needed.

### [2026-09-28] [Phase 8] R3 draft-11 wire format (post-cutover item 1)

RESOLVED in four commits:

- `368aa85`: `r3_conditional` is now `r3_per_call`. The public names follow:
  `PerCallClaim`, `AuthTokenClaims.PerCall`, `R3EnforcementDecision.PerCall`,
  `R3EnforcementDecisionKind.PerCall` and `IsPerCallOperation`. The R3 sample
  config key is now `PerCallOperations`.
- `f849825`: R3 documents and proposals no longer carry `version`. The reader is
  tolerant, so a `version` member sent by a peer is ignored.
- `88c0882`: the OpenAPI Gateway vocabulary is removed. Catalog now publishes one
  merged OpenAPI definition that renames the colliding `list` operations to
  `listDestinations` and `listExperiences` (R3 #operation-identifier-scope). The
  `/catalog-gateway` route name is kept so links stay stable.
- `ad40801`: the core SDK accepts `per-call` as an `access_mode`. The new
  `R3AccessAnnotations` writes and reads the OpenAPI/AsyncAPI and MCP encodings
  and applies the spec rules: `session-token` is rejected, a budget flag means
  at least `auth-token`, and annotations are sparse. OData is left to
  `$metadata` XML; gRPC, GraphQL and WSDL have no encoding. Bookings marks
  `confirmReservation` as `per-call`.

DECISION: a reader ignores an unrecognized or `session-token` annotation
value, the same way it treats an unknown `access_mode`. Only the writer
rejects them.

ISSUE: my first draft of the Catalog snippet opened with a `//` comment. That
broke `SnippetCompilationTests`, which classifies a snippet as a member by
checking `StartsWith("public static")`. I dropped the comment rather than
change the harness.

Evidence: `Draft11WireNames_PerCallClaimAndNoDocumentVersion`,
`R3Draft11FixtureTests` (the spec's R3 document example pins
`DB_rCyQ4eWAg8LYhNyyKl-Ze3_hmuGK3zf-AnoK4WOU`; the spec's annotation examples
read as `per-call` plus budget), `MergedDefinition_RenamedCollidingOperationsAreDistinct`,
`MalformedOrRemovedDiscoveryFails`, `OpenApi_AnnotatesOnlyConfirmationAsPerCall`
and `EmitsEachAccessMode(per-call)`. Gates: R3 tests 323, Conformance 1161,
AAuth.Tests 1658, Events 75; the API map and docs inventory are current; e2e
76 passed, 1 skipped (Keycloak), including 6/6 Catalog.

Not done in this item: atomic single-use per-call grants, per-document PS
readership, and release gating (the `result` member). These stay open under
their own Phase 8 boxes.

### [2026-09-28] [Phase 7] Revocation body coverage at every endpoint (post-cutover item 2)

RESOLVED. Before this change, only hosts using `MapAAuthIssuerRevocation` (the
PS, the AS and R3) demanded `content-type` and `content-digest`. A resource that
mapped `MapAAuthRevocationEndpoint` behind its own `UseAAuth` verifier accepted
a revocation whose signature covered neither (L2672: "at a resource's
revocation endpoint as much as a PS's or an AS's").

Fix:

- `AAuthVerificationResult.CoveredComponents` exposes the components the
  verified signature covers.
- The shared revocation handler now answers `401 Signature-Error:
  invalid_input` with `required_input` when either component is missing. This
  holds whatever the host verifier was configured to require.
- The middleware already rejects a covered digest that does not match the body.

Every SDK revocation route goes through that handler: PS, AS and R3 via
`MapAAuthIssuerRevocation`, resources directly.

Evidence: `Revocation_RequiresBodyCoverageAtEveryRecipient` (the host verifier
has no required components; the uncovered request gets 401 and the token is not
revoked) and `Revocation_RejectsTamperedBody`. The test helper now signs as
`RevocationClient` does. Conformance 1163 passed.

### [2026-09-28] [Phase 8] Event tokens carry `jti`; dedup on `(iss, jti)` (post-cutover item 7)

RESOLVED. The gap was wider than the sample key. The SDK issued event tokens
with no `jti`, although Events -11 lists `jti` among the required payload claims
(L363). Two tests encoded the old behaviour:

- `EventWithoutJtiOrCnfVerifies` asserted that no `jti` was present;
- `AgentContextAndLiteralIssuerEidDedupPersist` asserted that a second event on
  the same `eid` was dropped.

The docs also said "No required per-event `jti` was added." Deduplicating on
`eid` drops every event after the first on an unlimited subscription.

Fix:

- `EventTokenBuilder.Jti` defaults to a fresh value, and the builder emits it.
- `EventsTokens.Verify` requires `jti` on event tokens.
- `EventEnvelope` carries `Jti`, and the AP endpoint and `EventReceiver` fill it
  in.
- The sample AP receipt is now a hash of `(iss, jti)` rather than of the token.
  A re-signed copy is the same delivery, costs no quota, and a different body is
  still 400.
- The agent table `received_events` is keyed `(issuer, jti)`. It is a new table
  name so that existing sample databases pick up the new key.

Evidence:

- `EventWithJtiAndWithoutCnfVerifies`, `EventWithoutJtiFails` and
  `InvalidEventClaimsFail(jti, ...)`;
- `BuilderIssuesDistinctJtiPerEvent`;
- `AgentContextPersistsAndEventsDedupeOnIssuerAndJti` (a re-signed copy is
  ignored; a second event on the same `eid` is recorded);
- `ProviderAcceptsEachJtiOnceWithoutSpendingQuotaOnDuplicates`;
- `HttpStatusQuotaUnlimitedUnknownAndWrongAudience`, where a true retry resends
  the same token and a new event on a single-use subscription is 429.

The ticket-key half of the box was already covered by
`TicketRedemptionIsAtomicAndPreservesAccount`. Events tests 80 passed; Events
e2e 4/4.

## Open questions

### [2026-09-11] [Phase 0] Q1-Q14 implementation decision gate

BLOCKED for SDK implementation authorization and affected conformance claims,
not for research or Git branch publication. See
[research questions](research.md#gaps-and-open-questions) for both-sided evidence
and [questions for Dick](research.md#questions-for-dick-hardt) for upstream items.

| ID | Ruling needed | Current state |
|---|---|---|
| Q1 | WIP target and missing Signature Keys errors | Proposed pin with WIP qualification; no conformance closure |
| Q2 | Person-only authorization versus runtime step-up | Specific-flow interpretation proposed, not approved |
| Q3 | Upstream-token audience/key contradiction | Trust-boundary ruling required |
| Q4 | Delegated person/mission authority and consent caches | PS-authoritative evidence proposed; no act fallback |
| Q5 | Protected Events ticket identity | Trusted binding and persistent contract unresolved |
| Q6 | Optional capability selection | Core migration and existing capabilities proposed; optional slices explicit |
| Q7 | Expiry/future iat/ceiling strength/refresh margin | Separate timing policies proposed; ambiguity retained |
| Q8 | Retained-result completion versus terminal 410 | Specific execute-once rule proposed; transaction/retention ruling pending |
| Q9 | Revocation graph/store and outbound delivery | Separate dependency/expiry edges proposed |
| Q10 | Budgets/release accounting and usage audience | Separate Budgets and disabled release execution proposed |
| Q11 | Additional claims versus fixed directed subject | Reject conflicting repeated identity proposed |
| Q12 | Ownership and persisted schema migration | Reuse current abstractions; explicit migration/isolation proposed |
| Q13 | Clarification replacement token-pair carriage | Atomic verified pair replacement proposed; upstream wire shape unresolved |
| Q14 | Fresh challenge naming a revoked auth token | Fresh-person recovery proposed; upstream choreography clarification required |

At implementation time append `RESOLVED`, `PROCEEDED (default ...)`, or `BLOCKED`
entries per question, retaining this original record. Record selected baselines,
packages if any, exact tests and unavailable environments when they occur.
Do not retrospectively invent baseline test evidence or promote research
defaults into approvals silently.

### [2026-09-25] [Phase 0] Q1-Q14 status after published draft-11

BLOCKED for SDK implementation authorization only. Upstream uncertainty no
longer blocks the gate: [PR #162](https://github.com/dickhardt/AAuth/pull/162)
and the published text resolve Q1-Q5, Q7-Q11, Q13 and Q14. The citations are in
[the plan's upstream rulings](implementation-plan.md#upstream-rulings). Q4, Q8
and Q9 leave SDK design choices (consent caches, retained-result storage,
revocation delivery). Q6 (optional capability selection) and Q12 (persistence
and public API migration) remain SDK decisions. Record each as `RESOLVED` or
`PROCEEDED` when implementation is authorized; this entry does not approve them.

### [2026-09-28] [Phase 4] AS verification of `agent_token` (AAuth issue #199)

OPEN upstream. The access-server checklist notes that -11 gives no error code
for a failing `agent_token` body parameter, and no rule for verifying it (step 1
of Agent Token Verification compares against the signing key, which at the AS
is the PS's). The -12 proposal restores `invalid_agent_token` and
`expired_agent_token` and compares `agent_token`'s `cnf.jwk` with the resource
token's `agent_jkt`. Phase 4 must choose a disposition for the AS path before
removing the draft-10 codes.

### [2026-09-28] [Phase 5] MockAgentProvider refresh signature errors

OPEN. The sample AP refresh endpoint answers a missing or unparsable
`Signature-Key` with a problem body (`invalid_request`), not `401` with
`Signature-Error`. Move it to the shared verifier or to -09 codes when the agent
refresh path is reworked.

### [2026-09-28] [Phase 6] Upstream verification step 4 not enforced

RESOLVED 2026-09-28 by "[Phase 6] Step 4 agent-token half already enforced".
Originally OPEN. At the PS, step 4 identifies the calling agent from its own records: the
agent it issued the upstream person token to, or the one behind an upstream auth
token. If that agent's token or person binding is revoked, the PS must reject
with `revoked_upstream_token` (#upstream-token-verification, L1835). The PS keeps
no issued-to record yet, so only the token-level check runs. No test covers it.
This needs an issuance record keyed by person-token `jti`, and Phase 7's binding
revocation.

### [2026-09-28] [Phase 3] `person_tokens` in mission approval

RESOLVED 2026-09-28 by "[Phase 3] Mission approval issues `person_tokens`".
Originally OPEN. The approval response may carry `person_tokens` for the proposal's
`resources`, each with `mission_s256` (#mission-creation, L1415).
`MissionProposal.Resources` is sent, but the PS issues no `person_tokens`, and
`Mission.PersonTokens` stays empty. Agents fall back to per-resource
person-token requests, which the spec allows.

### [2026-09-28] [Phase 5] `408 expired` outside polling

RESOLVED 2026-09-28 by "[Phase 5] Fresh token requests name the expired source".
Originally OPEN (SDK design). If an issued token's ceiling passes during a synchronous
direct `/token` audit, the R3 AS returns `408 expired`. The spec defines that
code for pending polls (L2623). A fresh-request error (for example
`expired_presented_token`) may fit better. R3 test
`TokenEndpoint_DoesNotReleaseTokenThatExpiresDuringAudit` pins the current code.

### [2026-09-28] [Phase 7] Revocation endpoint still uses the draft-10 body

RESOLVED 2026-09-28 by "[Phase 7] Revocation wire cutover to `{jti, exp}`".
Originally OPEN (Phase 7 not started). `RevocationEndpoint` accepts `{iss, jti}` and
returns 404 for unknown tokens. Draft-11 revocation requests are `{jti, exp}`,
with one recipient per token type and no "not found" (#token-revocation). A
replay-detection docs test pins the `{iss, jti}` example.

### [2026-09-28] [Phase 10] Stale local sample state breaks e2e startup

RESOLVED 2026-09-28 by "[Phase 10] E2E isolates demo server state".
Originally OPEN (environment, not a regression). MockAgentProvider aborted at startup
loading `~/.aauth/ap-keys/ap-key-1`, a key file from June without `alg`
(`alg` has been required since `75980b2`, draft-10). All samples persist under
`$HOME/.aauth`, so e2e ran with a scratch `HOME` and the real NuGet and
Playwright caches. Consider giving e2e its own state directory, or having
`FileKeyStore` report the offending path.

### [2026-09-28] [Phase 10] Remaining stale citations in docs

RESOLVED 2026-09-28 by "[Phase 10] Docs spec links on v11" (the Wallet
`DirectAs` label remains). Originally OPEN. `docs/` still links v10 in three places whose anchors or lines moved in
v11 and were not re-derived: `document-release.md` L965/L973, the R3
`openapi-gateway-vocabulary` anchor in `catalog-gateway.md`, and the
`signature-key-08` links (v11 vendors `-09`). The Wallet sample still labels a
flow `DirectAs` although it routes through the PS.

### [2026-09-28] [Phase 10] E2E baseline after the cutover

OPEN. Full Playwright run (isolated `HOME`, commit `979ce07`): 36 passed,
40 failed, 1 skipped. The failures are the demo flows that still drive draft-10
agent-to-auth exchanges, which resources now answer with `person-token`:

- **GuidedTour:** autonomous, deferred, call-chain, federated, mission,
  mission-call-chain, rich-requests, sub-agent, catalog, events, reset, and the
  wallet protocol walkthroughs.
- **SampleApp:** bookings, call-chain, federated, jwt, mission-call-chain,
  sub-agent, catalog, events, and the wallet protocol pages.

Sub-agent specs also assert a nested `act`, which draft-11 removes. These pages
are the remaining Phase 10 sweep.