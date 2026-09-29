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

### [2026-09-28] [Phase 6] Agent-person binding half of step 4 (post-cutover item 3)

RESOLVED. L1835 step 4 requires the PS to answer `revoked_upstream_token`
when it has revoked the calling agent's agent token or its binding to the
person.

DECISION: the binding is an entry in the PS token inventory,
`AgentPersonBinding.Key(ps, agentIss, agentSub)`. It is keyed by the agent
identity, not by an agent-token `jti`, so it survives agent-token refresh.
Every token the PS issues directly to an agent is recorded as a grant of that
binding: direct token requests and mission `person_tokens`. Chained requests
are not, because L2918 says a chained request neither uses nor establishes a
binding.

Revoking the binding with `AgentPersonBinding.RevokeAsync` has three effects
through the existing ancestor check:

- any upstream token issued under it becomes a revoked ancestor, so a chained
  request gets `400 revoked_upstream_token`;
- the agent's own requests fail source registration (`401 revoked_jwt`), even
  with a refreshed agent token;
- other agents are unaffected.

DECISION: the binding entry uses a fixed far expiry. A binding has no natural
expiry, and `RegisterAsync` rejects an existing key registered with a different
expiry.

Not done: revoking a binding does not cascade downstream revocation calls.
Only the rejection is a MUST.

ISSUE: the first test registered `IJtiStore` in the PS's DI container. That
switched on PS request replay detection, and the harness resends identical
signatures, so 7 unrelated tests failed. Hosts now pass the inventory through
the new `AAuthPersonServerOptions.TokenInventory`, and
`MapAAuthIssuerRevocation` takes an optional `inventory`.

Evidence: `UpstreamFromRevokedBinding_IsRevokedUpstreamToken` (three- and
four-party). The agent token is not revoked; the chained request is `400
revoked_upstream_token`; the refreshed agent token is refused; another agent is
unaffected. Conformance 1165 passed. The call-chaining docs have a
compile-checked snippet.

### [2026-09-28] [Phase 5] MockAgentProvider refresh signature failures (post-cutover item 4)

RESOLVED. The sample AP's `/refresh` answered most signature failures with
`400 invalid_request`, or with a 401 that had no `Signature-Error`. Every
signature failure is now `401` with `Signature-Error`:

- a missing or unparseable `Signature-Key`, `Signature-Input` or `Signature`
  is `invalid_input`, with `required_input`;
- a scheme other than hwk or jkt-jwt is `unsupported_scheme`, with
  `Accept-Signature-Scheme: hwk, jkt-jwt`;
- an hwk header without its key is `invalid_key`;
- a naming-JWT or HTTP signature failure carries the verifier's code.

An unknown enrolled key stays `400 invalid_grant`, because it is not a
signature failure.

Evidence: `MockAgentProviderRefreshTests` (unsigned, unsupported scheme,
tampered signature). The tests isolate the AP's key directory and databases:
with the defaults, a stale `~/.aauth/ap-keys` key from an earlier release made
the host fail to start.

### [2026-09-28] [Phase 3] Deferred mission approval keeps `expires_at` (post-cutover item 8)

RESOLVED. When `IMissionApprover` returned `Defer()` with an `ExpiresAt`, the
parked `DeferredConsent` dropped it, so the mission approved after the user
decided had no expiry. `DeferredConsent.MissionExpiresAt` now carries the
approver's value, and the completion passes it to `CompleteMissionAsync`.

Evidence: `Mission_Prompt_ApprovalKeepsApproverExpiry`. The mission parsed from
the completed poll has the approver's `expires_at`. Governance mapper tests: 37
passed.

### [2026-09-28] [Phase 10] Wallet `DirectAs` renamed (post-cutover item 12)

RESOLVED. Draft-11 has no direct agent-to-AS path, so the Wallet flow is now
`WalletFlow.AsGrantChaining` (UI label "Chaining an AS-issued grant"), with
`WalletScenarioCode.AsGrantChaining`. The e2e flow names, the docs and the
three READMEs follow. The wallet guide no longer says "The sample still labels
this flow `DirectAs`".

Evidence: Wallet e2e 9/9 passed, the snippet tests pass, and a grep finds no
`DirectAs` or "direct-AS" in the samples, docs or tests.

### [2026-09-28] [Phase 7] PS revokes only where a person token was presented (post-cutover item 9)

RESOLVED. The SDK cascade already works this way: an auth token an AS issued
against a PS person token is recorded as that token's grant. Revocation
revokes the person token at each such AS once, and never at an AS with no
record.

The MockPersonServer demo route `/local/wallet/revoke` revoked at every
configured Access Server instead. The sample now passes `TokenInventory` and
revokes only at the trusted Access Servers recorded as issuers of the person
token's grants.

Evidence:

- the SDK path: `ProviderRevoke_BlocksSourceAndCascadesExactIssuedOrProvidedGrants`
  and `UpstreamRevocationCascadesToDownstreamGrant` (federated), which assert
  exactly the AS revocations;
- the sample route: Wallet e2e Revocation (9/9). The PS revocation's result
  names the AS and its downstream Wallet. That result can only come from the
  recorded presentation.

### [2026-09-29] [Phase 7] Per-issuer revocation bounds (post-cutover item 5)

RESOLVED. L2745: a recipient that accepts any verified issuer SHOULD bound what
one issuer can hold, in entries and in rate, and answer `rate_limited` beyond
either (429, `Retry-After` REQUIRED, L2740). `AAuthRevocationOptions.Limits`
(`RevocationLimits`) is on by default: 10,000 unexpired entries and 600
requests a minute per issuer; `null` turns it off.

The check runs after body validation and before anything is recorded:

- an entry counts from acceptance until its `exp` plus clock skew;
- a repeat of a held `jti` is not a new entry;
- `Retry-After` is the time until the oldest request leaves the window, or
  until the earliest entry expires.

DECISION: bounds apply on every mapped endpoint, not only under
`AAuthTrust.Any`, because an accepted-issuer list does not bound volume either.

Not done: the limiter is in memory per endpoint instance. A scaled-out host
needs a shared limiter; this is recorded as a deployment limit, not a gap.

Evidence: `Revocation_EntryBound_IsRateLimited` and
`Revocation_RateBound_IsRateLimited` (429 `rate_limited` with `Retry-After`,
and the token is not recorded). Conformance 1168 passed.

### [2026-09-29] [Phase 7] Deferred `202` revocation (post-cutover item 6)

RESOLVED. Revocation follows L2728-L2730. When the cascade outlasts
`AAuthRevocationOptions.DeferAfter` (default 20 s, which a caller's
`Prefer: wait` can shorten), the recipient answers `202` with:

- `Location: {path}/pending/{id}`;
- `Retry-After: 0` and `Cache-Control: no-store`;
- a `{"status":"pending"}` body and no `AAuth-Requirement`.

The poll is a bodyless signed `GET`. Only the verified identity that made the
revocation gets an answer; any other gets `404`. The terminal answer is what
the synchronous path would have returned. A recipient with nothing downstream
never answers `202`. The cascade runs on the host's stopping token, not on the
aborted request.

`RevocationClient` now follows a `202`. It polls the same-origin pending URL
under its own signing identity, with `Prefer: wait`, until a terminal answer or
`MaxPollDuration` (2 min). After that the downstream is
`revocation_unavailable`.

BUG found and fixed: the PS and AS agent-verification branches excluded only
the exact revocation path, so a poll of `/revoke/pending/{id}` was verified as
an agent request and got `unsupported_scheme`. Both now exclude by path
prefix, and `MapAAuthIssuerRevocation` adds a verification branch for the
pending route that requires no body components.

Evidence:

- `Revocation_SlowCascade_DefersAndOnlyTheRevokerPolls`: 202 headers; the
  agent identity gets 404; `Prefer: wait=0` still gets 202; the terminal 200
  carries `downstream`;
- `Revocation_NothingDownstream_NeverDefers`;
- `RevocationClient_FollowsDeferredRecipient`;
- `SlowDownstream_PersonServerDefersAndCompletesOnPoll`, end to end through the
  PS.

Conformance 1172 passed.

### [2026-09-29] [Phase 5] Agents reuse mission person tokens (post-cutover item 11)

RESOLVED. `MissionContextHandler` now also sets
`AAuthRequestOptions.MissionPersonTokens` from `Mission.PersonTokens`. On a
`person-token` challenge, `ChallengeHandler` presents the approval's token for
the resource instead of calling `/person` when all of these hold:

- the request is not chained;
- the token is a person token whose `iss` is the PS in use and whose `aud` is
  the resource;
- its `mission_s256` equals the request's mission;
- its `cnf.jwk` is the signing key;
- it has more than a minute left.

Any mismatch falls back to `/person`. A reused token the resource then refuses
is not offered again, and the next challenge calls `/person`. The token's
signature is left to the resource; the agent received it over its signed PS
channel.

Evidence: `MissionPersonToken_ReusedOnlyWhenItMatches`. A match makes no PS
call; resource, mission, key and expiry mismatches each fall back.

### [2026-09-29] [Phase 3, 10] Sample mission approvals carry `person_tokens` (post-cutover item 10)

RESOLVED. MockPersonServer's own `/mission` and its parked approval now return
`person_tokens`. The SDK gains `HttpContext.IssueMissionPersonTokensAsync`, so
a host that maps its own mission endpoint gets the tokens with one call instead
of building `MissionPersonTokenRequest` by hand. `MapAAuthGovernance` uses the
same helper, which removed a private duplicate.

Both apps now propose missions naming the Trips resource in `resources`:

- GuidedTour's raw proposal body and its narrative;
- SampleApp's proposal. SampleApp also presents the returned person token
  instead of calling `/person`, falling back when it is absent; its code sample
  shows the same.

Evidence: `MissionNamingResources_ApprovalCarriesPersonTokens` against the real
MockPersonServer (one token keyed by the resource, with the mission's
`mission_s256`, `iss` and `aud`).

The first mission e2e run failed: the GuidedTour proposal got 400, because
`GovernanceEndpoints.ParseMissionProposal` validated `resources` against the
production (HTTPS-only) policy and the tour names `http://localhost:5002`. The
parser now takes an optional egress policy. `MapAAuthGovernance` passes its
`EgressPolicy`; MockPersonServer passes its sample policy. The default stays
HTTPS-only. Evidence: `ParseMissionProposal_LoopbackResourcesNeedDevelopmentPolicy`;
Playwright `--grep "[Mm]ission"`: 8 passed.

### [2026-09-29] [Phase 3] Person-token lifetime bounds and request fields

RESOLVED. Two DoD boxes lacked a `/person` test. The existing cited tests
covered `/token` and auth tokens, not person tokens.

- `PersonTokenEndpoint_LifetimeIsCappedByEveryBound`: the issued `exp` is capped
  by the one-hour default, the agent token, the upstream token and the mission,
  one case each.
- `PersonTokenRequest_CapabilitiesAndLoginHintReachAsserter`: `capabilities` and
  `login_hint` from the `/person` body reach the person asserter.

### [2026-09-29] [Phase 3] Partial resource approval

RESOLVED (SDK change). A PS could not approve only some proposed resources.
`MissionApprovalDecision.ApprovedResources` (and
`DeferredConsent.MissionApprovedResources` for the parked path) now set
`approved_resources`. The governance pipeline keeps only the intersection with
`proposal.resources` and issues person tokens only for those. Leaving it unset
approves every proposed resource, as before.

Evidence: `PartialResourceApproval_LimitsApprovedResourcesAndPersonTokens`, sync
and deferred. An unproposed resource in the decision is dropped. That
capabilities stay outside the mission hash is covered by
`MissionModelTests.FromApprovalResponse_ParsesSessionMembers`.

Gates: build 0 warnings; AAuth.Tests 1667, Conformance 1180, R3 323, Events 80;
API and docs maps refreshed; snippet and link tests 108.

### [2026-09-29] [Phase 3] Mission store keeps terminal state and expiry

RESOLVED (SDK fix). `InMemoryMissionStore` broke two §Mission Management rules
("A terminated mission MUST NOT return to `active`", L1516):

- `SaveAsync` overwrote a stored mission, so re-saving a terminated mission
  revived it and could drop or extend `ExpiresAt`;
- `SetStateAsync` read then wrote, so a concurrent `Active` could overwrite
  `Terminated`, and `SetStateAsync(Active)` reopened a terminated mission.

`SaveAsync` now merges atomically: terminated stays terminated and the
earliest expiry wins. `SetStateAsync` uses compare-and-swap and ignores any
transition out of `Terminated`. `IMissionStore` documents both rules for
custom stores.

Evidence: `MissionStore_TerminatedIsFinal`,
`MissionStore_ReplacementKeepsEarliestExpiry` and
`MissionStore_ConcurrentMutationKeepsTerminal` (50 rounds of 16 racing
transitions and saves).

### [2026-09-29] [Phase 3] Accepted updates keep exact bytes

RESOLVED (test only). §Mission Update (L1471, L1479) returns `s256` over the
update's persisted bytes and leaves the mission unchanged. The existing test
only checked that `s256` was non-empty. `MissionUpdate_OwnedMissionOnly` now
checks:

- the returned `s256` equals `Mission.ComputeS256` of the logged entry's bytes;
- the entry retains the description;
- the stored mission keeps its blob and `Active` state under the same
  `mission_s256`.

Conformance 1183 passed.

### [2026-09-29] [Phase 4] Wire tests for the prerequisite and step-up legs

RESOLVED (test only). The exchange legs already had wire tests:

- agent to PS: `UpstreamTokenIncludedInPostBody` checks `resource_token`,
  `presented_token` and `upstream_token`;
- PS to AS: `FederateAsync_ReturnsVerifiedAuthToken_OnSuccess` checks
  `resource_token` and `agent_token`; `FederateAsync_IncludesUpstreamToken_WhenProvided`
  and `FederateAsync_ForwardsChildToken` check `upstream_token`,
  `subagent_token` and `presented_token`.

The agent side of the prerequisite and of step-up (L641) had no wire test.
`PrerequisiteAndStepUp_WireBodies` covers both:

- **prerequisite:** an agent-token request is answered `requirement=person-token`.
  The agent sends exactly one `/person` POST, naming the resource and carrying
  no resource or presented token;
- **step-up:** an auth-token request is answered `requirement=auth-token` with a
  resource token naming that auth token's `jti`. The agent sends exactly one
  `/token` POST, with that resource token and the auth token itself as
  `presented_token`.

The resource side of step-up is covered by
`Enforcement_PerCallChallengeResultEmitsAAuthRequirementWithProposalResourceToken`
(`presented_jti` equals the verified auth token's `jti`).

### [2026-09-29] [Phase 4] Identity overwrite fails at PS and at AS

RESOLVED (test only). Stripping and substitution had tests at both servers.
Overwritten identity fields did not:

- PS: only `sub`, `presented_jti` and `ps` were tested, through MockPersonServer;
- AS: only `ps`, `subject` and the presented key were tested.

Each server now has its own theory. A resource token with one binding
overwritten (`ps`, `sub`, `presented_jti`, `mission_s256`, `tenant`,
`agent_jkt`) is rejected `invalid_resource_token`:

- PS: `TokenRequest_OverwrittenIdentity_Rejected` also checks the asserter was
  never called;
- AS: `AsRejectsResourceTokenNotNamingTheSigningPsOrPresentedToken` also checks
  the access policy was never called.

Stripping is covered by `TokenRequest_MissingPresentedToken_Rejected` (PS) and
`AsRequiresAgentResourceAndPresentedTokens` (AS). Substitution is covered by
`TokenRequest_MismatchedPresentedToken_Rejected` (PS) and the AS
`presented-key` case.

### [2026-09-29] [Phase 4] PS and AS require body coverage

RESOLVED (SDK fix). §Covered Components (L2211) requires every body-bearing
request to a PS or AS to cover `content-type` and `content-digest`. The SDK
enforced this only at revocation endpoints, and its own agent and PS clients did
not cover a body. Neither side followed the rule.

Changes:

- **Signer:** `AAuthSigningHandler.SignAsync` now covers `content-type` and
  `content-digest` on every request with a body, and computes the digest itself.
  It can't tell a PS or AS from a resource, and covering more is always
  accepted. Callers of the synchronous `Sign` are unchanged.
- **Verifier:** new `AAuthVerificationOptions.RequireBodyCoverage`. When the
  request has a body and doesn't cover both, verification answers `401
  invalid_input` naming them in `required_input`, before replay recording or
  any handler.
- **Servers:** the option is on for the `MapAAuthPersonServer` branch
  (initial, pending and governance paths), the `MapAAuthAccessServer` branch,
  and R3 `VerifyFetcherAsync` (the R3 AS token endpoint).
- **Governance:** `MapAAuthGovernance` handlers also check coverage themselves,
  so a host that mounts governance without the PS branch still enforces it.
- **Sample:** MockAgentProvider `/refresh` now passes header fields to
  `AAuthVerifier.Verify`. Without them it couldn't resolve the newly covered
  components, and the first full e2e run failed two flows (`inbox`, `jkt-jwt`).
  Covered by `BodyCoveredRefresh_VerifiesSignature`.

Evidence. Each test also checks that no policy, consent or pending state was
touched:

- PS: `PsBody_UncoveredOrTampered_FailsBeforeAsserter` (`/token`, `/person`;
  uncovered gives `invalid_input`, a body swapped after signing gives
  `invalid_signature`) and `PsPendingBodyWithoutCoverageFailsBeforePendingState`;
- AS: `AsBodyUncoveredOrTampered_FailsBeforePolicyOrPendingState`;
- governance: `UncoveredBody_RejectedBeforeSeams` (`/mission`, mission action,
  `/permission`, `/audit`, `/mission-interaction`);
- R3 AS: `UncoveredOrTamperedBodyFailsBeforeDocumentPolicyOrAudit`.

Shared test helpers `UncoveredBodySigner` and `BodySwapHandler` live in
`tests/TestEgress.cs`. The revocation coverage tests now use the former, since
the signer would otherwise cover the body. Docs: `signing-modes/overview.md`
describes the automatic coverage. The stale "Deferred `202` and `rate_limited`
are not implemented" sentence in `replay-detection.md` is gone (items 5 and 6
implemented both).

Full Playwright run after the fix: 74 passed, 1 skipped; the two failures
above pass on rerun.

### [2026-09-29] [Phase 4] AS timeouts are not local cancellation

RESOLVED (SDK fix). The PS mapped every `OperationCanceledException` from
federation to `408 expired`. An AS call that timed out in `HttpClient` (also an
`OperationCanceledException`) was therefore reported as a local expiry. Only the
PS's own cancellation (agent `DELETE` or pending expiry) is `expired` now; an AS
timeout is `502 as_unreachable`, like any other AS failure.

Evidence: `AsOutcomesMapSeparatelyFromLocalCancellation`:

- AS `deny` gives `403 denied`;
- an unstructured AS `502`, an unverifiable AS token, and a client timeout each
  give `502 as_unreachable`.

Local cancellation stays covered by `ProductionPsRelaysClarificationAndResumes`
(`cancel`) and `ClarificationDeadlineTerminatesBothPendingRequests` (`408`).

Expiry: agent, parent and upstream bounds on immediate and deferred issuance
are covered by `DirectAndDeferred_UseOriginalAgentAndParentBounds`,
`Deferred_RejectsOriginalExpiryDespiteFreshPollCarrier`,
`Direct_RejectsExpiredParentOrChild` and
`UpstreamExpiry_IsPreservedThroughDeferredIssuance`. The mission bound had no
auth-token test; `AuthToken_IsCappedByMissionExpiry` covers immediate and
deferred (clarification) issuance.

Gates: AAuth.Tests 1670, Conformance 1211, R3 325, Events 80; API and docs maps
refreshed.

### [2026-09-29] [Phase 4] Consent attributes agent-asserted content

RESOLVED (SDK and sample). §Consent Presentation (L1031, L1039) requires a
PS to visually separate resource-asserted from agent-asserted content and to
attribute the latter to the agent, and to convey the same distinction to a
supervision server. The PS ignored `justification`, `platform` and `device`,
so no hook or consent page could show them. `MissionTokenConsentContext.Prompt`
was also mis-documented as the justification (it is OIDC `prompt`).

Changes:

- **New type:** public record `AgentAssertedContent` (`Justification`,
  `Platform`, `Device`).
- **Parsing:** the PS reads these from `/person` and `/token` bodies. A
  non-string value gets `400 invalid_request` before the asserter runs.
- **Hooks:** `IdentityAssertionRequest.AgentAsserted` and
  `MissionTokenConsentContext.AgentAsserted` carry the content;
  `PersonPendingEntry.AgentAsserted` keeps it for re-review.
- **Docs comments:** `ResourceContext` is now documented as resource-asserted.
- **Sample:** the MockPersonServer consent page renders a "From the resource"
  panel and a separately styled "The agent says (not verified)" panel, with
  HTML-encoded values. Its approve handler forwards `AgentAsserted`.
- **Docs:** `server/token-issuance.md` gains a resource-asserted versus
  agent-asserted table.

Evidence:

- `AgentAssertedContent_ReachesAsserterApartFromResourceContext` (`/token`,
  `/person`);
- `AgentAssertedContent_NonString_Rejected` (each member);
- `AgentAssertedContent_ReachesMissionSupervisor` (gate and post-clarification
  review);
- `Interaction_ConsentPage_AttributesAgentAssertedContentApartFromResource`:
  separate sections, encoded `<script>`, and no agent text in the resource
  section.

Conformance 1217, AAuth.Tests 1671; API and docs maps refreshed.

### [2026-09-29] [Phase 5] `202` auth-token delivery, retained results, error outcomes and refresh margin

Checked each Phase 5 box against the code, not only the cited tests. Two were
real gaps, not missing tests.

**`202` delivery (SDK fix, agent MUST).** §Deferred Delivery (L659, L663):
agents MUST support both the `401` and the `202` form of
`requirement=auth-token`. `ChallengeHandler` handled only `401`, so a held
invocation came back to the caller as a bare `202`. It now accepts a `202` that
carries `requirement=auth-token` and a `Location`, exchanges the resource token
exactly as for a `401`, and then polls the validated pending URL with signed
`GET`s. It never resends the original request. The poll carries the original
request's options (account, mission, resource) except the body's covered
components; that exception came from a failure in the first run of the test.

**Retained results (SDK addition, selects RS-36).** L661: the resource runs
the held invocation once, keeps its result keyed by the auth token's `jti`
until that token's `exp`, and answers a repeat of the same token from it. The
SDK had no resource-side support. New `AAuthHeldInvocations` provides:

- `Hold(resourceToken, requiredScopes, execute)` answers `202` with
  `Location` and the requirement;
- `MapAAuthHeldInvocations` maps the poll endpoint;
- the poll runs the invocation under a per-entry gate for the first valid
  auth token bound to the resource token's `agent_jkt` with the required
  scopes;
- the result is retained per `jti` until `exp`; another token after
  completion gets `410`, and another key gets `404`.

`HeldInvocationResult` carries the exact response. The shipped samples keep
using `401`. Docs: `server/challenge-middleware.md`.

**Error detail.** `PollingErrorException` now carries the problem `detail`
(AG-60 to AG-62); before, only the code reached the agent.

**Refresh margin.** §Expiry and the Refresh Margin (L1301) says agents SHOULD
refresh with fewer than five minutes left. `TokenRefreshHandler` defaulted to
60 s; the default is now five minutes.

Evidence per box:

1. **Partitioning:** `CachedCarrierTracksRefreshedSourceAndRequestBindings`
   (account, mission, key) and `CachedAuthToken_IsSelectedOnlyForMatchingAccount`
   (resource). New `CachedCarrier_IsNotSharedAcrossUpstreamPeopleOrConcurrentAccounts`
   covers another person's upstream token, no upstream token, and 200
   concurrent requests alternating accounts. Mission person tokens are covered
   by `MissionPersonToken_ReusedOnlyWhenItMatches`.
2. **Exact presented token:** new `PresentedToken_SurvivesHolderRefresh` (the
   holder rotates between the resource's challenge and the exchange;
   `presented_token` is still the token the resource saw). Replacement is
   covered by `ClarificationResponse_UpdatedRequest_PostsNewResourceToken`.
3. **No resent body:** `DeferredAuthToken_PollsPendingUrlWithoutResendingBody`
   checks the resource saw exactly one POST (with the person token) and one GET
   of `/pending/1` (with the auth token).
4. **Retained result:** `HeldInvocationTests`:
   - pending until an auth token arrives;
   - same `jti` gets the same body with one execution;
   - another `jti` gets `410`;
   - after `exp` the result is gone;
   - 8 concurrent polls execute once;
   - a foreign key or missing scope does not execute.
5. **Distinct outcomes:** new `Exchange_EveryPublishedError_IsDistinct` covers
   all 17 codes in §Token Endpoint Error Codes (code, status and detail, each
   distinct). New `TerminalCodes_AreDistinctWithDetail` covers the six terminal
   polling codes. `slow_down` is covered by the existing backoff test.
6. **Refresh order, ownership, cancellation, recovery:**
   - margin: new `DefaultMargin_IsFiveMinutes`;
   - order: a refreshed agent token supersedes a cached auth token
     (`CachedCarrierTracksRefreshedSourceAndRequestBindings`);
   - concurrency: `ConcurrentRequests_OnlyRefreshOnce`;
   - cancellation: `CancellationDuringRefreshDoesNotPublishToken` and
     `RefreshAsync_CancellationDoesNotSend`;
   - ownership: `PipelineOwnsFactoryRefresherButNotInjectedRefresher`,
     `FailedBuildDisposesOwnedRefresher` and
     `FactoryRefresherIsDisposableAndBorrowsInjectedHttpClient`;
   - recovery: new `RevokedAuthToken_RecoversThroughFreshPersonToken` (Q14,
     L2764) checks that `requirement=person-token` on a revoked auth token
     leads to `/person` with no `presented_token`.

Gates: AAuth.Tests 1678, Conformance 1228, R3 325, Events 80; API and docs maps
refreshed; snippet and link tests 108.

### [2026-09-29] [Phase 6] Mission meaning after updates; delegation checks

Checked each box against the code. One real gap (fast-path consent) and
several missing tests.

**Accepted updates reach consent (SDK fix).** §Mission Update (L1481): from
acceptance on, the mission means the blob plus its accepted updates. Two things
were wrong:

- `IMissionTokenConsent` saw only the blob;
- the prior-consent fast path granted silently on a consent given before an
  update.

`MissionTokenConsentContext.AcceptedUpdates` now carries the update entries
(retained bytes in `Detail`). A prior consent counts only if it was recorded
after the latest accepted update.

Evidence per box:

1. **Owner, expiry, termination across continuations:**
   - `MissionAuthorization_RejectsInvalidContext` now includes `expired` for
     permission, audit and interaction, and the `/mission/{s256}` action for
     foreign, terminated and expired;
   - `Permission_Deferred_RevalidatesMissionBeforeDelivery` now includes
     `expired` alongside `owner` and `terminated` (the resumed poll
     re-checks);
   - `Mission_Terminated_Rejected` covers terminated and expired at `/token`
     and `/person`.
2. **Updated meaning reaches consent and audit:**
   - `AcceptedUpdate_ReachesConsentAndResetsFastPath`: the fast path grants
     before the update; after it, the Supervisor is asked again and sees the
     update; the new consent restores the fast path;
   - `AcceptedUpdate_ReachesPermissionDecision`: the permission decider's log
     holds the update with its bytes.
3. **Distinct caller, intermediary and worker keys (Q3, Q4):**
   `FourPartyUsesDistinctChildKeyAndUpstreamBounds` uses separate keys for the
   upstream caller, the intermediary and the worker. It checks that:
   - `cnf` is the worker key;
   - `sub` is the PS's record, not the upstream `sub`;
   - `mission_s256` is copied from the upstream;
   - `exp` is capped by the upstream and the child.

   Binding resolution is covered by `UpstreamFromRevokedBinding_IsRevokedUpstreamToken`.
4. **`aud` mismatch, foreign-AP intermediary, copied `sub`:**
   - new `CallChaining_UpstreamAudienceMustBeIntermediaryIssuer`: a PS person
     token at `/token` and `/person`, and an AS auth token, audienced to
     another AP give `invalid_upstream_token`; the same AS token audienced
     correctly is allowed (`CallChaining_FourPartyUpstream_WithMission_Allowed`);
   - a foreign-AP intermediary is the same check seen from the other side
     (upstream `aud` ≠ intermediary `iss`); also covered by
     `CombinedFederationRejectsMismatchedVerifiedContext(upstream-audience)`;
   - copied `sub`: `CallChaining_ThreePartyUpstream_NoMission_Allowed` and the
     four-party test.
5. **`invalid_subagent_token`:** the check existed
   (`AgentIssuanceContext.VerifyAsync`) but was untested. New
   `SubagentTokenFromAnotherIssuerOrParent_IsInvalidSubagentToken` covers PS and
   AS, each with another issuer and another parent. It asserts the error code
   and that the binding check (not a signature failure) fired. Writing it
   showed that a naive other-AP token fails earlier on its `sub` domain; the
   test now keeps the `sub` consistent with its `iss`.
6. **Direct worker and wrong parent:** `SubAgent_DirectRequest_Rejected` (a
   sub-agent signing directly gets `400 invalid_request`) and the `parent`
   cases above.

Gates: AAuth.Tests 1678, Conformance 1247, R3 325, Events 80; API and docs maps
refreshed.

### [2026-09-29] [Phase 7] Revocation dependency, races and retention clocks

RESOLVED (tests only; the production behavior was already right).

1. **The resource token does not cap the auth token.** The PS registers the
   agent, sub-agent, upstream and presented tokens as sources, never the
   five-minute resource token (`RegisterSourcesAsync`). The auth-token ceiling
   is the agent and presented expiry. New
   `ResourceTokenLifetime_DoesNotCapAuthTokenOrGrant` (with an inventory on a
   controlled clock) checks that:
   - the auth token outlives the resource token by more than 30 minutes;
   - one minute past the resource token's `exp` and after `Cleanup`, revoking
     the presented person token still reaches the auth-token grant.
2. **Races:**
   - consent completion: `UpstreamRevokedDuringConsentCannotMintAfterApproval`
     (a revocation while consent is pending ends the poll `403 revoked` with no
     token);
   - registration: `RevokedAncestorBlocksEveryDescendantAndConcurrentExtension`
     (40 grant registrations racing a root revocation: every accepted one ends
     revoked; the revoked `jti` cannot be registered again; minting checks
     ancestry first).
3. **Cascades, notification failure, retention on controlled clocks.**
   Retention: `UnseenRevocation_IsRetainedUntilItsExpiryPlusRetention` and
   `ExpiredKnownToken_RemainsIdempotentUntilBoundedCleanup` on a mutable clock.
   New `CascadedDescendant_IsRetainedOnItsOwnExpiry`: a descendant cascaded from
   a later-expiring root stays refused through its own `exp` plus retention,
   then is purged while the root stays revoked and still blocks new grants.
   Cascades: `ThreeGenerationsRevokeAndNotifyAllLocalDescendants` and
   `UpstreamRevocationCascadesToDownstreamGrant`. Notification failure:
   `AccessServer_ReportsDownstreamOutcome_AndRetriesOnRepeat` (injected
   failure, then retried). The slow-recipient path
   (`Revocation_SlowCascade_DefersAndOnlyTheRevokerPolls`) is driven by a
   test-controlled completion rather than wall-clock waits.

### [2026-09-29] [Phase 8] Per-call single use, R3 readership and release gating

Checked the three open Phase 8 boxes against the code. All three were real
gaps.

**Single use (SDK and sample fix).** R3 #per-call-flow step 4 (r3 L676): a
resource MUST NOT execute more than one invocation under one per-call auth
token, and repeats are answered from the retained result keyed by `jti`.
Bookings ran every proposal-approved call again for each freshly signed
presentation of the same token. Changes:

- new SDK `AAuthSingleUseGrants.ExecuteOnceAsync(jti, exp, execute)` runs once
  per grant under a per-grant gate and retains the result until `exp`;
- `HeldInvocationResult.ToResult()` replays the exact bytes;
- Bookings routes every proposal-approved call through it.

Disposition on "mark the stored proposal consumed": consumption is keyed by
the grant (`jti`), not the proposal hash. Proposals are content-addressed, so
an identical re-approval gets the same `r3_s256`; per-proposal consumption
would make a legitimately re-approved identical call impossible. This follows
the plan's rule to separate same-content proposal identity from per-grant
execution.

Evidence:

- `EveryRoute_EnforcesGrantedPerCallRejectedAndApprovedParameters` (all five
  routes) now re-presents the approved token with a fresh signature after
  1.1 s and gets the byte-identical retained body. The hold route's
  `expires_at` would otherwise differ.
- `SingleUseGrant_ExecutesOncePerJti` sends 16 concurrent presentations; they
  execute once and share one result.

**Per-document readership (SDK and sample fix).** `R3DocumentReaderPolicy`
let any configured PS evaluator read every document. Changes:

- `R3ProposalStore.Entitle` and `IsEntitled` record which PS may read which
  content;
- `R3DocumentReaderPolicy.IsEntitledPersonServer` is consulted by
  `MapR3Document`, and an unentitled evaluator gets `404`;
- Bookings entitles the PS named by the resource token (the presenter's `iss`,
  or the auth token's `ps` for proposals).

Evidence: `PersonServerEvaluator_ReadsOnlyDocumentsItIsEntitledTo` (two valid,
configured PSes: the named one reads `200`, the foreign one gets `404`, the AS
still reads `200`).

**Result and Budgets cannot imply enforcement (SDK fix).** R3 `result` (r3
L649) marks a release-gated proposal. `R3ProposalDocument.FromUtf8Bytes`
ignored the unknown member, so the R3 AS would have treated a release approval
as an execution approval. It now fails closed (`InvalidOperationException`,
which the R3 AS answers `400 r3_evaluation_failed`). The Budget annotation is
documented as annotation-only; it only raises the access-mode floor, and no
metadata or API claims budget accounting.

Evidence: `ResultBearingProposal_FailsClosedInsteadOfBecomingAnExecutionApproval`.
The existing `Annotations_ApplySpecRules` covers the budget floor.

Gates: AAuth.Tests 1678, Conformance 1250, R3 327, Events 80; API and docs maps
refreshed. The both-app scenario box waits for the final full Playwright run.

### [2026-09-29] [Phase 8] Full R3, Events and both-app run

Full Playwright run on the stub profile with `--retries=0`, both apps, desktop
and mobile: 76 passed, 1 skipped (the Keycloak-only case), 0 failed, 0 flaky.
R3 327 and Events 80 pass, and the Release solution builds with 0 warnings. This
evidence ticks the last Phase 8 box.

### [2026-09-29] [Phase 0] Citations re-derived against published draft-11

The deviation logged on 2026-09-25 is resolved. Research was written against
the WIP spec in `e6d18a3`, and `5f15f87` re-vendored the published text in
place. That commit rewrote 2,529 protocol lines, so every early citation had
drifted. Some drifted into unrelated sections; for example, "P937
`#person-token-endpoint`" had landed in `#ps-token-endpoint`.

Method:

1. Each citation's introducing commit came from `git blame`. Citations from
   before `5f15f87` were mapped from the old line's text to the published line:
   first by `difflib` equal blocks, then by exact text, then by fragment
   matching.
2. Every match under 0.75 similarity (44 lines) was resolved by hand, by
   grepping the requirement text. One 0.86 fuzzy match was also wrong (Budgets
   L722 to L603, an unrelated example) and was corrected to L724.
3. The rewritten lines were checked to equal the computed targets (0
   mismatches).
4. A checker now reports 184 v11 citations across research, the ledger, the
   plan and the capability scenarios, with no blank or out-of-range target.

Result: 123 research lines and 17 ledger lines were rewritten, and the plan's
own 26 citations were already correct. The six `v10` citations in research are
deliberate draft-10 baselines, labelled as such. `spec-open-questions.md` is
left as a historical record: its header already says its snapshot lines are
read at `e6d18a3`. Research's links to the superseded Signature Keys working
source and draft-08 now point at draft-09.

The published text changed these requirements, and the research prose predates
the change:

- P1117: an `updated_request` now carries `presented_token` and is
  re-verified with step 3. This closes the `presented_jti` gap research raised
  at P1194.
- P2840: `410 Gone` now has an exception for flows that repeat a presentation.
  This settles Q8.
- R719: metered or billed calls are never candidates for release gating. The
  "unresolved accounting" paragraph at R745 is gone.
- R499: R3 no longer restates base claims (R504 and R506).
- E603: tickets bind to the signing key (Q5).
- P2317 and P2320: expiry and `iat` skew moved to common verification.
- B724 and B1017: the budget example drops `cost`, and callers are named by
  the Signature-Key `id` and `dwk`.
- P1680: a claims push no longer carries `sub` (PS-55).
- Interop L52 and L75: both flows now send `presented_token`.

### [2026-09-29] [Phase 0] Finding owners, checklist ownership and negative evidence

[conformance-ledger.md](conformance-ledger.md) gained three sections:

- **Finding owners and executed checks:** F01-F24 each have an owning
  component, a phase and named discriminatory tests.
- **Negative requirements: execution evidence:** 17 rows, each with executed
  tests or an explicit conditional disposition.
- **Upgrade checklist ownership:** all 147 IDs. 131 have an owning phase and
  16 optional items have a disposition.

Checks:

- Every test name in these sections resolves to a method or class in
  `tests/`, and every owner symbol resolves in `src/`.
- `comm` between the table and the checklist files shows no missing and no
  extra IDs.

Two subagent drafts were used as leads only. The F-map draft cited
non-existent owner paths, and the checklist draft marked PS-90 as implemented.

Building the checklist table found two real gaps, each fixed in the next
entries:

- PS-112 and AS-42: withdrawn resource tokens were never checked.
- AG-34 and PS-90: `termination_reason` was absent, and `mission_status`
  carried a non-spec `expired` value.

### [2026-09-29] [Phase 3, 5] `mission_terminated` carries `termination_reason`

§Mission Status Errors (P1548 to P1567) fixes `mission_status` at
`terminated` and adds an OPTIONAL `termination_reason`. The agent reads it to
decide whether to propose again: `expired` invites a new proposal, `revoked`
does not.

Before this fix:

- The PS answered an expired mission with `mission_status: "expired"`, a
  value the spec does not define.
- Four PS paths rethrew `mission_terminated` through the generic problem
  writer, so the body had no `mission_status` at all.
- The agent did not read `termination_reason` (AG-34).

Changes:

- `GovernanceEndpoints.MissionTerminated(string? terminationReason)` and
  `MissionTerminatedBody(...)` always emit `mission_status: terminated`, and
  add `termination_reason` when one is given. The parameter was renamed from
  `missionStatus`, a public signature change recorded in the API map.
- `GovernanceEndpoints.Authorize` reports `expired` for a mission past
  `expires_at`.
- The PS's local `ExchangeFailure` routes every `mission_terminated` through
  `GovernanceEndpoints.MissionTerminated`. A mission found expired throws with
  `expired`.
- `AAuthMissionTerminatedException.TerminationReason` is new, and
  `DeferredExchange` and `ClarificationExchange` populate it.
- `docs/advanced/error-handling.md` shows the property, and the docs inventory
  was refreshed.

PS-90 is only partly selected: `IMissionStore` records no reason, so the SDK
reports `expired` and omits the others.

Evidence:

- `Mission_Terminated_Rejected`: all four cases assert `mission_status` and
  the reason.
- `MissionAuthorization_RejectsInvalidContext` asserts the terminated and
  expired bodies on the governance endpoints.
- `MissionTerminatedBody_MatchesSpec` covers the body builder.
- `MissionTerminated_OnTokenRequest_Throws` and
  `MissionTerminated_DuringPolling_Throws` assert `TerminationReason`.

With the PS source changes stashed, all four `Mission_Terminated_Rejected`
cases fail.

### [2026-09-29] [Phase 7] Withdrawn resource tokens (PS-112, AS-42)

P2753 (#token-revocation) says a PS or AS that receives a resource-token
revocation MUST NOT issue an auth token against that token. It rejects a
request naming it with `revoked_resource_token`, and SHOULD end a pending
request with polling `revoked`. Before this fix, the revocation endpoints
recorded `(resource, jti)`, but neither token endpoint ever consulted it. The
resource token is deliberately not a grant source, because it must not cap the
auth token (`ResourceTokenLifetime_DoesNotCapAuthTokenOrGrant`), so the
existing source check never covered it.

Changes:

- **Request time:** the PS `VerifyPairAsync` and the AS resource-token step
  check `IJtiStore.IsRevokedAsync(iss, jti)` and fail with the resource
  credential, so the response is `400 revoked_resource_token` before policy
  runs.
- **Pending requests:** both pending-poll handlers check the same key first.
  The AS reads it from the retained `ResourceContext`. A hit is
  `403 revoked`, with the detail "The resource token was revoked.", and the PS
  cancels any federation.

Evidence:

- `RevokedResourceToken_RejectedAndEndsPending` covers the PS, immediate and
  pending.
- `AsRefusesWithdrawnResourceToken` covers the AS, immediate and pending. The
  resource revokes through the AS's real `/revoke` endpoint, signed as the
  resource, which also exercises RS-62.

All four cases fail with the source changes stashed.

A first version registered an `IJtiStore` in the AS fixture's DI. That turned
on request replay detection for the whole fixture and broke two clarification
tests that repeat identical signed POSTs, so the test now revokes over HTTP
instead.

Gates: Release build 0 warnings; AAuth.Tests 1678, Conformance 1254, R3 327,
Events 80; ApiSurface rewritten (0 unmapped); docs inventory refreshed; snippet
and link tests 108.

### [2026-09-29] [Phase 9] High-stakes findings reproduced at their controlling code

Research rates 15 findings P1. Thirteen have an R (reproduced) source
assessment; F15 and F20 are D (derived). Each R finding was checked by
mutation on a clean tree: disable the controlling check with a temporary edit,
build, run the discriminating test, then restore with `git checkout -- src`.
Every targeted test failed under its mutation:

| F | Controlling check disabled | Test that failed |
|---|---|---|
| F02 | `TokenVerifier`: person token carrying `scope`/`account` | `RawMalformedValuesHaveTypedErrorsWithoutTrustedContext` (both person cases) |
| F03 | `AAuthChallengeMiddleware`: agent token answered with `requirement=person-token` | `ChallengesAgentTokenWithPersonTokenRequirement` |
| F04 | `TokenVerifier.VerifyPresentedTokenAsync`: `presented_jti` match | `TokenRequest_MismatchedPresentedToken_Rejected` (`other-person-token`) |
| F06 | `AAuthVerificationMiddleware`: person-token issuer trust separate from auth-token trust | `PersonTokenIssuerTrustIsIndependent` (PS trusted for person tokens only; separate run) |
| F08 | PS mission review: prior consent must postdate the latest update | `AcceptedUpdate_ReachesConsentAndResetsFastPath` |
| F09 | `InMemoryMissionStore.SetStateAsync`: terminal state is final | `MissionStore_TerminatedIsFinal` |
| F10 | PS `TryReadAgentAsserted`: agent-asserted content reaches consent | `AgentAssertedContent_ReachesAsserterApartFromResourceContext` (both paths; separate run) |
| F11 | `AgentIssuanceContext` and PS: sub-agent cannot request directly | `SubAgent_DirectRequest_Rejected` |
| F12 | PS: auth-token ceiling includes mission `expires_at` | `AuthToken_IsCappedByMissionExpiry` (immediate and deferred) |
| F13 | PS verification: `RequireBodyCoverage` | `PsBody_UncoveredOrTampered_FailsBeforeAsserter` (both uncovered paths) |
| F14 | `InMemoryJtiStore.RevokeAsync`: record unseen tokens | `UnseenRevocation_IsRetainedUntilItsExpiryPlusRetention` |
| F17 | `AAuthSingleUseGrants.ExecuteOnceAsync`: retain the result | `SingleUseGrant_ExecutesOncePerJti` |
| F19 | `R3DocumentEndpoint`: entitlement check | `PersonServerEvaluator_ReadsOnlyDocumentsItIsEntitledTo` |

F15 was reproduced earlier in this session: with the withdrawn-resource-token
fix stashed, all four cases failed. The main batch of mutations was built
once, and its targets ran together (14 Conformance, 29 AAuth.Tests, 1 R3), so
a failure could come from a neighbouring mutation. Each failing test's display
name matches its own mutation, which rules this out. The restored tree builds
with 0 warnings.

**API map (Phase 9).** `tools/ApiSurface` reports 153 changed public-source
files, +300/-145 declarations and 0 unmapped files. It writes only
`2026-09-11-aauth-v11-spec-migration/api-surface-map.md`, the default
`--map`. The draft-10 plan folder changed only through `74f8d7e`, a
repository-wide Markdown frontmatter change merged from `main`, and
`e1e85c0`, which re-pinned 8 links to removed files to tag `v0.10.0-alpha.1`
so the record stays readable. Its content is otherwise untouched.

### [2026-09-29] [Phase 10] Old wire and API name sweep

Swept `README.md`, `docs/`, `samples/`, `src/` and `tests/e2e` for the map's
pattern list, case-insensitively and by both wire and .NET names. The terms
were `token_endpoint` (word-bounded), `aauth-access-token`, `AAuth-Mission`,
`MissionHeader*`, `MissionAware`, `mission_aware`, `MissionClaim`, `ActChain`,
`act.agent`, `"act"`, `r3_conditional`, `openapi-gateway`, `unknown_token`,
`TrustedPersonServers`, `PresentedTokenId`, `login_endpoint`,
`person_token_jti`, `DirectAs`, `approver` mission references, R3
`Conditional` and `{iss, jti}` revocation bodies.

Stale live guidance found and fixed:

- **MissionAgent** (`README.md`, `Program.cs`): the step list and sequence
  diagram showed the agent sending an `AAuth-Mission` header and an
  `Authorization:` auth token. They now show a person token carrying
  `mission_s256` and an auth token in `Signature-Key`.
- **MissionAgent runtime bug:** the console printed `first?["mission"]`, but
  Trips returns `mission_s256`, so the "echoed mission" line was always empty.
  It now reads `mission_s256`, and the comments no longer describe an
  `{approver, s256}` claim.
- **Trips** (`README.md`, `Program.cs`): mission-aware prose referred to the
  `AAuth-Mission` header and a mission object.
- **MockPersonServer** (`README.md`, `Program.cs`): the mission endpoint was
  described as returning an `AAuth-Mission` header. It now describes the
  approval response (`mission`, `s256`, `person_tokens`).
- **SampleApp** `CallChain.razor`: the note described the draft-10
  "no mission, `iss` is a PS" routing and `AAuth-Mission` forwarding. It now
  says requests route to the PS the upstream token names, even when an AS
  issued it, and that `mission_s256` travels on.
- **Concierge** `README.md`: the flow and sample response showed a nested
  `act` chain. They now show the person-token-with-`upstream_token` leg and the
  actual response shape (`chain`, `upstream`, `concierge`, `downstream`).

Kept, with reasons:

- `TrustedPersonServers` is a current R3 and Access Server option.
- "no act chain" appears in comments that assert the absence.
- `Conditional` appears only as a requirement-level column value.
- `wallet-protocol.md` explicitly says draft-11 has no direct agent-to-AS
  path.

The docs inventory was regenerated: 174 files, 662 blocks. `CheckSnippet`
fails `Documentation_FrozenSurface` for any block it cannot classify, so every
block carries a validation class. Snippet and link tests: 108 pass.

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