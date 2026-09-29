---
description: Proposed phased SDK, API, sample and docs migration to published AAuth draft-11.
---

# Implementation plan - AAuth draft-11

Created 2026-09-11 against the draft-11 WIP; retargeted 2026-09 to the published
draft. Companion to [research.md](research.md), based on SDK
`94576a3ebcba8cd1d167923e50c8796132057600`. Implementation was authorized on
2026-09-28 and is in progress on `wip/aauth-draft-11`; decisions and evidence
are in [implementation-log.md](implementation-log.md). A box is ticked only when
a named, passing test or gate backs it. The SDK and both apps now run the
draft-11 identity model, exchange and revocation contracts. The open boxes, and
the post-cutover items added to Phases 3 and 5-10, are what remains before
[closing out the plan](#closing-out-the-plan).

## Target pins

| Artifact | Pin | Local copy |
|---|---|---|
| Protocol, Bootstrap, R3, Events, Budgets, interop profile | AAuth tag `draft-hardt-oauth-aauth-protocol-11`, commit `178e9e6`, 2026-09-25 | [aauth-spec/v11/](../../../aauth-spec/v11/) |
| HTTP Signature Keys | `draft-hardt-httpbis-signature-key-09`, 2026-09-13 | [signature-key-09.txt](../../../aauth-spec/v11/draft-hardt-httpbis-signature-key-09.txt) |
| Per-role upgrade checklists | AAuth commit `180bc95` (committed after the tag) | [upgrade-10-to-11/](../../../aauth-spec/v11/upgrade-10-to-11/README.md) |

R3, Events and Budgets are editor's copies at the tag, not Datatracker
revisions. `origin/main` has moved to `f44587f` (`v0.10.0-alpha.1`), which adds
README, Markdown-guidance and live-interop test changes after `94576a3`. Rebase
this branch before Phase 1 and re-run the baseline there.

## Upstream rulings

[AAuth PR #162](https://github.com/dickhardt/AAuth/pull/162) answered the 18
upstream questions, and the published text settles most research questions.
Lines below are verified against [the published protocol](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md)
unless another file is named. Phase 0 still records each ruling in the log.

| Q | Status | Governing text | Plan effect |
|---|---|---|---|
| Q1 | Resolved by spec | Signature Keys -09 defines [`revoked_jwt`](../../../aauth-spec/v11/draft-hardt-httpbis-signature-key-09.txt#L2102) and [`clock_skew`](../../../aauth-spec/v11/draft-hardt-httpbis-signature-key-09.txt#L2133) | Phase 1 uses registered codes; no provisional extension |
| Q2 | Resolved by spec | Resource token only after a person or auth token (#requirement-auth-token, [L639](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L639)); authorization endpoint needs a person token (#authorization-endpoint-request, [L667](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L667)) | Phase 4 accepts either at challenge, person only at authorization endpoint |
| Q3 | Resolved by spec | Upstream `aud` MUST equal the intermediary's agent-token `iss` (#upstream-token-verification, [L1834](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1834)); intermediary is its own AP (#intermediary-agent-identity, [L1864](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1864)) | Phase 6 |
| Q4 | Resolved by spec; consent-cache design is SDK | PS resolves the person from its own record for upstream `aud` and `sub`, rejects without one, copies upstream `mission_s256`; intermediary sends none (#person-token-endpoint, [L842](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L842)) | Phase 6 |
| Q5 | Resolved by spec | Ticket bound to the JWK thumbprint of the `cnf` key, not an agent identifier; subscribe `sub` does not bind it (Events #pre-authorized-subscription-url-security, [L603](../../../aauth-spec/v11/draft-hardt-aauth-events.md#L603); #protected-subscriptions, [L306](../../../aauth-spec/v11/draft-hardt-aauth-events.md#L306)) | Phases 4 and 8 unblocked |
| Q6 | SDK decision | Optional capabilities and checklist items | Phase 0 selection |
| Q7 | Resolved by spec | Future `iat` refusal is optional (60 s window, `clock_skew`); `exp - iat` MUST NOT exceed 1 h for person/auth tokens, SHOULD NOT exceed agent/resource recommendations (#common-verification, [L2320](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2320)); five-minute refresh margin is SHOULD (#refresh-margin, [L1301](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1301)) | Phases 2 and 5 |
| Q8 | Resolved by spec; storage design is SDK | Retain the invocation result keyed by auth-token `jti` until its `exp` (#deferred-auth-token, [L661](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L661)); retained-result flows are the `410` exception (#pending-url-security, [L2840](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2840)) | Phases 5 and 8 |
| Q9 | Resolved by spec; delivery design is SDK | Record first, `200` only when every downstream is terminal, AS `downstream` array, `202` polled by the same identity (#token-revocation, [L2703](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2703), [L2710](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2710), [L2730](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2730)); records and chain walking (#revocation-cascade, [L2758](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2758)) | Phase 7 |
| Q10 | Resolved by spec; full Budgets stays separate | Metered execution is not release-gated (R3 #release-gating, [L719](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L719)); refusals do not draw down and carry `required`, not `cost` (Budgets #exhaustion, [L712](../../../aauth-spec/v11/draft-hardt-aauth-budgets.md#L712)) | Phase 8, out-of-scope table |
| Q11 | Resolved by spec | `sub` is never a requested claim (#requirement-claims, [L1680](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1680)) | Phase 4 |
| Q12 | SDK decision | Persistence and public API migration | Phase 0 |
| Q13 | Resolved by spec | `updated_request` REQUIRES `presented_token`; the pair is verified and must keep `iss`, `ps`, `sub`, `agent_jkt`, `mission_s256`, `tenant` (#updated-request, [L1117](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1117)) | Phase 4 unblocked |
| Q14 | Resolved by spec | Revoked auth token: SHOULD add `requirement=person-token`, MUST NOT offer `requirement=auth-token` (#revocation-cascade, [L2764](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2764)) | Phases 5 and 7 |

New published requirements not in the WIP research are assigned below. They
include the person-token lifetime ceilings (#person-token-structure,
[L863](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L863)), person
tokens as `upstream_token` (#call-chaining,
[L1850](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1850)), the
sub-agent issuer rule (#sub-agent-identity,
[L1894](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1894)),
uppercase agent-identifier local parts (#agent-identifiers,
[L488](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L488)) and
Ed25519 for every party (#signature-algorithms,
[L2166](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2166)).

## Guiding principles

- Spec conformance over backward compatibility: one coordinated alpha wire/API
  cutover, no legacy aliases or dual-format parsers. Intermediate scaffolding
  must not be advertised as completed v11 support.
- Requirement strength matters. Optional capabilities and checklist items get
  recorded selections; unsupported behavior cannot be advertised as enforced.
- The per-role upgrade checklists are an index into the spec, not a substitute
  for it. Each checklist ID maps to one owning phase; the cited section governs.
- Parsed claims, proof of a key, verified issuer identity, and person/mission
  authority remain distinct. Convenience APIs never manufacture verified context.
- Preserve exact-byte hashing, scope/account checks, source-expiry bounds, egress
  admission, typed errors, cancellation/disposal and replay protections.
- Every contract phase updates its compiled callers and coupled fixtures to keep
  the solution buildable. Both primary apps' executable steps, snippets and
  payload selectors move in the owning phase, not only in the final docs sweep.
  This includes API-dependent Markdown fences, reference tables and inventory
  expectations enforced by existing snippet tests. Do not suppress those gates
  until Phase 10; that phase reconciles remaining content and finished scenarios.
- Each selected user-facing capability has a runnable scenario and browser tests
  in both apps per [capability-scenarios.md](capability-scenarios.md). Reuse current
  focused resources and shared support; do not add a server per test variation.
- Token lifetime bounds, revocation edges, invocation consumption and retained
  results are separate concepts even when existing stores combine them.
- Reuse existing libraries and ownership conventions. No package upgrade,
  destructive state reset, merge, deployment or package publication is implied.
  Persistent schema changes require explicit migration or isolated new sample
  storage without deleting user data.

## Verification strategy

Each phase starts with the narrow discriminating regression in
[conformance-ledger.md](conformance-ledger.md), then preserves positive/security
behavior. Use independent JWTs and captured HTTP where mutually consistent
fixtures could hide a wire break. Retain exact verified source expiry through
deferred operations. At shared contract boundaries run whole affected test
projects and the solution build. Fix local failures before expanding scope.

Future implementation gates, not executed during research:

```bash
make build
make test-unit
make test-conformance
dotnet test tests/AAuth.R3.Tests/AAuth.R3.Tests.csproj
make test-events
dotnet build AAuth.slnx -c Release
dotnet test AAuth.slnx -c Release --no-build
npm --prefix tests/e2e run typecheck
```

[CI](../../../.github/workflows/ci.yml) uses .NET 10 Release solution tests,
explicit Events tests, Node 20 and Chromium. Run both configured e2e projects
with fresh services and zero retries, separately for stub and live Keycloak.
Use the selectors in [Playwright configuration](../../../tests/e2e/playwright.config.ts),
not an assumed default policy mode. Record exact commands, environment, failures,
skips and reruns. External whoami/mission/worker interop requires compatible
deployed drafts and reachable HTTPS metadata/JWKS; unavailable is not passed.

## Phase 0 - decisions and baseline gate

Dependencies: none. Findings: all. Phase rule: exact published draft-11
semantics, no compatibility shims or silent trust-boundary interpretations.

### Responsibilities

- Obtain SDK implementation authorization and record Q1-Q14 in the append-only
  implementation log, using the [upstream rulings](#upstream-rulings). Twelve are
  resolved by spec; Q6 and Q12 are SDK decisions. Defaults are proposals.
- Rebase onto current `origin/main`, then verify the worktree and all
  [target pins](#target-pins). Preserve the WIP snapshot at `e6d18a3` and this
  folder's history; do not rewrite earlier plans.
- Re-derive every `v11` line citation in [research.md](research.md),
  [conformance-ledger.md](conformance-ledger.md) and the maps against the
  published text. WIP lines are not valid published citations. Re-check F01-F24
  and the ledger for WIP-only statements the published text changed.
- Map every upgrade-checklist ID (55 PS, 33 RS, 30 AG, 7 AP, 22 AS) to one
  owning phase in the ledger. Gaps found in the mapping review are assigned in
  the phases below.
- Select optional checklist items explicitly: PS-05, RS-04 and AP-06 algorithm
  advertisement; RS-04 and AG-03 `aauth-resource` links; RS-13 person-token
  access mode; RS-35 `login_hint`; RS-36 `202` auth-token delivery; RS-62
  resource-initiated revocation; PS-87 to PS-90, AG-35 and AG-36 mission
  update/resources/expiry/reasons; PS-96 out-of-band interaction.
- Confirm core person/exchange/mission/revocation migration, existing R3/Events,
  compiled callers and both apps.
- Default full Budgets, hosted child provisioning, supervision/control plane and
  delayed artifacts to separate work. Default result-release execution disabled
  with explicit unsupported handling unless its full scenario is selected.
- Record baseline tests/browser availability, persistent schema strategy and key
  custody. No previous migration's counts substitute for this baseline.

### Definition of Done

- [x] Every Q1-Q14 has a recorded ruling in the implementation log.
- [x] Implementation authorization, scope and affected-capability blocks are explicit.
- [x] Rebased baseline tree, pins, environment and failures are recorded.
- [ ] Research, ledger and map citations resolve to published draft-11 lines.
- [ ] Every F01-F24 has an owner, phase and discriminatory check.
- [ ] Every upgrade-checklist ID has an owning phase or a recorded optional exclusion.

## Phase 1 - tooling and isolated vocabulary contracts

Dependencies: Phase 0. Findings: F05/F13/F16/F18/F24.
Phase rule: one final vocabulary; no historical-map rewrites or OIDC renames.

### Responsibilities and files

- Parameterize [ApiSurface](../../../tools/ApiSurface/Program.cs) destination and
  baseline; retarget [snippet tests](../../../tests/AAuth.Tests/Api/SnippetCompilationTests.cs)
  without overwriting the v10 maps. Replace the jti-implies-iss heuristic with
  explicit HTTP example classification.
- Introduce endpoint/mode/error vocabulary in
  [constants](../../../src/AAuth/AAuthConstants.cs),
  [metadata](../../../src/AAuth/Discovery/ServerMetadata.cs),
  [well-known endpoints](../../../src/AAuth/Server/Metadata/WellKnownEndpoints.cs)
  and [errors](../../../src/AAuth/Errors/). Coordinate renamed producers/consumers
  and compiled samples; new person-endpoint publication completes in Phase 2.
- If selected, derive advertised algorithms from actual accepted policy. Preserve
  generic signing carriers and server identity. Inventory R3 rename/removal
  callers before Phase 8; keep raw-byte hash regressions.
- Accept `A-Z` in the agent-identifier `local` part and compare exactly, with
  no case folding (#agent-identifiers, PS-104, RS-52, AP-01).
  [AgentId](../../../src/AAuth/Identifiers/AgentId.cs) rejects uppercase today;
  the domain stays lowercase.
- Prove Ed25519 acceptance on every verifier role: PS, AS, resource, AP and
  agent (#signature-algorithms, PS-100, RS-50, AG-52, AP-05, AS-30). The shared
  middleware already lists it; add role-level tests, not new algorithm code.
- Add the published error codes as typed values: `expired_presented_token`,
  `revoked_presented_token`, `revoked_resource_token`, `as_unreachable`,
  `invalid_`/`expired_`/`revoked_upstream_token`, `invalid_subagent_token`,
  `revoked_subagent_token`, `invalid_account`, `user_unreachable`,
  `rate_limited`, polling `revoked`
  (`403` with `detail`) and the revocation outcomes `revocation_unavailable`
  and `revocation_unsupported`. Use Signature Keys -09 `revoked_jwt` and
  `clock_skew` for header tokens (Q1).

### Definition of Done

- [x] Inventory targets this folder/baseline without modifying historical evidence.
- [x] Renamed metadata/modes have no active old-field aliases in migrated paths.
- [x] New error types preserve header/body/status distinctions.
- [x] Uppercase local parts round-trip exactly; case variants are distinct identities.
- [x] Ed25519 is accepted at every verifier role.
- [x] Focused metadata/error/snippet tests and compiled callers/build pass.

## Phase 2 - person tokens and temporal trust

Dependencies: Phase 1. Findings: F02/F05/F12.
Phase rule: typed person verification, never person-to-auth fallback.

### Responsibilities and files

- Extend [token types](../../../src/AAuth/AAuthTokenType.cs),
  [TokenVerifier](../../../src/AAuth/Tokens/TokenVerifier.cs),
  [resolver](../../../src/AAuth/HttpSig/DefaultSignatureKeyResolver.cs) and
  middleware with person-token builder/verifier and verified issuance inputs.
- Add PS person endpoint/client/result using existing consent, clocks, egress,
  keys and transport. Direct no-mission issuance comes first; mission approval
  integration follows in Phase 3. Record issuance destinations for revocation,
  not as a required lookup during token verification.
- Separate strict AAuth expiry, optional future iat and generic naming-token
  time policy. Keep fully specified algorithms and existing lifetime checks.
  Enforce `exp - iat` at most 1 h for person and auth tokens, and treat agent
  and resource lifetimes as SHOULD bounds (Q7, #common-verification).
- Cap person-token `exp` at 1 h and at the presented agent token, the
  `upstream_token` when present, and the mission `expires_at` when
  `mission_s256` is present (#person-token-structure, L863).
- Accept the person-token request's optional parameters with the auth-request
  definitions: `capabilities`, `login_hint`, `tenant`, `domain_hint`, `prompt`,
  `justification`, `platform`, `device` (#person-token-endpoint, PS-10). The
  agent sends `capabilities`; without it a PS that must reach the person answers
  `user_unreachable` (AG-10).
- Agents read `person_token_endpoint` from PS metadata rather than deriving it
  (AG-01). Reject `aa-person+jwt` wherever an auth token is required
  (#person-token-verification, L920).
- Publish the required person/auth endpoint metadata and minimal PS contract.

### Definition of Done

- [x] Person typ/claims/DWK/issuer/audience/key and forbidden scope/account cases pass.
- [x] Person tokens cannot satisfy auth-only authorization.
- [x] Person-token lifetime is capped by 1 h, agent, upstream and mission expiry.
- [x] `capabilities` and `login_hint` reach the person-token decision.
- [x] Immediate/deferred issuance retains exact verified source expiry.
- [x] Header/body expiry and optional future iat boundaries have separate tests.
- [x] Metadata, compiled callers, focused tests and solution build pass.

## Phase 3 - mission envelopes and lifecycle storage

Dependencies: Phase 2. Findings: F07-F09; mission portions of F02/F12.
Phase rule: exact blob bytes and mission_s256, no legacy header compatibility.

### Responsibilities and files

- Change [Mission](../../../src/AAuth/Agent/Mission.cs),
  [MissionClient](../../../src/AAuth/Agent/Governance/MissionClient.cs),
  [governance mapper](../../../src/AAuth/DependencyInjection/AAuthGovernanceApplicationBuilderExtensions.cs)
  and custom [sample PS](../../../samples/MockPersonServer/Program.cs) approval
  into encoded-blob envelopes with separate capabilities and person-token maps.
  Retain RawBytes/Blob and hash decoded bytes, not envelope serialization.
- Extend proposal/approval contexts with resources, verified key/source expiry,
  approved resources and optional mission expiry; carry them through delayed
  consent without inventing a new expiry or trusting an unverified key.
- Add accepted-update bytes/digest and policy-visible history to
  [IMissionLog](../../../src/AAuth/Server/Governance/IMissionLog.cs). Make
  [mission storage](../../../src/AAuth/Server/Governance/InMemoryMissionStore.cs)
  terminal transitions atomic, including save/replacement paths.
- Update coupled mission sessions/tests and executable consumers. Phase 4
  completes token-claim integration; intermediate flows are not v11 conformance.
- Agents parse the new approval response: the base64url `mission` blob,
  `capabilities` outside the blob and the `person_tokens` resource map. Verify
  `mission_s256` over the decoded blob bytes before first use (AG-32). Stop
  sending `AAuth-Mission` and drop it from covered components; name the
  mission with `mission_s256` on person-token requests (AG-30).
- Keep the approver's `expires_at` on deferred mission approval. The
  `MissionCreation` pending path currently completes without it, so a mission
  approved after `202` never expires (post-cutover item 8).
- Make [MockPersonServer](../../../samples/MockPersonServer/Program.cs)'s own
  `/mission` handler issue `person_tokens` through `IMissionPersonTokenIssuer`,
  and have one sample mission proposal name `resources`, so the demos show the
  approval map (#mission-approval; post-cutover item 10).

### Definition of Done

- [x] Envelope formatting does not affect digest; modified blob bytes fail.
- [x] Capabilities are outside the hash and partial resource approvals work.
- [x] Expiry and terminal-state invariants survive store mutation/races.
- [x] Accepted updates have retained exact bytes without changing mission identity.
- [x] Agents reject an approval whose blob bytes do not match `mission_s256`.
- [x] Compiled callers and focused governance/build checks pass.
- [x] Approval issues `person_tokens` for asserted resources, omits the rest, and tracks each as an agent-token grant.
- [x] A deferred mission approval keeps the approver's `expires_at`.
- [x] MockPersonServer approvals carry `person_tokens`, and both apps show a proposal that names `resources`.

## Phase 4 - resource and exchange cutover

Dependencies: Phases 2-3. Q2, Q5, Q11 and Q13 are resolved by spec.
Findings: F01/F03/F04/F06/F07/F10/F12/F13/F16/F19/F20.
Phase rule: resource/auth identity is ps/sub/key based; no agent/act/mission fallback.

### Responsibilities and files

- Cut over [ResourceTokenBuilder](../../../src/AAuth/Tokens/ResourceTokenBuilder.cs),
  [AuthTokenBuilder](../../../src/AAuth/Tokens/AuthTokenBuilder.cs), validators,
  verified results and authn/authz projection together. Preserve agent identity
  on agent-token paths, never synthesize it from a person subject.
- Require person identity at authorization/initial challenges and accept a
  person or auth token before resource-token issuance (Q2). Add exact required
  presented-token carriage to [agent exchange](../../../src/AAuth/Agent/TokenExchangeClient.cs)
  and [PS-AS exchange](../../../src/AAuth/Access/AccessServerClient.cs). The AS
  body is `resource_token`, `agent_token`, `presented_token` and optional
  `subagent_token` and `upstream_token`; `agent_token` stays required for
  posture and is the parent's for a sub-agent (AS-11).
- Carry `login_hint` end to end: a resource MAY set it in the resource token,
  the agent passes it unchanged and the PS passes it through (RS-35, AG-24,
  PS-33). Resources check the auth token rather than assuming it was honored.
- Apply paired-token verification to core PS/AS, R3 AS and custom issuers before
  policy or pending-state mutation. Bind PS/subject/tenant/mission/key/account;
  claims or policy cannot replace verified person identity.
- Update `ClarificationResponse.Update` and PS/AS pending replacement handlers
  per Q13: `updated_request` carries the required `presented_token`, the pair is
  verified, and `iss`, `ps`, `sub`, `agent_jkt`, `mission_s256` and `tenant`
  must match. Verify and replace both tokens atomically; retain prior state on
  failure.
- Separate agent-asserted consent content (justification, platform, device) from
  resource-asserted content (metadata, R3 display) in consent UI and hooks, with
  visible attribution (PS-40).
- Remove AAuth-Mission and MissionAware-dependent propagation, including
  forwarding/covered-component configuration. Enforce agent/presented/mission
  ceilings through immediate and deferred issuance.
- Require body content-type/digest coverage on PS/AS initial and pending calls,
  including governance and R3. Preserve AS terminal status/error while mapping
  unavailable/unverifiable results separately from local cancellation.
- Migrate all compiled custom resources and fixtures alongside shared contracts.
  Update both apps' affected executable steps, snippets and captured payloads.
  This is the highest-blast-radius phase, not a constants-only change.
- Include the minimum person acquisition/challenge support from Phase 5 and the
  protected Events ticket binding from Phase 8 at this identity boundary. Q5
  binds the ticket to the JWK thumbprint of the key the resource verified, not
  an agent identifier. Otherwise removing agent claims breaks existing clients
  and Bookings ticket issuance. Phase 5 completes cache/202/refresh behavior;
  Phase 8 completes R3/Events integration. Do not call Phase 4 green while those
  consumers fail.

### Definition of Done

- [x] Independent wire tests cover prerequisite, step-up and both exchange legs.
- [x] Substitution/stripping/identity overwrite fails independently at PS and AS.
- [x] Removed identity/mission fields are absent from active core producers/consumers.
- [x] Missing body coverage/tampering fails before policy or consent mutation.
- [x] Immediate/deferred expiry and AS error mapping tests pass.
- [x] Clarification replacement rejects a mismatched or unverified pair.
- [x] Consent views attribute agent- and resource-asserted content separately.
- [x] Affected core/R3/Events projects and solution build are green.
- [x] Minimum person-client and protected-ticket consumers work with new identity contracts.

## Phase 5 - agent caches, refresh and deferred completion

Dependencies: Phase 4. Findings: F02/F04/F05/F12/F16/F17.
Phase rule: preserve original credential provenance; no blanket unsafe replay.

### Responsibilities and files

- Extend [builder](../../../src/AAuth/AAuthClientBuilder.cs),
  [token holder](../../../src/AAuth/Agent/AAuthTokenHolder.cs),
  [ChallengeHandler](../../../src/AAuth/Agent/ChallengeHandler.cs),
  [refresh](../../../src/AAuth/Agent/TokenRefreshHandler.cs) and deferred handlers
  with resource/mission/person/worker-key/authority cache partitions.
  Build on the minimum person acquisition/challenge path required in Phase 4;
  this is not the first working client for the already-migrated resource contract.
- Keep PS/AP agent signing separate from resource carriers. Refresh top-down,
  re-acquire lazily after rotation, coalesce concurrency and preserve borrowed
  versus factory-owned key/transport/store/clock disposal and cancellation.
- Add person challenge and 202 auth exchange followed by signed GET completion,
  never original-body resubmission. Agents MUST support both `401` and `202`
  delivery of `requirement=auth-token`; which one a resource uses is its choice
  per invocation (#requirement-auth-token). If RS-36 is selected, document the
  sample resources' policy for choosing `202`.
- Retain the held invocation's result keyed by auth-token `jti` until that
  token's `exp`, and answer a repeated presentation from it (Q8). Define atomic
  held-invocation/results with Phase 8 R3 consumers in mind.
- Distinguish skew, revocation, denial, remote unavailability and cancellation
  recovery. Handle `expired_presented_token`, `revoked_resource_token`,
  `as_unreachable` and polling `revoked` (`403`), surfacing `detail` (AG-60 to
  AG-62). A revoked auth token recovers through a fresh person token, never a
  resource token naming the revoked one (Q14). Refresh within the SHOULD
  five-minute margin, top-down; resource tokens are exempt (Q7, AG-70).
- Add selected link discovery only with URL checks before fetching
  and no verifier-key-discovery coupling.
- Reuse a matching `Mission.PersonTokens` entry (same resource and
  `mission_s256`, unexpired, bound to the signing key) before calling
  `person_token_endpoint`, from `ChallengeHandler` and `MissionSession`. That is
  the purpose of the approval map (#mission-approval). Update both apps' mission
  step plans and `PLAN_STEPS` if the `/person` step disappears (post-cutover
  item 11).
- Move the [MockAgentProvider](../../../samples/MockAgentProvider/Program.cs)
  refresh endpoint to the shared verifier, so a missing or unverifiable
  signature is `401` with `Signature-Error`, not a `400 invalid_request` body
  (#error-responses; post-cutover item 4).
- Deliver S01-S04/S13 in both hosts with actual wire captures.

### Definition of Done

- [ ] Concurrent people/missions/accounts/worker keys cannot share authorization state.
- [ ] Exact presented token survives holder refresh and clarification/replacement.
- [ ] 202 completion never resends the original non-idempotent request body.
- [ ] A repeated auth token at the pending URL returns the retained result.
- [ ] Each published token-endpoint and polling error has a distinct agent outcome.
- [ ] Refresh order, ownership, cancellation and recovery tests pass.
- [x] Both primary apps exercise person and deferred flows with matching steps.
- [x] Agents reuse an approved mission person token instead of calling `/person`; mismatched resource, mission, key or expiry falls back.
- [x] MockAgentProvider refresh answers signature failures with `401` and `Signature-Error`.

## Phase 6 - supervision, mission actions and delegation

Dependencies: Phase 5. Q3 and Q4 are resolved by spec. Findings: F08-F11/F23.
Phase rule: no act-derived authority or direct-AS agent routing; explicit trust rulings.

### Responsibilities and files

- Move completion to mission URL actions; implement update consent/follow-up and
  policy-visible accepted history in prior-consent paths. Enforce owner/expiry
  uniformly on new and resumed PS decisions.
- Extend existing consent/claims hooks with assertion provenance and accumulated
  mission context. Update authenticated sample consent; keep OIDC prompt and
  justification distinct. Do not invent a Supervision server protocol.
- Update [router](../../../src/AAuth/Server/CallChaining/CallChainingRouter.cs),
  [upstream validation](../../../src/AAuth/Tokens/UpstreamTokenValidator.cs),
  [Concierge](../../../samples/Concierge/) and
  [worker scenario](../../../samples/FederatedWorkerScenario.cs) for PS routing,
  parent-issued person token handoff and explicit delegated-person/mission proof.
- Derive downstream subjects from authenticated context, rejecting unresolved
  persons. Retain parent/worker checks and source bounds. Remove obsolete ActChain
  APIs only after their consumers use PS/AS evidence instead.
- Upstream tokens (Q3, Q4, #upstream-token-verification): accept a person or
  auth token by `typ`; require `aud` equal to the intermediary's agent-token
  `iss`, so each intermediary is its own AP. The PS resolves the person from its
  own record for that `aud` and `sub`, copies the upstream `mission_s256`, and
  caps downstream expiry at the upstream token. Never copy a directed `sub` from
  an upstream token (#call-chaining).
- Sub-agents (#sub-agent-identity): the AP issues under the parent's `iss` with
  a `parent+discriminator` local part (AP-02). The PS rejects a different `iss`
  with `invalid_subagent_token` (PS-71). Auth tokens bind to the sub-agent key,
  and the AS records the parent from `agent_token`, not `act` (AS-12, AS-13).
  The AS verifies `upstream_token` too (AS-14).
- Upstream Token Verification step 4 (L1835): the agent-token half is enforced
  through the PS token graph and tested. Add the person-binding half: a PS
  seam (for example an `IIdentityClaimsAsserter` outcome or an agent-person
  binding store) through which the host reports a revoked binding, answered
  `revoked_upstream_token` (L2593; post-cutover item 3).
- Deliver S05-S07 in both apps, with MissionAgent and AgentConsole aligned.

### Definition of Done

- [ ] Actions enforce owner, expiry and irreversible termination across continuations.
- [ ] Updated mission meaning reaches fast-path consent and audit.
- [ ] Distinct caller/intermediary/worker-key cases validate Q3/Q4 rulings.
- [ ] Upstream `aud` mismatch, foreign-AP intermediaries and copied `sub` fail.
- [ ] Sub-agent `iss` mismatch fails with `invalid_subagent_token`.
- [ ] Direct-worker and wrong-parent PS requests fail.
- [x] Both apps' sequences and payload assertions use PS-recorded delegation.
- [x] An upstream token issued from a revoked calling agent's agent token is `revoked_upstream_token`.
- [x] A host-revoked agent-person binding makes the upstream token `revoked_upstream_token`.

## Phase 7 - revocation authority and dependency graph

Dependencies: Phase 6. Q9 and Q14 are resolved by spec. Findings: F14-F16.
Phase rule: caller's namespace only; no old issuer override or unknown-token 404.

### Responsibilities and files

- Cut over [RevocationClient](../../../src/AAuth/Server/RevocationClient.cs),
  [endpoint](../../../src/AAuth/Server/RevocationEndpoint.cs),
  [options](../../../src/AAuth/Server/AAuthRevocationOptions.cs),
  [IJtiStore](../../../src/AAuth/Server/IJtiStore.cs) and implementations.
  Authenticate server role/id before body; record unseen jti/exp atomically with
  bounded capacity, admission and retention.
- Separate revocation edges from lifetime ceilings; preserve ancestor checks
  without limiting auth grants to short resource-token expiry. Record person
  destinations, AS federation and step-up presented-token ancestry.
- Implement AP-to-PS, PS-person-to-AS/resource, AS-auth-to-resource and resource
  withdrawal. Prevent pending issuance after revocation; track retryable delivery
  separately from durable local acknowledgement.
- Response contract (#token-revocation): record first, including tokens never
  seen (PS-112), and answer `200` only when every downstream call is terminal.
  The AS reports a `downstream` array of `recipient` and optional `error`
  (`revocation_unavailable`, `revocation_unsupported`), which the PS reads
  (AS-41, PS-114). The PS answers the AP with an empty body. A slow cascade
  answers `202` with a pending URL. Only the revoking identity may poll; others
  get `404`. Without `Prefer: wait`, hold about 20 seconds. Parties with nothing
  downstream never answer `202`. Rate limiting uses `rate_limited` (`429`,
  `Retry-After` required).
- Cascade an agent-token revocation by agent identity from the PS's records,
  and walk person-token chains through the recorded upstream `(iss, jti)`
  (#revocation-cascade). A resource refusing a revoked auth token SHOULD send
  `requirement=person-token` (Q14). RS-62 resource-initiated revocation is
  selected in Phase 0.
- Update header/body/poll codes and S08 in both apps; remove Wallet/Bookings
  cross-issuer PS-revocation examples.
- Post-cutover items (the `{jti, exp}` cutover itself is done):
  - Require `content-digest` and `content-type` coverage at every revocation
    endpoint, including resource endpoints mapped behind `UseAAuth`. The spec
    MUST says "at a resource's revocation endpoint as much as a PS's or an
    AS's" (L2672). Endpoint metadata needs a required-components field (item 2).
  - Bound entries and rate per accepted issuer, answering `rate_limited` (`429`,
    `Retry-After` REQUIRED). This SHOULD applies because
    `MapAAuthIssuerRevocation` defaults to `AAuthTrust.Any` (L2745; item 5).
  - Deferred revocation: answer `202` with a pending URL when the cascade
    outlasts the hold (about 20 seconds without `Prefer: wait`). Polls must come
    from the revoking identity (others `404`), and a recipient with nothing
    downstream never answers `202`. As a caller, poll a downstream `202` rather
    than reporting `revocation_unavailable` (L2728-L2730; item 6).
  - Record every AS the PS presents each person token to, and revoke only there.
    Make the MockPersonServer `/local/wallet/revoke` route use those records
    instead of calling every configured AS (#revocation-cascade; item 9).

### Definition of Done

- [x] Valid unseen/repeated revocation returns 200 and blocks presentation.
- [x] Namespace collisions, injected issuer, forbidden roles and malformed expiry fail safely.
- [ ] Resource dependency does not impose a five-minute auth expiry.
- [ ] Registration, consent completion and revocation races are covered.
- [ ] Cascades, notification failure and retention have controlled-clock tests.
- [x] `downstream` outcomes, `202` polling identity and `rate_limited` have wire tests.
- [x] Requests are `{jti, exp}` keyed by the verified caller; body `iss` is ignored and `unsupported_iss` is enforced.
- [x] Every revocation endpoint rejects a request whose signature omits `content-digest` or `content-type`.
- [x] One accepted issuer cannot exceed its entry or rate bound without `429 rate_limited` and `Retry-After`.
- [x] The PS revokes a person token only at the Access Servers it was presented to, and the sample route uses those records.

## Phase 8 - R3 execution, Catalog and Events

Dependencies: Phase 7. Q5, Q8 and Q10 are resolved by spec; Q6 is a Phase 0
selection. Findings: F17-F22.
Phase rule: PerCall and seven standard vocabularies, no gateway/conditional aliases.

### Responsibilities and files

- Rename R3 Conditional contracts; remove document/proposal Version and OpenAPI
  Gateway APIs from [models](../../../src/AAuth.R3/Model/), schemas, metadata,
  claims and factories. Preserve byte hashes, structural equality and legitimate
  format qualifiers. On the wire (post-cutover item 1): the auth token claim
  `r3_conditional` becomes `r3_per_call`, R3 documents and proposals drop
  `version`, and the `per-call` access mode plus operation access-mode
  annotations are supported (R3 #access-mode-annotation, #operation-identifier-scope).
  Other draft-11 R3 implementations cannot interoperate until this lands.
- Redesign [Catalog](../../../samples/MockResourceServers/Catalog/) using the
  selected standard definition/resource layout, with unique operation IDs,
  discovery, shared UI/session, snippets and negative tests.
- Add atomic per-call consumption/retained results using Phase 5 contracts.
  Separate same-content proposal identity from per-grant execution; protect
  concurrency, retry, key/account binding and lost-response recovery.
- Scope R3 readership to entitled PS/AS per document and retain verified
  person/key/agent-at-AS audit evidence and persistent audit atomicity.
- Add selected annotations and result-model support. Default release execution
  disabled: result-bearing proposals reach capable policy or fail unsupported,
  never silently downgrade to ordinary execute approval.
- Resolve [BookingsEvents](../../../samples/EventSupport/BookingsEvents.cs)
  ticket binding and [Events stores](../../../src/AAuth.Events/EventStores.cs)
  per Q5: record the JWK thumbprint of the key the resource verified and match
  the subscribe token's `cnf.jwk` at redemption (done). Deduplicate event
  deliveries on `(iss, jti)`, not `eid`: the sample store still keys
  `agent_events` by `(issuer, eid)` (Events L363, L456; post-cutover item 7).
  Answer `404` for unknown or finished
  subscriptions. Complete the identity contract already migrated in Phase 4 with
  SQLite transition/redemption and per-call retained-result integration. Preserve
  public subscriptions and self-JWT semantics. Deliver S09-S12 and selected
  S14-S16 in both apps.
- Metered or billed execution is never release-gated; approval precedes it (Q10,
  R3 #release-gating). Do not claim full Budgets support without its separately
  approved plan.

### Definition of Done

- [x] No obsolete R3 names/emission; seven vocabulary and Catalog tests pass.
- [x] A draft-11 R3 fixture (`r3_per_call`, no `version`, `per-call` annotation) round-trips with its published hash.
- [ ] One grant cannot execute twice under fresh signatures; retries return retained result.
- [ ] Foreign valid PS cannot read unentitled R3 documents.
- [x] Protected Events tickets reject a different key; deliveries dedupe on `(iss, jti)`.
- [ ] Optional result/Budgets behavior cannot imply unimplemented enforcement.
- [ ] Full R3/Events tests, solution build and both-app scenarios pass.

## Phase 9 - security reconciliation and API freeze

Dependencies: Phase 8. Findings: all, especially F06/F09/F13/F20/F24.
Phase rule: report only verified checks; preserve generic and deployed-profile boundaries.

### Responsibilities

- Re-audit negatives across mappers, custom resources, replacements, pending
  issuance, R3 and Events. Recheck no-claims consent, identity/scope/account
  narrowing, reserved claims, egress/metadata, replay, revocation and mission privacy.
- Review cache/key/transport/store ownership and schema isolation. Optional
  delayed verification cannot change online acceptance. Record deployment limits.
- Generate and review exact public API delta with the retargeted tool: changed,
  removed and behavior-only members, defaults, ownership and compiled callers.
  Freeze contracts before the trailing static-content sweep.

### Definition of Done

- [ ] Ledger negatives have execution evidence or explicit conditional/deployment dispositions.
- [ ] High-stakes R findings are directly reproduced at their controlling code.
- [ ] API map has no unmapped changed public-source files; historical maps untouched.
- [x] Release/full solution, explicit R3/Events and TypeScript gates pass.

## Phase 10 - samples, snippets and docs analysis-and-update sweep

Dependencies: Phase 9 API freeze. Findings: F24 and all consumer effects.
Phase rule: current-format live guidance; preserve intentional generic/OIDC/historical content.

### Responsibilities

- Execute [docs-surface-map.md](docs-surface-map.md)'s pattern/classification
  sweep across READMEs, docs, consoles, Razor, string snippets, diagrams, JSON/HTTP
  and browser assertions. Enumerate all discovered display blocks, not only
  representative examples.
- Check completed S01-S13 and selected optional flows in both hosts: navigation,
  reset, plans, selected payloads, snippet associations, approval/poll indices,
  diagrams and completion. Missing executable flows must already be fixed in
  their owning phases.
- Validate exact C# snippets, response shapes, source/default tables, links,
  TypeScript and fresh desktop/mobile browser matrices with zero retries.
- Reconcile draft-10 to draft-11 target language only with verified supported scope.
- Rename the Wallet sample's `DirectAs` flow and its UI, snippet and spec
  labels, since it now routes through the PS (post-cutover item 12).

### Definition of Done

- [ ] Every discovered instructional block has a validation class and disposition.
- [ ] No unexplained old wire/API name remains in live guidance.
- [ ] Both apps' real traces and static instructions agree for selected flows.
- [ ] Stub/Keycloak browser results and external/unavailable limits are recorded separately.
- [x] No Wallet flow is labelled as a direct agent-to-AS exchange.

## Phase 11 - independent internal review and closure

Dependencies: Phase 10. Findings: all.
Phase rule: fresh spec-grounded review; no implicit acceptance of unresolved trust risks.

### Responsibilities

- Dispatch a fresh read-only reviewer against actual final source, pinned specs,
  research, plan and all maps. Require severity-graded evidence and cross-area
  synthesis, not matching names or inherited v10 verdicts.
- Focus on person/auth separation, presented-token proof, delegated mission
  authority, expiry versus revocation, execute-once retention and Events tickets.
  Recheck contradictory reviewer claims directly against code and spec.
- Repair accepted issues locally, rerun narrow and affected gates, refresh maps
  after public changes, and record explicit exclusions and upstream rulings.
- Reconfirm final build/test/browser evidence and target language. No package
  release or deployment occurs without separate authorization.

### Definition of Done

- [ ] No unresolved P1/P2 findings remain in claimed supported scope.
- [ ] Each finding is fixed with rerun evidence or explicitly excluded by approval.
- [ ] Q1-Q14 and subsequent ambiguities have current recorded dispositions.
- [ ] Final maps, ledger/log and release/browser evidence match the actual source.
- [ ] External limits and published-draft target language remain accurate.

## Closing out the plan

Run this once every phase's Definition of Done is ticked. AAuth issue #199
(AS verification of `agent_token`) is excluded: it stays an open upstream
question under the interim ruling in the log.

1. Implement and test the 12 post-cutover items folded into Phases 3 and
   5-10: R3 draft-11 wire names; revocation body coverage at every endpoint;
   the person-binding half of step 4; MockAgentProvider `401` Signature-Error;
   per-issuer bounds and `rate_limited`; deferred `202` revocation; event
   dedup on `(iss, jti)`; deferred-approval expiry; AS presentation records;
   MockPersonServer `person_tokens` and a `resources` proposal; agent reuse of
   `Mission.PersonTokens`; the Wallet `DirectAs` rename. Then tick the
   remaining Phase 2-11 boxes, each backed by a named test or gate recorded
   in the log. Leave no box ticked on intent alone.
2. Finish Phase 0: re-derive every `v11` citation in research, ledger and maps;
   give F01-F24 an owner and check; assign each upgrade-checklist ID or record
   its optional exclusion.
3. Run Phase 9 security reconciliation over the finished source, then the
   Phase 11 independent review. Fix or explicitly exclude each finding.
4. Final gates on a clean tree: Release build with zero warnings; all four test
   projects; ApiSurface "current"; docs inventory current; e2e typecheck; a full
   Playwright run with zero retries (stub), and Keycloak separately when
   available.
5. Append a dated closure entry to the implementation log with commit, gate
   results, exclusions and remaining upstream questions. Update this plan's
   status paragraph to "complete".
6. Push, open a PR or tag a release only with explicit authorization.

## Out of scope and conditional work

These are proposed Phase 0 dispositions, not silent removal of existing support.

| Item | Default disposition | Re-entry requirement |
|---|---|---|
| SDK edits in this research task | Out of scope | Separate implementation authorization |
| Draft-10 aliases/dual-wire support | Excluded by spec-first alpha policy | Explicit logged exception |
| Full Budgets metering/settlement | Separate initiative | Transaction/persistence model and both-app scenarios; Q10 spec rulings apply |
| Result-release execution | Disabled; explicit unsupported handling/model awareness | Q6 selection and safe S16 in both hosts |
| Optional upgrade-checklist items | Selected individually in Phase 0 | Real support and tests, not metadata-only claims |
| Annotations, link discovery, algorithm advertisement | Select small optional slices in Phase 0 | Conditional validation and real support, not metadata-only claims |
| Hosted child provisioning/native attestation | Guidance and existing regression only | Approved platform-specific design |
| Supervision/control-plane protocol | Separate companion/deployment concern | Pinned defined companion and authorized scope |
| Delayed/offline verification | Separate opt-in | Explicit time/replay/retention policy; preserve online verifier |
| X.509/cached generic carriers | Existing exclusions retained | Explicit scope and complete scheme tests |
| Production distributed persistence/delivery | Interface obligations and sample schema safety only | Approved durable backend and operational guarantees |
| External whoami/mission/worker success | Unverified until live evidence | Compatible remote draft, HTTPS/JWKS and consent |
| Package release, deployment, PR creation | Not requested | Explicit authorization; research-branch push is already authorized |