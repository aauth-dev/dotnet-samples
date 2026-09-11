---
description: Proposed phased SDK, API, sample and docs migration to pinned draft-11 WIP.
---

# Implementation plan - AAuth draft-11 WIP

Created 2026-09-11. Companion to [research.md](research.md), based on SDK
`94576a3ebcba8cd1d167923e50c8796132057600` and its recorded WIP spec pins.
SDK implementation has not been authorized or begun. All completion boxes remain
open. The SDK still targets draft-10. Git publication of this research branch
is separately authorized in [implementation-log.md](implementation-log.md).

## Guiding principles

- Spec conformance over backward compatibility: one coordinated alpha wire/API
  cutover, no legacy aliases or dual-format parsers. Intermediate scaffolding
  must not be advertised as completed v11 support.
- Requirement strength matters. Optional capabilities and WIP interpretations
  get recorded rulings; unsupported behavior cannot be advertised as enforced.
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

Dependencies: none. Findings: all. Phase rule: exact pinned WIP semantics, no
compatibility shims or silent trust-boundary interpretations.

### Responsibilities

- Obtain SDK implementation authorization and record Q1-Q14 from research in
  the append-only implementation log. Defaults are proposals, not approvals.
  Q3-Q5 gate chained/delegated authority and protected Events compatibility.
- Verify baseline/worktree and all spec pins. Re-diff any subsequently published
  revision before changing the chosen target; preserve earlier snapshots/plans.
- Confirm core person/exchange/mission/revocation migration, existing R3/Events,
  compiled callers and both apps. Select optional annotations, link discovery
  and algorithm advertisement explicitly.
- Default full Budgets, hosted child provisioning, supervision/control plane and
  delayed artifacts to separate work. Default result-release execution disabled
  with explicit unsupported handling unless its full scenario is selected.
- Record baseline tests/browser availability, persistent schema strategy and key
  custody. No previous migration's counts substitute for this baseline.

### Definition of Done

- [ ] Every Q1-Q14 has a recorded ruling in the implementation log.
- [ ] Implementation authorization, scope and affected-capability blocks are explicit.
- [ ] Baseline tree, pins, environment and failures are recorded.
- [ ] Every F01-F24 has an owner, phase and discriminatory check.

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

### Definition of Done

- [ ] Inventory targets this folder/baseline without modifying historical evidence.
- [ ] Renamed metadata/modes have no active old-field aliases in migrated paths.
- [ ] New error types preserve header/body/status distinctions.
- [ ] Focused metadata/error/snippet tests and compiled callers/build pass.

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
- Publish the required person/auth endpoint metadata and minimal PS contract.

### Definition of Done

- [ ] Person typ/claims/DWK/issuer/audience/key and forbidden scope/account cases pass.
- [ ] Person tokens cannot satisfy auth-only authorization.
- [ ] Immediate/deferred issuance retains exact verified source expiry.
- [ ] Header/body expiry and optional future iat boundaries have separate tests.
- [ ] Metadata, compiled callers, focused tests and solution build pass.

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

### Definition of Done

- [ ] Envelope formatting does not affect digest; modified blob bytes fail.
- [ ] Capabilities are outside the hash and partial resource approvals work.
- [ ] Expiry and terminal-state invariants survive store mutation/races.
- [ ] Accepted updates have retained exact bytes without changing mission identity.
- [ ] Compiled callers and focused governance/build checks pass.

## Phase 4 - resource and exchange cutover

Dependencies: Phases 2-3 and Q5/Q13. Findings: F01/F03/F04/F06/F07/F10/F12/F13/F16/F19/F20.
Phase rule: resource/auth identity is ps/sub/key based; no agent/act/mission fallback.

### Responsibilities and files

- Cut over [ResourceTokenBuilder](../../../src/AAuth/Tokens/ResourceTokenBuilder.cs),
  [AuthTokenBuilder](../../../src/AAuth/Tokens/AuthTokenBuilder.cs), validators,
  verified results and authn/authz projection together. Preserve agent identity
  on agent-token paths, never synthesize it from a person subject.
- Require person identity at authorization/initial challenges and explicit auth
  context for agreed runtime step-up. Add exact required presented-token carriage
  to [agent exchange](../../../src/AAuth/Agent/TokenExchangeClient.cs) and
  [PS-AS exchange](../../../src/AAuth/Access/AccessServerClient.cs).
- Apply paired-token verification to core PS/AS, R3 AS and custom issuers before
  policy or pending-state mutation. Bind PS/subject/tenant/mission/key/account;
  claims or policy cannot replace verified person identity.
- Update `ClarificationResponse.Update` and PS/AS pending replacement handlers
  under Q13. Preserve the original pair for unchanged requests; when jti changes,
  verify and replace both tokens atomically, retaining prior state on failure.
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
  Q5-approved protected Events ticket binding from Phase 8 at this identity
  boundary. Otherwise removing agent claims breaks existing clients and Bookings
  ticket issuance. Phase 5 completes cache/202/refresh behavior; Phase 8 completes
  R3/Events integration. Do not call Phase 4 green while those consumers fail.

### Definition of Done

- [ ] Independent wire tests cover prerequisite, step-up and both exchange legs.
- [ ] Substitution/stripping/identity overwrite fails independently at PS and AS.
- [ ] Removed identity/mission fields are absent from active core producers/consumers.
- [ ] Missing body coverage/tampering fails before policy or consent mutation.
- [ ] Immediate/deferred expiry and AS error mapping tests pass.
- [ ] Affected core/R3/Events projects and solution build are green.
- [ ] Minimum person-client and protected-ticket consumers work with new identity contracts.

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
  never original-body resubmission. Define atomic held-invocation/results with
  Phase 8 R3 consumers in mind.
- Distinguish skew, revocation, denial, remote unavailability and cancellation
  recovery. Add selected link discovery only with URL checks before fetching
  and no verifier-key-discovery coupling.
- Deliver S01-S04/S13 in both hosts with actual wire captures.

### Definition of Done

- [ ] Concurrent people/missions/accounts/worker keys cannot share authorization state.
- [ ] Exact presented token survives holder refresh and clarification/replacement.
- [ ] 202 completion never resends the original non-idempotent request body.
- [ ] Refresh order, ownership, cancellation and recovery tests pass.
- [ ] Both primary apps exercise person and deferred flows with matching steps.

## Phase 6 - supervision, mission actions and delegation

Dependencies: Phase 5 and Q3/Q4. Findings: F08-F11/F23.
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
- Deliver S05-S07 in both apps, with MissionAgent and AgentConsole aligned.

### Definition of Done

- [ ] Actions enforce owner, expiry and irreversible termination across continuations.
- [ ] Updated mission meaning reaches fast-path consent and audit.
- [ ] Distinct caller/intermediary/worker-key cases validate Q3/Q4 rulings.
- [ ] Direct-worker and wrong-parent PS requests fail.
- [ ] Both apps' sequences and payload assertions use PS-recorded delegation.

## Phase 7 - revocation authority and dependency graph

Dependencies: Phase 6 and Q9. Findings: F14-F16.
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
- Update header/body/poll codes and S08 in both apps; remove Wallet/Bookings
  cross-issuer PS-revocation examples.

### Definition of Done

- [ ] Valid unseen/repeated revocation returns 200 and blocks presentation.
- [ ] Namespace collisions, injected issuer, forbidden roles and malformed expiry fail safely.
- [ ] Resource dependency does not impose a five-minute auth expiry.
- [ ] Registration, consent completion and revocation races are covered.
- [ ] Cascades, notification failure and retention have controlled-clock tests.

## Phase 8 - R3 execution, Catalog and Events

Dependencies: Phase 7 and Q5/Q6/Q8/Q10. Findings: F17-F22.
Phase rule: PerCall and seven standard vocabularies, no gateway/conditional aliases.

### Responsibilities and files

- Rename R3 Conditional contracts; remove document/proposal Version and OpenAPI
  Gateway APIs from [models](../../../src/AAuth.R3/Model/), schemas, metadata,
  claims and factories. Preserve byte hashes, structural equality and legitimate
  format qualifiers.
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
  under Q5, completing the identity contract already migrated in Phase 4 with
  SQLite transition/redemption and per-call retained-result integration. Preserve public subscriptions
  and self-JWT semantics. Deliver S09-S12 and selected S14-S16 in both apps.
- Do not claim full Budgets support without its separately approved plan.

### Definition of Done

- [ ] No obsolete R3 names/emission; seven vocabulary and Catalog tests pass.
- [ ] One grant cannot execute twice under fresh signatures; retries return retained result.
- [ ] Foreign valid PS cannot read unentitled R3 documents.
- [ ] Protected Events has approved trusted binding, persistence and negative tests.
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
- [ ] Release/full solution, explicit R3/Events and TypeScript gates pass.

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
- Reconcile published/WIP target language only with verified supported scope.

### Definition of Done

- [ ] Every discovered instructional block has a validation class and disposition.
- [ ] No unexplained old wire/API name remains in live guidance.
- [ ] Both apps' real traces and static instructions agree for selected flows.
- [ ] Stub/Keycloak browser results and external/unavailable limits are recorded separately.

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
- [ ] External limits and unpublished-draft status remain accurate.

## Out of scope and conditional work

These are proposed Phase 0 dispositions, not silent removal of existing support.

| Item | Default disposition | Re-entry requirement |
|---|---|---|
| SDK edits in this research task | Out of scope | Separate implementation authorization |
| Draft-10 aliases/dual-wire support | Excluded by spec-first alpha policy | Explicit logged exception |
| Full Budgets metering/settlement | Separate initiative | Q10 rulings, transaction/persistence model and both-app scenarios |
| Result-release execution | Disabled; explicit unsupported handling/model awareness | Q6/Q10 selection and safe S16 in both hosts |
| Annotations, link discovery, algorithm advertisement | Select small optional slices in Phase 0 | Conditional validation and real support, not metadata-only claims |
| Hosted child provisioning/native attestation | Guidance and existing regression only | Approved platform-specific design |
| Supervision/control-plane protocol | Separate companion/deployment concern | Pinned defined companion and authorized scope |
| Delayed/offline verification | Separate opt-in | Explicit time/replay/retention policy; preserve online verifier |
| X.509/cached generic carriers | Existing exclusions retained | Explicit scope and complete scheme tests |
| Production distributed persistence/delivery | Interface obligations and sample schema safety only | Approved durable backend and operational guarantees |
| External whoami/mission/worker success | Unverified until live evidence | Compatible remote draft, HTTPS/JWKS and consent |
| Package release, deployment, PR creation | Not requested | Explicit authorization; research-branch push is already authorized |