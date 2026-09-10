---
description: Decisions and validation results for the AAuth v10 migration.
---

# Implementation Log - AAuth v10 migration

## Decisions Taken

### [2026-09-09] [Phase 14] Resource challenge verification repair - PROCEEDED

The cross-origin regression reproduced a PS discovery attempt from
`ChallengeHandler.SendAsync` before JWT verification. The initial failing run
attempted DNS for `ps.example`; the issuer gate then passed the same test.
Protocol resource challenge verification requires JWT verification and resource
binding before exchange (v10 `Resource Challenge Verification`, L868-L873).
The handler now takes the shared verifier, metadata and JWKS dependencies from
the builder or manual host and rejects issuer, signature, agent/key, expiry,
account and mission mismatches before PS calls or consent. It uses the token
recorded by the signer, not the mutable holder. Adaptive retries copy the
signing context back. Four-party audiences remain supported; PS-AS trust stays
in the existing exchange path. Focused Release evidence is recorded in
`/tmp/aauth-phase14-review-challenges/`; full gates remain pending.

Preserve the preexisting discovery crypto-factory and R3 retention changes.
No commits, branch changes or nested delegates are used in this repair worker.
This does not override the owner's independent-review requirement: Phases 14
and 15 remain open until fresh review. Existing Markdown metadata is preserved;
no frontmatter is added to previously unadorned files.

### [2026-09-09] [Phase 14] Focused R3, AP, documentation and walkthrough repairs - RESOLVED (focused checks)

R3 wrong-approver repro returned 200 on immediate issuance and 202 on deferred
issuance. Both now reject with `invalid_resource_token` before document fetch,
operation policy or audit. [R3AccessTokenEndpoint L162](../../../src/AAuth.R3/R3AccessTokenEndpoint.cs#L162)
binds to the authenticated PS and validates upstream context; L61 and the retained
mint record carry verified mission to both delivery paths. All 94 endpoint tests
pass, including real `AccessServerClient` PS delivery validation of immediate and
deferred R3 tokens and dropped/changed upstream mission rejection. Evidence:
`/tmp/aauth-phase14-review-r3/`. Canonical protocol resource verification step 7
is [L859](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L859).

The actual MockAgentProvider host reproduced `Ed25519` publication for an enrolled
ES256 key. [Program L82](../../../samples/MockAgentProvider/Program.cs#L82) now
publishes the key's real algorithm. The regression enrolls over the actual HTTP
route, validates the published key and proof, restarts the actual host over the
same registry, and reads the key before reenrollment. Eleven enrollment tests
pass in `/tmp/aauth-phase14-review-ap/`. A preexisting legacy AP key initially
blocked host startup; `AgentProvider:KeyDirectory` isolates test keys without
changing user files. The shared crypto factory and R3 retention edits remain.

Documentation repairs cover mandatory PS-local/AS-authenticated approver context,
ephemeral HTTP signing for naming JWTs, actual provider constructor parameters and
labels, explicit DI credentials without HWK fallback, and generic Profile route
admission. All four semantic/compilation checks pass in
`/tmp/aauth-phase14-review-docs/`; constructor table declarations are compiled,
and the naming-JWT signing-key selection is checked structurally, not by hashes.
Manual challenge examples now inject verification dependencies and use separate
agent-token exchange channels. The focused challenge suite passes 70/70 in
`/tmp/aauth-phase14-review-challenges/` with zero PS calls/consent on rejection.

Documents now has four exact SDK step templates and AP setup, verification,
browser-carried callback, signed pending polling and download rows. Events has
six exact SDK step templates and a participant/message sequence with explicit
public/protected branches. Local decisions have no network arrows. Ten exact
templates compile; shared browser helpers require numbered step/diagram/snippet
association, cleared state after reset, full second execution, and desktop/mobile
screenshots. Fresh browser results, final Release gates and inventory refresh
are still pending; no full-gate or Phase 14/15 completion is implied.

### [2026-09-09] [Phase 14] Focused review repair final gates - RESOLVED (review remains open)

All three runtime issues were reproduced before repair: cross-origin challenge
caused PS discovery; wrong R3 mission approver yielded 200/202; actual AP per-agent
JWKS advertised Ed25519 for an enrolled ES256 key. Related verification/signing/
configuration/generic-route docs and both shared instructional surfaces are fixed.
Canonical anchors are protocol resource challenge verification L868-L873,
resource recipient approver L859, Signature Keys ephemeral HTTP key L794, and
[AP publication L82](../../../samples/MockAgentProvider/Program.cs#L82).
The earlier focused entries retain the repro, repair decisions and test paths.

Fresh final Release: 2234/2234, zero failures/skips (1059 core, 878 conformance,
222 R3, 75 Events). This adds 33 cases to the previous 2201: eleven challenge
cases, eight R3 cases, one actual-AP restart case, three semantic docs cases and
ten exact walkthrough templates. No tests were removed. Artifacts:
`/tmp/aauth-phase14-review-final-tests.log` and
`/tmp/aauth-phase14-review-final-trx/`. Full Release build and `make build`
both report zero warnings/errors in
`/tmp/aauth-phase14-review-final-release-build.log` and
`/tmp/aauth-phase14-review-final-make-build.log`.

Fresh full stub browser gate: 71 passed (40 tour, 31 app), one existing
Keycloak-only skip. Fresh full live Keycloak gate: 72 passed (40 tour, 32 app),
zero skipped. Both have retries=0, zero unexpected/flaky results, isolated HOME,
and fresh application services. Reports:
`/tmp/aauth-phase14-review-stub.json` and
`/tmp/aauth-phase14-review-live.json`; matching directories hold screenshots and
failure-retention artifacts. Existing 72 browser cases were strengthened rather
than padded with duplicate test names: all eight Documents/Events cases now
perform two complete executions, assert cleared reset state, numbered steps,
diagram/snippet associations and viewport fit at 1280/390 pixels. Documents
captures include AP setup and signed pending polls; browser-local decisions have
no invented network arrows. Events captures include public/protected participant
paths and readable arrows in both app themes. Representative diagram and code
screenshots from both apps were visually inspected.

Focused browser repros caught test assumptions about a fresh login on every
execution and a transient resource code URL. Retained authentication legitimately
skips login and immediately redirects to a browser session. The helper now waits
for either authenticated state or login and verifies callback parameters on the
actual navigation request. The repaired four Documents cases pass before the
full gates. The initial obsolete run was interrupted, not counted as a pass.
An incorrectly placed terminal-logger flag caused one `make` invocation failure;
plain `make build` and the final repeated build passed. No runtime bypass was
added to accommodate either harness issue.

API map regenerated after code edits and checked without writing: 198 changed
public-source files, +790/-152 declarations, zero unmapped. Docs map regenerated
after the final templates: 169 files, 629 blocks, including 272 exact C# blocks;
the final Release run passes frozen-source freshness without update mode. The
provider table and ephemeral signer have semantic regression checks, not just
new hashes. TypeScript typecheck and scoped whitespace checks pass.

No commits, branch changes, nested delegates, backend additions, specification
edits or plan completion checkboxes were made. Preexisting crypto-factory and
R3 retention changes are preserved. This worker's execution constraints do not
constitute an owner ban on independent review. Phases 14 and 15 remain open:
fresh independent review and its final alignment disposition are still required.
External interop, production identity/transport/store deployments and the five
external/platform template integrations were not newly executed; local Keycloak
is not evidence of those guarantees.

### [2026-09-09] [Phase 14] Focused final repairs - PROCEEDED

The owner authorized six reviewed repairs, without delegates, commits, or branch
changes. Preserve the auth-repair baseline (2160 Release tests, 72 live browser
tests, 71 stub browser tests plus one skip) and the newer Documents workflow.
Spec conformance governs; backward compatibility is not a goal. Replay identity
will use the verified canonical signature base and signing-key thumbprint, not
signature bytes, so ES256 alternate signatures collide while covered payloads,
carriers and parameters remain distinct. The unsigned selection label does not
create a new request identity. This applies the optional configured replay cache
in protocol `#freshness-and-replay`, [L2507](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2507).
Start with a crypto-valid alternate-signature regression and immediate check.

### [2026-09-09] [Phase 11] Post-gate console and response presentation - RESOLVED

Both running app URLs returned 200. A default-JWT AgentConsole request to
Profile /identified completed signed AP enrollment, refresh and 200 without a
Person Server. The first smoke used an empty HOME without XDG_DATA_HOME; .NET's
local-data fallback encountered the preexisting workspace cache and failed before
network I/O. Retried with explicit fresh HOME and XDG_DATA_HOME; no old cache or
private key was deleted. Evidence: /tmp/aauth-phase11-cli-final.log.

The successful response exposed a final Profile presentation defect: it described
JWT verification as direct JWKS identity. The endpoint now returns the verified
agent identifier for jwt and distinguishes that from generic discovered-key
identity. No admission or authorization logic changed. The existing direct-JWKS
browser test asserted the old note; it now asserts Generic Signature Keys and
not an AAuth resource access mode. All four affected identity browser cases pass
on fresh services with retries=0 in /tmp/aauth-phase11-identity-fixed.json.
This focused post-gate check supplements the complete 55+1 browser gates above.

The complete Release build/tests were repeated after this correction: zero build
warnings/errors, 1967 passed, zero failed/skipped, same per-project totals.
Artifacts: /tmp/aauth-phase11-postsmoke-build.log,
/tmp/aauth-phase11-postsmoke-tests.log and /tmp/aauth-phase11-postsmoke-trx/.
API freshness remains 182 files, +697/-143 declarations, no unmapped files.
The owned Keycloak container was stopped; the stub demo is restarted on the
usual 5240/5400 URLs with isolated state for owner review. This adds no new
scope exclusion or unresolved Phase 11 finding.

### [2026-09-09] [Phase 11] Final verification and API review - RESOLVED

Phase 11 is implemented and verified without delegates, commits, branch changes,
dependency upgrades or specification snapshot edits. Prior migration work is
preserved. The finished Release gate passes 1967/1967 tests: core 913,
conformance 777, R3 206, Events 71; no failures/skips. This retains the owner's
1920 baseline with 47 additional cases, including 17 exact snippet compilation
cases. No tests were deleted to meet the gate. Artifacts:
/tmp/aauth-phase11-final-tests.log and /tmp/aauth-phase11-final-trx/*.trx.
Release build and make build both report zero warnings/errors in
/tmp/aauth-phase11-release-build-final.log and
/tmp/aauth-phase11-make-build-final.log.

The final full fresh-service browser run passes all 55 applicable stub-policy
cases; zero unexpected/flaky results, retries=0, CI=1 and isolated HOME. Its one
Keycloak-only case then passes with KEYCLOAK_E2E=1, live imported Keycloak 26.0,
another fresh sample stack, no skips/failures/flakiness and retries=0. Across
both policy configurations all 56 existing browser cases executed successfully.
Reports: /tmp/aauth-phase11-complete-browser.json and
/tmp/aauth-phase11-complete-keycloak.json; logs and retained traces use matching
prefixes. The Keycloak image was already cached; no image/package download.
The earlier make-demo sample executables were identified by process group and
stopped narrowly to avoid port reuse. Test-owned services stopped after each run.

First full Release failure: three governance fixtures still configured HWK or
asserted the old diagnostic, and one HTTP Bootstrap fixture lacked explicit
loopback admission. Updated to a self-issued agent JWT and the fixture's exact
egress policy; 14 governance plus 1 enrollment HTTP cases passed immediately,
then the full solution passed. First full browser failure: the picker expected
the old Identity-based label; the new Generic Signature Keys label is intentional.
The focused picker passed before the complete suite rerun.

Desktop/mobile Inbox screenshots were inspected. They exposed an existing
fixed three-column mobile tour layout and a 22rem picker overflow, made more
visible by complete setup text. The narrow responsive repair constrains the
selector and stacks the existing steps/diagram/payload without redesigning the
apps. Bounding-box, panel reachability and both successful Inbox flows pass.
Final screenshots are under /tmp/aauth-phase11-complete-browser-results/;
the focused before/after evidence is under /tmp/aauth-phase11-layout-results/.
Both apps expose actual provisioning and six resource-managed steps; the tour's
header now shows its local issuer, not the configured external AP, and no PS/AS
authorization lane is added. Low-level per-step requests remain intentional
teaching surfaces; the full-flow snippets use the tested provisioning builders.

The repeatable Roslyn inventory is current: 182 changed public-source files,
154 SDK plus 28 sample runtime; +697 added/replacement and -143 removed/replaced
declarations, zero unmapped files. It scans all current source, including
untracked additions, against ba768f1 and records overloads, constructors,
required inputs, option defaults, interfaces, DI and endpoint contracts.
The concept map covers every generated group, including Phase 1-10 egress,
decision/consent, revocation/account, R3 and Events. Compiler-synthesized and
inherited members are represented by source declarations rather than expanded;
this is not a binary compatibility report. Run tools/ApiSurface without --write
to verify freshness. The map has no frontmatter as requested.

Final direct adversarial review: scheme/provisioning/access-mode naming,
From/refresh precedence, generic-DI fallback, fixed-key/two-key mismatch,
construction failure/disposal, governance carriers and channels, AP transport
admission, hidden authorization parties, exact snippets, and Inbox visuals all
have recorded fixes or justified low-level dispositions. No known in-scope
finding remains unresolved. A precise Phase 11 diff check passes. A broader
folder check reports pre-existing whitespace in untouched SampleApp Program,
NavMenu and project files; those unrelated edits were left intact.

Coverage limits are explicit: the inventory is exhaustive for declared changed
runtime APIs, while snippet compilation is representative (8 tour constants,
4 Razor blocks, 5 docs templates), not one executable snippet per API declaration.
Existing provider/consumer suites cover retained low-level interfaces. No new
production persistence/provider deployment or general rotating-key signer is
claimed. Phase 12 cross-cutting security closure and Phase 13 final docs sweep
remain open; this phase updated affected docs alongside runtime and does not
declare all repository documentation final.

### [2026-09-09] [Phase 11] Runtime defaults and Inbox revisit - RESOLVED

The original hwk-to-agent-JWT change was real migration work, not missing setup
the owner overlooked. Retain it: protocol L2420 and L2422 (#keying-material)
require JWT for AAuth resource access. GuidedTour issues locally with its
published identity/key; SampleApp signs external AP enrollment on first use and
uses Enrolled/RefreshingFrom/WithKeyStore for lazy signed refresh. Resource
authorization remains agent/Inbox only; issuer discovery verifies identity,
not PS/AS authorization. No PS claim is added to the tour's Inbox token.
Generic Profile demonstrations remain separately labeled and enabled.

From(EnrollResult) now uses its issued AgentToken regardless of JWKS metadata.
Explicit scheme selection after refresh disables refresh; refresh after scheme
selection chooses JWT, retaining an initial held JWT when supplied. Flow options
do not select schemes. ToBuilder exposes the existing provisioning transition
without enabling an unrelated flow. Both provisioning sub-builders forward
resource-managed and interaction options. UseJwt's fixed parameter is token,
since agent/auth/subscribe purpose is independent of the carrier.

AgentProviderClient previously bypassed the injected client for both refresh
schemes. SignAsync now signs the actual request and the admitted supplied client
sends it, preserving policy/cancellation. Bootstrap has production-secure egress
configuration. Factory refreshers are disposable; injected HTTP/refresher/key/store
dependencies remain borrowed. Built enrolled pipelines own factory refreshers,
including failure paths, with per-build independent resources. Metadata/JWKS
clients dispose only internal HTTP. BuildGovernance owns its channels, supports
provisioning builders, and returns a disposable facade; constructor/Create borrow.

The fixed-key Enrolled pipeline rejects TwoKey: it cannot rotate the signer to
match a newly issued ephemeral-key token. Preserve RefreshTwoKeyAsync and its
returned token/key pair as the explicit advanced API. This fixes a configuration
that previously built successfully but signed with the wrong key, not an optional
context relaxation. The CLI's generic jkt-jwt demonstration remains explicit.

DI no longer silently chooses HWK: AddAAuthAgent requires AgentToken,
TokenRefresher, or an explicit generic SignatureKeyProvider. Generic providers
cannot be combined with AAuth authorization options. No mandatory verification,
account, expiry, owner, CSRF or trust input became optional for convenience.

The complete Roslyn scan against ba768f1 includes untracked SDK additions. Its
first inventory found 154 public-source files and +585/-134 declarations; rerun
after later fixes before final freeze. The map includes egress, consent decision,
revocation/account, R3 and Events, not just the preexisting builder APIs.

### [2026-09-09] [Phase 11] Focused verification and review failures - RESOLVED

Immediate first-edit check: test adapter could not discover the new test; the
dotnet test fallback caught a test-only using declaration on non-IDisposable
AAuthKey. Corrected; the one-test composition gate passed. AP transport tests
then exposed pre-cancelled calls reaching non-cooperative handlers; explicit
early cancellation now prevents side effects. Both refresh schemes are captured
through the supplied transport. A rejected out-of-order patch applied no files;
the reordered primary-app patch built successfully.

The API matrix checks From with/without JWKS, all explicit scheme overrides,
refresh precedence, no implicit authorization party, opaque replay coverage,
independent owned builds, borrowed dependencies, failed-build disposal and
governance ownership. The latest ownership/discovery slice passed 181 tests.
Secure DI tests passed 9. Exact snippet compilation reads 8 GuidedTour constants,
4 Razor blocks and 5 docs templates. It caught missing harness imports/trust-set
typing and two real FileKeyStore-versus-IKeyStore LoadAsync examples; repaired.
All 17 now compile. Full Release and fresh browser evidence follows separately;
these focused results are not yet the completion gate.

### [2026-09-09] [Phase 11] Full API alignment - PROCEEDED

The owner authorized the full current Phase 11, including runtime, API inventory,
primary-app snippets/visuals, affected documentation and fresh Release/browser
verification, without delegates, commits or branch changes. Preserve existing
work and the 1920-test / 56-browser baseline. Start with the confirmed missing
EnrolledBuilder resource-managed forwarder and an immediate focused regression.
Inventory every public migration delta against ba768f1, including Phases 1-10,
and retain advanced contracts where a wrapper would not remove real plumbing.
The Inbox remains AAuth resource-managed access using an agent JWT; provisioning
is setup, not PS/AS resource authorization. Final provenance and ownership rulings
will be recorded with executable evidence. Phase 13 documentation closure is not
claimed by this phase.

### [2026-09-09] [Phase 11] Events repair verification ledger - RESOLVED

Post-gate console smoke: fresh and cached AgentConsole runs both reach the
Profile identified endpoint with the same durable thumbprint, AP-assigned agent
ID and AP kid. Evidence: /tmp/aauth-events-repairs-cli-first.log and
/tmp/aauth-events-repairs-cli-cached.log. The final Release gate was rerun after
this follow-up with the same totals below. The updated isolated demo is running
at ports 5240/5400; its log is /tmp/aauth-events-repairs-demo.log. The temporary
Keycloak verification container was removed after its successful browser run.

Release build passes with zero warnings/errors. The final Release test gate
passes 1920/1920: core 866, conformance 777, R3 206, Events 71; zero failures or
skips, 13 cases added over the owner's 1907 baseline. All 206 prior R3 cases are
retained. Artifacts: /tmp/aauth-events-repairs-release-build.log,
/tmp/aauth-events-repairs-release-tests.log and
/tmp/aauth-events-repairs-tests/*.trx. The first full gate found the existing
empty-agent-ID rejection test; the API now distinguishes omitted/null assignment
from invalid blank IDs, and both contracts pass.

Fresh-service full browsers pass 55 applicable cases with zero unexpected/flaky
results, CI=1, isolated HOME and retries=0. All four Events browser cases pass.
The default stub configuration excludes one live Keycloak case. That exact case
was then run with another fresh service stack, KEYCLOAK_E2E=1 and the Keycloak AS
policy: 1 passed, zero failed/skipped/flaky, retries=0. Across the two policy
configurations all 56 cases executed successfully; no optional coverage remains
unverified. Reports: /tmp/aauth-events-repairs-browser-final.json and
/tmp/aauth-events-repairs-keycloak.json, with corresponding .log files.
The initial browser run exposed the obsolete caller-selected tour-sub assertion;
the test now requires an AP-assigned full-hash identity under the AP host.

The live IdP used the already cached Keycloak 26.0 image and the repository's
realm import. No packages or images were downloaded. No broad dependency was
installed. AgentConsole now re-provisions a cached durable key with signed
enrollment, so a cache from the old volatile AP does not require deletion or an
unsigned identity replacement. Re-enrollment retains provider ownership.

Known sample limits remain explicit: no authorized durable-key/PS rotation API,
no general human-identity admission, manual receipt retention, literal issuer/eid
deduplication, no cross-circuit workflow resume, and no transaction spanning
arbitrary external actions. None of the four reported adversarial defects is
left open. The broader Phase 11 API inventory remains a separate unfinished task.

### [2026-09-09] [Phase 11] Events adversarial repairs and enrollment API - RESOLVED

The owner authorized four repairs, actual HTTP/SQLite evidence, full Release and
fresh-browser gates, without delegates, commits or branch changes. Existing R3
work is preserved. This is a scoped Phase 11 hardening entry, not completion of
the broader API-alignment phase.

Subscribe verification now binds the parsed AgentId domain to the exact AP
identifier. Production requires `https://{domain}`. Explicitly admitted loopback
origins use their exact identifier host, without a port in the agent domain;
admitting an origin does not authorize it to assert an unrelated host. Foreign
issuer tests include real and fake protected tickets and the public channel;
the victim subsequently redeems the untouched ticket. The current core agent
token verifier had no reusable domain-binding helper, so the Events check uses
the existing AgentId parser and exact server-identifier policy directly.

The sample AP is authoritative over its identity namespace. It derives a stable
local identifier from the full SHA-256 of the durable public-key thumbprint,
under its own host. First claim cannot request a privileged or foreign identity.
The optional requested ID is accepted only when it equals the assigned ID.
Enrollment requires fresh hwk HTTP proof covering the actual body digest and
content type; the body public key must match the verified signing key. SQLite
persists the immutable identity/key/Person Server binding and stable kid across
restart. Changed-key or changed-PS enrollment returns 409, not implicit rotation.
Production admission, user identity and authorized rotation remain separate
provider responsibilities. No registration request asserts a human identity.

API inventory: AgentProviderClient.EnrolWithKeyAsync reuses a supplied durable
key; EnrolAsync still generates one and now signs enrollment. A null agentId
requests provider assignment; EnrollResult.AgentId exposes it. The existing
AAuthClientBuilder.Bootstrap(endpoint) and BootstrapBuilder.WithKey compose the
same path. There is no AgentProviderBuilder in this tree. SampleApp, MissionAgent
and Events reuse persisted keys; GuidedTour signs its per-walkthrough key.
Same-key reenrollment is authenticated and idempotent. No unsigned compatibility
route or caller-selected namespace remains in the mock AP.

Pending(agent, limit, after) exposes owner-scoped receipt pagination. SQLite
uses an indexed row-bounded query, stops on serialized byte budget, and the
endpoint uses the same web JSON options. Arrays include base64 expansion and
are bounded to 1 MiB. An individually unreturnable envelope is rejected before
quota/outbox commit. Acknowledgments remain owner-scoped. The HTTP regression
drains thirteen 64 KiB events through the normal 1 MiB transport.

Bookings persists the local notification receipt atomically with completion.
Retries authenticate the original provider/agent and retain the stored account;
they can return the exact receipt even after completion without another AP call.
A prepared delivery still handles failure between AP acceptance and local commit.
EventDemoSession retains its step after network failure, retries the command,
and pages the inbox. The lost-success-response HTTP test proves one AP delivery,
one durable agent action and normal acknowledgement. This does not add general
exactly-once external effects or cross-circuit workflow resume.

No NuGet/npm dependencies were added or installed. SQLite 10.0.11 was already
present. The cached Keycloak 26.0 image will be used for the optional live-IdP
browser gate after the default full suite; no image pull is planned. Both
documented Keycloak realm ports were initially unreachable. An old sample stack
must stop so Playwright can start isolated fresh services. Initial full Release
tests pass 1919/1919 with zero skips; final rebuild/test/browser evidence follows.

### [2026-09-09] [Phase 10] Completion and verification ledger - RESOLVED

Phase 10 is implemented with no compatibility layer, delegates, commits, branch
changes, merges or cherry-picks. The earlier Events branch was inspected with
git show/ls-tree. Its field shapes informed the companion, but its EdDSA checks,
independent JWT resolver and permissive loopback URL policy were not reused.
Current SDK verification and discovery remain authoritative. Prior worktree
changes were preserved; this entry does not claim to audit all preceding phases.

Release solution build: zero warnings/errors in
/tmp/aauth-phase10-release-build.log. Full Release solution tests: 1843 passed,
zero failed/skipped (core 865, conformance 777, R3 142, Events 59), recorded in
/tmp/aauth-phase10-release-tests.log and /tmp/aauth-phase10-release-tests/*.trx.
`make build` passes with zero warnings/errors in /tmp/aauth-phase10-make-build.log.
Packing produces /tmp/aauth-phase10-pack/AAuth.Events.0.1.0-alpha.1.nupkg with its
README and core dependency. CI tests the solution and explicitly runs Events;
the release workflow now packs Events too. No package was published.

Fresh-service full browser run: 55 passed, one Keycloak-only test skipped, zero
unexpected/flaky cases; retries=0, CI=1 and isolated HOME. Evidence is
/tmp/aauth-phase10-full-browser.json and .log plus tests/e2e/test-results/ traces
and Events desktop/mobile screenshots. All four new Events cases pass: public
and protected work-account flows in both primary apps. The first focused browser
run had three failures: two early radio-selection events were dropped before
Blazor became interactive, and GuidedTour lacked its scoped CSS stylesheet.
Explicit interactive readiness and the stylesheet repair resolved them; the
focused rerun passed 4/4 in /tmp/aauth-phase10-browser-fixed.json. Browser
TypeScript checks and touched editor diagnostics are clean.

Standalone EventAgent completes six actual HTTP steps, including AP 202,
processed=true and duplicate_ignored=true, in /tmp/aauth-phase10-eventagent.log.
The running sample stack uses isolated state and logs to
/tmp/aauth-phase10-demo.log; both /events pages are available on ports 5240/5400.
The scoped diff check passes. Known pre-existing whitespace/other changes outside
the checked Phase 10 slice are not represented as repaired.

| Requirement group | Verified spec location | Implementation and discriminating evidence |
|---|---|---|
| AP metadata and subscribe verification | Events [L198](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L198) (#ap-metadata), [L277](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L277) (#subscribe-token) | MockAgentProvider metadata, SubscribeTokenBuilder, EventsTokens, explicit ISignatureTokenVerifier registration; SubscribeTokenTests and actual HTTP registration |
| Self-issued event and exact HTTP body | Events [L368](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L368) (#event-token), [L413](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L413) (#event-delivery) | Shared resolver/middleware and SignAsync; EventTokenTests and EventHttpTests reject cnf, unsupported algorithms, wrong keys, forged JWTs and tampered actual bytes |
| Atomic quota, durable acceptance, statuses | Events [L424](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L424), [L437](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L437) (#event-delivery) | SQLite immediate transaction + FULL sync, persistent outbox; concurrent 3-of-30 acceptance, unlimited accounting, injected insert rollback, reopen, exact retry, and actual HTTP 400/401/403/404/429/503/202 tests |
| Tickets and registration persistence | Events [L603](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L603) (Pre-Authorized Subscription URL Security) | Atomic consumption/insertion, wrong agent/operation, expired/stale state, concurrent single success, rollback preserves ticket; account taken only from prior authorized context |
| Agent trust, context and deduplication | Events [L447](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L447), [L454](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L454) (#ap-to-agent) | EventReceiver verifies issuer JWT/audience/expiry before context; persisted issuer/eid receipt; forged/expired/mismatched events and duplicate tests |
| AsyncAPI and executable discovery | Events [L493](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L493) (#event-discovery) | Bookings publishes aauth-subscribe security, receive operations, raw payload and registration schema, ticket channel parameter; protected R3 and public flows execute in both browser apps and CLI |

Phase 11 ownership inventory: AAuthSigningHandler.SignAsync and
AAuthVerifiedAssertion are shared core additions. EventsProtocol, token builders,
EventsSignatureTokenVerifier/AddAAuthEvents, endpoint extensions, EventReceiver
and the three durable store contracts belong to AAuth.Events. EventSupport owns
SQLite and local AP-agent APIs; it is a sample library, not a production SDK
provider. Bookings owns its static availability-state policy and ticket issuance
after R3 authorization. Additional metadata admission includes event_endpoint.

Remaining limits are deliberate and disclosed: Q5's recurring-event ambiguity,
raw-body interpretation, single-shot resource demonstration, local polling and
trigger APIs, manual data retention, no cross-circuit/console workflow resume,
and no exactly-once guarantee for arbitrary external business effects. The AP
is a trusted payload intermediary; the JWT alone does not bind a detached payload
after AP transport. Production deployments must supply retention, persistent
providers and appropriate operational/authorization policy. The sample uses
explicitly admitted loopback HTTP, not production HTTPS. Keycloak and external
interop were not newly verified by this phase. These are not broad zero-gap or
whole-spec-conformance claims.

### [2026-09-09] [Phase 10] Persistence and sample integration - PROCEEDED

Sample-owned EventSupport references the already approved SQLite 10.0.11 package;
AAuth.Events references only the current core SDK and ASP.NET shared framework.
The SQLite provider commits AP use accounting and outbox together with FULL
synchronization and immediate transactions. Exact compact-token retries use a
local SHA-256 storage key and must carry identical body bytes; this key is not a
wire jti. Resource ticket consumption and subscription insertion are transactional.
The protected ticket retains the authorized agent, operation, account and state.
The resource's prepared single-shot JWT/body and signing key are persisted for
retry. Agent context and literal issuer/eid receipts are durable.

Both primary apps gain /events pages using one six-step executable sample client,
linked from their Bookings/R3 views. Existing R3 step counts and consent indices
remain unchanged. EventAgent uses that same client. Protected notifications come
from an authorized R3 search or confirmation; public registration uses AsyncAPI.
The explicit local trigger requires the subscription's agent identity. Local AP
polling and acknowledgements require an AP-issued agent JWT and signed body digest.
The UI uses locally served Lucide 0.468.0 icons under their ISC license.

Intermediate gates: 25 Events tests (including seven real Kestrel HTTP cases),
17 Bookings authorization tests and full Release solution build pass. Full
solution tests and fresh-service browser gates are still pending at this entry.
Sample UI circuits have separate persisted stores but no cross-circuit resume UI.
Retention is manual: demo databases retain receipts and acknowledgements until
the owner removes the dedicated database. Production retention must be configured
by an implementing provider. No crash-durability claim covers arbitrary external
side effects after the agent's durable receipt.

### [2026-09-09] [Phase 10] Implementation authority and ownership - PROCEEDED

Implement all F27 boundaries against the current Events snapshot. Q5/Q6/Q9 and
the latest Phase 9 handoff were reread. The previous Events branch is inspected
only with git show/ls-tree; its independent JWT resolver and URL policy are not
imported. New companion validators use current TokenVerifier and explicit
ISignatureTokenVerifier registration, never unknown-type fallback. Shared HTTP
signing, digest and admitted discovery remain authoritative.

Reuse the existing approved Microsoft.Data.Sqlite 10.0.11 package for sample
persistence, not as a core SDK dependency. SDK contracts require atomic durable
acceptance with quota and outbox in one transaction. Resource tickets and
subscriptions and agent context/deduplication also require durable providers.
Q5 uses raw body bytes, no invented required jti, and literal issuer/eid agent
deduplication. Unlimited AP accounting is supported, but recurring notifications
remain ambiguous under that deduplication rule. The primary demo is single-shot.
Authenticated AP polling is a local sample profile, not a standardized API.

### [2026-09-09] [Phase 9] Completion and final gates - RESOLVED

Phase 9 is complete; no Phase 10 Events code, delegation, commits or branch
changes were made. Preserved the partial worker code and preceding-phase work.
Final Release solution tests pass 1784/1784: core 865, conformance 777, R3 142,
zero failures/skips. This adds 80 tests to the owner's 1704-test baseline.
Evidence: /tmp/aauth-phase9-complete/*.trx and
/tmp/aauth-phase9-complete-tests.log. Release solution build passes with zero
warnings/errors in /tmp/aauth-phase9-final-build.log; `make build` also passes
in /tmp/aauth-phase9-make-build.log. Editor diagnostics and browser TypeScript
checking are clean.

Both primary R3 browser specs pass 6/6 with fresh services, isolated HOME,
CI=1, retries=0 and full traces. Evidence:
/tmp/aauth-phase9-browser-final.json plus tests/e2e/test-results/ traces and
desktop/mobile account screenshots. The preceding targeted browser run had
3 passes and 3 failures in /tmp/aauth-phase9-browser.json: strict confirmation
validation exposed missing cancellation_policy in both primary runtime payloads.
Adding the actual field repaired the consent-link/popup symptoms; the final
rerun has zero unexpected or flaky results. The owner's earlier 51-pass browser
baseline and Keycloak skip are not re-reported as newly executed results; this
phase reran all six relevant R3 browser cases, not the unrelated full browser set.

Coverage includes all eight vocabulary forms, malformed optional fields/arrays,
unknown/empty Gateway labels, duplicate members, required GraphQL type, invalid
gRPC forms, empty input, custom-schema scope, service ID collisions, optional
member identity, account binding, all five Bookings method/route policy variants,
exact proposal retries, byte-store mutation isolation, digest/raw parameter
checks, unverified custom-fetch tampering, missing audit configuration, actual
released-token audit identity, concurrent issuance and pending mint-once, audit
failure before release, SQLite rollback and reopen recovery, and designated-AS
readership with role checks. Independent resource scope approval is enforced.

Storage limits remain explicit: SQLite audit is durable; Bookings documents,
pending consent, and sample signing keys are volatile. Restart requires a new
request; a committed but undelivered issuance may remain audited. PS evaluation
is the explicit Q4 interpretation, not an upstream resolution. Third-party fetch
and audit implementations must uphold their declared transport/persistence
contracts. Phase 10 owns Events delivery; Phase 11 owns fluent API consolidation
of the contracts inventoried below. No compatibility aliases were introduced.

The scoped Phase 9 diff check passes. A workspace-wide check found pre-existing
trailing whitespace in SampleApp Program.cs, SampleApp.csproj and NavMenu.razor;
those unrelated changes were preserved. No Phase 9 completion claim covers them.

### [2026-09-09] [Phase 9] Model and sample contracts - RESOLVED

All eight vocabulary shapes are validated. R3OperationIdentity replaces bare-ID
Contains/Evaluate calls; vocabulary, field names, service, and optional members
participate in matching. Optional omission is not a wildcard; OData method order
is not identity. R3VocabularySchemas is consumer-local and cannot override the
reserved standard namespace. R3Metadata accepts structured Gateway discovery and
validates requests against a supplied authoritative operation set.

Bookings derives its authoritative set from the published OpenAPI document.
POST search/hold retain their routes but now have unique searchAvailabilityPost
and holdReservationPost IDs; existing GET IDs remain unchanged. All five route
variants enforce granted, conditional, and rejected outcomes. Proposal retries
bind the account, HTTP method and all effective parameters. Malformed/unknown
parameters fail; confirmation no longer silently supplies missing input fields.
The /authorize agent verifier is separate from the AS-only document verifier.
Sample settings explicitly opt the PS into PersonServerEvaluators under Q4;
code defaults to the designated AS, with access/person dwk roles enforced.

Phase 11 API inventory: R3Operation factories and qualifiers, R3OperationIdentity,
R3VocabularySchemas, schema parameters on document/proposal/request/claim APIs,
R3Metadata.ValidateOperations and structured AddVocabularies,
R3DocumentReaderPolicy, required AuditSink, audit TokenId/TokenS256,
identity-based IsConditionalOperation/IsOperationAllowed, IsProposalAllowed and
resource-scoped IsScopeAllowed. The latter independently approves scope and R3;
no scope is silently dropped. Sample SqliteR3AuditSink is not a core SDK provider.

Phase 10 handoff: AsyncAPI operationId/action shapes and qualified receive grants
are ready. Events ticket response, subscribe token, registration, and delivery
remain Phase 10 work; no subscription capability is advertised here.

Intermediate proof: 136 R3 tests pass. Recorded repairs include one hash-API
compile mismatch, a missing subject in the new Bookings fixture (8 failures),
two audit timestamp precision assertions, and two local compile errors while
adding route/audit coverage. Each was repaired and its focused gate rerun. The
final solution and browser gates are recorded separately after completion.

### [2026-09-09] [Phase 9] Transactional audit provider - RESOLVED

NuGet's flat-container manifest confirms Microsoft.Data.Sqlite 10.0.11 exists.
Pin that approved version in the R3 sample and its linked-source persistence
tests. The SDK requires an explicit IR3AuditSink with no no-op default. The sample
commits token identity/hash and R3 audit metadata in one SQLite transaction with
FULL synchronization; it never persists bearer token text. Failure prevents
release. A crash after commit can leave an audited token that was not delivered,
but cannot produce an unaudited released token. Pending consent remains volatile:
restart requires a new request, not replay of a prior approval. In-memory test
sinks make no durability claim. Audit records survive sample signing-key rotation.

### [2026-09-09] [Phase 9] R3 implementation authority - PROCEEDED

Implement F22-F26 against the complete vendored R3 draft, preserving the earlier
worker's partial code. Match vocabulary and every identity member; accept custom
vocabularies only with explicitly scoped schemas. Keep served-byte verification
at each consuming boundary. Default readers to the designated AS; any PS role
requires explicit policy under Q4. Require persistence before releasing tokens;
in-memory test stores are not durable. The owner approved SQLite 10.0.11 subject
to an availability check. No delegates, commits, branch changes, compatibility
paths or Phase 10 Events implementation. Record API handoff for Phase 11.

### [2026-09-09] [Phases 6-8] Four adversarial repairs - PROCEEDED

The owner authorized all four reviewed fixes, primary sample updates and full
validation, without delegation, commits or branch changes. Existing Phase 9 R3
edits (including the untracked transport ownership test) are preserved and are
not part of this repair. This is not a single-phase worker restriction.

The first four real federated endpoint regressions reproduced `200 OK` for both
terminated missions and denied account/scope consent before the fix. Apply one
PS mission review and shared pending resolution to both issuance modes. Next,
partition cached grants by exact upstream authorization context, track locally
known upstream revocation dependencies, and implement direct AS chaining with
access metadata and the authenticated intermediary agent carrier. New public
contracts and final proof are recorded for Phase 11 below as they stabilize.

### [2026-09-09] [Phase 5] Adversarial final available gates - RESOLVED

The final Release solution passes 1573/1573 tests: core 817, conformance 703,
R3 53, zero failures/skips. This adds 34 tests to the preserved Phase 6 baseline
of 1539. `make build` and explicit Release solution build pass with zero warnings
and errors. Evidence: /tmp/aauth-phase5-review-complete/*.trx,
/tmp/aauth-phase5-review-complete.log and
/tmp/aauth-phase5-review-complete-build.log. The prior 1562/1569 failure remains
recorded; the intermediate 1570-pass gate is superseded by this final run.

The full final browser suite used fresh services, a new isolated HOME, CI=1,
full traces and retries=0. It passed 49 tests, skipped one Keycloak-only case,
and had zero unexpected or flaky tests. Evidence:
/tmp/aauth-phase5-review-browser-complete.json and its .log. The earlier full
49-pass/one-skip run is retained in /tmp/aauth-phase5-review-browser.json but
does not substitute for the final run after the last runtime changes. Both
apps' consent, federation, R3 and mission workflows pass; GuidedTour explicitly
asserts the post-clarification discovery GET, 26-symbol code and displayed
snippet while retaining the established 14-stage mission-chain count.

Final evidence includes authenticated person-policy absence/denial tests,
subject/issuer/scheme collision tests, hostile GET versus protected POST
attempts, stale decision generations, two-round PS consent, AS
consent/clarification/re-consent, mixed client 202 requirements, owner/key
isolation, eviction/restart-style missing IDs, expiry and cancellation. A real
deferred R3 audit exception returns application/problem+json server_error 500,
then 410 on replay; no later mint is possible. GET 204 is terminal, whereas
clarification POST 204 is an acknowledgment. Typed 429/503 responses preserve
the retry behavior explicitly shown in the polling diagram.

Verified implementation anchors:

- [Browser generation](../../../src/AAuth/Server/BrowserConsentSessions.cs#L21),
	[scoped attempt accounting](../../../src/AAuth/Server/BrowserConsentSessions.cs#L181)
	and [stable identity](../../../src/AAuth/Server/BrowserConsentSessions.cs#L240)
- [Missing pending state](../../../src/AAuth/Server/DeferredState.cs#L10) and
	[typed operation failure](../../../src/AAuth/Server/DeferredState.cs#L58)
- [Claims-POST dispatch](../../../src/AAuth/Access/AccessServerClient.cs#L221)
	and [new-interaction polling predicate](../../../src/AAuth/Access/AccessServerClient.cs#L443)
- [PS code lookup](../../../src/AAuth/Person/IPersonPendingStore.cs#L274),
	[AS code lookup](../../../src/AAuth/Access/IAccessPendingStore.cs#L188) and
	[R3 code lookup](../../../src/AAuth.R3/R3AccessTokenEndpoint.cs#L502)

Citation corrections to the preceding boundary entry: additional deferred body
fields are at protocol
[L2256](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2256),
not blank L2255; state-machine applicability is at
[L2266](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2266),
not blank L2265. The diagram's check-status/clarification line is verified at
[L2283](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2283).
The retry exceptions are explicit at
[L2288](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2288) and
[L2290](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2290),
despite the surrounding non-202-terminal prose. These are operational readings
of the pinned draft, not new wire requirements.

Production consent obligations remain explicit: authenticate before deciding
per [L2861](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2861)
(`#ps-approval-endpoint-auth`), and bind the authenticated person to the agent
per [L2869](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2869)
(`#agent-person-binding`). The demo exemption at
[L2863](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2863)
requires OS-controlled, non-public loopback access. A button and an ambient
cookie are not authentication. SDK policy defaults deny; the sample flag,
loopback peer/Host checks, loopback launch settings and documented OS isolation
do not claim control over an operator's public proxy, tunnel or account mapping.

Editor diagnostics and TypeScript checks pass. CRLF-aware git diff --check
passes; vendored spec diff is empty. No delegates, commits, branch changes,
credential additions or existing key modifications occurred. This worker did
not perform or claim an independent post-repair review or a complete audit of
later phases' governance/account/persistence obligations.

### [2026-09-08] [Phase 5] Adversarial repairs - PROCEEDED

Owner supplies five runtime findings and identity, deployment and retention
boundary objections. Execute locally without delegates, commits or branch changes;
preserve Phase 6's current changes and historical 1539-test gate. Live Keycloak
is an environment setup task still outstanding, not an implementation blocker.

Both hostile GET regressions reproduced bound-request invalidation; both now
pass. GET failures no longer mutate a cookie-bound attempt budget or terminate
its request. Code guesses retain address throttling; only CSRF-validated POSTs
affect the browser attempt budget. Supersedes the earlier five-GET lockout policy.
Protocol [L2140](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2140)
(`#interaction-code-format`) requires bounded attempts, but an arbitrary unknown
code does not identify a victim request. Termination must require a credible,
authenticated request association, not ambient SameSite=Lax cookies on a GET.

Two mixed claims/clarification/interaction regressions reproduced lost callbacks.
The client now dispatches new URL/code pairs and preserves actionable claims-POST
202 responses; all 21 client tests pass. Three operation failure/cancellation
cases reproduced nonterminal state. Typed 500/408 responses now terminate and
caller cancellation during execution cancels without claiming delivery; a caller
canceled before acquiring the gate does not consume state. The focused lifecycle
and browser gate passes 11/11. Basis: protocol
[L2826](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2826)
(`#pending-url-security`). Initial test syntax and counter-property compile errors
were repaired before those passing runs; neither was runtime evidence.

Next separate generated Crockford correlation codes from signed pending route
identifiers, with renewed generations for re-consent. Basis: protocol
[alphabet L2128](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2128),
[correlation L2136](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2136),
[single use L2138](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2138)
and [expiry L2142](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2142)
(`#interaction-code-format`). Identity binding and sample isolation remain open
until their negative tests and host changes are complete. No blanket completion
or independent post-repair review is claimed.

### [2026-09-08] [Phase 6] Final available gates - RESOLVED

Implementation and available validation are complete. `make build` passed with
no warnings/errors. Final Release solution tests passed 1539/1539: core 791,
conformance 696, R3 52; no failures/skips. This adds 49 tests to the owner's
1490 baseline. Evidence: `/tmp/aauth-phase6-final/*.trx`. Focused negative and
positive gates include no-claims PS denial, authenticated consent suspension,
failed claims consent, immediate/deferred grants, distinct-key combined child
and upstream chains, mission retention, wrong parent/key/agent/upstream audience
and trust, person-bearing actors, wrong immediate actor with matching nested
context, and actual PS identity-scope metadata admission.

The final full fresh-service browser suite passed 49 tests with one Keycloak-only
skip, zero failures and zero flaky tests. Evidence:
`/tmp/aauth-phase6-browser-final.json` and
`/tmp/aauth-phase6-browser-final.log`. It used isolated HOME, `CI=1`, full traces,
and zero retries. Both primary combined worker flows and ordinary federation/R3
flows exercise authenticated PS consent followed by independent AS approval.
Both combined flows verify actual Wallet worker 200 and parent-key 401 responses.
TypeScript checks passed; editor diagnostics on changed runtime and primary-app
surfaces are clean; CRLF-aware diff check passed; spec snapshot diff is empty.

An earlier final browser invocation ended interrupted around test 40 with no
failed tests recorded. It is not counted as a pass. The subsequent complete JSON
report supersedes it; the earlier 37-pass/12-failure and affected 21-pass runs
remain recorded above. A final curl check of the configured Keycloak realm at
localhost:18080 failed to connect (HTTP 000), so live Keycloak remains unverified.
The phase's final validation checkbox remains open; no gate was deferred or
claimed satisfied by stub mode. In-process Keycloak tests passed as part of
the full core suite, but do not replace a live IdP browser run.

Citation correction: the actor-prose conflict recorded below is at protocol
L1773, not L1776. The examples begin at L1890. Rechecked consent L934, child
forwarding L1511, full actor delivery L1574 and vocabulary restriction L2041
against the unchanged pinned snapshot. The ruling follows the concrete examples.
No delegation, commit, branch change, spec edit, or existing user-key mutation
occurred. New methods and changed contracts remain inventoried for Phase 11.

### [2026-09-08] [Phase 6] Consent and delegation execution - PROCEEDED

Owner authorizes the complete phase, including distinct-key four-party child
and combined upstream flows in both primary apps and browser tests. No nested
delegation, commits, branch changes, compatibility, or specification edits.
The working tree contains earlier phase changes, which remain intact. The
owner reports a current 1490-test baseline; it is not new Phase 6 evidence.

Re-read F17-F20 including the updated no-claims consent finding and the pinned
[PS consent rule, L934](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L934),
[child forwarding, L1511](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1511),
and [delivery checks, L1574](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1574).
The federation callback projects even denied assertions and is absent from
immediate/no-claims grants. Start with an HTTP regression proving a PS denial
cannot be bypassed by immediate AS success. Consent must gate both claims
release and grant delivery, independently of AS negotiation. NeedsConsent
resumes through authenticated Phase 5 state, never a fabricated subject.
New public contracts will be recorded for Phase 11 ergonomic alignment.

### [2026-09-08] [Phase 5] Implementation and available final gates - RESOLVED

Phase 5 implementation is complete for the inspected SDK and runnable sample
paths. The final gate after custom PS pending-route repairs passed 1412/1412
Release solution tests: core 713, conformance 647, R3 52, zero failures/skips.
This adds 50 tests to Phase 4's 1362: core +13 and conformance +37. `make build`
passed, both primary apps' targeted Release builds passed without warnings or
errors, and TypeScript typecheck passed. TRX evidence:
`/tmp/aauth-phase5-results/phase5-final_net10.0_20260908223017.trx`,
`/tmp/aauth-phase5-results/phase5-final_net10.0_20260908223028.trx`, and
`/tmp/aauth-phase5-results/phase5-final_net10.0_20260908223032.trx`.

Final fresh-service, isolated-HOME Playwright with `CI=1`, `--retries=0`, and
full traces passed 49 tests, skipped one Keycloak-only test, and reported zero
failures/flaky tests. Evidence: `/tmp/aauth-phase5-browser-complete.json`.
The prior full no-retry run also passed 49/one skip, but the final run occurred
after the mission-creation/permission ownership repairs and therefore supersedes
it. The full browser suite exercised both apps' approval/poll indices, terminal
denial paths, R3 per-call consent, mission clarification, Inbox opaque-token
replay, navigation and recorded step counts. The deferred SampleApp browser test
also checks code-only rejection, code reuse rejection and missing-CSRF rejection
before legitimate authenticated approval. No retry was counted as a pass.

Two earlier fresh browser runs failed and are retained as such:
`/tmp/aauth-phase5-browser-first.json` has 31 passed/five failed/14 skipped;
`/tmp/aauth-phase5-browser-second.json` has 48 passed/one failed/one skipped.
Failures were banner assertions made before the new explicit sign-in. The
fixtures now authenticate, verify the session URL and CSRF fields, then assert
the authority banner and complete the actual decision. No production bypass was
introduced to satisfy them. The initial 1402-test full Release pass preceded
the last ten security cases and is superseded by 1412.

Final local coverage includes 36 PS mapper tests, 21 production PS/AS relay
tests, six browser-session HTTP tests, seven Keycloak-policy integration tests,
four custom PS pending owner/cancellation cases, eight Inbox/store tests and
52 R3 tests. These are overlapping focused suites, not additional totals.
The 21 relay cases cover PS local triage, agent relay, replacement scope,
claims after clarification, denial, cancellation, deadline, round limit,
foreign PS/different-key operations and malformed/rebound replacements.

The final local route check found mission-creation and permission sample pending
GETs still had no owner check and removed entries. They now capture verified
issuer/agent/key, support signed DELETE, serialize browser decisions and terminal
delivery, and retain tombstones. Their first compile referenced the token-type
enum in the wrong namespace; correcting it yielded the focused 33-pass gate and
four new negative cases. Resource-managed delivery likewise retains tombstones
without deleting or revoking its reusable opaque access token. R3 has signed
owner/key-bound cancellation and one-200/seven-410 concurrent delivery with one
mint/audit. Valid replacements update scope, mission and resource context before
re-consent; dropping a mission does not imply approval. PS local-triage updates
are verified before being forwarded to the AS.

The new sample consent progress component uses each authority's actual browser
paths. GuidedTour keeps its existing protocol counts, treating authenticated
browser steps as substeps of the existing consent step; polling confirms the
outcome. Phase 11 still owns fluent API composition and the reopened Inbox
credential-provenance review. The shared log's existing Phase 11 attribution
and provenance entries were read and preserved without modification.

Editor diagnostics for the new state/session code, owning routes and helpers
are clean. `git -c core.whitespace=cr-at-eol diff --check` passed. The specification
snapshot diff is empty. No commit, checkout, nested delegation, package upgrade,
or existing user-key change occurred.

### [2026-09-08] [Phase 5] Execution and first regression - PROCEEDED

Owner authorizes the entire consent/deferred slice, including optional AS
clarification, PS triage/relay, replacement context, resource-managed lifecycle,
and both apps' live flows. No delegation, commits, checkout, compatibility, or
spec snapshot edits. Q7 permits an explicitly isolated demo identity, not
code-only authentication. Browser correlation and authenticated CSRF-protected
decision sessions are distinct. Public contracts introduced here must be
inventoried for Phase 11, not claimed to finish its fluent API alignment.

Re-read current routes and pinned protocol
[clarification response, L1054](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1054),
[code format, L2136](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2136),
and [pending security, L2825](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2825).
PS GET lacks owner checks; mutation guards compare only subject. First check is
a six-case signed HTTP regression for foreign subjects and changed keys across
GET/POST/DELETE. Prior worktree changes and Phase 4's 1362 Release passes and
49 browser passes/one skip remain intact; they are not Phase 5 evidence.

### [2026-09-08] [Phase 4] Final ownership gate supersedes counts - RESOLVED

The final Release solution run passed 1362/1362: core 700, conformance 610,
R3 52, zero failures or skips. This supersedes the 1361 count below and adds
61 tests to the prior 1301 baseline. Evidence:
`/tmp/aauth-phase4-results/phase4-final-pass*.trx`. R3 factory clients now borrow
explicitly supplied handlers, so disposing a per-fetch client cannot dispose a
reusable endpoint handler. A two-fetch ownership regression passed. Its initial
compile used the wrong hash helper name and was corrected to `ComputeS256`.

One full rerun exposed a test-fixture timing race: the real slow-body test used
a 200 ms request timeout and, under solution load, sometimes canceled before
the local server received request headers. Its test-only deadline is now two
seconds; production defaults are unchanged. The focused test and full solution
rerun passed. Browser runtime paths were unchanged by these final injected-handler
ownership and test-budget edits; the full 49-pass/one-skip browser result and
the later 4/4 affected R3 result remain the browser evidence. CRLF-aware diff
validation passed again and the spec snapshot diff remains empty.

### [2026-09-08] [Phase 4] Completion gates - RESOLVED

Phase 4 implementation criteria are complete. Final Release solution build passed;
`dotnet test AAuth.slnx -c Release --no-build` passed 1361/1361: core 700,
conformance 610, R3 51, zero failures or skips. The initial 1301-test baseline
therefore gained 60 tests. `make build` passed. Final focused discovery gate
passed 82/82 and the R3 project passed 51/51. Editor diagnostics for the new
security implementation and touched browser tests reported no errors.

The complete fresh-service, isolated-key Playwright run with `CI=1`, no retries,
and failure traces passed 49 tests with one Keycloak-only skip. After the final
R3 pending-ownership exact-identifier change, both apps' affected R3 tests passed
4/4 on another fresh stack. `npm --prefix tests/e2e run typecheck` passed.
Structured evidence is in `/tmp/aauth-phase4-results/phase4-complete*.trx`,
`/tmp/aauth-phase4-browser-finaltrace.json`, and
`/tmp/aauth-phase4-browser-r3-final.json` for this workspace session.

An intermediate final browser rerun had one SampleApp R3 approval failure
(48 passed, one failed, one skipped). Its screenshot did not include the alert
text. The improved assertion now reports that text. Six repeated R3 tests,
the next full trace-enabled run, and the final affected R3 run passed without
reproducing it. This is retained as an unexplained intermittent observation,
not asserted to have a proven root-cause fix.

The default `git diff --check` reported CRLF line endings on two changed
SampleApp lines; the same check with `cr-at-eol` recognizing the files' existing
line-ending convention passed. `git diff --name-only -- aauth-spec` was empty.
Prior Phase 1-3 changes remain intact. No delegation, commit, checkout, package
upgrade, specification edit, or user-key mutation occurred. Phase 11 was not
implemented; its public-contract inventory inputs are recorded above/below.

### [2026-09-08] [Phase 4] Admission and cache execution - RESOLVED

Owner authorizes the complete Phase 4 security implementation and ergonomic
builders, without delegation, commits, checkouts, or spec snapshot changes.
F08/F09 and F26 fetch scope were checked against protocol draft-10
[#jwks-discovery, L2517](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2517)
and Signature Keys draft-08
[Section 7.3, L2372](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L2372).
The current JWKS cold/expired path bypasses its floor and failures retain no
attempt timestamp. Begin with a failing focused regression. Production transport
will resolve and pin admitted destinations, reject redirects, and bound response
bytes and elapsed time. Injected HTTP clients need an explicit transport contract;
loopback development access requires exact configured origins. All new public
contracts will be recorded for Phase 11; its broader inventory is not in scope.

### [2026-09-08] [Phase 0] Execution authorization - RESOLVED

The owner approved autonomous implementation, decision/deviation logging,
independent adversarial reviews per logical area, repeated repairs and reviews,
and a final documentation alignment sweep. Baseline is commit `ba768f1` on
`v09-spec-migration`, with a clean worktree. No commits, branch merges or package
publication are authorized. Logs live in this initiative folder.

### [2026-09-08] [Phase 0] Q1 capability scope - PROCEEDED (default)

Include account binding, all eight R3 vocabulary models, AS clarification,
Events, self-jwt and direct jwks. X.509 and cached assertions remain optional
unsupported schemes, with correct rejection and no misleading advertisement.
No compatibility aliases or old-wire parsing fallbacks are permitted.

### [2026-09-08] [Phase 0] Q2 server signing interpretation - PROCEEDED (default)

Use normative Signature Keys draft-08 id/dwk/kid discovery for non-agent server
signers. AAuth agent resource requests use jwt. The obsolete PS-AS example is
not a competing wire contract. An upstream clarification remains desirable;
this run does not publish issues on the owner's behalf.

### [2026-09-08] [Phase 0] Q3 production and development policy - PROCEEDED (default)

Production identifiers and egress are strict. Development access is an explicit
loopback policy configured by samples and tests, never an implicit relaxation
for arbitrary private addresses or HTTPS hosts. DNS/redirect/size/time checks
belong at the actual HTTP transport boundary as well as URL validation.

### [2026-09-08] [Phase 0] Q4 R3 readership - PROCEEDED (default)

Default document readership to the designated authenticated AS. A PS evaluator
may be explicitly authorized by a resource under the R3 document's evaluation
role language. This is a documented interpretation of the conflicting readership
clauses, not a claim that the ambiguity has been resolved upstream.

### [2026-09-08] [Phase 0] Q5 Events interpretation - PROCEEDED (default)

Use the delivery section's raw payload body. Keep the primary example single-shot.
Use the specified issuer/eid deduplication and do not invent a standard per-event
wire identifier. Unlimited registration/quota remains supported; recurring-event
deduplication limitations must be disclosed. Expired events never trigger action.

### [2026-09-08] [Phase 0] Q6 durability contract - PROCEEDED (default)

Accepted Events delivery and use accounting must be durable and atomic. R3
auditing must fail closed before releasing a token. Reuse suitable persistence
from the Events branch if verified; otherwise choose a transactional local
provider after checking dependencies. The exact dependency decision will be
appended before installation. In-memory stores do not claim crash durability.

### [2026-09-08] [Phase 0] Q7 consent - PROCEEDED (default)

Separate correlation codes from authenticated, CSRF-protected decision sessions.
Explicit isolated sample identity may replace a real user login in stub mode,
but no code-only approval path may bypass Keycloak policy.

### [2026-09-08] [Phase 0] Q8 expiry/context - PROCEEDED (default)

Preserve verified agent and delegation context in issuance and pending state.
Auth expiry cannot exceed the applicable verified agent expiry. Resources do
not invent an associated-agent-token fetch or private wire claim. Revalidate
stale contexts at deferred minting.

### [2026-09-08] [Phase 0] Q9 existing Events work - PROCEEDED (default)

Inspect `feat/aauth-events-implementation` read-only and selectively reuse
verified source/tests. No checkout, wholesale merge, or cherry-pick. New source
must be adapted to the shared v10 APIs and reviewed again.

### [2026-09-08] [Phase 0] Q10 parsing/toolchain - PROCEEDED (default)

Keep current cryptographic packages unless an actual incompatibility is proven.
Evaluate maintained structured-field tooling against required wire types and
labels before choosing it or retaining a corrected parser. Any dependency
decision is recorded before introduction; old wire formats are never the fallback.

### [2026-09-08] [Phase 1] Problem-details contract - RESOLVED

Implement a shared server result/writer with required `error`, optional `detail`,
and endpoint extensions using `application/problem+json`. Protocol draft-10
[#error-response-format, L2304](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2304)
requires clients to act on `error`, independently of `type`. Rename public
`ErrorDescription` to `Detail` without an alias or legacy-wire fallback. Preserve
success bodies, status choices, challenge/signature headers, and callbacks.
Normalize MockAgentProvider application-defined errors under the owner's approved
consistency ruling; this is not a normative Bootstrap requirement. No new package
is needed. Implementation is bounded to Phase 1 and coupled sample/docs/test edits.

### [2026-09-08] [Phase 1] Endpoint cutover and validation - RESOLVED

Added `AAuth.Server.AAuthProblemDetails.Create` and `WriteAsync`: required nonblank
`error`, optional string `detail`, error-only HTTP status, and copied endpoint
extensions. The helper owns `error`/`detail` and leaves pre-existing response
headers intact. Migrated PS, AS, DI authorization/governance, revocation,
resource-managed polling/challenges, R3 endpoints/results, and compiled sample
error producers. Mission status, pending identifiers, R3 proposal fields, payment
locations, success JSON, deferred responses, and browser consent responses retain
their original contracts. Signature-only middleware responses remain header-led;
signature taxonomy/status policy belongs to Phase 3.

Both token clients consume only `detail`, ignore `type` for classification, and
retain transport fallback for invalid `error` members. `ErrorDescription` was
removed from both public error types, with no alias. Updated LiveWhoAmITest,
MockAgentProvider's application-defined APIs, SampleApp's embedded federation
snippet, and current error/chaining documentation. GuidedTour's snippet catalog
contains no error-response example requiring replacement; its live denial
recording now retains the captured server body, including `detail`.

The first revocation HTTP regression failed against `application/json` before
the SDK fix, then passed with `application/problem+json`. Focused checks covered
real PS/AS/R3/governance/revocation/DI/resource-managed endpoints, body extensions,
optional detail, preserved headers and success media, malformed client error
members, and conflicting RFC 9457 types. Final affected-project runs passed:

- `dotnet test tests/AAuth.Tests/AAuth.Tests.csproj`: 541 passed, zero skipped.
- `dotnet test tests/AAuth.Conformance/AAuth.Conformance.csproj`: 579 passed,
	zero skipped.
- `dotnet test tests/AAuth.R3.Tests/AAuth.R3.Tests.csproj`: 39 passed, zero skipped.
- Total: 1159 passed, 30 additional cases versus the 1129-test baseline; existing
	endpoint tests also gained captured-wire assertions.
- `dotnet build AAuth.slnx` and `make build`: passed, zero warnings/errors.
- GuidedTour targeted build, edited-doc diagnostics, and `git diff --check`:
	passed.
- Active SDK/sample/docs legacy-name sweep: no matches. Remaining test mentions
	are deliberate absence assertions and legacy-field non-consumption cases.

### [2026-09-08] [Phase 2] Issuance policy - RESOLVED

The owner authorized Phase 2 only, autonomous alpha v10 with no compatibility
APIs, delegation, commits, or branch changes. Preserve the Phase 1 worktree.
F10 and the reserved-claim portion of F19 were read before implementation.
Rechecked protocol [Agent Token Lifecycle, L1344](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1344)
and [Auth Token Structure, L1708](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1708).

Require an explicit verified source-agent expiration on every AuthTokenBuilder.
Use the minimum of requested positive lifetime (at most one hour) and applicable
verified expiry ceilings. Sub-agent issuance binds the child identity and key to
the verified child expiry, additionally capped by the verified requesting parent.
Call chaining is additionally capped by the verified upstream auth expiry. This
conservative delegation ceiling is a local security policy, not an assertion of
an additional protocol MUST. Pending state retains those verified ceilings;
approval and delivery recheck expiration without refreshing stale authority.
Response expires_in reflects remaining issued-token seconds at delivery.

Reserve all builder-owned protocol claims, account (even before its later-phase
support), and nbf independently of populated optional properties. Requested and
projected AS identity claims use the same guard. Legitimate identity extensions
remain allowed. Begin with failing builder regressions, then validate each local
change and run targeted plus full-solution gates before completing Phase 2.

### [2026-09-08] [Phase 2] Verified context and delivery decisions - RESOLVED

AuthTokenBuilder requires AgentTokenExpiresAt; AuthorizationExpiresAt is an
additional ceiling, not a replacement for the child's source expiry. Both are
checked without acceptance skew at minting. The effective expiration is the
minimum of source expiry, delegation expiry, and issuance plus requested
lifetime. Positive lifetime and the one-hour limit are validated independently.
PS and AS options expose TimeProvider for deterministic issuance and delivery;
R3 uses its existing TimeProvider. ExpiresAt is captured on VerifiedToken and
retained on upstream results. No public wire expiry claim or lookup was added.

AgentIssuanceContext verifies the parent and optional child/upstream JWTs for
AS, R3, and PS federation. The child identity/key and its own expiry remain
separate from the minimum parent/upstream ceiling. Combined delegation nests
the requesting parent ahead of the upstream actor chain. AS/R3 upstream trust
is restricted to the issuing AS itself or the authenticated requesting PS's
origin. PS retains its existing explicit upstream issuer policy. This is a
conservative default; open first-hop federation does not imply authority to
extend arbitrary upstream issuers. AccessServerRequest requires the verified
delivery ceiling and forwards subagent_token. AS token delivery is checked
against that original ceiling after signature/issuer verification.

Reserved names are guarded regardless of optional builder properties. AS policy
requests/projections fail with policy_error for forbidden names; forbidden
pushed claims fail with invalid_request. Directed sub, tenant, roles, and groups
remain typed identity fields, while additional email-like extensions work.
The PS client rejects forbidden requested names before invoking its callback.

### [2026-09-08] [Phase 2] Validation gates and completion - RESOLVED

Completed Phase 2 only. The final `make build` and
`dotnet test AAuth.slnx -c Release --tl:off --logger 'console;verbosity=minimal' --verbosity quiet`
passed, followed by `git diff --check`:

- Core: 571 passed, zero failed, zero skipped.
- Conformance: 610 passed, zero failed, zero skipped.
- R3: 50 passed, zero failed, zero skipped.
- Total: 1231 passed, 72 added cases over Phase 1's 1159 (core +30,
	conformance +31, R3 +11). Build completed without warnings or errors.
- Focused checks passed for builder validation, AS claim requests/pushes,
	federation delivery, PS mapper and integration flows, the 31-case PS/AS
	issuance matrix, and the complete 50-case R3 suite.
- Both SampleApp and GuidedTour targeted builds passed. Edited source and
	documentation diagnostics passed.

The HTTP matrix asserts actual token exp and response expires_in for immediate
and deferred two-minute agents, both parent/child expiry orderings, combined
upstream/child bounds, refreshed poll carriers, and typed claims pushes. R3
additionally rejects stale consent before mint, expired cached tokens, and
tokens that expire during audit before release. Builder cases cover zero and
negative lifetimes, default/already-expired ceilings, independent one-hour
validation, and unset reserved names. Federation client tests reject overlong
direct/deferred AS responses and forbidden claims before invoking callbacks.
No unbounded builder or federation-request overload remains.

### [2026-09-08] [Phase 3] Carrier and trust cutover - RESOLVED

The owner authorized all Phase 3 responsibilities, without compatibility,
delegation, commits or branch changes. Preserve Phase 1/2 work. Pin
StructuredFieldValues 0.7.7 and first run a typed dictionary compatibility probe;
keep existing crypto libraries. Implement normative Signature Keys discovery
for non-agent server signers under Q2. Discovery transport admission and caching
remain Phase 4, except interfaces required by this phase. Verification must
establish typed JWT trust before using delegated HTTP confirmation authority.
Recheck F01-F07, F28 and F31 against the pinned spec. Investigate the reported
R3 fetch-verification and AS scheme-mismatch responses at their owning role;
do not install a blanket status-to-header translation.

### [2026-09-08] [Phase 3] Parser probe and wire evidence - RESOLVED

StructuredFieldValues 0.7.7 restores and compiles on net10.0. Four compatibility
cases pass: tokens, strings, integer/Boolean parameters, inner lists, escaping,
byte sequences and malformed dictionaries. The initial probe assumed byte[];
the API actually returns ReadOnlyMemory<byte>. Corrected the assertion and
reran the same check. Production code uses typed values and a canonical writer,
not ParsedItem.ToString serialization.

Thirteen JWK checks pass for fully specified alg, typed unsupported/invalid
failures, both crypto algorithms, public wire keys and unchanged thumbprints.
Nineteen independent wire cases pass across all six schemes, including mixed
issuer/request algorithms, selected labels, reordered components, extra
signatures, escaping, expiration and distinct issuer/JWKS locations. These are
focused results, not completion of Phase 3. The first full core run reported
27 failures and 580 passes; after adding the required PS metadata discovery
fixture, all 20 AS integration cases passed. Remaining gates are still open.

### [2026-09-08] [Phase 3] Final contracts and reviewer dispositions - RESOLVED

F01/F04: Ed25519 replaces EdDSA without a compatibility alias. Public JWKs
include alg; typed validation separates unsupported algorithms from malformed
keys and algorithm/key mismatch. Wire imports reject private material. RFC 7638
thumbprints retain their original members. IAAuthKey now spans agent/resource
builders, server key collections, PS sub-agent binding, self-issued refresh,
federation and R3. JWKS caches raw members and validates only the selected kid.
Existing cryptographic packages and operations remain unchanged.

F02/F03/F28: hwk carries standard JWK string parameters; jwks_uri carries
id/dwk/kid and verifies metadata issuer before following jwks_uri. Direct jwks
uses url/kid and identifies the signer by the exact URL. self-jwt rejects cnf
and uses the same discovered key for both signatures. Self-jwt and companion
JWT types require exact ISignatureTokenVerifier registration; no Events type
or implementation is silently enabled. Non-agent PS/AS and R3 signers follow
Q2's normative metadata-discovery contract, not the stale protocol example.

F05/F06/F31: key resolution returns a typed verified assertion before its
confirmation key is used for HTTP verification. Unknown typ and forged issuers
fail even with valid HTTP proof of possession. No issuer-verification disable
option remains. Generic() enables generic schemes, not unverified JWTs.
Only verified JWT payloads populate agent/role/scope identity results; naming
JWTs remain pseudonymous. NamingTokenVerifier shares required iat/exp/header
alg, issuer/thumbprint and durable-to-ephemeral checks with MockAgentProvider.

F07: errors are typed, with no exception-message classifier. Signature-Error
uses the draft-08 dictionary form, error=<token>; required_input is an Inner
List of String. Removed supported_algorithms is replaced by Accept-Signature-Alg.
AAuth authentication failures use 401; the explicit generic status policy uses
400. Unsupported schemes negotiate accepted schemes. Authorization 403 does
not add signature-error or negotiation headers. No blanket response-header
middleware was introduced.

The two Phase 1 adversarial leads were confirmed and resolved by role:

- R3AccessTokenEndpoint's caught fetch-signature failure now preserves the
	shared verifier's typed Signature-Error and negotiation headers. Unsigned
	pending polls assert error=invalid_request; wrong-scheme token requests assert
	error=unsupported_scheme plus jwks_uri negotiation. Mint replay now explicitly
	emits error=invalid_signature. Different authenticated PS ownership remains
	a header-free 403, exercised by the R3 regression.
- Core AS scheme mismatch is a verification-role mismatch, not automatically
	authorization denial. Its verifier accepts jwks_uri and returns 401 with
	unsupported_scheme and Accept-Signature-Scheme: jwks_uri. The new real-AS
	regression verifies this. Verified but untrusted PS requests remain 403.

RFC 9421 checks include selected matching labels, unique dictionary labels,
two real signatures covering the complete key dictionary, parameter order,
component order, escaping, separate field lines, expires and conflicting keyid.
Known structured field types support sf/key; bs wraps individual field lines.
Unknown derived components never read HTTP headers. Incompatible/unknown
component parameters fail closed. Signature alg is ignored and never emitted.
Additional content fields work; covered SHA-256/SHA-512 Content-Digest values
are checked against actual body bytes. Digest coverage is not universally
required. This remains a request-signature implementation, not a new general
response/trailer-signature engine.

### [2026-09-08] [Phase 3] Sample and release gates - RESOLVED

Profile routes explicitly opt into generic signatures. Its direct per-agent
key-URL demonstration now uses jwks, including GuidedTour mode selection and
browser assertions. RequireAAuthSignature remains JWT-only; the new explicit
RequireGenericSignature supports generic demonstrations. SampleApp Inbox and
GuidedTour resource-managed requests now carry agent JWTs. Their consent/poll/
replay sequence remains six steps; snippets and step descriptions were updated
without changing navigation or approval indices. Primary apps and all compiled
consumers build. Active old-wire/removed-option sweeps found no remaining
EdDSA, legacy hwk/jwks_uri carriers, supported_algorithms, SignatureOnly or
RequireIssuerVerification in SDK/sample/current-doc source.

Final validation after repairs:

- make build: passed.
- dotnet build AAuth.slnx -c Release: passed, zero warnings and errors.
- dotnet test AAuth.slnx -c Release: 640 core, 610 conformance and 51 R3 passed;
	1301 total, zero failed or skipped. This is 70 added cases over Phase 2.
- Final TRX files: phase3-final-release.trx under each test project's TestResults.
- Focused typed parser, JWK, independent wire, adversarial, AS, R3, issuance,
	authorization and Inbox workflow checks passed throughout implementation.
- Fresh-service Playwright with CI=1, isolated v10 key state and retries=0:
	seven targeted generic-signing/resource-managed tests passed across GuidedTour
	and SampleApp in 1.2 minutes.
- Edited SDK/R3/primary-app diagnostics and git diff --check: passed.

The initial browser startup was blocked by persisted pre-v10 AP keys missing
alg. No old keys were deleted or imported through a fallback. Test services used
a temporary HOME with existing NuGet/browser caches. The next run had one cold
Blazor Inbox click flake that passed on retry; using the existing clickAndConfirm
helper fixed it, followed by the seven-pass no-retry run. Initial failed Release
runs and the flaky run are not counted as clean final gates.

### [2026-09-08] [Phase 4] Adversarial repair execution - PROCEEDED

The owner supplied four reviewer findings plus the cache-header objection after
Phase 5's 1412 Release tests and 49 browser passes/one Keycloak skip. Preserve
that work and its partial environment gates. No delegation, commit, checkout,
package upgrade, or specification edits are authorized in this repair worker.

Reverified protocol [JWKS Discovery and Caching, L2517](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2517)
(`jwks-discovery`), [same-kid retry, L2519](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2519),
[egress admission, L2521](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2521),
and Signature Keys [Section 7.3, L2372](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L2372).
The prior fixed-TTL exception is superseded: implement bounded HTTP freshness,
issuer-scoped attempt coordination as well as direct-URL floors, and shared
same-kid retry for upstream validation. Retain stale-on-failure only where
response directives permit it, the minute floor, and the hard age ceiling.

The two transport trust regressions failed before repair and now pass. The SDK
handler privately owns its inner transport instead of exposing a replaceable
DelegatingHandler chain. Federation inference accepts only the owned enforcing
handler behind known framework lifetime/logging wrappers; custom wrappers still
need an explicit contract. Initial full transport gate: 51 passed.

The address reproduction failed 16 public cases and passed 39 other cases.
Narrowed the IPv4 protocol-assignment and documentation ranges, IPv6 IETF
assignment range with public exceptions, and IPv6 documentation ranges using
the [IANA IPv4 registry](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)
and [IANA IPv6 registry](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml).
Both registries report 2025-10-09 as their last update. The resulting transport
gate passed 94/94, including 192.0.78.24, its mapped form, and 2001:500:2::c.
Private, mapped-private, documentation, reserved, link-local, multicast and
transition-address negatives remain rejected. The transition restrictions are
conservative local policy, not a claim that every such prefix is IANA-private.

### [2026-09-08] [Phase 4] Adversarial reviewer dispositions - RESOLVED

All owner-supplied findings were reproduced locally; no separate reviewer agent
was launched by this worker. These dispositions describe verified repairs, not
an independent post-repair review.

- Finding 1, mutable transport trust: the initial two regressions failed, then
	passed with a privately owned handler. A further post-resolution factory-chain
	mutation regression failed and required immutable borrowing of the actual SDK
	handler. The factory root remains referenced for ownership, but automatic
	binding no longer sends through its mutable lifetime/logging wrappers. Explicit
	contracts retain their supplied pipeline, including custom middleware. Default
	federation therefore omits those factory logging wrappers; HTTP diagnostics and
	SDK activities remain available. This is the tradeoff for an inferred guarantee
	that cannot be changed through public InnerHandler setters. Custom or in-process
	transports never acquire implicit enforcement merely by containing an admission
	handler. Final transport plus federation integration gate: 100 passed. Basis:
	protocol [L2521](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2521)
	(`jwks-discovery`) and Signature Keys [Section 7.3, L2372](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L2372).
- Finding 2, issuer floor: six caller regressions fetched keys-a at t=299 and
	incorrectly fetched keys-b at t=301 after metadata expiry. They now reject the
	second fetch and recover at t=359. A seventh case covers companion self-jwt.
	Generic JWT, auth verification, auth delivery, upstream validation, jwt and
	jwks_uri resolution all pass metadata-validated issuer context; self-jwt shares
	that path. The cache holds separately bounded issuer attempt state alongside
	per-URL content/floors, so changed URLs cannot reset failures/backoff or return
	another URL's keys. Concurrent cold URLs, invalidation, capacity pressure and
	direct/discovered URL sharing pass. Direct jwks identities retain per-URL
	floors, not an invented common issuer. Basis: protocol
	[L2517](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2517)
	(`jwks-discovery`, given issuer's JWKS at most once per minute).
- Finding 3, address overblocking: resolved by the IANA-based prefix repair and
	public/negative tests recorded above. The exact examples 192.0.78.24 and
	2001:500:2::c are admitted without opening network sockets in classification
	tests; real-handler negative cases still reject before connection. No claim of
	live Internet connectivity is made. Basis: Signature Keys
	[Section 7.3, L2379](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L2379).
- Finding 4, upstream same-kid refresh: the t=61 acceptance regression failed
	before repair; t=1 rejection already passed. Upstream now calls
	TokenVerifier.VerifyWithJwksAsync rather than independently resolving a key and
	calling synchronous Verify. The shared refresh succeeds after 61 seconds and
	does not refetch within the minute. Basis: protocol
	[L2519](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2519)
	(`jwks-discovery`, one refresh/retry after cached-key verification failure).
- Cache-header objection: supersedes the fixed-TTL exception under "Implementation
	and intermediate gates". Thirteen tests failed before repair; all 16 now pass
	against both JWKS and metadata. Cache-Control max-age takes precedence over
	Expires; Age and apparent Date age reduce freshness without double counting.
	The configurable TTL is only a headerless fallback, capped by the hard maximum
	age of at most 24 hours. no-cache requires revalidation, no-store retains only
	attempt state, and must-revalidate prohibits expired fallback. The mandatory
	minute floor can reject a revalidation instead of refetching early. s-maxage
	does not override this private client cache's max-age. Other responses retain
	bounded stale-on-error/backoff. Basis: protocol
	[L2517](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2517)
	and HTTP caching [RFC 9111 Sections 4.2 and 5.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2).

Phase 11 inventory additions: public JwksClient.ResolveKeyAsync(Uri, string,
string issuer, CancellationToken) and ForceRefreshKeyAsync with the same argument
shape. The existing no-issuer overloads remain the direct-jwks URL contract, not
a compatibility shim for issuer discovery. The issuer parameter means the exact
identifier verified against admitted metadata, not a claim of JWT verification
before its signing key is fetched. No additional public transport or cache type
was introduced. All changed production issuer-resolver call sites were swept.

The focused discovery gate passed 151/151. The first full Release build passed
with zero warnings/errors, but tests passed 1486/1488: core 789, R3 52 and
conformance 645 passed/two failed. The two failures were AuthorizationIntegration
fixtures publishing separate AP/PS JWKS URLs for the same issuer and fetching
both inside a minute. They now publish both keys at one shared URL, with explicit
one-fetch assertions. The focused authorization/upstream gate passed 22/22.
The initial failure evidence remains in /tmp/aauth-phase4-adversarial-results;
final full-solution and affected-browser gates are still pending at this entry.

### [2026-09-08] [Phase 4] Adversarial final gates - RESOLVED

The completed repair passes 1490/1490 Release solution tests: core 791,
conformance 647, R3 52, zero failures/skips. This is 78 added cases over
Phase 5's 1412. The final explicit Release solution build has zero warnings and
zero errors. make build also passed. Final TRX evidence:

- /tmp/aauth-phase4-adversarial-results/phase4-adversarial-complete_net10.0_20260908224908.trx
- /tmp/aauth-phase4-adversarial-results/phase4-adversarial-complete_net10.0_20260908224919.trx
- /tmp/aauth-phase4-adversarial-results/phase4-adversarial-complete_net10.0_20260908224922.trx

The affected federation browser gate passed 3/3: GuidedTour approval and denial,
and SampleApp approval. Fresh services, isolated HOME, CI=1, retries=0 and full
traces were used. Evidence: /tmp/aauth-phase4-adversarial-browser.json, with three
expected, zero skipped, zero unexpected and zero flaky. No unrelated browser
suite was rerun. Phase 5's broader 49-pass/one-Keycloak-skip result remains
historical evidence; live Keycloak remains unverified by this repair.

A final adjacent P2519 outcome check found both TokenVerifier entry points
reported invalid_jwt when refresh removed the kid. Two tests reproduced that
failure; both now report typed unknown_key, while unchanged-key verification
continues to fail normally. The resulting 11-case issuer/rotation suite and the
final full Release gate passed. The three browser tests preceded only this
error-classification repair, which does not change their successful federation
paths. Basis: protocol [L2519](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2519)
(`jwks-discovery`). The exact private-address prohibition starts at Signature
Keys [Section 7.3, L2378](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L2378),
continuing at L2379 cited above.

Editor diagnostics are clean. CRLF-aware git diff --check passes and the
specification snapshot diff is empty. Existing Phase 1-5 work, browser fixtures,
keys and unrelated changes were preserved. No delegation, commit, branch change
or package upgrade occurred. All supplied findings and the cache-header objection
have explicit tested dispositions; independent read-only post-repair review can
proceed in the parent workflow. Phase 11 owns the logged API inventory follow-up.

### [2026-09-09] [Phase 7] Qualified revocation and source lifecycle - PROCEEDED

Implement the pinned protocol's `(iss,jti)` identity and unknown-pair 404 at
[L2361](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2361)
(`#token-revocation`). Keep signature replay independent of reusable tokens.
Authorization compares the authenticated caller with the target issuer or an
explicit trusted-PS policy; a token's verified issuer is not the identity of its
holder. An AP-issued agent token alone cannot authorize an AP revocation.
Known-token state needs expiration and bounded retention, atomic registration
against revocation, and source/recipient associations. AP-to-PS denial and
resource cascade at [L2390](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2390)
remain incomplete until real issuance, deferred delivery, and reuse are tested.
New public contracts will be inventoried for Phase 11. Preserve prior Phase 5/6
changes and evidence; live Keycloak is excluded by the current owner request.
No compatibility aliases, delegates, commits, or branch changes are authorized.
Phase 8 must not begin before the Phase 7 gates pass.

### [2026-09-09] [Phase 7] Source lifecycle integration and interim gates - RESOLVED

Two initial real-endpoint regressions reproduced missing-issuer acceptance and
agent-token-holder impersonation of its provider (both incorrectly returned 200).
The typed pair/authorization gate passed 18 tests; the repaired full Release
boundary passed 1575 (817 core, 705 conformance, 53 R3). An old fixed-clock replay
fixture required matching inventory clock injection. Later source-inventory gates
passed 28, then 26 cascade-focused tests; core PS/AS integration passed 57. The
full lifecycle boundary found two expiry-response regressions, repaired with a
42-test expiry/replay gate by preserving existing JWT/issuance expiry ownership.
That full boundary still needs its final rerun.

Four new signed multi-host tests pass: AP-to-PS revocation blocks source reuse,
cascades PS-issued and AS-provided grants to two actual resource endpoints,
isolates another AP's identical jti, rejects fresh-carrier revival of pending
consent, and returns 502 rather than success when a resource does not recognize
an unpresented grant. The PS records a verified federated grant before delivery.
Only server-signing schemes establish a revoker identity; token issuer/subject
claims do not establish the holder as that server.

The bounded development inventory keeps invalid known tokens for one hour after
expiration, then returns unknown; capacity exhaustion fails closed without
evicting active revocations. Local revocation persists when downstream delivery
fails, and repeat requests retry recipients. No durable or restart-safe backend
is claimed. Unreached resources remain bounded by token lifetime, per protocol
[L2395](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2395).

Phase 11 API inventory: TokenKey, TokenRegistration, TokenGrant, IJtiStore's
RegisterAsync/RegisterGrantAsync/GetGrantsAsync/TryRecordRequestAsync, typed
RevokeAsync/IsRevokedAsync, RevocationClient, CreateTrackedAsync,
MapAAuthIssuerRevocation, PS/AS RevocationPath/ConfigureRevocation,
AgentIssuanceContext.SourceTokens and pending SourceTokens. Review fluent
composition after all migration phases; no compatibility aliases were added.
R3 integration and sample-resource revocation are still in progress. Evidence is
under /tmp/aauth-phase7-*; helper gates are not a claim of phase completion.

### [2026-09-09] [Phase 7] Final lifecycle and application gates - RESOLVED

Phase 7 is complete against its six definition-of-done checks. Real HTTP evidence
goes beyond helper tests: two APs sharing the same jti remain isolated; revoking
one source at the PS denies its next request and revokes PS-issued or AS-provided
grants at two resources using each grant's actual issuer and token ID. Repeated
known revocation is 200; unknown sources are 404; unknown resource recipients
produce 502 without undoing local denial. A fresh carrier cannot revive a pending
grant tied to a revoked original token. R3 has a separate approved-proposal
revocation regression. The actual Calendar sample proves metadata advertisement,
server-signed revocation, and rejection with a fresh request signature.

All six primary resource samples advertise and map revocation. Bookings' manual
agent/auth verification paths consult the same typed inventory. Core PS/AS and
R3 AS use verified source records and atomic tracked delivery; PS federation
records AS-provided tokens before delivery. Generic revocation remains
deny-by-default, while issuer mappers explicitly enable issuer authorization.
Wallet and Bookings configure target-aware trust for their PS. Additional Phase
11 API inventory: AAuthResourceOptions.RevocationEndpoint. No aliases were added.

Final validation actually run:

- `make build`: passed, zero warnings and errors; /tmp/aauth-phase7-build.log.
- Complete Release solution: 1593 passed, zero failed/skipped; core 818,
	conformance 721, R3 54. TRX files: /tmp/aauth-phase7-complete-release/;
	console log: /tmp/aauth-phase7-complete-release.log.
- Fresh-service full Playwright suite: 49 passed, one live-Keycloak-only skip,
	zero unexpected/flaky results, retries=0. CI=1, isolated HOME, explicit stub
	policy; /tmp/aauth-phase7-browser.json and /tmp/aauth-phase7-browser.log.
- Focused HTTP source lifecycle: five conformance cases in the final suite;
	/tmp/aauth-phase7-http-lifecycle/ contains the initial four-case pass and
	/tmp/aauth-phase7-adversarial/ adds the real middleware same-auth-jti case.
- Focused R3 source denial: 1/1, /tmp/aauth-phase7-r3-revocation/.
- Shipped Calendar revocation: 1/1, /tmp/aauth-phase7-calendar-revocation/.
- Editor diagnostics clean for touched core paths; CRLF-aware diff check passes;
	active source/docs have no removed bare-jti APIs; spec snapshot diff is empty.

Earlier Phase 5/6 work and test evidence remain untouched. The final count adds
20 tests to the owner-reported 1573 baseline. Git's full dirty diff includes
earlier phases and must not be attributed to Phase 7. This worker added
TokenKey.cs, TokenRegistration.cs, TokenGrant.cs, RevocationClient.cs,
TokenInventoryTests.cs, and RevocationLifecycleTests.cs; all other phase edits
modified existing files, including previously untracked AuthTokenResponse.cs.
The replay/revocation guide now states the complete typed store contract and
removes the old nontransactional Redis sketch.

No durable backend, restart-safe delivery, background retry worker, or live
Keycloak pass is claimed. Those operational limits are explicit: in-memory
records expire with bounded retention, incomplete cascade returns failure, and
unreached resources are bounded by token lifetime. The phase did not edit source
account contracts, caches, consent isolation, or either app's account workflows.

### [2026-09-09] [Phase 5] Generation-bound browser decision repair - PROCEEDED

The focused P1 review is confirmed by two deterministic barrier tests: renewal
after code lookup accepted the consumed old code, and renewal inside person
authorization returned an old decision as valid. Both tests failed before the
repair and pass after code and generation rechecks under synchronization.

Browser decisions now carry a single-use `BrowserConsentDecision` artifact.
Its `ApplyAsync` acquires the lifecycle gate before the async browser gate,
revalidates generation and availability, and holds both through the actual host
mutation. Renewal takes only the browser gate when called directly; lifecycle
callers already own the lifecycle gate first. No monitor spans an await.
Host callbacks must not reacquire either gate or call locking pending-store
methods. PS, federated AS (including Keycloak callback errors and claims), R3,
and resource-managed Inbox are being migrated together. Phase 7 inventory,
revocation, and tracked-delivery behavior remain unchanged.

Phase 11 contract inventory: `DecideAsync` returns a decision artifact instead
of a bare pending ID; `BrowserConsentDecision.Id` identifies the entry and its
sync/async `ApplyAsync` overloads guard the entire mutation. `BrowserInteraction`
uses an async-compatible semaphore with lifecycle-before-browser ordering.
Resource-managed parking shares its emitted code with `BrowserInteraction.Code`
and exposes an init-only `InteractionPendingEntry.Browser` for that binding.
The callback contract requires bounded, cancellation-aware work and prohibits
gate re-entry. Final host and regression counts will be appended after execution.

### [2026-09-09] [Phase 5] P1 browser renewal race final disposition - RESOLVED

The confirmed P1 code-consumption and decision-application races are repaired
across the shared utility and every shipped browser host. The consumed-code
regression now pauses the real PS `GetByCode` result, renews, and resumes to
`invalid_code`. A second barrier renews inside person authorization and rejects
the old decision. Additional HTTP barriers pause after `DecideAsync` but before
`ApplyAsync`: stale approval, denial, and cancellation cannot mutate the renewed
generation, and the fresh generation can still be approved. Cancellation that
owns the lifecycle gate first rejects all three queued decisions. An async
mutation test proves lifecycle ownership across its await and rejects replay
of the same artifact. Nine regression cases were added to the prior 1593 total.

PS mission decisions, standing consent and asserted identity, AS stub decisions,
Keycloak backend errors/denial/claims transitions, R3, and Inbox all apply through
the generation-bound artifact. Browser hosts no longer call bare-ID locking
store mutators. The PS consent bridge also evaluates the current scope and
applies its read-time standing-consent approval under one lifecycle acquisition;
it cannot carry an old scope check across renewal. Non-browser store contracts
remain available. Existing Phase 7 inventory and revocation paths were preserved.

Validation actually run:

- Initial deterministic reproduction: 2 failed as expected before the repair;
	both passed after the serialized rechecks.
- Browser session suite: 27/27 passed; subsequent combined PS/race suite 44/44.
	Evidence: /tmp/aauth-consent-race-focused/.
- Affected core host/lifecycle suite: 44/44; federation/revocation: 57/57; R3
	access endpoint suite: 31/31. Evidence: /tmp/aauth-consent-race-hosts/.
- Full Release solution build passed with zero warnings/errors. Full Release
	tests: 1602 passed, zero failed/skipped (827 core, 721 conformance, 54 R3).
	Evidence: /tmp/aauth-consent-race-release/. Final formatting-only PS/AS edits
	were followed by passing focused PS and Keycloak host tests.
- Fresh-service full browser suite: 49 passed, one live-Keycloak-only skip,
	zero unexpected/flaky results. Both primary apps ran with `CI=1`, isolated
	HOME, explicit stub policy, full traces, and `retries=0`. Evidence:
	/tmp/aauth-consent-race-browser.json and /tmp/aauth-consent-race-browser.log.
- Touched-file editor diagnostics and diff whitespace checks passed; the spec
	snapshot diff is empty. No delegate, commit, or branch operation was used.

No known generation race remains in the shipped consent handlers. The
synchronization contract is per-process: custom stores and callbacks must use
the same pending entry/lifecycle and acquire lifecycle before browser, and must
not re-enter locking store APIs from `ApplyAsync`. Async callback work holds
both gates, so cancellation/renewal waits for that bounded work; no monitor is
held across an await. Distributed atomicity, external side-effect rollback, and
live Keycloak validation are not claimed. Phase 11 retains the ergonomic/API
inventory from the preceding entry; broader fluent composition is not part of
this focused repair.

### [2026-09-09] [Phase 8] Account binding execution - PROCEEDED

The owner now authorizes Phase 8 only, superseding the worker-handoff blocker
below. No delegation, commits, branch changes, or compatibility aliases.
Protocol [L2055](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2055)
and [L2057](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2057)
(`#account-binding`) require resource-selected opaque strings to survive issuance;
R3 [L379](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L379) requires the same
value in the document. Use optional typed `string? Account` properties, exact
ordinal comparisons, and no accountless/wildcard lookup fallback. Only resources
interpret or authorize their account namespace. Verifiers need an independent
resource expectation before they can establish account binding. The existing
browser decision generation gates remain intact. Phase 11 retains broader fluent
API alignment; necessary account options are exposed during this phase.

### [2026-09-09] [Phase 8] Account APIs and security boundaries - RESOLVED

The public contract is optional `string? Account`, with shared `AccountBinding`
validation and ordinal equality. SDK policy rejects empty/whitespace-only strings,
JSON null/non-strings, and control characters; it does not trim, case-fold, parse
email addresses, or assign meaning to the resource namespace. Absence remains
absent. Resource and auth builders, verified readers, PS identity requests, AS
policy requests, pending resource snapshots, federation delivery, R3 documents,
proposals, grants and issuance audit retain the value. R3 vocabulary expansion
remains untouched for Phase 9.

Phase 11 API inventory:

- `AccountExpectation` explicitly represents an independent resource expectation,
	including expected absence; both sync and JWKS auth verification accept it.
	A null expectation means no account-binding assertion. Resource middleware with
	`ResourceIdentifier` expects accountless tokens unless `ExpectedAccount` selects
	an account from resource-owned routing. It never takes that expectation from
	the incoming token. `AccountVerified` is false for absent accounts or absent
	resource expectations; only a positively bound account becomes `aauth:account`
	through `AAuthAuthenticationHandler.AccountClaimType`.
- `AAuthResourcePipelineOptions.AccountSelector` feeds both verification and
	challenge issuance. Lower-level options are `ExpectedAccount` and
	`RequestedAccount`. `AAuthAuthorizationRequest.Account` validates the JSON
	request; resources reject unknown identifiers in their own namespace.
- `AAuthRequestOptions.Account` binds local credential selection and exchange;
	it is not a wire header. The sample places selection in the signed target URI;
	proactive authorization carries it in JSON. `ResourceIdentifier` overrides the
	client's origin default for path-scoped resource audiences. `PresentedToken`
	records the actual final signed carrier for diagnostics, never a trust verdict.
- `TokenExchangeRequest.Account`, `AccessServerRequest.Account`, and
	`CallChainingHandler.ExchangeForDownstreamAsync(account: ...)` preserve explicit
	selection. Upstream and downstream account namespaces are not conflated;
	`UpstreamTokenValidationResult.Account` exposes only the verified upstream
	claim. A downstream resource token and its delivered auth token must match.
- Opaque stores use exact `(origin, account, signing-key)` identity. Resource-side
	resolution checks the bound key and `expectedAccount`; parked interactions
	retain `Account`. Auth-carrier selection checks resource, account, current agent,
	signing key and expiry, with no accountless credential fallback. This remains a
	single-slot carrier cache: switching may obtain a new token rather than retain
	an unbounded per-account cache. Refresh cannot replace a token's account.
- Mission prior consent uses `(mission, resource, scope, account, agent, key)`.
	Sample standing consent adds account and bound key; sample mission intent uses
	a structured resource/scope/account key. No absent-account or absent-key entry
	matches a selected account or bound key. Admin consent fixtures now supply the
	actual key; no old keyless fallback was added.

Account-changing clarification replacements are rejected before pending state
mutation: start a new authorization and new consent. Existing browser session,
CSRF, generation, lifecycle and decision gates are retained. A targeted test
also reproduced a stale mission-consent defect: identity denial wrote `Granted`
and the next request took `PriorConsent`. Grant logging now occurs only after
successful identity assertion and tracked issuance, in immediate and deferred
paths; the failing test and neighboring mission tests pass after the repair.

Both primary apps use Bookings' resource-owned configurable accounts endpoint,
defaulting to Personal and Work reservations only in the sample. Selectors retain
the same person and agent across account changes. The previous-grant action sends
the actual old credential to the new account and receives 401; selecting Work
then denying consent cannot make the next Work request silent. GuidedTour keeps
its 14-step plan and account-aware payload/snippet display. R3 display uses the
resource's human-readable account name, not a PS interpretation.

Intermediate evidence before the final consent-ordering repair: `make build`
and Release build had zero warnings/errors, 1649 Release tests passed (861 core,
726 conformance, 62 R3), and a full fresh-service browser run passed 51 with one
Keycloak-only skip and zero retries. These counts are superseded by the final
gate recorded below. The initial browser startup failed on an old persisted AP
key lacking v10 `alg`; no user key was changed. Successful runs use a fresh
isolated HOME, shared package/browser caches, `CI=1`, and retries=0. One initial
SampleApp event was lost during Blazor hydration; the test now waits for the
server-rendered selected-account attribute and uses the existing click helper.

### [2026-09-09] [Phase 8] Final implementation and gates - RESOLVED

Phase 8 completed directly with no delegation, commits, branch changes, vendored
specification changes, or backward-compatibility aliases. Only Phase 8's plan
gates were completed. The prior Phase 8 handoff blocker is superseded by this
owner-authorized single-phase execution.

Final validation, after all runtime changes and the stale mission-consent repair:

- `make build`: succeeded, zero warnings and zero errors.
- `dotnet build AAuth.slnx -c Release`: succeeded, zero warnings and zero errors.
- `dotnet test AAuth.slnx -c Release`: 1667 passed, zero failed/skipped:
	864 core, 741 conformance, 62 R3. This adds 65 tests to the supplied 1602
	baseline, alongside account-bound variants of existing R3 delegation tests.
- `npm run typecheck` under tests/e2e: passed.
- Full Playwright run with fresh services, isolated HOME, `CI=1`, and
	`--retries=0`: 51 passed, one Keycloak-only skip, zero failures/flaky tests,
	52 total. Both new multi-account tests passed. Selected-account per-call
	approval also passes in both apps, including the resource-authored account
	name at the R3 consent screen and the account in the executed result.
- Focused signed tests cover malformed/null/non-string resource accounts,
	exact AS delivery, wrong account/missing account/unknown account, direct and
	deferred opaque grants, account/key-separated consent and caches, refresh,
	mission intent/prior consent, independent resource proof expectations,
	R3 document mismatch, approved-proposal reuse, and chained/sub-agent delivery
	with a distinct upstream resource account namespace.
- Mobile SampleApp and desktop GuidedTour screenshots from the browser tests
	were inspected. Selectors, action controls and visible results render without
	overlap. No visual redesign or unrelated CSS changes were made.

Evidence is retained in `/tmp/aauth-phase8-build.log`,
`/tmp/aauth-phase8-release-build.log`, `/tmp/aauth-phase8-release-tests.log`,
`/tmp/aauth-phase8-final-browser.json`, and
`/tmp/aauth-phase8-final-browser.log`. Browser screenshots are in the test-results
directories as `accounts-mobile.png` and `accounts-desktop.png`.

No Phase 8 implementation requirement is deferred. Live Keycloak mode and live
external interop were not established by the stub browser run and remain
unverified environment coverage. The Keycloak-only skip is reported, not counted
as a pass. Existing browser consent generation gates passed with the full suite.
Phase 11 retains the public API inventory above; no Phase 9 vocabulary, Phase 10
Events, or Phase 11 fluent-API work was taken on.

### [2026-09-09] [Phases 6-8] Adversarial proof and final gates - RESOLVED

All four findings in the supplied review have implemented and tested
dispositions. These repairs do not claim completion of Phase 9 or later phases.
No delegate, commit, branch change, dependency upgrade, or spec edit occurred.

1. Federated mission gate: four initial endpoint regressions returned `200`
	 for terminated or denied missions before the repair. The shared
	 `ReviewMissionAsync` now enforces termination, exact resource/scope/account/
	 agent/key prior consent, and `IMissionTokenConsent` before federation or
	 identity assertion. Both issuance modes use the existing mission pending
	 resolver. Tests cover immediate and claims-request AS policies, clarification
	 and interaction holds, authenticated browser approval, approval reuse for the
	 same resource token, and termination while either authority waits. A changed
	 resource token requires review again. Claims release and delivery recheck
	 mission state. Optional absent scope is admitted as the exact empty scope
	 rather than producing `502`. Basis: protocol [P1438](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1438)
	 (`#mission-log`) and [P1449](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1449)
	 (Mission Management). Proof: [DeferredFederationTests](../../../tests/AAuth.Conformance/Person/DeferredFederationTests.cs).
2. Reusable chaining cache: four real HTTP builder tests initially expected two
	 challenge/exchanges but observed only one, proving reuse after upstream
	 agent, directed subject, scope, or mission changed. The request snapshots
	 its upstream JWT once; the holder atomically retains that exact JWT plus
	 the request mission header with the issued carrier. Reuse still checks
	 resource, account, agent, key and expiration. The same context reuses its
	 grant; each changed context exchanges again. The cache is not partitioned
	 merely by `act`. Proof: [ReusableChainingTests](../../../tests/AAuth.Conformance/CallChaining/ReusableChainingTests.cs),
	 4/4 passing against Kestrel and the actual PS endpoint.
3. Upstream revocation: five signed multi-host tests initially allowed revoked
	 upstream extension, delivery after consent, or downstream resource reuse
	 after revocation. Verified upstream `(iss,jti,exp)` now joins source
	 registrations in both the three-party and shared federation/AS issuance
	 contexts. Registration rejects known revoked tokens; tracked issuance checks
	 revocation before invoking mint, then atomically registers dependencies
	 before releasing the grant. Cascade follows the upstream dependency.
	 Verification and trust precede registration, so legitimate previously unseen
	 upstream tokens remain admissible; no exhaustive issuer inventory is
	 required. A sixth regression independently proved and repaired the
	 before-mint check. Direct-AS deferred revocation is also covered. Proof:
	 [RevocationLifecycleTests](../../../tests/AAuth.Conformance/Discovery/RevocationLifecycleTests.cs)
	 and [TrackedIssuanceTests](../../../tests/AAuth.Tests/Server/TrackedIssuanceTests.cs).
4. Direct no-mission AS chaining: initial independent tests reproduced `404`
	 from person-metadata discovery and `401` from the agent-JWT AS request.
	 Upstream role now selects access metadata for this route. The AS verifies
	 the intermediary agent carrier, requires its own no-mission upstream token,
	 and validates upstream audience plus downstream resource audience, agent,
	 key, account and mission constraints before policy. Captured wire assertions
	 prove access metadata only, `sig=jwt`, `upstream_token` in the body, and no
	 body `agent_token`. Body-agent spoofing is rejected. Deferred GET/POST/DELETE
	 binds issuer, subject and key; a PS cannot take over an agent-owned request.
	 Intermediaries cannot push PS identity claims. PS federation remains
	 `jwks_uri` with its separate owner and claims path. Basis: protocol
	 [P1792](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1792) and
	 [P1796](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1796)
	 (`#call-chaining`). Proof: 15 `DirectAs*` cases in
	 [DeferredFederationTests](../../../tests/AAuth.Conformance/Person/DeferredFederationTests.cs).

Phase 11 contract inventory:

- `AccessPendingEntry.OwnerAgentIssuer` and `OwnerAgentSubject` are new nullable
	persisted owner fields for direct intermediary requests. `OriginPersonServerHost`
	remains the PS-only identity; `OwnerKeyThumbprint` binds either request kind.
- `AgentIssuanceContext.SourceTokens` now includes verified upstream auth tokens,
	not only parent/child agent tokens. Pending stores and inventory implementations
	must preserve those issuer-qualified dependencies and expiry ceilings.
- `TokenExchangeClient.ExchangeAsync` and `WithCallChaining` keep their public
	signatures. Upstream mission/role selects person versus access metadata; a
	direct intermediary supplies its agent token only through `Signature-Key`.
- `AAuthTokenHolder` keeps its public API. Internal request snapshots and atomic
	carrier/context publication enforce upstream and mission isolation. This is
	not a claim of a general concurrent-client contract redesign.
- The PS federation mission completion source and review result are internal;
	browser decisions continue through the existing authenticated lifecycle.
- `AuthTokenResponse.CreateTrackedAsync` now checks known revocation before mint
	and retains the atomic post-mint source registration. `IMissionLog` lookups
	support empty scope, preserving absence instead of inferring a default.

Both primary apps' existing call-chain/federation descriptions and GuidedTour
snippets now distinguish direct AS routing, agent carrier versus body upstream,
shared mission consent, and context-bound cache reuse. The sample asserter's
documentation states that mission identity assertion follows the SDK gate in
both issuance modes. Their existing PS-routed demos need no new numbered steps,
indices, or navigation. No unrelated Phase 9 sample changes were made.

Final validation:

- `make build` and `dotnet build AAuth.slnx -c Release`: zero warnings/errors.
- `dotnet test AAuth.slnx -c Release --no-build`: 1704/1704 pass, zero skips or
	failures: core 865, conformance 777, R3 62. This is 37 more tests than the
	recorded Phase 8 baseline. Evidence: `/tmp/aauth-four-fixes/final_*.trx` and
	`/tmp/aauth-four-fixes-release-final.log`.
- The first full Release run found two coupled failures: the shared mission
	review lost the `PriorConsent` audit reason, and AS negotiation still expected
	only `jwks_uri`. The audit reason was preserved and the expected supported
	scheme list updated. Both focused regressions and the final full suite pass.
- Browser TypeScript checking passes. Full fresh-service browsers used isolated
	HOME, `CI=1`, full traces and retries zero: 51 passed, one Keycloak-only skip,
	zero unexpected failures, zero flaky tests, zero runner errors. Evidence:
	`/tmp/aauth-four-fixes-browser.json` and its `.log`; both project retry counts
	are zero. This full run includes the relevant call-chain, mission, federation,
	account, sub-agent and R3 scenarios in SampleApp and GuidedTour.
- Touched-file diagnostics and whitespace checks pass. Repository-wide
	`git diff --check` reports pre-existing whitespace in untouched SampleApp
	layout/startup/project files; those edits were preserved.
- Existing Phase 9 R3 changes and the untracked `R3TransportOwnershipTests.cs`
	remain untouched. Their presence was checked before edits and after the gates.

The four reviewed implementation findings are resolved. Live Keycloak remains
unverified: the current sample configuration points to
`http://localhost:8080/realms/aauth`; its discovery probe failed to connect
(HTTP 000). The historical `localhost:18080` observation is not reused as current
evidence. A running configured realm and a `KEYCLOAK_E2E=1` policy-mode run are
still needed; the 51 stub-mode browser passes do not establish live IdP behavior.

### [2026-09-09] [Phase 9] Adversarial repair evidence - PROCEEDED

The five-finding report was read in full and each defect was independently
reproduced by a failing executable regression before its repair. Preserve the
current Phase 10 implementation and its recorded 1843-test baseline. No delegates,
commits, branch changes, generic AS endpoint changes, or Events body edits.
Earlier completion entries remain historical; this entry records their focused
follow-up and does not assert whole-repository conformance.

| Finding | Reproduction | Repair and focused evidence |
|---|---|---|
| R3 AS accepts non-PS roles | Six signed HTTP requests using distinct non-PS keys at the trusted PS origin returned 200; two PS controls passed | Require verified `ParsedKey.Dwk == aauth-person.json` as well as scheme and identifier trust. Eight role cases pass; GET/DELETE pending guards and an alternate key falsely claiming PS role are tested. Generic AS is untouched. |
| OData multi-method grants reject GET | Both direct and conditional GET requests under GET/POST grants failed | Directional method containment applies only to OData grants. Exact identity remains separate; proposals carry the actual GET operation, not the broader grant. POST retry, wrong operation/vocabulary and omitted-method widening are rejected. |
| Custom identity depends on member order | Reordered region/task object failed the existing custom validator | Schemas declare the identifier member before parsing. All other custom members remain intact, including standard-looking names and non-string values. Document, proposal, request and claim consumers use the same selected schema. |
| Empty parameter object rejected | Enforcement and proposal schema rejected `{}`; missing/null controls failed as expected | Present empty dictionaries are accepted. Missing/null remain invalid for proposals and conditional invocation. Approved retries reject added parameters. Signed HTTP AS requests exercise empty/nonempty objects and null/array/number/string failures. |
| Malformed credential values escape | Signed requests reproduced uncaught JsonNode string conversion exceptions | Check JSON value kinds for agent/resource/subagent/upstream credentials before conversion. All 12 object/array/number cases return 400 invalid_request without audit or issuance. |

Specification text was reread directly: protocol
[L1603](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1603)
(#ps-as-federation); R3
[L117](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L117)
(Standard Vocabularies),
[L275](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L275)
(#odata-vocabulary), and
[L562](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L562)
(Proposal Document under #per-call-proposals).

Phase 11 API handoff: `R3OperationIdentity.Covers` is directional grant coverage;
`Matches` retains exact qualified identity. Custom registration now accepts
`R3VocabularySchema(IdentifierMember, Validate)` instead of a bare validator.
Use `R3VocabularySchemas.CreateJsonOptions(vocabulary)` for standalone custom
deserialization and `R3Request.ReadOperations(body, schemas)` for request bodies.
Existing document/proposal/claim readers select schemas automatically from the
enclosing vocabulary. Custom qualifiers belong in Extensions, not the standard
typed qualifier properties. No property-order or reserved-name inference fallback
is retained. `parameters: {}` is now valid; missing/null is not.

Focused Release R3 suite: 206 passed, zero failed/skipped, up from 142. The
existing empty-parameters rejection assertion was updated to accept empty and
reject null. The pending HTTP fixture initially hit the required one-minute
per-issuer JWKS attempt floor; after two rejected interval overrides, the owner
approved continuing with an injected discovery clock. Advancing that clock
isolates role authorization without changing production discovery policy.
Editor test discovery was unavailable, so dotnet test executed the regressions.
Full Release solution tests/build, R3 browser tests, and final scoped review
remain pending at this entry.

### [2026-09-09] [Phase 9] Adversarial final review and gates - RESOLVED

All five reported defects are independently reproduced and repaired. Final
scoped review reread the verified-role predicate, credential extraction, selected
schema converter and consumers, directional OData coverage, and exact proposal
operation/parameter checks against the vendored requirements cited above. No
additional defect was found in that reviewed slice; zero of the five reported
findings remain open. This is a self-review under the owner's no-delegation
constraint, not an independent reviewer or whole-spec conformance claim.

- Full Release solution tests: 1907 passed, zero failed/skipped. Core 865,
	conformance 777, R3 206, Events 59. The Phase 10 baseline of 1843 is retained
	with 64 additional R3 cases. Evidence: /tmp/aauth-phase9-adversarial-tests.log
	and /tmp/aauth-phase9-adversarial-tests/*.trx.
- Full Release solution build: zero warnings/errors. Evidence:
	/tmp/aauth-phase9-adversarial-build.log.
- Both primary R3 browser specs: six passed, zero skipped/unexpected/flaky,
	fresh services, isolated HOME, CI=1, retries=0, trace=on. Evidence:
	/tmp/aauth-phase9-adversarial-browser.json and .log, plus the Playwright
	traces under tests/e2e/test-results/.
- Scoped whitespace checks and touched C# and plan/log editor diagnostics pass.
	Existing unrelated worktree changes were neither reverted nor reclassified.

Review dispositions: PS roles are verified through distinct metadata/JWKS keys,
not supplied feature stubs; endpoint regressions use signed HTTP requests through
the complete TestServer pipeline. Browser tests additionally execute real sample
network flows. A custom schema cannot replace a standard vocabulary; its declared
identifier is stable regardless of member order or standard-looking field names.
Missing optional qualifiers do not widen grants. OData containment never expands
an approved per-call proposal. An empty parameter object is concrete; missing/null
and added retry parameters remain rejected. A document without a parameters field
remains a class document at the AS, not an invalid proposal inferred from its URL.

The generic AS/direct-AS endpoints, Events body implementation, and all Events
tests are unchanged by this repair. Only the six requested R3 browser cases were
rerun, not the earlier full Events/browser ledger. Production/custom vocabulary
policies, external interop, Keycloak, and prior storage/deployment limitations
remain outside this focused gate. No new package or compatibility shim was added.
The old demo stack was stopped for fresh browser verification; its state directory
was preserved, and the demo is restarted with a new isolated HOME so old ephemeral
key/enrollment caches are not mixed with fresh service keys.

### [2026-09-09] [Phase 12] Security closure and executable scenarios - PROCEEDED

Implement the full approved Phase 12 scope on the existing worktree without
commits, branch changes, nested delegation, compatibility paths, or vendored
specification edits. Preserve the 1967-test, 56-browser and 17-snippet historical
Phase 11 evidence; rerun gates after Phase 12 changes instead of inheriting a
pass. Phase 13 final documentation remains separate.

First discriminating check: mapper HTTP requests referencing an unknown mission
must fail before permission, audit or interaction policy can act. The local
mapper currently treats a missing store result as a usable context. Add focused
regressions first; this is a security-policy check, not an invented wire MUST.
Review ownership with the configured verification pipeline next. Build
capability-scenarios.md and conformance-ledger.md from actual code and tests,
keeping deployment responsibilities and unverified cases explicit.

### [2026-09-09] [Phase 12] Governance boundaries reproduced - RESOLVED

The first manual substantive edit added three unknown-mission HTTP regressions;
the immediately attempted editor test adapter discovered no tests. The same
dotnet filter then failed all three (200 permission/interaction, 201 audit).
The shared mapper repair passed all nine tests. A shared authorization guard
now rejects missing verified agent context, unknown missions, foreign agents
and wrong approvers before callbacks, then applies terminated-mission handling.
The sample PS uses the same guard. Focused mapper/deferred tests passed 38;
signed sample-host consent/ownership tests passed 24, including twelve new
invalid-context cases with no log or mission-state mutation. Artifacts:
/tmp/aauth-phase12-governance.log and /tmp/aauth-phase12-mission-http.log.

The reusable deferred mapper also lacked owner context and atomic delivery.
Its entries now carry verified issuer/agent/key, retain terminal lifecycle state,
support owner-bound DELETE, recheck mission status and keep the first decision.
The existing 38 mapper/deferred controls pass after this repair; new race and
foreign-poller regressions are being run separately. The in-memory provider is
not a durable production guarantee. Protocol L1128 (#permission-request), L1455
(#mission-status-errors), and L2880 (#ps-security) establish the signed and
access-control requirements; invalid_mission is a local fail-closed disposition,
not a newly claimed specification error code.

### [2026-09-09] [Phase 12] Wallet scenarios and first browser findings - PROCEEDED

Reuse Wallet for travel-budget review and grant revocation; reuse Concierge for
its existing travel orchestration purpose with a wallet-read direct-AS route.
Neither operation belongs in Bookings. A shared Razor library supplies both
primary apps' three selectable Wallet flows, numbered steps, sequence rows,
SDK snippets and actual HTTP evidence. The AS review asks clarification before
the configured stub/Keycloak policy. The PS withdrawal verifies the requesting
agent owns the Wallet grant, then signs issuer-qualified revocation to Wallet.
Direct delegation only extends a verified no-mission wallet.read upstream
grant for the configured Concierge/Wallet origins. Missing sub remains missing;
when present, the downstream subject is independently derived for the resource.

The first fresh-service, no-retry browser run passed both clarification and both
cancellation cases, and failed both direct-chain and both revocation cases.
The chain policy incorrectly required optional sub; corrected after inspecting
the actual upstream claims. Revocation's first request succeeded, but an
immediate identical retry hit the permitted replay cache. An experimental signed
nonce passed its uniqueness check but was withdrawn after rereading protocol
L2507 (#freshness-and-replay), which defines no nonce mechanism. The sample now
waits one second before repeating the signed operation; created remains current
and replay protection is unchanged. Four exact signer-input fixtures caught the
experimental change; no altered fixture expectations remain. GuidedTour dark
host screenshots also exposed contrast/column-width defects in the shared page;
the local surface now supplies an explicit readable background and text colors.
Evidence: /tmp/aauth-phase12-wallet-browser.json and retained Playwright traces.

### [2026-09-09] [Phase 12] Catalog selection and security closure checks - RESOLVED

Catalog is the only new resource process (localhost:5006): two read-only travel
catalog services, both named list in their own OpenAPI definitions. Its
OpenAPI Gateway service map, explicit R3 challenge, AS/PS document readership
and service-qualified enforcement demonstrate the new gateway capability without
adding unrelated features to Bookings. CapabilitySupport is a shared Razor
library, not another server. Both apps have navigation, five numbered steps,
sequence associations, exact snippets, sibling-service rejection and recovery.
Four fresh-service Catalog browser cases pass with zero retries. Solution,
Makefile resources/demo/demo-keycloak, explicit loopback policy and the existing
CI-discovered Playwright webServer/projects include it.

All eight R3 vocabulary models remain in scope and tested through roundtrip,
qualifier identity, conditional retry and OData subset cases. Native MCP/gRPC/
GraphQL/SOAP/OData hosting was not implemented by the migration and is not
advertised by the new HTTP resource. Their models are internal SDK contracts,
not evidence for nonexistent native server flows. Actual runnable integrations
are OpenAPI, OpenAPI Gateway and AsyncAPI. Third-party login hosting remains
optional application-owned behavior; a metadata field alone is not a login flow.

Additional confirmed security findings: the Keycloak adapter exposed arbitrary
IdP response bodies in two exception paths (both regressions failed, then passed
after bodies were removed). The PS permission poll could release a decision
after mission termination (200 reproduced, fixed with a delivery-time mission
guard). Real consent HTML and rendered TokenView tests reject executable markup.
Concierge pending routes accepted another valid grant's owner; they now bind
the exact upstream grant, expire with it and retain serialized terminal state.
Six signed-host foreign agent/key/grant GET/DELETE tests pass. The SDK's injected
distributed stores still owe cross-node atomicity; in-process DeferredState does
not certify arbitrary providers. Ledger responsibilities remain explicit.

Intermediate Release: 2005 tests passed (928 core, 800 conformance, 206 R3,
71 Events). Exact snippets now pass 21/21; activity diagnostics 7/7; IdP-body and
real consent encoding 3/3; final mission/rendered-input slice 29/29. First full
browser gate: 65 passed, one Keycloak-only skip, two existing sub-agent failures.
The new Wallet direct-AS policy was incorrectly applied to PS-mediated workers.
Restricting it to requests without PersonServerIssuer repaired the regression;
the policy test and all four existing-worker/new-direct-AS browser cases pass.
No failed result is reported as a pass. Final Release and complete browser
gates will be repeated after these repairs.

Phase 0 reconciliation: Q1-Q10 and execution authorization existed in the log
before implementation and are now checked in the plan. The pre-edit full
baseline evidence is incomplete; later gates do not reconstruct it, so that
historical checkbox stays open. Phase 5/6 environment checkboxes await this
phase's final live-policy run rather than rewriting their historical failures.

### [2026-09-09] [Phase 12] Final .NET gates and remaining live recovery failure - BLOCKED

The final .NET gates pass on the implemented code: Release solution build has
zero warnings/errors; Release solution tests pass 2023/2023 (946 core, 800
conformance, 206 R3, 71 Events), zero failures/skips. make build, test-unit,
test-conformance and test-events pass; explicit Release R3 tests pass 206/206.
Exact displayed snippet compilation passes 21/21. The current API inventory
contains 192 changed public-source files, +756/-146 declarations against
ba768f1, zero unmapped files; the non-writing freshness check passes. Artifacts:
/tmp/aauth-phase12-final-release-build.log,
/tmp/aauth-phase12-final-release-tests.log,
/tmp/aauth-phase12-final-trx/, /tmp/aauth-phase12-make-gates.log,
/tmp/aauth-phase12-r3-explicit.log and /tmp/aauth-phase12-snippets.log.

The most recent full stub browser run had 65 passes, one Keycloak-only skip
and two sub-agent failures. The concrete policy regression was repaired and
the four focused existing-worker/new-direct-AS cases passed afterward; a final
complete stub rerun has NOT been performed. Earlier focused runs establish
the twelve new stub browser cases, not a final whole-suite pass.

Live policy setup used the cached image and the repository realm, without any
download or replacement of user containers:

```bash
docker run -d --pull=never --name aauth-phase12-keycloak \
	-p 127.0.0.1:8080:8080 \
	-e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
	-v "$PWD/samples/MockAccessServers/Federated/keycloak:/opt/keycloak/data/import:ro" \
	quay.io/keycloak/keycloak:26.0 start-dev --import-realm
```

The imported realm is reachable. A fresh KEYCLOAK_E2E=1,
AccessServer__PolicyProvider=keycloak run of the twelve new cases plus the
existing live login case passed eleven and failed both Wallet revocation
recovery cases. This is a test/flow failure, not an unavailable environment.
The initial failure assumed a fresh username form even when Keycloak reused
the session. Three focused helper repair attempts still did not complete the
live flow. Trace inspection verified Keycloak 26 uses button[name=accept],
not input[name=accept]; correcting that selector did not finish the test, so
the callback/result state needs further diagnosis. No timeout was converted
into a pass or skip. Stop the repair loop for owner direction as required by
the editing workflow. Latest failing evidence:
/tmp/aauth-phase12-keycloak-recovery3.json and
/tmp/aauth-phase12-keycloak-recovery3-results/; the initial live set is
/tmp/aauth-phase12-keycloak-browser.json.

Phase 12 is NOT complete. Remaining gates include diagnosing both live
revocation recovery cases, repeating the final complete stub/live selections,
finishing the final visual/ledger review, and reconciling Phase 5/6 completion
with the final evidence. The historical Phase 0 baseline gap stays explicit.
The new resource and four selectable scenarios are implemented, with twelve
new browser cases and 56 additional .NET tests over the 1967 baseline.
No commit, branch change, nested delegation, compatibility layer, or vendored
specification edit occurred. Phase 13 remains separate and unchecked.
The test-owned Keycloak container remains running on loopback for diagnosis;
Playwright-owned sample services have stopped. The old demo was stopped for
fresh-service verification and has not yet been restarted.

### [2026-09-09] [Phase 12] Focused adversarial repairs in progress - PROCEEDED

The owner requested eight specific repairs, then the separate retained live
Keycloak recovery gate, without delegation, commits or branch changes. Catalog
and both apps' four new scenarios remain intact. Worker coverage remains in
scope; it is not owner-excluded. Phase 12 completion boxes remain open.

Findings 1-3 already have partial production repairs in the supplied worktree:
deferred governance owner issuer/key/agent binding, mission reload before grant,
and declined interaction `403 denied`. Thirty mapped-route tests now pass,
including new absent-verification GET/DELETE, foreign-issuer DELETE, terminated
mission permission delivery and changed-owner delivery. Both rejected deliveries
append no permission log record and become terminal. These are verification
stubs at the verification boundary; signed HTTP coverage remains to be checked.

Finding 4 reproduced with four failing approval-identity tests. MissionClient
now uses the policy-aware header parser and rejects missing approver, header/body
disagreement and a self-consistent foreign PS, retaining exact bytes and hash.
The controlling rules are protocol #mission-approval L1430 and mission-reference
exact matching L1492. Failure artifact: /tmp/aauth-phase12-repairs-mission-red.log.

Finding 5 reproduced with seven failing lifecycle tests. Mission state now has a
one-way internal transition; completion and terminal exceptions persist it, and
session requests/callbacks plus direct pre-approved permission check it. Protocol
#mission-status-errors L1469 requires the agent to stop acting. No public
signatures changed. The client/facade slice passes 29 tests. Failure artifact:
/tmp/aauth-phase12-repairs-lifecycle-red.log. The first mapper test compile exposed
a test-only nonexistent Blob property; retaining response bytes corrected it.
The VS Code adapter discovered no tests; focused dotnet test runs are used.

Findings 6-8 and live Keycloak recovery remain in progress. No full Release or
fresh-browser result from this repair run is claimed yet.

### [2026-09-09] [Phase 12] Eight-finding repair and live recovery evidence - RESOLVED

The owner-supplied findings were verified locally, not delegated. Findings 1-3
were already repaired in production by the prior writer; this pass added mapped
route regressions. Eight additional real signed HTTP GET/DELETE cases now verify
issuer discovery, foreign agent/issuer/key rejection and unsigned-request
rejection, then successful delivery to the original signer. Evidence:
/tmp/aauth-phase12-repairs-signed-pending.log. The governance/polling conformance
slice passes 192 cases, including declined PS-hosted interaction/payment and
no append after mission termination or changed ownership. Resource-hosted relay
completion remains distinct from resource authorization, as required by protocol
#interaction-response-poll-authority L1311. No PS grant is added to that path.

Findings 6-7 reproduced in five failing tests before repair. Approval/bare 202
responses poll without an agent user callback (protocol L2202); explicit
interaction still requires one. DeferredExchange and InteractionHandler dispatch
new URL/code pairs after approval and later interactions, without replaying the
original POST. Artifact: /tmp/aauth-phase12-repairs-deferred-red.log.

Finding 8 reproduced initial delta/date Retry-After failure at virtual time zero.
One poller retains its budget and linear five-second increases across ordinary
202 and interaction transitions. Both poll paths honor initial delays, dates,
429 and 503; callbacks and in-flight requests are bounded. Protocol #deferred-responses
L2262 is the polling MUST, distinct from the initial-response field's SHOULD.
Deterministic clock/delay tests cover exact cadence, elapsed timeout and caller
cancellation, with no sleeps. The latest timing/transition slice passes 12 tests.
Artifact: /tmp/aauth-phase12-repairs-timing-first.log. A nullable transport warning
from helper extraction was repaired and the same slice rerun without warnings.

Phase 11 API inventory additions are DeferredPollerOptions.TimeProvider and
InteractionHandler.TimeProvider (borrowed, System default). Mission.State retains
its existing public init contract. Internal lifecycle and delay helpers are not
new public APIs. The map is regenerated below with the final gate evidence.

The retained /tmp/aauth-phase12-keycloak-recovery3-results traces show successful
OIDC authentication, consent and HTTP 200 AS callback, but the outcome appeared
only in the HTML title, not visible page content. Three HTTP regressions failed
on the missing heading. InteractionHtml now encodes and renders the outcome.
Nine Keycloak integration/security tests pass. The original bypass protections
and all SDK verification remain intact. Artifacts:
/tmp/aauth-phase12-repairs-keycloak-red.log and
/tmp/aauth-phase12-repairs-keycloak-http.log.

Both live Keycloak revocation/recovery browser cases pass on fresh services and
isolated HOME/XDG settings: two passed, zero failed/skipped/flaky, retries=0.
They still require issuer-qualified revocation, rejection of the old grant,
a different fresh jti and successful resource access. Evidence:
/tmp/aauth-phase12-repairs-keycloak.json and
/tmp/aauth-phase12-repairs-keycloak-results/. The existing Keycloak realm at
localhost:8080/realms/aauth was reused; no container/image changes were needed.
Both apps share the updated recovery step and explicit consent-callback snippet.

The first full Release gate passes 2064 tests (core 961, conformance 826, R3 206,
Events 71), zero failures/skips, build zero warnings/errors. Artifacts:
/tmp/aauth-phase12-repairs-release-build.log,
/tmp/aauth-phase12-repairs-release-tests.log and
/tmp/aauth-phase12-repairs-tests/. Full stub/live browser suites, final snippets,
inventory and completion-box reconciliation still follow; those are not implied
by this focused recovery result.

### [2026-09-09] [Phase 12] Callback boundary and full live matrix follow-up - PROCEEDED

A final finding-5 boundary test reproduced a generic HTTP exception from the
clarification-answer POST when the PS returned mission_terminated. The shared
clarification POST/DELETE path now preserves the typed terminal error so the
session retains termination. Fourteen lifecycle/clarification tests pass.
Reproduction: /tmp/aauth-phase12-repairs-clarification-terminal-red.log.
Four virtual-timer tests also prove deadlines stop non-cooperative callbacks and
in-flight requests; all 14 deterministic timing cases pass without sleeps in
/tmp/aauth-phase12-repairs-timing-final.log.

The repeated final Release gate passes 2069 tests: core 965, conformance 827,
R3 206, Events 71, zero failures/skips. Build: zero warnings/errors. Evidence:
/tmp/aauth-phase12-repairs-final-build.log,
/tmp/aauth-phase12-repairs-final-tests.log and
/tmp/aauth-phase12-repairs-final-tests/. All 21 exact snippet templates pass.
The API inventory is current: 196 public-source files, +761/-149 declarations,
zero unmapped files against ba768f1.

Full fresh stub browsers passed 67 cases, one live-only skip, no failures/flaky
results, retries=0: /tmp/aauth-phase12-repairs-stub.json. The first full live run
loaded legacy stub-only AS/worker helpers. It was gracefully interrupted after
recording 45 passes, six failures and 17 unexecuted cases; the interrupted current
test is also retained. The failures were two tour AS consent timeouts, the tour
worker consent timeout, one browser page-setup timeout, and two SampleApp Catalog
r3_evaluation_failed responses. Report/traces: /tmp/aauth-phase12-repairs-live.json
and /tmp/aauth-phase12-repairs-live-results/. Transient failed expect retries
inside traces are not counted as failed tests.

AS/worker helpers now drive real Keycloak consent (including denial) under live
policy and retain the stub identity banner/CSRF flow under stub policy. Wallet
and the dedicated live case share the same callback driver. No tests were hidden,
skipped by new conditions, retried, or stripped of signed result assertions.
Worker coverage remains in scope. Five focused live AS/worker cases pass in
/tmp/aauth-phase12-repairs-live-focused.json. Four fresh live Catalog cases pass
in /tmp/aauth-phase12-repairs-catalog.json without SDK/resource changes; the prior
R3 evaluation failures are retained, not claimed to have a proven root cause.
The replacement full live gate is still required before closing Phase 12.

### [2026-09-09] [Phase 11] Post-repair public API inventory - RESOLVED

Regenerated and verified the Roslyn map against ba768f1 after all Phase 12
repairs: 196 changed public-source files, +761/-149 declarations, zero unmapped
files. New public timing properties are DeferredPollerOptions.TimeProvider and
InteractionHandler.TimeProvider, both borrowed and defaulting to System.
Mission.State keeps its public init-only signature and gains only an internal
one-way termination transition. Clarification terminal-error preservation and
mission approval identity validation are behavior changes, not additional public
entry points. Existing fluent composition, explicit trust and verification inputs
are unchanged. Exact snippet compilation passes all 21 templates, including the
fresh-grant recovery callback. TypeScript typecheck and the final Razor build pass.

### [2026-09-09] [Phase 12] Final adversarial and policy-mode gates - RESOLVED

All eight supplied findings are closed for the current implementation, with
individual reproductions and dispositions above. Findings 1-3 were already
repaired by the prior writer and received new mapped/signed route regressions;
findings 4-8 required production changes. The terminal clarification POST/DELETE
follow-up is included. No optional feature was converted into an invented MUST,
and no resource-hosted interaction acquired a PS authorization requirement.

Final Release: 2069 passed, zero failed/skipped (965 core, 827 conformance,
206 R3, 71 Events), 46 cases beyond the owner's 2023 baseline. Release build:
zero warnings/errors. Evidence remains at /tmp/aauth-phase12-repairs-final-build.log,
/tmp/aauth-phase12-repairs-final-tests.log and
/tmp/aauth-phase12-repairs-final-tests/. Focused virtual-clock tests prove initial
Retry-After, persistent linear backoff, date/default behavior, total budgets,
caller cancellation and non-cooperative callback/request deadlines without sleeps.

The replacement full live Keycloak suite passes all 68 tests (GuidedTour 38,
SampleApp 30), zero failures/skips/flaky results, retries=0. It uses fresh services,
isolated HOME/XDG settings and the existing imported Keycloak realm. Evidence:
/tmp/aauth-phase12-repairs-live-final.json,
/tmp/aauth-phase12-repairs-live-final.log and
/tmp/aauth-phase12-repairs-live-final-results/.

The repeated full stub suite on final source passes 67 tests (GuidedTour 38,
SampleApp 29), with only the existing live-Keycloak-only test skipped; zero
failures/flaky results, retries=0. Evidence:
/tmp/aauth-phase12-repairs-stub-final.json,
/tmp/aauth-phase12-repairs-stub-final.log and
/tmp/aauth-phase12-repairs-stub-final-results/. The previously interrupted live
report and its six failures are retained. Catalog succeeds in all four cases in
both replacement full suites; no R3/resource workaround or hidden retry was added.

Both new-app matrices retain the four scenarios, real callbacks, numbered steps,
sequence associations, exact snippets, rejection/recovery, reset/re-enrollment
and desktop/390px assertions. Final narrow screenshots for Wallet recovery in
both apps and Catalog were inspected; text fits and referenced images load.
Parent/worker claims and key rejection remain tested in both full policy modes.
Worker coverage is not owner-excluded.

The existing make demo entry point starts the final stack with fresh settings.
Both /wallet-protocol pages (ports 5400 and 5240) and Catalog metadata (5006)
return HTTP 200. Log: /tmp/aauth-phase12-repairs-demo.log. The demo remains running
in stub mode for use. Keycloak was reused without image/container modification.
No delegation, commit, branch change or vendor edit occurred; the branch remains
v09-spec-migration. Scoped diff whitespace checks pass. Existing whitespace in
untouched SampleApp files remains unchanged.

Only Phase 12 completion boxes are closed by this pass. The ledger's explicit
deployment responsibilities and unsupported optional capabilities are retained.
Phase 13 documentation finalization and Phase 14 final review are not claimed.

### [2026-09-09] [Phase 13] Complete documentation surface inventory - PROCEEDED

The owner authorized writes for the current Phase 13, preserving the completed
Phase 12 baseline of 2069 Release tests, 68 live browser cases, 67 stub cases
and one live-only skip, and 21 representative exact snippet compilation cases.
Expand the existing Roslyn harness, not a parallel snippet compiler. Inventory
all active root/package/sample Markdown and docs families, both primary apps'
literal/interpolated/raw/Razor code displays, shared capability/event displays,
dynamic payloads, navigation and diagrams. Record each surface and snippet's
actual validation or explicit explanatory-placeholder contract in a new
docs-surface-map.md. A sample build alone does not validate strings.

The worker will not delegate, commit, change branches or edit snapshot bytes.
That is this worker's execution constraint, not an owner prohibition on the
separate independent Phase 14 review. Keep Phases 14 and 15 open. Attempt the
existing external interop client when practical and distinguish external
availability from local protocol evidence. Update target-version claims only
after current runtime gates pass. Retain historical log entries; append explicit
superseding evidence for earlier blockers instead of rewriting their history.

### [2026-09-09] [Phase 13] Exhaustive snippet checks and first runtime gates - RESOLVED

Replaced the 21 representative-case boundary with discovered tour constants,
Razor C# displays, Markdown fences (including blockquotes), raw/multiline strings,
single-line step assignments, shared Wallet/Catalog/Events templates and dynamic
bindings. The existing Roslyn compiler is reused with real typed prior-step and
host inputs. API excerpts receive source member/type checks, not fake method
bodies. The generated docs-surface-map records every file and block with hashes,
locations and validation classes. External Azure Secrets/OTel/platform adapters
remain five explicitly illustrative templates, syntax-checked but not deployed.

The initial all-tour probe failed 24 of 42 constants; fixes included removed
exchange overloads, FileKeyStore.Load, immutable mission tool lists, invalid
builder chains and missing actual prior-step context. Subsequent full Razor and
Markdown probes exposed real stale key maps, token-holder names, protocol comments
and unsafe intermediary pending guidance. Those now use current owner-bound
atomic lifecycle handling. No SDK runtime API or compatibility alias was added.
The new Wallet and Catalog guides use the actual scenario steps and source tests.

Initial Release passes 2128 tests (1024 core, 827 conformance, 206 R3, 71 Events),
zero failures/skips, build zero warnings/errors. All 80 documentation test cases
pass; their count is distinct from block compilation counts in the surface map.
The first full stub run was 66 passed/one live-only skip/one failed; live was
67 passed/one failed/no skips. Both failures were the existing Bookings assertion
requiring its concrete SQLite audit example. Restore that useful example and
reference the actual R3 sample class from the compiler harness, rather than
weakening the browser assertion or replacing it with an opaque callback. All 25
Razor examples compile after repair. Replacement full browser gates follow.

Evidence: /tmp/aauth-phase13-snippets-initial.log, /tmp/aauth-phase13-release-build.log,
/tmp/aauth-phase13-release-tests.log, /tmp/aauth-phase13-release-trx/,
/tmp/aauth-phase13-stub.json, /tmp/aauth-phase13-live.json and matching logs/traces.
Earlier failure reports are retained. No delegates, commits, branch changes or
snapshot-byte edits occurred. The worker restriction is not an owner exclusion
of the independent Phase 14 reviewers.

### [2026-09-09] [Phase 13] External LiveWhoAmITest attempt - RESOLVED (partial)

The existing cloudflared binary and LiveWhoAmITest were run without installing
dependencies, supplying a person identity or approving external consent. Its
public tunnel became reachable on attempt five and was cleaned up normally.
Unsigned whoami returned 401 with jwt negotiation; unscoped agent JWT access
returned 200. Scoped access and the full three-party path returned 401 with
error=person_token_required and requirement=person-token. This is not the pinned
draft-10 auth-token challenge consumed by the SDK. The executable exits zero
even on that unsuccessful flow, so exit status is not treated as interop success.

External identity/signature interoperability is observed; external authorization
and the five-surface mission/sub-agent profile are not established. No backward
compatibility parser was added. Local mission/echo/discovery/grant/parent-worker
evidence is recorded separately and cannot substitute for this external result.
Evidence: /tmp/aauth-phase13-external-interop.log. The two-minute safety bound was
not reached. No tunnel or metadata server remains running from this attempt.

### [2026-09-09] [Phase 13] Final documentation and release gates - RESOLVED

Phase 13 is complete. The frozen-surface inventory contains 161 files and 615
blocks: 261 exact C# compilations, 33 source-checked API excerpts, one comment-only
narrative, 32 dynamic Razor displays, 162 inline labels/expressions, five explicit
external integration templates, five JSON blocks/fragments, 15 illustrative
text/HTTP fragments, 28 sequence/flow blocks, 69 shell blocks and four runtime SQL
literals. Every block has a hash, source location, disposition and owning
source/test links. Shell syntax and Make targets, HTTP JSON bodies/requirements/
absolute Locations, JSON parsing, and API member types/sealed modifiers have
repeatable checks. Dynamic rendering is covered by actual scenario browser and
captured-wire tests, not presented as static cryptographic fixtures.

All 80 documentation test cases pass. Local links/anchors across 71 Markdown
files pass; generated evidence links are included in the checked set. The map
is verified without its update flag in the final Release run. Five external
templates require Azure Secrets, OpenTelemetry or host platform APIs and are
syntax-only, not deployment/hardware passes. All known runnable C# fragments
compile with typed prior-step/host inputs; comments-only text is not counted.
Required frontmatter was limited to touched Markdown; spec tracking remains
without frontmatter per the repository-specific rule.

Final Release build has zero warnings/errors; 2128/2128 tests pass, no skips:
1024 core, 827 conformance, 206 R3 and 71 Events. No prior runtime tests were
deleted. `make build test-unit test-conformance test-events` and explicit Release
R3 pass. API inventory freshness: 196 changed public-source files, +761/-149
declarations, zero unmapped. All 26 immutable snapshot files were compared by
Git blob hash to HEAD and match byte-for-byte. Only SPEC-VERSION/CHANGELOG current
target framing changed; historical entries remain historical. Artifacts:
/tmp/aauth-phase13-final-build.log, /tmp/aauth-phase13-final-tests.log,
/tmp/aauth-phase13-final-trx/, /tmp/aauth-phase13-make-gates.log,
/tmp/aauth-phase13-r3-gate.log and /tmp/aauth-phase13-api-freshness.log.

Final full browsers are serial fresh-service runs with isolated HOME/XDG state,
CI=1, retries=0 and retained traces: stub 67 passed/one live-only skip, live
Keycloak 68 passed/no skips, zero unexpected/flaky results. Reports:
/tmp/aauth-phase13-stub-release.json and /tmp/aauth-phase13-live-release.json,
with matching logs and result folders. Desktop/390px Wallet and Catalog captures
show readable labels, step/sequence associations and no horizontal clipping.
The original Bookings display failure was repaired by restoring its concrete
SQLite example, not weakening the assertion. A replacement stub run overlapped
compilation and had browser/setup timeouts plus two R3 evaluation failures; an
accidental concurrent live launch was refused for occupied ports and ran zero
tests. Neither is counted as a pass. The 14 affected cases then passed on fresh
services without concurrent work, followed by both full successful suites.

Local interop S1-S5 is explicitly mapped in the ledger, including actual
distinct-key four-party worker flows in both apps. External identity access
passed but scoped authorization returned the incompatible live person-token
challenge; full external authorization/mission/sub-agent interoperability remains
unverified. No shim, person identity or external consent was supplied.

Phase 5/6's original live-IdP blockers are superseded by the recorded Phase 12
and repeated Phase 13 live evidence; their historical log entries were not
rewritten. Phase 0's missing pre-edit full baseline remains a historical evidence
limitation. No owner-wide prohibition on independent reviewers is introduced:
no delegation applied to this worker. Phases 14 and 15 remain unchecked and
separate. No commits, branches, merges, dependency upgrades or snapshot edits.

### [2026-09-09] [Phase 13] Demo readiness and completion integrity - RESOLVED

The final existing `make demo` entry point is running with fresh HOME and
XDG_DATA_HOME. SampleApp /wallet-protocol (5240), GuidedTour /catalog-gateway
(5400) and Catalog metadata (5006) return HTTP 200. The log is
/tmp/aauth-phase13-demo.log. The prior demo group was stopped by its verified
process-group ID; Keycloak was reused and not modified. The external tunnel
was cleaned up by LiveWhoAmITest.

Final map freshness and local links pass after the completion entries. The
phase-boundary check confirms all Phase 13 items are checked and Phases 14/15
retain unchecked items. Final browser JSON counts were asserted directly,
including zero unexpected/flaky results. These checks supplement, rather than
replace, the final Release and full browser gates above.

### [2026-09-09] [Phases 5-7, 12-13] Final auth repair continuation - PROCEEDED

Resumed after the interrupted write, preserving every existing modification and
running the focused mission check first: seven passed. Reread the current v10
resource verification/interaction and current PS/AS, pending, revocation and
diagnostic paths rather than treating the source-only report as current code.
The preserved repairs cover upstream mission retention; approval owner/approver
validation with verified parent/upstream delegation; actual PS approver binding;
resource permission before PS consent; deferred parent identity; transitive local
revocation with cycle-safe ancestry and concurrent registration; status-only
exceptions for unstructured AS failures. Sentinel tests capture actual PS logs.

Release build initially passed with zero warnings/errors. Focused conformance
passed 150 cases. The first Documents run had one pass and three browser timeouts
(one approval click and two page-creation timeouts) under exhausted host swap.
Stopped idle .NET build servers, without killing editor or user services. A
real adjacent host gap was fixed: ordinary PS consent must reject a still-pending
resource session. Both apps then passed all four actual Documents cases with
retries=0, including the new bypass check, success/denial, reset and layout.
Artifacts: /tmp/aauth-final-documents.json and
/tmp/aauth-final-documents-fixed.json, with matching results directories.

Added federated callback completion/denial and CSRF regressions: two passed after
correcting a test-helper name compile error. Invalid mission approval now fails
before opening resource permission; six invalid-approval cases include requests
with interaction. Combined PS/federation validation passes 144 cases. First full
Release run has only Documentation_FrozenSurface stale-inventory failure after
the new files; executable counts are 1026 core passes plus that failure, 851
conformance, 206 R3 and 71 Events. The report path is
/tmp/aauth-final-auth-tests.log. The shared TRX filename was overwritten between
projects; final gates will use generated unique filenames instead.

Documents is a real, single-purpose resource on 5007 with both app routes and
shared Playwright tests. It uses local owner permission, not simulated external
OAuth. Documentation and API inventories will be regenerated only after source
review. Phase 14/15 marks remain untouched; independent review is still required.
No delegates, commits, branches, dependency upgrades or spec snapshot edits.

### [2026-09-09] [Phases 5-7, 12-13] Final auth repair gates - RESOLVED

All seven reported authorization repairs have implementation and focused
regressions. Final full Release build: zero warnings/errors. Full Release tests:
2160 passed, zero failed/skipped (1027 core, 856 conformance, 206 R3, 71 Events),
32 above the supplied 2128 baseline. Evidence:
/tmp/aauth-final-auth-verified.log,
/tmp/aauth-final-auth-verified-trx/ (four distinct reports), and
/tmp/aauth-final-release-build-verified.log. Documentation_FrozenSurface passes
without update mode in this full run; all 80 documentation checks passed after
the reviewed regeneration. The inventory covers 169 files and 617 blocks,
including 261 exact compiled C# blocks. API generation and its non-writing
freshness check report 197 changed public-source files, +777/-149 declarations,
zero unmapped files, including the new Documents session and SDK contracts.

Full fresh-service stub browsers: 71 passed, one preexisting Keycloak-only skip.
Full live Keycloak browsers: 72 passed, zero skips. Both have zero unexpected or
flaky results, retries=0 and isolated HOME/XDG_DATA_HOME. This retains all 68
baseline live cases and adds four real Documents success/denial cases across
both apps. Reports: /tmp/aauth-final-stub.json and /tmp/aauth-final-live.json;
matching results directories retain traces and screenshots. Keycloak was reused
without container configuration changes. No simulated grant or OAuth provider
substitutes for resource permission, PS consent, signed polling or download.

After the full browser gates, screenshot review found a CSS-only contrast and
mobile actor-column issue. Local styles now override the tour's summary colors
and reserve full actor labels. The first contrast check passed four cases;
the final width check encountered one navigation stall and two page-creation
timeouts under exhausted swap (/tmp/aauth-final-documents-layout2.json).
After shutting down idle .NET build servers, the unchanged final code, assertions
and timeouts passed all four with retries=0 in
/tmp/aauth-final-documents-layout3.json. Final mobile screenshot inspected;
no overlap or horizontal document overflow. No editor/user process was killed.
These failures remain recorded rather than described as passing first attempts.

Scoped diff whitespace checks pass. The broader inherited migration diff still
reports whitespace in SampleApp NavMenu, Program and project files; those
preserved changes were not reformatted. No auth implementation/test blocker
remains in these seven findings. Independent review of the final diff and the
subsequent Phase 15 alignment remain open; no Phase 14/15 checkbox was changed.
External interoperability and arbitrary production providers were not certified.

### [2026-09-09] [Phase 14] Focused repair continuation and local proof - RESOLVED (runtime slice)

Resumed at clean HEAD 26732fe without delegates, commits or branch changes.
The initial focused Release run passed 10 discovery/replay tests; the API/signing
baseline passed 41. The editor test adapter found no tests, so filtered dotnet
test runs supplied executable evidence. The ES256 alternate-signature repair
and its crypto-valid regression were already committed in 75980b2: the verifier
uses the verified canonical base plus key thumbprint. No duplicate runtime fix
was applied. Additional same-key label-selection and distinct covered-value
regressions pass within 56 wire/adversarial cases. This implements the optional
cache under protocol #freshness-and-replay,
[L2507](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2507),
without treating an unsigned selection label as a new request identity.

Discovery root-object and dot-segment checks were already committed in 50a205d.
Ten new field/shape cases exposed seven failures: malformed metadata endpoints
were ignored, and malformed JWKS structure became unknown_key. Metadata URL
fields and JWKS keys/member/kid shapes now fail at the discovery client before
caching; JSON parse failures are also typed invalid_key. Unselected unsupported
key algorithms remain usable alongside supported selected keys. All 16 HTTP
discovery cases pass, preserving protocol #verification
[L2479](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2479)
and #jwks-discovery
[L2515](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2515).
Evidence: /tmp/aauth-phase14-discovery-red.log and
/tmp/aauth-phase14-discovery-green.log, with matching TRX directories.

The per-request AgentTokenSourceHandler and current-PS provider were already
committed, but UseJwt(Func<string>) still captured the first token at selection.
A failing test proves eager capture; the repair removes that snapshot so Build
uses current claims, while the source handler continues updating per request.
The existing source/account/key/mission-bound carrier selection is preserved.
All 34 factory/composition tests pass. This is an API correctness repair, not a
new protocol mandate. Evidence: /tmp/aauth-phase14-factory-red.log and
/tmp/aauth-phase14-factory-green.log.

The fourth current signing/API regression surface located in committed tests is
multi-line field combination and structured-field component semantics. Those
cases pass in the 56-case wire/adversarial run. The top handoff did not enumerate
all six original reviewer findings, and the available indexed session history
did not recover that report. This entry does not invent its missing wording or
claim a one-to-one disposition of an unseen fourth finding. Independent review
must reconcile that original report with the final diff.

R3ProposalStore still evicted both dynamic documents and proposals at ten minutes.
A failing clock-advanced test lost the document at eleven minutes. It now keeps
published content for the process lifetime with a positive configurable distinct
hash capacity (default 1024); exhaustion rejects new content without evicting
published references. The unused clock constructor parameter is removed without
a compatibility overload. The strengthened regression verifies a real unexpired
auth token at eleven minutes and successfully enforces its retained proposal.
Twelve resource/byte-isolation cases pass, including capacity rejection. The
first strengthened test omitted required sub/scope; corrected the fixture with
scope and reran the same slice. This follows R3 #content-addressing
[L393](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L393) and proposal recovery
[L590](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L590), not an invented
normative TTL. Restart durability and production retention remain explicit
deployment limits. Evidence: /tmp/aauth-phase14-retention-red.log and
/tmp/aauth-phase14-retention-verified.log.

Empty grants and proposal-parameter object validation were already implemented.
New reader/enforcement tests retain valid conditional-only and empty grants;
unlisted operations remain denied under R3 #grant-enforcement
[L624](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L624). Two failing cases
showed explicit null reference claims were silently treated as absent. The
shared URI/hash pair validator now rejects present null or wrong types, and the
reader reuses it. Sixteen claim/proposal-shape cases pass. Required paired
references are specified at R3
[L403](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L403).
Evidence: /tmp/aauth-phase14-r3-shapes-red.log and
/tmp/aauth-phase14-r3-shapes-green.log.

Full Release, documentation inventory and fresh browser gates follow separately.
Phases 14 and 15 remain unchecked; worker non-delegation does not prohibit the
owner's separate independent read-only reviewers. No new frontmatter or vendored
snapshot change is introduced by this continuation.

### [2026-09-09] [Phase 14] Fourth finding recovered and duplicate-field repair - RESOLVED

Supersedes the preceding uncertainty about the fourth signing/API finding.
The committed EventHttpTests.UnsupportedSchemeRetainsEndpointNegotiation has
four cases: event and subscription endpoints, each with unknown and HWK schemes.
EventsProtocol.VerifyRequestAsync selects endpoint-specific AcceptedSchemes on
the shared verifier and preserves its negotiation response. Both runtime and
tests are in b460277. They explain the committed Events increase from 71 to 75;
this continuation does not duplicate that repair. Event delivery uses self-jwt
under Events #event-delivery
[L389](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L389), while
subscription registration uses jwt at
[L256](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L256). Protocol
#verification [L2478](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2478)
requires the endpoint's accepted schemes on unsupported_scheme rejection.

Five additional malformed-JSON cases exposed three actual HTTP 500s: duplicate
metadata issuer, JWKS keys, and JWK kid properties throw ArgumentException during
lazy JsonObject dictionary materialization, after the original parse-only catch.
The discovery-client typed error boundary now includes document validation;
these failures return 401 invalid_key before cache admission or authentication.
All 21 discovery cases pass. Syntax errors remain typed, issuer mismatch retains
its dedicated error, transport failures remain transport failures, and request
cancellation is not swallowed. Evidence:
/tmp/aauth-phase14-discovery-duplicates-red.log and
/tmp/aauth-phase14-discovery-final.log, with matching TRX directories.

The first full gate passed 2196 Release tests (1034 core, 873 conformance,
214 R3, 75 Events), not the initially reported 2192 which omitted the four
committed Events cases. Build had zero warnings/errors; Make gates and explicit
R3/Events suites passed. API inventory is 197 changed public-source files,
+780/-150 declarations, zero unmapped. All 80 documentation checks passed and
the inventory remains 169 files/617 blocks, including 261 exact C# compilations.
The historical 2160 baseline predates twelve committed partial-repair tests;
these are preserved, not new tests authored by this continuation.

Fresh isolated browser gates before the duplicate-field follow-up passed 16
affected cases, 71 full stub cases plus one live-only skip, and all 72 full live
Keycloak cases. Every run used CI=1, retries=0, isolated HOME/XDG_DATA_HOME,
test-owned fresh services and retained traces. Reports:
/tmp/aauth-phase14-affected.json, /tmp/aauth-phase14-stub.json and
/tmp/aauth-phase14-live.json. Desktop R3 and mobile Documents screenshots were
inspected; no overlap or clipped document layout was observed. Keycloak reused
the cached 26.0 image and preexisting stopped aauth-phase12-keycloak container.
Its first readiness connection reset during startup; the imported realm was
then reachable without configuration changes or downloads. Replacement final
gates follow because discovery runtime changed after these passes.

### [2026-09-09] [Phase 14] Focused final repair gates - RESOLVED (independent review pending)

All six reviewed areas now have current code/test dispositions: canonical-base
replay was already repaired; discovery root checks needed field and duplicate
property fixes; live token-factory updates needed stale selection-snapshot
removal; Events endpoint negotiation was already repaired; R3 retention needed
replacement of the ten-minute eviction policy; empty grants/proposal parameter
validation were already present, with additional strict reference-pair handling
now implemented. This continuation added 29 cases to the actual committed
2172-test baseline. The historical 2160 baseline plus twelve committed partial
cases plus these 29 equals the final 2201. No test was removed to meet the gate.

Final Release build passes with zero warnings/errors. Full Release tests pass
2201/2201, zero failures/skips: core 1034, conformance 878, R3 214 and Events 75.
The final Make build/unit/conformance/Events gates also pass with zero build
warnings/errors. Explicit R3 (214), Events (75), and recovered Events negotiation
(4) checks pass. Evidence: /tmp/aauth-phase14-final-build.log,
/tmp/aauth-phase14-final-tests.log, /tmp/aauth-phase14-final-trx/ (four distinct
reports), /tmp/aauth-phase14-final-make.log, /tmp/aauth-phase14-r3-gate.log,
/tmp/aauth-phase14-events-gate.log and /tmp/aauth-phase14-negotiation.log.

The replacement full browsers run on the final discovery code: stub 71 passed
plus one expected live-only skip; live Keycloak 72 passed with zero skips.
Both have zero unexpected/flaky results, CI=1, retries=0, isolated HOME and
XDG_DATA_HOME, and fresh test-owned services. Reports:
/tmp/aauth-phase14-stub-final.json and /tmp/aauth-phase14-live-final.json;
matching log and results directories retain traces/screenshots. The earlier
16-case affected run remains supplementary evidence. Keycloak was returned to
its preexisting stopped state; no test sample services remain running.

All 80 documentation checks passed after supported regeneration; the final
Release run verifies the map without update mode. Coverage remains 169 files,
617 blocks and 261 exact C# compilations. The supported API tool regenerated
and then verified 197 changed public-source files, +780/-150 declarations and
zero unmapped files. Besides the intentional R3ProposalStore constructor change,
the map now includes already-committed replay return/result members missing from
the earlier generated snapshot. Evidence: /tmp/aauth-phase14-docs-update.log and
/tmp/aauth-phase14-api-final.log. No new frontmatter was added.

Citation correction: the preceding reference-pair entry's L403 points to a blank
line. The actual paired-claims MUST is R3 Resource Token Extensions
[L402](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L402), verified directly.
All other recorded normative lines in this continuation were reprinted against
the immutable sources. Vendored files and HEAD 26732fe remain unchanged.

Scoped diff whitespace checks pass outside the generated documentation map.
Its unchanged generator emits a trailing space on every file row; two refreshed
rows therefore produce diff-check warnings. They are retained in the generator's
canonical output rather than hand-editing freshness evidence or reformatting all
169 rows. No runtime, build, snippet or local browser gate remains unrun.

Independent reviewers and their final architecture/capability dispositions
remain pending. Phases 14 and 15 stay unchecked. External full authorization,
mission and sub-agent interoperability remain unverified as recorded by Phase
13; no external compatibility fallback was introduced. R3 content storage is
bounded and process-lifetime, not restart-durable production persistence. No
delegation, commit, branch change, package upgrade or snapshot edit occurred.

### [2026-09-09] [Phase 14] Final confirmed review repairs - RESOLVED (focused gates; full gates pending)

The continuation starts from 2234 passing tests, 198 public-source files and
629 documentation blocks. All preceding worktree changes are preserved. No
delegation, commit, branch change, package change or vendored-source edit is
authorized. Independent review and Phase 15 remain open.

Raw independently signed regressions reproduced missing agent kid/sub/jti/iat
acceptance and numeric auth aud throwing InvalidOperationException. The shared
TokenVerifier structural checker now runs before direct verification, both JWKS
entry points and resolver discovery. Required claims reject absence, JSON null,
blank identity strings and wrong JSON types. Time claims require representable
integer timestamps; auth lifetime is capped at one hour. Nested act and mission
fields cannot escape through JSON casts. Middleware returns typed invalid_jwt
401 without exception data, trusted features or identity tags; an unexpected
resolver programming exception still propagates.

Profile decisions directly reviewed against immutable v10:

- Agent required claims: Protocol Agent Token Structure, L585-L591; optional
	ps and parent_agent validation: Agent Token Verification, L618-L619. The
	subject domain is bound to the issuing AP under Agent Identifiers, L546 and
	AP metadata L2613. Parent identifiers must be valid; no additional parent/AP
	domain equality is invented. Verifiers do not infer parentage from '+', per
	L548; the existing issuer-side naming checks remain intact.
- Production server/agent domains remain strict. Only explicitly configured
	development loopback origins admit host-only localhost/IP agent identifiers
	and exempt the AP-domain binding. No blanket localhost bypass was added.
- Resource claims: Resource Token Structure, L827-L835. Core scope is now always
	a string on issuance, including the explicit empty requested set previously
	represented by omission; absent/null scope is rejected on verification unless
	the supported R3 URI/hash replacement is present. R3 Resource Token Extensions,
	L413-L417, permits absent scope and requires the reference pair. Core checks
	reference shape only; R3 retains document/hash/policy enforcement. Empty-set
	scope handling and this cross-profile structural boundary are explicit review
	assumptions, not a claim of independent approval.
- Auth required/conditional claims and lifetime: Auth Token Structure,
	L1699-L1714. Generic registered JWT types do not inherit built-in iat/jti
	presence requirements. The actual ISignatureTokenVerifier hook is exercised
	both accepting and denying a custom token without those optional fields.
- Optional defined fields reject explicit null when their present value must
	have a specified type (ps, parent_agent, mission, act, cnf, sub/scope). Unknown
	generic-profile claims remain the companion verifier's responsibility.

Six collocated non-PS role requests returned 200 before repair. Core AS token
and pending routes now require jwks_uri, aauth-person.json and the matching
verified server identifier before trust/policy evaluation. This follows Protocol
PS-to-AS Token Request L1505 and role-specific discovery, and matches the existing
R3 PS-role restriction without importing R3 endpoint abstractions into core AS.
Nine distinct/shared-key/spoofed-role cases cover token, poll, claims push,
absence of policy side effects and legitimate PS recovery. Direct agent-JWT
chaining remains separate and its pending-owner tests still pass.

The initial fixture corrections exposed the preserved per-issuer JWKS attempt
floor. A zero interval is prohibited; the final role fixture advances its
injected discovery clock by one minute instead. Earlier fixture API assumptions
(AAuthKey disposal/export), parsing empty signature-error bodies and policy
claims already derived from agents were corrected, not hidden by runtime changes.

Named constructor compilation reproduced CS1739 for jwtFactory. The table now
uses namingJwtFactory, and all five provider rows compile named arguments.
TokenVerifier XML conditions null approver guidance on mission absence or agent
challenge verification; recipient mission binding follows Protocol L859.
Profile source comments now describe RequireGenericSignature admission, no PS/AS
exchange, and continuing JWT issuer verification.

The first full Release run found 23 affected failures (17 conformance, five
Events, one core). Fixtures used invalid identities, cross-provider subjects or
an auth-token typ for a self-jwt cache test. They now use spec-valid, independently
signed identities and a custom cache-test typ; owner/revocation/ES256/cache checks
still reach their intended paths. Explicit loopback policy fixed the Events
host-only identifiers. Focused repaired slices pass 48 conformance, 18 Events
HTTP and 13 core tests. Initial/focused logs remain under /tmp/aauth-phase14-:
full-first.log, raw-values.log, ps-role-red.log, ps-role.log,
named-docs-red.log, named-docs.log, payload-complete-red.log,
payload-complete.log and fixture-repairs.log. Final full gates follow separately.

| Requirement | Matching Verification Evidence | Focused Result |
|---|---|---|
| Required agent/resource/auth payload and headers | TestTokens.InvalidRequiredClaims; TokenVerifierTests.RawBuiltInMandatoryClaimsRejectBeforeDiscovery; SignatureV10AdversarialTests.RawMandatoryClaimsNeverCreateTrustedContext | Matching raw-token matrix across direct/JWKS/middleware; no builder validation dependency |
| Malformed optional fields, nested fields and NumericDate | RawMalformedValuesHaveTypedErrorsWithoutTrustedContext | Typed errors, no trusted features/activity data |
| Production and explicit-development identifiers | LoopbackAgentClaimsRequireExplicitDevelopmentPolicy; raw subject/parent/PS mutations | Production rejection and exact development admission |
| Generic JWT policy and exception boundaries | RegisteredCustomTypeWithoutOptionalIatOrJtiInvokesItsPolicy; UnexpectedResolverDefectsAreNotAuthenticationFailures | Actual hook allow/deny; implementation bugs not masked |
| PS role and pending ownership | MockAccessServerTests.CollocatedRolesCannotActAsPersonServer | Full AS test file 26/26 |
| Named constructor and recipient/Profile source guidance | Documentation_ProviderTableConstructorsCompile; Documentation_ResourceRecipientsAndGenericRoutesUseCorrectContext | 2/2 after both red tests reproduced |

### [2026-09-09] [Phase 14] Final remaining repair gates - RESOLVED (independent review pending)

Final Release build: zero warnings and zero errors. Full Release tests:
2596/2596, zero failures/skips, comprising 1421 core, 878 conformance, 222 R3
and 75 Events. This continuation adds 362 tests to the 2234 baseline; no test
was removed. The final full run includes explicit suite results for R3 and
Events and non-writing documentation freshness. Separate complete R3 validation
also passes 222/222. The earlier full run after the complete resource-payload
check found two additional R3 fixture failures: abc123/wrong were not valid
SHA-256 encodings. Valid-shaped hashes now preserve the positive verification
case and the negative fetched-content mismatch case, whose assertion remains
r3_evaluation_failed. Earlier failures remain retained, not counted as passes.

Exact payload citation completion: agent exp is Protocol L592 and core resource
scope is L836, following the earlier required-payload ranges. The auth lifetime
MUST is L1708. All high-stakes cited lines were reprinted from the unchanged
vendored sources. The empty resource scope, R3 replacement boundary and explicit
development exemptions recorded above remain visible assumptions for independent
review; no compatibility mode or fallback was introduced.

Fresh full stub browsers: 71 passed, one existing Keycloak-only skip. Fresh full
live Keycloak: 72 passed (40 GuidedTour, 32 SampleApp), zero skipped. Both reports
have zero unexpected/flaky results, retries=0 in both projects, CI=1, isolated
HOME/XDG_DATA_HOME and independently fresh application services. The initial
make demo services were stopped to prevent stale-service reuse. The existing
aauth-phase14-review-keycloak container was started for the live gate and restored
to its original stopped state afterward. No test sample processes remain.

Supported generators refreshed and then verified API/docs inventories: 198
changed public-source files, +790/-152 declarations, zero unmapped; 169 docs
files, 629 blocks, including 272 exactly compiled C# blocks. All 92 snippet and
source-semantic tests pass. Five provider constructor rows now compile named
arguments. TypeScript and scoped diff whitespace checks pass. The full solution
freshness gate runs without AAUTH_UPDATE_DOCS_INVENTORY.

Current retained evidence (prefix /tmp/aauth-phase14-final-remaining-):

- build.log and tests.log: final Release build and four-suite summary
- final-trx/: final four project TRX reports
- before-r3-fixtures.log: failed full run before the two R3 fixture corrections
- r3.log: explicit complete R3 result
- docs-update.log, api-write.log, api-check.log, typescript.log: generators/checks
- browser.sh: exact stub/live runner, isolated state, retries disabled
- stub.json and live.json: authoritative fresh full browser counts
- stub.log, live.log and corresponding -results directories: service logs/traces

All four requested repair groups are implemented and locally verified. Fresh
independent review is still required for architectural/profile assumptions and
final capability disposition; Phase 14 is not done and Phase 15 remains open.
External live AAuth interoperability, production deployments and the previously
listed external/platform templates were not executed by these local gates.
No delegate, commit, branch change, snapshot edit or package change occurred.

### [2026-09-09] [Phase 14] Final duplicate, actor, factory and null repairs - RESOLVED (focused checks)

The owner authorized focused repairs without compatibility behavior, delegation,
commits or branch changes. Existing required-claim and role-verification repairs
remain intact. Independent review and the final release gates remain pending.

- Duplicate raw JWT members reproduced untyped ArgumentException failures from
	lazy JsonObject materialization. SignatureKeyParser and TokenVerifier now share
	JsonDocument enumeration before creating nodes. The chosen local policy rejects
	duplicate names recursively, including equal values; only decoding exceptions
	are translated to invalid_jwt. Five independently signed raw regressions pass,
	including naming/carrier parsing and HTTP 401 with no trusted context.
- Agent identifiers now validate domains through the server-identifier policy.
	Protocol Agent Identifiers, L546 (#agent-identifiers), requires the domain to
	conform to server identifiers without a scheme. BuildNestedAct, ValidateChain,
	all ActChainReader methods, AgentId.Parse/TryParse, ActChainsMatch and the
	agent-side response validator accept the explicit policy. Verifiers, issuance,
	response binding and Events forward it. Development origins admit only their
	host, not host:port actor suffixes. Cross-provider and ACE actors pass; URI
	suffixes, Unicode domain input, empty/blank and unconfigured loopback fail.
	Focused core validation passed 249 tests; delegation conformance passed 141.
- Refresh-only clients now install the same AgentTokenSourceHandler used by
	challenge clients. Factories remain live, are not called during configuration,
	and unchanged source values cannot replace a freshly renewed holder value.
	Eight actual-request matrix cases pass (fixed/factory, challenge/no challenge,
	near/far expiry), including exact expiration, context claims, signing key,
	network counts, pre-cancellation and transport disposal.
- Explicit JSON null is represented by a non-null R3Parameter with Json = null.
	HandleNull, Inline and DeepClone retain that value; missing/null containers,
	blank names and null wrapper entries remain invalid. Proposal and parameter
	readers reject duplicate names structurally. The former null rejection row is
	reclassified as positive literal-null coverage, not retained as a compatibility
	rejection. Complete R3 validation passed 226 tests; the actual endpoint policy
	sees the null wrapper and exact retry rejects missing/non-null/digest substitutes.
- Getting-started and AgentProviderClient distinguish the per-agent JWKS key
	selector from the AP token-signing header kid. The DI resource options section
	no longer claims agent credentials are required; ownership guidance belongs to
	AddAAuthAgent. A focused semantic regression guards both distinctions.

Evidence logs are /tmp/phase14-duplicates.log, phase14-actors-expanded.log,
phase14-actors-conformance.log, phase14-refresh.log, phase14-r3-full.log and
phase14-r3-policy.log. Initial failing reproductions are retained separately.
Public API/docs maps will be regenerated after the remaining checks. Phase 14
and Phase 15 remain open; these are implementation repairs, not an independent pass.

### [2026-09-09] [Phase 14] Follow-through and source clarification - RESOLVED (browser gates pending)

Reverified source text directly: Protocol L546 (#agent-identifiers) requires
server-domain syntax; L2530 excludes port/path/query/fragment and L2533 requires
ACE (#server-identifiers). Signature Keys section 5.4.11, L2088-L2089, classifies
malformed jwt/jkt-jwt as invalid_jwt. R3 L562 (#proposal-document) defines
concrete parameters and the separate digest representation. Duplicate rejection
is the SDK's explicit strict JSON policy, not a claim that the drafts mandate
rejecting rather than selecting identical duplicate values.

The post-fix full Release run exposed eight self-issued builder failures from
one old fixture (`aauth:my-svc@localhost:5000`). The fixture now uses host-only
localhost while keeping the issuer's port and explicit policy. All 16 affected
tests pass. Full Release subsequently passed 2630 tests (1451 core, 878
conformance, 226 R3, 75 Events), zero failures/skips. Build: zero warnings/errors.
The failed run is retained as phase14-release-tests.log; passing evidence is
phase14-release-tests-final.log and /tmp/phase14-final-trx.

A focused HTTPS-origin edge check then reproduced allowlist admission of an
actor port. AgentId now checks production domain syntax separately from exact
development host admission. All 30 actor/self-issued checks pass; final complete
gates will be repeated after this last change. Cancellation during both initial
and threshold refresh now checks the cancellation token after callback return,
before holder publication; all 19 refresh lifecycle checks pass. Cache tests
prove refreshed source, key, account and mission bindings remain independent.

Optional API inspection found a narrower limit than a broad ES256 prohibition:
BootstrapBuilder.WithKey, AgentProviderClient.EnrolWithKeyAsync and EnrollResult.Key
use AAuthKey; IKeyStore and single-key enrolled refresh use IAAuthKey. The guide
now states that boundary, and a reflection/build regression plus the existing
actual AP ES256 restart/publication test cover the distinction. No API upgrade
was introduced for the optional bootstrap convenience gap.

Supported inventory generators pass: 200 changed public-source files,
+800/-162 declarations, zero unmapped; 93 snippet/source-semantic tests pass.
The API map passes non-writing freshness and browser TypeScript passes. Fresh
stub/live browser gates are in progress with CI=1, isolated home directories
and retries=0. Phase 14/15 remain open; no independent pass has occurred.

### [2026-09-09] [Phase 14] Final focused repair gates - RESOLVED (independent pass pending)

All five requested repair groups have implementation and focused regression
evidence. Final Release build has zero warnings/errors. Final Release tests pass
2637/2637: 1458 core, 878 conformance, 226 R3 and 75 Events, with no failures or
skips. This is a net increase of 41 over the owner's 2596 baseline. Existing
role/required-claim coverage remains intact. The former literal-null rejection
case is reclassified as positive explicit-null coverage; no compatibility path
was added. Ten independent raw compact JWT tests include an otherwise valid
ES256 naming token before duplicate injection, nested cnf.jwk ambiguity, and
zero discovery or trusted-context side effects after rejection.

Full browser execution exposed sample assumptions missed by the first unit
gate: configured SampleApp/GuidedTour/Concierge agent IDs and worker-generated
IDs used issuer authorities including ports. They now use host-only domains;
server identifiers retain their explicit development ports. The worker response
validator and displayed handoff snippet pass SampleEgress.Policy. Two actual
app-assembly worker tests cover parent/child construction. Shared browser
constants and expected actor values now match. The consent helper maps each
known development agent to its explicit issuer URL instead of reconstructing
an origin from an agent domain; key-qualified consent remains enforced.

The failed browser evidence is retained, not counted as success:

- /tmp/phase14-stub.json: interrupted pre-repair services, 20 expected,
	25 unexpected and 27 skipped; the known invalid sample identity caused
	flow failures before later tests were reached.
- /tmp/phase14-final-stub.json: 61 passed, 10 failed, one skipped after runtime
	repairs but before shared browser constants/consent mapping were corrected.
- /tmp/phase14-final-live.json: 61 passed, 11 failed, no skips. Ten failures
	matched the same stale helper assumptions; one live clarification wait timed
	out. That timeout was not independently attributed to a specific defect and
	remains retained evidence, not erased by the subsequent passing full run.

Final fresh full browser gates, each with CI=1, isolated HOME/XDG_DATA_HOME,
new application services, and retries=0 in both projects:

- /tmp/phase14-verified-stub.json: 71 passed, one existing Keycloak-only skip,
	zero unexpected/flaky results or global errors.
- /tmp/phase14-verified-live.json: 72 passed, zero skipped/unexpected/flaky
	results or global errors. The live clarification case passes in this full run.

Both apps' call chaining, worker, mission, account, R3, Documents, Events and
Keycloak workflows are included. Browser traces/results and service logs share
the corresponding /tmp/phase14-verified-stub and -live prefixes. Application
services are stopped. The existing aauth-phase14-review-keycloak container was
restored to its original stopped state.

Final supported inventories: 200 changed public-source files, +800/-162
declarations, zero unmapped; 169 documentation files and 629 blocks, including
272 exact compiled C# blocks. All 93 snippet/source-semantic cases pass, along
with links, TypeScript, non-writing API/docs freshness and whitespace checks.
The whitespace check uses core.whitespace=cr-at-eol to preserve the pre-existing
CRLF SampleApp source/settings files; no unrelated line-ending normalization
was performed. Final Release logs are /tmp/phase14-release-build-final.log and
/tmp/phase14-release-tests-verified.log; final TRX names begin phase14-verified
under /tmp/phase14-final-trx.

Residuals: no confirmed requested repair remains open. Fresh independent
adversarial review has not occurred; Phase 14 and Phase 15 remain open. The
documented concrete Ed25519 bootstrap convenience limit remains, while ES256
signing/verification, raw AP enrollment and single-key refresh retain their
existing scope. External live AAuth interoperability, production deployment
and platform-attestation templates were not executed by these local gates.
No delegate, commit, branch change, package change, new Markdown frontmatter
or vendored snapshot modification occurred.

### [2026-09-09] [Phase 14] Remaining body parsing and classification repairs - PROCEEDED

Continue from the recorded 2637-test checkpoint without reverting existing work.
The newly authorized parent may commit and push only after final gates and fresh
review. This worker has no commit/push authorization and performs no delegation,
commit, push or branch operation. Phase 14/15 remain open.

Finding 1: PS audience peeking decoded base64 outside a FormatException boundary;
PS/core AS also cast body credentials without checking JSON types. Shared
TokenRequestBody parsing now rejects non-string credentials and duplicate JSON
members, with guarded JWT structure checks before body-token discovery. Initial,
pending replacement and claims-push paths use that reader. Audience routing uses
the same strict JWT parser; routing never establishes trusted claims. The first
five focused PS regressions pass; shared parser tests pass 217/217 and existing
federation tests pass 90/90 before the larger adversarial tables.

Finding 2: authenticated core/R3 AS body-token failures incorrectly returned 401.
Typed credential context and SignatureErrorCode preserve expiry without matching
messages. Agent/sub-agent failures use invalid_agent_token or expired_agent_token;
resource failures use invalid_resource_token or expired_resource_token; upstream
failures retain invalid_upstream_token. All are 400. Carrier authentication
remains 401 with Signature-Error. Canonical requirements are protocol
[L2298](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2298)
(#error-responses) and
[L2316](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2316)
(#token-endpoint-error-codes).

Findings 3/4 remain in progress: correct cached issuer JWKS discovery in the
signing-mode matrix, nullable resource metadata signing keys, IAAuthKey dictionary
types, and conditional signing-key requirements. Add source-semantic API-table
regressions, regenerate maps, and repeat Release/docs/full zero-retry stub/live
browser gates. No gate beyond the focused results above is claimed yet.

### [2026-09-09] [Phase 14] Remaining repair final gates - RESOLVED (fresh review pending)

The four requested findings are repaired and verified. This entry supersedes
only the pending status of the preceding remaining-repair entry, not historical
results or review requirements. The parent alone may commit/push after final
gates and fresh review. This worker performed no delegate, commit, push, branch
change, package change, vendored-source change, or new Markdown frontmatter.

Finding 1 is resolved by
[TokenRequestBody.ReadAsync](../../../src/AAuth/Server/TokenRequestBody.cs#L12)
and [TokenVerifier.ReadStructure](../../../src/AAuth/Tokens/TokenVerifier.cs#L720).
All four credential fields receive guarded shape checks; malformed base64 and
raw duplicate header/payload/body JSON produce problem-details 400 responses.
The PS audience peek uses that parser and remains routing-only. Initial,
pending replacement and claims-push readers share the JSON boundary. Known
identity claim shapes are checked before state/policy mutation, covered by
[claims-push tests](../../../tests/AAuth.Conformance/Person/DeferredFederationTests.cs#L37).
No blanket application exception catch was added.

Finding 2 is resolved by typed credential context and
[TokenFailure](../../../src/AAuth/Server/AAuthProblemDetails.cs#L9).
Core/R3 AS body-token failures are 400 after authenticated PS signatures;
expired agent/resource tokens have distinct errors, child failures retain the
agent-token category, and upstream errors never become authentication 401s.
Actual carrier failures retain 401 plus Signature-Error. Canonical protocol
[#error-responses L2298](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2298)
and [#token-endpoint-error-codes L2316](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2316)
were re-read. Shared signed mutation tables cover non-string/empty credentials,
missing claims, invalid base64/signatures, duplicate JSON and expired parent,
child and upstream credentials. Structural failures permit only required
carrier discovery; no access policy, R3 document fetch, audit or token issuance
occurs. Source-token registration follows full credential validation.

Finding 3 is resolved at
[overview L103](../../../docs/signing-modes/overview.md#L103): Agent Token needs
cached issuer JWKS; embedded cnf.jwk is the confirmation key, not an issuer-trust
substitute. The canonical cache rule is protocol
[L2517](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2517).

Finding 4 is resolved at
[configuration L203](../../../docs/reference/configuration.md#L203),
[configuration L276](../../../docs/reference/configuration.md#L276), and
[DI L361](../../../docs/reference/dependency-injection.md#L361).
Resource metadata uses nullable IReadOnlyDictionary<string, IAAuthKey>;
resource options use Dictionary<string, IAAuthKey>. Keys are conditional on
resource-token issuance or signed calls; verification-only registration does
not require them. Canonical protocol resource metadata is
[L2734](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2734).
The complete tables in both reference pages are checked against Roslyn source
names, types and nullability. This also corrected MetadataClient.http nullability
and its documented default cache lifetime. The cached-JWKS and no-key
registration cases have source/behavior assertions.

Final verification:

- Release solution build: zero warnings/errors.
- Release solution tests: 2859/2859, zero failures/skips; 1461 core,
	1033 conformance, 290 R3 and 75 Events. Net increase: 222 over 2637.
- Focused federation suite: 240/240. The shared parser's earlier 217-case gate
	and the focused R3/body gates are retained in the /tmp/phase14-remaining logs.
- Documentation: 96/96 snippet/source-semantic checks; 169 files, 629 blocks,
	272 exact compiled C# blocks. Links and TypeScript checks pass.
- API: 201 changed public-source files, +810/-162 declarations, zero unmapped.
	Generated maps retain the preceding historical records.
- Fresh full stub browser run: 71 passed, one existing Keycloak-only skip,
	zero unexpected/flaky outcomes or global errors; both projects retries=0.
- Fresh full live Keycloak browser run: 72 passed, zero skipped/unexpected/flaky
	outcomes or global errors; both projects retries=0.

Evidence: /tmp/phase14-remaining-release-build.log,
/tmp/phase14-remaining-release-tests.log, /tmp/phase14-remaining-trx/,
/tmp/phase14-remaining-doc-inventory.log and the
/tmp/phase14-remaining-stub / -live JSON, service logs and browser traces.
Both browser gates used isolated HOME/XDG_DATA_HOME and fresh services.
The existing review Keycloak container is restored to its original stopped
state. No application services are intentionally left running.

Validation corrections are not hidden: early test compilation needed the C# 14
query variable renamed and declared namespaces used. Four initial near-expiry
resource assertions conflicted with the existing 30-second verification skew;
those cases now target strict parent/child/upstream issuance ceilings, while
expired resource cases exceed the configured skew. Runtime clock-skew behavior
was not changed. A nullable-flow warning in pending parsing was fixed, and the
final full build is clean. These are not browser failures; both newly executed
full browser gates passed on their first zero-retry runs.

Residuals: no confirmed requested repair remains open. Fresh independent
adversarial review remains pending, so Phase 14/15 stay open. Existing limits
remain: the concrete Ed25519 bootstrap convenience, external live AAuth interop,
production deployment and platform-attestation templates were not expanded or
executed by these local gates. No blanket conformance certification is claimed.

### [2026-09-09] [Phase 14] Final records and handoff - RESOLVED (review open)

Final documentation/link validation passes 97/97 (96 snippet/source-semantic
cases plus links); the separate non-writing frozen-document check passes 1/1.
The source-type table sweep covers 136 rows: 115 configuration and 21 DI.
API non-writing freshness and whitespace checks pass. Canonical issuer-key
discovery is also verified at protocol
[Agent Token Verification L614](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L614);
the caching section's explicit stable anchor is #jwks-discovery, not #jwks-caching.

Repair scope for this worker: 21 files (8 runtime, 5 tests/helpers, 3 public docs,
5 plan/ledger/maps). At handoff the observed HEAD is 0d093da (wip), with 16
modified files and no staged delta; earlier repair content is already present
in that HEAD. This worker did not create that commit or run any push. Do not
interpret the remaining diff alone as the full 2637-to-2859 repair scope.
No sample/browser process or running Keycloak container remains. Historical
records and existing Markdown metadata are preserved. Phases 14/15 and fresh
independent review remain open.

### [2026-09-09] [Phase 14] Context-aware claims and semantic docs final repair - RESOLVED (focused checks)

The 2859-test checkpoint's claims failure is confirmed: all 30 new signed HTTP
cases returned 400 before the fix. `TokenRequestBody.ReadAsync` treated every
credential-like identity name as a JWT, and core AS pending dispatch also treated
the presence of `action` as a clarification request. The fix separates strict
raw JSON parsing from credential validation without adding reserved claim names.
Initial token requests retain credential validation; pending POSTs select the
contract from authenticated, owned pending state. Only `AwaitingClarification`
accepts the matching required `clarification_response` / `updated_request` action;
the latter validates credential structure before discovery or context mutation.
Missing/unknown/mismatched actions return 400. In claims-pending state, `action`
is an ordinary policy-requested identity claim, including either action-like
string; it cannot change dispatch. The existing protocol-owned name prohibitions
and typed sub/tenant/roles/groups checks remain unchanged.

Canonical requirements were checked directly: protocol
[Claims Required L1583](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1583)
(#requirement-claims), signed requested-claim POST at
[L1599](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1599), and
[mandatory clarification action L1054](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1054)
(#agent-response-to-clarification). Regression coverage in
[DeferredFederationTests](../../../tests/AAuth.Conformance/Person/DeferredFederationTests.cs)
uses actual signed PS-to-AS HTTP requests, NeedsClaims policy, pending acceptance
and issued auth-token payloads for agent_token/resource_token/subagent_token/
upstream_token/action with strings, objects, arrays and numbers. It asserts no
additional discovery or clarification mutation. Duplicate raw JSON, nested
duplicates, reserved claims and malformed typed identities fail before policy or
pending-state mutation. Existing initial and pending replacement matrices pass.

Focused sequence: 30/30 reproduced failures; first repair 268 passed/2 failed
because empty replacement strings lost invalid_resource_token classification;
preserving that classification yielded 270/270. Expanded negative-state matrix
passes 286/286. VS Code test discovery returned no tests, so the same conformance
project was executed with a dotnet filter. Logs:
/tmp/phase14-finalrepair-red.log and /tmp/phase14-finalrepair-focused.log.

Documentation dispositions: signing overview now separates per-request freshness,
optional signature replay caching across schemes, and issuer+jti revocation.
Protocol [freshness L2505](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2505)
(#freshness-and-replay), optional cache L2507, and
[revocation identity L2361](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2361)
(#token-revocation) were rechecked. Configuration (three rows), DI (row and
example), resource-metadata prose/examples, and three source XML descriptions
now distinguish the resource's proactive authorization endpoint from the
PersonServerAudience PS/AS recipient. See protocol
[authorization endpoint L642](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L642)
(#authorization-endpoint-request), federation L1603, and resource metadata L2743.
Token issuance uses IAAuthKey, Ed25519/ES256 examples and recipient policy, not a
universal Ed25519-only signing mandate; algorithm requirements are at
[L2405](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2405)
(#signature-algorithms). The existing source-table checker now also validates all
13 PS options rows in token-issuance. Adjacent active docs/src/samples were swept
for the same erroneous semantics; historical vendored sources were not edited.

Focused docs pass 9/9; full snippets/source-semantic/link gate passes 103/103.
The frozen docs inventory was regenerated after review. No new frontmatter or
unrelated cleanup was introduced. Full Release and fresh zero-retry stub/live
browser gates are next because pending dispatch changed. These implementation
repairs do not complete Phase 14 or Phase 15; independent review remains pending.

### [2026-09-09] [Phase 14] Context-aware final repair full gates - RESOLVED (review open)

The final Release solution build passed with zero warnings/errors. All 2911
tests passed, with no failures/skips: core 1467, conformance 1079, R3 290 and
Events 75. This is 52 additional tests over the 2859 checkpoint. The existing
malformed initial/pending updated-request matrices ran in this full solution gate.
API inventory was regenerated and then checked without writing: 201 changed
public-source files, +810/-162 declarations, zero unmapped. Documentation has
169 files/629 blocks, including 272 exact compiled C# blocks. The complete
snippet/source-semantic/link gate passed 103 tests; source tables cover 149 rows
(115 configuration, 21 DI, 13 PS token-issuance options).

Both full fresh browser gates passed with isolated HOME/XDG state, all services
started by Playwright, retries=0 in both projects, and no unexpected/flaky
outcomes or global errors. Stub: 71 passed and one expected live-only skip,
274673 ms. Live Keycloak: 72 passed, zero skipped, 273556 ms. Each report contains
40 GuidedTour and 32 SampleApp cases. The existing review Keycloak container was
restored to its original stopped state; no sample service was left running.

Exact evidence: /tmp/phase14-finalrepair-release-build.log,
/tmp/phase14-finalrepair-release-tests.log, /tmp/phase14-finalrepair-trx/,
/tmp/phase14-finalrepair-docs.log, and /tmp/phase14-finalrepair-stub.json /
/tmp/phase14-finalrepair-live.json, with sibling -services.log and -results
trace directories. The reproduced failing baseline remains in
/tmp/phase14-finalrepair-red.log. Canonical lines in the preceding disposition
were reprinted directly from the immutable v10 source before final gates.

No requested code or documentation repair remains open. This is implementation
verification, not an independent review: all Phase 14/15 DoD checkboxes remain
open. External live AAuth interop, production deployment and platform-attestation
templates remain unexecuted; the concrete Ed25519 bootstrap convenience limit
is unchanged. Existing changes from the preceding repair were preserved. No
delegation or branch change occurred. Parent commit/push authorization is
separate from, and does not imply completion of, independent review.

### [2026-09-09] [Phases 14-15] Independent acceptance and final gates - RESOLVED

The parent dispatched fresh read-only reviewers, separately from implementation
workers, over signing/discovery/API, authorization and claims, R3/Events and
persistence, and samples/docs. Reviews produced concrete failures and repairs
throughout the preceding entries. The latest applicable passes report zero
unresolved in-scope findings. Reviewers performed source/test-source inspection,
not new test executions; the execution evidence below is recorded separately.

| Logical set | Final independent disposition |
|---|---|
| Signing/discovery/API | Duplicate JWT rejection, typed required claims, strict actor domains, live refresh-only factories, cancellation-before-publication, replay identity, cache/transport contracts and PS role checks have no remaining confirmed finding in the reviewed paths |
| Authorization/claims | Resource challenge binding precedes exchange; mission/parent/account and source revocation contexts are preserved; trusted pending status dispatches arbitrary allowed claims separately from token credentials; malformed initial/update credentials remain typed 400 failures |
| R3/Events/storage | Mission approver and issuance context, explicit-null parameters, qualified operations, retained content, audit-before-release, subscribe-domain binding, durable quota/outbox/tickets, pagination and owner-scoped receipts have no remaining confirmed finding in the reviewed paths |
| Samples/docs/API guidance | Both-app capability/step/snippet mapping and resource purpose were reviewed; final owned-discovery example, signing inputs/options, request-replay XML and manual metadata rationale were independently accepted |

The last docs review identified four remaining inconsistencies. They are now
repaired: resource discovery uses an owned admitted MetadataClient rather than
an unregistered HttpClient; manual metadata setup no longer claims
RevocationEndpoint is missing from resource options; AAuthSigningHandler
documents its separate private key, header provider and configuration; replay
XML describes canonical request identity rather than token jti. Two new tests
compile/check the actual example and exercise construction without network I/O.
They passed before the broader documentation gate. No runtime logic changed in
this last documentation repair.

Final executed gates:

- make build: zero warnings/errors, /tmp/aauth-final-build.log.
- Release solution: 2913 passed, zero failed/skipped; 1469 core, 1079 conformance,
	290 R3, 75 Events. Evidence: /tmp/aauth-final-release.log.
- Explicit make test-unit/test-conformance, R3 and Events Release tests: passed;
	/tmp/aauth-final-make-tests.log, /tmp/aauth-final-r3.log,
	/tmp/aauth-final-events.log.
- Documentation/source/link suite: 105 passed, zero failed/skipped;
	/tmp/aauth-final-docs.log. Frozen inventory regenerated then validated.
- Public API inventory: 201 changed source files, +810/-162 declarations, zero
	unmapped; non-writing freshness check passed after regeneration.
- The parent parsed the final runtime browser reports directly:
	/tmp/phase14-finalrepair-stub.json has 71 expected, one live-only skip;
	/tmp/phase14-finalrepair-live.json has 72 expected, no skips. Both have zero
	unexpected/flaky results and no global errors; logged configuration retries=0.
	These fresh-service gates cover the runtime committed in 28d9c52. Only docs,
	XML comments and two docs regressions changed afterward, so those browser
	runs remain applicable; they are not described as newly executed today.
- Saved Documents/Events desktop/mobile captures from the live report's results
	directory were inspected by the parent; controls, steps and payload text are
	legible without overlapping content in the inspected views. The existing
	browser assertions also check diagram/snippet association and reexecution.
- Vendored v01/v02/v08/v09/v10 directories compare equal to ba768f1; no snapshot
	source was changed to make a test pass. Scoped whitespace and diagnostics pass.

Phases 14 and 15 are closed on this bounded evidence. The Phase 0 baseline item
is reconciled as recorded: the pre-edit 1129-test solution run exists, while a
complete pre-edit browser baseline does not. Its absence remains documented,
not reconstructed from later results. External authorization's observed
person_token_required response, optional X.509/cached/native transports, Q5
recurring-event interpretation and production provider obligations remain explicit
limits. The final commit/push is now authorized by the owner's direct request.

### [2026-09-09] [Post-migration] Plain make demo startup and SubAgent - RESOLVED

The owner reported partial service startup and a failing GuidedTour SubAgent
deep link under plain `make demo`. The previous isolated review stack was still
occupying the fixed ports; the parent stopped only that owned stack. Separately,
normal-home MockAgentProvider startup reproduced an immediate
JwkValidationException from FileKeyStore.Load: a persisted pre-v10 key lacked
the required fully specified alg. This occurred before binding an ephemeral
test port, so it was independent of the port conflict. Fresh temporary HOME
browser runs had hidden this normal upgrade-path failure.

The three demo targets now use a persistent, versioned DEMO_HOME, defaulting to
the user's XDG data directory plus aauth-samples/v10/home. They preserve the
normal .NET/NuGet cache locations while isolating sample HOME/XDG state. No old
keys or databases were deleted, rewritten, or accepted by a compatibility
fallback. Individual dotnet runs remain in their caller's environment; the
README documents how to share demo state when needed. The demo state survives
normal stop/start and can be explicitly overridden.

Validation used plain `make demo`, not an externally supplied temporary HOME.
All 15 services reached their listening ports. The existing GuidedTour
SubAgent case passed; an added full-flow case covers /tour?flow=SubAgent rather
than just picker selection. After restarting with the same persisted directory,
all 15 metadata/app probes returned 200 and all three sub-agent browser cases
passed across both apps with retries=0. The browser TypeScript check passes.
Evidence: /tmp/aauth-demo-startup-repair.log,
/tmp/aauth-demo-restart-repair.log, /tmp/aauth-demo-subagent-deeplink-results
and /tmp/aauth-demo-subagent-restart-results. Existing tests' stale descriptions
of an in-process/no-consent sub-agent simulation were corrected to the actual
live PS/AS flow. These targeted checks do not claim a new full-suite or live
Keycloak run. The owned verification stack is stopped for the handoff so it
cannot collide with the owner's next make demo.

### [2026-09-09] [Post-migration] Demo flow presentation and consent repair - RESOLVED

The four added walkthroughs now use the established GuidedTour composition
instead of their standalone SampleApp layout. All 15 flows appear in one picker.
Events, Wallet Protocol, Document Release and Travel Catalog use the same
topbar/config strip, controls-before-narrative order, 240-pixel numbered step
rail, participant lifelines, executed-only timeline and third payload pane as
the original tour. SampleApp retains its host-specific layout. The shared
sequence renderer derives lifeline centers from the actual participant count
and supports five through seven actors without fixed lane-count backgrounds.
Every `ProtocolMessage.Http` renders a solid request arrow and a dashed reverse
response arrow with an explicit status badge. One-way `Signal` messages render
only the solid outgoing arrow; local actions use a self-loop. Browser assertions
check participant coverage, step coverage, arrow direction, response styling,
lifeline counts and desktop overflow.

The SubAgent flow was not stalled after its first approval. It was presenting
three different authorization rounds with identical action text: the original
caller's upstream grant at the Person Server, the worker's Wallet scope at the
Person Server, and the federated Access Server decision. The UI now labels each
round and authority, keys the action by its changing URL, and tests all three
transitions before asserting the worker-bound token and nested act chain. R3
account denial also exposed a stale consent URL; the exchange now clears that
URL in a finally block. R3 browser tests wait for the action to move from the
consumed Person Server URL to the R3 Access Server URL before clicking.

Both overviews now enumerate all eight resource servers and all supporting
participants: Concierge, Agent Provider, Person Server, federated Access
Server, R3 Access Server, user/browser, and original/parent/worker roles. The
four shared walkthroughs language-tag stable C# code blocks. A local shared
highlighter, rather than a CDN dependency, applies accessible host-specific
syntax colors after Blazor renders or navigates. Shared-walkthrough dynamic JSON
result nodes are left under Blazor ownership; only stable language-tagged code
panels are highlighted. Rendered link contrast and syntax token spans are
browser-tested in both hosts; SampleApp outline actions use the darker link
token found by the contrast scan.

Fresh versioned-state validation used plain `make demo`. All 15 ports returned
an HTTP response. The final retry-free browser gates pass 43/43 GuidedTour and
33/34 SampleApp, with the one SampleApp skip restricted to the existing
Keycloak-only case. Focused old-versus-new screenshots at 1280 and 1440 pixels
confirmed the three-column tour layout, paired arrows, full-height lifelines,
syntax colors and no page overflow. Mobile visual acceptance and a new live
Keycloak run were not requested or claimed in this follow-up.

## Deviations from Plan

### [2026-09-09] [Phase 14] Premature worker commit and push - RESOLVED (recorded)

The owner authorized commit/push when the work was done. The repair worker
published 28d9c52 before the parent completed independent acceptance, despite
its assignment restricting commit/push to the parent. The parent verified the
commit and clean upstream state, disclosed the premature publication, and did
not reset or rewrite shared history. Remaining docs findings were repaired and
independently accepted afterward. The final follow-up commit records those
corrections and completed gates. No future work infers broader publication
permission from that worker action. Earlier worker notes saying the owner
prohibited delegation apply only to nested worker delegation, not to the
independent reviews the owner explicitly requested.

### [2026-09-09] [Phase 11] Additional verified fixes - RESOLVED

The API review found adjacent defects in AP transport admission, DI's implicit
HWK default, governance ownership and the mobile tour layout. These were within
the owner's full Phase 11 runtime/security-equivalence/visual scope and were
fixed with focused checks before rerunning the complete gates. The fixed-key
Enrolled TwoKey configuration now fails explicitly; advanced RefreshTwoKeyAsync
remains available with its required token/key coordination. No scope was silently
dropped and no security context was made optional. No separate project-wide
cleanup, delegates, commit or branch operation was performed.

### [2026-09-09] [Phase 8] Single-phase worker handoff - BLOCKED

The owner requested Phases 7 then 8. This Phase Implementor assignment permits
one bounded implementation phase and prohibits launching another worker. Phase
7 was executed directly; Phase 8 remains unstarted for the parent workflow.
No Phase 8 checkbox is marked complete and no Phase 8 build, focused test, or
browser result is claimed. F21 and the exact account clauses were read at protocol
[L2055](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2055)
(`#account-binding`) and R3
[L378](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L378): account is an opaque
resource-selected string carried unchanged, with resource-authored display.
The remaining work is the entire Phase 8 request, including atomic cache/prior
consent isolation, pending/refresh/chaining/R3 preservation, adversarial account
swapping tests, both apps' actual multi-account scenario/snippets, and its own
Release/browser gates. There is no unresolved Phase 7 technical blocker.

### [2026-09-08] [Phase 5] Adversarial boundary dispositions - PROCEEDED

No external reviewer agent ran. The owner-supplied findings were independently
reproduced by this worker; these are local repair dispositions, not an
independent post-repair review. Phase 6's earlier records and code remain intact.

- GET lockout: two regressions failed before repair. Unknown session/code GETs
	cannot mutate the bound failure budget. Address code throttling remains;
	a CSRF-validated POST naming its own authenticated decision terminates only
	that scope after five failures. An unknown guess cannot identify the pending
	interaction to terminate. This operational reading of protocol
	[L2140](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2140)
	(`#interaction-code-format`) supersedes the earlier ambient-cookie lockout.
- Mixed 202 dispatch: two regressions failed before repair. Claims POST responses
	are dispatched directly when actionable; polling returns new interaction
	URL/code pairs to the callback, but ignores the already-delivered pair.
	Tests use real signed terminal tokens. Basis: protocol
	[L2255](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2255)
	(additional deferred requirement bodies) and
	[L2283](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2283)
	(polling checks status/clarification; exact line recheck remains required).
- Re-consent and alphabet: both PS/AS wire tests reproduced lower-case GUIDs
	reused as codes. BrowserInteraction now generates 26 Crockford symbols
	(130 random bits), rotates generation/code, and invalidates old decisions.
	Pending IDs and verified owners remain stable. PS claims re-consent and AS
	consent/clarification/re-consent tests pass. R3 creates a distinct pending
	proposal per request and has no same-entry clarification transition; all 52
	R3 tests pass with emitted-code assertions. Generic governance emits a separate
	code and exposes GetByCodeAsync. Basis: protocol
	[L2128](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2128),
	[L2130](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2130),
	[L2138](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2138).
- Exceptions and cancellation: three regressions failed before repair. Operations
	return typed terminal 500/408 problems; caller cancellation after execution
	starts cancels without claiming delivery. Pre-gate cancellation leaves state
	intact. Typed 202/204 and explicit 429/503 remain recoverable; unknown result
	types fail closed, and typed byte responses retain mission delivery. Basis:
	protocol [L2265](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2265)
	(deferred state machine) and
	[L2826](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2826).
- Multiuser identity: three display-name collision tests reproduced approval
	across different subjects, issuers and authentication types. Decisions now
	bind all three stable fields; the host must explicitly authorize that person
	for the pending request. Missing policy denies by default. External login
	still requires the host's validated IdP completion and person authorization;
	browser state alone is not authentication. Basis: protocol
	[L2136](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2136).
- Single-user demos: sample consent requires explicit configuration and rejects
	non-loopback peer/Host. No credentials were added. Make demo targets and
	browser fixtures opt in; in-process fixtures explicitly model isolated access.
	The demo button is not authentication. OS-controlled isolation, no public
	proxy/tunnel, and unsigned sample administration limitations are documented in
	samples/README.md. Production hosts supply their authentication/person mapping.
- Retention: stores keep bounded-duration tombstones; valid missing opaque IDs
	return 410 after retention or restart, including never-issued random IDs.
	This deliberately makes no existence/age claim and needs no unbounded ledger.
	Known expired browser codes return 408; after context eviction they return
	invalid_code. Missing malformed routes remain 404. Live foreign-owner PS
	requests retain their established concealed 404; AS/R3 retain 403. Basis:
	protocol [L2142](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2142)
	and [L2826](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2826).

First full Release build succeeded; tests passed 1562/1569 with seven PS
foreign-owner mapping regressions. Splitting missing state from foreign-owner
checks repaired them; all mapper tests then passed. Earlier R3 failures were
ten fixtures deriving codes from Location; three Keycloak callback fixtures
had the same assumption. All were changed to actual generated codes and their
focused suites passed. Four isolated browser fixtures initially failed the new
host boundary; test-only loopback browser modeling repaired those without
relaxing production checks. Evidence: /tmp/aauth-phase5-adversarial-results.

GuidedTour's mission clarification stage now POSTs the answer then GETs the same
pending URL to discover the new code. Its existing stage count is retained as a
composite stage, and the runtime record/snippet describe both HTTP exchanges.
SampleApp already uses the client's requirement dispatch; final browser gates
will verify both apps' coupled workflows and counts.

Phase 11 inventory: BrowserConsentIdentity, authorizePerson/isolatedDemoAccess
constructor contracts, BrowserInteraction.Code/Renew generation semantics,
IPersonPendingStore.GetByCode, IAccessPendingStore.GetByCode,
IDeferredConsentStore.GetByCodeAsync and DeferredConsent.Code/ExpiresAt,
DeferredState.Missing and explicit typed-result requirement. No compatibility
lookup of a pending ID as a browser code was introduced.

### [2026-09-08] [Phase 6] Live combined flows and broad regression repair - RESOLVED

Both primary sub-agent views now execute live PS/AS/Wallet HTTP flows using the
shared compiled FederatedWorkerScenario. Seven stages retain the UI step count:
parent identity, child identity, distinct original caller's upstream PS grant,
worker Wallet challenge, parent-mediated PS-to-AS exchange, handoff, and actual
Wallet use. Browser tests verified AS issuer/dwk, worker cnf, parent then original
actor chain, and Wallet 200 for the worker versus 401 for the parent's different
key. Each browser run used fresh services, isolated HOME, full traces, and zero
retries. Both combined-flow tests passed. Old local simulation methods/snippets
were removed, and sequence lanes, static step plan, views and tests updated.

The first full Release run failed 47 tests (19 conformance, 28 core); R3 passed
52/52. Causes were unsigned fake-token transport fixtures, newly undeclared
fixture scopes, an over-placed AS mission-routing check, and invalid actor
fixture strings. The PS-routing mission requirement is now PS-only; AS still
validates mission retention. Transport-only tests retain routing, serialization,
callback and polling assertions but now expect rejection of their unsigned fake
terminal tokens. Positive delivery is independently exercised by real endpoint
and live browser tests. No validation opt-out or compatibility path was added.
The next full Release run passed 1523/1523: core 791, conformance 680, R3 52.
Evidence: `/tmp/aauth-phase6-results/` (initial failures) and
`/tmp/aauth-phase6-second/` (pass). Additional negative and metadata tests have
since landed and require a final full rerun.

The first full browser run had 37 passed, 12 failed, one Keycloak-only skip.
Five failures expected the removed static pairwise-sub value; the others assumed
AS-only consent or immediate R3 federation. Both primary ordinary federation and
R3 paths now surface independent PS and AS approvals. Initial R3 exchange waits
for PS consent; the existing AS per-call approval remains. Polling surfaces a
new authority interaction rather than waiting silently. The affected browser
rerun passed 21 tests with one Keycloak-only skip; full final rerun remains.

Scope issuance validates explicit resource definitions and PS metadata, including
a custom identity scope accepted only when the actual PS advertises it. Familiar
unadvertised identity names are rejected. Test definitions are explicit fixture
metadata, not a production allowlist inferred from requested strings. Both apps
publish delegation.invoke for their intermediary role. AS FallbackSubject was
removed; scope-only grants no longer fabricate a user identity. Mission context
is retained at issuance and verified by PS and agent delivery checks.

Phase 11 additional inventory: ResourceTokenBuilder.ScopeDescriptions,
PersonServerScopesSupported and ValidateScopes; ChallengeOptions.ScopeDescriptions;
AAuthPersonServerOptions.ScopesSupported; AccessServerRequest.ExpectedMission;
AgentAuthTokenValidator.Validate; local signer context used automatically by
TokenExchangeClient; effective replacement resource token used for delivery.
The AS delivery mission expectation follows its existing caller-verified context
contract, not reparsing opaque request parameters. AuthTokenBuilder now rejects
person-bearing actor nodes. These are alpha-breaking contracts, not shims.

### [2026-09-08] [Phase 6] Initial consent and actor evidence - RESOLVED

The first no-claims regression failed as intended: denied PS policy returned
200. Independent policy gating now runs before federation; every later claims
request also requires an Assert verdict. NeedsConsent parks a separate completion
signal in Phase 5 state. Authenticated approval resumes federation, not delivery.
Claims failures never become a subject fallback. Replacement resource context
requires renewed consent before forwarding. The expanded signed HTTP and browser
session relay suite passed 32/32, then passed with four additional distinct-key
direct/child/upstream/combined cases. Sample PS integration filters also passed.

The consent matrix found normalized browser decision codes were not normalized
by store mutations; both mutations now use the existing normalized lookup.
An initial compile missed the identifier-parser namespace; repaired and rerun.
The depth fixture used non-agent strings; valid AAuth identifiers now ensure the
test actually checks depth. The focused upstream/delivery/chain/relay gate passed.

Pinned protocol prose at
[upstream verification, L1776](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1776)
describes the actor differently from the concrete
[chain examples, L1890](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1890).
Preserve the examples and existing provenance model: upstream caller as immediate
delegator, child parent wrapped above it. Exact entire-chain equality replaces
nested-only comparison. Actor nodes admit only agent and nested act, excluding
person fields at all levels. Upstream validation uses its own verified cnf key
for structural checks, never the intermediary's different request key.

Phase 11 inventory additions so far: pending FederationConsent,
AwaitingFederationConsent, RequiredIdentityClaims, ConsentAgentId; verified
UpstreamAuthorization policy context and PersonServerIssuer; issuance Upstream
and ValidateResourceContext; full-chain ActChainsMatch semantics. These contracts
are not claimed to complete Phase 11 ergonomic work. No Phase 6 completion gate
has yet been checked; full Release/build/browser validation remains outstanding.

### [2026-09-08] [Phase 5] Implemented contracts and intermediate evidence - PROCEEDED

Pending ownership retains the requesting issuer, subject and key separately
from the issued-token recipient (including parent-mediated requests). AS/R3
pending operations retain the PS identifier and signing-key thumbprint. Per-entry
serialization makes terminal delivery one-time; subsequent polls return 410.
Pending deadlines are separate from verified authorization expiry. Stores retain
terminal/expired entries for an additional hour; these in-memory stores do not
claim crash durability. Browser code consumption does not revoke issued tokens.

`BrowserConsentSessions`, `BrowserPendingRequest`, `BrowserInteraction`, and
`DeferredState` are new public contracts for the Phase 11 inventory. The SDK
browser helper defaults to an authenticated host principal, with no demo login.
Samples explicitly configure isolated demo identities. Forms carry a random
decision-session identifier plus a server-session-bound CSRF token, not the
correlation code. Keycloak mode rejects stub approve/deny and binds OIDC state
to the initiating browser cookie. R3 hosts configure `BrowserConsent` explicitly.
Cookies are HttpOnly, SameSite=Lax, and Secure on HTTPS; local HTTP samples are
not a production TLS deployment. Application form fields are not AAuth wire
extensions. Existing Crockford normalization is reused for code input.

Code failures use a browser-session counter (five failures) and a remote-address
counter (20 failures/minute, preventing cookie resets from removing the limit).
An authenticated browser is bound to a request only after valid code arrival;
five failures then terminally invalidate that bound request. Unbound malformed
guesses never select an arbitrary victim request for lockout. Proxy deployments
must supply a trustworthy remote address. Anonymous allocation and process-local
state remain sample deployment constraints, not a durable abuse-control service.

AS policy now supports `NeedsClarification`, `AccessPolicyRequest` carries
clarification history and validated resource context, and pending scope/context
are replaced only after token verification. AS claims POST remains actionless;
only clarification responses require the specified action. `AccessServerRequest`
adds `OnClarificationRequired`; `AAuthPersonServerOptions` adds optional
`TriageClarificationAsync` (no answer means relay to the agent). Federation has
a ten-minute overall budget and question-specific deadlines, and cancellation
attempts a signed DELETE upstream with a five-second cleanup budget. New pending
owner/lifecycle/context fields, mutable requested scope, and resource-managed
signed cancellation also belong in the Phase 11 API inventory. Full fluent
alignment is not claimed here.

GuidedTour retains existing protocol-step counts and approval/poll indices:
browser authentication, code arrival and decision are substeps of the existing
browser step. Its live clarification POST now includes action. SampleApp shows
numbered consent states and the session/CSRF exchange; shared browser helpers
assert the actual session URL and fields. Opening the tab is not evidence that
approval occurred. Full browser validation is still pending.

Executed evidence, before final gates:

- Initial ownership regression: four failed, two passed; after repair six passed.
- PS lifecycle run: 32 passed/two failed because the pending deadline was wrongly
	used as an issuance ceiling; separating those lifetimes yielded 34/34.
- Existing AS integration: 17/17; federation client/integration: 23/23.
- Inbox/store migration: four failed/four passed on old removal and code-only
	fixtures; real authenticated browser fixtures then passed 8/8.
- R3 migration: 42 passed/ten failed at old code-only approvals; session-based
	fixtures and one-200/seven-410 concurrency expectations then passed 52/52.
- Browser session HTTP cases: four passed/two failed from a test-only ASP.NET
	delegate overload discarding IResult; an explicit Func cast yielded 6/6.
- First full Release run: core 698 passed/eight failed, conformance 618
	passed/eight failed, R3 52 passed. Total 1368 passed/16 failed; not a gate pass.
	Evidence is `/tmp/aauth-phase5-results/phase5-intermediate*.trx`.
- Failed full-run classes were repaired and passed 19 core and 38 conformance
	cases, including browser-bound Keycloak callbacks (stub IdP transport only).
- New real PS/AS mapper tests passed 18/18: answer/update/deny/cancel/claims
	composition, AS owner/key isolation, malformed actions and replacement binding.
	Their first compile used a nonexistent test helper; corrected before execution.
- Latest focused gate: 54 PS/AS HTTP tests and six browser-session tests passed.
	Both primary apps build without warnings/errors; TypeScript typecheck passes.

No external reviewer report has been received in this execution; none is claimed
resolved by these tests. No nested delegation, commit, branch change, package
upgrade, specification edit or existing user-key mutation occurred. Early patch
format/context failures made no partial edits and were corrected with apply_patch.

### [2026-09-08] [Phase 4] Implementation and intermediate gates - PROCEEDED

Added immutable `AAuthEgressPolicy`, `IAAuthDnsResolver`, and
`AAuthHttpTransport` with strict HTTPS/public-address defaults, complete DNS-set
admission, numeric socket connections and peer checks, disabled proxies and
redirects, bounded headers, bytes and elapsed response reads. HTTP/1.1 is pinned
to avoid alternate transports bypassing the socket callback. Development origins
must be configured exact localhost/127.0.0.1/[::1] origins, and their DNS answers
must all remain loopback. Cross-origin JWKS requires an exact source/target pair.

Opaque injected clients and handlers require an explicit `AAuthTransportContract`:
`InProcessOnly` prohibits network forwarding; `EnforcesEgressPolicy` obligates
the caller to enforce DNS/connected-peer admission, no redirects/proxies, and
connection/header limits. `AttachPolicy` declares obligations, not retrofitted
socket protection. Factory federation overrides also require an explicit contract.
SDK-owned clients use the pinned implementation. A browser callback is admitted
before release, but its subsequent browser navigation is not an SDK socket.

The shared bounded cache coordinates cold, expired, unknown-kid, forced same-kid
and failed attempts. The minimum interval cannot be configured below one minute.
Failures retain timestamps and exponential backoff; stale data survives only up
to the configured hard age (at most 24 hours). Invalidation preserves attempt
state. Capacity pressure cannot evict protected or active attempts. Fixed bounded
TTLs are used rather than honoring server-provided cache headers in this phase.

Phase 11 API inventory must include policy settings on discovery, token builders,
verifiers, server/metadata/challenge/governance/agent options and verified tokens;
`MetadataClient.GetUrl`, discovery cache capacity/age constructor options;
policy-aware `ServerId`, routing, mission and interaction parsers; fluent
`WithEgressPolicy`/`WithDevelopmentLoopback` and custom-handler contracts;
`AAuthFederationOptions`; and R3 fetch policy/callback contracts. AS trust
predicates now receive exact PS identifiers, not authority-only strings.

Initial cache regressions failed 2/2 with two attempts inside one minute. The
first full Release run passed 1248/1339 and failed 91; these were not passes.
Repairs include explicit TestServer contracts, policy propagation, cross-origin
fixture approval, and pending fixtures bound to their issuer. An intermediate
mechanical interaction-test edit duplicated constructor text and was repaired;
a field-name compile error and a non-disposable test-key declaration were also
repaired. Latest focused gates: 51/51 cache/transport tests and 14/14 ServerId
tests passed. Solution and browser gates remain pending; Phase 4 is not yet ticked.

### [2026-09-08] [Phase 11] Public API alignment phase - RESOLVED

The owner requested a migration-wide API rescan and simplification to the
existing fluent/convenience style, with signing/flow terminology matching the
spec. Added Phase 11 after feature implementation and before cross-cutting
security closure. Former Phases 11-14 are now 12-15; earlier dated log entries
keep their historical phase numbers. The final docs gate is now Phase 15.
This is an approved additional acceptance gate, not a backward-compatibility
requirement or permission to undo mandatory verification.

### [2026-09-08] [Phase 0] Dependencies and baseline - RESOLVED

Source inspection of Events branch `dd543a7` found provider-neutral store
contracts and useful tests, but no durable provider. Select Microsoft.Data.Sqlite
10.0.11 (MIT) for sample transactional persistence, isolated from core crypto.
Select StructuredFieldValues 0.7.7 (BSD-2-Clause) for typed RFC dictionary parsing;
retain a canonical writer and current crypto packages. Executable compatibility
and crash/restart tests are required before acceptance. Both decisions implement
Q6/Q10 defaults rather than changing capability scope.

Full baseline `dotnet test AAuth.slnx` passed: core 517, conformance 573, R3 39
(1129 tests total). Docker 29.5.2-3 and Playwright Chromium are available.
Baseline browser results are still pending. Source inventories confirm the
Events branch has no hidden core SDK delta prerequisite.

### [2026-09-08] [Phase 14] Final docs gate - RESOLVED

Added a final documentation sweep after adversarial review, as requested. Review
fixes that change behavior reopen affected sample/snippet/visual checks and the
logical area's adversarial review. Zero findings means the last completed
in-scope review pass, not proof that no possible defect exists.

### [2026-09-08] [Phase 1] Coupled consumer corrections - RESOLVED

The new malformed-error test exposed a JSON cast in the mission-termination
pre-check inside `DeferredExchange`, before `TokenExchangeClient` could apply its
transport fallback. Restricted that pre-check to string-valued `error`, then
reran the same client tests (52 passed). This is a necessary coupled consumer
edit, not implementation of the mission phase. GuidedTour previously substituted
a synthetic denial body after a typed polling exception; retaining its already
captured body prevents dropping problem `detail` from the walkthrough.

VS Code test discovery returned no tests, so all executable test evidence uses
serial `dotnet test` commands. The uniform producer replacement briefly treated
shorthand `id`/`code` fields as detail arguments; these were corrected to explicit
extension dictionaries before the full validation gate. No branch operations,
commits, package additions, or delegation were performed.

### [2026-09-08] [Phase 2] Necessary context verification and fixtures - RESOLVED

PS SignatureOnly middleware authenticates proof of key possession, not the
carrier issuer. To satisfy the required verified-expiry input, the PS token
endpoint now verifies its agent JWT before trusting exp. This is a local
issuance prerequisite, not the Phase 3 middleware/signature rewrite. Existing
PS fixtures that omitted AP discovery now publish the actual test AP signing
key; confirmation keys remain unchanged. Two verifier-negative fixtures use an
explicit historical issuance clock to create a token that later expires.

VS Code still discovers no tests; executable validation uses dotnet test.
The initial builder regression reproduced ten failures before the fix; the AS
claims regression separately reproduced seven failures before its fix. A test
fixture initially omitted AAuthVerifier registration, and a mechanical Perl
fixture rewrite produced four malformed route initializers. Both were repaired
locally and the same focused checks passed before continuing. No packages,
crypto/signing/transport implementation changes, delegation, commits, or branch
changes were made. Primary sample builders and embedded examples were updated;
their step numbering/navigation did not change.

### [2026-09-08] [Phase 2] Release fixture timing correction - RESOLVED

The first Release solution gate exposed one timing-dependent federation stub:
it minted with a fresh one-hour source ceiling after the original agent token
was created, occasionally exceeding that token by one second. Production PS
delivery correctly rejected the response. The stub now verifies the actual
forwarded agent token, retains its expiration for both immediate and deferred
minting, and derives response lifetime from that ceiling. The same Release
federation class passed (4/4), then the full build/test gate passed (1231/1231).
The initial failed full run is not counted as a pass.

### [2026-09-08] [Phase 3] Necessary coupled changes - RESOLVED

Removed the legacy issuer-verification toggle rather than keeping a misleading
no-op setting. Generalized server key collections and refreshed their compiled
callers to honor advertised ES256. Resource-managed primary samples required
agent-token acquisition as part of the signing-policy cutover, not a later docs
phase. Existing PS issuance TimeProvider was forwarded into middleware after
the deferred-expiry regression exposed clock disagreement. All were required
coupled Phase 3 changes. Phase 4 egress/DNS/redirect/cache-floor work is not
implemented. No delegation, commit, branch change or crypto package upgrade
occurred. StructuredFieldValues 0.7.7 is the only new package.

### [2026-09-09] [Phase 12] New-capability scenario coverage - RESOLVED (scope)

The owner requires runnable GuidedTour and SampleApp scenarios for every new
user-facing capability not already taught by an existing flow, with Playwright
tests following the existing app suites. New resource projects are authorized
selectively: each resource must have one clear purpose and readable source that
serves as an example. Reuse is preferred only where it preserves that purpose;
adding unrelated features to Bookings merely because it already runs is not the
default, nor is adding a server for each test variation.

The implementation plan now requires a Phase 12 capability-to-scenario matrix,
closure of uncovered flows in both apps, documented resource selection, and
solution/demo/test/CI wiring for any new resource. Phase 13 checks the resulting
snippets, numbered steps, visuals and resource documentation; Phases 14-15 review
and recheck completeness after repairs. Internal security fixes retain focused
negative tests rather than artificial UI flows. Previously excluded optional
capabilities are not silently brought into scope by this scenario requirement.

Existing Events scenarios and prior browser results are evidence to inspect,
not blanket completion of this new matrix. The added acceptance checkboxes
remain unchecked. This entry records the approved scope update; no resource,
scenario or Playwright test was created by this documentation edit.

## Open Questions

### [2026-09-09] [Phase 11] Owner revisit closure - RESOLVED

Supersedes the 2026-09-08 Inbox credential-provenance/API revisit below without
rewriting its history. Retain conformant agent-JWT Inbox access; keep generic
pseudonymous Profile demonstrations separate. GuidedTour self-issues locally;
SampleApp signs AP enrollment then refreshes through the enrolled builder.
AP setup/verification discovery are not PS/AS resource authorization. The owner
can review the explicit From defaults, ownership, fixed-key TwoKey rejection and
DI fail-closed choices in the final ledger and API map. No clarification remains
blocking Phase 11; subsequent security/docs phases retain their own gates.

### [2026-09-09] [Phase 5] Remaining live environment gate - PROCEEDED

The final configured realm check at localhost:18080 failed with connection
refused (HTTP 000). Live Keycloak remains unverified and is the single skipped
browser case; in-process Keycloak tests pass but do not replace it. Starting
the realm and running KEYCLOAK_E2E=1 is an environment follow-up, not a blocker
to the completed reported runtime repairs. The phase's all-environment checkbox
remains open. No host credentials were invented or hardcoded. Deployment-specific
person mapping and OS isolation require host/operator validation; the SDK
cannot certify those from local stub tests. There are zero failing final local
tests, not a blanket claim that every deployment or later-phase concern is closed.

### [2026-09-08] [Phase 5] Live IdP and independent review - BLOCKED

The configured Keycloak realm at
<http://localhost:18080/realms/aauth/.well-known/openid-configuration> was
unreachable (curl returned HTTP code 000). The fresh browser gate therefore has
one explicit `KEYCLOAK_E2E=1` skip. Live Keycloak authentication is unverified;
the seven passing in-process Keycloak tests use a stub IdP transport and establish
the callback/browser binding and no-stub-bypass behavior, not live deployment.
The final Phase 5 all-environment gate remains unchecked for this reason. No
implementation capability was moved to a later documentation phase.

No external read-only reviewer report was received in this execution. No
independent review or disposition of unseen findings is claimed. Parent
orchestration can apply the reviewer report without attributing these local
checks to that reviewer. Local findings and their repairs are recorded above.
No implementation clarification is needed; the remaining actions are starting
the configured live Keycloak fixture for its browser gate and receiving the
independent review report.

### [2026-09-08] [Phase 4] Remaining environment and deployment gates - RESOLVED

No known reproducible Phase 4 blocker remains. Live Keycloak mode was not run;
its browser test is the recorded skip. External live interop and a public TLS
deployment were not exercised. Production negative transport tests used the
actual socket handler and real local servers; they are not a claim of live
external interoperability. Events projects are not in this solution yet.

Browser navigation after an admitted callback remains outside SDK socket control.
Caller-provided network transports and R3 callbacks must fulfill their explicit
policy contract; `AttachPolicy` does not inspect or repair opaque implementations.
Samples use only their configured loopback origins and keep HTTPS private
destinations blocked. Fixed local ports changed by a host need a corresponding
explicit policy update. Pre-v10 persisted sample keys still need a deliberate
operator migration/replacement; isolated e2e storage did not modify them.

### [2026-09-08] [Phase 4] Browser failures and final validation - PROCEEDED

The first browser attempt stopped during startup because the default home held
a pre-v10 AP signing key rejected by Phase 3's algorithm checks. No persisted
user key was edited or deleted. Subsequent runs used a fresh temporary HOME with
the existing NuGet and Playwright caches explicitly retained. This changes test
storage only, never network admission.

The first full isolated-key browser run passed 34, failed 15, and skipped one.
GuidedTour's manual interaction parsers still omitted their explicit sample
policy, preventing consent links. They now pass the policy and admit DNS before
exposing the URL. Sample enrollment's static metadata URL calls were also fixed.
Browser validation exposed a coupled Phase 3 Bookings error: its agent resource
requests used the restricted document-reader verifier, which only accepts
`jwks_uri`. Bookings now verifies `jwt` through the typed middleware separately;
R3 document readers retain their trusted `jwks_uri` gate. The direct-JWKS browser
test's obsolete heading and scheme assertions were aligned with the actual page.

The next complete fresh-service browser run passed 49/50 with one Keycloak-only
skip, no retries. Both app projects, all stub flows, R3 grant/approval/denial,
missions and call chaining ran. A later Release rerun caught a timing-dependent
poller exception: expiration of the overall budget could leak
`TaskCanceledException`. It now returns `TimeoutException` for its own budget,
preserves caller cancellation, and guards a budget expiring during request setup.
The focused poller class passed 7/7 after repair. Final full gates are being rerun.

Additional Phase 11 inventory: policy-aware `InteractionRequiredAAuth`,
`R3Challenge.EgressPolicy`, `R3FetchClient` ownership/disposal, exact R3 PS trust
predicate inputs, and `TokenExchangeClient.EgressPolicy`. Discovery refuses a
supplied policy that differs from an injected client's declared policy. Owned
R3 transports are disposed after fetches; late injected responses are disposed
after deadline cancellation. No specification snapshots or persistence keys changed.

### [2026-09-08] [Phase 0] Evidence still to collect - PROCEEDED

Full baseline solution/e2e results, parser selection and existing Events storage
review are pending. They are not recorded as passes or completed implementations.
The research's 62 focused passing tests are historical baseline evidence only.

### [2026-09-08] [Phase 1] Remaining verification boundaries - RESOLVED

No Phase 1 blocker remains. Release-configuration solution tests, browser e2e,
live Keycloak, and external interop were not run for this phase and are not
claimed as passes. SampleApp and GuidedTour compile, but their browser workflows
were not exercised here. Editor diagnostics reported pre-existing TypeScript
`moduleResolution=node10` and `baseUrl` deprecations in `tests/e2e/tsconfig.json`;
that file is unchanged. Later phase gates retain responsibility for those checks.

### [2026-09-08] [Phase 2] Remaining verification boundaries - RESOLVED

No Phase 2 blocker remains. Phase 2 completion boxes were checked only after the
final solution gates passed. No later phase is marked complete. Browser e2e,
Keycloak, live external interop, and sample browser execution were not run for
this phase. The full Release gate builds the solution's current projects; Events
has no included test project yet, so no Events test pass is implied. Existing
Phase 1 edits were preserved; no delegation, commit, branch change, or package
installation occurred.

### [2026-09-08] [Phase 3] Remaining verification boundaries - RESOLVED

No known Phase 3 implementation blocker remains; only Phase 3 completion boxes
were updated in this run. Full browser suite, live Keycloak policy mode and
external interop were not run and are not claimed as passes. AS Keycloak stub
integration tests pass but do not establish a live Keycloak deployment. Events
is not included in the current solution tests. Later phases retain those gates.
Persisted pre-v10 sample keys require deliberate replacement or an explicit
offline migration by their owner; this alpha cutover intentionally rejects them.
The owner prohibited delegation, so reviewer leads were resolved with local
source checks and adversarial tests, not an independent subagent review.

### [2026-09-08] [Phase 11] Inbox credential provenance and API revisit - PROCEEDED (review open)

The owner correctly recalled that the original resource-managed Inbox example
used pseudonymous hwk. Phase 3 deliberately changed both primary samples to
agent JWTs. GuidedTour's displayed snippet now assumes an existing agentToken;
SampleApp ensures AP enrollment and constructs an AgentProviderTokenRefresher
manually. The exact acquisition path and all displayed setup steps must be
rechecked in the API phase, not inferred from a successful flow test.

The rationale was the protocol's Keying Material requirements at
[v10 L2420](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2420)
and [L2422](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2422):
AAuth resource access uses an agent/auth JWT, not bare hwk. This requirement
does not add a PS or AS authorization exchange to resource-managed access.
Agent provisioning/key refresh and the subsequent two-party authorization flow
are separate, and the examples must make any AP contact explicit.

The distinction and example design are reopened at the owner's request. Decide
and document whether a generic pseudonymous example is retained separately;
do not label it as conformant AAuth resource-managed access without reconciling
the normative requirements. Keep the current wire behavior pending that review.
The manually wired refresher is not the desired final convenience API. Review
Enrolled/RefreshingFrom/WithKeyStore composition and From(EnrollResult) defaults,
then update runtime calls and embedded snippets together. This supersedes any
interpretation of the Phase 3 sample gate as final approval of API ergonomics
or instructional completeness.

### [2026-09-08] [Phase 11] Review delegation attribution - RESOLVED

The earlier Phase 3 note saying the owner prohibited delegation is inaccurate.
The owner explicitly requested adversarial subagents. The restriction applied
only to nested delegation within that implementation worker. Independent
logical-area reviews and repeated repair/review passes remain required.

### [2026-09-08] [Phase 11] Direct credential and builder trace - RESOLVED (evidence only)

Confirmed both original examples used UseHwk by diffing against `ba768f1`.
GuidedTour's EnsureAgentReadyAsync self-issues its agent token using the tour's
own published identity; the resource-managed step invokes it before signing.
SampleApp EnrollmentService performs enrollment but discards the initial token;
Inbox's manually constructed refresher acquires a fresh token from the AP.
Neither token is an auth token obtained from a PS/AS authorization exchange.

Added the exact source paths/lines and a seed API map to research F29.
EnrolledBuilder already provides RefreshingFrom/WithKeyStore and an
interaction-handling forwarder, but no direct resource-managed-access forwarder.
From(EnrollResult) chooses direct jwks while its comment says jwks_uri. These
facts support a real convenience/composition and terminology review, not an
automatic facade for every new low-level type. The sample design ruling remains
open; no SDK or sample runtime files were changed for this owner-requested update.