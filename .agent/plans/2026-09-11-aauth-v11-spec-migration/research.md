---
description: Draft-11 WIP breaking-change research against the current draft-10 SDK.
---

# Research - AAuth draft-11 WIP migration

## Status and scope

Research date: 2026-09-11. Analysis baseline: SDK commit
`94576a3ebcba8cd1d167923e50c8796132057600` on `wip/aauth-draft-11`.
Existing uncommitted changes vendor the draft-11 working reference; they do not
change SDK behavior. Research and planning do not authorize implementation.

The SDK currently targets published draft-10. The proposed target is the
unpublished draft-11 working snapshot, not a published release or a conformance
claim. Spec accuracy takes precedence over backward compatibility: a later
approved migration uses one coordinated wire/API cutover, without legacy aliases
or dual-format parsing. Unresolved WIP requirements receive explicit rulings.

## Evidence baseline

- [Protocol](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md),
  [R3](../../../aauth-spec/v11/draft-hardt-aauth-r3.md),
  [Bootstrap](../../../aauth-spec/v11/draft-hardt-aauth-bootstrap.md),
  [Events](../../../aauth-spec/v11/draft-hardt-aauth-events.md),
  [Budgets](../../../aauth-spec/v11/draft-hardt-aauth-budgets.md), and the
  [interop profile](../../../aauth-spec/v11/interop-demo-profile.md) are pinned to
  AAuth commit `55ae44cc3a07da29c4d6821c3800569ac77b9441` (2026-09-08).
- [Signature Keys working source](../../../aauth-spec/v11/draft-hardt-httpbis-signature-key.md)
  is pinned to `10a7563beecb2a461d5b412549a69d49f97f500c` (2026-09-03).
  [Published draft-08](../../../aauth-spec/v11/draft-hardt-httpbis-signature-key-08.txt)
  is retained separately. The protocol's dependency reference is unversioned.
- [Draft-10 migration research](../2026-09-08-aauth-v10-spec-migration/research.md)
  supplies the document pattern, not evidence of today's defects. Its original
  code findings describe a baseline that the completed migration replaced.

## Research method

Five read-only reviewers inspected token/exchange/discovery contracts, missions
and delegation, signatures/revocation/errors, companion specifications, and
sample/documentation consumers. The primary reviewer reconciled overlaps and
re-read the highest-risk token, R3 execution, Events ticket, revocation graph,
and upstream-token boundaries. Wire names and separator-free .NET names were
both searched. Earlier plans, source summaries, and history bullets were leads,
not proof of current behavior. No runtime tests were run for this initiative.

The evidence distinguishes DELTA, PRE-EXISTING, ALREADY, OPTIONAL, and
WIP-AMBIGUITY. P1 denotes a trust-boundary, identity, or execution-safety migration
risk; P2 a wire/API or workflow break; P3 a documentation or optional feature
impact. These are migration priorities, not claims that implementing draft-10
was itself a vulnerability. D means the primary reviewer directly re-read the
decisive source; R means a read-only area reviewer inspected it. R is not an
independently reproduced runtime defect. See the
[conformance ledger](conformance-ledger.md) for negative requirements and planned
checks; passing old fixtures is not evidence for a changed contract.

Coverage is a change-oriented source audit of the SDK, all companion packages,
compiled callers, and live documentation. It is not a new complete MUST-by-MUST
certification, exhaustive generated overload inventory, or browser test run.
Explicit WIP conflicts and deployment-only controls remain open below.

## Executive assessment

This is a coordinated identity and authorization redesign, not a version bump.
The person-token leg precedes resource authorization; resource-facing identity
becomes person/key based; exchanges carry the credential whose `jti` the
resource named. Mission provenance, delegation records, cache partitions,
revocation ancestry, R3 execution state, and both walkthrough apps change with it.

Two cross-package risks require early decisions: protected Events tickets
currently require an agent identifier that draft-11 auth tokens do not carry
(F20), and the grant store conflates revocation ancestry with expiry ceilings
(F15). Removing OpenAPI Gateway affects a complete public API and Catalog sample,
not just a vocabulary constant (F18).

> [!NOTE]
> The earlier vendoring summary overstates R3 hashing and per-call proposals as
> new changes. Exact-byte hashing, per-call proposals, and multi-definition
> composition already occur in the pinned v10 text. F18 and the preservation
> table below use the actual source comparison. The existing changelog is not
> modified by this research.

## Deliverables

- [API surface map](api-surface-map.md): current contracts, proposed replacements,
  consumers, ownership, and defaults; not a generated declaration delta.
- [Docs surface map](docs-surface-map.md): live pages and embedded-content classes.
- [Capability scenarios](capability-scenarios.md): both primary apps and their
  shared protocol/test changes.
- [Conformance ledger](conformance-ledger.md): findings, negative requirements,
  governing evidence, and discriminating future regressions.
- [Implementation plan](implementation-plan.md): dependency-ordered phases and
  unchecked definitions of done.
- [Implementation log](implementation-log.md): research scope record and pending
  Phase 0 rulings, with no implementation authorization implied.

## Confirmed breaking changes

### F01 - Auth-token identity contract changes

P1 migration risk; draft-11 delta; directly reverified.

Draft-11 requires `ps` and `sub` at
[protocol L1878](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1878)
(`#auth-token-structure`) and
[L1879](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1879).
It removes the agent identifier and delegation chain at
[L1884](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1884),
and carries the mission hash as `mission_s256` at
[L1889](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1889).

The current [AuthTokenBuilder](../../../src/AAuth/Tokens/AuthTokenBuilder.cs#L44)
requires `Agent`, exposes optional `Subject`, and accepts a
scope-only token at
[L167](../../../src/AAuth/Tokens/AuthTokenBuilder.cs#L167).
The controlling payload construction emits `agent` at
[L209](../../../src/AAuth/Tokens/AuthTokenBuilder.cs#L209) and `act` at
[L219](../../../src/AAuth/Tokens/AuthTokenBuilder.cs#L219).

This affects producers and consumers together, not a constant rename. Future
verification must inspect issued claims and reject missing person identity while
preserving confirmation-key, issuer, audience, scope, account, and expiry checks.
The lack of an agent identifier at a resource must not be filled by trusting
claims from an unverified JWT or by inventing an agent identity from `sub`.

### F02 - Person-token issuance, verification, and caching are absent

P1; DELTA; R. [P937](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L937)
(`#person-token-endpoint`) requires every PS to issue person tokens;
[P603](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L603)
(`#person-token-structure`) bounds expiry, and
[P633](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L633)
forbids `scope` and `account` in them.
[DefaultSignatureKeyResolver L70](../../../src/AAuth/HttpSig/DefaultSignatureKeyResolver.cs#L70)
rejects unrecognized JWT types; there is no built-in person-token lifecycle.
Adding an enum alone cannot establish issuer trust or prevent person tokens
being accepted where an auth token is required.

[P977](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L977)
(`#person-token-endpoint`) requires issuance records for revocation;
[P979](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L979)
describes resource/mission caching and lazy re-acquisition after key rotation.
[AAuthTokenHolder](../../../src/AAuth/Agent/AAuthTokenHolder.cs#L25)
holds one current carrier, not a collection of person tokens. Proposed cache
partitioning also includes the owning person/PS, effective worker or caller key,
and upstream authorization context. PS requests must continue using the agent
credential, never the current resource-facing person/auth credential.

### F03 - Resource tokens need verified presented identity

P1; DELTA, WIP-AMBIGUITY; R.
[P781](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L781)
(`#requirement-auth-token`) forbids issuing an auth-token challenge to an
agent-only request. [P688](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L688)
(`#authorization-endpoint-request`) requires a person token at that endpoint.
[AAuthChallengeMiddleware L127](../../../src/AAuth/Server/Challenge/AAuthChallengeMiddleware.cs#L127)
currently starts resource-token issuance from an agent token;
[ResourceTokenBuilder L126](../../../src/AAuth/Tokens/ResourceTokenBuilder.cs#L126)
emits the agent identifier. The future issuance context must retain verified
`ps`, `sub`, `presented_jti`, key thumbprint, mission, and tenant.

The broad person-only statement at
[P674](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L674)
(`#resource-tokens`) conflicts with the explicit person-or-auth step-up rule at
[P858](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L858)
(`#resource-token`). Q2 records the proposed initial-person/runtime-step-up distinction.

### F04 - Every exchange needs the exact presented token

P1; DELTA; R. [P1004](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1004)
(`#ps-token-endpoint`) makes `presented_token` required;
[P903](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L903)
(`#resource-token-verification`) defines the signature, audience, key, `jti`,
PS, subject, mission, and tenant correspondence; the AS repeats the check at
[P1688](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1688)
(`#ps-to-as-token-request`).
[TokenExchangeClient L104](../../../src/AAuth/Agent/TokenExchangeClient.cs#L104)
starts with only `resource_token`;
[AccessServerClient L121](../../../src/AAuth/Access/AccessServerClient.cs#L121)
forwards the agent token without this new parameter.

Capturing the original request credential matters: a concurrent holder refresh
must not substitute a different token with otherwise identical claims. Pending
consent, clarification replacement, worker requests, and federation must retain
that provenance. Resource-token binding changes are independent of the old
resource signature and key checks, which remain necessary.

Clarification replacement is a separate WIP ambiguity, not a rule to retain
the original credential forever. [P1194](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1194)
(`#updated-request`) constrains replacement `iss/ps/sub/agent_jkt`, but not
`presented_jti`. The new resource token can therefore name a different presented
credential. [ClarificationResponse.Update L63](../../../src/AAuth/Agent/ClarificationExchange.cs#L63)
accepts only a resource token and justification. Both PS and AS pending handlers
need the Q13-agreed replacement wire contract: retain the original pair when
unchanged, or verify and atomically install a new pair. Never mix an old
presented token with a resource token naming a refreshed one.

### F05 - Metadata and access-mode contracts break

P2; DELTA, OPTIONAL; R.
[P2737](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2737)
(`#ps-metadata`) starts the new auth/person endpoint requirements;
[P2807](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2807)
(`#resource-metadata`) defines person/session modes and unknown-mode fallback.
[ServerMetadata L84](../../../src/AAuth/Discovery/ServerMetadata.cs#L84)
reads `token_endpoint`, and
[WellKnownEndpoints L230](../../../src/AAuth/Server/Metadata/WellKnownEndpoints.cs#L230)
emits it. Public properties, option validation, serializers, consumers, and
fixtures need the same cutover. Keycloak's OIDC `token_endpoint` is unrelated.

[P2667](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2667)
(`#metadata-documents`) defines optional `accept_signature_algs`;
[P2832](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2832)
(`#resource-metadata-link`) constrains discovery links before fetching, and
[P2836](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2836)
excludes links from verifier key discovery. Link discovery and algorithm
advertisement are explicit optional capabilities, not trust shortcuts.

### F06 - Resource authorization must stop depending on agent claims

P1; DELTA with ALREADY controls; R.
[P1920](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1920)
(`#request-context-binding`) establishes resource identity by `(iss, sub)`;
[P2959](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2959)
(`#person-token-org-policy`) excludes tenant from that person identifier.
[AAuthAuthenticationHandler L98](../../../src/AAuth/Server/Verification/AAuthAuthenticationHandler.cs#L98)
already qualifies person identity by issuer; preserve it.
[AgentAuthTokenValidator L41](../../../src/AAuth/Tokens/AgentAuthTokenValidator.cs#L41)
instead requires the removed `agent` claim for token correspondence, and
[verification middleware L290](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs#L290)
reads `act`. Verified result types, claims projection, authorization policies,
token holders, resource response bodies, and inspectors all consume these fields.
Agent identity remains valid on agent-token/AP/PS paths; blanket removal is wrong.

### F07 - Mission approval becomes an exact-byte envelope

P2; DELTA with ALREADY byte preservation; R.
[P1509](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1509)
(`#mission-approval`) encodes the blob, and
[P1534](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1534)
(`#mission-identifier`) hashes the persisted bytes.
[MissionClient L73](../../../src/AAuth/Agent/Governance/MissionClient.cs#L73)
parses the entire response as the mission;
[governance mapper L485](../../../src/AAuth/DependencyInjection/AAuthGovernanceApplicationBuilderExtensions.cs#L485)
returns raw blob bytes. The new envelope separates `s256`, encoded `mission`,
session `capabilities`, and optional resource-keyed `person_tokens`.
Existing `Mission.RawBytes` and `StoredMission.Blob` are useful preservation
boundaries. Envelope formatting must not affect the mission digest.

[P886](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L886)
(`#resource-token-structure`) requires mission-hash copying from the presented
token. [AAuthChallengeMiddleware L195](../../../src/AAuth/Server/Challenge/AAuthChallengeMiddleware.cs#L195)
currently gates parsed `AAuth-Mission` propagation on `MissionAware`.
Header removal includes clients, server options, covered-component lists,
code snippets and forwarding middleware, not just the header parser.

### F08 - Mission updates and completion change routes and policy state

P1; DELTA; R.
[P1414](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1414)
(`#missions`) defines update/completion action routes;
[P1568](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1568)
(`#mission-update`) binds accepted update bytes; at
[P1578](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1578)
auditing must include both blob and updates.
[MissionSession L139](../../../src/AAuth/Agent/Governance/MissionSession.cs#L139)
currently proposes completion through interaction.
[IMissionLog L9](../../../src/AAuth/Server/Governance/IMissionLog.cs#L9)
has no accepted-update entry, while
[PS endpoints L621](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L621)
can use prior consent before policy evaluation. Updates must be visible to that
fast path; immutable blob identity does not imply unchanged supervision context.
Existing deferred consent and person-accepted completion should be reused.

### F09 - Mission expiry, irreversibility, and owner privacy

P1; DELTA and PRE-EXISTING API risk; R.
[P1522](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1522)
(`#mission-approval`) applies expiry to every PS decision;
[P1637](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1637)
(`#mission-endpoint-errors`) requires equivalent missing/foreign responses,
including observable timing.
[GovernanceEndpoints L33](../../../src/AAuth/Server/Governance/GovernanceEndpoints.cs#L33)
checks owner and state, but not the new expiry field. Deferred and resumed
decisions need the same clock-aware checks.

[P1613](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1613)
(`#mission-management`) forbids reactivation, while
[InMemoryMissionStore L39](../../../src/AAuth/Server/Governance/InMemoryMissionStore.cs#L39)
permits assigning another state; saving a replacement record is another path.
Permanent termination already appears in
[v10 P1449](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1449),
so the permissive store is a pre-existing risk, not wholly a v11 delta.
Termination reason is an open string separate from state. Timing equivalence
cannot be claimed from equal status codes or an unexecuted unit-test proposal.

### F10 - Consent evidence needs provenance through extension hooks

P1; DELTA, OPTIONAL supervision extension; R.
[P1111](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1111)
(`#consent-presentation`) requires visual distinction and attribution;
[P1113](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1113)
forbids relying solely on agent assertions when resource evidence is available.
[MissionTokenConsentContext L122](../../../src/AAuth/Server/Governance/IMissionTokenConsent.cs#L122)
does not separate the new evidence classes, and
[sample consent L891](../../../samples/MockPersonServer/Program.cs#L891)
renders a limited agent/resource/scope view. The API needs resource descriptions,
R3 display, justification, and accumulated mission context with their sources,
without treating sanitized Markdown as trustworthy authorization evidence.
[P456](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L456)
(`#roles`) leaves delegated supervision to a companion; it does not define a
new on-wire SS role. Existing policy/consent hooks are the appropriate extension.

### F11 - Parent and chained person acquisition change trust topology

P1; DELTA and WIP-AMBIGUITY, partly PRE-EXISTING; D for upstream ambiguity,
R for parent and mission paths.
[P2020](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2020)
(`#sub-agents`) begins with the parent obtaining the worker's person token;
[FederatedWorkerScenario L52](../../../samples/FederatedWorkerScenario.cs#L52)
currently presents the worker agent token directly.
[P1951](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1951)
(`#call-chaining`) routes via upstream `ps` rather than the current router's
[issuer fallback](../../../src/AAuth/Server/CallChaining/CallChainingRouter.cs#L96).
Removing `act` must not remove authenticated parent/delegation evidence at PS/AS.

The spec imports resource-context verification at
[P1936](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1936)
(`#upstream-token-verification`), but requires intermediary audience at
[P1938](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1938).
[P1955](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1955)
says the upstream token's `cnf` is the intermediary key, although the caller's
received auth token normally binds the caller key.
[UpstreamTokenValidator L120](../../../src/AAuth/Tokens/UpstreamTokenValidator.cs#L120)
uses the token's own confirmation key, not a comparison with the intermediary.
The conflicting key/audience wording also exists at
[v10 P1770](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1770)
and [P1796](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1796).
This requires Q3, not a silent weakening or a fabricated normative rule.

Mission ownership at
[P944](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L944)
(`#person-token-endpoint`) and upstream person resolution at
[P948](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L948)
need explicit delegated context. Downstream `sub` must be independently derived,
not copied, under
[P1965](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1965)
(`#directed-sub-chaining`). Q4 covers evidence and consent-cache isolation.

### F12 - Strict expiry and refresh coordination

P1; DELTA with ALREADY issuance bounds; R.
[P1386](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1386)
(`#refresh-margin`) removes verifier expiry tolerance and makes a future-`iat`
bound optional. [TokenVerifier L122](../../../src/AAuth/Tokens/TokenVerifier.cs#L122)
uses `exp + skew`, while
[NamingTokenVerifier L40](../../../src/AAuth/HttpSig/NamingTokenVerifier.cs#L40)
also admits expiry skew. Both header and body paths matter. Agent expiry and
the one-hour auth limit are already checked; the new presented-token and
mission ceilings augment them, as required by
[P1882](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1882)
(`#auth-token-structure`).

[TokenRefreshHandler L34](../../../src/AAuth/Agent/TokenRefreshHandler.cs#L34)
defaults to a one-minute threshold. The five-minute recommendation and top-down
refresh at [P1390](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1390)
and [P1398](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1398)
(`#refresh-margin`) require coordinated agent/person/auth caches.
It is not a rule to reject all five-minute resource tokens; Q7 records this
ambiguity and the permitted idempotent reactive renewal exception at
[P1400](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1400).

### F13 - Role-specific body signatures and time errors

P1; DELTA with ALREADY server identity; R.
[P2535](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2535)
(`#covered-components`) requires PS/AS body digest and content-type coverage.
[AAuthSigningHandler L145](../../../src/AAuth/HttpSig/AAuthSigningHandler.cs#L145)
digests only when configured; verification options default to no extra required
components. Correctly signed malformed JSON remains a body error, while missing
coverage or changed bytes fails authentication before policy runs.

[P2501](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2501)
(`#keying-material`) fixes server signing as `jwks_uri`; current
[federation registration L65](../../../src/AAuth/DependencyInjection/AAuthFederationServiceCollectionExtensions.cs#L65)
already uses the PS issuer and role document.
[P2572](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2572)
(`#verification`) distinguishes future `created` as `clock_skew`; current
[AAuthVerifier L149](../../../src/AAuth/HttpSig/AAuthVerifier.cs#L149)
combines past/future rejection and uses a different future allowance.
Generic signing and Events profiles must remain separate from these role rules.

### F14 - Revocation wire authority and unknown-token behavior change

P1; DELTA; R for endpoint/client, D for store.
[P2400](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2400)
(`#token-revocation`) derives issuer from the verified caller;
[P2430](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2430)
requires recorded revocation to return 200 even without a token record.
[RevocationClient L28](../../../src/AAuth/Server/RevocationClient.cs#L28)
sends `iss/jti`, while
[InMemoryJtiStore L69](../../../src/AAuth/Server/InMemoryJtiStore.cs#L69)
cannot revoke an unknown token. New bodies use `jti/exp`, with bounded unseen-token
records, authenticated issuer admission, idempotent acknowledgement, and no
policy override allowing a PS to select an AS issuer namespace.
Retain the internal `TokenKey(iss,jti)` model and collision protection.

### F15 - Revocation dependencies are not all lifetime ceilings

P1; DELTA; D.
[P2447](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2447)
and [P2448](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2448)
(`#token-revocation`) add person/resource-token withdrawal and cascades.
[InMemoryJtiStore L112](../../../src/AAuth/Server/InMemoryJtiStore.cs#L112)
requires every source record to outlive the issued grant. Reusing that rule for
resource-token ancestry would incorrectly cap auth tokens at resource-token
expiry. Resource-token lifetime is explicitly independent of mission lifetime at
[P892](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L892)
(`#resource-token-structure`); auth ceilings are separately enumerated at
[P1882](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1882).

The model needs distinct revocation edges and verified expiry bounds, including
person-token destination/AS records, step-up ancestry, pending issuance, and
withdrawal while consent is open. In four-party access a PS revokes its person
token at the AS; it does not directly revoke an AS-issued auth token. Atomic
recording, retryable delivery, and retention are separate responsibilities.

### F16 - Error taxonomy and AS failure propagation

P2; DELTA with ALREADY typed carriage; R.
[P2461](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2461)
(`#token-revocation`) uses header `revoked_jwt`, body revoked-token codes, and
pending `revoked`; current
[verification middleware L262](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs#L262)
returns `InvalidJwt` for revocation.
[P1755](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1755)
(`#auth-token-delivery`) relays AS terminal error/status and maps unavailable
or unverifiable results to `as_unreachable` (502).
[PS endpoints L1458](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L1458)
uses `federation_failed`; some deferred error paths collapse distinctions.

Typed signature-versus-body errors already exist. Extend `TokenCredential`,
error enums, problem mapping, pending results and client recovery without
reintroducing body-token failures as signature 401s. Clock skew calls for wait
or surfacing, not automatic token refresh; revoked resource tokens must not be
resubmitted. The 403 signature-header prohibition remains unchanged at
[P2584](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2584)
(`#verification`). Signature Keys does not yet define the new two header codes:
Q1 is a conformance gate, not an excuse to invent dependency text.

### F17 - Deferred auth challenges require an execute-once state machine

P1; DELTA, conditional resource capability; D for R3 consumer, R for agent loop.
[P812](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L812)
(`#deferred-auth-token`) requires agents to support 401 and 202 delivery;
[P810](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L810)
requires retained results for repeated presentation.
[ChallengeHandler L197](../../../src/AAuth/Agent/ChallengeHandler.cs#L197)
handles only 401 auth challenges. Existing interaction polling alone is not
auth-token exchange followed by signed GET completion.

[R702](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L702)
(`#per-call-flow`) requires single-use per-call grants on either delivery.
[R3Enforcement L142](../../../src/AAuth.R3/R3Enforcement.cs#L142)
checks grant/proposal/parameters then returns `Granted`, with no consumption
transaction. Per-signature replay protection does not prevent a second freshly
signed request under the same grant. Immutable proposal bytes and mutable
invocation/result state need separate identities and atomic ownership.
Generic pending-URL terminal 410 wording at
[P2909](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2909)
(`#pending-url-security`) conflicts with retained-result repetition: Q8 applies.

### F18 - R3 per-call APIs and OpenAPI Gateway removal

P2; DELTA with ALREADY hashing/proposals; D for vocabulary and hash comparison,
R for all public consumers.
[R596](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L596)
(`#auth-token-extensions`) defines `r3_per_call`;
[R3AuthClaims L12](../../../src/AAuth.R3/R3AuthClaims.cs#L12)
still defines `r3_conditional`. The document fields at
[R469](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L469)
(`#r3-document`) omit the v10 `version` field, while
[R3Document L16](../../../src/AAuth.R3/Model/R3Document.cs#L16)
and proposal/factory APIs expose it. Remove obsolete emission and public members,
but do not turn ignore-unknown extension parsing into a blanket rejection policy.

[R154](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L154)
(`#operation-identifier-scope`) requires a single valid definition or separate
resources; [R158](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L158)
lists seven standards. The eighth, OpenAPI Gateway, disappears, while
[Vocabulary L8](../../../src/AAuth.R3/Model/Vocabulary.cs#L8)
and [R3Metadata L27](../../../src/AAuth.R3/R3Metadata.cs#L27)
still expose its constant and service-map metadata. Catalog requires a real
replacement design; WSDL's legitimate `service` field is not a deletion target.

Exact-byte hashing is already stated at
[v10 R393](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L393)
(`#content-addressing`) and retained at
[v11 R488](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L488).
[R3Hash L10](../../../src/AAuth.R3/R3Hash.cs#L10) implements it, and
[R3Enforcement L170](../../../src/AAuth.R3/R3Enforcement.cs#L170)
already uses structural inline equality with separate digest-byte matching.
Neither requires introducing canonicalization.

### F19 - R3 person provenance, readership, and operation annotations

P1; DELTA, PRE-EXISTING readership risk, OPTIONAL annotation capability; R.
[R504](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L504) and
[R506](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L506)
(`#resource-token-extensions`) follows presented identity;
[R561](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L561)
(`#r3-processing`) identifies audit fields from verified resource/agent tokens.
[R3Challenge L65](../../../src/AAuth.R3/R3Challenge.cs#L65)
still emits `agent`; R3 AS policy can supply a subject independently of the
future presented identity. Shared exchange validation must cover R3 endpoints,
not only the core AS mapper.

[R754](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L754)
(`#r3-document-access-restriction`) identifies the entitled PS through the
resource token. [R3DocumentReaderPolicy L22](../../../src/AAuth.R3/R3DocumentReaderPolicy.cs#L22)
uses a global PS allowlist. Document-specific entitlement is necessary in
multi-PS hosts; a successful signature alone does not grant document access.

[R328](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L328) and
[R332](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L332)
(`#applying-annotations`) make annotations sparse and advisory;
[R312](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L312)
(`#access-mode-annotation`) forbids operation `session-token`.
MCP/OpenAPI/AsyncAPI/OData have encodings, not gRPC/GraphQL/WSDL.
Budget annotations are hints, never proof of metering. The rationale at
[R314](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L314)
mentions agent tokens on every request, contrary to person presentation at
[P637](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L637)
(`#person-token-usage`); it does not authorize stacking credentials.

### F20 - Unchanged Events breaks through protected ticket identity

P1; DELTA through dependency, WIP-AMBIGUITY; D.
[Events L607](../../../aauth-spec/v11/draft-hardt-aauth-events.md#L607)
(`#pre-authorized-subscription-url-security`) binds tickets to the originating
agent, but [P1884](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1884)
(`#auth-token-structure`) removes that identity at resources.
[BookingsEvents L23](../../../samples/EventSupport/BookingsEvents.cs#L23)
requires `authorization.Payload["agent"]` to issue a ticket;
[EventStores L18](../../../src/AAuth.Events/EventStores.cs#L18)
persists agent identity in the ticket contract. The proposed new auth token
cannot satisfy this path. Person `sub` is not an agent ID, and parsing an
unverified agent claim is not a repair. Q5 must resolve trusted binding and any
SQLite schema transition before claiming protected Events compatibility.

The Events source itself is byte-identical to v10. AP-issued subscribe-token
`sub`, event audience, and the `self-jwt` event-token no-`cnf` rule at
[Events L368](../../../aauth-spec/v11/draft-hardt-aauth-events.md#L368)
(`#event-token`) remain distinct; do not remove those while deleting core `agent`.

### F21 - Result-release approval is optional but changes R3 policy inputs

P1 when enabled; DELTA model, OPTIONAL execution, WIP-AMBIGUITY; R.
[R675](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L675)
(`#proposal-document`) adds optional `result`; current
[R3ProposalDocument](../../../src/AAuth.R3/Model/R3ProposalDocument.cs#L16)
does not expose it to policy.
[R720](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L720)
(`#release-gating`) requires truthful display for already-executed operations;
[R722](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L722)
forbids executing first where execution is audited, metered, or billed.
It is unsafe to treat a missing policy field as an ordinary execute approval.
The conservative default is to expose the shape and reject unsupported release
requests explicitly, unless a complete scenario is selected.

[R745](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L745)
discusses unresolved executed-but-unreleased budget accounting. The pinned
[Budgets L867](../../../aauth-spec/v11/draft-hardt-aauth-budgets.md#L867)
(`#failed-calls`) instead delegates failed-call accounting to resource policy.
This is a cross-companion decision, not permission to ignore the prohibition.

### F22 - Budgets is a separate optional capability, not claim passthrough

P1 if enabled; OPTIONAL, WIP-AMBIGUITY; R.
[Budgets L560](../../../aauth-spec/v11/draft-hardt-aauth-budgets.md#L560)
(`#as-token-endpoint`) forbids AS budget issuance when the PS omitted it;
[L861](../../../aauth-spec/v11/draft-hardt-aauth-budgets.md#L861)
(`#overshoot`) requires atomic reservation/consumption bounds.
No built-in budget implementation was found; `AdditionalClaims` is not a
metering implementation. Required scope if selected includes amounts/units and
range validation, narrowing, reserve/commit/release transactions, usage and
settlement, issuer/person/resource isolation, headers/trailers, exhaustion,
cache/denomination rules, persistent records, and signed usage access.

Unresolved examples include no-drawdown refusal at
[L710](../../../aauth-spec/v11/draft-hardt-aauth-budgets.md#L710)
(`#exhaustion`) versus positive cost at
[L722](../../../aauth-spec/v11/draft-hardt-aauth-budgets.md#L722), and identifier
audience at [L942](../../../aauth-spec/v11/draft-hardt-aauth-budgets.md#L942)
(`#usage-response`) versus key-URL audience at
[L1007](../../../aauth-spec/v11/draft-hardt-aauth-budgets.md#L1007)
(`#usage-authorization`). Q10 defaults to a separately planned capability, with
explicit no-budget support rather than inert budget claims or sample promises.

### F23 - Bootstrap and generic signatures must retain their boundaries

P3; OPTIONAL additions, ALREADY generic support; R.
[Bootstrap L133](../../../aauth-spec/v11/draft-hardt-aauth-bootstrap.md#L133)
(`#conventions-and-definitions`) is informational, and
[L366](../../../aauth-spec/v11/draft-hardt-aauth-bootstrap.md#L366)
(`#sub-agent-tokens`) defines no hosted enrollment endpoint. New guidance covers
one operator/AP with multiple separately keyed agents and hosted/self-hosted
worker issuance. Current
[FederatedWorkerScenario L95](../../../samples/FederatedWorkerScenario.cs#L95)
already creates a parent-qualified worker token, not a hosted enrollment protocol.
The concrete-key [BootstrapBuilder L42](../../../src/AAuth/BootstrapBuilder.cs#L42)
limitation is pre-existing, not a draft-11 blocker.

Generic `hwk`, `jwks`, `self-jwt`, and naming-JWT APIs are not obsolete.
[P2596](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2596)
(`#scheme-rejection`) permits resources to serve non-AAuth clients too.
The delayed-verifier capability at
[P2604](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2604)
(`#freshness-and-replay`) needs an explicit offline/delayed policy and a cache
covering accepted delay; it must not weaken the normal online verifier.

### F24 - Executable walkthroughs and inventories encode old contracts

P2; DELTA and tooling limitation; D for generator, R for complete sample inventory.
The consumer implications of F01-F23 are mapped in the
[API](api-surface-map.md), [docs](docs-surface-map.md), and
[scenario](capability-scenarios.md) inventories.
[TourSession L300](../../../samples/GuidedTour/TourSession.cs#L300) and
[e2e tour helper L48](../../../tests/e2e/helpers/tour.ts#L48) hardcode step counts;
shared Wallet tests assert actor-chain fields. Updating only code snippets
leaves executable sequencing and captured payload selection inconsistent.

[ApiSurface L9](../../../tools/ApiSurface/Program.cs#L9) hardcodes the v10 map;
its default baseline is also historical. The
[snippet harness L228](../../../tests/AAuth.Tests/Api/SnippetCompilationTests.cs#L228)
uses the old docs inventory, and its
[HTTP-body check L299](../../../tests/AAuth.Tests/Api/SnippetCompilationTests.cs#L299)
expects `iss` whenever it sees `jti`, which is wrong for v11 revocation.
Do not run the writing generator against this initiative until destination and
baseline are parameterized. No declaration counts are claimed in these maps.

## Preservation and classification corrections

| Existing control | Evidence | Migration treatment |
|---|---|---|
| Exact R3 bytes, no JCS | v10 R393 and v11 R488 above; `R3Hash` | Preserve; not a new delta |
| Structural inline parameter equality | `R3Enforcement` L170, F18 | Preserve alongside single-use state |
| Per-call proposals and combined definitions | [v10 R3 L552](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L552), `#per-call-proposals`, and [L337](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L337), `#operations-spanning-multiple-definitions` | Already in v10; new execution guarantees remain F17 |
| Agent/auth expiry ceilings | `AuthTokenBuilder` L174-L182, F12 | Add presented/mission bounds without regenerating source expiry |
| Issuer-qualified person identity | `AAuthAuthenticationHandler` L98, F06 | Preserve; tenant is context, not identity |
| Server metadata issuer validation | `DefaultSignatureKeyResolver`, F13 | Preserve while adding metadata fields |
| Distinct parameter versus signature errors | Current typed error/result APIs, F16 | Extend rather than replace with string matching |
| Agent-token worker restriction | [PS endpoints L361](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L361) | Retain for new person endpoint too |
| Event token no-`cnf` | [EventsTokens L62](../../../src/AAuth.Events/EventsTokens.cs#L62), Events L368 above | Preserve distinct companion profile |

## Gaps and open questions

Defaults below are recommendations for Phase 0, not approved implementation
rulings. Security-sensitive ambiguities block the affected capability's
conformance claim; they do not block recording unrelated research.

| ID | Decision | Proposed default and evidence |
|---|---|---|
| Q1 | WIP baseline and Signature Keys error gap | Pin current sources; label interim behavior WIP. New header codes are protocol-local pending dependency alignment, not a claim of published Signature Keys conformance (F16). Re-diff publication before changing target claims. |
| Q2 | Person-only issuance wording versus auth-token step-up | Person at authorization endpoint and initial grant; verified auth for runtime step-up, following the explicit flow (F03). |
| Q3 | Upstream-token audience and confirmation-key contradiction | Keep live caller proof and intermediary signature distinct; obtain an upstream clarification or explicitly approved interpretation. No conformance closure based on matching the token's own key to itself (F11). |
| Q4 | Delegated person/mission authority after `act` removal | PS-authoritative person/grant records, explicit upstream/parent context; fail closed if unresolved. Scope consent caches by that authority and accepted mission updates (F08/F11). |
| Q5 | Events ticket binding without resource-visible agent ID | Block protected-ticket migration closure until a trusted binding contract is agreed. A verified key-bound ticket with agent proof at redemption is a candidate, not yet a spec ruling; never use person `sub` as agent ID (F20). |
| Q6 | Optional capability scope | Include core person/exchange/mission/revocation migration, existing R3 and Events, both apps, and seven-vocabulary Catalog replacement. Defaults for release, Budgets, annotations, link discovery, hosted enrollment, delayed verification are explicit in the plan. |
| Q7 | Time boundaries, lifetime wording, five-minute margin | Strict AAuth `exp`, independent optional future-`iat` bound using effective signature window; preserve generic profile separation. Resolve `exp-iat` MUST wording versus agent/resource SHOULD ceilings and margin versus five-minute resource lifetime before enforcement (F12). |
| Q8 | Execute-once result retention versus generic terminal 410 | Specific per-call/held-invocation retained-result rule wins for authenticated repeat completion until required retention ends; unrelated terminal pending URLs retain 410. Record atomicity, credential binding, concurrent behavior, and response-size limits (F17). |
| Q9 | Revocation store and delivery ownership | Separate expiry bounds from revocation edges; bounded unseen-token recording; acknowledge after local durability, track retryable outbound delivery independently. Confirm production store obligations and fail-before-issuance races (F14/F15). |
| Q10 | Full Budgets, release accounting, usage audience | Separate Budgets initiative by default. Release execution remains disabled unless its safety and accounting semantics are selected explicitly (F21/F22). |
| Q11 | Claims push versus fixed directed subject | Additional claims cannot replace verified `ps/sub/tenant/mission` provenance. A repeated `sub` must match, reconciling [P1686](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1686) (`#ps-to-as-token-request`) with [P1777](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1777) (`#requirement-claims`). |
| Q12 | Persistence and public API ownership | Reuse established keys, transports, clocks and stores; no package upgrade or parallel builder hierarchy by default. Choose explicit format isolation or migration for old mission/ticket/result stores without deleting user data (F07/F20/F24). |
| Q13 | Clarification replacement token pair | Confirm the `updated_request` body and PS-to-AS continuation contract when `presented_jti` changes. Verify a new pair before atomic replacement; never mix credentials across requests (F04). |
| Q14 | Revoked-auth challenge recovery | Clarify how a fresh resource token naming a revoked auth token can be redeemed while revoked presented tokens are refused. Proposed restart from fresh person token where necessary; no bypass of revocation (F16). |

Additional non-controlling inconsistencies remain visible: the profile's
[L52](../../../aauth-spec/v11/interop-demo-profile.md#L52) and
[L75](../../../aauth-spec/v11/interop-demo-profile.md#L75) omit explicit presented
token carriage, unlike P1004 (`#ps-token-endpoint`); and the identity exposure
prose at [P2947](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2947)
(`#person-token-exposure`) says no access while
[P576](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L576)
(`#person-tokens`) explains that identity-only resources may grant access.
Samples must teach the governing flow and actual resource policy, not repeat
misleading prose. The source snapshot remains unchanged.

## Questions for Dick Hardt

These questions concern the editor's draft at AAuth commit
`55ae44cc3a07da29c4d6821c3800569ac77b9441`, not a published draft-11 revision.
They distinguish blocking trust/flow questions from wording and optional-companion
clarifications. The linked lines identify the frozen source; section anchors are
listed so the questions remain useful when upstream line numbers move.

### Core trust and flow questions

1. Which Signature Keys revision should draft-11 implementations target for
  `clock_skew` and `revoked_jwt`? The protocol uses them at
  [P1388](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1388)
  (`#refresh-margin`) and
  [P2461](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2461)
  (`#token-revocation`), but neither published draft-08 nor the pinned working
  source defines them. Should they be treated as provisional AAuth extensions
  until a matching dependency revision is available? Related gate: Q1.

2. In call chaining, whose key is in `upstream_token.cnf`, and what exactly must
  the PS/AS compare it with? The received upstream auth token normally binds
  the original caller's key, but
  [P1955](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1955)
  (`#call-chaining`) says the intermediary's key. Meanwhile
  [P1936](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1936)
  imports full resource verification and
  [P1938](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1938)
  (`#upstream-token-verification`) binds audience to intermediary agent-token
  `iss`, which otherwise identifies its AP. Must intermediaries be their own
  AP, or is another authenticated resource-to-agent binding intended? Q3.

3. How does downstream person-token issuance prove delegated person and mission
  authority after `act` is removed? In four-party access the upstream auth
  token is AS-issued, while
  [P948](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L948)
  (`#person-token-endpoint`) says the upstream subject must have been issued
  by this PS. Does that mean a PS-derived subject copied into the AS token,
  resolved through retained federation records? Also, how does the intermediary
  satisfy mission ownership at
  [P944](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L944)
  when it acts under the caller's mission per
  [P1953](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1953)
  (`#call-chaining`)? Q4.

4. What trusted identity binds a protected Events subscription ticket when the
  resource no longer receives an agent ID? Events requires the originating
  agent binding at
  [E607](../../../aauth-spec/v11/draft-hardt-aauth-events.md#L607)
  (`#pre-authorized-subscription-url-security`), but core auth tokens explicitly
  omit agent identity at
  [P1884](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1884)
  (`#auth-token-structure`). Is a key-bound ticket followed by AP-verified
  subscribe-token identity at redemption intended, and are there extra binding
  requirements? We will not substitute person `sub` for the agent ID. Q5.

5. Should clarification `updated_request` carry a replacement `presented_token`
  when the new resource token names a different `presented_jti`? The replacement
  rule at [P1194](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1194)
  (`#updated-request`) does not require the old `presented_jti`, but verification
  at [P903](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L903)
  (`#resource-token-verification`) requires an exact match. Please specify the
  agent-to-PS and PS-to-AS pending-update bodies and which identity/mission
  fields must remain unchanged when the pair is replaced. Q13.

6. Is the intended prerequisite person-token-only at the authorization endpoint
  and initial grant, but person-or-auth at runtime step-up/per-call challenges?
  [P674](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L674)
  (`#resource-tokens`) broadly requires a verified person token; the more specific
  [P858](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L858)
  (`#resource-token`) allows either. We propose that specific distinction rather
  than requiring a resource to retain an earlier person token. Q2.

7. Does the retained-result rule explicitly override generic terminal pending
  URL behavior? [P810](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L810)
  (`#deferred-auth-token`) and
  [R702](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L702)
  (`#per-call-flow`) require repeat completion to return the original result,
  whereas [P2909](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2909)
  (`#pending-url-security`) requires 410 after a terminal response. Is retention
  keyed by the individual auth grant/invocation rather than proposal hash when
  multiple grants approve identical proposal bytes? Q8.

8. How should a revoked auth token recover through the fresh resource-token
  challenge recommended at
  [P2461](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2461)
  (`#token-revocation`)? That challenge names the revoked token as presented,
  but [P2353](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2353)
  (`#token-endpoint-error-codes`) rejects a revoked presented token and directs
  the agent to obtain a fresh person token, then a fresh resource token.
  Should the client instead obtain a fresh person token and new resource token,
  and should the recommended challenge signal that route? We will not bypass
  revocation to make the retry succeed. Q14.

### Time and identity clarifications

9. Does the five-minute non-presentation recommendation exclude resource tokens?
  [P1390](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1390)
  (`#refresh-margin`) says an agent should not present a token inside the margin,
  but resource tokens should live at most five minutes at
  [P892](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L892)
  (`#resource-token-structure`). We propose applying the margin to agent/person/
  reusable auth credentials, with the explicit reactive exception, rather than
  making freshly issued resource tokens immediately unsuitable. Q7.

10. Are agent/resource maximum lifetimes mandatory verifier ceilings or issuance
   recommendations? [P1388](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1388)
   (`#refresh-margin`) says `exp - iat` MUST NOT exceed the type ceiling, while
   [P545](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L545)
   (`#agent-token-structure`) and P892 use SHOULD NOT for 24 hours/five minutes.
   Also confirm whether the future-`iat` check remains optional despite its
   inclusion in the verification error list. Q7.

11. Can an AS request `sub` again in `requirement=claims`, and must any repeated
   value exactly match the verified presented-token subject? The federation
   description at
   [P1686](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1686)
   (`#ps-to-as-token-request`) reserves claims requests for additional identity
   claims, while [P1777](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1777)
   (`#requirement-claims`) still says to include directed `sub`. We propose
   rejecting conflicting repeats, never replacing the verified identity. Q11.

### Optional companion clarifications

12. Before implementing result release or Budgets, please clarify the following
   companion mismatches. They do not block the proposed core-only migration.
   Q10 records them as optional capability gates.

   - R3 forbids pre-execution when execution is billed/metered/audited at
    [R722](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L722)
    (`#release-gating`), but discusses metered executed-but-unreleased calls at
    [R745](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L745). Is that discussion
    only future work outside the currently permitted release-gating behavior?
   - Budgets says refusal must not draw down a grant at
    [B710](../../../aauth-spec/v11/draft-hardt-aauth-budgets.md#L710)
    (`#exhaustion`), but its example at
    [B722](../../../aauth-spec/v11/draft-hardt-aauth-budgets.md#L722)
    includes positive `cost`. What should the refused-response usage fields mean?
   - Is a signed usage response's `aud` the caller's server identifier, as at
    [B942](../../../aauth-spec/v11/draft-hardt-aauth-budgets.md#L942)
    (`#usage-response`), or its JWKS URL, as at
    [B1007](../../../aauth-spec/v11/draft-hardt-aauth-budgets.md#L1007)
    (`#usage-authorization`)? These are different identifiers.

SDK choices such as public .NET names, cache ownership, persistence backend,
Catalog's replacement layout and which optional capabilities to implement are
our decisions (Q6/Q9/Q12), not questions Dick needs to answer.