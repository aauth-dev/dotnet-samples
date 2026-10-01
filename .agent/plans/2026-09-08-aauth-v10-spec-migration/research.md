# Research - AAuth v10 repository conformance

## Status and scope

Research date: 2026-09-08. This initiative audits the current repository against
the complete v10 specification family, not only the changes since draft-09.
It covers the core SDK, R3, Events, tests, runnable samples, embedded examples,
and documentation. Baseline: commit `0144eb1` on `v09-spec-migration`.
Implementation has not begun.

Spec accuracy takes precedence over backward compatibility. The intended alpha
cutover has one current wire format and public API, without legacy aliases or
dual-format parsing. Earlier migration decisions remain historical records;
their exclusions are not automatically exclusions for this initiative.

## Evidence baseline

The reference snapshot is [aauth-spec/v10](../../../aauth-spec/v10/), pinned to
upstream commit `9dee49fbf49074d1460d0a7c0670bf355aef5e1e`.
The published protocol is
[draft-hardt-oauth-aauth-protocol-10](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/10/)
(2026-08-06). Companion source files come from the same pinned snapshot;
HTTP Signature Keys is the published draft-08 text.

Implementation-file citations in the original findings describe the recorded
research baseline, not code replaced during migration. Read that baseline in
git when checking a historical implementation claim. Dated updates identify
current observations; canonical vendored spec-line citations remain unchanged.

The moving upstream editor's copy is not the conformance baseline. Source-line
citations below refer to the vendored files; stable section anchors are recorded
where available. Publication metadata is separate from stale source-frontmatter
dates.

## Research method

Read-only reviewers examine distinct requirement groups, including negative
requirements and samples/documentation. Findings distinguish confirmed defects,
missing optional capabilities, deployment policy, and unresolved spec questions.
The primary reviewer rechecks high-stakes findings directly against the cited
requirement and the controlling implementation. Existing plans and memories are
leads, not evidence of present behavior.

No SDK or sample changes are part of this research task. The implementation plan
is derived from this evidence inventory and cross-area synthesis. An independent
review of both documents checked high-stakes findings and phase coverage; its
no-claims federation consent finding is incorporated into F17 and Phase 6.

## Executive assessment

Changing the version label, algorithm constant, and error JSON is insufficient.
There are pre-existing authentication, consent, delegation, and interaction-state
defects as well as draft-10 changes. Several existing tests preserve the old
behavior rather than independently establish conformance.

The most consequential findings are unverified JWT types being reported as
verified (F05), pending-route identity gaps (F12), claims release without honoring
the PS consent decision (F17), code-only sample approval bypassing Keycloak
(F14), and missing agent-expiry ceilings (F10). Those findings are code-path
observations, not claims of a tested remote exploit.

Events is not implemented in the tracked source on this branch. Directories
named `AAuth.Events`, `AAuth.Events.Tests`, and `EventAgent` contain leftover build
artifacts, not active projects. Another local branch,
`feat/aauth-events-implementation`, is a potential source of reusable work, not
evidence that this branch implements Events.

### Classification and verification

- P1: security/trust-boundary or major authorization correctness defect
- P2: wire incompatibility, missing required validation, or workflow defect
- P3: documentation, configuration, or unsupported optional capability
- D: primary reviewer directly reread the controlling implementation and spec
- R: focused read-only reviewer inspected the implementation; target citations
	are checked here, but the complete implementation path was not reread here

R findings are explicitly reported evidence, not independently reproduced bugs.
The first broad reviewer pass included incorrect lines and overclaims. A focused
second pass replaced those claims. In particular, optional features are not
universal MUSTs; the AS does not mint policy-expanded scope merely because a
policy can return claims; scope-narrowing and structured confirmation-key checks
already exist; and a replay cache is optional under [P2507].

### Canonical source map

| Source | Immutable local text | Canonical publication or source |
|---|---|---|
| Protocol draft-10, P citations | [Protocol](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md) | [IETF draft-10](https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-10.txt) |
| Signature Keys draft-08, S citations | [Signature Keys](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt) | [IETF draft-08](https://www.ietf.org/archive/id/draft-hardt-httpbis-signature-key-08.txt) |
| R3 draft-01, R citations | [R3](../../../aauth-spec/v10/draft-hardt-aauth-r3.md) | [Pinned source](https://github.com/dickhardt/AAuth/blob/9dee49fbf49074d1460d0a7c0670bf355aef5e1e/draft-hardt-aauth-r3.md) |
| Events draft-00, E citations | [Events](../../../aauth-spec/v10/draft-hardt-aauth-events.md) | [Pinned source](https://github.com/dickhardt/AAuth/blob/9dee49fbf49074d1460d0a7c0670bf355aef5e1e/draft-hardt-aauth-events.md) |
| Bootstrap draft-02 | [Bootstrap L113](../../../aauth-spec/v10/draft-hardt-aauth-bootstrap.md#L113), What Bootstrapping Is Not | [Pinned source](https://github.com/dickhardt/AAuth/blob/9dee49fbf49074d1460d0a7c0670bf355aef5e1e/draft-hardt-aauth-bootstrap.md) |
| Interop profile | [Profile L9](../../../aauth-spec/v10/interop-demo-profile.md#L9), Surface 1 onward | [Pinned source](https://github.com/dickhardt/AAuth/blob/9dee49fbf49074d1460d0a7c0670bf355aef5e1e/interop-demo-profile.md) |

P/S/R/E citation labels include the exact local line number. Markdown source
lines do not equal rendered IETF text lines. Signature Keys citations use the
published text's actual lines, including page breaks. The source commit, rather
than a moving `latest` frontmatter value, identifies the companion revision.

## Signing, discovery, and errors

### F01 - Algorithm identifiers and JWK validation

P2, D; v10 change. [P2409] and [P2412] (`#signature-algorithms`) require an
explicit fully specified `alg` and rejection of key/algorithm disagreement.
[P2515] (`#jwks-discovery`) requires independent selection of the matching key.
[AAuthKey L19](../../../src/AAuth/Crypto/AAuthKey.cs#L19) names Ed25519 as
`EdDSA`; [L98](../../../src/AAuth/Crypto/AAuthKey.cs#L98) exports no `alg`.
[KeyFactory L18](../../../src/AAuth/Crypto/KeyFactory.cs#L18) dispatches by
`kty`/`crv`, not a validated algorithm. The ECDSA import/export path has the same
missing-algorithm contract. A constant rename alone leaves invalid JWKs accepted.
Key thumbprints must remain RFC 7638 thumbprints, not hashes of the expanded JWK.

### F02 - Existing hwk wire format is not the standard scheme

P2, D; pre-existing, plus the new required algorithm member. [S641], [S647],
and [S660] (Section 3.4) define inline `kty`, `crv`, `x`, and `alg` parameters,
with `y` for EC; [S690] applies the algorithm constraint.
[SignatureKeyHeader L49](../../../src/AAuth/HttpSig/SignatureKeyHeader.cs#L49)
instead emits `jkt` plus base64url JSON `jwk`;
[SignatureKeyParser L136](../../../src/AAuth/HttpSig/SignatureKeyParser.cs#L136)
expects that private format. Local signer/verifier agreement hides interop
failure. Providers, bootstrap refresh, snippets, and tests share the defect.

### F03 - jwks_uri is implemented as a different discovery scheme

P2, D; pre-existing. [S964] (Section 3.6) requires `id`, `dwk`, and `kid`, then
metadata issuer verification and JWKS discovery at [S975] and [S979].
[S1021] defines the separate
direct-fetch `jwks` scheme. [SignatureKeyHeader L60](../../../src/AAuth/HttpSig/SignatureKeyHeader.cs#L60)
uses `uri`/`kid`; [DefaultSignatureKeyResolver L63](../../../src/AAuth/HttpSig/DefaultSignatureKeyResolver.cs#L63)
fetches that URI directly. Reusing this behavior under the name `jwks_uri` is
not conformant. Server identity must come from the scheme's verified identifier,
not be guessed by stripping the key URL. Q2 addresses contradictory protocol
examples, not the unambiguous Signature Keys definition.

### F04 - ES256 support does not reach jwt confirmation-key parsing

P2, D; pre-existing supported-feature inconsistency. [P2405]
(`#signature-algorithms`) recommends ES256; the middleware advertises it at
[L46](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs#L46).
However, [SignatureKeyParser L123](../../../src/AAuth/HttpSig/SignatureKeyParser.cs#L123)
and its legacy `Parse` overload use `AAuthKey.FromJwk`, restricted to Ed25519.
The generic key interface and ECDSA implementation exist; JWT carrier parsing
and endpoint key types do not consistently use them. This is not a requirement
to add every JOSE algorithm, but advertised supported algorithms must work.

### F05 - Issuer verification can be claimed without verification

P1, D; pre-existing. [S1160] (Section 3.8) rejects unexpected JWT types and
[S1186] requires JWT signature verification before using delegated key authority;
[P2479] (`#verification`) specifies key-resolution failures.
[Middleware L229](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs#L229)
verifies agent/auth tokens only, skips other types, then reports
`IssuerVerified=true` for any `jwt` carrier when the option is enabled at
[L277](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs#L277).
An attacker-controlled confirmation key can prove possession without proving
the asserted issuer. Endpoint policy may still reject that type, so this is not
a claim that every resource is bypassable. Future subscribe-token support must
not inherit this behavior. Verification success needs an explicit typed result.

### F06 - Signature parameter and delegation-lifetime checks

P2, D; pre-existing. [P2505] (`#freshness-and-replay`) says `expires`, when
present, MUST be honored. [AAuthVerifier L244](../../../src/AAuth/HttpSig/AAuthVerifier.cs#L244)
ignores it. Ignoring signature `alg` is correct for v10 [P2467]; ignoring
`expires` and a conflicting `keyid` is not the same rule ([P2469]).
[S789] and [S917] (Section 3.5) require naming-JWT `iat`/`exp` validation.
[DefaultSignatureKeyResolver L140](../../../src/AAuth/HttpSig/DefaultSignatureKeyResolver.cs#L140)
defers it to middleware, which only checks an `exp` that happens to exist at
[L202](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs#L202).
Missing expiry and future issuance need explicit rejection, including AP refresh.

### F07 - Verification error taxonomy and negotiation are obsolete

P2, D; v10 plus pre-existing parsing behavior. [P2475] (`#verification`)
orders checks and [P2478] defines `unsupported_scheme`; [P2487] pins AAuth
signature failures to 401 and [P2489] excludes signature headers on 403.
[Middleware L128](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs#L128)
classifies exception messages and emits the removed `supported_algorithms`
member rather than `Accept-Signature-Alg` ([S2997], Document History;
[S1953], Section 5.4.1, SHOULD send the header with unsupported_algorithm).
[SignatureKeyHeader L119](../../../src/AAuth/HttpSig/SignatureKeyHeader.cs#L119)
assumes a single literal `sig` dictionary member and throws `FormatException`,
outside that catch. [S430] and [S437] define label consistency and multiple
signatures. Malformed/unsupported input must yield defined errors, not 500s;
unselected schemes must not poison an otherwise valid selected signature.

### F08 - Egress admission and exact identifiers are incomplete

P1, D; pre-existing. [P2521] (`#jwks-discovery`) and [S2372] (Section 7.3)
require admitted HTTPS fetches with size/time limits, redirect constraints,
destination-address checks, DNS-rebinding defense, and cross-origin policy.
[MetadataClient L74](../../../src/AAuth/Discovery/MetadataClient.cs#L74) and
[JwksClient L101](../../../src/AAuth/Discovery/JwksClient.cs#L101) fetch
caller-influenced URLs without those controls. Metadata issuer checking exists;
it is not SSRF admission. R3's narrower same-origin/IP-literal checks are useful
but not a complete reusable network policy. [P2529] and [P2548] (Server
Identifiers) also require strict identifier syntax and exact comparison.
[PS routing L339](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L339)
uses case-insensitive, slash-trimmed comparison. Production policy and explicit
loopback-only development exceptions need separate contracts (Q3).

### F09 - JWKS floor is not enforced across all fetch paths

P2, D; pre-existing. [P2517] (`#jwks-discovery`) requires caching and at most
one fetch per minute; it recommends stale-on-error/backoff and bounded age.
[JwksClient L58](../../../src/AAuth/Discovery/JwksClient.cs#L58) fetches on a
cold/expired cache independently of the refresh floor. Concurrent callers can
all enter it; failed attempts do not update a shared attempt timestamp. The
unknown-kid/same-kid refresh helpers and default one-minute interval already
exist and should be retained, with shared per-URI concurrency and failure state.

### F10 - Auth-token expiry can exceed the agent token

P1, D; pre-existing. [P1344] explicitly bounds auth `exp` by the agent token's
`exp`, separately from the one-hour ceiling at [P1708].
[AuthTokenBuilder L152](../../../src/AAuth/Tokens/AuthTokenBuilder.cs#L152)
computes `iat + Lifetime`; [PS mint L249](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L249)
and [AS mint L245](../../../src/AAuth/Access/AAuthAccessServerEndpoints.cs#L245)
have no agent-expiry input. Pending state also needs the verified ceiling,
including parent/sub-agent and upstream contexts. A resource receiving only an
auth token cannot independently discover an absent associated-agent expiry;
issuance is the directly observable enforcement point, not an invented token lookup.

### F11 - Problem details require a coordinated producer/consumer cutover

P2, D; draft-09 requirement still unmet. [P2304], [P2306], and [P2309]
(`#error-response-format`) specify `application/problem+json`, required `error`,
optional `detail`, and no reliance on `type` for AAuth decisions.
[RevocationEndpoint L62](../../../src/AAuth/Server/RevocationEndpoint.cs#L62)
emits `error_description`; ordinary PS/AS `Results.Json` errors default to
`application/json`. [TokenExchangeClient L201](../../../src/AAuth/Agent/TokenExchangeClient.cs#L201)
and [AccessServerClient L439](../../../src/AAuth/Access/AccessServerClient.cs#L439)
read the legacy description. R3/governance/resource-managed helpers also produce
errors. Bootstrap HTTP APIs are app-defined, so normalizing their bodies is an
SDK consistency decision, not a normative Bootstrap requirement (F31).

## Authorization, interactions, and delegation

### F12 - PS pending operations do not establish the request owner safely

P1, D; pre-existing. [P2825] (`#pending-url-security`) requires identity
verification on every poll. [PS L224](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L224)
installs `SignatureOnly`; [L354](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L354)
fetches a pending entry without checking the poller's identity. POST/DELETE use
[RequesterMatches L1054](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L1054),
which compares a carrier `sub` rather than verified issuer/key-bound ownership.
A known pending URL can be polled by another signer; a forged same-sub carrier
can pass the mutation guard. Disclosed auth tokens remain bound to the original
key. Token-endpoint verification does not repair later pending-route checks.

### F13 - Clarification dispatch and replacement semantics are incomplete

P2, D; action is draft-09, replacement validation is pre-existing.
[P1054] (`#agent-response-to-clarification`) requires explicit `action` and 400
for missing/unknown values. [P1099] requires the replacement resource token's
issuer, agent, and key binding to match the original context.
[PS L429](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L429) dispatches
by payload presence; a supplied replacement is logged and discarded, not
validated or substituted. [ClarificationExchange](../../../src/AAuth/Agent/ClarificationExchange.cs)
and [TourSession L5003](../../../samples/GuidedTour/TourSession.cs#L5003) emit
actionless answers. AS claims POSTs exist, but AS clarification production and
resumption are an additional optional capability ([P1546]), not already implemented.

### F14 - Browser sample decisions treat correlation codes as authorization

P1, D; pre-existing. [P2136] (`#interaction-code-format`) says the code alone
MUST NOT authorize a decision. [Federated sample L173](../../../samples/MockAccessServers/Federated/Program.cs#L173)
registers code-only approval unconditionally and [L189](../../../samples/MockAccessServers/Federated/Program.cs#L189)
marks it allowed without the configured Keycloak policy. The route disables
antiforgery. PS [L887](../../../samples/MockPersonServer/Program.cs#L887) and the
R3 consent helper also use demo code-only approval. Local demo identity shortcuts
must be explicit and isolated; they cannot bypass the real Keycloak flow. The
local PS exemption at [P2863] requires OS-controlled access, not merely a localhost URL.

### F15 - Consent code and pending lifecycles are not uniform

P2, R; pre-existing. [P2132], [P2134], [P2138], [P2140], and [P2142]
(`#interaction-code-format`) require normalization, single use, bounded failed
attempts, and expiry. [P2826] requires a terminal pending URL to return 410 on
later polls. [PS store L234](../../../src/AAuth/Person/IPersonPendingStore.cs#L234)
and [AS store L151](../../../src/AAuth/Access/IAccessPendingStore.cs#L151) look up
raw code strings; expiry eviction loses the distinction between expired and
unknown. The PS allowed branch [L392](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L392)
remints on repeated polls. Actual consent routes do not use the normalization
helper or a failed-attempt limiter. Resource-managed stores have separate
normalization/atomic-consumption controls; that does not prove PS/AS correctness.
Browser code consumption and the authenticated decision session are distinct
states, so single use must not prevent legitimate approval after page arrival.

### F16 - Revocation keys and authorization context are incomplete

P1, D; v10 pair/routing change. [P2361], [P2363], [P2382], and [P2393]
(`#token-revocation`) define `(iss,jti)`, 404 for unknown pairs, and authorized
issuer/trusted-PS revocation. [RevocationEndpoint L78](../../../src/AAuth/Server/RevocationEndpoint.cs#L78)
reads only `jti`, then always returns success. [Middleware L172](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs#L172)
also queries by bare `jti`. Deny-by-default revoker configuration already exists,
so the earlier claim that any issuer can revoke any token is too broad. Once
authorized, a revoker still operates in a shared unqualified namespace. Replay
state must stay per-request; changing it to token single-use would break legitimate
reuse. AP-to-PS cascade behavior at [P2390] needs explicit routing and issuance records.

### F17 - Four-party claims release ignores the PS consent outcome

P1, D; pre-existing. [P934] (`#ps-response`) requires the PS to handle
consent in both access cases. [PS L939](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L939)
calls the asserter, then unconditionally returns a `ClaimsResponse`, substituting
`pairwise-sub` when needed. It never branches on `Deny` or `NeedsConsent`, unlike
the three-party path. AS policy still decides whether to mint, but it may receive
claims and approve despite the PS's contrary decision. Consent gating belongs
before claims release, not only before final token delivery.

The callback is also the only federated asserter invocation. If the AS grants
immediately, or after interaction without requesting claims, the client reaches
[delivery L248](../../../src/AAuth/Access/AccessServerClient.cs#L248) without
invoking it, and the [PS L960](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L960)
marks the grant allowed. PS consent determination must therefore be independent
of AS claims negotiation. Prior consent can satisfy it; always showing a prompt
is not required. Fixing only the callback leaves this no-claims path untouched.

### F18 - Federation loses sub-agent and delegation context

P1, D/R; pre-existing. [P1511] (PS-to-AS Token Request) specifies child binding
and parent recording. [P1574] (Auth Token Delivery) validates both immediate and
nested actors; [P1870] (`#sub-agents`) defines the parent's position.
[PS L341](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L341) omits the
sub-agent parameter when choosing federation; [L718](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L718)
also retains an upstream actor without adding the parent wrapper in the combined
case. The AS [L315](../../../src/AAuth/Access/AAuthAccessServerEndpoints.cs#L315)
does not process forwarded upstream context. The response validator's context
check [L113](../../../src/AAuth/Tokens/AuthTokenResponseValidator.cs#L113) is
optional, incomplete for the immediate actor, and not populated by the PS request.
Ordinary three-party sub-agent key binding exists and must not regress.

### F19 - Upstream validation and reserved-claim boundaries need tightening

P2, R; pre-existing structural gap, with a v10 actor prohibition.
[P1770] (`#upstream-token-verification`) requires Auth Token Verification;
[P1751] and [P1753] require confirmation structure and `sub` or `scope`.
[UpstreamTokenValidator L219](../../../src/AAuth/Tokens/UpstreamTokenValidator.cs#L219)
uses generic JWT verification without all those checks. Trust and audience
checks exist. [P1809] (`#directed-sub-chaining`) prohibits person
identifiers inside `act`; [ActChainBuilder L32](https://github.com/aauth-dev/dotnet-samples/blob/v0.10.0-alpha.1/src/AAuth/Tokens/ActChainBuilder.cs#L32)
clones upstream objects and [L55](https://github.com/aauth-dev/dotnet-samples/blob/v0.10.0-alpha.1/src/AAuth/Tokens/ActChainBuilder.cs#L55)
only checks agent presence/depth. Direct top-level upstream `sub` copying was
not found. [AuthTokenBuilder L211](../../../src/AAuth/Tokens/AuthTokenBuilder.cs#L211)
blocks only already-populated extra claims, allowing unset reserved fields such
as `act` or `mission` through `AdditionalClaims`. That last issue is an API guard
defect; protocol impact depends on the inserted value, not arbitrary overwrite of `iss`.

### F20 - Resource scope vocabulary is not validated at issuance

P2, R; pre-existing. [P2041] (`#scopes`) restricts resource scopes to published
`scope_descriptions` and identity scopes to the PS's `scopes_supported`.
[Challenge middleware L206](../../../src/AAuth/Server/Challenge/AAuthChallengeMiddleware.cs#L206)
passes configured scopes into [ResourceTokenBuilder L127](../../../src/AAuth/Tokens/ResourceTokenBuilder.cs#L127)
without a vocabulary check. This permits invalid configuration, not proof that
every sample issues invalid scopes. Existing auth-scope subset checks remain
valuable. The AS mint uses `requestedScope`, so a policy returning broader claims
does not establish the scope-escalation allegation from the first review.

### F21 - Account binding is an unsupported end-to-end capability

P3 capability, D; v10 addition. [P2055] and [P2057] (`#account-binding`)
describe optional account selection and its propagation through resource/auth
tokens; [R378] and [R380] define R3 carriage and human-readable display.
[ResourceTokenBuilder](../../../src/AAuth/Tokens/ResourceTokenBuilder.cs),
[AuthTokenBuilder](../../../src/AAuth/Tokens/AuthTokenBuilder.cs), and
[R3Document](../../../src/AAuth.R3/Model/R3Document.cs) have no typed account
contract. Generic additional claims are not end-to-end support. Selection,
pending state, token caches, consent/prior grants, refresh, enforcement, and
R3 proposals must distinguish accounts once this capability is enabled.
Absence in a single-account deployment is not itself a vulnerability.

## R3, Events, and bootstrap

### F22 - Vocabulary and discovery models exclude valid shapes

P3 capability, R; pre-existing plus Gateway in v10. [R179] requires Gateway
`service`/`operationId`; [R218] requires GraphQL `operation`/`type`;
[R236], [R257], and [R275] describe optional AsyncAPI/WSDL/OData members.
[R3Operation L74](../../../src/AAuth.R3/Model/R3Operation.cs#L74) requires one
string-valued member. MCP/OpenAPI/gRPC and minimal forms of other vocabularies
fit; it is incorrect to say six vocabularies are wholly absent.
[R3Metadata L11](../../../src/AAuth.R3/R3Metadata.cs#L11) only accepts string
discovery values, excluding the Gateway map at [R161]. The full-v10 plan defaults
to modeling all eight vocabularies while preserving third-party vocabulary extensibility.

### F23 - Operation identity matching ignores vocabulary and member names

P2, D/R; pre-existing. [R316] requires the advertised vocabulary; [R620]
requires authoritative operation validation; [R624] requires grant enforcement.
[Bookings L407](../../../samples/MockResourceServers/Bookings/Program.cs#L407)
checks only `operation.Id`, accepting another vocabulary or arbitrary member
with a known identifier. [R3Grant L28](../../../src/AAuth.R3/Model/R3Grant.cs#L28)
and [R3Enforcement L42](../../../src/AAuth.R3/R3Enforcement.cs#L42) also compare
bare identifiers. Qualified identity must travel through request, proposal,
grant, and execution, especially where two Gateway services reuse an operationId.

### F24 - Bookings assumes one fixed grant policy

P2, R; pre-existing. [R542] and [R624] distinguish unconditional grant,
conditional challenge, and rejection. [Bookings L165](../../../samples/MockResourceServers/Bookings/Program.cs#L165)
and [L189](../../../samples/MockResourceServers/Bookings/Program.cs#L189) reject
conditional search/hold grants instead of challenging;
[L214](../../../samples/MockResourceServers/Bookings/Program.cs#L214) assumes
confirmation requires proposal-retry verification even for an unconditional
grant. Current matching sample policy can hide these cases. Parameter/hash
checking itself exists and must remain mandatory on actual proposal retries
([R590], Per-Call Proposals).

### F25 - R3 auditing can silently be disabled

> Update (2026-09): Phase 9 removes the no-op audit default and requires an
> explicit sink. NuGet availability for Microsoft.Data.Sqlite 10.0.11 was verified
> from its flat-container nuspec before installation. The sample uses a FULL-sync
> SQLite transaction for token identity/hash plus audit metadata; endpoint,
> rollback, concurrent-write and reopen tests pass. Pending consent remains
> volatile and is not presented as crash-durable. See the Phase 9 implementation
> log for the release boundary and recovery semantics. The finding below records
> the pre-implementation state.

P2, R; pre-existing. [R616] (Audit Log Integrity) requires audit entries
atomically with issuance. [R3AccessTokenEndpoint L60](../../../src/AAuth.R3/R3AccessTokenEndpoint.cs#L60)
awaits audit before returning a token, and pending mint-once protection exists.
However, the default [L569](../../../src/AAuth.R3/R3AccessTokenEndpoint.cs#L569)
is a no-op sink ([R3Audit L39](../../../src/AAuth.R3/R3Audit.cs#L39)). No-op
auditing cannot satisfy the requirement. Transactional or equivalent durable
semantics remain a deployment contract; absence of a database transaction alone
does not prove failure. Tests already cover audit failure and concurrent mint-once.

### F26 - R3 document readership is a specification decision

P3 ambiguity, R. [R446] says both PS and AS fetch R3 documents, whereas [R602]
(`#r3-document-access-restriction`) requires rejecting requests not signed by the resource's AS.
[Bookings L28](../../../samples/MockResourceServers/Bookings/Program.cs#L28)
allows both configured PS and AS; [R3DocumentEndpoint L41](../../../src/AAuth.R3/R3DocumentEndpoint.cs#L41)
does verify an explicit trust predicate. Neither blanket unrestricted-access
nor blanket AS-only compliance is accurate. Q4 records a default without
silently relaxing this requirement. [R393] and [R612] require served-byte hashes;
the default store/fetch path already preserves them, while custom callbacks are
trusted contracts and need documented verification obligations.

### F27 - Events requires a complete companion implementation

P3 capability, D inventory; optional until supported. [E198] (`#ap-metadata`)
conditions `event_endpoint` on Events support. No tracked project, token builder,
router, subscription store, or EventAgent exists on this branch. The complete
capability boundaries are:

| Boundary | Exact requirement | Current state |
|---|---|---|
| AP metadata and subscribe tokens | [E198], [E214], [E277] (`#ap-metadata`, `#subscribe-token`) | No runtime implementation |
| Public/protected registration | [E294], [E304], [E603] (`#subscription-registration`, `#protected-subscriptions`) | No registration or bound single-use tickets |
| Event token and self-jwt | [E368], [E415] (`#event-token`, `#event-delivery`) | Missing scheme and typed verifier |
| Routing, quota, durable acceptance | [E418], [E421], [E424] (`#event-delivery`) | No atomic quota/outbox or delivery service |
| Agent verification and context | [E447], [E454] (`#ap-to-agent`) | No event verifier/context mapping |
| AsyncAPI discovery and R3 handoff | [E470], [E493], [R238] (`#event-discovery`, AsyncAPI Vocabulary) | No linked working flow |

Durable recording before 202 is a MUST, not an in-memory-demo convenience.
AP-to-agent transport is explicitly implementation-specific at [E441]; a polling
or streaming example is a local profile, not a new standard. Q5 covers recurring
event deduplication and Q6 covers persistence. External platform transports and
unspecified subscription-renewal APIs must not be invented as conformance demands.

### F28 - Optional Signature Keys capabilities need explicit dispositions

P3 capability, D inventory. [S1021], [S1222], [S1370], and [S1429] define
`jwks`, `self-jwt`, `x509`, and `cached`. The parser supports none of them.
`self-jwt` is necessary for the included Events work ([E368]); direct `jwks`
is a useful separate mode when fixing F03. X.509 and assertion caching are
optional capability choices, not mandatory AAuth access modes. Rejection must
still be correct ([P2478]). Cache implementation would require bounded state,
expiry, cache-miss recovery, and advertisement semantics; a stub is not support.

### F29 - AAuth access modes and generic signing modes are conflated

> **Update (2026-09-09):** Phase 11 resolves the runtime/API ruling: retain
> agent-JWT resource-managed access per [P2420]/[P2422] (#keying-material).
> GuidedTour self-issues locally; SampleApp signs AP enrollment then refreshes
> lazily. Generic Profile signing is a separate demonstration, not that access
> mode. The complete baseline-to-current inventory and ownership/default choices
> are in [api-surface-map.md](api-surface-map.md). The earlier seed observations
> below remain historical evidence, not the current API status.

> **Update (2026-09):** The paragraph below records the pre-implementation
> baseline. Phase 3 changed the Inbox examples to agent JWTs. The owner has
> reopened credential provenance, the pseudonymous example's intended role and
> API ergonomics for explicit review in the new Phase 11; details follow below.

P2 documentation/sample behavior, D. [P2420] and [P2422] (`#keying-material`)
require agent/auth JWTs for AAuth resource access and restrict pseudonymous
schemes to other contexts. [Identity workflow L15](../../../docs/workflows/identity-based-access.md#L15)
teaches `hwk`, `jkt-jwt`, or `jwks_uri` as identity-based AAuth access.
[TourSession L2581](../../../samples/GuidedTour/TourSession.cs#L2581) describes
pseudonymous resource access. Generic signature demonstrations can remain,
but their routes, names, policies, and diagrams must not imply they implement
one of the four AAuth access modes. This is not just a spec-link update.

#### Resource-managed sample revisit and API map

The diff against implementation baseline `ba768f1` confirms that the Inbox
examples previously used `UseHwk`. Phase 3 switched the GuidedTour snippet to
`UseJwt(agentToken)` and the SampleApp runtime to explicit enrollment and an
AgentProviderTokenRefresher. These were implementation changes, not pre-existing
setup the user overlooked. The policy rationale is [P2420]/[P2422]
(`#keying-material`): an agent token is the minimum AAuth resource credential.
Resource-managed authorization still occurs at the resource; provisioning an
agent identity does not require PS/AS authorization exchange. Generic
pseudonymous HTTP signing and that AAuth access mode are distinct concepts.

Current provenance, directly checked on 2026-09-08:

- [GuidedTour EnsureAgentReadyAsync L1149](../../../samples/GuidedTour/TourSession.cs#L1149)
	self-issues with AgentTokenBuilder at
	[L1163](../../../samples/GuidedTour/TourSession.cs#L1163), using the tour's own
	published identity/key. The resource-managed step calls this helper at
	[L2544](../../../samples/GuidedTour/TourSession.cs#L2544); no external AP
	enrollment is performed by that helper for this flow.
- [SampleApp EnrollmentService L37](../../../samples/SampleApp/EnrollmentService.cs#L37)
	ensures enrollment and intentionally discards the returned agent token.
	[Inbox L175](../../../samples/SampleApp/Components/Pages/Inbox.razor#L175)
	wires AgentProviderTokenRefresher manually. Its
	[RefreshAsync L77](../../../src/AAuth/Agent/AgentProviderTokenRefresher.cs#L77)
	obtains the runtime agent token from the AP. The displayed snippet omits this
	setup and uses an unexplained `refresher` variable.
- [GuidedTour snippet L220](../../../samples/GuidedTour/CodeSnippets.cs#L220)
	assumes `agentToken` is already available. The Inbox server snippet still says
	"verify the HTTP signature only" despite the new agent-token verification
	policy. Successful browser tests do not establish instructional consistency.

This is a seed inventory, not a completed rescan of the migration's public API.
The phase-level inventory covers later features as they are implemented.

| Concept | Current public surface | Observed alignment concern |
|---|---|---|
| Enrolled agent token acquisition | [EnrolledBuilder L43](../../../src/AAuth/EnrolledBuilder.cs#L43): RefreshingFrom/WithKeyStore | Existing fluent style can hide required refresher plumbing without hiding that an AP call occurs |
| Resource-managed access and interaction | [EnrolledBuilder L99](../../../src/AAuth/EnrolledBuilder.cs#L99) forwards WithInteractionHandling to the main builder | No direct WithResourceManagedAccess forwarding; interaction-first chaining can reach the main builder, but natural flow-option composition needs review |
| Low-level refresh | [AgentProviderTokenRefresher L54](../../../src/AAuth/Agent/AgentProviderTokenRefresher.cs#L54) constructor and Create builder | Inbox manually constructs HttpClient and refresher; ownership and repeat-call lifecycle need coverage |
| Enrollment-result defaults | [AAuthClientBuilder L59](../../../src/AAuth/AAuthClientBuilder.cs#L59): From(EnrollResult) | Selects direct jwks when key URL/kid exist; comment says jwks_uri; default ignores intended AAuth agent-token use case |
| JWT carrier vs token purpose | [AAuthClientBuilder L176](../../../src/AAuth/AAuthClientBuilder.cs#L176): UseJwt(string agentToken) | Also used with auth tokens; parameter/comment terminology should not conflate scheme and token type |
| Server discovery vs direct key URL | [AAuthClientBuilder L189](../../../src/AAuth/AAuthClientBuilder.cs#L189): UseJwksUri, UseJwks | Distinct contracts per [S964]/[S975] and [S1021]; names, defaults and snippets must preserve that distinction |
| Self-issued agent vs self-jwt | [SelfIssuingBuilder](../../../src/AAuth/SelfIssuingBuilder.cs) and [UseSelfJwt L201](../../../src/AAuth/AAuthClientBuilder.cs#L201) | Agent provisioning still produces an agent JWT with cnf; self-jwt is a different carrier with no cnf per [E368] |

The owner requested the convenience/builder style, not restoration of invalid
wire formats. Phase 11 resolves setup presentation and retains separately
labeled generic pseudonymous examples. Enrolled and self-issued flow options
compose directly; From uses the issued JWT, and explicit scheme/refresh
precedence is tested. Mandatory trust, account, expiry and consent context remain
required. Final verification evidence is recorded in the implementation log.

### F30 - Documentation, fixtures, and snippets preserve obsolete contracts

P2/P3, D. Requirements are [P2409] (algorithms), [P2304] (errors), [P1054]
(clarification), [P2363] (revocation), [S630]/[S957] (key carriers), and [P2057]
(account propagation). [Error handling L106](../../../docs/advanced/error-handling.md#L106),
[signing overview L10](../../../docs/signing-modes/overview.md#L10),
[CodeSnippets L60](../../../samples/GuidedTour/CodeSnippets.cs#L60),
[TourSession L497](../../../samples/GuidedTour/TourSession.cs#L497), and
[MockAgentProvider README L15](../../../samples/MockAgentProvider/README.md#L15)
encode old wire formats or misleading roles. [AuthTokenStructureTests L55](../../../tests/AAuth.Conformance/AuthTokens/AuthTokenStructureTests.cs#L55)
and [PersonServerMapperTests L479](../../../tests/AAuth.Conformance/Person/PersonServerMapperTests.cs#L479)
preserve old algorithm/action shapes. Compiled samples and embedded strings need
different validation: successful compilation does not check a string-literal demo.
Historical plans and immutable vendored drafts are not rewrite targets.

### F31 - Bootstrap is informational, but its produced tokens must be valid

P3 consistency/capability, D/R. [Bootstrap L113](../../../aauth-spec/v10/draft-hardt-aauth-bootstrap.md#L113)
and [L131](../../../aauth-spec/v10/draft-hardt-aauth-bootstrap.md#L131) explicitly
say its ceremony is not normative. Existing enrollment, key storage, attestation
hooks, and single/two-key refresh are useful. Their shared formats inherit
F01-F03/F06; [MockAgentProvider L201](../../../samples/MockAgentProvider/Program.cs#L201)
also duplicates naming-JWT verification. Platform-native attestors are extension
points, not mandatory implementations. Software/file keys must not be described
as hardware-backed. The updated example at
[Bootstrap L255](../../../aauth-spec/v10/draft-hardt-aauth-bootstrap.md#L255)
does not make the current SDK's emitted JWTs compliant by itself.

## Coverage and preserved behavior

This is a section-oriented audit with verified findings, not a proof of every
MUST in the draft. Absence of a finding is not a conformance verdict. Unexercised
branches and application-owned policy retain the following explicit boundaries.

| Area | Evidence/coverage | Remaining uncertainty or preserved control |
|---|---|---|
| Core keys, headers, discovery | F01-F09 | Structured-field edge cases and injected HTTP handlers need adversarial tests |
| Agent/resource/auth JWTs | F10, F18-F21; [P1751] | Existing confirmation structure, key thumbprints, audience and scope subset checks remain; full claim negative matrix still needed |
| Identity, resource-managed, PS-asserted, federated | F12, F17, F18, F29; [P2420] | Resource-managed opaque tokens and signed owner checks exist; test identity/key/account isolation together |
| Challenges, payment, claims, deferred callbacks | F11-F15, F17; [P1543], [P2280] | Payment settlement is external; callback-code mapping exists; retry/backoff/cancellation need mixed-response integration coverage |
| Missions and governance | [P1488], [P1490]; F13, F18, F21 | Mission hash/reference echo and terminated-state paths exist; permission/audit/interaction caller ownership and unknown mission handling remain explicit final-review checks |
| Delegation/sub-agents | F18-F19; [P1511], [P1574], [P1870] | Parent-mediated three-party binding works; combined/federated cases are incomplete |
| Revocation vs request replay | F16; [P2363], [P2507] | Deny-by-default revoker config and per-signature replay exist; no universal token single-use rule |
| R3 content and operations | F22-F26; [R393], [R590], [R616], [R624] | Byte hashes, parameter checks, fail-before-release auditing and pending mint-once are existing controls |
| Events and Bootstrap | F27-F28, F31 | Events source absent on active branch; platform attestation and AP-agent transport are implementation policy |
| Five interop surfaces | [Profile L9](../../../aauth-spec/v10/interop-demo-profile.md#L9), [L45](../../../aauth-spec/v10/interop-demo-profile.md#L45) | Existing mission/R3 examples are not a substitute for four-party parent-mediated sub-agent interoperability |

### Sample and documentation ownership map

| Surface | Relevant findings and verification concerns |
|---|---|
| AgentConsole, LiveWhoAmITest | F01-F03, F06, F10, F29; enrollment/refresh and captured-wire interop, not just local mock agreement |
| MissionAgent, Concierge | F10-F13, F18-F21; mission bytes, chained audience, parent actor, pending ownership, cancellation |
| MockAgentProvider | F01-F03, F06, F27, F31; genuine enrollment-key proof, refresh, Events metadata and durable routing |
| MockPersonServer | F10-F21; consent/session separation, federation decisions, pending state and account-scoped grants |
| MockAccessServers/Federated | F03-F11, F14-F21; stub and Keycloak paths, no code-only bypass, claims/delegation validation |
| MockAccessServers/R3 and Bookings | F21-F27; vocabulary identity, conditional/unconditional policy variants, audit, ticket handoff |
| Profile, Calendar, Trips, Wallet, Inbox | F01-F11, F16, F20-F21, F29; all four access modes, scope definitions, ownership and key/account isolation |
| GuidedTour and SampleApp | F13-F15, F21, F27, F29-F30; Razor views, live flows, recorded exchanges, CodeSnippets and Playwright assertions |
| Root/sample/package READMEs and docs index/concepts/glossary | F29-F31; capability matrix, accurate version/roles, no unsupported claims |
| docs/signing-modes and docs/server | F01-F11, F16, F29; actual headers, strict identifiers, trust/egress, revocation and error negotiation |
| docs/workflows | F12-F29; each workflow matches the same compiled scenario, including negative outcomes |
| docs/advanced and docs/reference | F08-F28, F31; governance, key management, attestation limits, configuration, DI, observability without secrets |

## Toolchain and validation observations

[AAuth.csproj L4](../../../src/AAuth/AAuth.csproj#L4) targets .NET 10;
[L31](../../../src/AAuth/AAuth.csproj#L31) and
[L43](../../../src/AAuth/AAuth.csproj#L43) use Microsoft.IdentityModel.Tokens
8.18.0 and BouncyCastle.Cryptography 2.6.2. No cryptographic-library replacement
is established as necessary: wire identifiers and validation contracts are the
confirmed issues. [Test props L18](../../../tests/Directory.Build.props#L18)
pins Microsoft.NET.Test.Sdk 17.14.1, xUnit 2.9.3, and its VS runner 3.1.4.

[Makefile L115](../../../Makefile#L115) runs only core tests for `test-unit`,
and `test-conformance` is a separate project. R3 tests are a third project, not
part of either target. [CI L26](../../../.github/workflows/ci.yml#L26) runs
the solution tests. [Playwright L44](../../../tests/e2e/playwright.config.ts#L44)
defines two UI projects with shared servers; Keycloak is opt-in, and neither
Events nor a new sub-agent interop flow is automatically covered.

The editor test tool found no tests for the selected C# files. Direct `dotnet test`
was therefore used for AuthTokenStructureTests/PersonServerMapperTests and
ResourceR3Tests/AccessEndpointR3Tests. Quiet invocations returned no summary;
the detailed completion summaries were subsequently checked:

| Focused baseline | Result |
|---|---|
| AuthTokenStructureTests and PersonServerMapperTests | 37 passed, zero failed |
| ResourceR3Tests and AccessEndpointR3Tests | 25 passed, zero failed |

Both builds reported zero warnings/errors. These 62 passing existing tests
establish a baseline, not v10 compliance or reproduction of every finding.
No full-solution test run, browser run, live interop, load test, or exploit
reproduction is claimed.

## Gaps and open questions

These are proposed defaults for the implementation decision gate, not approved
decisions. Rulings belong in the future implementation log.

| ID | Question and evidence | Proposed default |
|---|---|---|
| Q1 | Capability breadth: optional Events [E198], all R3 vocabularies [R179], optional schemes [S1370]/[S1429] | Include account binding, all eight R3 models, AS clarification, Events, self-jwt and direct jwks. Defer x509/cached with accurate unsupported-scheme behavior and documented boundaries; do not inherit the old v09 exclusions silently |
| Q2 | Protocol [P2420] profiles agent JWT access, but the PS-to-AS example [P1523] contains obsolete jwks_uri syntax | Use normative Signature Keys [S964]/[S975] for non-agent server signing; keep AAuth agent requests jwt. Record the PS-AS profile interpretation and report the stale example upstream |
| Q3 | Production identifiers/egress [P2529], [P2521] vs existing HTTP localhost demos | Strict production defaults, an explicit development policy limited to configured loopback origins, no global permissive fallback |
| Q4 | R3 PS readership [R446] vs AS-only [R602] | Default resource documents to authenticated designated-AS access; provide an explicitly configured PS evaluation role only with a logged interpretation, pending upstream clarification |
| Q5 | Events uses one eid for a subscription [E229], but deduplicates by eid/iss [E454]; raw body [E389] (`#event-delivery`) vs payload-field privacy text [E625] | Ship a single-shot sample first; enforce the stated deduplication rule, do not invent a wire event-id. Follow delivery-section raw body. Recurring-event semantics require a recorded ruling; expired events never trigger action per [E366] |
| Q6 | Durable acceptance [E424], atomic quota [E421], R3 audit [R616] | Reusable persistent store contracts and a transactional local sample provider; pin any new persistence package only after checking existing branch work and license/runtime support. No in-memory production durability claim |
| Q7 | Browser approval cannot rely on code [P2136] | Authenticated decision session and CSRF protection; stub identity available only in an explicit isolated demo mode; no bypass endpoints in Keycloak mode |
| Q8 | Agent-expiry observability [P1344], federation delivery binding [P1574] | Carry verified ceilings/context through issuer and pending state; no unverifiable resource lookup or invented public claim; reject stale agent context before minting |
| Q9 | Prior Events work exists on another branch; active solution has none | Inspect and selectively reuse verified source, tests, and persistence choices, adapting to v10. Do not merge/cherry-pick an entire branch without approval |
| Q10 | Structured fields and signature extensions [S430], [P2445] | Prefer an existing maintained RFC parser/library where suitable; retain current crypto primitives. Pin a choice only after a small compatibility test for labels, parameter types, escaping, and additional covered components |

## Synthesis

The common dependencies are typed verified-token context, admitted discovery,
exact wire models, and state transitions that preserve owner/key/account/expiry.
They cross package boundaries: an Events implementation cannot safely reuse
F05, account support cannot stop at token properties, and R3 Gateway cannot
retain bare-id equality. Compiled samples move with each API change; a final
non-compiled documentation sweep follows the frozen code surface.

The companion [implementation plan](implementation-plan.md) maps every finding
to a phase, carries the unresolved interpretations through Phase 0, and includes
final independent review of the coverage limits above.

[P934]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L934
[P1054]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1054
[P1099]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1099
[P1344]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1344
[P1488]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1488
[P1490]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1490
[P1511]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1511
[P1523]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1523
[P1543]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1543
[P1546]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1546
[P1574]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1574
[P1708]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1708
[P1751]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1751
[P1753]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1753
[P1770]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1770
[P1809]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1809
[P1870]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1870
[P2041]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2041
[P2055]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2055
[P2057]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2057
[P2132]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2132
[P2134]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2134
[P2136]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2136
[P2138]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2138
[P2140]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2140
[P2142]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2142
[P2280]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2280
[P2304]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2304
[P2306]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2306
[P2309]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2309
[P2361]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2361
[P2363]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2363
[P2382]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2382
[P2390]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2390
[P2393]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2393
[P2405]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2405
[P2409]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2409
[P2412]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2412
[P2420]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2420
[P2422]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2422
[P2445]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2445
[P2467]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2467
[P2469]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2469
[P2475]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2475
[P2478]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2478
[P2479]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2479
[P2487]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2487
[P2489]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2489
[P2505]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2505
[P2507]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2507
[P2515]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2515
[P2517]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2517
[P2521]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2521
[P2529]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2529
[P2548]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2548
[P2825]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2825
[P2826]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2826
[P2863]: ../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2863
[S430]: ../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L430
[S437]: ../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L437
[S630]: ../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L630
[S641]: ../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L641
[S647]: ../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L647
[S660]: ../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L660
[S690]: ../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L690
[S789]: ../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L789
[S917]: ../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L917
[S957]: ../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L957
[S964]: ../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L964
[S975]: ../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L975
[S979]: ../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L979
[S1021]: ../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L1021
[S1160]: ../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L1160
[S1186]: ../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L1186
[S1953]: ../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L1953
[S1222]: ../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L1222
[S1370]: ../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L1370
[S1429]: ../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L1429
[S2372]: ../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L2372
[S2997]: ../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L2997
[R161]: ../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L161
[R179]: ../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L179
[R218]: ../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L218
[R236]: ../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L236
[R238]: ../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L238
[R257]: ../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L257
[R275]: ../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L275
[R316]: ../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L316
[R378]: ../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L378
[R380]: ../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L380
[R393]: ../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L393
[R446]: ../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L446
[R542]: ../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L542
[R590]: ../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L590
[R602]: ../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L602
[R612]: ../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L612
[R616]: ../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L616
[R620]: ../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L620
[R624]: ../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L624
[E198]: ../../../aauth-spec/v10/draft-hardt-aauth-events.md#L198
[E214]: ../../../aauth-spec/v10/draft-hardt-aauth-events.md#L214
[E229]: ../../../aauth-spec/v10/draft-hardt-aauth-events.md#L229
[E277]: ../../../aauth-spec/v10/draft-hardt-aauth-events.md#L277
[E294]: ../../../aauth-spec/v10/draft-hardt-aauth-events.md#L294
[E304]: ../../../aauth-spec/v10/draft-hardt-aauth-events.md#L304
[E366]: ../../../aauth-spec/v10/draft-hardt-aauth-events.md#L366
[E368]: ../../../aauth-spec/v10/draft-hardt-aauth-events.md#L368
[E389]: ../../../aauth-spec/v10/draft-hardt-aauth-events.md#L389
[E415]: ../../../aauth-spec/v10/draft-hardt-aauth-events.md#L415
[E418]: ../../../aauth-spec/v10/draft-hardt-aauth-events.md#L418
[E421]: ../../../aauth-spec/v10/draft-hardt-aauth-events.md#L421
[E424]: ../../../aauth-spec/v10/draft-hardt-aauth-events.md#L424
[E441]: ../../../aauth-spec/v10/draft-hardt-aauth-events.md#L441
[E447]: ../../../aauth-spec/v10/draft-hardt-aauth-events.md#L447
[E454]: ../../../aauth-spec/v10/draft-hardt-aauth-events.md#L454
[E470]: ../../../aauth-spec/v10/draft-hardt-aauth-events.md#L470
[E493]: ../../../aauth-spec/v10/draft-hardt-aauth-events.md#L493
[E603]: ../../../aauth-spec/v10/draft-hardt-aauth-events.md#L603
[E625]: ../../../aauth-spec/v10/draft-hardt-aauth-events.md#L625