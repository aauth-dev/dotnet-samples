# Research - AAuth SDK migration to protocol draft-09

> Research-only. Implementation work belongs in
> [`implementation-plan.md`](implementation-plan.md); owner rulings and later
> deviations belong in [`implementation-log.md`](implementation-log.md).

## Goal

Determine the complete repository impact of moving the SDK from protocol
**draft-08** to the published **draft-09** snapshot. The target also ships a
revised R3 draft, a new AAuth Events companion draft, and HTTP Signature Keys
draft-06. The snapshot is vendored at
[`aauth-spec/v09/`](../../../aauth-spec/v09/); the confirmed baseline is
[`aauth-spec/v08/`](../../../aauth-spec/v08/).

## Method

Four independent read-only subagents analyzed non-overlapping logical change
sets: RFC 9457 errors, clarification actions, AAuth Events plus R3, and
Signature Keys `self-jwt`. Their reports were collated and then checked directly
against the vendored specifications and current repository code.

The following high-stakes findings were directly re-verified:

- the exact `action` values and the server's new `400` rejection requirement;
- the `application/problem+json`, `detail`, and `error` requirements;
- every newly introduced token type, metadata member, and R3 wire member;
- the Events draft's `dwk`-without-`cnf` verification extension;
- the separate Signature Keys `self-jwt` trust and cache requirements;
- construction/verification symmetry in the current clarification and error
  paths; and
- claims that Events and `self-jwt` have no current runtime attachment point.

Repository citations below are workspace-relative. Protocol and companion
citations use stable anchors where available and exact lines in the vendored
target.

## Authoritative sources

| Source | Role |
|---|---|
| [`v09/draft-hardt-oauth-aauth-protocol.md`](../../../aauth-spec/v09/draft-hardt-oauth-aauth-protocol.md) | Published protocol draft-09 target |
| [`v08/draft-hardt-oauth-aauth-protocol.md`](../../../aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md) | Confirmed protocol draft-08 baseline |
| [`v09/draft-hardt-aauth-events.md`](../../../aauth-spec/v09/draft-hardt-aauth-events.md) | New Events draft-00 companion source |
| [`v09/draft-hardt-aauth-r3.md`](../../../aauth-spec/v09/draft-hardt-aauth-r3.md) | Revised R3 draft-00 companion |
| [`v09/draft-hardt-httpbis-signature-key-06.txt`](../../../aauth-spec/v09/draft-hardt-httpbis-signature-key-06.txt) | Target Signature Keys dependency |
| [`v08/draft-hardt-httpbis-signature-key-05.txt`](../../../aauth-spec/v08/draft-hardt-httpbis-signature-key-05.txt) | Baseline Signature Keys dependency |
| [`aauth-spec/CHANGELOG.md`](../../../aauth-spec/CHANGELOG.md) | Vendored snapshot catalogue |

## Snapshot accounting

| Document | Baseline-to-target status | Research disposition |
|---|---|---|
| Protocol | Revised | Two wire cutovers plus Events integration |
| Bootstrap | Byte-identical | No migration delta |
| R3 | Revised | Explicit include-or-spin-off ruling required |
| Interop Demo Profile | Byte-identical | No migration delta |
| AAuth Events | New draft-00 companion | Explicit include-or-spin-off ruling required |
| HTTP Signature Keys | draft-05 -> draft-06 | Adds `self-jwt`; explicit include-or-spin-off ruling required |

The byte-identical Bootstrap and Interop claims were confirmed with direct byte
comparisons. The new Events file is pinned by the protocol draft-09 tag but had
no separate published tag or Datatracker revision when vendored.

## Cross-cutting conclusions

1. **Two draft-09 changes attach directly to implemented flows.** RFC 9457
   errors and clarification `action` values require coordinated producer and
   consumer cutovers.
2. **Events is a new protocol, not a small extension.** Its normative flow
   requires token builders and verifiers, resource registration endpoints,
   subscription storage, an AP delivery endpoint, durable routing, replay
   enforcement, agent verification, and AsyncAPI discovery. None exists today.
3. **R3 exposes an existing model boundary.** Current R3 operations deliberately
   support one-member objects, while a valid AsyncAPI operation has
   `operationId` plus optional `action`.
4. **`self-jwt` and the Events JWT extension are not the same wire scheme.**
   Signature Keys draft-06 defines `sig=self-jwt`; Events presents
   `sig=jwt` with `dwk` and no `cnf`. Both discover a key and use it for JWT and
   HTTP signatures, but they are specified separately and must not be conflated.

## Change set 1 - RFC 9457 AAuth error responses

### Target and baseline

Draft-09 makes the common error body an RFC 9457 problem-details object with
`Content-Type: application/problem+json`. `error` remains REQUIRED and controls
AAuth behavior; `detail` replaces `error_description`; standard `type`, `title`,
`status`, and `instance` members MAY appear, but receivers MUST NOT identify an
AAuth error from `type` (`#error-responses`, `#error-response-format`,
L2230-L2243). The token and polling examples use the new media type and `detail`
(L2259-L2268, L2283-L2292).

The draft-08 baseline limited the named format to token endpoints and used
`application/json` plus optional `error_description`
(`#error-response-format`, L2242-L2247).

Draft-09 also points authorization endpoint, interaction endpoint, and
mission-status errors at the common format (protocol L704-L714, L1296-L1306,
L1419-L1434). Authentication failures still use the `Signature-Error` header
(L2232-L2234); a JSON body, when present, is still an error body governed by the
common format.

### Current repository state

No `application/problem+json` occurrence exists in `src/`, `tests/`, `samples/`,
or `docs/`.

Most PS and AS errors already serialize `error` plus `detail`, but use
`Results.Json` or typed convenience results without an explicit problem-details
media type. Representative producers are
[`AAuthPersonServerEndpoints.cs`](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs)
(L284-L310, L417-L434, L506-L596, L643-L757) and
[`AAuthAccessServerEndpoints.cs`](../../../src/AAuth/Access/AAuthAccessServerEndpoints.cs)
(L214-L238, L272-L325, L378-L444, L491-L591). `Results.NotFound` error bodies
on the same endpoints also default to ordinary JSON.

The complete directly attached producer inventory includes:

| Surface | Evidence | Classification |
|---|---|---|
| PS and AS endpoints | `AAuthPersonServerEndpoints.cs` L284-L909; `AAuthAccessServerEndpoints.cs` L214-L601 | `detail` mostly present; media type missing |
| Governance endpoints | `AAuthGovernanceApplicationBuilderExtensions.cs` L88-L164 and L227-L396; `GovernanceEndpoints.cs` L113-L123 | Media type missing |
| Resource-managed interaction | `AAuthInteractionEndpointExtensions.cs` L41-L74 | Media type missing |
| Authorization helper | `AAuthApplicationBuilderExtensions.cs` L138-L170 | Still emits `error_description`; media type missing |
| Revocation | `RevocationEndpoint.cs` L62-L98 | Still emits `error_description`; media type missing |
| Resource challenge helper | `AAuthHttpContextExtensions.cs` L62-L70 | Error body media type missing |
| R3 runtime endpoints | `R3AccessTokenEndpoint.cs`, `R3DocumentEndpoint.cs`, `R3Enforcement.cs`, `R3Challenge.cs` | Uses AAuth-shaped errors; scope ruling required |
| Mock Agent Provider | `samples/MockAgentProvider/Program.cs` L86-L270 | Bootstrap-family errors still use `error_description`; scope ruling required |

This inventory is broader than the initial subagent report: direct search found
the governance application mappings and challenge helper as additional
producers. Success responses in the same files are not part of the cutover and
must not be bulk-rewritten.

Both SDK error consumers still parse only `error_description`:

- [`TokenExchangeClient.cs`](../../../src/AAuth/Agent/TokenExchangeClient.cs)
  L196-L249; and
- [`AccessServerClient.cs`](../../../src/AAuth/Access/AccessServerClient.cs)
  L470-L515.

They already branch on the required `error` member and do not inspect RFC 9457
`type`, so the `MUST NOT rely on type` requirement is already satisfied. Reading
only `error_description` loses human-readable detail from the existing PS/AS
producers even before the content-type migration; this is a tightly coupled
pre-existing defect.

Two public API names mirror the removed wire member:

- `AAuthTokenExchangeException.ErrorDescription`
  ([`AAuthTokenExchangeException.cs`](../../../src/AAuth/Errors/AAuthTokenExchangeException.cs),
  L9-L45); and
- `TokenErrorResponse.ErrorDescription`
  ([`TokenError.cs`](../../../src/AAuth/Errors/TokenError.cs), L43-L50).

The repository's spec-accuracy posture forbids a dual-wire fallback unless the
owner approves an exception. A clean cutover therefore reads `detail`, not
`detail ?? error_description`. Whether the public .NET names also become
`Detail` is an explicit API decision.

Tests currently mock `error_description` in
`AccessServerClientTests.cs` L311 and `ChallengeHandlerTests.cs` L328, while
`PersonServerMapperTests.cs` and the error conformance tests assert codes but
not `application/problem+json`. `docs/advanced/error-handling.md` contains the
same stale wire member and public API names at L97-L149 and L323.

### Classification and validation evidence

The core error work is a **coordinated wire and public-API cutover**:

- producers must emit the new media type and `detail`;
- consumers must read `detail` while continuing to branch on `error`;
- error fixtures and public API references must move with them; and
- success responses and header-only authentication failures must remain
  unchanged.

Evidence must include positive media-type/body assertions for representative PS,
AS, authorization, interaction, governance, challenge, and revocation errors;
client parsing of `detail`; tolerance of optional RFC 9457 members; and a search
showing no consumer relies on `type`. R3 and Mock Agent Provider coverage depend
on owner scope rulings.

## Change set 2 - clarification response `action`

### Target and baseline

Every clarification POST body now MUST carry `action`. The two recognized values
are `clarification_response` and `updated_request`; a server MUST reject a
missing or unrecognized value with `400 Bad Request`
(`#agent-response-to-clarification`, L1012-L1021). The two request examples show
the exact body shapes (L1022-L1062). Cancellation remains `DELETE` and has no
body (L1064-L1068).

Draft-08 inferred the response type from `clarification_response` or
`resource_token` and defined no `action` member (protocol draft-08 L1022-L1071).

### Current repository state

The implemented producer and consumer are symmetric for draft-08 and both must
move together:

| Role | Evidence | Current behavior |
|---|---|---|
| Agent producer | `ClarificationExchange.cs` L149-L165 | Sends only `clarification_response` or `resource_token` |
| PS consumer | `AAuthPersonServerEndpoints.cs` L420-L446 | Infers type from key presence; never validates `action` |
| Manual sample producer | `samples/GuidedTour/TourSession.cs` L4997-L5008 | Posts an anonymous body without `action` |
| Test bypass producers | `PersonServerMapperTests.cs` L479, L568, L575 | Post old draft-08 bodies |
| Test consumers | `ClarificationChatTests.cs` L201-L212; `ChallengeClarificationSeamTests.cs` L201; `GovernanceClientTests.cs` L299 | Do not assert `action` |

The public `ClarificationResponse` model already distinguishes Respond, Update,
and Cancel (`ClarificationExchange.cs` L15-L71); no public model redesign is
needed. `DeferredExchange` delegates to this serializer, so it inherits the
wire fix.

Compiled SampleApp paths use the SDK model and inherit the change. GuidedTour
constructs one body manually and must move with the code phase. Non-compiled
prose and the displayed snippet in `samples/GuidedTour/CodeSnippets.cs`
L472-L480 belong in the post-code sweep. Existing Playwright mission-flow tests
exercise the exchange but do not inspect the new member.

The baseline already said that both PSes and ASes can issue clarification
requirements (draft-08 L1018-L1022). The current AS has no clarification
response receiver, so that is a **pre-existing unattached flow**, not a new
draft-09 delta. Whether to add it now is an explicit scope ruling.

### Classification and validation evidence

This is a **coordinated wire cutover**. Producer and consumer must use the same
two exact action strings. The server MUST reject missing and unknown actions.
Rejecting a recognized action whose required payload is missing or mismatched is
defensive `invalid_request` validation implied by the selected operation's body
shape, but draft-09 does not mandate its status code.

Required evidence includes captured producer JSON for both actions; positive PS
acceptance; negative `400` tests for missing and unknown values; negative tests
for defensive handling of a recognized action without its required payload; the
existing end-to-end clarification round trip; and a GuidedTour e2e assertion
exposing the action member.

## Change set 3 - AAuth Events and protocol integration

### Protocol integration

Draft-09 adds optional `event_endpoint` to agent-provider metadata, required when
the AP supports Events (`#metadata-documents`, protocol L2482-L2510), and records
the companion's `aa-subscribe+jwt` and `aa-event+jwt` types (L2899-L2915). It
also describes the AP as an event router and asynchronous delivery as a protocol
capability (L142-L146, L377-L382).

Current `AAuthAgentMetadataOptions` has no `EventEndpoint` property
([`AAuthAgentMetadataOptions.cs`](../../../src/AAuth/Server/Metadata/AAuthAgentMetadataOptions.cs),
L8-L49), `BuildAgentMetadata` does not emit it
([`WellKnownEndpoints.cs`](../../../src/AAuth/Server/Metadata/WellKnownEndpoints.cs),
L208-L223), and the discovery model does not parse it
([`ServerMetadata.cs`](../../../src/AAuth/Discovery/ServerMetadata.cs),
L10-L87). The Events token strings do not occur outside the vendored spec and
tracking documents.

### New Events companion

The new companion is a complete protocol. Its normative groups are:

| Feature group | Target evidence |
|---|---|
| AP metadata | `#ap-metadata`, Events L190-L202 |
| Subscribe token claims, presentation, verification | `#subscribe-token`, L204-L283 |
| Public and protected registration | `#subscription-registration`, `#protected-subscriptions`, L285-L339 |
| Event token claims | `#event-token`, L340-L374 |
| Resource-to-AP delivery and AP validation | `#event-delivery`, L376-L429 |
| AP-to-agent routing and agent verification | `#ap-to-agent`, L430-L447 |
| AsyncAPI discovery and security scheme | `#event-discovery`, L449-L573 |
| Replay, ticket, privacy, and retention constraints | L574-L616 |
| JWT type and vocabulary registrations | L618-L632 |

No runtime attachment exists for any complete group:

- no subscribe/event token builder or verifier;
- no subscription registration or ticket endpoint;
- no subscription record or `eid` context store;
- no AP `event_endpoint` implementation or durable-delivery queue;
- no resource event-delivery client;
- no agent event verifier or deduplication path; and
- no AsyncAPI vocabulary constant or sample.

The Events verification boundary is especially important. Event delivery uses
`sig=jwt` with a JWT carrying `dwk` but no `cnf`; the AP must discover the
resource key by `iss`, `dwk`, and `kid`, verify the JWT, and verify the HTTP
signature with the same key (`#event-delivery`, L391-L410). Current
`SignatureKeyParser` accepts `scheme=jwt`, but `DefaultSignatureKeyResolver`
requires `cnf.jwk` (`SignatureKeyParser.cs` L89-L101;
`DefaultSignatureKeyResolver.cs` L28-L48). Supporting Events would therefore
introduce a new trust branch and token-type separation, not a harmless reuse of
the agent-token path.

### Classification and validation evidence

The full companion is **unsupported by any current flow**. Its trust, storage,
delivery, and replay requirements should be implemented only as an approved
initiative with its own research and plan. If included here, validation would
need positive and negative token verification, ticket single-use and
agent-binding tests, atomic `max_uses`, durable-before-`202`, replay and expiry
tests, resource/AP/agent integration, AsyncAPI discovery, and a fresh full-stack
e2e scenario.

The small protocol metadata and registry additions are additive, but exposing
them without the underlying flow can imply support that does not exist. Their
include-versus-spin-off disposition should follow an explicit owner ruling.

## Change set 4 - revised R3 AsyncAPI vocabulary

R3 keeps draft number 00 but revises the AsyncAPI operation: `operationId`
remains REQUIRED, `action` becomes OPTIONAL, and an R3-granted subscription
hands off to AAuth Events using a subscription ticket and subscribe token
(`#asyncapi-vocabulary`, R3 L186-L200).

Current `Vocabulary` defines only MCP and OpenAPI
([`Vocabulary.cs`](../../../src/AAuth.R3/Model/Vocabulary.cs), L1-L8). More
importantly, `R3Operation` deliberately accepts exactly one string member and
documents AsyncAPI as unsupported
([`R3Operation.cs`](../../../src/AAuth.R3/Model/R3Operation.cs), L6-L14,
L55-L84). A valid AsyncAPI operation can carry both `operationId` and `action`,
so current deserialization rejects it. No sample or test uses the AsyncAPI
vocabulary.

This is a **changed companion with no current runtime attachment point**. Adding
only a vocabulary constant is safe but incomplete; full conformance needs a
multi-member operation model and Events registration semantics. Include or
spin-off requires an explicit owner ruling independent of the Events ruling.

## Change set 5 - HTTP Signature Keys `self-jwt`

Signature Keys draft-06 adds `sig=self-jwt`. The JWT MUST contain HTTPS `iss`
and `dwk`, MUST have `kid`, MUST NOT contain `cnf`, and SHOULD contain standard
claims. Verification discovers the issuer JWKS, rejects `cnf`, verifies the JWT,
then verifies the HTTP signature with the same key (draft-06 section 3.7,
L757-L830). Discovered keys are cached by `iss + kid` until JWT expiry
(section 6.2, L1412-L1421). The issuer-controlled discovery path inherits SSRF
admission requirements, and a JWT containing `cnf` MUST be rejected
(section 6.3, L1494-L1502).

The main AAuth protocol still requires agents to use `scheme=jwt` for resource,
PS, and AS requests and does not attach `self-jwt` to an implemented protocol
flow (`#keying-material`, protocol L2334-L2341).

Current code has no `self-jwt` constant, formatter, parser branch, provider,
resolver, builder, test, sample, or documentation. Direct searches found no
occurrence in `src/`, `tests/`, `samples/`, or `docs/`. Relevant dispatch points
are `AAuthConstants.Schemes` (`AAuthConstants.cs` L41-L57),
`SignatureKeyHeader` L16-L88, `SignatureKeyParser.ParseAny` L89-L101, and
`DefaultSignatureKeyResolver.ResolveAsync` L28-L48. `JwksClient` caches JWKS
documents by URI with a fixed TTL, not discovered keys by `iss + kid` bounded by
JWT expiry (`JwksClient.cs` L15-L68).

This dependency feature has **no current attachment point** and requires an
explicit include-or-spin-off ruling.

If implementation is approved, two upstream example inconsistencies need a
ruling first: the example uses `typ=aauth-resource+jwt` and
`dwk=aauth-resource`, while this repository and the AAuth protocol use
`aa-resource+jwt` and `aauth-resource.json` (draft-06 L829-L872). These values
are illustrative rather than an AAuth protocol mandate, but they prevent a
safe implementation from being inferred without a selected use case.

Although Events `sig=jwt` without `cnf` and Signature Keys `sig=self-jwt` are
distinct wire paths, both need the same admitted
`{iss}/.well-known/{dwk}` -> JWKS -> `kid` discovery primitive. Separate
spin-off plans must coordinate on one shared resolver/cache seam so SSRF,
refresh, and expiry behavior cannot diverge.

## Surface inventory

| Surface | Draft-09 impact |
|---|---|
| SDK model/wire | Error media type/member; clarification action; conditional Events/R3/self-jwt additions |
| Trust/policy | `error` remains discriminator; Events no-`cnf` branch and self-jwt discovery are new conditional trust boundaries |
| Endpoint/client pairs | PS/AS errors and clients; clarification producer/PS consumer |
| Tests | Error media-type/body tests; strict action positives/negatives; conditional companion suites |
| Compiled samples | GuidedTour manual clarification body; LiveWhoAmITest if error API is renamed |
| Non-compiled surfaces | Error and clarification docs/snippets; version statements after code freeze |
| Runtime verification | Existing mission clarification e2e; no Events/self-jwt e2e attachment |
| Version tracking | Vendoring correctly says latest v09 and SDK target v08 until migration completes |
| Companions | Bootstrap/interop unchanged; R3 revised; Events new; Signature Keys revised |

## Gaps and open questions

| ID | Question | Recommended ruling |
|---|---|---|
| Q1 | **Resolved:** public `ErrorDescription` members become `Detail`. | Clean spec-shaped cutover; no alias or dual-wire fallback |
| Q2 | **Resolved:** RFC 9457 applies to all runtime R3 error endpoints in this migration. | Include them in the common error cutover |
| Q3 | **Resolved:** unchanged Bootstrap/MockAgentProvider errors do not move to RFC 9457 here. | Create a focused research-and-plan spin-off |
| Q4 | **Resolved:** do not build the missing AS clarification receiver here. | Migrate the implemented PS flow and create an AS clarification spin-off |
| Q5 | **Resolved:** do not implement AAuth Events or its source seams here. | Spin off the complete Events protocol into a separate initiative |
| Q6 | **Resolved:** revised R3 AsyncAPI support is not implemented here. | Spin off the AsyncAPI model and subscription handoff with Events |
| Q7 | **Resolved:** Signature Keys `self-jwt` is not implemented here. | Create a coordinated dependency/use-case spin-off |

The Events and `self-jwt` spin-offs must share one admitted `dwk` discovery
primitive while preserving their different wire schemes and token checks.
