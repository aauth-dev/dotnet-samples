# AAuth draft-09 SDK Migration - Conformance Research

- Created: 2026-07-29
- Specification:
  [aauth-spec/v09/draft-hardt-oauth-aauth-protocol.md](../../../aauth-spec/v09/draft-hardt-oauth-aauth-protocol.md)
  (draft-09, published 2026-07-04), with companions
  [draft-hardt-aauth-r3.md](../../../aauth-spec/v09/draft-hardt-aauth-r3.md) and
  [draft-hardt-httpbis-signature-key-06.txt](../../../aauth-spec/v09/draft-hardt-httpbis-signature-key-06.txt)
- Baseline: **draft-08** ([aauth-spec/v08/](../../../aauth-spec/v08/)), migrated 2026-06-25
- Scope: `src/AAuth/` and `src/AAuth.R3/`, plus the test and documentation surfaces
  that carry the wire contract
- Provenance: [issue #44](https://github.com/aauth-dev/dotnet-samples/issues/44)
  and the research and plan on `origin/v09-spec-migration` were incorporated and
  independently checked on 2026-07-29
- Status: research complete; no implementation started

## Problem and scope

This is conformance research for migrating the SDK to draft-09. It deliberately
covers two classes of gap, because a migration that fixes only the first leaves the
SDK non-conformant against the very spec it claims to target:

- **DELTA** — the requirement changed between draft-08 and draft-09. The SDK was
  conformant when written and is now behind.
- **PRE-EXISTING** — the requirement is unchanged from draft-08 or older and the SDK
  is already non-conformant. A delta-scoped sweep will not surface these, because
  there is no diff to follow.

A third category emerged during research and is tracked separately:

- **CONTRACT DEBT** — tests and documentation encoding the draft-08 wire shape.
  These do not affect the shipped product directly, but they will let a broken
  migration pass CI and will actively mislead integrators.

`src/AAuth.Events/` is excluded — under separate review in
[PR #45](https://github.com/aauth-dev/dotnet-samples/pull/45). `samples/` is
excluded because the samples on the current branch are being reverted.

## Source-of-truth status

This document supersedes issue #44 and
`.agent/plans/2026-07-19-aauth-v09-spec-migration/research.md` as the technical
source of truth for the migration. Issue #44 may remain as a work tracker, but no
technical finding or scope boundary depends on it. The earlier branch artifacts
contributed five change sets, seven scope rulings, validation requirements, and a
surface inventory; all are incorporated below with this audit's pre-existing gaps
and contract debt.

The complete migration evidence set is:

| Change set | Findings |
|---|---|
| RFC 9457 error responses | A1-A3, C1-C3 |
| Clarification `action` | A4, B10, C1, C3 |
| AAuth Events and protocol integration | A5 |
| Revised R3 AsyncAPI vocabulary | A6 and B3 |
| Signature Keys `self-jwt` | A7 |
| Pre-existing conformance remediation | B1-B8 and B11 |

### Imported migration rulings

These rulings came from the earlier migration plan and are retained here so that
removing or closing issue #44 does not lose implementation-shaping context:

| ID | Ruling |
|---|---|
| D1 | Rename public `ErrorDescription` APIs to `Detail`; use only the draft-09 `detail` wire member, with no compatibility alias or dual-wire fallback |
| D2 | Include existing R3 token, document, challenge, and enforcement error bodies in the RFC 9457 cutover |
| D3 | Do not treat MockAgentProvider/Bootstrap-family error normalization as core SDK work |
| D4 | Migrate the implemented PS clarification flow; research the pre-existing missing AS clarification receiver separately |
| D5 | Keep the complete Events protocol in its dedicated package initiative; core exposes no partial Events support beyond an explicitly approved metadata seam |
| D6 | Coordinate revised R3 AsyncAPI support with Events because the handoff requires both a multi-member operation model and subscription semantics |
| D7 | Implement Signature Keys `self-jwt` only through a coordinated dependency/use-case initiative; do not conflate it with Events `sig=jwt` tokens |

### Sequencing consequence

The pre-existing findings are not uniformly separate work. Several touch **exactly
the same code** the delta already forces open, and are far cheaper done together
than scheduled independently:

| Pre-existing finding | Shares code with | Recommendation |
|---|---|---|
| B8 missing polling outcomes | A1/A2 error cutover (same response helpers) | Ride along where the endpoint state exists |
| B9 endpoint-specific extension codes | A1/A2 (same response helpers) | Preserve and document deliberately |
| B10 updated-request token identity | A4 clarification handler | Ride along |
| B1 auth token `exp` ceiling | nothing | Separate, and urgent |
| B2, B4, B5, B6, B7, B11 | nothing | Separate initiatives |

## Research method

Two passes.

**Pass 1** partitioned draft-09 by its own section structure — nine read-only
subagents, one per area, weighted by normative density (~200 MUST/SHOULD statements,
82 of them in `# Protocol Primitives` alone). This was deliberately *not* partitioned
by the known draft-08 → draft-09 delta, so unchanged requirements were audited with
equal weight. That choice is what surfaced the pre-existing set.

**Pass 2** was designed against pass 1's demonstrated blind spots rather than against
the spec: six sweeps targeting error emission by pattern, wire-name-to-.NET API
mirroring, negative/prohibition requirements, test and documentation surfaces,
cross-cutting synthesis, and client-side conformance.

### Verification posture

Subagent output was treated as a lead, not a finding. Every claim recorded here as
CRITICAL or HIGH was re-verified by hand against source. That pass changed the result
materially — see [Corrections to subagent findings](#corrections-to-subagent-findings),
which records **seven** wrong claims including two false "conformant" verdicts on
requirements that are in fact unimplemented.

Line citations were re-derived by grepping the requirement text and then printing
each cited line to confirm it matches the quotation. Seven of the line numbers
originally reported were wrong.

**Recorded as reported, not individually re-verified:** the per-document metadata
field tables, the CONFORMANT determinations in agent identity, delegation, missions,
and federation, and the full 45-row negative-requirement inventory.

### Final independent verification

After consolidation, six fresh read-only verifiers checked every finding and every
confirmed-conformant claim against the named spec area and current source:

| Verification area | Items | Outcome |
|---|---|---|
| Error responses and clarification | A1-A4, B8-B10, C1-C4 | Verified; error-body inventory fixed at 12 files; B9 reframed as legal endpoint extensions |
| AAuth Events | A5, D5-D7, companion evidence | Verified against the complete Events draft and current package boundary |
| R3 | A6, B3, D2, D6, R3 evidence | Verified; capability wording narrowed to conditional multi-member rejection |
| Signature Keys and discovery | A7, B4, B5, D7 | Verified; B4 raised to HIGH and B5 default/enforcement distinction clarified |
| Tokens, scopes, missions, federation | B1, B2, B10, B11 and corresponding conformant claims | Verified; B10 confirmed PRE-EXISTING from draft-08 L1071 |
| Interaction, metadata, replay, IANA | B6-B8 and corresponding conformant claims | Verified; optional metadata omissions retained as capability gaps |

The final pass did not accept verifier conclusions blindly. Conflicts were resolved
against source: B10 is not a draft-09 delta; B6 remains an SDK conformance gap despite
one verifier calling it a deployment obligation, because L2076 places both MUSTs on
"the server"; and the test file locations in C2 were confirmed directly.

#### Finding verification ledger

| Item | Governing spec area | Final verdict |
|---|---|---|
| A1 | Protocol `#error-responses`, `#error-response-format`, L2230-L2243 | VERIFIED |
| A2 | Protocol `#error-response-format`, L2238-L2243; draft-08 baseline L2242-L2247 | VERIFIED |
| A3 | Protocol `#error-response-format`, especially `error`/`detail` at L2240-L2241 | VERIFIED |
| A4 | Protocol `#agent-response-to-clarification`, L1012-L1021 | VERIFIED DELTA |
| A5 | Protocol agent metadata and JWT registrations; complete Events draft L190-L632 | VERIFIED, separate initiative |
| A6 | R3 `#asyncapi-vocabulary`, v09 L186-L200 versus v08 L180-L188 | VERIFIED DELTA |
| A7 | Signature Keys draft-06 §3.7, L757-L830; protocol `#keying-material` | VERIFIED DELTA, separate initiative |
| B1 | Protocol `## Re-authorization`, L1304-L1310 | VERIFIED PRE-EXISTING; resource-side clause needs upstream clarification |
| B2 | Protocol `#scopes`, L1980-L1994 | VERIFIED PRE-EXISTING |
| B3 | R3 standard vocabularies L110-L243 | VERIFIED capability limitation with narrowed wording |
| B4 | Protocol `#jwks-discovery`, L2409; Signature Keys §6.3 | VERIFIED PRE-EXISTING |
| B5 | Protocol `#jwks-discovery`, L2405-L2407 | VERIFIED PRE-EXISTING with safe-default caveat |
| B6 | Protocol `#interaction-code-format`, L2064-L2080; security rationale L2729 | VERIFIED PRE-EXISTING |
| B7 | Protocol metadata documents L2452-L2638 | VERIFIED capability/SHOULD gaps, not one blanket violation |
| B8 | Protocol Polling Error Codes L2270-L2280 plus each producing state machine | PARTLY VERIFIED; `invalid_code` is a definite B6 gap, other outcomes need reachability evidence |
| B9 | Protocol common error format L2238-L2243 plus endpoint-specific definitions | VERIFIED inventory requirement; custom codes are not inherently non-conformant |
| B10 | Protocol clarification updated request, v09 L1065 and v08 L1071 | VERIFIED PRE-EXISTING |
| B11 | Protocol Agent Token `exp`, L560 | VERIFIED PRE-EXISTING SHOULD-grade gap |
| C1 | Derivative evidence for `#error-response-format` and `#agent-response-to-clarification` | VERIFIED contract debt |
| C2 | Derivative evidence for the RFC 9457 wire/public-API cutover | VERIFIED contract debt |
| C3 | Derivative documentation evidence for A1-A4 | VERIFIED contract debt |
| C4 | End-to-end evidence for coordinated producer/consumer cutover | VERIFIED coverage gap; no existing assertion needs a mechanical rename |

## Why the first pass missed findings

The earlier migration research found four things pass 1 did not. Rather than treat
that as bad luck, each was traced to a mechanical cause and confirmed. These causes
shaped pass 2.

### 1. Case and separator blindness

Pass 1 grepped the wire name `error_description` and reported 5 files. The .NET
mirror is `ErrorDescription` — PascalCase, no underscore — so
[TokenError.cs](../../../src/AAuth/Errors/TokenError.cs) was invisible. Confirmed: a
case-insensitive search returns that file, the exact-case search does not. The
consequence was missing a **public API breaking change** entirely.

*Countermeasure:* pass 2 searched case-insensitively and with separators stripped.

### 2. File-role intuition instead of pattern sweeps

Pass 1 looked for error emission in files it judged to be "endpoints". Error bodies
also come from helpers and policy types. A pattern-first sweep finds **12 files that
emit JSON AAuth error bodies**; pass 1's "exhaustive" inventory listed 9. It missed
[AAuthHttpContextExtensions.cs](../../../src/AAuth/Server/Verification/AAuthHttpContextExtensions.cs)
(a challenge helper) and
[R3Enforcement.cs](../../../src/AAuth.R3/R3Enforcement.cs) (a decision type emitting
`r3_denied` and `r3_approval_required`), among others.

*Countermeasure:* pass 2's error sweep was forbidden from filtering by file role and
was given the specific misses as examples.

### 3. Scope exclusion of tests and documentation

Pass 1 excluded `tests/` and `docs/` as "not the SDK". For a wire-format cutover that
was the wrong call: fixtures encoding the old shape keep passing while the product
breaks. This exclusion hid the most operationally dangerous category in this
document — see [C1](#c1-the-conformance-suite-cannot-detect-a-broken-migration).

*Countermeasure:* pass 2 swept them as first-class surfaces.

### 4. Negative requirements are invisible to "find the implementation"

Pass 1's prompts asked subagents to locate the code implementing each requirement.
That method cannot evaluate requirements phrased as MUST NOT / MUST reject / MUST
ignore, because for those the *absence* of code is ambiguous — it may mean the SDK
correctly never does the forbidden thing, or that it fails to reject input a
conformant implementation must refuse. Those are opposite outcomes.

*Countermeasure:* pass 2 ran a dedicated sweep classifying every negative requirement
as ENFORCED / VACUOUS / UNENFORCED / UNENFORCEABLE. That sweep proved the least
reliable of the six (corrections X4-X5) — the framework was right, its verdicts
needed heavy checking.

### 5. Partitioning prevents synthesis

Nine area-scoped reviewers cannot see relationships spanning areas. The earlier
migration research noted that Signature Keys `self-jwt` and the Events
`sig=jwt`-with-`dwk`
presentation are structurally similar but separate wire schemes that must not be
conflated. No area-scoped reviewer held both.

*Countermeasure:* pass 2 included a synthesis sweep given the whole picture.

## Findings: draft-09 deltas

### A1. No JSON AAuth error body uses RFC 9457 problem details — CRITICAL

> Error response bodies use the HTTP problem details format ([@!RFC9457]) with
> `Content-Type: application/problem+json`.
> — [L2238](../../../aauth-spec/v09/draft-hardt-oauth-aauth-protocol.md)

`application/problem+json` appears **zero times** in `src/AAuth/` and
`src/AAuth.R3/`. Every error body goes out via `Results.Json` / `Results.NotFound`
and serialises as `application/json`.

The verified producer surface is 12 files:

| Package | Error-body producer |
|---|---|
| Core | `AAuthAccessServerEndpoints.cs` |
| Core | `AAuthApplicationBuilderExtensions.cs` |
| Core | `AAuthGovernanceApplicationBuilderExtensions.cs` |
| Core | `AAuthPersonServerEndpoints.cs` |
| Core | `GovernanceEndpoints.cs` |
| Core | `AAuthInteractionEndpointExtensions.cs` |
| Core | `RevocationEndpoint.cs` |
| Core | `AAuthHttpContextExtensions.cs` |
| R3 | `R3AccessTokenEndpoint.cs` |
| R3 | `R3Challenge.cs` |
| R3 | `R3DocumentEndpoint.cs` |
| R3 | `R3Enforcement.cs` |

[R3Enforcement.cs](../../../src/AAuth.R3/R3Enforcement.cs) emits `r3_denied` and
`r3_approval_required`; the helper
[AAuthHttpContextExtensions.cs](../../../src/AAuth/Server/Verification/AAuthHttpContextExtensions.cs)
emits `auth_token_required`. These non-endpoint-shaped files are why pattern-first
enumeration is required.

Three emitters already use what become RFC 9457 **extension members** —
`{error, mission_status}` in `GovernanceEndpoints`, `{error, id}` in the governance
pending handler, and `{error, r3_uri, r3_s256}` in `R3Enforcement`. Legal under
RFC 9457, but they should be declared deliberately rather than inherited by accident.

Correctly excluded from the cutover:
[AAuthVerificationMiddleware.cs](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs)
and `AAuthChallengeMiddleware.cs` emit status plus header and no body —
authentication failures use the `Signature-Error` header per
[L2232-L2234](../../../aauth-spec/v09/draft-hardt-oauth-aauth-protocol.md). The spec
does not forbid an accompanying problem body, but the migration should preserve the
current bodyless behavior rather than invent one without a use case; any future body
would still be governed by A1.

### A2. Six emission sites still use the removed `error_description` — HIGH

draft-09 replaced `error_description` with `detail`
([L2241](../../../aauth-spec/v09/draft-hardt-oauth-aauth-protocol.md); `error` becomes
a REQUIRED extension member at
[L2240](../../../aauth-spec/v09/draft-hardt-oauth-aauth-protocol.md)). Six sites
remain: [RevocationEndpoint.cs](../../../src/AAuth/Server/RevocationEndpoint.cs) ×3 and
[AAuthApplicationBuilderExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs) ×3.

This is a **breaking public .NET API change**, not only a wire change. Two public
members mirror the removed wire member:

| Public member | Location |
|---|---|
| `TokenErrorResponse.ErrorDescription` | [TokenError.cs:50](../../../src/AAuth/Errors/TokenError.cs#L50) |
| `AAuthTokenExchangeException.ErrorDescription` | [AAuthTokenExchangeException.cs:27](../../../src/AAuth/Errors/AAuthTokenExchangeException.cs#L27) |

A dedicated sweep confirmed these are the **only** public members mirroring a removed
or renamed draft-09 wire member. The SDK constructs wire names explicitly in code and
uses exactly one `[JsonPropertyName]` attribute, so there is no hidden serialisation
drift to chase. D1 rules that both become `Detail` without aliases.

### A3. SDK clients cannot read draft-09 error text — HIGH

The client parsers read **only** `error_description`, with no `detail` fallback:
[TokenExchangeClient.cs:247](../../../src/AAuth/Agent/TokenExchangeClient.cs#L247) and
[AccessServerClient.cs:514](../../../src/AAuth/Access/AccessServerClient.cs#L514).
Against a conformant draft-09 server the explanation is silently discarded — no
exception, no log, just a null diagnostic exactly when one is wanted.

A dedicated client-side sweep found this is the SDK's **only** silent failure of this
shape; request construction, polling, challenge handling, and header emission and
parsing were all confirmed conformant.

### A4. Clarification `action` discriminator absent on both sides — HIGH

> A POST body MUST include an `action` member identifying the response type. A server
> MUST reject a POST with a missing or unrecognized `action` value with
> `400 Bad Request`.
> — [L1020](../../../aauth-spec/v09/draft-hardt-oauth-aauth-protocol.md)

`"action"` appears in neither
[ClarificationExchange.cs](../../../src/AAuth/Agent/ClarificationExchange.cs) nor the
pending-URL POST handler in
[AAuthPersonServerEndpoints.cs](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs).
Both directions break.

See [C1](#c1-the-conformance-suite-cannot-detect-a-broken-migration): seven
conformance test locations pass whether or not this is fixed correctly.

### A5. AAuth Events is a complete companion protocol — SEPARATE INITIATIVE

draft-09 adds the optional `event_endpoint` to Agent Provider metadata, required
when the AP supports Events (protocol L2482-L2511), and references the companion's
`aa-subscribe+jwt` and `aa-event+jwt` types (L2899-L2915). Core
`AAuthAgentMetadataOptions`, `BuildAgentMetadata`, and `ServerMetadata` cannot emit
or parse `event_endpoint`.

The companion itself defines complete AP, resource, and agent roles:

| Feature group | Spec evidence |
|---|---|
| AP metadata | Events `#ap-metadata`, L190-L202 |
| Subscribe-token claims and verification | Events `#subscribe-token`, L204-L283 |
| Public and protected registration | Events L285-L339 |
| Event-token claims | Events `#event-token`, L340-L374 |
| Resource-to-AP delivery and atomic acceptance | Events `#event-delivery`, L376-L429 |
| AP-to-agent routing and agent verification | Events `#ap-to-agent`, L430-L447 |
| AsyncAPI discovery | Events `#event-discovery`, L449-L573 |
| Replay, privacy, and retention | Events L574-L616 |

The current branch contains a dedicated `AAuth.Events` implementation under review,
so this migration must not duplicate it. D5 retains Events as a coordinated package
initiative. Core metadata support is added only if that package boundary cannot emit
and consume the required field without implying partial core support.

The critical shared primitive is issuer-controlled key discovery. Events delivery
uses `sig=jwt` with `dwk` and no `cnf`; the AP discovers the resource key by
`iss`/`dwk`/`kid`, verifies the JWT, then verifies the HTTP signature with the same
key. That is **not** Signature Keys `self-jwt`, despite the structural similarity.

### A6. Revised R3 AsyncAPI operations exceed the current model — SEPARATE INITIATIVE

The revised R3 draft keeps `operationId` REQUIRED, makes `action` OPTIONAL, and hands
an R3-granted subscription to AAuth Events through a ticket and subscribe token
(`#asyncapi-vocabulary`, R3 L186-L200).

[R3Operation.cs](../../../src/AAuth.R3/Model/R3Operation.cs) deliberately accepts
exactly one string member. A valid AsyncAPI entry can contain both `operationId` and
`action`, so deserialization rejects it. Adding only a vocabulary constant is
therefore incomplete; D6 coordinates the model change and subscription handoff with
Events.

This limitation also affects GraphQL, WSDL, and OData multi-member operations. gRPC
is different: its one-member `{method: ...}` operation is representable through the
generic `Field`/`Id` model even though no convenience constant or factory exists.

### A7. Signature Keys `self-jwt` is absent — SEPARATE INITIATIVE

Signature Keys draft-06 adds `sig=self-jwt` (§3.7, L757-L830). The JWT MUST contain
HTTPS `iss` and `dwk`, MUST have `kid`, MUST NOT contain `cnf`, and SHOULD contain
standard claims. Verification must reject malformed or unexpected input cheaply,
discover `{iss}/.well-known/{dwk}` and `jwks_uri`, verify the JWT, and verify the HTTP
signature with the same discovered key.

[AAuthConstants.cs](../../../src/AAuth/AAuthConstants.cs) declares only `jwt`, `hwk`,
`jkt-jwt`, and `jwks_uri`; there is no `self-jwt` formatter, parser branch, provider,
resolver, test, or documentation. A presented `self-jwt` is rejected as an unsupported
scheme.

D7 keeps this as a dependency/use-case initiative because the main AAuth protocol
still requires `scheme=jwt` for resource, PS, and AS requests and attaches no current
core flow to `self-jwt`. It must share one admitted `iss`/`dwk` JWKS resolver with
Events while preserving the distinct wire schemes and the mandatory `cnf` rejection.
The draft's illustrative `typ` and `dwk` values also differ from this repository's
AAuth values, so a concrete use case must be selected before implementation.

## Findings: pre-existing non-conformance

None of these appeared in the earlier delta-scoped migration research.

### B1. Auth token `exp` is not bounded by the agent token `exp` — CRITICAL

> Auth tokens MUST NOT have an `exp` value that exceeds the `exp` of the agent token
> used to obtain them — a resource MUST reject an auth token whose associated agent
> token has expired.
> — [L1310](../../../aauth-spec/v09/draft-hardt-oauth-aauth-protocol.md)

[AuthTokenBuilder.cs](../../../src/AAuth/Tokens/AuthTokenBuilder.cs) caps `Lifetime` at
one hour (L141-L143) and computes `exp = iat + Lifetime` (L152). It never reads the
agent token's `exp`, and no file in the SDK compares the two. An agent token with five
minutes remaining yields an auth token valid for a further hour.

Identical text in draft-08, so this is a pre-existing defect, not migration debt.

The second clause deserves an upstream question rather than an implementation: when an
agent presents an auth token, that token *is* the `Signature-Key` JWT, so the resource
never sees the agent token and cannot observe its expiry. As written the resource-side
obligation appears unenforceable.

### B2. Resource-token scopes are not validated against published metadata — HIGH

[L1987](../../../aauth-spec/v09/draft-hardt-oauth-aauth-protocol.md) carries two
requirements; the SDK satisfies one:

| Requirement | Status |
|---|---|
| Auth token scope MUST NOT be broader than resource token scope | **Conformant** — [TokenVerifier.cs:166-167, 276](../../../src/AAuth/Tokens/TokenVerifier.cs#L166) |
| Resource token MUST only include scopes defined in `scope_descriptions`, and identity scopes declared in `scopes_supported` | **Missing** |

`scope_descriptions` and `scopes_supported` are emitted and parsed as metadata but
never consulted when issuing or verifying a token, so a resource can mint scopes it
never published.

### B3. Multi-member forms of four R3 vocabularies are unsupported — MEDIUM

[Vocabulary.cs](../../../src/AAuth.R3/Model/Vocabulary.cs) declares `mcp` and
`openapi`. R3 defines seven vocabulary identifiers, but missing convenience constants
do not alone establish wire nonconformance. `grpc` uses a one-member `{method: ...}`
shape and is representable through the generic `Field`/`Id` API.

The structural gap is the multi-member form of four vocabularies. GraphQL always
requires `{operation, type}` and is therefore always rejected. AsyncAPI, WSDL, and
OData have one required member plus an optional second member; the one-member form is
representable, but the converter rejects a conformant entry when that optional member
is present. [R3Operation.cs](../../../src/AAuth.R3/Model/R3Operation.cs) rejects a
second member and its own API documentation names those four as unsupported. A6 covers
the draft-09 AsyncAPI delta; the other three are pre-existing capability limitations
in a preview package, not proof that every R3 use is non-conformant.

### B4. No egress admission on metadata and JWKS fetches — HIGH

[L2409](../../../aauth-spec/v09/draft-hardt-oauth-aauth-protocol.md) requires egress
admission per the signature-key spec before fetching issuer metadata or `jwks_uri`;
signature-key §6.3 details the checklist. Neither
[MetadataClient.cs](../../../src/AAuth/Discovery/MetadataClient.cs) nor
[JwksClient.cs](../../../src/AAuth/Discovery/JwksClient.cs) applies any of it.

Notably [R3FetchClient.cs](../../../src/AAuth.R3/R3FetchClient.cs) *does* enforce
HTTPS, private-IP rejection, and no-redirect — the control exists in the codebase and
simply was not applied to the core discovery path. This is HIGH because L2409 is a
MUST and the missing controls sit on an issuer-controlled network-fetch boundary.

### B5. JWKS cache ignores HTTP cache headers and the 24-hour cap — MEDIUM

[L2405](../../../aauth-spec/v09/draft-hardt-oauth-aauth-protocol.md) requires caching
JWKS, says implementations SHOULD respect `Cache-Control` and `Expires`, and says
cached entries SHOULD be discarded after a maximum of 24 hours regardless of cache
headers. `JwksClient` never reads response headers. Its default one-hour TTL is safely
inside the 24-hour recommendation, but the constructor accepts any caller-supplied TTL
and enforces no maximum, so a 30-day cache is possible. The once-per-minute floor and
the same-`kid` refresh at
[L2407](../../../aauth-spec/v09/draft-hardt-oauth-aauth-protocol.md) *are* implemented
correctly.

### B6. Interaction-code rate limiting is delegated, not enforced — HIGH

Two normative MUSTs, neither met:

> the server MUST rate-limit code-validation attempts at the interaction URL. After a
> small number of failed attempts the server MUST treat the pending interaction as
> terminally failed and return `invalid_code`.
> — [L2076](../../../aauth-spec/v09/draft-hardt-oauth-aauth-protocol.md)

[L2729](../../../aauth-spec/v09/draft-hardt-oauth-aauth-protocol.md) then names entropy
and rate limiting together as *the* brute-force defence. The SDK implements entropy
and single-use;
[IInteractionPendingStore.cs](../../../src/AAuth/Server/ResourceManaged/IInteractionPendingStore.cs)
documents rate limiting as a deployment control and provides no seam, and nothing
implements the terminal-failure transition.

### B7. Metadata capability gaps — LOW to MEDIUM

Absent from options and emission: `mission_control_endpoint` (PS),
`additional_signature_components` (resource), `claims_supported` (PS),
`localhost_callback_allowed` (agent). `additional_signature_components` is the
consequential one — without it a resource cannot advertise extra covered components,
so agents cannot know to sign them.

These are not one class of normative violation:

| Field | Spec status | Assessment |
|---|---|---|
| `mission_control_endpoint` | OPTIONAL | Capability omission, not nonconformance |
| `localhost_callback_allowed` | OPTIONAL, default `false` | Capability omission; omission safely preserves the default |
| `additional_signature_components` | OPTIONAL | Capability omission that prevents resources from using the extension through typed SDK metadata |
| `claims_supported` | RECOMMENDED | SHOULD-grade gap; the PS cannot advertise supported identity claims through typed metadata |

### B8. Required polling outcomes are incomplete — MEDIUM

`abandoned`, `expired`, `invalid_code`, and `slow_down` exist in
[PollingError.cs](../../../src/AAuth/Errors/PollingError.cs) and are normative in the
Polling Error Codes table at
[L2270-L2280](../../../aauth-spec/v09/draft-hardt-oauth-aauth-protocol.md), but direct
search finds no endpoint emitting those four strings. `user_unreachable` is likewise
defined but never emitted.

The table defines wire meanings; it does not require every implementation to produce
every outcome unconditionally. The concrete conformance gap is narrower:

- B6 requires failed interaction-code attempts to become terminal `invalid_code`, but
  no such transition or body exists.
- Expired pending state and polling throttling should use `expired` and `slow_down`
  when those states occur; current endpoints use other codes or bare status handling.
- `abandoned` and `user_unreachable` need flow-by-flow evidence before being called
  defects, rather than mere currently unattached outcomes.

### B9. Endpoint-specific error extensions need an explicit inventory — LOW

The SDK emits additional codes, including:
`policy_unavailable`, `policy_error`, `payment_required`, `untrusted_person_server`,
`untrusted_access_server`, `invalid_carrier`, `invalid_carrier_token`,
`unknown_interaction`, `unknown_pending`, `request_withdrawn`,
`invalid_upstream_token`, `untrusted_fetcher`, `invalid_signature`,
`r3_evaluation_failed`, `r3_denied`, `r3_approval_required`, `auth_token_required`,
`mission_terminated`, and dynamic pending-entry errors.

These are **not automatically out of spec**. The common format says `error` is a code
"as defined by the endpoint returning the error," and several values come from
endpoint-specific or companion behavior rather than the token/polling tables. The
migration requirement is to inventory them, preserve their statuses and extension
members deliberately, and document which are SDK extensions. Upstream proposals are
appropriate only where interoperability requires a common value.

### B10. Updated-request resource token identity unvalidated — MEDIUM

[L1065](../../../aauth-spec/v09/draft-hardt-oauth-aauth-protocol.md) requires a
replacement resource token in a clarification exchange to carry the same `iss`,
`agent`, and `agent_jkt` as the original. The pending-URL POST handler accepts the new
token without comparing any of the three. Shares code with A4.

### B11. Agent token lifetime is unbounded — MEDIUM

[L560](../../../aauth-spec/v09/draft-hardt-oauth-aauth-protocol.md) says agent tokens
SHOULD NOT exceed 24 hours.
[AgentTokenBuilder.cs:66](../../../src/AAuth/Tokens/AgentTokenBuilder.cs#L66) defaults
`Lifetime` to one hour but enforces no maximum, so a caller can set 30 days and the
builder emits it.

Most persuasive as an **internal inconsistency**: the SDK's other two token builders
both enforce their ceilings —
[AuthTokenBuilder.cs:143](../../../src/AAuth/Tokens/AuthTokenBuilder.cs#L143) throws
above 1 hour and
[ResourceTokenBuilder.cs:99](../../../src/AAuth/Tokens/ResourceTokenBuilder.cs#L99)
throws above 5 minutes. Agent tokens are the only one without a guard.

## Findings: test and documentation contract debt

New in pass 2, and the category most likely to let an apparently successful migration
ship broken.

### C1. The conformance suite cannot detect a broken migration

`tests/AAuth.Conformance/` asserts `application/problem+json` nowhere, and asserts
the clarification `action` discriminator nowhere. (`["action"]` does occur 11 times
in the suite, but every occurrence is the unrelated **governance** `action` field
of permission and audit requests — `"SendEmail"`, `"WebSearch"` — in
`Missions/Governance*Tests.cs`. None is in a clarification test.)

Multiple tests exercise the clarification POST by checking which *keys are present* —
exactly the inference draft-09 removed:

| Test | Lines |
|---|---|
| `Missions/ClarificationChatTests.cs` | L81, L201, L207 |
| `Missions/ChallengeClarificationSeamTests.cs` | L201 |
| `Missions/GovernanceClientTests.cs` | L299 |
| `Person/PersonServerMapperTests.cs` | L479, L568, L575 |

Every cited location passes whether or not `action` is implemented. A migration could be declared
complete with `make test-conformance` green while clarification flows fail against
every conformant peer.

### C2. Error-shape fixtures encode the removed member

`Agent/ChallengeHandlerTests.cs` L328/L336 and `AccessServerClientTests.cs` L311 mock
`{"error": ..., "error_description": ...}` and assert on `ErrorDescription`.
`Errors/TokenErrorTests.cs` L37 asserts the property directly — that one at least
fails at compile time under a rename, which is the desirable behaviour.
`Errors/PollingErrorTests.cs` L29/L65/L89 assert error codes over `application/json`
and never check the content type.

### C3. Documentation teaches the draft-08 shape

[docs/advanced/error-handling.md](../../../docs/advanced/error-handling.md) shows the
old wire member and public API at L97, L106, L114, L149, and L323.
[docs/advanced/clarification-chat.md](../../../docs/advanced/clarification-chat.md)
describes the agent responses at L43 and L161 without mentioning the required `action`
discriminator. [docs/README.md](../../../docs/README.md) L273 lists the old type names.
No document anywhere shows `application/problem+json` or `detail`. Integrators copying
these snippets will build draft-08 requests that draft-09 servers reject.

### C4. Existing e2e assertions do not inspect the new wire members

`tests/e2e/` asserts at the UI level and does not depend on the error wire shape or the
clarification body directly. Existing assertions therefore need no mechanical rename,
but that does **not** make e2e unaffected: the live clarification flow should gain an
assertion or captured-wire check proving `action=clarification_response`, and a full
e2e run remains a migration gate because the producer and consumer cut over together.

## Migration acceptance evidence

These are validation requirements, not implementation steps. They are incorporated
from the earlier migration plan so this document remains sufficient to derive a new
implementation plan.

### RFC 9457 cutover evidence

- Representative PS, AS, authorization, interaction, governance, challenge,
  revocation, and R3 tests assert status, `application/problem+json`, required
  `error`, and optional `detail`.
- `TokenExchangeClient` and `AccessServerClient` parse `detail` and continue to branch
  only on `error`; optional RFC 9457 `type`, `title`, `status`, and `instance` do not
  affect classification.
- Public `ErrorDescription` APIs and compiled consumers move to `Detail` without an
  alias or `error_description` fallback, per D1.
- Header-only authentication failures retain `Signature-Error` behavior and do not
  acquire an invented JSON body.
- R3 extension members (`r3_uri`, `r3_s256`) and core extension members
  (`mission_status`, `id`) survive the media-type cutover.
- A post-change search finds no `error_description` in the migrated SDK, tests, or
  documentation.

### Clarification cutover evidence

- Captured agent JSON proves both exact shapes:
  `action=clarification_response` with `clarification_response`, and
  `action=updated_request` with `resource_token`.
- The PS accepts both recognized actions and rejects missing or unknown actions with
  `400` problem details.
- A recognized action without its required payload fails defensively as
  `invalid_request`; cancellation remains a bodyless `DELETE`.
- Updated requests enforce B10's unchanged `iss`, `agent`, and `agent_jkt` binding.
- Unit and conformance fixtures stop inferring the operation from member presence.
- The live clarification flow exposes the action member in captured wire evidence.

### Companion initiative evidence

- Events validation covers every feature group listed in A5, including token
  positives and negatives, protected-ticket single use, atomic `max_uses`, durable
  acceptance before `202`, replay, expiry, resource/AP/agent integration, and
  AsyncAPI discovery.
- R3 AsyncAPI validation proves multi-member operation round trips and the handoff to
  Events registration; adding only a vocabulary constant is insufficient.
- `self-jwt` validation covers cheap structural rejection, required `iss`/`dwk`/`kid`,
  mandatory `cnf` absence, JWT and HTTP verification with the same key, cache expiry,
  SSRF admission, and unknown-key behavior.
- Events `sig=jwt` and Signature Keys `sig=self-jwt` share one admitted discovery
  primitive but remain separate parser and verification branches.

### Repository validation matrix

Every implementation phase must pass the narrow tests for its touched surface and the
repository gates:

```bash
make build
make test-unit
make test-conformance
make e2e
```

An unavailable e2e environment is a blocker requiring an explicit ruling, not a
silent skip.

## Corrections to subagent findings

Recorded because they calibrate how much weight the un-re-verified findings deserve.

| # | Claim | Correction |
|---|---|---|
| X1 | Scope narrowing is MISSING | **Wrong.** Implemented at [TokenVerifier.cs:166-167, 276](../../../src/AAuth/Tokens/TokenVerifier.cs#L166). Two other subagents independently reported it conformant. The real gap is the other half of L1987 — B2. |
| X2 | Unemitted polling error codes are a DELTA | **Wrong.** The polling table is unchanged from draft-08; reclassified PRE-EXISTING (B8). |
| X3 | Error-format gap is "6 sites" | **Understated.** Six sites use the removed member, but every JSON AAuth error-body producer emits the wrong content type, across 12 verified files (A1). |
| X4 | Clarification `action` rejection is ENFORCED | **Wrong.** Verified: `action` appears nowhere in the PS endpoint or the agent client. Reported ENFORCED on the strength of nearby unrelated code. |
| X5 | Auth token `exp` ceiling is ENFORCED at `AAuthVerificationMiddleware.cs:195` | **Wrong.** That line is a jkt-jwt naming-JWT expiry check. No file compares auth token `exp` to agent token `exp` (B1). |
| X6 | Verified claims are re-read from an unverified payload (trust-boundary defect) | **Overstated — investigated and cleared.** The cited lines are OpenTelemetry tagging. Signature resolution, `_verifier.Verify`, and issuer verification all occur before `AAuthVerificationResult` is populated. Not a defect. |
| X7 | Assorted spec line numbers | **Drifted.** Seven citations were wrong by 5-50 lines. All citations here were re-derived from the requirement text and validated by printing the cited line. |

X4 and X5 came from the same sweep — the negative-requirements pass. Its inventory of
*which* requirements exist is useful; its ENFORCED verdicts are not reliable without
checking, because the method rewards finding any nearby plausible code.

## Confirmed conformant

Recorded so coverage is auditable, and because these were checked with the same rigour
as the failures.

- **Agent identity and delegation** — all 21 sampled requirements, including identifier
  syntax and case-sensitive comparison, the `+` sub-agent delimiter, single-level depth
  enforced on both AP and PS sides, and `act.agent` naming the immediate delegator.
- **Call chaining** — upstream token `aud` verified equal to the intermediary agent
  token's `iss`.
- **Missions** — `s256` over exact received bytes with no re-serialisation; `approver`
  validated as a server identifier; reference copied unchanged into resource and auth
  tokens.
- **AS federation** — all seven auth-token delivery verification steps.
- **R3 content addressing** — `R3Hash` computes `r3_s256` over exact bytes and the
  document endpoint serves the stored bytes without canonicalisation or
  re-serialisation.
- **R3 protected fetch** — `R3DocumentEndpoint` requires a verified AS HTTP signature
  before returning an R3 document; unauthenticated agent fetches are rejected.
- **R3 claim pairing** — `r3_uri` and `r3_s256` are required together and preserved in
  the conditional-approval flow; `r3_uri` and `r3_s256` on
  `r3_approval_required` remain intentional RFC 9457 extension members after A1.
- **HTTP message signatures** — the four mandated covered components in order; agent
  keying material restricted to `scheme=jwt`, with `hwk` and `jkt-jwt` rejected for
  agent and auth tokens.
- **Client behaviour** — request construction, `Retry-After` handling with the
  5-second default, linear 429 backoff, unrecognised `status` treated as pending,
  challenge handling, and tolerant header parsing. The identified client defects are
  A3's stale error-member parser and A4's stale clarification serializer.
- **Token discipline** — `none` rejected; `typ` and `dwk` verified on every token type;
  auth tokens capped at 1 hour and resource tokens at 5 minutes; `cnf`
  proof-of-possession enforced. (Agent token ceiling is the exception — B11.)
- **Metadata issuer binding** — a document whose `issuer` does not match its fetch URL
  is rejected.
- **Replay** — keyed on the verified signature within the freshness window rather than
  token `jti`, which is the correct scoping.
- **Interaction codes** — Crockford base32, ≥40 bits entropy, hyphen stripping, glyph
  folding, case-insensitive comparison, single-use consume, and documented as a
  correlation identifier rather than an authorization credential.
- **IANA registrations** — all three `typ` values and all six registered claim names
  match the spec strings exactly.
- **Verification ordering** — claims exposed on `AAuthVerificationResult` are read
  after signature resolution and JWT verification (see X6).

## Gaps and open questions

1. **Is the resource-side half of B1 implementable as written?** The resource never
   sees the agent token when an auth token is presented. Either the SDK lacks a
   mechanism or the spec clause needs an upstream question.
2. **Which B8 outcomes are reachable in the current SDK?** `invalid_code` is required
  by B6; `expired`, `slow_down`, `abandoned`, and `user_unreachable` need state-machine
  evidence before their absence is classified as a defect.
3. **Which B9 codes need standardization?** Preserve endpoint-specific values during
  the media-type cutover, then propose only values whose cross-implementation
  interpretation is necessary.
4. **How far should B3 go?** Supporting the multi-member forms of GraphQL, AsyncAPI,
  WSDL, and OData means reshaping `R3Operation` — a public API change in a preview
  package. gRPC already fits the generic one-member model.
5. **Does B6 warrant an SDK seam** (an `IInteractionAttemptLimiter`-style contract), or
   is documenting the deployment obligation sufficient given it is two MUSTs?
6. **Should C1 be fixed before the migration rather than with it?** Tests that cannot
   fail are worse than absent tests, because they are read as assurance.

## Out of scope

| Item | Reason |
|---|---|
| `src/AAuth.Events/` | Under separate review in PR #45 |
| `samples/` | Being reverted on the current branch |
| Vendoring a newer spec revision | draft-09 is latest; signature-key draft-07 exists but draft-09 cites draft-06 |
| Upstream specification edits | Draft maintenance is outside this repository |
