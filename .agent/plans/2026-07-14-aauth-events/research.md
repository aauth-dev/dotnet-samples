# AAuth Events - Research

- Created: 2026-07-14
- Specification:
  [aauth-spec/v09/draft-hardt-aauth-events.md](../../../aauth-spec/v09/draft-hardt-aauth-events.md)
  (2026-06-24 draft)
- Precedent:
  [src/AAuth.R3](../../../src/AAuth.R3) and
  [.agent/plans/2026-07-02-r3-rich-resource-requests](../2026-07-02-r3-rich-resource-requests)
- Updated: 2026-07-15 (review follow-up)
- Status: ready for owner review; no implementation or commit has been made

## Problem and scope

AAuth Events adds asynchronous subscription and delivery to AAuth. An Agent
Provider (AP) issues a resource-scoped subscribe token, a resource registers the
subscription, and the resource later sends a signed event token and optional
payload to the AP. The AP is the durable inbox because agents need not expose a
public endpoint. Agent-to-AP token acquisition and AP-to-agent transport are
explicitly outside the protocol; only token issuance, receipt verification, and
agent-side event verification are in SDK scope
([protocol overview](../../../aauth-spec/v09/draft-hardt-aauth-events.md#fig-overview),
L143-L188; [AP-to-agent](../../../aauth-spec/v09/draft-hardt-aauth-events.md#ap-to-agent),
L430-L447).

The selected deliverable is a complementary `AAuth.Events` NuGet package that
depends on `AAuth`, not a feature folded into the core SDK. It covers all
protocol-defined AP, resource, and agent roles. The non-normative sample uses
agent-authenticated polling to make the full flow runnable.

## Research method

Three read-only research threads were collated:

1. The complete Events draft, split by protocol role, wire artifact, security
   requirement, and conformance scenario.
2. The `AAuth.R3` package and its research, implementation plan, and log as the
   packaging and planning precedent.
3. The core SDK's public crypto, JWT, HTTP-signature, discovery, metadata, DI,
   endpoint, test, sample, and release seams.

> **Update (2026-07-15):** The four missed findings in
> [spec-inconsistency-review.md](spec-inconsistency-review.md) and its
> cross-package metadata risk were re-verified against the vendored draft,
> `R3Metadata`, the Bookings metadata setup, and the
> [AsyncAPI 3.0.0 Operation Object](https://www.asyncapi.com/docs/reference/specification/v3.0.0#operationObject).
> The resulting decisions are recorded as RF1-RF5 below. A subsequent
> consistency pass exposed the C14 token-identity ambiguity, resolved by C23.

The highest-risk findings were then re-verified directly against the vendored
specification and current source. In particular:

- token claims and validation sequences were checked at
  [Subscribe Token](../../../aauth-spec/v09/draft-hardt-aauth-events.md#subscribe-token)
  L204-L280 and
  [Event Token](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-token)
  L340-L374;
- AP delivery ordering, atomic use counts, durability, and status codes were
  checked at
  [Event Delivery](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-delivery)
  L376-L428;
- discovery and AsyncAPI requirements were checked at
  [Event Discovery](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-discovery)
  L449-L573;
- core signer/verifier asymmetry was checked in
  [AAuthSigningHandler.cs](../../../src/AAuth/HttpSig/AAuthSigningHandler.cs#L38-L52),
  [AAuthVerifier.cs](../../../src/AAuth/HttpSig/AAuthVerifier.cs#L20-L23), and
  [SignatureKeyParser.cs](../../../src/AAuth/HttpSig/SignatureKeyParser.cs#L89-L119);
- the AP metadata limitation was checked in
  [AAuthAgentMetadataOptions.cs](../../../src/AAuth/Server/Metadata/AAuthAgentMetadataOptions.cs)
  and
  [WellKnownEndpoints.cs](../../../src/AAuth/Server/Metadata/WellKnownEndpoints.cs#L46-L58).

Finer sample file placement reported by the repository research thread was
re-checked only where it affects the planned Bookings, MockAgentProvider, and
EventAgent flow.

## Protocol findings

### Roles and boundaries

| Role | Protocol responsibility | SDK boundary |
|---|---|---|
| AP | Publish `event_endpoint`; issue subscribe tokens; retain AP subscription state; authenticate, authorize, atomically account for, and durably record delivered events | Token issuer, AP store contract, delivery endpoint, metadata composition |
| Agent | Obtain and present a subscribe token; retain `eid` context; verify resource event tokens; deduplicate events | Registration client, event verifier, context/dedup seams |
| Resource | Verify subscription requests; enforce public or protected channel policy; store subscriptions; discover the current AP endpoint; issue and deliver event tokens | Registration verifier/mapper, resource store/handler seams, delivery client |
| Application | Define channel parameters, ticket format, subscription lifetime, event payload schema, durable persistence, and AP-to-agent transport | Explicit policy and storage interfaces; no invented wire fields |

The AP must advertise an HTTPS `event_endpoint`, may change it, and the resource
must resolve it from current AP metadata rather than from the subscribe token
([AP Metadata](../../../aauth-spec/v09/draft-hardt-aauth-events.md#ap-metadata),
L190-L202).

### Subscribe token

The AP-signed JWT uses `typ: aa-subscribe+jwt`. Its header requires `alg`, `typ`,
and `kid`; `none` must not be accepted and EdDSA is recommended. Required payload
claims are `iss`, fixed `dwk: aauth-agent.json`, `sub`, resource `aud`,
`cnf.jwk`, opaque `eid`, `iat`, and `exp`. Optional `max_uses` is a positive
integer enforced by the AP; omission means unlimited
([Subscribe Token](../../../aauth-spec/v09/draft-hardt-aauth-events.md#subscribe-token),
L204-L244).

The resource validation order is:

1. require `typ: aa-subscribe+jwt`;
2. require `dwk: aauth-agent.json`, resolve the AP key by `kid`, and verify the
   JWT signature;
3. validate `exp` and `iat`;
4. bind `aud` to the resource;
5. bind `cnf.jwk` to the HTTP-signature key;
6. require a non-empty `eid`.

The resource then stores enough state to deliver events and resolves the AP
metadata at delivery time
([Subscribe Token verification](../../../aauth-spec/v09/draft-hardt-aauth-events.md#subscribe-token),
L268-L280).

### Registration

Public channels accept the subscribe token as the sole `Signature-Key` JWT on a
signed POST. Protected channels first return an opaque, HTTPS, short-lived,
single-use ticket URL from an authenticated interaction. Registration at that
URL carries no additional auth token; the resource must atomically enforce the
ticket and bind subscribe-token `sub` to the previously authenticated agent
([Subscription Registration](../../../aauth-spec/v09/draft-hardt-aauth-events.md#subscription-registration),
L285-L290;
[Protected Subscriptions](../../../aauth-spec/v09/draft-hardt-aauth-events.md#protected-subscriptions),
L291-L339).

The ticket format and response field are application-defined. The resource
should reject a second registration for an existing `eid`
([Subscribe Token Replay](../../../aauth-spec/v09/draft-hardt-aauth-events.md#subscribe-token-replay-at-registration),
L588-L590).

### Event token and delivery

The resource-signed JWT uses `typ: aa-event+jwt`. Its header requires `alg`,
`typ`, and `kid`; its required payload is resource `iss`, fixed
`dwk: aauth-resource.json`, agent `aud`, subscription `eid`, `iat`, and `exp`.
It deliberately has no `cnf` and no event-specific data
([Event Token](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-token),
L340-L374).

Unlike the subscribe-token header, which explicitly forbids `alg: none` at
[L212](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L212), the
event-token header only recommends EdDSA at
[L348](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L348). This is a
draft omission, not permission to accept unsigned event tokens. C21 applies to
both token types: `none` and unsupported algorithms are rejected.

The draft defines no per-event identifier in its event-token claims
([L351-L359](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L351-L359)).
Hashing the compact token therefore cannot distinguish a retry from two
legitimate events whose other claims and whole-second timestamps are equal;
deterministic signatures can make those compact tokens identical. C23 adds a
required, fresh, cryptographically random `jti` to each event token and requires
AP and agent verifiers to reject a missing or empty value. This is a deliberate
wire extension that makes C14's compact-token hash safe as an idempotency key
and follows the core builders' fresh-token-ID convention
([ResourceTokenBuilder.cs](../../../src/AAuth/Tokens/ResourceTokenBuilder.cs#L102-L122)).

The event token is the `Signature-Key` JWT on a POST to the current AP
`event_endpoint`. The same resource key identified by `kid` verifies the JWT
and HTTP signature. A payload is the direct, optional AsyncAPI-defined request
body
([Event Delivery](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-delivery),
L376-L400).

The AP validation order is:

1. parse the event JWT and validate `typ`;
2. resolve the resource key and verify the JWT;
3. verify the HTTP signature with that same key;
4. find an active `eid`;
5. bind resource `iss` to the resource authorized by the subscribe token;
6. validate event expiry;
7. enforce and atomically increment `max_uses`;
8. bind event `aud` to the stored agent.

Only after a durable inbox write may the AP return `202`. A limited subscription
returns `remaining_uses`; exhausted subscriptions return `429` on later
deliveries
([AP Validation](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-delivery),
L402-L428).

### Agent verification

The agent verifies event `typ`, resource JWKS signature, its own `aud`, `exp`,
and local `eid` context, then applies deduplication. Payload interpretation is
defined by the resource's AsyncAPI schema, not by the event JWT
([Agent Verification](../../../aauth-spec/v09/draft-hardt-aauth-events.md#ap-to-agent),
L436-L447).

That verification authenticates the event envelope, not the payload. The event
token contains no event data
([L361](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L361)), and the
resource-to-AP `Content-Digest`
([L387](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L387)) is consumed
at the AP rather than conveyed in an agent-verifiable artifact. An AP can
therefore replace or inject a payload without invalidating the event token,
despite the draft saying the agent may use the payload directly
([L447](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L447)). Agent APIs
must label the payload unauthenticated; consequential or sensitive details
should be fetched from the resource API with a current auth token, consistent
with [Event Content](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-content)
L614-L616.

### Discovery

The R3 vocabulary identifier is `urn:aauth:vocabulary:asyncapi`; supporting
resources should publish it in `r3_vocabularies`. AsyncAPI documents describe
channels, receive operations, direct payload schemas, and the
`aauth_subscribe` security scheme. Public operations declare the scheme;
protected ticket operations omit it and explain the prior authenticated call
([Event Discovery](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-discovery),
L449-L505).

The package only needs constants, metadata composition, and validation of these
AAuth declarations. Applications remain responsible for full AsyncAPI document
generation and payload schema validation.

The examples use `action: receive`
([L537](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L537),
[L544](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L544)). AsyncAPI 3.0
defines `action` from the perspective of the application described by the
document, so a resource-owned producer document would ordinarily use `send`.
The draft instead frames the document for the agent reader
([L721](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L721)), making its
intended application perspective ambiguous. The SDK follows the draft examples
but does not treat operation direction as an AAuth validity rule.

### Security and privacy invariants

- A subscribe token is bound to one resource by `aud`; AP delivery rechecks the
  recorded resource
  ([Subscribe Token Scope](../../../aauth-spec/v09/draft-hardt-aauth-events.md#subscribe-token-scope),
  L574-L579).
- Protected tickets are short-lived, single-use, and agent-bound
  ([Pre-Authorized Subscription URL Security](../../../aauth-spec/v09/draft-hardt-aauth-events.md#pre-authorized-subscription-url-security),
  L592-L599).
- The AP sees event tokens and payloads and should document retention
  ([AP as Delivery Intermediary](../../../aauth-spec/v09/draft-hardt-aauth-events.md#ap-as-delivery-intermediary),
  L600-L603).
- Stable agent identifiers are visible to resources, and payloads should exclude
  unnecessary sensitive data
  ([Privacy Considerations](../../../aauth-spec/v09/draft-hardt-aauth-events.md#privacy-considerations),
  L608-L617).
- Body-bearing event deliveries bind the raw payload through
  `Content-Digest`; the AP stores and forwards the verified raw bytes, avoiding a
  parse/reserialize gap on the resource-to-AP hop. This does not provide
  end-to-end payload authentication to the agent.
- Issuer metadata, JWKS, and delivery destinations are outbound trust inputs.
  The selected policy is HTTPS except loopback HTTP, no redirects, private or
  link-local IP-literal rejection except loopback, and an application trust
  callback.

## Repository findings

### `AAuth.R3` precedent

`AAuth.R3` is a packable preview project that references `AAuth`, includes its
own README and ASP.NET framework reference, and tracks the core version
([AAuth.R3.csproj](../../../src/AAuth.R3/AAuth.R3.csproj#L8-L30)). It centralizes
wire names and exposes typed helpers such as `R3AuthClaims`; consumers pass the
result through generic core seams rather than teaching core about R3
([R3AuthClaims.cs](../../../src/AAuth.R3/R3AuthClaims.cs#L7-L44),
[R3AccessTokenEndpoint.cs](../../../src/AAuth.R3/R3AccessTokenEndpoint.cs#L48-L59)).

R3 also uses JSON composition for optional metadata
([R3Metadata.cs](../../../src/AAuth.R3/R3Metadata.cs#L7-L31)). Its project and
test project are explicit solution members, and the shared release workflow
packs it with the same version as core
([AAuth.slnx](../../../AAuth.slnx#L24-L31),
[publish.yml](../../../.github/workflows/publish.yml#L35-L41)).

`R3Metadata.AddVocabularies` creates and assigns the complete
`r3_vocabularies` object rather than merging a nested entry
([R3Metadata.cs](../../../src/AAuth.R3/R3Metadata.cs#L11-L29)). Bookings
currently assigns one OpenAPI-only object through `AdditionalMetadata`
([Program.cs](../../../samples/MockResourceServers/Bookings/Program.cs#L50-L55)).
When Events is added, both package contributions must be collected in one
caller-owned vocabulary map before that map is assigned to metadata. The Events
helper operates on that map rather than an already serialized top-level
property; `R3Metadata` or core `AdditionalMetadata` performs the single final
assignment. This avoids order-dependent overwrites while preserving package
independence. The helper is idempotent for the same AsyncAPI mapping and rejects
malformed or conflicting mappings.

The Events package should copy these boundary and release patterns, not R3's
protocol-specific models.

### Reusable public core surface

| Need | Existing public surface | Finding |
|---|---|---|
| Token crypto | `IAAuthKey`, `AAuthKey`, `EcdsaAAuthKey`, `KeyFactory` | Sufficient for EdDSA and ES256 signing and verification |
| Generic JWT validation | `TokenVerifier.Verify` and `VerifyWithJwksAsync` | Accept caller-supplied `typ`, `dwk`, audience, clocks, and keys ([TokenVerifier.cs](../../../src/AAuth/Tokens/TokenVerifier.cs#L49-L151), [TokenVerifier.cs](../../../src/AAuth/Tokens/TokenVerifier.cs#L387-L475)) |
| Outbound HTTP signatures | `AAuthSigningHandler`, `JwtSignatureKeyProvider` | Supports per-request `content-type` and `content-digest`; computes SHA-256 digest when requested ([AAuthSigningHandler.cs](../../../src/AAuth/HttpSig/AAuthSigningHandler.cs#L43-L52), [AAuthSigningHandler.cs](../../../src/AAuth/HttpSig/AAuthSigningHandler.cs#L114-L165)) |
| Header parsing | `SignatureKeyHeader.GetJwt` | Can extract a compact JWT without requiring `cnf` ([SignatureKeyHeader.cs](../../../src/AAuth/HttpSig/SignatureKeyHeader.cs#L90-L104)) |
| Metadata and JWKS | `MetadataClient`, `JwksClient` | Cached metadata with issuer binding and rate-limited JWKS refresh ([MetadataClient.cs](../../../src/AAuth/Discovery/MetadataClient.cs#L23-L104), [JwksClient.cs](../../../src/AAuth/Discovery/JwksClient.cs#L23-L109)) |
| ASP.NET/test stack | `Microsoft.AspNetCore.App`, TestHost, shared xUnit props | Matches the R3 package and test project ([tests/Directory.Build.props](../../../tests/Directory.Build.props#L10-L25), [AAuth.R3.Tests.csproj](../../../tests/AAuth.R3.Tests/AAuth.R3.Tests.csproj#L5-L11)) |

### Events-owned gaps

| Gap | Evidence | No-core resolution |
|---|---|---|
| Core JWT `Signature-Key` parsing requires `cnf.jwk`; event tokens intentionally omit it. It also parses `cnf.jwk` with Ed25519-only `AAuthKey.FromJwk`, so it cannot handle an ES256 subscribe-token confirmation key | [SignatureKeyParser.cs](../../../src/AAuth/HttpSig/SignatureKeyParser.cs#L104-L127); Events [L394-L398](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L394-L398) | Extract with `SignatureKeyHeader.GetJwt`, parse confirmation keys with `KeyFactory`, perform cheap structural checks, resolve the issuer key, then use `TokenVerifier` |
| Core inbound verifier rejects `content-type` and `content-digest` extension components | [AAuthVerifier.cs](../../../src/AAuth/HttpSig/AAuthVerifier.cs#L20-L23), [AAuthVerifier.cs](../../../src/AAuth/HttpSig/AAuthVerifier.cs#L93-L113) | Package-owned Events HTTP-message verifier with an exact allowlist and raw-body digest verification |
| Core agent metadata options have no extension bag and its JSON builder is private | [AAuthAgentMetadataOptions.cs](../../../src/AAuth/Server/Metadata/AAuthAgentMetadataOptions.cs), [WellKnownEndpoints.cs](../../../src/AAuth/Server/Metadata/WellKnownEndpoints.cs#L208-L225) | Metadata composer that adds `event_endpoint`; samples already own AP metadata/JWKS JSON ([MockAgentProvider/Program.cs](../../../samples/MockAgentProvider/Program.cs#L32-L58)) |
| Core discovery client permits default redirects and has no Events trust callback | [AAuthDiscoveryServiceCollectionExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthDiscoveryServiceCollectionExtensions.cs#L38-L41) | Events-owned hardened HTTP handlers and pluggable URL policy for Events-initiated network calls |
| Core compact JWT writer is internal | `src/AAuth/Tokens/JwtWriter.cs` | One internal shared writer inside `AAuth.Events`; no public core API expansion |

### Core change assessment

No core SDK change is required.

Two generic core changes would be convenient but fail the user's
"absolutely necessary" threshold:

| Candidate core change | Files affected | Why it is not planned |
|---|---|---|
| Add `AdditionalMetadata` to agent metadata | `src/AAuth/Server/Metadata/AAuthAgentMetadataOptions.cs`, `src/AAuth/Server/Metadata/WellKnownEndpoints.cs`, discovery tests | A package metadata composer and the existing hand-built MockAgentProvider document can emit `event_endpoint`; convenience does not justify a core edit |
| Generalize JWT parsing and HTTP verification for no-`cnf` tokens and arbitrary covered fields | `src/AAuth/HttpSig/SignatureKeyParser.cs`, `src/AAuth/HttpSig/AAuthVerifier.cs`, middleware and conformance tests | This would widen the core security surface. An Events-specific verifier can enforce the narrower draft exactly without changing existing behavior |

`AAuth.R3` also remains unchanged. `AAuth.Events` owns the AsyncAPI vocabulary
constant and only the Bookings sample references both optional packages.

## Selected package boundary

The selected dependency graph is:

```text
AAuth.Events -> AAuth
AAuth.R3     -> AAuth
Bookings     -> AAuth + AAuth.R3 + AAuth.Events
```

The package surface divides into:

- token builders/readers and typed verified claims;
- Events-specific HTTP signing requirements and inbound verification;
- AP subscription issuance, durable inbox contracts, and event endpoint;
- resource registration validation/mapping and event delivery;
- agent verification and pluggable deduplication;
- event endpoint and AsyncAPI metadata/discovery helpers;
- one-call DI registration for AP, resource, and agent roles.

The AP store contract must make subscription creation collision-safe and event
acceptance atomic: active-subscription lookup, resource and agent binding,
expiry, required event `jti`, event-token hash idempotency, `max_uses`, use-count
update, and durable inbox write are one operation. No in-memory implementation
is registered by the package; test and sample implementations are explicitly
non-production.

## Clarification record

Every implementation-shaping clarification asked during research is captured
below, normalized to ASCII for this repository.

| ID | Question | Response |
|---|---|---|
| C1 | Which roles should the first `AAuth.Events` package plan cover? | All protocol-defined roles (Recommended): AP token issuance/event inbox, resource registration/event delivery, and agent verification; exclude only the spec-defined AP<->agent transport |
| C2 | Should `AAuth.Events` depend directly on the experimental `AAuth.R3` package for AsyncAPI discovery integration? | No (Recommended): depend only on `AAuth`; keep the AsyncAPI vocabulary constant/helper in `AAuth.Events`, with optional sample integration |
| C3 | The draft uses `eid` as a subscription ID and permits unlimited multi-event subscriptions, but Agent Verification says to deduplicate every event by `{iss, eid}`, which would discard all events after the first. How should the plan handle this contradiction? | Expose pluggable deduplication and default to exact event-token hash (Recommended); log the deliberate deviation pending a spec correction |
| C4 | The draft's HTTP example sends the AsyncAPI payload as the direct `application/json` body, while the discovery text calls it a `payload` field and the AsyncAPI example says `contentType: application/jwt`. Which wire shape should the plan target? | Direct AsyncAPI-defined JSON body with `application/json` (Recommended), matching the delivery example |
| C5 | The draft shows extra signed components only in examples, without normative prose. Should the plan require `content-type` for JSON subscription bodies and both `content-type` plus `content-digest` for event payload bodies? | Yes (Recommended): enforce the shown components when a body is present; use base components only when absent |
| C6 | For the AP's durability MUST, should the package require an application-supplied durable inbox implementation rather than register an in-memory production default? | Require a durable store interface; keep in-memory implementations test/sample-only (Recommended) |
| C7 | Which sample topology should the implementation plan use for the end-to-end flow? | Extend existing Bookings + MockAgentProvider and add an event-focused agent flow (Recommended), matching the draft's waitlist example |
| C8 | The draft references subscription expiry but defines no lifetime negotiation field. Should the package model lifetime as application policy recorded at registration, without adding a non-standard wire claim or body field? | Yes (Recommended): application policy supplies `ExpiresAt`; no new wire field |
| C9 | Should the preview `AAuth.Events` package track the core `AAuth` version and be packed by the same release workflow, as `AAuth.R3` does? | Yes (Recommended): same version and release workflow |
| C10 | For the event-focused agent flow, should the plan add a small dedicated console sample or extend the existing GuidedTour? | Add `samples/EventAgent` (Recommended): focused subscribe/receive/verify flow without widening GuidedTour |
| C11 | For resource registration, should the package include an opinionated ASP.NET endpoint mapper in addition to low-level verification primitives, despite the draft not defining registration error bodies/statuses? | Provide both (Recommended): typed verifier plus mapper with documented defaults and an application callback for channel/ticket policy |
| C12 | Which default registration response mapping should the plan record for the mapper where the draft is silent? | 200 success; 400 malformed; 401 signature/JWT failure; 403 audience or agent-ticket mismatch; 404 unknown/expired ticket; 409 duplicate `eid` or reused ticket (Recommended) |
| C13 | For AP delivery failures the draft omits mappings for an expired event token and a wrong event-token `aud`. Which defaults should the plan use? | 401 for expired/invalid event token; 403 for wrong `aud` (Recommended) |
| C14 | How should the AP handle a retry carrying an already durably recorded event token, given the draft has no per-event `jti`? | Treat the compact event-token hash as idempotency key; return 202 without another inbox record or use-count increment (Recommended) |
| C15 | What outbound URL policy should the plan require for issuer metadata, JWKS, and `event_endpoint` fetch/delivery targets? | HTTPS except loopback HTTP, no automatic redirects, reject private/link-local IP literals except loopback, plus a pluggable trust policy (Recommended) |
| C16 | What `eid` generation rule should the plan use where the draft says only "opaque" and "unique to the AP"? | At least 128 bits from a cryptographic RNG, base64url, never reused by the AP (Recommended) |
| C17 | Should the Events endpoint helpers impose a configurable payload-size limit before buffering the body for `Content-Digest` verification? | Yes; default 1 MiB and allow applications to lower/raise it (Recommended) |
| C18 | How much AsyncAPI support should the first package include? | Integration helpers only (Recommended): vocabulary/security constants, metadata composition, and validation of required AAuth declarations; applications own AsyncAPI documents/schemas |
| C19 | Which explicitly non-normative AP<->agent mechanism should the samples use to complete the runnable flow? | Authenticated polling for pending events (Recommended), matching the workload-agent example |
| C20 | The event token lists `iat` as required, but AP/agent validation steps omit an `iat` check. Should the package require it and reject future-issued event tokens using configured clock skew? | Yes (Recommended), consistent with subscribe-token and core JWT validation |
| C21 | Should AAuth Events accept both signing algorithms already supported by core (`EdDSA` and `ES256`), while emitting whichever algorithm the supplied `IAAuthKey` uses? | Yes (Recommended); reject `none` and all unsupported algorithms |
| C22 | May an AP's `event_endpoint` be on a different HTTPS origin from its `iss`, as the draft does not require same-origin? | Yes (Recommended): allow cross-origin after the configured URL trust policy accepts it |
| C23 | A consistency pass found one unresolved C14 edge case: event tokens have no `jti`, and `iat`/`exp` use whole seconds, so two legitimate EdDSA events for the same subscription in one second can produce the same compact token and be mistaken for a retry. Which ruling should the plan record? | Add a random `jti` to each event token (Recommended; deliberate draft extension) |

No clarification questions were required for RF1-RF5. C23 was asked during the
post-edit consistency pass and its response is recorded verbatim above.

## Reviewer-comment resolutions

| ID | Finding | Decision |
|---|---|---|
| RF1 | Event-token header omits the subscribe-token `none` prohibition | **Fix:** record the draft asymmetry; C21 still rejects `none` for every Events token |
| RF2 | Event payload lacks end-to-end integrity at the agent | **Fix:** expose it only as an unauthenticated payload and direct consequential actions to a resource-API re-fetch; do not invent a signed payload wire format |
| RF3 | Registration JSON is not covered by `Content-Digest` | **Push back on changing the wire profile:** retain C5 and the draft example for interoperability, label the body signature-unbound, and make non-reliance for authorization an explicit application contract rather than claim cryptographic enforcement |
| RF4 | AsyncAPI examples use `receive` where a resource-owned producer document would use `send` | **Push back on validator enforcement:** follow the draft examples because its agent-reader perspective is ambiguous; record the issue and leave operation direction outside AAuth declaration validation |
| RF5 | `AAuth.R3` and `AAuth.Events` can overwrite each other's `r3_vocabularies` contribution | **Fix:** compose one caller-owned map before a single metadata assignment, preserve existing entries, reject conflicts, and add a cross-package test |

## Specification issues to retain in the implementation log

The owner rulings remove implementation blockers but do not erase upstream draft
issues:

| Issue | Draft evidence | Local ruling |
|---|---|---|
| `eid` is a subscription identifier but agent deduplication treats it as an event identifier | Unlimited subscriptions at [L229](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L229); dedup at [L445](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L445) | C3 and C14: SHA-256 of the compact event token is the event idempotency key |
| Payload wording and media type conflict | Direct body at [L380](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L380); AsyncAPI `application/jwt` at [L551](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L551) | C4: direct `application/json` body |
| Extra covered components appear in examples, not normative prose | Registration example [L251-L266](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L251-L266); delivery example [L382-L399](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L382-L399) | C5: require the shown fields when a body exists |
| Subscription lifetime is described but has no negotiation field | [Design rationale](../../../aauth-spec/v09/draft-hardt-aauth-events.md#design-rationale) L681-L687 | C8: application policy records `ExpiresAt`; no wire extension |
| Registration statuses and two AP failure mappings are unspecified | Overview `200` at [L163](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L163); AP status list at [L428](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L428) | C12 and C13 |
| Required event `iat` is omitted from AP and agent validation lists | Claim at [L358](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L358); validation at [L402-L413](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L402-L413) and [L438-L445](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L438-L445) | C20: require and validate with clock skew |
| AP validation increments `max_uses` at step 7 before step 8 checks agent `aud` | [L412-L413](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L412-L413) | The durable store commits no use increment or inbox write unless all eight checks pass |
| The resource's stated minimum record `{eid, iss}` omits the agent identifier needed as event-token `aud` | Registration state at [L279](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L279); event `aud` at [L352](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L352) | Persist subscribe-token `sub` in resource subscription state; no wire change |
| Event-token `alg` omits the subscribe-token prohibition on `none` | Subscribe header at [L212](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L212); event header at [L348](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L348) | RF1/C21: reject `none` for both token types |
| The event payload is authenticated to the AP but not end to end to the agent | Token excludes event data at [L361](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L361); AP-hop digest at [L387](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L387); direct agent use at [L447](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L447) | RF2: surface an unauthenticated payload and re-fetch consequential data from the resource |
| Registration JSON is not bound by `Content-Digest` | Registration profile at [L251-L266](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L251-L266); delivery profile at [L382-L399](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L382-L399) | RF3/C5: retain the draft profile, label the body signature-unbound, and document that applications must not rely on it to grant or widen authorization |
| AsyncAPI operation perspective is ambiguous | Draft `receive` examples at [L537](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L537) and [L544](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L544); agent-reader rationale at [L721](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L721) | RF4: follow the draft examples; do not validate `send` versus `receive` |
| Event tokens have no per-event identity, so exact-token retry detection can collide with a legitimate event | Event claims omit `jti` at [L351-L359](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L351-L359); AP validation has no idempotency step at [L406-L413](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L406-L413) | C23: require a fresh random `jti`; retain C14's compact-token hash as the AP and agent idempotency key |

These rulings must be copied into `implementation-log.md` as Phase 0
`RESOLVED` decisions before implementation begins.
