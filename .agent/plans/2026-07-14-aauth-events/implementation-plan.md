# AAuth Events - Implementation Plan

Phased plan for a complementary `AAuth.Events` preview package implementing
[AAuth Events](../../../aauth-spec/v09/draft-hardt-aauth-events.md).

- Research: [research.md](research.md)
- Created: 2026-07-14
- Updated: 2026-07-15 (review comments addressed)
- Package: `src/AAuth.Events/`
- Review gate: no implementation or commit until the repository owner approves
  this plan

## Guiding principles

- **Spec conformance is paramount; backwards compatibility is not a goal.**
  This is a spec-accurate alpha SDK. Use one wire format, do not add legacy
  shims, and record every deliberate draft interpretation in
  `implementation-log.md`.
- **Keep Events outside core.** `AAuth.Events` depends only on `AAuth`.
  `src/AAuth/` and `src/AAuth.R3/` are not modified.
- **Reuse public primitives, own Events semantics.** Reuse core keys, JWT
  validation, discovery caches, headers, and outbound signer. Keep the
  no-`cnf` event-token path, body-bound verifier, stores, and endpoints in the
  Events package.
- **Spec owns the wire; applications own policy.** Ticket formats, channel
  parameters, subscription lifetime, payload schemas, retention, and durable
  storage remain explicit application seams.
- **Durability and atomicity are API contracts.** The AP cannot return `202`
  until one store operation has enforced subscription state and durably
  recorded the event
  ([Event Delivery](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-delivery),
  L402-L428).
- **Security invariants are test targets.** Key binding, covered components,
  raw-body digest, audience/resource binding, expiry, replay, `max_uses`,
  ticket consumption, URL policy, and concurrency each get negative tests.
- **A verified event envelope does not authenticate its payload to the agent.**
  Agent-facing APIs label payload bytes unauthenticated and direct consequential
  actions to re-fetch details from the verified resource.

## Cross-cutting decisions

| ID | Decision |
|---|---|
| D1 | Ship `AAuth.Events` as a preview NuGet package covering AP, resource, and agent roles; exclude standardized AP-to-agent transport |
| D2 | The production `AAuth.Events` project depends only on `AAuth`; do not modify `AAuth.R3`; track the `AAuth` package version and release. A test-only R3 reference is allowed for RF5 |
| D3 | Use SHA-256 of the compact event token as the default event idempotency key; expose a pluggable deduplicator (C3/C14) |
| D4 | Send the AsyncAPI-defined payload directly as `application/json`; preserve raw bytes, but expose them to agents only as `UnauthenticatedEventPayload` because the event token does not bind them (RF2) |
| D5 | Follow the draft's exact body profiles: registration signs `content-type` but not `content-digest`; event delivery signs both. Registration parameters are signature-unbound, and application contracts must not use them to grant or widen authorization (C5/RF3) |
| D6 | Require an application-provided durable AP store; in-memory stores exist only in tests/samples |
| D7 | Subscription lifetime is application policy recorded as `ExpiresAt`; add no wire claim |
| D8 | Generate never-reused `eid` values from at least 128 cryptographically random bits, base64url encoded |
| D9 | Registration mapper defaults: 200/400/401/403/404/409 as recorded in research C12 |
| D10 | AP delivery adds 401 for expired/invalid event JWT and 403 for wrong `aud`; exact event-token retries return idempotent 202 without another write/use |
| D11 | Outbound Events URLs use HTTPS except loopback HTTP, disable redirects, reject private/link-local IP literals except loopback, and pass a pluggable trust policy; cross-origin `event_endpoint` is allowed after policy approval |
| D12 | Buffer at most 1 MiB by default for digest verification; make the limit configurable |
| D13 | Support core algorithms EdDSA and ES256; reject `none` and unsupported algorithms for both token types per RF1; require and validate `iat` with clock skew |
| D14 | AsyncAPI support is limited to AAuth constants, metadata composition, and declaration validation; follow the draft's `action: receive` examples but do not validate operation direction (RF4) |
| D15 | Samples extend Bookings and MockAgentProvider, add `samples/EventAgent`, and use agent-authenticated non-normative polling |
| D16 | Compose OpenAPI and AsyncAPI in one caller-owned vocabulary map before a single `r3_vocabularies` assignment; preserve entries and reject malformed/conflicting mappings without a production `AAuth.R3` dependency (RF5) |
| D17 | Require a fresh random `jti` in every event token so compact-token hashing distinguishes legitimate same-time events from exact retries; reject missing/empty `jti` (C23, deliberate draft extension) |

Full questions and owner responses are retained in
[research.md](research.md#clarification-record). Reviewer follow-up decisions
RF1-RF5 are retained in
[Reviewer-comment resolutions](research.md#reviewer-comment-resolutions).

## Core SDK change assessment

No core change is planned or required.

| Core file(s) considered | Potential change | Decision |
|---|---|---|
| `src/AAuth/Server/Metadata/AAuthAgentMetadataOptions.cs`, `src/AAuth/Server/Metadata/WellKnownEndpoints.cs` | Generic agent `AdditionalMetadata` seam | Rejected as convenient, not necessary; Events composes metadata and MockAgentProvider already owns its document |
| `src/AAuth/HttpSig/SignatureKeyParser.cs`, `src/AAuth/HttpSig/AAuthVerifier.cs` | General no-`cnf` JWT parsing and arbitrary covered-field verification | Rejected because it broadens core security behavior; Events uses a package-local exact verifier |
| `src/AAuth/Tokens/JwtWriter.cs` | Make compact signing public | Rejected; keep one internal writer in `AAuth.Events` |

If implementation discovers a genuine blocker, work stops before touching core.
The proposed change must be added here with exact files, affected APIs, rejected
package-only alternatives, and a correctness argument for owner approval.

## Phase 0 - Decision and deviation gate

Create the append-only implementation record before code. Seed it with C1-C23
and RF1-RF5 from research, including every draft discrepancy in
[Specification issues](research.md#specification-issues-to-retain-in-the-implementation-log).
The local rulings are explicit draft interpretations, not silent compatibility
behavior.

### Implementation decisions

- Package and namespace: `AAuth.Events`.
- No core or `AAuth.R3` changes.
- No commit until owner approval of this plan.

### Definition of Done

- [x] `implementation-log.md` exists with every C1-C23 and RF1-RF5 ruling
      recorded as `[YYYY-MM-DD] [Phase 0] ... - RESOLVED`.
- [x] Every draft discrepancy identifies the selected behavior and the
      spec lines it interprets.
- [x] Package public API names and role boundaries are confirmed without adding
      Events behavior to core or a production `AAuth.R3` dependency.
- [x] The owner has approved implementation to begin.

## Phase 1 - Package foundation and token primitives

**Goal:** establish the optional package and byte-accurate subscribe/event token
surface before adding network or server behavior.

**Spec:** [Subscribe Token](../../../aauth-spec/v09/draft-hardt-aauth-events.md#subscribe-token)
L204-L244;
[Event Token](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-token)
L340-L374.

### Files

| File | Action and responsibility |
|---|---|
| `src/AAuth.Events/AAuth.Events.csproj` | New packable `net10.0` preview project; project-reference `AAuth`; ASP.NET framework reference; package README; same version/repository metadata as `AAuth.R3` |
| `src/AAuth.Events/README.md` | New package status, role matrix, storage requirements, and preview warnings |
| `src/AAuth.Events/AAuthEventsConstants.cs` | New token types, claim names, DWK names, header components, AsyncAPI vocabulary, and security-scheme constants |
| `src/AAuth.Events/Internal/EventsJwtWriter.cs` | New shared compact-JWS writer using `IAAuthKey`; no duplicated token signing |
| `src/AAuth.Events/Tokens/SubscribeTokenBuilder.cs` | New required AP/resource/agent/key/time inputs; optional positive `max_uses`; secure `eid` generation |
| `src/AAuth.Events/Tokens/EventTokenBuilder.cs` | New required resource/agent/`eid`/key/time inputs and a fresh random `jti` per build |
| `src/AAuth.Events/Tokens/SubscribeTokenClaims.cs` | New typed verified subscribe-token projection |
| `src/AAuth.Events/Tokens/EventTokenClaims.cs` | New typed verified event-token projection including required `jti` |
| `tests/AAuth.Events.Tests/AAuth.Events.Tests.csproj` | New optional-package test project using shared xUnit props and TestHost |
| `tests/AAuth.Events.Tests/Tokens/*Tests.cs` | New token structure, validation, algorithm, time, claim, and tamper tests |
| `AAuth.slnx` | Add package and package-test projects |

### Implementation decisions

- Builders accept `IAAuthKey`, emit its `Algorithm`, and require a private key.
- `exp > iat`; `max_uses > 0`; `eid`, `iss`, `sub`, and `aud` are non-empty
  and typed where core types exist.
- Event `jti` uses at least 128 cryptographically random bits, base64url
  encoded. AP and agent readers require a non-empty value.
- Token readers require every draft-required claim; they do not silently
  default missing values.
- Core `TokenVerifier.Verify` checks `iat` only when present. The typed
  subscribe/event claim readers must therefore require `iat` explicitly before
  returning a verified projection.

### Definition of Done

- [ ] Subscribe tokens contain exactly the required header/payload claims and
      optional `max_uses`.
- [ ] Event tokens contain no `cnf` and no event payload, but include the
      required local `jti` extension.
- [ ] EdDSA and ES256 round-trip through the builders and `TokenVerifier`;
      both subscribe and event token readers reject `none`, unsupported
      algorithms, missing `kid`, missing claims, invalid times, empty `eid`,
      missing/empty event `jti`, and non-positive `max_uses`.
- [ ] Two event tokens built with the same resource, agent, `eid`, `iat`, and
      `exp` still have different `jti` values and compact serializations.
- [ ] Generated `eid` values are base64url, at least 128 random bits, and
      collision handling never returns a reused ID.
- [ ] The production package references `AAuth` only; `AAuth.R3` is absent from
      `src/AAuth.Events/obj/project.assets.json`.
- [ ] `dotnet test tests/AAuth.Events.Tests/AAuth.Events.Tests.csproj` passes
      for token tests.

## Phase 2 - Events HTTP signing and verification

**Goal:** implement the draft's two signed POST profiles without widening the
core verifier.

**Spec:** subscribe presentation and verification
([Subscribe Token](../../../aauth-spec/v09/draft-hardt-aauth-events.md#subscribe-token),
L247-L280); event delivery and `dwk`-without-`cnf`
([Event Delivery](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-delivery),
L376-L413).

### Files

| File | Action and responsibility |
|---|---|
| `src/AAuth.Events/Http/EventsHttpMessageVerifier.cs` | New RFC 9421 verifier restricted to the base fields plus the D5 Events profiles; freshness and exact field-order checks |
| `src/AAuth.Events/Http/EventsRequestBody.cs` | New bounded raw-body reader and RFC 9530 SHA-256 `Content-Digest` parser/verifier |
| `src/AAuth.Events/Http/EventsJwtKeyResolver.cs` | New AP/resource metadata + `kid` resolver for subscribe and no-`cnf` event JWTs; returns the same key for JWT and HTTP verification |
| `src/AAuth.Events/Http/EventsRequestSigner.cs` | New thin adapter over `AAuthSigningHandler.AdditionalComponentsKey` for registration and event profiles |
| `src/AAuth.Events/Http/EventsVerificationError.cs` | New typed failure categories used by both endpoint mappers |
| `src/AAuth.Events/Discovery/IEventsUrlPolicy.cs` | New pluggable outbound trust decision used before metadata, JWKS, or delivery network access |
| `src/AAuth.Events/Discovery/DefaultEventsUrlPolicy.cs` | New D11 scheme/IP/cross-origin rules |
| `src/AAuth.Events/Discovery/EventsHttpClientFactory.cs` | New no-redirect handler used by Events metadata, JWKS, and delivery calls |
| `tests/AAuth.Events.Tests/Http/*Tests.cs` | New covered-field, raw-body, digest, timestamp, key-binding, malformed-header, and algorithm tests |

### Implementation decisions

- Do not call `SignatureKeyParser.ParseAny` for event JWTs because core requires
  `cnf.jwk`; extract with public `SignatureKeyHeader.GetJwt`. Parse subscribe
  `cnf.jwk` through `KeyFactory` so EdDSA and ES256 are both supported.
- Verify cheap syntax/type/DWK/URL policy before network fetch, then JWT
  signature, then HTTP signature and body digest.
- `EventsJwtKeyResolver` receives the Events URL policy and hardened no-redirect
  client through constructor injection; it never falls back to core's default
  discovery transport.
- After core JWT verification, typed claim readers explicitly reject missing
  `iat` before returning success.
- The verifier accepts no arbitrary extension components.

### Definition of Done

- [ ] Bodyless requests verify only the four base components.
- [ ] Registration JSON requires signed `content-type` and deliberately does
      not claim signature-bound body integrity; `content-digest` is absent from
      this exact draft profile.
- [ ] Event JSON requires signed `content-type` and `content-digest`; digest is
      compared with the exact bounded bytes later passed to storage.
- [ ] Missing, reordered, duplicated, or unexpected covered components fail.
- [ ] Event JWT and HTTP signature must verify with the same resource `kid`.
- [ ] Wrong `cnf.jwk` binding fails registration.
- [ ] Requests over the configured body limit fail before durable storage or
      application callbacks.
- [ ] Redirects, disallowed schemes, non-loopback private/link-local IP
      literals, cross-origin policy rejection, and loopback exceptions are
      covered before a discovery request is sent.
- [ ] Verification tests include tampered event body/header/path/authority/token,
      stale/future signature time, unknown `kid`, silent key rotation, and
      algorithm mismatch.

## Phase 3 - Metadata, discovery, AsyncAPI, and URL policy

**Goal:** provide Events discovery without an `AAuth.R3` dependency, using the
hardened outbound transport established in Phase 2.

**Spec:** AP metadata
([AP Metadata](../../../aauth-spec/v09/draft-hardt-aauth-events.md#ap-metadata),
L190-L202); AsyncAPI vocabulary and security declarations
([Event Discovery](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-discovery),
L449-L505).

### Files

| File | Action and responsibility |
|---|---|
| `src/AAuth.Events/Discovery/AAuthEventsMetadata.cs` | New `event_endpoint`, `WithAsyncApiVocabulary`, and vocabulary-value helpers; compose a caller-owned map before one metadata assignment |
| `src/AAuth.Events/Discovery/EventEndpointResolver.cs` | New cached AP metadata resolver that reads the current `event_endpoint` at delivery time |
| `src/AAuth.Events/Discovery/AsyncApiAAuthValidator.cs` | New validation for AsyncAPI 3.0, `aauth_subscribe`, public-operation security, and protected-channel annotation |
| `tests/AAuth.Events.Tests/AAuth.Events.Tests.csproj` | Add an `AAuth.R3` project reference for cross-package tests only; the production `AAuth.Events` project remains independent |
| `tests/AAuth.Events.Tests/Discovery/*Tests.cs` | New metadata, cross-package composition, cache/update, endpoint-policy integration, and AsyncAPI tests |

### Implementation decisions

- `event_endpoint` must be absolute HTTPS except loopback HTTP.
- Cross-origin endpoints are allowed only after URL-policy approval.
- AsyncAPI helpers validate AAuth declarations, not arbitrary AsyncAPI schemas.
- `WithAsyncApiVocabulary` returns a validated map that preserves every existing
  entry, is idempotent for the same endpoint, and throws for malformed values
  or a conflicting AsyncAPI endpoint. A separate helper serializes that map as
  the one `r3_vocabularies` value.
- Operation `action` is not an AAuth validity criterion. Samples use the draft's
  `receive`; the validator accepts either direction rather than asserting which
  application the document describes.

### Definition of Done

- [ ] AP metadata composition emits one valid `event_endpoint` without
      overriding typed base metadata.
- [ ] Resource metadata can advertise both existing OpenAPI and Events AsyncAPI
      vocabulary entries in one `r3_vocabularies` object.
- [ ] A cross-package test starts with a caller-owned OpenAPI map, applies the
      Events helper, passes the completed map once to
      `R3Metadata.AddVocabularies`, and proves both entries survive; identical
      reapplication is stable and malformed/conflicting values fail.
- [ ] Tests and sample code never call a whole-object R3 composer after Events
      metadata has already been assigned; composition precedes serialization.
- [ ] Delivery resolves the endpoint from AP metadata at send time and honors
      the configured metadata cache; it never persists an endpoint copied from
      a subscribe token.
- [ ] Metadata and endpoint resolution use the Phase 2 hardened client and URL
      policy; no default-redirect path is reachable.
- [ ] Required AsyncAPI AAuth declarations are accepted; missing/wrong scheme
      and incorrectly secured public/protected operations are reported.
- [ ] AsyncAPI tests pin that operation direction is outside validator scope and
      that the draft's `action: receive` example is accepted.

## Phase 4 - Agent Provider issuance and durable event endpoint

**Goal:** issue subscribe tokens against AP subscription state and accept event
deliveries only through one atomic durable store operation.

**Spec:** AP setup and `max_uses`
([Subscribe Token](../../../aauth-spec/v09/draft-hardt-aauth-events.md#subscribe-token),
L218-L229); AP validation and responses
([Event Delivery](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-delivery),
L402-L428).

### Files

| File | Action and responsibility |
|---|---|
| `src/AAuth.Events/AgentProvider/IAAuthAgentProviderEventStore.cs` | New durable contract for collision-safe subscription creation and atomic/idempotent event acceptance |
| `src/AAuth.Events/AgentProvider/AgentProviderSubscription.cs` | New stored `eid`, agent, resource, max-use, use-count, lifetime, and status model |
| `src/AAuth.Events/AgentProvider/IncomingEvent.cs` | New compact token, token hash, required `jti`, verified claims, raw payload, content type/digest, and receipt metadata |
| `src/AAuth.Events/AgentProvider/EventAcceptanceResult.cs` | New accepted/idempotent/unknown/expired/forbidden/exhausted outcomes and remaining uses |
| `src/AAuth.Events/AgentProvider/SubscribeTokenIssuer.cs` | New generate-sign-store service; returns a token only after subscription creation succeeds |
| `src/AAuth.Events/AgentProvider/EventEndpointExtensions.cs` | New `MapAAuthEventEndpoint` with ordered verification and exact response mapping |
| `src/AAuth.Events/DependencyInjection/AAuthEventsAgentProviderExtensions.cs` | New one-call AP registration; requires an application store |
| `tests/AAuth.Events.Tests/AgentProvider/*Tests.cs` | New issuance, endpoint, durability, response, replay, and concurrency tests |

### Implementation decisions

- The package throws during AP DI/startup when no durable store is registered.
- The store, not the endpoint, owns the transaction that checks state, writes
  the inbox event, and updates uses.
- Exact token-hash retries return the original successful outcome and
  `remaining_uses` without another write or increment.
- A missing/empty event `jti` fails before the store. A distinct token with a
  fresh `jti` is never collapsed into an earlier event merely because the other
  claims and timestamps match.

### Definition of Done

- [ ] Subscribe-token issuance stores the AP-side resource `aud`, agent `sub`,
      `eid`, optional `max_uses`, and application `ExpiresAt`.
- [ ] Unknown/expired subscription returns 404; resource mismatch and wrong
      agent `aud` return 403; invalid/expired JWT or signature returns 401;
      malformed input returns 400; exhausted uses return 429.
- [ ] `202` occurs only after the store reports durable acceptance.
- [ ] Limited subscriptions return exact `remaining_uses`; unlimited
      subscriptions accept either no response body or `{}` through the client.
- [ ] Concurrent final-use deliveries produce one durable event and one
      successful use; later distinct events return 429.
- [ ] A delivery rejected at step 8 for wrong agent `aud` returns 403 without
      incrementing the use count or writing an inbox event.
- [ ] Exact retries are idempotent under concurrency and do not consume uses.
- [ ] Two same-time events with identical non-`jti` claims are both durably
      accepted; retrying either exact compact token is idempotent.
- [ ] No package-provided in-memory AP store is registered.

## Phase 5 - Resource subscription registration

**Goal:** support public and protected registration with layered verifier and
endpoint APIs while leaving channel/ticket policy application-owned.

**Spec:** public and protected registration
([Subscription Registration](../../../aauth-spec/v09/draft-hardt-aauth-events.md#subscription-registration),
L285-L339); registration replay
([Security Considerations](../../../aauth-spec/v09/draft-hardt-aauth-events.md#subscribe-token-replay-at-registration),
L588-L599).

### Files

| File | Action and responsibility |
|---|---|
| `src/AAuth.Events/Resource/SubscriptionRegistrationVerifier.cs` | New low-level subscribe JWT + HTTP request verifier |
| `src/AAuth.Events/Resource/SignatureUnboundRegistrationBody.cs` | New bounded raw-body projection whose name and API documentation state that the registration signature does not cover its content |
| `src/AAuth.Events/Resource/VerifiedSubscriptionRegistration.cs` | New typed AP issuer, agent, resource, `eid`, max-use, key data, and optional `SignatureUnboundRegistrationBody` kept separate from verified authorization facts |
| `src/AAuth.Events/Resource/IAAuthSubscriptionRegistrationHandler.cs` | New application callback for public policy or atomic protected-ticket consume + subscription persistence; contract separates verified authorization facts from signature-unbound preferences |
| `src/AAuth.Events/Resource/SubscriptionRegistrationResult.cs` | New accepted/malformed/unauthorized/forbidden/not-found/conflict outcomes |
| `src/AAuth.Events/Resource/SubscriptionEndpointExtensions.cs` | New public/protected endpoint mapper with D9 defaults |
| `src/AAuth.Events/Agent/SubscriptionRegistrationClient.cs` | New signed POST client using subscribe token as the sole credential |
| `src/AAuth.Events/DependencyInjection/AAuthEventsResourceExtensions.cs` | New one-call resource registration |
| `tests/AAuth.Events.Tests/Resource/Subscription*Tests.cs` | New public/protected, binding, ticket, duplicate, body, and status tests |

### Implementation decisions

- The package does not define ticket syntax or a ticket response property.
- A protected handler receives the verified subscribe `sub` and ticket path
  value and must consume/register atomically; failed validation does not burn a
  ticket.
- Authorization and channel scope come only from the verified subscribe claims,
  endpoint, and protected-ticket state. The handler contract requires
  signature-unbound body parameters to be treated only as preferences within
  that boundary. Because channel schemas are application-defined, the package
  cannot cryptographically enforce an arbitrary callback's policy.
- Success defaults to 200 as shown in the overview
  ([L163](../../../aauth-spec/v09/draft-hardt-aauth-events.md#L163)).

### Definition of Done

- [ ] Public registration needs no credential beyond the subscribe token.
- [ ] Protected registration rejects expired, unknown, reused, wrong-context,
      and wrong-agent tickets.
- [ ] The subscribe token's `aud`, AP signature, times, `cnf`/HTTP key, and
      `eid` are enforced before the application handler.
- [ ] Duplicate `eid` registration returns 409.
- [ ] Application-supplied `ExpiresAt` is persisted without a new wire field.
- [ ] Optional direct JSON registration parameters are size-bounded, covered
      only by signed `content-type`, and exposed under the signature-unbound type.
- [ ] Package API documentation, endpoint integration tests, and Bookings prove
      the first-party path never uses altered body parameters to widen the event
      type, channel, agent, or resource authorization held by the ticket and
      verified subscribe token; low-level callback users receive the same warning.
- [ ] Default 200/400/401/403/404/409 mapping has integration tests; low-level
      verifier users receive typed failures without forced HTTP responses.

## Phase 6 - Resource event delivery

**Goal:** turn a stored resource subscription into a signed event delivery and
maintain resource-side remaining-use state.

**Spec:** event construction and request
([Event Token](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-token),
L340-L374;
[Event Delivery](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-delivery),
L376-L400); remaining-use handling L415-L426.

### Files

| File | Action and responsibility |
|---|---|
| `src/AAuth.Events/Resource/ResourceSubscription.cs` | New `eid`, AP issuer, agent, resource, lifetime, and remaining-use model |
| `src/AAuth.Events/Resource/PreparedEventDelivery.cs` | New immutable logical-delivery artifact containing the once-generated `jti`, compact token, raw body, and content metadata; exact retries reuse it |
| `src/AAuth.Events/Resource/EventDeliveryClient.cs` | New endpoint resolution, delivery preparation/send APIs, raw JSON POST signing, response parsing, and typed failure handling |
| `src/AAuth.Events/Resource/EventDeliveryResult.cs` | New accepted/idempotent/exhausted/error outcome with optional remaining uses |
| `tests/AAuth.Events.Tests/Resource/EventDelivery*Tests.cs` | New endpoint refresh, token/body signing, response, retry, and cancellation tests |

### Implementation decisions

- The client accepts raw UTF-8 JSON bytes or no payload; it does not
  parse/reserialize application data.
- A caller supplies event `exp`; the package does not infer business response
  windows.
- A fresh `jti` is generated once when a logical event is prepared. Retrying an
  ambiguous or failed transport attempt reuses the same
  `PreparedEventDelivery`; preparing again means a distinct event.

### Definition of Done

- [ ] Every event token copies the subscription `eid`, targets stored agent
      `sub`, uses resource `iss`/DWK/key, and carries a fresh random `jti`.
- [ ] Separate preparations with otherwise identical same-time inputs produce
      different compact tokens; retrying one preparation sends the byte-identical
      compact token and payload.
- [ ] AP metadata is resolved at delivery time through the hardened resolver.
- [ ] Payload bytes produce and are bound to the transmitted `Content-Digest`.
- [ ] 202 with `remaining_uses`, 202 with no body, and 202 with `{}` parse
      correctly.
- [ ] Resource callers can remove exhausted subscriptions on `remaining_uses:
      0`; 429 is a typed exhausted result.
- [ ] Transport, metadata, verification, timeout, and cancellation failures are
      surfaced, not converted to success.

## Phase 7 - Agent event verification and deduplication

**Goal:** verify AP-delivered event artifacts without defining the AP-to-agent
transport.

**Spec:** [Agent Verification](../../../aauth-spec/v09/draft-hardt-aauth-events.md#ap-to-agent)
L436-L447 and local interpretation C3/C14.

### Files

| File | Action and responsibility |
|---|---|
| `src/AAuth.Events/Agent/EventTokenVerifier.cs` | New resource discovery/JWT verification, agent audience, `iat`/`exp`, required `jti`, and typed claims |
| `src/AAuth.Events/Agent/UnauthenticatedEventPayload.cs` | New raw bytes and content type with API documentation that no agent-verifiable artifact binds them |
| `src/AAuth.Events/Agent/VerifiedAgentEvent.cs` | New verified token and SHA-256 idempotency key with an optional, separately named `UnauthenticatedEventPayload` |
| `src/AAuth.Events/Agent/IEventDeduplicator.cs` | New pluggable processed-event contract |
| `src/AAuth.Events/Agent/InMemoryEventDeduplicator.cs` | New bounded/expiring convenience implementation for agents and samples |
| `src/AAuth.Events/DependencyInjection/AAuthEventsAgentExtensions.cs` | New agent verifier/deduplicator registration |
| `tests/AAuth.Events.Tests/Agent/*Tests.cs` | New issuer, audience, time, context, payload, and dedup tests |

### Implementation decisions

- Default dedup keys SHA-256 over the exact compact event token, not
  `{iss,eid}`; record this deliberate draft deviation in the log.
- Unknown local `eid` context is returned as a typed result for application
  policy; it is never treated as a verified actionable event.
- Event-token verification authenticates only the resource, audience, timing,
  and subscription context. Payloads may inform display or relevance, but
  consequential actions re-fetch details from verified `iss` with a current
  auth token.

### Definition of Done

- [ ] Wrong type/DWK/signature/issuer/audience, missing/future `iat`, expired
      `exp`, and missing/empty `jti` fail.
- [ ] Multiple distinct event tokens for one unlimited `eid`, including tokens
      with otherwise identical same-time claims, can be processed.
- [ ] An exact compact-token replay is ignored by the default deduplicator.
- [ ] Payload bytes remain unchanged but are surfaced only as
      `UnauthenticatedEventPayload`; payload business/schema validation remains
      application-owned.
- [ ] A test substitutes the payload while retaining the event token and proves
      token verification cannot detect the change and never labels the payload
      authenticated.
- [ ] No polling, SSE, WebSocket, push, or callback transport enters the package
      API.

## Phase 8 - Cross-role conformance and adversarial tests

**Goal:** prove the complete package behavior against the draft and owner
rulings, including state races that isolated unit tests cannot prove.

### Files

| File | Action and responsibility |
|---|---|
| `tests/AAuth.Events.Tests/Conformance/SubscribeTokenConformanceTests.cs` | Full positive/negative subscribe matrix |
| `tests/AAuth.Events.Tests/Conformance/RegistrationConformanceTests.cs` | Public/protected registration and error matrix |
| `tests/AAuth.Events.Tests/Conformance/EventDeliveryConformanceTests.cs` | Resource-to-AP request, status, durability, uses, and replay matrix |
| `tests/AAuth.Events.Tests/Conformance/AgentVerificationConformanceTests.cs` | Agent validation and multi-event/dedup interpretation |
| `tests/AAuth.Events.Tests/Conformance/EventsEndToEndTests.cs` | In-process AP/resource/agent flow with controllable clocks and stores |

### Definition of Done

- [ ] Every MUST/MUST NOT in spec L190-L617 that falls within package scope has
      at least one positive or negative test.
- [ ] Public and protected flows pass end to end with EdDSA and ES256.
- [ ] Key rotation, cached metadata, changed AP endpoint, redirect attempts, and
      URL-policy rejections are covered.
- [ ] Concurrent ticket use, duplicate registration, event retry, final
      `max_uses`, and durable-store failure are deterministic.
- [ ] Conformance pairs two same-time events that differ only by `jti` with an
      exact retry of each, proving distinct acceptance and retry idempotency.
- [ ] Adversarial coverage includes registration-body parameter substitution
      and AP-side event-payload substitution, asserting the documented
      authorization and trust boundaries rather than false cryptographic
      detection.
- [ ] The AP never returns success after a failed/cancelled durable operation.
- [ ] A coverage-to-spec table in test names or test documentation maps each
      scenario to its section and line range.

## Phase 9 - Runnable Bookings/AP/EventAgent sample

**Goal:** demonstrate the draft's protected appointment waitlist flow while
clearly separating sample-only AP-to-agent polling and in-memory persistence
from package guarantees.

### Files

| File | Action and responsibility |
|---|---|
| `samples/MockResourceServers/Bookings/Bookings.csproj` | Reference `AAuth.Events` alongside existing `AAuth.R3` |
| `samples/MockResourceServers/Bookings/Program.cs` | Wire Events DI, one merged OpenAPI+AsyncAPI vocabulary map, protected waitlist registration, and deterministic event trigger |
| `samples/MockResourceServers/Bookings/Events/BookingsEventSubscriptions.cs` | Sample-only ticket/subscription persistence and policy |
| `samples/MockResourceServers/Bookings/asyncapi.json` | AsyncAPI 3.0 protected waitlist channel, AAuth annotation, and direct JSON payload schema |
| `samples/MockAgentProvider/MockAgentProvider.csproj` | Reference `AAuth.Events` |
| `samples/MockAgentProvider/Program.cs` | Publish `event_endpoint`; wire issuer and event endpoint; add authenticated sample acquisition/polling routes |
| `samples/MockAgentProvider/Events/SampleAgentProviderEventStore.cs` | Clearly labelled in-memory, non-durable sample implementation |
| `samples/MockAgentProvider/Events/SampleAgentEventEndpoints.cs` | Non-normative agent-signed subscribe-token acquisition and pending-event polling |
| `samples/EventAgent/EventAgent.csproj` | New console project referencing `AAuth` and `AAuth.Events` |
| `samples/EventAgent/Program.cs` | Enrol, obtain protected ticket, acquire subscribe token, register, poll, verify, deduplicate, and display the explicitly unauthenticated payload without acting on it |
| `samples/EventAgent/README.md` | Commands and normative/non-normative boundary |
| `Makefile` | Add focused AP/Bookings/EventAgent launch targets |
| `AAuth.slnx` | Add EventAgent |

### Implementation decisions

- The sample uses a protected Bookings waitlist; public registration remains in
  conformance tests.
- Polling endpoints require the enrolled agent's signed identity. They are
  sample-only and are not exported by `AAuth.Events`.
- A deterministic sample trigger replaces timing-dependent background jobs.

### Definition of Done

- [ ] Bookings publishes both OpenAPI and AsyncAPI R3 vocabulary entries.
- [ ] Bookings emits exactly one `r3_vocabularies` object; composing Events
      metadata does not replace the OpenAPI entry supplied through the R3 path.
- [ ] Its AsyncAPI document validates through `AsyncApiAAuthValidator`.
- [ ] The initial authenticated Bookings response returns a short-lived,
      single-use, agent-bound ticket URL.
- [ ] EventAgent registers using only the subscribe token at the ticket URL.
- [ ] Bookings sends a body-bound event to the AP; AP records it; EventAgent
      polls, verifies, resolves context, and prints the direct JSON payload with
      an unauthenticated-data warning.
- [ ] Reusing a ticket or `eid`, changing agent/resource/audience, replaying the
      same event token, and exceeding `max_uses` are demonstrated or covered by
      adjacent integration tests.
- [ ] Sample output labels AP acquisition/polling and in-memory storage as
      non-normative/non-production.

## Phase 10 - Release, samples, snippets, and docs sweep

**Goal:** publish the optional package with core/R3 and update all non-compiled
surfaces after APIs are frozen.

### Files

| File | Action and responsibility |
|---|---|
| `.github/workflows/publish.yml` | Pack `src/AAuth.Events/AAuth.Events.csproj` with the shared version |
| `README.md` | Add optional package, EventAgent, and Events workflow links |
| `docs/workflows/aauth-events.md` | Role diagram, public/protected flows, storage contracts, security, and draft deviations |
| `src/AAuth.Events/README.md` | Final public API and setup snippets |
| `samples/MockResourceServers/Bookings/README.md` | Waitlist and event-trigger instructions |
| `samples/MockAgentProvider/README.md` | Event endpoint and non-normative polling notes |
| `Makefile`, sample configs, inline snippets | Final command/port/name consistency sweep |

### Definition of Done

- [ ] Release dry-run builds, tests, and produces `AAuth`, `AAuth.R3`, and
      `AAuth.Events` packages at the same requested version.
- [ ] Packed `AAuth.Events` has only the intended `AAuth` dependency and includes
      its README.
- [ ] Every README/snippet uses the frozen API names and direct JSON payload.
- [ ] Docs state that production APs must supply durable storage and document
      retention; sample storage is not conformant durability.
- [ ] Docs disclose C3/C4/C5/C8/C12/C13/C14/C20/C23 and RF1-RF4, including
      event-token `none`/`jti`, registration-body integrity, agent payload
      trust, and AsyncAPI operation perspective.
- [ ] No docs imply that the sample polling endpoints are standardized.

## Phase 11 - Internal review

**Goal:** use a fresh read-only reviewer after implementation to find
spec/security/logic defects before owner review or commit.

### Review inputs

- vendored Events draft, especially L190-L617;
- [research.md](research.md), including all clarification responses;
- this plan and `implementation-log.md`;
- package, tests, samples, docs, solution, and release diff.

### Definition of Done

- [ ] A fresh subagent reports severity-graded findings for spec conformance,
      crypto/key binding, body integrity, SSRF/redirects, atomicity/durability,
      replay/idempotency, metadata composition, error mapping, package
      boundaries, agent payload trust, and sample claims.
- [ ] Every CRITICAL/HIGH finding is fixed; MEDIUM/LOW findings are fixed or
      explicitly ruled in `implementation-log.md`.
- [ ] The reviewer confirms no `src/AAuth/` or `src/AAuth.R3/` production file
      changed.
- [ ] Targeted Events tests, full solution build/test, and package dry-run pass.
- [ ] The final diff contains no generated `bin/` or `obj/` artifacts.
- [ ] Work is flagged ready for owner review before any commit.

## Out of scope

| Item | Reason |
|---|---|
| Standard AP-to-agent subscribe-token acquisition or delivery protocol | Explicitly out of scope in Events L182-L188 and L430-L434; samples use non-normative polling |
| Production durable store provider | Persistence technology is host-specific; the package defines the atomic contract |
| Full AsyncAPI object model, generation, or payload-schema engine | First release provides AAuth integration declarations only |
| Changes to `AAuth` core or `AAuth.R3` | Public core primitives and package-local Events behavior are sufficient |
| GuidedTour or SampleApp Events mode | Dedicated EventAgent is the approved focused sample |
| SSE, WebSocket, mobile push, webhook, or queue adapters | AP-to-agent transport is platform-specific |
| Payload encryption | The draft defines signed transport and privacy guidance, not encryption |
| End-to-end event payload authentication | The draft defines no agent-verifiable payload signature or digest claim (RF2); the package labels payloads unauthenticated and directs consequential actions to a resource re-fetch instead of inventing a wire extension |
| Non-JSON event payloads | The selected first-release wire interpretation is direct `application/json` |
| Subscription lifetime negotiation claim/body field | The draft defines no such wire field; applications set `ExpiresAt` |
| Upstream specification edits or IANA registration | Draft maintenance is outside this repository implementation |
