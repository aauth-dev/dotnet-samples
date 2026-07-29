# AAuth Events Specification Review

**Spec:** `draft-hardt-aauth-events-00`, 2026-06-24.

**Method:** Compiled from [research.md](research.md),
[implementation-plan.md](implementation-plan.md), and
[implementation-log.md](implementation-log.md), then checked against the
vendored draft, `src/AAuth.Events`, and its conformance tests. These are
upstream specification issues, not unresolved SDK defects.

## 1. `eid` cannot be both a subscription ID and an event idempotency key

- **Nature:** Internal contradiction. `eid` identifies a subscription, which
  may accept unlimited events, but agent verification deduplicates every event
  by `{iss, eid}` ([Terminology](../../../aauth-spec/v09/draft-hardt-aauth-events.md#terminology),
  L138; [Subscribe Token](../../../aauth-spec/v09/draft-hardt-aauth-events.md#subscribe-token),
  L229; [Agent Verification](../../../aauth-spec/v09/draft-hardt-aauth-events.md#ap-to-agent),
  L445).
- **Concern:** All events in one subscription share the same key.
- **If unchanged:** An agent following the draft processes the first event and
  discards every later event in an ongoing subscription.
- **SDK assumption/trade-off:** Deduplicate the exact compact token hash, not
  `{iss, eid}`, and rely on a fresh `jti` to distinguish later events
  ([EventTokenVerifier.cs](../../../src/AAuth.Events/Agent/EventTokenVerifier.cs#L155-L211),
  [EventTokenBuilder.cs](../../../src/AAuth.Events/Tokens/EventTokenBuilder.cs#L30-L87)).
  This deliberately deviates from the draft; a newly signed token is a new
  event even if its business payload is equivalent.

## 2. Event tokens do not explicitly forbid `alg: none`

- **Nature:** Missing security requirement. Subscribe tokens say
  implementations `MUST NOT` accept `none`; the equivalent event-token rule is
  absent ([Subscribe Token](../../../aauth-spec/v09/draft-hardt-aauth-events.md#subscribe-token),
  L212; [Event Token](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-token),
  L348).
- **Concern:** The asymmetry permits an event-only implementation to interpret
  unsigned JWTs as allowed.
- **If unchanged:** A permissive verifier can accept forged events without a
  resource private key.
- **SDK assumption/trade-off:** Apply one strict algorithm allowlist to both
  token types: EdDSA or ES256 only
  ([EventsJwtKeyResolver.cs](../../../src/AAuth.Events/Http/EventsJwtKeyResolver.cs#L122-L124)).
  This closes the gap but requires an SDK update before any future algorithm
  can interoperate.

## 3. The minimum resource record cannot populate event `aud`

- **Nature:** Internal contradiction. The stated minimum resource state is
  `{eid, iss}`, while event issuance and AP validation require the agent
  identifier in `aud`
  ([Subscription Verification](../../../aauth-spec/v09/draft-hardt-aauth-events.md#subscribe-token),
  L279; [Event Token](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-token),
  L356; [AP Validation](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-delivery),
  L413).
- **Concern:** Neither `eid` nor the AP issuer identifies the subscribed agent.
- **If unchanged:** A resource storing only the documented minimum cannot issue
  an acceptable event token; delivery fails the AP audience check.
- **SDK assumption/trade-off:** Persist subscribe-token `sub` as
  `AgentSubject`, in addition to the stated minimum, and use it as event `aud`
  ([ResourceSubscription.cs](../../../src/AAuth.Events/Resource/ResourceSubscription.cs#L45-L63),
  [EventDeliveryClient.cs](../../../src/AAuth.Events/Resource/EventDeliveryClient.cs#L190-L203)).
  This adds required durable state without changing the wire format.

## 4. Event payload integrity ends at the AP

- **Nature:** End-to-end integrity gap. The event token excludes event data;
  `Content-Digest` protects the resource-to-AP hop, but the agent may use the
  forwarded payload directly
  ([Event Token](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-token),
  L361; [Event Delivery](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-delivery),
  L387; [Agent Verification](../../../aauth-spec/v09/draft-hardt-aauth-events.md#ap-to-agent),
  L447).
- **Concern:** The agent has no resource-signed digest with which to authenticate
  payload bytes supplied by the AP.
- **If unchanged:** A compromised or malicious AP can substitute actionable
  payload content while the event token still verifies.
- **SDK assumption/trade-off:** Expose payload bytes only as
  `UnauthenticatedEventPayload`; consequential details must be re-fetched from
  the verified resource
  ([UnauthenticatedEventPayload.cs](../../../src/AAuth.Events/Agent/UnauthenticatedEventPayload.cs#L9-L46)).
  This avoids a private wire extension but adds application work and another
  authenticated request.

## 5. Registration JSON is not integrity-bound

- **Nature:** Signature-profile gap. Registration signs `content-type` but not
  `content-digest`, unlike event delivery
  ([Registration Presentation](../../../aauth-spec/v09/draft-hardt-aauth-events.md#subscribe-token),
  L251-L266; [Event Delivery](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-delivery),
  L382-L399).
- **Concern:** The HTTP signature authenticates the agent and path, not the
  registration body bytes.
- **If unchanged:** A TLS-terminating intermediary or compromised hop can alter
  requested event types or other body preferences without invalidating the
  HTTP signature.
- **SDK assumption/trade-off:** Retain the draft profile for interoperability,
  label the body `SignatureUnboundRegistrationBody`, and prohibit body
  preferences from widening authorization
  ([SignatureUnboundRegistrationBody.cs](../../../src/AAuth.Events/Resource/SignatureUnboundRegistrationBody.cs#L9-L35)).
  This contains the authorization impact but does not provide body integrity.

## 6. Event payload wire shape and media type conflict

- **Nature:** Conflicting wire definitions. The HTTP example sends a direct
  JSON body, discovery prose calls it a `payload` field, and the AsyncAPI
  example declares `application/jwt`
  ([Event Delivery](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-delivery),
  L380-L395; [AsyncAPI Document](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-discovery),
  L479; [Example AsyncAPI Document](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-discovery),
  L551).
- **Concern:** The alternatives describe different HTTP bodies and parsers.
- **If unchanged:** Implementations may send a JSON object, a wrapper object, or
  a JWT and fail to interoperate.
- **SDK assumption/trade-off:** Follow the concrete delivery example: preserve
  the direct payload bytes and require `application/json`, with no wrapper
  ([PreparedEventDelivery.cs](../../../src/AAuth.Events/Resource/PreparedEventDelivery.cs#L28-L49)).
  Peers choosing either other interpretation are incompatible.

## 7. Required signed components exist only in examples

- **Nature:** Normative omission. Examples cover `content-type` for
  registration and `content-type` plus `content-digest` for event delivery, but
  the verification algorithms do not require those components
  ([Registration Verification](../../../aauth-spec/v09/draft-hardt-aauth-events.md#subscribe-token),
  L265-L279; [AP Validation](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-delivery),
  L404-L413).
- **Concern:** Examples and normative steps define different signature
  profiles.
- **If unchanged:** Strict implementations can reject each other, while lenient
  implementations may leave event bodies unprotected.
- **SDK assumption/trade-off:** Treat the examples as normative and require the
  exact component sequence: base components only when bodyless,
  `content-type` for registration JSON, and `content-type` plus
  `content-digest` for event JSON
  ([AAuthEventsConstants.cs](../../../src/AAuth.Events/AAuthEventsConstants.cs#L63-L75),
  [EventsHttpMessageVerifier.cs](../../../src/AAuth.Events/Http/EventsHttpMessageVerifier.cs#L42-L93)).
  This is secure and deterministic but may reject a peer following only the
  prose.

## 8. `max_uses` is incremented before audience validation

- **Nature:** Invalid validation order. AP step 7 mutates use state before step
  8 checks the event audience
  ([AP Validation](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-delivery),
  L412-L413).
- **Concern:** A request can fail authorization after consuming a finite use.
- **If unchanged:** Wrong-audience deliveries can exhaust a subscription
  without delivering any event.
- **SDK assumption/trade-off:** Require one durable store transaction to check
  subscription, resource, audience, expiry, replay, and limits before committing
  use count and inbox state
  ([IAAuthAgentProviderEventStore.cs](../../../src/AAuth.Events/AgentProvider/IAAuthAgentProviderEventStore.cs#L5-L29),
  [EventEndpointExtensions.cs](../../../src/AAuth.Events/AgentProvider/EventEndpointExtensions.cs#L129-L132)).
  Correctness depends on the application-provided store honoring this contract.

## 9. The protocol has no per-event identity or AP retry rule

- **Nature:** Missing replay/idempotency model. Event claims omit `jti`, and AP
  validation has no exact-retry check
  ([Event Token](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-token),
  L351-L359; [AP Validation](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-delivery),
  L404-L413).
- **Concern:** A retry is indistinguishable from another use; token-hash
  deduplication alone also collides when two same-second events serialize
  identically.
- **If unchanged:** Network retries can double-deliver and double-count
  `max_uses`; attempts to add local deduplication can suppress legitimate
  same-second events.
- **SDK assumption/trade-off:** Add a required, fresh 128-bit `jti`; use the
  compact-token SHA-256 hash as the AP and agent idempotency key; return the
  prior `202` result for an exact retry without another use
  ([EventTokenBuilder.cs](../../../src/AAuth.Events/Tokens/EventTokenBuilder.cs#L30-L87),
  [IncomingEvent.cs](../../../src/AAuth.Events/AgentProvider/IncomingEvent.cs#L24-L42),
  [EventAcceptanceResult.cs](../../../src/AAuth.Events/AgentProvider/EventAcceptanceResult.cs#L3-L38)).
  This is a deliberate wire extension: otherwise spec-conforming event tokens
  that omit `jti` are rejected.

## 10. Subscription expiry has no wire representation

- **Nature:** Missing lifecycle contract. The AP can return `404` for an expired
  subscription, but subscribe-token `exp` is explicitly only the registration
  window
  ([AP Validation](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-delivery),
  L409-L428; [Design Rationale](../../../aauth-spec/v09/draft-hardt-aauth-events.md#design-rationale),
  L681-L687).
- **Concern:** No field communicates or negotiates subscription lifetime
  between AP and resource.
- **If unchanged:** Implementations apply unrelated local expiry policies and
  can disagree about whether a subscription is active.
- **SDK assumption/trade-off:** Keep `TokenLifetime` and AP-side
  `SubscriptionLifetime` separate, and require resource applications to supply
  their own stored `ExpiresAt`
  ([SubscribeTokenIssuer.cs](../../../src/AAuth.Events/AgentProvider/SubscribeTokenIssuer.cs#L22-L24),
  [ResourceSubscription.cs](../../../src/AAuth.Events/Resource/ResourceSubscription.cs#L74-L92)).
  No non-standard claim is added, so cross-party lifetime synchronization
  remains unsolved.

## 11. Required event `iat` is never listed as validated

- **Nature:** Missing validation requirement. `iat` is required, but neither
  the AP nor agent validation sequence says to reject a future value
  ([Event Token](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-token),
  L358; [AP Validation](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-delivery),
  L404-L413; [Agent Verification](../../../aauth-spec/v09/draft-hardt-aauth-events.md#ap-to-agent),
  L438-L445).
- **Concern:** Requiring a claim without defining its validation gives it no
  consistent security meaning.
- **If unchanged:** Future-issued events may be accepted by some
  implementations and rejected by others.
- **SDK assumption/trade-off:** Require `iat`, require `exp > iat`, and reject
  future issuance using configured clock skew
  ([EventTokenClaims.cs](../../../src/AAuth.Events/Tokens/EventTokenClaims.cs#L30-L42),
  [TokenVerifier.cs](../../../src/AAuth/Tokens/TokenVerifier.cs#L107-L130)).
  This is stricter than the event-specific validation lists.

## 12. Failure status codes are incomplete

- **Nature:** Interoperability omission. Registration defines no failure map;
  AP delivery omits outcomes for an expired event token and wrong event
  audience
  ([Protocol Overview](../../../aauth-spec/v09/draft-hardt-aauth-events.md#protocol-overview),
  L163; [AP Validation](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-delivery),
  L404-L428).
- **Concern:** Callers cannot implement deterministic retry, re-registration,
  or terminal-failure policy.
- **If unchanged:** Servers return different statuses for the same failure and
  clients handle them inconsistently.
- **SDK assumption/trade-off:** Registration maps to
  `200/400/401/403/404/409`; expired or invalid event tokens map to `401`; wrong
  event audience maps to `403`
  ([SubscriptionRegistrationResult.cs](../../../src/AAuth.Events/Resource/SubscriptionRegistrationResult.cs#L3-L11),
  [SubscriptionEndpointExtensions.cs](../../../src/AAuth.Events/Resource/SubscriptionEndpointExtensions.cs#L183-L190),
  [EventEndpointExtensions.cs](../../../src/AAuth.Events/AgentProvider/EventEndpointExtensions.cs#L157-L191)).
  These are opinionated defaults, not guaranteed peer behavior.

## 13. AsyncAPI operation direction is reversed or perspective-dependent

- **Nature:** Vocabulary ambiguity. A resource-owned document uses
  `action: receive` for messages emitted by the resource, while the rationale
  frames the document for an agent reader
  ([AsyncAPI Document](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-discovery),
  L478; [Example AsyncAPI Document](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-discovery),
  L537 and L544; [Design Rationale](../../../aauth-spec/v09/draft-hardt-aauth-events.md#design-rationale),
  L721).
- **Concern:** AsyncAPI normally describes `send`/`receive` from the document
  owner's perspective; the draft mixes resource ownership with agent
  perspective.
- **If unchanged:** Generic tooling can model the resource as a consumer and
  generate the wrong integration shape.
- **SDK assumption/trade-off:** Do not validate operation direction; validate
  only AAuth-specific declarations
  ([AsyncApiAAuthValidator.cs](../../../src/AAuth.Events/Discovery/AsyncApiAAuthValidator.cs#L53-L103),
  [DiscoveryTests.cs](../../../tests/AAuth.Events.Tests/Discovery/DiscoveryTests.cs#L118-L136)).
  This accepts both interpretations but cannot diagnose a direction error.
