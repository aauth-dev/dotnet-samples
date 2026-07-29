# AAuth.Events

> **Preview.** Version `0.1.0-alpha.1` implements a changing AAuth Events
> draft. APIs, wire decisions, and transport boundaries may change.

`AAuth.Events` targets `net10.0` and depends only on the `AAuth` package
(`0.1.0-alpha.1` in this release). It contains protocol helpers for the AP,
resource, and agent roles; it does not standardize AP-to-agent transport.

## Role matrix

| Role | Use | Main APIs |
|---|---|---|
| AP | Issue subscribe tokens and durably accept deliveries | `SubscribeTokenIssuer`, `IAAuthAgentProviderEventStore`, `MapAAuthEventEndpoint` |
| Resource | Register subscriptions and deliver event envelopes | `SubscriptionRegistrationVerifier`, `MapAAuthPublicSubscription`, `MapAAuthProtectedSubscription`, `EventDeliveryClient` |
| Agent | Register with a resource and verify event envelopes | `SubscriptionRegistrationClient`, `EventTokenVerifier`, `IEventDeduplicator` |
| Application | Define tickets, channel policy, payload schema, retention, and AP-to-agent transport | `IAAuthSubscriptionRegistrationHandler`, `IEventContextLookup`, application stores |

## Installation

```bash
dotnet add package AAuth.Events --version 0.1.0-alpha.1
```

The package includes ASP.NET Core integration. `AAuth.R3` is not a production
dependency of this package.

## Setup

Register the resource role and map a protected channel:

```csharp
builder.Services.AddAAuthEventsResource(options =>
{
    options.MaxBodyBytes = AAuthEventsConstants.DefaultMaxBodyBytes;
    options.SignatureMaxAge = TimeSpan.FromSeconds(60);
    options.SignatureFutureSkew = TimeSpan.FromSeconds(5);
});

var channel = SubscriptionChannel.Protected(
    "waitlist-subscriptions",
    "/waitlist/subscriptions/{ticket}",
    ["slot.available"],
    resourceAudience: resourceUrl);
app.MapAAuthProtectedSubscription(channel, registrationHandler);
```

`resourceAudience` is mandatory and canonical: pass the resource's own absolute
URL, and do not infer it from the request `Host`.

`registrationHandler` implements:

```csharp
ValueTask<SubscriptionRegistrationResult> RegisterAsync(
    SubscriptionEndpointContext endpoint,
    VerifiedSubscriptionRegistration registration,
    SignatureUnboundRegistrationBody? preferences,
    CancellationToken cancellationToken = default);
```

The handler must atomically consume protected tickets, bind the ticket to
`registration.AgentSubject` and the channel, reject duplicate `registration.Eid`,
and persist an application-selected `ExpiresAt`.

Issue subscribe tokens with separate JWT and subscription lifetimes:

```csharp
var issuer = new SubscribeTokenIssuer(durableStore, new SubscribeTokenIssuerOptions
{
    Issuer = apIssuer,
    Agent = agentSubject,
    Resource = resourceUrl,
    KeyId = apKeyId,
    Key = apKey,
    ConfirmationKey = agentConfirmationKey,
    TokenLifetime = TimeSpan.FromHours(1),
    SubscriptionLifetime = TimeSpan.FromHours(24),
});
SubscribeTokenArtifact artifact = await issuer.IssueAsync(ct);
```

`TokenLifetime` is the JWT registration window and sets the token `exp`. The
persisted subscription `ExpiresAt` comes from `SubscriptionLifetime`; no extra
wire lifetime claim is added. `TokenLifetime` defaults to one hour, and
`SubscriptionLifetime` is required and must be positive.

Register the AP role only with an application-provided durable store:

```csharp
builder.Services.AddAAuthEventsAgentProvider(
    durableStore,
    options =>
    {
        options.JwtKeyResolver = resolver;
        options.HttpMessageVerifier = new EventsHttpMessageVerifier();
    });
app.MapAAuthEventEndpoint("/events");
```

`IAAuthAgentProviderEventStore.AcceptEventAsync(...)` runs after the endpoint's
resolver/verifier chain checks event signature freshness and event-token
`exp`/`iat` with configured skew. The store then owns subscription
lookup/state, resource/audience binding, exact-token idempotency, use
accounting, and inbox persistence; it does not revalidate the event token
expiry.

> **Interop warning.** v09 has no event `jti`. This SDK deliberately requires a
> fresh, non-empty `jti` on every event token and rejects peers that omit it.
> There is no missing-`jti` fallback: same-second legitimate events can collide
> with exact-token retry identity.

For agent verification, supply durable local context and deduplication:

```csharp
builder.Services.AddAAuthEventsAgent(
    expectedAudience: agentSubject,
    contextLookup: new DelegateEventContextLookup(
        eid => contexts.TryGetValue(eid, out var context) ? context : null),
    configure: options => options.Deduplicator = durableDeduplicator);
```

`expectedAudience` is required and must be the agent's own identifier; the
verifier rejects missing or mismatched audiences.

## Tokens and HTTP profiles

`SubscribeTokenBuilder` emits `aa-subscribe+jwt` with `iss`, `dwk:
aauth-agent.json`, `sub`, resource `aud`, `cnf.jwk`, `eid`, `iat`, `exp`, and
optional positive `max_uses`. `EventTokenBuilder` emits `aa-event+jwt` with
resource `iss`, `dwk: aauth-resource.json`, agent `aud`, `eid`, `iat`, `exp`,
and a fresh random `jti`; it has no `cnf` and no payload.

Both builders support EdDSA and ES256 and reject `none`/unsupported algorithms.
`EventTokenClaims.Read(...)` and `SubscribeTokenClaims.Read(...)` consume a
core verified token.

The frozen builder properties are explicit:

```csharp
var subscribe = new SubscribeTokenBuilder
{
    Issuer = apIssuer,
    Subject = agentSubject,
    Audience = resourceUrl,
    KeyId = apKeyId,
    Key = apSigningKey,
    ConfirmationKey = agentConfirmationKey,
    Lifetime = TimeSpan.FromHours(1),
    MaxUses = 3,
}.Build();

var eventToken = new EventTokenBuilder
{
    Issuer = resourceUrl,
    Audience = agentSubject,
    Eid = subscription.Eid,
    KeyId = resourceKeyId,
    Key = resourceSigningKey,
    Lifetime = TimeSpan.FromMinutes(5),
}.Build();
```

Events HTTP signatures have exact profiles:

- bodyless: `@method`, `@authority`, `@path`, `signature-key`;
- registration JSON: those four plus `content-type` (the JSON body is
  signature-unbound);
- event JSON: those four plus `content-type` and `content-digest`.

Use `EventsRequestSigner`, `EventsHttpMessageVerifier`, or the higher-level
clients. Event bodies are direct raw JSON bytes, not a wrapper.

## Discovery and delivery

```csharp
var policy = new DefaultEventsUrlPolicy();
var endpointResolver = new EventEndpointResolver(urlPolicy: policy);
using var http = EventsHttpClientFactory.Create(policy);
var delivery = new EventDeliveryClient(
    endpointResolver, resourceKey, "bookings-1", http);
var prepared = delivery.Prepare(
    subscription, payload, expiresAt, AAuthEventsConstants.JsonMediaType);
EventDeliveryResult result = await delivery.SendAsync(prepared);
```

`EventEndpointResolver` reads the current AP `event_endpoint` from
`/.well-known/aauth-agent.json`; it does not trust a copied endpoint in a
subscribe token. `DefaultEventsUrlPolicy` permits HTTPS and loopback HTTP,
rejects user-info and non-loopback private/link-local IP literals, supports a
trust callback, and is used with redirect-disabled
`EventsHttpClientFactory`.

For metadata and AsyncAPI declarations:

```csharp
var map = AAuthEventsMetadata.WithAsyncApiVocabulary(
    existingVocabularies, "https://resource.example/asyncapi.json");
JsonObject r3Vocabularies = AAuthEventsMetadata.ToVocabulariesJson(map);
AsyncApiAAuthValidator.EnsureValid(asyncApiDocument);
```

The helpers preserve caller-owned vocabulary entries and validate AAuth
declarations only. AsyncAPI operation direction (`send` versus `receive`) is
not an AAuth validity rule.

## Storage and security requirements

Production APs **must** implement durable `IAAuthAgentProviderEventStore`
storage. The transaction must make subscription creation and event acceptance
atomic and durable. Production agents need durable event context and
`IEventDeduplicator` state. `InMemoryEventDeduplicator` and sample stores are
single-process convenience implementations only.

The event envelope does not authenticate its optional payload. Agents receive
`UnauthenticatedEventPayload` with `IsAuthenticated == false`; display or
relevance decisions are permitted, but consequential data must be re-fetched
from the verified resource using normal AAuth. The AP sees event tokens and
payloads, so production APs must document retention and access controls.

Default body buffering is 1 MiB (`AAuthEventsConstants.DefaultMaxBodyBytes`).
The package does not provide payload schemas, ticket formats, subscription
expiry negotiation, polling, ACK, or a standard AP-to-agent transport.
