# AAuth Events

## Scope

`AAuth.Events` implements the vendored v11 Events companion: AP-issued
`aa-subscribe+jwt` registration, resource-issued `aa-event+jwt` delivery using
`self-jwt`, public/protected subscription endpoints, AP acceptance and agent
verification. It depends on the current AAuth SDK and the ASP.NET shared framework.
It does not include a database package or a default volatile acceptance store.

See the [Events workflow](../../docs/workflows/events.md) and the
[EventAgent sample](../../samples/EventAgent/README.md).

## Verification

Register `services.AddAAuthEvents(o => o.EgressPolicy = …)`: it adds the Events
context-based `ISignatureTokenVerifier` instances and a singleton `EventsProtocol` built from
`AAuthEventsOptions` (`EgressPolicy`, `TimeProvider`, and an optional
`InnerHandler` with its `TransportContract`). Register the host's durable
`IAgentProviderEventStore` or `IResourceEventStore`; `MapAAuthEventEndpoint(path)`
and `MapAAuthSubscriptionEndpoint(path, o => { o.Operation = …; o.ValidateParameters = …; })`
resolve the protocol and store from DI per request. The subscription `Resource`
defaults to the registered `AAuthResourceOptions.Issuer`. `ValidateParameters`
is optional for channels with no body parameters; the default accepts only an
omitted body or an empty JSON object. Agent-side code may still
construct its own `EventsProtocol`. Unknown token types and
unregistered Events types fail closed. The companion uses the shared
`TokenVerifier`, `DefaultSignatureKeyResolver`, `AAuthVerificationMiddleware`,
`KeyFactory`, metadata/JWKS cache and admitted transport. There is no separate
Events URL policy or cryptographic verifier.

Both supported algorithms, Ed25519 and ES256, require fully specified public
JWK algorithms. `EdDSA` and `none` are rejected. Subscribe tokens require
`cnf.jwk`; event tokens forbid `cnf`. Both reject unsupported JOSE `crit` and
require current issuance/expiration claims, exact well-known document names, an
audience and a non-empty `eid`; `exp` has zero tolerance. Event tokens require
`jti` for `(iss, jti)` delivery deduplication. Subscribe tokens do not require
`jti`; a permitted optional `jti` is accepted.

Events requests with no payload omit the HTTP body and do not cover
`content-type` or `content-digest`. `EventsProtocol.SendAsync` treats both
`null` and `Array.Empty<byte>()` as no payload. A body-bearing Events request
must cover both `content-type` and `content-digest`; the shared signer computes
SHA-256 and the shared verifier compares it with the actual received bytes.
Incoming Events requests are bounded to 64 KiB.

## Provider Obligations

`IAgentProviderEventStore.Accept` returns a typed `EventAcceptanceOutcome`.
It must atomically validate the active subscription, resource/agent binding and
quota, update use accounting, and persist a delivery outbox before returning
`Accepted`. An exact retry returns `Duplicate` with the previous
`remaining_uses`; it must not consume another use or replace payload bytes.
`Unknown`, `Expired` and `Exhausted` map to 404, while a persisted binding
conflict maps to 403. Subscription lifetime is separate from the subscribe JWT's
registration validity window. Omitted `max_uses` means unlimited; zero and
sentinel values are invalid.

`IResourceEventStore.Register` must atomically validate and consume a protected
ticket and insert the subscription. Tickets must retain authorized agent,
operation, account and resource state, reject expiration and changed state, and
remain single-use after restart. Public registrations still reject duplicate
provider/eid pairs. Implementations must not trust caller-supplied account or
state over the protected ticket's stored context.

`IAgentEventStore` persists context and deduplicates receipts by resource issuer
and event token `jti`; every event on a subscription shares its `eid`, so `eid`
cannot serve. `EventTokenBuilder` issues a fresh `jti` per event, and
`EventsTokens.Verify` rejects an event token without one. `EventReceiver` verifies the resource JWT and agent audience before
looking up context. It never records expired or mismatched events. A receipt is
not an exactly-once transaction with arbitrary external business effects; hosts
must coordinate those effects with their own durable processing mechanism.

## Transport and Persistence Ownership

The [EventSupport sample](../../samples/EventSupport/) provides SQLite 10.0.11
implementations with immediate transactions, WAL and FULL synchronization. It
also contains authenticated AP polling, token acquisition, acknowledgement and
the controlled notification trigger. None of those local endpoints are
standardized by Events. Production callers must supply admitted HTTPS transports,
durable providers, authorization policy, retention and operational limits.

The raw AsyncAPI payload travels in the POST body, following the delivery
section. The AP can read it. An agent receives payload bytes through its trusted
AP transport; the resource JWT alone does not authenticate detached payload bytes
after that transport has been discarded.

## Draft Limitation

The draft uses `eid` and issuer as the subscription identity. The implementation
stores subscription context by `eid`, but event delivery requires a fresh event
token `jti` and deduplicates received events by `(iss, jti)`. The sample's
controlled notification trigger is single-shot with `max_uses: 1`; it does not
invent additional recurring-event semantics beyond distinct event-token `jti`
values.