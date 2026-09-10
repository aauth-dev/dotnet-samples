---
title: AAuth Events
description: Events companion package, verification boundaries and durable provider contracts.
---

## Scope

`AAuth.Events` implements the vendored v10 Events companion: AP-issued
`aa-subscribe+jwt` registration, resource-issued `aa-event+jwt` delivery using
`self-jwt`, public/protected subscription endpoints, AP acceptance and agent
verification. It depends on the current AAuth SDK and the ASP.NET shared framework.
It does not include a database package or a default volatile acceptance store.

See the [Events workflow](../../docs/workflows/events.md) and the
[EventAgent sample](../../samples/EventAgent/README.md).

## Verification

Register `services.AddAAuthEvents()` and pass the registered
`ISignatureTokenVerifier` instances to `EventsProtocol`. Unknown token types and
unregistered Events types fail closed. The companion uses the shared
`TokenVerifier`, `DefaultSignatureKeyResolver`, `AAuthVerificationMiddleware`,
`KeyFactory`, metadata/JWKS cache and admitted transport. There is no separate
Events URL policy or cryptographic verifier.

Both supported algorithms, Ed25519 and ES256, require fully specified public
JWK algorithms. `EdDSA` and `none` are rejected. Subscribe tokens require
`cnf.jwk`; event tokens forbid `cnf`. Both require current issuance/expiration
claims, exact well-known document names, an audience and a non-empty `eid`.
No Events `jti` requirement is introduced; a permitted optional `jti` is accepted.

The local HTTP profile requires a signed Content-Digest and, when present,
Content-Type. Empty bodies use the digest of zero bytes. The shared signer
computes SHA-256; the shared verifier compares it with the actual received bytes.
Incoming Events requests are bounded to 64 KiB. This stronger body-binding profile
is an implementation choice, not a universal AAuth requirement.

## Provider Obligations

`IAgentProviderEventStore.Accept` must atomically validate the active subscription,
resource/agent binding and quota, update use accounting, and persist a delivery
outbox before reporting 202. An exact retry must not consume another use or
replace payload bytes. Subscription lifetime is separate from the subscribe
JWT's registration validity window. Omitted `max_uses` means unlimited; zero and
sentinel values are invalid.

`IResourceEventStore.Register` must atomically validate and consume a protected
ticket and insert the subscription. Tickets must retain authorized agent,
operation, account and resource state, reject expiration and changed state, and
remain single-use after restart. Public registrations still reject duplicate
provider/eid pairs. Implementations must not trust caller-supplied account or
state over the protected ticket's stored context.

`IAgentEventStore` persists context and deduplicates receipts by resource issuer
and `eid`. `EventReceiver` verifies the resource JWT and agent audience before
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

The draft permits unlimited subscriptions but tells agents to deduplicate by
`eid` and issuer. The implementation follows that rule literally. Later distinct
notifications for the same pair are ignored by the agent. The sample is
single-shot with `max_uses: 1`; it does not invent a standard per-event identifier
or claim to resolve recurring-event semantics.