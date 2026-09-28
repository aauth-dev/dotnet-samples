# Events Workflow

## Run the Demonstration

Start the sample stack with `make demo`, then visit
[SampleApp Events](http://localhost:5240/events) or
[GuidedTour Events](http://localhost:5400/events). Both run the same six-step
client against MockAgentProvider and Bookings:

1. Discover resource metadata, AsyncAPI channels and AP `event_endpoint`.
2. Enrol an agent. Select the public channel or obtain a protected subscription
   ticket through an authorized R3 Bookings search with the selected account.
3. Request a subscribe token through the AP's local authenticated API.
4. Register using `scheme=jwt` and the subscribe token's confirmation key.
5. Trigger the local sample event. Bookings sends the resource JWT using
   `self-jwt` and signs the actual payload digest. The AP commits before 202.
6. Poll the local authenticated inbox, independently verify the resource JWT,
   recover persisted context, persist one receipt and acknowledge delivery.

The console equivalent is `make agent-events` for the public channel, or
`make agent-events ARGS="--protected --work"` for protected work-account
notifications. Follow the printed consent URL for a protected subscription.

The previous R3 reservation pages retain their original flow and link to the
optional Events demonstration. The ticket issued from an authorized search or
confirmation binds the authenticated agent's key (its JWK thumbprint, not the
agent identifier), receive operation, selected account and current resource
state. The subscription records the same key thumbprint from the subscribe
request's HTTP signing key. Its five-minute lifetime is separate from the
subscription's one-hour lifetime and the subscribe token's five-minute validity.

## SDK Integration

```csharp
services.AddAAuthEvents();
using var http = AAuthHttpTransport.CreateClient(egressPolicy);
var protocol = new EventsProtocol(http,
    serviceProvider.GetServices<ISignatureTokenVerifier>());

app.MapAAuthEventEndpoint("/events", protocol, durableProviderStore);
app.MapAAuthSubscriptionEndpoint("/subscriptions/{ticket}", resource,
    "receiveReservationAvailable", true, protocol, durableResourceStore,
    validateSubscriptionParameters);

var endpoint = await protocol.ResolveEventEndpointAsync(subscription.Provider);
using var response = await protocol.SendAsync(HttpMethod.Post, endpoint,
    resourceKey, eventToken, selfIssued: true, body: payloadBytes);

var receiver = new EventReceiver(protocol, durableAgentStore, agentIdentifier);
var firstReceipt = await receiver.ReceiveAsync(eventToken, payloadBytes);
```

Use `SubscribeTokenBuilder` and `EventTokenBuilder` for issuer-generated tokens.
AP issuance must persist its subscription record before releasing the subscribe
token. Resource delivery must retain a prepared token and identical payload
across retries. The sample stores both before transmission. After the AP reports
`remaining_uses: 0`, Bookings atomically records its local delivery receipt and
marks its subscription complete. An authenticated retry returns that receipt
without another AP call. The subscribing agent and stored account still bind
the receipt; an explicitly different account is rejected.

The AP returns 400 for malformed requests, 401 for failed verification, 403 for
resource/agent binding failure, 404 for unknown/expired subscriptions, and 429
for exhausted quota. Storage failure returns 503, never 202. A bounded accepted
delivery includes `remaining_uses`; an unlimited accepted delivery has no body.
An identical accepted-token retry returns its durable result without incrementing
quota. Reusing the same token with changed payload bytes is rejected.

## Local Profile and Limits

The `/local/events/...` endpoints are explicitly sample-specific. Polling and
acknowledgement use an AP-issued agent JWT and a signed body digest. The resource
trigger also verifies the subscribing agent. These endpoints are not intended
as production administrative APIs. Enrollment requires body-bound `hwk` proof
of possession and assigns the identity under the AP's own host. Caller-chosen
identities and silent key replacement are rejected. Same-key signed enrollment
is idempotent across restarts. This proves key ownership, not a human identity;
production admission and authorized rotation remain provider responsibilities.
Isolated browser consent remains an explicit demonstration policy.

Inbox responses are JSON arrays bounded to 1 MiB, including base64 payloads.
Use `?limit=1` through `?limit=100` to reduce the batch, and `?after={receipt}`
to continue after its last receipt without acknowledging unrelated events.
The cursor and acknowledgments are agent-scoped. The sample client pages until
it finds its subscription; a lost notify response can be retried in the same
session before inbox verification.

SQLite lives under `~/.aauth`: `ap-agents.db`, `ap-events.db`, `bookings-events.db`, and per-agent
or per-UI-circuit agent databases. AP and Bookings signing keys are persisted.
`AgentProvider:Database` overrides the durable enrollment database, and
`Events:Database` overrides the AP/resource event database path. No automatic retention
job is supplied; acknowledged records remain for deduplication until the owner
removes the dedicated database. Protect database/key directories with OS access
controls. UI circuits do not offer cross-circuit resume; persisted agent receipts
and context remain available to a provider implementation.

The event payload uses the delivery section's raw body, not a new wrapper.
Metadata, keys and outbound event endpoints use the shared SDK's admission,
cache and connection-pinning policy. Development permits only explicitly listed
sample loopback origins. External platform transports, renewal APIs, arbitrary
business-effect exactly-once execution and general recurring-event semantics are
not claimed. Unlimited AP accounting is implemented. Event tokens carry a required
`jti`, and the AP and agent deduplicate on `(iss, jti)`, so each notification
under one subscription is a distinct event and only a resent copy is ignored.

## Verification

Run `make test-events`, `dotnet test AAuth.slnx -c Release`, and `make e2e`.
The [Events tests](../../tests/AAuth.Events.Tests/) cover token types, strict
claims/algorithms, real HTTP signatures and exact payload bytes, public/protected
registration, ticket/account/state binding, quota concurrency, rollback,
reopening stores, local inbox authentication and agent deduplication. Both primary
apps' browser suites exercise public and protected work-account notifications.