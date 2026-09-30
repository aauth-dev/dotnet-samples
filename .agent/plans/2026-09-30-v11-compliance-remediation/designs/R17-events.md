# R17 — Events

Findings: A24-01, A24-02, A24-03, S06-01. Spec: Events #protected-subscriptions L296-L344 (body MAY include parameters at L305), #event-delivery L385-L442 (payload optional at L389; AP status mapping at L437-L441), #pre-authorized-subscription-url-security L597-L604; Protocol #covered-components L2202-L2229 (body-bound digest/type rule, especially L2211-L2214). Files read: `src/AAuth.Events/EventsEndpoints.cs`, `EventsProtocol.cs`, `EventStores.cs`, `EventReceiver.cs`, `src/AAuth.Events/README.md`, `tests/AAuth.Events.Tests/EventHttpTests.cs`, `EventPersistenceTests.cs`, `EventsDependencyInjectionTests.cs`, `samples/EventSupport/SqliteEventStore.cs`, `BookingsEvents.cs`, `LocalEventProvider.cs`, `docs/workflows/events.md`, audit finding files `sdk/A24-events.md` and `samples/S06-sample-support.md`, API-surface research/log extracts.

## Problem restated (verified)

- **A24-01: subscription registration rejects the spec-valid no-body form.** Verified `MapSubscriptionCore` always parses `ReadFromJsonAsync<JsonObject>()` and rejects `parameters is null` before calling the store (`EventsEndpoints.cs:86`, `EventsEndpoints.cs:89`). The protected subscription flow says the step-4 request body **MAY** include additional AsyncAPI parameters, so a ticket URL that already carries the authorization and needs no extra channel parameters must be accepted (#protected-subscriptions L305). The current options also require `ValidateParameters` (`EventsEndpoints.cs:72-L73`), which makes zero-parameter channels unnecessarily hard to map.
- **A24-02: no-payload event deliveries are forced to carry `Content-Digest`.** Verified `EventsProtocol.VerifyRequestAsync` computes `RequiredComponents = context.Request.ContentType is null ? ["content-digest"] : ["content-digest", "content-type"]` (`EventsProtocol.cs:67`), so a bodyless event request still needs a digest. `EventsProtocol.SendAsync` also always creates `ByteArrayContent(body ?? [])`, assigns `Content-Type: application/json`, and signs `content-type` plus `content-digest` (`EventsProtocol.cs:94-L96`). Events says the POST body is optional and omitted when the event has no payload (#event-delivery L389); the base protocol requires digest/type only on body-bearing PS/AS/revocation requests (#covered-components L2211-L2214), not on every bodyless Events request.
- **A24-03 / S06-01: exhausted event subscriptions can return 429.** Verified the SDK endpoint trusts arbitrary store status codes (`EventsEndpoints.cs:51-L52`), `EventAcceptance` is a public raw `int StatusCode` record (`EventStores.cs:7`), the HTTP test pins `429` for a second distinct event after a single-use subscription is spent (`EventHttpTests.cs:350`), and the sample SQLite AP store hard-codes `new(429)` (`SqliteEventStore.cs:89`; `EventPersistenceTests.cs:21`). Events requires unknown, expired, and max-use-exhausted subscriptions to answer `404`, and states `429 Too Many Requests` is not used (#event-delivery L437-L441). The bug is not just the sample value: the SDK API lets every store select non-spec wire statuses.

## Candidate fixes

| # | Approach | Pros | Cons | Spec fit | API-surface fit (C1–C13) |
|---|---|---|---|---|---|
| 1 | Patch only `SqliteEventStore` and tests from `429` to `404`; leave `EventAcceptance(int StatusCode)`. | Smallest change; fixes the observed sample. | Third-party stores can still return `429`, `410`, or `500` for protocol states; endpoint still delegates wire mechanics to persistence. | Partial: S06-01 fixed, A24-03 class remains. | Fails C6 because stores own spec mechanics; weak C7 due raw numeric protocol values. |
| 2 | Keep raw status codes but clamp `429` to `404` in `MapAAuthEventEndpoint`. | Avoids public API churn. | Still permits other invalid statuses; hides rather than removes the unsafe seam; store tests continue to encode wire details. | Partial: closes this exact status but not the AP response contract. | Poor C1/C6; a compatibility shim by another name. |
| 3 | Replace `EventAcceptance(int StatusCode, ...)` with a typed outcome (`Accepted`, `Duplicate`, `Unknown`, `Expired`, `Exhausted`, `Forbidden`) and have the endpoint map outcomes to spec statuses. `Accepted`/exact `Duplicate` return `202`; `Unknown`/`Expired`/`Exhausted` return `404`; `Forbidden` returns `403`; storage exceptions remain `503`. | SDK owns AP wire mechanics; stores report durable state only; prevents stale `429`; typed protocol seam is testable. | Breaking API for custom `IAgentProviderEventStore` implementations; needs sample/test/doc updates. | Strong for A24-03/S06-01 and aligns #event-delivery L437-L441. | Strong C1, C6, C7; raw status indirection removed. |
| 4 | Treat missing subscription/event bodies as an empty JSON object but continue requiring `content-digest` for all signed requests. | Fixes only JSON parser rejection when clients send an empty-body digest. | Still rejects conforming no-payload event delivery without digest; `SendAsync` keeps emitting body headers on bodyless GET/POST. | Partial for A24-01; fails A24-02. | Weak C6: SDK producer remains non-conformant. |
| 5 | Compute required signature components from actual body presence and make JSON parsing optional. No body means no `content-type`/`content-digest` requirement and subscription parameters are an empty `JsonObject`; a body means both components are required and parsed as JSON. `SendAsync` omits `HttpContent` and extra components when `body is null`, but keeps JSON body signing when bytes are supplied. Default subscription validation accepts only empty parameters when no delegate is configured. | Fixes conforming no-body subscriptions and no-payload events; producer and verifier agree; body-bearing payloads stay strongly bound. | `SendAsync(..., body: null)` changes wire shape for existing sample local GET/ack calls; tests must assert no-body verification. | Strong for A24-01/A24-02 and consistent with #covered-components L2211-L2214. | Strong C2/C6; no consumer HTTP plumbing (C8); no compat overloads (C1). |

## Recommendation

Adopt **3 + 5** as one cutover. Events should distinguish persistence outcomes from protocol mechanics: stores return typed durable outcomes, while SDK endpoints decide status codes and response bodies. Separately, `EventsProtocol` should decide body-bound signature components from body presence, not from a stale Events profile assumption that empty bodies are signed as zero-length JSON. This closes all four findings and avoids teaching store authors or sample readers the wrong retry semantics.

Adversarial closure: a malicious or buggy resource might replay a distinct `jti` after seeing `remaining_uses: 0`; the typed `Exhausted` outcome always maps to `404`, so the resource gets a non-retryable cleanup signal. A conforming no-payload resource might omit both payload and digest; verifier required-components is empty for bodyless delivery, but the event JWT, `Signature-Key`, HTTP signature base components, issuer/resource binding, `eid`, `aud`, and `exp` are still enforced before store acceptance. A client that sends bytes without signing digest/type remains rejected because any body-bearing request requires both components.

## Public API delta

- **Changed:** `public sealed record EventAcceptance(int StatusCode, long? RemainingUses = null)` becomes `public sealed record EventAcceptance(EventAcceptanceOutcome Outcome, long? RemainingUses = null)`.
- **Added:** `public enum EventAcceptanceOutcome { Accepted, Duplicate, Unknown, Expired, Exhausted, Forbidden }` in `AAuth.Events`.
- **Behavioral change:** `AAuthSubscriptionEndpointOptions.ValidateParameters` remains `Func<JsonObject, bool>?`, but `null` no longer fails endpoint mapping. Default validation accepts an empty parameter object and rejects non-empty bodies. If a channel defines parameters, the host still supplies `ValidateParameters`.
- **Behavioral change:** `EventsProtocol.SendAsync(..., byte[]? body = null, ...)` now treats `null` as no HTTP content and no body-bound signed components; callers pass `[]` only when they intentionally send an empty JSON payload.
- ApiSurface impact: breaking signature for `EventAcceptance` construction and any custom `IAgentProviderEventStore.Accept` return values; no new overloads or shims per C1.

## Wire effect

- Protected or public subscription POST with no body and no `Content-Type`/`Content-Digest` can succeed when the subscribe token, HTTP signature, ticket, and empty-parameter validation pass.
- Subscription POST with a body still requires signed `content-type` and `content-digest`, parses JSON, and returns `400 invalid_request` for malformed JSON or schema mismatch.
- Event delivery with no payload can be signed and accepted without `Content-Type` or `Content-Digest`.
- Event delivery with a payload still requires signed `content-type` and `content-digest`; tampered body remains `401` from signature verification.
- AP store outcomes map to: `Accepted`/`Duplicate` → `202` (with `remaining_uses` when bounded); `Unknown`/`Expired`/`Exhausted` → `404 event_rejected`; `Forbidden` → `403 event_rejected`; store exceptions → `503 temporarily_unavailable`. `429` is never produced by the SDK Events AP.

## Implementation sketch

1. **Body detection helper:** in `EventsProtocol`, add a private helper such as `HasHttpBody(HttpRequest request)` that returns true for positive `Content-Length`, chunked/transfer-encoded bodies, or a present `Content-Type`. Treat absent length/type/transfer as omitted body. Use it to set `RequiredComponents` to `[]` or `["content-type", "content-digest"]` (`EventsProtocol.cs:55-L69`). Preserve the base signature headers check.
2. **Producer symmetry:** update `EventsProtocol.SendAsync` (`EventsProtocol.cs:92-L98`) so `body is null` leaves `HttpRequestMessage.Content` null and does not set `AAuthSigningHandler.AdditionalComponentsKey`; `body is not null` creates `ByteArrayContent`, sets `application/json`, and signs `content-type`/`content-digest`.
3. **Optional subscription JSON:** in `EventsEndpoints.MapSubscriptionCore`, replace the unconditional `ReadFromJsonAsync`/null rejection (`EventsEndpoints.cs:86-L89`) with: if `HasHttpBody` is false, use `new JsonObject()`; otherwise parse JSON and reject malformed input. Default `validateParameters` to `parameters => parameters.Count == 0` when the option is null, instead of throwing at map time (`EventsEndpoints.cs:72-L73`). Keep protected-ticket lookup and JWK thumbprint enforcement unchanged (#pre-authorized-subscription-url-security L597-L604).
4. **Typed AP acceptance:** in `EventStores.cs`, add `EventAcceptanceOutcome` and change `EventAcceptance` to carry `Outcome`. Update `EventsEndpoints.MapAAuthEventEndpoint` (`EventsEndpoints.cs:47-L53`) to switch over `Outcome` and create the spec status. Only `Accepted` and `Duplicate` may include `remaining_uses`.
5. **Sample store:** update `samples/EventSupport/SqliteEventStore.cs` so unknown/expired subscription rows return `Unknown`/`Expired`, resource/agent mismatch returns `Forbidden`, exact existing `(iss,jti,body_hash)` returns `Duplicate` with the same remaining-use value, exhausted quota returns `Exhausted`, and a newly persisted event returns `Accepted`. For direct store checks that currently return `400` for impossible expired-token or changed-body states, use `Forbidden` or throw an application exception that the endpoint maps to `503`; do not reintroduce raw status codes.
6. **Tests and sample call sites:** update all `new EventAcceptance(...)` and `.StatusCode` assertions to use `Outcome`; update HTTP assertions from `429` to `404`; add no-body subscription and no-payload event coverage before changing docs.

## Tests

- `tests/AAuth.Events.Tests/EventHttpTests`:
  - Extend `HttpStatusQuotaUnlimitedUnknownAndWrongAudience`: after a bounded first accepted event reports `remaining_uses: 0`, a distinct second `jti` returns `404 NotFound`, not `429`. Negative control is the audit's max_uses=1 second event scenario.
  - Add `NoPayloadEventDeliveryOmitsDigestAndBody`: create a subscription, build an event token, send a POST with `Signature-Key: self-jwt`, `Signature-Input`, and `Signature` covering only base components plus `signature-key`, no `HttpContent`, no `Content-Digest`, and assert `202` plus empty stored `Body`.
  - Keep/extend `TamperedActualBodyOrMismatchedHttpKeyFails` to prove body-bearing events still reject unsigned/tampered payload bytes.
  - Add `SubscriptionTicketAcceptsNoBodyWhenNoParameters`: protected ticket + subscribe token, signed request with no body/digest/type, channel `ValidateParameters = p => p.Count == 0`, assert `200` and ticket consumed. Negative controls: non-empty body with no validator returns `400`; body bytes missing digest/type fail verification.
  - Add a `SendAsyncNullBodyOmitsContentHeaders` assertion by inspecting `LastSignatureInput` for a no-body delivery/local GET: no `content-type`/`content-digest` entries.
- `tests/AAuth.Events.Tests/EventPersistenceTests`:
  - Replace raw status expectations with `EventAcceptanceOutcome` assertions. `ConcurrentQuotaIsAtomicAndRetriesSurviveRestart` should count `Accepted` and `Exhausted`, not `202` and `429`.
  - Add an explicit exact-duplicate assertion for `Duplicate` (or assert endpoint-equivalent `202` separately) so duplicate handling remains no-quota-spend.
- `tests/AAuth.Events.Tests/EventsDependencyInjectionTests`:
  - Add endpoint mapping coverage that omitting `ValidateParameters` no longer throws and a bodyless signed subscription can use the default empty-parameter policy; keep a non-empty body rejection test.
- No `dotnet build/test/restore` in this design phase. Implementation phase should run targeted `dotnet test tests/AAuth.Events.Tests` first, then the ASP gate suite required by C13.

## Samples and docs to update

- `samples/EventSupport/SqliteEventStore.cs`: migrate to `EventAcceptanceOutcome`; remove `new(429)` at line 89 and all raw status returns from `Accept`.
- `samples/EventSupport/BookingsEvents.cs`: verify payload-carrying deliveries still pass `body`; no wire change needed unless adding a no-payload demonstration.
- `samples/EventSupport/LocalEventProvider.cs`: no direct code change expected, but regression-test local GET and ack paths because `EventsProtocol.SendAsync(body: null)` will stop sending zero-length JSON bodies.
- `src/AAuth.Events/README.md`: replace the current statement that empty bodies use the digest of zero bytes; document bodyless Events requests omit `content-type`/`content-digest`, while body-bearing requests sign both. Update provider obligations to describe typed acceptance outcomes instead of raw status codes.
- `docs/workflows/events.md`: change the AP status paragraph at lines 75-L79 from `429 for exhausted quota` to `404 for unknown, expired, or exhausted subscriptions`; retain `remaining_uses: 0` as the in-band exhaustion signal.
- `samples/GuidedTour/TourSession.Capabilities.cs` and `samples/GuidedTour/TourSession.cs`: grep hits describe body-bearing sample calls that cover `content-type`/`content-digest`; review wording but no mandatory change unless it states all subscription/event requests require those components.

## Dependencies and conflicts with other Rnn

- Depends on R13 only for shared HTTP-signature behavior: the Events helper should use the existing `AAuthSigningHandler.AdditionalComponentsKey` and verifier challenge machinery, not invent a new signer path.
- No conflict with R16 identifier validation; issuer/AP URL validation stays in `EventsTokens` and `MetadataClient`.
- The typed outcome pattern is local to Events AP acceptance. Do not silently apply it to `RegistrationResult` unless a separate finding requires subscription registration status rework.
- If R11 changes shared error codes/challenges, ensure body-bearing missing digest/type still returns the shared signature `invalid_input` shape; this design only changes which components Events asks the verifier to require.

## Open questions (with proposed default)

1. **How should an exact duplicate be represented on the wire?** Default: store returns `Duplicate` with the previously computed `RemainingUses`; endpoint maps it to the same `202` shape as the original accepted delivery without incrementing quota.
2. **How should direct store calls report impossible invalid-token states currently represented as `400`?** Default: token validation belongs to `EventsProtocol`; stores should return `Forbidden` only for persisted binding conflicts and throw for persistence/policy failures. Endpoint-level malformed/signature failures remain `400`/`401` before the store.
3. **What counts as body-bearing when `Content-Length: 0` is present?** Default: treat it as no body unless `Content-Type` or transfer encoding indicates a body. Senders that intentionally sign an empty JSON body pass `Array.Empty<byte>()`, producing content headers and digest.
