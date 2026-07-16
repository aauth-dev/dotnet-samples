# AAuth Events - Implementation Log

Append-only record for decisions, deviations, and open questions made while
implementing the approved AAuth Events research and plan.

## Decisions Taken

### [2026-07-15] [Phase 0] Owner implementation approval - RESOLVED

The owner approved implementation on branch
`feat/aauth-events-implementation`. Child-branch commits are allowed after this
approval; integration remains subject to the phase gates and owner review.

### [2026-07-15] [Phase 0] C1 role coverage - RESOLVED

The package covers AP issuance/inbox, resource registration/delivery, and agent
verification. Standard AP-to-agent transport remains out of scope.

### [2026-07-15] [Phase 0] C2 package dependency - RESOLVED

`AAuth.Events` depends only on `AAuth`. It does not depend on or modify
`AAuth.R3`; R3 is referenced only by a metadata-composition test and Bookings.

### [2026-07-15] [Phase 0] C3 agent deduplication - RESOLVED

Agent deduplication uses SHA-256 of the exact compact event token instead of the
draft's `{iss,eid}` key, which would discard later events on one subscription.

### [2026-07-15] [Phase 0] C4 event body shape - RESOLVED

The wire body is the direct AsyncAPI-defined JSON payload with
`application/json`, matching the delivery example rather than a wrapper or JWT
body.

### [2026-07-15] [Phase 0] C5 covered components - RESOLVED

Bodyless requests cover the four base components. Registration JSON also
covers `content-type`; event JSON covers `content-type` and `content-digest`.

### [2026-07-15] [Phase 0] C6 AP durability - RESOLVED

Production AP hosts must provide a durable store implementation. The package
does not register an in-memory production default.

### [2026-07-15] [Phase 0] C7 sample topology - RESOLVED

The runnable sample extends Bookings and MockAgentProvider and adds a focused
EventAgent console application.

### [2026-07-15] [Phase 0] C8 subscription lifetime - RESOLVED

Subscription lifetime is application policy represented by stored `ExpiresAt`.
No non-standard lifetime wire field is added.

### [2026-07-15] [Phase 0] C9 package versioning - RESOLVED

`AAuth.Events` tracks the `AAuth` version and is packed by the same release
workflow.

### [2026-07-15] [Phase 0] C10 EventAgent sample - RESOLVED

The focused event flow is implemented in `samples/EventAgent`; GuidedTour is
not widened.

### [2026-07-15] [Phase 0] C11 registration API layers - RESOLVED

Resource registration exposes both a low-level typed verifier and an
opinionated ASP.NET endpoint mapper with an application policy callback.

### [2026-07-15] [Phase 0] C12 registration response mapping - RESOLVED

The default mapper uses 200 success, 400 malformed, 401 signature/JWT failure,
403 audience or agent-ticket mismatch, 404 unknown/expired ticket, and 409
duplicate `eid` or reused ticket.

### [2026-07-15] [Phase 0] C13 AP failure mapping - RESOLVED

Expired or invalid event tokens map to 401; wrong event-token audience maps to
403.

### [2026-07-15] [Phase 0] C14 AP retry idempotency - RESOLVED

SHA-256 of the exact compact event token is the AP idempotency key. Exact
retries return the prior 202 outcome without another inbox write or use.

### [2026-07-15] [Phase 0] C15 outbound URL policy - RESOLVED

Events network calls require HTTPS except loopback HTTP, disable redirects,
reject private/link-local IP literals except loopback, and invoke a pluggable
trust policy.

### [2026-07-15] [Phase 0] C16 event ID generation - RESOLVED

Generated `eid` values contain at least 128 CSPRNG bits, are base64url encoded,
and are never reused by the AP.

### [2026-07-15] [Phase 0] C17 body limit - RESOLVED

Events endpoints buffer at most 1 MiB by default before verification. Hosts can
configure a different limit.

### [2026-07-15] [Phase 0] C18 AsyncAPI scope - RESOLVED

The first package supplies AAuth vocabulary/security constants, metadata
composition, and AAuth declaration validation. Applications own complete
AsyncAPI documents and schemas.

### [2026-07-15] [Phase 0] C19 sample AP-to-agent transport - RESOLVED

The sample uses agent-authenticated polling and explicitly labels it
non-normative.

### [2026-07-15] [Phase 0] C20 event issued-at validation - RESOLVED

Event `iat` is required and future-issued events are rejected using configured
clock skew at AP and agent verification.

### [2026-07-15] [Phase 0] C21 signing algorithms - RESOLVED

Events supports EdDSA and ES256 through `IAAuthKey`, emits the supplied key's
algorithm, and rejects `none` and unsupported algorithms.

### [2026-07-15] [Phase 0] C22 cross-origin event endpoint - RESOLVED

An AP `event_endpoint` may be on another HTTPS origin after the configured URL
trust policy accepts it.

### [2026-07-15] [Phase 0] C23 event token identity - RESOLVED

Every event token includes a required fresh random `jti` so legitimate
same-time events cannot collapse into the compact-token retry key. This is a
deliberate draft extension.

### [2026-07-15] [Phase 0] RF1 event-token none asymmetry - RESOLVED

The event-header omission does not permit unsigned tokens. Both token types
reject `none`.

### [2026-07-15] [Phase 0] RF2 agent payload trust - RESOLVED

Agent-facing APIs expose payloads only as unauthenticated data. Consequential
details are re-fetched through the application's normal AAuth client; no generic
Events re-fetch API is added.

### [2026-07-15] [Phase 0] RF3 registration body integrity - RESOLVED

The draft registration profile is retained for interoperability. Body data is
named and documented as signature-unbound and cannot widen the mapper's
configured channel authorization.

### [2026-07-15] [Phase 0] RF4 AsyncAPI operation direction - RESOLVED

Samples follow the draft's `action: receive`. The validator ignores operation
direction rather than treating `send` or `receive` as an AAuth validity rule.

### [2026-07-15] [Phase 0] RF5 vocabulary composition - RESOLVED

OpenAPI and AsyncAPI entries are composed in one caller-owned map before a
single `r3_vocabularies` assignment. Existing entries are preserved and
conflicts fail.

### [2026-07-15] [Phase 0] D1 package deliverable - RESOLVED

Ship one preview `AAuth.Events` package for all protocol-defined roles, excluding
standard AP-to-agent transport.

### [2026-07-15] [Phase 0] D2 production dependency boundary - RESOLVED

The production Events project references only `AAuth`; a test-only R3 reference
is permitted for RF5.

### [2026-07-15] [Phase 0] D3 idempotency surface - RESOLVED

Compact-token SHA-256 is the default key and agent deduplication remains
pluggable.

### [2026-07-15] [Phase 0] D4 payload API - RESOLVED

Direct JSON bytes are preserved and exposed to agents only through
`UnauthenticatedEventPayload`.

### [2026-07-15] [Phase 0] D5 exact HTTP profiles - RESOLVED

Standardized Events requests reject unexpected covered components.
Registration body authorization is explicitly out of scope.

### [2026-07-15] [Phase 0] D6 store requirement - RESOLVED

AP DI fails when no application store is registered; in-memory implementations
are test/sample-only.

### [2026-07-15] [Phase 0] D7 stored expiry - RESOLVED

The SDK models application-supplied `ExpiresAt` without adding a wire claim.

### [2026-07-15] [Phase 0] D8 random eid format - RESOLVED

Generated event IDs use at least 128 random bits and base64url encoding.

### [2026-07-15] [Phase 0] D9 registration defaults - RESOLVED

The endpoint mapper applies the C12 status defaults while low-level users retain
typed failures.

### [2026-07-15] [Phase 0] D10 AP delivery defaults - RESOLVED

AP delivery adds the C13 mappings and exact-token idempotent 202 behavior.

### [2026-07-15] [Phase 0] D11 Events network transport - RESOLVED

All Events metadata, JWKS, and delivery calls use an Events-owned no-redirect
client and URL policy.

### [2026-07-15] [Phase 0] D12 bounded buffering - RESOLVED

The default body limit is 1 MiB and configurable.

### [2026-07-15] [Phase 0] D13 algorithms and time - RESOLVED

Both token types support EdDSA/ES256, reject `none`, and require valid `iat`.

### [2026-07-15] [Phase 0] D14 AsyncAPI integration boundary - RESOLVED

The validator checks AAuth declarations only and does not validate operation
direction.

### [2026-07-15] [Phase 0] D15 sample scope - RESOLVED

The sample extends Bookings and MockAgentProvider, adds EventAgent, and uses
authenticated non-normative polling.

### [2026-07-15] [Phase 0] D16 one vocabulary map - RESOLVED

AsyncAPI is added to one completed vocabulary map before metadata assignment,
with no production R3 dependency.

### [2026-07-15] [Phase 0] D17 required event jti - RESOLVED

Every event token requires a fresh random `jti`; missing or empty values fail.

### [2026-07-15] [Phase 0] Execution model - RESOLVED

Implementation uses balanced parallel waves, isolated worktrees, disjoint file
ownership, child-branch commits, and non-fast-forward coordinator merges.

### [2026-07-15] [Phase 0] Payload re-fetch API - RESOLVED

Payload re-fetch remains application-owned and documentation-driven; the SDK
adds no generic resource re-fetch abstraction.

### [2026-07-15] [Phase 0] Sample polling acknowledgment - RESOLVED

Signed polling returns a non-destructive batch. A separate signed ACK removes
each processed event after verification and display.

### [2026-07-15] [Phase 0] Resource subscription factory - RESOLVED

`ResourceSubscription.FromRegistration(...)` maps verified registration facts
while the application supplies `ExpiresAt`.

### [2026-07-15] [Phase 0] Protected waitlist ticket endpoint - RESOLVED

Bookings adds `POST /waitlist/request`, protected by the existing
`searchAvailability` grant, to issue the sample ticket URL.

### [2026-07-15] [Phase 0] Pre-change validation baseline - RESOLVED

`dotnet test AAuth.slnx` passed before implementation changes: AAuth.Tests 517,
AAuth.Conformance 573, and AAuth.R3.Tests 39, with no failures or skips.

### [2026-07-15] [Phase 1] Package and token foundation - RESOLVED

Added the `AAuth.Events` preview project and tests, package-local compact JWS
writer, complete Events constants, strict subscribe/event builders and claim
readers, required agent confirmation-key binding, AgentId validation, EdDSA and
ES256 support, 128-bit random `eid`/`jti`, and the required event `jti`
extension. Seventeen token tests pass, the full solution builds, and the
production assets contain no `AAuth.R3` dependency.

### [2026-07-15] [Phase 2] Events HTTP security layer - RESOLVED

Added exact bodyless, registration, and event RFC 9421 profiles; bounded raw
body and RFC 9530 digest verification; typed errors; EdDSA/ES256 subscribe and
event key resolution; signature-only silent re-key retry; no-redirect
policy-checked transport; and URL trust rules. Review fixes prevent
deterministic claim failures from triggering JWKS refreshes and reject malformed
Authorization headers on inbound verification. Fifty-two token/HTTP tests pass
and the full solution builds without warnings.

### [2026-07-15] [Phase 3] Metadata, discovery, and AsyncAPI - RESOLVED

Added collision-safe AP metadata composition, immutable OpenAPI/AsyncAPI
vocabulary composition, policy-checked cached event-endpoint resolution, and a
focused AsyncAPI AAuth validator that deliberately ignores operation direction.
Cross-package R3 composition, issuer binding, unresolved channel references,
cache invalidation, endpoint policy, and public/protected declarations are
covered by discovery tests.

### [2026-07-15] [Phase 4] Agent Provider role contracts - RESOLVED

Added collision-retrying subscribe-token issuance, required durable store
contracts, defensive subscription/incoming-event models, atomic acceptance
outcomes, endpoint verification/status mapping, and required-store DI. Review
removed unbounded in-process ID retention and fixed content-header preservation.
Twenty-five AP tests cover issuance, mappings, durability failures,
EdDSA/ES256, cancellation, and concurrent final use.

### [2026-07-15] [Phase 5] Resource registration role - RESOLVED

Added explicit channel/context boundaries, low-level subscribe-token and HTTP
verification, signature-unbound body projection, public/protected endpoint
mapping, selected-event subset enforcement, signed registration client, and DI.
Protected paths preserve escaped PathBase values and reject missing tickets
before invoking application policy. Fourteen registration tests cover both
algorithms, binding, tickets, mappings, bodies, cancellation, and DI.

### [2026-07-15] [Phase 7] Agent verification and deduplication - RESOLVED

Added typed event verification outcomes, exact-token SHA-256 idempotency,
pluggable and bounded/expiring deduplication, defensive unauthenticated payload
projection, context lookup, and validated DI registration. Sixteen agent tests
cover both algorithms, context, replay, concurrency, payload substitution,
typed failures, expiry/capacity, and cancellation.

### [2026-07-15] [Phase 6] Resource event delivery - RESOLVED

Added immutable resource subscription state, `FromRegistration`, defensive
prepared deliveries, once-only event `jti`, current AP endpoint resolution,
exact-token/body retries with fresh HTTP signatures, and typed AP response
parsing. Review removed an artificial signature-time sequence, restored
metadata-cache semantics, and corrected C8 so application subscription lifetime
may extend beyond the subscribe-token registration window. Twenty-four delivery
tests cover both algorithms, retries, payload immutability, endpoint changes,
all response variants, malformed responses, transport failures, timeout, and
cancellation.

### [2026-07-15] [Phase 8] Cross-role conformance and API freeze - RESOLVED

Added four role-specific conformance matrices, a true in-process AP/resource/
agent flow, and an executable spec-coverage matrix for every in-scope
MUST/MUST NOT in Events L190-L617. Review corrected stored-resource/audience
validation order and made protected-ticket matching and consumption atomic.
The API-freeze gate passes: Events 278, AAuth.Tests 517,
AAuth.Conformance 573, and AAuth.R3.Tests 39, with no failures or skips; the
full solution builds with zero warnings.

### [2026-07-15] [Phase 9] Runnable Bookings/AP/EventAgent sample - RESOLVED

Extended Bookings with merged OpenAPI/AsyncAPI metadata, protected waitlist
tickets, registration, and an authenticated deterministic trigger. Extended
MockAgentProvider with the normative event endpoint and explicitly
non-normative in-memory token acquisition, polling, and ACK routes. Added
EventAgent with durable enrollment, generic challenge handling, registration,
polling, verification, deduplication, unauthenticated payload display, and ACK.
The integrated focused stack completed the full flow successfully. Review
corrected the Bookings resource URL, trigger grant ordering/lifetime, revoked
subscription state, and bodyless/empty payload handling.

### [2026-07-15] [Phase 10] Documentation and release dry run - RESOLVED

Added the Events workflow, final package/sample READMEs, root documentation and
sample indexes, focused Makefile targets, and shared release packing. The
workflow-equivalent Release gate restored, built, and ran 1,407 tests, then
packed `AAuth`, `AAuth.R3`, and `AAuth.Events` at one version. The Events nupkg
contains its README and only the matching `AAuth` dependency. Final docs review
confirmed frozen API names, routes, security disclosures, retention/durability
requirements, and the non-normative polling/ACK boundary.

### [2026-07-15] [Phase 11] Independent internal review - RESOLVED

Three disjoint read-only reviewers covered protocol/crypto, state/concurrency,
and package/sample/docs. All reported HIGH and MEDIUM findings were fixed:
bodyless AP delivery (including `Content-Length: 0`), conventional/transient
agent DI, bounded sample idempotency retention, non-empty selected event types,
and bounded outbound response reads. Follow-up reviewers reported no remaining
high-confidence findings.

The definitive Release gate restored, built, ran 1,413 tests
(AAuth.Tests 517, AAuth.Conformance 573, AAuth.R3.Tests 39, and
AAuth.Events.Tests 284), and packed all three packages at one version. The
Events package includes its README, depends only on matching-version `AAuth`,
and has no `AAuth.R3` dependency. No core/R3 production file or generated
artifact is in the implementation diff.

## Deviations from Plan

None.

### [2026-07-15] [Phase 1] AP-wide eid uniqueness moved to Phase 4 - PROCEEDED

Phase 1 proves 128-bit CSPRNG/base64url generation but cannot prove that an AP
never returns a previously stored ID without the durable subscription store.
The collision-retry requirement is therefore tested at `SubscribeTokenIssuer`
in Phase 4, where store insertion is authoritative. This changes no wire or
public token behavior.

### [2026-07-15] [Phase 6] Registration expiry is not subscription expiry - RESOLVED

The first delivery implementation incorrectly limited
`ResourceSubscription.ExpiresAt` to the subscribe token's `exp`. C8 and the
draft rationale define that `exp` only as the registration credential window.
The guard was removed and a regression test now permits the application policy
lifetime to extend beyond the token window.

### [2026-07-15] [Phase 11] Owner review gate follows child-branch commits - RESOLVED

The execution plan originally phrased owner review as preceding any commit.
The owner explicitly approved implementation-time commits on isolated child
branches. Final owner review therefore gates push/final acceptance rather than
the already-approved rollback-unit commits.

## Open Questions / Inputs Needed

None.

## Post-Code-Review Decisions

> **Appended after code review (2026-07-16):** The entries below evaluate
> findings 1-3 and deviations A-B in
> [implementation-review-report.md](implementation-review-report.md).
> `RESOLVED` means the decision is settled; pending implementation is marked
> `TODO`. No clarification was required.

### [2026-07-16] [Phase 5] Review gap 1 - resource audience must fail closed - RESOLVED

**Decision: agree.** The draft requires the resource to match the subscribe
token `aud` to its own URL
([Subscribe Token](../../../aauth-spec/v09/draft-hardt-aauth-events.md#subscribe-token),
L221 and L275). A nullable `ResourceAudience` silently disables that check, so
this is a security and conformance gap. The canonical resource identifier must
be explicit; deriving it from the request host is unsafe behind proxies or
aliases.

**TODO (code):** Make a non-empty resource audience mandatory for channel
descriptors and low-level registration verification. Fail before discovery or
handler invocation when it is absent. Add tests proving missing configuration
fails closed and a token for another resource never reaches the handler.

### [2026-07-16] [Phase 4] Review gap 2 - separate issuer lifetimes - RESOLVED

**Decision: agree.** The draft explicitly separates the subscribe-token
registration window from subscription lifetime
([Design Rationale](../../../aauth-spec/v09/draft-hardt-aauth-events.md#why-exp-is-the-jwt-validity-period-not-the-subscription-lifetime),
L681-L687). Reusing one `Lifetime` for JWT `exp` and AP
`AgentProviderSubscription.ExpiresAt` contradicts C8/D7 and forces an avoidable
security-versus-usability tradeoff.

**TODO (code):** Replace the ambiguous issuer lifetime with separate positive
token and subscription lifetime settings. Use the former for JWT `exp` and the
latter for AP `ExpiresAt`; add a short-token/long-subscription regression test
and update sample configuration accordingly. Add no wire lifetime claim.

### [2026-07-16] [Phase 9] Review gap 3 - event expiry must not expire a subscription - RESOLVED

**Decision: agree with the gap, but not with duplicating event-expiry rejection
inside the store.** `claims.ExpiresAt` is the event response window, not
subscription state ([AP Validation](../../../aauth-spec/v09/draft-hardt-aauth-events.md#event-delivery),
L411). The endpoint resolver already validates it using configured clock skew;
a second strict store check produces inconsistent status codes and must never
transition the subscription to `Expired`.

**TODO (code):** Remove event-token expiry from the sample store's subscription
expiry branch. Only stored subscription status and
`subscription.ExpiresAt` may expire the subscription. Add a regression proving
an event admitted within verifier skew cannot invalidate the subscription and
a later valid event remains acceptable; events outside skew must still fail
with 401 before the store call.

### [2026-07-16] [Phase 0] Review deviation A - required event jti - RESOLVED

**Decision: retain the strict `jti` requirement and accept the reported
interoperability consequence.** The claim is a deliberate draft extension, but
without a per-event identity two legitimate same-second events can produce the
same compact token and become indistinguishable from a retry. Accepting missing
`jti` would reintroduce that ambiguity, so no code fallback will be added.

**TODO (documentation/upstream):** Before release, state prominently that peers
must include `jti` and propose the claim for the upstream draft. Do not modify
the vendored specification as part of the SDK fix.

### [2026-07-16] [Phase 7] Review deviation B - exact-token agent deduplication - RESOLVED

**Decision: agree with the reviewer; no action.** Draft deduplication on
`{iss,eid}` ([Agent Verification](../../../aauth-spec/v09/draft-hardt-aauth-events.md#ap-to-agent),
L445) would discard every event after the first on an unlimited subscription.
Hashing the exact compact token, together with the required fresh `jti`,
distinguishes retries from later events and remains the selected C3/C14
behavior.

### [2026-07-16] [Phase 0] Post-review implementation clarifications - RESOLVED

The owner resolved the implementation-planning questions as follows:

1. **Question:** How should the `jti` upstream-spec TODO be handled?
   **Response:** Update the SDK README and draft an upstream issue/proposal for
   owner review. Do not post it during implementation.
2. **Question:** What public API shape should separate issuer lifetimes use?
   **Response:** Replace `Lifetime` with `TokenLifetime` and
   `SubscriptionLifetime`.
3. **Question:** What defaults should the new lifetime options have?
   **Response:** Keep the one-hour default for `TokenLifetime`; require callers
   to set a positive `SubscriptionLifetime`.

### [2026-07-16] [Phase 5] Post-review gap 1 implementation - RESOLVED

The pending audience action above is complete. Channel descriptors, low-level
registration verification, and subscribe-token resolution now require a
non-empty canonical resource audience. Missing or mismatched `aud` fails before
metadata/JWKS discovery; no request-host inference or compatibility overload
was added. Regression tests cover invalid configuration, zero-request
pre-discovery rejection, wrong-resource 403 mapping, and handler non-invocation.

### [2026-07-16] [Phase 4] Post-review gap 2 implementation - RESOLVED

The pending lifetime action above is complete.
`SubscribeTokenIssuerOptions.Lifetime` was replaced by a one-hour-defaulted
`TokenLifetime` and a required positive `SubscriptionLifetime`. JWT `exp` and
AP `AgentProviderSubscription.ExpiresAt` now use those values independently.
MockAgentProvider demonstrates a 300-second registration token and a
3,600-second subscription without adding a wire claim.

### [2026-07-16] [Phase 9] Post-review gap 3 implementation - RESOLVED

The pending sample action above is complete. Event-token `exp` no longer
changes subscription state; the endpoint resolver remains the sole event-expiry
validator with configured clock skew. Accepted receipts use a separate,
positive, one-hour-defaulted retention window, so a skew-accepted event remains
pollable while sample replay state stays bounded. Endpoint-level EdDSA/ES256
tests cover within-skew acceptance, later events, outside-skew 401, and
retention expiry.

### [2026-07-16] [Phase 10] Post-review jti interoperability action - RESOLVED

The pending documentation/upstream action above is complete. The package README
prominently states that v09 omits event `jti`, this SDK requires it, peers
without it are rejected, and no fallback is provided. A review-only upstream
proposal is saved as `files/aauth-events-jti-upstream-proposal.md` in the
session folder. It was not posted, and the vendored specification was not
modified.

### [2026-07-16] [Phase 11] Follow-up review decisions - RESOLVED

A fresh read-only review found and resolved two coupled issues: wrong-audience
tokens now fail before outbound discovery, and skew-accepted sample receipts
are retained independently of event-token `exp`. A subsequent review reported
no remaining high-confidence findings.

The suggestion to bump the package version or add compatibility shims was not
adopted. This is an intentionally breaking alpha SDK, compatibility shims are
prohibited by the approved plan, and the publish workflow supplies the next
release version explicitly.

### [2026-07-16] [Phase 11] Post-review validation - RESOLVED

The Release build passed. The full test gate passed 1,432 tests:
AAuth.Events.Tests 303, AAuth.Tests 517, AAuth.Conformance 573, and
AAuth.R3.Tests 39. The Events package packed as
`9.9.9-events-postreview`; its README contains the new warnings and lifetime
API, and its only package dependency is matching-version `AAuth`.

The focused MockAgentProvider/Person Server/R3 AS/Bookings/EventAgent stack
completed acquisition, protected registration, event delivery, polling,
verification, and ACK. The upstream proposal remains unposted. No commit was
created.
