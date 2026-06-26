---
title: R3 Latest Spec Conformance Research
description: Research on the latest upstream AAuth R3 draft changes and implementation conformance gaps.
ms.date: 2026-06-26
ms.topic: concept
---

## Purpose

Capture the June 2026 follow-up research for aligning the `AAuth.R3` preview
library and Rich Trip Booking sample with the latest upstream AAuth R3 draft.
This research builds on the completed GuidedTour R3 scenario plan at
[../2026-06-19-r3-guided-tour-scenario/research.md](../2026-06-19-r3-guided-tour-scenario/research.md)
and focuses on spec drift plus post-implementation conformance findings.

The implementation plan for this follow-up work lives in
[implementation-plan.md](implementation-plan.md).

## Source Baseline

| Source | Location | Notes |
|--------|----------|-------|
| Latest upstream R3 draft | <https://github.com/dickhardt/AAuth/blob/main/draft-hardt-aauth-r3.md> | User-requested validation target, fetched on 2026-06-26 |
| Local checked-in R3 draft | [../../../aauth-spec/v02/draft-hardt-aauth-r3.md](../../../aauth-spec/v02/draft-hardt-aauth-r3.md) | Close to upstream, with one current content drift around AsyncAPI |
| Current R3 implementation | [../../../samples/AAuth.R3](../../../samples/AAuth.R3) | Extraction-ready preview library under `samples/` |
| Demo implementation | [../../../samples/MockResourceServers/Bookings](../../../samples/MockResourceServers/Bookings), [../../../samples/MockAccessServer](../../../samples/MockAccessServer), [../../../samples/MockPersonServer](../../../samples/MockPersonServer) | Live mock-server R3 flow used by GuidedTour scenario 10 |
| Existing R3 scenario plan | [../2026-06-19-r3-guided-tour-scenario/implementation-plan.md](../2026-06-19-r3-guided-tour-scenario/implementation-plan.md) | Historical plan with completed phases and prior decisions |

## Latest Upstream Spec Updates

The local v02 draft and the latest upstream raw draft were compared on
2026-06-26. The checked-in v02 document differs from upstream `main` only in the
AsyncAPI vocabulary section and an added informational reference.

| Area | Upstream change | Implementation effect |
|------|-----------------|-----------------------|
| AAuth Events reference | Adds `I-D.hardt-aauth-events` as a referenced draft | No code effect for the current MCP-only implementation |
| AsyncAPI vocabulary wording | Changes AsyncAPI description from a generic event-driven interface to resources that emit events | No code effect unless AsyncAPI vocabulary support is added later |
| AsyncAPI `action` field | Changes `action` from required to optional, with `send` or `receive` values when present | Future AsyncAPI model must treat `action` as optional |
| AsyncAPI subscriptions | States that R3-granted subscriptions use the AAuth Events protocol and a subscription ticket URL | Future AsyncAPI support needs an AAuth Events handoff design |

The latest upstream drift does not change the MCP wire shape used by the current
Rich Trip Booking implementation. The larger conformance gaps below come from
normative R3 text already present in the local v02 draft.

## Current Implementation Shape

The implementation already covers the core MCP happy path.

* `R3Request` creates the `r3_operations` authorization body.
* `R3Hash` computes `r3_s256` over exact served bytes.
* `R3DocumentEndpoint` requires signed fetches and lets the resource apply a
  trusted-fetcher predicate.
* `R3FetchClient` signs AS or PS fetches and verifies the fetched bytes against
  `r3_s256`.
* `R3AccessTokenEndpoint` verifies agent and resource tokens, fetches R3, splits
  operations into granted and conditional sets, and mints R3 auth-token claims.
* Bookings publishes R3 metadata, accepts `POST /authorize` with
  `r3_operations`, persists R3/proposal bytes, and enforces MCP operations from
  `r3_granted` and `r3_conditional`.

Focused validation run on 2026-06-26:

```text
dotnet test tests/AAuth.R3.Tests/AAuth.R3.Tests.csproj --no-restore
Test summary: total: 23, failed: 0, succeeded: 23, skipped: 0
```

The test suite verifies the implemented contract, but it does not yet cover every
normative requirement in the latest draft.

## Conformance Findings

### AS audit logging

The draft requires the AS to record `r3_uri` and `r3_s256` alongside token
issuance metadata, including the agent identifier and timestamp. It also requires
audit log integrity: token issuance must not succeed without the corresponding
audit log entry. The current `R3AccessTokenEndpoint` mints tokens without an audit
store or callback surface.

Relevant implementation surface:

* [../../../samples/AAuth.R3/R3AccessTokenEndpoint.cs](../../../samples/AAuth.R3/R3AccessTokenEndpoint.cs)
* [../../../tests/AAuth.R3.Tests/AccessEndpointR3Tests.cs](../../../tests/AAuth.R3.Tests/AccessEndpointR3Tests.cs)

The sample needs a minimal audit abstraction before it can claim conformance with
the AS processing and audit integrity requirements.

### `display.irreversible` type

The draft defines `display.irreversible` as a plain-language description of
actions that cannot be undone. The current model represents it as `bool?`, and
Bookings serializes `false`. That produces a non-conformant R3 document even
though the rest of the display object is well formed.

Relevant implementation surface:

* [../../../samples/AAuth.R3/Model/R3Display.cs](../../../samples/AAuth.R3/Model/R3Display.cs)
* [../../../samples/MockResourceServers/Bookings/Program.cs](../../../samples/MockResourceServers/Bookings/Program.cs)
* [../../../tests/AAuth.R3.Tests/R3ModelTests.cs](../../../tests/AAuth.R3.Tests/R3ModelTests.cs)

The model should change to `string?`. Samples can omit the field when no action is
irreversible, or provide explanatory text when it applies.

The type change also affects the Person Server consent path. `R3ConsentDisplay`
currently mirrors `display.irreversible` as `bool?`, and the consent HTML renders
`display.Irreversible.Value`. Once the field becomes resource-controlled text,
that value must be HTML-encoded like the adjacent optional display rows. Otherwise
the fix would introduce a stored-XSS path through R3 display content.

Relevant Person Server surface:

* [../../../samples/MockPersonServer/FederatedPendingStore.cs](../../../samples/MockPersonServer/FederatedPendingStore.cs)
* [../../../samples/MockPersonServer/Program.cs](../../../samples/MockPersonServer/Program.cs)

### Per-call digest parameter binding

The draft allows large or sensitive proposal parameters to be represented by a
digest object containing `s256`, `excerpt`, and `media_type`. On retry, the
resource must verify that the presented value bytes hash to the stored `s256`.

The current implementation binds inline parameters by reconstructing the whole
proposal document and comparing its document hash. That is useful for inline JSON,
but it does not implement the digest-object path because the full presented value
is never separately hashed against the stored parameter digest.

Relevant implementation surface:

* [../../../samples/AAuth.R3/Model/R3Parameter.cs](../../../samples/AAuth.R3/Model/R3Parameter.cs)
* [../../../samples/AAuth.R3/R3Enforcement.cs](../../../samples/AAuth.R3/R3Enforcement.cs)
* [../../../samples/MockResourceServers/Bookings/Program.cs](../../../samples/MockResourceServers/Bookings/Program.cs)
* [../../../tests/AAuth.R3.Tests/ResourceR3Tests.cs](../../../tests/AAuth.R3.Tests/ResourceR3Tests.cs)

The follow-up work needs an explicit way for resources to supply presented bytes
for digest-backed parameters. The retry verifier should compare inline parameters
structurally and digest parameters by hashing the presented bytes.

### Reusable conditional challenge helper

The draft says an operation matched in `r3_conditional` must trigger an
`AAuth-Requirement` response containing a resource token that references the
proposal via `r3_uri` and `r3_s256`. Bookings does this directly in its endpoint.
The reusable `R3EnforcementDecision.ToResult()` helper only emits JSON with the
proposal URI and hash, with no `AAuth-Requirement` header and no resource token.

Relevant implementation surface:

* [../../../samples/AAuth.R3/R3Enforcement.cs](../../../samples/AAuth.R3/R3Enforcement.cs)
* [../../../samples/AAuth.R3/R3Challenge.cs](../../../samples/AAuth.R3/R3Challenge.cs)
* [../../../samples/MockResourceServers/Bookings/Program.cs](../../../samples/MockResourceServers/Bookings/Program.cs)

This is not a Bookings runtime bug today because Bookings hand-rolls the correct
challenge. It is a reusable-library conformance gap that can mislead future
resources.

### Vocabulary scope

The latest R3 draft defines seven standard vocabularies: MCP, OpenAPI, gRPC,
GraphQL, AsyncAPI, WSDL, and OData. The preview library intentionally supports
MCP only. That scope remains acceptable for the demo, but the implementation and
documentation should be explicit that `AAuth.R3` is an MCP-focused preview rather
than a complete implementation of every standard vocabulary.

The upstream AsyncAPI update does not require immediate code changes while MCP is
the only supported vocabulary. If additional vocabularies are added later,
AsyncAPI should use the latest upstream shape with optional `action` and an AAuth
Events handoff for subscriptions.

### Operation validation

The draft requires the resource to validate declared operations against its
authoritative definition before issuing a resource token. For the current MCP
demo, Bookings should continue to validate `r3_operations` against the same
`SupportedTools` set it exposes from `/mcp`. This is implemented today, but the
follow-up should keep it visible in tests and documentation because it is a
normative security requirement, not a convenience check.

Relevant implementation surface:

* [../../../samples/MockResourceServers/Bookings/Program.cs](../../../samples/MockResourceServers/Bookings/Program.cs)

### Operations spanning multiple definitions

The draft also requires a resource to compose a single content-addressed R3
document when requested operations span multiple internal authorization
definitions. The Rich Trip Booking sample uses one internal definition path, so
this behavior is not exercised. That is acceptable for the MCP demo if it is
documented as out of scope rather than silently omitted. Future resources with
multiple internal R3 definitions must compose and persist one combined document
for the resource token.

## Security Invariants To Preserve

The follow-up changes must preserve the invariants already achieved by the
current implementation.

* R3 and proposal documents are hashed over exact bytes as served.
* R3 document and proposal endpoints require valid HTTP Message Signatures.
* The resource owns the trusted-fetcher allowlist and rejects agents and
  untrusted callers.
* Fetch targets are origin-bound to the verified resource issuer before the AS or
  PS fetches documents.
* Resources validate requested operations against their authoritative operation
  definitions before issuing resource tokens.
* Auth tokens carry `r3_uri`, `r3_s256`, `r3_granted`, and optional
  `r3_conditional` claims.
* Conditional operations require per-call approval before serving the operation.

## Open Questions

| Question | Current direction |
|----------|-------------------|
| What audit store should the sample use? | Add a small in-memory `IR3AuditSink` suitable for tests and mock servers, with an option hook on `R3AccessTokenEndpointOptions` |
| How should audit atomicity be represented in the sample? | Make token issuance fail when the configured audit sink throws, and test that behavior |
| How should digest-backed retry values be supplied? | Add a structured retry input that can carry inline JSON parameters plus presented byte values for digest parameters |
| Should multi-definition composition be implemented now? | No; the demo uses a single definition, but docs should name composition as required for future multi-definition resources |
| Should local v02 spec be updated from upstream now? | The upstream drift is AsyncAPI-only; defer unless the broader spec-sync plan wants local docs updated |
| Should non-MCP vocabularies be implemented now? | No; keep them out of scope for this conformance pass and document MCP-only status |

## Out Of Scope For This Research

| Item | Reason |
|------|--------|
| Implementing AsyncAPI or AAuth Events | Current implementation is MCP-only, and upstream drift affects only future AsyncAPI support |
| Adding all standard vocabularies | Larger design effort, not needed to fix current conformance gaps |
| Moving `AAuth.R3` into `src/` or packaging it | Existing decision keeps R3 as an extraction-ready preview library under `samples/` |
| Reworking the GuidedTour scenario narrative | Current Rich Trip Booking flow remains compatible with latest MCP draft behavior |
| Multi-definition R3 document composition in Bookings | The demo maps requested tools through one internal definition path; future multi-definition resources must compose a single content-addressed document |