---
title: R3 Latest Spec Conformance Implementation Plan
description: Phased plan to align the AAuth.R3 preview implementation with the latest upstream R3 draft.
ms.date: 2026-06-26
ms.topic: concept
---

## Overview

Align the existing `AAuth.R3` preview library and Rich Trip Booking sample with
the latest upstream AAuth R3 draft. The current MCP flow works and the focused
R3 tests pass, but the post-implementation review found several conformance gaps
that should be closed before treating the sample as draft-faithful.

This follow-up keeps the existing architectural decisions from
[../2026-06-19-r3-guided-tour-scenario/implementation-plan.md](../2026-06-19-r3-guided-tour-scenario/implementation-plan.md):

* No R3-specific models or claims are added to `src/AAuth`; generic Person
  Server extensibility may live there when needed by the sample.
* `AAuth.R3` remains an extraction-ready preview library under `samples/`.
* The implemented vocabulary remains MCP only.
* Bookings remains the live mock resource for the Rich Trip Booking scenario.

See [research.md](research.md) for the latest upstream spec delta and the
conformance findings that drive this plan.

## Cross-Cutting Decisions

* Preserve MCP-only scope for this pass. Document non-MCP vocabularies as out of
  scope rather than partially modeling them.
* Preserve byte-based content addressing. Do not introduce JSON canonicalization.
* Keep resource trust policy resource-owned. The R3 endpoint helper verifies the
  HTTP Message Signature and exposes the caller; the resource still decides which
  AS and PS fetchers are trusted.
* Treat audit logging as part of AS token issuance. A configured audit failure
  must prevent auth-token issuance.
* Keep existing GuidedTour behavior stable while correcting underlying R3 model
  and enforcement details.

## Phase 1: Spec Delta Documentation

### Goal

Document the latest upstream drift and make the MCP-only implementation scope
explicit in local docs and comments that describe R3 support.

| File | Action |
|------|--------|
| [../../../aauth-spec/v02/draft-hardt-aauth-r3.md](../../../aauth-spec/v02/draft-hardt-aauth-r3.md) | Optional: sync the AsyncAPI wording from upstream if this repo wants local spec files current |
| [../../../samples/AAuth.R3/AAuth.R3.csproj](../../../samples/AAuth.R3/AAuth.R3.csproj) and nearest package docs | Add or update a note that the preview library implements MCP only |
| [../../../docs/workflows/rich-resource-requests.md](../../../docs/workflows/rich-resource-requests.md) | Mention latest upstream AsyncAPI/AAuth Events drift as future scope if the workflow page discusses standard vocabularies |
| [../../../samples/GuidedTour/README.md](../../../samples/GuidedTour/README.md) | Keep the Rich Trip Booking description scoped to MCP |
| [../../../samples/MockResourceServers/Bookings/Program.cs](../../../samples/MockResourceServers/Bookings/Program.cs) | Keep the operation validation contract visible: `r3_operations` must be checked against the MCP tool set before issuing a resource token |

### Implementation Decisions

The upstream delta is currently AsyncAPI-only. This plan should not add AsyncAPI
models or AAuth Events logic. If the local spec file is not synced, record that
decision in the docs or PR notes so reviewers know the implementation was still
validated against upstream `main`.

The latest-draft operation validation and operations-spanning requirements are
also part of the baseline. Bookings exercises operation validation against a
single MCP tool set. Multi-definition composition is not exercised by this demo
and should be documented as future scope for resources that split operations
across internal R3 definitions.

### Definition of Done

- [x] Documentation states that current `AAuth.R3` support is MCP-only.
- [x] Bookings' `r3_operations` validation is documented as checking requested
      tools against its MCP tool set before issuing a resource token.
- [x] Multi-definition R3 document composition is explicitly named as not
      exercised by this single-definition demo.
- [x] Any local spec-sync decision is recorded: either update the checked-in v02
      draft with upstream AsyncAPI text or explicitly defer it.
- [x] No implementation code is added for AsyncAPI in this phase.

## Phase 2: Fix `display.irreversible` Shape

### Goal

Make R3 display serialization conform to the draft by representing
`display.irreversible` as optional plain-language text instead of a boolean.

| File | Action |
|------|--------|
| [../../../samples/AAuth.R3/Model/R3Display.cs](../../../samples/AAuth.R3/Model/R3Display.cs) | Change `Irreversible` from `bool?` to `string?` |
| [../../../samples/MockResourceServers/Bookings/Program.cs](../../../samples/MockResourceServers/Bookings/Program.cs) | Omit `Irreversible` where no irreversible action applies, or provide explanatory text where it does |
| [../../../samples/MockPersonServer/FederatedPendingStore.cs](../../../samples/MockPersonServer/FederatedPendingStore.cs) | Change `R3ConsentDisplay.Irreversible` from `bool?` to `string?` so the consent record mirrors the R3 display shape |
| [../../../samples/MockPersonServer/Program.cs](../../../samples/MockPersonServer/Program.cs) | Replace `.Value` rendering with optional string rendering and HTML-encode the irreversible text in the consent view |
| [../../../tests/AAuth.R3.Tests/R3ModelTests.cs](../../../tests/AAuth.R3.Tests/R3ModelTests.cs) | Add serialization and round-trip coverage for string `display.irreversible` |
| [../../../tests/AAuth.R3.Tests/R3TestHelpers.cs](../../../tests/AAuth.R3.Tests/R3TestHelpers.cs) | Update fixtures that currently assign booleans |

### Implementation Decisions

Use `string?` rather than a custom type. The draft asks for human-readable text,
and `null` cleanly represents an omitted optional field.

Because the new value is resource-controlled free text, every Person Server
consent rendering path must HTML-encode it. The existing boolean interpolation was
safe by type; the string version is not safe unless encoded like the adjacent
optional display rows.

### Definition of Done

- [x] `R3Display.Irreversible` serializes as a JSON string when present.
- [x] Bookings no longer emits boolean `display.irreversible` values.
- [x] `R3ConsentDisplay.Irreversible` in MockPersonServer uses `string?`.
- [x] Person Server consent HTML encodes irreversible text before rendering.
- [x] R3 model tests cover the corrected field shape.
- [x] Existing GuidedTour and R3 tests pass after fixture updates.

## Phase 3: Add AS R3 Audit Logging

### Goal

Satisfy the AS processing and audit integrity requirements by recording R3 token
issuance metadata atomically with auth-token issuance.

| File | Action |
|------|--------|
| [../../../samples/AAuth.R3/R3AccessTokenEndpoint.cs](../../../samples/AAuth.R3/R3AccessTokenEndpoint.cs) | Add audit sink option and call it before returning a minted auth token |
| New `samples/AAuth.R3/R3Audit.cs` | Define a small audit record and sink abstraction, for example `R3TokenIssuanceAuditRecord` and `IR3AuditSink` |
| [../../../samples/MockAccessServer/Program.cs](../../../samples/MockAccessServer/Program.cs) | Wire a sample in-memory audit sink for R3 mode if useful for diagnostics |
| [../../../tests/AAuth.R3.Tests/AccessEndpointR3Tests.cs](../../../tests/AAuth.R3.Tests/AccessEndpointR3Tests.cs) | Assert audit records include `r3_uri`, `r3_s256`, agent id, resource issuer, timestamp, and issuance kind |

### Implementation Decisions

Audit should be opt-in for hosting, but token issuance must fail when a
configured audit sink fails. For the preview library, a no-op default is
acceptable only if the documentation clearly says production deployments must
configure a durable sink. Tests should exercise the configured-sink path. The
spec-required fields are `r3_uri`, `r3_s256`, agent identifier, and timestamp;
resource issuer, AS issuer, and issuance kind are useful preview-library
superset fields.

### Definition of Done

- [x] `R3AccessTokenEndpoint` can write an audit record for class R3 token
      issuance and per-call proposal token issuance.
- [x] Audit record includes at least `r3_uri`, `r3_s256`, agent identifier,
      resource issuer, AS issuer, timestamp, and issuance kind.
- [x] If the configured audit sink throws, the endpoint does not return a minted
      auth token.
- [x] Tests cover successful audit and audit-failure behavior.

## Phase 4: Implement Digest Parameter Binding

### Goal

Support the draft's large/sensitive payload path by verifying digest-backed
proposal parameters against bytes presented on retry.

| File | Action |
|------|--------|
| [../../../samples/AAuth.R3/Model/R3Parameter.cs](../../../samples/AAuth.R3/Model/R3Parameter.cs) | Keep digest object shape and add helper APIs if needed for digest validation |
| [../../../samples/AAuth.R3/R3Enforcement.cs](../../../samples/AAuth.R3/R3Enforcement.cs) | Replace whole-proposal-hash-only retry verification with explicit inline and digest parameter matching |
| [../../../samples/MockResourceServers/Bookings/Program.cs](../../../samples/MockResourceServers/Bookings/Program.cs) | Use the shared verifier for retry matching, including digest-backed values if the sample adds one |
| [../../../tests/AAuth.R3.Tests/ResourceR3Tests.cs](../../../tests/AAuth.R3.Tests/ResourceR3Tests.cs) | Add positive and negative tests for digest-backed parameters |

### Implementation Decisions

Represent retry data with a structure that can carry both parsed JSON parameters
and raw bytes for digest-backed parameters. Inline JSON values should still be
matched structurally against the approved proposal. Digest objects should be
matched by computing `BASE64URL(SHA-256(presented-value-bytes))` and comparing it
to the stored `s256`.

### Definition of Done

- [x] Inline parameter retry matching still rejects changed JSON values.
- [x] Digest-backed parameter retry matching accepts the correct presented bytes.
- [x] Digest-backed parameter retry matching rejects changed presented bytes.
- [x] Bookings continues to reject a `book_trip` retry whose approved proposal
      does not match the submitted parameters.

## Phase 5: Correct Reusable Conditional Challenge Output

### Goal

Make the reusable enforcement helper capable of emitting the draft-required
`AAuth-Requirement` challenge with a resource token referencing the proposal.

| File | Action |
|------|--------|
| [../../../samples/AAuth.R3/R3Enforcement.cs](../../../samples/AAuth.R3/R3Enforcement.cs) | Replace or extend `ToResult()` so conditional decisions can include a real challenge header and resource token |
| [../../../samples/AAuth.R3/R3Challenge.cs](../../../samples/AAuth.R3/R3Challenge.cs) | Reuse resource-token minting for conditional proposal challenges |
| [../../../samples/MockResourceServers/Bookings/Program.cs](../../../samples/MockResourceServers/Bookings/Program.cs) | Optionally reduce duplicated challenge code if the helper now covers the Bookings path cleanly |
| [../../../tests/AAuth.R3.Tests/ResourceR3Tests.cs](../../../tests/AAuth.R3.Tests/ResourceR3Tests.cs) | Assert conditional helper output includes `AAuth-Requirement` with a resource token, not only JSON `r3_uri`/`r3_s256` |

### Implementation Decisions

Avoid hiding resource-token signing requirements inside a parameterless
`ToResult()`. Prefer an overload or companion method that receives an `HttpContext`
and an `R3Challenge` or callback capable of minting the proposal resource token.
Keep the existing decision object useful for tests and non-HTTP callers.

### Definition of Done

- [x] Reusable conditional challenge path emits `AAuth-Requirement` with a
      resource token whose payload carries the proposal `r3_uri` and `r3_s256`.
- [x] The helper no longer encourages JSON-only conditional challenges.
- [x] Bookings behavior remains unchanged or becomes simpler through the shared
      helper.
- [x] Tests verify the challenge header can be parsed by `AAuthRequirementHeader`.

## Phase 6: Focused Validation And Regression Checks

### Goal

Validate that conformance fixes do not regress the completed GuidedTour R3 flow
or existing R3 tests.

| Check | Command |
|-------|---------|
| R3 unit tests | `dotnet test tests/AAuth.R3.Tests/AAuth.R3.Tests.csproj --no-restore` |
| Relevant solution build | `dotnet build AAuth.slnx --no-restore` |
| GuidedTour R3 E2E | `cd tests/e2e && npx playwright test --project=guided-tour rich-request.spec.ts` |
| Optional broader GuidedTour check | `cd tests/e2e && npx playwright test --project=guided-tour home.spec.ts rich-request.spec.ts` |

### Definition of Done

- [x] Focused R3 unit tests pass.
- [x] Relevant build passes.
- [x] GuidedTour RichRequest E2E passes or any environment blocker is documented.
- [x] Research is updated with any new facts discovered during implementation.

## Out Of Scope

| Item | Reason |
|------|--------|
| Implementing AsyncAPI and AAuth Events | Latest upstream drift affects future AsyncAPI support, not the MCP demo path |
| Implementing OpenAPI, gRPC, GraphQL, WSDL, or OData | Larger vocabulary expansion outside this conformance pass |
| Moving `AAuth.R3` into `src/` | Existing architecture keeps R3 as a preview library under `samples/` |
| Rewriting the Rich Trip Booking scenario | Current scenario remains valid once conformance gaps are fixed |
| Changing the trusted AS + PS fetch decision | Existing plan documents this as a deliberate resolution of draft tension between AS-only access text and PS processing text |