---
description: Draft-11 WIP documentation and embedded-snippet impact inventory.
---

# Documentation surface map - draft-11 WIP

Analysis only, 2026-09-11, baseline `94576a3ebcba8cd1d167923e50c8796132057600`.
This map follows the draft-10 inventory pattern without claiming every embedded
block has already been enumerated or validated. Requirements and citations live
in [research.md](research.md); F labels associate the change with that evidence.
Public documentation still correctly targets draft-10 until implementation and
verification change that claim. A WIP research snapshot is not a target bump.

## Live page inventory

| Surface | Current locations | Required content change | Validation class |
|---|---|---|---|
| Product and package entry points | [README](../../../README.md), [samples README](../../../samples/README.md), [core package](../../../src/AAuth/), [R3 package](../../../src/AAuth.R3/), [Events package](../../../src/AAuth.Events/) | Five access modes, person-token leg, current supported/excluded capabilities, WIP versus published target; do not claim all companions are migrated. F02/F20/F22/F23 | Target/source consistency, links, compiled quick-start excerpts |
| Learning path | [docs index](../../../docs/README.md), [concepts](../../../docs/concepts.md), [getting started](../../../docs/getting-started.md), [glossary](../../../docs/glossary.md) | Agent/person/session/auth distinction; person continuity versus proofing; resource-visible key/person identity, not agent/actor chain. F01-F06 | Semantic review and runnable first-use scenario |
| API/configuration | [configuration](../../../docs/reference/configuration.md), [dependency injection](../../../docs/reference/dependency-injection.md) | Required new endpoint fields and builders; clock policy, role body coverage, caches, ownership, expiry/revocation storage. F02/F05/F12-F15 | Source declaration/default checks and C# compilation |
| Server contracts | [server guides](../../../docs/server/) | Token issuance, claims projection, verification, authorization policies, challenges, metadata, replay/revocation; person token must never bypass scope authorization. F01-F06/F13-F16 | Endpoint tests plus prose/HTTP examples |
| Revocation | [replay detection](../../../docs/server/replay-detection.md) | `jti/exp` body, verified caller namespace, unseen-token 200, person-to-AS cascade, expiry versus dependency. Remove cross-issuer PS override examples. F14/F15 | Parse examples and exercise actual HTTP responses |
| Signing modes | [signing-mode guides](../../../docs/signing-modes/) | Separate generic Signature Keys demonstrations from AAuth agent/server role rules; preserve Events self-JWT and AP naming-key refresh. F13/F23 | Carrier matrix tests and exact code examples |
| Standard workflows | [workflow guides](../../../docs/workflows/) | Person acquisition before Calendar/Wallet resource challenges, PS/AS presented-token forwarding, runtime step-up/202 completion; keep Inbox resource-managed flow distinct. F02-F05/F17 | Captured-wire assertions and matching diagrams |
| Missions | [missions](../../../docs/advanced/missions.md), [governance clients](../../../docs/advanced/mission-governance-clients.md), [mission workflow](../../../docs/workflows/mission-governed-access.md) | Encoded approval, hash of decoded blob, optional resource-keyed person-token map, no AAuth-Mission, accepted updates and new completion URL, terminal reasons/expiry. F07-F10 | Blob hash tests, compiled client examples, actual consent workflow |
| Chaining and workers | [advanced guides](../../../docs/advanced/), [workflow guides](../../../docs/workflows/), [worker scenario](../../../samples/FederatedWorkerScenario.cs) | Upstream `ps` routing, parent-issued worker person token, no resource actor chain. Keep Q3-Q5 caveats visible until resolved. F11/F20 | Distinct-key/person tests and both-app flows |
| R3 and Catalog | [R3 workflow](../../../docs/workflows/rich-resource-requests.md), [Catalog guide](../../../docs/workflows/catalog-gateway.md) | PerCall rename, remove document Version and OpenAPI Gateway standard contract, redesign Catalog discovery, seven vocabularies; preserve raw-byte hashing. F17-F19 | JSON/schema/claim checks, executed Catalog and Bookings scenarios |
| Errors, interaction and observability | [error handling](../../../docs/advanced/error-handling.md), [interaction chaining](../../../docs/advanced/interaction-chaining.md), [clarification](../../../docs/advanced/clarification-chat.md), [observability](../../../docs/advanced/observability.md) | Presented-token errors, truthful revocation, AS relay versus unavailability, clock-skew recovery, captured credential in clarification; redact sensitive person/mission/ticket state. F04/F08/F16 | Negative endpoint/polling tests; example response classification |
| Bootstrap and keys | [key management](../../../docs/advanced/key-management.md), [platform attestation](../../../docs/advanced/platform-attestation.md), sample AP/console help | Multiple agent keys versus published AP key; parent acquisition guidance remains informational; avoid unsupported platform/hosted-enrollment claims. F23 | Existing enrollment/refresh regressions, source review |
| New optional features | R3 annotations/result-release descriptions and Budgets references | State selection and limitations explicitly. An annotation is not a grant or implemented metering; a result field is not permission to pre-execute billable work. F19/F21/F22 | Capability guard tests or explicit unsupported status |

## Embedded and executable content

| Content class | Owning files/directories | Required treatment |
|---|---|---|
| GuidedTour runtime | [TourSession](../../../samples/GuidedTour/TourSession.cs), [components](../../../samples/GuidedTour/Components/) | Step plans/counts, dispatcher indices, approval/poll indices, actor lanes, selected payloads, nested sequences, reset and completion must agree. |
| SampleApp runtime | [pages](../../../samples/SampleApp/Components/Pages/), [EnrollmentService](../../../samples/SampleApp/EnrollmentService.cs), [SelfIssuedIdentity](../../../samples/SampleApp/SelfIssuedIdentity.cs) | Real button actions, account selectors, consent links, state and payload panels move with API changes. Do not assume every legacy page is a numbered GuidedTour sequence. |
| Shared capability UI | [CapabilitySupport](../../../samples/CapabilitySupport/), [EventSupport](../../../samples/EventSupport/) | Sessions, code templates, protocol sequence components and wrapper routes in both apps must stay synchronized. |
| Compiled server/console examples | [mock resources](../../../samples/MockResourceServers/), [mock PS](../../../samples/MockPersonServer/), [mock AS](../../../samples/MockAccessServers/), [AgentConsole](../../../samples/AgentConsole/), [MissionAgent](../../../samples/MissionAgent/), [Concierge](../../../samples/Concierge/), [EventAgent](../../../samples/EventAgent/), [LiveWhoAmITest](../../../samples/LiveWhoAmITest/) | Fix callers in the owning code phase, including custom minting/approval paths that bypass standard mappers. Console output and help are instructional too. |
| Non-compiled snippets | Markdown and quoted fences, raw/interpolated/ordinary C# strings, Razor preformatted/inline blocks, JSON/HTTP examples, Mermaid diagrams | Inventory by syntax and old-wire patterns; compilation alone cannot find stale text or wrong captured-step associations. |
| Browser expectations | [e2e tests](../../../tests/e2e/), [tour helper](../../../tests/e2e/helpers/tour.ts), [Wallet helper](../../../tests/e2e/helpers/wallet-protocol.ts) | Numeric step selectors, totals, payload assumptions and actor assertions change with runtime plans; retain desktop/mobile and both-host coverage. |
| Local demo state | [Makefile](../../../Makefile), sample state/key configuration, SQLite stores | Version isolation or explicit migration for old credentials/tickets/missions; update displayed labels and restart guidance without deleting state. |

## Pattern and classification sweep

Search live surfaces case-insensitively with both wire and .NET names:

```text
token_endpoint / TokenEndpoint
aauth-access-token / AAuthAccessToken
AAuth-Mission / AAuthMissionHeader / MissionAware / missionAware
mission.approver / MissionClaim / mission blob / approval bytes
presented_token / PresentedToken / presented_jti / PresentedTokenId
act.agent / ActChain / ActChainsMatch / parent_agent
r3_conditional / Conditional / r3_per_call / PerCall
openapi-gateway / OpenApiGateway / service-qualified
version / Version (R3 documents, not OpenAPI/AsyncAPI or package versions)
revocation / RevokeAsync / unknown_token / TrustedPersonServers
clock_skew / ClockSkew / expires / refresh / four access modes
```

Every match gets a disposition: executable migration, display migration,
intentional generic signing, OIDC/other protocol, historical record, or unrelated
domain term. Do not rename OIDC endpoints, remove AP agent claims, change WSDL
service qualifiers, or scrub historical snapshots/plans. Truncated search output
cannot establish completeness. Exclude generated bin/obj and browser artifacts.

## Verification classes

| Class | Evidence it establishes | What it does not establish |
|---|---|---|
| Exact C# snippet compilation | Symbols, types, overloads, required members | Runtime trust, network exchange, or current UI use |
| JSON/schema/HTTP parsing | Shape, field types, expected status/carriage | Cryptographically valid placeholder tokens/signatures |
| Captured-wire endpoint tests | Actual emitted values and verification behavior | External deployment compatibility |
| Browser scenario | Action, approval, selected-step payload and rendering agree | Every SDK overload or security condition |
| Link/anchor validation | Targets exist and citations identify intended lines | Correctness of the claimed behavior |
| Semantic source review | Claims match pinned requirements and capability scope | An executed test pass |

## Tooling prerequisites

[SnippetCompilationTests L228](../../../tests/AAuth.Tests/Api/SnippetCompilationTests.cs#L228)
targets the old docs map, and its
[L299](../../../tests/AAuth.Tests/Api/SnippetCompilationTests.cs#L299)
heuristic expects `iss` in a `jti` body. Retarget the map and classify revocation
before using it as a v11 gate. Inspect
[DocumentationInventory](../../../tests/AAuth.Tests/Api/DocumentationInventory.cs)
for selected-directory exclusions; supplement it with console/server/string and
wire-pattern inventory. Do not manufacture passing counts from the v10 appendix.

The final sweep occurs after public API freeze. Compiled callers and executable
sample flow changes occur in their code phases so the solution stays buildable.
API-dependent Markdown fences, reference tables and inventory expectations that
the existing snippet tests validate also change in those contract phases; do not
disable or suppress those tests to defer the work.
The sweep checks finished behavior and remaining static content; it does not
defer the walkthrough implementation until documentation time.