# R3 (Rich Resource Requests) — Implementation Plan

Phased plan to add AAuth **Rich Resource Requests (R3)** support to the .NET SDK
(`src/AAuth`) and the samples, including a new **Bookings** resource server (and a
dedicated Bookings AS) aligned with the Aria narrative.

- **Research:** [research.md](research.md)
- **Log:** [implementation-log.md](implementation-log.md)
- **Created:** 2026-07-02
- **R3 spec:** [aauth-spec/v08/draft-hardt-aauth-r3.md](../../../aauth-spec/v08/draft-hardt-aauth-r3.md) (draft-00)
- **Base spec:** [aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md](../../../aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md) (draft-08)

## Guiding principles

- **Spec conformance is paramount; backwards compatibility is not a goal.** This is
  a spec-accurate alpha SDK. Do a single coordinated cutover — add the R3 surface
  and wire every consumer in the same change set; no dual-format shims. Deliberate
  exceptions are logged as `PROCEEDED`/`RESOLVED` entries in
  [implementation-log.md](implementation-log.md).
- **Consumability is a first-class requirement.** R3 must extend the shipped server
  surface ([.agent/plans/2026-06-27-server-api-surface](../2026-06-27-server-api-surface/implementation-plan.md)),
  not fight it: one-call DI, declarative per-route protection, opt-in modules,
  **no string indirection** (typed handles, not magic strings), **no manual
  `HttpClient` wiring**, layered 80/20, and **spec-owns-the-wire / app-owns-policy
  and presentation**.
- **Reuse, don't rewrite.** R3 hashing reuses the verbatim-bytes `ComputeS256`
  pattern; the per-call conditional flow reuses the existing `AAuth-Requirement`
  challenge + token exchange; AS-signed R3 fetch reuses `AAuthSigningHandler`.
- **Verbatim bytes, no canonicalization.** `r3_s256 = base64url(SHA-256(served
  bytes))`. Serialize once, persist, serve raw. There is **no** RFC 8785 dependency
  ([research §A.2](research.md)).
- **Security invariants are test targets, not afterthoughts** (research §F): AS-only
  R3-fetch (issuer-pinned), hash-verify-before-use, atomic audit-with-issuance,
  per-call digest verification, operation validation.
- **R3 ships as a separate package** (revised 2026-07-02). R3 is an Exploratory
  Draft, so it lives in a new **`AAuth.R3`** NuGet package (`src/AAuth.R3/`) that
  depends on `AAuth`. The **only** changes to the core `AAuth` package are *generic*
  extensibility seams (a `ResourceTokenBuilder.AdditionalClaims` bag, a metadata
  `AdditionalMetadata` bag, an AS resource-token decision hook) — **never**
  R3-specific knowledge. Consumers opt in by referencing `AAuth.R3`; the package
  exposes typed helpers so callers never touch raw claim-name strings (the strings
  are centralized constants inside the package).

## Cross-cutting decisions (defaults; see log for rulings)

| # | Decision | Default |
|---|---|---|
| CC1 | Vocabulary coverage | MCP + OpenAPI first-class + generic escape hatch (Q1) |
| CC2 | Bookings vocabulary | **MCP-first**; package stays OpenAPI-capable (Q2, revised) |
| CC3 | Bookings access mode | Four-party, **reusing the single shared MockAccessServer** via a unified R3-aware decision hook (research §E, revised 2026-07-02) |
| CC4 | AS instance / port | **Reuse MockAccessServer at :5500** — no dedicated R3 AS, no per-sample R3 config (Q3, revised) |
| CC5 | AS-only-fetch gate shape | Dedicated `MapAAuthR3Document(store, asIssuer)` mapper (Q4) |
| CC6 | Proposal store seam | Reuse `IR3DocumentStore` for docs + proposals (Q5) |
| CC7 | Packaging | **Separate `AAuth.R3` NuGet package** (`src/AAuth.R3/`, preview) depending on `AAuth`; core gets only generic seams (2026-07-02) |

---

## Phase 0 — Decision gate

Resolve the research open questions before code. Each ruling is recorded in
[implementation-log.md](implementation-log.md); prefer a default ruling over
blocking.

**Definition of Done**

- [x] Every research open question (Q1–Q6) has a recorded ruling in
      `implementation-log.md`.
- [x] CC1–CC7 confirmed or overridden.
- [x] Branch created; research committed (see the git steps at the end of this plan).

---

## Phase 1 — R3 primitives (new `AAuth.R3` package)

**Goal:** strongly-typed R3 models, verbatim-bytes hashing, and a byte-persisting
document store. Isolated and unit-testable; everything else depends on a correct
hash.

**Spec:** r3 §Vocabularies L101–L232; §R3 Document L285–L340; §Per-Call Proposals
L491–L539; `#content-addressing` L331–L340.

> All `src/AAuth/R3/…` paths below now live in the new **`src/AAuth.R3/`** package
> project (CC7), not core `src/AAuth`. Add `src/AAuth.R3/AAuth.R3.csproj`
> (references `AAuth`) to `AAuth.slnx`.

> **Seeded 2026-07-02** from Ana's imported `samples/AAuth.R3/` (log entry
> `[Phase 1] Seeded R3 primitives`). The `Model/` records, `R3Hash`, `R3AuthClaims`,
> `R3ClaimReader`, `R3ProposalStore`, etc. already exist and build against our core
> (full `AAuth.slnx` green). Remaining Phase 1 work: **relocate**
> `samples/AAuth.R3` → `src/AAuth.R3` as a packable preview package, **reconcile**
> the hand-built resource-token JWT onto the generic
> `ResourceTokenBuilder.AdditionalClaims` seam, and **port** Ana's
> `tests/AAuth.R3.Tests` (23 tests). Many `New` rows below are therefore now
> **Adapt** (from the imported files).

### Files

| File | Action |
|---|---|
| `src/AAuth/R3/R3OperationSet.cs` | **New** — `{ Vocabulary, Operations[] }`; `ToJsonObject()`/`FromJson()` |
| `src/AAuth/R3/R3Operation.cs` | **New** — MCP `{tool}` + OpenAPI `{operationId}` first-class; `JsonObject` escape hatch; factories `Mcp(tool)`/`OpenApi(operationId)` |
| `src/AAuth/R3/R3Document.cs` | **New** — `Version?`, `Vocabulary`, `Operations[]`, `Display?`; proposal variant adds `Parameters` |
| `src/AAuth/R3/R3Display.cs` | **New** — `Summary`, `Implications?`, `DataAccessed?`, `Irreversible?`, `Detail?` |
| `src/AAuth/R3/R3Hash.cs` | **New** — verbatim-bytes SHA-256 → base64url(no-pad); shared with/refactored from `Mission.ComputeS256` |
| `src/AAuth/R3/IR3DocumentStore.cs` + `InMemoryR3DocumentStore.cs` | **New** — `Store(doc) → (uri, s256)` / `TryGet(s256) → bytes`; persists serialized bytes verbatim |
| `src/AAuth/AAuthConstants.cs` | **Modify** — add `Vocabularies` group (7 URIs) + R3 claim-name constants |
| `tests/AAuth.Conformance/R3/R3HashTests.cs`, `R3ModelTests.cs` | **New** |

**Implementation Decisions**

- Do **not** name any helper `…Canonical…` (no canonicalization; research §A.2).
- `R3Document` serializes **once**; the store keeps the exact bytes. Consumers that
  serve the document write those bytes **raw**, never via `Results.Json`.
- Escape-hatch operations MUST preserve each vocabulary's REQUIRED extra keys
  (`graphql.type`, `asyncapi.action`, `wsdl.service`, `odata.methods`) and
  snake_case names.

**Definition of Done**

- [ ] `r3_s256` matches hand-computed hashes for the spec's example documents.
- [ ] `R3OperationSet` round-trips JSON for MCP + OpenAPI and via the escape hatch.
- [ ] Store returns byte-identical content for a stored `(uri, s256)`.
- [ ] `dotnet build AAuth.slnx` green; conformance suite green.

---

## Phase 2 — `r3_vocabularies` resource metadata

**Goal:** advertise supported vocabularies in `aauth-resource.json`.

**Spec:** r3 `#resource-metadata-extensions` L83–L112.

### Files

| File | Action |
|---|---|
| [src/AAuth/Server/Metadata/WellKnownEndpoints.cs](../../../src/AAuth/Server/Metadata/WellKnownEndpoints.cs) | **Modify (generic seam)** — add an `AdditionalMetadata` bag to `AAuthResourceMetadataOptions`, emitted in `BuildResourceMetadata` (mirror the `ScopeDescriptions` guarded-map block); **no R3 knowledge in core** |
| `src/AAuth.R3/R3Metadata.cs` | **New (R3 package)** — supplies the `r3_vocabularies` object through the generic seam |
| `tests/AAuth.R3.Tests/R3MetadataTests.cs` | **New** |

**Definition of Done**

- [ ] `AddAAuthResource(o => o.R3Vocabularies = …)` emits `r3_vocabularies` in the
      well-known document.
- [ ] Absent when unset (OPTIONAL); shape is `{ vocab-URI → discovery endpoint }`.

---

## Phase 3 — Token claims (resource token, auth token, verification result)

**Goal:** carry R3 claims on the wire and surface them to resource endpoints.

**Spec:** r3 §Resource Token Extensions L342–L360; §Auth Token Extensions
L419–L475; base `sub|scope` rule L1686 / L1724.

### Files

| File | Action |
|---|---|
| [src/AAuth/Tokens/ResourceTokenBuilder.cs](../../../src/AAuth/Tokens/ResourceTokenBuilder.cs) | **Modify (generic seam)** — add an `AdditionalClaims` bag (mirrors `AuthTokenBuilder`); **no R3-specific props** |
| `src/AAuth.R3/R3AuthClaims.cs` | **New (R3 package)** — typed API producing the resource-token (`r3_uri`/`r3_s256`) and auth-token (`+r3_granted`/`r3_conditional`) claim dicts; centralizes claim-name constants; validates both-or-neither |
| `src/AAuth.R3/R3ClaimReader.cs` | **New (R3 package)** — parse R3 claims from a verified auth-token payload for enforcement |
| `tests/AAuth.R3.Tests/R3TokenClaimsTests.cs` | **New** |

**Implementation Decisions**

- Core builders gain only a **generic** `AdditionalClaims` bag; R3 knowledge stays
  in the package. The package's typed `R3AuthClaims`/`R3Grant`/`R3OperationSet` API
  means consumers never handle raw claim-name strings.
- `AAuthVerificationResult` is **unchanged** — the R3 package reads R3 claims from
  the auth-token payload it already holds (`R3ClaimReader`).
- An R3 auth token still carries a `scope` (even coarse) or `sub` — `r3_granted`
  does **not** satisfy the base rule (keep the `AuthTokenBuilder` guard).

**Definition of Done**

- [ ] Resource token serializes `r3_uri`+`r3_s256` together (rejects one-without-the-other).
- [ ] Auth token serializes `r3_granted` (and optional `r3_conditional`) as objects.
- [ ] `AAuthVerificationResult` exposes typed granted/conditional to endpoints.
- [ ] Round-trip conformance tests green.

---

## Phase 4 — Agent-side proactive authorize + `r3_operations`

**Goal:** let an agent proactively declare intended operations to a resource's
authorization endpoint.

**Spec:** r3 `#authorization-endpoint-extensions` L234–L266 (recipient = **resource**
authorize endpoint, **not** PS/AS token endpoint); base authorize `scope` REQUIRED
L620–L622.

### Files

| File | Action |
|---|---|
| [src/AAuth/Server/AAuthAuthorizationRequest.cs](../../../src/AAuth/Server/AAuthAuthorizationRequest.cs) | **Modify** — carry optional `R3Operations` |
| [src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs) | **Modify** — `MapAAuthAuthorizationEndpoint` parses `r3_operations` from the body |
| `src/AAuth/Agent/AuthorizeClient.cs` (name TBD) | **New** — agent-side proactive `POST authorization_endpoint` carrying `scope` (+ optional `r3_operations`); returns the resource token |
| `tests/AAuth.Conformance/R3/AgentR3AuthorizeTests.cs` | **New** |

**Implementation Decisions**

- Do **not** add `R3Operations` to `TokenExchangeRequest`/`TokenExchangeClient` — the
  PS/AS learns R3 from the resource token's `r3_uri`/`r3_s256`, which it fetches.
- The conditional per-call round-trip reuses the existing challenge + exchange path;
  **no** new agent header or handler.

**Definition of Done**

- [ ] Agent emits `r3_operations` (object) only on the authorize endpoint body.
- [ ] `scope` remains REQUIRED there; `r3_operations` is additive/optional.
- [ ] Agent reads `r3_granted`/`r3_conditional` off the parsed auth token.

---

## Phase 5 — Resource-side enforcement + AS-only-fetch gate (security)

**Goal:** enforce grants from token claims, mint per-call proposals dynamically, and
gate the R3-document endpoint to the resource's AS only.

**Spec:** r3 §Resource Enforcement L479–L485; Grant Enforcement L563–L565; Per-Call
Proposals L491–L539 (digest verify L531); AS-only fetch L297, L541–L549.

### Files

| File | Action |
|---|---|
| [src/AAuth/Server/Verification/AAuthHttpContextExtensions.cs](../../../src/AAuth/Server/Verification/AAuthHttpContextExtensions.cs) | **Modify** — `GetAAuthR3Grant()`, `MatchR3Operation(op) → {Granted,Conditional,None}`, `RequireAAuthProposal(proposal, store)` (dynamic mint via `ResourceTokenBuilder` + `ChallengeAAuth`), `VerifyR3Proposal(store, presentedParams)` |
| `src/AAuth/Server/R3/AAuthR3DocumentEndpoint.cs` (name TBD) | **New** — `MapAAuthR3Document(pattern, store, asIssuer)` serving persisted bytes **raw**, pinned to the AS signer |
| [src/AAuth/Server/Verification/AAuthVerificationResult.cs](../../../src/AAuth/Server/Verification/AAuthVerificationResult.cs) | **Modify (if needed)** — expose the verified signer URI for jwks_uri scheme so the AS pin can assert it |
| `tests/AAuth.Conformance/R3/R3EnforcementTests.cs`, `R3DocumentGateTests.cs` | **New** |

**Implementation Decisions**

- Per-call proposals are **dynamic** — mint via `ResourceTokenBuilder` +
  `HttpContext.ChallengeAAuth(resourceToken)`, **not** static `ChallengeOptions`.
- The AS-only gate is **new** — `.RequireAAuthSignature(identified:)` accepts any
  signer; pin the verified signer to the configured AS identity.

**Definition of Done**

- [ ] `granted → serve` / `conditional → challenge+proposal` / `none → reject` matches spec.
- [ ] Per-call retry rejects when a presented parameter's digest ≠ approved proposal.
- [ ] R3-document endpoint returns byte-identical content and **rejects non-AS signers** (test proves a valid non-AS signature is refused).

---

## Phase 6 — AS/PS-side R3 processing (SDK-owned)

**Goal:** the SDK fetches, hash-verifies, caches, and audits R3 documents before
policy runs; the AS mints grants; the PS gets `display` for consent.

**Spec:** r3 §AS Processing L396–L404; PS display L388–L389; atomic audit L557;
AS-only fetch (client side) L297.

### Files

| File | Action |
|---|---|
| `src/AAuth.R3/R3DocumentFetcher.cs` | **New (R3 package)** — AS-signed GET (`AAuthSigningHandler` + jwks_uri provider), hash-verify, cache by `s256`; no manual `HttpClient` |
| [src/AAuth/Access/AAuthAccessServerEndpoints.cs](../../../src/AAuth/Access/AAuthAccessServerEndpoints.cs) | **Modify (generic seam)** — add an optional resource-token decision hook so an extension can handle tokens the base policy does not; **no R3 knowledge in core** |
| `src/AAuth.R3/R3AccessDecision.cs` (name TBD) | **New (R3 package)** — the hook: when the resource token carries `r3_uri`, fetch+verify+audit, split granted/conditional, mint R3 claims via `R3AuthClaims`; otherwise defer to the base policy |
| [src/AAuth/Person/IIdentityClaimsAsserter.cs](../../../src/AAuth/Person/IIdentityClaimsAsserter.cs) | **Modify** — expose the fetched R3 `display` on the request (**display-only**; no grant minting) |
| `tests/AAuth.R3.Tests/R3AccessProcessingTests.cs` | **New** |

**Implementation Decisions**

- Only the **AS** populates `r3_granted`/`r3_conditional`; the PS is display-only.
- Fetch/hash-verify/audit live in the R3 package's host path, not the sample policy.
- The AS is R3-aware via a **generic hook**, so a **single** instance serves both
  scope-based (Wallet) and R3 (Bookings) resource tokens with **no per-sample
  config** — it branches on `r3_uri` in the resource token.
- The granted-vs-conditional split is derived from the **R3 document** (e.g.
  operations whose `display.irreversible` is set are conditional), not a per-server
  `ConditionalTools` config list.

**Definition of Done**

- [ ] AS rejects a resource token whose fetched document fails `r3_s256`.
- [ ] Audit entry is written atomically with issuance (test asserts no issuance
      without a log entry).
- [ ] Policy sample sees a verified `R3Document` and returns typed grants.

---

## Phase 7 — Bookings resource server (samples), reusing the shared AS

**Goal:** a runnable R3 demonstrator in the Aria suite — an external **Reservations**
provider (dining & experiences), served by the existing shared MockAccessServer.

**Spec / research:** research §D-S7, §E (revised 2026-07-02).

### Files

| File | Action |
|---|---|
| `samples/MockResourceServers/Bookings/` (`Bookings.csproj`, `Program.cs`, `Entry` partial, `README.md`) | **New** — port **5005**; MCP vocabulary; `search_availability`/`hold_reservation` = granted, `confirm_reservation` = conditional (charges a non-refundable deposit); `AddAAuthResource` + `MapAAuthWellKnown` + `UseAAuth` + per-route helpers + `MapAAuthR3Document` |
| [samples/MockAccessServer/Program.cs](../../../samples/MockAccessServer/Program.cs) | **Modify** — register the Phase 6 R3 decision hook so the **single** instance also serves Bookings' R3 tokens (no `Mode` switch, no per-sample config) |
| [samples/MockResourceServers](../../../samples/MockResourceServers) READMEs | **Modify** — add the Bookings row |

**Implementation Decisions**

- **Reframe (narrative).** Bookings is an **external Reservations provider**
  (dining & experiences — reserve a table / book a tour) whose irreversible
  **`confirm_reservation`** charges a deposit; distinct from Trips (mission
  itinerary) and Wallet (bank rail). No "trip"/`book_trip` naming (avoids the Trips
  collision; research §D-S7).
- **Reuse the shared AS, config-free** (research §E revised). One MockAccessServer
  instance (:5500) serves Wallet (scope) and Bookings (R3) by branching on the
  resource token's `r3_uri` via the Phase 6 hook — no `Mode=R3`, no `ConditionalTools`
  list.
- **MCP-first vocabulary** (Q2 revised); the package stays OpenAPI-capable.

**Definition of Done**

- [ ] `confirm_reservation` triggers a per-call proposal; approval + enforced retry
      succeed; a tampered parameter (changed deposit or venue) is rejected.
- [ ] Bookings serves its R3 document only to the AS (and PS for display).
- [ ] The single MockAccessServer serves both Wallet and Bookings with **no**
      R3-specific launch profile or config.
- [ ] Bookings `Program.cs` carries no manual `HttpClient` and no magic-string policies.

---

## Phase 8 — Integration (GuidedTour, SampleApp, Makefile, e2e)

**Goal:** wire Bookings into the tour, the app, the demo orchestration, and the
in-process integration tests.

### Files

| File | Action |
|---|---|
| [samples/GuidedTour/TourOptions.cs](../../../samples/GuidedTour/TourOptions.cs) + `TourSession.cs` | **Modify** — new `TourMode.RichRequests` after `Federated`; add matching switch arms + URL/highlighter wiring |
| [samples/SampleApp](../../../samples/SampleApp) `Components/Pages/Bookings.razor` | **New** — conditional per-call approval demo |
| [Makefile](../../../Makefile) | **Modify** — `BOOKINGS_PROJECT`/`BOOKINGS_URL` (5005); wire `resources` + `demo`. The AS is the existing MockAccessServer — **no new AS target** |
| `samples/GuidedTour/appsettings.json`, `samples/SampleApp/appsettings.json` | **Modify** — add `BOOKINGS_URL` |
| `tests/AAuth.Tests/Integration/BookingsFlowTests.cs` | **New** — three in-proc hosts (Bookings + the **shared** MockAccessServer + PS) via `MultiHostHandler`, like `MockPersonServerFederationTests` |

**Definition of Done**

- [ ] `make demo` starts Bookings; the shared MockAccessServer serves it (no new AS
      target); the tour's new mode runs end-to-end.
- [ ] `BookingsFlowTests` cover granted-serve, conditional-approve-retry, and
      tamper-reject; all integration suites green.

---

## Phase 9 — Docs / snippets / samples sweep

Run **after** the code surface is frozen. Non-compiled surfaces drift silently.

### Files

| File | Action |
|---|---|
| `docs/workflows/rich-resource-requests.md` | **New** — slotted after `federated-access.md`, near `mission-governed-access.md` |
| [docs/concepts.md](../../../docs/concepts.md), [docs/glossary.md](../../../docs/glossary.md), [docs/README.md](../../../docs/README.md), [README.md](../../../README.md), [samples/README.md](../../../samples/README.md) | **Modify** — R3 concepts, vocabulary/`r3_*` glossary rows, Bookings in server tables/API map |
| [docs/reference/configuration.md](../../../docs/reference/configuration.md), [docs/reference/dependency-injection.md](../../../docs/reference/dependency-injection.md) | **Modify** — new R3 options/DI helpers |

**Definition of Done**

- [ ] R3 workflow doc explains vocabulary → `r3_operations` → grants → per-call proposal.
- [ ] Invariant greps confirm no non-conformant snippets (no `AAuth-Conditional-Access`,
      no `r3_operations` at the token endpoint, no RFC 8785 references).
- [ ] All embedded code fences compile-check against the shipped surface.

---

## Phase 10 — Internal review

A fresh subagent validates the implementation against the spec, `research.md`, and
this plan, with severity-graded findings.

**Definition of Done**

- [ ] Subagent report attached (or logged) with findings triaged.
- [ ] Every security invariant (research §F) has a passing test.
- [ ] No open `PROCEEDED` decision left unreviewed in `implementation-log.md`.

---

## Out of scope

| Item | Reason |
|---|---|
| RFC 8785 / JCS canonical JSON | R3 hashes verbatim bytes (r3 L335); not required |
| Fully-typed models for all seven vocabularies | Escape hatch suffices for the demo (Q1) |
| Vocabulary *discovery* parsing (MCP tool list / OpenAPI / `$metadata` fetch) | Later R3 phase at most |
| PS-side `r3_granted` minting | Out of spec — PS is display-only (r3 L391, L404) |
| Dedicated Bookings AS project | Superseded 2026-07-02 — the shared MockAccessServer serves R3 via a generic hook, config-free (research §E revised) |
| R3-specific claims/props in the core `AAuth` package | R3 ships as the separate `AAuth.R3` package (CC7); core gets only generic seams |
| Mission ↔ R3 combined governance flow | Spec undefined; keep orthogonal unless decided |

---

## Git steps (Phase 0 companion)

1. Create a local feature branch off the current branch.
2. Commit `research.md`, `implementation-plan.md`, and `implementation-log.md`.
3. Do **not** push; comparison against `nedruk:feat/r3-rich-resource-requests`
   happens in a separate worktree.
