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
| CC3 | Bookings access mode | Four-party; **two dedicated access servers** under `samples/MockAccessServers/` — `Federated` (Wallet) + `R3` (Bookings) — mirroring `MockResourceServers/` (revised 2026-07-02; supersedes the "reuse single instance" ruling) |
| CC4 | AS ports | **Federated AS :5500** (Wallet, scope) + **dedicated R3 AS :5501** (Bookings); each single-purpose, always-on, no launch-mode switch (revised 2026-07-02) |
| CC5 | AS-only-fetch gate shape | Dedicated `MapAAuthR3Document(store, asIssuer)` mapper (Q4) |
| CC6 | Proposal store seam | Reuse `IR3DocumentStore` for docs + proposals (Q5) |
| CC7 | Packaging | **Separate `AAuth.R3` NuGet package** (`src/AAuth.R3/`, preview) depending on `AAuth`; core gets only generic seams (2026-07-02) |
| CC8 | R3 package version | **Same version as `AAuth`** for now — no separate version input (2026-07-02) |
| CC9 | R3 conditional split | **Doc-derived** — `R3Document.conditional` lists the conditional ops; the R3 AS reads it (no per-AS tool config). Option A (2026-07-02) |

---

## Phase 0 — Decision gate

Resolve the research open questions before code. Each ruling is recorded in
[implementation-log.md](implementation-log.md); prefer a default ruling over
blocking.

**Definition of Done**

- [x] Every research open question (Q1–Q6) has a recorded ruling in
      `implementation-log.md`.
- [x] CC1–CC8 confirmed or overridden.
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

> **Seeded 2026-07-02 — relocated + tests ported.** From Ana's imported library:
> `Model/` records, `R3Hash`, `R3AuthClaims`, `R3ClaimReader`, `R3ProposalStore`,
> etc. **Done in Phase 1:** relocated `samples/AAuth.R3` → `src/AAuth.R3` (packable
> preview, `PackageId=AAuth.R3`, version tracks `AAuth`); ported Ana's
> `tests/AAuth.R3.Tests` (**30** tests, all green). **Deferred to Phase 3:**
> reconcile the hand-built resource-token JWT onto the generic
> `ResourceTokenBuilder.AdditionalClaims` seam (created there). The `New` file rows
> below are already present as imported files.

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

- [x] `r3_s256` matches hand-computed hashes for the spec's example documents.
- [x] `R3OperationSet` round-trips JSON for MCP + the escape hatch (OpenAPI
      first-class deferred — CC2 MCP-first; see log).
- [x] Store returns byte-identical content for a stored `(uri, s256)`.
- [x] `dotnet build AAuth.slnx` green; conformance suite green (R3 30, AAuth.Tests
      517, AAuth.Conformance 571).

---

## Phase 2 — `r3_vocabularies` resource metadata

> **Status (2026-07-02): satisfied by the imported `AAuth.R3` library** (`R3Metadata`);
> the generic `AdditionalMetadata` core seam is deferred as unnecessary (see log).

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

> **Status (2026-07-02): satisfied by the imported `AAuth.R3` library**
> (`R3AuthClaims`/`R3ClaimReader`; `R3Challenge` for the resource token); the generic
> `ResourceTokenBuilder.AdditionalClaims` core seam is deferred as unnecessary (see log).

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

> **Status (2026-07-02): satisfied by the imported `AAuth.R3` library**
> (`R3Enforcement`, `R3Challenge` proposals, `R3DocumentEndpoint` trusted-fetcher
> gate); no core seam needed (see log). Re-verify the security invariants in Phase 11.

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

> **Status (2026-07-02): delivered by the dedicated R3 AS** (`samples/MockAccessServers/R3`)
> over the imported `AAuth.R3` library (`R3FetchClient` AS-signed fetch + hash-verify,
> `R3AccessTokenEndpoint` mint, `R3Audit` sink). The granted/conditional split is
> **doc-derived** (`R3Document.conditional`, option A / CC9) — no generic core hook,
> no per-AS tool config (see log).

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
- **Two single-purpose access servers** under `samples/MockAccessServers/` (mirroring
  `MockResourceServers/`): `Federated` (:5500, Wallet, scope) and `R3` (:5501,
  Bookings). No dual-personality server, no launch-mode switch, no `r3_uri`-branching
  middleware.
- The granted-vs-conditional split is **doc-derived** (CC9): `R3Document.conditional`
  lists the conditional ops and the R3 AS reads it — no per-server `ConditionalTools`.

**Definition of Done**

- [ ] AS rejects a resource token whose fetched document fails `r3_s256`.
- [ ] Audit entry is written atomically with issuance (test asserts no issuance
      without a log entry).
- [ ] Policy sample sees a verified `R3Document` and returns typed grants.

---

## Phase 7 — Bookings resource server + dedicated R3 AS (samples)

**Goal:** a runnable R3 demonstrator in the Aria suite — an external **Reservations**
provider (dining & experiences), guarded by a dedicated R3 access server.

**Spec / research:** research §D-S7, §E (revised 2026-07-02).

### Files

| File | Action |
|---|---|
| `samples/MockResourceServers/Bookings/` (`Bookings.csproj`, `Program.cs`, `Entry` partial, `README.md`) | **New** — port **5005**; MCP vocabulary; `search_availability`/`hold_reservation` = granted, `confirm_reservation` = conditional (charges a non-refundable deposit); `AddAAuthResource` + `MapAAuthWellKnown` + `UseAAuth` + per-route helpers + `MapAAuthR3Document` |
| `samples/MockAccessServers/R3/` (`R3.csproj`, `Program.cs`, `Entry`) | **New** — dedicated R3 AS on **:5501** via `MapR3AccessTokenEndpoint` + `AddAAuthDiscovery`. The existing `MockAccessServer` moved to `MockAccessServers/Federated` (sibling, :5500) |
| [samples/MockResourceServers](../../../samples/MockResourceServers) READMEs | **Modify** — add the Bookings row |

**Implementation Decisions**

- **Reframe (narrative).** Bookings is an **external Reservations provider**
  (dining & experiences — reserve a table / book a tour) whose irreversible
  **`confirm_reservation`** charges a deposit; distinct from Trips (mission
  itinerary) and Wallet (bank rail). No "trip"/`book_trip` naming (avoids the Trips
  collision; research §D-S7).
- **Two dedicated, config-free access servers** (revised 2026-07-02; supersedes the
  "reuse single instance" ruling). `MockAccessServers/Federated` (:5500) keeps the
  scope-based Wallet flow untouched; `MockAccessServers/R3` (:5501) guards Bookings
  and derives the conditional split from `R3Document.conditional` (CC9) — no `Mode=R3`,
  no `ConditionalTools`.
- **High-level DI everywhere** (owner directive): the R3 AS uses `AddAAuthDiscovery`,
  Bookings uses `AddAAuthResource` — no manual `HttpClient` wiring. Bookings still
  hand-rolls its well-known/JWKS (r3_vocabularies + R3 signing not modelled by core
  metadata) — logged good-reason.
- **MCP-first vocabulary** (Q2 revised); the package stays OpenAPI-capable.

**Definition of Done**

- [ ] `confirm_reservation` triggers a per-call proposal; approval + enforced retry
      succeed; a tampered parameter (changed deposit or venue) is rejected.
- [x] Bookings serves its R3 document only to trusted fetchers (its AS + PS); agents rejected.
- [x] `MockAccessServers/` holds two single-purpose AS (`Federated` :5500, `R3` :5501);
      neither needs an R3-specific launch mode. Solution builds 0/0; 1118 tests green.
- [x] R3 samples/AS carry **no** manual `HttpClient` wiring (AddAAuthDiscovery/AddAAuthResource).

---

## Phase 8 — Integration (GuidedTour, SampleApp, Makefile, e2e)

> **Status (2026-07-02): partial.** ✅ Makefile wires Bookings (:5005) + the R3 AS
> (:5501) into `resources`/`demo`. ⏳ Remaining: GuidedTour R3 mode, SampleApp R3
> page, Playwright e2e specs, and a dedicated `BookingsFlowTests` — the interactive
> demo + e2e surface (the R3 protocol itself is covered by the 31 in-proc
> `AAuth.R3.Tests`). Ana's GuidedTour/SampleApp R3 work on the fork is the
> adaptation candidate (attribute to her).

**Goal:** wire Bookings into the tour, the app, the demo orchestration, and the
in-process integration tests.

### Files

| File | Action |
|---|---|
| [samples/GuidedTour/TourOptions.cs](../../../samples/GuidedTour/TourOptions.cs) + `TourSession.cs` | **Modify** — new `TourMode.RichRequests` after `Federated`; add matching switch arms + URL/highlighter wiring |
| [samples/SampleApp](../../../samples/SampleApp) `Components/Pages/Bookings.razor` | **New** — conditional per-call approval demo |
| [Makefile](../../../Makefile) | **Modify** — `BOOKINGS_PROJECT`/`BOOKINGS_URL` (5005) + `R3AS_PROJECT`/`R3AS_URL` (5501); wire `resources` + `demo`. `Federated` AS path moved under `MockAccessServers/` |
| `samples/GuidedTour/appsettings.json`, `samples/SampleApp/appsettings.json` | **Modify** — add `BOOKINGS_URL` |
| `tests/AAuth.Tests/Integration/BookingsFlowTests.cs` | **New** — three in-proc hosts (Bookings + the **R3 AS** + PS) via `MultiHostHandler`, like `MockPersonServerFederationTests` |

**Definition of Done**

- [ ] `make demo` starts Bookings + the R3 AS (:5501); the tour's new mode runs end-to-end.
- [ ] `BookingsFlowTests` cover granted-serve, conditional-approve-retry, and
      tamper-reject; all integration suites green.

---

## Phase 9 — Docs / snippets / samples sweep

> **Status (2026-07-02): partial.** ✅ New `docs/workflows/rich-resource-requests.md`;
> Bookings row + narrative in `samples/MockResourceServers/README.md`. ⏳ Remaining:
> `docs/concepts.md` / `docs/glossary.md` / `docs/README.md` / root `README.md` /
> `samples/README.md` R3 rows, and `docs/reference/*` R3 options.

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

## Phase 10 — CI + packaging / release automation

Wire the new `AAuth.R3` package into the existing CI and release pipelines. Repo-side
and automatable; the **owner-only nuget.org steps are deferred to Phase 12**.

**Findings (existing pipelines):**

- [.github/workflows/ci.yml](../../../.github/workflows/ci.yml) builds and tests the
  **whole solution** (`dotnet build/test AAuth.slnx`) and runs a Playwright e2e job
  (`npm test` in `tests/e2e`). Because `AAuth.R3` (and, once ported, `AAuth.R3.Tests`)
  are in `AAuth.slnx`, **CI needs no workflow-file change** — new projects/tests are
  picked up automatically. Verify only that the ported test project is added to the
  solution and that the e2e harness starts Bookings + the shared AS (a Phase 8
  dependency), not that `ci.yml` itself changes.
- [.github/workflows/publish.yml](../../../.github/workflows/publish.yml) packs
  **only** `src/AAuth/AAuth.csproj` with `-p:PackageVersion=${{ inputs.version }}`,
  then `dotnet nuget push ./nupkg/*.nupkg` (wildcard) and `gh release create …
  ./nupkg/*.nupkg`. It authenticates via **OIDC trusted publishing** (`NuGet/login@v1`).

**Files**

| File | Action |
|---|---|
| `src/AAuth.R3/AAuth.R3.csproj` | **Modify** (on Phase 1 relocation) — `IsPackable=true`, `PackageId=AAuth.R3`, description/authors/license/repository/README/tags, preview; **no `<Version>`** (the pipeline stamps it, CC8) |
| [.github/workflows/publish.yml](../../../.github/workflows/publish.yml) | **Modify** — add a second `dotnet pack` for `src/AAuth.R3/AAuth.R3.csproj` with the **same** `-p:PackageVersion=${{ inputs.version }}` into the same `./nupkg`. The existing wildcard `push` and `gh release` steps then cover both nupkgs unchanged |

**Implementation Decisions**

- **Same version as `AAuth`** (CC8): no new version input. Packing `AAuth.R3` with the
  same global `-p:PackageVersion` stamps both the package and its `AAuth` dependency.
- Validate via the workflow's **`dry-run=true`** path that (a) two nupkgs are produced
  and (b) the `AAuth.R3` nuspec's `AAuth` dependency version equals `inputs.version`.

**Definition of Done**

- [x] `AAuth.R3` is packable (`PackageId=AAuth.R3`) with complete package metadata.
- [x] Packing produces **both** `AAuth` and `AAuth.R3` nupkgs (verified locally with
      `dotnet pack -p:PackageVersion=9.9.9-test`, replicating the workflow step).
- [x] The `AAuth.R3` nupkg depends on `AAuth` at the **same** version.
- [x] CI is green with the new projects/tests via solution-wide commands; **no**
      `ci.yml` edit was required (confirmed).

---

## Phase 11 — Internal review

A fresh subagent validates the implementation against the spec, `research.md`, and
this plan, with severity-graded findings.

**Definition of Done**

- [ ] Subagent report attached (or logged) with findings triaged.
- [ ] Every security invariant (research §F) has a passing test.
- [ ] The release **dry-run** (Phase 10) is green — both nupkgs, correct dependency version.
- [ ] No open `PROCEEDED` decision left unreviewed in `implementation-log.md`.

---

## Phase 12 — Manual nuget.org tasks (owner) — FINAL

> **The only steps that cannot be automated in-repo** — they require owner action on
> nuget.org and are deliberately kept **last**. Do them **after** Phases 10–11 land
> and the dry-run publish is green; nothing else in the plan depends on them. The
> agent cannot perform these.

**Owner tasks (nuget.org):**

- [ ] **Trusted Publishing policy for `AAuth.R3`.** The publish workflow authenticates
      via OIDC (`NuGet/login@v1`). Add a Trusted Publishing policy on nuget.org for
      the **new** package ID `AAuth.R3` (same GitHub repo/workflow/owner as the
      existing `AAuth` policy). Without it, the OIDC push of `AAuth.R3` is rejected.
- [ ] **Package ID availability / prefix reservation.** Confirm `AAuth.R3` is
      available; if the `AAuth` ID-prefix is reserved, extend the reservation to the
      `AAuth.*` glob (else the first publish establishes ownership).
- [ ] **First real release.** Run `publish.yml` with `dry-run=false` at the chosen
      version (same as `AAuth`); confirm both packages list on nuget.org and the
      GitHub release carries both nupkgs.
- [ ] Confirm the `AAuth.R3` listing shows **prerelease/preview** (version suffix).

**Definition of Done**

- [ ] Owner has completed the nuget.org trusted-publishing + ID steps above.
- [ ] A real (`dry-run=false`) publish pushes both `AAuth` and `AAuth.R3`.

---

## Out of scope

| Item | Reason |
|---|---|
| RFC 8785 / JCS canonical JSON | R3 hashes verbatim bytes (r3 L335); not required |
| Fully-typed models for all seven vocabularies | Escape hatch suffices for the demo (Q1) |
| Vocabulary *discovery* parsing (MCP tool list / OpenAPI / `$metadata` fetch) | Later R3 phase at most |
| PS-side `r3_granted` minting | Out of spec — PS is display-only (r3 L391, L404) |
| Single dual-mode access server | Superseded 2026-07-02 — replaced by two single-purpose AS under `MockAccessServers/` (`Federated` + `R3`); see log |
| R3-specific claims/props in the core `AAuth` package | R3 ships as the separate `AAuth.R3` package (CC7); core gets only generic seams |
| Mission ↔ R3 combined governance flow | Spec undefined; keep orthogonal unless decided |

---

## Git steps (Phase 0 companion)

1. Create a local feature branch off the current branch.
2. Commit `research.md`, `implementation-plan.md`, and `implementation-log.md`.
3. Do **not** push; comparison against `nedruk:feat/r3-rich-resource-requests`
   happens in a separate worktree.
