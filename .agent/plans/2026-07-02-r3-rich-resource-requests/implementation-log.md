# R3 (Rich Resource Requests) — Implementation Log

Dated, append-only record of decisions, deviations, and open inputs made while
implementing. Append; do not rewrite. A reversed decision gets a new entry that
supersedes the old one.

- **Plan:** [implementation-plan.md](implementation-plan.md)
- **Research:** [research.md](research.md)

## Decisions

### [2026-07-02] [Phase 0] Q1 — Vocabulary coverage — PROCEEDED (default)

Type **MCP + OpenAPI** first-class with a generic `JsonObject` escape hatch for the
other five vocabularies. The spec does not require all seven be typed
([research §D-S1](research.md)); the escape hatch must preserve each vocabulary's
REQUIRED extra keys and snake_case names. Revert to full typing if a later sample
needs gRPC/GraphQL/etc. first-class.

### [2026-07-02] [Phase 0] Q2 — Bookings vocabulary — PROCEEDED (default)

Bookings advertises the **OpenAPI** vocabulary (`operationId`) — the natural
ASP.NET fit. MCP remains available and MAY be advertised simultaneously (r3 L112).
Revert/extend if the tour wants to show Aria as an MCP client here.

### [2026-07-02] [Phase 0] Q3 — Bookings AS port — PROCEEDED (default)

Dedicated Bookings AS on **:5501** (groups with the AS role at :5500). :5005 is the
Bookings resource. Revert to :5006 if AS-role grouping is undesirable.

### [2026-07-02] [Phase 0] Q4 — AS-only-fetch gate shape — PROCEEDED (default)

A dedicated **`MapAAuthR3Document(pattern, store, asIssuer)`** mapper that (a) serves
persisted bytes raw and (b) pins the verified signer to the resource's AS. Preferred
over a `.RequireAAuthSignature(pinnedIssuer:)` overload because the mapper also owns
byte-verbatim serving — the two obligations travel together (research §D-S5,
security invariant F2). Revert to an overload if the mapper proves redundant.

### [2026-07-02] [Phase 0] Q5 — Proposal store seam — PROCEEDED (default)

Reuse **`IR3DocumentStore`** for both class documents and per-call proposals (both
are content-addressed R3 documents). Revert to a distinct `IR3ProposalStore` only if
proposal lifecycle (single-use, short TTL) diverges enough to warrant it.

### [2026-07-02] [Phase 0] Q6 — GuidedTour placement — PROCEEDED (default)

New `TourMode.RichRequests` inserted **after `Federated`** (its four-party
neighbour). Enum has no persisted int values, so insertion is safe; every
`Mode is TourMode.X ? …` switch gets a matching arm. Revert ordering if the tour
narrative reads better elsewhere.

### [2026-07-02] [Phase 0] CC3 — Bookings access mode — RESOLVED

Four-party with a **dedicated** Bookings AS (not reusing MockAccessServer). R3 grant
population and per-call evaluation are AS-centric (r3 L391/L404/L530); three-party
would force the PS to improvise the AS role. MockAccessServer is wallet/Keycloak-
shaped and scope-based; a dedicated operation-based AS keeps the teaching suite
clean (research §E).

### [2026-07-02] [Phase 0] CC7 — R3 ships as a separate `AAuth.R3` package — RESOLVED

Owner steer. R3 is an Exploratory Draft, so it lives in a new **`AAuth.R3`** NuGet
package (`src/AAuth.R3/`) depending on `AAuth` — not baked into core (our original
`src/AAuth/R3`) and not left as a sample-only library (Ana's `samples/AAuth.R3`).
Constraint this creates: core's sealed builders cannot gain R3-specific props, so
the **only** core changes are **generic** seams — `ResourceTokenBuilder.AdditionalClaims`,
a metadata `AdditionalMetadata` bag, and an AS resource-token decision hook. The
package's typed `R3AuthClaims`/`R3OperationSet` API keeps claim-name strings out of
consumer code (centralized constants inside the package), satisfying the
no-string-indirection principle at the API surface. Ana's `samples/AAuth.R3` is the
promotion candidate (she built it "extraction-ready"). Revert to core-`src/AAuth/R3`
only if R3 stabilizes and we want it first-class in the main package.

### [2026-07-02] [Phase 0] CC3/CC4 — REVISED: reuse the shared AS, config-free — SUPERSEDES the dedicated-AS ruling above

Owner steer ("reusing the same AS is okay, but one instance must work with all
samples without separate config"). Keep four-party, but **reuse the single
MockAccessServer** (:5500) rather than a dedicated Bookings AS (:5501). To make one
instance serve both Wallet and Bookings **without per-sample config**, make the AS
**R3-aware via a generic decision hook** (Phase 6): the `/token` handler branches on
whether the incoming resource token carries `r3_uri` — if so, fetch+verify+audit the
R3 document and mint R3 claims; otherwise run the base scope policy. This avoids
Ana's `Mode=R3` early-return and her `ConditionalTools` config: the granted-vs-
conditional split is **derived from the R3 document** (e.g. operations whose
`display.irreversible` is set are conditional). Net: no new AS port, no R3 launch
profile. Supersedes the [Q3] and [CC3 dedicated-AS] entries above.

### [2026-07-02] [Phase 0] Q2 — REVISED: MCP-first vocabulary — SUPERSEDES the OpenAPI default

Owner steer. The Bookings sample advertises **MCP** first (Aria is an agent that
"calls tools"; reuses Ana's working MCP models). The `AAuth.R3` package stays
**vocabulary-agnostic** so OpenAPI (or a second advertised vocabulary on the same
server — the spec allows it, r3 L112) is a cheap follow-up. Supersedes the [Q2]
OpenAPI default above.

### [2026-07-02] [Phase 0] Narrative reframe — Bookings = external Reservations provider — RESOLVED

Owner directive ("let's reframe the narrative"). Bookings is an **external
Reservations provider** for **dining & experiences** — not trip booking (Trips owns
that; Ana's `book_trip`/"Rich Trip Booking" collides). MCP tools:
`search_availability` (read → granted), `hold_reservation` (granted),
`confirm_reservation` (conditional — charges a non-refundable deposit, so it drives
the per-call proposal with venue/time/party-size/deposit as `parameters`). Threads
into Aria: "found a table and a tour; holding is free, confirming charges a deposit
→ per-call approval." Distinct from Trips (itinerary) and Wallet (bank rail).

### [2026-07-02] [Phase 1] Seeded R3 primitives from Ana's `AAuth.R3` library — PROCEEDED

Imported `samples/AAuth.R3/` verbatim from `nedruk/feat/r3-rich-resource-requests`
(HEAD `8402061`) as the Phase 1 starting point — 21 files (the `Model/` records,
`R3Hash`, `R3AuthClaims`, `R3ClaimReader`, `R3Challenge`, `R3Enforcement`,
`R3FetchClient`, `R3DocumentEndpoint`, `R3ProposalStore`, `R3Metadata`, `R3Request`,
`R3AccessTokenEndpoint`, `R3Audit`). Added to `AAuth.slnx`; builds cleanly against
our core (0 warnings/errors) and the full solution build stays green.

The import **confirms the generic-seam approach (CC7)**: her lib needs **no** core
changes — it hand-builds the resource-token JWT via the public
`ResourceTokenBuilder.TokenType`/`ResourceDwk` constants and mints auth-token claims
via the existing `AuthTokenBuilder.AdditionalClaims`. It already covers several
Phase 1/3/5/6 mechanics: verbatim `R3Hash`, MCP models, both-or-neither
`r3_uri`/`r3_s256` validation, AS-signed fetch + hash-verify (`R3FetchClient`),
the AS-only-fetch predicate (`R3DocumentEndpoint`), per-call proposal + digest
enforcement (`R3Challenge`/`R3Enforcement`), and an R3 audit sink (`R3Audit`).

Provenance: **only** the library was imported — not Ana's Bookings server, AS `Mode=R3`
switch, GuidedTour, or SampleApp changes (those are Phases 7–8 and are reworked per
the revised plan: shared AS, reservations narrative). Phase 1 follow-ups: (1) relocate
`samples/AAuth.R3` → `src/AAuth.R3` as a packable preview package; (2) reconcile the
hand-built resource token onto the generic `ResourceTokenBuilder.AdditionalClaims`
seam; (3) port `tests/AAuth.R3.Tests` (23 tests); (4) the `book_trip` →
`confirm_reservation` rename is sample-side (the lib is tool-agnostic).

### [2026-07-02] [Phase 0] CC8 — R3 package version tracks `AAuth` — PROCEEDED (default)

Owner steer ("we could technically use the same version as aauth for r3 for now").
`AAuth.R3` ships at the **same version** as `AAuth` — no separate version input in
`publish.yml`. Packing `AAuth.R3` with the same global `-p:PackageVersion` stamps
both the package and its `AAuth` dependency. Revisit if R3 needs an independent
release cadence once it stabilizes.

### [2026-07-02] [Phase 0] CI / release pipeline plan — RESOLVED

Reviewed the existing pipelines. **`ci.yml` needs no change**: it builds/tests the
whole `AAuth.slnx` and runs Playwright e2e via `npm test`, so the new `AAuth.R3` +
`AAuth.R3.Tests` (and any Bookings e2e specs) are covered once they are in the
solution / e2e harness. **`publish.yml` needs one change**: a second `dotnet pack`
for `src/AAuth.R3/AAuth.R3.csproj` (same version) into `./nupkg`; the existing
wildcard `push` and `gh release` steps then cover both nupkgs. These are Phase 10
(automatable). The **manual nuget.org steps** (Trusted Publishing policy for the new
`AAuth.R3` ID, ID/prefix availability, first real publish) cannot be done in-repo and
are deferred to the **final Phase 12**, per the owner instruction to keep them last.

### [2026-07-02] [Phase 1] Relocation + test port complete — RESOLVED

Moved `samples/AAuth.R3` → `src/AAuth.R3` (packable, `PackageId=AAuth.R3`) and ported
Ana's `tests/AAuth.R3.Tests` — now **30** tests (not 23; she grew it in later
commits) — repointing the project reference to `src/AAuth.R3`. Full suite green:
AAuth.R3.Tests 30, AAuth.Tests 517, AAuth.Conformance 571; `dotnet build AAuth.slnx`
0/0. The test commit is authored to `ana <asmirnova@microsoft.com>` (committer = me)
per the owner's attribution instruction.

### [2026-07-02] [Phases 2–6] SDK-side R3 delivered by the import — generic core seams DROPPED — RESOLVED

Inspecting the imported library shows it implements the Phase 2–6 functionality
**entirely sample-side with zero core changes**: `R3Metadata` composes
`r3_vocabularies`; `R3Challenge` hand-builds the resource token (its own
`SignCompact`, reusing `ResourceTokenBuilder.TokenType`/`ResourceDwk` constants);
`R3AuthClaims`/`R3ClaimReader` handle auth-token claims via
`AuthTokenBuilder.AdditionalClaims`; `R3DocumentEndpoint` gates the R3 doc to a
trusted-fetcher set; `R3FetchClient` does AS-signed fetch + hash-verify;
`R3AccessTokenEndpoint` + `R3Audit` mint + audit. All covered by the 30 tests.

Decision: **drop the planned generic core seams** (`ResourceTokenBuilder.AdditionalClaims`,
metadata `AdditionalMetadata`, AS decision hook). They are unnecessary — R3 needs
**zero** core changes, which is even better isolation for an Exploratory-Draft feature
(CC7's intent taken to its conclusion). The one tradeoff (`R3Challenge` duplicates
~6 lines of JWT signing because core `JwtWriter` is `internal`) is accepted; revisit
only if R3 is promoted into core. Phases 2/3/5/6 are therefore **satisfied by the
import**; their generic-seam DoD items are out of scope. Active remaining work:
Phase 7 (Bookings sample), Phase 8 (integration), Phase 9 (docs), Phase 10 (release,
done below), Phase 11 (review), Phase 12 (owner nuget.org).

### [2026-07-02] [Phase 10] publish.yml packs AAuth.R3 — RESOLVED

Added a second `dotnet pack` for `src/AAuth.R3/AAuth.R3.csproj` (same
`-p:PackageVersion`) to the `Pack` step; the existing wildcard push + `gh release`
cover both nupkgs unchanged. Local dry-run (`-p:PackageVersion=9.9.9-test`) confirms
both nupkgs build and the `AAuth.R3` nuspec depends on `AAuth` at the **same**
version. `ci.yml` unchanged (solution-wide build/test covers the new projects).

### [2026-07-02] [Phase 7] AS structure — two dedicated servers under `MockAccessServers/` — SUPERSEDES CC3/CC4 (reuse-single-instance)

Owner steer ("cleaner to have a folder … one normal and one r3-specific … following
how we did the resource servers"). Reversed the "reuse one MockAccessServer via a
config-free hook" ruling. Added `samples/MockAccessServers/` mirroring
`samples/MockResourceServers/`:
- `Federated/` — the existing MockAccessServer, **moved + renamed** (namespace
  `Federated`), scope-based AS for Wallet, :5500. Pure rename (validated); rewired
  slnx / AAuth.Tests ref / Makefile / e2e / test type refs; 517 AAuth.Tests green.
- `R3/` — **new** dedicated R3 AS (:5501, namespace `R3AccessServer`) via
  `MapR3AccessTokenEndpoint`; guards Bookings.
Two single-purpose, always-on servers — no `Mode=R3` switch, no `r3_uri`-branching
middleware. Cleaner than the reuse approach; matches the original research §E lean.

### [2026-07-02] [Phase 7] Conditional split — option A (doc-derived) — RESOLVES the open A/B/C question

Chose **option A**: added an optional `conditional` operations list to the preview
`R3Document`; the R3 AS derives the granted/conditional split from it and the
`ConditionalTools` AS option was removed. Bookings authors
`conditional:[confirm_reservation]`. Config-free (no per-AS tool list), keeps the
`r3_conditional` claim exercised, and the field is `[JsonIgnore(WhenWritingNull)]`
so it is omitted from the wire/hash when null (existing doc hashes unchanged). Note:
`conditional` is a **non-spec extension field** — it relocates the grant/conditional
decision from AS policy to a resource-authored hint (validation flagged this LOW;
revisit if a spec-literal AS-policy split is wanted).

### [2026-07-02] [Phase 7] High-level DI helpers in R3 samples/AS — RESOLVED

Owner directive (use the 2026-06-27 server-api-surface high-level APIs everywhere in
R3 samples/AS unless there is a very good reason not to). Fixed a manual-HttpClient
regression: the R3 AS now uses `AddAAuthDiscovery()` and Bookings uses
`AddAAuthResource(...)` (which folds in the verifier + shared discovery clients) —
zero `AddHttpClient`/named-client wiring, matching the `Federated` AS. Behavior-
preserving; solution builds 0/0, R3 tests 30 green.

### [2026-07-02] [Phase 7] Validation subagent — spec-compliant, no sample regressions — RESOLVED

A read-only validator audited the R3 implementation against v08 R3, checked the diff
scope, and ran the suites. Results: **no CRITICAL/HIGH/MEDIUM spec violations** (every
hard invariant — verbatim hashing, both-or-neither `r3_uri`/`r3_s256`, AS-only fetch
gate, per-call digest verify, atomic audit, hash-verify-before-use — compliant);
**one LOW** note (the `conditional` extension field, above). Change scope **PASS**:
only R3-relevant files touched; **zero** changes to other resource servers / PS / AP /
GuidedTour / SampleApp / Concierge / core `src/AAuth`; the `Federated` move is a pure
rename. Build 0/0; **1118 tests green** (R3 30, AAuth.Tests 517, Conformance 571);
e2e harness intact (45 specs, config parses with the moved AS path; R3 not yet in the
Playwright suite — Phase 8).

### [2026-07-02] [Phase 7] R3 AS Person-Server trust made 100% spec-compliant — RESOLVED

Owner directive (issuer validation must be 100% spec-compliant + the config pattern
must support it, per the 2026-06-29 ps-asserted-any-issuer-trust narrative). The R3
AS's PS trust check previously treated **both** null and empty `TrustedPersonServers`
as reject-all — wrong. Fixed to the canonical model: **null = open** (broker any
*verifiable* PS — the draft-08 spec default), **empty = deny-all**, entries narrow,
plus an optional `IsTrustedPersonServer` predicate composed by **AND**. The R3 AS now
reuses the **same `IssuerTrust.IsTrusted` decision path as the core Access Server**
(authority-normalized), so there is a single trust model. Added a `null=open` test
(broker any verifiable PS); renamed the empty-deny test; 31 R3 tests green.

### [2026-07-02] [Phase 7] Conditional split moved to AS policy — 100% spec-compliant — SUPERSEDES option A (doc-derived)

Owner directive ("make it 100% compliant"). r3 §Auth Token Extensions (L489) is
explicit: "the AS populates `r3_granted` and `r3_conditional` based on the operations
defined in the R3 document **and its own policy. The AS decides which operations to
grant outright and which to make conditional.**" The R3 document's spec model has only
`operations` (L322) + a **document-level** `display` (L324) — there is **no**
`conditional` field, and because `display` is document-level it cannot mark one
operation in a multi-op document as conditional. Option A's resource-authored
`R3Document.conditional` therefore relocated an AS-policy decision into a non-spec
document field (the earlier LOW validator finding).

Fix: **removed `R3Document.conditional`** and added an AS-policy input
`R3AccessTokenEndpointOptions.IsConditionalOperation` (`Func<McpOperation,bool>?`;
`null` ⇒ grant all, since `r3_conditional` is OPTIONAL). `EvaluateDocumentAsync` splits
via this policy. The dedicated Bookings R3 AS supplies it from config
(`R3AccessServer:ConditionalOperations`, default `["confirm_reservation"]`), mirroring
the `TrustedPersonServers` config pattern — this *is* "the AS's own policy." Bookings'
R3 document now carries only spec fields (`operations` + `display`, keeping the
`display.irreversible` human signal). Wire claims unchanged (`r3_granted`/
`r3_conditional`); doc hashes unaffected (the field was `WhenWritingNull`). Test fixture
sets `IsConditionalOperation = op => op.Tool == "book_trip"`; `R3TestData.Document()`
dropped its `Conditional`. Build 0/0; 31 R3 tests green. Supersedes the option-A
entries above and clears the sole LOW validator finding.

### [2026-07-02] [Phase 7] AdditionalMetadata seam added; Bookings uses MapAAuthWellKnown — SUPERSEDES "generic seams dropped" (metadata bag) + the well-known half of "Bookings hand-rolls"

Owner directive: prefer the high-level `MapAAuthWellKnown` API and add the generic
`AdditionalMetadata` seam for extensibility ("the seam allows extensibility"). Re-introduced
**one** of the three core seams originally dropped when Ana's import proved zero-core-change:
added `AAuthResourceMetadataOptions.AdditionalMetadata`
(`IReadOnlyDictionary<string, JsonNode?>?`) + the matching
`AAuthResourceOptions.AdditionalMetadata`, emitted verbatim in `BuildResourceMetadata`
after the typed fields (a colliding key is skipped — the typed field wins; core attaches
no meaning). Two conformance tests (merge + collision-skip); Conformance 573.

Bookings now configures metadata through `AddAAuthResource` (Name, Description,
AccessMode, AuthorizationEndpoint, SigningKeys, and `AdditionalMetadata` =
`{ mission_aware, r3_vocabularies }`) and serves discovery via `MapAAuthWellKnown()` —
dropping its hand-rolled `/.well-known/aauth-resource.json` + `/.well-known/jwks.json`
+ `BuildJwks`. Bonus fix: the hand-rolled doc emitted the legacy `client_name`; the
core builder emits the draft-08 `name`. This resolves the well-known/JWKS half of the
earlier "Bookings diverges" deviation. The other half stands: R3 authz is
operation-based (match against `r3_granted`/`r3_conditional` in-handler), so Bookings
still does not use `UseAAuth`/`.RequireAAuth`. Build 0/0; 517 + 573 + 31 tests green.

### [2026-07-02] [Phase 13] Bookings switches to the OpenAPI vocabulary; AAuth.R3 made vocabulary-agnostic — SUPERSEDES CC2/Q2 MCP-first

Owner steer ("just use the openapi vocabulary"). The MCP vocabulary is defined "for
resources that expose an MCP server" (r3 L107): discovery endpoint = MCP server URL,
tool names via MCP tool discovery. Bookings is a plain ASP.NET HTTP API and the `/mcp`
route was only a stand-in tool list — not a conformant MCP server — so advertising
`urn:aauth:vocabulary:mcp` misrepresented the resource. Switched Bookings to
`urn:aauth:vocabulary:openapi` (operations `{operationId}`, discovery = the OpenAPI
spec URL, r3 L124-L140).

To do this honestly, replaced the MCP-typed `McpOperation` with a single
vocabulary-agnostic `R3Operation` (`{ <field>: <id> }`, self-describing so any
single-identifier vocabulary — `tool`/`operationId`/`method`/… — round-trips
byte-stably via a converter; factories `R3Operation.Mcp`/`OpenApi`). Clean cutover, no
compat shim (guiding principles). `R3Grant.ContainsTool` → `Contains(id)`; enforcement
builds proposals with the grant's own vocabulary (dropped the hardcoded
`Vocabulary.Mcp`); `IsConditionalOperation` is now `Func<R3Operation,bool>`. Bookings
operationIds `searchAvailability`/`holdReservation`/`confirmReservation`; the R3 AS
conditional policy keys on `confirmReservation`. See Phase 13.

### [2026-07-02] [Phase 13/9] Doc sweep for the OpenAPI switch + new sample READMEs — RESOLVED

Re-ran the docs sweep after the OpenAPI cutover and the earlier `MockAccessServer` →
`MockAccessServers/Federated` move. Changes:
- **New** [`samples/MockAccessServers/README.md`](../../../samples/MockAccessServers/README.md)
  — access-server suite overview (Federated :5500 + R3 :5501), mirroring the
  MockResourceServers README.
- **New** [`samples/MockResourceServers/Bookings/README.md`](../../../samples/MockResourceServers/Bookings/README.md)
  — Bookings resource README (the only resource server that lacked one), documenting
  the OpenAPI vocabulary, operationIds, per-call proposal, config, and run steps.
- **Refreshed** the `AAuth.R3` NuGet README: vocabulary-agnostic `R3Operation`
  (`Mcp`/`OpenApi`), corrected type names (`R3Operations`/`R3Operation`, not the
  non-existent `R3OperationSet`), dropped "MCP-first", and pointed at the OpenAPI
  Bookings demo.
- **Swept stale paths** from the Federated move in live docs: `samples/README.md`
  (added Bookings + both access-server rows, corrected count, fixed the AS link),
  `docs/workflows/federated-access.md` (3 links), `Wallet/README.md`, and the
  Federated README's own title + run command. Indexed the R3 workflow in
  `docs/README.md`. Historical `.agent/plans/*` references left untouched (append-only).
- **Workflow doc + MockResourceServers README** updated to OpenAPI wording
  (operationIds, `/openapi.json` discovery, `operationId` response field).

Net R3 doc surface: workflow doc, MockResourceServers README + Bookings README,
MockAccessServers README, R3 NuGet README, docs index. Build/tests unaffected
(docs only); last green state 32 / 517 / 573 stands.

### [2026-07-02] [Phase 8] SampleApp R3 (Bookings) page + nav + e2e — RESOLVED

Added `samples/SampleApp/Components/Pages/Bookings.razor` (`/bookings`), a nav item
after Federated (four-party grouping) with a `calendar-check` icon, and a home-page
card. The page reuses the ordinary four-party self-issued client
(`AAuthClientBuilder.SelfIssuing(...).WithChallengeHandling()`) — the R3 semantics ride
the tokens, not the client. Wiring: appsettings `AAuth:Bookings`/`AAuth:R3AccessServer`;
the e2e MockPersonServer now federates to both `:5500` and `:5501`.

Validated end-to-end via Playwright (`bookings.spec.ts`, sample-app project): **search
availability** completes the full four-party R3 flow (Bookings 401 → PS federates to
the R3 AS → AS fetches + hash-verifies the R3 doc → mints `r3_granted` → 200). Both R3
e2e tests green.

### [2026-07-02] [Phase 8] Per-call proposal AUTO-completion over the live stack — GAP (revisit)

`confirmReservation` is `r3_conditional`: the resource correctly replies
`401 r3_approval_required` with a per-call proposal (the SampleApp demo + e2e assert
exactly this — the correct observable). **Auto-completing** the proposal round-trip in
one agent call requires the agent to follow a *second* auth-token challenge (the
proposal), which the core `ChallengeHandler` does not do (it follows exactly one). A
looping variant (cap 3) was prototyped and passed all unit/conformance suites
(32/517/573), but over the **live** four-party stack the second (proposal) exchange
did not complete (the agent call blocked; the PS logged only the first PS→AS
federation) and the cause was not isolated in-session. To keep the demo/e2e reliable
and avoid an unexplained live block, the loop was **reverted** to the known-good
single-challenge behavior. The per-call proposal **mechanics are fully verified
in-proc** (`ResourceR3Tests` digest-match + approved-retry; `AccessEndpointR3Tests`
proposal mint), so the protocol is correct. **Revisit:** make the `ChallengeHandler`
follow chained auth-token challenges (needed for R3 conditional auto-completion) and
root-cause the live second-exchange block, then assert full `confirmReservation` → 200
completion in e2e.

### [2026-07-02] [Phase 8] GuidedTour interactive R3 flow — DEFERRED (follow-up)

The GuidedTour engine (`TourSession.RunNextAsync`) runs a bespoke, live, per-step HTTP
orchestration for each flow (the Federated flow alone is ~10 hand-written
`StepFederated*` methods plus plan/highlighter/lane wiring). A faithful R3 flow would
add a parallel step set (granted path ≈ the four-party Federated path; plus the
conditional per-call proposal, which shares the live auto-completion gap above), a
picker option, a home flow card, actor lanes, and an e2e spec. Given the SampleApp
already ships a **validated, interactive R3 demonstrator** (`/bookings`, both paths
green in Playwright), the tour flow is deferred as a single coherent follow-up rather
than shipped half-built. The GuidedTour home intro deliberately promises "each flow
below follows Aria across these services," so Bookings is **not** added to the intro
list until its flow exists (keeping the page coherent). Scaffolding already landed:
`TourMode.RichRequests` + `BookingsUrl`/`R3AccessServerUrl` options + appsettings.

**Owner pointers captured for the follow-up:** place the flow right after `Federated`
(four-party neighbour); add the SampleApp-style nav/index entry; update the tour home
resource-name list to include Bookings; add the e2e spec + update `home.spec.ts`
(FLOWS array + count) and `actor-bar-visual.spec.ts`.

### [2026-07-02] [Phase 8] Standalone in-proc BookingsFlowTests — DEFERRED (superseded)

Rationale: the Bookings sample's four-party composition (proactive/reactive resource
token → PS federation → R3 AS mint → granted enforcement) is now **validated
end-to-end by the SampleApp Playwright spec** against the real Bookings + R3 AS + PS,
and the R3 **mechanics** (granted/conditional split, per-call proposal digest match,
tamper reject) are covered by the in-proc `AAuth.R3.Tests` (`ResourceR3Tests`,
`AccessEndpointR3Tests`). A *true* in-proc four-party `BookingsFlowTests` is also
blocked by the same seam as the ChallengeHandler follow-up: the R3 AS sample's
document fetch uses a non-injectable `HttpClient` (`R3FetchClient.Create` default
handler), so a `TestServer`-hosted AS can't reach the in-proc Bookings. Revisit
alongside making that fetch handler injectable.

### [2026-07-03] [Phase 8] Per-call proposal AUTO-completion + human consent — RESOLVED — SUPERSEDES the [Phase 8] "AUTO-completion GAP (revisit)" entry

Owner directive: the SampleApp `confirmReservation` returned `401` to the user, and the
ask was to add the missing second step — follow the consent link and approve, like the
other interactive flows — "following the spec guidance to the letter." Chose the
spec-faithful path (r3 §Per-Call Proposals, Flow step 2: *"the PS renders `display` for
user consent. On approval, the AS issues a per-call auth token"*): full **per-call human
consent**, then `200`.

Three coordinated changes:

1. **Agent — `ChallengeHandler` now follows chained auth-token challenges** (cap 3).
   R3 grants against the class document, then the resource challenges again with the
   per-call proposal (resource step-up); the handler exchanges + retries each auth-token
   challenge. Single-challenge flows are unchanged (the loop body runs once).
   **Root cause of the earlier live block, isolated:** the token exchange to the PS MUST
   be **agent-signed** (§Agent Token Request — the PS rejects a non-agent carrier with
   `403 invalid_carrier_token`). The exchange signer reads the shared `AAuthTokenHolder`,
   and after the first exchange the holder carries the *first auth token*; the second
   exchange was therefore signed with that auth token and rejected `403`. Fix: capture
   the agent token at entry and **re-pin the holder to it before every exchange**, then
   install the returned auth token as the carrier for the resource retry. (This latent
   hazard also existed for any reused client doing a second challenge; now handled.)

2. **R3 AS — per-call proposal consent gate.** `R3AccessTokenEndpointOptions` gains
   `RequireProposalConsent` (default `false`), `ConsentPath` (`/interaction/consent`),
   `PendingPath` (`/pending`). When a **proposal** is presented and consent is required,
   `/token` returns `202 { status:"pending" }` + `Location: /pending/{id}` +
   `Retry-After` + `AAuth-Requirement: requirement=interaction; url=…; code=…` (the same
   202-interaction contract the PS relays and the agent polls). The AS renders the
   proposal's `display` at a browser consent screen (same `button.approve`/`button.deny`
   selectors as the Federated AS) and mints the per-call token **only on approval**
   (polled at `/pending/{id}`); denial ⇒ `403`. Minting + audit are shared by the granted
   path and the post-consent path (`MintAndAuditAsync`). The dedicated Bookings R3 AS sets
   `RequireProposalConsent = true`.

3. **SampleApp Bookings page — interaction + poll UX.** `confirmReservation` now wires
   `OnInteractionRequired` to surface the R3 AS consent link + a spinner (mirroring
   `Federated.razor`); after approval the SDK polls and the booking completes (`200`
   `status:"confirmed"`, `source:"per-call-r3_granted"`).

**Validation:** R3 34 (added `TokenEndpoint_RequiresConsentForProposal_ThenMintsOnApproval`
+ a deny test), AAuth.Tests 517, Conformance 573 — all green. `bookings.spec.ts` conditional
test rewritten to the full popup-approve → `200 confirmed` flow; **full sample-app e2e suite
green (20 specs)** — federated/deferred/call-chain/mission unaffected by the ChallengeHandler
change. Live wire verified: R3 AS `/token` → `202`, PS polls `/pending/{id}` `202`→`200` after
approval. The per-call digest match / tamper-reject mechanics remain covered in-proc
(`ResourceR3Tests`). **Note:** the R3 AS `/pending` is opaque-id (no signature verify) — an
accepted demo simplification (the minted token is `cnf`-bound).

### [2026-07-03] [Phase 8] GuidedTour interactive R3 flow — STILL DEFERRED (now partly unblocked)

The ChallengeHandler chained-challenge fix above removes the technical blocker that the
prior deferral cited (live per-call auto-completion). The GuidedTour flow remains deferred
as a coherent follow-up (bespoke `TourSession` step set + picker + home card + actor lanes
+ e2e), but the hard protocol gap is now closed; the follow-up is purely tour-authoring.

### [2026-07-03] [Phase 8] Consent hardening + docs/snippet follow-ups — RESOLVED

Four owner-requested follow-ups on the per-call consent flow:

1. **Docs now match the consent flow.** [rich-resource-requests.md](../../../docs/workflows/rich-resource-requests.md)
   sequence diagram + "Granted vs conditional" narrative now show the `202` + R3 AS consent
   screen + signed `/pending` poll before the per-call token is minted (r3 §Per-Call Proposals
   Flow step 2). [Bookings README](../../../samples/MockResourceServers/Bookings/README.md)
   conditional row/narrative updated to say **human approval** rather than "after AS approval".
2. **R3 AS consent banner is now red** (`#b91c1c` + `#fecaca` dot), matching the Federated AS
   **Access Server** banner / four-party swimlane, so the two AS consent screens are visually
   consistent.
3. **`/pending` poll is signature-verified (per spec).** The `GET {pendingPath}/{id}` handler
   now runs the same `R3DocumentEndpoint.VerifyFetcherAsync` + `IsCallerTrustedPersonServer`
   check as `/token` — the deferred poll rides the signed PS→AS federation channel (mirrors the
   core `MapAAuthAccessServer`, which signs `/pending/{id}` and leaves only the browser
   `/interaction/*` endpoints unsigned). The opaque-id simplification noted earlier is removed.
   Tests: added a signed `PollPendingAsync` fixture helper (the two consent tests now poll
   through it) and a `TokenEndpoint_PendingPoll_RejectsUnsignedCaller` negative test (401). R3 35.
4. **SampleApp agent snippet shows minimal interaction handling.** [Bookings.razor](../../../samples/SampleApp/Components/Pages/Bookings.razor)
   client snippet now wires `opts.OnInteractionRequired` (surface `interaction.BuildUserUrl()`)
   instead of a bare `.WithChallengeHandling()`, and the R3 AS snippet includes
   `RequireProposalConsent = true` — so the displayed code matches what the page actually runs.

Validation: build 0/0; R3 35, AAuth.Tests 517, Conformance 573; Bookings e2e (both specs) green
with the signed `/pending` poll (202→200).

### [2026-07-03] [Phase 8] Injectable AS fetch seam — RESOLVES the BookingsFlowTests blocker

The deferred in-proc `BookingsFlowTests` was blocked because the R3 AS's document fetch used
a non-injectable `HttpClient`, so a TestServer-hosted AS couldn't reach an in-proc resource.
Added `R3AccessTokenEndpointOptions.FetchHttpMessageHandler` (an optional inner handler for the
AS's signed R3-document fetch; ignored when `FetchAndVerifyAsync` is set) and wired it through
`FetchAsync` → `R3FetchClient.Create(..., handler)` (which already accepted a handler). New test
`TokenEndpoint_FetchesDocumentOverInjectedHandler_ThenMints` drives the AS's **real** R3FetchClient
signed fetch + `r3_s256` hash-verify + granted mint against an in-proc doc server via the seam —
coverage the `FetchAndVerifyAsync` bypass previously skipped. R3 36.

Scope note: this removes the blocker and covers the AS-side real fetch in-proc. A full
multi-app `WebApplicationFactory` orchestration of Bookings + R3 AS + PS + agent is **not** added —
the complete four-party Bookings composition is already validated end-to-end by the SampleApp
Playwright specs (granted + conditional-consent → 200), so an in-proc replica would be redundant
and fragile. Supersedes the "Standalone in-proc BookingsFlowTests — DEFERRED" entry.

### [2026-07-03] [Phase 8] GuidedTour R3 flow — scope refined; remains the last deferred item

Full implementation map produced (session research: engine = `TourSession.RunNextAsync`; model =
the `StepFederated*` methods; 33-item wiring checklist across `TourSession.cs`, `Tour.razor`,
`Home.razor`, `tests/e2e/helpers/tour.ts`, `home.spec.ts`, `actor-bar-visual.spec.ts` + a new tour
spec). Scaffolding already present: `TourMode.RichRequests`, `BookingsUrl`/`R3AccessServerUrl`
options + appsettings, `Actor.AccessServer` lane, shared poll/approve steps.

**Refined scope (important):** the R3 tour flow is **not** a clean copy of the Federated flow.
Federated's consent branch is an interactive login on the *first* exchange; R3's consent is a
**per-call proposal step-up on the conditional operation**. A faithful R3 tour is therefore a
bespoke ~12-step sequence — granted op (`search_availability` → `r3_granted` → 200), then the
conditional op (`confirm_reservation` → 401 per-call proposal → exchange → 202 consent at the
R3 AS → approve → poll → retry → 200) — with new plan arrays, dispatch, state, lanes, picker/home
entries, and a tour e2e. It needs a full live-stack Playwright validation cycle. Given its size
and that the SampleApp already ships the **validated, interactive** R3 demonstrator (`/bookings`,
both paths green), it is carried as the single remaining follow-up rather than shipped half-built.

### [2026-07-03] [Phase 14] GuidedTour R3 flow — planned (sub-research + phase added) — PROCEEDED

Owner directive: implement the GuidedTour R3 flow (every SampleApp flow has a mirrored tour
flow); use a subagent for sub-research; record in research/plan/log; and render backend hops
the agent can't observe as **bundled SubSteps within a component box** (like other tour flows).

Actions: dispatched one read-only research subagent (report:
`.copilot-tracking/research/subagents/2026-07-03/guided-tour-r3-flow.md`), re-verified the
highest-stakes anchors directly against source (Bookings/Program.cs response shapes; the
Federated dispatch + `SubStep` pattern; the "R3 Access Server" consent badge), added
**research Part H** (design + method) and **plan Phase 14** (files + DoD).

Design decisions (defaults; revert if disagreed):
- **Bundled backend SubSteps** (owner directive): PS→AS federation, AS→resource R3-fetch +
  hash-verify + granted/conditional split + mint, and per-call proposal evaluation are shown
  as `SubStep[]` in a component box on steps 5 & 9 — not separate agent steps. Mirrors
  `StepFederatedExchangeAsync`.
- **Single linear 14-step plan, no branch:** the R3 AS's `RequireProposalConsent = true` means
  `confirm_reservation` always needs consent, so (unlike Federated's 7-vs-10 `_federatedPending`
  branch) there is no pending flag and no ConsentPlan. Steps 1–6 granted (`search_availability`),
  7–14 conditional (per-call proposal → 202 consent → poll → retry).
- `SubStepsLabel = "inside person server + R3 AS"` (more precise than Federated's "inside
  person server" since the bundle spans the AS→resource fetch).
- Omit `hold_reservation` (mirror the SampleApp, which shows only search + confirm).
- Picker/home **position 8**; renumber Mission/MissionCallChain/SubAgent → 9/10/11.
- `PLAN_STEPS.RichRequests = 14`; the e2e approval-park done-count is validated empirically
  (approval is step 11).

Purely additive UI/demo — no core or `AAuth.R3` changes. Implementation follows.

### [2026-07-03] [Phase 14] GuidedTour R3 flow — IMPLEMENTED — RESOLVES the deferred GuidedTour follow-up

Implemented per the plan (via a Phase Implementor subagent; independently re-verified). Added a
single linear 14-step `TourMode.RichRequests` flow to GuidedTour mirroring the SampleApp Bookings
page: granted `search_availability` (steps 1–6) then conditional `confirm_reservation` per-call
proposal → 202 consent at the R3 AS → poll → digest-verified retry (steps 7–14). Backend hops
(PS→AS federation, AS→Bookings R3/proposal fetch + hash-verify + split/eval + mint) render as
**bundled `SubStep[]`** on steps 5 & 9, `SubStepsLabel = "inside person server + R3 AS"` — per
the owner directive, never separate agent steps.

Files: `TourSession.cs` (+629: mode props, `RichRequestsPlan`, dispatch, 11 `StepRichRequests*`
methods, state, `Reset`), `CodeSnippets.cs` (`R3ConfirmConditional`), `Tour.razor` (lanes, picker
pos 8 + renumber 9/10/11, consent wording, R3 AS topbar), `Home.razor` (Bookings server + card,
renumber), `wwwroot/app.css` (`.srv--bookings`), `tests/e2e/helpers/tour.ts`
(`RichRequests`/`PLAN_STEPS=14`), `home.spec.ts`, `actor-bar-visual.spec.ts`, new
`richrequests.spec.ts` (approve + deny tests).

**Empirical:** `runAll` done-count at the approval park = **10** (step 11 is the R3 AS approval);
after approve+poll → 12; final `runAll` → 14. Validated: build 0/0; R3 36 / AAuth.Tests 517 /
Conformance 573; guided-tour e2e green (richrequests approve+deny, home overview 11 flows +
Bookings server, actor-bar Bookings/:5005). Two minor additive polish items beyond the file list
(a `.srv--bookings` CSS rule; an R3 arm in the Tour topbar + runAll stop-message) — consistent
with the Federated model. This closes the last deferred R3 item.

## Deviations from plan

### [2026-07-02] [Phase 1] Mirror AAuth's `<Version>` in the R3 csproj — PROCEEDED (default)

Plan CC8/Phase 10 said "no `<Version>` (pipeline stamps it)", but core
`AAuth.csproj` itself hardcodes `<Version>0.1.0-alpha.1</Version>`. To keep the two
in lockstep and make the `AAuth` dependency resolve at the same version on a local
`dotnet pack`, `AAuth.R3.csproj` mirrors `<Version>0.1.0-alpha.1</Version>`. The
pipeline still overrides both via `-p:PackageVersion` (CC8 intact). Revert if the
version should be pipeline-only.

### [2026-07-02] [Phase 1] Defer resource-token seam reconciliation to Phase 3 — PROCEEDED (default)

The imported `R3Challenge` hand-builds the resource-token JWT using
`ResourceTokenBuilder.TokenType`/`ResourceDwk` constants (works, no core change).
The generic `ResourceTokenBuilder.AdditionalClaims` seam is **created in Phase 3**,
so routing the R3 resource-token claims through it is done there, not in Phase 1.
Phase 1 stays a clean relocate + test-port.

### [2026-07-02] [Phase 1] OpenAPI first-class models deferred — PROCEEDED (default)

The imported library is **MCP-only** (CC2 MCP-first). The Phase 1 DoD item is met
for MCP + the escape hatch; first-class OpenAPI operation typing is deferred (cheap
follow-up since the models generalize). Revert if OpenAPI is needed in the first cut.

### [2026-07-02] [Phase 7] Bookings diverges from the full resource convention — PROCEEDED (good reason)

Bookings uses `AddAAuthResource` (verifier + discovery) but **hand-rolls** its
well-known + JWKS and does **not** use `UseAAuth`/`.RequireAAuth`. Good reasons
(logged per owner request): (1) the well-known must advertise `r3_vocabularies`
(+ `mission_aware`), which `AAuthResourceMetadataOptions` does not model (we dropped
the generic `AdditionalMetadata` seam); (2) R3 enforcement is **operation-based**
(match the call against `r3_granted`/`r3_conditional` in-handler), which the
scope-based per-route `.RequireAAuth` filter does not express. The R3-specific
endpoint helpers (`MapR3Document`, `MapR3AccessTokenEndpoint`, per-call proposal) are
themselves the high-level API for R3. Revisit (add the `AdditionalMetadata` seam +
`MapAAuthWellKnown`) if R3 graduates from preview.

### [2026-07-02] [Phase 7] Federated config-section keys unchanged after the rename — PROCEEDED (default)

The moved AS kept its runtime config sections `MockAccessServer:TrustedPersonServers`
and `AccessServer:*` even though the project/namespace is now `Federated`. These are
shared with tests (`UseSetting`) and the Makefile env; renaming them is orthogonal
churn/risk with no functional benefit. Minor naming inconsistency accepted; revisit
if it confuses.

### [2026-07-02] [Phase 7] `IssuerTrust` promoted to public — PROCEEDED (generic core change)

To give the R3 AS the *same* trust decision as the core AS (rather than a divergent
copy), the generic `AAuth.Server.Verification.IssuerTrust` helper was made `public`
(was `internal`). This is a **generic, non-R3 core change** — a reusable trust
primitive for extension packages — not R3-specific knowledge, so it is consistent
with the CC7 "core gets only generic seams" posture (it slightly relaxes the earlier
"zero core changes" outcome). Revert to `internal` + duplicate the logic in the R3
package only if exposing it is unwanted.

### [2026-07-02] [Phase 7] Observed: `Federated` AS has a stale trust comment — NOTED (pre-existing, out of scope)

The moved `Federated` (ex-MockAccessServer) `Program.cs` carries a pre-existing
comment "An empty set trusts any signed caller," which is stale under the 2026-06-29
semantics (empty = deny-all; **null/unset** = open). Not changed here (out of scope
for R3; the move was a pure rename). Flagged for a separate cleanup.

## Open questions / inputs needed

_Q1–Q6 defaulted above. Revisit CC5/Q4 once the AS-signer URI exposure in
`AAuthVerificationResult` is confirmed during Phase 5._

### [2026-07-02] [Phase 7] How does the config-free AS learn which ops are conditional? — RESOLVED (option A + dedicated AS)

> **Resolved 2026-07-02:** chose **option A** (doc-derived `R3Document.conditional`)
> and, per the later owner steer, a **dedicated R3 AS** under `MockAccessServers/R3`
> (not a shared dual-mode instance). See the Decisions entries above. The options as
> originally weighed:

The shared MockAccessServer must serve Wallet **and** Bookings from one instance with
no R3-specific launch profile (owner requirement). Mounting R3 unconditionally is easy;
the open question is the **granted-vs-conditional split** without a per-server config
(Ana used `ConditionalTools=["book_trip"]`). Options:

- **A — doc-level conditional signal (recommended).** Add an OPTIONAL `conditional`
  operations list to the preview `R3Document` model (our package extension; not core,
  not the base-spec wire). Bookings authors `operations:[search,hold,confirm]` +
  `conditional:[confirm]`; the AS derives the split from the fetched doc. Config-free,
  keeps the `r3_conditional` auth-token claim exercised (the headline R3 feature).
  Cost: a non-standard doc field (logged) + small library/test changes.
- **B — resource step-up, AS grants all.** AS grants every op in the doc (zero policy);
  Bookings itself always challenges `confirm_reservation` with a per-call proposal
  (allowed resource step-up) and keys off its proposal store on retry. Simplest and
  fully config-free, but the `r3_conditional` claim is never populated (weaker demo).
- **C — keep a built-in default set in the AS.** Not truly config-free / couples the AS
  to Bookings' tool names. Rejected.

Recommendation: **A** (closest to the agreed "AS derives conditional from the R3
document"). Awaiting the owner's pick before implementing the AS rework.
