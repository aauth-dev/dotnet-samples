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

## Open questions / inputs needed

_None open; Q1–Q6 defaulted above. Revisit CC5/Q4 once the AS-signer URI exposure in
`AAuthVerificationResult` is confirmed during Phase 5._
