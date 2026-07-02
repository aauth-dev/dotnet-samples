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

## Deviations from plan

_None yet._

## Open questions / inputs needed

_None open; Q1–Q6 defaulted above. Revisit CC5/Q4 once the AS-signer URI exposure in
`AAuthVerificationResult` is confirmed during Phase 5._
