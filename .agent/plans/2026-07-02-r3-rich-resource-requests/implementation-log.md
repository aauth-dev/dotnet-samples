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

## Deviations from plan

_None yet._

## Open questions / inputs needed

_None open; Q1–Q6 defaulted above. Revisit CC5/Q4 once the AS-signer URI exposure in
`AAuthVerificationResult` is confirmed during Phase 5._
