# SDK API Surface Consistency — Implementation Log

Append-only. Entries: `[YYYY-MM-DD] [Phase N] <title>` with a status of
`PROCEEDED (default X)`, `BLOCKED`, or `RESOLVED`.

## Decisions taken

### [2026-09-29] [Phase 0] Q0 — Backward compatibility

RESOLVED (owner). "No backward compatibility required."
- Every API change is a single cutover.
- Deleted or reshaped members get no `[Obsolete]` bridges or retained
  overloads.

### [2026-09-29] [Phase 0] Q1–Q18 — Proposed defaults seeded

PROCEEDED (defaults as listed in
[research.md](research.md#gaps-and-open-questions)).
- Each default stands unless the owner overrides it before Phase 1 starts.
- An override gets its own dated `RESOLVED` entry that supersedes the
  default.
- The defaults most in need of owner review are:
  - **Q3**: keys and seams leave the options types and resolve from DI.
  - **Q4**: callbacks become DI interfaces, and builder lambdas adapt to them.
  - **Q8**: typed clients become keyed services by agent name.
  - **Q9**: new `AddAAuthPersonServer`/`AddAAuthAccessServer`, with
    `AddAAuthFederation` folded in.
  - **Q16**: the PS consent dashboard lands first.

## Deviations from plan

None yet.

## Open questions

### [2026-09-29] [Phase 0] Q16 — Sequencing with PS consent dashboard

BLOCKED (owner input). 2026-09-28-ps-consent-dashboard is open (1 of 23 DoD
boxes ticked). It edits MockPersonServer, SampleApp, and the walkthroughs,
which Phases 3, 8, and 9 rewrite.

The default is for the dashboard to land first. Confirm, or rule that this
initiative goes first and the dashboard rebases.
