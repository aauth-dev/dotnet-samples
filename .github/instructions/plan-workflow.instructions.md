---
description: "Workflow for using and maintaining research and implementation plan documents stored under .agent/plans/."
applyTo: ".agent/plans/**"
---

# Plan & Research Workflow

This repo uses a lightweight planning workflow. Each significant body of work
gets its own folder under `.agent/plans/` containing a research document and an
implementation plan. Follow the rules below when reading, creating, or updating
those files.

## Guiding principles

- **Spec conformance is paramount; backwards compatibility is not a goal.** This
  is a spec-accurate alpha SDK. When a spec revision changes a behavior, match it
  exactly — breaking renames, removals, and wire changes are acceptable, and
  expected, to stay spec-accurate. Do not add dual-format shims or compatibility
  fallbacks to preserve old behavior; do a single coordinated cutover (the SDK
  signs *and* verifies, so it stays internally consistent). Every implementation
  plan restates this in its phase-level guiding principles, and any deliberate
  exception is logged as a `PROCEEDED`/`RESOLVED` decision in
  `implementation-log.md`.

## Folder layout

```
.agent/plans/<YYYY-MM-DD>-<short-slug>/
    research.md            # Research-only. No implementation steps.
    implementation-plan.md # Phased plan with DoD checkboxes per phase.
    implementation-log.md  # Living record of decisions, deviations & open-question
                           # rulings made while implementing.
```

- `<YYYY-MM-DD>` is the date the plan was created (do not change later).
- `<short-slug>` is kebab-case, e.g. `dotnet-aauth-sdk`.
- One folder per initiative. Do not mix unrelated work into the same folder.
- `implementation-log.md` is added when implementation begins, or alongside the
  plan to seed the Phase 0 decision gate. Research-only initiatives may omit it.

## File responsibilities

### `research.md`

- Captures source repositories, protocol/spec summaries, library options,
  cryptographic operations, package inventories, and open questions.
- Contains **no** task lists or step-by-step instructions.
- **Cite spec/standard sections by line number every time you reference them**,
  plus the stable anchor where one exists — e.g. `(#delegation-chain, L1829)`.
  Verify the line against the vendored source before recording it. Line numbers
  shift on re-vendor, so anchors are the durable reference and lines are the
  precise one.
- Records the research **method**. For multi-part work, dispatch one read-only
  subagent per logical change set, collate the findings, then **re-verify the
  highest-stakes claims directly against source** (spec line, current code)
  before recording them — subagent line numbers and file paths drift. State which
  findings were re-verified versus reported.
- Update when external facts change: new spec revision, new library version,
  resolved open question, corrected gap, etc.
- When updating, prefer in-place edits with a short `> **Update (YYYY-MM):** ...`
  callout above the changed section instead of rewriting history.

### `implementation-plan.md`

- Phased plan with concrete files, responsibilities, and tests per phase.
- Phases are ordered by risk and dependency: cheap/isolated changes first, the
  highest-blast-radius rework mid-stream, security and docs work trailing.
- Each phase ends with a **Definition of Done** checklist using `- [ ]` /
  `- [x]` checkboxes.
- Each phase may include an **Implementation Decisions** subsection recording
  pinned package versions, library choices, and rationale agreed before work
  starts; the rationale itself lives in `implementation-log.md`.
- Open with a **Phase 0 decision gate** that resolves the research's open
  questions before any code. Its DoD is “every open question has a recorded ruling
  in `implementation-log.md`.” Prefer a default ruling (`default X, revert if you
  disagree`) over blocking.
- For migration / broad-refactor work, end with two trailing phases: a
  **samples / snippets / docs analysis-and-update sweep** run after the code
  surface is frozen (compiled code is fixed in its own phase to keep the build
  green; non-compiled surfaces — string-literal snippets, READMEs, docs prose and
  embedded fences, e2e assertions — drift silently and are swept here), and a
  final **internal-review** phase that has a fresh subagent validate the work
  against the spec, `research.md`, and the plan with severity-graded findings.
- Out-of-scope items belong in the dedicated table at the bottom, not silently
  dropped.

### `implementation-log.md`

- A dated, append-only narrative of **decisions taken**, **deviations from
  plan**, and **open questions / inputs needed** — recorded *while implementing*,
  for the owner to review at the end. Three sections, in that order.
- Each entry: `[YYYY-MM-DD] [Phase N] <title>` with a status —
  `PROCEEDED (default X)` (chose a default to stay unblocked; revert if you
  disagree), `BLOCKED`, or `RESOLVED`.
- This is where the Phase 0 decision-gate rulings (Q1–Qn) live; the plan's
  **Implementation Decisions** checkboxes point here for the rationale.
- Append; do not rewrite. A reversed decision gets a new dated entry that
  supersedes the old one.

## When to update which file

| Trigger | `research.md` | `implementation-plan.md` | `implementation-log.md` |
|---|---|---|---|
| New library / NuGet version becomes relevant | yes | only if pinned for a phase | — |
| Spec revision changes a behavior | yes | yes, if a phase relies on it | — |
| Decision made before/while implementing | no | tick its Implementation Decisions box | yes — entry with rationale |
| Deviation from the plan during implementation | no | adjust the phase if needed | yes — `[Phase N]` deviation entry |
| Phase task completed | no | tick the corresponding DoD checkbox | — |
| New phase needed | no | add a new phase section; renumber if required | — |
| Scope dropped or deferred | no | move to the Out of Scope table | note why, if decided mid-flight |
| Open question resolved | yes — update Gaps & Open Questions | yes, if the resolution changes a phase | yes — flip the Q entry to `RESOLVED` |

## Authoring rules

- Markdown only. Wrap lines at a sensible width; do not hard-wrap mid-table.
- Tables: keep column headers terse; one concept per row.
- Code fences: use language hints (` ```csharp `, ` ```bash `, etc.).
- Links: prefer workspace-relative paths for in-repo files and full URLs for
  external sources.
- Spec/source references: cite by line number and the stable anchor where
  available (e.g. `(#anchor, L1234)`); verify the line against the vendored
  source, and re-check after any re-vendor since line numbers shift.
- Dates: ISO 8601 (`YYYY-MM-DD`).
- Do not delete historical decisions. If a decision is reversed, add a new
  dated entry that supersedes the old one and mark the old one as superseded.

## Working with these files from chat

When the user asks to implement a phase:

1. Read `implementation-plan.md` and the relevant section of `research.md`.
2. Confirm or add an **Implementation Decisions** subsection for that phase
   before writing code, especially when:
   - Pinning NuGet versions.
   - Choosing between equivalent libraries listed in research.
   - Deviating from the file layout in the plan.
3. Implement the phase, then tick the DoD checkboxes as items land.
4. Log decisions and deviations in `implementation-log.md` **as they happen** —
   a dated `[Phase N]` entry with a status — not at the end. Never silently
   deviate; prefer a `PROCEEDED (default X)` ruling over stopping.
5. If new facts emerge during implementation (e.g. a library does not behave
   as research suggested), update `research.md` with a dated `> **Update**`
   callout and adjust the plan if needed.

When the user asks a research question:

- Update `research.md` only; do not add tasks or checkboxes there.
- For multi-part research, dispatch read-only subagents per logical change set
  and verify the highest-stakes findings against source before writing them in.

When the user asks to change scope:

- Update `implementation-plan.md` — move items into or out of the **Out of
  Scope** table and adjust phase contents.
