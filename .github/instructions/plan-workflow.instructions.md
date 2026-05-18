---
description: "Workflow for using and maintaining research and implementation plan documents stored under .agent/plans/."
applyTo: ".agent/plans/**"
---

# Plan & Research Workflow

This repo uses a lightweight planning workflow. Each significant body of work
gets its own folder under `.agent/plans/` containing a research document and an
implementation plan. Follow the rules below when reading, creating, or updating
those files.

## Folder layout

```
.agent/plans/<YYYY-MM-DD>-<short-slug>/
    research.md            # Research-only. No implementation steps.
    implementation-plan.md # Phased plan with DoD checkboxes per phase.
```

- `<YYYY-MM-DD>` is the date the plan was created (do not change later).
- `<short-slug>` is kebab-case, e.g. `dotnet-aauth-sdk`.
- One folder per initiative. Do not mix unrelated work into the same folder.

## File responsibilities

### `research.md`

- Captures source repositories, protocol/spec summaries, library options,
  cryptographic operations, package inventories, and open questions.
- Contains **no** task lists or step-by-step instructions.
- Update when external facts change: new spec revision, new library version,
  resolved open question, corrected gap, etc.
- When updating, prefer in-place edits with a short `> **Update (YYYY-MM):** ...`
  callout above the changed section instead of rewriting history.

### `implementation-plan.md`

- Phased plan with concrete files, responsibilities, and tests per phase.
- Each phase ends with a **Definition of Done** checklist using `- [ ]` /
  `- [x]` checkboxes.
- Each phase may include an **Implementation Decisions** subsection recording
  pinned package versions, library choices, and rationale agreed before work
  starts.
- Out-of-scope items belong in the dedicated table at the bottom, not silently
  dropped.

## When to update which file

| Trigger | Update `research.md` | Update `implementation-plan.md` |
|---|---|---|
| New library / NuGet version becomes relevant | yes | only if the version is pinned for a phase |
| Spec revision changes a behavior | yes | yes, if a phase relies on that behavior |
| Decision made before starting a phase (versions, design trade-off) | no | yes — add to that phase's Implementation Decisions section |
| Phase task completed | no | tick the corresponding DoD checkbox |
| New phase needed | no | add a new phase section; renumber if required |
| Scope dropped or deferred | no | move to the Out of Scope table |
| Open question resolved | yes — update Gaps & Open Questions | yes, if the resolution changes a phase |

## Authoring rules

- Markdown only. Wrap lines at a sensible width; do not hard-wrap mid-table.
- Tables: keep column headers terse; one concept per row.
- Code fences: use language hints (` ```csharp `, ` ```bash `, etc.).
- Links: prefer workspace-relative paths for in-repo files and full URLs for
  external sources.
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
4. If new facts emerge during implementation (e.g. a library does not behave
   as research suggested), update `research.md` with a dated `> **Update**`
   callout and adjust the plan if needed.

When the user asks a research question:

- Update `research.md` only; do not add tasks or checkboxes there.

When the user asks to change scope:

- Update `implementation-plan.md` — move items into or out of the **Out of
  Scope** table and adjust phase contents.
