---
description: Phased plan for the adversarial draft-11 compliance audit — SDK first, then samples, then docs.
---

# Implementation plan — draft-11 compliance audit

Research, area map, severity scale and agent brief: [research.md](research.md).
Decisions: [implementation-log.md](implementation-log.md). Per-area reports:
[findings/](findings/).

## Guiding principles

- **Spec conformance is paramount; backwards compatibility is not a goal.**
  Findings are judged against draft-11 text only; "matches earlier drafts" or
  "a sample relies on it" is not a defence.
- The audit is **read-only**. Remediation is a separate initiative seeded from
  the backlog produced in Phase 5.
- **Adversarial, small-scope subagents.** One agent per area in the research
  area map; each reads only its spec slice and listed files, and writes one
  findings file. No builds or tests inside agents (shared `obj/`).
- Every CRITICAL/HIGH finding is re-verified directly against spec and code by
  the orchestrator before it is recorded as `CONFIRMED`.
- Order: SDK → samples → docs. Samples and docs agents receive the confirmed
  SDK findings so inherited defects are attributed to the SDK.

## Phase 0 — Decision gate

Resolve scope questions (Q1–Q7 in the log) before dispatching agents.

**Definition of Done**

- [x] Every open question has a recorded ruling in `implementation-log.md`.
- [x] Area map, severity scale, template and agent brief recorded in `research.md`.

## Phase 1 — SDK adversarial audit (A01–A24)

Dispatch areas A01–A24 in waves of ~6 parallel background agents
(`general-purpose`, read-only brief). Each writes
`findings/sdk/<ID>-<slug>.md` and returns a ≤15-line summary.

**Definition of Done**

- [x] Wave 1: A01–A06 findings files present.
- [x] Wave 2: A07–A12 findings files present.
- [x] Wave 3: A13–A18 findings files present.
- [x] Wave 4: A19–A24 findings files present.
- [x] Any agent that failed or ran out of context is re-dispatched with a
      narrower slice (logged as a deviation).

## Phase 2 — SDK collation and re-verification

- De-duplicate cross-area findings; assign stable IDs `SDK-nn`.
- Re-verify every CRITICAL/HIGH directly (spec line + code line; optionally a
  scratch probe test outside the repo tree). Mark `CONFIRMED` / `REJECTED`.
- Spot-check ≥20% of MEDIUM findings; mark the rest `REPORTED`.
- Record the collated table in `research.md` → *Collated findings / SDK*.

**Definition of Done**

- [x] All CRITICAL/HIGH findings are `CONFIRMED` or `REJECTED` with reason.
- [x] MEDIUM spot-check done and noted.
- [x] SDK table in `research.md` populated; conformance summary per area.

## Phase 3 — Samples audit (S01–S10)

Dispatch S01–S10 (two waves), passing the confirmed SDK table. Collate into
`research.md` → *Collated findings / Samples*, re-verifying CRITICAL/HIGH.

**Definition of Done**

- [x] S01–S10 findings files present.
- [x] Samples table populated; inherited-from-SDK findings cross-referenced.

## Phase 4 — Docs audit (D01–D10)

Dispatch D01–D10 (two waves), passing the confirmed SDK table. Docs are checked
for spec-contradicting prose, stale draft-10 wording, code fences that would
not compile against the current API or would be non-conformant, and claims of
support for unimplemented features (Budgets, `accept_signature_algs`, x509,
cached). Collate into `research.md` → *Collated findings / Docs*.

**Definition of Done**

- [x] D01–D10 findings files present.
- [x] Docs table populated.

## Phase 5 — Report and remediation backlog

- Write the executive summary at the top of *Collated findings*: counts by
  severity × phase, top risks, areas assessed fully compliant.
- Produce a prioritised remediation backlog (grouped by fix locality) as the
  seed for a follow-up implementation plan, in
  [remediation-backlog.md](remediation-backlog.md). Do not implement fixes here.

**Definition of Done**

- [x] Executive summary written.
- [x] Remediation backlog written, every CONFIRMED/REPORTED ≥ MEDIUM item mapped.

## Phase 6 — Internal review

A fresh `rubber-duck` agent reviews `research.md` against the spec and a sample
of findings files for false positives, missed areas, and mis-graded severity.
Adjust and log outcomes.

**Definition of Done**

- [x] Review run; accepted/rejected review points logged.
- [x] Plan DoD fully ticked.

## Out of scope

| Item | Reason |
|---|---|
| Fixing findings | Audit only; backlog seeds a follow-up plan (Q1). |
| Budgets draft | Not implemented per `SPEC-VERSION.md`; only false support claims are flagged (Q4). |
| Bootstrap draft normative review | Informational draft; A06 checks only for contradictions (Q4). |
| Running live interop against third-party deployments | Not available; static audit (Q5). |
| `tests/` and `tools/` correctness | Not requested; tests are consulted as evidence only. |
| `aauth-spec/v01`–`v10` snapshots | Historical; not a compatibility target. |
