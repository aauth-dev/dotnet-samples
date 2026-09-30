---
description: Decisions, deviations and open questions for the draft-11 compliance audit.
---

# Implementation log — draft-11 compliance audit

## Decisions taken

- [2026-09-30] [Phase 0] Q1 — Audit vs fix. PROCEEDED (default: audit only).
  The request is a compliance *check*; findings feed a remediation backlog
  (Phase 5) rather than being fixed in-flight. Revert if you want fixes inline.
- [2026-09-30] [Phase 0] Q2 — Spec baseline. RESOLVED: vendored `aauth-spec/v11/`
  snapshot at commit `30b8015`; upstream is not re-fetched.
- [2026-09-30] [Phase 0] Q3 — Order and scope. RESOLVED: SDK (`src/AAuth`,
  `src/AAuth.R3`, `src/AAuth.Events`) first, then `samples/`, then docs. The
  request's "samples and cos" is read as "samples and docs".
- [2026-09-30] [Phase 0] Q4 — Informational/unimplemented drafts. PROCEEDED
  (default: Bootstrap checked only for contradictions; Budgets and
  `accept_signature_algs` flagged only where code or docs claim support, or where
  the protocol draft makes them a MUST).
- [2026-09-30] [Phase 0] Q5 — Static vs dynamic. PROCEEDED (default: agents are
  static-only to avoid shared `obj/` contention; orchestrator may run scratch
  probe tests outside the repo tree to confirm CRITICAL/HIGH findings).
- [2026-09-30] [Phase 0] Q6 — Agent type and scope. PROCEEDED (default:
  `general-purpose` agents with an explicit read-only, adversarial brief; one
  area per agent sized to a spec slice ≤ ~500 lines plus ≤ ~2,500 lines of
  code; oversize areas split).
- [2026-09-30] [Phase 0] Q7 — Known deviations. RESOLVED: items recorded as
  deliberate in `SPEC-VERSION.md` or the v11 migration log are graded `INFO`
  unless they contradict a MUST.

- [2026-09-30] [Phase 2] Regrading rule. PROCEEDED (default: a MUST
  violation that is reachable only through non-default configuration, fails
  closed, or has a working in-protocol recovery path is MEDIUM, not HIGH;
  CRITICAL requires an attacker-exploitable bypass on a default path without a
  trusted-party compromise). Both agent CRITICALs (A18-001, A23-001) regraded to
  HIGH under this rule; 30 HIGHs regraded to MEDIUM/LOW; 3 rejected. Rationale
  per item is in `research.md` and the session verification notes.
- [2026-09-30] [Phase 2] SDK-01 merges A09-MED-001, A10-02 and an orchestrator
  observation; graded HIGH because the unsafe path is a public, documented API.
- [2026-09-30] [Phase 6] Internal review outcomes. RESOLVED:
  - SDK-01 upgraded HIGH → CRITICAL. The CRITICAL definition in the scale does
    not require a default path, and the unsafe path is public and recommended by
    DOC-03. This supersedes the "default path" clause of the Phase 2 regrading
    rule for SDK-01.
  - A23-002 upgraded MEDIUM → HIGH as SDK-19. It is an unconditional default-path
    MUST, so the earlier "audit completeness, no exploit" regrade was wrong.
  - SDK-03 regraded HIGH → MEDIUM. `IAAuthSingleUseGate.ExecuteOnceAsync`
    satisfies R3 L676 when composed; DOC-06 stays HIGH.
  - SDK-07 regraded HIGH → MEDIUM. Exploiting it needs a misbehaving host
    asserter. The backlog remediation now uses a stable internal person key,
    because the binding must not store the pairwise `sub`.
  - SDK-15 regraded HIGH → MEDIUM. `TwoKey` is a non-default composition, and
    `EnrolledBuilder` rejects it.
  - SDK-02 kept HIGH, with an explicit note that there is no issuer-restriction
    MUST.
  - Coverage: Signature-Key §7.2 and §7.3 were unassigned. The reviewer
    spot-checked them and they are compliant; recorded in `research.md`.

## Deviations from plan

- [2026-09-30] [Phase 1] Waves overlapped. PROCEEDED: the next wave's agents
  were dispatched as earlier agents finished (≤ ~12 concurrent) rather than
  strictly in batches of six; agents are static-only so there was no contention.
  No agent failed or needed a narrower re-dispatch.

- [2026-09-30] [Phase 3/4] Samples and docs agents dispatched concurrently.
  PROCEEDED: the docs audit depends only on the confirmed SDK table (not on
  samples findings), so D01–D10 were dispatched alongside S01–S10 once Phase 2
  was complete. Collation still runs SDK → samples → docs.
- [2026-09-30] [Phase 4] Area map gap. PROCEEDED: `docs/workflows/document-release.md`
  and `docs/signing-modes/pseudonymous-hwk.md` were missing from the D-area map;
  added to D07 and D02 respectively (D02 covers `signing-modes/*`).

## Open questions / inputs needed
