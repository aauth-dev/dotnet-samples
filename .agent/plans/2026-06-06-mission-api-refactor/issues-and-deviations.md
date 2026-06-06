# Mission API Refactor — Issues & Deviations Log

Significant issues, spec deviations, and decisions surfaced while implementing the
[implementation-plan.md](implementation-plan.md). Research findings stay in
[research.md](research.md); this file is the running ledger of **problems and
deviations** (not routine progress).

## How to use this log

- Add an entry whenever a phase surfaces a real issue, a deviation from the AAuth
  spec, or a design call that the user may want to revisit.
- Keep each entry short: what, where, why, and the disposition.
- `Status` values: `open`, `fixed`, `deferred`, `intentional`, `needs-decision`.
- Cite the governing spec section for anything spec-related.

## Spec references

- AAuth Protocol — `aauth-spec/draft-hardt-oauth-aauth-protocol.md`
- Upcoming changes — `aauth-spec/upcoming-changes-02.md`

## Open decisions for the user

These judgment calls were made during Phase 1. **All confirmed by the user on
2026-06-06**; the fixes are folded into the Phase 2 consistency pass.

- **D1 — Additive first pass, then remove (DECIDED).** Phase 1 adds the new surface
  *alongside* the existing per-call-PS methods so the solution keeps building 0/0
  and no flow breaks (DC6). **Phase 2 removes** the per-call `personServer` methods
  (sample migration completes in Phase 4), reaching DC1's "no dual surface" end
  state.
- **D2 — Flat `MissionSession` methods (DECIDED).** Keep the flat methods
  (`RequestPermissionAsync`, `RecordAuditAsync`, `AskQuestionAsync`,
  `ProposeCompletionAsync`); no nested facades.
- **D3 — Promote PS mission machinery into the SDK (DECIDED, Phase 2).** Move the
  approval-blob builder into the SDK + add an `IMissionApprover` seam so
  `MapAAuthGovernance` can map mission creation; add a pending/deferred-consent
  abstraction so a `Prompt` outcome returns a 202 deferred response. Closes DEV-1
  and DEV-2.

## Deviation entries

| ID | Phase | Area | Summary | Spec § | Status |
|----|-------|------|---------|--------|--------|
| DEV-1 | 1 | Resource mapper | `MapAAuthGovernance` resolved `PermissionOutcome.Prompt` as a denial — no built-in deferred (202) user-consent channel. | §Permission Endpoint (deferred consent) | resolved (Phase 2, D3 — `IDeferredConsentStore` seam + `AddAAuthDeferredConsent()`; mapper parks `Prompt` and answers 202 + poll route. Store is opt-in so the existing `Prompt`→denied default is preserved. Interactive browser page stays a sample concern.) |
| DEV-2 | 1 | Resource mapper | Mission-creation endpoint not mapped by `MapAAuthGovernance`; approval-blob building + proposal approval stayed PS-side (`MissionApproval` was sample-local). | §Mission Creation, §Mission Approval | resolved (Phase 2, D3 — `MissionApprovalBuilder` + `IMissionApprover`/`DefaultMissionApprover` promoted into the SDK; `MapAAuthGovernance` maps the mission endpoint, persists the `StoredMission`, and emits the `AAuth-Mission` header. MockPersonServer now uses `MissionApprovalBuilder`.) |
| DEV-3 | 1 | Default seams | `DefaultInteractionRelay` has no user channel: questions get an empty answer and completion is treated as not-accepted. A real PS must override it. Documented behavior, not a spec violation. | §Interaction Endpoint | intentional |

## Notes

- Known spec-alignment findings from research (F1–F6) are tracked in
  [research.md](research.md) Part F; only deviations discovered **during
  implementation** are logged here.
