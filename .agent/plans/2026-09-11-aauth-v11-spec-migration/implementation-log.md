---
description: Seeded decision gate for draft-11 WIP migration; implementation has not begun.
---

# Implementation log - AAuth draft-11 WIP

Append-only log. Research defaults do not grant implementation authorization.
No SDK runtime gates have been run for this initiative. Prior plans and existing
vendoring changes remain intact.

## Decisions taken

### [2026-09-11] [Phase 0] Research-only scope

RESOLVED. The user requested breaking-change and SDK/API/Samples/Docs analysis
following the draft-10 migration folder. This package records research, maps,
scenarios, a ledger and a proposed implementation plan. SDK baseline:
`94576a3ebcba8cd1d167923e50c8796132057600`; current target remains draft-10.
The reference is unpublished draft-11 WIP with pins in [research.md](research.md).
No SDK implementation or deployment is authorized by the analysis request.

### [2026-09-11] [Phase 0] Publish the research branch

RESOLVED. The follow-up request authorizes pushing `wip/aauth-draft-11` after
finishing the analysis. Commit and push the vendored WIP snapshot and this
research package; keep SDK implementation separate. This authorizes Git branch
publication, not package publication, runtime deployment or a conformance claim.

### [2026-09-11] [Phase 0] Research validation and review

RESOLVED for the research deliverable only. Five read-only area audits were
collated; a fresh reviewer checked the seven-document package, then rechecked
the identified repairs. The follow-up found no remaining P1/P2 document issues.
Repairs included owning-phase snippet updates, minimum client/Events dependencies
at the identity cutover, atomic clarification-pair replacement, and corrected
source citations. Q13 and Q14 retain newly identified upstream uncertainties.

The local reference check validated 464 file/line links with no missing files
or empty cited lines; both heading-fragment links resolved. Markdown diagnostics
and tracked-document whitespace checks were clear. These are documentation
checks, not SDK tests. No build, unit, conformance, browser or external interop
pass is claimed, and all implementation definitions of done remain unchecked.

## Deviations from plan

None. Implementation has not started. The package follows the seven-document
draft-10 pattern without inheriting completed checkboxes, historical API counts,
defect verdicts or test results. Its upstream-question section is part of the
research, not a new specification or modification of vendored bytes.

## Open questions

### [2026-09-11] [Phase 0] Q1-Q14 implementation decision gate

BLOCKED for SDK implementation authorization and affected conformance claims,
not for research or Git branch publication. See
[research questions](research.md#gaps-and-open-questions) for both-sided evidence
and [questions for Dick](research.md#questions-for-dick-hardt) for upstream items.

| ID | Ruling needed | Current state |
|---|---|---|
| Q1 | WIP target and missing Signature Keys errors | Proposed pin with WIP qualification; no conformance closure |
| Q2 | Person-only authorization versus runtime step-up | Specific-flow interpretation proposed, not approved |
| Q3 | Upstream-token audience/key contradiction | Trust-boundary ruling required |
| Q4 | Delegated person/mission authority and consent caches | PS-authoritative evidence proposed; no act fallback |
| Q5 | Protected Events ticket identity | Trusted binding and persistent contract unresolved |
| Q6 | Optional capability selection | Core migration and existing capabilities proposed; optional slices explicit |
| Q7 | Expiry/future iat/ceiling strength/refresh margin | Separate timing policies proposed; ambiguity retained |
| Q8 | Retained-result completion versus terminal 410 | Specific execute-once rule proposed; transaction/retention ruling pending |
| Q9 | Revocation graph/store and outbound delivery | Separate dependency/expiry edges proposed |
| Q10 | Budgets/release accounting and usage audience | Separate Budgets and disabled release execution proposed |
| Q11 | Additional claims versus fixed directed subject | Reject conflicting repeated identity proposed |
| Q12 | Ownership and persisted schema migration | Reuse current abstractions; explicit migration/isolation proposed |
| Q13 | Clarification replacement token-pair carriage | Atomic verified pair replacement proposed; upstream wire shape unresolved |
| Q14 | Fresh challenge naming a revoked auth token | Fresh-person recovery proposed; upstream choreography clarification required |

At implementation time append `RESOLVED`, `PROCEEDED (default ...)`, or `BLOCKED`
entries per question, retaining this original record. Record selected baselines,
packages if any, exact tests and unavailable environments when they occur.
Do not retrospectively invent baseline test evidence or promote research
defaults into approvals silently.