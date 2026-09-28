---
description: Seeded decision gate for the AAuth draft-11 migration; implementation has not begun.
---

# Implementation log - AAuth draft-11

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

### [2026-09-25] [Phase 0] Retarget to published draft-11

RESOLVED. Draft-11 was published at AAuth tag `draft-hardt-oauth-aauth-protocol-11`
(commit `178e9e6`) with HTTP Signature Keys -09. Both are vendored in
[`aauth-spec/v11/`](../../../aauth-spec/v11/), along with the per-role
[upgrade checklists](../../../aauth-spec/v11/upgrade-10-to-11/README.md) from
commit `180bc95`. The WIP snapshot remains readable at `e6d18a3`. The
[implementation plan](implementation-plan.md#target-pins) now targets the
published text. Its upstream rulings table gives the governing line for each Q.
This is a planning change. It does not authorize SDK implementation.

### [2026-09-28] [Phase 0] Implementation authorized

RESOLVED. The user asked to start implementing the plan. This authorizes SDK,
sample, test and docs changes on `wip/aauth-draft-11` in phase order. It does
not authorize package publication, deployment, PR creation or pushing.

### [2026-09-28] [Phase 0] Q1-Q14 rulings

RESOLVED (by spec) for Q1-Q5, Q7-Q11, Q13 and Q14, per the governing lines in
[the plan's upstream rulings](implementation-plan.md#upstream-rulings). The SDK
design choices those leave open are decided in their owning phases and logged
there: consent caches (Q4, Phase 6), retained-result storage (Q8, Phases 5
and 8) and revocation delivery (Q9, Phase 7).

PROCEEDED (default: core migration plus existing R3 and Events) for Q6. Full
Budgets, hosted child provisioning, supervision protocol and delayed artifacts
stay out of scope. Result-release execution stays disabled with explicit
unsupported handling. Optional checklist items are not selected yet; each
owning phase records its selection before implementing one.

PROCEEDED (default: reuse current abstractions; isolated or versioned sample
storage) for Q12. No destructive reset of user data. Public API changes are a
single alpha cutover, tracked by the regenerated API map.

### [2026-09-28] [Phase 0] Baseline

RESOLVED. `origin/main` (`f44587f`, tag `v0.10.0-alpha.1`) was merged into the
branch as `eef4175` before implementation. .NET SDK 10.0.300, Node 20.20.2.
Release build clean. Baseline tests: Events 75, R3 290, Conformance 1079, core
1496, all passing. e2e TypeScript typecheck passes. Browser suites were not
run for this baseline and are not claimed.

### [2026-09-28] [Phase 1] Tooling retarget

RESOLVED. `tools/ApiSurface` defaults to the v11 API map and baseline
`v0.10.0-alpha.1`, with `--map` and `--baseline` overrides. The docs inventory
test writes the v11 docs map. The v10 maps are unchanged. The `jti` implies
`iss` heuristic is replaced by an explicit table of HTTP examples carrying a
`jti` body; the only entry is the revocation request, whose member set Phase 7
cuts over.

### [2026-09-28] [Phase 1] Signature error codes and the `created` window

RESOLVED. Signature Keys -09 `revoked_jwt` and `clock_skew` are typed.
Missing or malformed `Signature` / `Signature-Input` is `invalid_signature`
(-09 section 5.4.4); a malformed `Signature-Key` is `invalid_key` (5.4.7).
The `created` window is symmetric (#verification, L2246): older is
`invalid_signature`, further ahead is `clock_skew`. `MaxFutureSkew` (5 s)
rejected in-window requests, so it is removed from `AAuthVerifier`,
`AAuthResourceOptions` and `AAuthVerificationOptions` (where it was never read).
Future `iat` handling moves in Phase 2 with temporal trust.

### [2026-09-28] [Phase 1] Metadata vocabulary

RESOLVED. `token_endpoint` is `auth_token_endpoint` on PS and AS metadata,
clients and the C# options (`AuthTokenEndpoint`). Agents parse
`person_token_endpoint`; the PS publishes it in Phase 2. `access_mode` values
are `agent-token`, `person-token`, `session-token` and `auth-token`;
`aauth-access-token` is rejected at configuration, and agents treat any
unrecognized value as no declaration (AG-02). `login_endpoint` is removed
(RS-02, AP-04). GuidedTour executable reads and snippets moved with it.

### [2026-09-28] [Phase 1] Token, polling and revocation error vocabulary

PROCEEDED (default: keep `invalid_agent_token` and `expired_agent_token` until
Phase 4). The published token table removes them, but the PS, AS and Bookings
emitters still send them for failures that become `revoked_presented_token`
and `expired_presented_token` only after the exchange cutover. Removing the
client codes first would misclassify our own servers. Phase 4 removes both
codes and their emitters together. All other published token codes, polling
`revoked`, and revocation errors and downstream outcomes are typed. The unused
`interaction_required` token code is removed.

### [2026-09-28] [Phase 1] Agent identifiers and Ed25519

RESOLVED. `AgentId` accepts `A-Z` in the local part and compares ordinally, so
case variants are distinct identities (#agent-identifiers, L488). The domain
stays lowercase. Ed25519 needed no code change: `AAuthKey.Generate()` is
Ed25519, and the PS, AS, resource, R3 and Events endpoints all verify through
`AAuthVerificationMiddleware`. Existing suites sign with Ed25519 at each role:
MockPersonServer and MockAccessServer integration, `DeferredFederationTests`,
`AccessServerClientTests`, and `EnrolledBuilderTests` against MockAgentProvider's
refresh endpoint.

### [2026-09-28] [Phase 1] Gates

RESOLVED. Release build clean. Tests: Events 75, R3 290, Conformance 1112, core
1499, all passing. API map regenerated: 26 changed public-source files, +35/-9
declarations, 0 unmapped, current on rerun. Docs inventory regenerated and
current on rerun. e2e typecheck passes. Browser suites not run.

## Deviations from plan

None. Implementation has not started. The package follows the seven-document
draft-10 pattern without inheriting completed checkboxes, historical API counts,
defect verdicts or test results. Its upstream-question section is part of the
research, not a new specification or modification of vendored bytes.

### [2026-09-25] [Phase 0] Research citations still point at WIP lines

PROCEEDED (default: callouts now, full re-derivation in Phase 0). The v11 line
citations in `research.md`, the ledger and the maps refer to the WIP capture.
The plan's new citations were checked against the published files. Phase 0 now
includes re-deriving the rest before implementation.

### [2026-09-28] [Phase 0] Merged `origin/main` instead of rebasing

PROCEEDED (default: keep the merge). The plan said rebase. The branch owner
merged `origin/main` (`eef4175`) instead. The published branch history is
preserved, and the API baseline uses the release tag directly.

### [2026-09-28] [Phase 1] Started before Phase 0 documentation re-derivation

PROCEEDED (default: finish before Phase 2). Phase 1 depends only on published
vocabulary, which was read from the published text directly. Re-deriving the
research, ledger and map citations, and assigning each upgrade-checklist ID to a
phase in the ledger, are still open Phase 0 items. Phase 2 does not start until
they are done.

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

### [2026-09-25] [Phase 0] Q1-Q14 status after published draft-11

BLOCKED for SDK implementation authorization only. Upstream uncertainty no
longer blocks the gate: [PR #162](https://github.com/dickhardt/AAuth/pull/162)
and the published text resolve Q1-Q5, Q7-Q11, Q13 and Q14. The citations are in
[the plan's upstream rulings](implementation-plan.md#upstream-rulings). Q4, Q8
and Q9 leave SDK design choices (consent caches, retained-result storage,
revocation delivery). Q6 (optional capability selection) and Q12 (persistence
and public API migration) remain SDK decisions. Record each as `RESOLVED` or
`PROCEEDED` when implementation is authorized; this entry does not approve them.

### [2026-09-28] [Phase 4] AS verification of `agent_token` (AAuth issue #199)

OPEN upstream. The access-server checklist notes that -11 gives no error code
for a failing `agent_token` body parameter, and no rule for verifying it (step 1
of Agent Token Verification compares against the signing key, which at the AS
is the PS's). The -12 proposal restores `invalid_agent_token` and
`expired_agent_token` and compares `agent_token`'s `cnf.jwk` with the resource
token's `agent_jkt`. Phase 4 must choose a disposition for the AS path before
removing the draft-10 codes.

### [2026-09-28] [Phase 5] MockAgentProvider refresh signature errors

OPEN. The sample AP refresh endpoint answers a missing or unparsable
`Signature-Key` with a problem body (`invalid_request`), not `401` with
`Signature-Error`. Move it to the shared verifier or to -09 codes when the agent
refresh path is reworked.