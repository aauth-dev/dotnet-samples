# Implementation Log - AAuth protocol draft-09 migration

> Append-only record for decisions, deviations, and owner inputs. See
> [`research.md`](research.md) and
> [`implementation-plan.md`](implementation-plan.md).

## Decisions taken

### [2026-07-19] [Phase 0] Q1 - Public error detail API

**RESOLVED.** Rename `AAuthTokenExchangeException.ErrorDescription` and
`TokenErrorResponse.ErrorDescription` to `Detail`. Producers and consumers use
only the draft-09 `detail` wire member; no public alias and no
`error_description` fallback will be retained. The owner ruled that exact
latest-spec compliance takes priority over backward compatibility.

### [2026-07-20] [Phase 0] Q2 - RFC 9457 on R3 runtime endpoints

**RESOLVED.** Include R3 token, document, challenge, and enforcement error
bodies in the common draft-09 RFC 9457 cutover. Their status codes and AAuth
`error` values remain unchanged; error bodies use
`application/problem+json` and optional `detail`.

### [2026-07-20] [Phase 0] Q3 - Bootstrap and MockAgentProvider errors

**RESOLVED.** Leave the informational, byte-unchanged Bootstrap companion and
the MockAgentProvider enrollment/refresh error format unchanged in this
migration. Create a focused research-and-plan spin-off; do not silently broaden
the draft-09 main-protocol error cutover into that companion.

### [2026-07-20] [Phase 0] Q4 - Missing AS clarification receiver

**RESOLVED.** Apply the draft-09 `action` cutover to the implemented
agent-to-PS clarification flow. The AS clarification receiver was already
missing under draft-08 and requires a complete pending-state/federation flow, so
create a separate research-and-plan initiative rather than adding a partial
receiver here.

### [2026-07-20] [Phase 0] Q5 - AAuth Events companion

**RESOLVED.** Spin off the complete AAuth Events protocol and all of its source
seams, including optional `event_endpoint` metadata, token-type APIs,
subscription registration, delivery, persistence, replay controls, agent
verification, discovery, samples, and e2e. The current AP does not support
Events, so omitting the conditional metadata remains conformant; this migration
must state the unsupported boundary explicitly.

### [2026-07-20] [Phase 0] Q6 - Revised R3 AsyncAPI behavior

**RESOLVED.** Spin off the new R3 AsyncAPI vocabulary/model and subscription
handoff with AAuth Events. Existing R3 token, document, challenge, and
enforcement endpoints remain in this migration only for the Q2 RFC 9457 error
format cutover.

### [2026-07-20] [Phase 0] Q7 - Signature Keys self-jwt

**RESOLVED.** Spin off `sig=self-jwt` as a dedicated dependency/use-case
initiative. It has no current main-protocol attachment point. Its future
discovery/cache implementation must coordinate with Events on one admitted
`{iss}/.well-known/{dwk}` JWKS seam while preserving distinct schemes and token
validation.

## Deviations from plan

No deviations have occurred.

## Open questions / inputs needed

### [2026-07-19] [Phase 0] Q1 - Public error detail API

**BLOCKED.** Decide whether `AAuthTokenExchangeException.ErrorDescription` and
`TokenErrorResponse.ErrorDescription` become `Detail`, or retain their .NET
names while consuming the draft-09 `detail` wire member.

> **Resolution (2026-07-20): RESOLVED.** Superseded by the Q1 entry under
> Decisions taken: rename both APIs to `Detail` with no compatibility alias.

### [2026-07-19] [Phase 0] Q2 - RFC 9457 on R3 runtime endpoints

**BLOCKED.** Decide whether the R3 token, document, challenge, and enforcement
error bodies join the common draft-09 problem-details cutover.

> **Resolution (2026-07-20): RESOLVED.** Superseded by the Q2 entry under
> Decisions taken: include all listed R3 runtime errors.

### [2026-07-19] [Phase 0] Q3 - Bootstrap and MockAgentProvider errors

**BLOCKED.** Decide whether errors belonging to the unchanged Bootstrap
companion remain unchanged and move to a spin-off, or adopt RFC 9457 here.

> **Resolution (2026-07-20): RESOLVED.** Superseded by the Q3 entry under
> Decisions taken: leave them unchanged and create a focused spin-off.

### [2026-07-19] [Phase 0] Q4 - Missing AS clarification receiver

**BLOCKED.** Decide whether to build the pre-existing missing AS clarification
response flow now or spin it off while migrating the implemented PS flow.

> **Resolution (2026-07-20): RESOLVED.** Superseded by the Q4 entry under
> Decisions taken: migrate the PS flow and spin off the AS receiver.

### [2026-07-19] [Phase 0] Q5 - AAuth Events companion

**BLOCKED.** Decide whether to implement the complete Events companion and its
protocol metadata/registry seams here or create a separate initiative.

> **Resolution (2026-07-20): RESOLVED.** Superseded by the Q5 entry under
> Decisions taken: spin off all Events source seams.

### [2026-07-19] [Phase 0] Q6 - Revised R3 AsyncAPI behavior

**BLOCKED.** Decide whether to add the multi-member AsyncAPI operation model and
Events handoff here or spin it off with Events.

> **Resolution (2026-07-20): RESOLVED.** Superseded by the Q6 entry under
> Decisions taken: spin off R3 AsyncAPI with Events.

### [2026-07-19] [Phase 0] Q7 - Signature Keys self-jwt

**BLOCKED.** Decide whether to implement `self-jwt` here or create a separate
dependency/use-case initiative.

> **Resolution (2026-07-20): RESOLVED.** Superseded by the Q7 entry under
> Decisions taken: create a coordinated `self-jwt` spin-off.
