---
description: Prioritised remediation backlog from the draft-11 compliance audit — seed for a follow-up implementation plan.
---

# Remediation backlog — draft-11 compliance audit

Source: [research.md](research.md) → *Collated findings*. IDs: `SDK-nn` / `SMP-nn` /
`DOC-nn` are confirmed HIGHs; other IDs are MEDIUM/LOW sources from
[findings/](findings/). Groups are ordered by risk; within a group, fix the SDK first,
then samples, then docs. This file is the seed for a follow-up
`implementation-plan.md`. It is not itself a plan.

> **Update (2026-09-30):** superseded by
> [2026-09-30-v11-compliance-remediation](../2026-09-30-v11-compliance-remediation/implementation-plan.md),
> which holds the fix designs, red-team rulings and the phased plan.

## P1 — Security-relevant (fix first)

| Group | Items | Locality | Notes |
|---|---|---|---|
| Resource audience and trust | **SDK-01 (CRITICAL)**, SDK-02, SDK-08; A07-001/A09-MED-002, A03-HIGH-002, A08-03 | `DependencyInjection/AAuthApplicationBuilderExtensions.cs`, `Server/Verification/*`, `Server/Endpoints/AAuthEndpointExtensions.cs`, `Server/Challenge/*` | `UseAAuthVerification` should resolve `ResourceIdentifier` from `AAuthResourceMetadataOptions.Issuer` and fail closed when absent. `AccessServer` should imply `AuthTokenIssuers = {AS}` + `dwk=aauth-access.json`. The authorization endpoint should require `aa-person+jwt`. `AgentTokenRequired` should accept only agent tokens. Then fix DOC-03, DOC-04, D09-01, D10-05, SMP-04. |
| R3 per-call single use | SDK-03 (MEDIUM), DOC-06 (HIGH) | `src/AAuth.R3/R3Enforcement.cs`, `R3ProposalStore.cs` | Consume the proposal or key a retained result by auth-token `jti` inside the enforcement API, or return a decision that cannot be executed twice. Then fix DOC-06 and the D10-04 claim. |
| Upstream provenance | SDK-04 | `Tokens/UpstreamTokenValidator.cs`, PS inventory | Record the AS-presentation `(as, aud, sub)` when federating. Accept AS-issued upstream tokens only against that record. Reject when the calling agent is unknown (L1835). Then fix D07-02. |
| Revocation before federation | SDK-05 | `Person/AAuthPersonServerEndpoints.cs:1447-1455` | Re-check source revocation immediately before `FederateAsync`. Then fix the D03-02 and D10-01 claims. |
| Agent–person binding | SDK-07 (MEDIUM) | `Person/AgentPersonBinding.cs`, `/person` handler, `IIdentityClaimsAsserter` contract | Bind `(agent iss, agent sub)` to a **stable internal person key** returned by the asserter, not to the pairwise per-resource `sub`. Reject a different person until the binding is revoked. |
| Grant bounds on `updated_request` | SDK-06, A12-04 | PS clarification paths | Recompute `AuthorizationExpiresAt`/`SourceTokens` from the replacement pair. Count triage rounds. |
| Sample privilege grant | SMP-01 | `samples/MockPersonServer/SampleIdentityClaimsAsserter.cs` | Match on the full agent id plus the AP issuer, not a prefix. |

## P2 — Wire incompatibility on default paths

| Group | Items | Locality |
|---|---|---|
| Deferred polling and status codes | SDK-11, SDK-12, SDK-13; A19-HIGH-003, A19-HIGH-004, A14-MED-004, A20-002, A20-003; S08-02, S08-03, S09-01, S05-002, D07-05, D10-02 | `Agent/ChallengeHandler.cs` (reuse `DeferredPoller`), `Server/DeferredState.cs`, `Server/HeldInvocations.cs`, error code catalogue |
| Governance endpoints | SDK-09, SDK-10; A15-002, A15-004, A15-005; SMP-02; DOC-07, D05-01, D05-03 | `Server/Governance/*`, `Person/AAuthPersonServerEndpoints.cs:195`, sample `/mission-interaction` |
| Missions | SDK-14; A16-001, A16-003, A16-004; D04-002, D05-02, D08-05, D10-03 | PS pending paths, `IMissionStore` (add termination reason) |
| Agent client | SDK-15 (MEDIUM), SDK-16; A08-02/A13-01, A10-01, A13-02, A13-04/A07-004, A06-02, A07-003, A07-005, A07-007 | `AAuthClientBuilder.cs` two-key refresh, `AAuthSigningHandler.cs` `created`, `ChallengeHandler.cs` `login_hint` |
| R3 authorization endpoint and audit | SDK-18, SDK-19 (A23-002); A22-MED-001, A23-003, A23-004; D07-04 | `MapAAuthAuthorizationEndpoint` R3 body, R3 audit record, reader policy |
| Federation | A17-001, A17-002, A17-003/A19-HIGH-005; S04-01; D06-02 | PS-AS collapse, `dwk` pinning, `402` flow |
| Events | A24-01, A24-02, A24-03; S06-01 | `src/AAuth.Events/*`, sample `SqliteEventStore` |
| Interaction chaining | A18-003; SMP-03; DOC-05 | `AAuthInteractionChainedException` guidance, Concierge |

## P3 — Hygiene, validation and documentation

| Group | Items |
|---|---|
| JWT / HTTP-sig / metadata validation | SDK-17 (`crit`); A01-H01, A01-M01, A01-M02, A02-HIGH-002, A03-HIGH-001, A04-01, A04-02, A04-04, A04-05, A04-06, A07-002, A19-HIGH-001, A21-TLS-01, A05-02/A06-03, A12-02, A12-03, A11-03, A11-04 |
| Docs rewrite | DOC-01 (getting-started, draft-10 flow); DOC-02 and D02-02 (signing modes); D01-01, D02-03 and D10-06 (five modes); D01-04, D03-03, D03-04, D04-001, D06-04, D06-05, D08-01, D08-02, D08-03, D10-07 |
| Samples | S07-01 (tour signing modes), S08-01 (pending same-origin), S09-02, S03-02, S03-03, plus the LOW prose items |
| LOW | See the LOW lists in `research.md` |

Every CONFIRMED or REPORTED item graded MEDIUM or higher in `research.md` appears above.
