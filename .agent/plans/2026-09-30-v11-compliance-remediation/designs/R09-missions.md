# R09 — Missions

Findings: SDK-14/A16-002, A16-001, A16-003, A16-004, D04-002, D05-02, D08-05, D10-03. Spec: #missions L1307-L1321; #mission-approval L1423-L1425; #mission-identifier L1431-L1440; #mission-management L1509-L1528; #mission-endpoint-errors L1532-L1547; #mission-status-errors L1548-L1568. Files read: `/root/.copilot/session-state/6914b16c-5d96-4ece-b683-aa71d7a4b36b/files/design-brief.txt`; remediation `research.md`; audit `research.md`; findings `sdk/A16-missions.md`, `docs/D04-server-authz-issuance.md`, `docs/D05-missions-governance.md`, `docs/D08-errors-config.md`, `docs/D10-readmes-claims.md`; API-surface `research.md` and `implementation-log.md`; spec `aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md`; code and docs named below.

## Problem restated (verified)

- **SDK-14 / A16-002 (verified):** initial mission validation now checks `StoredMission.PersonServer`, `State`, and `ExpiresAt` (`AAuthPersonServerEndpoints.cs:816-827`), but later pending/federated paths still use state-only checks. The pending poll path enters `DeferredState.ExecuteAsync(... entry.PendingExpiresAt ...)` before mission evaluation and then checks only `State` (`AAuthPersonServerEndpoints.cs:619-629`), while the federated helper checks only `State` at each re-entry (`AAuthPersonServerEndpoints.cs:1254-1259`, callers at `:1268`, `:1305`, `:1348`, `:1454`). An expired mission can therefore continue, or be reported as generic deferred `expired` instead of `403 mission_terminated` with `termination_reason=expired`, contrary to #mission-approval L1423-L1425 and #mission-status-errors L1548-L1568.
- **A16-001 (verified):** `StoredMission` persists `State` and `ExpiresAt`, but not a termination reason (`IMissionStore.cs:17-31`). `IMissionStore.SetStateAsync` has no reason parameter (`IMissionStore.cs:56`; `InMemoryMissionStore.cs:39`), and completion paths terminate without recording `completed` (`AAuthGovernanceApplicationBuilderExtensions.cs:424`, `:532`; `samples/MockPersonServer/Program.cs:557`, `:717`). This violates #mission-management L1518-L1528.
- **A16-003 (verified):** mission creation stores `PersonServer` (`AAuthGovernanceApplicationBuilderExtensions.cs:467`), and `/token` validation uses it (`AAuthPersonServerEndpoints.cs:816-821`), but governance authorization ignores it: `GovernanceEndpoints.Authorize` checks only carrier agent, `mission.S256`, and `mission.Agent` before active/expired state (`GovernanceEndpoints.cs:25-45`). A shared `IMissionStore` can accept `ps-a` missions at `ps-b`, violating #mission-identifier L1431-L1440.
- **A16-004 (verified, partially mitigated only at the body/status layer):** the public helper returns `404 mission_not_found` for absent and foreign-agent missions (`GovernanceEndpoints.cs:39-41`), and existing tests cover foreign agent vs unknown body/status. However every governance mapper first does a direct `GetAsync(s256)` (`AAuthGovernanceApplicationBuilderExtensions.cs:179`, `:252`, `:284`, `:375`, `:488`; sample at `Program.cs:394`, `:471`, `:502`, `:534`, `:584`), and the store API is keyed only by `s256` (`IMissionStore.cs:49`; `InMemoryMissionStore.cs:31`). Foreign-PS missions can be found and accepted (A16-003), and hit/miss timing can still reveal existence before authorization, contrary to #mission-endpoint-errors L1539-L1547.
- **Docs D04-002, D08-05, D10-03 (verified):** docs and conformance summaries claim mission expiry is enforced on pending/federated paths (`docs/server/token-issuance.md:165-168`, `docs/advanced/error-handling.md:336-340`, `README.md:301-303`, `aauth-spec/SPEC-VERSION.md:22-26`) while the code above does not.
- **Docs D05-02 (verified):** mission governance docs show `SetStateAsync(s256, MissionState.Terminated)` and a reasonless `MissionTerminated()` response (`docs/server/mission-governance.md:180-192`, `:315-326`), matching the SDK gap instead of #mission-management L1518-L1528.
- **API-surface ruling Q18 (verified):** termination reasons are the existing open-set `AAuthConstants.MissionTerminationReasons` `const string`s, and `AAuthMissionTerminatedException.TerminationReason` remains `string?` (`implementation-log.md:128-136`, `:200-218`; `AAuthConstants.cs:83-100`; `AAuthMissionTerminatedException.cs:30`).

## Candidate fixes

| # | Approach | Pros | Cons | Spec fit | API-surface fit (C1–C13) |
|---|---|---|---|---|---|
| 1 | Patch each caller: add `ExpiresAt` comparisons, add optional reason to `SetStateAsync`, and pass `PersonServer` into only the governance helper. | Smallest diff; familiar method names. | Repeats logic; future decision paths can miss expiry again; `SetStateAsync(..., state, reason?)` still allows illegal "active with reason" shapes; hit/miss timing remains store-dependent. | Medium: fixes visible defects but not the "one decision path" requirement or reason/state separation cleanly. | Weak C1/C6/C3: compat-shaped API and duplicated mechanics. |
| 2 | Add one mission-status evaluator used by all endpoints; keep `GetAsync(s256)` and `SetStateAsync(s256, state, reason?)`. | Centralizes expiry, state, and reason; less implementation churn than store re-keying. | Mission identity remains under-modeled; shared stores still need every caller to remember a separate `PersonServer` equality; `SetStateAsync` remains too permissive. | Medium-high for SDK-14/A16-001; incomplete for A16-003/A16-004. | Mixed C6/C7; weaker C1 because the old mental model survives. |
| 3 | **Recommended:** change mission persistence to the spec identity `(PersonServer, s256)`, replace generic state mutation with reasoned termination, and route every mission decision through one evaluator that checks owner, PS, state, expiry, and reason. | Enforces identity and lifecycle at the seam; one expiry/status implementation; records reasons for completed/revoked/expired; gives absent/foreign one uniform endpoint result; durable stores get an explicit contract. | Public breaking change to `IMissionStore` and snippets; requires touching all SDK/sample call sites; constant-time is "best effort" for arbitrary external stores. | High: directly implements #mission-approval, #mission-identifier, #mission-management, #mission-endpoint-errors, and #mission-status-errors. | Strong C1, C3, C6, C7, C12: single cutover, `TimeProvider`, SDK-owned mechanics, string constants, named/co-hosted PS safety. |

## Recommendation

Implement candidate 3.

Add one SDK-owned mission status evaluator in `AAuth.Server.Governance` and require all PS token, person-token, governance, pending, and sample decision paths to use it. The evaluator takes `(IMissionStore store, expectedPersonServer, missionS256, expectedAgent, TimeProvider, CancellationToken)` plus an ownership mode for upstream missions, performs the `(PS, s256)` lookup, does the same fixed-work owner checks for missing/foreign records, auto-terminates expired active missions with `AAuthConstants.MissionTerminationReasons.Expired`, and returns exactly one of: ok with `StoredMission`; `mission_not_found`; or `mission_terminated` with the stored/effective reason.

Change mission storage so termination is not a free-form state transition. `StoredMission` gains `TerminationReason`; `IMissionStore.GetAsync` is keyed by `personServer` and `s256`; `IMissionStore.TerminateAsync(personServer, s256, terminationReason, ct)` replaces `SetStateAsync`. `TerminateAsync` is idempotent, preserves the first reason, rejects blank reasons, and never revives a terminated mission. Completion uses `Completed`; admin/sample revocation uses `Revoked` or `Administrative`; expiry uses `Expired`; future unknown reasons are retained as opaque strings.

For A16-004, the SDK can make its in-memory default and helpers constant-time-ish, not mathematically constant for every durable backend. The contract should require custom stores to make `(personServer, s256)` lookup and miss/foreign paths observably equivalent; the default in-memory store should key by `(PersonServer, S256)` and the evaluator should always perform the same response construction, owner digest comparisons, cache-control/body/header writes, and optional security logging after lookup.

## Public API delta

- **Changed:** `StoredMission` adds `public string? TerminationReason { get; init; }`; `State == MissionState.Terminated` requires a non-empty reason. ApiSurface update required.
- **Changed/removed:** `IMissionStore.GetAsync(string s256, ...)` becomes `GetAsync(string personServer, string s256, ...)`. ApiSurface update required; no compatibility overload (C1).
- **Removed/replaced:** `IMissionStore.SetStateAsync(string s256, MissionState state, ...)` is removed. Add `TerminateAsync(string personServer, string s256, string terminationReason, CancellationToken ct = default)`. ApiSurface update required.
- **Changed:** `GovernanceEndpoints.Authorize(...)` should become async or be replaced by `AuthorizeMissionAsync(...)`/`EvaluateMissionAsync(...)` that accepts `expectedPersonServer` and `TimeProvider`; manual endpoints stop pre-loading missions themselves. ApiSurface update required.
- **Added:** `AAuthGovernancePipelineOptions.TimeProvider { get; set; } = TimeProvider.System` so governance expiry uses the same testable clock convention as PS endpoints. ApiSurface update required.
- **Unchanged by ruling Q18:** `AAuthConstants.MissionTerminationReasons` remains `const string`; `AAuthMissionTerminatedException.TerminationReason` remains `string?`; `GovernanceEndpoints.MissionTerminated(string? terminationReason = null)` remains string-based.

## Wire effect

- Expired missions on all PS decision paths return `403 application/problem+json` with `error=mission_terminated`, `mission_status=terminated`, and `termination_reason=expired`. This replaces current pending/federated cases that can continue or return generic `408/410 expired`.
- Terminated-but-owned missions include `termination_reason` when the store has one, including `completed`, `revoked`, `superseded`, `administrative`, and unknown opaque strings. Reason remains optional only for pre-existing/custom stores that somehow cannot supply one; SDK defaults always supply one after this cutover.
- Governance endpoints for nonexistent, foreign-agent, and foreign-PS missions return the same `404 mission_not_found` status, problem body, content type, cache-control behavior, and absence of signature error headers. Foreign-PS missions that previously succeeded become `404`.
- Completion success may continue to return `200 { "mission_status": "terminated" }`; adding `"termination_reason": "completed"` is acceptable but not required by #mission-status-errors because that section governs errors. Subsequent requests under that mission should return `mission_terminated` with `termination_reason=completed`.
- Admin/sample termination endpoints are non-protocol demo wire. Update them to accept or choose a reason and to echo it in their local JSON responses.

## Implementation sketch

1. **Store contract and model**
   - In `src/AAuth/Server/Governance/IMissionStore.cs`, add `StoredMission.TerminationReason`.
   - Replace `GetAsync(string s256, ...)` with `GetAsync(string personServer, string s256, ...)`.
   - Replace `SetStateAsync` with `TerminateAsync(string personServer, string s256, string terminationReason, ...)`.
   - Document invariants: active missions have no reason; terminated missions have a reason; replacement `SaveAsync` preserves terminated state/reason and earliest `ExpiresAt`.
2. **Default store**
   - In `InMemoryMissionStore`, key the dictionary by a private composite `(personServer, s256)` string or value tuple, not `s256` alone.
   - Make `TerminateAsync` an atomic add/update loop that no-ops on absent, preserves the first termination reason, and never writes a blank reason.
   - Use ordinal comparison and no user-visible difference between absent and foreign-PS lookups; do not expose a "found but not yours" return.
3. **Mission status evaluator**
   - Add an internal/public helper (prefer `MissionStatusEvaluator` or a new async `GovernanceEndpoints.AuthorizeMissionAsync`) that:
     1. validates a non-null mission reference only after the caller has already rejected malformed path/body values as `400 invalid_request`;
     2. fetches by `(expectedPersonServer, s256)`;
     3. compares the expected agent to the stored `Agent` using fixed-length digests and performs the same work with dummy values on null;
     4. returns uniform `mission_not_found` for null, wrong PS, wrong `s256`, or wrong agent;
     5. if active and `ExpiresAt <= timeProvider.GetUtcNow()`, calls `TerminateAsync(..., Expired)` and returns `mission_terminated` with the stored/current reason;
     6. if already terminated, returns `mission_terminated` with `TerminationReason`;
     7. otherwise returns the active `StoredMission`.
   - The helper should set `Cache-Control: no-store` consistently through `AAuthProblemDetails`, and should not include detail text on `mission_not_found`.
4. **Governance endpoints**
   - In `AAuthGovernanceApplicationBuilderExtensions`, stop doing `missions.GetAsync(missionS256)` before authorization. Pass `ResolvePersonServer(ctx, options)`, the verified agent, `options.TimeProvider`, and the mission reference into the evaluator for permission (`:179-181`), audit (`:252-253`), interaction (`:284-285`), pending governance (`:375-376`), and mission update/completion (`:488-489`).
   - Change completion acceptance to `TerminateAsync(personServer, missionS256, AAuthConstants.MissionTerminationReasons.Completed, ...)` in both immediate and deferred completion paths (`:424`, `:532`).
   - Make `GovernanceEndpoints.Authorize` either a thin async wrapper over the evaluator or remove it from internal call sites in favor of the evaluator. Keep `MissionTerminated(...)`/`MissionTerminatedBody(...)`.
5. **PS token/person endpoints**
   - In `AAuthPersonServerEndpoints.ValidateMissionAsync`, replace bespoke checks with the evaluator using `issuer` as `expectedPersonServer`. Preserve the upstream-owner rule: a valid upstream token carrying the same mission can authorize the downstream agent even when `StoredMission.Agent` is the upstream agent; this should be an explicit evaluator mode, not a side condition hidden in callers.
   - Replace `ThrowIfMissionTerminatedAsync` with evaluator-based `ThrowIfMissionInactiveAsync` that throws `AAuthTokenExchangeException("mission_terminated", reason, 403, terminal: true)` for both stored termination and expiry.
   - In pending poll, evaluate mission status under the pending lifecycle gate before generic deferred expiry wins. If `DeferredState.ExecuteAsync` must be extended, add a pre-expiry callback/result rather than checking mission expiry after `entry.PendingExpiresAt`.
   - Ensure federation cancellation occurs before returning mission termination, as the current state-only path does (`AAuthPersonServerEndpoints.cs:624-628`).
6. **Samples and docs**
   - Update `samples/MockPersonServer/Program.cs` manual governance and admin endpoints to call the evaluator and `TerminateAsync(..., Completed/Revoked/Administrative)`.
   - Update snippets and prose listed below.

## Tests

- `tests/AAuth.Tests`, new `Server/Governance/InMemoryMissionStoreTests`:
  - `TerminateAsync_StoresReasonAndPreservesFirstReason` (negative control: second termination tries `administrative`, first `completed` remains).
  - `GetAsync_UsesPersonServerAndS256Pair` (same `s256` at `ps-a` and `ps-b` do not alias).
  - `SaveAsync_DoesNotReviveTerminatedMissionOrExtendExpiry`.
- `tests/AAuth.Tests` or `tests/AAuth.Conformance`, new/extended mission evaluator tests:
  - active mission succeeds;
  - expired active mission returns/stores `termination_reason=expired`;
  - terminated mission returns stored unknown reason unchanged;
  - absent, wrong agent, and wrong PS all produce equal `mission_not_found` bodies and headers.
- `tests/AAuth.Conformance/Person/PersonServerMapperTests`:
  - extend `Mission_Terminated_Rejected` to assert stored termination reasons for explicit termination and expiry;
  - add `PendingMission_ExpiresBeforePoll_ReturnsMissionTerminated`, reproducing SDK-14's negative control where a deferred `/token` or `/person` request parks under a mission whose `expires_at` passes before poll. Expected: `403 mission_terminated`, not `408 expired`, and no token minted.
- `tests/AAuth.Conformance/Person/DeferredFederationTests`:
  - add a four-party case where mission expiry occurs while the PS is waiting on AS/resource interaction. Expected: federation is cancelled or its result discarded, `FederateAsync` cannot lead to a delivered token, and poll returns `termination_reason=expired`.
  - add a terminated-with-reason case to ensure `ThrowIfMissionInactiveAsync` propagates `revoked`/unknown reasons from the store.
- `tests/AAuth.Tests/Integration/MissionAgentFlowTests`:
  - extend `Governance_SignedInvalidMissionCannotAct` to cover a stored mission with correct agent and `s256` but wrong `PersonServer`.
  - add `Governance_SharedStoreWrongPersonServerIsMissionNotFound`: two PS hosts/share store; mission approved at `https://ps-a`; same agent posts to `https://ps-b/mission/{s256}`. Expected: same `404 mission_not_found` body/header as a random hash, and no log entry.
  - update `PermissionPending_TerminatedMissionCannotReleaseLateApproval` to assert `termination_reason` when the stored reason is `revoked` or `expired`.
- `tests/AAuth.Conformance/Missions/MissionTerminatedTests`:
  - keep existing constant-string and unknown-reason round-trip tests;
  - add an SDK-hosted response test showing `GovernanceEndpoints.MissionTerminated(storedReason)` is what pending/token paths emit, not only a fake HTTP handler.
- API surface gate: update `.agent/plans/.../api-surface-map.md` for `IMissionStore`, `StoredMission`, `AAuthGovernancePipelineOptions`, and `GovernanceEndpoints`.

## Samples and docs to update

- `samples/MockPersonServer/Program.cs`: replace all `GetAsync(s256)`/`SetStateAsync` governance calls (`:394`, `:471`, `:502`, `:534`, `:557`, `:584`, `:717`) with `(personServer, s256)` evaluator/termination calls.
- `samples/MockPersonServer/MissionGovernance.cs`: update comments if needed so mission policy cleanup names reasoned termination rather than state-only termination.
- `samples/MockPersonServer/README.md`: mention stored termination reasons if the admin/demo termination endpoint is documented.
- `docs/server/mission-governance.md`: update endpoint behavior (`:116-118`), `IMissionStore` snippet (`:180-192`), and termination guidance (`:315-326`) to use `TerminateAsync(..., reason)` and show `termination_reason`.
- `docs/advanced/missions.md`: update the "Two states" section (`:94-96`) to explain that state is active/terminated and the reason is stored alongside the mission as an open string.
- `docs/advanced/error-handling.md`: update mission termination prose (`:306-340`) after the implementation so it says SDK endpoints report stored reasons, including `expired` for `expires_at`.
- `docs/server/token-issuance.md`: keep the pending-ceiling claim (`:165-168`) only after tests prove pending/federated expiry now returns mission termination; otherwise make it conditional during rollout.
- `docs/workflows/mission-governed-access.md`: update termination paragraph (`:149-151`) to mention `TerminationReason`.
- `docs/README.md`: update `IMissionStore` description (`:192-193`) from "blob + state" to "blob + state + termination reason, keyed by PS+s256".
- `docs/reference/dependency-injection.md` and `docs/reference/configuration.md`: update public seam/options references for changed `IMissionStore` and new `AAuthGovernancePipelineOptions.TimeProvider`.
- `README.md` and `aauth-spec/SPEC-VERSION.md`: the broad "missions with expiry" claim becomes accurate only after this fix lands; adjust if the implementation is staged separately from docs.

## Dependencies and conflicts with other Rnn

- **R06 Revocation:** mission termination can be a revocation cascade trigger (#revocation-cascade L2754). This design records `revoked`/`administrative`; R06 should consume `TerminateAsync`/stored reasons instead of inventing a second mission-revocation state.
- **R11 Deferred polling:** this design needs mission termination to beat generic deferred expiry on mission-governed pending entries. If R11 changes `DeferredState` statuses (`invalid_code`, first timeout, `slow_down`), coordinate the pre-expiry hook so mission status errors remain `403 mission_terminated`.
- **R12 Governance endpoints:** R12 may touch `MapAAuthGovernance`/interaction defaults. It should call the same evaluator for permission/audit/interaction/mission actions and preserve `(PersonServer, s256)` identity.
- **R18/R19 Samples/docs:** sample and docs rewrite areas should not document the state-only `SetStateAsync` shape after this public API cutover.
- **API-surface initiative:** Q18 is not reopened; reasons stay string constants, not an enum or record struct.

## Open questions (with proposed default)

None. Defaults are part of the recommendation: single-cutover API break; reasons are `const string` open-set values; `IMissionStore` is keyed by `(PersonServer, s256)`; `TerminateAsync` replaces `SetStateAsync`; all mission decisions use the evaluator.
