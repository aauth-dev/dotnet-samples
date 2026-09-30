# R12 — Governance endpoints

Findings: SDK-09, SDK-10, A15-004, A15-005, SMP-02, DOC-07,
D05-01, D05-03. Spec: `#agent-governance` L457-L462,
`#interaction-endpoint` L1127-L1190, `#permission-endpoint` L1191-L1242,
`#audit-endpoint` L1243-L1288, `#ps-metadata` L2031-L2072. Files read:
`src/AAuth/Server/Governance/GovernanceEndpoints.cs`,
`DefaultInteractionRelay.cs`, `DelegateInteractionRelay.cs`,
`IInteractionRelay.cs`, `DefaultAuditSink.cs`, `IAuditSink.cs`,
`IMissionLog.cs`, `AAuthGovernancePipelineOptions.cs`,
`src/AAuth/DependencyInjection/AAuthGovernanceApplicationBuilderExtensions.cs`,
`AAuthGovernanceServiceCollectionExtensions.cs`,
`AAuthPersonServerServiceCollectionExtensions.cs`,
`src/AAuth/Person/AAuthPersonServerEndpoints.cs`,
`src/AAuth/Agent/Governance/InteractionClient.cs`, `InteractionResult.cs`,
`PermissionRequest.cs`, `AuditRecord.cs`, `samples/MockPersonServer/Program.cs`,
`MissionGovernance.cs`, and the cited docs/tests.

## Problem restated (verified)

- SDK-09 / D05-01 / SMP-02 are verified. The spec says an `interaction` or
  `payment` relay either returns a deferred response while the PS relays the
  user, or returns `424 interaction_unavailable` when no PS channel exists
  (`#interaction-response-poll-authority`, L1160-L1168;
  `#interaction-endpoint-errors`, L1183-L1190; relay overview L2404-L2408).
  The SDK already has `InteractionRelayResult.Unavailable`
  (`IInteractionRelay.cs:29-36`) and the mapper already maps it to 424
  (`AAuthGovernanceApplicationBuilderExtensions.cs:292`), and it can emit
  `202` + `Location` through `DeferredAccepted` (`:319-331`, `:538-552`).
  However the default relay still returns `{ Pending = false }` for
  `interaction`/`payment` (`DefaultInteractionRelay.cs:21-25`), and the mapper
  turns any non-pending non-question result into `200 {"status":"ok"}`
  (`AAuthGovernanceApplicationBuilderExtensions.cs:334`). The sample repeats the
  same bug in its hand-written `/mission-interaction` endpoint
  (`Program.cs:480-518`) and `SampleInteractionRelay` (`MissionGovernance.cs:217-223`).
- SDK-10 / DOC-07 are verified. PS metadata `interaction_endpoint` is the
  signed governance relay endpoint (`#ps-metadata`, L2063-L2065;
  `#interaction-endpoint`, L1127-L1133), but metadata falls back to the
  browser consent `InteractionPath` (`AAuthPersonServerEndpoints.cs:195`) while
  the governance mapper defaults to `/mission-interaction`
  (`AAuthGovernancePipelineOptions.cs:27`). `.WithGovernance()` only registers
  services (`AAuthPersonServerServiceCollectionExtensions.cs:111-118`), so the
  DI example advertises governance without mapping it
  (`docs/reference/dependency-injection.md:761-775`).
- A15-004 is verified. `parameters` and `result`, when present, are JSON
  objects (`#permission-endpoint`, L1201-L1204; `#audit-endpoint`, L1253-L1257),
  but parsing uses `as JsonObject`, silently dropping strings, arrays, numbers,
  and `null` (`GovernanceEndpoints.cs:67`, `:86-87`).
- A15-005 is verified. The audit endpoint exists so the PS has a complete
  mission record and records the entry in the mission log (`#audit-endpoint`,
  L1243-L1245, L1283-L1287), but `DefaultAuditSink` logs only action and
  description (`DefaultAuditSink.cs:26-31`), and `MissionLogEntry` has no
  `Parameters` or `Result` fields (`IMissionLog.cs:48-55`). The sample audit
  sink has the same loss (`MissionGovernance.cs:196-203`).
- D05-03 is verified. The spec distinguishes the PS relay poll URL from the
  resource-hosted pending URL: for resource-hosted interactions the resource
  pending URL is authoritative, and the PS relay only reports relay progress
  (`#interaction-response-poll-authority`, L1160-L1166). The client doc and XML
  comment still say `interaction`/`payment` "resolve once the user completes"
  (`docs/advanced/mission-governance-clients.md:169`;
  `InteractionResult.cs:11`), which is only true for PS-hosted interactions.

## Candidate fixes

| # | Approach | Pros | Cons | Spec fit | API-surface fit (C1–C13) |
|---|---|---|---|---|---|
| 1 | Minimal patch: default relay returns `Unavailable = true`; metadata fallback changes to omit `interaction_endpoint`; parsers validate object shape; mission log gains audit fields. | Smallest code delta; fixes copied default behavior. | Leaves governance paths declared twice (`AAuthPersonServerOptions` vs `AAuthGovernancePipelineOptions`); docs can still drift; custom relays can still return 200 for non-question interaction/payment. | Partial: default is correct, but non-default SDK mapper can still emit a forbidden 200. | Weak C5/C6 because mechanics remain manually coordinated. |
| 2 | Identity-once governance registration: `.WithGovernance()` declares paths on the PS registration, metadata and mapping derive from those paths, `MapAAuthPersonServer()` maps governance when enabled; mapper accepts only explicit `Unavailable` or `Pending` for `interaction`/`payment`; strict JSON validation; audit fields preserved. | Fixes all findings and prevents metadata/route drift by construction; fail-closed defaults; keeps primitive seams. | Public API/wire cutover; `MapAAuthGovernance` options need renaming/derivation; tests/docs/samples move to new pattern. | Strong: no `/interaction` fallback, no 200 relay success, valid object shapes, complete audit record. | Best C1/C2/C5/C6/C7/C8 fit. |
| 3 | Remove SDK governance mapper defaults and require every PS/sample to hand-map paths and relay behavior. | Maximum host control. | Reintroduces SMP-02/DOC-07 by design; every consumer owns protocol mechanics. | Poor: too easy to be non-conformant. | Violates C2/C6/C8. |

## Recommendation

Use candidate 2.

Make governance a PS-role feature declared once:

1. `.WithGovernance()` sets an internal "governance enabled" flag and default
   PS options for `MissionPath=/mission`, `PermissionPath=/permission`,
   `AuditPath=/audit`, and `InteractionEndpointPath=/mission-interaction`.
   The host may override those same PS options in the `AddAAuthPersonServer`
   configuration delegate. Do not infer `interaction_endpoint` from the
   browser `InteractionPath`; if governance is not enabled and
   `InteractionEndpointPath` is null, omit the metadata field.
2. `MapAAuthPersonServer()` maps the governance endpoints automatically when
   that flag is set, by calling an internal governance mapper built from the
   resolved PS registration (`issuer`, egress policy, paths, pending path, and
   browser interaction URL). Keep a primitive `MapAAuthGovernance(...)` for
   tests/advanced hosting, but rename its governance interaction property to
   `InteractionEndpointPath` so the browser `InteractionPath` name is never
   reused for the signed relay endpoint.
3. For `interaction`/`payment`, the mapper has only two successful relay states:
   `Unavailable = true` maps to `424 interaction_unavailable`; `Pending = true`
   maps to `202 Accepted` with `Location`, `Retry-After`, `Cache-Control:
   no-store`, and the existing pending-store poll route. If no
   `IDeferredConsentStore` is available, fail closed as `424
   interaction_unavailable` rather than returning 200. A relay result with
   neither `Pending` nor `Unavailable` for these types is also treated as
   unavailable. `question` remains `200 { "answer": ... }`.
4. Change `DefaultInteractionRelay` so `interaction` and `payment` return
   `Unavailable = true`. Keep `question` returning an empty answer until a PS
   supplies a user channel; leave completion behavior to R09's mission design.
5. Add a parser helper that distinguishes absent fields from present malformed
   fields and rejects present non-objects (including JSON `null`) for
   `parameters` and `result` with `400 invalid_request`.
6. Add `JsonObject? Parameters` and `JsonObject? Result` to `MissionLogEntry`.
   `DefaultAuditSink` deep-clones `record.Parameters` and `record.Result` into
   the log, and permission logging should also carry `request.Parameters` into
   `MissionLogEntry.Parameters` so the mission log sees the same object that
   policy evaluated.
7. Add constants for governance wire values that are currently string literals
   (`interaction_unavailable`, interaction types, `status` values) under
   `AAuthConstants` per C7 and use them in mapper/client/tests.

Adversarial closure: a custom relay can no longer suppress fallback by returning
the default record value, because non-question relays fail closed to 424 unless
they can create a pollable deferred response. Metadata cannot point agents at
the unsigned browser page unless the PS explicitly sets that as the signed
governance path. Malformed JSON can no longer be hidden by disappearing into
`null`. Audit data is cloned before storage so later mutation of caller-owned
`JsonObject` instances cannot rewrite the mission log.

## Public API delta

Yes.

- `MissionLogEntry` adds init-only `JsonObject? Parameters` and `JsonObject?
  Result`.
- `AAuthPersonServerBuilder.WithGovernance()` remains the high-level opt-in but
  now declares governance paths and causes `MapAAuthPersonServer()` to map them.
  Add an optional configure hook only if needed to keep all governance path
  declarations on the PS registration; do not add a second source of truth.
- `AAuthPersonServerOptions.InteractionEndpointPath` no longer falls back to
  `InteractionPath` in metadata. `MissionPath`, `PermissionPath`, `AuditPath`,
  and `InteractionEndpointPath` become the authoritative governance paths when
  `.WithGovernance()` is used.
- `AAuthGovernancePipelineOptions.InteractionPath` should be renamed to
  `InteractionEndpointPath` (single cutover; no compat alias). If the public
  `MapAAuthGovernance(Action<AAuthGovernancePipelineOptions>)` remains, document
  it as the primitive/advanced API and derive all high-level calls from PS
  options.
- `InteractionRelayResult` can keep the existing `Pending`/`Unavailable`
  properties; update XML docs to state that `interaction`/`payment` relays must
  return one of them. Static factory helpers are acceptable additions, but not
  required.

ApiSurface impact: additive `MissionLogEntry` properties; renamed governance
pipeline property; possible builder/options additions for governance-enabled
state/configure hook; changed XML docs.

## Wire effect

- A default PS with governance enabled now answers non-question
  `interaction`/`payment` relay attempts with `424` and
  `{"error":"interaction_unavailable"}` instead of `200 {"status":"ok"}`.
- A PS relay that can reach the user and has a deferred store answers `202
  Accepted` with `Location`, `Retry-After: 1`, `Cache-Control: no-store`, and
  `{"status":"pending"}`; it never answers initial `200 ok` for
  `interaction`/`payment`.
- If a custom relay returns `Pending = true` but no pending store is registered,
  the mapper returns `424 interaction_unavailable`.
- Minimal PS metadata no longer advertises `interaction_endpoint` as
  `{issuer}/interaction`. With `.WithGovernance()`, metadata advertises the same
  mission/permission/audit/interaction paths that `MapAAuthPersonServer()` maps.
- Permission/audit requests with present non-object `parameters` or present
  non-object `result` now return `400 invalid_request`.
- Audit records accepted with `201 Created` preserve `parameters` and `result`
  in the mission log.

## Implementation sketch

1. In `AAuthConstants`, add governance constants for error/type/status strings
   used by the mapper, client, and tests.
2. In `AAuthPersonServerOptions` / `AAuthPersonServerBuilder`, record whether
   `.WithGovernance()` was called. When called, set default governance paths
   only where the host did not explicitly configure them. Remove the metadata
   fallback from `InteractionEndpoint = OptionalUrl(...InteractionEndpointPath)
   ?? interactionUrl` to `OptionalUrl(...InteractionEndpointPath)`.
3. Refactor `MapAAuthPersonServer()` to invoke an internal governance mapping
   method after signature verification is set up when governance is enabled.
   Pass a single derived options instance with `PersonServer = issuer`,
   `InteractionEndpointPath = options.InteractionEndpointPath`, `MissionPath`,
   `PermissionPath`, `AuditPath`, `EgressPolicy`, `PendingPath`, and
   `InteractionUrl = issuer + options.InteractionPath`.
4. Rename `AAuthGovernancePipelineOptions.InteractionPath` to
   `InteractionEndpointPath`; update `MapAAuthGovernance()` and tests/docs.
5. Change `DefaultInteractionRelay` so `Interaction` and `Payment` return
   `Unavailable = true`. Update `IInteractionRelay` XML docs to require
   `Pending`/`Unavailable` for these types.
6. In `HandleInteractionAsync`, after invoking the relay:
   - if request type is `Question`, return answer as today;
   - if `result.Unavailable`, return 424;
   - if `result.Pending` and `IDeferredConsentStore` exists, park and return
     `DeferredAccepted`;
   - otherwise return 424. Do not keep the fallback `Results.Json(new { status =
     "ok" })` path for `interaction`/`payment`.
7. Add `ReadOptionalObject(JsonObject body, string propertyName)` to
   `GovernanceEndpoints`, using `TryGetPropertyValue` so present `null` is
   rejected. Use it for permission `parameters`, audit `parameters`, and audit
   `result`.
8. Extend `MissionLogEntry` and update `DefaultAuditSink`, permission logging,
   sample sinks, and any display code to carry/deep-clone `Parameters` and
   `Result`.
9. Replace the MockPersonServer hand-written `/permission`, `/audit`, and
   `/mission-interaction` routes with the SDK mapper where possible; at minimum
   delete the custom `/mission-interaction` route and use the SDK interaction
   mapper. Adapt `SampleInteractionRelay` to return `Pending = true` only when
   the sample registers a deferred store that can be polled; otherwise return
   `Unavailable = true`.

## Tests

- `tests/AAuth.Tests/DependencyInjection/AAuthGovernanceDITests`:
  - update `DefaultInteractionRelay_HasNoUserChannel` to assert
    `Unavailable = true` for `Interaction` and `Payment`;
  - keep `Question` answer behavior.
- `tests/AAuth.Tests/Server/ServerRoleRegistrationTests`:
  - add a negative control that a PS without `.WithGovernance()` omits
    `interaction_endpoint`, `mission_endpoint`, `permission_endpoint`, and
    `audit_endpoint`;
  - update `Metadata_DerivesEndpointUrls` to verify `.WithGovernance()` both
    advertises and maps the same derived paths through `MapAAuthPersonServer()`.
- `tests/AAuth.Conformance/Missions/GovernanceEndpointMapperTests`:
  - add the SDK-09 adversarial case: default `AddAAuthGovernance()` +
    non-question interaction returns 424, not 200;
  - add A15-004 negative controls:
    `{"parameters":"send all files"}` on `/permission`,
    `{"parameters":[]}` and `{"result":null}` on `/audit` all return
    `400 invalid_request`;
  - add valid object controls showing `JsonObject` parameters reach the
    `IPermissionDecider` / `IAuditSink`.
- `tests/AAuth.Conformance/Missions/GovernanceDeferredConsentMapperTests`:
  - keep `Interaction_PendingRelay_Parks202_ThenCompletes`;
  - replace `Interaction_NotPending_Returns200` and
    `Interaction_PendingRelay_NoStore_Returns200` with fail-closed 424 tests;
  - assert 202 includes `Location`, `Retry-After`, and no-store cache headers.
- `tests/AAuth.Conformance/Missions/GovernanceEndpointMapperTests` or
  `tests/AAuth.Tests/DependencyInjection/AAuthGovernanceDITests`:
  - add A15-005 default audit-sink test: POST valid audit with `parameters` and
    `result`, read `IMissionLog`, assert both objects are present and are not the
    same mutable instances supplied to the sink.
- `tests/e2e`: after the sample route replacement, run the existing mission
  walkthrough covering MockPersonServer and update assertions that mention
  `/mission-interaction` responses.

## Samples and docs to update

- `samples/MockPersonServer/Program.cs`: remove the custom
  `/mission-interaction` mapper; preferably use SDK governance mapping for
  permission/audit/interaction; keep only sample-specific policy/relay/sink
  seams.
- `samples/MockPersonServer/MissionGovernance.cs`: preserve audit
  `parameters`/`result`; return `Unavailable` or `Pending` for
  `interaction`/`payment`, never `Pending = false`.
- `samples/MockPersonServer/README.md`: endpoint table and governance wiring
  description should say the SDK mapper owns governance routes.
- `docs/server/mission-governance.md`: default relay is fail-closed 424, not
  "no-op"; `.WithGovernance()` declares and maps paths through the PS role;
  `MapAAuthGovernance()` is primitive/advanced usage; audit log includes
  parameters/result.
- `docs/advanced/mission-governance-clients.md`: fix D05-03. For resource-hosted
  interactions, the agent must keep polling the resource `Location`; the PS
  relay result only reports relay progress or unavailability.
- `docs/reference/dependency-injection.md`: replace the example at lines
  761-775 so `.WithGovernance()` plus `MapAAuthPersonServer()` is sufficient,
  and do not show metadata without mapping.
- `docs/server/token-issuance.md` and `docs/reference/configuration.md`: update
  `InteractionEndpointPath` default/fallback text; no fallback to
  `InteractionPath`.
- XML docs in `InteractionResult`, `InteractionClient`, `IInteractionRelay`,
  `DefaultInteractionRelay`, and `AAuthGovernancePipelineOptions`.

## Dependencies and conflicts with other Rnn

- R09 owns mission completion semantics and any removal of
  `InteractionType.Completion`; this design only prevents completion leakage
  through the interaction endpoint and keeps existing mission-action mapping.
- R11 owns generic deferred polling and error-code semantics. This design reuses
  the existing `IDeferredConsentStore` and `DeferredAccepted` mechanics, but
  requires them for interaction relay 202 responses.
- R10 / A15-002 owns PS binding of agent tokens. This design does not add the
  missing `ps` claim check, but its auto-mapping should compose with that check
  when R10 adds it.
- R03/R11 may add protocol constants and error helpers; coordinate the
  `AAuthConstants` namespace to avoid duplicate constant containers.

## Open questions (with proposed default)

1. Should `.WithGovernance()` automatically call `AddAAuthDeferredConsent()`?
   Proposed default: **no**. Keep permission/mission prompt behavior unchanged;
   for interaction/payment, return 424 when no pending store exists. A PS that
   can relay registers `AddAAuthDeferredConsent()` or its own
   `IDeferredConsentStore`.
2. Should `MapAAuthGovernance()` remain public after `MapAAuthPersonServer()`
   auto-maps governance? Proposed default: **yes, primitive/advanced API**, but
   it must use `InteractionEndpointPath` terminology and docs must steer normal
   PS hosts to `.WithGovernance()` + `MapAAuthPersonServer()`.
3. Should present JSON `null` for `parameters`/`result` be accepted as absent?
   Proposed default: **no**. The spec says present fields are JSON objects; null
   is a present non-object and should be `400 invalid_request`.
