# R10 — Agent–person binding and person-token defaults

Findings: SDK-07/A11-01, A11-03, A11-04, A15-002, SMP-01. Spec: #agent-governance L457-L462, #agent-token-structure L519-L526, #person-token-endpoint L801-L847, #person-token-structure L856-L899, #person-token-exposure L2872-L2879, #agent-person-binding L2912-L2926, #directed-identifiers L2953-L2962, #untrusted-input L2844. Files read: `src/AAuth/Person/AgentPersonBinding.cs`, `src/AAuth/Person/IIdentityClaimsAsserter.cs`, `src/AAuth/Person/AAuthPersonServerEndpoints.cs`, `src/AAuth/Tokens/AgentIssuanceContext.cs`, `src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs`, `src/AAuth/Server/Verification/AAuthVerificationResult.cs`, `src/AAuth/Server/Governance/GovernanceEndpoints.cs`, `src/AAuth/DependencyInjection/AAuthGovernanceApplicationBuilderExtensions.cs`, `src/AAuth/Server/Governance/AAuthGovernancePipelineOptions.cs`, `src/AAuth/Server/IJtiStore.cs`, `src/AAuth/Server/InMemoryJtiStore.cs`, `src/AAuth/DependencyInjection/AAuthPersonServerServiceCollectionExtensions.cs`, `samples/MockPersonServer/SampleIdentityClaimsAsserter.cs`, `samples/MockPersonServer/ConsentBridgePersonPendingStore.cs`, relevant tests and docs listed below.

## Problem restated (verified)

- SDK-07/A11-01 is still present, with the audit caveat that the fix must bind to a stable internal person key, not to a per-resource directed `sub`. `AgentPersonBinding.Key` records only `(personServer, agentIssuer, agentId)` in the token inventory (`Person/AgentPersonBinding.cs:21`) and `Registration` carries no person identifier (`:40`). `RegisterSourcesAsync` registers that binding before identity assertion (`Person/AAuthPersonServerEndpoints.cs:394-400`), while the `/person` handler later mints whatever `assertion.Subject` the asserter returns (`:526`, `:545-546`). `IdentityAssertion` exposes only `Subject` for the person identifier (`Person/IIdentityClaimsAsserter.cs:164`, `:185`). A custom asserter can therefore return Alice's directed subject once and Bob's later for the same `(agent_token.iss, agent_token.sub)`, violating #agent-person-binding L2914-L2919.
- A11-03 is still present. The default SDK asserter stores one configured `_subject` (`IIdentityClaimsAsserter.cs:208-214`) and returns it for every `ResourceUrl` (`:222`). The endpoint emits that subject as the person token `sub` (`AAuthPersonServerEndpoints.cs:545-546`), so two resources get the same identifier despite #directed-identifiers L2955-L2959 and #person-token-structure L867-L868.
- A11-04 is still present. The default asserter unconditionally asserts (`IIdentityClaimsAsserter.cs:222`), `/person` calls the asserter and mints immediately (`AAuthPersonServerEndpoints.cs:526`, `:545-546`), and there is no store keyed by `(person key, resource)` or metadata fetch before first issuance. A hostile but syntactically valid resource can receive a first person token without a new-resource approval screen, contrary to #person-token-exposure L2876 and #person-token-endpoint L838-L840.
- A15-002 is still present. The verification middleware extracts the agent `sub` for agent tokens (`AAuthVerificationMiddleware.cs:282`) but sets `PersonServer` only for person/auth tokens (`:283-286`, `:323`). `GovernanceEndpoints.Authorize` accepts any verified agent token, and for missionless calls returns success before checking any PS (`GovernanceEndpoints.cs:31-38`). All governance handlers call that helper without an expected PS (`AAuthGovernanceApplicationBuilderExtensions.cs:181`, `:253`, `:285`, `:376`, `:489`), so a missing or foreign `ps` agent token can use this PS's permission/interaction surfaces even though #agent-governance L459 says an agent with a PS carries `ps`.
- SMP-01 is still present in the sample support code. `SampleIdentityClaimsAsserter.IsAdminAgent` grants demo roles/groups to any `agentId` starting with `aauth:demo@` (`SampleIdentityClaimsAsserter.cs:46-47`, used at `:52`) and `ConsentBridgePersonPendingStore` repeats that test when releasing a pending entry (`ConsentBridgePersonPendingStore.cs:56-60`). The sample already derives resource-pairwise demo subjects (`SampleIdentityClaimsAsserter.cs:21-23`, `:55`), so the remaining sample issue is the prefix-based admin trust decision over untrusted agent-token content (#untrusted-input L2844).

## Candidate fixes

| # | Approach | Pros | Cons | Spec fit | API-surface fit (C1–C13) |
|---|---|---|---|---|---|
| 1 | Store the last emitted person-token `sub` in `IJtiStore` under the existing `AgentPersonBinding` key and compare it on later requests; change `DefaultIdentityClaimsAsserter` to hash `(subject, resource)`. | Small patch; few new services. | Wrong invariant: directed `sub` is per-resource and cannot prove the same person across resources; would reject legitimate pairwise subjects or bless cross-person asserter bugs for one resource. No first-issuance approval seam. | Poor: contradicts #directed-identifiers L2955-L2959 and the review's "do not store pairwise `sub` as binding" requirement. | Weak C6/C11: abuses token inventory for identity policy and keeps mechanics scattered. |
| 2 | Add only an `IdentityAssertion.PersonKey` and an in-memory binding dictionary inside the `/person` endpoint; keep subject derivation and first-use approval as consumer asserter duties. | Blocks the exact second-person claim with little API surface. | Still default-correlates resources; still silently issues first-resource tokens; no persistent/custom store; auth-token consent paths can still assert claims for a different internal person than the presented person token. | Partial: fixes #agent-person-binding but leaves A11-03/A11-04. | Weak C2/C4/C6/C12: no R0 seam, not suitable for production. |
| 3 | Add explicit person-key, binding, directed-subject, and first-issuance seams: `IdentityAssertion` carries an opaque stable person key; SDK enforces an `IAgentPersonBindingStore`; default subject derivation is HMAC(person key, resource) with a PS secret; a first-resource enrollment store requires approval and records the directed subject; governance requires the agent token `ps` to match the mapped PS; sample admin is exact allow-list based. | Enforces the invariant by default; does not store pairwise `sub` as the agent binding; closes pairwise and first-use defaults; supports persistent production stores; keeps policy (who the person is, who is admin) in host seams. | Largest API cutover; custom asserters, pending stores, snippets, and tests must update; needs careful treatment of login-on-consent where person key is learned at approval time. | Strong: maps directly to #agent-person-binding L2914-L2920, #person-token-endpoint L838-L844, #directed-identifiers L2955-L2959, and #agent-governance L459 while respecting #agent-token-structure L523-L526. | Strong C1/C2/C4/C6/C11/C12: no compat shim, R0 stores/services, SDK-owned mechanics, in-memory defaults warn outside Development. |

## Recommendation

Adopt candidate 3 as one coordinated cutover.

The key invariant should be: **the SDK binds `(personServer, agent_token.iss, agent_token.sub)` to one opaque `PersonKey`, and every non-upstream issuance for that agent must prove the same `PersonKey` before any person/auth token or identity claims leave the PS**. The binding store MUST NOT use or persist the directed per-resource `sub` as the binding identity. The directed `sub` is derived or recorded separately per `(PersonKey, resource)`.

Use a typed public value, for example `AAuthPersonKey`, to make the asserter's stable internal key hard to confuse with a wire `sub`. `IdentityAssertion.Assert` carries `PersonKey` and an optional explicit directed subject; when the subject is omitted the endpoint derives it through `IPersonSubjectDeriver`. `IdentityAssertion.NeedsConsent` may carry a `PersonKey` when the person is already known; otherwise the updated pending approval API must supply it before minting. `IdentityAssertion.Deny` need not carry one.

Add `IAgentPersonBindingStore` as the authoritative SDK seam:

- `BindOrVerifyAsync(AgentPersonBindingContext, ct)` atomically creates the first binding or returns conflict when the existing live binding names a different `PersonKey`.
- `RevokeAsync(personServer, agentIssuer, agentId, ct)` clears/marks the binding so a different `PersonKey` can be established.
- The in-memory default is keyed by PS instance, uses exact ordinal `(personServer, agentIssuer, agentId)`, and logs the same non-production warning style as the in-memory inventory defaults.
- `AgentPersonBinding.RevokeAsync` and `IAAuthRevocationService.RevokeAgentAsync` must revoke both the inventory key and the binding-store row, otherwise the "until revoked" spec escape hatch cannot work.

Add `IPersonResourceEnrollmentStore` as the first-issuance and directed-subject record:

- Records `(personServer, personKey, resource, directedSubject, approvedAt, metadata snapshot/hash)`.
- Resolves `(personServer, resource, directedSubject)` back to `PersonKey` for auth-token requests and call-chaining upstream tokens; unknown records fail closed because #person-token-endpoint L841-L843 says the PS resolves the person from its own record and rejects if it has none.
- First issuance for a `(personKey, resource)` fetches resource metadata through `MetadataClient.FetchResourceMetadataAsync` before surfacing approval. If metadata cannot be fetched, default to `400 invalid_request` with detail rather than minting silently; this stays within the token endpoint error set (#token-endpoint-error-codes L2580-L2616).

Add `IPersonSubjectDeriver` plus `AAuthPersonServerOptions.PairwiseSubjectSecret` (configuration-friendly base64url or key-handle-backed secret). The default derivation is `base64url(HMACSHA256(secret, personServer || "\0" || personKey || "\0" || resource))`, optionally truncated to a documented length. Do not derive from the PS signing key: signing-key rotation must not rotate person identifiers, and key reuse would couple JWT signing compromise to all pairwise subjects. If no secret is configured, the development default generates an ephemeral secret and warns; production guidance must require a persistent secret/store.

For A15-002, add `AAuthVerificationResult.AgentPersonServer` populated from the signed agent-token `ps` claim, leaving `PersonServer` semantics for person/auth tokens unchanged. Change `GovernanceEndpoints.Authorize` to require an `expectedPersonServer` parameter and reject when `AgentPersonServer` is absent or not exact-equal. Although #agent-token-structure L523-L526 calls `ps` informational for resources and says an authorization's PS is learned from the person token, governance endpoints do not receive a person/auth token. For these PS-owned endpoints, the signed AP-issued `ps` is the only in-band statement that the agent is governed by this PS; an agent without it is simply not a PS-governed agent and should fail closed. Also require a mission-bound request's stored `mission.PersonServer` to equal `expectedPersonServer` before comparing the agent, so shared mission stores cannot bleed across named PS instances.

For SMP-01, remove prefix trust entirely. Add sample configuration for exact admin agents, e.g. a set of `(AgentIssuer, AgentId)` pairs or a callback registered in `Program.cs`, and add `AgentIssuer` to `IdentityAssertionRequest` so the asserter and `ConsentBridgePersonPendingStore` can make the same exact decision. If no exact match is configured, no demo roles/groups are emitted.

Adversarial closure:

- A malicious asserter returning Bob's `PersonKey` after Alice is bound gets `403 denied` before minting or claim release.
- A malicious resource cannot cause cross-resource correlation on the default path because `sub` is HMAC-pairwise per resource, and first issuance cannot mint until metadata is fetched and approval is recorded.
- An intermediary carrying `upstream_token` neither uses nor changes its own agent binding; it resolves the upstream person's key from the enrollment store. Unknown `(resource, sub)` is rejected instead of inventing a binding.
- A conforming AP issuing no `ps` can still use non-governance protocol flows when the PS/asserter trusts it, but it cannot use governance endpoints whose entire purpose is PS governance.

## Public API delta

Breaking public changes are required (C1):

- Add `AAuthPersonKey` (or equivalent opaque value type) and `IdentityAssertion.PersonKey`.
- Change `IdentityAssertion.Assert(...)` factories to require `PersonKey`; allow an optional explicit directed `subject`. Change `NeedsConsent(...)` and `IPersonPendingStore.MarkAllowed(...)`/`PersonPendingEntry` so an approval can provide `PersonKey` and optional directed subject.
- Add `IdentityAssertionRequest.AgentIssuer`, and likely `FirstIssuance`, `ResourceMetadata`, and `BoundPersonKey`/`ResolvedPersonKey` fields so policy can render the right consent screen and verify auth-token assertions.
- Add public seams and defaults: `IAgentPersonBindingStore`/`InMemoryAgentPersonBindingStore`, `IPersonResourceEnrollmentStore`/`InMemoryPersonResourceEnrollmentStore`, `IPersonSubjectDeriver`/`HmacPersonSubjectDeriver`.
- Add builder methods following the R0 ladder: `UseAgentPersonBindingStore(...)`, `UsePersonResourceEnrollmentStore(...)`, `UsePersonSubjectDeriver(...)`; add `AAuthPersonServerOptions.PairwiseSubjectSecret`.
- Change `AgentPersonBinding.RevokeAsync` or add a canonical revocation API that updates both the binding store and the inventory; update `IAAuthRevocationService.RevokeAgentAsync` accordingly.
- Add `AAuthVerificationResult.AgentPersonServer`.
- Change `GovernanceEndpoints.Authorize` signature to include `expectedPersonServer`; update all call sites and snippets.

ApiSurface impact is expected in `Person`, `Server.Verification`, `Server.Governance`, and DI builder baselines. No compatibility overloads should remain.

## Wire effect

- Default person tokens for two resources change from `sub = "pairwise-sub"` to distinct HMAC-derived directed subjects; the same `(personKey, resource)` remains stable while the configured secret and enrollment store persist.
- First issuance for a new `(personKey, resource)` no longer returns `200` by default. It fetches resource metadata and returns `202 Accepted` with the existing interaction requirement/pending flow when approval is needed; if metadata cannot be fetched, default to `400 invalid_request` with a detail rather than minting silently.
- A second person trying to claim the same `(agent iss, agent sub)` receives `403 denied` until the binding is revoked and re-established. After revocation, new issuance uses a fresh binding and cascaded old grants remain revoked through the existing inventory key.
- Auth-token consent paths reject if the asserted/resolved `PersonKey` conflicts with the agent binding or with the directed-subject record for the presented/upstream token.
- Governance endpoints return `403 invalid_request` when the agent token has no `ps` or a `ps` other than the mapped PS. Mission-bound requests whose mission belongs to another PS continue to look like `404 mission_not_found`.
- The sample no longer emits demo admin roles/groups for `aauth:demo@attacker.example`; only exact configured admin agents receive them.

## Implementation sketch

1. Add `AAuthPersonKey` and update `IdentityAssertion`, `IdentityAssertionRequest`, XML docs, and all asserter implementations/tests to use stable person keys. Keep directed `Subject` terminology for the wire value only.
2. Add `IAgentPersonBindingStore` and `InMemoryAgentPersonBindingStore` under `src/AAuth/Person` or `src/AAuth/Server`; include atomic bind-or-verify and revoke operations. Register keyed defaults in `AAuthPersonServerServiceCollectionExtensions` with unkeyed fallback, matching existing `IIdentityClaimsAsserter`/`IJtiStore` conventions (`AAuthPersonServerServiceCollectionExtensions.cs:176-180`).
3. Add `IPersonSubjectDeriver`, `HmacPersonSubjectDeriver`, `AAuthPersonServerOptions.PairwiseSubjectSecret`, and option validation/warnings. Derive a subject only after `PersonKey` is known and the resource identifier has already passed `IsResourceIdentifier`.
4. Add `IPersonResourceEnrollmentStore` and in-memory keyed default. It stores first-resource approval and directed-subject resolution; it is separate from `IAgentPersonBindingStore` so the binding never stores pairwise `sub`.
5. Update `/person` (`AAuthPersonServerEndpoints.cs:490-570`):
   - call the asserter to identify/consent the person;
   - for non-upstream requests, `BindOrVerifyAsync` using `issuance.AgentIssuer` and `issuance.AgentId`;
   - for upstream requests, resolve `PersonKey` from the upstream token's `(aud, sub)` and skip binding;
   - derive/validate the directed subject;
   - for first `(personKey, resource)`, fetch metadata and require/record approval before minting;
   - register the enrollment before `AuthTokenResponse.CreateTrackedAsync` returns the person token.
6. Update auth-token assertion paths (`AAuthPersonServerEndpoints.cs:961`, `:1100`, `:1147`, `:1310`):
   - resolve the person key from the presented/upstream token record;
   - pass it to the asserter;
   - reject a mismatched returned key;
   - enforce the agent binding for direct non-upstream requests before minting or pushing claims to an AS.
7. Update pending entries and `IPersonPendingStore` so the parked first-issuance decision carries resource metadata, `PersonKey`, directed subject (or enough data to derive it), and enrollment-required state. On approval, record enrollment and binding before allowing mint.
8. Update revocation: `AgentPersonBinding.RevokeAsync` and `AAuthRevocationService.RevokeAgentAsync` revoke the inventory key and the binding-store row; tests should prove a different person can bind only after this step.
9. Update verification/governance: parse agent-token `ps` into `AAuthVerificationResult.AgentPersonServer`; change `GovernanceEndpoints.Authorize(ctx, expectedPersonServer, missionS256, mission)`; pass `ResolvePersonServer(ctx, options)` from every governance handler and sample call.
10. Update `samples/MockPersonServer` to configure exact admin agents by issuer and id, use `request.AgentIssuer`, and remove `StartsWith("aauth:demo@")`.
11. Sweep docs/snippets/tests for changed factory signatures, pending store APIs, and `GovernanceEndpoints.Authorize`.

## Tests

- `tests/AAuth.Conformance/Person/PersonServerMapperTests`:
  - add `PersonTokenEndpoint_RejectsSecondPersonForSameAgent`: asserter returns `PersonKey("alice")` then `PersonKey("bob")` for the same agent token; second request is `403 denied`, proving SDK-07.
  - add `AgentBinding_RebindsOnlyAfterRevocation`: after `AgentPersonBinding.RevokeAsync`/revocation service, Bob can bind and old Alice grants remain revoked through inventory cascade.
  - add `DefaultPersonTokenSubjects_ArePairwisePerResource`: default asserter + default deriver issues different `sub` for resource A/B and the same `sub` for repeat A, proving A11-03.
  - add `FirstResourceIssuance_DefersAndFetchesMetadata`: fake metadata client records a fetch; first issuance returns `202`, approval records enrollment, repeat issuance mints without re-prompt. Negative control: metadata unavailable returns the chosen fail-closed error and no token, proving A11-04.
  - add `AuthTokenRequest_RejectsAsserterPersonKeyMismatch`: presented token resolves to Alice but asserter returns Bob; no auth token or AS claims push occurs.
  - add `CallChaining_UnknownDirectedSubjectRejectedAndDoesNotBindIntermediary`: upstream `(aud, sub)` absent from enrollment store returns an upstream/presented-token error; known record succeeds without calling `IAgentPersonBindingStore`.
- `tests/AAuth.Tests/Server/ServerRoleRegistrationTests`:
  - assert the new stores/deriver resolve keyed, fall back to unkeyed DI, and can be replaced with builder `Use*` methods for multiple named PS instances.
  - assert the default asserter returns a stable `PersonKey` and no fixed directed `Subject`.
- `tests/AAuth.Conformance/Missions/GovernanceEndpointMapperTests`:
  - add missionless permission/interaction cases where agent token `ps` is absent or `https://other-ps.example`; both return `403 invalid_request`.
  - add `ps == expectedPersonServer` positive control.
  - add mission-bound stored mission with right `s256`/agent but wrong `PersonServer`; return `404 mission_not_found`.
- `tests/AAuth.Conformance/Missions/MissionPersonTokenIssuanceTests`:
  - mission approval issuing person tokens records first-resource enrollment and uses pairwise HMAC subjects for each approved resource.
- `tests/AAuth.Tests/Integration/MockPersonServerDashboardTests` or a new focused sample test:
  - exact configured admin `(issuer, id)` receives demo roles;
  - `aauth:demo@attacker.example` from an otherwise trusted issuer does not, reproducing SMP-01's negative control.
- Update existing tests that construct `DefaultIdentityClaimsAsserter("user-42")`, `IdentityAssertion.Assert(...)`, `IPersonPendingStore.MarkAllowed(...)`, or `GovernanceEndpoints.Authorize(...)`: `tests/AAuth.Conformance/AuthTokens/IssuanceBoundsTests.cs`, `tests/AAuth.Conformance/Agents/AgentFlowHost.cs`, `tests/AAuth.Conformance/CallChaining/ReusableChainingTests.cs`, `tests/AAuth.Conformance/Discovery/RevocationLifecycleTests.cs`, `tests/AAuth.Conformance/Person/DeferredFederationTests.cs`, `tests/AAuth.Tests/Api/DocumentationSnippetContext.cs`, and `tests/AAuth.Tests/Server/ServerRoleRegistrationTests.cs`.

## Samples and docs to update

The following files were found by grepping the changed APIs/patterns and must be updated:

- `samples/MockPersonServer/SampleIdentityClaimsAsserter.cs`
- `samples/MockPersonServer/ConsentBridgePersonPendingStore.cs`
- `samples/MockPersonServer/Program.cs`
- `samples/MockPersonServer/PersonConsentDecisions.cs`
- `samples/MockAccessServers/Federated/Program.cs`
- `docs/server/token-issuance.md`
- `docs/server/mission-governance.md`
- `docs/workflows/ps-asserted-access.md`
- `docs/workflows/call-chaining.md`
- `docs/reference/dependency-injection.md`
- `docs/reference/configuration.md`

Docs must explain that `PersonKey` is an internal stable key never emitted on the wire; directed `sub` is per resource; default in-memory binding/enrollment stores are not production persistence; production PS deployments must configure a persistent pairwise subject secret and persistent stores; and governance requires `ps` to match the mapped PS.

## Dependencies and conflicts with other Rnn

- R05 (upstream provenance and call chaining): the enrollment store's `(resource, directedSubject) -> PersonKey` resolution overlaps with upstream-token person resolution. Coordinate error names and avoid duplicate stores.
- R06 (revocation): `AgentPersonBinding.RevokeAsync` and `IAAuthRevocationService.RevokeAgentAsync` must update both the existing inventory key and the new binding store. R06's source-guard changes should keep using the inventory key for cascade; this design only adds the identity-binding row.
- R09/R12 (missions/governance): `GovernanceEndpoints.Authorize` signature and PS check touch governance code also covered by governance endpoint remediations. Apply this PS-binding check before or together with R12 parser/audit fixes to avoid repeated call-site churn.
- R18 (sample-only fixes): SMP-01 is fixed here because it needs `AgentIssuer` from the SDK request context. R18 should not reintroduce prefix-based demo admin checks.
- API-surface initiative: this is a deliberate C1 breaking cutover and must update ApiSurface baselines after implementation.

## Open questions (with proposed default)

1. **Exact name/type for the opaque person key.** Proposed default: `readonly record struct AAuthPersonKey(string Value)` with non-empty validation and no JSON converter in protocol models, to discourage accidental emission.
2. **Metadata-fetch failure on first issuance.** Proposed default: `400 invalid_request` with detail and no token. The spec says first-resource metadata fetch is SHOULD, but fail-closed avoids minting for an unpresentable resource and stays within the token endpoint error set.
3. **Default pairwise secret when unset.** Proposed default: generate an ephemeral per-process secret only in Development/test and log a warning elsewhere; production docs and option validation warn that persistent identifiers require a configured secret or custom deriver.
4. **Can `NeedsConsent` omit `PersonKey`?** Proposed default: yes, but only pending approval may complete it; no token can mint until `PersonKey` is supplied and binding/enrollment checks pass.
