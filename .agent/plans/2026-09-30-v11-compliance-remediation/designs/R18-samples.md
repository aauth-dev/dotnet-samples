# R18 — Samples-only fixes

Findings: SMP-01, S07-01, S08-01, S03-02, S03-03, S04-01, S05-002, S01-02, S01-03, S01-04, S03-04, S03-05, S04-03, S05-003, S05-004, S05-005, S06-02, S06-03, S07-02, S10-001. Spec: #resource-access-modes L230-L238; #agent-token-usage L530-L534; #resource-challenge-verification L770-L781; #ps-token-endpoint L936-L942; #interaction-endpoint L1129-L1135; #mission-approval L1412-L1414; #requirement-claims L1680; #call-chaining L1859; #keying-material L2177-L2197; #verification L2247-L2263; #deferred-responses L2516-L2531; #polling-error-codes L2623-L2626; #token-revocation L2668-L2698; #revocation-response L2703-L2726; #aauth-access L2796; #untrusted-input L2844; #agent-person-binding L2914-L2916; #directed-identifiers L2955-L2957; #ps-visibility L2965. Files read: `.agent/plans/2026-09-30-v11-compliance-remediation/research.md`; `.agent/plans/2026-09-30-v11-compliance-audit/research.md`; `.agent/plans/2026-09-30-v11-compliance-audit/findings/samples/S01-mock-person-server.md`; `S02-mock-ps-support.md`; `S03-mock-resource-servers.md`; `S04-mock-as-ap.md`; `S05-agent-samples.md`; `S06-sample-support.md`; `S07-guided-tour-1.md`; `S08-guided-tour-2.md`; `S09-guided-tour-3.md`; `S10-guided-tour-misc.md`; `.agent/plans/2026-09-29-sdk-api-surface-consistency/research.md`; `.agent/plans/2026-09-29-sdk-api-surface-consistency/implementation-log.md`; `aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md`; `src/AAuth/AAuthConstants.cs`; `src/AAuth/Person/IIdentityClaimsAsserter.cs`; `src/AAuth/Person/IPersonPendingStore.cs`; `src/AAuth/Discovery/AAuthEgressPolicy.cs`; `src/AAuth/Server/RevocationEndpoint.cs`; `samples/MockPersonServer/Program.cs`; `samples/MockPersonServer/SampleIdentityClaimsAsserter.cs`; `samples/MockPersonServer/ConsentBridgePersonPendingStore.cs`; `samples/MockPersonServer/README.md`; `samples/MockResourceServers/*/Program.cs`; `samples/MockResourceServers/README.md`; `samples/MockAccessServers/Federated/Program.cs`; `samples/MockAccessServers/Federated/Policy/KeycloakAccessPolicy.cs`; `samples/MockAccessServers/Federated/README.md`; `samples/Concierge/Program.cs`; `samples/Concierge/PendingStore.cs`; `samples/AgentConsole/Program.cs`; `samples/EventAgent/Program.cs`; `samples/MissionAgent/Program.cs`; `samples/MissionAgent/README.md`; `samples/LiveWhoAmITest/Program.cs`; `samples/README.md`; `samples/GuidedTour/TourOptions.cs`; `samples/GuidedTour/TourSession.cs`; `samples/GuidedTour/Components/Pages/Tour.razor`; `samples/GuidedTour/Components/Pages/Home.razor`; `samples/GuidedTour/CapturingMessageHandler.cs`; `samples/GuidedTour/StepRecord.cs`; `samples/GuidedTour/CodeSnippets.cs`; `samples/GuidedTour/README.md`; `samples/GuidedTour/playwright-tests/identity.spec.ts`; `docs/signing-modes/overview.md`.

## Problem restated (verified)

The sample defects are verified in current code, with two partial fixes noted.

- **SMP-01 / S02-01 remains.** `SampleIdentityClaimsAsserter.IsAdminAgent` grants `roles` and `groups` to any `AgentId` beginning `aauth:demo@` (`samples/MockPersonServer/SampleIdentityClaimsAsserter.cs:45-54`, `:73-88`). `ConsentBridgePersonPendingStore` repeats the same prefix decision when an admin consent flips a parked entry to allowed (`samples/MockPersonServer/ConsentBridgePersonPendingStore.cs:56-60`). The current `IdentityAssertionRequest` carries `AgentId` and `AgentKeyThumbprint`, but not the token issuer (`src/AAuth/Person/IIdentityClaimsAsserter.cs:39-65`), while `PersonPendingEntry` does carry owner issuer/subject/key information for parked requests (`src/AAuth/Person/IPersonPendingStore.cs:118-141`). Prefix-only privilege therefore still treats untrusted token claims as authorization policy, contrary to #untrusted-input L2844 and #agent-person-binding L2914-L2916.
- **S07-01 is partially fixed in prose/UI but not in behavior.** `TourOptions` and `Tour.razor` now label non-`jwt` choices as generic Signature Keys, not AAuth access modes (`samples/GuidedTour/TourOptions.cs:39-70`; `samples/GuidedTour/Components/Pages/Tour.razor:165-176`), and `docs/signing-modes/overview.md:1-5`, `:125-132` says AAuth agents use `jwt`. However the identity picker still offers only `hwk`, `jwks`, and `jkt-jwt` (`Tour.razor:53-56`), the tour still defaults to `SigningMode.Hwk` (`TourSession.cs:151`), the identity URL switch sends those modes to Profile (`TourSession.cs:200-204`), and `BuildSigningHandler` still calls `UseHwk`, `UseJwks`, and `UseJktJwt` for resource requests (`TourSession.cs:833-855`). This still demonstrates prohibited AAuth agent schemes unless the page is made an explicit generic-signature lesson; #keying-material L2177-L2197 requires agents to present `jwt` for AAuth resource/PS/AS requests and reserves `jkt-jwt` for AP key refresh.
- **S08-01 remains.** The tour resolves pending `Location` headers by accepting any absolute string starting with `http` for PS token exchange, Inbox resource-managed access, PS call-chain exchange, and Concierge call-chain pending (`TourSession.cs:2312`, `:2493`, `:3093`, `:3203`), then sends signed polls to `_pendingUrl` (`TourSession.cs:2399`, `:2548`, `:3275`). The SDK already exposes `AAuthEgressPolicy.ValidatePendingLocation`, which enforces same-origin (`src/AAuth/Discovery/AAuthEgressPolicy.cs:124-131`), but these sample paths bypass it. #deferred-responses L2516 requires pending URLs to be on the same origin as the responding server.
- **S03-02 remains.** Catalog accepts person tokens and AS auth tokens in its `/catalog` verification branch (`samples/MockResourceServers/Catalog/Program.cs:56-63`) but does not configure `RevocationEndpoint` or map a revocation endpoint (`Catalog/Program.cs:35-44`, `:56-63`). Documents accepts person-token-driven grants (`samples/MockResourceServers/Documents/Program.cs:32-39`, `:55-68`) with no revocation metadata or endpoint (`Documents/Program.cs:18-27`, `:32-39`). #token-revocation L2668 says a resource accepting person tokens SHOULD provide and advertise revocation.
- **S03-03 remains.** Bookings advertises and maps resource revocation, but accepts revocations only from the configured PS or AS (`samples/MockResourceServers/Bookings/Program.cs:71-72`, `:106`). Its manual `/authorize` helper verifies person tokens by JWKS with no sample issuer allow-list (`Bookings/Program.cs:448-456`), so the resource can accept a person token from a PS whose later revocation would be rejected. #token-revocation L2690-L2698 keys revocation by the verified issuer and expects the issuer that minted the accepted token to revoke it.
- **S03-04 remains.** Profile and Inbox advertise and map revocation endpoints (`samples/MockResourceServers/Profile/Program.cs:40-57`; `samples/MockResourceServers/Inbox/Program.cs:46-76`) even though Profile is a generic-signature/agent-token lesson and Inbox is resource-managed opaque access; neither consumes revocable person/auth-token issuers in its protected path. That is misleading relative to #token-revocation L2668-L2672.
- **S04-01 remains in the Keycloak callback path.** `KeycloakAccessPolicy.TryParseNeedInfo` copies every Keycloak `required_claims[].name` into `RequiredClaims` (`samples/MockAccessServers/Federated/Policy/KeycloakAccessPolicy.cs:226-255`), and the browser callback parks those names as `entry.RequiredClaims` (`samples/MockAccessServers/Federated/Program.cs:311-317`). A Keycloak policy can therefore make the AS ask the PS for `sub`, which #requirement-claims L1680 forbids.
- **S05-002 remains.** Concierge re-emits pending interaction with body `{ "status": "interaction_required" }` (`samples/Concierge/Program.cs:210-225`) and answers an unknown or mismatched pending URL with `404 unknown_pending` (`samples/Concierge/Program.cs:289-317`). #deferred-responses L2523 defines waiting bodies as `"pending"` and #polling-error-codes L2623-L2626 defines unrecognized or already consumed interaction codes as `410 invalid_code`.
- **LOW prose and hygiene items remain.** Current files still contain stale or over-broad teaching text: Mock PS README says `/token` derives only from `resource_token` (`samples/MockPersonServer/README.md:27-48`) and `/mission-interaction` handles completion proposals (`MockPersonServer/README.md:122-136`); its wallet revocation demo answers `502` and `revocations` instead of `200`/`downstream` (`samples/MockPersonServer/Program.cs:195-201`); MockResourceServers README says “four AAuth access modes” and lists Profile's generic schemes as access-mode rows (`samples/MockResourceServers/README.md:1-24`, `:44-50`); Federated AS comments imply empty trusted-PS sets mean open trust (`samples/MockAccessServers/Federated/Program.cs:44-50`) while current SDK semantics treat empty `Allowed` as deny-all; sample index says Concierge uses nested `act` delegation (`samples/README.md:18`); sample index and LiveWhoAmITest still use `Accept-Signature` instead of `Accept-Signature-Scheme` (`samples/README.md:374`; `samples/LiveWhoAmITest/Program.cs:9`, `:143-165`); MissionAgent calls the mission blob “signed approval blob” (`samples/MissionAgent/Program.cs:195-199`; `samples/MissionAgent/README.md:48-50`, `:95`); LiveWhoAmITest calls a draft-11 challenge “Draft-10” (`samples/LiveWhoAmITest/Program.cs:249-252`); GuidedTour stores and renders full credential headers/JWTs (`samples/GuidedTour/CapturingMessageHandler.cs:25-48`; `samples/GuidedTour/StepRecord.cs:48-54`); and one GuidedTour snippet says Signature Keys draft-08 (`samples/GuidedTour/CodeSnippets.cs:97`).

## Candidate fixes

| # | Approach | Pros | Cons | Spec fit | API-surface fit (C1–C13) |
|---|---|---|---|---|---|
| 1 | Documentation-only rewording for the samples, leaving current runnable behavior intact. | Fast; no sample compile/e2e churn. | Leaves admin-prefix grants, cross-origin signed polling, missing revocation endpoints, Keycloak `sub` claims, and Concierge polling wires exploitable or non-compliant. | Poor: confirms known spec violations. | Poor: violates C6 by keeping sample policy unsafe and C15 by teaching wrong primitives. |
| 2 | Surgical sample remediation: remove prefix grants, fix pending URL resolution and Concierge polling wires, align revocation surfaces with accepted token issuers, filter `sub`, re-label/adjust signing lessons, and update stale prose/logging. No SDK surface changes. | Fixes every R18-owned defect where it lives; keeps samples as teaching artifacts; avoids stepping on SDK designs. | Requires coordinated sample/e2e updates and careful wording so generic Signature Keys are not confused with AAuth access modes. | Strong: each sample wire now matches the cited draft-11 sections. | Strong: C1 no compat; C2/C8 use high-level SDK paths except primitive teaching panes; C15 explicitly preserved. |
| 3 | Drop all generic signing samples and all hand-stepped tour logic, replacing them with only high-level DI agents and SDK pollers. | Eliminates confusion and most manual code. | Over-corrects: removes useful primitive lessons allowed by Q15, hides `RequireGenericSignature`, and would not exercise Profile/docs signing-mode samples. | Correct but incomplete educational coverage. | Mixed: C8 strong, but C15 weaker because legitimate primitive teaching panes disappear. |

## Recommendation

Implement candidate 2.

For S07-01, keep a clearly labelled **“Generic Signature-Key primitives (non-AAuth)”** subsection/page against the existing Profile `RequireGenericSignature` endpoints, but move it out of the AAuth access-mode path. The identity flow should default to and visibly offer **JWT agent-token identity** as the AAuth identity-based mode. `hwk`, `jwks`/`jwks_uri`, and `jkt-jwt` remain only in the generic lesson, with warnings that agents MUST NOT use them for AAuth resource, PS, or AS requests and that `jkt-jwt` is AP key-refresh material. This preserves Q15’s “teaching panes keep the builder where the lesson is the primitive” ruling while making the spec boundary explicit.

The adversarial closure is: a malicious PS/resource can no longer redirect signed polls cross-origin because the tour resolves pending URLs through the SDK egress policy; an attacker-controlled `aauth:demo@evil` no longer obtains roles without an exact demo binding; a Keycloak policy cannot ask for `sub`; and resource revocation endpoints accept exactly the issuers whose person/auth tokens the samples accept.

## Public API delta

No SDK public API delta for R18.

If R07 adds a claim-name constant such as `AAuthConstants.Claims.Subject`, the Federated sample should use it instead of a local `"sub"` literal. If R10 adds agent binding issuer data to `IdentityAssertionRequest`, the Mock PS sample should consume that field; until then it should use exact demo agent subject plus key thumbprint, and `PersonPendingEntry.OwnerIssuer/OwnerSubject/OwnerKeyThumbprint` where available, rather than prefix matching. No `ApiSurface` change is owned by this design.

## Wire effect

- Mock PS no longer emits demo `roles`/`groups` for arbitrary `aauth:demo@*` agents; only configured exact demo admin bindings receive them.
- GuidedTour rejects a cross-origin pending `Location` before polling; no signed GET is sent to the foreign origin.
- Catalog and Documents metadata gain `revocation_endpoint`; their resources record revocations from accepted person/auth-token issuers.
- Profile and Inbox metadata lose misleading `revocation_endpoint` values, unless a future flow actually accepts revocable person/auth tokens.
- Bookings stops accepting person tokens from PS issuers it will not accept revocations from, or equivalently widens revocation acceptance to the same issuer predicate; choose the bounded allow-list form.
- Federated AS never returns `requirement=claims` with `required_claims` containing `sub`.
- Concierge pending interaction responses change from body status `"interaction_required"` to `"pending"`; unknown or consumed/mismatched pending codes change from `404 unknown_pending` to `410 invalid_code`.
- Mock PS local wallet revocation demo changes terminal downstream-unavailable results from `502` to `200` with a JSON-object `downstream` member.
- Redaction changes CLI/UI output by replacing credential-bearing headers and compact tokens with labelled redacted/truncated values.

## Implementation sketch

1. **Mock PS admin binding (SMP-01 / S02-01).**
   - `samples/MockPersonServer/Program.cs:116-120`: read a new sample-only config section such as `MockPersonServer:DemoAdminAgents` containing exact demo admin records. Seed the existing demo subject/key used by local samples so the happy path still works.
   - `samples/MockPersonServer/SampleIdentityClaimsAsserter.cs:45-54`, `:73-88`: replace `IsAdminAgent(string agentId)` prefix matching with `IsAdminAgent(IdentityAssertionRequest request)` that requires exact agent subject and non-null key thumbprint; when R10 exposes issuer in the request, include exact issuer as well.
   - `samples/MockPersonServer/ConsentBridgePersonPendingStore.cs:56-60`: use the same binding predicate over `PersonPendingEntry.OwnerIssuer`, `ConsentAgentId`, and `OwnerKeyThumbprint`/`ResourceKeyThumbprint`, not a prefix.
   - `samples/MockPersonServer/README.md`: document that demo roles are sample configuration, not inferred from an agent-id prefix.
2. **GuidedTour signing-mode boundary (S07-01, S07-02).**
   - `samples/GuidedTour/TourSession.cs:136-159`: default `_signingMode` to `SigningMode.Jwt`; update comments to say the Identity flow's AAuth mode is JWT agent-token identity and generic modes are separate lessons.
   - `samples/GuidedTour/TourSession.cs:166-204`: fix access-mode prose to list draft-11’s five modes; route `SigningMode.Jwt` in identity mode to Profile `/identified` rather than Calendar `/events`, and keep Calendar for PS-asserted flows.
   - `samples/GuidedTour/TourSession.cs:833-855`: leave `UseHwk`, `UseJwks`, and `UseJktJwt` only when the selected page/step is the generic Signature-Key lesson; otherwise use `UseJwt(tokenFactory)` for AAuth resource requests.
   - `samples/GuidedTour/Components/Pages/Tour.razor:53-56`, `:165-176`; `samples/GuidedTour/Components/Pages/Home.razor:79`; `samples/GuidedTour/TourOptions.cs:39-70`; `samples/GuidedTour/playwright-tests/identity.spec.ts:21-41`: add a JWT agent-token option/default and re-scope the existing non-JWT cases under “Generic Signature-Key primitives (non-AAuth)”.
   - `samples/MockResourceServers/Profile/Program.cs:63-138`; `samples/MockResourceServers/README.md:1-24`, `:44-50`; `docs/signing-modes/overview.md:1-5`, `:125-132`: keep Profile as the `RequireGenericSignature` demo, but remove “AAuth identity access mode” wording from the generic rows and add a JWT agent-token Profile row.
3. **GuidedTour same-origin pending URLs (S08-01).**
   - Add a small helper in `samples/GuidedTour/TourSession.cs` near the pending helpers, for example `ResolvePendingLocation(HttpResponseMessage response, string issuingEndpoint)`, that calls `SampleEgress.Policy.ValidatePendingLocation(new Uri(issuingEndpoint), response.Headers.Location!)` and returns the absolute URI string. The endpoint argument is the exact URL that produced the `202`, not a UI-configured unrelated base.
   - Replace the four `StartsWith("http")` branches at `TourSession.cs:2312`, `:2493`, `:3093`, and `:3203`. Use the PS `/token` endpoint for PS token exchanges, the Inbox request URL for resource-managed pending, and the Concierge/chain request URL for intermediary pending.
   - On validation failure, add a StepRecord explaining that the sample stopped because the server violated same-origin pending requirements; do not poll.
4. **Resource revocation surfaces (S03-02, S03-03, S03-04).**
   - `samples/MockResourceServers/Catalog/Program.cs:35-63`: set `options.RevocationEndpoint = $"{issuer}/revoke"` and `ConfigureRevocation` to accept exactly the Catalog AS and configured PS; call `app.MapAAuthResourceRevocation()` after `MapAAuthWellKnown()`.
   - `samples/MockResourceServers/Documents/Program.cs:18-39`: set `RevocationEndpoint`, configure revocation acceptance for the same PS issuer allowed by `Trust.AuthTokenIssuers.Allowed`, and map `MapAAuthResourceRevocation()`.
   - `samples/MockResourceServers/Bookings/Program.cs:71-72`, `:448-456`: introduce one trusted-PS predicate/list and use it in both manual person-token acceptance and `ConfigureRevocation`. Prefer rejecting untrusted PS person tokens over widening revocation to all verifiable issuers.
   - `samples/MockResourceServers/Profile/Program.cs:40-57` and `samples/MockResourceServers/Inbox/Program.cs:46-76`: remove `RevocationEndpoint` and `MapAAuthRevocationEndpoint` unless a protected path starts accepting person/auth tokens.
   - `samples/MockResourceServers/README.md`: update the table to the five draft-11 modes and identify Profile as generic Signature-Key support, not a resource access mode.
5. **Federated AS claims filtering (S04-01, S04-03).**
   - `samples/MockAccessServers/Federated/Policy/KeycloakAccessPolicy.cs:226-255`: filter out `sub` before returning `requiredClaims`; if no claims remain, treat the Keycloak `need_info` response as a denied/policy-error path rather than a `requirement=claims` round trip.
   - `samples/MockAccessServers/Federated/Program.cs:311-317`: defensively filter again before assigning `entry.RequiredClaims`, so future policies cannot bypass the helper.
   - `samples/MockAccessServers/Federated/Program.cs:44-50` and `samples/MockAccessServers/Federated/README.md:69`: change “empty set trusts any signed caller” to “empty set denies all; omit/null is open only if explicitly configured by the SDK trust option”.
6. **Concierge polling shape (S05-002).**
   - `samples/Concierge/Program.cs:210-225`: return `Results.Json(new { status = "pending" }, statusCode: 202)` while preserving `Location`, `Retry-After`, `Cache-Control`, and `AAuth-Requirement`.
   - `samples/Concierge/Program.cs:289-317`: update comments and change unknown/mismatched/consumed pending responses to `AAuthProblemDetails.Create("invalid_code", statusCode: 410)`. If the pending entry is expired, return `408 expired`.
   - `samples/Concierge/PendingStore.cs:13-19`: update prose so it does not normalize pass-through interaction ownership beyond what R05/R11 will fix.
7. **LOW sample prose and logging hygiene.**
   - `samples/MockPersonServer/README.md:27-48`: include both `resource_token` and `presented_token`; `samples/MockPersonServer/README.md:122-136`: remove completion proposals from `/mission-interaction`.
   - `samples/MockPersonServer/Program.cs:195-201`: for `/local/wallet/revoke`, always return `200` once local/downstream outcomes are terminal; use `downstream` instead of `revocations`.
   - `samples/README.md:18`: replace nested `act` language with `upstream_token`; `samples/README.md:374` and `samples/LiveWhoAmITest/Program.cs:9`, `:143-165`: replace `Accept-Signature` with `Accept-Signature-Scheme`/`Accept-Signature-Alg` as applicable.
   - `samples/MissionAgent/Program.cs:195-199` and `samples/MissionAgent/README.md:48-50`, `:95`: replace “signed approval blob” with “mission blob plus `s256` digest”.
   - `samples/LiveWhoAmITest/Program.cs:249-252`: replace “Draft-10 scoped challenge” with “draft-11 auth-token challenge”.
   - `samples/AgentConsole/Program.cs:323-335`, `samples/EventAgent/Program.cs:24-25`, `samples/GuidedTour/CapturingMessageHandler.cs:25-48`, `samples/GuidedTour/StepRecord.cs:48-54`: redact `Signature-Key`, `Authorization`, `AAuth-Requirement` embedded resource tokens, `AAuth-Access`, compact JWTs, and decoded person/auth claim payloads by default; keep an explicit local-only debug switch if the lesson needs to show decoded structure.
   - `samples/GuidedTour/CodeSnippets.cs:97`: update Signature Keys draft reference to draft-09; `samples/GuidedTour/README.md:108-116`: add one local-only redaction/disclosure warning for the tour inspector.

## Tests

- `tests/AAuth.Tests/Samples/MockPersonServerAdminClaimsTests` (new): construct `SampleIdentityClaimsAsserter` and `ConsentBridgePersonPendingStore` with seeded demo admin bindings. Positive control: exact `(agent subject, key thumbprint)` receives demo roles. Negative control: `aauth:demo@attacker.example` with a different key receives no roles/groups and pending bridge does not promote it.
- `tests/e2e` GuidedTour identity suite (`samples/GuidedTour/playwright-tests/identity.spec.ts`): add a JWT agent-token identity case as the default AAuth identity flow; keep `hwk`/`jwks`/`jkt-jwt` tests only under the generic Signature-Key section and assert the page visibly says “non-AAuth”. Negative control: no AAuth flow sends `sig=hwk`, `sig=jwks_uri`/`jwks`, or `sig=jkt-jwt` to a PS/AS/resource request.
- `tests/AAuth.Tests/Samples/GuidedTourPendingLocationTests` (new): unit-test the TourSession helper with a `202 Location: https://evil.example/pending`; assert no poll request is sent and a violation step is recorded. Positive control: relative `/pending/id` and same-origin absolute URLs resolve.
- `tests/AAuth.Conformance/Discovery/JtiStoreAndRevocationTests` or a new `Samples/MockResourceRevocationTests`: host Catalog/Documents/Bookings minimal pipelines. Positive controls: accepted PS/AS revocations return 200 and later matching tokens are rejected. Negative control: Bookings rejects a person token from a PS outside the trusted list, or if accepted, its revocation is accepted by the same predicate.
- `tests/AAuth.Conformance/AuthTokens/IssuanceBoundsTests` or new `Samples/FederatedClaimsRequirementTests`: feed Keycloak `need_info` JSON containing only `sub`, and `sub` plus `tenant`. Negative control: `sub` never appears in the pending `required_claims`; mixed response keeps only `tenant`.
- `tests/AAuth.Conformance/Errors/PollingErrorTests` or new `Samples/ConciergePendingTests`: unknown Concierge pending id returns `410` with `error=invalid_code`; waiting pending returns `202` with body `status=pending`.
- Documentation/snippet gates: `tests/AAuth.Tests/Api/DocumentationInventory`, `DocumentationLinkTests`, and `SnippetCompilationTests` must pass after README/snippet edits.
- Existing Playwright `sample-app` and GuidedTour suites should cover the updated sample prose and UI flows; add a targeted assertion that credential headers are redacted in visible GuidedTour exchanges unless an explicit local debug setting is on.

## Samples and docs to update

- `samples/MockPersonServer/Program.cs:116-120`
- `samples/MockPersonServer/SampleIdentityClaimsAsserter.cs:45-54`, `:73-88`
- `samples/MockPersonServer/ConsentBridgePersonPendingStore.cs:56-60`
- `samples/MockPersonServer/README.md:27-48`, `:122-136`
- `samples/MockPersonServer/Program.cs:195-201`
- `samples/MockResourceServers/Catalog/Program.cs:35-63`
- `samples/MockResourceServers/Documents/Program.cs:18-39`, `:55-68`
- `samples/MockResourceServers/Bookings/Program.cs:71-72`, `:106`, `:448-456`
- `samples/MockResourceServers/Profile/Program.cs:40-57`, `:63-138`
- `samples/MockResourceServers/Inbox/Program.cs:46-76`
- `samples/MockResourceServers/README.md:1-24`, `:44-50`
- `samples/MockAccessServers/Federated/Program.cs:44-50`, `:311-317`
- `samples/MockAccessServers/Federated/Policy/KeycloakAccessPolicy.cs:226-255`
- `samples/MockAccessServers/Federated/README.md:35-75`
- `samples/Concierge/Program.cs:210-225`, `:289-317`
- `samples/Concierge/PendingStore.cs:13-19`
- `samples/AgentConsole/Program.cs:323-335`
- `samples/EventAgent/Program.cs:24-25`
- `samples/MissionAgent/Program.cs:195-199`
- `samples/MissionAgent/README.md:48-50`, `:92-98`
- `samples/LiveWhoAmITest/Program.cs:9`, `:143-165`, `:249-252`
- `samples/README.md:18`, `:374`
- `samples/GuidedTour/TourOptions.cs:39-70`
- `samples/GuidedTour/TourSession.cs:136-159`, `:166-204`, `:833-855`, `:1968-2035`, `:2300-2320`, `:2488-2502`, `:3088-3102`, `:3198-3212`
- `samples/GuidedTour/Components/Pages/Tour.razor:53-56`, `:165-176`
- `samples/GuidedTour/Components/Pages/Home.razor:79`
- `samples/GuidedTour/CapturingMessageHandler.cs:25-48`
- `samples/GuidedTour/StepRecord.cs:48-54`
- `samples/GuidedTour/CodeSnippets.cs:93-100`
- `samples/GuidedTour/README.md:108-116`
- `samples/GuidedTour/playwright-tests/identity.spec.ts:21-41`
- `docs/signing-modes/overview.md:1-5`, `:125-132`

## Dependencies and conflicts with other Rnn

- **R10 owns SDK agent-person binding design for SMP-01.** R18 must not invent SDK issuer plumbing. The sample should remove prefix privilege now using exact subject/key and should consume R10’s eventual `(agent issuer, sub, key)` binding seam when it lands.
- **R07 owns federation SDK behavior for S04-01.** R18 only filters the sample Keycloak policy/callback. If R07 adds constants or SDK-owned claim filtering, the sample should call that helper rather than duplicate claim-name policy.
- **R11 owns SDK deferred polling and S05-002 in shared SDK paths.** R18 changes only Concierge’s sample-owned pending body/error shape and GuidedTour’s sample-owned `Location` handling. Excluded S08-02/S08-03/S09-01 remain R11.
- **R17 owns S06-01.** R18 changes only S06-02/S06-03 prose in the samples index.
- **R12/R05/R03 own SMP-02/SMP-03/SMP-04.** Do not fold their governance, upstream provenance, or authorization endpoint redesigns into this sample-only pass.
- **C8/C15 boundary.** Host apps and mock servers should use DI/high-level SDK registration; GuidedTour and docs may keep `AAuthClientBuilder` only in explicitly labelled primitive signing-mode lessons.

## Open questions (with proposed default)

1. **Should the generic Signature-Key lesson stay in GuidedTour?** Proposed default: yes, but only as a clearly separated “non-AAuth generic Signature-Key primitives” section backed by Profile `RequireGenericSignature`; AAuth access-mode flows default to `jwt`.
2. **What exact demo admin binding seed should the Mock PS ship?** Proposed default: seed the current local demo agent subject plus generated/local key thumbprint at startup for the demo scripts, and document configuration for additional bindings. When R10 exposes issuer in `IdentityAssertionRequest`, require issuer too.
3. **Should redaction be bypassable?** Proposed default: redacted by default everywhere; allow an explicit local-only `ShowSensitiveProtocolArtifacts` development setting in GuidedTour because the tour is educational, but never in CLI output unless a similarly explicit flag is passed.
