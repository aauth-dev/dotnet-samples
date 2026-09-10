# Implementation Plan - AAuth SDK migration to protocol draft-09

Companion to [`research.md`](research.md). All Phase 0 scope rulings are recorded
in [`implementation-log.md`](implementation-log.md); this completed plan is
awaiting explicit owner approval.

> Status: **Plan approval gate.** The immutable draft-09 snapshot and evidence
> map are approved, and Q1-Q7 are resolved. No SDK code changes are permitted
> until this complete plan is explicitly approved.

## Guiding principles

- **Spec accuracy over compatibility.** This is an alpha SDK. Wire and public API
  changes use one coordinated draft-09 shape; no dual-format shims or stale
  aliases unless the owner explicitly approves an exception.
- **Construction and verification move together.** Error producers/consumers and
  clarification producers/consumers cut over atomically.
- **Do not imply unsupported companion support.** Events, R3 AsyncAPI,
  `self-jwt`, Bootstrap error normalization, and the missing AS clarification
  flow are research-and-plan spin-offs; this migration adds no partial runtime
  API for them.
- **Keep compiled consumers green in-phase.** Non-compiled prose and illustrative
  snippets wait for the post-code sweep; executable samples and e2e assertions
  move with the behavior they exercise.
- **Re-check target citations before edits.** Every phase begins by verifying its
  cited target lines against `aauth-spec/v09/`.
- **Validate every phase boundary.** Run `make build`, `make test-unit`,
  `make test-conformance`, and `make e2e`. An unavailable e2e environment is a
  blocker requiring an owner ruling.

## Phase 0 - owner decision gate

Resolve every open question from `research.md`, one at a time, and append each
ruling with rationale to `implementation-log.md`.

### Implementation decisions

- [x] **Q1:** Rename public `ErrorDescription` APIs to `Detail`; use only the
      draft-09 `detail` wire member, with no alias or compatibility fallback.
- [x] **Q2:** Include R3 token, document, challenge, and enforcement error
      bodies in the common RFC 9457 cutover.
- [x] **Q3:** Leave MockAgentProvider/Bootstrap errors unchanged and create a
      focused research-and-plan spin-off.
- [x] **Q4:** Migrate the implemented PS clarification flow and create a
      separate initiative for the pre-existing missing AS receiver.
- [x] **Q5:** Spin off the complete Events protocol and all optional
      metadata/registry source seams.
- [x] **Q6:** Spin off the revised R3 AsyncAPI model and subscription handoff
      with Events; retain Q2's RFC 9457 update for existing R3 endpoints.
- [x] **Q7:** Spin off Signature Keys `self-jwt` as a coordinated
      dependency/use-case initiative.
- [ ] The completed dependency-ordered plan is explicitly approved.

### Definition of Done

- [x] Every open question has a `RESOLVED` ruling in
      `implementation-log.md`.
- [x] The plan's phases and spin-off boundaries match those rulings.
- [ ] The owner has approved the final plan before SDK code changes.

## Phase 1 - coordinated RFC 9457 error cutover

Target: protocol `#error-responses` and `#error-response-format`, L2230-L2243,
plus the token/polling examples at L2259-L2292. This phase has no dependency on
Phase 2.

### Scope

- Add `src/AAuth/Server/AAuthProblemDetails.cs` as the shared result seam for a
  required AAuth `error`, optional `detail`, and endpoint-specific extension
  members, always serialized as `application/problem+json`.
- Move all approved AAuth error producers to
  `application/problem+json`, `error`, and optional `detail`, without touching
  success responses.
- Preserve endpoint status codes, `Signature-Error`, `AAuth-Requirement`, and
  endpoint-specific extension members; clients branch only on `error`.
- Move `TokenExchangeClient` and `AccessServerClient` to `detail` only. Do not
  retain an `error_description` fallback.
- Rename public `AAuthTokenExchangeException.ErrorDescription` and
  `TokenErrorResponse.ErrorDescription` to `Detail`, including compiled
  consumers.
- Include R3 token, document, challenge, and enforcement error bodies under Q2.
- Exclude MockAgentProvider enrollment/refresh errors under Q3.

### Primary files

- `src/AAuth/Server/AAuthProblemDetails.cs` (new)
- `src/AAuth/Agent/TokenExchangeClient.cs`
- `src/AAuth/Access/AccessServerClient.cs`
- `src/AAuth/Errors/AAuthTokenExchangeException.cs`
- `src/AAuth/Errors/TokenError.cs`
- `src/AAuth/Person/AAuthPersonServerEndpoints.cs`
- `src/AAuth/Access/AAuthAccessServerEndpoints.cs`
- `src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs`
- `src/AAuth/DependencyInjection/AAuthGovernanceApplicationBuilderExtensions.cs`
- `src/AAuth/Server/RevocationEndpoint.cs`
- `src/AAuth/Server/Governance/GovernanceEndpoints.cs`
- `src/AAuth/Server/ResourceManaged/AAuthInteractionEndpointExtensions.cs`
- `src/AAuth/Server/Verification/AAuthHttpContextExtensions.cs`
- `src/AAuth.R3/R3AccessTokenEndpoint.cs`
- `src/AAuth.R3/R3DocumentEndpoint.cs`
- `src/AAuth.R3/R3Challenge.cs`
- `src/AAuth.R3/R3Enforcement.cs`
- `samples/LiveWhoAmITest/Program.cs`
- `tests/AAuth.Tests/Agent/ChallengeHandlerTests.cs`
- `tests/AAuth.Tests/AccessServerClientTests.cs`
- `tests/AAuth.Conformance/Errors/ProblemDetailsTests.cs` (new)
- `tests/AAuth.Conformance/Errors/TokenErrorTests.cs`
- `tests/AAuth.Conformance/Errors/PollingErrorTests.cs`
- `tests/AAuth.Conformance/Person/PersonServerMapperTests.cs`
- `tests/AAuth.Conformance/Discovery/JtiStoreAndRevocationTests.cs`
- `tests/AAuth.Conformance/Missions/GovernanceServerTests.cs`
- `tests/AAuth.R3.Tests/AccessEndpointR3Tests.cs`
- `tests/AAuth.R3.Tests/ResourceR3Tests.cs`

### Definition of Done

- [ ] Every approved error body uses `application/problem+json`; success
      response media types are unchanged.
- [ ] `error` remains the only AAuth behavior discriminator.
- [ ] Human-readable text uses `detail` end to end, including public .NET API
      names and compiled consumers.
- [ ] No consumer branches on RFC 9457 `type`.
- [ ] No `error_description` remains in migrated `src/`, fixtures, or compiled
      consumers; Q3's MockAgentProvider residue is explicitly excluded.
- [ ] Representative PS, AS, authorization, interaction, governance, challenge,
      revocation, and R3 tests assert status, media type, `error`, and `detail`.
- [ ] Optional RFC 9457 members do not affect client error classification.
- [ ] Targeted unit, conformance, and R3 tests pass.
- [ ] `make build`, `make test-unit`, `make test-conformance`, and `make e2e`
      pass.

## Phase 2 - coordinated clarification `action` cutover

Target: protocol `#agent-response-to-clarification`, L1012-L1080. Depends on
Phase 1 so invalid action responses use the approved problem-details seam.

### Scope

- Define the two exact action strings once and use them in agent construction
  and PS validation.
- Emit `action=clarification_response` and `action=updated_request` from
  `ClarificationExchange`.
- At the PS, reject missing or unknown actions with `400`; apply defensive
  `invalid_request` validation when a recognized action lacks its matching
  `clarification_response` or `resource_token`.
- Stop inferring the operation from payload-member presence.
- Update manual compiled producers and all directly coupled fixtures/mocks.
- Leave cancellation as `DELETE`.
- Do not add an AS clarification receiver under Q4.

### Primary files

- `src/AAuth/AAuthConstants.cs`
- `src/AAuth/Agent/ClarificationExchange.cs`
- `src/AAuth/Person/AAuthPersonServerEndpoints.cs`
- `samples/GuidedTour/TourSession.cs`
- `tests/AAuth.Conformance/Missions/ClarificationChatTests.cs`
- `tests/AAuth.Conformance/Missions/ChallengeClarificationSeamTests.cs`
- `tests/AAuth.Conformance/Missions/GovernanceClientTests.cs`
- `tests/AAuth.Conformance/Person/PersonServerMapperTests.cs`
- `tests/AAuth.Tests/Integration/MissionAgentFlowTests.cs`
- `samples/GuidedTour/playwright-tests/mission-call-chain.spec.ts`
- `samples/SampleApp/playwright-tests/mission-call-chain.spec.ts`

### Definition of Done

- [ ] Both POST actions use the exact draft-09 strings.
- [ ] Missing and unknown actions return `400` as draft-09 mandates.
- [ ] Recognized actions without their required payload fail as defensive
      `invalid_request` validation; this is not reported as a spec status-code
      requirement.
- [ ] Cancel remains a bodyless `DELETE`.
- [ ] SDK, PS, manual sample producers, and fixtures are symmetric.
- [ ] Captured-wire tests prove both emitted JSON shapes.
- [ ] The live clarification flow exposes and exercises
      `action=clarification_response`.
- [ ] No AS clarification receiver or partial AS state machine is introduced.
- [ ] `make build`, `make test-unit`, `make test-conformance`, and `make e2e`
      pass.

## Phase 3 - frozen-surface inventory and update

After all approved code phases are green, run the post-code checklist from
`REVIEW-CHECKLISTS.md` with independent read-only reviewers split by surface.
Present the resulting `surface | file | delta | required edit` table and wait
for approval before edits.

The approved sweep covers string-literal snippets, illustrative code, READMEs,
docs, e2e assertions, and version tracking. Tracking documents name draft-09 as
the SDK target only after the approved runtime work and explicitly list
unsupported/spun-off companion behavior.

Expected direct surfaces include:

- `samples/GuidedTour/CodeSnippets.cs`
- `docs/advanced/error-handling.md`
- `docs/advanced/clarification-chat.md`
- top-level and sample READMEs discovered by the approved inventory
- `aauth-spec/SPEC-VERSION.md` and `aauth-spec/CHANGELOG.md`

### Definition of Done

- [ ] The owner approved the complete surface inventory.
- [ ] Every approved non-compiled edit is present.
- [ ] Stale `error_description`, old clarification bodies, and outdated version
      claims are absent or explicitly justified; MockAgentProvider Bootstrap
      errors remain only under the Q3 disposition.
- [ ] Tracking names draft-09 as the SDK target and states that Events, R3
      AsyncAPI, `self-jwt`, and AS clarification remain unsupported/spun off.
- [ ] A fresh full-stack e2e boot exercises affected samples.
- [ ] All four validation targets pass.

## Phase 4 - research-and-plan-only spin-offs

Create these separate initiatives without implementing their source changes:

| Initiative | Required research boundary |
|---|---|
| Bootstrap problem-details format | Q3 MockAgentProvider enrollment/refresh errors and companion ownership |
| Access Server clarification | Q4 pending state, PS-to-AS signed response, polling/federation, and e2e |
| AAuth Events plus R3 AsyncAPI | Q5/Q6 complete Events feature groups, R3 multi-member operations, persistence, replay, routing, samples, and e2e |
| Signature Keys `self-jwt` | Q7 concrete use case, parser/provider APIs, admitted discovery, cache, `cnf` rejection, SSRF, and tests |

The Events and `self-jwt` initiatives cross-reference one shared admitted
`{iss}/.well-known/{dwk}` JWKS resolution/cache primitive while preserving
their distinct wire schemes and token-type checks.

### Definition of Done

- [ ] All four initiatives have research, a Phase 0 decision gate, a
      dependency-ordered implementation plan, and an implementation log.
- [ ] The Events initiative accounts for every Events section and the complete
      revised R3 AsyncAPI delta.
- [ ] The `self-jwt` and Events initiatives cross-link their shared discovery
      seam without conflating the wire schemes.
- [ ] This migration links each spin-off and states its unsupported runtime
      boundary.

## Phase 5 - independent final review

Give a fresh read-only reviewer the complete diff, target specifications,
research, approved plan, and implementation log. Present every severity-graded
finding before edits and obtain one owner ruling per finding.

### Definition of Done

- [ ] Every finding has a recorded disposition.
- [ ] Every approved fix is validated.
- [ ] A materially changed design receives a fresh review.
- [ ] The final full validation matrix is green.
- [ ] All changes remain uncommitted for owner inspection.

## Out of scope

| Item | Reason |
|---|---|
| Compatibility aliases or dual-wire parsing | Conflicts with the owner's exact latest-spec ruling |
| MockAgentProvider/Bootstrap error normalization | Q3 spin-off |
| Access Server clarification receiver | Q4 spin-off |
| AAuth Events runtime and metadata/token seams | Q5 spin-off |
| R3 AsyncAPI vocabulary/model and Events handoff | Q6 spin-off |
| Signature Keys `self-jwt` support | Q7 spin-off |
| Unrelated pre-existing defects | Not part of the draft-09 cutover |
