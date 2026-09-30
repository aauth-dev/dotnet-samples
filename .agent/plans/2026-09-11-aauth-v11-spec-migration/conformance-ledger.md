---
description: Draft-11 WIP requirement risks, negative controls, and planned verification ledger.
---

# Conformance ledger - draft-11 WIP

Source audit only, 2026-09-11. SDK baseline
`94576a3ebcba8cd1d167923e50c8796132057600`; spec pins and citations are in
[research.md](research.md). No row is an executed draft-11 conformance pass.
F labels refer to research findings; phase numbers refer to the
[implementation plan](implementation-plan.md). Test files are existing homes
to extend, not assertions that proposed cases already exist or pass.

## Requirement-to-check map

| ID | Source assessment | Discriminating future regression | Existing test home | Phase |
|---|---|---|---|---|
| F01 | D: auth builder requires agent, permits absent subject, emits act | Require ps/sub without agent/act; reject missing subject and reserved-claim injection | [AuthTokenStructureTests](../../../tests/AAuth.Conformance/AuthTokens/AuthTokenStructureTests.cs), [AuthTokenBuilderTests](../../../tests/AAuth.Tests/Tokens/AuthTokenBuilderTests.cs) | 4 |
| F02 | R: person-token lifecycle absent | Verify person typ/DWK/issuer/audience/key/expiry; reject scope/account; isolate resource/mission/key caches | [TokenVerifierTests](../../../tests/AAuth.Tests/Tokens/TokenVerifierTests.cs), [PersonServerMapperTests](../../../tests/AAuth.Conformance/Person/PersonServerMapperTests.cs), [holder tests](../../../tests/AAuth.Tests/Agent/AAuthTokenHolderTests.cs) | 2, 3, 5 |
| F03 | R: agent-only challenge still mints resource token | Agent yields person requirement; person mints; runtime auth step-up mints; auth-only authorization endpoint fails | [ChallengeMiddlewareTests](../../../tests/AAuth.Conformance/HttpSignatures/ChallengeMiddlewareTests.cs) | 4 |
| F04 | R: no presented parameter; D clarification replacement API gap | Same claims/different jti; stripped mission/tenant; wrong key/audience/PS; refreshed holder; reject at PS/AS before mutation; atomically replace both tokens under Q13 | [ChallengeHandlerTests](../../../tests/AAuth.Tests/Agent/ChallengeHandlerTests.cs), [AccessServerClientTests](../../../tests/AAuth.Tests/AccessServerClientTests.cs), [DeferredFederationTests](../../../tests/AAuth.Conformance/Person/DeferredFederationTests.cs) | 4, 5 |
| F05 | R: old endpoint/session names | Minimal PS metadata; missing/invalid endpoint; unknown-mode fallback; exact algorithm list; bad link rejected before fetch | [AllRolesWellKnownMetadataTests](../../../tests/AAuth.Conformance/Discovery/AllRolesWellKnownMetadataTests.cs), [ResourceAccessModeMetadataTests](../../../tests/AAuth.Conformance/Discovery/ResourceAccessModeMetadataTests.cs), [MetadataClientTests](../../../tests/AAuth.Tests/Discovery/MetadataClientTests.cs) | 1, 2, 5 |
| F06 | R: qualified identity exists, validators use agent/act | Same sub across issuers distinct; tenant change preserves person; agent policy cannot silently accept person-token requests | [AuthorizationIntegrationTests](../../../tests/AAuth.Conformance/HttpSignatures/AuthorizationIntegrationTests.cs), [AuthTokenDeliveryTests](../../../tests/AAuth.Conformance/AuthTokens/AuthTokenDeliveryTests.cs) | 4, 9 |
| F07 | R: exact bytes exist, approval is raw body/header | Envelope formatting independent of digest; blob mutation rejected; capabilities not hashed; no mission header | [MissionS256Tests](../../../tests/AAuth.Conformance/Missions/MissionS256Tests.cs), [MissionHeaderSeamTests](../../../tests/AAuth.Conformance/Missions/MissionHeaderSeamTests.cs) | 3, 4 |
| F08 | R: no update log; completion via interaction | Update changes later consent without changing mission hash; required action; completion remains active until acceptance | [GovernanceServerTests](../../../tests/AAuth.Conformance/Missions/GovernanceServerTests.cs), [GovernanceDeferredConsentMapperTests](../../../tests/AAuth.Conformance/Missions/GovernanceDeferredConsentMapperTests.cs) | 3, 6 |
| F09 | R: no mission expiry; store allows reactivation | Expire during resumed PS operations; terminal/save races; opaque reason; foreign/missing equal responses and controlled timing | [MissionTerminatedTests](../../../tests/AAuth.Conformance/Missions/MissionTerminatedTests.cs), [GovernanceEndpointMapperTests](../../../tests/AAuth.Conformance/Missions/GovernanceEndpointMapperTests.cs) | 3, 6, 9 |
| F10 | R: consent evidence provenance incomplete | Misleading justification cannot replace resource display; fixed subject survives claims push; updates reach policy/UI | [MockPersonServerTests](../../../tests/AAuth.Tests/Integration/MockPersonServerTests.cs), [DeferredFederationTests](../../../tests/AAuth.Conformance/Person/DeferredFederationTests.cs) | 4, 6 |
| F11 | D upstream conflict; R parent/routing | Distinct caller/intermediary/worker keys; upstream PS differs from issuer/intermediary PS; downstream sub not copied; direct worker rejected | [CallChainingRouterTests](../../../tests/AAuth.Conformance/CallChaining/CallChainingRouterTests.cs), [UpstreamTokenValidationTests](../../../tests/AAuth.Conformance/AuthTokens/UpstreamTokenValidationTests.cs), [CallChainingTests](../../../tests/AAuth.Conformance/AuthTokens/CallChainingTests.cs) | 6 |
| F12 | R: expiry skew and isolated refresh | Exact-now/subsecond exp in header/body; independent future iat; preserved source ceilings through consent; top-down concurrent refresh | [TokenVerifierTests](../../../tests/AAuth.Tests/Tokens/TokenVerifierTests.cs), [IssuanceBoundsTests](../../../tests/AAuth.Conformance/AuthTokens/IssuanceBoundsTests.cs), [TokenRefreshHandlerTests](../../../tests/AAuth.Tests/Agent/TokenRefreshHandlerTests.cs) | 2, 4, 5 |
| F13 | R: PS identity signing exists; default body coverage absent | Missing coverage, altered bytes, and signed malformed JSON get distinct outcomes before policy; future created gets clock skew | [SignatureV10AdversarialTests](../../../tests/AAuth.Tests/HttpSig/SignatureV10AdversarialTests.cs), [SignatureV10WireTests](../../../tests/AAuth.Tests/HttpSig/SignatureV10WireTests.cs), [SignatureErrorTests](../../../tests/AAuth.Conformance/Errors/SignatureErrorTests.cs) | 1, 4, 9 |
| F14 | D store; R wire: unseen revocation absent | Unseen/repeated jti/exp returns 200; injected issuer cannot select namespace; bad exp rejected; old override removed | [JtiStoreAndRevocationTests](../../../tests/AAuth.Conformance/Discovery/JtiStoreAndRevocationTests.cs) | 7 |
| F15 | D: every ancestry source also bounds expiry | Five-minute resource source can back a longer auth grant; withdrawal still blocks issuance; person/step-up ancestry retained | [RevocationLifecycleTests](../../../tests/AAuth.Conformance/Discovery/RevocationLifecycleTests.cs), [IssuanceBoundsTests](../../../tests/AAuth.Conformance/AuthTokens/IssuanceBoundsTests.cs) | 7 |
| F16 | R: revoked/federation error meanings differ | Header revocation 401, body 400, pending withdrawal 403; immediate/polled AS denial preserved; malformed success maps 502 | [SignatureErrorTests](../../../tests/AAuth.Conformance/Errors/SignatureErrorTests.cs), [PollingErrorTests](../../../tests/AAuth.Conformance/Errors/PollingErrorTests.cs), [AccessServerClientTests](../../../tests/AAuth.Tests/AccessServerClientTests.cs) | 1, 4, 5, 7 |
| F17 | D R3; R agent: no consumed grant/results | 202 never resends original body; concurrent completion executes once; lost-response retry returns retained result; 401 retry also single-use | [DeferredExchangeTests](../../../tests/AAuth.Tests/Agent/DeferredExchangeTests.cs), [DeferredStateTests](../../../tests/AAuth.Tests/Server/DeferredStateTests.cs), [ResourceR3Tests](../../../tests/AAuth.R3.Tests/ResourceR3Tests.cs) | 5, 8 |
| F18 | D: gateway removed, hash already correct | No Conditional/Version/gateway API or emission; seven vocabularies; collision-free Catalog; unchanged byte/structural equality | [R3VocabularyTests](../../../tests/AAuth.R3.Tests/R3VocabularyTests.cs), [R3ModelTests](../../../tests/AAuth.R3.Tests/R3ModelTests.cs), [R3HashTests](../../../tests/AAuth.R3.Tests/R3HashTests.cs) | 1, 8 |
| F19 | R: R3 identity/reader context changes | R3 AS checks provenance; foreign PS cannot read unentitled document; persistent audit; annotations never grant access | [AccessEndpointR3Tests](../../../tests/AAuth.R3.Tests/AccessEndpointR3Tests.cs), [R3SqliteAuditTests](../../../tests/AAuth.R3.Tests/R3SqliteAuditTests.cs), [ResourceR3Tests](../../../tests/AAuth.R3.Tests/ResourceR3Tests.cs) | 4, 8 |
| F20 | D: protected ticket reads removed agent | Agreed trusted binding survives new token; wrong key/agent/account/operation rejected; persistence/replay and event no-cnf preserved | [EventHttpTests](../../../tests/AAuth.Events.Tests/EventHttpTests.cs), [EventPersistenceTests](../../../tests/AAuth.Events.Tests/EventPersistenceTests.cs), [EventsTokenTests](../../../tests/AAuth.Events.Tests/EventsTokenTests.cs) | 4, 8 |
| F21 | R: result not exposed to policy | Result reaches capable policy or explicit unsupported response; never silently treat release request as execute approval | [R3ModelTests](../../../tests/AAuth.R3.Tests/R3ModelTests.cs), [AccessEndpointR3Tests](../../../tests/AAuth.R3.Tests/AccessEndpointR3Tests.cs) | 8 or separate |
| F22 | R: Budgets unsupported | No false metering claims; selected future capability needs atomic amount/denomination/reservation/settlement tests | [ScopeNarrowingTests](../../../tests/AAuth.Conformance/AuthTokens/ScopeNarrowingTests.cs) is a starting point, not budget coverage | 0, separate |
| F23 | R: informational bootstrap and generic carriers | Existing enrollment/carrier matrix retained; optional delayed verifier never changes live acceptance | [Bootstrap tests](../../../tests/AAuth.Tests/HttpSig/AAuthClientBuilderBootstrapTests.cs), [AAuthVerifierTests](../../../tests/AAuth.Tests/HttpSig/AAuthVerifierTests.cs) | 6, 9 or separate |
| F24 | D tool paths; R UI/static inventory | Generator cannot overwrite v10 map; exact snippets compile; both apps run matching steps and payloads; no stale live wire text | [SnippetCompilationTests](../../../tests/AAuth.Tests/Api/SnippetCompilationTests.cs), [e2e](../../../tests/e2e/) | 1, 9-11 |

## Negative requirement audit

ENFORCED means an actual rejecting/bounding path was inspected. VACUOUS means
the built-in capability is absent, not compliant. UNENFORCEABLE means the local
verifier lacks the evidence needed; another boundary or deployment must own it.
All verdicts are scoped source observations, not runtime test results.

| Requirement | Governing clause | Current verdict | Disposition |
|---|---|---|---|
| Person token no scope/account | [P898](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L898), `#person-token-structure` | VACUOUS absent issuer | Reserved claims and negative verification, F02 |
| Person cannot replace required auth | [P920](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L920), `#person-token-verification` | Unsupported type rejected; new acceptance path unimplemented | Explicit typed policy separation, F02/F06 |
| Agent-only request cannot mint challenge | [P637](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L637), `#requirement-auth-token` | UNENFORCED v11 prerequisite | Verified person/auth context, F03 |
| No substituted or stripped identity/mission | [P767](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L767), `#resource-token-verification` | UNENFORCED new paired-token check | Compare exact named credential at PS/AS, F04 |
| No resource-visible agent/act | [P1781](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1781), `#auth-token-structure` | UNENFORCED v11 producer contract | Remove core issuance, preserve AP/Events identities, F01/F20 |
| Auth cannot outlive source agent | [P1775](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1775), `#auth-token-structure` | ENFORCED builder ceiling; UNENFORCEABLE independently without source at resource | Preserve issuer bound; add presented/mission, F12 |
| Terminal mission cannot reactivate | [P1516](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1516), `#mission-management` | UNENFORCED store mutation/replacement | Atomic terminal state, F09 |
| No mission disclosure before owner authorization | [P1540](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1540), `#mission-endpoint-errors` | Owner rejection exists; equivalence UNVERIFIED | Equal responses and measured timing, F09 |
| Worker cannot authorize itself | [P1917](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1917), `#sub-agents` | ENFORCED PS auth parent check | Apply to person endpoint, F11 |
| Caller cannot select another revocation issuer | [P2690](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2690), `#token-revocation` | UNENFORCED with existing cross-issuer override | Signer-derived namespace, F14 |
| Revoked resource token cannot mint auth | [P2753](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2753), `#token-revocation` | UNENFORCED new source tracking | Withdrawal edge distinct from expiry ceiling, F15 |
| One per-call grant cannot execute twice | [R676](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L676), `#per-call-flow` | UNENFORCED R3 execution boundary | Atomic consumption/result retention, F17 |
| Event self-JWT no cnf | [E367](../../../aauth-spec/v11/draft-hardt-aauth-events.md#L367), `#event-token` | ENFORCED EventsTokens rejection | Preserve companion profile, F20 |
| Link cannot direct arbitrary fetch/key trust | [P2154](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2154), `#resource-metadata-link` | VACUOUS absent consumer | Validate before fetch; exclude key resolver, F05 |
| 403 no signature error/negotiation headers | [P2254](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2254), `#verification` | ENFORCED inspected SDK signature paths, not arbitrary host middleware | Regress new polling/AS/issuer-admission errors, F16 |
| No pre-execution of billed/metered/audited work | [R696](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L696), `#release-gating` | VACUOUS absent capability; side effects UNENFORCEABLE from JSON alone | Explicit host policy, default disabled, F21 |
| Consumption plus reservations cannot exceed budget | [B871](../../../aauth-spec/v11/draft-hardt-aauth-budgets.md#L871), `#overshoot` | VACUOUS absent metering | Separate selected capability, F22 |

## Finding owners and executed checks

Recorded 2026-09-29, after implementation. The tables above keep the
pre-implementation source audit. This table names the component that owns each
finding and the tests that now discriminate it. Every test name was confirmed
in `tests/` by grep. The implementation log records each test's rerun
evidence.

| F | Owner | Phase | Executed discriminatory checks |
|---|---|---|---|
| F01 | `AuthTokenBuilder` | 4 | `AuthTokenStructureTests.PayloadNamesPersonNotAgent`, `.PayloadAct_Omitted`, `.ReservedClaims_RejectedInAdditionalClaims`, `.Builder_RejectsMissingSubjectOrPersonServer` |
| F02 | `PersonTokenBuilder`, `TokenVerifier`, `AAuthPersonServerEndpoints` | 2, 3, 5 | `PersonServerMapperTests.PersonTokenEndpoint_IssuesPersonToken`, `.PersonTokenEndpoint_LifetimeIsCappedByEveryBound`; `SignatureV10AdversarialTests.RawMalformedValuesHaveTypedErrorsWithoutTrustedContext` (person `scope`/`account`); `AuthTokenVerificationTests.Rejects_PersonToken`; `AccountBindingTests.CachedPersonToken_IsSelectedForAnyAccount` |
| F03 | `AAuthChallengeMiddleware` | 4 | `ChallengeMiddlewareTests.ChallengesAgentTokenWithPersonTokenRequirement`, `.ChallengesPersonTokenWithResourceToken`; `ChallengeHandlerTests.PrerequisiteAndStepUp_WireBodies` |
| F04 | `TokenVerifier.VerifyPresentedTokenAsync`, PS and AS token endpoints | 4, 5 | `PersonServerMapperTests.TokenRequest_MissingPresentedToken_Rejected`, `.TokenRequest_MismatchedPresentedToken_Rejected`, `.TokenRequest_OverwrittenIdentity_Rejected`, `.Clarification_ReplacementIsVerifiedAndChangesConsentScope`; `DeferredFederationTests.AsRejectsResourceTokenNotNamingTheSigningPsOrPresentedToken`; `ChallengeHandlerTests.PresentedToken_SurvivesHolderRefresh` |
| F05 | `MetadataClient`, `WellKnownEndpoints` | 1, 2, 5 | `AllRolesWellKnownMetadataTests.PsMetadata_RequiresPersonTokenEndpoint`; `ResourceAccessModeMetadataTests.AgentReadsDraft11PersonServerEndpoints`, `.RejectsRenamedAccessMode`, `.AgentParsesOnlyKnownAccessModes`. Algorithm lists and `aauth-resource` links are excluded optional items (see below). |
| F06 | `AAuthVerificationMiddleware`, `IssuerTrust`, `IJtiStore` keys | 4, 9 | `ChallengeMiddlewareTests.PersonTokenIssuerTrustIsIndependent`; `TokenInventoryTests.SameIdFromTwoIssuers_IsolatedIncludingGrants`; `RevocationLifecycleTests.ResourceMiddleware_SameAuthJtiFromTwoIssuers_RemainsIsolated`; `AuthTokenDeliveryTests.AccountDelivery_MatchesExactResourceExpectation` |
| F07 | `Mission`, `MissionProposal`, governance endpoints | 3, 4 | `MissionS256Tests.RawBytes_AreVerbatim`, `.Envelope_RejectsMismatchedS256`; `GovernanceDeferredConsentMapperTests.Mission_DefaultApprover_ReturnsApprovedBlob` (no `AAuth-Mission` header), `.MissionUpdate_OwnedMissionOnly` (update bytes and hash) |
| F08 | `MissionTokenConsentContext`, PS mission review | 3, 6 | `PersonServerMapperTests.AcceptedUpdate_ReachesConsentAndResetsFastPath`; `GovernanceDeferredConsentMapperTests.AcceptedUpdate_ReachesPermissionDecision`, `.MissionUpdate_OwnedMissionOnly` |
| F09 | `InMemoryMissionStore`, `GovernanceEndpoints` | 3, 6, 9 | `GovernanceServerTests.MissionStore_TerminatedIsFinal`, `.MissionStore_ConcurrentMutationKeepsTerminal`, `.MissionStore_ReplacementKeepsEarliestExpiry`; `GovernanceEndpointMapperTests.MissionAuthorization_RejectsInvalidContext`; `PersonServerMapperTests.Mission_Terminated_Rejected` |
| F10 | `AgentAssertedContent`, PS consent context | 4, 6 | `PersonServerMapperTests.AgentAssertedContent_ReachesAsserterApartFromResourceContext`; `MockPersonServerTests.Interaction_ConsentPage_AttributesAgentAssertedContentApartFromResource`; `DeferredFederationTests.ClaimsPushPreservesRequestedCredentialNamedIdentity` |
| F11 | `CallChainingRouter`, `UpstreamTokenValidator`, `AgentIssuanceContext` | 6 | `PersonServerMapperTests.CallChaining_UpstreamAudienceMustBeIntermediaryIssuer`, `.SubAgent_DirectRequest_Rejected`; `DeferredFederationTests.FourPartyUsesDistinctChildKeyAndUpstreamBounds`, `.SubagentTokenFromAnotherIssuerOrParent_IsInvalidSubagentToken` |
| F12 | `TokenVerifier`, `AuthTokenBuilder`, `TokenRefreshHandler` | 2, 4, 5 | `IssuanceBoundsTests.DirectAndDeferred_UseOriginalAgentAndParentBounds`, `.Deferred_RejectsOriginalExpiryDespiteFreshPollCarrier`; `PersonServerMapperTests.AuthToken_IsCappedByMissionExpiry`; `TokenRefreshHandlerTests.DefaultMargin_IsFiveMinutes`, `.ConcurrentRequests_OnlyRefreshOnce` |
| F13 | `AAuthVerifier`, `AAuthSigningHandler`, `AAuthVerificationMiddleware` | 1, 4, 9 | `SignatureErrorTests.CreatedOutsideWindow_ReturnsDistinctCodes`; `PersonServerMapperTests.PsBody_UncoveredOrTampered_FailsBeforeAsserter`; `DeferredFederationTests.AsBodyUncoveredOrTampered_FailsBeforePolicyOrPendingState`; `JtiStoreAndRevocationTests.Revocation_RequiresBodyCoverageAtEveryRecipient` |
| F14 | `RevocationEndpoint`, `InMemoryJtiStore` | 7 | `JtiStoreAndRevocationTests.Revocation_IssuerCannotRevokeOtherIssuerWithSameId`, `.Revocation_RejectsMalformedRequest`; `TokenInventoryTests.UnseenRevocation_IsRetainedUntilItsExpiryPlusRetention` |
| F15 | `AuthTokenResponse`, `IJtiStore` grants, PS and AS token endpoints | 7 | `PersonServerMapperTests.ResourceTokenLifetime_DoesNotCapAuthTokenOrGrant`, `.RevokedResourceToken_RejectedAndEndsPending`; `DeferredFederationTests.AsRefusesWithdrawnResourceToken`; `TokenInventoryTests.MissingOrRevokedSource_CannotCreateGrant`; `RevocationLifecycleTests.UpstreamRevokedDuringConsentCannotMintAfterApproval` |
| F16 | `SignatureErrorResult`, `AAuthProblemDetails`, `PollingErrorException` | 1, 4, 5, 7 | `ReplayDetectionMiddlewareTests.RevokedAuthToken_Rejected`; `PollingErrorTests.TerminalCodes_AreDistinctWithDetail`; `ChallengeHandlerTests.Exchange_EveryPublishedError_IsDistinct`; `DeferredFederationTests.AsOutcomesMapSeparatelyFromLocalCancellation` |
| F17 | `AAuthHeldInvocations`, `AAuthSingleUseGrants`, `ChallengeHandler` | 5, 8 | `ChallengeHandlerTests.DeferredAuthToken_PollsPendingUrlWithoutResendingBody`; `HeldInvocationTests.SingleUseGrant_ExecutesOncePerJti`; `BookingsPolicyTests.EveryRoute_EnforcesGrantedPerCallRejectedAndApprovedParameters` |
| F18 | R3 model and vocabularies | 1, 8 | `TokenClaimTests.Draft11WireNames_PerCallClaimAndNoDocumentVersion`; `R3VocabularyTests.MalformedOrRemovedDiscoveryFails`, `.MergedDefinition_RenamedCollidingOperationsAreDistinct`; `R3Draft11FixtureTests.Annotations_ApplySpecRules` |
| F19 | `R3DocumentReaderPolicy`, R3 AS token endpoint | 4, 8 | `BookingsPolicyTests.PersonServerEvaluator_ReadsOnlyDocumentsItIsEntitledTo`; `AccessEndpointR3Tests.UncoveredOrTamperedBodyFailsBeforeDocumentPolicyOrAudit`, `.TokenEndpoint_DoesNotReleaseTokenThatExpiresDuringAudit`; `R3SqliteAuditTests.Commit_SurvivesRestartAndConcurrentIssuance` |
| F20 | `EventsTokens`, subscription tickets | 4, 8 | `EventHttpTests.ForeignIssuerCannotSpendVictimTicketOrInjectSubscription`; `EventPersistenceTests.TicketRedemptionIsAtomicAndPreservesAccount`, `.AgentContextPersistsAndEventsDedupeOnIssuerAndJti`; `EventsTokenTests.InvalidEventClaimsFail` (`cnf`) |
| F21 | `R3ProposalDocument` | 8 | `R3Draft11FixtureTests.ResultBearingProposal_FailsClosedInsteadOfBecomingAnExecutionApproval`. Release gating is unsupported and fails closed. |
| F22 | None (Budgets) | Separate | Excluded: the SDK meters nothing and claims no Budgets support. Re-entry needs its own plan. |
| F23 | `AAuthClientBuilder` bootstrap | 6 | `AAuthClientBuilderBootstrapTests.Enrolled_ResourceManagedAccess_ComposesBeforeInteractionHandling`. No delayed verifier exists, so live acceptance is unchanged. Delayed verification stays separate work. |
| F24 | `tools/ApiSurface`, documentation tests, e2e | 1, 9-11 | `SnippetCompilationTests.Documentation_FrozenSurface`; `DocumentationLinkTests`; the full Playwright run (76 passed, 1 skipped, 2026-09-29) |

## Negative requirements: execution evidence

Recorded 2026-09-29. The verdicts in the audit above describe the source before
implementation. This table records each negative's execution evidence, or its
explicit conditional disposition.

| Requirement | Evidence or disposition |
|---|---|
| Person token no scope/account | `SignatureV10AdversarialTests.RawMalformedValuesHaveTypedErrorsWithoutTrustedContext` (`aa-person+jwt` with `scope` or `account` is `invalid_jwt`) |
| Person cannot replace required auth | `AuthTokenVerificationTests.Rejects_PersonToken` |
| Agent-only request cannot mint challenge | `ChallengeMiddlewareTests.ChallengesAgentTokenWithPersonTokenRequirement` (bare `requirement=person-token`, no resource token) |
| No substituted or stripped identity/mission | `PersonServerMapperTests.TokenRequest_OverwrittenIdentity_Rejected`, `.TokenRequest_MismatchedPresentedToken_Rejected`; `DeferredFederationTests.AsRejectsResourceTokenNotNamingTheSigningPsOrPresentedToken` |
| No resource-visible agent/act | `AuthTokenStructureTests.PayloadNamesPersonNotAgent`, `.PayloadAct_Omitted`, `.ReservedClaims_RejectedInAdditionalClaims` |
| Auth cannot outlive source agent | `IssuanceBoundsTests.DirectAndDeferred_UseOriginalAgentAndParentBounds`; `PersonServerMapperTests.AuthToken_IsCappedByMissionExpiry`. A resource cannot check the agent ceiling itself, since it never sees the agent token. The issuer owns that bound. |
| Terminal mission cannot reactivate | `GovernanceServerTests.MissionStore_TerminatedIsFinal`, `.MissionStore_ConcurrentMutationKeepsTerminal` |
| No mission disclosure before owner authorization | `GovernanceEndpointMapperTests.MissionAuthorization_RejectsInvalidContext` (foreign equals missing: `404 mission_not_found`, nothing logged). Conditional: equal timing is a property of the `IMissionStore` implementation. The in-memory store does one keyed lookup for both cases; a deployment's store owns its own timing. |
| Worker cannot authorize itself | `PersonServerMapperTests.SubAgent_DirectRequest_Rejected` |
| Caller cannot select another revocation issuer | `JtiStoreAndRevocationTests.Revocation_IssuerCannotRevokeOtherIssuerWithSameId` |
| Revoked resource token cannot mint auth | `PersonServerMapperTests.RevokedResourceToken_RejectedAndEndsPending`; `DeferredFederationTests.AsRefusesWithdrawnResourceToken` (added 2026-09-29, after this audit found the check missing) |
| One per-call grant cannot execute twice | `HeldInvocationTests.SingleUseGrant_ExecutesOncePerJti`; `BookingsPolicyTests.EveryRoute_EnforcesGrantedPerCallRejectedAndApprovedParameters` |
| Event self-JWT no cnf | `EventsTokenTests.InvalidEventClaimsFail` (`cnf` present fails) |
| Link cannot direct arbitrary fetch/key trust | Conditional: no `aauth-resource` link consumer exists (AG-03 excluded). Selecting AG-03 requires validation before fetch. |
| 403 no signature error/negotiation headers | `SignatureV10AdversarialTests.AuthorizationDenialHasNoSignatureHeaders`; `GovernanceEndpointMapperTests.MissionAuthorization_RejectsInvalidContext` |
| No pre-execution of billed/metered/audited work | Conditional: release gating is unsupported. `R3Draft11FixtureTests.ResultBearingProposal_FailsClosedInsteadOfBecomingAnExecutionApproval` proves a release request never becomes an execute approval. |
| Consumption plus reservations cannot exceed budget | Conditional: Budgets is excluded (F22). No metering exists to overshoot. |

## Upgrade checklist ownership

Recorded 2026-09-29. Every ID in
[upgrade-10-to-11](../../../aauth-spec/v11/upgrade-10-to-11/README.md) is listed
here: 55 PS, 33 RS, 30 AG, 7 AP and 22 AS. Each has one owning phase or a
recorded optional disposition.

| Role | Phase | IDs |
|---|---|---|
| PS | 1 | PS-01, PS-100, PS-101, PS-102, PS-103, PS-104 |
| PS | 2 | PS-02, PS-10, PS-11, PS-12, PS-13, PS-20, PS-95 |
| PS | 3 | PS-04, PS-80, PS-81, PS-82, PS-83, PS-84, PS-85, PS-86 |
| PS | 4 | PS-30, PS-31, PS-32, PS-33, PS-34, PS-35, PS-36, PS-40, PS-50, PS-51, PS-52, PS-53, PS-54, PS-55 |
| PS | 6 | PS-60, PS-61, PS-62, PS-63, PS-64, PS-70, PS-71 |
| PS | 7 | PS-03, PS-110, PS-111, PS-112, PS-113, PS-114, PS-115 |
| RS | 1 | RS-01, RS-02, RS-50, RS-51, RS-52 |
| RS | 2 | RS-10, RS-11, RS-12 |
| RS | 4 | RS-20, RS-21, RS-30, RS-31, RS-32, RS-33, RS-34, RS-40, RS-41, RS-42 |
| RS | 6 | RS-70, RS-71, RS-72, RS-73, RS-74, RS-75 |
| RS | 7 | RS-03, RS-43, RS-60, RS-61 |
| AG | 1 | AG-01, AG-02, AG-52 |
| AG | 2 | AG-10 |
| AG | 3 | AG-30, AG-31, AG-32, AG-33, AG-34 |
| AG | 4 | AG-20, AG-21, AG-22, AG-23, AG-24, AG-25 |
| AG | 5 | AG-11, AG-12, AG-26, AG-50, AG-51, AG-60, AG-61, AG-62, AG-63, AG-64, AG-70 |
| AG | 6 | AG-40 |
| AP | 1 | AP-01, AP-03, AP-04, AP-05 |
| AP | 6 | AP-02 |
| AP | 7 | AP-07 |
| AS | 1 | AS-01, AS-30, AS-31, AS-32 |
| AS | 4 | AS-10, AS-11, AS-15, AS-16, AS-17, AS-20, AS-21, AS-22 |
| AS | 6 | AS-12, AS-13, AS-14 |
| AS | 7 | AS-02, AS-40, AS-41, AS-42, AS-43, AS-44 |

Optional items:

| ID | Disposition | Evidence |
|---|---|---|
| PS-05, RS-04, AP-06, AS-03 | Excluded: no `accept_signature_algs` advertisement. Verifiers still enforce their algorithm set. | No `accept_signature_algs` in `src/` |
| RS-04 (link), AG-03 | Excluded: no `aauth-resource` link publishing or discovery | No link consumer in `src/` |
| RS-13 | Excluded as a dedicated mode. Identity-only endpoints pass verified person tokens, and metadata can declare `access_mode: person-token`. No per-endpoint step-up helper exists for person-identity resources. | `ResourceAccessModeMetadataTests.EmitsEachAccessMode` |
| RS-35 | Selected (Phase 4) | `ResourceTokenBuilder.LoginHint`; `PersonServerMapperTests.PersonTokenRequest_CapabilitiesAndLoginHintReachAsserter` |
| RS-36 | Selected (Phase 5) | `AAuthHeldInvocations`; `HeldInvocationTests`; `ChallengeHandlerTests.DeferredAuthToken_PollsPendingUrlWithoutResendingBody` |
| RS-62 | Selected (Phase 7): resources revoke with the generic `RevocationClient`. PS and AS recipients enforce PS-112 and AS-42. | `DeferredFederationTests.AsRefusesWithdrawnResourceToken` (signed as the resource) |
| PS-87, AG-35 | Selected (Phase 3) | `MissionClient.UpdateAsync`; `GovernanceDeferredConsentMapperTests.MissionUpdate_OwnedMissionOnly` |
| PS-88, AG-36 | Selected (Phase 3) | `MissionProposal` `resources`; `MissionPersonTokenIssuanceTests.PartialResourceApproval_LimitsApprovedResourcesAndPersonTokens` |
| PS-89 | Selected (Phase 3) | `GovernanceServerTests.MissionStore_ReplacementKeepsEarliestExpiry`; `PersonServerMapperTests.Mission_Terminated_Rejected` (expired) |
| PS-90 | Partly selected (Phase 3): the SDK reports `termination_reason: expired`. `IMissionStore` records no other reasons, so they are omitted. | `PersonServerMapperTests.Mission_Terminated_Rejected`; `GovernanceEndpointMapperTests.MissionAuthorization_RejectsInvalidContext` |
| PS-96 | Host capability: a PS completes a hosted interaction over its own channel by calling `IPersonPendingStore.MarkAllowed` or `MarkDenied`. No sample demonstrates a non-browser channel. | `IPersonPendingStore` |

## Revocation cascade: executed checks

Recorded 2026-09-30 by the SDK API surface plan, Phase 6
([log](../2026-09-29-sdk-api-surface-consistency/implementation-log.md)).
The cascades run through `IAAuthRevocationService`, which the inbound endpoint
and app code share.

| Requirement | Governing clause | Executed discriminatory checks |
|---|---|---|
| PS revokes a person token at its `aud` and at every AS it presented it to; SHOULD revoke person tokens issued from it as an upstream token | [P2752](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2752), `#revocation-cascade` | `PersonTokenRevocationCascadeTests.RevokeToken_ReachesAudienceAndEveryAccessServer`, `.RevokeToken_RevokesUpstreamDerivedPersonTokens` |
| PS revokes a mission: later requests under its `s256` are denied; SHOULD revoke the tokens issued under it | [P2754](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2754), `#revocation-cascade` | `MissionRevocationCascadeTests.RevokeMission_TerminatesAndRevokesMissionTokens` |
| AP revokes an agent token: the PS MUST deny it and SHOULD revoke what it issued to that agent's `sub`, whichever agent token it presented; the binding is unaltered | [P2755](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2755), `#revocation-cascade` | `AgentTokenRevocationCascadeTests.ProviderRevoke_CascadesBySubAcrossAgentTokens`, `.RevokeAgent_RevokesIssuedTokensOnly` |
| Records: agent token `(iss, jti)` with its `sub`; issued tokens with resource and `exp`; upstream `(iss, jti)` | [P2758](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2758), `#revocation-cascade` | Covered by the three rows above; `IJtiStore.RecordSubjectAsync` and `GetGrantAsync` close the gap |

## Evidence state

Implementation must record exact commands, failures, fixes/reruns, API/docs
inventory output, fresh browser modes and unavailable prerequisites in
[implementation-log.md](implementation-log.md). No test counts are inherited
from the historical v10 ledger. Research checks concern Markdown, source
references, classification and coverage only.

Final independent review includes synthesis across F04/F07 mission stripping,
F08/F11 consent authority after updates, F12/F15 expiry versus withdrawal,
F17/F20 ticket issuance on retained-result retries, and F18/F24 Catalog examples.