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
| Person token no scope/account | [P633](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L633), `#person-token-structure` | VACUOUS absent issuer | Reserved claims and negative verification, F02 |
| Person cannot replace required auth | [P659](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L659), `#person-token-verification` | Unsupported type rejected; new acceptance path unimplemented | Explicit typed policy separation, F02/F06 |
| Agent-only request cannot mint challenge | [P781](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L781), `#requirement-auth-token` | UNENFORCED v11 prerequisite | Verified person/auth context, F03 |
| No substituted or stripped identity/mission | [P903](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L903), `#resource-token-verification` | UNENFORCED new paired-token check | Compare exact named credential at PS/AS, F04 |
| No resource-visible agent/act | [P1884](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1884), `#auth-token-structure` | UNENFORCED v11 producer contract | Remove core issuance, preserve AP/Events identities, F01/F20 |
| Auth cannot outlive source agent | [P1882](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1882), `#auth-token-structure` | ENFORCED builder ceiling; UNENFORCEABLE independently without source at resource | Preserve issuer bound; add presented/mission, F12 |
| Terminal mission cannot reactivate | [P1613](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1613), `#mission-management` | UNENFORCED store mutation/replacement | Atomic terminal state, F09 |
| No mission disclosure before owner authorization | [P1637](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L1637), `#mission-endpoint-errors` | Owner rejection exists; equivalence UNVERIFIED | Equal responses and measured timing, F09 |
| Worker cannot authorize itself | [P2011](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2011), `#sub-agents` | ENFORCED PS auth parent check | Apply to person endpoint, F11 |
| Caller cannot select another revocation issuer | [P2400](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2400), `#token-revocation` | UNENFORCED with existing cross-issuer override | Signer-derived namespace, F14 |
| Revoked resource token cannot mint auth | [P2448](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2448), `#token-revocation` | UNENFORCED new source tracking | Withdrawal edge distinct from expiry ceiling, F15 |
| One per-call grant cannot execute twice | [R702](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L702), `#per-call-flow` | UNENFORCED R3 execution boundary | Atomic consumption/result retention, F17 |
| Event self-JWT no cnf | [E368](../../../aauth-spec/v11/draft-hardt-aauth-events.md#L368), `#event-token` | ENFORCED EventsTokens rejection | Preserve companion profile, F20 |
| Link cannot direct arbitrary fetch/key trust | [P2832](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2832), `#resource-metadata-link` | VACUOUS absent consumer | Validate before fetch; exclude key resolver, F05 |
| 403 no signature error/negotiation headers | [P2584](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md#L2584), `#verification` | ENFORCED inspected SDK signature paths, not arbitrary host middleware | Regress new polling/AS/issuer-admission errors, F16 |
| No pre-execution of billed/metered/audited work | [R722](../../../aauth-spec/v11/draft-hardt-aauth-r3.md#L722), `#release-gating` | VACUOUS absent capability; side effects UNENFORCEABLE from JSON alone | Explicit host policy, default disabled, F21 |
| Consumption plus reservations cannot exceed budget | [B861](../../../aauth-spec/v11/draft-hardt-aauth-budgets.md#L861), `#overshoot` | VACUOUS absent metering | Separate selected capability, F22 |

## Evidence state

Implementation must record exact commands, failures, fixes/reruns, API/docs
inventory output, fresh browser modes and unavailable prerequisites in
[implementation-log.md](implementation-log.md). No test counts are inherited
from the historical v10 ledger. Research checks concern Markdown, source
references, classification and coverage only.

Final independent review includes synthesis across F04/F07 mission stripping,
F08/F11 consent authority after updates, F12/F15 expiry versus withdrawal,
F17/F20 ticket issuance on retained-result retries, and F18/F24 Catalog examples.