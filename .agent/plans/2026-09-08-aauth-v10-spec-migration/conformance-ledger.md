# Conformance Ledger

## Final Status

Closed 2026-09-09 for the approved migration scope. This supersedes the numbered
repair checkpoints below without rewriting their historical evidence. Final
Release: 2913 tests, zero failed/skipped; explicit core/conformance/R3/Events
and 105 documentation/source/link checks pass, with a clean build. API inventory:
201 changed public-source files, +810/-162 declarations, zero unmapped;
documentation inventory remains 169 files and 629 classified blocks.

The final runtime browser reports contain 71 stub passes plus the expected
live-only skip and 72 live Keycloak passes, no failures or flaky results.
Subsequent edits only correct docs/XML and add two documentation regressions.
Fresh independent reviewers report zero remaining confirmed findings in their
respective signing/discovery/API, authorization/claims, R3/Events/storage and
sample/docs scopes after repair cycles. This is bounded acceptance, not a
certification of arbitrary injected contracts or unexercised external systems.

Both apps' capability scenarios, numbered steps, sequence displays, snippets and
their Playwright coverage were reviewed; saved desktop/mobile captures were
inspected. The [implementation log](implementation-log.md) records exact gate
artifacts and the premature worker-push deviation. External full authorization
returned `person_token_required` and is not a passing interoperability result.
The optional, ambiguous and deployment-owned dispositions below remain in force.

Pinned sources are the immutable v10 protocol, Signature Keys draft 08, R3 and
Events snapshots. References below use canonical source lines and section names.
This is an area/requirement ledger, not a certification of arbitrary applications
that inject their own policies, stores, renderers or transports. A passing suite
does not prove every branch of a compound normative sentence independently.

Disposition vocabulary:

- **Implemented**: the owning code and named tests exercise the stated contract.
- **Policy**: SDK mechanics are implemented; the stated decision or operational
  guarantee belongs to the host/operator and is not silently assumed.
- **Optional unsupported**: capability is not enabled, so its conditional
  requirements are not claimed as implemented.
- **Ambiguous**: pinned text conflicts; the logged interpretation is explicit.
- **Inapplicable**: registration, rationale, historical text or a non-runtime role.

The normative sweep includes positive MUST/REQUIRED, negative MUST NOT/reject,
SHOULD recommendations, and conditional optional features. Document history,
examples with placeholders, appendices labeled non-normative and IANA expert
procedures are not executable protocol requirements. Lines in those areas must
not be mistaken for a current runtime contract.

## Protocol

| Requirement / canonical area | Owning code | Tests and disposition |
|---|---|---|
| [Terminology L203](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L203), Markdown sanitization L226 | [PS consent rendering](../../../samples/MockPersonServer/Program.cs), [PayloadInspector](../../../samples/GuidedTour/Components/PayloadInspector.razor), Razor pages | Implemented for shipped renderers: MissionConsent_RendersUntrustedMarkdownAsEncodedText in [MissionAgentFlowTests](../../../tests/AAuth.Tests/Integration/MissionAgentFlowTests.cs); arbitrary host Markdown renderers remain Policy |
| [Access modes L237](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L237), identity/resource-managed/PS/federated roles | [AAuthClientBuilder](../../../src/AAuth/AAuthClientBuilder.cs), [resource endpoints](../../../src/AAuth/Server/Endpoints/) | Implemented: [SigningModeEndToEndTests](../../../tests/AAuth.Conformance/HttpSignatures/SigningModeEndToEndTests.cs), [ResourceManagedFlowTests](../../../tests/AAuth.Conformance/ResourceTokens/ResourceManagedFlowTests.cs); app topology in [capability matrix](capability-scenarios.md) |
| [Roles and policy evaluation L400](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L400) | [IAccessPolicy](../../../src/AAuth/Access/IAccessPolicy.cs), [Person endpoints](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs) | Policy: verified claims are not an authorization decision; deny/consent-needed tested in [DeferredFederationTests](../../../tests/AAuth.Conformance/Person/DeferredFederationTests.cs) |
| [Agent identifiers L544](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L544) | [Identifiers](../../../src/AAuth/Identifiers/) | Implemented: [AgentIdTests](../../../tests/AAuth.Conformance/Identifiers/AgentIdTests.cs), invalid names and byte-sensitive comparison |
| [Agent acquisition/structure L566](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L566), required claims and cnf | [AgentTokenBuilder](../../../src/AAuth/Tokens/AgentTokenBuilder.cs), [TokenVerifier](../../../src/AAuth/Tokens/TokenVerifier.cs) | Implemented: [AgentTokenStructureTests](../../../tests/AAuth.Conformance/AgentTokens/AgentTokenStructureTests.cs), [AgentTokenVerificationTests](../../../tests/AAuth.Conformance/AgentTokens/AgentTokenVerificationTests.cs); AP issuance/account identity is Policy |
| [Agent verification L609](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L609), signature before identity trust | [AAuthVerificationMiddleware](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs) | Implemented: [VerificationMiddlewareTests](../../../tests/AAuth.Conformance/HttpSignatures/VerificationMiddlewareTests.cs), forged issuer/PoP negative tests |
| [Authorization request/response L640](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L640), account/scope definitions, with/without resource token | [Challenge middleware](../../../src/AAuth/Server/Challenge/), [ResourceTokenBuilder](../../../src/AAuth/Tokens/ResourceTokenBuilder.cs) | Implemented: [ChallengeMiddlewareTests](../../../tests/AAuth.Conformance/HttpSignatures/ChallengeMiddlewareTests.cs), [ScopeVocabularyTests](../../../tests/AAuth.Conformance/ResourceTokens/ScopeVocabularyTests.cs) |
| [Agent-token requirement L748](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L748), no generic carrier substitution | [AAuthClientBuilder](../../../src/AAuth/AAuthClientBuilder.cs), resource verification | Implemented: [ClientCompositionTests](../../../tests/AAuth.Tests/HttpSig/ClientCompositionTests.cs), actual Inbox flows; HWK demonstrations explicitly generic |
| [AAuth-Access L761](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L761), opaque grammar, covered authorization | [ResourceManaged](../../../src/AAuth/Server/ResourceManaged/), [AAuthSigningHandler](../../../src/AAuth/HttpSig/AAuthSigningHandler.cs) | Implemented: [AAuthAccessTokenGrammarTests](../../../tests/AAuth.Conformance/ResourceTokens/AAuthAccessTokenGrammarTests.cs), [AAuthAccessSignedComponentTests](../../../tests/AAuth.Conformance/HttpSignatures/AAuthAccessSignedComponentTests.cs) |
| [Resource-managed authorization L781](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L781), agent/key/account binding | [ResourceManaged](../../../src/AAuth/Server/ResourceManaged/) | Implemented: [ResourceManagedFlowTests](../../../tests/AAuth.Conformance/ResourceTokens/ResourceManagedFlowTests.cs), [OpaqueTokenStoreTests](../../../tests/AAuth.Conformance/ResourceTokens/OpaqueTokenStoreTests.cs), account-aware store tests |
| [Resource-token structure L818](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L818), iss/aud/agent/cnf/scope/mission/account | [ResourceTokenBuilder](../../../src/AAuth/Tokens/ResourceTokenBuilder.cs) | Implemented: [ResourceTokenStructureTests](../../../tests/AAuth.Conformance/ResourceTokens/ResourceTokenStructureTests.cs), [AccountBindingTests](../../../tests/AAuth.Tests/Tokens/AccountBindingTests.cs) |
| [Resource and challenge verification L849](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L849), expiry, request/key/issuer binding | [TokenVerifier](../../../src/AAuth/Tokens/TokenVerifier.cs), [ChallengeHandler](../../../src/AAuth/Agent/ChallengeHandler.cs) | Implemented: resource-token and [TokenVerifierTests](../../../tests/AAuth.Tests/Tokens/TokenVerifierTests.cs); expired resource replacement is not a fresh unbounded grant |
| [PS token request L895](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L895), independent concurrent pending requests | [Person endpoints](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs) | Implemented: [PersonServerMapperTests](../../../tests/AAuth.Conformance/Person/PersonServerMapperTests.cs), owner/key checks and separate request state; user interaction scheduling is Policy |
| [PS response L930](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L930), consent before claims/grant delivery | Person endpoints and [AccessServerClient](../../../src/AAuth/Access/AccessServerClient.cs) | Implemented: PsDenialPreventsGrantWithoutAsClaimsRequest, FailedClaimsConsentNeverBecomesClaims, FederatedMissionGatePrecedesIdentityAndAccessServer in [DeferredFederationTests](../../../tests/AAuth.Conformance/Person/DeferredFederationTests.cs) |
| [Resource-initiated interaction L961](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L961), resource before PS consent L965, abandon on callback error L973 | [PersonResourceInteraction](../../../src/AAuth/Person/PersonResourceInteraction.cs), Person endpoints and configured BrowserConsentSessions | Implemented: PersonServerMapperTests callback state/browser/context/replay/error matrix; DeferredFederationTests success/denial before AS policy; [both Documents browsers](../../../tests/e2e/helpers/documents.ts) exercise permission, PS consent and signed download. Resource OAuth validation and browser-network controls remain host responsibilities |
| [Callback errors L995](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L995) | [Errors](../../../src/AAuth/Errors/), interaction clients | Implemented: [InteractionCallbackErrorTests](../../../tests/AAuth.Conformance/Errors/InteractionCallbackErrorTests.cs); callbacks do not substitute for signed terminal polling |
| [Clarification L1013](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1013), explicit response/update/cancel actions L1046 | [ClarificationExchange](../../../src/AAuth/Agent/ClarificationExchange.cs), PS/AS endpoints | Implemented: [ClarificationChatTests](../../../tests/AAuth.Conformance/Missions/ClarificationChatTests.cs), [PersonServerMapperTests](../../../tests/AAuth.Conformance/Person/PersonServerMapperTests.cs), [DeferredFederationTests](../../../tests/AAuth.Conformance/Person/DeferredFederationTests.cs); missing/mismatched action, foreign replacement and narrowed scope tested |
| [Clarification limits L1116](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1116) | ClarificationExchange, [DeferredExchange](../../../src/AAuth/Agent/DeferredExchange.cs) | Implemented bounded rounds/deadline: AsEnforcesClarificationRoundLimit and ClarificationDeadlineTerminatesBothPendingRequests; real AS answer and DELETE browser flows in both apps |
| [Permission L1128](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1128), signed agent and mission association | [GovernanceEndpoints.Authorize](../../../src/AAuth/Server/Governance/GovernanceEndpoints.cs), [mapper](../../../src/AAuth/DependencyInjection/AAuthGovernanceApplicationBuilderExtensions.cs), sample PS | Implemented: [GovernanceEndpointMapperTests](../../../tests/AAuth.Conformance/Missions/GovernanceEndpointMapperTests.cs), signed [MissionAgentFlowTests](../../../tests/AAuth.Tests/Integration/MissionAgentFlowTests.cs); unknown/foreign/approver/terminated failures have no policy/log side effects |
| [Audit L1184](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1184), required mission and 201 acknowledgement | Governance parsers/authorization, sample audit sink | Implemented: same signed boundary tests plus [GovernanceServerTests](../../../tests/AAuth.Conformance/Missions/GovernanceServerTests.cs); durable mission log retention is Policy |
| [Interaction L1242](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1242), relay/question/payment/completion, final poll authority | Governance mapper, [InteractionClient](../../../src/AAuth/Agent/Governance/InteractionClient.cs) | Implemented: [GovernanceDeferredConsentMapperTests](../../../tests/AAuth.Conformance/Missions/GovernanceDeferredConsentMapperTests.cs), [InteractionChainingTests](../../../tests/AAuth.Tests/Agent/InteractionChainingTests.cs); payment settlement/user-channel delivery is Policy |
| [Reauthorization L1338](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1338), agent expiry limits and renewed consent | PS/AS minting, [AuthTokenBuilder](../../../src/AAuth/Tokens/AuthTokenBuilder.cs) | Implemented: [IssuanceBoundsTests](../../../tests/AAuth.Conformance/AuthTokens/IssuanceBoundsTests.cs); Wallet fresh-grant recovery browser cases |
| [Mission creation/approval L1350](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1350), exact bytes/hash L1428 | [Mission](../../../src/AAuth/Agent/Mission.cs), governance builder/store | Implemented: [MissionS256Tests](../../../tests/AAuth.Conformance/Missions/MissionS256Tests.cs), [MissionModelTests](../../../tests/AAuth.Conformance/Missions/MissionModelTests.cs), HTTP mission approvals |
| [Mission log/completion/status L1432](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1432), permanently terminated L1449/L1455 | Governance mapper and PS state gates | Implemented terminal rejection: [MissionTerminatedTests](../../../tests/AAuth.Conformance/Missions/MissionTerminatedTests.cs), new signed three-endpoint tests and deferred completion tests. Production store permanence/retention is Policy |
| [Mission presentation L1488](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1488), no dereference L1490 and exact reference echo | [Mission header](../../../src/AAuth/Agent/Mission.cs), challenge/chain handlers | Implemented reference-only data flow: [MissionReferenceValidationTests](https://github.com/aauth-dev/dotnet-samples/blob/v0.10.0-alpha.1/tests/AAuth.Conformance/Missions/MissionReferenceValidationTests.cs), [MissionHeaderSeamTests](https://github.com/aauth-dev/dotnet-samples/blob/v0.10.0-alpha.1/tests/AAuth.Conformance/Missions/MissionHeaderSeamTests.cs), [MissionSignedComponentTests](https://github.com/aauth-dev/dotnet-samples/blob/v0.10.0-alpha.1/tests/AAuth.Conformance/HttpSignatures/MissionSignedComponentTests.cs). Resource/AS have no mission-fetch implementation; no arbitrary application callback guarantee |
| [PS-to-AS request L1503](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1503), child/upstream propagation and signing | [AccessServerClient](../../../src/AAuth/Access/AccessServerClient.cs), [AgentIssuanceContext](../../../src/AAuth/Tokens/AgentIssuanceContext.cs) | Implemented: [AccessServerClientTests](../../../tests/AAuth.Tests/AccessServerClientTests.cs), [DeferredFederationTests](../../../tests/AAuth.Conformance/Person/DeferredFederationTests.cs). Q2 uses normative Signature Keys jwks_uri discovery, not stale protocol example syntax |
| [AS response/delivery L1531](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1531), claims composition L1581 | AS endpoints, [AuthTokenResponseValidator](../../../src/AAuth/Tokens/AuthTokenResponseValidator.cs) | Implemented: [AuthTokenDeliveryTests](../../../tests/AAuth.Conformance/AuthTokens/AuthTokenDeliveryTests.cs), [MockAccessServerTests](../../../tests/AAuth.Tests/Integration/MockAccessServerTests.cs); reserved claim requests/pushes rejected |
| [Signed requested claims L1599](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1599) (#requirement-claims), [clarification action L1054](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1054) (#agent-response-to-clarification) | [TokenRequestBody](../../../src/AAuth/Server/TokenRequestBody.cs), [AS pending dispatch](../../../src/AAuth/Access/AAuthAccessServerEndpoints.cs) | Implemented, 2026-09-09 final repair: ClaimsPushPreservesRequestedCredentialNamedIdentity in [DeferredFederationTests](../../../tests/AAuth.Conformance/Person/DeferredFederationTests.cs) preserves policy-requested credential-like names and action values through signed HTTP issuance; trusted pending state controls dispatch. Raw duplicate/nested-duplicate and reserved/typed-identity failures leave policy and pending state unchanged; initial and updated-request malformed credential matrices retained |
| [Federation trust L1601](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1601), PS-AS collapse L1679 | Explicit configured trust and policy interfaces | Policy: configured trust/pairwise identity, no issuer-to-policy inference; [MockPersonServerFederationTests](../../../tests/AAuth.Tests/Integration/MockPersonServerFederationTests.cs). Organization visibility and directory policy require host integration |
| [Auth-token structure L1690](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1690), optional/reserved claims and expiry ceilings | AuthTokenBuilder, TokenVerifier | Implemented: [AuthTokenStructureTests](../../../tests/AAuth.Conformance/AuthTokens/AuthTokenStructureTests.cs), [IssuanceBoundsTests](../../../tests/AAuth.Conformance/AuthTokens/IssuanceBoundsTests.cs) |
| [Auth verification L1736](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1736), request binding and response validation | TokenVerifier, [AgentAuthTokenValidator](../../../src/AAuth/Tokens/AgentAuthTokenValidator.cs) | Implemented: [AuthTokenVerificationTests](../../../tests/AAuth.Conformance/AuthTokens/AuthTokenVerificationTests.cs), [ScopeNarrowingTests](../../../tests/AAuth.Conformance/AuthTokens/ScopeNarrowingTests.cs); optional sub is not manufactured by sample direct-AS policy |
| [Upstream verification L1766](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1766), AS/PS route L1784, directed sub L1800 | [UpstreamTokenValidator](../../../src/AAuth/Tokens/UpstreamTokenValidator.cs), [CallChainingRouter](../../../src/AAuth/Server/CallChaining/CallChainingRouter.cs) | Implemented: [UpstreamTokenValidationTests](../../../tests/AAuth.Conformance/AuthTokens/UpstreamTokenValidationTests.cs), DirectAsChainingUsesAccessMetadataAndAgentCarrier / RejectsUnboundAuthorization in DeferredFederationTests; distinct intermediary key and audience are preserved |
| [Interaction chaining L1819](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1819) | Concierge and shared interaction helpers | Implemented representative flows: [InteractionChainingTests](../../../tests/AAuth.Tests/Agent/InteractionChainingTests.cs), call-chain deferred browsers. Intermediary-owned pending storage requires its own ownership/retention controls; see review limits below |
| [Sub-agents L1825](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1825), single depth and parent authorization L1859 | AgentIssuanceContext, agent identifiers and token builders | Implemented: [PersonServerMapperTests](../../../tests/AAuth.Conformance/Person/PersonServerMapperTests.cs), four-party [FederatedWorkerScenario](../../../samples/FederatedWorkerScenario.cs) and both sub-agent browser specs |
| [Delegation chain L1874](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1874), actor nesting/no person identifiers | [ActChainBuilder](https://github.com/aauth-dev/dotnet-samples/blob/v0.10.0-alpha.1/src/AAuth/Tokens/ActChainBuilder.cs), [ActChainReader](https://github.com/aauth-dev/dotnet-samples/blob/v0.10.0-alpha.1/src/AAuth/Tokens/ActChainReader.cs) | Implemented: [ActChainBuilderTests](https://github.com/aauth-dev/dotnet-samples/blob/v0.10.0-alpha.1/tests/AAuth.Conformance/AuthTokens/ActChainBuilderTests.cs), [ActChainReaderTests](https://github.com/aauth-dev/dotnet-samples/blob/v0.10.0-alpha.1/tests/AAuth.Conformance/AuthTokens/ActChainReaderTests.cs) |
| [Third-party login L1928](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1928), conditional ps/start_path validation L2000 | Metadata field only | Optional unsupported by sample hosts. No login_endpoint flow is advertised/implemented by the migration; hosts enabling their own endpoint must validate PS discovery and same-origin relative start_path. Metadata serialization tests do not establish login conformance |
| [Capabilities L2010](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2010), ignore unknown/no assumed capabilities | [AAuthCapabilitiesHeader](../../../src/AAuth/Agent/AAuthCapabilitiesHeader.cs), exchange options | Implemented: [CapabilitiesHeaderTests](../../../tests/AAuth.Conformance/HttpSignatures/CapabilitiesHeaderTests.cs), client callback/capability tests |
| [Scopes L2034](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2034), identity scopes and account L2051 | Scope validation and [AccountBinding](../../../src/AAuth/Tokens/AccountBinding.cs) | Implemented: [ScopeVocabularyTests](../../../tests/AAuth.Conformance/ResourceTokens/ScopeVocabularyTests.cs), [AccountBindingTests](../../../tests/AAuth.Tests/Tokens/AccountBindingTests.cs), two-account Bookings/Events browsers |
| [Requirement responses L2061](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2061), code format L2124 and relay L2144 | Header parsers, [BrowserConsentSessions](../../../src/AAuth/Server/BrowserConsentSessions.cs) | Implemented: [InteractionCodeTests](../../../tests/AAuth.Tests/Headers/InteractionCodeTests.cs), [BrowserConsentSessionTests](../../../tests/AAuth.Tests/Server/BrowserConsentSessionTests.cs); code is not an approval credential |
| [Deferred responses L2206](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2206), GET/pending/terminal state L2258 | [DeferredState](../../../src/AAuth/Server/DeferredState.cs), [DeferredPoller](../../../src/AAuth/Agent/DeferredPoller.cs) | Implemented: [DeferredStateTests](../../../tests/AAuth.Tests/Server/DeferredStateTests.cs), new governance owner/cancel/first-decision/concurrency tests; injected stores need atomic contracts |
| [Error format L2302](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2302), error controls behavior, detail only | [AAuthProblemDetails](../../../src/AAuth/Server/AAuthProblemDetails.cs), typed clients | Implemented: [AAuthProblemDetailsTests](../../../tests/AAuth.Tests/Server/AAuthProblemDetailsTests.cs), [TokenErrorTests](../../../tests/AAuth.Conformance/Errors/TokenErrorTests.cs); no stale-error production rewrite performed in Phase 12 |
| [Polling errors L2336](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2336), slow_down and Retry-After | DeferredPoller / DeferredExchange | Implemented: [PollingErrorTests](../../../tests/AAuth.Conformance/Errors/PollingErrorTests.cs), [DeferredPollerTests](../../../tests/AAuth.Tests/Agent/DeferredPollerTests.cs), AccessServerClientTests mixed claims/clarification/new interactions; payment settlement remains external |
| [Revocation L2359](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2359), issuer-qualified identity/cascade/trusted revoker | [RevocationEndpoint](../../../src/AAuth/Server/RevocationEndpoint.cs), [RevocationClient](../../../src/AAuth/Server/RevocationClient.cs), IJtiStore | Implemented: [JtiStoreAndRevocationTests](../../../tests/AAuth.Conformance/Discovery/JtiStoreAndRevocationTests.cs), [RevocationLifecycleTests](../../../tests/AAuth.Conformance/Discovery/RevocationLifecycleTests.cs), both Wallet browser flows. Production persistence and cascade retry scheduling are Policy |
| [Algorithms/carriers L2403](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2403), jwt for AAuth L2418 | Crypto factories and verification policy | Implemented Ed25519/ES256 and six generic carriers; negative polymorphic/private/symmetric/unknown tests in [SignatureV10AdversarialTests](../../../tests/AAuth.Tests/HttpSig/SignatureV10AdversarialTests.cs) |
| [Covered components L2434](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2434), created/alg/keyid L2461 | Signer/verifier and structured fields | Implemented: [CoveredComponentsTests](../../../tests/AAuth.Conformance/HttpSignatures/CoveredComponentsTests.cs), [SignatureV10WireTests](../../../tests/AAuth.Tests/HttpSig/SignatureV10WireTests.cs); content-digest only where required, no universal invented mandate |
| [Verification/status L2471](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2471), unsupported negotiation and no signature headers on 403 | Verification middleware and typed errors | Implemented: [SignatureErrorTests](../../../tests/AAuth.Conformance/Errors/SignatureErrorTests.cs), [VerificationMiddlewareTests](../../../tests/AAuth.Conformance/HttpSignatures/VerificationMiddlewareTests.cs), new governance 403 assertions |
| [Freshness/replay L2503](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2503), honor expires, no nonce mechanism | Signer/verifier and short-lived signature replay store | Implemented: [ReplayDetectionMiddlewareTests](../../../tests/AAuth.Conformance/HttpSignatures/ReplayDetectionMiddlewareTests.cs), wire/adversarial tests. Wallet idempotent retries wait for a new created second; no nonce extension remains |
| [Discovery/cache L2509](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2509), identifiers/URLs L2523 | [Discovery](../../../src/AAuth/Discovery/), ServerId/AAuthUrl | Implemented: [IssuerDiscoverySecurityTests](../../../tests/AAuth.Tests/Discovery/IssuerDiscoverySecurityTests.cs), [DiscoveryCacheSecurityTests](../../../tests/AAuth.Tests/Discovery/DiscoveryCacheSecurityTests.cs), [EgressTransportTests](../../../tests/AAuth.Tests/Discovery/EgressTransportTests.cs) |
| [Metadata L2564](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2564), AP/PS/AS/resource fields | [Metadata endpoints](../../../src/AAuth/Server/Metadata/), MetadataClient | Implemented: [AllRolesWellKnownMetadataTests](../../../tests/AAuth.Conformance/Discovery/AllRolesWellKnownMetadataTests.cs), [ResourceAccessModeMetadataTests](../../../tests/AAuth.Conformance/Discovery/ResourceAccessModeMetadataTests.cs); issuer_missing/mismatch distinguished |
| [Security L2809](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2809), PoP/token/pending/input/approval/person binding | Verification, consent, egress and sample policies above | Implemented tested mechanics; Policy for secure key storage, authenticated user directory, deployment isolation, retention and monitoring. [KeycloakDiagnosticSecurityTests](../../../tests/AAuth.Tests/Integration/KeycloakDiagnosticSecurityTests.cs) prove IdP bodies are not leaked; [ActivityDiagnosticsTests](../../../tests/AAuth.Conformance/Observability/ActivityDiagnosticsTests.cs) excludes token material |
| [TLS L2892](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2892), audit after rotation L2896, privacy L2908 | Production egress defaults, explicit SampleEgress, typed audit stores | Policy: samples use admitted loopback HTTP only; production TLS, key custody, archival keys, privacy/retention and external interoperability require operator validation. No resource/AS mission body fetch path is added |
| [IANA L2924](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2924), history/rationale | Constants and metadata values | Inapplicable registration/expert procedures; wire constants tested. Historical/non-normative examples do not override active requirements |

## Final Authorization Repair Evidence

These focused regressions supplement the protocol rows; they do not mark the
independent Phase 14 review complete.

### Remaining Credential and Reference Repairs

The 2637-test checkpoint below is historical. The remaining repairs pass 2859
Release tests, 96 snippet/source-semantic checks, 71 full stub browsers plus
one live-only skip, and 72 full live browsers, retries=0. Fresh independent
review remains pending; no Phase 14/15 closure is implied.

| Canonical requirement | Repair and disposition |
|---|---|
| [Protocol L2316](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2316), #token-endpoint-error-codes | Implemented: [TokenRequestBody](../../../src/AAuth/Server/TokenRequestBody.cs#L12) uses strict duplicate-rejecting JSON/JWT structural reads for initial, pending replacement and claims paths. [DeferredFederationTests](../../../tests/AAuth.Conformance/Person/DeferredFederationTests.cs#L61) and [R3 endpoint tests](../../../tests/AAuth.R3.Tests/AccessEndpointR3Tests.cs#L47) cover credential shapes, missing claims, base64, signatures and expired parent/child/upstream context before policy/audit/document fetch. |
| [Protocol L2298](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2298), #error-responses | Implemented: [TokenFailure](../../../src/AAuth/Server/AAuthProblemDetails.cs#L9) preserves typed 400 token errors; expired agent/resource codes are distinct, upstream failures retain invalid_upstream_token, and genuine carrier failure remains 401 with Signature-Error. |
| [Protocol L614](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L614), Agent Token Verification; [L2517](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2517), #jwks-discovery | Resolved documentation: [signing-mode matrix](../../../docs/signing-modes/overview.md#L103) shows cached issuer JWKS discovery and separates embedded cnf.jwk from issuer verification. |
| [Protocol L2734](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2734), Resource Metadata | Resolved documentation: [configuration](../../../docs/reference/configuration.md#L203) and [DI](../../../docs/reference/dependency-injection.md#L361) distinguish nullable metadata keys and conditional issuance/signing requirements. [Whole-table checks](../../../tests/AAuth.Tests/Api/DocumentationApiExcerpts.cs#L66) validate source names, types and nullability across both reference pages. |

### Final Focused Input and State Repairs

Final implementation checkpoint: 2637 Release tests and a clean Release build;
93 snippet/source-semantic cases; 71 full stub browser passes plus one live-only
skip, and 72 full live Keycloak passes, retries=0. Host-only sample identities,
explicit development issuer mappings and both real worker scenarios are included.
Earlier failed reports, including an unattributed live clarification timeout,
remain in the append-only log. Independent Phase 14 review remains pending.

| Source and disposition | Repair and executable evidence |
|---|---|
| [Signature Keys invalid_jwt L2086](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L2086), section 5.4.11 | Local strict policy rejects all duplicate raw JWT names, including equal values and nested objects/arrays. `DuplicateRawMembersRejectBeforeDiscovery` independently signs raw compact input; direct/JWKS verification, naming/carrier parsing and HTTP middleware return typed invalid_jwt with zero discovery calls or trusted context. |
| [Agent identifiers L546](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L546), #agent-identifiers; [server identifiers L2529](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2529), #server-identifiers | `InvalidActorDomainsRejectAtEveryDepth` and `ActorDomainsUseExplicitPolicyWithoutSameProviderRequirement` cover immediate/nested actors, URI suffixes, blank/Unicode domains, ACE and distinct APs. HTTP/HTTPS development origins never admit actor ports. Builder, reader, token verifier and issuance/response contexts use the same explicit policy. |
| SDK source/refresh lifetime and binding contract, not a new normative wire requirement | `RefreshPipelinePreservesCurrentToken` covers eight fixed/factory and challenge/no-challenge cases; `CancellationDuringRefreshDoesNotPublishToken` rejects post-cancellation publication. `CachedCarrierTracksRefreshedSourceAndRequestBindings` checks source, key, account and mission cache isolation. |
| [R3 proposal parameters L562](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L562), #proposal-document | Explicit null is a concrete inline JSON value, distinct from missing parameter, null container and digest representation. `ExplicitNullParameterRoundTripsAndBindsExactRetry` and `TokenEndpoint_ProposalParametersRequireObject` prove policy receives null, deferred minting works, and exact retry rejects missing/non-null/digest substitutions. Duplicate object names reject before node materialization. |
| Optional provisioning boundary | `BootstrapEnrollmentHasConcreteKeyBoundaryButEnrolledRefreshDoesNot` records the existing concrete Ed25519 bootstrap convenience limit. Actual AP ES256 enrollment/publication remains covered by `ActualAgentProviderPublishesEnrolledEs256KeyAfterRestart`; no broad fluent ES256 enrollment claim is made. |

| Requirement | Repair and executable evidence |
|---|---|
| [Resource verification L859](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L859) | Initial and replacement AS resource tokens bind approver to the authenticated PS; collapsed/local PS verification also supplies its issuer. MissionApproverMustBeAuthenticatedPs and CollapsedPersonServerRejectsForeignApproverBeforeConsent reject before policy |
| [Mission approval L1416](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1416), [chaining L1788](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1788) | ValidateMissionAsync rejects unknown/foreign-owner/foreign-approver records before policy or resource interaction, retaining verified parent and upstream delegation. Clarification_UpstreamMissionCannotBeStrippedOrChanged preserves original state and termination checks |
| [Parent consent L1827](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L1827) | Mission_ParentConsentIdentitySurvivesClarification preserves consenting parent identity while worker agent/cnf remain bound to the worker |
| [Revocation L2390](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2390) | ThreeGenerationsRevokeAndNotifyAllLocalDescendants checks actual descendant rejection/notifications; TrackedIssuanceTests rejects cycles and concurrent extension of revoked ancestry. Local guarantees only; arbitrary stores and remote retry scheduling remain host contracts |
| [Privacy L2695](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L2695) | UnstructuredErrorsDoNotEnterExceptionDiagnostics and UnstructuredFederationErrorsNeverReachPersonLogs reject sentinel tokens, PII and forged log lines in exceptions and captured PS warnings |

## Signature Keys

| Requirement / canonical area | Owning code | Tests and disposition |
|---|---|---|
| [Section 3 L341](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L341), structured dictionary, labels/multiple signatures L430/L437 | [SignatureKeyHeader](../../../src/AAuth/HttpSig/SignatureKeyHeader.cs), [SignatureKeyParser](../../../src/AAuth/HttpSig/SignatureKeyParser.cs), verifier | Implemented using StructuredFieldValues; [SignatureV10WireTests](../../../tests/AAuth.Tests/HttpSig/SignatureV10WireTests.cs), [SignatureV10AdversarialTests](../../../tests/AAuth.Tests/HttpSig/SignatureV10AdversarialTests.cs) cover selected labels, escaping/types and malformed fields |
| [3.3 L462](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L462), alg/key consistency, public-only and unsupported distinction | [Crypto](../../../src/AAuth/Crypto/) | Implemented Ed25519 and ES256; [EcdsaKeyTests](../../../tests/AAuth.Conformance/HttpSignatures/EcdsaKeyTests.cs), adversarial key matrix. Other algorithms are unsupported, not silently substituted |
| [3.4 hwk L630](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L630) | HWK header/provider/parser | Implemented standard JWK members; [SignatureKeySchemesTests](../../../tests/AAuth.Conformance/HttpSignatures/SignatureKeySchemesTests.cs), wire vectors; legacy embedded-jwk shape rejected |
| [3.5 jkt-jwt L705](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L705), validation L891 | Naming JWT validation and key binding | Implemented: [NamingJwtValidationTests](../../../tests/AAuth.Conformance/HttpSignatures/NamingJwtValidationTests.cs), [JktJwtAndEcdsaTests](../../../tests/AAuth.Conformance/HttpSignatures/JktJwtAndEcdsaTests.cs); iat/exp/type/header-key/thumbprint/ephemeral binding |
| [3.6 jwks_uri L957](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L957), exact issuer and metadata discovery | Resolver, MetadataClient/JwksClient | Implemented id/dwk/kid; wire tests, missing/mismatched issuer, egress/cache tests; not a direct key URL alias |
| [3.7 jwks L1021](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L1021) | Direct JWKS provider/resolver | Implemented url/kid; direct Profile browser plus wire tests; generic identity, not an AAuth mode |
| [3.8 jwt L1091](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L1091), validation L1160 | DefaultSignatureKeyResolver, registered token verifiers | Implemented admitted key resolution plus explicit token-type validation; forged issuer with valid PoP rejected; unknown typ fails closed |
| [3.9 self-jwt L1222](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L1222), absent cnf L1307 and same key | Shared resolver and Events verifier | Implemented: wire tests and [EventHttpTests](../../../tests/AAuth.Events.Tests/EventHttpTests.cs); real Events delivery in both apps |
| [3.10 x509 L1370](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L1370), [3.11 cached L1429](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L1429) | Unsupported scheme dispatch | Optional unsupported per Q1. No certificate-chain, revocation-cache or cached-assertion implementation claimed |
| Accept-Signature negotiation / Signature-Error (sections 4-5) | [SignatureError](../../../src/AAuth/Errors/SignatureError.cs), middleware | Implemented: [SignatureErrorTests](../../../tests/AAuth.Conformance/Errors/SignatureErrorTests.cs); AAuth 401 vs generic policy distinguished, 403 has no authentication negotiation |
| Signature-Key-Cache (section 6) | No cache-carrier feature | Optional unsupported with cached scheme; mandatory ordinary metadata/JWKS caching remains implemented separately |
| [7.1 key validation L2257](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L2257), [7.2 caching L2283](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L2283) | Crypto and discovery caches | Implemented key/public-material checks and bounded synchronized fetch floor; discovery and crypto tests |
| [7.3 risks L2327](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L2327), egress, redirects, DNS and actual connection | AAuthEgressPolicy/AAuthHttpTransport | Implemented for SDK transport: EgressTransportTests real socket/private/redirect/mixed-DNS/oversize/timeout checks. Injected transport obligations are Policy |
| [7.4 algorithms L2425](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L2425), [7.5 symmetric prohibition L2485](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L2485) | KeyFactory and verifier algorithm admission | Implemented negative matrix; optional post-quantum algorithms not advertised |
| [7.6 cache identity L2504](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L2504), [7.7 sizes L2581](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L2581), [7.8 integrity L2603](../../../aauth-spec/v10/draft-hardt-httpbis-signature-key-08.txt#L2603) | Bounded parsing/HTTP; required signature-key coverage | Implemented required coverage; cached/PQ-specific requirements Optional unsupported; host proxy/header-size configuration is Policy |
| Privacy, registry and expert procedures | Public key identity and deployment policy | Policy for correlation/privacy; Inapplicable registry administration. No universal anonymity claim |

## R3

| Requirement / canonical area | Owning code | Tests and disposition |
|---|---|---|
| [Metadata L93](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L93), identifier scope L109 | [R3Metadata](../../../src/AAuth.R3/R3Metadata.cs) | Implemented: [R3VocabularyTests](../../../tests/AAuth.R3.Tests/R3VocabularyTests.cs), actual Catalog gateway definitions and sibling-service rejection browsers |
| [Eight vocabularies L115](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L115), MCP L121/OpenAPI L139/gateway L157/gRPC L194/GraphQL L212/AsyncAPI L231/WSDL L250/OData L268 | [R3Operation](../../../src/AAuth.R3/Model/R3Operation.cs), [R3VocabularySchemas](../../../src/AAuth.R3/Model/R3VocabularySchemas.cs), [R3OperationIdentity](../../../src/AAuth.R3/Model/R3OperationIdentity.cs) | Implemented typed shape/qualifier/directional subset semantics: all-vocabulary roundtrips, malformed identifiers, qualifier-preserving conditional retries and OData method narrowing. Native protocol hosting/discovery is a host responsibility; sample integrations are OpenAPI/gateway/AsyncAPI |
| [Authorization L287](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L287), operations spanning definitions L333 | R3Operations, R3Request, R3Metadata | Implemented: [AgentR3RequestTests](../../../tests/AAuth.R3.Tests/AgentR3RequestTests.cs), vocabulary collision and metadata tests |
| [Document L346](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L346), fields/account L370, content addressing L389 | R3Document/R3Hash/proposal store | Implemented exact bytes: [R3HashTests](../../../tests/AAuth.R3.Tests/R3HashTests.cs), [R3ModelTests](../../../tests/AAuth.R3.Tests/R3ModelTests.cs), stored-buffer isolation |
| [Resource token extensions L400](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L400), pointer/hash/account/agent | R3Challenge and token verification | Implemented: [TokenClaimTests](../../../tests/AAuth.R3.Tests/TokenClaimTests.cs), [ResourceR3Tests](../../../tests/AAuth.R3.Tests/ResourceR3Tests.cs) |
| [Processing L444](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L444), AS fetch/audit L453, cache L464 | R3FetchClient, R3AccessTokenEndpoint | Implemented hash/issuer/admission checks and audit-before-release; [AccessEndpointR3Tests](../../../tests/AAuth.R3.Tests/AccessEndpointR3Tests.cs). PS-reader permission is Ambiguous Q4, explicitly configured, not generic issuer trust |
| [Auth extensions L469](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L469), granted/conditional narrowing | R3Grant/claim reader/AS validation | Implemented: TokenClaimTests, AccessEndpointR3Tests; empty grants valid but empty requests rejected |
| [Enforcement L538](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L538), per-call proposals L550 | [R3Enforcement](../../../src/AAuth.R3/R3Enforcement.cs), proposal store | Implemented: ResourceR3Tests, R3VocabularyTests; wrong service/vocabulary/parameters/hash/account and missing vs empty parameters rejected |
| [Sensitive payloads L592](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L592) | R3Parameter/R3PresentedParameters | Implemented digest and exact byte checks, excerpt/display does not authorize content; caller data minimization is Policy |
| [Reader restriction L600](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L600), endpoint access L606, hashes L610 | R3DocumentReaderPolicy/R3DocumentEndpoint | Implemented verified designated-AS role plus explicit Q4 PS evaluation role; forged role/key tests. Ambiguous source readership statements remain logged |
| [Audit L614](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L614), authoritative operations L618, grants L622 | AS audit sink; resource R3Metadata/enforcement | Implemented sample SQLite write-before-release and resource authority: [R3SqliteAuditTests](../../../tests/AAuth.R3.Tests/R3SqliteAuditTests.cs), [BookingsPolicyTests](../../../tests/AAuth.R3.Tests/BookingsPolicyTests.cs). Injected durable stores and native definitions remain Policy |
| [IANA L626](../../../aauth-spec/v10/draft-hardt-aauth-r3.md#L626), experts/history/rationale | Vocabulary constants | Inapplicable registration/expert procedures; codec namespace validation tested |

## Events

| Requirement / canonical area | Owning code | Tests and disposition |
|---|---|---|
| [AP metadata L196](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L196), optional event endpoint | [EventsProtocol](../../../src/AAuth.Events/EventsProtocol.cs), MockAgentProvider | Implemented discovery; no endpoint means Events unsupported at that AP. Events browser discovery assertions |
| [Subscribe structure L212](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L212), required claims, alg, audience, expiry and positive max_uses | SubscribeTokenBuilder / EventsTokens | Implemented: [SubscribeTokenTests](../../../tests/AAuth.Events.Tests/SubscribeTokenTests.cs), [EventsTokenTests](../../../tests/AAuth.Events.Tests/EventsTokenTests.cs), malformed/foreign issuer/subject/key cases |
| [Presentation L254](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L254), verification L275 and context L288 | EventsProtocol/EventsSignatureTokenVerifier/receiver | Implemented jwt subscribe carrier and authenticated context; [EventHttpTests](../../../tests/AAuth.Events.Tests/EventHttpTests.cs), both public/protected browser flows |
| [Public registration L294](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L294), protected tickets L298 | BookingsEvents/SqliteEventStore | Implemented owner/key/account-bound registration, consume-once tickets, idempotent registration: EventHttpTests and [EventPersistenceTests](../../../tests/AAuth.Events.Tests/EventPersistenceTests.cs) |
| [Event structure L349](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L349), absent cnf L368 and no event-specific claims | EventTokenBuilder/EventsTokens | Implemented self-jwt structure/alg/aud/eid/expiry and payload separation: EventsTokenTests/EventHttpTests |
| [Delivery L385](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L385), same signer and body integrity | EventsProtocol / AP delivery endpoint | Implemented actual signed HTTP and raw body forwarding; malformed/signature/issuer failures tested. Ambiguous Q5 privacy wording is not used to invent a payload wrapper |
| [AP validation L411](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L411), atomic quota L421 and durable-before-202 L424 | Events endpoints and configured SqliteEventStore | Implemented for sample backend: EventHttpTests/EventPersistenceTests, competing quota, failed write, restart, receipt retry, unknown/expired eid and wrong aud/resource |
| [Remaining uses L424](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L424), unlimited subscription response | Same AP/store | Implemented bounded integer or empty unlimited response; quota is not inferred from token expiry alone |
| [AP-to-agent L439](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L439), final verification L445 and deduplication L454 | EventReceiver and durable context/receipt store | Implemented agent issuer/audience/expiry/context checks and issuer/eid deduplication. AP transport is Policy: sample uses authenticated bounded polling/ack, not standardized push |
| [Discovery L458](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L458), AsyncAPI security L491 | BookingsEvents AsyncAPI document | Implemented actual document and aauth-subscribe scheme; both app specs inspect it |
| [Security L583](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L583), replay/tickets/intermediary/enumeration | Events verifier, stores and AP enrollment ownership | Implemented sample protections: [EnrollmentHttpTests](../../../tests/AAuth.Events.Tests/EnrollmentHttpTests.cs), EventHttpTests/EventPersistenceTests. TLS/key custody/storage ACL/rate policy are deployment responsibilities |
| [Privacy L617](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L617), content L623 | Namespace assignment and raw payload delivery | Ambiguous recurring eid/dedup semantics: sample is single-shot, literal dedup; no new per-event jti. Payload minimization is resource policy, AP is not confidential from payload by design |
| [IANA L627](../../../aauth-spec/v10/draft-hardt-aauth-events.md#L627), history and non-normative delivery examples | Token/vocabulary constants | Inapplicable registry administration and platform examples; no cloud/mobile delivery claim |

## Injected Contracts And Review Limits

- IMissionStore/IMissionLog/IDeferredConsentStore are development in-memory
  defaults. Production stores must preserve owner context, exact mission bytes,
  monotonic decisions/termination, shared atomicity and terminal retention.
  DeferredState serializes a shared in-process entry; it cannot serialize two
  independent objects loaded by a custom distributed provider. That provider
  must supply transactional compare-and-set behavior and equivalent retention.
- Events acceptance requires durable event+quota+receipt state before 202. The
  configured SQLite provider has restart/concurrency/failure tests. Arbitrary
  implementations of the interfaces are not certified by those tests.
- R3 audit sinks must commit before release. Sample SQLite tests cover actual
  persistence; a callback returning success before a durable write violates its
  contract even though the SDK cannot inspect its implementation.
- Injected HttpClient/HttpMessageHandler and R3 fetch callbacks explicitly declare
  their transport contract. AttachPolicy is not a socket sandbox. Production
  callers must enforce URL, DNS, connected-address, redirect, timeout and size
  admission; InProcessOnly is a test contract, not a production bypass.
- Policy callbacks must use authenticated principal context and correct directed
  identifiers. The SDK cannot prove a tenant directory, account mapping or human
  identity assertion supplied by a host. Stub consent is isolated demo behavior;
  Keycloak mode must never use stub approve/deny as an authorization fallback.
- The reusable governance mapper and sample PS reject unknown/foreign mission
  actions and recheck mission status before deferred delivery. Concierge pending
  entries now require the exact verified upstream grant, retain terminal state,
  expire with that grant and serialize delivery/cancellation. Six signed-host
  cases in [ConciergePendingSecurityTests](../../../tests/AAuth.Tests/Integration/ConciergePendingSecurityTests.cs)
  reject foreign agent/key/grant GET and DELETE, then prove owner cancellation
  and terminal replay. The new direct-AS route creates no intermediary pending entry.
- Live external HTTPS interop and production storage deployments are not covered
  by local browser/tests. Optional X.509/cached, third-party login hosting and
  native platform transports remain explicitly unsupported or application-owned.

## Verification

### Phase 13 local interop and documentation

The five informational interop surfaces run locally through the existing
sample/test harness; they are not five external interoperability passes:

| Surface | Executed local evidence | External disposition |
|---|---|---|
| S1 mission approval and exact blob hash | GovernanceClientTests approval/header/body/PS binding and S256 mismatch; both mission browsers | Not exercised against an external PS |
| S2 signed mission presentation and challenge echo | MissionHeaderSeamTests, MissionSignedComponentTests, MissionReferenceValidationTests; both mission/call-chain browsers | Not exercised externally |
| S3 resource issuance and issuer discovery | ResourceTokenStructureTests, ResourceTokenVerificationTests, AllRolesWellKnownMetadataTests; captured resource challenges in both apps | External whoami responded with its live person-token requirement, not the pinned auth-token challenge |
| S4 auth issuance, audience and proof binding | AuthTokenVerificationTests, AuthTokenDeliveryTests, both stub/live federated and mission browser flows | LiveWhoAmITest full authorization returned 401 person_token_required; incomplete |
| S5 distinct-key four-party parent/worker | FederatedWorkerScenario in both sub-agent browser specs, including parent-key rejection and child/act assertions; PS/AS endpoint regressions | Not exercised externally |

LiveWhoAmITest reached whoami through its normal public metadata tunnel.
Unsigned 401 and agent-JWT identity 200 were observed; full external authorization
was not established. Its zero process exit did not override the 401 wire result.
No person consent was approved and no legacy person-token compatibility was added.

The current [docs surface map](docs-surface-map.md) records exact file/block
hashes, validation classes and source/test links. It supersedes the earlier
representative 21-template limit for documentation inventory, without relabeling
external/platform templates or dynamic displays as compiled signed requests.
That Phase 13 checkpoint recorded 196 files, +761/-149 declarations and zero
unmapped files. It is historical, not the current Phase 14 API count: the review
repairs change challenge verification dependencies and sample instructional
surfaces. The generated API/docs maps and current repair checkpoint below govern
the updated worktree; freshness must be checked after the final edits.

### Phase 14 focused review repair checkpoint

Resource challenge verification now precedes exchange and binds the original
origin, presented token, signing key, account and mission. The 70-test focused
challenge gate passes, including invalid-signature/cross-origin rejection without
PS calls or consent, mutable-holder isolation, routing and Calendar consent.
Canonical challenge ordering: [L868](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L868).

R3 AS issuance now checks mission approver against the authenticated PS and
validates upstream mission retention before document/policy/audit work. Verified
mission survives immediate and deferred AS delivery through the real PS federation
client. The endpoint suite passes 94/94. The actual AP endpoint publishes ES256
correctly before and after registry restart; enrollment suite passes 11/11.

Four documentation checks cover constructor tables, actual signing-key selection,
mandatory recipient context and generic routes; ten exact Documents/Events step
templates compile. Both shared browser helpers cover step/diagram/snippet
association and full reset/reexecution. The repaired Release gate passes 2234
tests (1059 core, 878 conformance, 222 R3, 75 Events), with zero failures/skips.
Release and make builds have zero warnings/errors. Fresh stub browsers pass
71 with the existing live-only skip; fresh live Keycloak passes all 72, with
zero retries, failures or flaky results in either mode. Desktop/mobile captures
cover both apps, diagrams and associated snippets. Current API inventory is
198 files, +790/-152 declarations and zero unmapped; docs inventory is 169 files,
629 blocks, including 272 exact C# blocks. Final non-writing freshness checks
are recorded in the implementation log. Phases 14 and 15 remain open for fresh
independent review; local Keycloak does not establish external interop.

### Phase 14 final mandatory-claim and PS-role repair coverage

The append-only implementation log records the final confirmed-review repair
matrix and exact profile assumptions. Independently signed malformed JWTs cover
the required agent/resource/auth claims at direct verification and JWKS entry
points, with matching agent/auth middleware cases before trusted context. The
central checker covers typed values, optional PS/parent identifiers, nested
mission/actor fields, NumericDate bounds and auth lifetime. Required absence and
explicit null both fail. Generic JWT iat/jti presence stays optional and the
registered verifier hook is exercised, not bypassed by a builder-only assertion.

Core AS token/pending gates now require the verified person-server metadata role
before issuer trust or access policy. Distinct/shared collocated role keys and
wrong-key PS-role spoofing are covered across issuance, poll and claims push,
including no policy side effects and legitimate recovery. Direct agent-JWT
chaining remains covered separately. Named provider parameters are compiled;
mission-recipient XML and Profile generic-admission comments are source-checked.
The 2234/198/629 checkpoint above is historical. Final verified checkpoint:

| Gate | Final Result |
|---|---|
| Release solution build | Zero warnings/errors |
| Release solution tests | 2596 passed: 1421 core, 878 conformance, 222 R3, 75 Events; zero failures/skips; +362 from 2234 |
| Full fresh stub browsers | 71 passed, one existing live-only skip; zero retries/unexpected/flaky |
| Full fresh live Keycloak browsers | 72 passed: 40 tour, 32 app; zero skips/retries/unexpected/flaky |
| Snippets and source semantics | 92 passed; named constructor arguments and recipient/Profile guidance checked |
| API inventory | 198 changed public-source files; +790/-152 declarations; zero unmapped; non-writing freshness passes |
| Documentation inventory | 169 files, 629 blocks, 272 exact C# compilations; final non-writing freshness passes |
| Browser TypeScript and scoped whitespace | Pass |

The latest reports and reproducible runner use the prefix
/tmp/aauth-phase14-final-remaining-; tests.log, final-trx/, stub.json and
live.json contain the authoritative final counts. The implementation log retains
failed runs, fixture repairs and spec/profile decisions. Independent review and
Phase 15 remain pending; local Keycloak is not external AAuth interoperability.

### Phase 12 adversarial repair evidence

The eight owner-supplied findings were independently checked in the current
worktree. Findings 1-3 already contained production repairs; mapped-route tests
now include unauthenticated/foreign GET and DELETE, changed ownership, terminated
permission delivery without log append, and terminal PS interaction denial.
[GovernancePendingSignatureTests](../../../tests/AAuth.Conformance/Missions/GovernancePendingSignatureTests.cs)
adds eight actual signed HTTP cases, not injected verification features.

The mission approval and lifecycle rows now include
[GovernanceClientTests](../../../tests/AAuth.Conformance/Missions/GovernanceClientTests.cs)
and [GovernanceFacadeTests](../../../tests/AAuth.Conformance/Missions/GovernanceFacadeTests.cs):
header/body/bound-PS agreement, missing approver rejection, exact bytes, completion,
terminal errors/callbacks and no further pre-approved or network actions.
References: #mission-approval L1430 and #mission-status-errors L1469.

The deferred/polling rows now include
[DeferredExchangeTests](../../../tests/AAuth.Tests/Agent/DeferredExchangeTests.cs)
and [DeferredTimingTests](../../../tests/AAuth.Tests/Agent/DeferredTimingTests.cs):
approval without a user callback, bare 202, changed interaction URL/code, initial
Retry-After delta/date, persistent five-second linear backoff, default/past dates,
503, bounded timeout and cancellation. The new timing tests use injected clock
and delay, not sleeps. References: approval L2202 and polling L2262.

Live revocation recovery is no longer inferred from stub coverage: the retained
callback trace exposed an invisible completion title, repaired with encoded
visible outcome text. Both apps' focused live recovery cases pass with fresh
settings and zero retries in /tmp/aauth-phase12-repairs-keycloak.json. Original
failures, HTTP regressions and final full-suite gates are retained in the
append-only implementation log. Catalog and parent/worker attribution are unchanged.

### Historical Phase 12 gates

Final repair gate: 2069/2069 Release tests (965 core, 827 conformance, 206 R3,
71 Events), zero failures/skips; Release build zero warnings/errors; 21 exact
snippet templates; TypeScript typecheck and scoped whitespace check pass.
All 68 live-Keycloak browser cases pass (38 tour, 30 app) with zero skips;
stub mode passes 67 with the one existing live-only skip. Both full suites use
fresh services, isolated settings, retries=0 and retained traces, with zero
unexpected/flaky results. Final reports are
/tmp/aauth-phase12-repairs-live-final.json and
/tmp/aauth-phase12-repairs-stub-final.json. Original failed/interrupted reports
remain recorded in the implementation log; none are silently replaced as passes.

The eight supplied findings and live callback/recovery gate have no remaining
open in-scope finding. The clarification POST/DELETE path preserves terminal
mission errors, and virtual timers prove non-cooperative callback/request bounds.
Catalog and parent/worker scenarios pass in both final full suites. These results
do not certify arbitrary injected stores/policies or remove the deployment and
optional-feature dispositions above. Phase 13/14 remain separate gates.

Initial full Release run was blocked by a duplicate solution project registration;
the duplicate was removed and the repeated suite passed 2005 tests, zero failures
or skips (928 core, 800 conformance, 206 R3, 71 Events). Four exact new snippet
cases bring template coverage from 17 to 21. Seven activity tests verify no token
material in diagnostics. Two IdP error-body tests reproduced disclosure and pass
after removing response bodies; real consent HTML encoding also passes.

These are intermediate executed results. Final full Release/build, both browser
projects, live Keycloak, catalog lifecycle and ledger checks are recorded in the
final implementation-log entry. Phase 13 remains open. No vendor bytes, branch
or commits were changed by this phase.