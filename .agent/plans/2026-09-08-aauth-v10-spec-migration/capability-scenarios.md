# Capability Scenarios

Baseline: ba768f1. Cross-checked against [api-surface-map.md](api-surface-map.md),
the Phase 1-11 findings, current sample routes and the browser specs below.
An API declaration is not automatically a new end-user workflow. Mandatory
validation, transport contracts and typed codecs have negative tests; protocol
workflows have executable pages in both apps. Native gRPC, SOAP and GraphQL
applications are not claimed by a codec test or by an HTTP gateway.

## Runnable Workflows

Both apps use the existing Playwright projects. Links below identify the actual
page or flow implementation; spec paths identify assertions, not inferred
coverage from unrelated successful requests.

| Capability | Flow | GuidedTour entry | SampleApp entry | Resource purpose | Playwright evidence and limits |
|---|---|---|---|---|---|
| Resource-initiated interaction before PS consent | Document Release | [/documents](../../../samples/GuidedTour/Components/Pages/Documents.razor) | [/documents](../../../samples/SampleApp/Components/Pages/Documents.razor) | Work document release, not external OAuth simulation | [shared Documents specs](../../../tests/e2e/helpers/documents.ts): real AP enrollment, signed challenge/poll/download, session/CSRF continuation, ordinary-consent bypass rejection, resource success/denial, account/scope preservation and reset/layout |
| Signed enrollment, provider-assigned agent identity | Existing setup; new Wallet setup | [/wallet-protocol](../../../samples/GuidedTour/Components/Pages/WalletProtocol.razor), step 1 | [/wallet-protocol](../../../samples/SampleApp/Components/Pages/WalletProtocol.razor), step 1 | AP provisions an agent, not a resource authorization party | [shared Wallet specs](../../../tests/e2e/helpers/wallet-protocol.ts) execute enrollment again after reset; [bootstrap](../../../samples/GuidedTour/playwright-tests/bootstrap.spec.ts) covers the tour ceremony |
| Self-issued agent JWT and PS authorization | Existing Autonomous / Calendar | [TourSession](../../../samples/GuidedTour/TourSession.cs), Autonomous selector | [/calendar](../../../samples/SampleApp/Components/Pages/Jwt.razor) | Calendar reads a person's events | [autonomous](../../../samples/GuidedTour/playwright-tests/autonomous.spec.ts), [jwt](../../../samples/SampleApp/playwright-tests/jwt.spec.ts): signed resource challenge, PS grant, resource response |
| Agent JWT plus opaque resource-managed access | Existing Inbox | [TourSession](../../../samples/GuidedTour/TourSession.cs), ResourceManaged selector | [/inbox](../../../samples/SampleApp/Components/Pages/Inbox.razor) | Inbox imports trip confirmations | [resource-managed](../../../samples/GuidedTour/playwright-tests/resource-managed.spec.ts), [inbox](../../../samples/SampleApp/playwright-tests/inbox.spec.ts): AP/local setup, authenticated consent, opaque credential and replay; no PS/AS resource exchange |
| Generic hwk, jkt-jwt and direct jwks signing | Existing generic Profile flows | [TourSession](../../../samples/GuidedTour/TourSession.cs), identity selectors | [Hwk](../../../samples/SampleApp/Components/Pages/Hwk.razor), [JktJwt](../../../samples/SampleApp/Components/Pages/JktJwt.razor), [JwksUri](../../../samples/SampleApp/Components/Pages/JwksUri.razor) | Profile exposes travel preferences using explicitly generic Signature Keys | [identity](../../../samples/GuidedTour/playwright-tests/identity.spec.ts), [hwk](../../../samples/SampleApp/playwright-tests/hwk.spec.ts), [jkt-jwt](../../../samples/SampleApp/playwright-tests/jkt-jwt.spec.ts), [jwks-uri](../../../samples/SampleApp/playwright-tests/jwks-uri.spec.ts); not described as AAuth resource modes |
| Authenticated deferred consent | Existing Deferred | [TourSession](../../../samples/GuidedTour/TourSession.cs), Deferred selector | [/calendar-deferred](../../../samples/SampleApp/Components/Pages/Deferred.razor) | Calendar consent | [deferred tour](../../../samples/GuidedTour/playwright-tests/deferred.spec.ts), [deferred app](../../../samples/SampleApp/playwright-tests/deferred.spec.ts): 202, authenticated session/CSRF, approval/poll transitions |
| Four-party authorization and claims policy | Existing Federated | [TourSession](../../../samples/GuidedTour/TourSession.cs), Federated selector | [/wallet](../../../samples/SampleApp/Components/Pages/Federated.razor) | Wallet delegates policy to its AS | [federated tour](../../../samples/GuidedTour/playwright-tests/federated.spec.ts), [federated app](../../../samples/SampleApp/playwright-tests/federated.spec.ts), [live Keycloak](../../../samples/SampleApp/playwright-tests/federated-deferred.spec.ts): issuer, directed identity and consent. Claims push is also covered by actual AS endpoint tests, not inferred from every browser grant |
| Mission creation, permissions, audit and completion | Existing mission flows | [TourSession](../../../samples/GuidedTour/TourSession.cs), Mission selector | [/trips](../../../samples/SampleApp/Components/Pages/Mission.razor) | Trips is mission-aware travel planning | [mission tour](../../../samples/GuidedTour/playwright-tests/mission.spec.ts), [mission app](../../../samples/SampleApp/playwright-tests/mission.spec.ts); foreign/unknown/terminated cases are HTTP regressions, not artificial UI controls |
| PS clarification and mission call chaining | Existing mission chain | [TourSession](../../../samples/GuidedTour/TourSession.cs), MissionCallChain selector | [/mission-call-chain](../../../samples/SampleApp/Components/Pages/MissionCallChain.razor) | Concierge orchestrates Trips under a mission | [mission-chain tour](../../../samples/GuidedTour/playwright-tests/mission-call-chain.spec.ts), [mission-chain app](../../../samples/SampleApp/playwright-tests/mission-call-chain.spec.ts): question, answer, actor/mission propagation |
| PS-routed and interaction-chained calls | Existing CallChain | [TourSession](../../../samples/GuidedTour/TourSession.cs), CallChain selector | [/call-chain](../../../samples/SampleApp/Components/Pages/CallChain.razor) | Concierge orchestrates Calendar access | [call-chain tour](../../../samples/GuidedTour/playwright-tests/call-chain.spec.ts), [call-chain app](../../../samples/SampleApp/playwright-tests/call-chain.spec.ts), [deferred chain](../../../samples/SampleApp/playwright-tests/call-chain-deferred.spec.ts): downstream consent and resource result |
| Parent-mediated child and combined upstream delegation | Existing SubAgent | [TourSession](../../../samples/GuidedTour/TourSession.cs), SubAgent selector | [/sub-agent](../../../samples/SampleApp/Components/Pages/SubAgent.razor) | Wallet read delegated through distinct parent/worker keys | Both [tour](../../../samples/GuidedTour/playwright-tests/sub-agent.spec.ts) and [app](../../../samples/SampleApp/playwright-tests/sub-agent.spec.ts) execute [FederatedWorkerScenario](../../../samples/FederatedWorkerScenario.cs), including parent-key rejection |
| Account selection and account-bound R3 approval | Existing RichRequests / Bookings | [TourSession](../../../samples/GuidedTour/TourSession.cs), RichRequests selector | [/bookings](../../../samples/SampleApp/Components/Pages/Bookings.razor) | Bookings owns personal/work reservation accounts | [richrequests](../../../samples/GuidedTour/playwright-tests/richrequests.spec.ts), [bookings](../../../samples/SampleApp/playwright-tests/bookings.spec.ts): actual account claims, selected account and per-call consent |
| R3 unconditional and conditional operations, proposal integrity | Existing RichRequests / Bookings | Same RichRequests entry | Same Bookings entry | Search, hold and confirm a reservation | Same two specs check numbered flow and proposal consent; byte/parameter tampering and audit failure have [resource HTTP tests](../../../tests/AAuth.R3.Tests/ResourceR3Tests.cs) |
| Events public registration | Existing Events public channel | [/events](../../../samples/GuidedTour/Components/Pages/Events.razor) | [/events](../../../samples/SampleApp/Components/Pages/Events.razor) | Bookings announces availability | [shared Events specs](../../../tests/e2e/helpers/events.ts): discover AsyncAPI/AP metadata, subscribe JWT, HTTP 202 delivery, agent receipt and duplicate ignored |
| Events protected registration and account context | Existing Events protected work account | Same Events page | Same Events page | Account-authorized reservation notifications | Same Events specs: real PS consent/ticket, work account, durable receipt/ack and payload; recurring delivery ambiguity remains explicit |
| AS clarification, PS relay, answer and cancellation | **New Wallet Clarification** | [/wallet-protocol](../../../samples/GuidedTour/Components/Pages/WalletProtocol.razor), AS clarification option | [/wallet-protocol](../../../samples/SampleApp/Components/Pages/WalletProtocol.razor), same option | Wallet review requires a travel justification before normal AS policy | Both [tour spec](../../../samples/GuidedTour/playwright-tests/wallet-protocol.spec.ts) and [app spec](../../../samples/SampleApp/playwright-tests/wallet-protocol.spec.ts) invoke shared tests: real clarification_response, wallet.review grant, rejected charge; separate DELETE cancellation/reset case |
| No-mission direct-AS chaining | **New Wallet DirectAs** | Same page, Direct AS chaining option | Same page and option | Concierge reads Wallet on an existing AS grant | Shared Wallet spec: AS-issued upstream with no mission, AS-issued downstream, Concierge agent and actor chain, 401 when upstream grant is presented directly to Wallet, repeated call. The capture sees resource requests, not the builder's separate exchange channel; direct-AS body validation belongs to HTTP endpoint tests |
| Issuer-qualified token revocation and recovery | **New Wallet Revocation** | Same page, Issuer-qualified revocation option | Same page and option | Owner withdraws an issued Wallet grant through the PS | Shared Wallet spec: agent revoker 403, signed PS withdrawal twice with HTTP 200, revoked resource call 401, fresh grant with different jti and recovered read |
| Service-qualified OpenAPI gateway operations | **New Catalog Gateway** | [/catalog-gateway](../../../samples/GuidedTour/Components/Pages/Catalog.razor) | [/catalog-gateway](../../../samples/SampleApp/Components/Pages/Catalog.razor) | Read two travel catalogs, each with operationId list | Both [tour spec](../../../samples/GuidedTour/playwright-tests/catalog.spec.ts) and [app spec](../../../samples/SampleApp/playwright-tests/catalog.spec.ts) invoke [shared assertions](../../../tests/e2e/helpers/catalog.ts): actual definitions, selected service, sibling 403, reauthorization and recovery for both service selections |

## Internal Contracts And Exclusions

These rows are not substitutes for missing end-user workflows. They classify
low-level API changes from the public delta and the explicitly excluded optional
capabilities. Their evidence is executable SDK/host tests, not new UI.

| API-map group / capability | Disposition | Evidence |
|---|---|---|
| Problem details and typed errors | Shared wire correction; all live flows consume it | [problem-details tests](../../../tests/AAuth.Tests/Server/AAuthProblemDetailsTests.cs), endpoint error assertions |
| Verified issuance ceiling, reserved claims and narrowed delivery | Internal token security contract | [IssuanceBoundsTests](../../../tests/AAuth.Conformance/AuthTokens/IssuanceBoundsTests.cs), [AuthTokenDeliveryTests](../../../tests/AAuth.Conformance/AuthTokens/AuthTokenDeliveryTests.cs) |
| Six carrier codecs, fully specified algorithms and selected labels | Generic carrier support plus AAuth profile restrictions | [SignatureV10WireTests](../../../tests/AAuth.Tests/HttpSig/SignatureV10WireTests.cs), [SignatureV10AdversarialTests](../../../tests/AAuth.Tests/HttpSig/SignatureV10AdversarialTests.cs); Events is the actual self-jwt workflow |
| Discovery admission, caches and injected transports | Internal security and deployment contract | [EgressTransportTests](../../../tests/AAuth.Tests/Discovery/EgressTransportTests.cs), [DiscoveryCacheSecurityTests](../../../tests/AAuth.Tests/Discovery/DiscoveryCacheSecurityTests.cs) |
| All eight typed R3 vocabularies | Model and enforcement support, not eight native transport implementations | [R3VocabularyTests](../../../tests/AAuth.R3.Tests/R3VocabularyTests.cs): Shapes_RoundTripDocumentRequestClaimsAndProposal, AllVocabularies_MatchReorderedObjectsAndBindConditionalRetries, OptionalMembers_ArePartOfIdentity, OData_MultiMethodGrantCoversIndividualCallWithoutWidening. Runnable protocol integrations are OpenAPI, OpenAPI Gateway and AsyncAPI; native MCP/gRPC/GraphQL/SOAP/OData sample services are not claimed |
| Consent owner/key/account binding, tombstones and atomic delivery | Internal enforcement of every applicable live consent flow | [BrowserConsentSessionTests](../../../tests/AAuth.Tests/Server/BrowserConsentSessionTests.cs), [GovernanceDeferredConsentMapperTests](../../../tests/AAuth.Conformance/Missions/GovernanceDeferredConsentMapperTests.cs), signed [MissionAgentFlowTests](../../../tests/AAuth.Tests/Integration/MissionAgentFlowTests.cs) |
| Fluent composition and ownership | Existing builders retained; low-level fixed token usage only for explicit steps | [ClientCompositionTests](../../../tests/AAuth.Tests/HttpSig/ClientCompositionTests.cs), [SnippetCompilationTests](../../../tests/AAuth.Tests/Api/SnippetCompilationTests.cs) |
| Persistent provider contracts | Operator responsibility; configured SQLite implementations tested | [Events persistence](../../../tests/AAuth.Events.Tests/EventPersistenceTests.cs), [R3 audit persistence](../../../tests/AAuth.R3.Tests/R3SqliteAuditTests.cs); arbitrary injected implementations are not certified |
| X.509 and cached Signature Keys | Unsupported optional, Phase 0 Q1 | Unsupported-scheme tests; no compatibility parser or fake UI |
| Platform-native attestation and AP-agent push transports | Extension points / deployment choices | Bootstrap software keys and polling are real; hardware assurance and mobile push are not claimed |
| Payment settlement | External protocol, not an AAuth payment implementation | Payment requirement/cancellation tests exercise response handling; no fake settlement UI |

## Resource Decisions

- Wallet remains a travel wallet: review and revocation concern its own grants.
- Concierge remains a travel intermediary: the direct-AS wallet read is another
  travel orchestration path, with the existing WithCallChaining builder.
- Bookings remains reservations, including reservation events and accounts.
- Catalog is the Phase 12 resource process, at localhost:5006. It reads travel
  catalogs and demonstrates service-qualified authorization with colliding
  operation names. It contains no payments, Events or unrelated endpoints.
- Documents is the final authorization-repair resource at localhost:5007. It
  owns one document-release permission and requires that permission as well as
  the PS grant on download. It does not extend Catalog or fabricate OAuth.
- CapabilitySupport is a shared Razor library, not a server. It prevents the two
  apps' runtime steps/snippets from diverging and uses the existing SDK clients.

Catalog is registered once in AAuth.slnx, Makefile resources/demo and the shared
Playwright webServer array. SampleEgress admits only its explicit loopback origin.
CI already discovers the app-local specs through the shared Playwright projects.
Reset creates a fresh agent/session; Catalog domain data and definitions are
immutable, so no unauthenticated reset endpoint or external database is needed.

## Verification Record

### Final Authorization Repairs

Full fresh-service stub suite: 71 passed, one existing live-only skip. Full live
Keycloak suite: 72 passed, no skips. Both use retries=0, with zero unexpected or
flaky results. The four added Documents cases execute actual resource permission
and denial in both apps; all 68 baseline live cases remain. Reports:
/tmp/aauth-final-stub.json and /tmp/aauth-final-live.json. CSS-only follow-up
passes the same four Documents cases with final screenshots in
/tmp/aauth-final-documents-layout3-results/. The timeout attempts and memory
recovery are retained in the implementation log.

Full Release: 2160 passed, zero failed/skipped. Documentation inventory: 169
files, 617 blocks, 261 exact compiled C# blocks; 80 docs checks pass. API map:
197 changed public-source files, +777/-149 declarations, zero unmapped files,
verified current. These supersede the earlier counts below, not their recorded
evidence limitations. Independent Phase 14/15 gates remain open.

### Phase 13 documentation alignment

The [docs surface map](docs-surface-map.md) now covers both primary apps and
shared scenario sources, including raw/multiline/single-line C# strings, quoted
Markdown fences, inline Razor code, dynamic payloads and shell/JSON/HTTP examples.
Wallet's guide follows its actual 5/6/8 steps; Catalog follows five steps and
the destinations/experiences service labels. Both guides link the existing shared
Playwright wrappers, not a second test harness. Catalog has a single-purpose
resource README, and both app READMEs/indexes expose the new routes.

Final Phase 13 full fresh-service results: 67 stub passes plus one live-only
skip, and 68 live-Keycloak passes, zero unexpected/flaky results, retries=0.
Reports: /tmp/aauth-phase13-stub-release.json and
/tmp/aauth-phase13-live-release.json. Initial display/timing failures and the
14-case focused recovery run remain in the log. Final Release passes 2128 tests;
80 documentation test cases include 261 exact compiled blocks and separately
classified excerpts/templates/displays. These supersede the representative
21-template boundary below, which records the earlier Phase 12 checkpoint.

### Phase 12 checkpoint

Final policy-mode matrix: all 68 live cases pass (38 GuidedTour, 30 SampleApp),
and stub mode passes 67 with the one existing live-only skip. Both runs use
fresh services, isolated settings and retries=0, with no failures/flaky results.
The four new scenarios, Catalog's two service selections, worker attribution,
callbacks and reset/layout assertions are included in both full runs. Reports:
/tmp/aauth-phase12-repairs-live-final.json and
/tmp/aauth-phase12-repairs-stub-final.json. Exact snippet compilation passes 21
templates. The make demo entry point also starts both apps and Catalog on fresh
settings; final readiness endpoints return 200.

The adversarial repair pass retains all four new selectable scenarios and
Catalog's single resource purpose. Wallet recovery now labels its fresh-grant
consent callback in the numbered step, sequence row and exact compiled snippet.
The shared Keycloak driver waits for the actual AS callback outcome; successful
popup completion still does not replace signed token/resource assertions.
Existing AS approval/denial and parent/worker tests now execute both policy modes
without owner-excluding worker coverage. Five focused live AS/worker cases and
four live Catalog cases pass with fresh settings and retries=0. The earlier
full-live failures and replacement full-suite evidence remain in the log.

Initial Wallet browser run: four passed, four failed. Repairs and reasons are
recorded in [implementation-log.md](implementation-log.md), not hidden by retries.
The second run passed six cases; two direct-AS assertions overclaimed the capture
surface. Corrected observable assertions then passed both direct-AS cases.
Catalog fresh-service run passed all four cases. These focused runs establish
12 new browser cases for four selectable scenarios across the two apps, including
two cancellation cases and both catalog service selections. Full final browser
and policy-mode counts belong in the final gate entry, not these earlier results.

Every new flow checks its numbered list, sequence row count, corresponding C#
snippet, navigation, reset/re-enrollment and desktop/narrow layout. New snippets
are compiled exactly alongside the original 17 templates. Screenshots exposed
and drove a contrast repair in the dark GuidedTour host. Phase 13's repository-wide
documentation and snippet sweep remains separate.