# Public API surface map

Phase 11, 2026-09-09. Implementation baseline: `ba768f1`. This is the complete migration source inventory,
not a claim that the trailing Phase 12 security review or Phase 13 docs sweep
has finished. The generated appendix includes tracked and untracked SDK source.

Historical status (Phase 13, 2026-09-09): Phase 12 security closure and Phase 13
documentation alignment are complete; the paragraphs reporting Phase 11 totals
below retain that checkpoint's history. API freshness then covered 196 changed files,
+761/-149 declarations and zero unmapped files. The current
[docs inventory](docs-surface-map.md) replaces representative snippet coverage
with every discovered display block and explicit validation classes. Final
Release is 2128 tests; browsers are 68 live and 67 stub plus one live-only skip.
Independent Phase 14 review and Phase 15 post-review alignment remain open.

Final authorization repairs supersede that checkpoint's source surface:
197 changed public-source files, +777/-149 declarations, zero unmapped files,
with non-writing freshness verified. The generated appendix includes the new
Documents session and current mission consent contracts. Full Release is 2160
passed; browsers are 72 live and 71 stub plus one live-only skip. Details are in the
[implementation log](implementation-log.md); this update does not complete the
independent review.

Current Phase 14 repair checkpoint (2026-09-09): 198 changed public-source files,
+790/-152 declarations, zero unmapped files. `ChallengeHandler` now takes the
shared verifier, metadata and JWKS clients; the builder owns its discovery
dependencies while manual hosts retain ownership. Verification precedes any
exchange and uses the original signed request context. R3 issuance retains
verified mission and checks the authenticated PS approver. The sample AP exposes
an entry marker for actual-host testing and a configurable isolated key directory.
Documents/Events provide ten exact compiled step templates. Full Release passes
2234 tests; fresh browsers pass 72 live and 71 stub plus one live-only skip,
all with zero retries. This supersedes earlier counts, not independent review.

## Reading the map

Final Phase 14 focused repair delta (2026-09-09): 200 changed public-source files,
+800/-162 declarations, zero unmapped files. `AgentId.Parse/TryParse`, the actor
builder/reader helpers, `ActChainsMatch`, and `AgentAuthTokenValidator.Validate`
accept an optional explicit egress policy; production remains the default.
Agent domains remain host-only even under HTTPS loopback origin admission.
`R3Parameter.Json` and `Inline` accept nullable JSON values through a non-null
parameter wrapper. Factory-backed refresh-only clients retain live sources and
check cancellation before publishing renewed state. These ownership and null
semantics are covered by the focused tests in the append-only implementation log.
Bootstrap enrollment still exposes concrete Ed25519 keys; the documented limit
does not apply to algorithm-neutral single-key refresh or signing/verification.
No compatibility alias, new enrollment abstraction, or independent-review closure
is implied by this source inventory.

Remaining-repair checkpoint (2026-09-09): 201 changed public-source files,
+810/-162 declarations, zero unmapped files. `TokenRequestBody.ReadAsync`
returns structurally checked but unverified JSON; only subsequent verification
can establish trusted claims. `TokenCredential`, the exception's optional
credential context, `UpstreamTokenValidationResult.FailureCode`, and
`AAuthProblemDetails.TokenFailure` preserve typed token/expiry classification
without treating body parameters as failed request authentication. Existing
success bodies and trust boundaries are unchanged. Tests cover every credential
field, raw duplicate JSON, pending replacement/claims non-mutation, and carrier
401 headers. Release passes 2859 tests; independent review remains open.

Each concept row applies to every explicitly listed file/member in its appendix
group. The appendix records exact old/new declarations, including defaults and
mandatory inputs, rather than relying on the earlier phase handoff lists.
Behavior-only changed files are retained. Spec references name concepts, not
required .NET method names. Public options and store interfaces remain explicit
capabilities; convenience never grants trust, selects accounts or manufactures
verified context.

Reproduce with `dotnet run --project tools/ApiSurface -- . ba768f1 --write`.
Omit `--write` to fail on a stale inventory. Roslyn comes from the installed .NET
SDK, so no new NuGet package is needed. The source scanner inventories declared
APIs, not binary compatibility or compiler-generated member expansion.

## Agent clients

| Spec concept | Existing entry point | New low-level contract | Chosen convenience | Ownership/defaults | Callers/snippets | Validation |
|---|---|---|---|---|---|---|
| Agent provisioning, distinct from Signature-Key scheme | Bootstrap, From, Enrolled, SelfIssuing | EnrolWithKeyAsync; optional requested ID; EnrollResult.AgentId | Bootstrap.WithKey/WithEgressPolicy; Enrolled.RefreshingFrom.WithKeyStore | Signed enrollment; provider assigns identity; default production admission; factory owns HTTP, store/key borrowed | SampleApp EnrollmentService; AgentConsole; GuidedTour enrollment | AP enrollment HTTP tests; BootstrapTests; snippet compilation |
| Issued agent JWT as resource credential | From(EnrollResult), UseJwt | Fixed token and Func<string> carrier APIs | From defaults to enrollment AgentToken, never key URL; UseJwt parameter is token, not agentToken | No network at construction; no implicit refresh/topology; explicit scheme after refresh disables refresh; later refresh selects jwt | AgentConsole; docs bootstrap and JWT; fixed auth-token tour steps | ClientCompositionTests carrier matrix |
| AP refresh with fixed durable key | Enrolled, AgentProviderTokenRefresher.Create | ITokenRefresher; TokenRefreshContext.Account; admitted refresh transport | Direct resource-managed forwarder; ToBuilder transition | Built pipeline owns factory refresher/client; injected refresher/client borrowed; reuse builds independent owned resources; cancellation forwarded | SampleApp Inbox; docs resource-managed | ClientCompositionTests; AgentProviderTokenRefresherTests; TokenRefreshHandlerTests |
| Two-key AP refresh | AgentProviderClient.RefreshTwoKeyAsync | TwoKeyRefreshResult.EphemeralKey/AgentToken | Keep explicit advanced result; no rotating-key wrapper | Fixed-key Enrolled rejects TwoKey; raw refresher supports advanced coordinated rotation; no stale fixed signer | JktJwt generic demonstration; AgentConsole | Both refresh carriers captured; fixed-key rejection regression |
| Self-issued agent token | SelfIssuing.As.WithKid | SelfIssuedTokenRefresher with explicit egress policy | WithResourceManagedAccess, WithInteractionHandling, ToBuilder | Locally issues aa-agent+jwt with cnf; not self-jwt; issuer/key must be published; key borrowed | GuidedTour Inbox; SampleApp Calendar/Bookings | SelfIssuingBuilderTests; ClientCompositionTests; browsers |
| Challenge, deferred, clarification and chaining | WithChallengeHandling, WithInteractionHandling, WithCallChaining, WithMission | DeferredExchange/ClarificationExchange; required action; exact token/account context | Existing options already express callbacks, polling and mission; retain advanced exchange/poller | Flow options do not choose carriers; PS/AS requests require agent JWT; origin/account/key-bound carriers | GuidedTour individual steps; SampleApp deferred/federated/mission | Core challenge, clarification, deferred and chain tests; full browsers |

## Discovery

Phase 12 adds `DeferredPollerOptions.TimeProvider` and
`InteractionHandler.TimeProvider`, both defaulting to `TimeProvider.System`.
These borrowed clock sources control Retry-After dates, elapsed budgets, delays
and cancellation deadlines; no production timing requirement becomes optional.
The internal delay hook exists only for deterministic friend-assembly tests.
Mission state keeps its public init-only API; session completion and terminal
errors now update its one-way internal lifecycle. Approval bytes remain exact.

| Spec concept | Existing entry point | New low-level contract | Chosen convenience | Ownership/defaults | Callers/snippets | Validation |
|---|---|---|---|---|---|---|
| Admitted metadata, JWKS and interaction URLs | MetadataClient, JwksClient, AAuthUrl, ServerId | AAuthEgressPolicy, AAuthHttpTransport, AAuthTransportContract, bounded cache inputs, URI ResolveKeyAsync | WithEgressPolicy/WithDevelopmentLoopback across provisioning builders; DI discovery options | Production rejects private/HTTP destinations; explicit narrow development origins; injected transport declares obligations; MetadataClient disposes internally created HTTP only | All sample hosts use SampleEgress; tests use InProcessOnly; AP refresh now honors supplied transport | Discovery policy/cache/transport tests; AP transport regression; R3 ownership tests |

## Signatures

| Spec concept | Existing entry point | New low-level contract | Chosen convenience | Ownership/defaults | Callers/snippets | Validation |
|---|---|---|---|---|---|---|
| Six Signature-Key carriers and fully specified algorithms | UseHwk/UseJwt/UseJktJwt/UseJwksUri, key factories, signer/verifier | UseJwks, UseSelfJwt, typed key-validation errors, structured fields, resolver context, SignAsync, ISignatureTokenVerifier | Keep one selector per actual scheme; custom provider and sign-only operation remain advanced | No selector authorizes a resource; jwt token purpose independent; default AAuth verification disallows generic carriers; Ed25519/ES256, public key material | Generic Profile demos vs AAuth access flows; Events uses self-jwt for event tokens only | SignatureConformanceTests and negative carrier fixtures; override matrix; Events verification |
| Authenticated assertions vs parsed claims | AAuthVerifier, UseAAuth, GetAAuthVerification | AAuthVerifiedAssertion; typed verification results/options | Existing middleware/context extensions; companion verifier opt-in | Required issuer/type/key/audience/expiry/replay checks preserved; no fluent trusted-claims shortcut | PS/AS/R3/Events endpoints; SDK DI | Conformance verification, wrong-token and forged-context tests |

## Tokens

| Spec concept | Existing entry point | New low-level contract | Chosen convenience | Ownership/defaults | Callers/snippets | Validation |
|---|---|---|---|---|---|---|
| Verified issuance ceilings and claim ownership | AuthTokenBuilder, ResourceTokenBuilder, AgentTokenBuilder, TokenVerifier | AgentTokenExpiresAt; AgentIssuanceContext; reserved claims; AuthTokenExpiredException; AgentAuthTokenValidator | Existing object initializers with required verified context; no optional expiry overload | Agent/auth/delegation ceilings explicit; caller cannot replace reserved claims; stale deferred approvals rejected | PS/AS endpoints; R3 issuance; sample issuer snippets | Token builder, deferred expiry, reserved-claim and conformance tests |
| Account selection and grant narrowing | ResourceTokenBuilder/TokenExchangeRequest | AccountBinding; account-aware verification and upstream validators | Required request Account on existing request objects, not a global implicit selection | Exact opaque account value; omission distinct; resource-token/auth-token/R3 binding; PS not an account selector | Bookings personal/work flows; AAuthRequestOptions | Account isolation tests, R3 subset tests, both browser accounts |
| Delegation and sub-agent hierarchy | ActChainBuilder/Reader, UpstreamTokenValidator | Validated child/parent context; narrower identities and expiration | Existing builders and validators retained | No invented trusted parent or unbounded lifetime; exact key/audience/mission/chain checks | FederatedWorkerScenario; SubAgent flow | Core/conformance delegation; R3 worker cases; full browsers |

## Consent

Resource-token `interaction` is now coordinated by the internal
`PersonResourceInteraction`, mapped under the configured PS `InteractionPath`.
`AAuthPersonServerOptions.ResourceInteractionSessions` borrows the host's
authenticated browser authorization configuration; its default denies people
without authorization. `PersonPendingEntry.AwaitingResourceInteraction` is the
public host guard before presenting or recording ordinary consent. Callback
state and resource snapshots stay internal, not caller-mutable approval APIs.
Both Documents apps use the same `DocumentDemoSession`; its low-level exchanges
are deliberate numbered steps, not a second authorization protocol.

| Spec concept | Existing entry point | New low-level contract | Chosen convenience | Ownership/defaults | Callers/snippets | Validation |
|---|---|---|---|---|---|---|
| Authenticated human consent vs correlation code | PS/AS endpoint mappers and pending stores | BrowserConsentSessions, BrowserConsentIdentity, decision artifacts; DeferredState, owner/generation-bound stores | Retain explicit service/store contracts and endpoint options | Correlation alone is not approval; signed pending operations require stored verified owner; browser decision requires identity/session/CSRF; production decision capability opt-in | MockPersonServer, Federated AS, R3 AS, Inbox consent pages | HTTP owner/key/correlation/CSRF/terminal races; live Keycloak bypass tests |
| PS claims and AS authorization/clarification | AccessServerClient, IAccessPolicy, IIdentityClaimsAsserter | Expanded requests, pending snapshots, decision results, explicit clarification action | Existing policy interfaces and options; no wrapper around policy decisions | Trust and authorization explicit; claims assertion not AS authorization; retries retain narrowed request and account | Federated policy; PS triage/relay; sample consent | AS clarification, client normalization, consent generation tests |

## Resource managed

| Spec concept | Existing entry point | New low-level contract | Chosen convenience | Ownership/defaults | Callers/snippets | Validation |
|---|---|---|---|---|---|---|
| Agent JWT plus opaque AAuth-Access | WithResourceManagedAccess, AddAAuthResourceManaged | Account/key-qualified IAAuthAccessStore, AAuthRequestOptions, owner-aware pending/opaque stores | Direct Enrolled and SelfIssuing forwarders; existing server module | No PS/AS exchange; default isolated in-memory cache; authorization covered by signature; required account/key context preserved | Both Inbox pages and six tour steps | Actual Inbox consent browsers; ClientCompositionTests replay/party assertions; resource-managed owner isolation |

## Revocation

The existing inventory API now checks all locally retained ancestors under its
registration lock, rejects cycles and prevents extension after revocation.
The endpoint traverses descendants with a visited set and notifies each recorded
grant. No API claims global remote revocation or distributed transactional
guarantees for custom providers.

| Spec concept | Existing entry point | New low-level contract | Chosen convenience | Ownership/defaults | Callers/snippets | Validation |
|---|---|---|---|---|---|---|
| Issuer-qualified revocation and cascades | MapAAuthRevocation, IJtiStore | TokenKey, TokenRegistration, TokenGrant, RevocationClient, expanded AAuthRevocationOptions | Keep endpoint/client pair and typed registration; no alias to jti-only API | (iss,jti) identity; authenticated caller issuer; durable/idempotent store and cascade obligations explicit; production providers implement persistence | PS/AS token issuance and revocation; conformance fixtures | JtiStoreAndRevocationTests; HTTP mixed-issuer/cascade/retry tests |

## Governance

`MissionTokenConsentContext.ConsentAgentId` distinguishes the consenting parent
from the worker's token identity. `UpstreamAuthorization` retains verified
delegation and `ValidatedApproval` is SDK-set after local owner/approver checks;
host policy cannot set that property outside the assembly. Immediate and deferred
identity assertions use the same consenting principal, while tokens remain bound
to the worker. Replacement resource tokens cannot discard an upstream mission.

| Spec concept | Existing entry point | New low-level contract | Chosen convenience | Ownership/defaults | Callers/snippets | Validation |
|---|---|---|---|---|---|---|
| Mission/permission/audit/interaction and call chaining | BuildGovernance, AAuthGovernanceClient.Create, MissionSession | Expanded consent/log/mission context and expiry; disposable facade | Existing facade now accepts enrolled/self-issued configuration; no additional wrapper | Build owns signed and discovery channels; constructor/Create borrow; explicit PS and verified mission context; no implicit approval | MissionAgent; SampleApp mission pages; advanced docs | Governance tests; builder ownership test; mission browser cases |

## R3

| Spec concept | Existing entry point | New low-level contract | Chosen convenience | Ownership/defaults | Callers/snippets | Validation |
|---|---|---|---|---|---|---|
| Eight vocabularies, operation subsets and typed identity | R3Document, R3Operation, R3Operations, R3Request | R3OperationIdentity, R3VocabularySchemas, qualifiers, proposal/readership models | Existing R3Operation factories and document object initializers | Vocabulary-specific validation and directional coverage remain mandatory; no generic wildcard wrapper | Bookings HTTP, GraphQL, gRPC, MCP etc. fixtures; R3 docs | All R3 vocabulary, projection and subset tests |
| R3 discovery, proposals, audit and authorization | R3FetchClient, R3DocumentEndpoint, R3AccessTokenEndpoint, R3Enforcement | R3DocumentReaderPolicy, required agent/account/expiry, bounded process-lifetime proposal storage, audit headers/options | Existing endpoint/fetch/request APIs; R3ProposalStore(maxEntries: 1024) | Explicit signed PS readership; exact bytes/hash, no eviction of published references, no restart durability, proposal ownership, admission, failure-before-release audit | Bookings/R3 AS; both apps; representative request snippets | Full R3 suite, real HTTP two-account and tamper regressions, unexpired-grant retention and capacity tests; bookings/richrequests browsers |

## Events

| Spec concept | Existing entry point | New low-level contract | Chosen convenience | Ownership/defaults | Callers/snippets | Validation |
|---|---|---|---|---|---|---|
| Subscribe vs event JWT purpose | New companion; shared core verifier/signer | EventsProtocol, SubscribeTokenBuilder, EventTokenBuilder, EventsTokens, EventsSignatureTokenVerifier | AddAAuthEvents registers explicit verifier capability; existing token builders | Subscribe jwt binds AP namespace/agent/key; event self-jwt has no cnf; no implicit generic token acceptance | EventSupport, MockAgentProvider, Bookings, EventAgent | SubscribeTokenTests, EventTokenTests, real HTTP forged issuer/context tests |
| Subscription, bounded inbox and durable delivery | Events endpoint extensions, EventReceiver | Durable subscription/delivery/receipt store interfaces and request/result objects | Keep typed endpoints/receiver; no wrapper that hides transactional provider obligations | Atomic quota/ticket/receipt/account binding; SQLite is sample-owned, not SDK default persistence; signed body, deduplication and restart safety explicit | Both Events pages; AP sample; AsyncAPI registration | Events HTTP/SQLite tests and four browser flows; lost-response replay tests |

## DI

| Spec concept | Existing entry point | New low-level contract | Chosen convenience | Ownership/defaults | Callers/snippets | Validation |
|---|---|---|---|---|---|---|
| Explicit server capabilities and policy | AddAAuthAgent/Discovery/Resource/Federation/ResourceManaged, UseAAuth, governance mappers | Expanded options, AAuthFederationOptions, contextual endpoint inputs | Reuse options/registrations; AddAAuthEvents in companion | Fail closed without issuer/trust/authorization policy; registered transport obligations and service lifetimes explicit; no convenience trust bypass | Every sample Program; dependency-injection docs | DI pipeline/trust diagnostics, HTTP endpoint integration and full solution |

## Server contracts

| Spec concept | Existing entry point | New low-level contract | Chosen convenience | Ownership/defaults | Callers/snippets | Validation |
|---|---|---|---|---|---|---|
| Problem details, response shaping, endpoint requirements and metadata | Existing clients, mappers, requirement/header helpers | AAuthProblemDetails, AuthTokenResponse; Detail rename; new metadata/endpoint context | Reuse shared result/writer and options; removed old error aliases | error controls behavior; application/problem+json; successful responses unchanged; scopes/account/expiry context not inferred | PS/AS/R3/resource endpoints and all error consumers | Problem-details HTTP tests; conformance error and scope tests |

## Sample runtime

| Spec concept | Existing entry point | New low-level contract | Chosen convenience | Ownership/defaults | Callers/snippets | Validation |
|---|---|---|---|---|---|---|
| Runnable providers, consent decisions and primary-app workflows | Sample hosts, TourSession, EnrollmentService, EventDemoSession | Public sample policies/SQLite stores, enrollment identity records, R3 catalogs and UI state | Existing SDK builders and explicit sample services; no packaged sample facade | Sample runtime is not a production SDK API; host/circuit owns clients/state, persisted private keys stay local, consent policy requires authenticated sessions; loopback/demo admission is explicit | All primary-app steps, console scenarios and sample endpoints | Full compiled solution, fresh browser stack, live Keycloak, Events/R3 HTTP persistence tests |

## Review scope

Protocol [L2420](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2420)
and [L2422](../../../aauth-spec/v10/draft-hardt-oauth-aauth-protocol.md#L2422)
(#keying-material) require JWT resource credentials. Inbox remains conformant
resource-managed access, not generic pseudonymous signing. GuidedTour self-issues
locally; SampleApp signs AP enrollment on first use and lazily refreshes. Issuer
metadata/key discovery is verification, not PS/AS authorization. The Profile
pseudonymous endpoints remain separately labeled generic demonstrations.

The inventory includes public SDK and sample runtime declarations; tests are
verification callers, not exported runtime API. Compilation coverage is
representative, not one executable snippet per declaration. Interface contracts
are exercised by their existing provider/consumer tests. External production
provider deployment, arbitrary OAuth comparisons, all Phase 12 security closure
and the final Phase 13 docs sweep are not implied by a passing Phase 11 gate.

Final evidence: 1967 Release tests (913 core, 777 conformance, 206 R3, 71 Events),
zero failures/skips; Release/make builds zero warnings/errors. All 56 browser
cases pass across fresh stub and live-Keycloak policy configurations, retries=0.
Exact snippet compilation: 17 cases (8 GuidedTour, 4 Razor, 5 docs). The inventory
contains 154 SDK and 28 sample-runtime changed public-source files. Default DI
requires AgentToken/TokenRefresher or an explicit generic SignatureKeyProvider;
no implicit HWK fallback. Metadata and JWKS clients both dispose internal HTTP
only. No known Phase 11 finding remains open; see the implementation log for
failures, repairs, provenance and mobile screenshot evidence.

<!-- generated-public-api-delta -->

## Complete declaration delta

Baseline `ba768f1`; 201 changed public-source files, 810 added/replacement declarations, 162 removed/replaced declarations.

Generated from all current SDK source files, including untracked additions, and the baseline tree. Public/protected declarations include containing namespaces/types, overload parameters, required members, attributes, optional defaults, primary constructors and interface members. Compiler-synthesized/inherited members are represented by their source declarations, not expanded. Unchanged signatures in changed files are listed by containing type as behavior-review entries; the concept table above supplies their entry point, ownership, callers and tests. No source file is excluded by guessed file role.

### samples/CapabilitySupport/CatalogDemoSession.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [CatalogDemoSession.cs](../../../samples/CapabilitySupport/CatalogDemoSession.cs).

```diff
+ AAuth.Samples.Capabilities.CatalogDemoSession: public Func < Task > ? Changed { get ; set ; }
+ AAuth.Samples.Capabilities.CatalogDemoSession: public List < ScenarioExchange > Exchanges { get ; } = [ ]
+ AAuth.Samples.Capabilities.CatalogDemoSession: public async Task NextAsync ( CancellationToken cancellationToken )
+ AAuth.Samples.Capabilities.CatalogDemoSession: public int Step { get ; private set ; }
+ AAuth.Samples.Capabilities.CatalogDemoSession: public static string [  ] Steps { get ; } = [ "Discover catalog services" , "Authorize selected service" , "Read selected catalog" , "Reject a sibling-service grant" , "Authorize sibling and recover" ]
+ AAuth.Samples.Capabilities.CatalogDemoSession: public string ? ConsentUrl { get ; private set ; }
+ AAuth.Samples.Capabilities.CatalogDemoSession: public string ? Result { get ; private set ; }
+ AAuth.Samples.Capabilities.CatalogDemoSession: public string OtherService
+ AAuth.Samples.Capabilities.CatalogDemoSession: public string Service { get ; set ; } = "destinations"
+ AAuth.Samples.Capabilities.CatalogDemoSession: public void Dispose ( )
+ AAuth.Samples.Capabilities: public sealed class CatalogDemoSession ( string provider , string person , string resource ) : IDisposable
```

Public owners: `AAuth.Samples.Capabilities.CatalogDemoSession`, `AAuth.Samples.Capabilities`.

### samples/CapabilitySupport/DocumentDemoSession.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [DocumentDemoSession.cs](../../../samples/CapabilitySupport/DocumentDemoSession.cs).

```diff
+ AAuth.Samples.Capabilities.DocumentDemoSession: public Func < Task > ? Changed { get ; set ; }
+ AAuth.Samples.Capabilities.DocumentDemoSession: public List < ScenarioExchange > Exchanges { get ; } = [ ]
+ AAuth.Samples.Capabilities.DocumentDemoSession: public async Task NextAsync ( CancellationToken cancellationToken )
+ AAuth.Samples.Capabilities.DocumentDemoSession: public bool Denied { get ; private set ; }
+ AAuth.Samples.Capabilities.DocumentDemoSession: public int Step { get ; private set ; }
+ AAuth.Samples.Capabilities.DocumentDemoSession: public static string [  ] Steps { get ; } = [ "Enroll document agent" , "Request document release" , "Authorize document access" , "Download released document" ]
+ AAuth.Samples.Capabilities.DocumentDemoSession: public string ? ConsentUrl { get ; private set ; }
+ AAuth.Samples.Capabilities.DocumentDemoSession: public string ? Result { get ; private set ; }
+ AAuth.Samples.Capabilities.DocumentDemoSession: public void Dispose ( )
+ AAuth.Samples.Capabilities: public sealed class DocumentDemoSession ( string provider , string person , string resource ) : IDisposable
```

Public owners: `AAuth.Samples.Capabilities.DocumentDemoSession`, `AAuth.Samples.Capabilities`.

### samples/CapabilitySupport/ScenarioWireHandler.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [ScenarioWireHandler.cs](../../../samples/CapabilitySupport/ScenarioWireHandler.cs).

```diff
+ AAuth.Samples.Capabilities.ScenarioWireHandler: protected override async Task < HttpResponseMessage > SendAsync ( HttpRequestMessage request , CancellationToken cancellationToken )
+ AAuth.Samples.Capabilities.ScenarioWireHandler: public static JsonNode ? Display ( string ? text )
+ AAuth.Samples.Capabilities.ScenarioWireHandler: public static JsonObject Claims ( string token )
+ AAuth.Samples.Capabilities: public sealed class ScenarioWireHandler ( Action < ScenarioExchange > record ) : DelegatingHandler
+ AAuth.Samples.Capabilities: public sealed record ScenarioExchange ( string Method , string Url , int Status , string ? Scheme , string ? Requirement , JsonNode ? Request , JsonNode ? Response )
```

Public owners: `AAuth.Samples.Capabilities.ScenarioWireHandler`, `AAuth.Samples.Capabilities`.

### samples/CapabilitySupport/WalletDemoSession.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [WalletDemoSession.cs](../../../samples/CapabilitySupport/WalletDemoSession.cs).

```diff
+ AAuth.Samples.Capabilities.WalletDemoSession: public Func < Task > ? Changed { get ; set ; }
+ AAuth.Samples.Capabilities.WalletDemoSession: public List < ScenarioExchange > Exchanges { get ; } = [ ]
+ AAuth.Samples.Capabilities.WalletDemoSession: public WalletFlow Flow { get ; set ; }
+ AAuth.Samples.Capabilities.WalletDemoSession: public async Task NextAsync ( CancellationToken cancellationToken )
+ AAuth.Samples.Capabilities.WalletDemoSession: public bool Cancelled { get ; private set ; }
+ AAuth.Samples.Capabilities.WalletDemoSession: public int Step { get ; private set ; }
+ AAuth.Samples.Capabilities.WalletDemoSession: public static JsonSerializerOptions Pretty { get ; } = new ( ) { WriteIndented = true }
+ AAuth.Samples.Capabilities.WalletDemoSession: public string ? Agent { get ; private set ; }
+ AAuth.Samples.Capabilities.WalletDemoSession: public string ? ConsentUrl { get ; private set ; }
+ AAuth.Samples.Capabilities.WalletDemoSession: public string ? Question { get ; private set ; }
+ AAuth.Samples.Capabilities.WalletDemoSession: public string ? Result { get ; private set ; }
+ AAuth.Samples.Capabilities.WalletDemoSession: public string [  ] Steps
+ AAuth.Samples.Capabilities.WalletDemoSession: public void Answer ( string text )
+ AAuth.Samples.Capabilities.WalletDemoSession: public void Cancel ( )
+ AAuth.Samples.Capabilities.WalletDemoSession: public void Dispose ( )
+ AAuth.Samples.Capabilities.WalletFlow: Clarification
+ AAuth.Samples.Capabilities.WalletFlow: DirectAs
+ AAuth.Samples.Capabilities.WalletFlow: Revocation
+ AAuth.Samples.Capabilities: public enum WalletFlow
+ AAuth.Samples.Capabilities: public sealed class WalletDemoSession ( string provider , string person , string wallet , string concierge ) : IDisposable
```

Public owners: `AAuth.Samples.Capabilities.WalletDemoSession`, `AAuth.Samples.Capabilities.WalletFlow`, `AAuth.Samples.Capabilities`.

### samples/CapabilitySupport/WalletScenarioCode.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [WalletScenarioCode.cs](../../../samples/CapabilitySupport/WalletScenarioCode.cs).

```diff
+ AAuth.Samples.Capabilities.WalletScenarioCode: public const string Clarification = """
        public static Task<string> ClarifyAsync(HttpClient signedAgent, MetadataClient metadata,
            string personServer, string resourceToken,
            Func<Interaction, CancellationToken, Task> consent,
            Func<ClarificationRequirement, CancellationToken, Task<ClarificationResponse>> answer,
            CancellationToken cancellationToken)
            => new TokenExchangeClient(signedAgent, metadata).ExchangeAsync(personServer, resourceToken,
                new TokenExchangeRequest { OnInteractionRequired = consent, OnClarificationRequired = answer },
                cancellationToken);

        public static ClarificationResponse Answer(string justification)
            => ClarificationResponse.Respond(justification);

        public static ClarificationResponse Cancel() => ClarificationResponse.Cancel();
        """ ;
+ AAuth.Samples.Capabilities.WalletScenarioCode: public const string DirectAs = """
        public static async Task<string> ReadWalletAsync(IAAuthKey key, string issuer, string agent,
            string kid, string upstreamToken, string wallet, AAuthEgressPolicy egress,
            CancellationToken cancellationToken)
        {
            using var client = AAuthClientBuilder.SelfIssuing(key).As(issuer, agent).WithKid(kid)
                .WithEgressPolicy(egress).WithCallChaining(upstreamToken)
                .WithChallengeHandling(options => options.Capabilities = Array.Empty<string>()).Build();
            using var response = await client.GetAsync(wallet + "/wallet", cancellationToken);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync(cancellationToken);
        }
        """ ;
+ AAuth.Samples.Capabilities.WalletScenarioCode: public const string Revocation = """
        public static Task<HttpStatusCode> RevokeAsync(HttpClient signedPersonServer,
            Uri resourceRevocationEndpoint, string issuer, string tokenId, CancellationToken cancellationToken)
            => new RevocationClient(signedPersonServer).RevokeAsync(resourceRevocationEndpoint,
                new TokenKey(issuer, tokenId), cancellationToken);

        public static Task<string> RecoverAsync(HttpClient signedAgent, MetadataClient metadata,
            string personServer, string freshResourceToken,
            Func<Interaction, CancellationToken, Task> consent, CancellationToken cancellationToken)
            => new TokenExchangeClient(signedAgent, metadata).ExchangeAsync(personServer, freshResourceToken,
                new TokenExchangeRequest { OnInteractionRequired = consent }, cancellationToken);
        """ ;
+ AAuth.Samples.Capabilities.WalletScenarioCode: public static string For ( WalletFlow flow )
+ AAuth.Samples.Capabilities: public static class WalletScenarioCode
```

Public owners: `AAuth.Samples.Capabilities.WalletScenarioCode`, `AAuth.Samples.Capabilities`.

### samples/Concierge/ChainCaptureHandler.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [ChainCaptureHandler.cs](../../../samples/Concierge/ChainCaptureHandler.cs).

```diff
+ Concierge.ChainCaptureHandler: protected override async Task < HttpResponseMessage > SendAsync ( HttpRequestMessage request , CancellationToken cancellationToken )
+ Concierge.ChainCaptureHandler: public List < ChainExchange > Exchanges { get ; } = [ ]
+ Concierge: public sealed class ChainCaptureHandler : DelegatingHandler
+ Concierge: public sealed record ChainExchange ( string Method , string Url , string ? Scheme , string [  ] Fields , int Status )
```

Public owners: `Concierge.ChainCaptureHandler`, `Concierge`.

### samples/Concierge/PendingStore.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [PendingStore.cs](../../../samples/Concierge/PendingStore.cs).

```diff
+ Concierge.PendingStore.Entry: public DateTimeOffset ExpiresAt { get ; } = DateTimeOffset . FromUnixTimeSeconds ( JsonNode . Parse ( Base64UrlEncoder . DecodeBytes ( UpstreamToken . Split ( '.' ) [ 1 ] ) ) ! [ "exp" ] ! . GetValue < long > ( ) )
+ Concierge.PendingStore.Entry: public DeferredState Lifecycle { get ; } = new ( )
+ Concierge.PendingStore.Entry: public bool Matches ( string ? upstreamToken )
```

Public owners: `Concierge.PendingStore.Entry`, `Concierge.PendingStore`, `Concierge`.

### samples/Concierge/Program.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [Program.cs](../../../samples/Concierge/Program.cs).

Public signatures unchanged (1); behavior reviewed under sample-runtime.

Public owners: `Concierge`.

### samples/EventSupport/BookingsEvents.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [BookingsEvents.cs](../../../samples/EventSupport/BookingsEvents.cs).

```diff
+ AAuth.Samples.Events.BookingsEvents: public JsonObject Document ( )
+ AAuth.Samples.Events.BookingsEvents: public const string EventType = "reservation.available" ;
+ AAuth.Samples.Events.BookingsEvents: public const string Operation = "receiveReservationAvailable" ;
+ AAuth.Samples.Events.BookingsEvents: public object IssueTicket ( TokenVerifier . VerifiedToken authorization )
+ AAuth.Samples.Events.BookingsEvents: public void Map ( IEndpointRouteBuilder routes )
+ AAuth.Samples.Events: public sealed class BookingsEvents ( string issuer , IAAuthKey key , string keyId , EventsProtocol protocol , SqliteEventStore store )
```

Public owners: `AAuth.Samples.Events.BookingsEvents`, `AAuth.Samples.Events`.

### samples/EventSupport/EventDemoCode.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [EventDemoCode.cs](../../../samples/EventSupport/EventDemoCode.cs).

```diff
+ AAuth.Samples.Events.EventDemoCode: public const string Delivery = """
        public static async Task TriggerSampleEventAsync(EventsProtocol protocol, string resource,
            string eid, IAAuthKey agentKey, string agentToken, string? account, CancellationToken cancellationToken)
        {
            using var response = await protocol.SendAsync(HttpMethod.Post,
                new Uri(resource + "/local/events/" + eid + "/notify"
                    + (account is null ? "" : "?account=" + Uri.EscapeDataString(account))), agentKey, agentToken,
                selfIssued: false, cancellationToken: cancellationToken);
            response.EnsureSuccessStatusCode();
        }

        public static async Task DeliverResourceEventAsync(EventsProtocol protocol, string resource,
            string provider, string agent, string eid, IAAuthKey resourceKey, string resourceKid,
            byte[] payload, CancellationToken cancellationToken)
        {
            var token = new EventTokenBuilder
            {
                Issuer = resource, Audience = agent, Eid = eid, Key = resourceKey,
                KeyId = resourceKid, Verifier = protocol.TokenVerifier,
            }.Build();
            var endpoint = await protocol.ResolveEventEndpointAsync(provider, cancellationToken);
            using var response = await protocol.SendAsync(HttpMethod.Post, endpoint,
                resourceKey, token, selfIssued: true, body: payload, cancellationToken: cancellationToken);
            response.EnsureSuccessStatusCode();
        }
        """ ;
+ AAuth.Samples.Events.EventDemoCode: public const string Discover = """
        public static async Task<JsonObject> DiscoverChannelsAsync(HttpClient http,
            EventsProtocol protocol, string resource, string provider, CancellationToken cancellationToken)
        {
            using var metadata = new MetadataClient(http);
            var resourceMetadata = await metadata.FetchAsync(
                new Uri(resource + "/.well-known/aauth-resource.json"), cancellationToken);
            var documentUrl = resourceMetadata["r3_vocabularies"]!["urn:aauth:vocabulary:asyncapi"]!.GetValue<string>();
            var channels = await http.GetFromJsonAsync<JsonObject>(
                new Uri(new Uri(resource), documentUrl), cancellationToken);
            var eventEndpoint = await protocol.ResolveEventEndpointAsync(provider, cancellationToken);
            return channels!;
        }
        """ ;
+ AAuth.Samples.Events.EventDemoCode: public const string Example = """
        builder.Services.AddAAuthEvents();
        var app = builder.Build();
        using var http = AAuthHttpTransport.CreateClient(egressPolicy);
        var protocol = new EventsProtocol(http,
            app.Services.GetServices<ISignatureTokenVerifier>());

        // Public registration uses an AsyncAPI channel URL; protected
        // registration uses the ticket from an authorized Bookings response.
        using var registration = await protocol.SendAsync(HttpMethod.Post,
            subscriptionUrl, agentKey, subscribeToken, selfIssued: false,
            body: subscriptionParameters);

        // Resource signs both JWT and HTTP with the same discoverable key.
        var eventToken = new EventTokenBuilder
        {
            Issuer = resource, Audience = agent, Eid = subscription.Eid,
            Key = resourceKey, KeyId = resourceKid,
            Verifier = protocol.TokenVerifier
        }.Build();
        var endpoint = await protocol.ResolveEventEndpointAsync(subscription.Provider);
        using var delivery = await protocol.SendAsync(HttpMethod.Post,
            endpoint, resourceKey, eventToken, selfIssued: true, body: payloadBytes);

        // AP endpoint requires a durable transactional quota/outbox store.
        app.MapAAuthEventEndpoint("/events", protocol, providerStore);

        // Agent verifies the issuer JWT and context before persisting receipt.
        var receiver = new EventReceiver(protocol, agentStore, agent);
        var firstReceipt = await receiver.ReceiveAsync(eventToken, payloadBytes);
        """ ;
+ AAuth.Samples.Events.EventDemoCode: public const string Receipt = """
        public static async Task VerifyInboxAsync(EventsProtocol protocol, IAgentEventStore store,
            string provider, string agent, string eid, IAAuthKey key, string agentToken,
            CancellationToken cancellationToken)
        {
            using var response = await protocol.SendAsync(HttpMethod.Get,
                new Uri(provider + "/local/events/inbox"), key, agentToken,
                selfIssued: false, cancellationToken: cancellationToken);
            response.EnsureSuccessStatusCode();
            var pending = (await response.Content.ReadFromJsonAsync<PendingEvent[]>(cancellationToken))!;
            var item = pending.Single(delivery => delivery.Event.Eid == eid);
            var receiver = new EventReceiver(protocol, store, agent);
            await receiver.ReceiveAsync(item.Event.Token, item.Event.Body, cancellationToken);
            var duplicate = await receiver.ReceiveAsync(item.Event.Token, item.Event.Body, cancellationToken);
            if (duplicate) throw new InvalidOperationException("Duplicate event was not suppressed.");
            using var acknowledged = await protocol.SendAsync(HttpMethod.Post,
                new Uri(provider + "/local/events/inbox/" + item.Receipt + "/ack"), key, agentToken,
                selfIssued: false, cancellationToken: cancellationToken);
            acknowledged.EnsureSuccessStatusCode();
        }
        """ ;
+ AAuth.Samples.Events.EventDemoCode: public const string Registration = """
        public static async Task RegisterSubscriptionAsync(EventsProtocol protocol,
            Uri subscriptionUrl, IAAuthKey key, string subscribeToken, CancellationToken cancellationToken)
        {
            using var response = await protocol.SendAsync(HttpMethod.Post, subscriptionUrl,
                key, subscribeToken, selfIssued: false,
                body: "{\"event_types\":[\"reservation.available\"]}"u8.ToArray(),
                cancellationToken: cancellationToken);
            response.EnsureSuccessStatusCode();
        }
        """ ;
+ AAuth.Samples.Events.EventDemoCode: public const string SubscribeToken = """
        public static async Task<JsonObject> AcquireSubscribeTokenAsync(EventsProtocol protocol,
            IAgentEventStore store, IAAuthKey key, string agentToken, string agent,
            string provider, string resource, string context, CancellationToken cancellationToken)
        {
            var body = System.Text.Encoding.UTF8.GetBytes(new JsonObject
                { ["resource"] = resource, ["max_uses"] = 1 }.ToJsonString());
            using var response = await protocol.SendAsync(HttpMethod.Post,
                new Uri(provider + "/local/events/subscribe"), key, agentToken,
                selfIssued: false, body: body, cancellationToken: cancellationToken);
            response.EnsureSuccessStatusCode();
            var result = (await response.Content.ReadFromJsonAsync<JsonObject>(cancellationToken))!;
            store.Remember(new(result["eid"]!.GetValue<string>(), resource, agent, context));
            return result;
        }
        """ ;
+ AAuth.Samples.Events.EventDemoCode: public const string SubscriptionUrl = """
        public static async Task<(string Agent, string AgentToken, string SubscriptionUrl)> ObtainSubscriptionUrlAsync(AAuthKey key,
            string provider, string person, string resource, string account, bool protectedChannel,
            string publicSubscriptionUrl, AAuthEgressPolicy policy,
            Func<Interaction, CancellationToken, Task> showConsent, CancellationToken cancellationToken)
        {
            var enrolled = await AAuthClientBuilder.Bootstrap(provider + "/enrol")
                .WithKey(key).WithKeyStore(new InMemoryKeyStore()).WithPersonServer(person)
                .WithEgressPolicy(policy).EnrolAsync(cancellationToken);
            if (!protectedChannel) return (enrolled.AgentId!, enrolled.AgentToken!, publicSubscriptionUrl);
            using var agent = new AAuthClientBuilder(key).UseJwt(enrolled.AgentToken!)
                .WithEgressPolicy(policy).WithChallengeHandling(person,
                    options => options.OnInteractionRequired = showConsent).Build();
            using var request = new HttpRequestMessage(HttpMethod.Get,
                resource + "/search_availability?account=" + Uri.EscapeDataString(account));
            request.Options.Set(AAuthRequestOptions.Account, account);
            using var response = await agent.SendAsync(request, cancellationToken);
            response.EnsureSuccessStatusCode();
            var result = await response.Content.ReadFromJsonAsync<JsonObject>(cancellationToken);
            return (enrolled.AgentId!, enrolled.AgentToken!, result!["notifications"]!["subscribe_url"]!.GetValue<string>());
        }
        """ ;
+ AAuth.Samples.Events.EventDemoCode: public static readonly string [  ] Steps = [ Discover , SubscriptionUrl , SubscribeToken , Registration , Delivery , Receipt ] ;
+ AAuth.Samples.Events: public static class EventDemoCode
```

Public owners: `AAuth.Samples.Events.EventDemoCode`, `AAuth.Samples.Events`.

### samples/EventSupport/EventDemoSession.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [EventDemoSession.cs](../../../samples/EventSupport/EventDemoSession.cs).

```diff
+ AAuth.Samples.Events.EventDemoSession: public EventDemoSession ( string directory , string provider = "http://localhost:5301" , string resource = "http://localhost:5005" , string person = "http://localhost:5100" , HttpClient ? http = null )
+ AAuth.Samples.Events.EventDemoSession: public Func < Task > ? Changed { get ; set ; }
+ AAuth.Samples.Events.EventDemoSession: public List < EventDemoEvidence > Evidence { get ; } = [ ]
+ AAuth.Samples.Events.EventDemoSession: public async Task NextAsync ( CancellationToken cancellationToken = default )
+ AAuth.Samples.Events.EventDemoSession: public bool Protected { get ; set ; } = true
+ AAuth.Samples.Events.EventDemoSession: public int Step { get ; private set ; }
+ AAuth.Samples.Events.EventDemoSession: public static readonly string [  ] Steps = [ "Discover event channels" , "Obtain subscription URL" , "Acquire subscribe token" , "Register subscription" , "Deliver sample event" , "Verify inbox event" ] ;
+ AAuth.Samples.Events.EventDemoSession: public string ? ConsentUrl { get ; private set ; }
+ AAuth.Samples.Events.EventDemoSession: public string ? Context { get ; private set ; }
+ AAuth.Samples.Events.EventDemoSession: public string ? Eid { get ; private set ; }
+ AAuth.Samples.Events.EventDemoSession: public string ? Payload { get ; private set ; }
+ AAuth.Samples.Events.EventDemoSession: public string Account { get ; set ; } = "personal"
+ AAuth.Samples.Events.EventDemoSession: public string Agent { get ; private set ; } = ""
+ AAuth.Samples.Events.EventDemoSession: public void Dispose ( )
+ AAuth.Samples.Events: public sealed class EventDemoSession : IDisposable
+ AAuth.Samples.Events: public sealed record EventDemoEvidence ( int Step , string Exchange , int StatusCode , string Json )
```

Public owners: `AAuth.Samples.Events.EventDemoSession`, `AAuth.Samples.Events`.

### samples/EventSupport/LocalEventProvider.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [LocalEventProvider.cs](../../../samples/EventSupport/LocalEventProvider.cs).

```diff
+ AAuth.Samples.Events.LocalEventProvider: public static void MapLocalEventProvider ( this IEndpointRouteBuilder routes , string issuer , IAAuthKey key , string keyId , EventsProtocol protocol , IAgentProviderEventStore store )
+ AAuth.Samples.Events: public static class LocalEventProvider
```

Public owners: `AAuth.Samples.Events.LocalEventProvider`, `AAuth.Samples.Events`.

### samples/EventSupport/SampleAgentEnrollment.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [SampleAgentEnrollment.cs](../../../samples/EventSupport/SampleAgentEnrollment.cs).

```diff
+ AAuth.Samples.Events.SampleAgentEnrollment: public static void MapSampleAgentEnrollment ( this IEndpointRouteBuilder routes , string issuer , IAAuthKey key , string keyId , AAuthEgressPolicy policy , SampleAgentRegistry registry )
+ AAuth.Samples.Events: public static class SampleAgentEnrollment
```

Public owners: `AAuth.Samples.Events.SampleAgentEnrollment`, `AAuth.Samples.Events`.

### samples/EventSupport/SampleAgentRegistry.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [SampleAgentRegistry.cs](../../../samples/EventSupport/SampleAgentRegistry.cs).

```diff
+ AAuth.Samples.Events.SampleAgentRegistry: public IReadOnlyList < SampleAgentRecord > List ( )
+ AAuth.Samples.Events.SampleAgentRegistry: public SampleAgentRecord ? Enrol ( string issuer , string ? requestedId , IAAuthKey publicKey , string ? personServer )
+ AAuth.Samples.Events.SampleAgentRegistry: public SampleAgentRecord ? Find ( string agent )
+ AAuth.Samples.Events.SampleAgentRegistry: public SampleAgentRecord ? FindByKey ( string thumbprint )
+ AAuth.Samples.Events.SampleAgentRegistry: public SampleAgentRegistry ( string path )
+ AAuth.Samples.Events: public sealed class SampleAgentRegistry
+ AAuth.Samples.Events: public sealed record SampleAgentRecord ( string AgentId , IAAuthKey PublicKey , string KeyId , DateTimeOffset RegisteredAt , string ? PersonServer )
```

Public owners: `AAuth.Samples.Events.SampleAgentRegistry`, `AAuth.Samples.Events`.

### samples/EventSupport/SqliteEventStore.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [SqliteEventStore.cs](../../../samples/EventSupport/SqliteEventStore.cs).

```diff
+ AAuth.Samples.Events.SqliteEventStore: public AgentEventContext ? FindContext ( string eid )
+ AAuth.Samples.Events.SqliteEventStore: public EventAcceptance Accept ( EventEnvelope envelope , DateTimeOffset now )
+ AAuth.Samples.Events.SqliteEventStore: public EventEnvelope PrepareDelivery ( string provider , string eid , Func < EventEnvelope > create )
+ AAuth.Samples.Events.SqliteEventStore: public IReadOnlyList < PendingEvent > Pending ( string agent , int limit = 100 , string ? after = null )
+ AAuth.Samples.Events.SqliteEventStore: public IReadOnlyList < ProcessedEvent > ReadEvents ( string agent )
+ AAuth.Samples.Events.SqliteEventStore: public RegistrationResult Register ( ResourceSubscription subscription , string ? ticket , DateTimeOffset now )
+ AAuth.Samples.Events.SqliteEventStore: public ResourceSubscription ? Find ( string provider , string eid , DateTimeOffset now )
+ AAuth.Samples.Events.SqliteEventStore: public ResourceSubscription ? FindNotification ( string provider , string eid )
+ AAuth.Samples.Events.SqliteEventStore: public SqliteEventStore ( string path )
+ AAuth.Samples.Events.SqliteEventStore: public bool Acknowledge ( string agent , string receipt )
+ AAuth.Samples.Events.SqliteEventStore: public bool RecordOnce ( ProcessedEvent received , DateTimeOffset now )
+ AAuth.Samples.Events.SqliteEventStore: public const int InboxMaxBytes = 1024 * 1024 ;
+ AAuth.Samples.Events.SqliteEventStore: public static JsonSerializerOptions InboxJson { get ; } = new ( JsonSerializerDefaults . Web )
+ AAuth.Samples.Events.SqliteEventStore: public string ? DeliveryReceipt ( ResourceSubscription subscription )
+ AAuth.Samples.Events.SqliteEventStore: public string EnsureState ( string operation , string ? account , string initialState )
+ AAuth.Samples.Events.SqliteEventStore: public string RecordDelivery ( ResourceSubscription subscription , string response , bool complete )
+ AAuth.Samples.Events.SqliteEventStore: public void Complete ( string provider , string eid )
+ AAuth.Samples.Events.SqliteEventStore: public void Create ( ProviderSubscription subscription )
+ AAuth.Samples.Events.SqliteEventStore: public void IssueTicket ( SubscriptionTicket ticket )
+ AAuth.Samples.Events.SqliteEventStore: public void Remember ( AgentEventContext context )
+ AAuth.Samples.Events.SqliteEventStore: public void SetState ( string operation , string ? account , string state )
+ AAuth.Samples.Events: public sealed class SqliteEventStore : IAgentProviderEventStore , IResourceEventStore , IAgentEventStore
```

Public owners: `AAuth.Samples.Events.SqliteEventStore`, `AAuth.Samples.Events`.

### samples/FederatedWorkerScenario.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [FederatedWorkerScenario.cs](../../../samples/FederatedWorkerScenario.cs).

```diff
+ AAuth.Samples.FederatedWorkerScenario: public Func < Interaction , CancellationToken , Task > ? OnInteraction { get ; set ; }
+ AAuth.Samples.FederatedWorkerScenario: public async Task CallWalletAsync ( CancellationToken ct = default )
+ AAuth.Samples.FederatedWorkerScenario: public async Task ExchangeAsync ( CancellationToken ct = default )
+ AAuth.Samples.FederatedWorkerScenario: public async Task ObtainResourceAsync ( CancellationToken ct = default )
+ AAuth.Samples.FederatedWorkerScenario: public async Task ObtainUpstreamAsync ( CancellationToken ct = default )
+ AAuth.Samples.FederatedWorkerScenario: public static IReadOnlyDictionary < string , string > ScopeDescriptions { get ; } = new Dictionary < string , string > { [ "delegation.invoke" ] = "Delegate a wallet lookup to the parent and worker" }
+ AAuth.Samples.FederatedWorkerScenario: public static JsonObject Payload ( string jwt )
+ AAuth.Samples.FederatedWorkerScenario: public string ? AuthToken { get ; private set ; }
+ AAuth.Samples.FederatedWorkerScenario: public string ? InteractionUrl { get ; private set ; }
+ AAuth.Samples.FederatedWorkerScenario: public string ? ParentToken { get ; private set ; }
+ AAuth.Samples.FederatedWorkerScenario: public string ? ResourceResponse { get ; private set ; }
+ AAuth.Samples.FederatedWorkerScenario: public string ? ResourceToken { get ; private set ; }
+ AAuth.Samples.FederatedWorkerScenario: public string ? UpstreamToken { get ; private set ; }
+ AAuth.Samples.FederatedWorkerScenario: public string ? WorkerToken { get ; private set ; }
+ AAuth.Samples.FederatedWorkerScenario: public string ParentId
+ AAuth.Samples.FederatedWorkerScenario: public string WorkerId
+ AAuth.Samples.FederatedWorkerScenario: public void Dispose ( )
+ AAuth.Samples.FederatedWorkerScenario: public void IssueParent ( )
+ AAuth.Samples.FederatedWorkerScenario: public void IssueWorker ( )
+ AAuth.Samples: public sealed class FederatedWorkerScenario ( IAAuthKey providerKey , string providerKid , string provider , string personServer , string wallet ) : IDisposable
```

Public owners: `AAuth.Samples.FederatedWorkerScenario`, `AAuth.Samples`.

### samples/GuidedTour/Program.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [Program.cs](../../../samples/GuidedTour/Program.cs).

Public signatures unchanged (2); behavior reviewed under sample-runtime.

Public owners: `GuidedTour`.

### samples/GuidedTour/TourOptions.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [TourOptions.cs](../../../samples/GuidedTour/TourOptions.cs).

```diff
- GuidedTour.SigningMode: JwksUri
+ GuidedTour.SigningMode: Jwks
```

Public owners: `GuidedTour.SigningMode`, `GuidedTour.TourMode`, `GuidedTour.TourOptions`, `GuidedTour`.

### samples/GuidedTour/TourSession.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [TourSession.cs](../../../samples/GuidedTour/TourSession.cs).

```diff
+ GuidedTour.TourSession: public BookingAccount [  ] BookingsAccounts { get ; private set ; } = [ ]
+ GuidedTour.TourSession: public async Task CheckPreviousAccountAsync ( )
+ GuidedTour.TourSession: public async Task LoadBookingsAccountsAsync ( )
+ GuidedTour.TourSession: public bool CanCheckPreviousAccount
+ GuidedTour.TourSession: public sealed record BookingAccount ( string Id , string Name )
+ GuidedTour.TourSession: public string ? AccountProbeResult { get ; private set ; }
+ GuidedTour.TourSession: public string ? BookingsAccount { get ; private set ; }
+ GuidedTour.TourSession: public string ? WorkerConsentUrl { get ; private set ; }
+ GuidedTour.TourSession: public void SelectBookingsAccount ( string ? account )
```

Public owners: `GuidedTour.TourSession`, `GuidedTour`.

### samples/MockAccessServers/Federated/Policy/KeycloakAccessPolicy.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [KeycloakAccessPolicy.cs](../../../samples/MockAccessServers/Federated/Policy/KeycloakAccessPolicy.cs).

```diff
- MockAccessServer.Policy.KeycloakAccessPolicy: public KeycloakAccessPolicy ( HttpClient http , KeycloakOptions options )
+ MockAccessServer.Policy.KeycloakAccessPolicy: public KeycloakAccessPolicy ( HttpClient http , KeycloakOptions options , WalletPolicyRules ? walletRules = null )
```

Public owners: `MockAccessServer.Policy.KeycloakAccessPolicy`, `MockAccessServer.Policy`.

### samples/MockAccessServers/Federated/Policy/StubAccessPolicy.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [StubAccessPolicy.cs](../../../samples/MockAccessServers/Federated/Policy/StubAccessPolicy.cs).

```diff
- MockAccessServer.Policy.StubAccessPolicy: public StubAccessPolicy ( IReadOnlyList < string > ? requiredClaims = null , bool requireConsent = false )
+ MockAccessServer.Policy.StubAccessPolicy: public StubAccessPolicy ( IReadOnlyList < string > ? requiredClaims = null , bool requireConsent = false , WalletPolicyRules ? walletRules = null )
```

Public owners: `MockAccessServer.Policy.StubAccessPolicy`, `MockAccessServer.Policy`.

### samples/MockAccessServers/Federated/Policy/WalletPolicyRules.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [WalletPolicyRules.cs](../../../samples/MockAccessServers/Federated/Policy/WalletPolicyRules.cs).

```diff
+ MockAccessServer.Policy.WalletPolicyRules: public AccessDecision ? Evaluate ( AccessPolicyRequest request )
+ MockAccessServer.Policy.WalletPolicyRules: public const string ReviewScope = "wallet.review" ;
+ MockAccessServer.Policy: public sealed class WalletPolicyRules ( string wallet , string concierge )
```

Public owners: `MockAccessServer.Policy.WalletPolicyRules`, `MockAccessServer.Policy`.

### samples/MockAccessServers/Federated/Program.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [Program.cs](../../../samples/MockAccessServers/Federated/Program.cs).

Public signatures unchanged (1); behavior reviewed under sample-runtime.

Public owners: `Federated`.

### samples/MockAccessServers/R3/Program.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [Program.cs](../../../samples/MockAccessServers/R3/Program.cs).

Public signatures unchanged (1); behavior reviewed under sample-runtime.

Public owners: `R3AccessServer`.

### samples/MockAccessServers/R3/SqliteR3AuditSink.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [SqliteR3AuditSink.cs](../../../samples/MockAccessServers/R3/SqliteR3AuditSink.cs).

```diff
+ R3AccessServer.SqliteR3AuditSink: public IReadOnlyList < R3TokenIssuanceAuditRecord > ReadRecords ( )
+ R3AccessServer.SqliteR3AuditSink: public SqliteR3AuditSink ( string path )
+ R3AccessServer.SqliteR3AuditSink: public Task RecordTokenIssuanceAsync ( R3TokenIssuanceAuditRecord record , CancellationToken cancellationToken = default )
+ R3AccessServer: public sealed class SqliteR3AuditSink : IR3AuditSink
```

Public owners: `R3AccessServer.SqliteR3AuditSink`, `R3AccessServer`.

### samples/MockAgentProvider/Program.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [Program.cs](../../../samples/MockAgentProvider/Program.cs).

```diff
+ MockAgentProvider: public sealed class Entry
```

Public owners: `MockAgentProvider`.

### samples/MockPersonServer/ConsentBridgePersonPendingStore.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [ConsentBridgePersonPendingStore.cs](../../../samples/MockPersonServer/ConsentBridgePersonPendingStore.cs).

```diff
- MockPersonServer.ConsentBridgePersonPendingStore: public PersonPendingEntry Add ( string resourceUrl , string scope , string agentId , IAAuthKey ? agentConfirmationKey , JsonObject ? upstreamAct = null , MissionClaim ? mission = null )
+ MockPersonServer.ConsentBridgePersonPendingStore: public PersonPendingEntry ? GetByCode ( string code )
+ MockPersonServer.ConsentBridgePersonPendingStore: public PersonPendingEntry Add ( string resourceUrl , string scope , string agentId , IAAuthKey ? agentConfirmationKey , DateTimeOffset agentTokenExpiresAt , JsonObject ? upstreamAct = null , MissionClaim ? mission = null , DateTimeOffset ? authorizationExpiresAt = null )
```

Public owners: `MockPersonServer.ConsentBridgePersonPendingStore`, `MockPersonServer`.

### samples/MockPersonServer/ConsentStore.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [ConsentStore.cs](../../../samples/MockPersonServer/ConsentStore.cs).

```diff
- MockPersonServer.ConsentStore: public bool IsConsented ( string agent , string resource , string scope )
- MockPersonServer.ConsentStore: public void Grant ( string agent , string resource , string scope )
- MockPersonServer.ConsentStore: public void Revoke ( string agent , string resource , string scope )
+ MockPersonServer.ConsentStore: public bool IsConsented ( string agent , string resource , string scope , string ? account = null , string ? key = null )
+ MockPersonServer.ConsentStore: public void Grant ( string agent , string resource , string scope , string ? account = null , string ? key = null )
+ MockPersonServer.ConsentStore: public void Revoke ( string agent , string resource , string scope , string ? account = null , string ? key = null )
```

Public owners: `MockPersonServer.ConsentStore`, `MockPersonServer`.

### samples/MockPersonServer/MissionGovernance.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [MissionGovernance.cs](../../../samples/MockPersonServer/MissionGovernance.cs).

```diff
- MockPersonServer.MissionConsentScript: public static string ScopeKey ( string resource , string scope )
- MockPersonServer.MissionConsentScript: public void SeedInScope ( string resource , string scope )
- MockPersonServer.MissionPolicyStore: public bool IsInScope ( string s256 , string resource , string scope )
+ MockPersonServer.MissionConsentScript: public static string ScopeKey ( string resource , string scope , string ? account = null )
+ MockPersonServer.MissionConsentScript: public void SeedInScope ( string resource , string scope , string ? account = null )
+ MockPersonServer.MissionPendingEntry: public AAuth . Server . BrowserInteraction Browser { get ; } = new ( )
+ MockPersonServer.MissionPendingEntry: public AAuth . Server . DeferredState Lifecycle { get ; } = new ( )
+ MockPersonServer.MissionPendingEntry: public DateTimeOffset ExpiresAt { get ; } = DateTimeOffset . UtcNow . AddMinutes ( 10 )
+ MockPersonServer.MissionPendingEntry: public bool Decide ( bool allow )
+ MockPersonServer.MissionPendingEntry: public bool MatchesOwner ( Microsoft . AspNetCore . Http . HttpContext context )
+ MockPersonServer.MissionPendingEntry: public string ? OwnerIssuer { get ; init ; }
+ MockPersonServer.MissionPendingEntry: public string ? OwnerKeyThumbprint { get ; init ; }
+ MockPersonServer.MissionPendingStore: public MissionPendingEntry ? GetByCode ( string code )
+ MockPersonServer.MissionPolicyStore: public bool IsInScope ( string s256 , string resource , string scope , string ? account = null )
```

Public owners: `MockPersonServer.MissionConsentScript`, `MockPersonServer.MissionPendingEntry`, `MockPersonServer.MissionPendingKind`, `MockPersonServer.MissionPendingState`, `MockPersonServer.MissionPendingStore`, `MockPersonServer.MissionPolicyStore`, `MockPersonServer.SampleAuditSink`, `MockPersonServer.SampleInteractionRelay`, `MockPersonServer.SamplePermissionDecider`, `MockPersonServer`.

### samples/MockPersonServer/Program.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [Program.cs](../../../samples/MockPersonServer/Program.cs).

Public signatures unchanged (1); behavior reviewed under sample-runtime.

Public owners: `MockPersonServer`.

### samples/MockPersonServer/SampleIdentityClaimsAsserter.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [SampleIdentityClaimsAsserter.cs](../../../samples/MockPersonServer/SampleIdentityClaimsAsserter.cs).

```diff
+ MockPersonServer.SampleIdentityClaimsAsserter: public static string DirectedSubject ( string resource )
```

Public owners: `MockPersonServer.SampleIdentityClaimsAsserter`, `MockPersonServer`.

### samples/MockPersonServer/ScriptMissionTokenConsent.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [ScriptMissionTokenConsent.cs](../../../samples/MockPersonServer/ScriptMissionTokenConsent.cs).

Public signatures unchanged (3); behavior reviewed under sample-runtime.

Public owners: `MockPersonServer.ScriptMissionTokenConsent`, `MockPersonServer`.

### samples/MockResourceServers/Bookings/Program.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [Program.cs](../../../samples/MockResourceServers/Bookings/Program.cs).

Public signatures unchanged (1); behavior reviewed under sample-runtime.

Public owners: `Bookings`.

### samples/MockResourceServers/Calendar/Program.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [Program.cs](../../../samples/MockResourceServers/Calendar/Program.cs).

Public signatures unchanged (1); behavior reviewed under sample-runtime.

Public owners: `Calendar`.

### samples/MockResourceServers/Catalog/Program.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [Program.cs](../../../samples/MockResourceServers/Catalog/Program.cs).

```diff
+ Catalog: public sealed class Entry
```

Public owners: `Catalog`.

### samples/MockResourceServers/Inbox/Program.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [Program.cs](../../../samples/MockResourceServers/Inbox/Program.cs).

Public signatures unchanged (1); behavior reviewed under sample-runtime.

Public owners: `Inbox`.

### samples/MockResourceServers/Profile/Program.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [Program.cs](../../../samples/MockResourceServers/Profile/Program.cs).

Public signatures unchanged (1); behavior reviewed under sample-runtime.

Public owners: `Profile`.

### samples/MockResourceServers/Trips/Program.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [Program.cs](../../../samples/MockResourceServers/Trips/Program.cs).

Public signatures unchanged (1); behavior reviewed under sample-runtime.

Public owners: `Trips`.

### samples/MockResourceServers/Wallet/Program.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [Program.cs](../../../samples/MockResourceServers/Wallet/Program.cs).

Public signatures unchanged (1); behavior reviewed under sample-runtime.

Public owners: `Wallet`.

### samples/SampleApp/EnrollmentService.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [EnrollmentService.cs](../../../samples/SampleApp/EnrollmentService.cs).

Public signatures unchanged (10); behavior reviewed under sample-runtime.

Public owners: `SampleApp.EnrollmentService`, `SampleApp`.

### src/AAuth.Events/EventReceiver.cs

Concept/decision: [events](#events). Source: [EventReceiver.cs](../../../src/AAuth.Events/EventReceiver.cs).

```diff
+ AAuth.Events.EventReceiver: public async Task < bool > ReceiveAsync ( string token , byte [  ] body , CancellationToken cancellationToken = default )
+ AAuth.Events: public sealed class EventReceiver ( EventsProtocol protocol , IAgentEventStore store , string agent )
```

Public owners: `AAuth.Events.EventReceiver`, `AAuth.Events`.

### src/AAuth.Events/EventStores.cs

Concept/decision: [events](#events). Source: [EventStores.cs](../../../src/AAuth.Events/EventStores.cs).

```diff
+ AAuth.Events.IAgentEventStore: AgentEventContext ? FindContext ( string eid )
+ AAuth.Events.IAgentEventStore: IReadOnlyList < ProcessedEvent > ReadEvents ( string agent )
+ AAuth.Events.IAgentEventStore: bool RecordOnce ( ProcessedEvent received , DateTimeOffset now )
+ AAuth.Events.IAgentEventStore: void Remember ( AgentEventContext context )
+ AAuth.Events.IAgentProviderEventStore: EventAcceptance Accept ( EventEnvelope envelope , DateTimeOffset now )
+ AAuth.Events.IAgentProviderEventStore: IReadOnlyList < PendingEvent > Pending ( string agent , int limit = 100 , string ? after = null )
+ AAuth.Events.IAgentProviderEventStore: bool Acknowledge ( string agent , string receipt )
+ AAuth.Events.IAgentProviderEventStore: void Create ( ProviderSubscription subscription )
+ AAuth.Events.IResourceEventStore: RegistrationResult Register ( ResourceSubscription subscription , string ? ticket , DateTimeOffset now )
+ AAuth.Events.IResourceEventStore: ResourceSubscription ? Find ( string provider , string eid , DateTimeOffset now )
+ AAuth.Events.IResourceEventStore: void Complete ( string provider , string eid )
+ AAuth.Events.IResourceEventStore: void IssueTicket ( SubscriptionTicket ticket )
+ AAuth.Events.IResourceEventStore: void SetState ( string operation , string ? account , string state )
+ AAuth.Events: public interface IAgentEventStore
+ AAuth.Events: public interface IAgentProviderEventStore
+ AAuth.Events: public interface IResourceEventStore
+ AAuth.Events: public sealed record AgentEventContext ( string Eid , string Resource , string Agent , string Context )
+ AAuth.Events: public sealed record EventAcceptance ( int StatusCode , long ? RemainingUses = null )
+ AAuth.Events: public sealed record EventEnvelope ( string Token , string Eid , string Issuer , string Agent , DateTimeOffset ExpiresAt , byte [  ] Body )
+ AAuth.Events: public sealed record PendingEvent ( string Receipt , EventEnvelope Event )
+ AAuth.Events: public sealed record ProcessedEvent ( AgentEventContext Context , EventEnvelope Event )
+ AAuth.Events: public sealed record ProviderSubscription ( string Eid , string Agent , string Resource , DateTimeOffset ExpiresAt , long ? MaxUses )
+ AAuth.Events: public sealed record RegistrationResult ( int StatusCode , ResourceSubscription ? Subscription = null )
+ AAuth.Events: public sealed record ResourceSubscription ( string Eid , string Provider , string Agent , string Operation , string ? Account , string State , DateTimeOffset ExpiresAt )
+ AAuth.Events: public sealed record SubscriptionTicket ( string Ticket , string Agent , string Operation , string ? Account , string State , DateTimeOffset ExpiresAt )
```

Public owners: `AAuth.Events.IAgentEventStore`, `AAuth.Events.IAgentProviderEventStore`, `AAuth.Events.IResourceEventStore`, `AAuth.Events`.

### src/AAuth.Events/EventTokenBuilders.cs

Concept/decision: [events](#events). Source: [EventTokenBuilders.cs](../../../src/AAuth.Events/EventTokenBuilders.cs).

```diff
+ AAuth.Events.EventTokenBuilder: public TimeSpan Lifetime { get ; init ; } = TimeSpan . FromMinutes ( 5 )
+ AAuth.Events.EventTokenBuilder: public TokenVerifier Verifier { get ; init ; } = new ( )
+ AAuth.Events.EventTokenBuilder: public required IAAuthKey Key { get ; init ; }
+ AAuth.Events.EventTokenBuilder: public required string Audience { get ; init ; }
+ AAuth.Events.EventTokenBuilder: public required string Eid { get ; init ; }
+ AAuth.Events.EventTokenBuilder: public required string Issuer { get ; init ; }
+ AAuth.Events.EventTokenBuilder: public required string KeyId { get ; init ; }
+ AAuth.Events.EventTokenBuilder: public string Build ( )
+ AAuth.Events.SubscribeTokenBuilder: public TimeSpan Lifetime { get ; init ; } = TimeSpan . FromMinutes ( 5 )
+ AAuth.Events.SubscribeTokenBuilder: public TokenVerifier Verifier { get ; init ; } = new ( )
+ AAuth.Events.SubscribeTokenBuilder: public long ? MaxUses { get ; init ; }
+ AAuth.Events.SubscribeTokenBuilder: public required IAAuthKey ConfirmationKey { get ; init ; }
+ AAuth.Events.SubscribeTokenBuilder: public required IAAuthKey Key { get ; init ; }
+ AAuth.Events.SubscribeTokenBuilder: public required string Audience { get ; init ; }
+ AAuth.Events.SubscribeTokenBuilder: public required string Eid { get ; init ; }
+ AAuth.Events.SubscribeTokenBuilder: public required string Issuer { get ; init ; }
+ AAuth.Events.SubscribeTokenBuilder: public required string KeyId { get ; init ; }
+ AAuth.Events.SubscribeTokenBuilder: public required string Subject { get ; init ; }
+ AAuth.Events.SubscribeTokenBuilder: public string Build ( )
+ AAuth.Events: public sealed class EventTokenBuilder
+ AAuth.Events: public sealed class SubscribeTokenBuilder
```

Public owners: `AAuth.Events.EventTokenBuilder`, `AAuth.Events.SubscribeTokenBuilder`, `AAuth.Events`.

### src/AAuth.Events/EventsEndpoints.cs

Concept/decision: [events](#events). Source: [EventsEndpoints.cs](../../../src/AAuth.Events/EventsEndpoints.cs).

```diff
+ AAuth.Events.EventsEndpoints: public static IEndpointConventionBuilder MapAAuthEventEndpoint ( this IEndpointRouteBuilder routes , string path , EventsProtocol protocol , IAgentProviderEventStore store )
+ AAuth.Events.EventsEndpoints: public static IEndpointConventionBuilder MapAAuthSubscriptionEndpoint ( this IEndpointRouteBuilder routes , string path , string resource , string operation , bool protectedChannel , EventsProtocol protocol , IResourceEventStore store , Func < JsonObject , bool > validateParameters , TimeSpan ? subscriptionLifetime = null )
+ AAuth.Events: public static class EventsEndpoints
```

Public owners: `AAuth.Events.EventsEndpoints`, `AAuth.Events`.

### src/AAuth.Events/EventsProtocol.cs

Concept/decision: [events](#events). Source: [EventsProtocol.cs](../../../src/AAuth.Events/EventsProtocol.cs).

```diff
+ AAuth.Events.EventsProtocol: public EventsProtocol ( HttpClient http , IEnumerable < ISignatureTokenVerifier > tokenVerifiers , Func < DateTimeOffset > ? clock = null )
+ AAuth.Events.EventsProtocol: public TokenVerifier TokenVerifier { get ; }
+ AAuth.Events.EventsProtocol: public async Task < AAuthVerifiedAssertion ? > VerifyRequestAsync ( HttpContext context , string type , string ? audience = null )
+ AAuth.Events.EventsProtocol: public async Task < HttpResponseMessage > SendAsync ( HttpMethod method , Uri url , IAAuthKey key , string jwt , bool selfIssued , byte [  ] ? body = null , CancellationToken cancellationToken = default )
+ AAuth.Events.EventsProtocol: public async Task < TokenVerifier . VerifiedToken > VerifyEventAsync ( string jwt , string agent , CancellationToken cancellationToken = default )
+ AAuth.Events.EventsProtocol: public async Task < Uri > ResolveEventEndpointAsync ( string provider , CancellationToken cancellationToken = default )
+ AAuth.Events: public sealed class EventsProtocol
```

Public owners: `AAuth.Events.EventsProtocol`, `AAuth.Events`.

### src/AAuth.Events/EventsSignatureTokenVerifier.cs

Concept/decision: [events](#events). Source: [EventsSignatureTokenVerifier.cs](../../../src/AAuth.Events/EventsSignatureTokenVerifier.cs).

```diff
+ AAuth.Events.EventsServiceExtensions: public static IServiceCollection AddAAuthEvents ( this IServiceCollection services )
+ AAuth.Events.EventsSignatureTokenVerifier: public Task < TokenVerifier . VerifiedToken > VerifyAsync ( string jwt , IAAuthKey issuerKey , TokenVerifier verifier , CancellationToken cancellationToken )
+ AAuth.Events.EventsSignatureTokenVerifier: public string Scheme
+ AAuth.Events.EventsSignatureTokenVerifier: public string TokenType
+ AAuth.Events: public sealed class EventsSignatureTokenVerifier ( bool subscribe ) : ISignatureTokenVerifier
+ AAuth.Events: public static class EventsServiceExtensions
```

Public owners: `AAuth.Events.EventsServiceExtensions`, `AAuth.Events.EventsSignatureTokenVerifier`, `AAuth.Events`.

### src/AAuth.Events/EventsTokens.cs

Concept/decision: [events](#events). Source: [EventsTokens.cs](../../../src/AAuth.Events/EventsTokens.cs).

```diff
+ AAuth.Events.EventsTokens: public const string AgentDwk = "aauth-agent.json" ;
+ AAuth.Events.EventsTokens: public const string EventType = "aa-event+jwt" ;
+ AAuth.Events.EventsTokens: public const string ResourceDwk = "aauth-resource.json" ;
+ AAuth.Events.EventsTokens: public const string SubscribeType = "aa-subscribe+jwt" ;
+ AAuth.Events.EventsTokens: public static TokenVerifier . VerifiedToken Verify ( string jwt , IAAuthKey issuerKey , bool subscribe , TokenVerifier verifier , string ? audience = null )
+ AAuth.Events.EventsTokens: public static string Create ( IAAuthKey key , string keyId , JsonObject payload , bool subscribe , TokenVerifier ? verifier = null )
+ AAuth.Events.EventsTokens: public static string RequireText ( JsonObject value , string name )
+ AAuth.Events: public static class EventsTokens
```

Public owners: `AAuth.Events.EventsTokens`, `AAuth.Events`.

### src/AAuth.R3/Model/R3Document.cs

Concept/decision: [r3](#r3). Source: [R3Document.cs](../../../src/AAuth.R3/Model/R3Document.cs).

```diff
- AAuth.R3.Model.R3Document: public byte [  ] ToUtf8Bytes ( JsonSerializerOptions ? options = null )
- AAuth.R3.Model.R3Document: public static R3Document FromUtf8Bytes ( ReadOnlySpan < byte > bytes , JsonSerializerOptions ? options = null )
- AAuth.R3.Model.R3Document: public void Validate ( )
+ AAuth.R3.Model.R3Document: [ JsonPropertyName ( "account" ) ] [ JsonIgnore ( Condition = JsonIgnoreCondition . WhenWritingNull ) ] public string ? Account { get ; init ; }
+ AAuth.R3.Model.R3Document: public byte [  ] ToUtf8Bytes ( JsonSerializerOptions ? options = null , R3VocabularySchemas ? schemas = null )
+ AAuth.R3.Model.R3Document: public static R3Document FromUtf8Bytes ( ReadOnlySpan < byte > bytes , JsonSerializerOptions ? options = null , R3VocabularySchemas ? schemas = null )
+ AAuth.R3.Model.R3Document: public void Validate ( R3VocabularySchemas ? schemas = null )
```

Public owners: `AAuth.R3.Model.R3Document`, `AAuth.R3.Model`.

### src/AAuth.R3/Model/R3Grant.cs

Concept/decision: [r3](#r3). Source: [R3Grant.cs](../../../src/AAuth.R3/Model/R3Grant.cs).

```diff
- AAuth.R3.Model.R3Grant: public bool Contains ( string operationId )
- AAuth.R3.Model.R3Grant: public void Validate ( bool allowEmpty = false )
+ AAuth.R3.Model.R3Grant: public bool Contains ( R3OperationIdentity operation )
+ AAuth.R3.Model.R3Grant: public void Validate ( bool allowEmpty = false , R3VocabularySchemas ? schemas = null )
```

Public owners: `AAuth.R3.Model.R3Grant`, `AAuth.R3.Model`.

### src/AAuth.R3/Model/R3Json.cs

Concept/decision: [r3](#r3). Source: [R3Json.cs](../../../src/AAuth.R3/Model/R3Json.cs).

Public signatures unchanged (2); behavior reviewed under r3.

Public owners: `AAuth.R3.Model.R3Json`, `AAuth.R3.Model`.

### src/AAuth.R3/Model/R3Operation.cs

Concept/decision: [r3](#r3). Source: [R3Operation.cs](../../../src/AAuth.R3/Model/R3Operation.cs).

```diff
+ AAuth.R3.Model.R3Operation: public IReadOnlyDictionary < string , JsonElement > ? Extensions { get ; init ; }
+ AAuth.R3.Model.R3Operation: public IReadOnlyList < string > ? Methods { get ; init ; }
+ AAuth.R3.Model.R3Operation: public static R3Operation AsyncApi ( string operationId , string ? action = null )
+ AAuth.R3.Model.R3Operation: public static R3Operation GraphQl ( string operation , string type )
+ AAuth.R3.Model.R3Operation: public static R3Operation Grpc ( string method )
+ AAuth.R3.Model.R3Operation: public static R3Operation OData ( string operation , params string [  ] methods )
+ AAuth.R3.Model.R3Operation: public static R3Operation OpenApiGateway ( string service , string operationId )
+ AAuth.R3.Model.R3Operation: public static R3Operation Wsdl ( string operation , string ? service = null )
+ AAuth.R3.Model.R3Operation: public string ? Action { get ; init ; }
+ AAuth.R3.Model.R3Operation: public string ? Service { get ; init ; }
+ AAuth.R3.Model.R3Operation: public string ? Type { get ; init ; }
+ AAuth.R3.Model.R3OperationConverter: public R3OperationConverter ( )
+ AAuth.R3.Model.R3OperationConverter: public R3OperationConverter ( string identifierMember )
```

Public owners: `AAuth.R3.Model.R3OperationConverter`, `AAuth.R3.Model.R3Operation`, `AAuth.R3.Model`.

### src/AAuth.R3/Model/R3OperationIdentity.cs

Concept/decision: [r3](#r3). Source: [R3OperationIdentity.cs](../../../src/AAuth.R3/Model/R3OperationIdentity.cs).

```diff
+ AAuth.R3.Model.R3OperationIdentity: public bool Covers ( R3OperationIdentity requested )
+ AAuth.R3.Model.R3OperationIdentity: public bool Matches ( string vocabulary , R3Operation operation )
+ AAuth.R3.Model.R3OperationIdentity: public static R3OperationIdentity Mcp ( string tool )
+ AAuth.R3.Model.R3OperationIdentity: public static R3OperationIdentity OpenApi ( string operationId )
+ AAuth.R3.Model: public sealed record R3OperationIdentity ( string Vocabulary , R3Operation Operation )
```

Public owners: `AAuth.R3.Model.R3OperationIdentity`, `AAuth.R3.Model`.

### src/AAuth.R3/Model/R3Operations.cs

Concept/decision: [r3](#r3). Source: [R3Operations.cs](../../../src/AAuth.R3/Model/R3Operations.cs).

```diff
- AAuth.R3.Model.R3Operations: public void Validate ( )
+ AAuth.R3.Model.R3Operations: public void Validate ( R3VocabularySchemas ? schemas = null )
```

Public owners: `AAuth.R3.Model.R3Operations`, `AAuth.R3.Model`.

### src/AAuth.R3/Model/R3Parameter.cs

Concept/decision: [r3](#r3). Source: [R3Parameter.cs](../../../src/AAuth.R3/Model/R3Parameter.cs).

```diff
- AAuth.R3.Model.R3Parameter: public required JsonNode Json { get ; init ; }
- AAuth.R3.Model.R3Parameter: public static R3Parameter Inline ( JsonNode value )
+ AAuth.R3.Model.R3Parameter: public required JsonNode ? Json { get ; init ; }
+ AAuth.R3.Model.R3Parameter: public static R3Parameter Inline ( JsonNode ? value )
+ AAuth.R3.Model.R3Parameter: public void Validate ( )
```

Public owners: `AAuth.R3.Model.R3Parameter`, `AAuth.R3.Model.R3PresentedParameters`, `AAuth.R3.Model`.

### src/AAuth.R3/Model/R3ProposalDocument.cs

Concept/decision: [r3](#r3). Source: [R3ProposalDocument.cs](../../../src/AAuth.R3/Model/R3ProposalDocument.cs).

```diff
- AAuth.R3.Model.R3ProposalDocument: public byte [  ] ToUtf8Bytes ( JsonSerializerOptions ? options = null )
- AAuth.R3.Model.R3ProposalDocument: public static R3ProposalDocument FromUtf8Bytes ( ReadOnlySpan < byte > bytes , JsonSerializerOptions ? options = null )
- AAuth.R3.Model.R3ProposalDocument: public void Validate ( )
+ AAuth.R3.Model.R3ProposalDocument: [ JsonPropertyName ( "account" ) ] [ JsonIgnore ( Condition = JsonIgnoreCondition . WhenWritingNull ) ] public string ? Account { get ; init ; }
+ AAuth.R3.Model.R3ProposalDocument: public byte [  ] ToUtf8Bytes ( JsonSerializerOptions ? options = null , R3VocabularySchemas ? schemas = null )
+ AAuth.R3.Model.R3ProposalDocument: public static R3ProposalDocument FromUtf8Bytes ( ReadOnlySpan < byte > bytes , JsonSerializerOptions ? options = null , R3VocabularySchemas ? schemas = null )
+ AAuth.R3.Model.R3ProposalDocument: public void Validate ( R3VocabularySchemas ? schemas = null )
```

Public owners: `AAuth.R3.Model.R3ProposalDocument`, `AAuth.R3.Model`.

### src/AAuth.R3/Model/R3VocabularySchemas.cs

Concept/decision: [r3](#r3). Source: [R3VocabularySchemas.cs](../../../src/AAuth.R3/Model/R3VocabularySchemas.cs).

```diff
+ AAuth.R3.Model.R3VocabularySchemas: public JsonSerializerOptions CreateJsonOptions ( string vocabulary , JsonSerializerOptions ? options = null )
+ AAuth.R3.Model.R3VocabularySchemas: public R3VocabularySchemas ( IReadOnlyDictionary < string , R3VocabularySchema > ? custom = null )
+ AAuth.R3.Model.R3VocabularySchemas: public static R3VocabularySchemas Standard { get ; } = new ( )
+ AAuth.R3.Model.R3VocabularySchemas: public static void ValidateUri ( string vocabulary )
+ AAuth.R3.Model.R3VocabularySchemas: public void Validate ( string vocabulary , R3Operation operation )
+ AAuth.R3.Model.R3VocabularySchemas: public void ValidateVocabulary ( string vocabulary )
+ AAuth.R3.Model: public sealed class R3VocabularySchemas
+ AAuth.R3.Model: public sealed record R3VocabularySchema ( string IdentifierMember , Action < R3Operation > Validate )
```

Public owners: `AAuth.R3.Model.R3VocabularySchemas`, `AAuth.R3.Model`.

### src/AAuth.R3/Model/Vocabulary.cs

Concept/decision: [r3](#r3). Source: [Vocabulary.cs](../../../src/AAuth.R3/Model/Vocabulary.cs).

```diff
+ AAuth.R3.Model.Vocabulary: public const string AsyncApi = "urn:aauth:vocabulary:asyncapi" ;
+ AAuth.R3.Model.Vocabulary: public const string GraphQl = "urn:aauth:vocabulary:graphql" ;
+ AAuth.R3.Model.Vocabulary: public const string Grpc = "urn:aauth:vocabulary:grpc" ;
+ AAuth.R3.Model.Vocabulary: public const string OData = "urn:aauth:vocabulary:odata" ;
+ AAuth.R3.Model.Vocabulary: public const string OpenApiGateway = "urn:aauth:vocabulary:openapi-gateway" ;
+ AAuth.R3.Model.Vocabulary: public const string Wsdl = "urn:aauth:vocabulary:wsdl" ;
```

Public owners: `AAuth.R3.Model.Vocabulary`, `AAuth.R3.Model`.

### src/AAuth.R3/R3AccessTokenEndpoint.cs

Concept/decision: [r3](#r3). Source: [R3AccessTokenEndpoint.cs](../../../src/AAuth.R3/R3AccessTokenEndpoint.cs).

```diff
- AAuth.R3.R3AccessTokenEndpointOptions: public Func < Model . R3Operation , bool > ? IsConditionalOperation { get ; init ; }
- AAuth.R3.R3AccessTokenEndpointOptions: public IR3AuditSink AuditSink { get ; init ; } = R3NoOpAuditSink . Instance
- AAuth.R3.R3AccessTokenEndpointOptions: public required IReadOnlyDictionary < string , AAuthKey > SigningKeys { get ; init ; }
+ AAuth.R3.R3AccessTokenEndpointOptions: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; init ; } = AAuth . Discovery . AAuthEgressPolicy . Production
+ AAuth.R3.R3AccessTokenEndpointOptions: public AAuth . Discovery . AAuthTransportContract ? FetchTransportContract { get ; init ; }
+ AAuth.R3.R3AccessTokenEndpointOptions: public BrowserConsentSessions ? BrowserConsent { get ; init ; }
+ AAuth.R3.R3AccessTokenEndpointOptions: public Func < R3OperationIdentity , bool > ? IsConditionalOperation { get ; init ; }
+ AAuth.R3.R3AccessTokenEndpointOptions: public Func < R3OperationIdentity , bool > ? IsOperationAllowed { get ; init ; }
+ AAuth.R3.R3AccessTokenEndpointOptions: public Func < R3ProposalDocument , bool > ? IsProposalAllowed { get ; init ; }
+ AAuth.R3.R3AccessTokenEndpointOptions: public Func < string , string , bool > ? IsScopeAllowed { get ; init ; }
+ AAuth.R3.R3AccessTokenEndpointOptions: public R3VocabularySchemas VocabularySchemas { get ; init ; } = R3VocabularySchemas . Standard
+ AAuth.R3.R3AccessTokenEndpointOptions: public required IR3AuditSink AuditSink { get ; init ; }
+ AAuth.R3.R3AccessTokenEndpointOptions: public required IReadOnlyDictionary < string , IAAuthKey > SigningKeys { get ; init ; }
```

Public owners: `AAuth.R3.R3AccessTokenEndpointOptions`, `AAuth.R3.R3AccessTokenEndpoint`, `AAuth.R3`.

### src/AAuth.R3/R3Audit.cs

Concept/decision: [r3](#r3). Source: [R3Audit.cs](../../../src/AAuth.R3/R3Audit.cs).

```diff
- AAuth.R3.R3NoOpAuditSink: public Task RecordTokenIssuanceAsync ( R3TokenIssuanceAuditRecord record , CancellationToken cancellationToken = default )
- AAuth.R3.R3NoOpAuditSink: public static R3NoOpAuditSink Instance { get ; } = new ( )
- AAuth.R3: public sealed class R3NoOpAuditSink : IR3AuditSink
+ AAuth.R3.R3TokenIssuanceAuditRecord: public required string TokenId { get ; init ; }
+ AAuth.R3.R3TokenIssuanceAuditRecord: public required string TokenS256 { get ; init ; }
+ AAuth.R3.R3TokenIssuanceAuditRecord: public string ? Account { get ; init ; }
```

Public owners: `AAuth.R3.IR3AuditSink`, `AAuth.R3.InMemoryR3AuditSink`, `AAuth.R3.R3NoOpAuditSink`, `AAuth.R3.R3TokenIssuanceAuditRecord`, `AAuth.R3.R3TokenIssuanceKind`, `AAuth.R3`.

### src/AAuth.R3/R3AuthClaims.cs

Concept/decision: [r3](#r3). Source: [R3AuthClaims.cs](../../../src/AAuth.R3/R3AuthClaims.cs).

```diff
- AAuth.R3.R3AuthClaims: public static IReadOnlyDictionary < string , JsonNode ? > AuthToken ( string r3Uri , string r3S256 , R3Grant granted , R3Grant ? conditional = null )
+ AAuth.R3.R3AuthClaims: public static IReadOnlyDictionary < string , JsonNode ? > AuthToken ( string r3Uri , string r3S256 , R3Grant granted , R3Grant ? conditional = null , R3VocabularySchemas ? schemas = null )
```

Public owners: `AAuth.R3.R3AuthClaims`, `AAuth.R3`.

### src/AAuth.R3/R3Challenge.cs

Concept/decision: [r3](#r3). Source: [R3Challenge.cs](../../../src/AAuth.R3/R3Challenge.cs).

```diff
- AAuth.R3.R3Challenge: public IResult Challenge ( HttpContext context , string agent , string agentJkt , string r3Uri , string r3S256 , string ? scope = null )
- AAuth.R3.R3Challenge: public string BuildResourceToken ( string agent , string agentJkt , string r3Uri , string r3S256 , string ? scope = null )
+ AAuth.R3.R3Challenge: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; init ; } = AAuth . Discovery . AAuthEgressPolicy . Production
+ AAuth.R3.R3Challenge: public IResult Challenge ( HttpContext context , string agent , string agentJkt , string r3Uri , string r3S256 , string ? scope = null , string ? account = null )
+ AAuth.R3.R3Challenge: public string BuildResourceToken ( string agent , string agentJkt , string r3Uri , string r3S256 , string ? scope = null , string ? account = null )
```

Public owners: `AAuth.R3.R3Challenge`, `AAuth.R3`.

### src/AAuth.R3/R3ClaimReader.cs

Concept/decision: [r3](#r3). Source: [R3ClaimReader.cs](../../../src/AAuth.R3/R3ClaimReader.cs).

```diff
- AAuth.R3.R3ClaimReader: public static AuthTokenClaims ReadAuthToken ( JsonObject payload )
- AAuth.R3.R3ClaimReader: public static R3Grant ? ReadGrant ( JsonNode ? node )
+ AAuth.R3.R3ClaimReader.AuthTokenClaims: public string ? Account { get ; init ; }
+ AAuth.R3.R3ClaimReader.ResourceDocumentClaims: public string ? Account { get ; init ; }
+ AAuth.R3.R3ClaimReader: public static AuthTokenClaims ReadAuthToken ( JsonObject payload , R3VocabularySchemas ? schemas = null )
+ AAuth.R3.R3ClaimReader: public static R3Grant ? ReadGrant ( JsonNode ? node , R3VocabularySchemas ? schemas = null )
```

Public owners: `AAuth.R3.R3ClaimReader.AuthTokenClaims`, `AAuth.R3.R3ClaimReader.ResourceDocumentClaims`, `AAuth.R3.R3ClaimReader`, `AAuth.R3`.

### src/AAuth.R3/R3DocumentEndpoint.cs

Concept/decision: [r3](#r3). Source: [R3DocumentEndpoint.cs](../../../src/AAuth.R3/R3DocumentEndpoint.cs).

```diff
- AAuth.R3: public sealed record R3VerifiedFetcher ( string Scheme , Uri ? JwksUri , string ? Kid , string ? KeyThumbprint , SignatureKeyParser . ParsedSignatureKeyInfo ParsedKey )
+ AAuth.R3.R3DocumentEndpoint: public static IEndpointRouteBuilder MapR3Document ( this IEndpointRouteBuilder endpoints , string pattern , Func < HttpContext , byte [  ] ? > getBytes , R3DocumentReaderPolicy readerPolicy )
+ AAuth.R3: public sealed record R3VerifiedFetcher ( string Scheme , string Identifier , string ? Kid , string ? KeyThumbprint , SignatureKeyParser . ParsedSignatureKeyInfo ParsedKey )
```

Public owners: `AAuth.R3.R3DocumentEndpoint`, `AAuth.R3.R3FetchVerificationException`, `AAuth.R3.R3UntrustedJwksUriException`, `AAuth.R3`.

### src/AAuth.R3/R3DocumentReaderPolicy.cs

Concept/decision: [r3](#r3). Source: [R3DocumentReaderPolicy.cs](../../../src/AAuth.R3/R3DocumentReaderPolicy.cs).

```diff
+ AAuth.R3.R3DocumentReaderPolicy: public R3DocumentReaderPolicy ( string designatedAccessServer , IEnumerable < string > ? personServerEvaluators = null , AAuthEgressPolicy ? egressPolicy = null )
+ AAuth.R3.R3DocumentReaderPolicy: public bool Allows ( R3VerifiedFetcher fetcher )
+ AAuth.R3: public sealed class R3DocumentReaderPolicy
```

Public owners: `AAuth.R3.R3DocumentReaderPolicy`, `AAuth.R3`.

### src/AAuth.R3/R3Enforcement.cs

Concept/decision: [r3](#r3). Source: [R3Enforcement.cs](../../../src/AAuth.R3/R3Enforcement.cs).

```diff
- AAuth.R3.R3Enforcement: public R3Enforcement ( R3ProposalStore proposalStore , Uri resourceBaseUri , string proposalPathPrefix = "/r3/proposals" )
- AAuth.R3.R3Enforcement: public R3EnforcementDecision Evaluate ( JsonObject verifiedAuthTokenPayload , string operation , IReadOnlyDictionary < string , R3Parameter > ? parameters = null , string ? approvedProposalS256 = null )
- AAuth.R3.R3Enforcement: public R3EnforcementDecision Evaluate ( R3ClaimReader . AuthTokenClaims claims , string operation , IReadOnlyDictionary < string , R3Parameter > ? parameters = null , Func < string , IReadOnlyDictionary < string , R3Parameter > , R3Display ? > ? displayFactory = null , string ? approvedProposalS256 = null )
- AAuth.R3.R3Enforcement: public R3EnforcementDecision Evaluate ( R3ClaimReader . AuthTokenClaims claims , string operation , R3PresentedParameters presentedParameters , string approvedProposalS256 )
+ AAuth.R3.R3Enforcement: public R3Enforcement ( R3ProposalStore proposalStore , Uri resourceBaseUri , string proposalPathPrefix = "/r3/proposals" , R3VocabularySchemas ? schemas = null )
+ AAuth.R3.R3Enforcement: public R3EnforcementDecision Evaluate ( JsonObject verifiedAuthTokenPayload , R3OperationIdentity operation , IReadOnlyDictionary < string , R3Parameter > ? parameters = null , string ? approvedProposalS256 = null , string ? expectedAccount = null )
+ AAuth.R3.R3Enforcement: public R3EnforcementDecision Evaluate ( R3ClaimReader . AuthTokenClaims claims , R3OperationIdentity operation , IReadOnlyDictionary < string , R3Parameter > ? parameters = null , Func < R3OperationIdentity , IReadOnlyDictionary < string , R3Parameter > , R3Display ? > ? displayFactory = null , string ? approvedProposalS256 = null , string ? expectedAccount = null )
+ AAuth.R3.R3Enforcement: public R3EnforcementDecision Evaluate ( R3ClaimReader . AuthTokenClaims claims , R3OperationIdentity operation , R3PresentedParameters presentedParameters , string approvedProposalS256 , string ? expectedAccount = null )
+ AAuth.R3.R3EnforcementDecision: public string ? Account { get ; init ; }
```

Public owners: `AAuth.R3.R3EnforcementDecisionKind`, `AAuth.R3.R3EnforcementDecision`, `AAuth.R3.R3Enforcement`, `AAuth.R3`.

### src/AAuth.R3/R3FetchClient.cs

Concept/decision: [r3](#r3). Source: [R3FetchClient.cs](../../../src/AAuth.R3/R3FetchClient.cs).

```diff
- AAuth.R3.R3FetchClient: public R3FetchClient ( HttpClient http )
- AAuth.R3.R3FetchClient: public static R3FetchClient Create ( IAAuthKey signingKey , string jwksUri , string kid , HttpMessageHandler ? innerHandler = null )
- AAuth.R3.R3FetchClient: public static Uri ValidateFetchTarget ( string r3Uri , string resourceIssuer )
- AAuth.R3: public sealed class R3FetchClient
+ AAuth.R3.R3FetchClient: public R3FetchClient ( HttpClient http , bool ownsClient = false )
+ AAuth.R3.R3FetchClient: public static R3FetchClient Create ( IAAuthKey signingKey , string identifier , string dwk , string kid , HttpMessageHandler ? innerHandler = null , AAuthEgressPolicy ? policy = null , AAuthTransportContract ? transportContract = null )
+ AAuth.R3.R3FetchClient: public static Uri ValidateFetchTarget ( string r3Uri , string resourceIssuer , AAuthEgressPolicy ? policy = null )
+ AAuth.R3.R3FetchClient: public void Dispose ( )
+ AAuth.R3: public sealed class R3FetchClient : IDisposable
```

Public owners: `AAuth.R3.R3FetchClient`, `AAuth.R3`.

### src/AAuth.R3/R3Metadata.cs

Concept/decision: [r3](#r3). Source: [R3Metadata.cs](../../../src/AAuth.R3/R3Metadata.cs).

```diff
+ AAuth.R3.R3Metadata: public static JsonObject AddVocabularies ( JsonObject metadata , IReadOnlyDictionary < string , JsonNode ? > vocabularies , R3VocabularySchemas ? schemas = null )
+ AAuth.R3.R3Metadata: public static void ValidateOperations ( R3Operations request , JsonObject metadata , IEnumerable < R3OperationIdentity > authoritativeOperations , R3VocabularySchemas ? schemas = null )
```

Public owners: `AAuth.R3.R3Metadata`, `AAuth.R3`.

### src/AAuth.R3/R3ProposalStore.cs

Concept/decision: [r3](#r3). Source: [R3ProposalStore.cs](../../../src/AAuth.R3/R3ProposalStore.cs).

```diff
- AAuth.R3.R3ProposalStore: public R3ProposalStore ( TimeProvider ? timeProvider = null )
- AAuth.R3.R3ProposalStore: public StoredR3Proposal Add ( R3ProposalDocument proposal , Uri baseUri , string pathPrefix = "/r3/proposals" )
+ AAuth.R3.R3ProposalStore: public R3ProposalStore ( int maxEntries = 1024 )
+ AAuth.R3.R3ProposalStore: public StoredR3Proposal Add ( R3ProposalDocument proposal , Uri baseUri , string pathPrefix = "/r3/proposals" , R3VocabularySchemas ? schemas = null )
```

Public owners: `AAuth.R3.R3ProposalStore`, `AAuth.R3`.

### src/AAuth.R3/R3Request.cs

Concept/decision: [r3](#r3). Source: [R3Request.cs](../../../src/AAuth.R3/R3Request.cs).

```diff
- AAuth.R3.R3Request: public static JsonObject CreateBody ( R3Operations operations )
- AAuth.R3.R3Request: public static async Task < HttpResponseMessage > PostAuthorizeAsync ( HttpClient http , string authorizationEndpoint , R3Operations operations , CancellationToken cancellationToken = default )
+ AAuth.R3.R3Request: public static JsonObject CreateBody ( R3Operations operations , string ? account = null , R3VocabularySchemas ? schemas = null )
+ AAuth.R3.R3Request: public static R3Operations ReadOperations ( JsonObject body , R3VocabularySchemas ? schemas = null )
+ AAuth.R3.R3Request: public static async Task < HttpResponseMessage > PostAuthorizeAsync ( HttpClient http , string authorizationEndpoint , R3Operations operations , CancellationToken cancellationToken = default , string ? account = null , R3VocabularySchemas ? schemas = null )
```

Public owners: `AAuth.R3.R3Request`, `AAuth.R3`.

### src/AAuth/AAuthClientBuilder.cs

Concept/decision: [agent-clients](#agent-clients). Source: [AAuthClientBuilder.cs](../../../src/AAuth/AAuthClientBuilder.cs).

```diff
- AAuth.AAuthClientBuilder: public AAuthClientBuilder UseJwksUri ( string uri , string kid )
- AAuth.AAuthClientBuilder: public AAuthClientBuilder UseJwt ( string agentToken )
- AAuth.AAuthClientBuilder: public AAuthClientBuilder WithInnerHandler ( HttpMessageHandler handler )
- AAuth.AAuthClientBuilder: public static BootstrapBuilder Bootstrap ( string enrollEndpoint , string agentId )
+ AAuth.AAuthClientBuilder: public AAuthClientBuilder UseJwks ( string url , string kid )
+ AAuth.AAuthClientBuilder: public AAuthClientBuilder UseJwksUri ( string id , string dwk , string kid )
+ AAuth.AAuthClientBuilder: public AAuthClientBuilder UseJwt ( string token )
+ AAuth.AAuthClientBuilder: public AAuthClientBuilder UseSelfJwt ( Func < string > tokenFactory )
+ AAuth.AAuthClientBuilder: public AAuthClientBuilder WithDevelopmentLoopback ( params string [  ] origins )
+ AAuth.AAuthClientBuilder: public AAuthClientBuilder WithEgressPolicy ( AAuthEgressPolicy policy )
+ AAuth.AAuthClientBuilder: public AAuthClientBuilder WithInnerHandler ( HttpMessageHandler handler , AAuthTransportContract ? transportContract = null )
+ AAuth.AAuthClientBuilder: public static BootstrapBuilder Bootstrap ( string enrollEndpoint , string ? agentId = null )
```

Public owners: `AAuth.AAuthClientBuilder`, `AAuth`.

### src/AAuth/AAuthConstants.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthConstants.cs](../../../src/AAuth/AAuthConstants.cs).

```diff
+ AAuth.AAuthConstants.Schemes: public const string Jwks = "jwks" ;
+ AAuth.AAuthConstants.Schemes: public const string SelfJwt = "self-jwt" ;
```

Public owners: `AAuth.AAuthConstants.AccessModes`, `AAuth.AAuthConstants.DwkFiles`, `AAuth.AAuthConstants.Headers`, `AAuth.AAuthConstants.Schemes`, `AAuth.AAuthConstants.TokenTypes`, `AAuth.AAuthConstants`, `AAuth`.

### src/AAuth/Access/AAuthAccessServerEndpoints.cs

Concept/decision: [consent](#consent). Source: [AAuthAccessServerEndpoints.cs](../../../src/AAuth/Access/AAuthAccessServerEndpoints.cs).

```diff
- AAuth.Access.AAuthAccessServerOptions: public required IReadOnlyDictionary < string , AAuthKey > SigningKeys { get ; init ; }
- AAuth.Access.AAuthAccessServerOptions: public string FallbackSubject { get ; init ; } = "pairwise-sub"
+ AAuth.Access.AAuthAccessServerOptions: public AAuthEgressPolicy EgressPolicy { get ; init ; } = AAuthEgressPolicy . Production
+ AAuth.Access.AAuthAccessServerOptions: public Action < AAuthRevocationOptions > ? ConfigureRevocation { get ; init ; }
+ AAuth.Access.AAuthAccessServerOptions: public TimeProvider TimeProvider { get ; init ; } = TimeProvider . System
+ AAuth.Access.AAuthAccessServerOptions: public required IReadOnlyDictionary < string , IAAuthKey > SigningKeys { get ; init ; }
+ AAuth.Access.AAuthAccessServerOptions: public string RevocationPath { get ; init ; } = "/revoke"
```

Public owners: `AAuth.Access.AAuthAccessServerEndpoints`, `AAuth.Access.AAuthAccessServerOptions`, `AAuth.Access`.

### src/AAuth/Access/AccessServerClient.cs

Concept/decision: [consent](#consent). Source: [AccessServerClient.cs](../../../src/AAuth/Access/AccessServerClient.cs).

Public signatures unchanged (3); behavior reviewed under consent.

Public owners: `AAuth.Access.AccessServerClient`, `AAuth.Access`.

### src/AAuth/Access/AccessServerRequest.cs

Concept/decision: [consent](#consent). Source: [AccessServerRequest.cs](../../../src/AAuth/Access/AccessServerRequest.cs).

```diff
- AAuth.Access.AccessServerRequest: public string ? RequestedScope { get ; init ; }
+ AAuth.Access.AccessServerRequest: public Func < ClarificationRequirement , CancellationToken , Task < ClarificationResponse > > ? OnClarificationRequired { get ; init ; }
+ AAuth.Access.AccessServerRequest: public MissionClaim ? ExpectedMission { get ; set ; }
+ AAuth.Access.AccessServerRequest: public required DateTimeOffset AuthorizationExpiresAt { get ; init ; }
+ AAuth.Access.AccessServerRequest: public string ? Account { get ; init ; }
+ AAuth.Access.AccessServerRequest: public string ? RequestedScope { get ; set ; }
+ AAuth.Access.AccessServerRequest: public string ? SubagentToken { get ; init ; }
```

Public owners: `AAuth.Access.AccessServerRequest`, `AAuth.Access`.

### src/AAuth/Access/IAccessPendingStore.cs

Concept/decision: [consent](#consent). Source: [IAccessPendingStore.cs](../../../src/AAuth/Access/IAccessPendingStore.cs).

```diff
- AAuth.Access.AccessPendingEntry: public required string Scope { get ; init ; }
- AAuth.Access.IAccessPendingStore: AccessPendingEntry Add ( string resourceUrl , string scope , string agentId , IAAuthKey agentConfirmationKey , JsonObject ? claims , IReadOnlyList < string > ? requiredClaims = null )
- AAuth.Access.InMemoryAccessPendingStore: public AccessPendingEntry Add ( string resourceUrl , string scope , string agentId , IAAuthKey agentConfirmationKey , JsonObject ? claims , IReadOnlyList < string > ? requiredClaims = null )
+ AAuth.Access.AccessPendingEntry: public AAuth . Headers . ClarificationRequirement ? Clarification { get ; set ; }
+ AAuth.Access.AccessPendingEntry: public AAuth . Server . BrowserInteraction Browser { get ; } = new ( )
+ AAuth.Access.AccessPendingEntry: public AAuth . Server . DeferredState Lifecycle { get ; } = new ( )
+ AAuth.Access.AccessPendingEntry: public AAuth . Tokens . UpstreamTokenValidationResult ? UpstreamAuthorization { get ; set ; }
+ AAuth.Access.AccessPendingEntry: public DateTimeOffset ? AuthorizationExpiresAt { get ; init ; }
+ AAuth.Access.AccessPendingEntry: public DateTimeOffset ? ClarificationDeadline { get ; set ; }
+ AAuth.Access.AccessPendingEntry: public DateTimeOffset ExpiresAt
+ AAuth.Access.AccessPendingEntry: public DateTimeOffset PendingExpiresAt
+ AAuth.Access.AccessPendingEntry: public IReadOnlyList < AAuth . Server . TokenKey > SourceTokens { get ; set ; } = [ ]
+ AAuth.Access.AccessPendingEntry: public JsonObject ? ResourceContext { get ; set ; }
+ AAuth.Access.AccessPendingEntry: public JsonObject ? UpstreamAct { get ; init ; }
+ AAuth.Access.AccessPendingEntry: public List < string > ClarificationAnswers { get ; } = [ ]
+ AAuth.Access.AccessPendingEntry: public int ClarificationRounds { get ; set ; }
+ AAuth.Access.AccessPendingEntry: public required DateTimeOffset AgentTokenExpiresAt { get ; init ; }
+ AAuth.Access.AccessPendingEntry: public required string Scope { get ; set ; }
+ AAuth.Access.AccessPendingEntry: public string ? Account
+ AAuth.Access.AccessPendingEntry: public string ? OwnerAgentIssuer { get ; set ; }
+ AAuth.Access.AccessPendingEntry: public string ? OwnerAgentSubject { get ; set ; }
+ AAuth.Access.AccessPendingEntry: public string ? OwnerKeyThumbprint { get ; set ; }
+ AAuth.Access.AccessPendingStatus: AwaitingClarification
+ AAuth.Access.AccessPendingStatus: Review
+ AAuth.Access.IAccessPendingStore: AccessPendingEntry ? GetByCode ( string code )
+ AAuth.Access.IAccessPendingStore: AccessPendingEntry Add ( string resourceUrl , string scope , string agentId , IAAuthKey agentConfirmationKey , DateTimeOffset agentTokenExpiresAt , JsonObject ? claims , IReadOnlyList < string > ? requiredClaims = null , DateTimeOffset ? authorizationExpiresAt = null , JsonObject ? upstreamAct = null )
+ AAuth.Access.InMemoryAccessPendingStore: public AccessPendingEntry ? GetByCode ( string code )
+ AAuth.Access.InMemoryAccessPendingStore: public AccessPendingEntry Add ( string resourceUrl , string scope , string agentId , IAAuthKey agentConfirmationKey , DateTimeOffset agentTokenExpiresAt , JsonObject ? claims , IReadOnlyList < string > ? requiredClaims = null , DateTimeOffset ? authorizationExpiresAt = null , JsonObject ? upstreamAct = null )
```

Public owners: `AAuth.Access.AccessPendingEntry`, `AAuth.Access.AccessPendingStatus`, `AAuth.Access.IAccessPendingStore`, `AAuth.Access.InMemoryAccessPendingStore`, `AAuth.Access`.

### src/AAuth/Access/IAccessPolicy.cs

Concept/decision: [consent](#consent). Source: [IAccessPolicy.cs](../../../src/AAuth/Access/IAccessPolicy.cs).

```diff
+ AAuth.Access.AccessDecision: public ClarificationRequirement ? Clarification { get ; private init ; }
+ AAuth.Access.AccessDecision: public static AccessDecision NeedsClarification ( string question , int ? timeoutSeconds = null , IReadOnlyList < string > ? options = null )
+ AAuth.Access.AccessDecisionKind: NeedsClarification
+ AAuth.Access.AccessPolicyRequest: public AAuth . Tokens . UpstreamTokenValidationResult ? UpstreamAuthorization { get ; init ; }
+ AAuth.Access.AccessPolicyRequest: public IReadOnlyList < string > ClarificationHistory { get ; init ; } = [ ]
+ AAuth.Access.AccessPolicyRequest: public JsonObject ? ResourceContext { get ; init ; }
+ AAuth.Access.AccessPolicyRequest: public string ? Account
+ AAuth.Access.AccessPolicyRequest: public string ? PersonServerIssuer { get ; init ; }
```

Public owners: `AAuth.Access.AccessDecisionKind`, `AAuth.Access.AccessDecision`, `AAuth.Access.AccessPolicyRequest`, `AAuth.Access.IAccessPolicy`, `AAuth.Access.IInteractiveAccessPolicy`, `AAuth.Access`.

### src/AAuth/Agent/AAuthAccessHandler.cs

Concept/decision: [resource-managed](#resource-managed). Source: [AAuthAccessHandler.cs](../../../src/AAuth/Agent/AAuthAccessHandler.cs).

```diff
- AAuth.Agent.AAuthAccessHandler: public AAuthAccessHandler ( IAAuthAccessStore store )
+ AAuth.Agent.AAuthAccessHandler: public AAuthAccessHandler ( IAAuthAccessStore store , string ? signingKeyThumbprint = null )
```

Public owners: `AAuth.Agent.AAuthAccessHandler`, `AAuth.Agent`.

### src/AAuth/Agent/AAuthRequestOptions.cs

Concept/decision: [resource-managed](#resource-managed). Source: [AAuthRequestOptions.cs](../../../src/AAuth/Agent/AAuthRequestOptions.cs).

```diff
+ AAuth.Agent.AAuthRequestOptions: public static readonly HttpRequestOptionsKey < string > Account = new ( "AAuth.Account" ) ;
+ AAuth.Agent.AAuthRequestOptions: public static readonly HttpRequestOptionsKey < string > PresentedToken = new ( "AAuth.PresentedToken" ) ;
+ AAuth.Agent.AAuthRequestOptions: public static readonly HttpRequestOptionsKey < string > ResourceIdentifier = new ( "AAuth.ResourceIdentifier" ) ;
+ AAuth.Agent.AAuthRequestOptions: public static string ? GetAccount ( HttpRequestMessage request )
+ AAuth.Agent: public static class AAuthRequestOptions
```

Public owners: `AAuth.Agent.AAuthRequestOptions`, `AAuth.Agent`.

### src/AAuth/Agent/AAuthTokenHolder.cs

Concept/decision: [agent-clients](#agent-clients). Source: [AAuthTokenHolder.cs](../../../src/AAuth/Agent/AAuthTokenHolder.cs).

```diff
+ AAuth.Agent.AAuthTokenHolder: public string SelectForRequest ( System . Net . Http . HttpRequestMessage request , string agentToken , string signingKeyThumbprint )
```

Public owners: `AAuth.Agent.AAuthTokenHolder`, `AAuth.Agent`.

### src/AAuth/Agent/AgentProviderClient.cs

Concept/decision: [agent-clients](#agent-clients). Source: [AgentProviderClient.cs](../../../src/AAuth/Agent/AgentProviderClient.cs).

```diff
- AAuth.Agent.AgentProviderClient: public async Task < EnrollResult > EnrolAsync ( string apIssuer , string agentId , string enrollEndpoint , string ? personServer = null , CancellationToken ct = default )
+ AAuth.Agent.AgentProviderClient: public async Task < EnrollResult > EnrolAsync ( string apIssuer , string ? agentId , string enrollEndpoint , string ? personServer = null , CancellationToken ct = default )
+ AAuth.Agent.AgentProviderClient: public async Task < EnrollResult > EnrolWithKeyAsync ( string apIssuer , string ? agentId , string enrollEndpoint , AAuthKey key , string ? personServer = null , CancellationToken ct = default )
+ AAuth.Agent.EnrollResult: public string ? AgentId { get ; init ; }
```

Public owners: `AAuth.Agent.AgentProviderClient`, `AAuth.Agent.EnrollResult`, `AAuth.Agent.TwoKeyRefreshResult`, `AAuth.Agent`.

### src/AAuth/Agent/AgentProviderTokenRefresher.cs

Concept/decision: [agent-clients](#agent-clients). Source: [AgentProviderTokenRefresher.cs](../../../src/AAuth/Agent/AgentProviderTokenRefresher.cs).

```diff
- AAuth.Agent: public sealed class AgentProviderTokenRefresher : ITokenRefresher
+ AAuth.Agent.AgentProviderTokenRefresher.RefresherBuilder: public RefresherBuilder WithEgressPolicy ( Discovery . AAuthEgressPolicy policy )
+ AAuth.Agent.AgentProviderTokenRefresher: public void Dispose ( )
+ AAuth.Agent: public sealed class AgentProviderTokenRefresher : ITokenRefresher , IDisposable
```

Public owners: `AAuth.Agent.AgentProviderTokenRefresher.RefresherBuilder`, `AAuth.Agent.AgentProviderTokenRefresher`, `AAuth.Agent.RefreshMode`, `AAuth.Agent`.

### src/AAuth/Agent/ChallengeHandler.cs

Concept/decision: [agent-clients](#agent-clients). Source: [ChallengeHandler.cs](../../../src/AAuth/Agent/ChallengeHandler.cs).

```diff
- AAuth.Agent.ChallengeHandler: public ChallengeHandler ( TokenExchangeClient exchange , AAuthTokenHolder holder , string ? personServer , Func < Interaction , CancellationToken , Task > ? onInteractionRequired , DeferredPollerOptions ? pollerOptions , Func < string ? > ? upstreamTokenProvider )
- AAuth.Agent.ChallengeHandler: public ChallengeHandler ( TokenExchangeClient exchange , AAuthTokenHolder holder , string personServer , Func < Interaction , CancellationToken , Task > ? onInteractionRequired = null , DeferredPollerOptions ? pollerOptions = null )
+ AAuth.Agent.ChallengeHandler: public ChallengeHandler ( TokenExchangeClient exchange , AAuthTokenHolder holder , TokenVerifier verifier , MetadataClient metadata , JwksClient jwks , string ? personServer , Func < Interaction , CancellationToken , Task > ? onInteractionRequired , DeferredPollerOptions ? pollerOptions , Func < string ? > ? upstreamTokenProvider )
+ AAuth.Agent.ChallengeHandler: public ChallengeHandler ( TokenExchangeClient exchange , AAuthTokenHolder holder , TokenVerifier verifier , MetadataClient metadata , JwksClient jwks , string personServer , Func < Interaction , CancellationToken , Task > ? onInteractionRequired = null , DeferredPollerOptions ? pollerOptions = null )
```

Public owners: `AAuth.Agent.ChallengeHandler`, `AAuth.Agent`.

### src/AAuth/Agent/ClarificationExchange.cs

Concept/decision: [agent-clients](#agent-clients). Source: [ClarificationExchange.cs](../../../src/AAuth/Agent/ClarificationExchange.cs).

Public signatures unchanged (21); behavior reviewed under agent-clients.

Public owners: `AAuth.Agent.ClarificationExchange`, `AAuth.Agent.ClarificationResponse.Kind`, `AAuth.Agent.ClarificationResponse`, `AAuth.Agent`.

### src/AAuth/Agent/DeferredPoller.cs

Concept/decision: [agent-clients](#agent-clients). Source: [DeferredPoller.cs](../../../src/AAuth/Agent/DeferredPoller.cs).

```diff
- AAuth.Agent.DeferredPoller: public async Task < HttpResponseMessage > PollAsync ( Uri pendingUrl , CancellationToken cancellationToken = default )
+ AAuth.Agent.DeferredPoller: public Task < HttpResponseMessage > PollAsync ( Uri pendingUrl , CancellationToken cancellationToken = default )
+ AAuth.Agent.DeferredPollerOptions: public TimeProvider TimeProvider { get ; init ; } = TimeProvider . System
```

Public owners: `AAuth.Agent.DeferredPollerOptions`, `AAuth.Agent.DeferredPoller`, `AAuth.Agent`.

### src/AAuth/Agent/Governance/AAuthGovernanceClient.cs

Concept/decision: [governance](#governance). Source: [AAuthGovernanceClient.cs](../../../src/AAuth/Agent/Governance/AAuthGovernanceClient.cs).

```diff
- AAuth.Agent.Governance: public sealed class AAuthGovernanceClient
+ AAuth.Agent.Governance.AAuthGovernanceClient: public void Dispose ( )
+ AAuth.Agent.Governance: public sealed class AAuthGovernanceClient : IDisposable
```

Public owners: `AAuth.Agent.Governance.AAuthGovernanceClient`, `AAuth.Agent.Governance`.

### src/AAuth/Agent/Governance/GovernanceOptions.cs

Concept/decision: [governance](#governance). Source: [GovernanceOptions.cs](../../../src/AAuth/Agent/Governance/GovernanceOptions.cs).

Public signatures unchanged (5); behavior reviewed under governance.

Public owners: `AAuth.Agent.Governance.GovernanceOptions`, `AAuth.Agent.Governance`.

### src/AAuth/Agent/Governance/MissionClient.cs

Concept/decision: [governance](#governance). Source: [MissionClient.cs](../../../src/AAuth/Agent/Governance/MissionClient.cs).

Public signatures unchanged (3); behavior reviewed under governance.

Public owners: `AAuth.Agent.Governance.MissionClient`, `AAuth.Agent.Governance`.

### src/AAuth/Agent/Governance/MissionSession.cs

Concept/decision: [governance](#governance). Source: [MissionSession.cs](../../../src/AAuth/Agent/Governance/MissionSession.cs).

```diff
- AAuth.Agent.Governance.MissionSession: public Task < bool > ProposeCompletionAsync ( string summary , GovernanceOptions ? options = null , CancellationToken cancellationToken = default )
+ AAuth.Agent.Governance.MissionSession: public async Task < bool > ProposeCompletionAsync ( string summary , GovernanceOptions ? options = null , CancellationToken cancellationToken = default )
```

Public owners: `AAuth.Agent.Governance.MissionSession`, `AAuth.Agent.Governance`.

### src/AAuth/Agent/Governance/PermissionClient.cs

Concept/decision: [governance](#governance). Source: [PermissionClient.cs](../../../src/AAuth/Agent/Governance/PermissionClient.cs).

Public signatures unchanged (4); behavior reviewed under governance.

Public owners: `AAuth.Agent.Governance.PermissionClient`, `AAuth.Agent.Governance`.

### src/AAuth/Agent/IAAuthAccessStore.cs

Concept/decision: [resource-managed](#resource-managed). Source: [IAAuthAccessStore.cs](../../../src/AAuth/Agent/IAAuthAccessStore.cs).

```diff
- AAuth.Agent.IAAuthAccessStore: bool TryGet ( string origin , out string token )
- AAuth.Agent.IAAuthAccessStore: void Remove ( string origin )
- AAuth.Agent.IAAuthAccessStore: void Set ( string origin , string token )
- AAuth.Agent.InMemoryAAuthAccessStore: public bool TryGet ( string origin , out string token )
- AAuth.Agent.InMemoryAAuthAccessStore: public void Remove ( string origin )
- AAuth.Agent.InMemoryAAuthAccessStore: public void Set ( string origin , string token )
+ AAuth.Agent.IAAuthAccessStore: bool TryGet ( string origin , out string token , string ? account = null , string ? signingKeyThumbprint = null )
+ AAuth.Agent.IAAuthAccessStore: void Remove ( string origin , string ? account = null , string ? signingKeyThumbprint = null )
+ AAuth.Agent.IAAuthAccessStore: void Set ( string origin , string token , string ? account = null , string ? signingKeyThumbprint = null )
+ AAuth.Agent.InMemoryAAuthAccessStore: public bool TryGet ( string origin , out string token , string ? account = null , string ? signingKeyThumbprint = null )
+ AAuth.Agent.InMemoryAAuthAccessStore: public void Remove ( string origin , string ? account = null , string ? signingKeyThumbprint = null )
+ AAuth.Agent.InMemoryAAuthAccessStore: public void Set ( string origin , string token , string ? account = null , string ? signingKeyThumbprint = null )
```

Public owners: `AAuth.Agent.IAAuthAccessStore`, `AAuth.Agent.InMemoryAAuthAccessStore`, `AAuth.Agent`.

### src/AAuth/Agent/ITokenRefresher.cs

Concept/decision: [agent-clients](#agent-clients). Source: [ITokenRefresher.cs](../../../src/AAuth/Agent/ITokenRefresher.cs).

```diff
+ AAuth.Agent.TokenRefreshContext: public string ? Account { get ; init ; }
```

Public owners: `AAuth.Agent.ITokenRefresher`, `AAuth.Agent.TokenRefreshContext`, `AAuth.Agent`.

### src/AAuth/Agent/InteractionHandler.cs

Concept/decision: [agent-clients](#agent-clients). Source: [InteractionHandler.cs](../../../src/AAuth/Agent/InteractionHandler.cs).

```diff
+ AAuth.Agent.InteractionHandler: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; init ; } = AAuth . Discovery . AAuthEgressPolicy . Production
+ AAuth.Agent.InteractionHandler: public AAuth . Discovery . AAuthTransportContract ? TransportContract { get ; init ; }
+ AAuth.Agent.InteractionHandler: public TimeProvider TimeProvider { get ; init ; } = TimeProvider . System
```

Public owners: `AAuth.Agent.InteractionHandler`, `AAuth.Agent`.

### src/AAuth/Agent/Mission.cs

Concept/decision: [agent-clients](#agent-clients). Source: [Mission.cs](../../../src/AAuth/Agent/Mission.cs).

```diff
- AAuth.Agent.AAuthMissionHeader: public static bool TryParseStructured ( string ? value , out string ? approver , out string ? s256 )
- AAuth.Agent.Mission: public MissionState State { get ; init ; } = MissionState . Active
+ AAuth.Agent.AAuthMissionHeader: public static bool TryParseStructured ( string ? value , out string ? approver , out string ? s256 , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
+ AAuth.Agent.Mission: public MissionState State { get ; init ; }
```

Public owners: `AAuth.Agent.AAuthMissionHeader`, `AAuth.Agent.Mission`, `AAuth.Agent`.

### src/AAuth/Agent/MissionForwardingHandler.cs

Concept/decision: [agent-clients](#agent-clients). Source: [MissionForwardingHandler.cs](../../../src/AAuth/Agent/MissionForwardingHandler.cs).

Public signatures unchanged (3); behavior reviewed under agent-clients.

Public owners: `AAuth.Agent.MissionForwardingHandler`, `AAuth.Agent`.

### src/AAuth/Agent/SelfIssuedTokenRefresher.cs

Concept/decision: [agent-clients](#agent-clients). Source: [SelfIssuedTokenRefresher.cs](../../../src/AAuth/Agent/SelfIssuedTokenRefresher.cs).

```diff
- AAuth.Agent.SelfIssuedTokenRefresher: public SelfIssuedTokenRefresher ( AAuthKey key , string issuer , string subject , string kid , string ? personServer = null , TimeSpan ? lifetime = null )
- AAuth.Agent.SelfIssuedTokenRefresher: public static RefresherBuilder Create ( AAuthKey key , string issuer , string subject )
+ AAuth.Agent.SelfIssuedTokenRefresher.RefresherBuilder: public RefresherBuilder WithEgressPolicy ( AAuth . Discovery . AAuthEgressPolicy policy )
+ AAuth.Agent.SelfIssuedTokenRefresher: public SelfIssuedTokenRefresher ( IAAuthKey key , string issuer , string subject , string kid , string ? personServer = null , TimeSpan ? lifetime = null , AAuth . Discovery . AAuthEgressPolicy ? egressPolicy = null )
+ AAuth.Agent.SelfIssuedTokenRefresher: public static RefresherBuilder Create ( IAAuthKey key , string issuer , string subject )
```

Public owners: `AAuth.Agent.SelfIssuedTokenRefresher.RefresherBuilder`, `AAuth.Agent.SelfIssuedTokenRefresher`, `AAuth.Agent`.

### src/AAuth/Agent/TokenExchangeClient.cs

Concept/decision: [agent-clients](#agent-clients). Source: [TokenExchangeClient.cs](../../../src/AAuth/Agent/TokenExchangeClient.cs).

```diff
+ AAuth.Agent.TokenExchangeClient: public AAuthEgressPolicy EgressPolicy { get ; }
```

Public owners: `AAuth.Agent.TokenExchangeClient`, `AAuth.Agent`.

### src/AAuth/Agent/TokenExchangeRequest.cs

Concept/decision: [agent-clients](#agent-clients). Source: [TokenExchangeRequest.cs](../../../src/AAuth/Agent/TokenExchangeRequest.cs).

```diff
+ AAuth.Agent.TokenExchangeRequest: public string ? Account { get ; init ; }
```

Public owners: `AAuth.Agent.TokenExchangeRequest`, `AAuth.Agent`.

### src/AAuth/BootstrapBuilder.cs

Concept/decision: [agent-clients](#agent-clients). Source: [BootstrapBuilder.cs](../../../src/AAuth/BootstrapBuilder.cs).

```diff
+ AAuth.BootstrapBuilder: public BootstrapBuilder WithDevelopmentLoopback ( params string [  ] origins )
+ AAuth.BootstrapBuilder: public BootstrapBuilder WithEgressPolicy ( Discovery . AAuthEgressPolicy policy )
+ AAuth.BootstrapBuilder: public BootstrapBuilder WithKey ( AAuthKey key )
```

Public owners: `AAuth.BootstrapBuilder`, `AAuth`.

### src/AAuth/Crypto/AAuthKey.cs

Concept/decision: [signatures](#signatures). Source: [AAuthKey.cs](../../../src/AAuth/Crypto/AAuthKey.cs).

```diff
- AAuth.Crypto.AAuthKey: public const string Algorithm = "EdDSA" ;
- AAuth.Crypto.AAuthKey: public const string Ed25519Algorithm = "EdDSA" ;
+ AAuth.Crypto.AAuthKey: public const string Ed25519Algorithm = "Ed25519" ;
```

Public owners: `AAuth.Crypto.AAuthKey`, `AAuth.Crypto`.

### src/AAuth/Crypto/EcdsaAAuthKey.cs

Concept/decision: [signatures](#signatures). Source: [EcdsaAAuthKey.cs](../../../src/AAuth/Crypto/EcdsaAAuthKey.cs).

Public signatures unchanged (13); behavior reviewed under signatures.

Public owners: `AAuth.Crypto.EcdsaAAuthKey`, `AAuth.Crypto`.

### src/AAuth/Crypto/IAAuthKey.cs

Concept/decision: [signatures](#signatures). Source: [IAAuthKey.cs](../../../src/AAuth/Crypto/IAAuthKey.cs).

Public signatures unchanged (8); behavior reviewed under signatures.

Public owners: `AAuth.Crypto.IAAuthKey`, `AAuth.Crypto`.

### src/AAuth/Crypto/JwkValidationException.cs

Concept/decision: [signatures](#signatures). Source: [JwkValidationException.cs](../../../src/AAuth/Crypto/JwkValidationException.cs).

```diff
+ AAuth.Crypto.JwkValidationException: public JwkValidationException ( SignatureErrorCode code , string message , Exception ? inner = null )
+ AAuth.Crypto.JwkValidationException: public SignatureErrorCode Code { get ; }
+ AAuth.Crypto: public sealed class JwkValidationException : ArgumentException
```

Public owners: `AAuth.Crypto.JwkValidationException`, `AAuth.Crypto`.

### src/AAuth/Crypto/KeyFactory.cs

Concept/decision: [signatures](#signatures). Source: [KeyFactory.cs](../../../src/AAuth/Crypto/KeyFactory.cs).

```diff
+ AAuth.Crypto.KeyFactory: public static IAAuthKey FromPublicJwk ( JsonObject jwk )
```

Public owners: `AAuth.Crypto.KeyFactory`, `AAuth.Crypto`.

### src/AAuth/DependencyInjection/AAuthAgentOptions.cs

Concept/decision: [di](#di). Source: [AAuthAgentOptions.cs](../../../src/AAuth/DependencyInjection/AAuthAgentOptions.cs).

```diff
+ AAuth.AAuthAgentOptions: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; set ; } = AAuth . Discovery . AAuthEgressPolicy . Production
+ AAuth.AAuthAgentOptions: public AAuth . HttpSig . ISignatureKeyProvider ? SignatureKeyProvider { get ; set ; }
+ AAuth.AAuthAgentOptions: public string ? AgentToken { get ; set ; }
```

Public owners: `AAuth.AAuthAgentOptions`, `AAuth`.

### src/AAuth/DependencyInjection/AAuthAgentServiceCollectionExtensions.cs

Concept/decision: [di](#di). Source: [AAuthAgentServiceCollectionExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthAgentServiceCollectionExtensions.cs).

Public signatures unchanged (2); behavior reviewed under di.

Public owners: `Microsoft.Extensions.DependencyInjection.AAuthAgentServiceCollectionExtensions`, `Microsoft.Extensions.DependencyInjection`.

### src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs

Concept/decision: [di](#di). Source: [AAuthApplicationBuilderExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs).

Public signatures unchanged (7); behavior reviewed under di.

Public owners: `Microsoft.AspNetCore.Builder.AAuthApplicationBuilderExtensions`, `Microsoft.AspNetCore.Builder`.

### src/AAuth/DependencyInjection/AAuthDiscoveryOptions.cs

Concept/decision: [di](#di). Source: [AAuthDiscoveryOptions.cs](../../../src/AAuth/DependencyInjection/AAuthDiscoveryOptions.cs).

```diff
+ AAuth.AAuthDiscoveryOptions: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; set ; } = AAuth . Discovery . AAuthEgressPolicy . Production
+ AAuth.AAuthDiscoveryOptions: public TimeSpan MaxCacheAge { get ; set ; } = TimeSpan . FromHours ( 24 )
+ AAuth.AAuthDiscoveryOptions: public int MaxCacheEntries { get ; set ; } = 1024
```

Public owners: `AAuth.AAuthDiscoveryOptions`, `AAuth`.

### src/AAuth/DependencyInjection/AAuthDiscoveryServiceCollectionExtensions.cs

Concept/decision: [di](#di). Source: [AAuthDiscoveryServiceCollectionExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthDiscoveryServiceCollectionExtensions.cs).

Public signatures unchanged (2); behavior reviewed under di.

Public owners: `Microsoft.Extensions.DependencyInjection.AAuthDiscoveryServiceCollectionExtensions`, `Microsoft.Extensions.DependencyInjection`.

### src/AAuth/DependencyInjection/AAuthFederationOptions.cs

Concept/decision: [di](#di). Source: [AAuthFederationOptions.cs](../../../src/AAuth/DependencyInjection/AAuthFederationOptions.cs).

```diff
+ AAuth.AAuthFederationOptions: public AAuthTransportContract ? TransportContract { get ; set ; }
+ AAuth: public sealed class AAuthFederationOptions
```

Public owners: `AAuth.AAuthFederationOptions`, `AAuth`.

### src/AAuth/DependencyInjection/AAuthFederationServiceCollectionExtensions.cs

Concept/decision: [di](#di). Source: [AAuthFederationServiceCollectionExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthFederationServiceCollectionExtensions.cs).

```diff
- Microsoft.Extensions.DependencyInjection.AAuthFederationServiceCollectionExtensions: public static IServiceCollection AddAAuthFederation ( this IServiceCollection services , AAuthKey personServerKey , string personServerIssuer , string personServerKeyId )
+ Microsoft.Extensions.DependencyInjection.AAuthFederationServiceCollectionExtensions: public static IServiceCollection AddAAuthFederation ( this IServiceCollection services , IAAuthKey personServerKey , string personServerIssuer , string personServerKeyId )
```

Public owners: `Microsoft.Extensions.DependencyInjection.AAuthFederationServiceCollectionExtensions`, `Microsoft.Extensions.DependencyInjection`.

### src/AAuth/DependencyInjection/AAuthGovernanceApplicationBuilderExtensions.cs

Concept/decision: [di](#di). Source: [AAuthGovernanceApplicationBuilderExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthGovernanceApplicationBuilderExtensions.cs).

Public signatures unchanged (2); behavior reviewed under di.

Public owners: `Microsoft.AspNetCore.Builder.AAuthGovernanceApplicationBuilderExtensions`, `Microsoft.AspNetCore.Builder`.

### src/AAuth/DependencyInjection/AAuthResourceOptions.cs

Concept/decision: [di](#di). Source: [AAuthResourceOptions.cs](../../../src/AAuth/DependencyInjection/AAuthResourceOptions.cs).

```diff
- AAuth.AAuthResourceOptions: public Dictionary < string , AAuthKey > SigningKeys { get ; set ; } = new ( )
+ AAuth.AAuthResourceOptions: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; set ; } = AAuth . Discovery . AAuthEgressPolicy . Production
+ AAuth.AAuthResourceOptions: public Dictionary < string , IAAuthKey > SigningKeys { get ; set ; } = new ( )
+ AAuth.AAuthResourceOptions: public string ? RevocationEndpoint { get ; set ; }
```

Public owners: `AAuth.AAuthResourceOptions`, `AAuth`.

### src/AAuth/DependencyInjection/AAuthResourcePipelineOptions.cs

Concept/decision: [di](#di). Source: [AAuthResourcePipelineOptions.cs](../../../src/AAuth/DependencyInjection/AAuthResourcePipelineOptions.cs).

```diff
- AAuth.AAuthResourcePipelineOptions: public bool RequireIssuerVerification { get ; set ; } = true
+ AAuth.AAuthResourcePipelineOptions: public Func < Microsoft . AspNetCore . Http . HttpContext , string ? > ? AccountSelector { get ; set ; }
```

Public owners: `AAuth.AAuthResourcePipelineOptions`, `AAuth`.

### src/AAuth/DependencyInjection/AAuthResourceServiceCollectionExtensions.cs

Concept/decision: [di](#di). Source: [AAuthResourceServiceCollectionExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthResourceServiceCollectionExtensions.cs).

Public signatures unchanged (6); behavior reviewed under di.

Public owners: `Microsoft.Extensions.DependencyInjection.AAuthResourceServiceCollectionExtensions`, `Microsoft.Extensions.DependencyInjection`.

### src/AAuth/Discovery/AAuthEgressPolicy.cs

Concept/decision: [discovery](#discovery). Source: [AAuthEgressPolicy.cs](../../../src/AAuth/Discovery/AAuthEgressPolicy.cs).

```diff
+ AAuth.Discovery.AAuthEgressPolicy: public AAuthEgressPolicy ( IEnumerable < string > ? developmentLoopbackOrigins = null , IEnumerable < ( string Source , string Target ) > ? crossOriginJwks = null , int maxResponseBytes = 1024 * 1024 , TimeSpan ? requestTimeout = null , IAAuthDnsResolver ? dnsResolver = null )
+ AAuth.Discovery.AAuthEgressPolicy: public TimeSpan RequestTimeout { get ; }
+ AAuth.Discovery.AAuthEgressPolicy: public Uri ValidateJwksUrl ( string value , string metadataIdentifier )
+ AAuth.Discovery.AAuthEgressPolicy: public Uri ValidatePendingLocation ( Uri endpoint , Uri location )
+ AAuth.Discovery.AAuthEgressPolicy: public Uri ValidateUrl ( string value , bool endpoint = false )
+ AAuth.Discovery.AAuthEgressPolicy: public async Task ValidateDestinationAsync ( string value , CancellationToken cancellationToken = default )
+ AAuth.Discovery.AAuthEgressPolicy: public bool IsValidIdentifier ( string ? identifier )
+ AAuth.Discovery.AAuthEgressPolicy: public int MaxResponseBytes { get ; }
+ AAuth.Discovery.AAuthEgressPolicy: public static AAuthEgressPolicy ForDevelopmentLoopback ( params string [  ] origins )
+ AAuth.Discovery.AAuthEgressPolicy: public static AAuthEgressPolicy Production { get ; } = new ( )
+ AAuth.Discovery.AAuthEgressPolicy: public void ValidateIdentifier ( string identifier )
+ AAuth.Discovery.IAAuthDnsResolver: Task < IPAddress [  ] > ResolveAsync ( string host , CancellationToken cancellationToken )
+ AAuth.Discovery: public interface IAAuthDnsResolver
+ AAuth.Discovery: public sealed class AAuthEgressPolicy
```

Public owners: `AAuth.Discovery.AAuthEgressPolicy`, `AAuth.Discovery.IAAuthDnsResolver`, `AAuth.Discovery`.

### src/AAuth/Discovery/AAuthHttpTransport.cs

Concept/decision: [discovery](#discovery). Source: [AAuthHttpTransport.cs](../../../src/AAuth/Discovery/AAuthHttpTransport.cs).

```diff
+ AAuth.Discovery.AAuthHttpTransport: public static AAuthEgressPolicy GetPolicy ( HttpClient client )
+ AAuth.Discovery.AAuthHttpTransport: public static HttpClient AttachPolicy ( HttpClient client , AAuthEgressPolicy policy , AAuthTransportContract contract )
+ AAuth.Discovery.AAuthHttpTransport: public static HttpClient CreateClient ( AAuthEgressPolicy ? policy = null )
+ AAuth.Discovery.AAuthHttpTransport: public static HttpMessageHandler CreateHandler ( AAuthEgressPolicy ? policy = null , HttpMessageHandler ? innerHandler = null , AAuthTransportContract ? contract = null )
+ AAuth.Discovery.AAuthHttpTransport: public static Task < HttpResponseMessage > SendAsync ( HttpClient client , HttpRequestMessage request , CancellationToken cancellationToken = default )
+ AAuth.Discovery.AAuthHttpTransport: public static Task AdmitInteractionAsync ( HttpClient client , string url , CancellationToken cancellationToken = default )
+ AAuth.Discovery.AAuthTransportContract: EnforcesEgressPolicy
+ AAuth.Discovery.AAuthTransportContract: InProcessOnly
+ AAuth.Discovery: public enum AAuthTransportContract
+ AAuth.Discovery: public static class AAuthHttpTransport
```

Public owners: `AAuth.Discovery.AAuthHttpTransport`, `AAuth.Discovery.AAuthTransportContract`, `AAuth.Discovery`.

### src/AAuth/Discovery/JwksClient.cs

Concept/decision: [discovery](#discovery). Source: [JwksClient.cs](../../../src/AAuth/Discovery/JwksClient.cs).

```diff
- AAuth.Discovery.JwksClient: public JwksClient ( HttpClient http , TimeSpan ? cacheTtl = null , TimeSpan ? minRefreshInterval = null , Func < DateTimeOffset > ? clock = null )
- AAuth.Discovery.JwksClient: public async Task < IAAuthKey ? > ForceRefreshKeyAsync ( Uri jwksUri , string kid , CancellationToken cancellationToken = default )
- AAuth.Discovery.JwksClient: public async Task < IAAuthKey ? > ResolveKeyAsync ( Uri jwksUri , string kid , CancellationToken cancellationToken = default )
- AAuth.Discovery: public sealed class JwksClient
+ AAuth.Discovery.JwksClient: public AAuthEgressPolicy Policy { get ; }
+ AAuth.Discovery.JwksClient: public JwksClient ( HttpClient ? http = null , TimeSpan ? cacheTtl = null , TimeSpan ? minRefreshInterval = null , Func < DateTimeOffset > ? clock = null , int maxCacheEntries = 1024 , TimeSpan ? maxCacheAge = null , AAuthEgressPolicy ? policy = null , AAuthTransportContract ? transportContract = null )
+ AAuth.Discovery.JwksClient: public Task < IAAuthKey ? > ForceRefreshKeyAsync ( Uri jwksUri , string kid , CancellationToken cancellationToken = default )
+ AAuth.Discovery.JwksClient: public Task < IAAuthKey ? > ForceRefreshKeyAsync ( Uri jwksUri , string kid , string issuer , CancellationToken cancellationToken = default )
+ AAuth.Discovery.JwksClient: public Task < IAAuthKey ? > ResolveKeyAsync ( Uri jwksUri , string kid , CancellationToken cancellationToken = default )
+ AAuth.Discovery.JwksClient: public Task < IAAuthKey ? > ResolveKeyAsync ( Uri jwksUri , string kid , string issuer , CancellationToken cancellationToken = default )
+ AAuth.Discovery.JwksClient: public void Dispose ( )
+ AAuth.Discovery: public sealed class JwksClient : IDisposable
```

Public owners: `AAuth.Discovery.JwksClient`, `AAuth.Discovery`.

### src/AAuth/Discovery/MetadataClient.cs

Concept/decision: [discovery](#discovery). Source: [MetadataClient.cs](../../../src/AAuth/Discovery/MetadataClient.cs).

```diff
- AAuth.Discovery.MetadataClient: public MetadataClient ( HttpClient http , TimeSpan ? cacheTtl = null , Func < DateTimeOffset > ? clock = null )
- AAuth.Discovery.MetadataClient: public static Uri BuildUrl ( string issuer , string dwk )
- AAuth.Discovery: public sealed class MetadataClient
+ AAuth.Discovery.MetadataClient: public AAuthEgressPolicy Policy { get ; }
+ AAuth.Discovery.MetadataClient: public MetadataClient ( HttpClient ? http = null , TimeSpan ? cacheTtl = null , Func < DateTimeOffset > ? clock = null , AAuthEgressPolicy ? policy = null , AAuthTransportContract ? transportContract = null , int maxCacheEntries = 1024 , TimeSpan ? maxCacheAge = null )
+ AAuth.Discovery.MetadataClient: public Uri GetUrl ( string issuer , string dwk )
+ AAuth.Discovery.MetadataClient: public static Uri BuildUrl ( string issuer , string dwk , AAuthEgressPolicy ? policy = null )
+ AAuth.Discovery.MetadataClient: public void Dispose ( )
+ AAuth.Discovery: public sealed class MetadataClient : IDisposable
```

Public owners: `AAuth.Discovery.MetadataClient`, `AAuth.Discovery`.

### src/AAuth/Discovery/ServerMetadata.cs

Concept/decision: [discovery](#discovery). Source: [ServerMetadata.cs](../../../src/AAuth/Discovery/ServerMetadata.cs).

Public signatures unchanged (37); behavior reviewed under discovery.

Public owners: `AAuth.Discovery.MetadataClientExtensions`, `AAuth.Discovery.ResourceMetadata`, `AAuth.Discovery.ServerMetadata`, `AAuth.Discovery`.

### src/AAuth/EnrolledBuilder.cs

Concept/decision: [agent-clients](#agent-clients). Source: [EnrolledBuilder.cs](../../../src/AAuth/EnrolledBuilder.cs).

```diff
- AAuth.EnrolledBuilder: public AAuthClientBuilder WithInnerHandler ( HttpMessageHandler handler )
+ AAuth.EnrolledBuilder: public AAuthClientBuilder ToBuilder ( )
+ AAuth.EnrolledBuilder: public AAuthClientBuilder WithInnerHandler ( HttpMessageHandler handler , AAuth . Discovery . AAuthTransportContract ? transportContract = null )
+ AAuth.EnrolledBuilder: public AAuthClientBuilder WithResourceManagedAccess ( IAAuthAccessStore ? store = null )
+ AAuth.EnrolledBuilder: public EnrolledBuilder WithDevelopmentLoopback ( params string [  ] origins )
+ AAuth.EnrolledBuilder: public EnrolledBuilder WithEgressPolicy ( AAuth . Discovery . AAuthEgressPolicy policy )
```

Public owners: `AAuth.EnrolledBuilder`, `AAuth`.

### src/AAuth/Errors/AAuthMetadataException.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthMetadataException.cs](../../../src/AAuth/Errors/AAuthMetadataException.cs).

```diff
+ AAuth.Errors.AAuthMetadataException: public SignatureErrorCode Code
+ AAuth.Errors.AAuthMetadataException: public string ErrorCode
```

Public owners: `AAuth.Errors.AAuthMetadataException`, `AAuth.Errors`.

### src/AAuth/Errors/AAuthTokenExchangeException.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthTokenExchangeException.cs](../../../src/AAuth/Errors/AAuthTokenExchangeException.cs).

```diff
- AAuth.Errors.AAuthTokenExchangeException: public AAuthTokenExchangeException ( string errorCode , string ? errorDescription , int statusCode , bool isTerminal )
- AAuth.Errors.AAuthTokenExchangeException: public string ? ErrorDescription { get ; }
+ AAuth.Errors.AAuthTokenExchangeException: public AAuthTokenExchangeException ( string errorCode , string ? detail , int statusCode , bool isTerminal )
+ AAuth.Errors.AAuthTokenExchangeException: public string ? Detail { get ; }
```

Public owners: `AAuth.Errors.AAuthTokenExchangeException`, `AAuth.Errors`.

### src/AAuth/Errors/SignatureError.cs

Concept/decision: [server-contracts](#server-contracts). Source: [SignatureError.cs](../../../src/AAuth/Errors/SignatureError.cs).

```diff
- AAuth.Errors.SignatureError: public static string Format ( SignatureErrorCode code , string [  ] ? requiredInput = null , string [  ] ? supportedAlgorithms = null )
+ AAuth.Errors.SignatureError: public static string Format ( SignatureErrorCode code , string [  ] ? requiredInput = null )
+ AAuth.Errors.SignatureErrorCode: IssuerMismatch
+ AAuth.Errors.SignatureErrorCode: IssuerMissing
+ AAuth.Errors.SignatureErrorCode: UnsupportedScheme
```

Public owners: `AAuth.Errors.SignatureErrorCode`, `AAuth.Errors.SignatureError`, `AAuth.Errors`.

### src/AAuth/Errors/TokenError.cs

Concept/decision: [server-contracts](#server-contracts). Source: [TokenError.cs](../../../src/AAuth/Errors/TokenError.cs).

```diff
- AAuth.Errors: public sealed record TokenErrorResponse ( TokenErrorCode Error , string ? ErrorDescription = null )
+ AAuth.Errors: public sealed record TokenErrorResponse ( TokenErrorCode Error , string ? Detail = null )
```

Public owners: `AAuth.Errors.TokenErrorCode`, `AAuth.Errors.TokenErrorResponse`, `AAuth.Errors`.

### src/AAuth/Headers/ClaimsResponse.cs

Concept/decision: [server-contracts](#server-contracts). Source: [ClaimsResponse.cs](../../../src/AAuth/Headers/ClaimsResponse.cs).

Public signatures unchanged (4); behavior reviewed under server-contracts.

Public owners: `AAuth.Headers.ClaimsResponse`, `AAuth.Headers`.

### src/AAuth/Headers/Interaction.cs

Concept/decision: [server-contracts](#server-contracts). Source: [Interaction.cs](../../../src/AAuth/Headers/Interaction.cs).

```diff
- AAuth.Headers.Interaction: public static Interaction ? FromRequirement ( AAuthRequirementHeader . ParsedRequirement requirement )
- AAuth.Headers.Interaction: public static string Format ( string url , string code )
+ AAuth.Headers.Interaction: public static Interaction ? FromRequirement ( AAuthRequirementHeader . ParsedRequirement requirement , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
+ AAuth.Headers.Interaction: public static string Format ( string url , string code , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
```

Public owners: `AAuth.Headers.Interaction`, `AAuth.Headers`.

### src/AAuth/HttpSig/AAuthSigningHandler.cs

Concept/decision: [signatures](#signatures). Source: [AAuthSigningHandler.cs](../../../src/AAuth/HttpSig/AAuthSigningHandler.cs).

```diff
- AAuth.HttpSig.AAuthSigningHandler: public AAuthSigningHandler ( AAuthKey key , Func < string > tokenFactory , Func < DateTimeOffset > ? clock = null )
+ AAuth.HttpSig.AAuthSigningHandler: public AAuthSigningHandler ( IAAuthKey key , Func < string > tokenFactory , Func < DateTimeOffset > ? clock = null )
+ AAuth.HttpSig.AAuthSigningHandler: public async Task SignAsync ( HttpRequestMessage request , CancellationToken cancellationToken = default )
+ AAuth.HttpSig.AAuthSigningHandler: public string Label { get ; init ; } = "sig"
```

Public owners: `AAuth.HttpSig.AAuthSigningHandler`, `AAuth.HttpSig`.

### src/AAuth/HttpSig/AAuthVerifier.cs

Concept/decision: [signatures](#signatures). Source: [AAuthVerifier.cs](../../../src/AAuth/HttpSig/AAuthVerifier.cs).

```diff
- AAuth.HttpSig.AAuthVerifier: public void Verify ( string method , string authority , string path , string signatureKey , string signatureInput , string signatureHeader , IAAuthKey publicKey , string ? authorization = null , string ? mission = null )
+ AAuth.HttpSig.AAuthVerificationException: public AAuth . Errors . SignatureErrorCode Code { get ; }
+ AAuth.HttpSig.AAuthVerificationException: public AAuthVerificationException ( AAuth . Errors . SignatureErrorCode code , string message , Exception ? inner = null )
+ AAuth.HttpSig.AAuthVerifier: public IReadOnlyDictionary < string , StructuredFieldType > StructuredFieldTypes { get ; init ; } = new Dictionary < string , StructuredFieldType > ( StringComparer . Ordinal ) { [ "signature-key" ] = StructuredFieldType . Dictionary , [ "signature-input" ] = StructuredFieldType . Dictionary , [ "signature" ] = StructuredFieldType . Dictionary , [ "content-digest" ] = StructuredFieldType . Dictionary , [ "repr-digest" ] = StructuredFieldType . Dictionary , }
+ AAuth.HttpSig.AAuthVerifier: public string Verify ( string method , string authority , string path , string signatureKey , string signatureInput , string signatureHeader , IAAuthKey publicKey , string ? authorization = null , string ? mission = null , string label = "sig" , IReadOnlyDictionary < string , string > ? fields = null , IReadOnlyCollection < string > ? requiredComponents = null , string ? keyId = null , IReadOnlyDictionary < string , string [  ] > ? fieldValues = null , string ? requestScheme = null , string ? query = null , string ? requestTarget = null )
```

Public owners: `AAuth.HttpSig.AAuthVerificationException`, `AAuth.HttpSig.AAuthVerifier`, `AAuth.HttpSig`.

### src/AAuth/HttpSig/DefaultSignatureKeyResolver.cs

Concept/decision: [signatures](#signatures). Source: [DefaultSignatureKeyResolver.cs](../../../src/AAuth/HttpSig/DefaultSignatureKeyResolver.cs).

```diff
- AAuth.HttpSig.DefaultSignatureKeyResolver: public DefaultSignatureKeyResolver ( JwksClient ? jwksClient = null )
+ AAuth.HttpSig.DefaultSignatureKeyResolver: public DefaultSignatureKeyResolver ( JwksClient ? jwksClient = null , MetadataClient ? metadataClient = null , TokenVerifier ? tokenVerifier = null , IEnumerable < ISignatureTokenVerifier > ? tokenVerifiers = null )
```

Public owners: `AAuth.HttpSig.DefaultSignatureKeyResolver`, `AAuth.HttpSig`.

### src/AAuth/HttpSig/HwkSignatureKeyProvider.cs

Concept/decision: [signatures](#signatures). Source: [HwkSignatureKeyProvider.cs](../../../src/AAuth/HttpSig/HwkSignatureKeyProvider.cs).

```diff
- AAuth.HttpSig.HwkSignatureKeyProvider: public HwkSignatureKeyProvider ( IAAuthKey key )
+ AAuth.HttpSig.HwkSignatureKeyProvider: public HwkSignatureKeyProvider ( IAAuthKey key , string label = "sig" )
```

Public owners: `AAuth.HttpSig.HwkSignatureKeyProvider`, `AAuth.HttpSig`.

### src/AAuth/HttpSig/ISignatureKeyResolver.cs

Concept/decision: [signatures](#signatures). Source: [ISignatureKeyResolver.cs](../../../src/AAuth/HttpSig/ISignatureKeyResolver.cs).

```diff
+ AAuth.HttpSig.SignatureKeyResolution: public AAuth . Tokens . TokenVerifier . VerifiedToken ? VerifiedToken { get ; init ; }
+ AAuth.HttpSig.SignatureKeyResolution: public IAAuthKey ? IssuerKey { get ; init ; }
+ AAuth.HttpSig.SignatureKeyResolution: public string ? DurableThumbprint { get ; init ; }
+ AAuth.HttpSig.SignatureKeyResolution: public string ? KeyId { get ; init ; }
+ AAuth.HttpSig.SignatureKeyResolution: public string ? VerifiedIdentifier { get ; init ; }
```

Public owners: `AAuth.HttpSig.ISignatureKeyResolver`, `AAuth.HttpSig.SignatureKeyResolution`, `AAuth.HttpSig`.

### src/AAuth/HttpSig/ISignatureTokenVerifier.cs

Concept/decision: [signatures](#signatures). Source: [ISignatureTokenVerifier.cs](../../../src/AAuth/HttpSig/ISignatureTokenVerifier.cs).

```diff
+ AAuth.HttpSig.ISignatureTokenVerifier: Task < TokenVerifier . VerifiedToken > VerifyAsync ( string jwt , IAAuthKey issuerKey , TokenVerifier verifier , CancellationToken cancellationToken )
+ AAuth.HttpSig.ISignatureTokenVerifier: string Scheme { get ; }
+ AAuth.HttpSig.ISignatureTokenVerifier: string TokenType { get ; }
+ AAuth.HttpSig: public interface ISignatureTokenVerifier
```

Public owners: `AAuth.HttpSig.ISignatureTokenVerifier`, `AAuth.HttpSig`.

### src/AAuth/HttpSig/JktJwtSignatureKeyProvider.cs

Concept/decision: [signatures](#signatures). Source: [JktJwtSignatureKeyProvider.cs](../../../src/AAuth/HttpSig/JktJwtSignatureKeyProvider.cs).

```diff
- AAuth.HttpSig.JktJwtSignatureKeyProvider: public JktJwtSignatureKeyProvider ( Func < string > namingJwtFactory )
+ AAuth.HttpSig.JktJwtSignatureKeyProvider: public JktJwtSignatureKeyProvider ( Func < string > namingJwtFactory , string label = "sig" )
```

Public owners: `AAuth.HttpSig.JktJwtSignatureKeyProvider`, `AAuth.HttpSig`.

### src/AAuth/HttpSig/JwksSignatureKeyProvider.cs

Concept/decision: [signatures](#signatures). Source: [JwksSignatureKeyProvider.cs](../../../src/AAuth/HttpSig/JwksSignatureKeyProvider.cs).

```diff
+ AAuth.HttpSig.JwksSignatureKeyProvider: public string GetSignatureKeyHeader ( )
+ AAuth.HttpSig: public sealed class JwksSignatureKeyProvider ( string url , string kid , string label = "sig" ) : ISignatureKeyProvider
```

Public owners: `AAuth.HttpSig.JwksSignatureKeyProvider`, `AAuth.HttpSig`.

### src/AAuth/HttpSig/JwksUriSignatureKeyProvider.cs

Concept/decision: [signatures](#signatures). Source: [JwksUriSignatureKeyProvider.cs](../../../src/AAuth/HttpSig/JwksUriSignatureKeyProvider.cs).

```diff
- AAuth.HttpSig.JwksUriSignatureKeyProvider: public JwksUriSignatureKeyProvider ( string uri , string kid )
+ AAuth.HttpSig.JwksUriSignatureKeyProvider: public JwksUriSignatureKeyProvider ( string id , string dwk , string kid , string label = "sig" )
```

Public owners: `AAuth.HttpSig.JwksUriSignatureKeyProvider`, `AAuth.HttpSig`.

### src/AAuth/HttpSig/JwtSignatureKeyProvider.cs

Concept/decision: [signatures](#signatures). Source: [JwtSignatureKeyProvider.cs](../../../src/AAuth/HttpSig/JwtSignatureKeyProvider.cs).

```diff
- AAuth.HttpSig.JwtSignatureKeyProvider: public JwtSignatureKeyProvider ( Func < string > tokenFactory )
+ AAuth.HttpSig.JwtSignatureKeyProvider: public JwtSignatureKeyProvider ( Func < System . Net . Http . HttpRequestMessage , string > tokenFactory , string label = "sig" )
+ AAuth.HttpSig.JwtSignatureKeyProvider: public JwtSignatureKeyProvider ( Func < string > tokenFactory , string label = "sig" )
+ AAuth.HttpSig.JwtSignatureKeyProvider: public string GetSignatureKeyHeader ( System . Net . Http . HttpRequestMessage request )
```

Public owners: `AAuth.HttpSig.JwtSignatureKeyProvider`, `AAuth.HttpSig`.

### src/AAuth/HttpSig/NamingTokenVerifier.cs

Concept/decision: [signatures](#signatures). Source: [NamingTokenVerifier.cs](../../../src/AAuth/HttpSig/NamingTokenVerifier.cs).

```diff
+ AAuth.HttpSig.NamingTokenVerifier: public sealed record VerifiedNamingToken ( IAAuthKey DurableKey , IAAuthKey ConfirmationKey , string Issuer , DateTimeOffset ExpiresAt )
+ AAuth.HttpSig.NamingTokenVerifier: public static VerifiedNamingToken Verify ( string jwt , DateTimeOffset now , TimeSpan clockSkew )
+ AAuth.HttpSig: public static class NamingTokenVerifier
```

Public owners: `AAuth.HttpSig.NamingTokenVerifier`, `AAuth.HttpSig`.

### src/AAuth/HttpSig/SelfJwtSignatureKeyProvider.cs

Concept/decision: [signatures](#signatures). Source: [SelfJwtSignatureKeyProvider.cs](../../../src/AAuth/HttpSig/SelfJwtSignatureKeyProvider.cs).

```diff
+ AAuth.HttpSig.SelfJwtSignatureKeyProvider: public string GetSignatureKeyHeader ( )
+ AAuth.HttpSig: public sealed class SelfJwtSignatureKeyProvider ( Func < string > tokenFactory , string label = "sig" ) : ISignatureKeyProvider
```

Public owners: `AAuth.HttpSig.SelfJwtSignatureKeyProvider`, `AAuth.HttpSig`.

### src/AAuth/HttpSig/SignatureKeyHeader.cs

Concept/decision: [signatures](#signatures). Source: [SignatureKeyHeader.cs](../../../src/AAuth/HttpSig/SignatureKeyHeader.cs).

```diff
- AAuth.HttpSig.SignatureKeyHeader: public static ( string Scheme , IReadOnlyDictionary < string , string > Parameters ) Parse ( string headerValue )
- AAuth.HttpSig.SignatureKeyHeader: public static string ? GetJwt ( string headerValue )
- AAuth.HttpSig.SignatureKeyHeader: public static string FormatHwk ( string jkt , string jwkBase64Url )
- AAuth.HttpSig.SignatureKeyHeader: public static string FormatJktJwt ( string jwt )
- AAuth.HttpSig.SignatureKeyHeader: public static string FormatJwksUri ( string uri , string kid )
- AAuth.HttpSig.SignatureKeyHeader: public static string FormatJwt ( string jwt )
+ AAuth.HttpSig.SignatureKeyHeader: public static ( string Scheme , IReadOnlyDictionary < string , object > Parameters ) Parse ( string headerValue , string label = "sig" )
+ AAuth.HttpSig.SignatureKeyHeader: public static string ? GetJwt ( string headerValue , string label = "sig" )
+ AAuth.HttpSig.SignatureKeyHeader: public static string FormatHwk ( IAAuthKey key , string label = "sig" )
+ AAuth.HttpSig.SignatureKeyHeader: public static string FormatJktJwt ( string jwt , string label = "sig" )
+ AAuth.HttpSig.SignatureKeyHeader: public static string FormatJwks ( string url , string kid , string label = "sig" )
+ AAuth.HttpSig.SignatureKeyHeader: public static string FormatJwksUri ( string id , string dwk , string kid , string label = "sig" )
+ AAuth.HttpSig.SignatureKeyHeader: public static string FormatJwt ( string jwt , string label = "sig" )
+ AAuth.HttpSig.SignatureKeyHeader: public static string FormatSelfJwt ( string jwt , string label = "sig" )
```

Public owners: `AAuth.HttpSig.SignatureKeyHeader`, `AAuth.HttpSig`.

### src/AAuth/HttpSig/SignatureKeyParser.cs

Concept/decision: [signatures](#signatures). Source: [SignatureKeyParser.cs](../../../src/AAuth/HttpSig/SignatureKeyParser.cs).

```diff
- AAuth.HttpSig.SignatureKeyParser.ParsedSignatureKey: public DateTimeOffset ? Expiration { get ; }
- AAuth.HttpSig.SignatureKeyParser: public sealed record ParsedSignatureKey ( string Jwt , JsonObject Header , JsonObject Payload , AAuthKey ConfirmationKey )
- AAuth.HttpSig.SignatureKeyParser: public static ParsedSignatureKey Parse ( string signatureKeyHeader )
- AAuth.HttpSig.SignatureKeyParser: public static ParsedSignatureKeyInfo ParseAny ( string signatureKeyHeader )
+ AAuth.HttpSig.SignatureKeyParser.ParsedSignatureKey: public DateTimeOffset ? Expiration
+ AAuth.HttpSig.SignatureKeyParser.ParsedSignatureKeyInfo: public string ? Dwk { get ; init ; }
+ AAuth.HttpSig.SignatureKeyParser.ParsedSignatureKeyInfo: public string ? Identifier { get ; init ; }
+ AAuth.HttpSig.SignatureKeyParser.ParsedSignatureKeyInfo: public string Label { get ; init ; } = "sig"
+ AAuth.HttpSig.SignatureKeyParser: public sealed record ParsedSignatureKey ( string Jwt , JsonObject Header , JsonObject Payload , IAAuthKey ConfirmationKey )
+ AAuth.HttpSig.SignatureKeyParser: public static ParsedSignatureKey Parse ( string signatureKeyHeader , string label = "sig" )
+ AAuth.HttpSig.SignatureKeyParser: public static ParsedSignatureKeyInfo ParseAny ( string signatureKeyHeader , string label = "sig" )
```

Public owners: `AAuth.HttpSig.SignatureKeyParser.ParsedSignatureKeyInfo`, `AAuth.HttpSig.SignatureKeyParser.ParsedSignatureKey`, `AAuth.HttpSig.SignatureKeyParser`, `AAuth.HttpSig`.

### src/AAuth/HttpSig/StructuredFieldType.cs

Concept/decision: [signatures](#signatures). Source: [StructuredFieldType.cs](../../../src/AAuth/HttpSig/StructuredFieldType.cs).

```diff
+ AAuth.HttpSig.StructuredFieldType: Dictionary
+ AAuth.HttpSig.StructuredFieldType: Item
+ AAuth.HttpSig.StructuredFieldType: List
+ AAuth.HttpSig: public enum StructuredFieldType
```

Public owners: `AAuth.HttpSig.StructuredFieldType`, `AAuth.HttpSig`.

### src/AAuth/Identifiers/AgentId.cs

Concept/decision: [discovery](#discovery). Source: [AgentId.cs](../../../src/AAuth/Identifiers/AgentId.cs).

```diff
- AAuth.Identifiers.AgentId: public static AgentId Parse ( string input )
- AAuth.Identifiers.AgentId: public static bool TryParse ( string ? input , out AgentId result , out string ? error )
+ AAuth.Identifiers.AgentId: public static AgentId Parse ( string input , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
+ AAuth.Identifiers.AgentId: public static bool TryParse ( string ? input , out AgentId result , out string ? error , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
```

Public owners: `AAuth.Identifiers.AgentId`, `AAuth.Identifiers`.

### src/AAuth/Identifiers/ServerId.cs

Concept/decision: [discovery](#discovery). Source: [ServerId.cs](../../../src/AAuth/Identifiers/ServerId.cs).

```diff
- AAuth.Identifiers.ServerId: public static ServerId Parse ( string input )
- AAuth.Identifiers.ServerId: public static bool TryParse ( string ? input , out ServerId result , out string ? error )
+ AAuth.Identifiers.ServerId: public static ServerId Parse ( string input , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
+ AAuth.Identifiers.ServerId: public static bool TryParse ( string ? input , out ServerId result , out string ? error , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
```

Public owners: `AAuth.Identifiers.ServerId`, `AAuth.Identifiers`.

### src/AAuth/Person/AAuthPersonServerEndpoints.cs

Concept/decision: [consent](#consent). Source: [AAuthPersonServerEndpoints.cs](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs).

```diff
- AAuth.Person.AAuthPersonServerOptions: public required IReadOnlyDictionary < string , AAuthKey > SigningKeys { get ; init ; }
+ AAuth.Person.AAuthPersonServerOptions: public AAuthEgressPolicy EgressPolicy { get ; init ; } = AAuthEgressPolicy . Production
+ AAuth.Person.AAuthPersonServerOptions: public Action < AAuthRevocationOptions > ? ConfigureRevocation { get ; init ; }
+ AAuth.Person.AAuthPersonServerOptions: public BrowserConsentSessions ? ResourceInteractionSessions { get ; init ; }
+ AAuth.Person.AAuthPersonServerOptions: public Func < PersonPendingEntry , ClarificationRequirement , System . Threading . CancellationToken , Task < ClarificationResponse ? > > ? TriageClarificationAsync { get ; init ; }
+ AAuth.Person.AAuthPersonServerOptions: public IReadOnlyList < string > ? ScopesSupported { get ; init ; }
+ AAuth.Person.AAuthPersonServerOptions: public TimeProvider TimeProvider { get ; init ; } = TimeProvider . System
+ AAuth.Person.AAuthPersonServerOptions: public required IReadOnlyDictionary < string , IAAuthKey > SigningKeys { get ; init ; }
+ AAuth.Person.AAuthPersonServerOptions: public string RevocationPath { get ; init ; } = "/revoke"
```

Public owners: `AAuth.Person.AAuthPersonServerEndpoints`, `AAuth.Person.AAuthPersonServerOptions`, `AAuth.Person`.

### src/AAuth/Person/IIdentityClaimsAsserter.cs

Concept/decision: [consent](#consent). Source: [IIdentityClaimsAsserter.cs](../../../src/AAuth/Person/IIdentityClaimsAsserter.cs).

```diff
+ AAuth.Person.IdentityAssertionRequest: public JsonObject ? ResourceContext { get ; init ; }
+ AAuth.Person.IdentityAssertionRequest: public UpstreamTokenValidationResult ? UpstreamAuthorization { get ; init ; }
+ AAuth.Person.IdentityAssertionRequest: public string ? Account { get ; init ; }
+ AAuth.Person.IdentityAssertionRequest: public string ? AgentKeyThumbprint { get ; init ; }
```

Public owners: `AAuth.Person.DefaultIdentityClaimsAsserter`, `AAuth.Person.IIdentityClaimsAsserter`, `AAuth.Person.IdentityAssertionKind`, `AAuth.Person.IdentityAssertionRequest`, `AAuth.Person.IdentityAssertion`, `AAuth.Person`.

### src/AAuth/Person/IPersonPendingStore.cs

Concept/decision: [consent](#consent). Source: [IPersonPendingStore.cs](../../../src/AAuth/Person/IPersonPendingStore.cs).

```diff
- AAuth.Person.IPersonPendingStore: PersonPendingEntry Add ( string resourceUrl , string scope , string agentId , IAAuthKey ? agentConfirmationKey , JsonObject ? upstreamAct = null , MissionClaim ? mission = null )
- AAuth.Person.InMemoryPersonPendingStore: public PersonPendingEntry Add ( string resourceUrl , string scope , string agentId , IAAuthKey ? agentConfirmationKey , JsonObject ? upstreamAct = null , MissionClaim ? mission = null )
- AAuth.Person.PersonPendingEntry: public MissionClaim ? Mission { get ; init ; }
- AAuth.Person.PersonPendingEntry: public required string Scope { get ; init ; }
+ AAuth.Person.IPersonPendingStore: PersonPendingEntry ? GetByCode ( string code )
+ AAuth.Person.IPersonPendingStore: PersonPendingEntry Add ( string resourceUrl , string scope , string agentId , IAAuthKey ? agentConfirmationKey , DateTimeOffset agentTokenExpiresAt , JsonObject ? upstreamAct = null , MissionClaim ? mission = null , DateTimeOffset ? authorizationExpiresAt = null )
+ AAuth.Person.InMemoryPersonPendingStore: public PersonPendingEntry ? GetByCode ( string code )
+ AAuth.Person.InMemoryPersonPendingStore: public PersonPendingEntry Add ( string resourceUrl , string scope , string agentId , IAAuthKey ? agentConfirmationKey , DateTimeOffset agentTokenExpiresAt , JsonObject ? upstreamAct = null , MissionClaim ? mission = null , DateTimeOffset ? authorizationExpiresAt = null )
+ AAuth.Person.PersonPendingEntry: public AAuth . Server . BrowserInteraction Browser { get ; } = new ( )
+ AAuth.Person.PersonPendingEntry: public AAuth . Server . DeferredState Lifecycle { get ; } = new ( )
+ AAuth.Person.PersonPendingEntry: public DateTimeOffset ? AuthorizationExpiresAt { get ; init ; }
+ AAuth.Person.PersonPendingEntry: public DateTimeOffset ? ClarificationDeadline { get ; set ; }
+ AAuth.Person.PersonPendingEntry: public DateTimeOffset ExpiresAt
+ AAuth.Person.PersonPendingEntry: public DateTimeOffset PendingExpiresAt
+ AAuth.Person.PersonPendingEntry: public IReadOnlyList < AAuth . Server . TokenKey > SourceTokens { get ; set ; } = [ ]
+ AAuth.Person.PersonPendingEntry: public IReadOnlyList < string > ? RequiredIdentityClaims { get ; set ; }
+ AAuth.Person.PersonPendingEntry: public JsonObject ? ResourceContext { get ; set ; }
+ AAuth.Person.PersonPendingEntry: public MissionClaim ? Mission { get ; set ; }
+ AAuth.Person.PersonPendingEntry: public System . Threading . CancellationTokenSource FederationCancellation { get ; } = new ( )
+ AAuth.Person.PersonPendingEntry: public TaskCompletionSource < AAuth . Agent . ClarificationResponse > ? FederationAnswer { get ; set ; }
+ AAuth.Person.PersonPendingEntry: public TaskCompletionSource < IdentityAssertion > ? FederationConsent { get ; set ; }
+ AAuth.Person.PersonPendingEntry: public UpstreamTokenValidationResult ? UpstreamAuthorization { get ; set ; }
+ AAuth.Person.PersonPendingEntry: public bool AwaitingFederationConsent
+ AAuth.Person.PersonPendingEntry: public bool AwaitingResourceInteraction
+ AAuth.Person.PersonPendingEntry: public int ClarificationRounds { get ; set ; }
+ AAuth.Person.PersonPendingEntry: public required DateTimeOffset AgentTokenExpiresAt { get ; init ; }
+ AAuth.Person.PersonPendingEntry: public required string Scope { get ; set ; }
+ AAuth.Person.PersonPendingEntry: public string ? Account
+ AAuth.Person.PersonPendingEntry: public string ? OwnerIssuer { get ; set ; }
+ AAuth.Person.PersonPendingEntry: public string ? OwnerKeyThumbprint { get ; set ; }
+ AAuth.Person.PersonPendingEntry: public string ? OwnerSubject { get ; set ; }
+ AAuth.Person.PersonPendingEntry: public string ? ResourceAudience { get ; set ; }
+ AAuth.Person.PersonPendingEntry: public string ? ResourceKeyThumbprint { get ; set ; }
+ AAuth.Person.PersonPendingEntry: public string ? ResourceToken { get ; set ; }
+ AAuth.Person.PersonPendingEntry: public string ConsentAgentId
```

Public owners: `AAuth.Person.IPersonPendingStore`, `AAuth.Person.InMemoryPersonPendingStore`, `AAuth.Person.PersonPendingEntry`, `AAuth.Person.PersonPendingStatus`, `AAuth.Person`.

### src/AAuth/SelfIssuingBuilder.cs

Concept/decision: [agent-clients](#agent-clients). Source: [SelfIssuingBuilder.cs](../../../src/AAuth/SelfIssuingBuilder.cs).

```diff
- AAuth.SelfIssuingBuilder: public AAuthClientBuilder WithInnerHandler ( HttpMessageHandler handler )
+ AAuth.SelfIssuingBuilder: public AAuthClientBuilder ToBuilder ( )
+ AAuth.SelfIssuingBuilder: public AAuthClientBuilder WithInnerHandler ( HttpMessageHandler handler , AAuth . Discovery . AAuthTransportContract ? transportContract = null )
+ AAuth.SelfIssuingBuilder: public AAuthClientBuilder WithInteractionHandling ( )
+ AAuth.SelfIssuingBuilder: public AAuthClientBuilder WithInteractionHandling ( Action < InteractionHandlingOptions > configure )
+ AAuth.SelfIssuingBuilder: public AAuthClientBuilder WithResourceManagedAccess ( Agent . IAAuthAccessStore ? store = null )
+ AAuth.SelfIssuingBuilder: public SelfIssuingBuilder WithDevelopmentLoopback ( params string [  ] origins )
+ AAuth.SelfIssuingBuilder: public SelfIssuingBuilder WithEgressPolicy ( AAuth . Discovery . AAuthEgressPolicy policy )
```

Public owners: `AAuth.SelfIssuingBuilder`, `AAuth`.

### src/AAuth/Server/AAuthAuthorizationRequest.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthAuthorizationRequest.cs](../../../src/AAuth/Server/AAuthAuthorizationRequest.cs).

```diff
+ AAuth.Server.AAuthAuthorizationRequest: public string ? Account { get ; init ; }
```

Public owners: `AAuth.Server.AAuthAuthorizationRequest`, `AAuth.Server`.

### src/AAuth/Server/AAuthProblemDetails.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthProblemDetails.cs](../../../src/AAuth/Server/AAuthProblemDetails.cs).

```diff
+ AAuth.Server.AAuthProblemDetails: public const string ContentType = "application/problem+json" ;
+ AAuth.Server.AAuthProblemDetails: public static IResult Create ( string error , string ? detail = null , int statusCode = StatusCodes . Status400BadRequest , IDictionary < string , object ? > ? extensions = null )
+ AAuth.Server.AAuthProblemDetails: public static IResult TokenFailure ( Tokens . TokenVerificationException exception , Tokens . TokenCredential credential = Tokens . TokenCredential . Agent )
+ AAuth.Server.AAuthProblemDetails: public static Task WriteAsync ( HttpContext context , string error , string ? detail = null , int statusCode = StatusCodes . Status400BadRequest , IDictionary < string , object ? > ? extensions = null )
+ AAuth.Server: public static class AAuthProblemDetails
```

Public owners: `AAuth.Server.AAuthProblemDetails`, `AAuth.Server`.

### src/AAuth/Server/AAuthRevocationOptions.cs

Concept/decision: [revocation](#revocation). Source: [AAuthRevocationOptions.cs](../../../src/AAuth/Server/AAuthRevocationOptions.cs).

```diff
- AAuth.Server.AAuthRevocationOptions: public Func < string , bool > ? IsTrustedRevoker { get ; set ; }
- AAuth.Server.AAuthRevocationOptions: public IReadOnlyCollection < string > ? TrustedRevokers { get ; set ; }
+ AAuth.Server.AAuthRevocationOptions: public Func < TokenGrant , CancellationToken , Task < bool > > ? RevokeGrantAsync { get ; set ; }
+ AAuth.Server.AAuthRevocationOptions: public Func < string , TokenKey , bool > ? IsTrustedPersonServer { get ; set ; }
+ AAuth.Server.AAuthRevocationOptions: public IReadOnlyCollection < string > ? TrustedPersonServers { get ; set ; }
+ AAuth.Server.AAuthRevocationOptions: public bool AllowTokenIssuer { get ; set ; }
```

Public owners: `AAuth.Server.AAuthRevocationOptions`, `AAuth.Server`.

### src/AAuth/Server/AuthTokenResponse.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AuthTokenResponse.cs](../../../src/AAuth/Server/AuthTokenResponse.cs).

```diff
+ AAuth.Server.AuthTokenResponse: public static IResult Create ( Func < string > mint , DateTimeOffset ceiling , TimeProvider ? timeProvider = null )
+ AAuth.Server.AuthTokenResponse: public static IResult Create ( string token , DateTimeOffset ceiling , TimeProvider ? timeProvider = null )
+ AAuth.Server.AuthTokenResponse: public static IResult Expired ( )
+ AAuth.Server.AuthTokenResponse: public static async Task < IResult > CreateTrackedAsync ( Func < string > mint , DateTimeOffset ceiling , IJtiStore inventory , IReadOnlyCollection < TokenKey > sources , TimeProvider ? timeProvider = null , CancellationToken cancellationToken = default )
+ AAuth.Server: public static class AuthTokenResponse
```

Public owners: `AAuth.Server.AuthTokenResponse`, `AAuth.Server`.

### src/AAuth/Server/BrowserConsentSessions.cs

Concept/decision: [consent](#consent). Source: [BrowserConsentSessions.cs](../../../src/AAuth/Server/BrowserConsentSessions.cs).

```diff
+ AAuth.Server.BrowserConsentDecision: public Task < IResult > ApplyAsync ( HttpContext context , Func < IResult > mutation )
+ AAuth.Server.BrowserConsentDecision: public async Task < IResult > ApplyAsync ( HttpContext context , Func < Task < IResult > > mutation )
+ AAuth.Server.BrowserConsentDecision: public string Id
+ AAuth.Server.BrowserConsentSessions: public BrowserConsentSessions ( string cookieName , string ? isolatedDemoIdentity = null , Func < HttpContext , BrowserPendingRequest , BrowserConsentIdentity , bool > ? authorizePerson = null , Func < HttpContext , bool > ? isolatedDemoAccess = null )
+ AAuth.Server.BrowserConsentSessions: public async Task < ( BrowserConsentDecision ? Decision , IResult ? Error ) > DecideAsync ( HttpContext context , bool externalLogin = false , string ? externalState = null )
+ AAuth.Server.BrowserConsentSessions: public async Task < ( string ? Id , string ? Decision , IResult ? Error ) > EnterAsync ( HttpContext context , Func < string , BrowserPendingRequest ? > lookup , bool externalLogin = false )
+ AAuth.Server.BrowserConsentSessions: public string ? DemoIdentity { get ; }
+ AAuth.Server.BrowserConsentSessions: public string Fields ( HttpContext context , string decision )
+ AAuth.Server.BrowserInteraction: public string Code { get ; private set ; } = InteractionCode . Generate ( 26 )
+ AAuth.Server.BrowserInteraction: public void Renew ( )
+ AAuth.Server: public sealed class BrowserConsentDecision
+ AAuth.Server: public sealed class BrowserConsentSessions
+ AAuth.Server: public sealed class BrowserInteraction
+ AAuth.Server: public sealed record BrowserConsentIdentity ( string AuthenticationType , string Issuer , string Subject )
+ AAuth.Server: public sealed record BrowserPendingRequest ( string Id , DateTimeOffset ExpiresAt , BrowserInteraction Browser , DeferredState Lifecycle )
```

Public owners: `AAuth.Server.BrowserConsentDecision`, `AAuth.Server.BrowserConsentSessions`, `AAuth.Server.BrowserInteraction`, `AAuth.Server`.

### src/AAuth/Server/CallChaining/CallChainingHandler.cs

Concept/decision: [governance](#governance). Source: [CallChainingHandler.cs](../../../src/AAuth/Server/CallChaining/CallChainingHandler.cs).

```diff
- AAuth.Server.CallChaining.CallChainingHandler: public async Task < string > ExchangeForDownstreamAsync ( string upstreamAuthToken , string resourceToken , Func < Interaction , CancellationToken , Task > ? onInteractionRequired = null , DeferredPollerOptions ? pollerOptions = null , CancellationToken cancellationToken = default )
+ AAuth.Server.CallChaining.CallChainingHandler: public async Task < string > ExchangeForDownstreamAsync ( string upstreamAuthToken , string resourceToken , Func < Interaction , CancellationToken , Task > ? onInteractionRequired = null , DeferredPollerOptions ? pollerOptions = null , CancellationToken cancellationToken = default , string ? account = null )
```

Public owners: `AAuth.Server.CallChaining.CallChainingHandler`, `AAuth.Server.CallChaining`.

### src/AAuth/Server/CallChaining/CallChainingRouter.cs

Concept/decision: [governance](#governance). Source: [CallChainingRouter.cs](../../../src/AAuth/Server/CallChaining/CallChainingRouter.cs).

```diff
- AAuth.Server.CallChaining.CallChainingRouter: public static string ResolveDownstreamServer ( string upstreamAuthToken )
+ AAuth.Server.CallChaining.CallChainingRouter: public static string ResolveDownstreamServer ( string upstreamAuthToken , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
```

Public owners: `AAuth.Server.CallChaining.CallChainingRouter`, `AAuth.Server.CallChaining`.

### src/AAuth/Server/Challenge/AAuthChallengeMiddleware.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthChallengeMiddleware.cs](../../../src/AAuth/Server/Challenge/AAuthChallengeMiddleware.cs).

Public signatures unchanged (3); behavior reviewed under server-contracts.

Public owners: `AAuth.Server.Challenge.AAuthChallengeMiddleware`, `AAuth.Server.Challenge`.

### src/AAuth/Server/Challenge/ChallengeOptions.cs

Concept/decision: [server-contracts](#server-contracts). Source: [ChallengeOptions.cs](../../../src/AAuth/Server/Challenge/ChallengeOptions.cs).

```diff
- AAuth.Server.Challenge.ChallengeOptions: public AAuthKey ? ResourceSigningKey { get ; init ; }
+ AAuth.Server.Challenge.ChallengeOptions: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; set ; } = AAuth . Discovery . AAuthEgressPolicy . Production
+ AAuth.Server.Challenge.ChallengeOptions: public IAAuthKey ? ResourceSigningKey { get ; init ; }
+ AAuth.Server.Challenge.ChallengeOptions: public IReadOnlyDictionary < string , string > ? ScopeDescriptions { get ; init ; }
+ AAuth.Server.Challenge.ChallengeOptions: public System . Func < Microsoft . AspNetCore . Http . HttpContext , string ? > ? RequestedAccount { get ; init ; }
```

Public owners: `AAuth.Server.Challenge.ChallengeOptions`, `AAuth.Server.Challenge`.

### src/AAuth/Server/DeferredState.cs

Concept/decision: [consent](#consent). Source: [DeferredState.cs](../../../src/AAuth/Server/DeferredState.cs).

```diff
+ AAuth.Server.DeferredState: public SemaphoreSlim Gate { get ; } = new ( 1 , 1 )
+ AAuth.Server.DeferredState: public async Task < IResult > ExecuteAsync ( HttpContext context , DateTimeOffset expiry , TimeProvider timeProvider , Func < Task < IResult > > operation )
+ AAuth.Server.DeferredState: public bool Cancelled { get ; private set ; }
+ AAuth.Server.DeferredState: public bool Delivered { get ; private set ; }
+ AAuth.Server.DeferredState: public bool InvalidCode { get ; set ; }
+ AAuth.Server.DeferredState: public static IResult Missing ( string id )
+ AAuth.Server.DeferredState: public void Cancel ( )
+ AAuth.Server: public sealed class DeferredState
```

Public owners: `AAuth.Server.DeferredState`, `AAuth.Server`.

### src/AAuth/Server/Endpoints/AAuthEndpointExtensions.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthEndpointExtensions.cs](../../../src/AAuth/Server/Endpoints/AAuthEndpointExtensions.cs).

```diff
+ Microsoft.AspNetCore.Builder.AAuthEndpointExtensions: public static RouteHandlerBuilder RequireGenericSignature ( this RouteHandlerBuilder builder , bool identified = false )
```

Public owners: `Microsoft.AspNetCore.Builder.AAuthEndpointExtensions`, `Microsoft.AspNetCore.Builder`.

### src/AAuth/Server/Endpoints/AAuthEndpointRequirement.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthEndpointRequirement.cs](../../../src/AAuth/Server/Endpoints/AAuthEndpointRequirement.cs).

```diff
- AAuth.Server.Endpoints.AAuthServerOptions: public AAuthKey ? ResourceSigningKey { get ; set ; }
- AAuth.Server.Endpoints.AAuthServerOptions: public bool RequireIssuerVerification { get ; set ; } = true
+ AAuth.Server.Endpoints.AAuthEndpointRequirement: public IReadOnlyList < string > AcceptedSchemes { get ; init ; } = [ "jwt" ]
+ AAuth.Server.Endpoints.AAuthServerOptions: public IAAuthKey ? ResourceSigningKey { get ; set ; }
```

Public owners: `AAuth.Server.Endpoints.AAuthEndpointRequirement`, `AAuth.Server.Endpoints.AAuthServerOptions`, `AAuth.Server.Endpoints`.

### src/AAuth/Server/Governance/AAuthGovernancePipelineOptions.cs

Concept/decision: [governance](#governance). Source: [AAuthGovernancePipelineOptions.cs](../../../src/AAuth/Server/Governance/AAuthGovernancePipelineOptions.cs).

```diff
+ AAuth.Server.Governance.AAuthGovernancePipelineOptions: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; set ; } = AAuth . Discovery . AAuthEgressPolicy . Production
```

Public owners: `AAuth.Server.Governance.AAuthGovernancePipelineOptions`, `AAuth.Server.Governance`.

### src/AAuth/Server/Governance/GovernanceEndpoints.cs

Concept/decision: [governance](#governance). Source: [GovernanceEndpoints.cs](../../../src/AAuth/Server/Governance/GovernanceEndpoints.cs).

```diff
- AAuth.Server.Governance.GovernanceEndpoints: public static AuditRecord ParseAudit ( JsonObject body )
- AAuth.Server.Governance.GovernanceEndpoints: public static InteractionRequest ParseInteraction ( JsonObject body )
- AAuth.Server.Governance.GovernanceEndpoints: public static PermissionRequest ParsePermission ( JsonObject body )
+ AAuth.Server.Governance.GovernanceEndpoints: public static AuditRecord ParseAudit ( JsonObject body , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
+ AAuth.Server.Governance.GovernanceEndpoints: public static IResult ? Authorize ( HttpContext context , MissionClaim ? reference , StoredMission ? mission )
+ AAuth.Server.Governance.GovernanceEndpoints: public static InteractionRequest ParseInteraction ( JsonObject body , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
+ AAuth.Server.Governance.GovernanceEndpoints: public static PermissionRequest ParsePermission ( JsonObject body , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
```

Public owners: `AAuth.Server.Governance.GovernanceEndpoints`, `AAuth.Server.Governance`.

### src/AAuth/Server/Governance/IDeferredConsentStore.cs

Concept/decision: [consent](#consent). Source: [IDeferredConsentStore.cs](../../../src/AAuth/Server/Governance/IDeferredConsentStore.cs).

```diff
+ AAuth.Server.Governance.DeferredConsent: public DateTimeOffset ExpiresAt { get ; init ; } = DateTimeOffset . UtcNow . AddMinutes ( 10 )
+ AAuth.Server.Governance.DeferredConsent: public DeferredState Lifecycle { get ; } = new ( )
+ AAuth.Server.Governance.DeferredConsent: public string ? OwnerIssuer { get ; init ; }
+ AAuth.Server.Governance.DeferredConsent: public string ? OwnerKeyThumbprint { get ; init ; }
+ AAuth.Server.Governance.DeferredConsent: public string Code { get ; } = AAuth . Headers . InteractionCode . Generate ( 26 )
+ AAuth.Server.Governance.IDeferredConsentStore: Task < DeferredConsent ? > GetByCodeAsync ( string code , CancellationToken ct = default )
```

Public owners: `AAuth.Server.Governance.DeferredConsentKind`, `AAuth.Server.Governance.DeferredConsent`, `AAuth.Server.Governance.IDeferredConsentStore`, `AAuth.Server.Governance`.

### src/AAuth/Server/Governance/IMissionLog.cs

Concept/decision: [governance](#governance). Source: [IMissionLog.cs](../../../src/AAuth/Server/Governance/IMissionLog.cs).

```diff
- AAuth.Server.Governance.IMissionLog: Task < bool > HasPriorConsentAsync ( string s256 , string resource , string scope , CancellationToken ct = default )
+ AAuth.Server.Governance.IMissionLog: Task < bool > HasPriorConsentAsync ( string s256 , string resource , string scope , CancellationToken ct = default , string ? account = null , string ? agentId = null , string ? agentKeyThumbprint = null )
+ AAuth.Server.Governance.MissionLogEntry: public string ? Account { get ; init ; }
+ AAuth.Server.Governance.MissionLogEntry: public string ? AgentId { get ; init ; }
+ AAuth.Server.Governance.MissionLogEntry: public string ? AgentKeyThumbprint { get ; init ; }
```

Public owners: `AAuth.Server.Governance.IMissionLog`, `AAuth.Server.Governance.MissionLogEntryKind`, `AAuth.Server.Governance.MissionLogEntry`, `AAuth.Server.Governance`.

### src/AAuth/Server/Governance/IMissionTokenConsent.cs

Concept/decision: [consent](#consent). Source: [IMissionTokenConsent.cs](../../../src/AAuth/Server/Governance/IMissionTokenConsent.cs).

```diff
+ AAuth.Server.Governance.MissionTokenConsentContext: public StoredMission ? ValidatedApproval { get ; internal init ; }
+ AAuth.Server.Governance.MissionTokenConsentContext: public System . Text . Json . Nodes . JsonObject ? ResourceContext { get ; init ; }
+ AAuth.Server.Governance.MissionTokenConsentContext: public UpstreamTokenValidationResult ? UpstreamAuthorization { get ; init ; }
+ AAuth.Server.Governance.MissionTokenConsentContext: public string ? Account { get ; init ; }
+ AAuth.Server.Governance.MissionTokenConsentContext: public string ? AgentKeyThumbprint { get ; init ; }
+ AAuth.Server.Governance.MissionTokenConsentContext: public string ? ConsentAgentId { get ; init ; }
```

Public owners: `AAuth.Server.Governance.IMissionTokenConsent`, `AAuth.Server.Governance.MissionTokenConsentContext`, `AAuth.Server.Governance.MissionTokenConsentDecision`, `AAuth.Server.Governance.MissionTokenConsentKind`, `AAuth.Server.Governance.MissionTokenConsentStage`, `AAuth.Server.Governance`.

### src/AAuth/Server/Governance/InMemoryDeferredConsentStore.cs

Concept/decision: [consent](#consent). Source: [InMemoryDeferredConsentStore.cs](../../../src/AAuth/Server/Governance/InMemoryDeferredConsentStore.cs).

```diff
- AAuth.Server.Governance.InMemoryDeferredConsentStore: public Task ResolveAsync ( string id , bool approved , CancellationToken ct = default )
+ AAuth.Server.Governance.InMemoryDeferredConsentStore: public Task < DeferredConsent ? > GetByCodeAsync ( string code , CancellationToken ct = default )
+ AAuth.Server.Governance.InMemoryDeferredConsentStore: public async Task ResolveAsync ( string id , bool approved , CancellationToken ct = default )
```

Public owners: `AAuth.Server.Governance.InMemoryDeferredConsentStore`, `AAuth.Server.Governance`.

### src/AAuth/Server/Governance/InMemoryMissionLog.cs

Concept/decision: [governance](#governance). Source: [InMemoryMissionLog.cs](../../../src/AAuth/Server/Governance/InMemoryMissionLog.cs).

```diff
- AAuth.Server.Governance.InMemoryMissionLog: public Task < bool > HasPriorConsentAsync ( string s256 , string resource , string scope , CancellationToken ct = default )
+ AAuth.Server.Governance.InMemoryMissionLog: public Task < bool > HasPriorConsentAsync ( string s256 , string resource , string scope , CancellationToken ct = default , string ? account = null , string ? agentId = null , string ? agentKeyThumbprint = null )
```

Public owners: `AAuth.Server.Governance.InMemoryMissionLog`, `AAuth.Server.Governance`.

### src/AAuth/Server/IJtiStore.cs

Concept/decision: [revocation](#revocation). Source: [IJtiStore.cs](../../../src/AAuth/Server/IJtiStore.cs).

```diff
- AAuth.Server.IJtiStore: Task < bool > IsRevokedAsync ( string jti , CancellationToken ct = default )
- AAuth.Server.IJtiStore: Task < bool > TryRecordAsync ( string jti , DateTimeOffset expiration , CancellationToken ct = default )
- AAuth.Server.IJtiStore: Task RevokeAsync ( string jti , CancellationToken ct = default )
+ AAuth.Server.IJtiStore: Task < IReadOnlyList < TokenGrant > > GetGrantsAsync ( TokenKey source , CancellationToken ct = default )
+ AAuth.Server.IJtiStore: Task < bool > IsRevokedAsync ( TokenKey token , CancellationToken ct = default )
+ AAuth.Server.IJtiStore: Task < bool > RegisterAsync ( TokenKey token , DateTimeOffset expiration , CancellationToken ct = default )
+ AAuth.Server.IJtiStore: Task < bool > RegisterGrantAsync ( IReadOnlyCollection < TokenKey > sources , TokenGrant grant , CancellationToken ct = default )
+ AAuth.Server.IJtiStore: Task < bool > RevokeAsync ( TokenKey token , CancellationToken ct = default )
+ AAuth.Server.IJtiStore: Task < bool > TryRecordRequestAsync ( string requestKey , DateTimeOffset expiration , CancellationToken ct = default )
```

Public owners: `AAuth.Server.IJtiStore`, `AAuth.Server`.

### src/AAuth/Server/IOpaqueTokenStore.cs

Concept/decision: [resource-managed](#resource-managed). Source: [IOpaqueTokenStore.cs](../../../src/AAuth/Server/IOpaqueTokenStore.cs).

```diff
+ AAuth.Server.OpaqueTokenInfo: public string ? Account { get ; init ; }
```

Public owners: `AAuth.Server.IOpaqueTokenStore`, `AAuth.Server.InMemoryOpaqueTokenStore`, `AAuth.Server.OpaqueTokenInfo`, `AAuth.Server`.

### src/AAuth/Server/InMemoryJtiStore.cs

Concept/decision: [revocation](#revocation). Source: [InMemoryJtiStore.cs](../../../src/AAuth/Server/InMemoryJtiStore.cs).

```diff
- AAuth.Server.InMemoryJtiStore: public Task < bool > IsRevokedAsync ( string jti , CancellationToken ct = default )
- AAuth.Server.InMemoryJtiStore: public Task < bool > TryRecordAsync ( string jti , DateTimeOffset expiration , CancellationToken ct = default )
- AAuth.Server.InMemoryJtiStore: public Task RevokeAsync ( string jti , CancellationToken ct = default )
+ AAuth.Server.InMemoryJtiStore: public InMemoryJtiStore ( TimeProvider ? timeProvider = null , int capacity = 100_000 , TimeSpan ? retention = null )
+ AAuth.Server.InMemoryJtiStore: public Task < IReadOnlyList < TokenGrant > > GetGrantsAsync ( TokenKey source , CancellationToken ct = default )
+ AAuth.Server.InMemoryJtiStore: public Task < bool > IsRevokedAsync ( TokenKey token , CancellationToken ct = default )
+ AAuth.Server.InMemoryJtiStore: public Task < bool > RegisterAsync ( TokenKey token , DateTimeOffset expiration , CancellationToken ct = default )
+ AAuth.Server.InMemoryJtiStore: public Task < bool > RegisterGrantAsync ( IReadOnlyCollection < TokenKey > sources , TokenGrant grant , CancellationToken ct = default )
+ AAuth.Server.InMemoryJtiStore: public Task < bool > RevokeAsync ( TokenKey token , CancellationToken ct = default )
+ AAuth.Server.InMemoryJtiStore: public Task < bool > TryRecordRequestAsync ( string requestKey , DateTimeOffset expiration , CancellationToken ct = default )
```

Public owners: `AAuth.Server.InMemoryJtiStore`, `AAuth.Server`.

### src/AAuth/Server/Metadata/AAuthAccessServerMetadataOptions.cs

Concept/decision: [resource-managed](#resource-managed). Source: [AAuthAccessServerMetadataOptions.cs](../../../src/AAuth/Server/Metadata/AAuthAccessServerMetadataOptions.cs).

```diff
- AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public required IReadOnlyDictionary < string , AAuthKey > SigningKeys { get ; init ; }
+ AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; init ; } = AAuth . Discovery . AAuthEgressPolicy . Production
+ AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public required IReadOnlyDictionary < string , IAAuthKey > SigningKeys { get ; init ; }
```

Public owners: `AAuth.Server.Metadata.AAuthAccessServerMetadataOptions`, `AAuth.Server.Metadata`.

### src/AAuth/Server/Metadata/AAuthAgentMetadataOptions.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthAgentMetadataOptions.cs](../../../src/AAuth/Server/Metadata/AAuthAgentMetadataOptions.cs).

```diff
- AAuth.Server.Metadata.AAuthAgentMetadataOptions: public required IReadOnlyDictionary < string , AAuthKey > SigningKeys { get ; init ; }
+ AAuth.Server.Metadata.AAuthAgentMetadataOptions: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; init ; } = AAuth . Discovery . AAuthEgressPolicy . Production
+ AAuth.Server.Metadata.AAuthAgentMetadataOptions: public required IReadOnlyDictionary < string , IAAuthKey > SigningKeys { get ; init ; }
```

Public owners: `AAuth.Server.Metadata.AAuthAgentMetadataOptions`, `AAuth.Server.Metadata`.

### src/AAuth/Server/Metadata/AAuthPersonServerMetadataOptions.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthPersonServerMetadataOptions.cs](../../../src/AAuth/Server/Metadata/AAuthPersonServerMetadataOptions.cs).

```diff
- AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public required IReadOnlyDictionary < string , AAuthKey > SigningKeys { get ; init ; }
+ AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; init ; } = AAuth . Discovery . AAuthEgressPolicy . Production
+ AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public required IReadOnlyDictionary < string , IAAuthKey > SigningKeys { get ; init ; }
```

Public owners: `AAuth.Server.Metadata.AAuthPersonServerMetadataOptions`, `AAuth.Server.Metadata`.

### src/AAuth/Server/Metadata/WellKnownEndpoints.cs

Concept/decision: [server-contracts](#server-contracts). Source: [WellKnownEndpoints.cs](../../../src/AAuth/Server/Metadata/WellKnownEndpoints.cs).

```diff
- AAuth.Server.Metadata.AAuthResourceMetadataOptions: public IReadOnlyDictionary < string , AAuthKey > ? SigningKeys { get ; init ; }
+ AAuth.Server.Metadata.AAuthResourceMetadataOptions: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; init ; } = AAuth . Discovery . AAuthEgressPolicy . Production
+ AAuth.Server.Metadata.AAuthResourceMetadataOptions: public IReadOnlyDictionary < string , IAAuthKey > ? SigningKeys { get ; init ; }
```

Public owners: `AAuth.Server.Metadata.AAuthResourceMetadataOptions`, `AAuth.Server.Metadata.WellKnownEndpoints`, `AAuth.Server.Metadata`.

### src/AAuth/Server/ResourceManaged/AAuthInteractionEndpointExtensions.cs

Concept/decision: [resource-managed](#resource-managed). Source: [AAuthInteractionEndpointExtensions.cs](../../../src/AAuth/Server/ResourceManaged/AAuthInteractionEndpointExtensions.cs).

Public signatures unchanged (2); behavior reviewed under resource-managed.

Public owners: `Microsoft.AspNetCore.Builder.AAuthInteractionEndpointExtensions`, `Microsoft.AspNetCore.Builder`.

### src/AAuth/Server/ResourceManaged/AAuthResourceManagedHttpContextExtensions.cs

Concept/decision: [resource-managed](#resource-managed). Source: [AAuthResourceManagedHttpContextExtensions.cs](../../../src/AAuth/Server/ResourceManaged/AAuthResourceManagedHttpContextExtensions.cs).

```diff
- AAuth.Server.AAuthResourceManagedHttpContextExtensions: public static IResult RequireAAuthInteraction ( this HttpContext context , string scope )
+ AAuth.Server.AAuthResourceManagedHttpContextExtensions: public static IResult RequireAAuthInteraction ( this HttpContext context , string scope , string ? account = null )
```

Public owners: `AAuth.Server.AAuthResourceManagedHttpContextExtensions`, `AAuth.Server`.

### src/AAuth/Server/ResourceManaged/IInteractionPendingStore.cs

Concept/decision: [resource-managed](#resource-managed). Source: [IInteractionPendingStore.cs](../../../src/AAuth/Server/ResourceManaged/IInteractionPendingStore.cs).

```diff
- AAuth.Server.IInteractionPendingStore: InteractionPendingEntry Park ( string scope , string agentJkt , TimeSpan ttl )
- AAuth.Server.InMemoryInteractionPendingStore: public InteractionPendingEntry Park ( string scope , string agentJkt , TimeSpan ttl )
+ AAuth.Server.IInteractionPendingStore: InteractionPendingEntry Park ( string scope , string agentJkt , TimeSpan ttl , string ? account = null )
+ AAuth.Server.InMemoryInteractionPendingStore: public InteractionPendingEntry Park ( string scope , string agentJkt , TimeSpan ttl , string ? account = null )
+ AAuth.Server.InteractionPendingEntry: public BrowserInteraction Browser { get ; init ; } = new ( )
+ AAuth.Server.InteractionPendingEntry: public DeferredState Lifecycle { get ; } = new ( )
+ AAuth.Server.InteractionPendingEntry: public bool Denied { get ; set ; }
+ AAuth.Server.InteractionPendingEntry: public string ? Account { get ; init ; }
+ AAuth.Server.InteractionPendingEntry: public string ? OwnerAgent { get ; set ; }
+ AAuth.Server.InteractionPendingEntry: public string ? OwnerIssuer { get ; set ; }
```

Public owners: `AAuth.Server.IInteractionPendingStore`, `AAuth.Server.InMemoryInteractionPendingStore`, `AAuth.Server.InteractionPendingEntry`, `AAuth.Server`.

### src/AAuth/Server/RevocationClient.cs

Concept/decision: [revocation](#revocation). Source: [RevocationClient.cs](../../../src/AAuth/Server/RevocationClient.cs).

```diff
+ AAuth.Server.RevocationClient: public RevocationClient ( HttpClient signedHttp )
+ AAuth.Server.RevocationClient: public async Task < HttpStatusCode > RevokeAsync ( Uri endpoint , TokenKey token , CancellationToken cancellationToken = default )
+ AAuth.Server: public sealed class RevocationClient
```

Public owners: `AAuth.Server.RevocationClient`, `AAuth.Server`.

### src/AAuth/Server/RevocationEndpoint.cs

Concept/decision: [revocation](#revocation). Source: [RevocationEndpoint.cs](../../../src/AAuth/Server/RevocationEndpoint.cs).

```diff
+ AAuth.Server.RevocationEndpoint: public static IJtiStore MapAAuthIssuerRevocation ( this WebApplication app , string issuer , string dwk , AAuth . Crypto . IAAuthKey signingKey , string signingKid , string path , AAuth . Discovery . AAuthEgressPolicy egressPolicy , TimeProvider clock , Action < AAuthRevocationOptions > ? configure )
```

Public owners: `AAuth.Server.RevocationEndpoint`, `AAuth.Server`.

### src/AAuth/Server/TokenGrant.cs

Concept/decision: [revocation](#revocation). Source: [TokenGrant.cs](../../../src/AAuth/Server/TokenGrant.cs).

```diff
+ AAuth.Server: public sealed record TokenGrant ( TokenKey Token , string Resource , DateTimeOffset ExpiresAt )
```

Public owners: `AAuth.Server`.

### src/AAuth/Server/TokenKey.cs

Concept/decision: [revocation](#revocation). Source: [TokenKey.cs](../../../src/AAuth/Server/TokenKey.cs).

```diff
+ AAuth.Server.TokenKey: public TokenKey ( string issuer , string tokenId )
+ AAuth.Server.TokenKey: public string Issuer { get ; }
+ AAuth.Server.TokenKey: public string TokenId { get ; }
+ AAuth.Server: public sealed record TokenKey
```

Public owners: `AAuth.Server.TokenKey`, `AAuth.Server`.

### src/AAuth/Server/TokenRegistration.cs

Concept/decision: [revocation](#revocation). Source: [TokenRegistration.cs](../../../src/AAuth/Server/TokenRegistration.cs).

```diff
+ AAuth.Server.TokenRegistration: public static TokenRegistration FromVerified ( TokenVerifier . VerifiedToken token )
+ AAuth.Server.TokenRegistration: public static async Task < IReadOnlyList < TokenKey > > RegisterAsync ( IJtiStore inventory , IReadOnlyCollection < TokenRegistration > tokens , CancellationToken cancellationToken = default )
+ AAuth.Server: public sealed record TokenRegistration ( TokenKey Token , DateTimeOffset ExpiresAt )
```

Public owners: `AAuth.Server.TokenRegistration`, `AAuth.Server`.

### src/AAuth/Server/TokenRequestBody.cs

Concept/decision: [server-contracts](#server-contracts). Source: [TokenRequestBody.cs](../../../src/AAuth/Server/TokenRequestBody.cs).

```diff
+ AAuth.Server.TokenRequestBody: public static async Task < JsonObject > ReadAsync ( HttpRequest request , TokenVerifier verifier )
+ AAuth.Server: public static class TokenRequestBody
```

Public owners: `AAuth.Server.TokenRequestBody`, `AAuth.Server`.

### src/AAuth/Server/Verification/AAuthAuthenticationHandler.cs

Concept/decision: [signatures](#signatures). Source: [AAuthAuthenticationHandler.cs](../../../src/AAuth/Server/Verification/AAuthAuthenticationHandler.cs).

```diff
+ AAuth.Server.Verification.AAuthAuthenticationHandler: public const string AccountClaimType = "aauth:account" ;
```

Public owners: `AAuth.Server.Verification.AAuthAuthenticationHandler`, `AAuth.Server.Verification`.

### src/AAuth/Server/Verification/AAuthHttpContextExtensions.cs

Concept/decision: [signatures](#signatures). Source: [AAuthHttpContextExtensions.cs](../../../src/AAuth/Server/Verification/AAuthHttpContextExtensions.cs).

```diff
- AAuth.Server.Verification.AAuthHttpContextExtensions: public static IResult InteractionRequiredAAuth ( this HttpContext context , string interactionUrl , string code , string pendingLocation )
- AAuth.Server.Verification.AAuthHttpContextExtensions: public static async Task < OpaqueTokenInfo ? > ResolveAAuthAccessAsync ( this HttpContext context , IOpaqueTokenStore store , CancellationToken cancellationToken = default )
+ AAuth.Server.Verification.AAuthHttpContextExtensions: public static IResult InteractionRequiredAAuth ( this HttpContext context , string interactionUrl , string code , string pendingLocation , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
+ AAuth.Server.Verification.AAuthHttpContextExtensions: public static async Task < OpaqueTokenInfo ? > ResolveAAuthAccessAsync ( this HttpContext context , IOpaqueTokenStore store , CancellationToken cancellationToken = default , string ? expectedAccount = null )
```

Public owners: `AAuth.Server.Verification.AAuthHttpContextExtensions`, `AAuth.Server.Verification`.

### src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs

Concept/decision: [signatures](#signatures). Source: [AAuthVerificationMiddleware.cs](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs).

```diff
+ AAuth.Server.Verification.AAuthVerificationMiddleware: public const string TokenStoreItemKey = "AAuth.TokenInventory" ;
```

Public owners: `AAuth.Server.Verification.AAuthVerificationMiddleware`, `AAuth.Server.Verification.VerificationResult`, `AAuth.Server.Verification`.

### src/AAuth/Server/Verification/AAuthVerificationOptions.cs

Concept/decision: [signatures](#signatures). Source: [AAuthVerificationOptions.cs](../../../src/AAuth/Server/Verification/AAuthVerificationOptions.cs).

```diff
- AAuth.Server.Verification.AAuthVerificationOptions: public bool RequireIssuerVerification { get ; init ; } = true
- AAuth.Server.Verification.AAuthVerificationOptions: public static AAuthVerificationOptions SignatureOnly ( Func < DateTimeOffset > ? clock = null )
+ AAuth.Server.Verification.AAuthVerificationOptions: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; set ; } = AAuth . Discovery . AAuthEgressPolicy . Production
+ AAuth.Server.Verification.AAuthVerificationOptions: public Func < Microsoft . AspNetCore . Http . HttpContext , string ? > ? ExpectedAccount { get ; init ; }
+ AAuth.Server.Verification.AAuthVerificationOptions: public IReadOnlyCollection < string > RequiredComponents { get ; init ; } = [ ]
+ AAuth.Server.Verification.AAuthVerificationOptions: public IReadOnlyList < string > AcceptedSchemes { get ; init ; } = [ "jwt" ]
+ AAuth.Server.Verification.AAuthVerificationOptions: public bool GenericSignatureKeys { get ; init ; }
+ AAuth.Server.Verification.AAuthVerificationOptions: public static AAuthVerificationOptions Generic ( Func < DateTimeOffset > ? clock = null )
+ AAuth.Server.Verification.AAuthVerificationOptions: public string SignatureLabel { get ; init ; } = "sig"
```

Public owners: `AAuth.Server.Verification.AAuthVerificationOptions`, `AAuth.Server.Verification`.

### src/AAuth/Server/Verification/AAuthVerificationResult.cs

Concept/decision: [signatures](#signatures). Source: [AAuthVerificationResult.cs](../../../src/AAuth/Server/Verification/AAuthVerificationResult.cs).

```diff
+ AAuth.Server.Verification.AAuthVerificationResult: public DateTimeOffset ? ReplayExpiresAt { get ; init ; }
+ AAuth.Server.Verification.AAuthVerificationResult: public bool AccountVerified { get ; init ; }
+ AAuth.Server.Verification.AAuthVerificationResult: public string ? Account { get ; init ; }
+ AAuth.Server.Verification.AAuthVerificationResult: public string ? ReplayIdentity { get ; init ; }
```

Public owners: `AAuth.Server.Verification.AAuthVerificationResult`, `AAuth.Server.Verification`.

### src/AAuth/Server/Verification/AAuthVerifiedAssertion.cs

Concept/decision: [signatures](#signatures). Source: [AAuthVerifiedAssertion.cs](../../../src/AAuth/Server/Verification/AAuthVerifiedAssertion.cs).

```diff
+ AAuth.Server.Verification: public sealed record AAuthVerifiedAssertion ( string CompactToken , TokenVerifier . VerifiedToken Token , IAAuthKey HttpSigningKey )
```

Public owners: `AAuth.Server.Verification`.

### src/AAuth/Tokens/AccountBinding.cs

Concept/decision: [tokens](#tokens). Source: [AccountBinding.cs](../../../src/AAuth/Tokens/AccountBinding.cs).

```diff
+ AAuth.Tokens.AccountBinding: public static bool IsValid ( string ? account )
+ AAuth.Tokens.AccountBinding: public static bool Matches ( string ? expected , string ? actual )
+ AAuth.Tokens.AccountBinding: public static bool TryRead ( JsonObject payload , out string ? account )
+ AAuth.Tokens.AccountBinding: public static string ? Read ( JsonObject ? payload )
+ AAuth.Tokens.AccountBinding: public static void Validate ( string ? account )
+ AAuth.Tokens.AccountExpectation: public AccountExpectation ( string ? account )
+ AAuth.Tokens.AccountExpectation: public string ? Account { get ; }
+ AAuth.Tokens: public sealed record AccountExpectation
+ AAuth.Tokens: public static class AccountBinding
```

Public owners: `AAuth.Tokens.AccountBinding`, `AAuth.Tokens.AccountExpectation`, `AAuth.Tokens`.

### src/AAuth/Tokens/ActChainBuilder.cs

Concept/decision: [tokens](#tokens). Source: [ActChainBuilder.cs](../../../src/AAuth/Tokens/ActChainBuilder.cs).

```diff
- AAuth.Tokens.ActChainBuilder: public static JsonObject BuildNestedAct ( string upstreamAgentId , JsonObject ? upstreamChain = null )
- AAuth.Tokens.ActChainBuilder: public static bool ValidateChain ( JsonObject act , int maxDepth = 10 )
+ AAuth.Tokens.ActChainBuilder: public static JsonObject BuildNestedAct ( string upstreamAgentId , JsonObject ? upstreamChain = null , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
+ AAuth.Tokens.ActChainBuilder: public static bool ValidateChain ( JsonObject act , int maxDepth = 10 , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
```

Public owners: `AAuth.Tokens.ActChainBuilder`, `AAuth.Tokens`.

### src/AAuth/Tokens/ActChainReader.cs

Concept/decision: [tokens](#tokens). Source: [ActChainReader.cs](../../../src/AAuth/Tokens/ActChainReader.cs).

```diff
- AAuth.Tokens.ActChainReader: public static IReadOnlyList < string > GetDelegationChain ( JsonObject payload , int maxDepth = 10 )
- AAuth.Tokens.ActChainReader: public static int GetChainDepth ( JsonObject payload , int maxDepth = 10 )
- AAuth.Tokens.ActChainReader: public static string ? GetImmediateActor ( JsonObject payload )
- AAuth.Tokens.ActChainReader: public static string ? GetOriginalActor ( JsonObject payload , int maxDepth = 10 )
+ AAuth.Tokens.ActChainReader: public static IReadOnlyList < string > GetDelegationChain ( JsonObject payload , int maxDepth = 10 , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
+ AAuth.Tokens.ActChainReader: public static int GetChainDepth ( JsonObject payload , int maxDepth = 10 , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
+ AAuth.Tokens.ActChainReader: public static string ? GetImmediateActor ( JsonObject payload , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
+ AAuth.Tokens.ActChainReader: public static string ? GetOriginalActor ( JsonObject payload , int maxDepth = 10 , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
```

Public owners: `AAuth.Tokens.ActChainReader`, `AAuth.Tokens`.

### src/AAuth/Tokens/AgentAuthTokenValidator.cs

Concept/decision: [tokens](#tokens). Source: [AgentAuthTokenValidator.cs](../../../src/AAuth/Tokens/AgentAuthTokenValidator.cs).

```diff
+ AAuth.Tokens.AgentAuthTokenValidator: public static void Validate ( string authToken , string resourceToken , IAAuthKey signingKey , string agentToken , string ? subagentToken = null , string ? upstreamToken = null , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
+ AAuth.Tokens: public static class AgentAuthTokenValidator
```

Public owners: `AAuth.Tokens.AgentAuthTokenValidator`, `AAuth.Tokens`.

### src/AAuth/Tokens/AgentIssuanceContext.cs

Concept/decision: [tokens](#tokens). Source: [AgentIssuanceContext.cs](../../../src/AAuth/Tokens/AgentIssuanceContext.cs).

```diff
+ AAuth.Tokens.AgentIssuanceContext: public IReadOnlyList < TokenRegistration > SourceTokens { get ; init ; } = [ ]
+ AAuth.Tokens.AgentIssuanceContext: public JsonObject ? Act { get ; init ; }
+ AAuth.Tokens.AgentIssuanceContext: public UpstreamTokenValidationResult ? Upstream { get ; init ; }
+ AAuth.Tokens.AgentIssuanceContext: public required DateTimeOffset AgentTokenExpiresAt { get ; init ; }
+ AAuth.Tokens.AgentIssuanceContext: public required DateTimeOffset ExpiresAt { get ; init ; }
+ AAuth.Tokens.AgentIssuanceContext: public required IAAuthKey ConfirmationKey { get ; init ; }
+ AAuth.Tokens.AgentIssuanceContext: public required string AgentId { get ; init ; }
+ AAuth.Tokens.AgentIssuanceContext: public static async Task < AgentIssuanceContext > VerifyAsync ( string agentToken , string ? subagentToken , string ? upstreamToken , TokenVerifier verifier , MetadataClient metadata , JwksClient jwks , Func < string , bool > isTrustedUpstreamIssuer , CancellationToken cancellationToken = default )
+ AAuth.Tokens.AgentIssuanceContext: public void ValidateResourceContext ( JsonObject resource , string ? governingPersonServer = null )
+ AAuth.Tokens: public sealed record AgentIssuanceContext
```

Public owners: `AAuth.Tokens.AgentIssuanceContext`, `AAuth.Tokens`.

### src/AAuth/Tokens/AgentTokenBuilder.cs

Concept/decision: [tokens](#tokens). Source: [AgentTokenBuilder.cs](../../../src/AAuth/Tokens/AgentTokenBuilder.cs).

```diff
- AAuth.Tokens.AgentTokenBuilder: public AAuthKey ? ConfirmationKey { get ; init ; }
- AAuth.Tokens.AgentTokenBuilder: public required AAuthKey Key { get ; init ; }
+ AAuth.Tokens.AgentTokenBuilder: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; init ; } = AAuth . Discovery . AAuthEgressPolicy . Production
+ AAuth.Tokens.AgentTokenBuilder: public IAAuthKey ? ConfirmationKey { get ; init ; }
+ AAuth.Tokens.AgentTokenBuilder: public required IAAuthKey Key { get ; init ; }
```

Public owners: `AAuth.Tokens.AgentTokenBuilder`, `AAuth.Tokens`.

### src/AAuth/Tokens/AuthTokenBuilder.cs

Concept/decision: [tokens](#tokens). Source: [AuthTokenBuilder.cs](../../../src/AAuth/Tokens/AuthTokenBuilder.cs).

```diff
+ AAuth.Tokens.AuthTokenBuilder: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; init ; } = AAuth . Discovery . AAuthEgressPolicy . Production
+ AAuth.Tokens.AuthTokenBuilder: public DateTimeOffset ? AuthorizationExpiresAt { get ; init ; }
+ AAuth.Tokens.AuthTokenBuilder: public TimeProvider TimeProvider { get ; init ; } = TimeProvider . System
+ AAuth.Tokens.AuthTokenBuilder: public required DateTimeOffset AgentTokenExpiresAt { get ; init ; }
+ AAuth.Tokens.AuthTokenBuilder: public static bool IsIdentityClaimAllowed ( string name )
+ AAuth.Tokens.AuthTokenBuilder: public static bool IsReservedClaim ( string name )
+ AAuth.Tokens.AuthTokenBuilder: public string ? Account { get ; init ; }
```

Public owners: `AAuth.Tokens.AuthTokenBuilder`, `AAuth.Tokens`.

### src/AAuth/Tokens/AuthTokenExpiredException.cs

Concept/decision: [tokens](#tokens). Source: [AuthTokenExpiredException.cs](../../../src/AAuth/Tokens/AuthTokenExpiredException.cs).

```diff
+ AAuth.Tokens.AuthTokenExpiredException: public AuthTokenExpiredException ( )
+ AAuth.Tokens: public sealed class AuthTokenExpiredException : InvalidOperationException
```

Public owners: `AAuth.Tokens.AuthTokenExpiredException`, `AAuth.Tokens`.

### src/AAuth/Tokens/AuthTokenResponseValidator.cs

Concept/decision: [tokens](#tokens). Source: [AuthTokenResponseValidator.cs](../../../src/AAuth/Tokens/AuthTokenResponseValidator.cs).

```diff
- AAuth.Tokens.AuthTokenResponseValidator: public async Task < AuthTokenDeliveryResult > ValidateAsync ( string authToken , string expectedIssuer , string expectedAudience , string expectedAgentId , IAAuthKey agentKey , JsonObject ? expectedActContext = null , string ? requestedScope = null , CancellationToken ct = default )
+ AAuth.Tokens.AuthTokenResponseValidator: public async Task < AuthTokenDeliveryResult > ValidateAsync ( string authToken , string expectedIssuer , string expectedAudience , string expectedAgentId , IAAuthKey agentKey , JsonObject ? expectedActContext = null , string ? requestedScope = null , CancellationToken ct = default , string ? expectedAccount = null )
+ AAuth.Tokens.AuthTokenResponseValidator: public static bool ActChainsMatch ( JsonObject ? actual , JsonObject ? expected , AAuthEgressPolicy ? policy = null )
```

Public owners: `AAuth.Tokens.AuthTokenDeliveryResult`, `AAuth.Tokens.AuthTokenResponseValidator`, `AAuth.Tokens`.

### src/AAuth/Tokens/MissionClaim.cs

Concept/decision: [tokens](#tokens). Source: [MissionClaim.cs](../../../src/AAuth/Tokens/MissionClaim.cs).

```diff
- AAuth.Tokens.MissionClaim: public static MissionClaim ? FromPayload ( JsonObject ? payload )
+ AAuth.Tokens.MissionClaim: public static MissionClaim ? FromPayload ( JsonObject ? payload , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
```

Public owners: `AAuth.Tokens.MissionClaim`, `AAuth.Tokens`.

### src/AAuth/Tokens/ResourceTokenBuilder.cs

Concept/decision: [tokens](#tokens). Source: [ResourceTokenBuilder.cs](../../../src/AAuth/Tokens/ResourceTokenBuilder.cs).

```diff
- AAuth.Tokens.ResourceTokenBuilder: public required AAuthKey Key { get ; init ; }
+ AAuth.Tokens.ResourceTokenBuilder: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; init ; } = AAuth . Discovery . AAuthEgressPolicy . Production
+ AAuth.Tokens.ResourceTokenBuilder: public AAuth . Headers . Interaction ? Interaction { get ; init ; }
+ AAuth.Tokens.ResourceTokenBuilder: public IReadOnlyCollection < string > ? PersonServerScopesSupported { get ; init ; }
+ AAuth.Tokens.ResourceTokenBuilder: public IReadOnlyDictionary < string , string > ? ScopeDescriptions { get ; init ; }
+ AAuth.Tokens.ResourceTokenBuilder: public required IAAuthKey Key { get ; init ; }
+ AAuth.Tokens.ResourceTokenBuilder: public static void ValidateScopes ( string ? scope , IReadOnlyDictionary < string , string > ? resourceScopes , IReadOnlyCollection < string > ? personServerScopes )
+ AAuth.Tokens.ResourceTokenBuilder: public string ? Account { get ; init ; }
```

Public owners: `AAuth.Tokens.ResourceTokenBuilder`, `AAuth.Tokens`.

### src/AAuth/Tokens/TokenVerifier.cs

Concept/decision: [tokens](#tokens). Source: [TokenVerifier.cs](../../../src/AAuth/Tokens/TokenVerifier.cs).

```diff
- AAuth.Tokens.TokenVerifier: public VerifiedToken VerifyAuthToken ( string jwt , IAAuthKey issuerKey , string expectedAudience , IAAuthKey httpSignatureKey , string expectedAgentId , string ? expectedDwk = null , string ? expectedMaxScope = null )
- AAuth.Tokens.TokenVerifier: public async Task < VerifiedToken > VerifyAuthTokenWithJwksAsync ( string jwt , MetadataClient metadata , JwksClient jwks , string expectedAudience , IAAuthKey httpSignatureKey , string expectedAgentId , string ? expectedMaxScope = null , CancellationToken cancellationToken = default )
+ AAuth.Tokens.TokenCredential: Agent
+ AAuth.Tokens.TokenCredential: Resource
+ AAuth.Tokens.TokenCredential: Subagent
+ AAuth.Tokens.TokenCredential: Upstream
+ AAuth.Tokens.TokenVerificationException: public AAuth . Errors . SignatureErrorCode Code { get ; }
+ AAuth.Tokens.TokenVerificationException: public TokenCredential ? Credential { get ; init ; }
+ AAuth.Tokens.TokenVerificationException: public TokenVerificationException ( AAuth . Errors . SignatureErrorCode code , string message , Exception ? inner = null )
+ AAuth.Tokens.TokenVerifier.VerifiedToken: public AAuthEgressPolicy EgressPolicy { get ; init ; } = AAuthEgressPolicy . Production
+ AAuth.Tokens.TokenVerifier.VerifiedToken: public DateTimeOffset ExpiresAt { get ; } = ReadExpiration ( Payload )
+ AAuth.Tokens.TokenVerifier.VerifiedToken: public string ? Account
+ AAuth.Tokens.TokenVerifier: public AAuthEgressPolicy EgressPolicy { get ; init ; } = AAuthEgressPolicy . Production
+ AAuth.Tokens.TokenVerifier: public VerifiedToken VerifyAuthToken ( string jwt , IAAuthKey issuerKey , string expectedAudience , IAAuthKey httpSignatureKey , string expectedAgentId , string ? expectedDwk = null , string ? expectedMaxScope = null , AccountExpectation ? accountExpectation = null )
+ AAuth.Tokens.TokenVerifier: public async Task < VerifiedToken > VerifyAuthTokenWithJwksAsync ( string jwt , MetadataClient metadata , JwksClient jwks , string expectedAudience , IAAuthKey httpSignatureKey , string expectedAgentId , string ? expectedMaxScope = null , CancellationToken cancellationToken = default , AccountExpectation ? accountExpectation = null )
+ AAuth.Tokens: public enum TokenCredential
```

Public owners: `AAuth.Tokens.TokenCredential`, `AAuth.Tokens.TokenVerificationException`, `AAuth.Tokens.TokenVerifier.VerifiedToken`, `AAuth.Tokens.TokenVerifier`, `AAuth.Tokens`.

### src/AAuth/Tokens/UpstreamTokenValidator.cs

Concept/decision: [tokens](#tokens). Source: [UpstreamTokenValidator.cs](../../../src/AAuth/Tokens/UpstreamTokenValidator.cs).

```diff
+ AAuth.Tokens.UpstreamTokenValidationResult: public AAuth . Errors . SignatureErrorCode FailureCode { get ; init ; } = AAuth . Errors . SignatureErrorCode . InvalidJwt
+ AAuth.Tokens.UpstreamTokenValidationResult: public DateTimeOffset ? ExpiresAt { get ; init ; }
+ AAuth.Tokens.UpstreamTokenValidationResult: public MissionClaim ? Mission { get ; init ; }
+ AAuth.Tokens.UpstreamTokenValidationResult: public TokenVerifier . VerifiedToken ? Verified { get ; init ; }
+ AAuth.Tokens.UpstreamTokenValidationResult: public string ? Account
```

Public owners: `AAuth.Tokens.UpstreamTokenValidationResult`, `AAuth.Tokens.UpstreamTokenValidator`, `AAuth.Tokens`.
