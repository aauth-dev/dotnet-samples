---
description: Proposed public API changes and consumer ownership for draft-11 WIP migration.
---

# Public API surface map - draft-11 WIP

Research baseline: `94576a3ebcba8cd1d167923e50c8796132057600`, 2026-09-11.
No SDK changes have been made. This is a concept/member impact inventory, not a
generated complete declaration delta or a binary compatibility report. Evidence
and requirement strengths are recorded in [research.md](research.md); F labels
refer to its findings. New names below are proposals, not implemented APIs.

## Contract map

| Concept | Current surface and owner | Proposed cutover | Callers and validation |
|---|---|---|---|
| Person-token type and verification, F02 | [AAuthTokenType](../../../src/AAuth/AAuthTokenType.cs), [TokenVerifier](../../../src/AAuth/Tokens/TokenVerifier.cs), [resolver](../../../src/AAuth/HttpSig/DefaultSignatureKeyResolver.cs) | Add `PersonToken` and a dedicated typed verified result; require person issuer/DWK, resource audience, key, opaque subject and lifetimes. Do not treat parsed claims as verified. | Middleware, endpoint policies, token inspector, test token factories; person/auth substitution negatives |
| Person issuance, F02 | [PS endpoints](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs), [governance](../../../src/AAuth/Server/Governance/) | Proposed `PersonTokenBuilder`, person-token endpoint/client, request/result and verified issuance context; include resource, mission, parent/upstream context and deferred consent. Forbid `scope/account` in person tokens. | Both apps, AgentConsole, MissionAgent, worker flow, PS tests |
| Resource token, F03/F04 | [ResourceTokenBuilder](../../../src/AAuth/Tokens/ResourceTokenBuilder.cs), [R3Challenge](../../../src/AAuth.R3/R3Challenge.cs) | Remove resource `Agent`; require verified `PersonServer`, `Subject`, `PresentedTokenId`, key thumbprint; replace nested mission with `MissionS256`; preserve account/tenant and request signature binding. | All custom resources and challenge middleware; raw issued-JWT assertions |
| Auth token, F01/F06 | [AuthTokenBuilder](../../../src/AAuth/Tokens/AuthTokenBuilder.cs), [AgentAuthTokenValidator](../../../src/AAuth/Tokens/AgentAuthTokenValidator.cs) | Remove `Agent/Act/Mission` wire inputs, require `PersonServer/Subject`, add `MissionS256` and explicit verified presented expiry. Update reserved claims to prevent old fields or new authority fields being injected. | PS/AS/R3 issuers, response validators, helpers; old-claim injection and scope-only output failures |
| Exchange contracts, F04 | [TokenExchangeClient](../../../src/AAuth/Agent/TokenExchangeClient.cs), [AccessServerClient](../../../src/AAuth/Access/AccessServerClient.cs), [AS endpoints](../../../src/AAuth/Access/AAuthAccessServerEndpoints.cs) | Required `PresentedToken` in agent-to-PS and PS-to-AS requests; preserve exact credential through pending/replacement paths. One paired-token verification implementation with explicit role context. | Deferred/clarification flows, R3 AS, worker and chain callers; independent AS verification and substitution tests |
| Clarification replacement, F04/Q13 | [ClarificationResponse.Update](../../../src/AAuth/Agent/ClarificationExchange.cs#L63), core PS/AS pending handlers | Add the agreed replacement presented-token input when jti changes; verify both before atomic installation. Retain old pair only for unchanged requests, not across a new resource-token binding. | Agent-to-PS and PS-to-AS clarification; refreshed person token, changed jti, failed replacement must leave pending state untouched |
| Resource identity/policy, F06 | [verification middleware](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs), [authentication handler](../../../src/AAuth/Server/Verification/AAuthAuthenticationHandler.cs), [access mode](../../../src/AAuth/Server/Verification/AAuthAccessMode.cs) | Add person-identity policy; model agent identity as absent on person/auth resource requests. Keep `(issuer, subject)` person identity and explicit key/mission/account state; no inferred agent fallback. | Profile, Calendar, Trips, Wallet, Bookings, Catalog, Documents; policy and captured-response tests |
| Metadata, F05 | [ServerMetadata](../../../src/AAuth/Discovery/ServerMetadata.cs), [WellKnownEndpoints](../../../src/AAuth/Server/Metadata/WellKnownEndpoints.cs), [constants](../../../src/AAuth/AAuthConstants.cs) | Rename AAuth `TokenEndpoint` to `AuthTokenEndpoint`; PS adds required `PersonTokenEndpoint`; session mode is `session-token`. Optional exact algorithm set and validated resource-link discovery are separate features. | All metadata producers/clients, configuration and fixtures; no old-field fallback; preserve OIDC names |
| Agent composition/cache, F02/F12 | [AAuthClientBuilder](../../../src/AAuth/AAuthClientBuilder.cs), [AAuthTokenHolder](../../../src/AAuth/Agent/AAuthTokenHolder.cs), [TokenRefreshHandler](../../../src/AAuth/Agent/TokenRefreshHandler.cs) | Extend existing builder with explicit person acquisition and resource/mission/authority/key-partitioned state. Keep dedicated agent credential for PS/AP. Refresh upstream dependencies before dependent tokens. | Fluent convenience and manually composed clients; factory ownership, concurrency, cancellation, rotation and account isolation |
| Challenges and deferred completion, F03/F17 | [ChallengeHandler](../../../src/AAuth/Agent/ChallengeHandler.cs), [InteractionHandler](../../../src/AAuth/Agent/InteractionHandler.cs), [DeferredExchange](../../../src/AAuth/Agent/DeferredExchange.cs) | Add person challenge and 202 auth-token handling; capture original request token before exchange. 202 completion uses GET at pending URL; no original-body resubmission. | Non-idempotent request tests, pending-resource hosts and both apps |
| Mission approval, F07 | [Mission](../../../src/AAuth/Agent/Mission.cs), [MissionClient](../../../src/AAuth/Agent/Governance/MissionClient.cs), [governance mapper](../../../src/AAuth/DependencyInjection/AAuthGovernanceApplicationBuilderExtensions.cs) | Proposed approval result holds encoded blob/verified bytes, hash, capabilities and person-token map. Remove `AAuth-Mission` transport and optional header-driven mission propagation. | PS custom approval code, inspectors, tool session, mission fences; envelope-versus-blob hashing |
| Mission lifecycle, F08/F09 | [MissionSession](../../../src/AAuth/Agent/Governance/MissionSession.cs), [IMissionLog](../../../src/AAuth/Server/Governance/IMissionLog.cs), [InMemoryMissionStore](../../../src/AAuth/Server/Governance/InMemoryMissionStore.cs) | Add update/completion action API at mission URL, accepted-update bytes/digest, expiry and separate open termination reason. Make terminal transitions atomic; remove interaction-based completion. | MissionAgent, PS pending routes, shared UI sessions; ownership, expiry during consent and irreversible-state tests |
| Consent policy, F10 | [IMissionTokenConsent](../../../src/AAuth/Server/Governance/IMissionTokenConsent.cs), [sample asserter](../../../samples/MockPersonServer/SampleIdentityClaimsAsserter.cs) | Separate resource assertions from justification/display hints; carry accepted mission updates and fixed person identity into consent/claims hooks. Do not rename protocol OIDC `prompt` into justification. | Sample consent, AS claims negotiation, no-claims path; provenance and subject-replacement negatives |
| Chain and worker authority, F11 | [CallChainingRouter](../../../src/AAuth/Server/CallChaining/CallChainingRouter.cs), [UpstreamTokenValidator](../../../src/AAuth/Tokens/UpstreamTokenValidator.cs), [ActChainBuilder](../../../src/AAuth/Tokens/ActChainBuilder.cs) | Route by verified upstream PS; person acquisition first; remove `ActChainBuilder` from the AAuth issuance API after consumers move to PS/AS records. Q3/Q4 settle verification/authority, not a compatibility overload. | Concierge, worker, Wallet protocol, chain tests and snippets |
| Temporal/signature policy, F12/F13 | [TokenVerifier](../../../src/AAuth/Tokens/TokenVerifier.cs), [NamingTokenVerifier](../../../src/AAuth/HttpSig/NamingTokenVerifier.cs), [AAuthVerifier](../../../src/AAuth/HttpSig/AAuthVerifier.cs), [signing handler](../../../src/AAuth/HttpSig/AAuthSigningHandler.cs) | Separate strict AAuth expiry, optional future issuance bound, live signature window and generic-profile rules. Require signed body components at PS/AS role boundaries. | Every body-bearing initial/pending request; TimeProvider boundary tests; no global delayed-verification shortcut |
| Revocation API/store, F14/F15 | [RevocationClient](../../../src/AAuth/Server/RevocationClient.cs), [RevocationEndpoint](../../../src/AAuth/Server/RevocationEndpoint.cs), [IJtiStore](../../../src/AAuth/Server/IJtiStore.cs), [InMemoryJtiStore](../../../src/AAuth/Server/InMemoryJtiStore.cs) | Body `jti/exp`, signer-derived issuer, bounded unseen-token recording; remove cross-issuer target override. Separate revocation dependency edges from expiry-bound sources; add destinations and delivery state. | Wallet, Bookings, PS/AP/AS, pending grants; races, namespace isolation, expiry and cascade tests |
| Errors and recovery, F16 | [errors](../../../src/AAuth/Errors/), [AAuthProblemDetails](../../../src/AAuth/Server/AAuthProblemDetails.cs) | Typed presented-token and revocation failures, clock-skew action, AS terminal-response versus unavailable outcome. Preserve status/carriage and never refresh indefinitely on clock skew. | All endpoint clients, deferred errors, console/UI error displays |
| R3 names and vocabulary, F18 | [R3AuthClaims](../../../src/AAuth.R3/R3AuthClaims.cs), [models](../../../src/AAuth.R3/Model/), [R3Metadata](../../../src/AAuth.R3/R3Metadata.cs) | `Conditional` protocol APIs become `PerCall`; remove R3 document/proposal `Version` and OpenAPI Gateway standard APIs. Keep raw-byte hashes and seven standard vocabularies; preserve valid format-specific qualifiers. | Bookings/Catalog, schemas, factories, policy options, tests and all examples |
| R3 execution/reader scope, F17/F19/F21 | [R3Enforcement](../../../src/AAuth.R3/R3Enforcement.cs), [R3ProposalStore](../../../src/AAuth.R3/R3ProposalStore.cs), [R3DocumentReaderPolicy](../../../src/AAuth.R3/R3DocumentReaderPolicy.cs), [R3AccessTokenEndpoint](../../../src/AAuth.R3/R3AccessTokenEndpoint.cs) | Atomic grant consumption/result retention; document-specific PS/AS entitlement; audit person/key provenance; optional `Result` must reach policy or be rejected as unsupported. | R3 resource/AS, SQLite audit, both apps; same proposal with distinct grants, concurrent retries and foreign-reader negatives |
| Protected Events tickets, F20 | [EventStores](../../../src/AAuth.Events/EventStores.cs), [BookingsEvents](../../../samples/EventSupport/BookingsEvents.cs) | Q5 gates replacement of agent-dependent ticket issuance and persisted contract. Keep subscribe-token agent IDs and `self-jwt` events unchanged. | Protected Events client/server sample and SQLite tests; do not claim unchanged package means no work |
| Optional companions, F21-F23 | [BootstrapBuilder](../../../src/AAuth/BootstrapBuilder.cs), R3 annotation/result models, no budget implementation | Reuse current provisioning; hosted child protocol, full Budgets and delayed verification require separate approval. Metadata hints cannot advertise unimplemented enforcement. | Native/platform work remains informational; no speculative new package dependencies |

## Ownership and defaults

- Existing injected keys, clocks, transports and stores remain caller-owned.
  Factory-created clients and refreshers remain pipeline-owned; propagate
  cancellation before publishing token/cache state. Repeated builds must not
  share disposed resources or mutable authorization state accidentally.
- Person/auth caches cannot be keyed solely by origin or agent token text.
  Account selects auth state, not person-token claims; mission, directed person,
  worker key, and upstream authority distinguish otherwise similar flows.
- Preserve explicit production egress admission and development loopback opt-in.
  New person endpoints and discovery links pass through the same transport rules.
- Generic signing APIs remain supported. Prefer extending established abstractions
  over introducing parallel `AAuthAgentBuilder`/generic builder families without
  evidence that the split reduces complexity.
- No obsolete wire aliases or backward-reading fallback in the proposed alpha
  cutover. Shared tokens and old APIs move with all compiled consumers. Historical
  spec files and plans remain untouched.
- Persistent mission, ticket and invocation schemas need either an explicit
  migration or separate versioned sample storage. No silent clearing of user data.

## Inventory tooling

> **Update (2026-09):** Phase 1 parameterized the tool. It now defaults to
> this map and baseline `v0.10.0-alpha.1` (`f44587f`, the released draft-10
> SDK merged into this branch), and accepts `--map` and `--baseline`. The v10
> map is written only when named explicitly. Run
> `dotnet run --project tools/ApiSurface -- . --write` after reviewing a delta.

[tools/ApiSurface/Program.cs L9](../../../tools/ApiSurface/Program.cs#L9) hardcodes
the v10 map and defaults to `ba768f1`. Parameterize the destination and choose
this research baseline before generating an implementation delta. Its source
scanner is useful for declared public/protected C# members, not synthesized or
inherited APIs, binary compatibility, Razor-generated code, or all runtime call
sites. The writing mode must not update the historical v10 evidence by accident.

After the contract freezes, the new map must include declarations, defaults,
required inputs, nullable states, disposal/ownership, behavior-only changes,
obsolete-member removal, and every compiled caller. This research map is not a
substitute for that future gate. See [docs-surface-map.md](docs-surface-map.md)
for non-compiled content and [conformance-ledger.md](conformance-ledger.md) for tests.

<!-- generated-public-api-delta -->

## Complete declaration delta

Baseline `v0.10.0-alpha.1`; 138 changed public-source files, 244 added/replacement declarations, 135 removed/replaced declarations.

Generated from all current SDK source files, including untracked additions, and the baseline tree. Public/protected declarations include containing namespaces/types, overload parameters, required members, attributes, optional defaults, primary constructors and interface members. Compiler-synthesized/inherited members are represented by their source declarations, not expanded. Unchanged signatures in changed files are listed by containing type as behavior-review entries; the concept table above supplies their entry point, ownership, callers and tests. No source file is excluded by guessed file role.

### samples/CapabilitySupport/CatalogDemoSession.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [CatalogDemoSession.cs](../../../samples/CapabilitySupport/CatalogDemoSession.cs).

```diff
- AAuth.Samples.Capabilities.CatalogDemoSession: public static string [  ] Steps { get ; } = [ "Discover catalog services" , "Authorize selected service" , "Read selected catalog" , "Reject a sibling-service grant" , "Authorize sibling and recover" ]
+ AAuth.Samples.Capabilities.CatalogDemoSession: public static string [  ] Steps { get ; } = [ "Discover catalog definition" , "Authorize selected operation" , "Read selected catalog" , "Reject a sibling-operation grant" , "Authorize sibling and recover" ]
```

Public owners: `AAuth.Samples.Capabilities.CatalogDemoSession`, `AAuth.Samples.Capabilities`.

### samples/CapabilitySupport/DocumentDemoSession.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [DocumentDemoSession.cs](../../../samples/CapabilitySupport/DocumentDemoSession.cs).

Public signatures unchanged (10); behavior reviewed under sample-runtime.

Public owners: `AAuth.Samples.Capabilities.DocumentDemoSession`, `AAuth.Samples.Capabilities`.

### samples/CapabilitySupport/WalletDemoSession.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [WalletDemoSession.cs](../../../samples/CapabilitySupport/WalletDemoSession.cs).

Public signatures unchanged (20); behavior reviewed under sample-runtime.

Public owners: `AAuth.Samples.Capabilities.WalletDemoSession`, `AAuth.Samples.Capabilities.WalletFlow`, `AAuth.Samples.Capabilities`.

### samples/CapabilitySupport/WalletScenarioCode.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [WalletScenarioCode.cs](../../../samples/CapabilitySupport/WalletScenarioCode.cs).

```diff
- AAuth.Samples.Capabilities.WalletScenarioCode: public const string Clarification = """
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
- AAuth.Samples.Capabilities.WalletScenarioCode: public const string Revocation = """
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
+ AAuth.Samples.Capabilities.WalletScenarioCode: public const string Clarification = """
        public static Task<string> ClarifyAsync(HttpClient signedAgent, MetadataClient metadata,
            string personServer, string resourceToken, string personToken,
            Func<Interaction, CancellationToken, Task> consent,
            Func<ClarificationRequirement, CancellationToken, Task<ClarificationResponse>> answer,
            CancellationToken cancellationToken)
            => new TokenExchangeClient(signedAgent, metadata).ExchangeAsync(personServer, resourceToken,
                new TokenExchangeRequest
                {
                    PresentedToken = personToken, OnInteractionRequired = consent, OnClarificationRequired = answer,
                },
                cancellationToken);

        public static ClarificationResponse Answer(string justification)
            => ClarificationResponse.Respond(justification);

        public static ClarificationResponse Cancel() => ClarificationResponse.Cancel();
        """ ;
+ AAuth.Samples.Capabilities.WalletScenarioCode: public const string Revocation = """
        public static async Task<RevocationResult> RevokePresentedPersonTokenAsync(HttpClient signedPersonServer,
            MetadataClient metadata, string accessServer, string personTokenId, DateTimeOffset personTokenExpiresAt,
            CancellationToken cancellationToken)
        {
            // The PS revokes, at the AS, the person token it presented; the AS cascades to the Wallet.
            var endpoint = (await metadata.FetchAccessServerMetadataAsync(accessServer, cancellationToken)).RevocationEndpoint
                ?? throw new InvalidOperationException("The Access Server publishes no revocation_endpoint.");
            return await new RevocationClient(signedPersonServer).RevokeAsync(new Uri(endpoint),
                personTokenId, personTokenExpiresAt, cancellationToken);
        }

        public static Task<string> RecoverAsync(HttpClient signedAgent, MetadataClient metadata,
            string personServer, string freshResourceToken, string personToken,
            Func<Interaction, CancellationToken, Task> consent, CancellationToken cancellationToken)
            => new TokenExchangeClient(signedAgent, metadata).ExchangeAsync(personServer, freshResourceToken,
                new TokenExchangeRequest { PresentedToken = personToken, OnInteractionRequired = consent }, cancellationToken);
        """ ;
```

Public owners: `AAuth.Samples.Capabilities.WalletScenarioCode`, `AAuth.Samples.Capabilities`.

### samples/Concierge/Program.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [Program.cs](../../../samples/Concierge/Program.cs).

Public signatures unchanged (1); behavior reviewed under sample-runtime.

Public owners: `Concierge`.

### samples/EventSupport/BookingsEvents.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [BookingsEvents.cs](../../../samples/EventSupport/BookingsEvents.cs).

Public signatures unchanged (6); behavior reviewed under sample-runtime.

Public owners: `AAuth.Samples.Events.BookingsEvents`, `AAuth.Samples.Events`.

### samples/EventSupport/SqliteEventStore.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [SqliteEventStore.cs](../../../samples/EventSupport/SqliteEventStore.cs).

Public signatures unchanged (22); behavior reviewed under sample-runtime.

Public owners: `AAuth.Samples.Events.SqliteEventStore`, `AAuth.Samples.Events`.

### samples/FederatedWorkerScenario.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [FederatedWorkerScenario.cs](../../../samples/FederatedWorkerScenario.cs).

```diff
+ AAuth.Samples.FederatedWorkerScenario: public async Task ObtainWorkerPersonTokenAsync ( CancellationToken ct = default )
+ AAuth.Samples.FederatedWorkerScenario: public async Task PresentWorkerPersonTokenAsync ( CancellationToken ct = default )
+ AAuth.Samples.FederatedWorkerScenario: public string ? WorkerPersonToken { get ; private set ; }
```

Public owners: `AAuth.Samples.FederatedWorkerScenario`, `AAuth.Samples`.

### samples/GuidedTour/TourOptions.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [TourOptions.cs](../../../samples/GuidedTour/TourOptions.cs).

Public signatures unchanged (31); behavior reviewed under sample-runtime.

Public owners: `GuidedTour.SigningMode`, `GuidedTour.TourMode`, `GuidedTour.TourOptions`, `GuidedTour`.

### samples/GuidedTour/TourSession.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [TourSession.cs](../../../samples/GuidedTour/TourSession.cs).

Public signatures unchanged (57); behavior reviewed under sample-runtime.

Public owners: `GuidedTour.TourSession`, `GuidedTour`.

### samples/MockAccessServers/Federated/Policy/WalletPolicyRules.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [WalletPolicyRules.cs](../../../samples/MockAccessServers/Federated/Policy/WalletPolicyRules.cs).

Public signatures unchanged (3); behavior reviewed under sample-runtime.

Public owners: `MockAccessServer.Policy.WalletPolicyRules`, `MockAccessServer.Policy`.

### samples/MockAccessServers/Federated/Program.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [Program.cs](../../../samples/MockAccessServers/Federated/Program.cs).

Public signatures unchanged (1); behavior reviewed under sample-runtime.

Public owners: `Federated`.

### samples/MockAccessServers/R3/Program.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [Program.cs](../../../samples/MockAccessServers/R3/Program.cs).

Public signatures unchanged (1); behavior reviewed under sample-runtime.

Public owners: `R3AccessServer`.

### samples/MockPersonServer/ConsentBridgePersonPendingStore.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [ConsentBridgePersonPendingStore.cs](../../../samples/MockPersonServer/ConsentBridgePersonPendingStore.cs).

```diff
- MockPersonServer.ConsentBridgePersonPendingStore: public PersonPendingEntry Add ( string resourceUrl , string scope , string agentId , IAAuthKey ? agentConfirmationKey , DateTimeOffset agentTokenExpiresAt , JsonObject ? upstreamAct = null , MissionClaim ? mission = null , DateTimeOffset ? authorizationExpiresAt = null )
+ MockPersonServer.ConsentBridgePersonPendingStore: public PersonPendingEntry Add ( string resourceUrl , string scope , string agentId , IAAuthKey ? agentConfirmationKey , DateTimeOffset agentTokenExpiresAt , string ? missionS256 = null , DateTimeOffset ? authorizationExpiresAt = null )
```

Public owners: `MockPersonServer.ConsentBridgePersonPendingStore`, `MockPersonServer`.

### samples/MockPersonServer/MissionGovernance.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [MissionGovernance.cs](../../../samples/MockPersonServer/MissionGovernance.cs).

```diff
- MockPersonServer.MissionPendingEntry: public JsonObject ? UpstreamAct { get ; init ; }
- MockPersonServer.MissionPendingEntry: public MissionClaim MissionClaim
- MockPersonServer.MissionPendingEntry: public required string Approver { get ; init ; }
+ MockPersonServer.MissionPendingEntry: public required string PersonServer { get ; init ; }
```

Public owners: `MockPersonServer.MissionConsentScript`, `MockPersonServer.MissionPendingEntry`, `MockPersonServer.MissionPendingKind`, `MockPersonServer.MissionPendingState`, `MockPersonServer.MissionPendingStore`, `MockPersonServer.MissionPolicyStore`, `MockPersonServer.SampleAuditSink`, `MockPersonServer.SampleInteractionRelay`, `MockPersonServer.SamplePermissionDecider`, `MockPersonServer`.

### samples/MockPersonServer/Program.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [Program.cs](../../../samples/MockPersonServer/Program.cs).

Public signatures unchanged (1); behavior reviewed under sample-runtime.

Public owners: `MockPersonServer`.

### samples/MockPersonServer/SampleIdentityClaimsAsserter.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [SampleIdentityClaimsAsserter.cs](../../../samples/MockPersonServer/SampleIdentityClaimsAsserter.cs).

Public signatures unchanged (5); behavior reviewed under sample-runtime.

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

Public signatures unchanged (1); behavior reviewed under sample-runtime.

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

### src/AAuth.Events/EventStores.cs

Concept/decision: [events](#events). Source: [EventStores.cs](../../../src/AAuth.Events/EventStores.cs).

```diff
- AAuth.Events: public sealed record ResourceSubscription ( string Eid , string Provider , string Agent , string Operation , string ? Account , string State , DateTimeOffset ExpiresAt )
- AAuth.Events: public sealed record SubscriptionTicket ( string Ticket , string Agent , string Operation , string ? Account , string State , DateTimeOffset ExpiresAt )
+ AAuth.Events: public sealed record ResourceSubscription ( string Eid , string Provider , string Agent , string Operation , string ? Account , string State , DateTimeOffset ExpiresAt , string ? KeyThumbprint = null )
+ AAuth.Events: public sealed record SubscriptionTicket ( string Ticket , string KeyThumbprint , string Operation , string ? Account , string State , DateTimeOffset ExpiresAt )
```

Public owners: `AAuth.Events.IAgentEventStore`, `AAuth.Events.IAgentProviderEventStore`, `AAuth.Events.IResourceEventStore`, `AAuth.Events`.

### src/AAuth.Events/EventsEndpoints.cs

Concept/decision: [events](#events). Source: [EventsEndpoints.cs](../../../src/AAuth.Events/EventsEndpoints.cs).

Public signatures unchanged (3); behavior reviewed under events.

Public owners: `AAuth.Events.EventsEndpoints`, `AAuth.Events`.

### src/AAuth.R3/Model/R3Document.cs

Concept/decision: [r3](#r3). Source: [R3Document.cs](../../../src/AAuth.R3/Model/R3Document.cs).

```diff
- AAuth.R3.Model.R3Document: [ JsonPropertyName ( "version" ) ] [ JsonPropertyOrder ( 1 ) ] [ JsonIgnore ( Condition = JsonIgnoreCondition . WhenWritingNull ) ] public string ? Version { get ; init ; }
```

Public owners: `AAuth.R3.Model.R3Document`, `AAuth.R3.Model`.

### src/AAuth.R3/Model/R3Grant.cs

Concept/decision: [r3](#r3). Source: [R3Grant.cs](../../../src/AAuth.R3/Model/R3Grant.cs).

Public signatures unchanged (7); behavior reviewed under r3.

Public owners: `AAuth.R3.Model.R3Grant`, `AAuth.R3.Model`.

### src/AAuth.R3/Model/R3Operation.cs

Concept/decision: [r3](#r3). Source: [R3Operation.cs](../../../src/AAuth.R3/Model/R3Operation.cs).

```diff
- AAuth.R3.Model.R3Operation: public static R3Operation OpenApiGateway ( string service , string operationId )
```

Public owners: `AAuth.R3.Model.R3OperationConverter`, `AAuth.R3.Model.R3Operation`, `AAuth.R3.Model`.

### src/AAuth.R3/Model/R3ProposalDocument.cs

Concept/decision: [r3](#r3). Source: [R3ProposalDocument.cs](../../../src/AAuth.R3/Model/R3ProposalDocument.cs).

```diff
- AAuth.R3.Model.R3ProposalDocument: [ JsonPropertyName ( "version" ) ] [ JsonPropertyOrder ( 1 ) ] [ JsonIgnore ( Condition = JsonIgnoreCondition . WhenWritingNull ) ] public string ? Version { get ; init ; }
```

Public owners: `AAuth.R3.Model.R3ProposalDocument`, `AAuth.R3.Model`.

### src/AAuth.R3/Model/R3VocabularySchemas.cs

Concept/decision: [r3](#r3). Source: [R3VocabularySchemas.cs](../../../src/AAuth.R3/Model/R3VocabularySchemas.cs).

Public signatures unchanged (8); behavior reviewed under r3.

Public owners: `AAuth.R3.Model.R3VocabularySchemas`, `AAuth.R3.Model`.

### src/AAuth.R3/Model/Vocabulary.cs

Concept/decision: [r3](#r3). Source: [Vocabulary.cs](../../../src/AAuth.R3/Model/Vocabulary.cs).

```diff
- AAuth.R3.Model.Vocabulary: public const string OpenApiGateway = "urn:aauth:vocabulary:openapi-gateway" ;
```

Public owners: `AAuth.R3.Model.Vocabulary`, `AAuth.R3.Model`.

### src/AAuth.R3/R3AccessAnnotations.cs

Concept/decision: [r3](#r3). Source: [R3AccessAnnotations.cs](../../../src/AAuth.R3/R3AccessAnnotations.cs).

```diff
+ AAuth.R3.R3AccessAnnotations: public const string McpAccessMode = "aauth.dev/access-mode" ;
+ AAuth.R3.R3AccessAnnotations: public const string McpBudget = "aauth.dev/budget" ;
+ AAuth.R3.R3AccessAnnotations: public const string McpMeta = "_meta" ;
+ AAuth.R3.R3AccessAnnotations: public const string ODataAccessMode = "AAuth.AccessMode" ;
+ AAuth.R3.R3AccessAnnotations: public const string ODataBudget = "AAuth.Budget" ;
+ AAuth.R3.R3AccessAnnotations: public const string OpenApiAccessMode = "x-aauth-access-mode" ;
+ AAuth.R3.R3AccessAnnotations: public const string OpenApiBudget = "x-aauth-budget" ;
+ AAuth.R3.R3AccessAnnotations: public static JsonObject Annotate ( JsonObject definition , string vocabulary , R3OperationAccess access )
+ AAuth.R3.R3AccessAnnotations: public static R3OperationAccess ? Read ( JsonObject definition , string vocabulary )
+ AAuth.R3.R3AccessAnnotations: public static string EffectiveAccessMode ( R3OperationAccess ? annotation , string ? resourceAccessMode )
+ AAuth.R3: public sealed record R3OperationAccess ( string ? AccessMode , bool Budget = false )
+ AAuth.R3: public static class R3AccessAnnotations
```

Public owners: `AAuth.R3.R3AccessAnnotations`, `AAuth.R3`.

### src/AAuth.R3/R3AccessTokenEndpoint.cs

Concept/decision: [r3](#r3). Source: [R3AccessTokenEndpoint.cs](../../../src/AAuth.R3/R3AccessTokenEndpoint.cs).

```diff
- AAuth.R3.R3AccessTokenEndpointOptions: public Func < R3OperationIdentity , bool > ? IsConditionalOperation { get ; init ; }
- AAuth.R3.R3AccessTokenEndpointOptions: public string Subject { get ; init ; } = "pairwise-sub"
+ AAuth.R3.R3AccessTokenEndpointOptions: public Func < R3OperationIdentity , bool > ? IsPerCallOperation { get ; init ; }
```

Public owners: `AAuth.R3.R3AccessTokenEndpointOptions`, `AAuth.R3.R3AccessTokenEndpoint`, `AAuth.R3`.

### src/AAuth.R3/R3AuthClaims.cs

Concept/decision: [r3](#r3). Source: [R3AuthClaims.cs](../../../src/AAuth.R3/R3AuthClaims.cs).

```diff
- AAuth.R3.R3AuthClaims: public const string ConditionalClaim = "r3_conditional" ;
- AAuth.R3.R3AuthClaims: public static IReadOnlyDictionary < string , JsonNode ? > AuthToken ( string r3Uri , string r3S256 , R3Grant granted , R3Grant ? conditional = null , R3VocabularySchemas ? schemas = null )
+ AAuth.R3.R3AuthClaims: public const string PerCallClaim = "r3_per_call" ;
+ AAuth.R3.R3AuthClaims: public static IReadOnlyDictionary < string , JsonNode ? > AuthToken ( string r3Uri , string r3S256 , R3Grant granted , R3Grant ? perCall = null , R3VocabularySchemas ? schemas = null )
```

Public owners: `AAuth.R3.R3AuthClaims`, `AAuth.R3`.

### src/AAuth.R3/R3Challenge.cs

Concept/decision: [r3](#r3). Source: [R3Challenge.cs](../../../src/AAuth.R3/R3Challenge.cs).

```diff
- AAuth.R3.R3Challenge: public IResult Challenge ( HttpContext context , string agent , string agentJkt , string r3Uri , string r3S256 , string ? scope = null , string ? account = null )
- AAuth.R3.R3Challenge: public string BuildResourceToken ( string agent , string agentJkt , string r3Uri , string r3S256 , string ? scope = null , string ? account = null )
+ AAuth.R3.R3Challenge: public IResult Challenge ( HttpContext context , string r3Uri , string r3S256 , string ? scope = null , string ? account = null )
+ AAuth.R3.R3Challenge: public string BuildResourceToken ( TokenVerifier . VerifiedToken presented , string agentJkt , string r3Uri , string r3S256 , string ? scope = null , string ? account = null )
```

Public owners: `AAuth.R3.R3Challenge`, `AAuth.R3`.

### src/AAuth.R3/R3ClaimReader.cs

Concept/decision: [r3](#r3). Source: [R3ClaimReader.cs](../../../src/AAuth.R3/R3ClaimReader.cs).

```diff
- AAuth.R3.R3ClaimReader: public sealed record AuthTokenClaims ( string Uri , string S256 , R3Grant Granted , R3Grant ? Conditional )
+ AAuth.R3.R3ClaimReader: public sealed record AuthTokenClaims ( string Uri , string S256 , R3Grant Granted , R3Grant ? PerCall )
```

Public owners: `AAuth.R3.R3ClaimReader.AuthTokenClaims`, `AAuth.R3.R3ClaimReader.ResourceDocumentClaims`, `AAuth.R3.R3ClaimReader`, `AAuth.R3`.

### src/AAuth.R3/R3Enforcement.cs

Concept/decision: [r3](#r3). Source: [R3Enforcement.cs](../../../src/AAuth.R3/R3Enforcement.cs).

```diff
- AAuth.R3.R3EnforcementDecision: public IResult ToResult ( HttpContext context , R3Challenge challenge , string agent , string agentJkt , string ? scope = null )
- AAuth.R3.R3EnforcementDecision: public static R3EnforcementDecision Conditional ( string proposalUri , string proposalS256 )
- AAuth.R3.R3EnforcementDecisionKind: Conditional
+ AAuth.R3.R3EnforcementDecision: public static R3EnforcementDecision PerCall ( string proposalUri , string proposalS256 )
+ AAuth.R3.R3EnforcementDecisionKind: PerCall
```

Public owners: `AAuth.R3.R3EnforcementDecisionKind`, `AAuth.R3.R3EnforcementDecision`, `AAuth.R3.R3Enforcement`, `AAuth.R3`.

### src/AAuth.R3/R3Metadata.cs

Concept/decision: [r3](#r3). Source: [R3Metadata.cs](../../../src/AAuth.R3/R3Metadata.cs).

Public signatures unchanged (6); behavior reviewed under r3.

Public owners: `AAuth.R3.R3Metadata`, `AAuth.R3`.

### src/AAuth/AAuthClientBuilder.cs

Concept/decision: [agent-clients](#agent-clients). Source: [AAuthClientBuilder.cs](../../../src/AAuth/AAuthClientBuilder.cs).

Public signatures unchanged (37); behavior reviewed under agent-clients.

Public owners: `AAuth.AAuthClientBuilder`, `AAuth`.

### src/AAuth/AAuthConstants.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthConstants.cs](../../../src/AAuth/AAuthConstants.cs).

```diff
- AAuth.AAuthConstants.AccessModes: public const string AAuthAccessToken = "aauth-access-token" ;
- AAuth.AAuthConstants.Headers: public const string AAuthMission = "AAuth-Mission" ;
+ AAuth.AAuthConstants.AccessModes: public const string PerCall = "per-call" ;
+ AAuth.AAuthConstants.AccessModes: public const string PersonToken = "person-token" ;
+ AAuth.AAuthConstants.AccessModes: public const string SessionToken = "session-token" ;
+ AAuth.AAuthConstants.TokenTypes: public const string PersonToken = "aa-person+jwt" ;
```

Public owners: `AAuth.AAuthConstants.AccessModes`, `AAuth.AAuthConstants.DwkFiles`, `AAuth.AAuthConstants.Headers`, `AAuth.AAuthConstants.Schemes`, `AAuth.AAuthConstants.TokenTypes`, `AAuth.AAuthConstants`, `AAuth`.

### src/AAuth/AAuthTokenType.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthTokenType.cs](../../../src/AAuth/AAuthTokenType.cs).

```diff
+ AAuth.AAuthTokenType: PersonToken
```

Public owners: `AAuth.AAuthTokenTypeExtensions`, `AAuth.AAuthTokenType`, `AAuth`.

### src/AAuth/Access/AAuthAccessServerEndpoints.cs

Concept/decision: [consent](#consent). Source: [AAuthAccessServerEndpoints.cs](../../../src/AAuth/Access/AAuthAccessServerEndpoints.cs).

Public signatures unchanged (16); behavior reviewed under consent.

Public owners: `AAuth.Access.AAuthAccessServerEndpoints`, `AAuth.Access.AAuthAccessServerOptions`, `AAuth.Access`.

### src/AAuth/Access/AccessServerClient.cs

Concept/decision: [consent](#consent). Source: [AccessServerClient.cs](../../../src/AAuth/Access/AccessServerClient.cs).

Public signatures unchanged (3); behavior reviewed under consent.

Public owners: `AAuth.Access.AccessServerClient`, `AAuth.Access`.

### src/AAuth/Access/AccessServerRequest.cs

Concept/decision: [consent](#consent). Source: [AccessServerRequest.cs](../../../src/AAuth/Access/AccessServerRequest.cs).

```diff
- AAuth.Access.AccessServerRequest: public JsonObject ? ExpectedActContext { get ; init ; }
- AAuth.Access.AccessServerRequest: public MissionClaim ? ExpectedMission { get ; set ; }
- AAuth.Access.AccessServerRequest: public required string ExpectedAgentId { get ; init ; }
+ AAuth.Access.AccessServerRequest: public required DateTimeOffset PresentedTokenExpiresAt { get ; set ; }
+ AAuth.Access.AccessServerRequest: public required string ExpectedPersonServer { get ; init ; }
+ AAuth.Access.AccessServerRequest: public required string ExpectedSubject { get ; init ; }
+ AAuth.Access.AccessServerRequest: public required string PresentedToken { get ; init ; }
+ AAuth.Access.AccessServerRequest: public string ? ExpectedMissionS256 { get ; set ; }
```

Public owners: `AAuth.Access.AccessServerRequest`, `AAuth.Access`.

### src/AAuth/Access/IAccessPendingStore.cs

Concept/decision: [consent](#consent). Source: [IAccessPendingStore.cs](../../../src/AAuth/Access/IAccessPendingStore.cs).

```diff
- AAuth.Access.AccessPendingEntry: public JsonObject ? UpstreamAct { get ; init ; }
- AAuth.Access.AccessPendingEntry: public string ? OwnerAgentIssuer { get ; set ; }
- AAuth.Access.AccessPendingEntry: public string ? OwnerAgentSubject { get ; set ; }
- AAuth.Access.AccessPendingEntry: public string ? SuppliedSubject { get ; set ; }
- AAuth.Access.IAccessPendingStore: AccessPendingEntry Add ( string resourceUrl , string scope , string agentId , IAAuthKey agentConfirmationKey , DateTimeOffset agentTokenExpiresAt , JsonObject ? claims , IReadOnlyList < string > ? requiredClaims = null , DateTimeOffset ? authorizationExpiresAt = null , JsonObject ? upstreamAct = null )
- AAuth.Access.InMemoryAccessPendingStore: public AccessPendingEntry Add ( string resourceUrl , string scope , string agentId , IAAuthKey agentConfirmationKey , DateTimeOffset agentTokenExpiresAt , JsonObject ? claims , IReadOnlyList < string > ? requiredClaims = null , DateTimeOffset ? authorizationExpiresAt = null , JsonObject ? upstreamAct = null )
+ AAuth.Access.IAccessPendingStore: AccessPendingEntry Add ( string resourceUrl , string scope , string agentId , IAAuthKey agentConfirmationKey , DateTimeOffset agentTokenExpiresAt , JsonObject ? claims , IReadOnlyList < string > ? requiredClaims = null , DateTimeOffset ? authorizationExpiresAt = null )
+ AAuth.Access.InMemoryAccessPendingStore: public AccessPendingEntry Add ( string resourceUrl , string scope , string agentId , IAAuthKey agentConfirmationKey , DateTimeOffset agentTokenExpiresAt , JsonObject ? claims , IReadOnlyList < string > ? requiredClaims = null , DateTimeOffset ? authorizationExpiresAt = null )
```

Public owners: `AAuth.Access.AccessPendingEntry`, `AAuth.Access.AccessPendingStatus`, `AAuth.Access.IAccessPendingStore`, `AAuth.Access.InMemoryAccessPendingStore`, `AAuth.Access`.

### src/AAuth/Access/IAccessPolicy.cs

Concept/decision: [consent](#consent). Source: [IAccessPolicy.cs](../../../src/AAuth/Access/IAccessPolicy.cs).

```diff
- AAuth.Access.AccessDecision: public static AccessDecision Allow ( string ? subject = null , string ? tenant = null , IReadOnlyDictionary < string , JsonNode ? > ? additionalClaims = null )
- AAuth.Access.AccessDecision: public string ? Subject { get ; }
+ AAuth.Access.AccessDecision: public static AccessDecision Allow ( string ? tenant = null , IReadOnlyDictionary < string , JsonNode ? > ? additionalClaims = null )
```

Public owners: `AAuth.Access.AccessDecisionKind`, `AAuth.Access.AccessDecision`, `AAuth.Access.AccessPolicyRequest`, `AAuth.Access.IAccessPolicy`, `AAuth.Access.IInteractiveAccessPolicy`, `AAuth.Access`.

### src/AAuth/Agent/AAuthRequestOptions.cs

Concept/decision: [resource-managed](#resource-managed). Source: [AAuthRequestOptions.cs](../../../src/AAuth/Agent/AAuthRequestOptions.cs).

```diff
+ AAuth.Agent.AAuthRequestOptions: public static readonly HttpRequestOptionsKey < string > MissionS256 = new ( "AAuth.MissionS256" ) ;
+ AAuth.Agent.AAuthRequestOptions: public static string ? GetMissionS256 ( HttpRequestMessage request )
```

Public owners: `AAuth.Agent.AAuthRequestOptions`, `AAuth.Agent`.

### src/AAuth/Agent/AAuthTokenHolder.cs

Concept/decision: [agent-clients](#agent-clients). Source: [AAuthTokenHolder.cs](../../../src/AAuth/Agent/AAuthTokenHolder.cs).

Public signatures unchanged (7); behavior reviewed under agent-clients.

Public owners: `AAuth.Agent.AAuthTokenHolder`, `AAuth.Agent`.

### src/AAuth/Agent/ChallengeHandler.cs

Concept/decision: [agent-clients](#agent-clients). Source: [ChallengeHandler.cs](../../../src/AAuth/Agent/ChallengeHandler.cs).

Public signatures unchanged (9); behavior reviewed under agent-clients.

Public owners: `AAuth.Agent.ChallengeHandler`, `AAuth.Agent`.

### src/AAuth/Agent/ClarificationExchange.cs

Concept/decision: [agent-clients](#agent-clients). Source: [ClarificationExchange.cs](../../../src/AAuth/Agent/ClarificationExchange.cs).

```diff
- AAuth.Agent.ClarificationExchange: public async Task UpdateRequestAsync ( string resourceToken , string ? justification = null , CancellationToken cancellationToken = default )
- AAuth.Agent.ClarificationResponse: public static ClarificationResponse Update ( string resourceToken , string ? justification = null )
+ AAuth.Agent.ClarificationExchange: public async Task UpdateRequestAsync ( string resourceToken , string presentedToken , string ? justification = null , CancellationToken cancellationToken = default )
+ AAuth.Agent.ClarificationResponse: public static ClarificationResponse Update ( string resourceToken , string presentedToken , string ? justification = null )
+ AAuth.Agent.ClarificationResponse: public string ? PresentedToken { get ; }
```

Public owners: `AAuth.Agent.ClarificationExchange`, `AAuth.Agent.ClarificationResponse.Kind`, `AAuth.Agent.ClarificationResponse`, `AAuth.Agent`.

### src/AAuth/Agent/Governance/AuditRecord.cs

Concept/decision: [governance](#governance). Source: [AuditRecord.cs](../../../src/AAuth/Agent/Governance/AuditRecord.cs).

```diff
- AAuth.Agent.Governance: public sealed record AuditRecord ( MissionClaim Mission , MissionAction Action )
+ AAuth.Agent.Governance: public sealed record AuditRecord ( string MissionS256 , MissionAction Action )
```

Public owners: `AAuth.Agent.Governance.AuditRecord`, `AAuth.Agent.Governance`.

### src/AAuth/Agent/Governance/InteractionClient.cs

Concept/decision: [governance](#governance). Source: [InteractionClient.cs](../../../src/AAuth/Agent/Governance/InteractionClient.cs).

```diff
- AAuth.Agent.Governance.InteractionClient: public Task < InteractionResult > RelayInteractionAsync ( string url , string code , string ? description = null , MissionClaim ? mission = null , GovernanceOptions ? options = null , CancellationToken cancellationToken = default )
- AAuth.Agent.Governance.InteractionClient: public Task < InteractionResult > RelayPaymentAsync ( string url , string code , string ? description = null , MissionClaim ? mission = null , GovernanceOptions ? options = null , CancellationToken cancellationToken = default )
- AAuth.Agent.Governance.InteractionClient: public async Task < bool > ProposeCompletionAsync ( string summary , MissionClaim mission , GovernanceOptions ? options = null , CancellationToken cancellationToken = default )
- AAuth.Agent.Governance.InteractionClient: public async Task < string ? > AskQuestionAsync ( string question , string ? description = null , MissionClaim ? mission = null , GovernanceOptions ? options = null , CancellationToken cancellationToken = default )
+ AAuth.Agent.Governance.InteractionClient: public Task < InteractionResult > RelayInteractionAsync ( string url , string code , string ? description = null , string ? missionS256 = null , GovernanceOptions ? options = null , CancellationToken cancellationToken = default )
+ AAuth.Agent.Governance.InteractionClient: public Task < InteractionResult > RelayPaymentAsync ( string url , string code , string ? description = null , string ? missionS256 = null , GovernanceOptions ? options = null , CancellationToken cancellationToken = default )
+ AAuth.Agent.Governance.InteractionClient: public async Task < string ? > AskQuestionAsync ( string question , string ? description = null , string ? missionS256 = null , GovernanceOptions ? options = null , CancellationToken cancellationToken = default )
```

Public owners: `AAuth.Agent.Governance.InteractionClient`, `AAuth.Agent.Governance`.

### src/AAuth/Agent/Governance/InteractionRequest.cs

Concept/decision: [governance](#governance). Source: [InteractionRequest.cs](../../../src/AAuth/Agent/Governance/InteractionRequest.cs).

```diff
- AAuth.Agent.Governance.InteractionRequest: public MissionClaim ? Mission { get ; init ; }
+ AAuth.Agent.Governance.InteractionRequest: public string ? MissionS256 { get ; init ; }
```

Public owners: `AAuth.Agent.Governance.InteractionRequest`, `AAuth.Agent.Governance.InteractionType`, `AAuth.Agent.Governance`.

### src/AAuth/Agent/Governance/MissionClient.cs

Concept/decision: [governance](#governance). Source: [MissionClient.cs](../../../src/AAuth/Agent/Governance/MissionClient.cs).

```diff
+ AAuth.Agent.Governance.MissionClient: public async Task < bool > CompleteAsync ( Mission mission , string summary , GovernanceOptions ? options = null , CancellationToken cancellationToken = default )
+ AAuth.Agent.Governance.MissionClient: public async Task < string > UpdateAsync ( Mission mission , string description , GovernanceOptions ? options = null , CancellationToken cancellationToken = default )
```

Public owners: `AAuth.Agent.Governance.MissionClient`, `AAuth.Agent.Governance`.

### src/AAuth/Agent/Governance/MissionProposal.cs

Concept/decision: [governance](#governance). Source: [MissionProposal.cs](../../../src/AAuth/Agent/Governance/MissionProposal.cs).

```diff
+ AAuth.Agent.Governance.MissionProposal: public IReadOnlyList < string > Resources { get ; init ; } = Array . Empty < string > ( )
```

Public owners: `AAuth.Agent.Governance.MissionProposal`, `AAuth.Agent.Governance`.

### src/AAuth/Agent/Governance/MissionSession.cs

Concept/decision: [governance](#governance). Source: [MissionSession.cs](../../../src/AAuth/Agent/Governance/MissionSession.cs).

```diff
+ AAuth.Agent.Governance.MissionSession: public Task < string > UpdateAsync ( string description , GovernanceOptions ? options = null , CancellationToken cancellationToken = default )
```

Public owners: `AAuth.Agent.Governance.MissionSession`, `AAuth.Agent.Governance`.

### src/AAuth/Agent/Governance/PermissionClient.cs

Concept/decision: [governance](#governance). Source: [PermissionClient.cs](../../../src/AAuth/Agent/Governance/PermissionClient.cs).

Public signatures unchanged (4); behavior reviewed under governance.

Public owners: `AAuth.Agent.Governance.PermissionClient`, `AAuth.Agent.Governance`.

### src/AAuth/Agent/Governance/PermissionRequest.cs

Concept/decision: [governance](#governance). Source: [PermissionRequest.cs](../../../src/AAuth/Agent/Governance/PermissionRequest.cs).

```diff
- AAuth.Agent.Governance.PermissionRequest: public MissionClaim ? Mission { get ; init ; }
+ AAuth.Agent.Governance.PermissionRequest: public string ? MissionS256 { get ; init ; }
```

Public owners: `AAuth.Agent.Governance.PermissionRequest`, `AAuth.Agent.Governance`.

### src/AAuth/Agent/Mission.cs

Concept/decision: [agent-clients](#agent-clients). Source: [Mission.cs](../../../src/AAuth/Agent/Mission.cs).

```diff
- AAuth.Agent.AAuthMissionHeader: public const string Name = "AAuth-Mission" ;
- AAuth.Agent.AAuthMissionHeader: public static bool TryParseStructured ( string ? value , out string ? approver , out string ? s256 , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
- AAuth.Agent.AAuthMissionHeader: public static string FormatStructured ( string approver , string s256 )
- AAuth.Agent.Mission: public required string Approver { get ; init ; }
- AAuth.Agent.Mission: public static Mission FromApprovalBytes ( ReadOnlySpan < byte > body )
- AAuth.Agent: public static class AAuthMissionHeader
+ AAuth.Agent.Mission: public DateTimeOffset ? ExpiresAt { get ; init ; }
+ AAuth.Agent.Mission: public IReadOnlyDictionary < string , string > PersonTokens { get ; init ; } = new Dictionary < string , string > ( )
+ AAuth.Agent.Mission: public IReadOnlyList < string > ApprovedResources { get ; init ; } = Array . Empty < string > ( )
+ AAuth.Agent.Mission: public required string PersonServer { get ; init ; }
+ AAuth.Agent.Mission: public static Mission FromApprovalResponse ( ReadOnlySpan < byte > body , string personServer )
+ AAuth.Agent.Mission: public static Mission FromBlob ( ReadOnlySpan < byte > blob , string personServer , IReadOnlyList < string > ? capabilities = null , IReadOnlyDictionary < string , string > ? personTokens = null )
```

Public owners: `AAuth.Agent.AAuthMissionHeader`, `AAuth.Agent.Mission`, `AAuth.Agent`.

### src/AAuth/Agent/MissionContextHandler.cs

Concept/decision: [agent-clients](#agent-clients). Source: [MissionContextHandler.cs](../../../src/AAuth/Agent/MissionContextHandler.cs).

```diff
+ AAuth.Agent.MissionContextHandler: protected override Task < HttpResponseMessage > SendAsync ( HttpRequestMessage request , CancellationToken cancellationToken )
+ AAuth.Agent.MissionContextHandler: public MissionContextHandler ( Mission mission )
+ AAuth.Agent: public sealed class MissionContextHandler : DelegatingHandler
```

Public owners: `AAuth.Agent.MissionContextHandler`, `AAuth.Agent`.

### src/AAuth/Agent/MissionForwardingHandler.cs

Concept/decision: [agent-clients](#agent-clients). Source: [MissionForwardingHandler.cs](../../../src/AAuth/Agent/MissionForwardingHandler.cs).

```diff
- AAuth.Agent.MissionForwardingHandler: public MissionForwardingHandler ( Func < string ? > upstreamTokenProvider )
+ AAuth.Agent.MissionForwardingHandler: public MissionForwardingHandler ( System . Func < string ? > upstreamTokenProvider )
```

Public owners: `AAuth.Agent.MissionForwardingHandler`, `AAuth.Agent`.

### src/AAuth/Agent/MissionHeaderHandler.cs

Concept/decision: [agent-clients](#agent-clients). Source: [MissionHeaderHandler.cs](../../../src/AAuth/Agent/MissionHeaderHandler.cs).

```diff
- AAuth.Agent.MissionHeaderHandler: protected override Task < HttpResponseMessage > SendAsync ( HttpRequestMessage request , CancellationToken cancellationToken )
- AAuth.Agent.MissionHeaderHandler: public MissionHeaderHandler ( Mission mission )
- AAuth.Agent: public sealed class MissionHeaderHandler : DelegatingHandler
```

Public owners: `AAuth.Agent.MissionHeaderHandler`, `AAuth.Agent`.

### src/AAuth/Agent/TokenExchangeClient.cs

Concept/decision: [agent-clients](#agent-clients). Source: [TokenExchangeClient.cs](../../../src/AAuth/Agent/TokenExchangeClient.cs).

```diff
- AAuth.Agent.TokenExchangeClient: public Task < string > ExchangeAsync ( string personServer , string resourceToken , CancellationToken cancellationToken = default )
+ AAuth.Agent.TokenExchangeClient: public Task < string > ExchangeAsync ( string personServer , string resourceToken , string presentedToken , CancellationToken cancellationToken = default )
+ AAuth.Agent.TokenExchangeClient: public Task < string > RequestPersonTokenAsync ( string personServer , string resource , CancellationToken cancellationToken = default )
+ AAuth.Agent.TokenExchangeClient: public async Task < string > RequestPersonTokenAsync ( string personServer , string resource , TokenExchangeRequest options , CancellationToken cancellationToken = default )
```

Public owners: `AAuth.Agent.TokenExchangeClient`, `AAuth.Agent`.

### src/AAuth/Agent/TokenExchangeRequest.cs

Concept/decision: [agent-clients](#agent-clients). Source: [TokenExchangeRequest.cs](../../../src/AAuth/Agent/TokenExchangeRequest.cs).

```diff
+ AAuth.Agent.TokenExchangeRequest: public string ? MissionS256 { get ; init ; }
+ AAuth.Agent.TokenExchangeRequest: public string ? PresentedToken { get ; init ; }
```

Public owners: `AAuth.Agent.TokenExchangeRequest`, `AAuth.Agent`.

### src/AAuth/Crypto/FileKeyStore.cs

Concept/decision: [signatures](#signatures). Source: [FileKeyStore.cs](../../../src/AAuth/Crypto/FileKeyStore.cs).

Public signatures unchanged (8); behavior reviewed under signatures.

Public owners: `AAuth.Crypto.FileKeyStore`, `AAuth.Crypto`.

### src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs

Concept/decision: [di](#di). Source: [AAuthApplicationBuilderExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs).

Public signatures unchanged (7); behavior reviewed under di.

Public owners: `Microsoft.AspNetCore.Builder.AAuthApplicationBuilderExtensions`, `Microsoft.AspNetCore.Builder`.

### src/AAuth/DependencyInjection/AAuthGovernanceApplicationBuilderExtensions.cs

Concept/decision: [di](#di). Source: [AAuthGovernanceApplicationBuilderExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthGovernanceApplicationBuilderExtensions.cs).

Public signatures unchanged (2); behavior reviewed under di.

Public owners: `Microsoft.AspNetCore.Builder.AAuthGovernanceApplicationBuilderExtensions`, `Microsoft.AspNetCore.Builder`.

### src/AAuth/DependencyInjection/AAuthGovernanceServiceCollectionExtensions.cs

Concept/decision: [di](#di). Source: [AAuthGovernanceServiceCollectionExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthGovernanceServiceCollectionExtensions.cs).

Public signatures unchanged (4); behavior reviewed under di.

Public owners: `Microsoft.Extensions.DependencyInjection.AAuthGovernanceServiceCollectionExtensions`, `Microsoft.Extensions.DependencyInjection`.

### src/AAuth/DependencyInjection/AAuthResourceOptions.cs

Concept/decision: [di](#di). Source: [AAuthResourceOptions.cs](../../../src/AAuth/DependencyInjection/AAuthResourceOptions.cs).

```diff
- AAuth.AAuthResourceOptions: public TimeSpan MaxFutureSkew { get ; set ; } = TimeSpan . FromSeconds ( 5 )
```

Public owners: `AAuth.AAuthResourceOptions`, `AAuth`.

### src/AAuth/DependencyInjection/AAuthResourcePipelineOptions.cs

Concept/decision: [di](#di). Source: [AAuthResourcePipelineOptions.cs](../../../src/AAuth/DependencyInjection/AAuthResourcePipelineOptions.cs).

```diff
+ AAuth.AAuthResourcePipelineOptions: public Func < string , bool > ? IsTrustedPersonServer { get ; set ; }
+ AAuth.AAuthResourcePipelineOptions: public IReadOnlySet < string > ? TrustedPersonServers { get ; set ; }
```

Public owners: `AAuth.AAuthResourcePipelineOptions`, `AAuth`.

### src/AAuth/DependencyInjection/AAuthResourceServiceCollectionExtensions.cs

Concept/decision: [di](#di). Source: [AAuthResourceServiceCollectionExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthResourceServiceCollectionExtensions.cs).

Public signatures unchanged (6); behavior reviewed under di.

Public owners: `Microsoft.Extensions.DependencyInjection.AAuthResourceServiceCollectionExtensions`, `Microsoft.Extensions.DependencyInjection`.

### src/AAuth/Discovery/MetadataClient.cs

Concept/decision: [discovery](#discovery). Source: [MetadataClient.cs](../../../src/AAuth/Discovery/MetadataClient.cs).

Public signatures unchanged (8); behavior reviewed under discovery.

Public owners: `AAuth.Discovery.MetadataClient`, `AAuth.Discovery`.

### src/AAuth/Discovery/ServerMetadata.cs

Concept/decision: [discovery](#discovery). Source: [ServerMetadata.cs](../../../src/AAuth/Discovery/ServerMetadata.cs).

```diff
- AAuth.Discovery.ServerMetadata: public string ? TokenEndpoint { get ; init ; }
+ AAuth.Discovery.ServerMetadata: public string ? AuthTokenEndpoint { get ; init ; }
+ AAuth.Discovery.ServerMetadata: public string ? PersonTokenEndpoint { get ; init ; }
```

Public owners: `AAuth.Discovery.MetadataClientExtensions`, `AAuth.Discovery.ResourceMetadata`, `AAuth.Discovery.ServerMetadata`, `AAuth.Discovery`.

### src/AAuth/Errors/PollingError.cs

Concept/decision: [server-contracts](#server-contracts). Source: [PollingError.cs](../../../src/AAuth/Errors/PollingError.cs).

```diff
+ AAuth.Errors.PollingErrorCode: Revoked
```

Public owners: `AAuth.Errors.PollingErrorCode`, `AAuth.Errors.PollingErrorException`, `AAuth.Errors`.

### src/AAuth/Errors/RevocationError.cs

Concept/decision: [revocation](#revocation). Source: [RevocationError.cs](../../../src/AAuth/Errors/RevocationError.cs).

```diff
+ AAuth.Errors.RevocationDownstreamError: RevocationUnavailable
+ AAuth.Errors.RevocationDownstreamError: RevocationUnsupported
+ AAuth.Errors.RevocationError: public static bool TryParseCode ( string ? code , out RevocationErrorCode result )
+ AAuth.Errors.RevocationError: public static bool TryParseDownstream ( string ? code , out RevocationDownstreamError result )
+ AAuth.Errors.RevocationError: public static int StatusCode ( RevocationErrorCode code )
+ AAuth.Errors.RevocationError: public static string ToWireCode ( RevocationDownstreamError error )
+ AAuth.Errors.RevocationError: public static string ToWireCode ( RevocationErrorCode code )
+ AAuth.Errors.RevocationErrorCode: InvalidRequest
+ AAuth.Errors.RevocationErrorCode: RateLimited
+ AAuth.Errors.RevocationErrorCode: ServerError
+ AAuth.Errors.RevocationErrorCode: UnsupportedIss
+ AAuth.Errors: public enum RevocationDownstreamError
+ AAuth.Errors: public enum RevocationErrorCode
+ AAuth.Errors: public static class RevocationError
```

Public owners: `AAuth.Errors.RevocationDownstreamError`, `AAuth.Errors.RevocationErrorCode`, `AAuth.Errors.RevocationError`, `AAuth.Errors`.

### src/AAuth/Errors/SignatureError.cs

Concept/decision: [server-contracts](#server-contracts). Source: [SignatureError.cs](../../../src/AAuth/Errors/SignatureError.cs).

```diff
+ AAuth.Errors.SignatureErrorCode: ClockSkew
+ AAuth.Errors.SignatureErrorCode: RevokedJwt
```

Public owners: `AAuth.Errors.SignatureErrorCode`, `AAuth.Errors.SignatureError`, `AAuth.Errors`.

### src/AAuth/Errors/TokenError.cs

Concept/decision: [server-contracts](#server-contracts). Source: [TokenError.cs](../../../src/AAuth/Errors/TokenError.cs).

```diff
- AAuth.Errors.TokenErrorCode: InteractionRequired
+ AAuth.Errors.TokenErrorCode: AsUnreachable
+ AAuth.Errors.TokenErrorCode: ClockSkew
+ AAuth.Errors.TokenErrorCode: ExpiredPresentedToken
+ AAuth.Errors.TokenErrorCode: ExpiredSubagentToken
+ AAuth.Errors.TokenErrorCode: ExpiredUpstreamToken
+ AAuth.Errors.TokenErrorCode: InvalidPresentedToken
+ AAuth.Errors.TokenErrorCode: InvalidSubagentToken
+ AAuth.Errors.TokenErrorCode: InvalidUpstreamToken
+ AAuth.Errors.TokenErrorCode: RevokedPresentedToken
+ AAuth.Errors.TokenErrorCode: RevokedResourceToken
+ AAuth.Errors.TokenErrorCode: RevokedSubagentToken
+ AAuth.Errors.TokenErrorCode: RevokedUpstreamToken
```

Public owners: `AAuth.Errors.TokenErrorCode`, `AAuth.Errors.TokenErrorResponse`, `AAuth.Errors`.

### src/AAuth/Headers/AAuthRequirementHeader.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthRequirementHeader.cs](../../../src/AAuth/Headers/AAuthRequirementHeader.cs).

```diff
+ AAuth.Headers.AAuthRequirementHeader: public const string PersonTokenRequirement = "person-token" ;
+ AAuth.Headers.AAuthRequirementHeader: public static string FormatPersonToken ( )
```

Public owners: `AAuth.Headers.AAuthRequirementHeader.ParsedRequirement`, `AAuth.Headers.AAuthRequirementHeader`, `AAuth.Headers`.

### src/AAuth/Headers/ClaimsResponse.cs

Concept/decision: [server-contracts](#server-contracts). Source: [ClaimsResponse.cs](../../../src/AAuth/Headers/ClaimsResponse.cs).

```diff
- AAuth.Headers.ClaimsResponse: public required string Subject { get ; init ; }
```

Public owners: `AAuth.Headers.ClaimsResponse`, `AAuth.Headers`.

### src/AAuth/HttpSig/AAuthSigningHandler.cs

Concept/decision: [signatures](#signatures). Source: [AAuthSigningHandler.cs](../../../src/AAuth/HttpSig/AAuthSigningHandler.cs).

Public signatures unchanged (13); behavior reviewed under signatures.

Public owners: `AAuth.HttpSig.AAuthSigningHandler`, `AAuth.HttpSig`.

### src/AAuth/HttpSig/AAuthVerifier.cs

Concept/decision: [signatures](#signatures). Source: [AAuthVerifier.cs](../../../src/AAuth/HttpSig/AAuthVerifier.cs).

```diff
- AAuth.HttpSig.AAuthVerifier: public TimeSpan MaxFutureSkew { get ; init ; } = TimeSpan . FromSeconds ( 5 )
- AAuth.HttpSig.AAuthVerifier: public string Verify ( string method , string authority , string path , string signatureKey , string signatureInput , string signatureHeader , IAAuthKey publicKey , string ? authorization = null , string ? mission = null , string label = "sig" , IReadOnlyDictionary < string , string > ? fields = null , IReadOnlyCollection < string > ? requiredComponents = null , string ? keyId = null , IReadOnlyDictionary < string , string [  ] > ? fieldValues = null , string ? requestScheme = null , string ? query = null , string ? requestTarget = null )
+ AAuth.HttpSig.AAuthVerifier: public string Verify ( string method , string authority , string path , string signatureKey , string signatureInput , string signatureHeader , IAAuthKey publicKey , string ? authorization = null , string label = "sig" , IReadOnlyDictionary < string , string > ? fields = null , IReadOnlyCollection < string > ? requiredComponents = null , string ? keyId = null , IReadOnlyDictionary < string , string [  ] > ? fieldValues = null , string ? requestScheme = null , string ? query = null , string ? requestTarget = null )
```

Public owners: `AAuth.HttpSig.AAuthVerificationException`, `AAuth.HttpSig.AAuthVerifier`, `AAuth.HttpSig`.

### src/AAuth/HttpSig/DefaultSignatureKeyResolver.cs

Concept/decision: [signatures](#signatures). Source: [DefaultSignatureKeyResolver.cs](../../../src/AAuth/HttpSig/DefaultSignatureKeyResolver.cs).

Public signatures unchanged (3); behavior reviewed under signatures.

Public owners: `AAuth.HttpSig.DefaultSignatureKeyResolver`, `AAuth.HttpSig`.

### src/AAuth/HttpSig/NamingTokenVerifier.cs

Concept/decision: [signatures](#signatures). Source: [NamingTokenVerifier.cs](../../../src/AAuth/HttpSig/NamingTokenVerifier.cs).

Public signatures unchanged (3); behavior reviewed under signatures.

Public owners: `AAuth.HttpSig.NamingTokenVerifier`, `AAuth.HttpSig`.

### src/AAuth/HttpSig/SignatureKeyHeader.cs

Concept/decision: [signatures](#signatures). Source: [SignatureKeyHeader.cs](../../../src/AAuth/HttpSig/SignatureKeyHeader.cs).

Public signatures unchanged (10); behavior reviewed under signatures.

Public owners: `AAuth.HttpSig.SignatureKeyHeader`, `AAuth.HttpSig`.

### src/AAuth/Identifiers/AgentId.cs

Concept/decision: [discovery](#discovery). Source: [AgentId.cs](../../../src/AAuth/Identifiers/AgentId.cs).

Public signatures unchanged (14); behavior reviewed under discovery.

Public owners: `AAuth.Identifiers.AgentId`, `AAuth.Identifiers`.

### src/AAuth/Person/AAuthPersonServerEndpoints.cs

Concept/decision: [consent](#consent). Source: [AAuthPersonServerEndpoints.cs](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs).

```diff
+ AAuth.Person.AAuthPersonServerOptions: public string PersonTokenPath { get ; init ; } = "/person"
```

Public owners: `AAuth.Person.AAuthPersonServerEndpoints`, `AAuth.Person.AAuthPersonServerOptions`, `AAuth.Person`.

### src/AAuth/Person/IIdentityClaimsAsserter.cs

Concept/decision: [consent](#consent). Source: [IIdentityClaimsAsserter.cs](../../../src/AAuth/Person/IIdentityClaimsAsserter.cs).

```diff
- AAuth.Person.IdentityAssertionRequest: public MissionClaim ? Mission { get ; init ; }
+ AAuth.Person.IdentityAssertionRequest: public bool PersonTokenRequest { get ; init ; }
+ AAuth.Person.IdentityAssertionRequest: public string ? LoginHint { get ; init ; }
+ AAuth.Person.IdentityAssertionRequest: public string ? MissionS256 { get ; init ; }
+ AAuth.Person.IdentityAssertionRequest: public string ? Subject { get ; init ; }
```

Public owners: `AAuth.Person.DefaultIdentityClaimsAsserter`, `AAuth.Person.IIdentityClaimsAsserter`, `AAuth.Person.IdentityAssertionKind`, `AAuth.Person.IdentityAssertionRequest`, `AAuth.Person.IdentityAssertion`, `AAuth.Person`.

### src/AAuth/Person/IPersonPendingStore.cs

Concept/decision: [consent](#consent). Source: [IPersonPendingStore.cs](../../../src/AAuth/Person/IPersonPendingStore.cs).

```diff
- AAuth.Person.IPersonPendingStore: PersonPendingEntry Add ( string resourceUrl , string scope , string agentId , IAAuthKey ? agentConfirmationKey , DateTimeOffset agentTokenExpiresAt , JsonObject ? upstreamAct = null , MissionClaim ? mission = null , DateTimeOffset ? authorizationExpiresAt = null )
- AAuth.Person.InMemoryPersonPendingStore: public PersonPendingEntry Add ( string resourceUrl , string scope , string agentId , IAAuthKey ? agentConfirmationKey , DateTimeOffset agentTokenExpiresAt , JsonObject ? upstreamAct = null , MissionClaim ? mission = null , DateTimeOffset ? authorizationExpiresAt = null )
- AAuth.Person.PersonPendingEntry: public JsonObject ? UpstreamAct { get ; init ; }
- AAuth.Person.PersonPendingEntry: public MissionClaim ? Mission { get ; set ; }
+ AAuth.Person.IPersonPendingStore: PersonPendingEntry Add ( string resourceUrl , string scope , string agentId , IAAuthKey ? agentConfirmationKey , DateTimeOffset agentTokenExpiresAt , string ? missionS256 = null , DateTimeOffset ? authorizationExpiresAt = null )
+ AAuth.Person.InMemoryPersonPendingStore: public PersonPendingEntry Add ( string resourceUrl , string scope , string agentId , IAAuthKey ? agentConfirmationKey , DateTimeOffset agentTokenExpiresAt , string ? missionS256 = null , DateTimeOffset ? authorizationExpiresAt = null )
+ AAuth.Person.PersonPendingEntry: public bool PersonToken { get ; set ; }
+ AAuth.Person.PersonPendingEntry: public string ? MissionS256 { get ; set ; }
+ AAuth.Person.PersonPendingEntry: public string ? PersonSubject { get ; set ; }
+ AAuth.Person.PersonPendingEntry: public string ? PersonTenant { get ; set ; }
+ AAuth.Person.PersonPendingEntry: public string ? PresentedToken { get ; set ; }
```

Public owners: `AAuth.Person.IPersonPendingStore`, `AAuth.Person.InMemoryPersonPendingStore`, `AAuth.Person.PersonPendingEntry`, `AAuth.Person.PersonPendingStatus`, `AAuth.Person`.

### src/AAuth/Server/AAuthProblemDetails.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthProblemDetails.cs](../../../src/AAuth/Server/AAuthProblemDetails.cs).

```diff
+ AAuth.Server.AAuthProblemDetails: public static IResult SourceExpired ( IEnumerable < TokenRegistration > sources , DateTimeOffset now , IResult ? otherwise = null )
+ AAuth.Server.AAuthProblemDetails: public static IResult SourceRevoked ( Tokens . TokenVerificationException exception )
```

Public owners: `AAuth.Server.AAuthProblemDetails`, `AAuth.Server`.

### src/AAuth/Server/AAuthRevocationOptions.cs

Concept/decision: [revocation](#revocation). Source: [AAuthRevocationOptions.cs](../../../src/AAuth/Server/AAuthRevocationOptions.cs).

```diff
- AAuth.Server.AAuthRevocationOptions: public Func < TokenGrant , CancellationToken , Task < bool > > ? RevokeGrantAsync { get ; set ; }
- AAuth.Server.AAuthRevocationOptions: public Func < string , TokenKey , bool > ? IsTrustedPersonServer { get ; set ; }
- AAuth.Server.AAuthRevocationOptions: public IReadOnlyCollection < string > ? TrustedPersonServers { get ; set ; }
- AAuth.Server.AAuthRevocationOptions: public bool AllowTokenIssuer { get ; set ; }
+ AAuth.Server.AAuthRevocationOptions: public Func < TokenGrant , CancellationToken , Task < RevocationDownstreamError ? > > ? RevokeGrantAsync { get ; set ; }
+ AAuth.Server.AAuthRevocationOptions: public Func < string , bool > ? IsAcceptedIssuer { get ; set ; }
+ AAuth.Server.AAuthRevocationOptions: public TimeSpan MaxTokenLifetime { get ; set ; } = TimeSpan . FromHours ( 24 )
+ AAuth.Server.AAuthRevocationOptions: public bool ReportDownstream { get ; set ; } = true
```

Public owners: `AAuth.Server.AAuthRevocationOptions`, `AAuth.Server`.

### src/AAuth/Server/AuthTokenResponse.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AuthTokenResponse.cs](../../../src/AAuth/Server/AuthTokenResponse.cs).

```diff
+ AAuth.Server.AuthTokenResponse: public static IResult Revoked ( )
+ AAuth.Server.AuthTokenResponse: public static Task < IResult > CreateTrackedAsync ( Func < string > mint , DateTimeOffset ceiling , IJtiStore inventory , IReadOnlyCollection < TokenRegistration > sources , string member , TimeProvider ? timeProvider = null , CancellationToken cancellationToken = default , IResult ? ceilingExpired = null )
+ AAuth.Server.AuthTokenResponse: public static async Task < IResult > CreateTrackedAsync ( Func < string > mint , DateTimeOffset ceiling , IJtiStore inventory , IReadOnlyCollection < TokenKey > sources , string member , TimeProvider ? timeProvider = null , CancellationToken cancellationToken = default )
```

Public owners: `AAuth.Server.AuthTokenResponse`, `AAuth.Server`.

### src/AAuth/Server/CallChaining/CallChainingHandler.cs

Concept/decision: [governance](#governance). Source: [CallChainingHandler.cs](../../../src/AAuth/Server/CallChaining/CallChainingHandler.cs).

```diff
- AAuth.Server.CallChaining.CallChainingHandler: public async Task < string > ExchangeForDownstreamAsync ( string upstreamAuthToken , string resourceToken , Func < Interaction , CancellationToken , Task > ? onInteractionRequired = null , DeferredPollerOptions ? pollerOptions = null , CancellationToken cancellationToken = default , string ? account = null )
+ AAuth.Server.CallChaining.CallChainingHandler: public async Task < string > ExchangeForDownstreamAsync ( string upstreamToken , string resourceToken , string presentedToken , Func < Interaction , CancellationToken , Task > ? onInteractionRequired = null , DeferredPollerOptions ? pollerOptions = null , CancellationToken cancellationToken = default , string ? account = null )
```

Public owners: `AAuth.Server.CallChaining.CallChainingHandler`, `AAuth.Server.CallChaining`.

### src/AAuth/Server/CallChaining/CallChainingRouter.cs

Concept/decision: [governance](#governance). Source: [CallChainingRouter.cs](../../../src/AAuth/Server/CallChaining/CallChainingRouter.cs).

```diff
- AAuth.Server.CallChaining.CallChainingRouter: public static string ResolveDownstreamServer ( string upstreamAuthToken , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
+ AAuth.Server.CallChaining.CallChainingRouter: public static string ResolveDownstreamServer ( string upstreamToken , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
```

Public owners: `AAuth.Server.CallChaining.CallChainingRouter`, `AAuth.Server.CallChaining`.

### src/AAuth/Server/Challenge/AAuthChallengeMiddleware.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthChallengeMiddleware.cs](../../../src/AAuth/Server/Challenge/AAuthChallengeMiddleware.cs).

```diff
+ AAuth.Server.Challenge.AAuthChallengeMiddleware: public static string BuildResourceToken ( ChallengeOptions options , AAuthVerifiedAssertion presented , string ? scope , string ? account = null , IReadOnlyDictionary < string , string > ? scopeDescriptions = null , IReadOnlyCollection < string > ? personServerScopes = null , Interaction ? interaction = null , string ? loginHint = null )
```

Public owners: `AAuth.Server.Challenge.AAuthChallengeMiddleware`, `AAuth.Server.Challenge`.

### src/AAuth/Server/Challenge/ChallengeOptions.cs

Concept/decision: [server-contracts](#server-contracts). Source: [ChallengeOptions.cs](../../../src/AAuth/Server/Challenge/ChallengeOptions.cs).

```diff
- AAuth.Server.Challenge.ChallengeOptions: public bool MissionAware { get ; init ; }
- AAuth.Server.Challenge.ChallengeOptions: public string ? PersonServerAudience { get ; init ; }
+ AAuth.Server.Challenge.ChallengeOptions: public string ? AccessServer { get ; init ; }
```

Public owners: `AAuth.Server.Challenge.ChallengeOptions`, `AAuth.Server.Challenge`.

### src/AAuth/Server/Endpoints/AAuthEndpointExtensions.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthEndpointExtensions.cs](../../../src/AAuth/Server/Endpoints/AAuthEndpointExtensions.cs).

```diff
- Microsoft.AspNetCore.Builder.AAuthEndpointExtensions: public static RouteHandlerBuilder RequireAAuth ( this RouteHandlerBuilder builder , string ? scope = null , string ? role = null , bool missionAware = false )
+ Microsoft.AspNetCore.Builder.AAuthEndpointExtensions: public static RouteHandlerBuilder RequireAAuth ( this RouteHandlerBuilder builder , string ? scope = null , string ? role = null )
```

Public owners: `Microsoft.AspNetCore.Builder.AAuthEndpointExtensions`, `Microsoft.AspNetCore.Builder`.

### src/AAuth/Server/Endpoints/AAuthEndpointRequirement.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthEndpointRequirement.cs](../../../src/AAuth/Server/Endpoints/AAuthEndpointRequirement.cs).

```diff
- AAuth.Server.Endpoints.AAuthEndpointRequirement: public bool MissionAware { get ; init ; }
- AAuth.Server.Endpoints.AAuthServerOptions: public string ? PersonServerAudience { get ; set ; }
+ AAuth.Server.Endpoints.AAuthServerOptions: public Func < string , bool > ? IsTrustedPersonServer { get ; set ; }
+ AAuth.Server.Endpoints.AAuthServerOptions: public IReadOnlySet < string > ? TrustedPersonServers { get ; set ; }
+ AAuth.Server.Endpoints.AAuthServerOptions: public string ? AccessServer { get ; set ; }
```

Public owners: `AAuth.Server.Endpoints.AAuthEndpointRequirement`, `AAuth.Server.Endpoints.AAuthServerOptions`, `AAuth.Server.Endpoints`.

### src/AAuth/Server/Governance/AAuthGovernancePipelineOptions.cs

Concept/decision: [governance](#governance). Source: [AAuthGovernancePipelineOptions.cs](../../../src/AAuth/Server/Governance/AAuthGovernancePipelineOptions.cs).

```diff
- AAuth.Server.Governance.AAuthGovernancePipelineOptions: public string ? Approver { get ; set ; }
+ AAuth.Server.Governance.AAuthGovernancePipelineOptions: public string ? PersonServer { get ; set ; }
```

Public owners: `AAuth.Server.Governance.AAuthGovernancePipelineOptions`, `AAuth.Server.Governance`.

### src/AAuth/Server/Governance/DefaultAuditSink.cs

Concept/decision: [governance](#governance). Source: [DefaultAuditSink.cs](../../../src/AAuth/Server/Governance/DefaultAuditSink.cs).

Public signatures unchanged (3); behavior reviewed under governance.

Public owners: `AAuth.Server.Governance.DefaultAuditSink`, `AAuth.Server.Governance`.

### src/AAuth/Server/Governance/DefaultPermissionDecider.cs

Concept/decision: [governance](#governance). Source: [DefaultPermissionDecider.cs](../../../src/AAuth/Server/Governance/DefaultPermissionDecider.cs).

Public signatures unchanged (2); behavior reviewed under governance.

Public owners: `AAuth.Server.Governance.DefaultPermissionDecider`, `AAuth.Server.Governance`.

### src/AAuth/Server/Governance/GovernanceEndpoints.cs

Concept/decision: [governance](#governance). Source: [GovernanceEndpoints.cs](../../../src/AAuth/Server/Governance/GovernanceEndpoints.cs).

```diff
- AAuth.Server.Governance.GovernanceEndpoints: public static AuditRecord ParseAudit ( JsonObject body , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
- AAuth.Server.Governance.GovernanceEndpoints: public static IResult ? Authorize ( HttpContext context , MissionClaim ? reference , StoredMission ? mission )
- AAuth.Server.Governance.GovernanceEndpoints: public static InteractionRequest ParseInteraction ( JsonObject body , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
- AAuth.Server.Governance.GovernanceEndpoints: public static PermissionRequest ParsePermission ( JsonObject body , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
+ AAuth.Server.Governance.GovernanceEndpoints: public static AuditRecord ParseAudit ( JsonObject body )
+ AAuth.Server.Governance.GovernanceEndpoints: public static IResult ? Authorize ( HttpContext context , string ? missionS256 , StoredMission ? mission )
+ AAuth.Server.Governance.GovernanceEndpoints: public static InteractionRequest ParseInteraction ( JsonObject body )
+ AAuth.Server.Governance.GovernanceEndpoints: public static PermissionRequest ParsePermission ( JsonObject body )
```

Public owners: `AAuth.Server.Governance.GovernanceEndpoints`, `AAuth.Server.Governance`.

### src/AAuth/Server/Governance/IDeferredConsentStore.cs

Concept/decision: [consent](#consent). Source: [IDeferredConsentStore.cs](../../../src/AAuth/Server/Governance/IDeferredConsentStore.cs).

```diff
- AAuth.Server.Governance.DeferredConsent: public string Approver { get ; init ; } = string . Empty
+ AAuth.Server.Governance.DeferredConsent: public string PersonServer { get ; init ; } = string . Empty
```

Public owners: `AAuth.Server.Governance.DeferredConsentKind`, `AAuth.Server.Governance.DeferredConsent`, `AAuth.Server.Governance.IDeferredConsentStore`, `AAuth.Server.Governance`.

### src/AAuth/Server/Governance/IMissionApprover.cs

Concept/decision: [governance](#governance). Source: [IMissionApprover.cs](../../../src/AAuth/Server/Governance/IMissionApprover.cs).

```diff
- AAuth.Server.Governance: public sealed record MissionApprovalContext ( string Agent , string Approver , MissionProposal Proposal )
+ AAuth.Server.Governance.MissionApprovalDecision: public System . DateTimeOffset ? ExpiresAt { get ; init ; }
+ AAuth.Server.Governance: public sealed record MissionApprovalContext ( string Agent , string PersonServer , MissionProposal Proposal )
```

Public owners: `AAuth.Server.Governance.IMissionApprover`, `AAuth.Server.Governance.MissionApprovalDecision`, `AAuth.Server.Governance.MissionApprovalOutcome`, `AAuth.Server.Governance`.

### src/AAuth/Server/Governance/IMissionLog.cs

Concept/decision: [governance](#governance). Source: [IMissionLog.cs](../../../src/AAuth/Server/Governance/IMissionLog.cs).

```diff
+ AAuth.Server.Governance.MissionLogEntryKind: Update
```

Public owners: `AAuth.Server.Governance.IMissionLog`, `AAuth.Server.Governance.MissionLogEntryKind`, `AAuth.Server.Governance.MissionLogEntry`, `AAuth.Server.Governance`.

### src/AAuth/Server/Governance/IMissionPersonTokenIssuer.cs

Concept/decision: [governance](#governance). Source: [IMissionPersonTokenIssuer.cs](../../../src/AAuth/Server/Governance/IMissionPersonTokenIssuer.cs).

```diff
+ AAuth.Server.Governance.IMissionPersonTokenIssuer: Task < IReadOnlyDictionary < string , string > > IssueAsync ( MissionPersonTokenRequest request , CancellationToken ct = default )
+ AAuth.Server.Governance.MissionPersonTokenRequest: public DateTimeOffset ? MissionExpiresAt { get ; init ; }
+ AAuth.Server.Governance.MissionPersonTokenRequest: public required DateTimeOffset AgentTokenExpiresAt { get ; init ; }
+ AAuth.Server.Governance.MissionPersonTokenRequest: public required IAAuthKey ConfirmationKey { get ; init ; }
+ AAuth.Server.Governance.MissionPersonTokenRequest: public required IReadOnlyList < TokenRegistration > SourceTokens { get ; init ; }
+ AAuth.Server.Governance.MissionPersonTokenRequest: public required IReadOnlyList < string > Resources { get ; init ; }
+ AAuth.Server.Governance.MissionPersonTokenRequest: public required string AgentId { get ; init ; }
+ AAuth.Server.Governance.MissionPersonTokenRequest: public required string MissionS256 { get ; init ; }
+ AAuth.Server.Governance.MissionPersonTokenRequest: public required string PersonServer { get ; init ; }
+ AAuth.Server.Governance: public interface IMissionPersonTokenIssuer
+ AAuth.Server.Governance: public sealed record MissionPersonTokenRequest
```

Public owners: `AAuth.Server.Governance.IMissionPersonTokenIssuer`, `AAuth.Server.Governance.MissionPersonTokenRequest`, `AAuth.Server.Governance`.

### src/AAuth/Server/Governance/IMissionStore.cs

Concept/decision: [governance](#governance). Source: [IMissionStore.cs](../../../src/AAuth/Server/Governance/IMissionStore.cs).

```diff
- AAuth.Server.Governance: public sealed record StoredMission ( string S256 , string Approver , string Agent , ReadOnlyMemory < byte > Blob )
+ AAuth.Server.Governance.StoredMission: public DateTimeOffset ? ExpiresAt { get ; init ; }
+ AAuth.Server.Governance: public sealed record StoredMission ( string S256 , string PersonServer , string Agent , ReadOnlyMemory < byte > Blob )
```

Public owners: `AAuth.Server.Governance.IMissionStore`, `AAuth.Server.Governance.StoredMission`, `AAuth.Server.Governance`.

### src/AAuth/Server/Governance/IMissionTokenConsent.cs

Concept/decision: [consent](#consent). Source: [IMissionTokenConsent.cs](../../../src/AAuth/Server/Governance/IMissionTokenConsent.cs).

```diff
- AAuth.Server.Governance.MissionTokenConsentContext: public required MissionClaim Mission { get ; init ; }
+ AAuth.Server.Governance.MissionTokenConsentContext: public required string MissionS256 { get ; init ; }
```

Public owners: `AAuth.Server.Governance.IMissionTokenConsent`, `AAuth.Server.Governance.MissionTokenConsentContext`, `AAuth.Server.Governance.MissionTokenConsentDecision`, `AAuth.Server.Governance.MissionTokenConsentKind`, `AAuth.Server.Governance.MissionTokenConsentStage`, `AAuth.Server.Governance`.

### src/AAuth/Server/Governance/MissionApprovalBuilder.cs

Concept/decision: [governance](#governance). Source: [MissionApprovalBuilder.cs](../../../src/AAuth/Server/Governance/MissionApprovalBuilder.cs).

```diff
- AAuth.Server.Governance.MissionApprovalBuilder: public static ( byte [  ] Blob , string S256 ) Build ( string approver , string agent , MissionProposal proposal , IReadOnlyList < MissionTool > approvedTools , DateTimeOffset approvedAt )
+ AAuth.Server.Governance.MissionApprovalBuilder: public static ( byte [  ] Blob , string S256 ) Build ( string agent , MissionProposal proposal , IReadOnlyList < MissionTool > approvedTools , DateTimeOffset approvedAt , DateTimeOffset ? expiresAt = null , IReadOnlyList < string > ? approvedResources = null )
+ AAuth.Server.Governance.MissionApprovalBuilder: public static JsonObject Response ( ReadOnlySpan < byte > blob , string s256 , IReadOnlyList < string > ? capabilities = null , IReadOnlyDictionary < string , string > ? personTokens = null )
```

Public owners: `AAuth.Server.Governance.MissionApprovalBuilder`, `AAuth.Server.Governance`.

### src/AAuth/Server/IJtiStore.cs

Concept/decision: [revocation](#revocation). Source: [IJtiStore.cs](../../../src/AAuth/Server/IJtiStore.cs).

```diff
- AAuth.Server.IJtiStore: Task < bool > RevokeAsync ( TokenKey token , CancellationToken ct = default )
+ AAuth.Server.IJtiStore: Task RevokeAsync ( TokenKey token , DateTimeOffset expiresAt , CancellationToken ct = default )
```

Public owners: `AAuth.Server.IJtiStore`, `AAuth.Server`.

### src/AAuth/Server/InMemoryJtiStore.cs

Concept/decision: [revocation](#revocation). Source: [InMemoryJtiStore.cs](../../../src/AAuth/Server/InMemoryJtiStore.cs).

```diff
- AAuth.Server.InMemoryJtiStore: public Task < bool > RevokeAsync ( TokenKey token , CancellationToken ct = default )
+ AAuth.Server.InMemoryJtiStore: public Task RevokeAsync ( TokenKey token , DateTimeOffset expiresAt , CancellationToken ct = default )
```

Public owners: `AAuth.Server.InMemoryJtiStore`, `AAuth.Server`.

### src/AAuth/Server/Metadata/AAuthAccessServerMetadataOptions.cs

Concept/decision: [resource-managed](#resource-managed). Source: [AAuthAccessServerMetadataOptions.cs](../../../src/AAuth/Server/Metadata/AAuthAccessServerMetadataOptions.cs).

```diff
- AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public required string TokenEndpoint { get ; init ; }
+ AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public required string AuthTokenEndpoint { get ; init ; }
```

Public owners: `AAuth.Server.Metadata.AAuthAccessServerMetadataOptions`, `AAuth.Server.Metadata`.

### src/AAuth/Server/Metadata/AAuthAgentMetadataOptions.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthAgentMetadataOptions.cs](../../../src/AAuth/Server/Metadata/AAuthAgentMetadataOptions.cs).

```diff
- AAuth.Server.Metadata.AAuthAgentMetadataOptions: public string ? LoginEndpoint { get ; init ; }
```

Public owners: `AAuth.Server.Metadata.AAuthAgentMetadataOptions`, `AAuth.Server.Metadata`.

### src/AAuth/Server/Metadata/AAuthPersonServerMetadataOptions.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthPersonServerMetadataOptions.cs](../../../src/AAuth/Server/Metadata/AAuthPersonServerMetadataOptions.cs).

```diff
- AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public required string TokenEndpoint { get ; init ; }
+ AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public required string AuthTokenEndpoint { get ; init ; }
+ AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public required string PersonTokenEndpoint { get ; init ; }
```

Public owners: `AAuth.Server.Metadata.AAuthPersonServerMetadataOptions`, `AAuth.Server.Metadata`.

### src/AAuth/Server/Metadata/WellKnownEndpoints.cs

Concept/decision: [server-contracts](#server-contracts). Source: [WellKnownEndpoints.cs](../../../src/AAuth/Server/Metadata/WellKnownEndpoints.cs).

Public signatures unchanged (23); behavior reviewed under server-contracts.

Public owners: `AAuth.Server.Metadata.AAuthResourceMetadataOptions`, `AAuth.Server.Metadata.WellKnownEndpoints`, `AAuth.Server.Metadata`.

### src/AAuth/Server/RevocationClient.cs

Concept/decision: [revocation](#revocation). Source: [RevocationClient.cs](../../../src/AAuth/Server/RevocationClient.cs).

```diff
- AAuth.Server.RevocationClient: public async Task < HttpStatusCode > RevokeAsync ( Uri endpoint , TokenKey token , CancellationToken cancellationToken = default )
+ AAuth.Server.RevocationClient: public async Task < RevocationResult > RevokeAsync ( Uri endpoint , string jti , DateTimeOffset expiresAt , CancellationToken cancellationToken = default )
```

Public owners: `AAuth.Server.RevocationClient`, `AAuth.Server`.

### src/AAuth/Server/RevocationEndpoint.cs

Concept/decision: [revocation](#revocation). Source: [RevocationEndpoint.cs](../../../src/AAuth/Server/RevocationEndpoint.cs).

Public signatures unchanged (4); behavior reviewed under revocation.

Public owners: `AAuth.Server.RevocationEndpoint`, `AAuth.Server`.

### src/AAuth/Server/RevocationResult.cs

Concept/decision: [revocation](#revocation). Source: [RevocationResult.cs](../../../src/AAuth/Server/RevocationResult.cs).

```diff
+ AAuth.Server.RevocationResult: public IReadOnlyList < RevocationDownstreamResult > Downstream { get ; init ; } = [ ]
+ AAuth.Server.RevocationResult: public RevocationDownstreamError ? Failure { get ; init ; }
+ AAuth.Server.RevocationResult: public required HttpStatusCode StatusCode { get ; init ; }
+ AAuth.Server.RevocationResult: public string ? Error { get ; init ; }
+ AAuth.Server: public sealed record RevocationDownstreamResult ( string Recipient , RevocationDownstreamError ? Error )
+ AAuth.Server: public sealed record RevocationResult
```

Public owners: `AAuth.Server.RevocationResult`, `AAuth.Server`.

### src/AAuth/Server/TokenRegistration.cs

Concept/decision: [revocation](#revocation). Source: [TokenRegistration.cs](../../../src/AAuth/Server/TokenRegistration.cs).

```diff
- AAuth.Server.TokenRegistration: public static TokenRegistration FromVerified ( TokenVerifier . VerifiedToken token )
+ AAuth.Server.TokenRegistration: public TokenCredential ? Credential { get ; init ; }
+ AAuth.Server.TokenRegistration: public static TokenRegistration FromVerified ( TokenVerifier . VerifiedToken token , TokenCredential ? credential = null )
```

Public owners: `AAuth.Server.TokenRegistration`, `AAuth.Server`.

### src/AAuth/Server/TokenRequestBody.cs

Concept/decision: [server-contracts](#server-contracts). Source: [TokenRequestBody.cs](../../../src/AAuth/Server/TokenRequestBody.cs).

Public signatures unchanged (2); behavior reviewed under server-contracts.

Public owners: `AAuth.Server.TokenRequestBody`, `AAuth.Server`.

### src/AAuth/Server/Verification/AAuthAuthenticationHandler.cs

Concept/decision: [signatures](#signatures). Source: [AAuthAuthenticationHandler.cs](../../../src/AAuth/Server/Verification/AAuthAuthenticationHandler.cs).

```diff
- AAuth.Server.Verification.AAuthAuthenticationHandler: public const string ActorAgentClaimType = "aauth:act_agent" ;
+ AAuth.Server.Verification.AAuthAuthenticationHandler: public const string MissionClaimType = "aauth:mission_s256" ;
+ AAuth.Server.Verification.AAuthAuthenticationHandler: public const string PersonServerClaimType = "aauth:ps" ;
+ AAuth.Server.Verification.AAuthAuthenticationHandler: public const string TenantClaimType = "aauth:tenant" ;
```

Public owners: `AAuth.Server.Verification.AAuthAuthenticationHandler`, `AAuth.Server.Verification`.

### src/AAuth/Server/Verification/AAuthHttpContextExtensions.cs

Concept/decision: [signatures](#signatures). Source: [AAuthHttpContextExtensions.cs](../../../src/AAuth/Server/Verification/AAuthHttpContextExtensions.cs).

```diff
+ AAuth.Server.Verification.AAuthHttpContextExtensions: public static AAuthVerifiedAssertion ? GetAAuthVerifiedAssertion ( this HttpContext context )
```

Public owners: `AAuth.Server.Verification.AAuthHttpContextExtensions`, `AAuth.Server.Verification`.

### src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs

Concept/decision: [signatures](#signatures). Source: [AAuthVerificationMiddleware.cs](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs).

Public signatures unchanged (14); behavior reviewed under signatures.

Public owners: `AAuth.Server.Verification.AAuthVerificationMiddleware`, `AAuth.Server.Verification.VerificationResult`, `AAuth.Server.Verification`.

### src/AAuth/Server/Verification/AAuthVerificationOptions.cs

Concept/decision: [signatures](#signatures). Source: [AAuthVerificationOptions.cs](../../../src/AAuth/Server/Verification/AAuthVerificationOptions.cs).

```diff
- AAuth.Server.Verification.AAuthVerificationOptions: public TimeSpan MaxFutureSkew { get ; init ; } = TimeSpan . FromSeconds ( 5 )
- AAuth.Server.Verification.AAuthVerificationOptions: public int MaxActDepth { get ; init ; } = 10
+ AAuth.Server.Verification.AAuthVerificationOptions: public Func < string , bool > ? IsTrustedPersonServer { get ; init ; }
+ AAuth.Server.Verification.AAuthVerificationOptions: public IReadOnlySet < string > ? TrustedPersonServers { get ; init ; }
```

Public owners: `AAuth.Server.Verification.AAuthVerificationOptions`, `AAuth.Server.Verification`.

### src/AAuth/Server/Verification/AAuthVerificationResult.cs

Concept/decision: [signatures](#signatures). Source: [AAuthVerificationResult.cs](../../../src/AAuth/Server/Verification/AAuthVerificationResult.cs).

```diff
- AAuth.Server.Verification.AAuthVerificationResult: public string ? ActorAgent { get ; init ; }
+ AAuth.Server.Verification.AAuthVerificationResult: public string ? MissionS256 { get ; init ; }
+ AAuth.Server.Verification.AAuthVerificationResult: public string ? PersonServer { get ; init ; }
+ AAuth.Server.Verification.AAuthVerificationResult: public string ? Tenant { get ; init ; }
```

Public owners: `AAuth.Server.Verification.AAuthVerificationResult`, `AAuth.Server.Verification`.

### src/AAuth/Tokens/ActChainBuilder.cs

Concept/decision: [tokens](#tokens). Source: [ActChainBuilder.cs](../../../src/AAuth/Tokens/ActChainBuilder.cs).

```diff
- AAuth.Tokens.ActChainBuilder: public static JsonObject BuildNestedAct ( string upstreamAgentId , JsonObject ? upstreamChain = null , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
- AAuth.Tokens.ActChainBuilder: public static bool ValidateChain ( JsonObject act , int maxDepth = 10 , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
- AAuth.Tokens: public static class ActChainBuilder
```

Public owners: `AAuth.Tokens.ActChainBuilder`, `AAuth.Tokens`.

### src/AAuth/Tokens/ActChainReader.cs

Concept/decision: [tokens](#tokens). Source: [ActChainReader.cs](../../../src/AAuth/Tokens/ActChainReader.cs).

```diff
- AAuth.Tokens.ActChainReader: public static IReadOnlyList < string > GetDelegationChain ( JsonObject payload , int maxDepth = 10 , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
- AAuth.Tokens.ActChainReader: public static int GetChainDepth ( JsonObject payload , int maxDepth = 10 , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
- AAuth.Tokens.ActChainReader: public static string ? GetImmediateActor ( JsonObject payload , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
- AAuth.Tokens.ActChainReader: public static string ? GetOriginalActor ( JsonObject payload , int maxDepth = 10 , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
- AAuth.Tokens: public static class ActChainReader
```

Public owners: `AAuth.Tokens.ActChainReader`, `AAuth.Tokens`.

### src/AAuth/Tokens/AgentAuthTokenValidator.cs

Concept/decision: [tokens](#tokens). Source: [AgentAuthTokenValidator.cs](../../../src/AAuth/Tokens/AgentAuthTokenValidator.cs).

```diff
- AAuth.Tokens.AgentAuthTokenValidator: public static void Validate ( string authToken , string resourceToken , IAAuthKey signingKey , string agentToken , string ? subagentToken = null , string ? upstreamToken = null , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
+ AAuth.Tokens.AgentAuthTokenValidator: public static void Validate ( string authToken , string resourceToken , IAAuthKey signingKey , string agentToken , string presentedToken , string ? subagentToken = null , string ? upstreamToken = null )
```

Public owners: `AAuth.Tokens.AgentAuthTokenValidator`, `AAuth.Tokens`.

### src/AAuth/Tokens/AgentIssuanceContext.cs

Concept/decision: [tokens](#tokens). Source: [AgentIssuanceContext.cs](../../../src/AAuth/Tokens/AgentIssuanceContext.cs).

```diff
- AAuth.Tokens.AgentIssuanceContext: public JsonObject ? Act { get ; init ; }
- AAuth.Tokens.AgentIssuanceContext: public static async Task < AgentIssuanceContext > VerifyAsync ( string agentToken , string ? subagentToken , string ? upstreamToken , TokenVerifier verifier , MetadataClient metadata , JwksClient jwks , Func < string , bool > isTrustedUpstreamIssuer , CancellationToken cancellationToken = default )
- AAuth.Tokens.AgentIssuanceContext: public void ValidateResourceContext ( JsonObject resource , string ? governingPersonServer = null )
+ AAuth.Tokens.AgentIssuanceContext: public bool SubAgent { get ; init ; }
+ AAuth.Tokens.AgentIssuanceContext: public required string AgentIssuer { get ; init ; }
+ AAuth.Tokens.AgentIssuanceContext: public static async Task < AgentIssuanceContext > VerifyAsync ( string agentToken , string ? subagentToken , string ? upstreamToken , string personServer , TokenVerifier verifier , MetadataClient metadata , JwksClient jwks , Func < string , bool > isTrustedAuthTokenIssuer , CancellationToken cancellationToken = default , TokenCredential ? agentTokenCredential = null )
+ AAuth.Tokens.AgentIssuanceContext: public void ValidateResourceContext ( JsonObject resource )
```

Public owners: `AAuth.Tokens.AgentIssuanceContext`, `AAuth.Tokens`.

### src/AAuth/Tokens/AuthTokenBuilder.cs

Concept/decision: [tokens](#tokens). Source: [AuthTokenBuilder.cs](../../../src/AAuth/Tokens/AuthTokenBuilder.cs).

```diff
- AAuth.Tokens.AuthTokenBuilder: public JsonObject ? Act { get ; init ; }
- AAuth.Tokens.AuthTokenBuilder: public MissionClaim ? Mission { get ; init ; }
- AAuth.Tokens.AuthTokenBuilder: public required string Agent { get ; init ; }
- AAuth.Tokens.AuthTokenBuilder: public string ? Subject { get ; init ; }
+ AAuth.Tokens.AuthTokenBuilder: public required string PersonServer { get ; init ; }
+ AAuth.Tokens.AuthTokenBuilder: public required string Subject { get ; init ; }
+ AAuth.Tokens.AuthTokenBuilder: public string ? MissionS256 { get ; init ; }
```

Public owners: `AAuth.Tokens.AuthTokenBuilder`, `AAuth.Tokens`.

### src/AAuth/Tokens/AuthTokenResponseValidator.cs

Concept/decision: [tokens](#tokens). Source: [AuthTokenResponseValidator.cs](../../../src/AAuth/Tokens/AuthTokenResponseValidator.cs).

```diff
- AAuth.Tokens.AuthTokenResponseValidator: public async Task < AuthTokenDeliveryResult > ValidateAsync ( string authToken , string expectedIssuer , string expectedAudience , string expectedAgentId , IAAuthKey agentKey , JsonObject ? expectedActContext = null , string ? requestedScope = null , CancellationToken ct = default , string ? expectedAccount = null )
- AAuth.Tokens.AuthTokenResponseValidator: public static bool ActChainsMatch ( JsonObject ? actual , JsonObject ? expected , AAuthEgressPolicy ? policy = null )
+ AAuth.Tokens.AuthTokenResponseValidator: public async Task < AuthTokenDeliveryResult > ValidateAsync ( string authToken , string expectedIssuer , string expectedAudience , string expectedSubject , string expectedPersonServer , IAAuthKey agentKey , DateTimeOffset presentedTokenExpiresAt , string ? requestedScope = null , CancellationToken ct = default , string ? expectedAccount = null )
```

Public owners: `AAuth.Tokens.AuthTokenDeliveryResult`, `AAuth.Tokens.AuthTokenResponseValidator`, `AAuth.Tokens`.

### src/AAuth/Tokens/MissionClaim.cs

Concept/decision: [tokens](#tokens). Source: [MissionClaim.cs](../../../src/AAuth/Tokens/MissionClaim.cs).

```diff
- AAuth.Tokens.MissionClaim: public JsonObject ToJsonObject ( )
- AAuth.Tokens.MissionClaim: public static MissionClaim ? FromPayload ( JsonObject ? payload , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
- AAuth.Tokens: public sealed record MissionClaim ( string Approver , string S256 )
```

Public owners: `AAuth.Tokens.MissionClaim`, `AAuth.Tokens`.

### src/AAuth/Tokens/MissionReference.cs

Concept/decision: [tokens](#tokens). Source: [MissionReference.cs](../../../src/AAuth/Tokens/MissionReference.cs).

```diff
+ AAuth.Tokens.MissionReference: public const string ClaimName = "mission_s256" ;
+ AAuth.Tokens.MissionReference: public static bool IsValid ( string ? value )
+ AAuth.Tokens.MissionReference: public static string ? Read ( JsonObject ? document )
+ AAuth.Tokens: public static class MissionReference
```

Public owners: `AAuth.Tokens.MissionReference`, `AAuth.Tokens`.

### src/AAuth/Tokens/PersonTokenBuilder.cs

Concept/decision: [tokens](#tokens). Source: [PersonTokenBuilder.cs](../../../src/AAuth/Tokens/PersonTokenBuilder.cs).

```diff
+ AAuth.Tokens.PersonTokenBuilder: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; init ; } = AAuth . Discovery . AAuthEgressPolicy . Production
+ AAuth.Tokens.PersonTokenBuilder: public DateTimeOffset ? AuthorizationExpiresAt { get ; init ; }
+ AAuth.Tokens.PersonTokenBuilder: public DateTimeOffset ? IssuedAt { get ; init ; }
+ AAuth.Tokens.PersonTokenBuilder: public TimeProvider TimeProvider { get ; init ; } = TimeProvider . System
+ AAuth.Tokens.PersonTokenBuilder: public TimeSpan Lifetime { get ; init ; } = TimeSpan . FromHours ( 1 )
+ AAuth.Tokens.PersonTokenBuilder: public const string PersonDwk = "aauth-person.json" ;
+ AAuth.Tokens.PersonTokenBuilder: public const string TokenType = "aa-person+jwt" ;
+ AAuth.Tokens.PersonTokenBuilder: public required DateTimeOffset AgentTokenExpiresAt { get ; init ; }
+ AAuth.Tokens.PersonTokenBuilder: public required IAAuthKey ConfirmationKey { get ; init ; }
+ AAuth.Tokens.PersonTokenBuilder: public required IAAuthKey Key { get ; init ; }
+ AAuth.Tokens.PersonTokenBuilder: public required string Audience { get ; init ; }
+ AAuth.Tokens.PersonTokenBuilder: public required string Issuer { get ; init ; }
+ AAuth.Tokens.PersonTokenBuilder: public required string KeyId { get ; init ; }
+ AAuth.Tokens.PersonTokenBuilder: public required string Subject { get ; init ; }
+ AAuth.Tokens.PersonTokenBuilder: public string ? MissionS256 { get ; init ; }
+ AAuth.Tokens.PersonTokenBuilder: public string ? Tenant { get ; init ; }
+ AAuth.Tokens.PersonTokenBuilder: public string ? TokenId { get ; init ; }
+ AAuth.Tokens.PersonTokenBuilder: public string Build ( )
+ AAuth.Tokens: public sealed class PersonTokenBuilder
```

Public owners: `AAuth.Tokens.PersonTokenBuilder`, `AAuth.Tokens`.

### src/AAuth/Tokens/ResourceTokenBuilder.cs

Concept/decision: [tokens](#tokens). Source: [ResourceTokenBuilder.cs](../../../src/AAuth/Tokens/ResourceTokenBuilder.cs).

```diff
- AAuth.Tokens.ResourceTokenBuilder: public MissionClaim ? Mission { get ; init ; }
- AAuth.Tokens.ResourceTokenBuilder: public required string Agent { get ; init ; }
+ AAuth.Tokens.ResourceTokenBuilder: public required string PersonServer { get ; init ; }
+ AAuth.Tokens.ResourceTokenBuilder: public required string PresentedJti { get ; init ; }
+ AAuth.Tokens.ResourceTokenBuilder: public required string Subject { get ; init ; }
+ AAuth.Tokens.ResourceTokenBuilder: public string ? LoginHint { get ; init ; }
+ AAuth.Tokens.ResourceTokenBuilder: public string ? MissionS256 { get ; init ; }
+ AAuth.Tokens.ResourceTokenBuilder: public string ? Tenant { get ; init ; }
```

Public owners: `AAuth.Tokens.ResourceTokenBuilder`, `AAuth.Tokens`.

### src/AAuth/Tokens/TokenVerifier.cs

Concept/decision: [tokens](#tokens). Source: [TokenVerifier.cs](../../../src/AAuth/Tokens/TokenVerifier.cs).

```diff
- AAuth.Tokens.TokenVerifier.VerifiedToken: public MissionClaim ? Mission
- AAuth.Tokens.TokenVerifier: public TimeSpan ClockSkew { get ; init ; } = TimeSpan . FromSeconds ( 30 )
- AAuth.Tokens.TokenVerifier: public VerifiedToken VerifyAuthToken ( string jwt , IAAuthKey issuerKey , string expectedAudience , IAAuthKey httpSignatureKey , string expectedAgentId , string ? expectedDwk = null , string ? expectedMaxScope = null , AccountExpectation ? accountExpectation = null )
- AAuth.Tokens.TokenVerifier: public async Task < VerifiedToken > VerifyAuthTokenWithJwksAsync ( string jwt , MetadataClient metadata , JwksClient jwks , string expectedAudience , IAAuthKey httpSignatureKey , string expectedAgentId , string ? expectedMaxScope = null , CancellationToken cancellationToken = default , AccountExpectation ? accountExpectation = null )
- AAuth.Tokens.TokenVerifier: public async Task < VerifiedToken > VerifyResourceTokenAsync ( string jwt , string expectedAudience , string expectedAgentId , string expectedAgentJkt , MetadataClient metadata , JwksClient jwks , string ? expectedApprover = null , string ? subagentAgentJkt = null , CancellationToken cancellationToken = default )
- AAuth.Tokens.TokenVerifier: public int MaxActDepth { get ; init ; } = 10
+ AAuth.Tokens.TokenCredential: Presented
+ AAuth.Tokens.TokenVerifier.VerifiedToken: public string ? MissionS256
+ AAuth.Tokens.TokenVerifier.VerifiedToken: public string ? Subject
+ AAuth.Tokens.TokenVerifier.VerifiedToken: public string ? Tenant
+ AAuth.Tokens.TokenVerifier.VerifiedToken: public string Jti
+ AAuth.Tokens.TokenVerifier: public Func < string , string , IAAuthKey ? > ? LocalIssuerKeys { get ; init ; }
+ AAuth.Tokens.TokenVerifier: public Task < VerifiedToken > VerifyAuthTokenWithJwksAsync ( string jwt , MetadataClient metadata , JwksClient jwks , string expectedAudience , IAAuthKey httpSignatureKey , string ? expectedMaxScope = null , CancellationToken cancellationToken = default , AccountExpectation ? accountExpectation = null )
+ AAuth.Tokens.TokenVerifier: public Task < VerifiedToken > VerifyPersonTokenWithJwksAsync ( string jwt , MetadataClient metadata , JwksClient jwks , string expectedAudience , IAAuthKey httpSignatureKey , CancellationToken cancellationToken = default )
+ AAuth.Tokens.TokenVerifier: public TimeSpan ClockSkew { get ; init ; } = TimeSpan . FromSeconds ( 60 )
+ AAuth.Tokens.TokenVerifier: public TokenVerifier WithLocalIssuer ( string issuer , IReadOnlyDictionary < string , IAAuthKey > keys )
+ AAuth.Tokens.TokenVerifier: public VerifiedToken VerifyAuthToken ( string jwt , IAAuthKey issuerKey , string expectedAudience , IAAuthKey httpSignatureKey , string ? expectedDwk = null , string ? expectedMaxScope = null , AccountExpectation ? accountExpectation = null )
+ AAuth.Tokens.TokenVerifier: public VerifiedToken VerifyPersonToken ( string jwt , IAAuthKey issuerKey , string expectedAudience , IAAuthKey httpSignatureKey )
+ AAuth.Tokens.TokenVerifier: public async Task < VerifiedToken > VerifyPresentedTokenAsync ( string presentedToken , VerifiedToken resourceToken , MetadataClient metadata , JwksClient jwks , CancellationToken cancellationToken = default )
+ AAuth.Tokens.TokenVerifier: public async Task < VerifiedToken > VerifyResourceTokenAsync ( string jwt , string expectedAudience , string expectedAgentJkt , MetadataClient metadata , JwksClient jwks , string ? subagentAgentJkt = null , string ? expectedPersonServer = null , CancellationToken cancellationToken = default )
```

Public owners: `AAuth.Tokens.TokenCredential`, `AAuth.Tokens.TokenVerificationException`, `AAuth.Tokens.TokenVerifier.VerifiedToken`, `AAuth.Tokens.TokenVerifier`, `AAuth.Tokens`.

### src/AAuth/Tokens/UpstreamTokenValidator.cs

Concept/decision: [tokens](#tokens). Source: [UpstreamTokenValidator.cs](../../../src/AAuth/Tokens/UpstreamTokenValidator.cs).

```diff
- AAuth.Tokens.UpstreamTokenValidationResult: public JsonObject ? UpstreamAct { get ; init ; }
- AAuth.Tokens.UpstreamTokenValidationResult: public MissionClaim ? Mission { get ; init ; }
- AAuth.Tokens.UpstreamTokenValidationResult: public string ? Agent { get ; init ; }
- AAuth.Tokens.UpstreamTokenValidationResult: public string ? IssuerDwk { get ; init ; }
- AAuth.Tokens.UpstreamTokenValidationResult: public string ? MissionApprover { get ; init ; }
- AAuth.Tokens.UpstreamTokenValidator: public Task < UpstreamTokenValidationResult > ValidateAsync ( string upstreamToken , string expectedAudience , IReadOnlySet < string > trustedIssuers , CancellationToken ct = default )
- AAuth.Tokens.UpstreamTokenValidator: public async Task < UpstreamTokenValidationResult > ValidateAsync ( string upstreamToken , string expectedAudience , Func < string , bool > isTrustedIssuer , CancellationToken ct = default )
+ AAuth.Tokens.UpstreamTokenValidationResult: public string ? Audience { get ; init ; }
+ AAuth.Tokens.UpstreamTokenValidationResult: public string ? MissionS256 { get ; init ; }
+ AAuth.Tokens.UpstreamTokenValidationResult: public string ? PersonServer { get ; init ; }
+ AAuth.Tokens.UpstreamTokenValidationResult: public string ? Tenant { get ; init ; }
+ AAuth.Tokens.UpstreamTokenValidationResult: public string ? TokenType { get ; init ; }
+ AAuth.Tokens.UpstreamTokenValidator: public async Task < UpstreamTokenValidationResult > ValidateAsync ( string upstreamToken , string intermediary , string expectedPersonServer , Func < string , bool > isTrustedAuthTokenIssuer , CancellationToken ct = default )
```

Public owners: `AAuth.Tokens.UpstreamTokenValidationResult`, `AAuth.Tokens.UpstreamTokenValidator`, `AAuth.Tokens`.
