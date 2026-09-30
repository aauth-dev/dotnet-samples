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

Baseline `v0.10.0-alpha.1`; 205 changed public-source files, 907 added/replacement declarations, 408 removed/replaced declarations.

Generated from all current SDK source files, including untracked additions, and the baseline tree. Public/protected declarations include containing namespaces/types, overload parameters, required members, attributes, optional defaults, primary constructors and interface members. Compiler-synthesized/inherited members are represented by their source declarations, not expanded. Unchanged signatures in changed files are listed by containing type as behavior-review entries; the concept table above supplies their entry point, ownership, callers and tests. No source file is excluded by guessed file role.

### samples/CapabilitySupport/CatalogDemoSession.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [CatalogDemoSession.cs](../../../samples/CapabilitySupport/CatalogDemoSession.cs).

```diff
- AAuth.Samples.Capabilities.CatalogDemoSession: public static string [  ] Steps { get ; } = [ "Discover catalog services" , "Authorize selected service" , "Read selected catalog" , "Reject a sibling-service grant" , "Authorize sibling and recover" ]
- AAuth.Samples.Capabilities.CatalogDemoSession: public string ? ConsentUrl { get ; private set ; }
+ AAuth.Samples.Capabilities.CatalogDemoSession: public Interaction ? Consent { get ; private set ; }
+ AAuth.Samples.Capabilities.CatalogDemoSession: public static string [  ] Steps { get ; } = [ "Discover catalog definition" , "Authorize selected operation" , "Read selected catalog" , "Reject a sibling-operation grant" , "Authorize sibling and recover" ]
+ AAuth.Samples.Capabilities.CatalogDemoSession: public string ? ConsentUrl
```

Public owners: `AAuth.Samples.Capabilities.CatalogDemoSession`, `AAuth.Samples.Capabilities`.

### samples/CapabilitySupport/DocumentDemoSession.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [DocumentDemoSession.cs](../../../samples/CapabilitySupport/DocumentDemoSession.cs).

```diff
- AAuth.Samples.Capabilities.DocumentDemoSession: public string ? ConsentUrl { get ; private set ; }
- AAuth.Samples.Capabilities: public sealed class DocumentDemoSession ( string provider , string person , string resource ) : IDisposable
+ AAuth.Samples.Capabilities.DocumentDemoSession: public Interaction ? Consent { get ; private set ; }
+ AAuth.Samples.Capabilities.DocumentDemoSession: public string ? ConsentUrl
+ AAuth.Samples.Capabilities: public sealed class DocumentDemoSession ( IAAuthAgentFactory agents , string provider , string person , string resource ) : IDisposable
```

Public owners: `AAuth.Samples.Capabilities.DocumentDemoSession`, `AAuth.Samples.Capabilities`.

### samples/CapabilitySupport/WalletDemoSession.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [WalletDemoSession.cs](../../../samples/CapabilitySupport/WalletDemoSession.cs).

```diff
- AAuth.Samples.Capabilities.WalletDemoSession: public string ? ConsentUrl { get ; private set ; }
- AAuth.Samples.Capabilities.WalletFlow: DirectAs
- AAuth.Samples.Capabilities: public sealed class WalletDemoSession ( string provider , string person , string wallet , string concierge ) : IDisposable
+ AAuth.Samples.Capabilities.WalletDemoSession: public Interaction ? Consent { get ; private set ; }
+ AAuth.Samples.Capabilities.WalletDemoSession: public string ? ConsentUrl
+ AAuth.Samples.Capabilities.WalletFlow: AsGrantChaining
+ AAuth.Samples.Capabilities: public sealed class WalletDemoSession ( IAAuthAgentFactory agents , string provider , string person , string wallet , string concierge ) : IDisposable
```

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
- AAuth.Samples.Capabilities.WalletScenarioCode: public const string DirectAs = """
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
+ AAuth.Samples.Capabilities.WalletScenarioCode: public const string AsGrantChaining = """
        public static async Task<string> ReadWalletAsync(IAAuthSigner key, string issuer, string agent,
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
+ AAuth.Samples.Capabilities.WalletScenarioCode: public const string Clarification = """
        public static Task<string> ClarifyAsync(AAuthAgent agent,
            string personServer, string resourceToken, string personToken,
            Func<Interaction, CancellationToken, Task> consent,
            Func<ClarificationRequirement, CancellationToken, Task<ClarificationResponse>> answer,
            CancellationToken cancellationToken)
            // The agent's TokenExchange client is signed as the agent, never with a carrier token.
            => agent.TokenExchange.ExchangeAsync(personServer, resourceToken,
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
        public static Task<RevocationCascadeResult> RevokePersonTokenAsync(IServiceProvider services,
            string personTokenId, CancellationToken cancellationToken)
        {
            // The PS revokes its person token at its resource and at every AS it presented it to;
            // each AS cascades to the auth tokens it issued against it.
            var revocation = services.GetRequiredKeyedService<IAAuthRevocationService>(AAuthPersonServerBuilder.DefaultName);
            return revocation.RevokeTokenAsync(personTokenId, cancellationToken);
        }

        public static Task<string> RecoverAsync(AAuthAgent agent,
            string personServer, string freshResourceToken, string personToken,
            Func<Interaction, CancellationToken, Task> consent, CancellationToken cancellationToken)
            => agent.TokenExchange.ExchangeAsync(personServer, freshResourceToken,
                new TokenExchangeRequest { PresentedToken = personToken, OnInteractionRequired = consent }, cancellationToken);
        """ ;
```

Public owners: `AAuth.Samples.Capabilities.WalletScenarioCode`, `AAuth.Samples.Capabilities`.

### samples/Concierge/ChainCaptureHandler.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [ChainCaptureHandler.cs](../../../samples/Concierge/ChainCaptureHandler.cs).

```diff
- Concierge.ChainCaptureHandler: public List < ChainExchange > Exchanges { get ; } = [ ]
+ Concierge.ChainCaptureHandler: public static List < ChainExchange > Begin ( )
```

Public owners: `Concierge.ChainCaptureHandler`, `Concierge`.

### samples/Concierge/Program.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [Program.cs](../../../samples/Concierge/Program.cs).

Public signatures unchanged (1); behavior reviewed under sample-runtime.

Public owners: `Concierge`.

### samples/ConsentSupport/PersonServerConsent.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [PersonServerConsent.cs](../../../samples/ConsentSupport/PersonServerConsent.cs).

```diff
+ ConsentSupport.PersonServerConsent: public static Interaction FromUserUrl ( string userUrl , string code )
+ ConsentSupport.PersonServerConsent: public static bool IsPersonServerHosted ( string ? personServer , Interaction interaction )
+ ConsentSupport.PersonServerConsent: public static string DashboardUrl ( string personServer , string ? code = null )
+ ConsentSupport: public static class PersonServerConsent
```

Public owners: `ConsentSupport.PersonServerConsent`, `ConsentSupport`.

### samples/EventSupport/BookingsEvents.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [BookingsEvents.cs](../../../samples/EventSupport/BookingsEvents.cs).

```diff
- AAuth.Samples.Events: public sealed class BookingsEvents ( string issuer , IAAuthKey key , string keyId , EventsProtocol protocol , SqliteEventStore store )
+ AAuth.Samples.Events: public sealed class BookingsEvents ( string issuer , IAAuthSigner key , string keyId , EventsProtocol protocol , SqliteEventStore store )
```

Public owners: `AAuth.Samples.Events.BookingsEvents`, `AAuth.Samples.Events`.

### samples/EventSupport/EventDemoCode.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [EventDemoCode.cs](../../../samples/EventSupport/EventDemoCode.cs).

```diff
- AAuth.Samples.Events.EventDemoCode: public const string Delivery = """
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
- AAuth.Samples.Events.EventDemoCode: public const string Example = """
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
- AAuth.Samples.Events.EventDemoCode: public const string Receipt = """
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
- AAuth.Samples.Events.EventDemoCode: public const string Registration = """
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
- AAuth.Samples.Events.EventDemoCode: public const string SubscribeToken = """
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
- AAuth.Samples.Events.EventDemoCode: public const string SubscriptionUrl = """
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
+ AAuth.Samples.Events.EventDemoCode: public const string Delivery = """
        public static async Task TriggerSampleEventAsync(EventsProtocol protocol, string resource,
            string eid, IAAuthSigner agentKey, string agentToken, string? account, CancellationToken cancellationToken)
        {
            using var response = await protocol.SendAsync(HttpMethod.Post,
                new Uri(resource + "/local/events/" + eid + "/notify"
                    + (account is null ? "" : "?account=" + Uri.EscapeDataString(account))), agentKey, agentToken,
                selfIssued: false, cancellationToken: cancellationToken);
            response.EnsureSuccessStatusCode();
        }

        public static async Task DeliverResourceEventAsync(EventsProtocol protocol, string resource,
            string provider, string agent, string eid, IAAuthSigner resourceKey, string resourceKid,
            byte[] payload, CancellationToken cancellationToken)
        {
            var token = await new EventTokenBuilder
            {
                Issuer = resource, Audience = agent, Eid = eid, Key = resourceKey,
                KeyId = resourceKid, Verifier = protocol.TokenVerifier,
            }.BuildAsync(cancellationToken);
            var endpoint = await protocol.ResolveEventEndpointAsync(provider, cancellationToken);
            using var response = await protocol.SendAsync(HttpMethod.Post, endpoint,
                resourceKey, token, selfIssued: true, body: payload, cancellationToken: cancellationToken);
            response.EnsureSuccessStatusCode();
        }
        """ ;
+ AAuth.Samples.Events.EventDemoCode: public const string Example = """
        builder.Services.AddAAuthEvents(options => options.EgressPolicy = egressPolicy);
        // AP endpoint requires a durable transactional quota/outbox store.
        builder.Services.AddSingleton(providerStore);
        var app = builder.Build();
        var protocol = app.Services.GetRequiredService<EventsProtocol>();

        // Public registration uses an AsyncAPI channel URL; protected
        // registration uses the ticket from an authorized Bookings response.
        using var registration = await protocol.SendAsync(HttpMethod.Post,
            subscriptionUrl, agentKey, subscribeToken, selfIssued: false,
            body: subscriptionParameters);

        // Resource signs both JWT and HTTP with the same discoverable key.
        var eventToken = await new EventTokenBuilder
        {
            Issuer = resource, Audience = agent, Eid = subscription.Eid,
            Key = resourceKey, KeyId = resourceKid,
            Verifier = protocol.TokenVerifier
        }.BuildAsync();
        var endpoint = await protocol.ResolveEventEndpointAsync(subscription.Provider);
        using var delivery = await protocol.SendAsync(HttpMethod.Post,
            endpoint, resourceKey, eventToken, selfIssued: true, body: payloadBytes);

        // The AP event endpoint resolves the protocol and store from DI.
        app.MapAAuthEventEndpoint("/events");

        // Agent verifies the issuer JWT and context before persisting receipt.
        var receiver = new EventReceiver(protocol, agentStore, agent);
        var firstReceipt = await receiver.ReceiveAsync(eventToken, payloadBytes);
        """ ;
+ AAuth.Samples.Events.EventDemoCode: public const string Receipt = """
        public static async Task VerifyInboxAsync(EventsProtocol protocol, IAgentEventStore store,
            string provider, string agent, string eid, IAAuthSigner key, string agentToken,
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
            Uri subscriptionUrl, IAAuthSigner key, string subscribeToken, CancellationToken cancellationToken)
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
            IAgentEventStore store, IAAuthSigner key, string agentToken, string agent,
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
        public static async Task<(string Agent, string AgentToken, string SubscriptionUrl)> ObtainSubscriptionUrlAsync(
            IAAuthAgentFactory agents, AAuthKey key,
            string provider, string person, string resource, string account, bool protectedChannel,
            string publicSubscriptionUrl, AAuthEgressPolicy policy,
            Func<Interaction, CancellationToken, Task> showConsent, CancellationToken cancellationToken)
        {
            var enrolled = await AAuthClientBuilder.Bootstrap(provider + "/enrol")
                .WithKey(key).WithKeyStore(new InMemoryKeyStore()).WithPersonServer(person)
                .WithEgressPolicy(policy).EnrolAsync(cancellationToken);
            if (!protectedChannel) return (enrolled.AgentId!, enrolled.AgentToken!, publicSubscriptionUrl);
            // One agent for the enrolled identity, created once and reused for the session.
            using var agent = agents.Create("event-agent", key, builder => builder.UseJwt(enrolled.AgentToken!)
                .WithEgressPolicy(policy).WithChallengeHandling(person,
                    options => options.OnInteractionRequired = showConsent));
            using var request = new HttpRequestMessage(HttpMethod.Get,
                resource + "/search_availability?account=" + Uri.EscapeDataString(account));
            request.Options.Set(AAuthRequestOptions.Account, account);
            using var response = await agent.HttpClient.SendAsync(request, cancellationToken);
            response.EnsureSuccessStatusCode();
            var result = await response.Content.ReadFromJsonAsync<JsonObject>(cancellationToken);
            return (enrolled.AgentId!, enrolled.AgentToken!, result!["notifications"]!["subscribe_url"]!.GetValue<string>());
        }
        """ ;
```

Public owners: `AAuth.Samples.Events.EventDemoCode`, `AAuth.Samples.Events`.

### samples/EventSupport/EventDemoSession.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [EventDemoSession.cs](../../../samples/EventSupport/EventDemoSession.cs).

```diff
- AAuth.Samples.Events.EventDemoSession: public EventDemoSession ( string directory , string provider = "http://localhost:5301" , string resource = "http://localhost:5005" , string person = "http://localhost:5100" , HttpClient ? http = null )
- AAuth.Samples.Events.EventDemoSession: public string ? ConsentUrl { get ; private set ; }
+ AAuth.Samples.Events.EventDemoSession: public AAuth . Headers . Interaction ? Consent { get ; private set ; }
+ AAuth.Samples.Events.EventDemoSession: public EventDemoSession ( IAAuthAgentFactory agents , string directory , string provider = "http://localhost:5301" , string resource = "http://localhost:5005" , string person = "http://localhost:5100" , HttpClient ? http = null )
+ AAuth.Samples.Events.EventDemoSession: public string ? ConsentUrl
```

Public owners: `AAuth.Samples.Events.EventDemoSession`, `AAuth.Samples.Events`.

### samples/EventSupport/LocalEventProvider.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [LocalEventProvider.cs](../../../samples/EventSupport/LocalEventProvider.cs).

```diff
- AAuth.Samples.Events.LocalEventProvider: public static void MapLocalEventProvider ( this IEndpointRouteBuilder routes , string issuer , IAAuthKey key , string keyId , EventsProtocol protocol , IAgentProviderEventStore store )
+ AAuth.Samples.Events.LocalEventProvider: public static void MapLocalEventProvider ( this IEndpointRouteBuilder routes , string issuer , IAAuthSigner key , string keyId )
```

Public owners: `AAuth.Samples.Events.LocalEventProvider`, `AAuth.Samples.Events`.

### samples/EventSupport/SampleAgentEnrollment.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [SampleAgentEnrollment.cs](../../../samples/EventSupport/SampleAgentEnrollment.cs).

```diff
- AAuth.Samples.Events.SampleAgentEnrollment: public static void MapSampleAgentEnrollment ( this IEndpointRouteBuilder routes , string issuer , IAAuthKey key , string keyId , AAuthEgressPolicy policy , SampleAgentRegistry registry )
+ AAuth.Samples.Events.SampleAgentEnrollment: public static void MapSampleAgentEnrollment ( this IEndpointRouteBuilder routes , string issuer , IAAuthSigner key , string keyId , AAuthEgressPolicy policy , SampleAgentRegistry registry )
```

Public owners: `AAuth.Samples.Events.SampleAgentEnrollment`, `AAuth.Samples.Events`.

### samples/EventSupport/SqliteEventStore.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [SqliteEventStore.cs](../../../samples/EventSupport/SqliteEventStore.cs).

```diff
- AAuth.Samples.Events.SqliteEventStore: public EventEnvelope PrepareDelivery ( string provider , string eid , Func < EventEnvelope > create )
+ AAuth.Samples.Events.SqliteEventStore: public async Task < EventEnvelope > PrepareDeliveryAsync ( string provider , string eid , Func < Task < EventEnvelope > > create )
```

Public owners: `AAuth.Samples.Events.SqliteEventStore`, `AAuth.Samples.Events`.

### samples/FederatedWorkerScenario.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [FederatedWorkerScenario.cs](../../../samples/FederatedWorkerScenario.cs).

```diff
- AAuth.Samples.FederatedWorkerScenario: public void IssueParent ( )
- AAuth.Samples.FederatedWorkerScenario: public void IssueWorker ( )
- AAuth.Samples: public sealed class FederatedWorkerScenario ( IAAuthKey providerKey , string providerKid , string provider , string personServer , string wallet ) : IDisposable
+ AAuth.Samples.FederatedWorkerScenario: public async Task IssueParentAsync ( CancellationToken ct = default )
+ AAuth.Samples.FederatedWorkerScenario: public async Task IssueWorkerAsync ( CancellationToken ct = default )
+ AAuth.Samples.FederatedWorkerScenario: public async Task ObtainWorkerPersonTokenAsync ( CancellationToken ct = default )
+ AAuth.Samples.FederatedWorkerScenario: public async Task PresentWorkerPersonTokenAsync ( CancellationToken ct = default )
+ AAuth.Samples.FederatedWorkerScenario: public string ? WorkerPersonToken { get ; private set ; }
+ AAuth.Samples: public sealed class FederatedWorkerScenario ( IAAuthSigner providerKey , string providerKid , string provider , string personServer , string wallet ) : IDisposable
```

Public owners: `AAuth.Samples.FederatedWorkerScenario`, `AAuth.Samples`.

### samples/GuidedTour/Program.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [Program.cs](../../../samples/GuidedTour/Program.cs).

Public signatures unchanged (2); behavior reviewed under sample-runtime.

Public owners: `GuidedTour`.

### samples/GuidedTour/TourOptions.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [TourOptions.cs](../../../samples/GuidedTour/TourOptions.cs).

```diff
+ GuidedTour.TourMode: Catalog
+ GuidedTour.TourMode: Documents
+ GuidedTour.TourMode: Events
+ GuidedTour.TourMode: WalletProtocol
+ GuidedTour.TourOptions: public string CatalogUrl { get ; set ; } = "http://localhost:5006"
+ GuidedTour.TourOptions: public string DocumentsUrl { get ; set ; } = "http://localhost:5007"
```

Public owners: `GuidedTour.SigningMode`, `GuidedTour.TourMode`, `GuidedTour.TourOptions`, `GuidedTour`.

### samples/GuidedTour/TourSession.Capabilities.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [TourSession.Capabilities.cs](../../../samples/GuidedTour/TourSession.Capabilities.cs).

```diff
+ GuidedTour.TourSession: public WalletFlow WalletScenario { get ; set ; }
+ GuidedTour.TourSession: public bool EventsProtected { get ; set ; }
+ GuidedTour.TourSession: public bool IsCapabilityMode
+ GuidedTour.TourSession: public bool IsCatalogMode
+ GuidedTour.TourSession: public bool IsDocumentsMode
+ GuidedTour.TourSession: public bool IsEventsMode
+ GuidedTour.TourSession: public bool IsWalletProtocolMode
+ GuidedTour.TourSession: public string ? EventsPayload { get ; private set ; }
+ GuidedTour.TourSession: public string CatalogService { get ; set ; }
+ GuidedTour.TourSession: public string EventsAccount { get ; set ; }
+ GuidedTour: public sealed partial class TourSession
```

Public owners: `GuidedTour.TourSession`, `GuidedTour`.

### samples/GuidedTour/TourSession.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [TourSession.cs](../../../samples/GuidedTour/TourSession.cs).

```diff
- GuidedTour.TourSession: public string ? WorkerConsentUrl { get ; private set ; }
- GuidedTour: public sealed class TourSession : IAsyncDisposable
+ GuidedTour.TourSession: public Interaction ? CurrentInteraction
+ GuidedTour.TourSession: public Interaction ? WorkerConsent { get ; private set ; }
+ GuidedTour.TourSession: public bool IsPersonServerConsent
+ GuidedTour.TourSession: public string ? PersonServer
+ GuidedTour.TourSession: public string ? WorkerConsentUrl
+ GuidedTour: public sealed partial class TourSession : IAsyncDisposable
```

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

### samples/MockAgentProvider/Program.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [Program.cs](../../../samples/MockAgentProvider/Program.cs).

Public signatures unchanged (1); behavior reviewed under sample-runtime.

Public owners: `MockAgentProvider`.

### samples/MockPersonServer/ConsentBridgePersonPendingStore.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [ConsentBridgePersonPendingStore.cs](../../../samples/MockPersonServer/ConsentBridgePersonPendingStore.cs).

```diff
- MockPersonServer.ConsentBridgePersonPendingStore: public ConsentBridgePersonPendingStore ( ConsentStore consent , IReadOnlyList < string > demoRoles , IReadOnlyList < string > demoGroups )
- MockPersonServer.ConsentBridgePersonPendingStore: public PersonPendingEntry Add ( string resourceUrl , string scope , string agentId , IAAuthKey ? agentConfirmationKey , DateTimeOffset agentTokenExpiresAt , JsonObject ? upstreamAct = null , MissionClaim ? mission = null , DateTimeOffset ? authorizationExpiresAt = null )
+ MockPersonServer.ConsentBridgePersonPendingStore: public ConsentBridgePersonPendingStore ( ConsentStore consent , ConsentRegistry registry , IReadOnlyList < string > demoRoles , IReadOnlyList < string > demoGroups )
+ MockPersonServer.ConsentBridgePersonPendingStore: public PersonPendingEntry Add ( string resourceUrl , string scope , string agentId , IAAuthKey ? agentConfirmationKey , DateTimeOffset agentTokenExpiresAt , string ? missionS256 = null , DateTimeOffset ? authorizationExpiresAt = null )
```

Public owners: `MockPersonServer.ConsentBridgePersonPendingStore`, `MockPersonServer`.

### samples/MockPersonServer/ConsentDashboard.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [ConsentDashboard.cs](../../../samples/MockPersonServer/ConsentDashboard.cs).

```diff
+ MockPersonServer.ConsentDashboard: public static void MapConsentDashboard ( this WebApplication app )
+ MockPersonServer.ConsentDashboardSessions.Session: public DateTimeOffset ExpiresAt { get ; } = DateTimeOffset . UtcNow . AddHours ( 8 )
+ MockPersonServer.ConsentDashboardSessions.Session: public string ? Person { get ; set ; }
+ MockPersonServer.ConsentDashboardSessions.Session: public string Csrf { get ; } = Secret ( )
+ MockPersonServer.ConsentDashboardSessions: public IResult ? Refusal ( HttpContext context )
+ MockPersonServer.ConsentDashboardSessions: public Session Current ( HttpContext context , bool create )
+ MockPersonServer.ConsentDashboardSessions: public const string CookieName = "AAuth.Person.Dashboard" ;
+ MockPersonServer.ConsentDashboardSessions: public const string CsrfHeader = "X-CSRF-Token" ;
+ MockPersonServer.ConsentDashboardSessions: public sealed class Session
+ MockPersonServer.ConsentDashboardSessions: public static IResult Problem ( string error , string ? detail , int status )
+ MockPersonServer.ConsentDashboardSessions: public static bool CsrfMatches ( Session session , string ? supplied )
+ MockPersonServer.ConsentDashboardSessions: public string ? DemoIdentity { get ; } = configuration . GetValue < bool > ( "AAuth:EnableIsolatedDemoConsent" ) ? "isolated-person-demo" : null
+ MockPersonServer: public sealed class ConsentDashboardSessions ( IConfiguration configuration )
+ MockPersonServer: public static class ConsentDashboard
```

Public owners: `MockPersonServer.ConsentDashboardSessions.Session`, `MockPersonServer.ConsentDashboardSessions`, `MockPersonServer.ConsentDashboard`, `MockPersonServer`.

### samples/MockPersonServer/ConsentRegistry.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [ConsentRegistry.cs](../../../samples/MockPersonServer/ConsentRegistry.cs).

```diff
+ MockPersonServer.ConsentDecider: Admin
+ MockPersonServer.ConsentDecider: Dashboard
+ MockPersonServer.ConsentDecider: Link
+ MockPersonServer.ConsentDecider: Policy
+ MockPersonServer.ConsentDecider: Script
+ MockPersonServer.ConsentKind: AccessServerInteraction
+ MockPersonServer.ConsentKind: FederatedConsent
+ MockPersonServer.ConsentKind: MissionCreation
+ MockPersonServer.ConsentKind: MissionToken
+ MockPersonServer.ConsentKind: Permission
+ MockPersonServer.ConsentKind: PersonToken
+ MockPersonServer.ConsentKind: Token
+ MockPersonServer.ConsentRecord: public BrowserInteraction Browser
+ MockPersonServer.ConsentRecord: public ConsentDecider ? DecidedBy { get ; private set ; }
+ MockPersonServer.ConsentRecord: public ConsentDecider ? Decider
+ MockPersonServer.ConsentRecord: public ConsentKind Kind
+ MockPersonServer.ConsentRecord: public ConsentStatus Status { get ; }
+ MockPersonServer.ConsentRecord: public DateTimeOffset ? DecidedAt { get ; private set ; }
+ MockPersonServer.ConsentRecord: public DateTimeOffset CreatedAt { get ; }
+ MockPersonServer.ConsentRecord: public DateTimeOffset ExpiresAt
+ MockPersonServer.ConsentRecord: public DeferredState Lifecycle
+ MockPersonServer.ConsentRecord: public IReadOnlyList < string > ProposedTools
+ MockPersonServer.ConsentRecord: public MissionPendingEntry ? MissionEntry { get ; }
+ MockPersonServer.ConsentRecord: public PersonPendingEntry ? PersonEntry { get ; }
+ MockPersonServer.ConsentRecord: public bool IsDecidable
+ MockPersonServer.ConsentRecord: public bool IsListed
+ MockPersonServer.ConsentRecord: public string ? Account
+ MockPersonServer.ConsentRecord: public string ? Action
+ MockPersonServer.ConsentRecord: public string ? ExternalInteractionUrl
+ MockPersonServer.ConsentRecord: public string ? MissionDescription
+ MockPersonServer.ConsentRecord: public string ? MissionS256
+ MockPersonServer.ConsentRecord: public string ? Resource
+ MockPersonServer.ConsentRecord: public string ? Scope
+ MockPersonServer.ConsentRecord: public string AgentId
+ MockPersonServer.ConsentRecord: public string Id
+ MockPersonServer.ConsentRegistry: public ConsentRecord ? Find ( string id )
+ MockPersonServer.ConsentRegistry: public ConsentRecord ? FindByCode ( string code )
+ MockPersonServer.ConsentRegistry: public ConsentRecord ? FindPendingByCode ( string code )
+ MockPersonServer.ConsentRegistry: public IReadOnlyList < ConsentRecord > Snapshot ( )
+ MockPersonServer.ConsentRegistry: public const int Capacity = 500 ;
+ MockPersonServer.ConsentRegistry: public void Clear ( )
+ MockPersonServer.ConsentRegistry: public void MarkDecided ( string id , ConsentDecider by )
+ MockPersonServer.ConsentRegistry: public void Register ( MissionPendingEntry entry )
+ MockPersonServer.ConsentRegistry: public void Register ( PersonPendingEntry entry )
+ MockPersonServer.ConsentStatus: Approved
+ MockPersonServer.ConsentStatus: Delivered
+ MockPersonServer.ConsentStatus: Denied
+ MockPersonServer.ConsentStatus: Expired
+ MockPersonServer.ConsentStatus: Pending
+ MockPersonServer.ConsentStatus: Withdrawn
+ MockPersonServer: public enum ConsentDecider
+ MockPersonServer: public enum ConsentKind
+ MockPersonServer: public enum ConsentStatus
+ MockPersonServer: public sealed class ConsentRecord
+ MockPersonServer: public sealed class ConsentRegistry ( MissionPolicyStore policy )
```

Public owners: `MockPersonServer.ConsentDecider`, `MockPersonServer.ConsentKind`, `MockPersonServer.ConsentRecord`, `MockPersonServer.ConsentRegistry`, `MockPersonServer.ConsentStatus`, `MockPersonServer`.

### samples/MockPersonServer/MissionGovernance.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [MissionGovernance.cs](../../../samples/MockPersonServer/MissionGovernance.cs).

```diff
- MockPersonServer.MissionPendingEntry: public DateTimeOffset ExpiresAt { get ; } = DateTimeOffset . UtcNow . AddMinutes ( 10 )
- MockPersonServer.MissionPendingEntry: public JsonObject ? UpstreamAct { get ; init ; }
- MockPersonServer.MissionPendingEntry: public MissionClaim MissionClaim
- MockPersonServer.MissionPendingEntry: public required string Approver { get ; init ; }
- MockPersonServer: public sealed class MissionPendingStore
+ MockPersonServer.MissionPendingEntry: public DateTimeOffset CreatedAt { get ; } = DateTimeOffset . UtcNow
+ MockPersonServer.MissionPendingEntry: public DateTimeOffset ExpiresAt
+ MockPersonServer.MissionPendingEntry: public required string PersonServer { get ; init ; }
+ MockPersonServer: public sealed class MissionPendingStore ( ConsentRegistry registry )
```

Public owners: `MockPersonServer.MissionConsentScript`, `MockPersonServer.MissionPendingEntry`, `MockPersonServer.MissionPendingKind`, `MockPersonServer.MissionPendingState`, `MockPersonServer.MissionPendingStore`, `MockPersonServer.MissionPolicyStore`, `MockPersonServer.SampleAuditSink`, `MockPersonServer.SampleInteractionRelay`, `MockPersonServer.SamplePermissionDecider`, `MockPersonServer`.

### samples/MockPersonServer/PersonConsentDecisions.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [PersonConsentDecisions.cs](../../../samples/MockPersonServer/PersonConsentDecisions.cs).

```diff
+ MockPersonServer.ConsentOutcome: AlreadyDecided
+ MockPersonServer.ConsentOutcome: Applied
+ MockPersonServer.ConsentOutcome: Expired
+ MockPersonServer.ConsentOutcome: NotDecidable
+ MockPersonServer.ConsentOutcome: Refused
+ MockPersonServer.ConsentOutcome: Unknown
+ MockPersonServer.PersonConsentDecisions: public ConsentOutcome ApplyHeld ( MissionPendingEntry entry , bool approve , ConsentDecider by )
+ MockPersonServer.PersonConsentDecisions: public async Task < ConsentOutcome > ApplyHeldAsync ( PersonPendingEntry entry , bool approve , ConsentDecider by , CancellationToken cancellationToken )
+ MockPersonServer.PersonConsentDecisions: public async Task < ConsentOutcome > DecideAsync ( string id , bool approve , ConsentDecider by , CancellationToken cancellationToken )
+ MockPersonServer: public enum ConsentOutcome
+ MockPersonServer: public sealed class PersonConsentDecisions ( ConsentStore consent , [ FromKeyedServices ( AAuthPersonServerBuilder . DefaultName ) ] IIdentityClaimsAsserter asserter , ConsentRegistry registry )
```

Public owners: `MockPersonServer.ConsentOutcome`, `MockPersonServer.PersonConsentDecisions`, `MockPersonServer`.

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

### samples/SampleApp/EnrollmentService.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [EnrollmentService.cs](../../../samples/SampleApp/EnrollmentService.cs).

```diff
- SampleApp.EnrollmentService: public EnrollmentService ( IConfiguration config )
- SampleApp.EnrollmentService: public IAAuthKey Key
- SampleApp: public sealed class EnrollmentService
+ SampleApp.EnrollmentService: public AAuthAgent Agent
+ SampleApp.EnrollmentService: public EnrollmentService ( IConfiguration config , SampleAgents agents , IAAuthAgentFactory factory )
+ SampleApp.EnrollmentService: public IAAuthSigner Key
+ SampleApp.EnrollmentService: public void Dispose ( )
+ SampleApp.EnrollmentService: public void StartOver ( string resource )
+ SampleApp: public sealed class EnrollmentService : IDisposable
```

Public owners: `SampleApp.EnrollmentService`, `SampleApp`.

### samples/SampleApp/SampleAgents.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [SampleAgents.cs](../../../samples/SampleApp/SampleAgents.cs).

```diff
+ SampleApp.SampleAgents: public DeferredPollerOptions PollerOptions { get ; }
+ SampleApp.SampleAgents: public HttpClient AriaClient
+ SampleApp.SampleAgents: public const string Aria = "aria" ;
+ SampleApp.SampleAgents: public string PersonServer
+ SampleApp.SampleAgents: public void StartOver ( )
+ SampleApp: public sealed class SampleAgents ( IHttpClientFactory clients , IOptionsMonitor < AAuthAgentOptions > options , IServiceProvider services )
```

Public owners: `SampleApp.SampleAgents`, `SampleApp`.

### src/AAuth.Events/EventReceiver.cs

Concept/decision: [events](#events). Source: [EventReceiver.cs](../../../src/AAuth.Events/EventReceiver.cs).

Public signatures unchanged (2); behavior reviewed under events.

Public owners: `AAuth.Events.EventReceiver`, `AAuth.Events`.

### src/AAuth.Events/EventStores.cs

Concept/decision: [events](#events). Source: [EventStores.cs](../../../src/AAuth.Events/EventStores.cs).

```diff
- AAuth.Events: public sealed record EventEnvelope ( string Token , string Eid , string Issuer , string Agent , DateTimeOffset ExpiresAt , byte [  ] Body )
- AAuth.Events: public sealed record ResourceSubscription ( string Eid , string Provider , string Agent , string Operation , string ? Account , string State , DateTimeOffset ExpiresAt )
- AAuth.Events: public sealed record SubscriptionTicket ( string Ticket , string Agent , string Operation , string ? Account , string State , DateTimeOffset ExpiresAt )
+ AAuth.Events: public sealed record EventEnvelope ( string Token , string Eid , string Jti , string Issuer , string Agent , DateTimeOffset ExpiresAt , byte [  ] Body )
+ AAuth.Events: public sealed record ResourceSubscription ( string Eid , string Provider , string Agent , string Operation , string ? Account , string State , DateTimeOffset ExpiresAt , string ? KeyThumbprint = null )
+ AAuth.Events: public sealed record SubscriptionTicket ( string Ticket , string KeyThumbprint , string Operation , string ? Account , string State , DateTimeOffset ExpiresAt )
```

Public owners: `AAuth.Events.IAgentEventStore`, `AAuth.Events.IAgentProviderEventStore`, `AAuth.Events.IResourceEventStore`, `AAuth.Events`.

### src/AAuth.Events/EventTokenBuilders.cs

Concept/decision: [events](#events). Source: [EventTokenBuilders.cs](../../../src/AAuth.Events/EventTokenBuilders.cs).

```diff
- AAuth.Events.EventTokenBuilder: public required IAAuthKey Key { get ; init ; }
- AAuth.Events.EventTokenBuilder: public string Build ( )
- AAuth.Events.SubscribeTokenBuilder: public required IAAuthKey Key { get ; init ; }
- AAuth.Events.SubscribeTokenBuilder: public string Build ( )
+ AAuth.Events.EventTokenBuilder: public ValueTask < string > BuildAsync ( CancellationToken cancellationToken = default )
+ AAuth.Events.EventTokenBuilder: public required IAAuthSigner Key { get ; init ; }
+ AAuth.Events.EventTokenBuilder: public string Jti { get ; init ; } = Guid . NewGuid ( ) . ToString ( "N" )
+ AAuth.Events.SubscribeTokenBuilder: public ValueTask < string > BuildAsync ( CancellationToken cancellationToken = default )
+ AAuth.Events.SubscribeTokenBuilder: public required IAAuthSigner Key { get ; init ; }
```

Public owners: `AAuth.Events.EventTokenBuilder`, `AAuth.Events.SubscribeTokenBuilder`, `AAuth.Events`.

### src/AAuth.Events/EventsEndpoints.cs

Concept/decision: [events](#events). Source: [EventsEndpoints.cs](../../../src/AAuth.Events/EventsEndpoints.cs).

```diff
- AAuth.Events.EventsEndpoints: public static IEndpointConventionBuilder MapAAuthEventEndpoint ( this IEndpointRouteBuilder routes , string path , EventsProtocol protocol , IAgentProviderEventStore store )
- AAuth.Events.EventsEndpoints: public static IEndpointConventionBuilder MapAAuthSubscriptionEndpoint ( this IEndpointRouteBuilder routes , string path , string resource , string operation , bool protectedChannel , EventsProtocol protocol , IResourceEventStore store , Func < JsonObject , bool > validateParameters , TimeSpan ? subscriptionLifetime = null )
+ AAuth.Events.AAuthSubscriptionEndpointOptions: public Func < JsonObject , bool > ? ValidateParameters { get ; set ; }
+ AAuth.Events.AAuthSubscriptionEndpointOptions: public TimeSpan ? SubscriptionLifetime { get ; set ; }
+ AAuth.Events.AAuthSubscriptionEndpointOptions: public bool ProtectedChannel { get ; set ; }
+ AAuth.Events.AAuthSubscriptionEndpointOptions: public string ? Resource { get ; set ; }
+ AAuth.Events.AAuthSubscriptionEndpointOptions: public string Operation { get ; set ; } = ""
+ AAuth.Events.EventsEndpoints: public static IEndpointConventionBuilder MapAAuthEventEndpoint ( this IEndpointRouteBuilder routes , string path )
+ AAuth.Events.EventsEndpoints: public static IEndpointConventionBuilder MapAAuthSubscriptionEndpoint ( this IEndpointRouteBuilder routes , string path , Action < AAuthSubscriptionEndpointOptions > configure )
+ AAuth.Events: public sealed class AAuthSubscriptionEndpointOptions
```

Public owners: `AAuth.Events.AAuthSubscriptionEndpointOptions`, `AAuth.Events.EventsEndpoints`, `AAuth.Events`.

### src/AAuth.Events/EventsProtocol.cs

Concept/decision: [events](#events). Source: [EventsProtocol.cs](../../../src/AAuth.Events/EventsProtocol.cs).

```diff
- AAuth.Events.EventsProtocol: public EventsProtocol ( HttpClient http , IEnumerable < ISignatureTokenVerifier > tokenVerifiers , Func < DateTimeOffset > ? clock = null )
- AAuth.Events.EventsProtocol: public async Task < HttpResponseMessage > SendAsync ( HttpMethod method , Uri url , IAAuthKey key , string jwt , bool selfIssued , byte [  ] ? body = null , CancellationToken cancellationToken = default )
+ AAuth.Events.EventsProtocol: public EventsProtocol ( HttpClient http , IEnumerable < ISignatureTokenVerifier > tokenVerifiers , TimeProvider ? timeProvider = null )
+ AAuth.Events.EventsProtocol: public async Task < HttpResponseMessage > SendAsync ( HttpMethod method , Uri url , IAAuthSigner key , string jwt , bool selfIssued , byte [  ] ? body = null , CancellationToken cancellationToken = default )
```

Public owners: `AAuth.Events.EventsProtocol`, `AAuth.Events`.

### src/AAuth.Events/EventsSignatureTokenVerifier.cs

Concept/decision: [events](#events). Source: [EventsSignatureTokenVerifier.cs](../../../src/AAuth.Events/EventsSignatureTokenVerifier.cs).

```diff
- AAuth.Events.EventsServiceExtensions: public static IServiceCollection AddAAuthEvents ( this IServiceCollection services )
+ AAuth.Events.AAuthEventsOptions: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; set ; } = AAuth . Discovery . AAuthEgressPolicy . Production
+ AAuth.Events.AAuthEventsOptions: public AAuth . Discovery . AAuthTransportContract ? TransportContract { get ; set ; }
+ AAuth.Events.AAuthEventsOptions: public HttpMessageHandler ? InnerHandler { get ; set ; }
+ AAuth.Events.AAuthEventsOptions: public TimeProvider TimeProvider { get ; set ; } = TimeProvider . System
+ AAuth.Events.EventsServiceExtensions: public static IServiceCollection AddAAuthEvents ( this IServiceCollection services , Action < AAuthEventsOptions > ? configure = null )
+ AAuth.Events: public sealed class AAuthEventsOptions
```

Public owners: `AAuth.Events.AAuthEventsOptions`, `AAuth.Events.EventsServiceExtensions`, `AAuth.Events.EventsSignatureTokenVerifier`, `AAuth.Events`.

### src/AAuth.Events/EventsTokens.cs

Concept/decision: [events](#events). Source: [EventsTokens.cs](../../../src/AAuth.Events/EventsTokens.cs).

```diff
- AAuth.Events.EventsTokens: public static string Create ( IAAuthKey key , string keyId , JsonObject payload , bool subscribe , TokenVerifier ? verifier = null )
+ AAuth.Events.EventsTokens: public static async ValueTask < string > CreateAsync ( IAAuthSigner key , string keyId , JsonObject payload , bool subscribe , TokenVerifier ? verifier = null , CancellationToken cancellationToken = default )
```

Public owners: `AAuth.Events.EventsTokens`, `AAuth.Events`.

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
- AAuth.R3.R3AccessTokenEndpoint: public static WebApplication MapR3AccessTokenEndpoint ( this WebApplication app , R3AccessTokenEndpointOptions options )
- AAuth.R3.R3AccessTokenEndpointOptions: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; init ; } = AAuth . Discovery . AAuthEgressPolicy . Production
- AAuth.R3.R3AccessTokenEndpointOptions: public AAuth . Discovery . AAuthTransportContract ? FetchTransportContract { get ; init ; }
- AAuth.R3.R3AccessTokenEndpointOptions: public BrowserConsentSessions ? BrowserConsent { get ; init ; }
- AAuth.R3.R3AccessTokenEndpointOptions: public Func < HttpContext , string , string , string , CancellationToken , Task < byte [  ] > > ? FetchAndVerifyAsync { get ; init ; }
- AAuth.R3.R3AccessTokenEndpointOptions: public Func < R3OperationIdentity , bool > ? IsConditionalOperation { get ; init ; }
- AAuth.R3.R3AccessTokenEndpointOptions: public Func < R3OperationIdentity , bool > ? IsOperationAllowed { get ; init ; }
- AAuth.R3.R3AccessTokenEndpointOptions: public Func < R3ProposalDocument , bool > ? IsProposalAllowed { get ; init ; }
- AAuth.R3.R3AccessTokenEndpointOptions: public Func < string , bool > ? IsTrustedPersonServer { get ; init ; }
- AAuth.R3.R3AccessTokenEndpointOptions: public Func < string , string , bool > ? IsScopeAllowed { get ; init ; }
- AAuth.R3.R3AccessTokenEndpointOptions: public HttpMessageHandler ? FetchHttpMessageHandler { get ; init ; }
- AAuth.R3.R3AccessTokenEndpointOptions: public IReadOnlyCollection < string > ? TrustedPersonServers { get ; init ; }
- AAuth.R3.R3AccessTokenEndpointOptions: public R3VocabularySchemas VocabularySchemas { get ; init ; } = R3VocabularySchemas . Standard
- AAuth.R3.R3AccessTokenEndpointOptions: public TimeProvider TimeProvider { get ; init ; } = TimeProvider . System
- AAuth.R3.R3AccessTokenEndpointOptions: public bool RequireProposalConsent { get ; init ; }
- AAuth.R3.R3AccessTokenEndpointOptions: public required IR3AuditSink AuditSink { get ; init ; }
- AAuth.R3.R3AccessTokenEndpointOptions: public required IReadOnlyDictionary < string , IAAuthKey > SigningKeys { get ; init ; }
- AAuth.R3.R3AccessTokenEndpointOptions: public required string Issuer { get ; init ; }
- AAuth.R3.R3AccessTokenEndpointOptions: public string ConsentPath { get ; init ; } = "/interaction/consent"
- AAuth.R3.R3AccessTokenEndpointOptions: public string PendingPath { get ; init ; } = "/pending"
- AAuth.R3.R3AccessTokenEndpointOptions: public string Subject { get ; init ; } = "pairwise-sub"
- AAuth.R3.R3AccessTokenEndpointOptions: public string TokenPath { get ; init ; } = "/token"
+ AAuth.R3.R3AccessTokenEndpoint: public static IServiceCollection AddR3AccessTokenEndpoint ( this IServiceCollection services , Action < R3AccessTokenEndpointOptions > configure )
+ AAuth.R3.R3AccessTokenEndpoint: public static WebApplication MapR3AccessTokenEndpoint ( this WebApplication app )
+ AAuth.R3.R3AccessTokenEndpointOptions: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; set ; } = AAuth . Discovery . AAuthEgressPolicy . Production
+ AAuth.R3.R3AccessTokenEndpointOptions: public AAuth . Discovery . AAuthTransportContract ? FetchTransportContract { get ; set ; }
+ AAuth.R3.R3AccessTokenEndpointOptions: public AAuthSigningKeySet SigningKeys { get ; set ; } = new ( )
+ AAuth.R3.R3AccessTokenEndpointOptions: public AAuthTrustOptions Trust { get ; set ; } = new ( )
+ AAuth.R3.R3AccessTokenEndpointOptions: public BrowserConsentSessions ? BrowserConsent { get ; set ; }
+ AAuth.R3.R3AccessTokenEndpointOptions: public Func < HttpContext , string , string , string , CancellationToken , Task < byte [  ] > > ? FetchAndVerifyAsync { get ; set ; }
+ AAuth.R3.R3AccessTokenEndpointOptions: public Func < R3OperationIdentity , bool > ? IsOperationAllowed { get ; set ; }
+ AAuth.R3.R3AccessTokenEndpointOptions: public Func < R3OperationIdentity , bool > ? IsPerCallOperation { get ; set ; }
+ AAuth.R3.R3AccessTokenEndpointOptions: public Func < R3ProposalDocument , bool > ? IsProposalAllowed { get ; set ; }
+ AAuth.R3.R3AccessTokenEndpointOptions: public Func < string , string , bool > ? IsScopeAllowed { get ; set ; }
+ AAuth.R3.R3AccessTokenEndpointOptions: public HttpMessageHandler ? FetchHttpMessageHandler { get ; set ; }
+ AAuth.R3.R3AccessTokenEndpointOptions: public IR3AuditSink AuditSink { get ; set ; } = null !
+ AAuth.R3.R3AccessTokenEndpointOptions: public R3VocabularySchemas VocabularySchemas { get ; set ; } = R3VocabularySchemas . Standard
+ AAuth.R3.R3AccessTokenEndpointOptions: public TimeProvider TimeProvider { get ; set ; } = TimeProvider . System
+ AAuth.R3.R3AccessTokenEndpointOptions: public bool RequireProposalConsent { get ; set ; }
+ AAuth.R3.R3AccessTokenEndpointOptions: public string ConsentPath { get ; set ; } = "/interaction/consent"
+ AAuth.R3.R3AccessTokenEndpointOptions: public string Issuer { get ; set ; } = ""
+ AAuth.R3.R3AccessTokenEndpointOptions: public string PendingPath { get ; set ; } = "/pending"
+ AAuth.R3.R3AccessTokenEndpointOptions: public string TokenPath { get ; set ; } = "/token"
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
- AAuth.R3.R3Challenge: public Func < DateTimeOffset > Clock { get ; init ; } = ( ) => DateTimeOffset . UtcNow
- AAuth.R3.R3Challenge: public IResult Challenge ( HttpContext context , string agent , string agentJkt , string r3Uri , string r3S256 , string ? scope = null , string ? account = null )
- AAuth.R3.R3Challenge: public required IAAuthKey Key { get ; init ; }
- AAuth.R3.R3Challenge: public string BuildResourceToken ( TokenVerifier . VerifiedToken verifiedAuthToken , string r3Uri , string r3S256 , string ? scope = null )
- AAuth.R3.R3Challenge: public string BuildResourceToken ( string agent , string agentJkt , string r3Uri , string r3S256 , string ? scope = null , string ? account = null )
+ AAuth.R3.R3Challenge: public IR3DocumentEntitlements ? Entitlements { get ; init ; }
+ AAuth.R3.R3Challenge: public TimeProvider TimeProvider { get ; init ; } = TimeProvider . System
+ AAuth.R3.R3Challenge: public ValueTask < string > BuildResourceTokenAsync ( TokenVerifier . VerifiedToken presented , string agentJkt , string r3Uri , string r3S256 , string ? scope = null , string ? account = null , CancellationToken cancellationToken = default )
+ AAuth.R3.R3Challenge: public ValueTask < string > BuildResourceTokenAsync ( TokenVerifier . VerifiedToken verifiedAuthToken , string r3Uri , string r3S256 , string ? scope = null , CancellationToken cancellationToken = default )
+ AAuth.R3.R3Challenge: public async Task < IResult > ChallengeAsync ( HttpContext context , string r3Uri , string r3S256 , string ? scope = null , string ? account = null )
+ AAuth.R3.R3Challenge: public required IAAuthSigner Key { get ; init ; }
```

Public owners: `AAuth.R3.R3Challenge`, `AAuth.R3`.

### src/AAuth.R3/R3ClaimReader.cs

Concept/decision: [r3](#r3). Source: [R3ClaimReader.cs](../../../src/AAuth.R3/R3ClaimReader.cs).

```diff
- AAuth.R3.R3ClaimReader: public sealed record AuthTokenClaims ( string Uri , string S256 , R3Grant Granted , R3Grant ? Conditional )
+ AAuth.R3.R3ClaimReader: public sealed record AuthTokenClaims ( string Uri , string S256 , R3Grant Granted , R3Grant ? PerCall )
```

Public owners: `AAuth.R3.R3ClaimReader.AuthTokenClaims`, `AAuth.R3.R3ClaimReader.ResourceDocumentClaims`, `AAuth.R3.R3ClaimReader`, `AAuth.R3`.

### src/AAuth.R3/R3DocumentEndpoint.cs

Concept/decision: [r3](#r3). Source: [R3DocumentEndpoint.cs](../../../src/AAuth.R3/R3DocumentEndpoint.cs).

```diff
- AAuth.R3.R3DocumentEndpoint: public static IEndpointRouteBuilder MapR3Document ( this IEndpointRouteBuilder endpoints , string pattern , Func < HttpContext , byte [  ] ? > getBytes , R3DocumentReaderPolicy readerPolicy )
+ AAuth.R3.R3DocumentEndpoint: public static IEndpointRouteBuilder MapR3Document ( this IEndpointRouteBuilder endpoints , string pattern , Func < HttpContext , byte [  ] ? > getBytes )
+ AAuth.R3.R3DocumentEndpoint: public static IServiceCollection AddAAuthR3Documents ( this IServiceCollection services , Func < IServiceProvider , R3DocumentReaderPolicy > readerPolicy )
```

Public owners: `AAuth.R3.R3DocumentEndpoint`, `AAuth.R3.R3FetchVerificationException`, `AAuth.R3.R3UntrustedJwksUriException`, `AAuth.R3`.

### src/AAuth.R3/R3DocumentEntitlements.cs

Concept/decision: [r3](#r3). Source: [R3DocumentEntitlements.cs](../../../src/AAuth.R3/R3DocumentEntitlements.cs).

```diff
+ AAuth.R3.IR3DocumentEntitlements: ValueTask < bool > IsEntitledAsync ( string s256 , string reader , CancellationToken cancellationToken = default )
+ AAuth.R3.IR3DocumentEntitlements: ValueTask EntitleAsync ( string s256 , string reader , CancellationToken cancellationToken = default )
+ AAuth.R3.InMemoryR3DocumentEntitlements: public ValueTask < bool > IsEntitledAsync ( string s256 , string reader , CancellationToken cancellationToken = default )
+ AAuth.R3.InMemoryR3DocumentEntitlements: public ValueTask EntitleAsync ( string s256 , string reader , CancellationToken cancellationToken = default )
+ AAuth.R3: public interface IR3DocumentEntitlements
+ AAuth.R3: public sealed class InMemoryR3DocumentEntitlements : IR3DocumentEntitlements
```

Public owners: `AAuth.R3.IR3DocumentEntitlements`, `AAuth.R3.InMemoryR3DocumentEntitlements`, `AAuth.R3`.

### src/AAuth.R3/R3DocumentReaderPolicy.cs

Concept/decision: [r3](#r3). Source: [R3DocumentReaderPolicy.cs](../../../src/AAuth.R3/R3DocumentReaderPolicy.cs).

```diff
+ AAuth.R3.R3DocumentReaderPolicy: public Func < Microsoft . AspNetCore . Http . HttpContext , string , bool > ? IsEntitledPersonServer { get ; init ; }
```

Public owners: `AAuth.R3.R3DocumentReaderPolicy`, `AAuth.R3`.

### src/AAuth.R3/R3Enforcement.cs

Concept/decision: [r3](#r3). Source: [R3Enforcement.cs](../../../src/AAuth.R3/R3Enforcement.cs).

```diff
- AAuth.R3.R3EnforcementDecision: public IResult ToResult ( HttpContext context , R3Challenge challenge , TokenVerifier . VerifiedToken verifiedAuthToken , string ? scope = null )
- AAuth.R3.R3EnforcementDecision: public IResult ToResult ( HttpContext context , R3Challenge challenge , string agent , string agentJkt , string ? scope = null )
- AAuth.R3.R3EnforcementDecision: public static R3EnforcementDecision Conditional ( string proposalUri , string proposalS256 )
- AAuth.R3.R3EnforcementDecisionKind: Conditional
+ AAuth.R3.R3EnforcementDecision: public async Task < IResult > ToResultAsync ( HttpContext context , R3Challenge challenge , TokenVerifier . VerifiedToken verifiedAuthToken , string ? scope = null )
+ AAuth.R3.R3EnforcementDecision: public static R3EnforcementDecision PerCall ( string proposalUri , string proposalS256 )
+ AAuth.R3.R3EnforcementDecisionKind: PerCall
```

Public owners: `AAuth.R3.R3EnforcementDecisionKind`, `AAuth.R3.R3EnforcementDecision`, `AAuth.R3.R3Enforcement`, `AAuth.R3`.

### src/AAuth.R3/R3FetchClient.cs

Concept/decision: [r3](#r3). Source: [R3FetchClient.cs](../../../src/AAuth.R3/R3FetchClient.cs).

```diff
- AAuth.R3.R3FetchClient: public static R3FetchClient Create ( IAAuthKey signingKey , string identifier , string dwk , string kid , HttpMessageHandler ? innerHandler = null , AAuthEgressPolicy ? policy = null , AAuthTransportContract ? transportContract = null )
+ AAuth.R3.R3FetchClient: public static R3FetchClient Create ( IAAuthSigner signingKey , string identifier , string dwk , string kid , HttpMessageHandler ? innerHandler = null , AAuthEgressPolicy ? policy = null , AAuthTransportContract ? transportContract = null )
```

Public owners: `AAuth.R3.R3FetchClient`, `AAuth.R3`.

### src/AAuth.R3/R3Metadata.cs

Concept/decision: [r3](#r3). Source: [R3Metadata.cs](../../../src/AAuth.R3/R3Metadata.cs).

Public signatures unchanged (6); behavior reviewed under r3.

Public owners: `AAuth.R3.R3Metadata`, `AAuth.R3`.

### src/AAuth/AAuthClientBuilder.cs

Concept/decision: [agent-clients](#agent-clients). Source: [AAuthClientBuilder.cs](../../../src/AAuth/AAuthClientBuilder.cs).

```diff
- AAuth.AAuthClientBuilder: public AAuthClientBuilder ( IAAuthKey key )
- AAuth.AAuthClientBuilder: public static EnrolledBuilder Enrolled ( IAAuthKey key )
- AAuth.AAuthClientBuilder: public static SelfIssuingBuilder SelfIssuing ( IAAuthKey key )
+ AAuth.AAuthClientBuilder: public AAuthClientBuilder ( IAAuthSigner key )
+ AAuth.AAuthClientBuilder: public AAuthClientBuilder WithTokenCache ( IAAuthTokenCache cache )
+ AAuth.AAuthClientBuilder: public static EnrolledBuilder Enrolled ( IAAuthSigner key )
+ AAuth.AAuthClientBuilder: public static SelfIssuingBuilder SelfIssuing ( IAAuthSigner key )
```

Public owners: `AAuth.AAuthClientBuilder`, `AAuth`.

### src/AAuth/AAuthConstants.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthConstants.cs](../../../src/AAuth/AAuthConstants.cs).

```diff
- AAuth.AAuthConstants.AccessModes: public const string AAuthAccessToken = "aauth-access-token" ;
- AAuth.AAuthConstants.Headers: public const string AAuthMission = "AAuth-Mission" ;
+ AAuth.AAuthConstants.AccessModes: public const string PerCall = "per-call" ;
+ AAuth.AAuthConstants.AccessModes: public const string PersonToken = "person-token" ;
+ AAuth.AAuthConstants.AccessModes: public const string SessionToken = "session-token" ;
+ AAuth.AAuthConstants.MissionTerminationReasons: public const string Administrative = "administrative" ;
+ AAuth.AAuthConstants.MissionTerminationReasons: public const string Completed = "completed" ;
+ AAuth.AAuthConstants.MissionTerminationReasons: public const string Expired = "expired" ;
+ AAuth.AAuthConstants.MissionTerminationReasons: public const string Revoked = "revoked" ;
+ AAuth.AAuthConstants.MissionTerminationReasons: public const string Superseded = "superseded" ;
+ AAuth.AAuthConstants.TokenTypes: public const string PersonToken = "aa-person+jwt" ;
+ AAuth.AAuthConstants: public static class MissionTerminationReasons
```

Public owners: `AAuth.AAuthConstants.AccessModes`, `AAuth.AAuthConstants.DwkFiles`, `AAuth.AAuthConstants.Headers`, `AAuth.AAuthConstants.MissionTerminationReasons`, `AAuth.AAuthConstants.Schemes`, `AAuth.AAuthConstants.TokenTypes`, `AAuth.AAuthConstants`, `AAuth`.

### src/AAuth/AAuthTokenType.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthTokenType.cs](../../../src/AAuth/AAuthTokenType.cs).

```diff
+ AAuth.AAuthTokenType: PersonToken
```

Public owners: `AAuth.AAuthTokenTypeExtensions`, `AAuth.AAuthTokenType`, `AAuth`.

### src/AAuth/Access/AAuthAccessServerEndpoints.cs

Concept/decision: [consent](#consent). Source: [AAuthAccessServerEndpoints.cs](../../../src/AAuth/Access/AAuthAccessServerEndpoints.cs).

```diff
- AAuth.Access.AAuthAccessServerEndpoints: public static WebApplication MapAAuthAccessServer ( this WebApplication app , AAuthAccessServerOptions options )
- AAuth.Access.AAuthAccessServerOptions: public AAuthEgressPolicy EgressPolicy { get ; init ; } = AAuthEgressPolicy . Production
- AAuth.Access.AAuthAccessServerOptions: public Action < AAuthRevocationOptions > ? ConfigureRevocation { get ; init ; }
- AAuth.Access.AAuthAccessServerOptions: public Func < string , JsonObject ? > ? DeriveAgentClaims { get ; init ; }
- AAuth.Access.AAuthAccessServerOptions: public Func < string , bool > ? IsTrustedPersonServer { get ; init ; }
- AAuth.Access.AAuthAccessServerOptions: public IReadOnlyCollection < string > ? TrustedPersonServers { get ; init ; }
- AAuth.Access.AAuthAccessServerOptions: public TimeProvider TimeProvider { get ; init ; } = TimeProvider . System
- AAuth.Access.AAuthAccessServerOptions: public required IReadOnlyDictionary < string , IAAuthKey > SigningKeys { get ; init ; }
- AAuth.Access.AAuthAccessServerOptions: public required string Issuer { get ; init ; }
- AAuth.Access.AAuthAccessServerOptions: public string DefaultScope { get ; init ; } = ""
- AAuth.Access.AAuthAccessServerOptions: public string InteractionLoginPath { get ; init ; } = "/interaction/login"
- AAuth.Access.AAuthAccessServerOptions: public string PendingPathPrefix { get ; init ; } = "/pending"
- AAuth.Access.AAuthAccessServerOptions: public string RevocationPath { get ; init ; } = "/revoke"
- AAuth.Access.AAuthAccessServerOptions: public string TokenPath { get ; init ; } = "/token"
+ AAuth.Access.AAuthAccessServerEndpoints: public static WebApplication MapAAuthAccessServer ( this WebApplication app , string ? name = null )
+ AAuth.Access.AAuthAccessServerOptions: public AAuthEgressPolicy EgressPolicy { get ; set ; } = AAuthEgressPolicy . Production
+ AAuth.Access.AAuthAccessServerOptions: public AAuthSigningKeySet SigningKeys { get ; set ; } = new ( )
+ AAuth.Access.AAuthAccessServerOptions: public AAuthTrustOptions Trust { get ; set ; } = new ( )
+ AAuth.Access.AAuthAccessServerOptions: public Action < AAuthRevocationOptions > ? ConfigureRevocation { get ; set ; }
+ AAuth.Access.AAuthAccessServerOptions: public Func < string , JsonObject ? > ? DeriveAgentClaims { get ; set ; }
+ AAuth.Access.AAuthAccessServerOptions: public TimeProvider TimeProvider { get ; set ; } = TimeProvider . System
+ AAuth.Access.AAuthAccessServerOptions: public bool MatchIssuerHost { get ; set ; }
+ AAuth.Access.AAuthAccessServerOptions: public string ? KeyHandle { get ; set ; }
+ AAuth.Access.AAuthAccessServerOptions: public string ? KeyId { get ; set ; }
+ AAuth.Access.AAuthAccessServerOptions: public string DefaultScope { get ; set ; } = ""
+ AAuth.Access.AAuthAccessServerOptions: public string InteractionLoginPath { get ; set ; } = "/interaction/login"
+ AAuth.Access.AAuthAccessServerOptions: public string Issuer { get ; set ; } = ""
+ AAuth.Access.AAuthAccessServerOptions: public string PendingPathPrefix { get ; set ; } = "/pending"
+ AAuth.Access.AAuthAccessServerOptions: public string RevocationPath { get ; set ; } = "/revoke"
+ AAuth.Access.AAuthAccessServerOptions: public string TokenPath { get ; set ; } = "/token"
```

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

### src/AAuth/Agent/AAuthAgentFactory.cs

Concept/decision: [agent-clients](#agent-clients). Source: [AAuthAgentFactory.cs](../../../src/AAuth/Agent/AAuthAgentFactory.cs).

```diff
+ AAuth.Agent.AAuthAgent: public AAuth . Server . RevocationClient Revocation
+ AAuth.Agent.AAuthAgent: public Governance . AAuthGovernanceClient Governance
+ AAuth.Agent.AAuthAgent: public HttpClient HttpClient { get ; }
+ AAuth.Agent.AAuthAgent: public TokenExchangeClient TokenExchange
+ AAuth.Agent.AAuthAgent: public string Name { get ; }
+ AAuth.Agent.AAuthAgent: public void Dispose ( )
+ AAuth.Agent.AAuthAgentDescriptor: public AAuthAgentDescriptor ( string name )
+ AAuth.Agent.AAuthAgentDescriptor: public string Name { get ; }
+ AAuth.Agent.IAAuthAgentFactory: AAuthAgent Create ( AAuthAgentDescriptor descriptor )
+ AAuth.Agent.IAAuthAgentFactory: AAuthAgent Create ( string name , IAAuthSigner signer , Action < AAuthClientBuilder > configure )
+ AAuth.Agent.IAAuthAgentFactory: AAuthAgent Get ( string name )
+ AAuth.Agent: public interface IAAuthAgentFactory
+ AAuth.Agent: public sealed class AAuthAgent : IDisposable
+ AAuth.Agent: public sealed class AAuthAgentDescriptor : AAuthAgentOptions
```

Public owners: `AAuth.Agent.AAuthAgentDescriptor`, `AAuth.Agent.AAuthAgent`, `AAuth.Agent.IAAuthAgentFactory`, `AAuth.Agent`.

### src/AAuth/Agent/AAuthCallbackHandlers.cs

Concept/decision: [agent-clients](#agent-clients). Source: [AAuthCallbackHandlers.cs](../../../src/AAuth/Agent/AAuthCallbackHandlers.cs).

```diff
+ AAuth.Agent.IAAuthClarificationHandler: Task < ClarificationResponse > OnClarificationRequiredAsync ( ClarificationRequirement clarification , CancellationToken cancellationToken )
+ AAuth.Agent.IAAuthDeferredObserver: Task OnApprovalPendingAsync ( CancellationToken cancellationToken )
+ AAuth.Agent.IAAuthDeferredObserver: void OnPoll ( HttpResponseMessage response )
+ AAuth.Agent.IAAuthInteractionHandler: Task OnInteractionRequiredAsync ( Interaction interaction , CancellationToken cancellationToken )
+ AAuth.Agent: public interface IAAuthClarificationHandler
+ AAuth.Agent: public interface IAAuthDeferredObserver
+ AAuth.Agent: public interface IAAuthInteractionHandler
```

Public owners: `AAuth.Agent.IAAuthClarificationHandler`, `AAuth.Agent.IAAuthDeferredObserver`, `AAuth.Agent.IAAuthInteractionHandler`, `AAuth.Agent`.

### src/AAuth/Agent/AAuthRequestOptions.cs

Concept/decision: [resource-managed](#resource-managed). Source: [AAuthRequestOptions.cs](../../../src/AAuth/Agent/AAuthRequestOptions.cs).

```diff
+ AAuth.Agent.AAuthRequestOptions: public static readonly HttpRequestOptionsKey < IAAuthClarificationHandler > ClarificationHandler = new ( "AAuth.ClarificationHandler" ) ;
+ AAuth.Agent.AAuthRequestOptions: public static readonly HttpRequestOptionsKey < IAAuthDeferredObserver > DeferredObserver = new ( "AAuth.DeferredObserver" ) ;
+ AAuth.Agent.AAuthRequestOptions: public static readonly HttpRequestOptionsKey < IAAuthInteractionHandler > InteractionHandler = new ( "AAuth.InteractionHandler" ) ;
+ AAuth.Agent.AAuthRequestOptions: public static readonly HttpRequestOptionsKey < System . Collections . Generic . IReadOnlyDictionary < string , string > > MissionPersonTokens = new ( "AAuth.MissionPersonTokens" ) ;
+ AAuth.Agent.AAuthRequestOptions: public static readonly HttpRequestOptionsKey < string > MissionS256 = new ( "AAuth.MissionS256" ) ;
+ AAuth.Agent.AAuthRequestOptions: public static string ? GetMissionS256 ( HttpRequestMessage request )
```

Public owners: `AAuth.Agent.AAuthRequestOptions`, `AAuth.Agent`.

### src/AAuth/Agent/AAuthTokenCache.cs

Concept/decision: [agent-clients](#agent-clients). Source: [AAuthTokenCache.cs](../../../src/AAuth/Agent/AAuthTokenCache.cs).

```diff
+ AAuth.Agent.IAAuthTokenCache: Task < string > AcquireAsync ( AAuthTokenCacheKey key , string ? presented , Func < CancellationToken , Task < string > > acquire , CancellationToken cancellationToken )
+ AAuth.Agent.IAAuthTokenCache: string ? Get ( AAuthTokenCacheKey key )
+ AAuth.Agent.IAAuthTokenCache: void Clear ( )
+ AAuth.Agent.IAAuthTokenCache: void Set ( AAuthTokenCacheKey key , string token , DateTimeOffset expiresAt )
+ AAuth.Agent.InMemoryAAuthTokenCache: public InMemoryAAuthTokenCache ( TimeProvider ? timeProvider = null )
+ AAuth.Agent.InMemoryAAuthTokenCache: public async Task < string > AcquireAsync ( AAuthTokenCacheKey key , string ? presented , Func < CancellationToken , Task < string > > acquire , CancellationToken cancellationToken )
+ AAuth.Agent.InMemoryAAuthTokenCache: public string ? Get ( AAuthTokenCacheKey key )
+ AAuth.Agent.InMemoryAAuthTokenCache: public void Clear ( )
+ AAuth.Agent.InMemoryAAuthTokenCache: public void Set ( AAuthTokenCacheKey key , string token , DateTimeOffset expiresAt )
+ AAuth.Agent: public interface IAAuthTokenCache
+ AAuth.Agent: public sealed class InMemoryAAuthTokenCache : IAAuthTokenCache
+ AAuth.Agent: public sealed record AAuthTokenCacheKey ( string AgentToken , string ? Upstream , string ? MissionS256 , string Audience , string ? Account , string KeyThumbprint )
```

Public owners: `AAuth.Agent.IAAuthTokenCache`, `AAuth.Agent.InMemoryAAuthTokenCache`, `AAuth.Agent`.

### src/AAuth/Agent/AAuthTokenHolder.cs

Concept/decision: [agent-clients](#agent-clients). Source: [AAuthTokenHolder.cs](../../../src/AAuth/Agent/AAuthTokenHolder.cs).

```diff
+ AAuth.Agent.AAuthTokenHolder: public AAuthTokenHolder ( IAAuthTokenCache ? cache )
```

Public owners: `AAuth.Agent.AAuthTokenHolder`, `AAuth.Agent`.

### src/AAuth/Agent/AgentProviderClient.cs

Concept/decision: [agent-clients](#agent-clients). Source: [AgentProviderClient.cs](../../../src/AAuth/Agent/AgentProviderClient.cs).

Public signatures unchanged (16); behavior reviewed under agent-clients.

Public owners: `AAuth.Agent.AgentProviderClient`, `AAuth.Agent.EnrollResult`, `AAuth.Agent.TwoKeyRefreshResult`, `AAuth.Agent`.

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

### src/AAuth/Agent/DeferredPoller.cs

Concept/decision: [agent-clients](#agent-clients). Source: [DeferredPoller.cs](../../../src/AAuth/Agent/DeferredPoller.cs).

```diff
- AAuth.Agent.DeferredPollerOptions: public Action < HttpResponseMessage > ? OnPoll { get ; init ; }
- AAuth.Agent.DeferredPollerOptions: public Func < HttpResponseMessage , bool > ? StopWhenAccepted { get ; init ; }
- AAuth.Agent.DeferredPollerOptions: public TimeProvider TimeProvider { get ; init ; } = TimeProvider . System
- AAuth.Agent.DeferredPollerOptions: public TimeSpan DefaultPollInterval { get ; init ; } = TimeSpan . FromSeconds ( 5 )
- AAuth.Agent.DeferredPollerOptions: public TimeSpan MaxTotalWait { get ; init ; } = TimeSpan . FromMinutes ( 5 )
- AAuth.Agent.DeferredPollerOptions: public TimeSpan MinPollInterval { get ; init ; } = TimeSpan . FromMilliseconds ( 100 )
- AAuth.Agent.DeferredPollerOptions: public int ? PreferWaitSeconds { get ; init ; }
+ AAuth.Agent.DeferredPollerOptions: public Action < HttpResponseMessage > ? OnPoll { get ; set ; }
+ AAuth.Agent.DeferredPollerOptions: public Func < HttpResponseMessage , bool > ? StopWhenAccepted { get ; set ; }
+ AAuth.Agent.DeferredPollerOptions: public TimeProvider TimeProvider { get ; set ; } = TimeProvider . System
+ AAuth.Agent.DeferredPollerOptions: public TimeSpan DefaultPollInterval { get ; set ; } = TimeSpan . FromSeconds ( 5 )
+ AAuth.Agent.DeferredPollerOptions: public TimeSpan MaxTotalWait { get ; set ; } = TimeSpan . FromMinutes ( 5 )
+ AAuth.Agent.DeferredPollerOptions: public TimeSpan MinPollInterval { get ; set ; } = TimeSpan . FromMilliseconds ( 100 )
+ AAuth.Agent.DeferredPollerOptions: public int ? PreferWaitSeconds { get ; set ; }
```

Public owners: `AAuth.Agent.DeferredPollerOptions`, `AAuth.Agent.DeferredPoller`, `AAuth.Agent`.

### src/AAuth/Agent/Governance/AuditRecord.cs

Concept/decision: [governance](#governance). Source: [AuditRecord.cs](../../../src/AAuth/Agent/Governance/AuditRecord.cs).

```diff
- AAuth.Agent.Governance: public sealed record AuditRecord ( MissionClaim Mission , MissionAction Action )
+ AAuth.Agent.Governance: public sealed record AuditRecord ( string MissionS256 , MissionAction Action )
```

Public owners: `AAuth.Agent.Governance.AuditRecord`, `AAuth.Agent.Governance`.

### src/AAuth/Agent/Governance/GovernanceOptions.cs

Concept/decision: [governance](#governance). Source: [GovernanceOptions.cs](../../../src/AAuth/Agent/Governance/GovernanceOptions.cs).

```diff
- AAuth.Agent.Governance.GovernanceOptions: public DeferredPollerOptions ? PollerOptions { get ; init ; }
- AAuth.Agent.Governance.GovernanceOptions: public Func < ClarificationRequirement , CancellationToken , Task < ClarificationResponse > > ? OnClarificationRequired { get ; init ; }
- AAuth.Agent.Governance.GovernanceOptions: public Func < Interaction , CancellationToken , Task > ? OnInteractionRequired { get ; init ; }
- AAuth.Agent.Governance.GovernanceOptions: public int MaxClarificationRounds { get ; init ; } = ClarificationExchange . DefaultMaxRounds
+ AAuth.Agent.Governance.GovernanceOptions: public DeferredPollerOptions ? PollerOptions { get ; set ; }
+ AAuth.Agent.Governance.GovernanceOptions: public Func < ClarificationRequirement , CancellationToken , Task < ClarificationResponse > > ? OnClarificationRequired { get ; set ; }
+ AAuth.Agent.Governance.GovernanceOptions: public Func < Interaction , CancellationToken , Task > ? OnInteractionRequired { get ; set ; }
+ AAuth.Agent.Governance.GovernanceOptions: public int MaxClarificationRounds { get ; set ; } = ClarificationExchange . DefaultMaxRounds
```

Public owners: `AAuth.Agent.Governance.GovernanceOptions`, `AAuth.Agent.Governance`.

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

### src/AAuth/Agent/InteractionHandler.cs

Concept/decision: [agent-clients](#agent-clients). Source: [InteractionHandler.cs](../../../src/AAuth/Agent/InteractionHandler.cs).

```diff
- AAuth.Agent.InteractionHandler: public InteractionHandler ( Func < string , string , CancellationToken , Task > ? onInteractionRequired = null , Func < CancellationToken , Task > ? onApprovalPending = null , TimeSpan ? pollingTimeout = null , TimeSpan ? defaultPollInterval = null , TimeSpan ? minPollInterval = null , int ? preferWaitSeconds = null , Action < HttpResponseMessage > ? onPoll = null )
+ AAuth.Agent.InteractionHandler: public InteractionHandler ( Func < Interaction , CancellationToken , Task > ? onInteractionRequired = null , Func < CancellationToken , Task > ? onApprovalPending = null , TimeSpan ? pollingTimeout = null , TimeSpan ? defaultPollInterval = null , TimeSpan ? minPollInterval = null , int ? preferWaitSeconds = null , Action < HttpResponseMessage > ? onPoll = null )
+ AAuth.Agent.InteractionHandler: public InteractionHandler ( IAAuthInteractionHandler ? interactionHandler , IAAuthDeferredObserver ? observer , TimeSpan ? pollingTimeout = null , TimeSpan ? defaultPollInterval = null , TimeSpan ? minPollInterval = null , int ? preferWaitSeconds = null )
```

Public owners: `AAuth.Agent.InteractionHandler`, `AAuth.Agent`.

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

### src/AAuth/Agent/NamingJwtBuilder.cs

Concept/decision: [agent-clients](#agent-clients). Source: [NamingJwtBuilder.cs](../../../src/AAuth/Agent/NamingJwtBuilder.cs).

```diff
- AAuth.Agent.NamingJwtBuilder: public static string Build ( IAAuthKey durableKey , IAAuthKey ephemeralKey )
+ AAuth.Agent.NamingJwtBuilder: public static ValueTask < string > BuildAsync ( IAAuthSigner durableKey , IAAuthKey ephemeralKey , CancellationToken cancellationToken = default )
```

Public owners: `AAuth.Agent.NamingJwtBuilder`, `AAuth.Agent`.

### src/AAuth/Agent/SelfIssuedTokenRefresher.cs

Concept/decision: [agent-clients](#agent-clients). Source: [SelfIssuedTokenRefresher.cs](../../../src/AAuth/Agent/SelfIssuedTokenRefresher.cs).

```diff
- AAuth.Agent.SelfIssuedTokenRefresher: public SelfIssuedTokenRefresher ( IAAuthKey key , string issuer , string subject , string kid , string ? personServer = null , TimeSpan ? lifetime = null , AAuth . Discovery . AAuthEgressPolicy ? egressPolicy = null )
- AAuth.Agent.SelfIssuedTokenRefresher: public static RefresherBuilder Create ( IAAuthKey key , string issuer , string subject )
+ AAuth.Agent.SelfIssuedTokenRefresher: public SelfIssuedTokenRefresher ( IAAuthSigner key , string issuer , string subject , string kid , string ? personServer = null , TimeSpan ? lifetime = null , AAuth . Discovery . AAuthEgressPolicy ? egressPolicy = null )
+ AAuth.Agent.SelfIssuedTokenRefresher: public static RefresherBuilder Create ( IAAuthSigner key , string issuer , string subject )
```

Public owners: `AAuth.Agent.SelfIssuedTokenRefresher.RefresherBuilder`, `AAuth.Agent.SelfIssuedTokenRefresher`, `AAuth.Agent`.

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

### src/AAuth/Crypto/AAuthKey.cs

Concept/decision: [signatures](#signatures). Source: [AAuthKey.cs](../../../src/AAuth/Crypto/AAuthKey.cs).

```diff
- AAuth.Crypto: public sealed class AAuthKey : IAAuthKey
+ AAuth.Crypto.AAuthKey: public ValueTask < byte [  ] > SignAsync ( ReadOnlyMemory < byte > data , CancellationToken cancellationToken = default )
+ AAuth.Crypto: public sealed class AAuthKey : IAAuthExportableKey
```

Public owners: `AAuth.Crypto.AAuthKey`, `AAuth.Crypto`.

### src/AAuth/Crypto/AAuthSigningKeySet.cs

Concept/decision: [signatures](#signatures). Source: [AAuthSigningKeySet.cs](../../../src/AAuth/Crypto/AAuthSigningKeySet.cs).

```diff
+ AAuth.Crypto.AAuthSigningKeySet: public ( string KeyId , IAAuthSigner Signer ) Active
+ AAuth.Crypto.AAuthSigningKeySet: public AAuthSigningKeySet ( string ? active = null )
+ AAuth.Crypto.AAuthSigningKeySet: public AAuthSigningKeySet ( string keyId , IAAuthSigner signer )
+ AAuth.Crypto.AAuthSigningKeySet: public AAuthSigningKeySet Activate ( string keyId )
+ AAuth.Crypto.AAuthSigningKeySet: public AAuthSigningKeySet Add ( string keyId , IAAuthSigner signer )
+ AAuth.Crypto.AAuthSigningKeySet: public IAAuthSigner this [ string keyId ] { get ; set ; }
+ AAuth.Crypto.AAuthSigningKeySet: public IEnumerator < KeyValuePair < string , IAAuthSigner > > GetEnumerator ( )
+ AAuth.Crypto.AAuthSigningKeySet: public IReadOnlyList < string > KeyIds
+ AAuth.Crypto.AAuthSigningKeySet: public bool Remove ( string keyId )
+ AAuth.Crypto.AAuthSigningKeySet: public bool TryGetSigner ( string keyId , [ NotNullWhen ( true ) ] out IAAuthSigner ? signer )
+ AAuth.Crypto.AAuthSigningKeySet: public int Count
+ AAuth.Crypto.AAuthSigningKeySet: public string ActiveKeyId
+ AAuth.Crypto: public sealed class AAuthSigningKeySet : IReadOnlyCollection < KeyValuePair < string , IAAuthSigner > >
```

Public owners: `AAuth.Crypto.AAuthSigningKeySet`, `AAuth.Crypto`.

### src/AAuth/Crypto/EcdsaAAuthKey.cs

Concept/decision: [signatures](#signatures). Source: [EcdsaAAuthKey.cs](../../../src/AAuth/Crypto/EcdsaAAuthKey.cs).

```diff
- AAuth.Crypto: public sealed class EcdsaAAuthKey : IAAuthKey
+ AAuth.Crypto.EcdsaAAuthKey: public ValueTask < byte [  ] > SignAsync ( ReadOnlyMemory < byte > data , CancellationToken cancellationToken = default )
+ AAuth.Crypto: public sealed class EcdsaAAuthKey : IAAuthExportableKey
```

Public owners: `AAuth.Crypto.EcdsaAAuthKey`, `AAuth.Crypto`.

### src/AAuth/Crypto/FileKeyStore.cs

Concept/decision: [signatures](#signatures). Source: [FileKeyStore.cs](../../../src/AAuth/Crypto/FileKeyStore.cs).

Public signatures unchanged (8); behavior reviewed under signatures.

Public owners: `AAuth.Crypto.FileKeyStore`, `AAuth.Crypto`.

### src/AAuth/Crypto/IAAuthKey.cs

Concept/decision: [signatures](#signatures). Source: [IAAuthKey.cs](../../../src/AAuth/Crypto/IAAuthKey.cs).

```diff
- AAuth.Crypto.IAAuthKey: JsonObject ToPrivateJwk ( )
- AAuth.Crypto.IAAuthKey: byte [  ] Sign ( byte [  ] data )
```

Public owners: `AAuth.Crypto.IAAuthKey`, `AAuth.Crypto`.

### src/AAuth/Crypto/IAAuthSigner.cs

Concept/decision: [signatures](#signatures). Source: [IAAuthSigner.cs](../../../src/AAuth/Crypto/IAAuthSigner.cs).

```diff
+ AAuth.Crypto.IAAuthExportableKey: JsonObject ToPrivateJwk ( )
+ AAuth.Crypto.IAAuthSigner: ValueTask < byte [  ] > SignAsync ( ReadOnlyMemory < byte > data , CancellationToken cancellationToken = default )
+ AAuth.Crypto: public interface IAAuthExportableKey : IAAuthSigner
+ AAuth.Crypto: public interface IAAuthSigner : IAAuthKey
```

Public owners: `AAuth.Crypto.IAAuthExportableKey`, `AAuth.Crypto.IAAuthSigner`, `AAuth.Crypto`.

### src/AAuth/Crypto/IKeyStore.cs

Concept/decision: [signatures](#signatures). Source: [IKeyStore.cs](../../../src/AAuth/Crypto/IKeyStore.cs).

```diff
- AAuth.Crypto.IKeyStore: Task < IAAuthKey ? > LoadAsync ( string handle , CancellationToken ct = default )
- AAuth.Crypto.IKeyStore: Task StoreAsync ( string handle , IAAuthKey key , CancellationToken ct = default )
+ AAuth.Crypto.IKeyStore: Task < IAAuthSigner ? > LoadAsync ( string handle , CancellationToken ct = default )
+ AAuth.Crypto.IKeyStore: Task StoreAsync ( string handle , IAAuthSigner key , CancellationToken ct = default )
```

Public owners: `AAuth.Crypto.IKeyStore`, `AAuth.Crypto`.

### src/AAuth/Crypto/InMemoryKeyStore.cs

Concept/decision: [signatures](#signatures). Source: [InMemoryKeyStore.cs](../../../src/AAuth/Crypto/InMemoryKeyStore.cs).

```diff
- AAuth.Crypto.InMemoryKeyStore: public Task < IAAuthKey ? > LoadAsync ( string handle , CancellationToken ct = default )
- AAuth.Crypto.InMemoryKeyStore: public Task StoreAsync ( string handle , IAAuthKey key , CancellationToken ct = default )
+ AAuth.Crypto.InMemoryKeyStore: public Task < IAAuthSigner ? > LoadAsync ( string handle , CancellationToken ct = default )
+ AAuth.Crypto.InMemoryKeyStore: public Task StoreAsync ( string handle , IAAuthSigner key , CancellationToken ct = default )
```

Public owners: `AAuth.Crypto.InMemoryKeyStore`, `AAuth.Crypto`.

### src/AAuth/Crypto/KeyFactory.cs

Concept/decision: [signatures](#signatures). Source: [KeyFactory.cs](../../../src/AAuth/Crypto/KeyFactory.cs).

```diff
- AAuth.Crypto.KeyFactory: public static IAAuthKey FromJwk ( JsonObject jwk )
+ AAuth.Crypto.KeyFactory: public static IAAuthExportableKey FromJwk ( JsonObject jwk )
```

Public owners: `AAuth.Crypto.KeyFactory`, `AAuth.Crypto`.

### src/AAuth/DependencyInjection/AAuthAccessServerServiceCollectionExtensions.cs

Concept/decision: [di](#di). Source: [AAuthAccessServerServiceCollectionExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthAccessServerServiceCollectionExtensions.cs).

```diff
+ Microsoft.Extensions.DependencyInjection.AAuthAccessServerBuilder: public AAuthAccessServerBuilder Configure ( Action < AAuthAccessServerOptions > configure )
+ Microsoft.Extensions.DependencyInjection.AAuthAccessServerBuilder: public AAuthAccessServerBuilder UsePendingStore ( Func < IServiceProvider , IAccessPendingStore > factory )
+ Microsoft.Extensions.DependencyInjection.AAuthAccessServerBuilder: public AAuthAccessServerBuilder UsePendingStore ( IAccessPendingStore store )
+ Microsoft.Extensions.DependencyInjection.AAuthAccessServerBuilder: public AAuthAccessServerBuilder UsePendingStore < T > ( ) where T : class , IAccessPendingStore
+ Microsoft.Extensions.DependencyInjection.AAuthAccessServerBuilder: public AAuthAccessServerBuilder UsePolicy ( Func < IServiceProvider , IAccessPolicy > factory )
+ Microsoft.Extensions.DependencyInjection.AAuthAccessServerBuilder: public AAuthAccessServerBuilder UsePolicy ( IAccessPolicy policy )
+ Microsoft.Extensions.DependencyInjection.AAuthAccessServerBuilder: public AAuthAccessServerBuilder UsePolicy < T > ( ) where T : class , IAccessPolicy
+ Microsoft.Extensions.DependencyInjection.AAuthAccessServerBuilder: public AAuthAccessServerBuilder UseTokenInventory ( IJtiStore inventory )
+ Microsoft.Extensions.DependencyInjection.AAuthAccessServerBuilder: public AAuthAccessServerBuilder UseTokenInventory < T > ( ) where T : class , IJtiStore
+ Microsoft.Extensions.DependencyInjection.AAuthAccessServerBuilder: public AAuthAccessServerBuilder UseTokenVerifier ( TokenVerifier verifier )
+ Microsoft.Extensions.DependencyInjection.AAuthAccessServerBuilder: public AAuthAccessServerBuilder WithTrust ( Action < AAuthTrustOptions > configure )
+ Microsoft.Extensions.DependencyInjection.AAuthAccessServerBuilder: public IServiceCollection Services { get ; }
+ Microsoft.Extensions.DependencyInjection.AAuthAccessServerBuilder: public const string DefaultName = "AccessServer" ;
+ Microsoft.Extensions.DependencyInjection.AAuthAccessServerBuilder: public string Name { get ; }
+ Microsoft.Extensions.DependencyInjection.AAuthAccessServerServiceCollectionExtensions: public const string ConfigurationSection = "AAuth:AccessServer" ;
+ Microsoft.Extensions.DependencyInjection.AAuthAccessServerServiceCollectionExtensions: public static AAuthAccessServerBuilder AddAAuthAccessServer ( this IServiceCollection services , IConfiguration configuration , string ? name = null , Action < AAuthAccessServerOptions > ? configure = null )
+ Microsoft.Extensions.DependencyInjection.AAuthAccessServerServiceCollectionExtensions: public static AAuthAccessServerBuilder AddAAuthAccessServer ( this IServiceCollection services , string ? name = null , Action < AAuthAccessServerOptions > ? configure = null )
+ Microsoft.Extensions.DependencyInjection: public sealed class AAuthAccessServerBuilder
+ Microsoft.Extensions.DependencyInjection: public static class AAuthAccessServerServiceCollectionExtensions
```

Public owners: `Microsoft.Extensions.DependencyInjection.AAuthAccessServerBuilder`, `Microsoft.Extensions.DependencyInjection.AAuthAccessServerServiceCollectionExtensions`, `Microsoft.Extensions.DependencyInjection`.

### src/AAuth/DependencyInjection/AAuthAgentOptions.cs

Concept/decision: [di](#di). Source: [AAuthAgentOptions.cs](../../../src/AAuth/DependencyInjection/AAuthAgentOptions.cs).

```diff
- AAuth.AAuthAgentOptions: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; set ; } = AAuth . Discovery . AAuthEgressPolicy . Production
- AAuth.AAuthAgentOptions: public AAuth . HttpSig . ISignatureKeyProvider ? SignatureKeyProvider { get ; set ; }
- AAuth.AAuthAgentOptions: public Func < CancellationToken , Task > ? OnApprovalPending { get ; set ; }
- AAuth.AAuthAgentOptions: public Func < Interaction , CancellationToken , Task > ? OnInteractionRequired { get ; set ; }
- AAuth.AAuthAgentOptions: public Func < string , string , CancellationToken , Task > ? OnResourceInteraction { get ; set ; }
- AAuth.AAuthAgentOptions: public IAAuthKey Key { get ; set ; } = null !
- AAuth.AAuthAgentOptions: public TimeSpan PollingTimeout { get ; set ; } = TimeSpan . FromMinutes ( 5 )
- AAuth: public sealed class AAuthAgentOptions
+ AAuth.AAuthAgentOptions: public AAuthAgentProviderOptions AgentProvider { get ; set ; } = new ( )
+ AAuth.AAuthAgentOptions: public AAuthEgressPolicy ? EgressPolicy { get ; set ; }
+ AAuth.AAuthAgentOptions: public AAuthJwksUriIdentityOptions JwksUri { get ; set ; } = new ( )
+ AAuth.AAuthAgentOptions: public AAuthSelfIssuedAgentOptions SelfIssued { get ; set ; } = new ( )
+ AAuth.AAuthAgentOptions: public AAuthTransportContract ? TransportContract { get ; set ; }
+ AAuth.AAuthAgentOptions: public Action < HttpRequestMessage , string > ? OnSignatureBase { get ; set ; }
+ AAuth.AAuthAgentOptions: public ChallengeHandlingOptions Challenge { get ; set ; } = new ( )
+ AAuth.AAuthAgentOptions: public Func < string > ? AgentTokenFactory { get ; set ; }
+ AAuth.AAuthAgentOptions: public Func < string ? > ? UpstreamTokenProvider { get ; set ; }
+ AAuth.AAuthAgentOptions: public HttpMessageHandler ? InnerHandler { get ; set ; }
+ AAuth.AAuthAgentOptions: public IAAuthSigner ? Signer { get ; set ; }
+ AAuth.AAuthAgentOptions: public IAAuthTokenCache ? TokenCache { get ; set ; }
+ AAuth.AAuthAgentOptions: public ISignatureKeyProvider ? SignatureKeyProvider { get ; set ; }
+ AAuth.AAuthAgentOptions: public InteractionHandlingOptions Interaction { get ; set ; } = new ( )
+ AAuth.AAuthAgentOptions: public Mission ? Mission { get ; set ; }
+ AAuth.AAuthAgentOptions: public TimeSpan ? TokenRefreshThreshold { get ; set ; }
+ AAuth.AAuthAgentOptions: public bool ? HandleChallenges { get ; set ; }
+ AAuth.AAuthAgentOptions: public bool ? HandleInteractions { get ; set ; }
+ AAuth.AAuthAgentOptions: public bool ChainFromHttpContext { get ; set ; }
+ AAuth.AAuthAgentOptions: public string ? KeyHandle { get ; set ; }
+ AAuth.AAuthAgentOptions: public string [  ] ? Capabilities { get ; set ; }
+ AAuth.AAuthAgentOptions: public string [  ] ? DevelopmentLoopbackOrigins { get ; set ; }
+ AAuth.AAuthAgentProviderOptions: public string ? RefreshEndpoint { get ; set ; }
+ AAuth.AAuthJwksUriIdentityOptions: public string ? Dwk { get ; set ; }
+ AAuth.AAuthJwksUriIdentityOptions: public string ? Id { get ; set ; }
+ AAuth.AAuthJwksUriIdentityOptions: public string ? KeyId { get ; set ; }
+ AAuth.AAuthSelfIssuedAgentOptions: public string ? Issuer { get ; set ; }
+ AAuth.AAuthSelfIssuedAgentOptions: public string ? KeyId { get ; set ; }
+ AAuth.AAuthSelfIssuedAgentOptions: public string ? Subject { get ; set ; }
+ AAuth: public class AAuthAgentOptions
+ AAuth: public sealed class AAuthAgentProviderOptions
+ AAuth: public sealed class AAuthJwksUriIdentityOptions
+ AAuth: public sealed class AAuthSelfIssuedAgentOptions
```

Public owners: `AAuth.AAuthAgentOptions`, `AAuth.AAuthAgentProviderOptions`, `AAuth.AAuthJwksUriIdentityOptions`, `AAuth.AAuthSelfIssuedAgentOptions`, `AAuth`.

### src/AAuth/DependencyInjection/AAuthAgentServiceCollectionExtensions.cs

Concept/decision: [di](#di). Source: [AAuthAgentServiceCollectionExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthAgentServiceCollectionExtensions.cs).

```diff
- Microsoft.Extensions.DependencyInjection.AAuthAgentServiceCollectionExtensions: public static IServiceCollection AddAAuthAgent ( this IServiceCollection services , string name , Action < AAuthAgentOptions > configure )
+ Microsoft.Extensions.DependencyInjection.AAuthAgentBuilder: public AAuthAgentBuilder Configure ( Action < AAuthAgentOptions > configure )
+ Microsoft.Extensions.DependencyInjection.AAuthAgentBuilder: public AAuthAgentBuilder WithAgentProvider ( Action < AAuthAgentProviderOptions > ? configure = null )
+ Microsoft.Extensions.DependencyInjection.AAuthAgentBuilder: public AAuthAgentBuilder WithGovernance ( GovernanceOptions ? defaultOptions = null )
+ Microsoft.Extensions.DependencyInjection.AAuthAgentBuilder: public IHttpClientBuilder HttpClientBuilder { get ; }
+ Microsoft.Extensions.DependencyInjection.AAuthAgentBuilder: public IServiceCollection Services { get ; }
+ Microsoft.Extensions.DependencyInjection.AAuthAgentBuilder: public string Name { get ; }
+ Microsoft.Extensions.DependencyInjection.AAuthAgentServiceCollectionExtensions: public const string ConfigurationSection = "AAuth:Agents" ;
+ Microsoft.Extensions.DependencyInjection.AAuthAgentServiceCollectionExtensions: public static AAuthAgentBuilder AddAAuthAgent ( this IServiceCollection services , string name , Action < AAuthAgentOptions > ? configure = null )
+ Microsoft.Extensions.DependencyInjection.AAuthAgentServiceCollectionExtensions: public static AAuthAgentBuilder AddAAuthAgent ( this IServiceCollection services , string name , IConfiguration configuration , Action < AAuthAgentOptions > ? configure = null )
+ Microsoft.Extensions.DependencyInjection.AAuthAgentServiceCollectionExtensions: public static IServiceCollection AddAAuthAgentFactory ( this IServiceCollection services )
+ Microsoft.Extensions.DependencyInjection: public sealed class AAuthAgentBuilder
```

Public owners: `Microsoft.Extensions.DependencyInjection.AAuthAgentBuilder`, `Microsoft.Extensions.DependencyInjection.AAuthAgentServiceCollectionExtensions`, `Microsoft.Extensions.DependencyInjection`.

### src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs

Concept/decision: [di](#di). Source: [AAuthApplicationBuilderExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs).

```diff
- Microsoft.AspNetCore.Builder.AAuthApplicationBuilderExtensions: public static IApplicationBuilder UseAAuthChallenge ( this IApplicationBuilder app , ChallengeOptions options )
- Microsoft.AspNetCore.Builder.AAuthApplicationBuilderExtensions: public static IApplicationBuilder UseAAuthIntermediary ( this IApplicationBuilder app , AAuthVerificationOptions verificationOptions , ChallengeOptions challengeOptions )
- Microsoft.AspNetCore.Builder.AAuthApplicationBuilderExtensions: public static IApplicationBuilder UseAAuthVerification ( this IApplicationBuilder app , AAuthVerificationOptions ? options = null )
+ Microsoft.AspNetCore.Builder.AAuthApplicationBuilderExtensions: public static IApplicationBuilder UseAAuthChallenge ( this IApplicationBuilder app , Action < ChallengeOptions > ? configure = null )
+ Microsoft.AspNetCore.Builder.AAuthApplicationBuilderExtensions: public static IApplicationBuilder UseAAuthIntermediary ( this IApplicationBuilder app , Action < AAuthVerificationOptions > ? configureVerification = null , Action < ChallengeOptions > ? configureChallenge = null )
+ Microsoft.AspNetCore.Builder.AAuthApplicationBuilderExtensions: public static IApplicationBuilder UseAAuthVerification ( this IApplicationBuilder app , Action < AAuthVerificationOptions > ? configure = null )
```

Public owners: `Microsoft.AspNetCore.Builder.AAuthApplicationBuilderExtensions`, `Microsoft.AspNetCore.Builder`.

### src/AAuth/DependencyInjection/AAuthFederationServiceCollectionExtensions.cs

Concept/decision: [di](#di). Source: [AAuthFederationServiceCollectionExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthFederationServiceCollectionExtensions.cs).

```diff
- Microsoft.Extensions.DependencyInjection.AAuthFederationServiceCollectionExtensions: public const string FederationHttpClientName = "aauth-federation" ;
- Microsoft.Extensions.DependencyInjection.AAuthFederationServiceCollectionExtensions: public static IServiceCollection AddAAuthFederation ( this IServiceCollection services , IAAuthKey personServerKey , string personServerIssuer , string personServerKeyId )
- Microsoft.Extensions.DependencyInjection: public static class AAuthFederationServiceCollectionExtensions
```

Public owners: `Microsoft.Extensions.DependencyInjection.AAuthFederationServiceCollectionExtensions`, `Microsoft.Extensions.DependencyInjection`.

### src/AAuth/DependencyInjection/AAuthGovernanceApplicationBuilderExtensions.cs

Concept/decision: [di](#di). Source: [AAuthGovernanceApplicationBuilderExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthGovernanceApplicationBuilderExtensions.cs).

Public signatures unchanged (2); behavior reviewed under di.

Public owners: `Microsoft.AspNetCore.Builder.AAuthGovernanceApplicationBuilderExtensions`, `Microsoft.AspNetCore.Builder`.

### src/AAuth/DependencyInjection/AAuthGovernanceClientServiceCollectionExtensions.cs

Concept/decision: [di](#di). Source: [AAuthGovernanceClientServiceCollectionExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthGovernanceClientServiceCollectionExtensions.cs).

```diff
- Microsoft.Extensions.DependencyInjection.AAuthGovernanceClientServiceCollectionExtensions: public static IServiceCollection AddAAuthGovernanceClient ( this IServiceCollection services , Func < IServiceProvider , AAuthClientBuilder > configureBuilder , GovernanceOptions ? defaultOptions = null )
- Microsoft.Extensions.DependencyInjection.AAuthGovernanceClientServiceCollectionExtensions: public static IServiceCollection AddAAuthGovernanceClient ( this IServiceCollection services , Func < IServiceProvider , AAuthGovernanceClient > factory )
- Microsoft.Extensions.DependencyInjection: public static class AAuthGovernanceClientServiceCollectionExtensions
```

Public owners: `Microsoft.Extensions.DependencyInjection.AAuthGovernanceClientServiceCollectionExtensions`, `Microsoft.Extensions.DependencyInjection`.

### src/AAuth/DependencyInjection/AAuthGovernanceServiceCollectionExtensions.cs

Concept/decision: [di](#di). Source: [AAuthGovernanceServiceCollectionExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthGovernanceServiceCollectionExtensions.cs).

Public signatures unchanged (4); behavior reviewed under di.

Public owners: `Microsoft.Extensions.DependencyInjection.AAuthGovernanceServiceCollectionExtensions`, `Microsoft.Extensions.DependencyInjection`.

### src/AAuth/DependencyInjection/AAuthPersonServerServiceCollectionExtensions.cs

Concept/decision: [di](#di). Source: [AAuthPersonServerServiceCollectionExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthPersonServerServiceCollectionExtensions.cs).

```diff
+ Microsoft.Extensions.DependencyInjection.AAuthPersonServerBuilder: public AAuthPersonServerBuilder Configure ( Action < AAuthPersonServerOptions > configure )
+ Microsoft.Extensions.DependencyInjection.AAuthPersonServerBuilder: public AAuthPersonServerBuilder UseClaimsAsserter ( Func < IServiceProvider , IIdentityClaimsAsserter > factory )
+ Microsoft.Extensions.DependencyInjection.AAuthPersonServerBuilder: public AAuthPersonServerBuilder UseClaimsAsserter ( IIdentityClaimsAsserter asserter )
+ Microsoft.Extensions.DependencyInjection.AAuthPersonServerBuilder: public AAuthPersonServerBuilder UseClaimsAsserter < T > ( ) where T : class , IIdentityClaimsAsserter
+ Microsoft.Extensions.DependencyInjection.AAuthPersonServerBuilder: public AAuthPersonServerBuilder UsePendingStore ( Func < IServiceProvider , IPersonPendingStore > factory )
+ Microsoft.Extensions.DependencyInjection.AAuthPersonServerBuilder: public AAuthPersonServerBuilder UsePendingStore ( IPersonPendingStore store )
+ Microsoft.Extensions.DependencyInjection.AAuthPersonServerBuilder: public AAuthPersonServerBuilder UsePendingStore < T > ( ) where T : class , IPersonPendingStore
+ Microsoft.Extensions.DependencyInjection.AAuthPersonServerBuilder: public AAuthPersonServerBuilder UseTokenInventory ( IJtiStore inventory )
+ Microsoft.Extensions.DependencyInjection.AAuthPersonServerBuilder: public AAuthPersonServerBuilder UseTokenInventory < T > ( ) where T : class , IJtiStore
+ Microsoft.Extensions.DependencyInjection.AAuthPersonServerBuilder: public AAuthPersonServerBuilder UseTokenVerifier ( TokenVerifier verifier )
+ Microsoft.Extensions.DependencyInjection.AAuthPersonServerBuilder: public AAuthPersonServerBuilder WithFederation ( )
+ Microsoft.Extensions.DependencyInjection.AAuthPersonServerBuilder: public AAuthPersonServerBuilder WithGovernance ( )
+ Microsoft.Extensions.DependencyInjection.AAuthPersonServerBuilder: public AAuthPersonServerBuilder WithTrust ( Action < AAuthTrustOptions > configure )
+ Microsoft.Extensions.DependencyInjection.AAuthPersonServerBuilder: public IServiceCollection Services { get ; }
+ Microsoft.Extensions.DependencyInjection.AAuthPersonServerBuilder: public const string DefaultName = "PersonServer" ;
+ Microsoft.Extensions.DependencyInjection.AAuthPersonServerBuilder: public const string FederationHttpClientName = "aauth-federation" ;
+ Microsoft.Extensions.DependencyInjection.AAuthPersonServerBuilder: public string Name { get ; }
+ Microsoft.Extensions.DependencyInjection.AAuthPersonServerServiceCollectionExtensions: public const string ConfigurationSection = "AAuth:PersonServer" ;
+ Microsoft.Extensions.DependencyInjection.AAuthPersonServerServiceCollectionExtensions: public static AAuthPersonServerBuilder AddAAuthPersonServer ( this IServiceCollection services , IConfiguration configuration , string ? name = null , Action < AAuthPersonServerOptions > ? configure = null )
+ Microsoft.Extensions.DependencyInjection.AAuthPersonServerServiceCollectionExtensions: public static AAuthPersonServerBuilder AddAAuthPersonServer ( this IServiceCollection services , string ? name = null , Action < AAuthPersonServerOptions > ? configure = null )
+ Microsoft.Extensions.DependencyInjection: public sealed class AAuthPersonServerBuilder
+ Microsoft.Extensions.DependencyInjection: public static class AAuthPersonServerServiceCollectionExtensions
```

Public owners: `Microsoft.Extensions.DependencyInjection.AAuthPersonServerBuilder`, `Microsoft.Extensions.DependencyInjection.AAuthPersonServerServiceCollectionExtensions`, `Microsoft.Extensions.DependencyInjection`.

### src/AAuth/DependencyInjection/AAuthResourceOptions.cs

Concept/decision: [di](#di). Source: [AAuthResourceOptions.cs](../../../src/AAuth/DependencyInjection/AAuthResourceOptions.cs).

```diff
- AAuth.AAuthResourceOptions: public Dictionary < string , IAAuthKey > SigningKeys { get ; set ; } = new ( )
- AAuth.AAuthResourceOptions: public Func < DateTimeOffset > ? Clock { get ; set ; }
- AAuth.AAuthResourceOptions: public TimeSpan MaxFutureSkew { get ; set ; } = TimeSpan . FromSeconds ( 5 )
+ AAuth.AAuthResourceOptions: public AAuthSigningKeySet SigningKeys { get ; set ; } = new ( )
+ AAuth.AAuthResourceOptions: public Action < AAuth . Server . AAuthRevocationOptions > ? ConfigureRevocation { get ; set ; }
+ AAuth.AAuthResourceOptions: public TimeProvider TimeProvider { get ; set ; } = TimeProvider . System
+ AAuth.AAuthResourceOptions: public string ? DocumentationUri { get ; set ; }
+ AAuth.AAuthResourceOptions: public string ? KeyHandle { get ; set ; }
+ AAuth.AAuthResourceOptions: public string ? KeyId { get ; set ; }
+ AAuth.AAuthResourceOptions: public string ? LogoDarkUri { get ; set ; }
+ AAuth.AAuthResourceOptions: public string ? LogoUri { get ; set ; }
+ AAuth.AAuthResourceOptions: public string ? PolicyUri { get ; set ; }
+ AAuth.AAuthResourceOptions: public string ? TosUri { get ; set ; }
```

Public owners: `AAuth.AAuthResourceOptions`, `AAuth`.

### src/AAuth/DependencyInjection/AAuthResourcePipelineOptions.cs

Concept/decision: [di](#di). Source: [AAuthResourcePipelineOptions.cs](../../../src/AAuth/DependencyInjection/AAuthResourcePipelineOptions.cs).

```diff
- AAuth.AAuthResourcePipelineOptions: public Func < string , bool > ? IsTrustedAgentProviderIssuer { get ; set ; }
- AAuth.AAuthResourcePipelineOptions: public Func < string , bool > ? IsTrustedAuthTokenIssuer { get ; set ; }
- AAuth.AAuthResourcePipelineOptions: public IReadOnlySet < string > ? TrustedAgentProviderIssuers { get ; set ; }
- AAuth.AAuthResourcePipelineOptions: public IReadOnlySet < string > ? TrustedAuthTokenIssuers { get ; set ; }
+ AAuth.AAuthResourcePipelineOptions: public AAuth . Server . AAuthTrustOptions Trust { get ; set ; } = new ( )
```

Public owners: `AAuth.AAuthResourcePipelineOptions`, `AAuth`.

### src/AAuth/DependencyInjection/AAuthResourceServiceCollectionExtensions.cs

Concept/decision: [di](#di). Source: [AAuthResourceServiceCollectionExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthResourceServiceCollectionExtensions.cs).

```diff
+ Microsoft.Extensions.DependencyInjection.AAuthResourceServiceCollectionExtensions: public const string ConfigurationSection = "AAuth:Resource" ;
+ Microsoft.Extensions.DependencyInjection.AAuthResourceServiceCollectionExtensions: public static IServiceCollection AddAAuthResource ( this IServiceCollection services , IConfiguration configuration , Action < AAuthResourceOptions > ? configure = null )
```

Public owners: `Microsoft.Extensions.DependencyInjection.AAuthResourceServiceCollectionExtensions`, `Microsoft.Extensions.DependencyInjection`.

### src/AAuth/Discovery/JwksClient.cs

Concept/decision: [discovery](#discovery). Source: [JwksClient.cs](../../../src/AAuth/Discovery/JwksClient.cs).

```diff
- AAuth.Discovery.JwksClient: public JwksClient ( HttpClient ? http = null , TimeSpan ? cacheTtl = null , TimeSpan ? minRefreshInterval = null , Func < DateTimeOffset > ? clock = null , int maxCacheEntries = 1024 , TimeSpan ? maxCacheAge = null , AAuthEgressPolicy ? policy = null , AAuthTransportContract ? transportContract = null )
+ AAuth.Discovery.JwksClient: public JwksClient ( HttpClient ? http = null , TimeSpan ? cacheTtl = null , TimeSpan ? minRefreshInterval = null , TimeProvider ? timeProvider = null , int maxCacheEntries = 1024 , TimeSpan ? maxCacheAge = null , AAuthEgressPolicy ? policy = null , AAuthTransportContract ? transportContract = null )
```

Public owners: `AAuth.Discovery.JwksClient`, `AAuth.Discovery`.

### src/AAuth/Discovery/MetadataClient.cs

Concept/decision: [discovery](#discovery). Source: [MetadataClient.cs](../../../src/AAuth/Discovery/MetadataClient.cs).

```diff
- AAuth.Discovery.MetadataClient: public MetadataClient ( HttpClient ? http = null , TimeSpan ? cacheTtl = null , Func < DateTimeOffset > ? clock = null , AAuthEgressPolicy ? policy = null , AAuthTransportContract ? transportContract = null , int maxCacheEntries = 1024 , TimeSpan ? maxCacheAge = null )
+ AAuth.Discovery.MetadataClient: public MetadataClient ( HttpClient ? http = null , TimeSpan ? cacheTtl = null , TimeProvider ? timeProvider = null , AAuthEgressPolicy ? policy = null , AAuthTransportContract ? transportContract = null , int maxCacheEntries = 1024 , TimeSpan ? maxCacheAge = null )
```

Public owners: `AAuth.Discovery.MetadataClient`, `AAuth.Discovery`.

### src/AAuth/Discovery/ServerMetadata.cs

Concept/decision: [discovery](#discovery). Source: [ServerMetadata.cs](../../../src/AAuth/Discovery/ServerMetadata.cs).

```diff
- AAuth.Discovery.ServerMetadata: public string ? TokenEndpoint { get ; init ; }
+ AAuth.Discovery.ServerMetadata: public string ? AuthTokenEndpoint { get ; init ; }
+ AAuth.Discovery.ServerMetadata: public string ? PersonTokenEndpoint { get ; init ; }
```

Public owners: `AAuth.Discovery.MetadataClientExtensions`, `AAuth.Discovery.ResourceMetadata`, `AAuth.Discovery.ServerMetadata`, `AAuth.Discovery`.

### src/AAuth/EnrolledBuilder.cs

Concept/decision: [agent-clients](#agent-clients). Source: [EnrolledBuilder.cs](../../../src/AAuth/EnrolledBuilder.cs).

Public signatures unchanged (20); behavior reviewed under agent-clients.

Public owners: `AAuth.EnrolledBuilder`, `AAuth`.

### src/AAuth/Errors/AAuthMissionTerminatedException.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthMissionTerminatedException.cs](../../../src/AAuth/Errors/AAuthMissionTerminatedException.cs).

```diff
- AAuth.Errors.AAuthMissionTerminatedException: public AAuthMissionTerminatedException ( string ? missionStatus = null )
- AAuth.Errors.AAuthMissionTerminatedException: public AAuthMissionTerminatedException ( string message , string ? missionStatus )
+ AAuth.Errors.AAuthMissionTerminatedException: public AAuthMissionTerminatedException ( string ? missionStatus = null , string ? terminationReason = null )
+ AAuth.Errors.AAuthMissionTerminatedException: public AAuthMissionTerminatedException ( string message , string ? missionStatus , string ? terminationReason = null )
+ AAuth.Errors.AAuthMissionTerminatedException: public string ? TerminationReason { get ; }
```

Public owners: `AAuth.Errors.AAuthMissionTerminatedException`, `AAuth.Errors`.

### src/AAuth/Errors/PollingError.cs

Concept/decision: [server-contracts](#server-contracts). Source: [PollingError.cs](../../../src/AAuth/Errors/PollingError.cs).

```diff
- AAuth.Errors.PollingErrorException: public PollingErrorException ( PollingErrorCode errorCode , int statusCode , string ? message = null )
+ AAuth.Errors.PollingErrorCode: Revoked
+ AAuth.Errors.PollingErrorException: public PollingErrorException ( PollingErrorCode errorCode , int statusCode , string ? message = null , string ? detail = null )
+ AAuth.Errors.PollingErrorException: public string ? Detail { get ; }
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

### src/AAuth/Headers/Interaction.cs

Concept/decision: [server-contracts](#server-contracts). Source: [Interaction.cs](../../../src/AAuth/Headers/Interaction.cs).

```diff
+ AAuth.Headers.Interaction: public InteractionSource Source { get ; init ; }
+ AAuth.Headers.InteractionSource: PersonServer
+ AAuth.Headers.InteractionSource: Resource
+ AAuth.Headers: public enum InteractionSource
```

Public owners: `AAuth.Headers.InteractionSource`, `AAuth.Headers.Interaction`, `AAuth.Headers`.

### src/AAuth/HttpSig/AAuthHttpClientExtensions.cs

Concept/decision: [signatures](#signatures). Source: [AAuthHttpClientExtensions.cs](../../../src/AAuth/HttpSig/AAuthHttpClientExtensions.cs).

```diff
- AAuth.HttpSig.AAuthClientOptions: public IAAuthKey Key { get ; set ; } = null !
- AAuth.HttpSig.AAuthClientOptions: public IReadOnlyList < string > ? Capabilities { get ; set ; }
- AAuth.HttpSig.AAuthClientOptions: public ISignatureKeyProvider SigningMode { get ; set ; } = null !
+ AAuth.HttpSig.AAuthClientOptions: public IAAuthSigner ? Signer { get ; set ; }
+ AAuth.HttpSig.AAuthClientOptions: public ISignatureKeyProvider ? SignatureKeyProvider { get ; set ; }
+ AAuth.HttpSig.AAuthClientOptions: public string ? KeyHandle { get ; set ; }
+ AAuth.HttpSig.AAuthClientOptions: public string [  ] ? Capabilities { get ; set ; }
```

Public owners: `AAuth.HttpSig.AAuthClientOptions`, `AAuth.HttpSig.AAuthHttpClientExtensions`, `AAuth.HttpSig`.

### src/AAuth/HttpSig/AAuthSigningHandler.cs

Concept/decision: [signatures](#signatures). Source: [AAuthSigningHandler.cs](../../../src/AAuth/HttpSig/AAuthSigningHandler.cs).

```diff
- AAuth.HttpSig.AAuthSigningHandler: public AAuthSigningHandler ( IAAuthKey key , Func < string > tokenFactory , Func < DateTimeOffset > ? clock = null )
- AAuth.HttpSig.AAuthSigningHandler: public AAuthSigningHandler ( IAAuthKey key , ISignatureKeyProvider signatureKeyProvider , Func < DateTimeOffset > ? clock = null )
- AAuth.HttpSig.AAuthSigningHandler: public static HttpClient CreateClient ( IAAuthKey key , ISignatureKeyProvider provider , HttpMessageHandler ? innerHandler = null )
- AAuth.HttpSig.AAuthSigningHandler: public void Sign ( HttpRequestMessage request )
+ AAuth.HttpSig.AAuthSigningHandler: public AAuthSigningHandler ( IAAuthSigner key , Func < string > tokenFactory , TimeProvider ? timeProvider = null )
+ AAuth.HttpSig.AAuthSigningHandler: public AAuthSigningHandler ( IAAuthSigner key , ISignatureKeyProvider signatureKeyProvider , TimeProvider ? timeProvider = null )
+ AAuth.HttpSig.AAuthSigningHandler: public async Task SignHeadersAsync ( HttpRequestMessage request , CancellationToken cancellationToken = default )
+ AAuth.HttpSig.AAuthSigningHandler: public static HttpClient CreateClient ( IAAuthSigner key , ISignatureKeyProvider provider , HttpMessageHandler ? innerHandler = null )
```

Public owners: `AAuth.HttpSig.AAuthSigningHandler`, `AAuth.HttpSig`.

### src/AAuth/HttpSig/AAuthVerifier.cs

Concept/decision: [signatures](#signatures). Source: [AAuthVerifier.cs](../../../src/AAuth/HttpSig/AAuthVerifier.cs).

```diff
- AAuth.HttpSig.AAuthVerifier: public Func < DateTimeOffset > Clock { get ; init ; } = ( ) => DateTimeOffset . UtcNow
- AAuth.HttpSig.AAuthVerifier: public TimeSpan MaxFutureSkew { get ; init ; } = TimeSpan . FromSeconds ( 5 )
- AAuth.HttpSig.AAuthVerifier: public string Verify ( string method , string authority , string path , string signatureKey , string signatureInput , string signatureHeader , IAAuthKey publicKey , string ? authorization = null , string ? mission = null , string label = "sig" , IReadOnlyDictionary < string , string > ? fields = null , IReadOnlyCollection < string > ? requiredComponents = null , string ? keyId = null , IReadOnlyDictionary < string , string [  ] > ? fieldValues = null , string ? requestScheme = null , string ? query = null , string ? requestTarget = null )
+ AAuth.HttpSig.AAuthVerifier: public TimeProvider TimeProvider { get ; init ; } = TimeProvider . System
+ AAuth.HttpSig.AAuthVerifier: public string Verify ( string method , string authority , string path , string signatureKey , string signatureInput , string signatureHeader , IAAuthKey publicKey , string ? authorization = null , string label = "sig" , IReadOnlyDictionary < string , string > ? fields = null , IReadOnlyCollection < string > ? requiredComponents = null , string ? keyId = null , IReadOnlyDictionary < string , string [  ] > ? fieldValues = null , string ? requestScheme = null , string ? query = null , string ? requestTarget = null )
```

Public owners: `AAuth.HttpSig.AAuthVerificationException`, `AAuth.HttpSig.AAuthVerifier`, `AAuth.HttpSig`.

### src/AAuth/HttpSig/DefaultSignatureKeyResolver.cs

Concept/decision: [signatures](#signatures). Source: [DefaultSignatureKeyResolver.cs](../../../src/AAuth/HttpSig/DefaultSignatureKeyResolver.cs).

Public signatures unchanged (3); behavior reviewed under signatures.

Public owners: `AAuth.HttpSig.DefaultSignatureKeyResolver`, `AAuth.HttpSig`.

### src/AAuth/HttpSig/InteractionHandlingOptions.cs

Concept/decision: [signatures](#signatures). Source: [InteractionHandlingOptions.cs](../../../src/AAuth/HttpSig/InteractionHandlingOptions.cs).

```diff
- AAuth.HttpSig.InteractionHandlingOptions: public Func < string , string , CancellationToken , Task > ? OnInteractionRequired { get ; set ; }
+ AAuth.HttpSig.InteractionHandlingOptions: public Func < AAuth . Headers . Interaction , CancellationToken , Task > ? OnInteractionRequired { get ; set ; }
```

Public owners: `AAuth.HttpSig.InteractionHandlingOptions`, `AAuth.HttpSig`.

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
- AAuth.Person.AAuthPersonServerEndpoints: public static WebApplication MapAAuthPersonServer ( this WebApplication app , AAuthPersonServerOptions options )
- AAuth.Person.AAuthPersonServerOptions: public AAuthEgressPolicy EgressPolicy { get ; init ; } = AAuthEgressPolicy . Production
- AAuth.Person.AAuthPersonServerOptions: public Action < AAuthRevocationOptions > ? ConfigureRevocation { get ; init ; }
- AAuth.Person.AAuthPersonServerOptions: public BrowserConsentSessions ? ResourceInteractionSessions { get ; init ; }
- AAuth.Person.AAuthPersonServerOptions: public Func < PersonPendingEntry , ClarificationRequirement , System . Threading . CancellationToken , Task < ClarificationResponse ? > > ? TriageClarificationAsync { get ; init ; }
- AAuth.Person.AAuthPersonServerOptions: public Func < string , bool > ? IsTrustedAccessServer { get ; init ; }
- AAuth.Person.AAuthPersonServerOptions: public IReadOnlyCollection < string > ? TrustedAccessServers { get ; init ; }
- AAuth.Person.AAuthPersonServerOptions: public IReadOnlyCollection < string > ? UnsignedPathPrefixes { get ; init ; }
- AAuth.Person.AAuthPersonServerOptions: public IReadOnlyList < string > ? ScopesSupported { get ; init ; }
- AAuth.Person.AAuthPersonServerOptions: public TimeProvider TimeProvider { get ; init ; } = TimeProvider . System
- AAuth.Person.AAuthPersonServerOptions: public required IReadOnlyDictionary < string , IAAuthKey > SigningKeys { get ; init ; }
- AAuth.Person.AAuthPersonServerOptions: public required string Issuer { get ; init ; }
- AAuth.Person.AAuthPersonServerOptions: public string ? AuditEndpoint { get ; init ; }
- AAuth.Person.AAuthPersonServerOptions: public string ? InteractionEndpoint { get ; init ; }
- AAuth.Person.AAuthPersonServerOptions: public string ? MissionEndpoint { get ; init ; }
- AAuth.Person.AAuthPersonServerOptions: public string ? PermissionEndpoint { get ; init ; }
- AAuth.Person.AAuthPersonServerOptions: public string DefaultScope { get ; init ; } = ""
- AAuth.Person.AAuthPersonServerOptions: public string InteractionPath { get ; init ; } = "/interaction"
- AAuth.Person.AAuthPersonServerOptions: public string PendingPathPrefix { get ; init ; } = "/pending"
- AAuth.Person.AAuthPersonServerOptions: public string RevocationPath { get ; init ; } = "/revoke"
- AAuth.Person.AAuthPersonServerOptions: public string TokenPath { get ; init ; } = "/token"
+ AAuth.Person.AAuthPersonServerEndpoints: public static WebApplication MapAAuthPersonServer ( this WebApplication app , string ? name = null )
+ AAuth.Person.AAuthPersonServerOptions: public AAuthEgressPolicy EgressPolicy { get ; set ; } = AAuthEgressPolicy . Production
+ AAuth.Person.AAuthPersonServerOptions: public AAuthSigningKeySet SigningKeys { get ; set ; } = new ( )
+ AAuth.Person.AAuthPersonServerOptions: public AAuthTrustOptions Trust { get ; set ; } = new ( )
+ AAuth.Person.AAuthPersonServerOptions: public Action < AAuthRevocationOptions > ? ConfigureRevocation { get ; set ; }
+ AAuth.Person.AAuthPersonServerOptions: public BrowserConsentSessions ? ResourceInteractionSessions { get ; set ; }
+ AAuth.Person.AAuthPersonServerOptions: public Func < PersonPendingEntry , ClarificationRequirement , System . Threading . CancellationToken , Task < ClarificationResponse ? > > ? TriageClarificationAsync { get ; set ; }
+ AAuth.Person.AAuthPersonServerOptions: public IReadOnlyCollection < string > ? UnsignedPathPrefixes { get ; set ; }
+ AAuth.Person.AAuthPersonServerOptions: public IReadOnlyList < string > ? ScopesSupported { get ; set ; }
+ AAuth.Person.AAuthPersonServerOptions: public TimeProvider TimeProvider { get ; set ; } = TimeProvider . System
+ AAuth.Person.AAuthPersonServerOptions: public bool MatchIssuerHost { get ; set ; }
+ AAuth.Person.AAuthPersonServerOptions: public string ? AuditPath { get ; set ; }
+ AAuth.Person.AAuthPersonServerOptions: public string ? InteractionEndpointPath { get ; set ; }
+ AAuth.Person.AAuthPersonServerOptions: public string ? KeyHandle { get ; set ; }
+ AAuth.Person.AAuthPersonServerOptions: public string ? KeyId { get ; set ; }
+ AAuth.Person.AAuthPersonServerOptions: public string ? MissionPath { get ; set ; }
+ AAuth.Person.AAuthPersonServerOptions: public string ? PermissionPath { get ; set ; }
+ AAuth.Person.AAuthPersonServerOptions: public string DefaultScope { get ; set ; } = ""
+ AAuth.Person.AAuthPersonServerOptions: public string InteractionPath { get ; set ; } = "/interaction"
+ AAuth.Person.AAuthPersonServerOptions: public string Issuer { get ; set ; } = ""
+ AAuth.Person.AAuthPersonServerOptions: public string PendingPathPrefix { get ; set ; } = "/pending"
+ AAuth.Person.AAuthPersonServerOptions: public string PersonTokenPath { get ; set ; } = "/person"
+ AAuth.Person.AAuthPersonServerOptions: public string RevocationPath { get ; set ; } = "/revoke"
+ AAuth.Person.AAuthPersonServerOptions: public string TokenPath { get ; set ; } = "/token"
```

Public owners: `AAuth.Person.AAuthPersonServerEndpoints`, `AAuth.Person.AAuthPersonServerOptions`, `AAuth.Person`.

### src/AAuth/Person/AgentAssertedContent.cs

Concept/decision: [consent](#consent). Source: [AgentAssertedContent.cs](../../../src/AAuth/Person/AgentAssertedContent.cs).

```diff
+ AAuth.Person.AgentAssertedContent: public string ? Device { get ; init ; }
+ AAuth.Person.AgentAssertedContent: public string ? Justification { get ; init ; }
+ AAuth.Person.AgentAssertedContent: public string ? Platform { get ; init ; }
+ AAuth.Person: public sealed record AgentAssertedContent
```

Public owners: `AAuth.Person.AgentAssertedContent`, `AAuth.Person`.

### src/AAuth/Person/AgentPersonBinding.cs

Concept/decision: [consent](#consent). Source: [AgentPersonBinding.cs](../../../src/AAuth/Person/AgentPersonBinding.cs).

```diff
+ AAuth.Person.AgentPersonBinding: public static Task RevokeAsync ( IJtiStore inventory , string personServer , string agentIssuer , string agentId , CancellationToken cancellationToken = default )
+ AAuth.Person.AgentPersonBinding: public static TokenKey Key ( string personServer , string agentIssuer , string agentId )
+ AAuth.Person: public static class AgentPersonBinding
```

Public owners: `AAuth.Person.AgentPersonBinding`, `AAuth.Person`.

### src/AAuth/Person/IIdentityClaimsAsserter.cs

Concept/decision: [consent](#consent). Source: [IIdentityClaimsAsserter.cs](../../../src/AAuth/Person/IIdentityClaimsAsserter.cs).

```diff
- AAuth.Person.IdentityAssertionRequest: public MissionClaim ? Mission { get ; init ; }
+ AAuth.Person.IdentityAssertionRequest: public AgentAssertedContent ? AgentAsserted { get ; init ; }
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
+ AAuth.Person.PersonPendingEntry: public AgentAssertedContent ? AgentAsserted { get ; set ; }
+ AAuth.Person.PersonPendingEntry: public bool PersonToken { get ; set ; }
+ AAuth.Person.PersonPendingEntry: public string ? MissionS256 { get ; set ; }
+ AAuth.Person.PersonPendingEntry: public string ? PersonSubject { get ; set ; }
+ AAuth.Person.PersonPendingEntry: public string ? PersonTenant { get ; set ; }
+ AAuth.Person.PersonPendingEntry: public string ? PresentedToken { get ; set ; }
```

Public owners: `AAuth.Person.IPersonPendingStore`, `AAuth.Person.InMemoryPersonPendingStore`, `AAuth.Person.PersonPendingEntry`, `AAuth.Person.PersonPendingStatus`, `AAuth.Person`.

### src/AAuth/SelfIssuingBuilder.cs

Concept/decision: [agent-clients](#agent-clients). Source: [SelfIssuingBuilder.cs](../../../src/AAuth/SelfIssuingBuilder.cs).

Public signatures unchanged (19); behavior reviewed under agent-clients.

Public owners: `AAuth.SelfIssuingBuilder`, `AAuth`.

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
+ AAuth.Server.AAuthRevocationOptions: public RevocationLimits ? Limits { get ; set ; } = new ( )
+ AAuth.Server.AAuthRevocationOptions: public TimeSpan DeferAfter { get ; set ; } = TimeSpan . FromSeconds ( 20 )
+ AAuth.Server.AAuthRevocationOptions: public TimeSpan MaxTokenLifetime { get ; set ; } = TimeSpan . FromHours ( 24 )
+ AAuth.Server.AAuthRevocationOptions: public bool ReportDownstream { get ; set ; } = true
```

Public owners: `AAuth.Server.AAuthRevocationOptions`, `AAuth.Server`.

### src/AAuth/Server/AAuthRevocationService.cs

Concept/decision: [revocation](#revocation). Source: [AAuthRevocationService.cs](../../../src/AAuth/Server/AAuthRevocationService.cs).

```diff
+ AAuth.Server.IAAuthRevocationService: Task < RevocationCascadeResult > CascadeAsync ( TokenKey token , DateTimeOffset expiresAt , CancellationToken cancellationToken = default )
+ AAuth.Server.IAAuthRevocationService: Task < RevocationCascadeResult > RevokeAgentAsync ( string agentIssuer , string sub , CancellationToken cancellationToken = default )
+ AAuth.Server.IAAuthRevocationService: Task < RevocationCascadeResult > RevokeMissionAsync ( string s256 , CancellationToken cancellationToken = default )
+ AAuth.Server.IAAuthRevocationService: Task < RevocationCascadeResult > RevokeTokenAsync ( string jti , CancellationToken cancellationToken = default )
+ AAuth.Server.IAAuthRevocationService: Task < RevocationDownstreamResult > RevokeAtAsync ( Uri endpoint , string jti , DateTimeOffset expiresAt , CancellationToken cancellationToken = default )
+ AAuth.Server: public interface IAAuthRevocationService
```

Public owners: `AAuth.Server.IAAuthRevocationService`, `AAuth.Server`.

### src/AAuth/Server/AAuthServerIdentity.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthServerIdentity.cs](../../../src/AAuth/Server/AAuthServerIdentity.cs).

```diff
+ AAuth.Server.IAAuthServerIdentity: AAuthEgressPolicy EgressPolicy { get ; }
+ AAuth.Server.IAAuthServerIdentity: AAuthSigningKeySet SigningKeys { get ; }
+ AAuth.Server.IAAuthServerIdentity: HttpClient CreateSignedClient ( HttpMessageHandler ? innerHandler = null , AAuthTransportContract ? transportContract = null )
+ AAuth.Server.IAAuthServerIdentity: string Dwk { get ; }
+ AAuth.Server.IAAuthServerIdentity: string Issuer { get ; }
+ AAuth.Server.IAAuthServerIdentity: string Name { get ; }
+ AAuth.Server.IAAuthServerIdentity: string Url ( string path )
+ AAuth.Server: public interface IAAuthServerIdentity
```

Public owners: `AAuth.Server.IAAuthServerIdentity`, `AAuth.Server`.

### src/AAuth/Server/AAuthTrust.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthTrust.cs](../../../src/AAuth/Server/AAuthTrust.cs).

Public signatures unchanged (2); behavior reviewed under server-contracts.

Public owners: `AAuth.Server.AAuthTrust`, `AAuth.Server`.

### src/AAuth/Server/AAuthTrustPolicy.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthTrustPolicy.cs](../../../src/AAuth/Server/AAuthTrustPolicy.cs).

```diff
+ AAuth.Server.AAuthTrustContext: public AAuthTrustContext ( string issuer , AAuthTrustedParty party , IServiceProvider services )
+ AAuth.Server.AAuthTrustContext: public AAuthTrustedParty Party { get ; }
+ AAuth.Server.AAuthTrustContext: public HttpContext ? HttpContext { get ; init ; }
+ AAuth.Server.AAuthTrustContext: public IServiceProvider Services { get ; }
+ AAuth.Server.AAuthTrustContext: public string ? TokenType { get ; init ; }
+ AAuth.Server.AAuthTrustContext: public string Issuer { get ; }
+ AAuth.Server.AAuthTrustOptions: public AAuthTrustRule AccessServers { get ; set ; } = new ( )
+ AAuth.Server.AAuthTrustOptions: public AAuthTrustRule AgentProviders { get ; set ; } = new ( )
+ AAuth.Server.AAuthTrustOptions: public AAuthTrustRule AuthTokenIssuers { get ; set ; } = new ( )
+ AAuth.Server.AAuthTrustOptions: public AAuthTrustRule PersonServers { get ; set ; } = new ( )
+ AAuth.Server.AAuthTrustOptions: public AAuthTrustRule RuleFor ( AAuthTrustedParty party )
+ AAuth.Server.AAuthTrustOptions: public IAAuthTrustPolicy ? Policy { get ; set ; }
+ AAuth.Server.AAuthTrustOptions: public ValueTask < bool > IsTrustedAsync ( AAuthTrustContext context , CancellationToken cancellationToken = default )
+ AAuth.Server.AAuthTrustOptions: public ValueTask < bool > IsTrustedAsync ( string issuer , AAuthTrustedParty party , IServiceProvider services , HttpContext ? httpContext = null , string ? tokenType = null , CancellationToken cancellationToken = default )
+ AAuth.Server.AAuthTrustOptions: public bool IsConfigured ( AAuthTrustedParty party , IServiceProvider ? services = null )
+ AAuth.Server.AAuthTrustRule: public Func < AAuthTrustContext , CancellationToken , ValueTask < bool > > ? PredicateAsync { get ; set ; }
+ AAuth.Server.AAuthTrustRule: public Func < string , bool > ? Predicate { get ; set ; }
+ AAuth.Server.AAuthTrustRule: public IReadOnlySet < string > ? Allowed { get ; set ; }
+ AAuth.Server.AAuthTrustRule: public async ValueTask < bool > EvaluateAsync ( AAuthTrustContext context , CancellationToken cancellationToken = default )
+ AAuth.Server.AAuthTrustRule: public bool IsConfigured
+ AAuth.Server.AAuthTrustedParty: AccessServer
+ AAuth.Server.AAuthTrustedParty: AgentProvider
+ AAuth.Server.AAuthTrustedParty: AuthTokenIssuer
+ AAuth.Server.AAuthTrustedParty: PersonServer
+ AAuth.Server.IAAuthTrustPolicy: ValueTask < bool > IsTrustedAsync ( AAuthTrustContext context , CancellationToken cancellationToken = default )
+ AAuth.Server: public enum AAuthTrustedParty
+ AAuth.Server: public interface IAAuthTrustPolicy
+ AAuth.Server: public sealed class AAuthTrustContext
+ AAuth.Server: public sealed class AAuthTrustOptions
+ AAuth.Server: public sealed class AAuthTrustRule
```

Public owners: `AAuth.Server.AAuthTrustContext`, `AAuth.Server.AAuthTrustOptions`, `AAuth.Server.AAuthTrustRule`, `AAuth.Server.AAuthTrustedParty`, `AAuth.Server.IAAuthTrustPolicy`, `AAuth.Server`.

### src/AAuth/Server/AuthTokenResponse.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AuthTokenResponse.cs](../../../src/AAuth/Server/AuthTokenResponse.cs).

```diff
- AAuth.Server.AuthTokenResponse: public static IResult Create ( Func < string > mint , DateTimeOffset ceiling , TimeProvider ? timeProvider = null )
- AAuth.Server.AuthTokenResponse: public static async Task < IResult > CreateTrackedAsync ( Func < string > mint , DateTimeOffset ceiling , IJtiStore inventory , IReadOnlyCollection < TokenKey > sources , TimeProvider ? timeProvider = null , CancellationToken cancellationToken = default )
+ AAuth.Server.AuthTokenResponse: public static IResult Revoked ( )
+ AAuth.Server.AuthTokenResponse: public static Task < IResult > CreateTrackedAsync ( Func < CancellationToken , ValueTask < string > > mint , DateTimeOffset ceiling , IJtiStore inventory , IReadOnlyCollection < TokenRegistration > sources , string member , TimeProvider ? timeProvider = null , CancellationToken cancellationToken = default , IResult ? ceilingExpired = null )
+ AAuth.Server.AuthTokenResponse: public static async Task < IResult > CreateAsync ( Func < CancellationToken , ValueTask < string > > mint , DateTimeOffset ceiling , TimeProvider ? timeProvider = null , CancellationToken cancellationToken = default )
+ AAuth.Server.AuthTokenResponse: public static async Task < IResult > CreateTrackedAsync ( Func < CancellationToken , ValueTask < string > > mint , DateTimeOffset ceiling , IJtiStore inventory , IReadOnlyCollection < TokenKey > sources , TimeProvider ? timeProvider = null , CancellationToken cancellationToken = default )
+ AAuth.Server.AuthTokenResponse: public static async Task < IResult > CreateTrackedAsync ( Func < CancellationToken , ValueTask < string > > mint , DateTimeOffset ceiling , IJtiStore inventory , IReadOnlyCollection < TokenKey > sources , string member , TimeProvider ? timeProvider = null , CancellationToken cancellationToken = default )
```

Public owners: `AAuth.Server.AuthTokenResponse`, `AAuth.Server`.

### src/AAuth/Server/BrowserConsentSessions.cs

Concept/decision: [consent](#consent). Source: [BrowserConsentSessions.cs](../../../src/AAuth/Server/BrowserConsentSessions.cs).

```diff
+ AAuth.Server.BrowserInteraction: public void Consume ( )
```

Public owners: `AAuth.Server.BrowserConsentDecision`, `AAuth.Server.BrowserConsentSessions`, `AAuth.Server.BrowserInteraction`, `AAuth.Server`.

### src/AAuth/Server/CallChaining/CallChainingHandler.cs

Concept/decision: [governance](#governance). Source: [CallChainingHandler.cs](../../../src/AAuth/Server/CallChaining/CallChainingHandler.cs).

```diff
- AAuth.Server.CallChaining.CallChainingHandler: public async Task < string > ExchangeForDownstreamAsync ( string upstreamAuthToken , string resourceToken , Func < Interaction , CancellationToken , Task > ? onInteractionRequired = null , DeferredPollerOptions ? pollerOptions = null , CancellationToken cancellationToken = default , string ? account = null )
+ AAuth.Server.CallChaining.CallChainingHandler: public async Task < string > ExchangeForDownstreamAsync ( string upstreamToken , string resourceToken , string presentedToken , Func < Interaction , CancellationToken , Task > ? onInteractionRequired = null , DeferredPollerOptions ? pollerOptions = null , CancellationToken cancellationToken = default , string ? account = null )
```

Public owners: `AAuth.Server.CallChaining.CallChainingHandler`, `AAuth.Server.CallChaining`.

### src/AAuth/Server/CallChaining/CallChainingOptions.cs

Concept/decision: [governance](#governance). Source: [CallChainingOptions.cs](../../../src/AAuth/Server/CallChaining/CallChainingOptions.cs).

```diff
- AAuth.Server.CallChaining.CallChainingOptions: public Func < HttpClient > ? HttpClientFactory { get ; init ; }
- AAuth.Server.CallChaining.CallChainingOptions: public required IAAuthKey AgentKey { get ; init ; }
- AAuth.Server.CallChaining.CallChainingOptions: public required ISignatureKeyProvider SignatureKeyProvider { get ; init ; }
+ AAuth.Server.CallChaining.CallChainingOptions: public Func < HttpClient > ? HttpClientFactory { get ; set ; }
+ AAuth.Server.CallChaining.CallChainingOptions: public required IAAuthSigner AgentKey { get ; set ; }
+ AAuth.Server.CallChaining.CallChainingOptions: public required ISignatureKeyProvider SignatureKeyProvider { get ; set ; }
```

Public owners: `AAuth.Server.CallChaining.CallChainingOptions`, `AAuth.Server.CallChaining`.

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
+ AAuth.Server.Challenge.AAuthChallengeMiddleware: public static async ValueTask < string > BuildResourceTokenAsync ( ChallengeOptions options , AAuthVerifiedAssertion presented , string ? scope , string ? account = null , IReadOnlyDictionary < string , string > ? scopeDescriptions = null , IReadOnlyCollection < string > ? personServerScopes = null , Interaction ? interaction = null , string ? loginHint = null , CancellationToken cancellationToken = default )
```

Public owners: `AAuth.Server.Challenge.AAuthChallengeMiddleware`, `AAuth.Server.Challenge`.

### src/AAuth/Server/Challenge/ChallengeOptions.cs

Concept/decision: [server-contracts](#server-contracts). Source: [ChallengeOptions.cs](../../../src/AAuth/Server/Challenge/ChallengeOptions.cs).

```diff
- AAuth.Server.Challenge.ChallengeOptions: public AAuthAccessMode AccessMode { get ; init ; } = AAuthAccessMode . RequireAuthToken
- AAuth.Server.Challenge.ChallengeOptions: public IAAuthKey ? ResourceSigningKey { get ; init ; }
- AAuth.Server.Challenge.ChallengeOptions: public IReadOnlyDictionary < string , string > ? ScopeDescriptions { get ; init ; }
- AAuth.Server.Challenge.ChallengeOptions: public IReadOnlySet < string > ? AllowedSignatureKeySchemes { get ; init ; }
- AAuth.Server.Challenge.ChallengeOptions: public System . Func < Microsoft . AspNetCore . Http . HttpContext , string ? > ? RequestedAccount { get ; init ; }
- AAuth.Server.Challenge.ChallengeOptions: public bool MissionAware { get ; init ; }
- AAuth.Server.Challenge.ChallengeOptions: public string ? DefaultScopes { get ; init ; }
- AAuth.Server.Challenge.ChallengeOptions: public string ? PersonServerAudience { get ; init ; }
- AAuth.Server.Challenge.ChallengeOptions: public string ? ResourceIdentifier { get ; init ; }
- AAuth.Server.Challenge.ChallengeOptions: public string ? ResourceKeyId { get ; init ; }
+ AAuth.Server.Challenge.ChallengeOptions: public AAuthAccessMode AccessMode { get ; set ; } = AAuthAccessMode . RequireAuthToken
+ AAuth.Server.Challenge.ChallengeOptions: public AAuthSigningKeySet ? ResourceSigningKeys { get ; set ; }
+ AAuth.Server.Challenge.ChallengeOptions: public IReadOnlyDictionary < string , string > ? ScopeDescriptions { get ; set ; }
+ AAuth.Server.Challenge.ChallengeOptions: public IReadOnlySet < string > ? AllowedSignatureKeySchemes { get ; set ; }
+ AAuth.Server.Challenge.ChallengeOptions: public System . Func < Microsoft . AspNetCore . Http . HttpContext , string ? > ? RequestedAccount { get ; set ; }
+ AAuth.Server.Challenge.ChallengeOptions: public string ? AccessServer { get ; set ; }
+ AAuth.Server.Challenge.ChallengeOptions: public string ? DefaultScopes { get ; set ; }
+ AAuth.Server.Challenge.ChallengeOptions: public string ? ResourceIdentifier { get ; set ; }
```

Public owners: `AAuth.Server.Challenge.ChallengeOptions`, `AAuth.Server.Challenge`.

### src/AAuth/Server/Endpoints/AAuthEndpointExtensions.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthEndpointExtensions.cs](../../../src/AAuth/Server/Endpoints/AAuthEndpointExtensions.cs).

```diff
- Microsoft.AspNetCore.Builder.AAuthEndpointExtensions: public static RouteHandlerBuilder RequireAAuth ( this RouteHandlerBuilder builder , string ? scope = null , string ? role = null , bool missionAware = false )
+ Microsoft.AspNetCore.Builder.AAuthEndpointExtensions: public static RouteHandlerBuilder RequireAAuth ( this RouteHandlerBuilder builder , string ? scope = null , string ? role = null , IAAuthTrustPolicy ? trust = null )
```

Public owners: `Microsoft.AspNetCore.Builder.AAuthEndpointExtensions`, `Microsoft.AspNetCore.Builder`.

### src/AAuth/Server/Endpoints/AAuthEndpointRequirement.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthEndpointRequirement.cs](../../../src/AAuth/Server/Endpoints/AAuthEndpointRequirement.cs).

```diff
- AAuth.Server.Endpoints.AAuthEndpointRequirement: public bool MissionAware { get ; init ; }
- AAuth.Server.Endpoints.AAuthServerOptions: public Func < string , bool > ? IsTrustedAgentProviderIssuer { get ; set ; }
- AAuth.Server.Endpoints.AAuthServerOptions: public Func < string , bool > ? IsTrustedAuthTokenIssuer { get ; set ; }
- AAuth.Server.Endpoints.AAuthServerOptions: public IAAuthKey ? ResourceSigningKey { get ; set ; }
- AAuth.Server.Endpoints.AAuthServerOptions: public IReadOnlySet < string > ? TrustedAgentProviderIssuers { get ; set ; }
- AAuth.Server.Endpoints.AAuthServerOptions: public IReadOnlySet < string > ? TrustedAuthTokenIssuers { get ; set ; }
- AAuth.Server.Endpoints.AAuthServerOptions: public string ? PersonServerAudience { get ; set ; }
- AAuth.Server.Endpoints.AAuthServerOptions: public string ? ResourceKeyId { get ; set ; }
+ AAuth.Server.Endpoints.AAuthEndpointRequirement: public IAAuthTrustPolicy ? Trust { get ; init ; }
+ AAuth.Server.Endpoints.AAuthServerOptions: public AAuthSigningKeySet ? ResourceSigningKeys { get ; set ; }
+ AAuth.Server.Endpoints.AAuthServerOptions: public AAuthTrustOptions Trust { get ; set ; } = new ( )
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
- AAuth.Server.Governance.GovernanceEndpoints: public static IResult MissionTerminated ( string missionStatus = "terminated" )
- AAuth.Server.Governance.GovernanceEndpoints: public static InteractionRequest ParseInteraction ( JsonObject body , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
- AAuth.Server.Governance.GovernanceEndpoints: public static JsonObject MissionTerminatedBody ( string missionStatus = "terminated" )
- AAuth.Server.Governance.GovernanceEndpoints: public static MissionProposal ParseMissionProposal ( JsonObject body )
- AAuth.Server.Governance.GovernanceEndpoints: public static PermissionRequest ParsePermission ( JsonObject body , AAuth . Discovery . AAuthEgressPolicy ? policy = null )
+ AAuth.Server.Governance.GovernanceEndpoints: public static AuditRecord ParseAudit ( JsonObject body )
+ AAuth.Server.Governance.GovernanceEndpoints: public static IResult ? Authorize ( HttpContext context , string ? missionS256 , StoredMission ? mission )
+ AAuth.Server.Governance.GovernanceEndpoints: public static IResult MissionTerminated ( string ? terminationReason = null )
+ AAuth.Server.Governance.GovernanceEndpoints: public static InteractionRequest ParseInteraction ( JsonObject body )
+ AAuth.Server.Governance.GovernanceEndpoints: public static JsonObject MissionTerminatedBody ( string ? terminationReason = null )
+ AAuth.Server.Governance.GovernanceEndpoints: public static MissionProposal ParseMissionProposal ( JsonObject body , AAuth . Discovery . AAuthEgressPolicy ? egressPolicy = null )
+ AAuth.Server.Governance.GovernanceEndpoints: public static PermissionRequest ParsePermission ( JsonObject body )
```

Public owners: `AAuth.Server.Governance.GovernanceEndpoints`, `AAuth.Server.Governance`.

### src/AAuth/Server/Governance/IDeferredConsentStore.cs

Concept/decision: [consent](#consent). Source: [IDeferredConsentStore.cs](../../../src/AAuth/Server/Governance/IDeferredConsentStore.cs).

```diff
- AAuth.Server.Governance.DeferredConsent: public string Approver { get ; init ; } = string . Empty
+ AAuth.Server.Governance.DeferredConsent: public DateTimeOffset ? MissionExpiresAt { get ; init ; }
+ AAuth.Server.Governance.DeferredConsent: public IReadOnlyList < string > ? MissionApprovedResources { get ; init ; }
+ AAuth.Server.Governance.DeferredConsent: public string PersonServer { get ; init ; } = string . Empty
```

Public owners: `AAuth.Server.Governance.DeferredConsentKind`, `AAuth.Server.Governance.DeferredConsent`, `AAuth.Server.Governance.IDeferredConsentStore`, `AAuth.Server.Governance`.

### src/AAuth/Server/Governance/IMissionApprover.cs

Concept/decision: [governance](#governance). Source: [IMissionApprover.cs](../../../src/AAuth/Server/Governance/IMissionApprover.cs).

```diff
- AAuth.Server.Governance: public sealed record MissionApprovalContext ( string Agent , string Approver , MissionProposal Proposal )
+ AAuth.Server.Governance.MissionApprovalDecision: public IReadOnlyList < string > ? ApprovedResources { get ; init ; }
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
+ AAuth.Server.Governance.MissionTokenConsentContext: public AAuth . Person . AgentAssertedContent ? AgentAsserted { get ; init ; }
+ AAuth.Server.Governance.MissionTokenConsentContext: public IReadOnlyList < MissionLogEntry > AcceptedUpdates { get ; internal init ; } = Array . Empty < MissionLogEntry > ( )
+ AAuth.Server.Governance.MissionTokenConsentContext: public required string MissionS256 { get ; init ; }
```

Public owners: `AAuth.Server.Governance.IMissionTokenConsent`, `AAuth.Server.Governance.MissionTokenConsentContext`, `AAuth.Server.Governance.MissionTokenConsentDecision`, `AAuth.Server.Governance.MissionTokenConsentKind`, `AAuth.Server.Governance.MissionTokenConsentStage`, `AAuth.Server.Governance`.

### src/AAuth/Server/Governance/InMemoryMissionStore.cs

Concept/decision: [governance](#governance). Source: [InMemoryMissionStore.cs](../../../src/AAuth/Server/Governance/InMemoryMissionStore.cs).

Public signatures unchanged (4); behavior reviewed under governance.

Public owners: `AAuth.Server.Governance.InMemoryMissionStore`, `AAuth.Server.Governance`.

### src/AAuth/Server/Governance/MissionApprovalBuilder.cs

Concept/decision: [governance](#governance). Source: [MissionApprovalBuilder.cs](../../../src/AAuth/Server/Governance/MissionApprovalBuilder.cs).

```diff
- AAuth.Server.Governance.MissionApprovalBuilder: public static ( byte [  ] Blob , string S256 ) Build ( string approver , string agent , MissionProposal proposal , IReadOnlyList < MissionTool > approvedTools , DateTimeOffset approvedAt )
+ AAuth.Server.Governance.MissionApprovalBuilder: public static ( byte [  ] Blob , string S256 ) Build ( string agent , MissionProposal proposal , IReadOnlyList < MissionTool > approvedTools , DateTimeOffset approvedAt , DateTimeOffset ? expiresAt = null , IReadOnlyList < string > ? approvedResources = null )
+ AAuth.Server.Governance.MissionApprovalBuilder: public static JsonObject Response ( ReadOnlySpan < byte > blob , string s256 , IReadOnlyList < string > ? capabilities = null , IReadOnlyDictionary < string , string > ? personTokens = null )
```

Public owners: `AAuth.Server.Governance.MissionApprovalBuilder`, `AAuth.Server.Governance`.

### src/AAuth/Server/Governance/MissionPersonTokenExtensions.cs

Concept/decision: [governance](#governance). Source: [MissionPersonTokenExtensions.cs](../../../src/AAuth/Server/Governance/MissionPersonTokenExtensions.cs).

```diff
+ AAuth.Server.Governance.MissionPersonTokenExtensions: public static async Task < IReadOnlyDictionary < string , string > ? > IssueMissionPersonTokensAsync ( this HttpContext context , string personServer , string missionS256 , IReadOnlyList < string > resources , DateTimeOffset ? expiresAt = null )
+ AAuth.Server.Governance: public static class MissionPersonTokenExtensions
```

Public owners: `AAuth.Server.Governance.MissionPersonTokenExtensions`, `AAuth.Server.Governance`.

### src/AAuth/Server/HeldInvocations.cs

Concept/decision: [server-contracts](#server-contracts). Source: [HeldInvocations.cs](../../../src/AAuth/Server/HeldInvocations.cs).

```diff
+ AAuth.Server.AAuthHeldInvocationExtensions: public static IEndpointConventionBuilder MapAAuthHeldInvocations ( this IEndpointRouteBuilder endpoints )
+ AAuth.Server.AAuthHeldInvocationExtensions: public static IServiceCollection AddAAuthHeldInvocations ( this IServiceCollection services , Action < AAuthHeldInvocationOptions > ? configure = null )
+ AAuth.Server.AAuthHeldInvocationExtensions: public static TBuilder WithHeldInvocation < TBuilder > ( this TBuilder builder , string operation , Func < HttpContext , JsonObject ? , CancellationToken , Task < HeldInvocationResult > > execute , TimeSpan ? pendingLifetime = null ) where TBuilder : IEndpointConventionBuilder
+ AAuth.Server.AAuthHeldInvocationOptions: public TimeProvider TimeProvider { get ; set ; } = TimeProvider . System
+ AAuth.Server.AAuthHeldInvocationOptions: public TimeSpan PendingLifetime { get ; set ; } = TimeSpan . FromMinutes ( 10 )
+ AAuth.Server.AAuthHeldInvocationOptions: public string PathPrefix { get ; set ; } = "/aauth/held"
+ AAuth.Server.AAuthSingleUseGateExtensions: public static async Task < HeldInvocationResult > ExecuteOnceAsync ( this IAAuthSingleUseGate gate , string jti , DateTimeOffset expiresAt , Func < CancellationToken , Task < HeldInvocationResult > > execute , CancellationToken cancellationToken = default )
+ AAuth.Server.HeldInvocation: public string ? ConsumedBy { get ; init ; }
+ AAuth.Server.HeldInvocationResult: public IResult ToResult ( )
+ AAuth.Server.HeldInvocationResult: public static HeldInvocationResult Json ( object value , int statusCode = StatusCodes . Status200OK )
+ AAuth.Server.IAAuthHeldInvocationStore: ValueTask < HeldInvocation ? > GetAsync ( string id , CancellationToken cancellationToken = default )
+ AAuth.Server.IAAuthHeldInvocationStore: ValueTask < bool > TryConsumeAsync ( string id , string jti , DateTimeOffset retainUntil , CancellationToken cancellationToken = default )
+ AAuth.Server.IAAuthHeldInvocationStore: ValueTask AddAsync ( HeldInvocation invocation , CancellationToken cancellationToken = default )
+ AAuth.Server.IAAuthHeldInvocations: Task < IResult > HoldAsync ( HttpContext context , string resourceToken , IReadOnlyCollection < string > requiredScopes , JsonObject ? state = null )
+ AAuth.Server.IAAuthHeldInvocations: Task < IResult > PollAsync ( HttpContext context , string id )
+ AAuth.Server.IAAuthHeldInvocations: string PathPrefix { get ; }
+ AAuth.Server.IAAuthSingleUseGate: ValueTask < HeldInvocationResult ? > GetResultAsync ( string key , CancellationToken cancellationToken = default )
+ AAuth.Server.IAAuthSingleUseGate: ValueTask < SingleUseClaim > TryClaimAsync ( string key , DateTimeOffset expiresAt , CancellationToken cancellationToken = default )
+ AAuth.Server.IAAuthSingleUseGate: ValueTask CompleteAsync ( string key , HeldInvocationResult result , CancellationToken cancellationToken = default )
+ AAuth.Server.IAAuthSingleUseGate: ValueTask ReleaseAsync ( string key , CancellationToken cancellationToken = default )
+ AAuth.Server.InMemoryHeldInvocationStore: public ValueTask < HeldInvocation ? > GetAsync ( string id , CancellationToken cancellationToken = default )
+ AAuth.Server.InMemoryHeldInvocationStore: public ValueTask < bool > TryConsumeAsync ( string id , string jti , DateTimeOffset retainUntil , CancellationToken cancellationToken = default )
+ AAuth.Server.InMemoryHeldInvocationStore: public ValueTask AddAsync ( HeldInvocation invocation , CancellationToken cancellationToken = default )
+ AAuth.Server.InMemorySingleUseGate: public ValueTask < HeldInvocationResult ? > GetResultAsync ( string key , CancellationToken cancellationToken = default )
+ AAuth.Server.InMemorySingleUseGate: public ValueTask < SingleUseClaim > TryClaimAsync ( string key , DateTimeOffset expiresAt , CancellationToken cancellationToken = default )
+ AAuth.Server.InMemorySingleUseGate: public ValueTask CompleteAsync ( string key , HeldInvocationResult result , CancellationToken cancellationToken = default )
+ AAuth.Server.InMemorySingleUseGate: public ValueTask ReleaseAsync ( string key , CancellationToken cancellationToken = default )
+ AAuth.Server: public interface IAAuthHeldInvocationStore
+ AAuth.Server: public interface IAAuthHeldInvocations
+ AAuth.Server: public interface IAAuthSingleUseGate
+ AAuth.Server: public readonly record struct SingleUseClaim ( bool Claimed , HeldInvocationResult ? Result )
+ AAuth.Server: public sealed class AAuthHeldInvocationOptions
+ AAuth.Server: public sealed class InMemoryHeldInvocationStore ( TimeProvider ? timeProvider = null ) : IAAuthHeldInvocationStore
+ AAuth.Server: public sealed class InMemorySingleUseGate ( TimeProvider ? timeProvider = null ) : IAAuthSingleUseGate
+ AAuth.Server: public sealed record HeldInvocation ( string Id , string Operation , string ResourceToken , string AgentJkt , IReadOnlyList < string > RequiredScopes , DateTimeOffset PendingExpiresAt , JsonObject ? State = null )
+ AAuth.Server: public sealed record HeldInvocationEndpointMetadata ( string Operation , Func < HttpContext , JsonObject ? , CancellationToken , Task < HeldInvocationResult > > Execute , TimeSpan ? PendingLifetime = null )
+ AAuth.Server: public sealed record HeldInvocationResult ( int StatusCode , string ? ContentType , byte [  ] Body )
+ AAuth.Server: public static class AAuthHeldInvocationExtensions
+ AAuth.Server: public static class AAuthSingleUseGateExtensions
```

Public owners: `AAuth.Server.AAuthHeldInvocationExtensions`, `AAuth.Server.AAuthHeldInvocationOptions`, `AAuth.Server.AAuthSingleUseGateExtensions`, `AAuth.Server.HeldInvocationResult`, `AAuth.Server.HeldInvocation`, `AAuth.Server.IAAuthHeldInvocationStore`, `AAuth.Server.IAAuthHeldInvocations`, `AAuth.Server.IAAuthSingleUseGate`, `AAuth.Server.InMemoryHeldInvocationStore`, `AAuth.Server.InMemorySingleUseGate`, `AAuth.Server`.

### src/AAuth/Server/IJtiStore.cs

Concept/decision: [revocation](#revocation). Source: [IJtiStore.cs](../../../src/AAuth/Server/IJtiStore.cs).

```diff
- AAuth.Server.IJtiStore: Task < bool > RevokeAsync ( TokenKey token , CancellationToken ct = default )
+ AAuth.Server.IJtiStore: Task < TokenGrant ? > GetGrantAsync ( TokenKey token , CancellationToken ct = default )
+ AAuth.Server.IJtiStore: Task < string ? > GetSubjectAsync ( TokenKey token , CancellationToken ct = default )
+ AAuth.Server.IJtiStore: Task RecordSubjectAsync ( TokenKey token , string subject , CancellationToken ct = default )
+ AAuth.Server.IJtiStore: Task RevokeAsync ( TokenKey token , DateTimeOffset expiresAt , CancellationToken ct = default )
```

Public owners: `AAuth.Server.IJtiStore`, `AAuth.Server`.

### src/AAuth/Server/InMemoryJtiStore.cs

Concept/decision: [revocation](#revocation). Source: [InMemoryJtiStore.cs](../../../src/AAuth/Server/InMemoryJtiStore.cs).

```diff
- AAuth.Server.InMemoryJtiStore: public Task < bool > RevokeAsync ( TokenKey token , CancellationToken ct = default )
+ AAuth.Server.InMemoryJtiStore: public Task < TokenGrant ? > GetGrantAsync ( TokenKey token , CancellationToken ct = default )
+ AAuth.Server.InMemoryJtiStore: public Task < string ? > GetSubjectAsync ( TokenKey token , CancellationToken ct = default )
+ AAuth.Server.InMemoryJtiStore: public Task RecordSubjectAsync ( TokenKey token , string subject , CancellationToken ct = default )
+ AAuth.Server.InMemoryJtiStore: public Task RevokeAsync ( TokenKey token , DateTimeOffset expiresAt , CancellationToken ct = default )
```

Public owners: `AAuth.Server.InMemoryJtiStore`, `AAuth.Server`.

### src/AAuth/Server/Metadata/AAuthAccessServerMetadataOptions.cs

Concept/decision: [resource-managed](#resource-managed). Source: [AAuthAccessServerMetadataOptions.cs](../../../src/AAuth/Server/Metadata/AAuthAccessServerMetadataOptions.cs).

```diff
- AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; init ; } = AAuth . Discovery . AAuthEgressPolicy . Production
- AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public required IReadOnlyDictionary < string , IAAuthKey > SigningKeys { get ; init ; }
- AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public required string Issuer { get ; init ; }
- AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public required string TokenEndpoint { get ; init ; }
- AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public string ? Description { get ; init ; }
- AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public string ? DocumentationUri { get ; init ; }
- AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public string ? LogoDarkUri { get ; init ; }
- AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public string ? LogoUri { get ; init ; }
- AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public string ? Name { get ; init ; }
- AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public string ? PolicyUri { get ; init ; }
- AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public string ? RevocationEndpoint { get ; init ; }
- AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public string ? TosUri { get ; init ; }
+ AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; set ; } = AAuth . Discovery . AAuthEgressPolicy . Production
+ AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public required AAuthSigningKeySet SigningKeys { get ; set ; }
+ AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public required string AuthTokenEndpoint { get ; set ; }
+ AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public required string Issuer { get ; set ; }
+ AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public string ? Description { get ; set ; }
+ AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public string ? DocumentationUri { get ; set ; }
+ AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public string ? LogoDarkUri { get ; set ; }
+ AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public string ? LogoUri { get ; set ; }
+ AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public string ? Name { get ; set ; }
+ AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public string ? PolicyUri { get ; set ; }
+ AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public string ? RevocationEndpoint { get ; set ; }
+ AAuth.Server.Metadata.AAuthAccessServerMetadataOptions: public string ? TosUri { get ; set ; }
```

Public owners: `AAuth.Server.Metadata.AAuthAccessServerMetadataOptions`, `AAuth.Server.Metadata`.

### src/AAuth/Server/Metadata/AAuthAgentMetadataOptions.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthAgentMetadataOptions.cs](../../../src/AAuth/Server/Metadata/AAuthAgentMetadataOptions.cs).

```diff
- AAuth.Server.Metadata.AAuthAgentMetadataOptions: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; init ; } = AAuth . Discovery . AAuthEgressPolicy . Production
- AAuth.Server.Metadata.AAuthAgentMetadataOptions: public required IReadOnlyDictionary < string , IAAuthKey > SigningKeys { get ; init ; }
- AAuth.Server.Metadata.AAuthAgentMetadataOptions: public required string Issuer { get ; init ; }
- AAuth.Server.Metadata.AAuthAgentMetadataOptions: public string ? CallbackEndpoint { get ; init ; }
- AAuth.Server.Metadata.AAuthAgentMetadataOptions: public string ? Description { get ; init ; }
- AAuth.Server.Metadata.AAuthAgentMetadataOptions: public string ? DocumentationUri { get ; init ; }
- AAuth.Server.Metadata.AAuthAgentMetadataOptions: public string ? LoginEndpoint { get ; init ; }
- AAuth.Server.Metadata.AAuthAgentMetadataOptions: public string ? LogoDarkUri { get ; init ; }
- AAuth.Server.Metadata.AAuthAgentMetadataOptions: public string ? LogoUri { get ; init ; }
- AAuth.Server.Metadata.AAuthAgentMetadataOptions: public string ? Name { get ; init ; }
- AAuth.Server.Metadata.AAuthAgentMetadataOptions: public string ? PolicyUri { get ; init ; }
- AAuth.Server.Metadata.AAuthAgentMetadataOptions: public string ? TosUri { get ; init ; }
+ AAuth.Server.Metadata.AAuthAgentMetadataOptions: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; set ; } = AAuth . Discovery . AAuthEgressPolicy . Production
+ AAuth.Server.Metadata.AAuthAgentMetadataOptions: public AAuthSigningKeySet SigningKeys { get ; set ; } = new ( )
+ AAuth.Server.Metadata.AAuthAgentMetadataOptions: public string ? CallbackEndpoint { get ; set ; }
+ AAuth.Server.Metadata.AAuthAgentMetadataOptions: public string ? Description { get ; set ; }
+ AAuth.Server.Metadata.AAuthAgentMetadataOptions: public string ? DocumentationUri { get ; set ; }
+ AAuth.Server.Metadata.AAuthAgentMetadataOptions: public string ? LogoDarkUri { get ; set ; }
+ AAuth.Server.Metadata.AAuthAgentMetadataOptions: public string ? LogoUri { get ; set ; }
+ AAuth.Server.Metadata.AAuthAgentMetadataOptions: public string ? Name { get ; set ; }
+ AAuth.Server.Metadata.AAuthAgentMetadataOptions: public string ? PolicyUri { get ; set ; }
+ AAuth.Server.Metadata.AAuthAgentMetadataOptions: public string ? TosUri { get ; set ; }
+ AAuth.Server.Metadata.AAuthAgentMetadataOptions: public string Issuer { get ; set ; } = ""
```

Public owners: `AAuth.Server.Metadata.AAuthAgentMetadataOptions`, `AAuth.Server.Metadata`.

### src/AAuth/Server/Metadata/AAuthPersonServerMetadataOptions.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthPersonServerMetadataOptions.cs](../../../src/AAuth/Server/Metadata/AAuthPersonServerMetadataOptions.cs).

```diff
- AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; init ; } = AAuth . Discovery . AAuthEgressPolicy . Production
- AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public IReadOnlyList < string > ? ScopesSupported { get ; init ; }
- AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public required IReadOnlyDictionary < string , IAAuthKey > SigningKeys { get ; init ; }
- AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public required string Issuer { get ; init ; }
- AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public required string TokenEndpoint { get ; init ; }
- AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public string ? AuditEndpoint { get ; init ; }
- AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public string ? Description { get ; init ; }
- AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public string ? DocumentationUri { get ; init ; }
- AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public string ? InteractionEndpoint { get ; init ; }
- AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public string ? LogoDarkUri { get ; init ; }
- AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public string ? LogoUri { get ; init ; }
- AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public string ? MissionEndpoint { get ; init ; }
- AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public string ? Name { get ; init ; }
- AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public string ? PermissionEndpoint { get ; init ; }
- AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public string ? PolicyUri { get ; init ; }
- AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public string ? RevocationEndpoint { get ; init ; }
- AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public string ? TosUri { get ; init ; }
+ AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; set ; } = AAuth . Discovery . AAuthEgressPolicy . Production
+ AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public IReadOnlyList < string > ? ScopesSupported { get ; set ; }
+ AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public required AAuthSigningKeySet SigningKeys { get ; set ; }
+ AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public required string AuthTokenEndpoint { get ; set ; }
+ AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public required string Issuer { get ; set ; }
+ AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public required string PersonTokenEndpoint { get ; set ; }
+ AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public string ? AuditEndpoint { get ; set ; }
+ AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public string ? Description { get ; set ; }
+ AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public string ? DocumentationUri { get ; set ; }
+ AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public string ? InteractionEndpoint { get ; set ; }
+ AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public string ? LogoDarkUri { get ; set ; }
+ AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public string ? LogoUri { get ; set ; }
+ AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public string ? MissionEndpoint { get ; set ; }
+ AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public string ? Name { get ; set ; }
+ AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public string ? PermissionEndpoint { get ; set ; }
+ AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public string ? PolicyUri { get ; set ; }
+ AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public string ? RevocationEndpoint { get ; set ; }
+ AAuth.Server.Metadata.AAuthPersonServerMetadataOptions: public string ? TosUri { get ; set ; }
```

Public owners: `AAuth.Server.Metadata.AAuthPersonServerMetadataOptions`, `AAuth.Server.Metadata`.

### src/AAuth/Server/Metadata/WellKnownEndpoints.cs

Concept/decision: [server-contracts](#server-contracts). Source: [WellKnownEndpoints.cs](../../../src/AAuth/Server/Metadata/WellKnownEndpoints.cs).

```diff
- AAuth.Server.Metadata.AAuthResourceMetadataOptions: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; init ; } = AAuth . Discovery . AAuthEgressPolicy . Production
- AAuth.Server.Metadata.AAuthResourceMetadataOptions: public IReadOnlyDictionary < string , IAAuthKey > ? SigningKeys { get ; init ; }
- AAuth.Server.Metadata.AAuthResourceMetadataOptions: public IReadOnlyDictionary < string , JsonNode ? > ? AdditionalMetadata { get ; init ; }
- AAuth.Server.Metadata.AAuthResourceMetadataOptions: public IReadOnlyDictionary < string , string > ? ScopeDescriptions { get ; init ; }
- AAuth.Server.Metadata.AAuthResourceMetadataOptions: public int ? SignatureWindow { get ; init ; }
- AAuth.Server.Metadata.AAuthResourceMetadataOptions: public required string Issuer { get ; init ; }
- AAuth.Server.Metadata.AAuthResourceMetadataOptions: public string ? AccessMode { get ; init ; }
- AAuth.Server.Metadata.AAuthResourceMetadataOptions: public string ? AuthorizationEndpoint { get ; init ; }
- AAuth.Server.Metadata.AAuthResourceMetadataOptions: public string ? Description { get ; init ; }
- AAuth.Server.Metadata.AAuthResourceMetadataOptions: public string ? DocumentationUri { get ; init ; }
- AAuth.Server.Metadata.AAuthResourceMetadataOptions: public string ? LogoDarkUri { get ; init ; }
- AAuth.Server.Metadata.AAuthResourceMetadataOptions: public string ? LogoUri { get ; init ; }
- AAuth.Server.Metadata.AAuthResourceMetadataOptions: public string ? Name { get ; init ; }
- AAuth.Server.Metadata.AAuthResourceMetadataOptions: public string ? PolicyUri { get ; init ; }
- AAuth.Server.Metadata.AAuthResourceMetadataOptions: public string ? RevocationEndpoint { get ; init ; }
- AAuth.Server.Metadata.AAuthResourceMetadataOptions: public string ? TosUri { get ; init ; }
- AAuth.Server.Metadata.WellKnownEndpoints: public static IEndpointRouteBuilder MapAAuthAccessServerWellKnown ( this IEndpointRouteBuilder endpoints , AAuthAccessServerMetadataOptions options )
- AAuth.Server.Metadata.WellKnownEndpoints: public static IEndpointRouteBuilder MapAAuthAgentWellKnown ( this IEndpointRouteBuilder endpoints , AAuthAgentMetadataOptions options )
- AAuth.Server.Metadata.WellKnownEndpoints: public static IEndpointRouteBuilder MapAAuthPersonServerWellKnown ( this IEndpointRouteBuilder endpoints , AAuthPersonServerMetadataOptions options )
- AAuth.Server.Metadata.WellKnownEndpoints: public static IEndpointRouteBuilder MapAAuthResourceWellKnown ( this IEndpointRouteBuilder endpoints , AAuthResourceMetadataOptions options )
+ AAuth.Server.Metadata.AAuthResourceMetadataOptions: public AAuth . Discovery . AAuthEgressPolicy EgressPolicy { get ; set ; } = AAuth . Discovery . AAuthEgressPolicy . Production
+ AAuth.Server.Metadata.AAuthResourceMetadataOptions: public AAuthSigningKeySet ? SigningKeys { get ; set ; }
+ AAuth.Server.Metadata.AAuthResourceMetadataOptions: public IReadOnlyDictionary < string , JsonNode ? > ? AdditionalMetadata { get ; set ; }
+ AAuth.Server.Metadata.AAuthResourceMetadataOptions: public IReadOnlyDictionary < string , string > ? ScopeDescriptions { get ; set ; }
+ AAuth.Server.Metadata.AAuthResourceMetadataOptions: public int ? SignatureWindow { get ; set ; }
+ AAuth.Server.Metadata.AAuthResourceMetadataOptions: public required string Issuer { get ; set ; }
+ AAuth.Server.Metadata.AAuthResourceMetadataOptions: public string ? AccessMode { get ; set ; }
+ AAuth.Server.Metadata.AAuthResourceMetadataOptions: public string ? AuthorizationEndpoint { get ; set ; }
+ AAuth.Server.Metadata.AAuthResourceMetadataOptions: public string ? Description { get ; set ; }
+ AAuth.Server.Metadata.AAuthResourceMetadataOptions: public string ? DocumentationUri { get ; set ; }
+ AAuth.Server.Metadata.AAuthResourceMetadataOptions: public string ? LogoDarkUri { get ; set ; }
+ AAuth.Server.Metadata.AAuthResourceMetadataOptions: public string ? LogoUri { get ; set ; }
+ AAuth.Server.Metadata.AAuthResourceMetadataOptions: public string ? Name { get ; set ; }
+ AAuth.Server.Metadata.AAuthResourceMetadataOptions: public string ? PolicyUri { get ; set ; }
+ AAuth.Server.Metadata.AAuthResourceMetadataOptions: public string ? RevocationEndpoint { get ; set ; }
+ AAuth.Server.Metadata.AAuthResourceMetadataOptions: public string ? TosUri { get ; set ; }
+ AAuth.Server.Metadata.WellKnownEndpoints: public static IEndpointRouteBuilder MapAAuthAgentWellKnown ( this IEndpointRouteBuilder endpoints , Action < AAuthAgentMetadataOptions > configure )
```

Public owners: `AAuth.Server.Metadata.AAuthResourceMetadataOptions`, `AAuth.Server.Metadata.WellKnownEndpoints`, `AAuth.Server.Metadata`.

### src/AAuth/Server/RevocationClient.cs

Concept/decision: [revocation](#revocation). Source: [RevocationClient.cs](../../../src/AAuth/Server/RevocationClient.cs).

```diff
- AAuth.Server.RevocationClient: public async Task < HttpStatusCode > RevokeAsync ( Uri endpoint , TokenKey token , CancellationToken cancellationToken = default )
+ AAuth.Server.RevocationClient: public TimeSpan MaxPollDuration { get ; init ; } = TimeSpan . FromMinutes ( 2 )
+ AAuth.Server.RevocationClient: public async Task < RevocationResult > RevokeAsync ( Uri endpoint , string jti , DateTimeOffset expiresAt , CancellationToken cancellationToken = default )
```

Public owners: `AAuth.Server.RevocationClient`, `AAuth.Server`.

### src/AAuth/Server/RevocationEndpoint.cs

Concept/decision: [revocation](#revocation). Source: [RevocationEndpoint.cs](../../../src/AAuth/Server/RevocationEndpoint.cs).

```diff
- AAuth.Server.RevocationEndpoint: public static IEndpointRouteBuilder MapAAuthRevocationEndpoint ( this IEndpointRouteBuilder endpoints , IJtiStore jtiStore , Action < AAuthRevocationOptions > ? configure , string path = "/revoke" )
- AAuth.Server.RevocationEndpoint: public static IEndpointRouteBuilder MapAAuthRevocationEndpoint ( this IEndpointRouteBuilder endpoints , IJtiStore jtiStore , string path = "/revoke" )
- AAuth.Server.RevocationEndpoint: public static IJtiStore MapAAuthIssuerRevocation ( this WebApplication app , string issuer , string dwk , AAuth . Crypto . IAAuthKey signingKey , string signingKid , string path , AAuth . Discovery . AAuthEgressPolicy egressPolicy , TimeProvider clock , Action < AAuthRevocationOptions > ? configure )
+ AAuth.Server.RevocationEndpoint: public static IEndpointRouteBuilder MapAAuthRevocationEndpoint ( this IEndpointRouteBuilder endpoints , string path = "/revoke" , Action < AAuthRevocationOptions > ? configure = null )
+ AAuth.Server.RevocationEndpoint: public static WebApplication MapAAuthResourceRevocation ( this WebApplication app )
```

Public owners: `AAuth.Server.RevocationEndpoint`, `AAuth.Server`.

### src/AAuth/Server/RevocationLimits.cs

Concept/decision: [revocation](#revocation). Source: [RevocationLimits.cs](../../../src/AAuth/Server/RevocationLimits.cs).

```diff
+ AAuth.Server.RevocationLimits: public TimeSpan Window { get ; set ; } = TimeSpan . FromMinutes ( 1 )
+ AAuth.Server.RevocationLimits: public int MaxEntriesPerIssuer { get ; set ; } = 10_000
+ AAuth.Server.RevocationLimits: public int MaxRequestsPerIssuer { get ; set ; } = 600
+ AAuth.Server: public sealed class RevocationLimits
```

Public owners: `AAuth.Server.RevocationLimits`, `AAuth.Server`.

### src/AAuth/Server/RevocationResult.cs

Concept/decision: [revocation](#revocation). Source: [RevocationResult.cs](../../../src/AAuth/Server/RevocationResult.cs).

```diff
+ AAuth.Server.RevocationCascadeResult: public IReadOnlyList < RevocationDownstreamResult > Downstream { get ; init ; } = [ ]
+ AAuth.Server.RevocationDownstreamResult: public IReadOnlyList < RevocationDownstreamResult > Downstream { get ; init ; } = [ ]
+ AAuth.Server.RevocationResult: public IReadOnlyList < RevocationDownstreamResult > Downstream { get ; init ; } = [ ]
+ AAuth.Server.RevocationResult: public RevocationDownstreamError ? Failure { get ; init ; }
+ AAuth.Server.RevocationResult: public required HttpStatusCode StatusCode { get ; init ; }
+ AAuth.Server.RevocationResult: public string ? Error { get ; init ; }
+ AAuth.Server: public sealed record RevocationCascadeResult
+ AAuth.Server: public sealed record RevocationDownstreamResult ( string Recipient , RevocationDownstreamError ? Error )
+ AAuth.Server: public sealed record RevocationResult
```

Public owners: `AAuth.Server.RevocationCascadeResult`, `AAuth.Server.RevocationDownstreamResult`, `AAuth.Server.RevocationResult`, `AAuth.Server`.

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
- AAuth.Server.Verification.AAuthVerificationOptions: public Func < DateTimeOffset > ? Clock { get ; init ; }
- AAuth.Server.Verification.AAuthVerificationOptions: public Func < Microsoft . AspNetCore . Http . HttpContext , string ? > ? ExpectedAccount { get ; init ; }
- AAuth.Server.Verification.AAuthVerificationOptions: public Func < string , bool > ? IsTrustedAgentProviderIssuer { get ; init ; }
- AAuth.Server.Verification.AAuthVerificationOptions: public Func < string , bool > ? IsTrustedAuthTokenIssuer { get ; init ; }
- AAuth.Server.Verification.AAuthVerificationOptions: public IReadOnlyCollection < string > RequiredComponents { get ; init ; } = [ ]
- AAuth.Server.Verification.AAuthVerificationOptions: public IReadOnlyList < string > AcceptedSchemes { get ; init ; } = [ "jwt" ]
- AAuth.Server.Verification.AAuthVerificationOptions: public IReadOnlySet < string > ? TrustedAgentProviderIssuers { get ; init ; }
- AAuth.Server.Verification.AAuthVerificationOptions: public IReadOnlySet < string > ? TrustedAuthTokenIssuers { get ; init ; }
- AAuth.Server.Verification.AAuthVerificationOptions: public TimeSpan ClockSkew { get ; init ; } = TimeSpan . FromSeconds ( 30 )
- AAuth.Server.Verification.AAuthVerificationOptions: public TimeSpan MaxFutureSkew { get ; init ; } = TimeSpan . FromSeconds ( 5 )
- AAuth.Server.Verification.AAuthVerificationOptions: public bool GenericSignatureKeys { get ; init ; }
- AAuth.Server.Verification.AAuthVerificationOptions: public int MaxActDepth { get ; init ; } = 10
- AAuth.Server.Verification.AAuthVerificationOptions: public static AAuthVerificationOptions Generic ( Func < DateTimeOffset > ? clock = null )
- AAuth.Server.Verification.AAuthVerificationOptions: public string ? ResourceIdentifier { get ; init ; }
- AAuth.Server.Verification.AAuthVerificationOptions: public string SignatureLabel { get ; init ; } = "sig"
+ AAuth.Server.Verification.AAuthVerificationOptions: public AAuthTrustOptions Trust { get ; set ; } = new ( )
+ AAuth.Server.Verification.AAuthVerificationOptions: public Func < Microsoft . AspNetCore . Http . HttpContext , string ? > ? ExpectedAccount { get ; set ; }
+ AAuth.Server.Verification.AAuthVerificationOptions: public IReadOnlyCollection < string > RequiredComponents { get ; set ; } = [ ]
+ AAuth.Server.Verification.AAuthVerificationOptions: public IReadOnlyList < string > AcceptedSchemes { get ; set ; } = [ "jwt" ]
+ AAuth.Server.Verification.AAuthVerificationOptions: public TimeProvider TimeProvider { get ; set ; } = TimeProvider . System
+ AAuth.Server.Verification.AAuthVerificationOptions: public TimeSpan ClockSkew { get ; set ; } = TimeSpan . FromSeconds ( 30 )
+ AAuth.Server.Verification.AAuthVerificationOptions: public bool GenericSignatureKeys { get ; set ; }
+ AAuth.Server.Verification.AAuthVerificationOptions: public bool RequireBodyCoverage { get ; set ; }
+ AAuth.Server.Verification.AAuthVerificationOptions: public static AAuthVerificationOptions Generic ( TimeProvider ? timeProvider = null )
+ AAuth.Server.Verification.AAuthVerificationOptions: public string ? ResourceIdentifier { get ; set ; }
+ AAuth.Server.Verification.AAuthVerificationOptions: public string SignatureLabel { get ; set ; } = "sig"
```

Public owners: `AAuth.Server.Verification.AAuthVerificationOptions`, `AAuth.Server.Verification`.

### src/AAuth/Server/Verification/AAuthVerificationResult.cs

Concept/decision: [signatures](#signatures). Source: [AAuthVerificationResult.cs](../../../src/AAuth/Server/Verification/AAuthVerificationResult.cs).

```diff
- AAuth.Server.Verification.AAuthVerificationResult: public string ? ActorAgent { get ; init ; }
+ AAuth.Server.Verification.AAuthVerificationResult: public IReadOnlySet < string > CoveredComponents { get ; init ; } = new HashSet < string > ( )
+ AAuth.Server.Verification.AAuthVerificationResult: public string ? MissionS256 { get ; init ; }
+ AAuth.Server.Verification.AAuthVerificationResult: public string ? PersonServer { get ; init ; }
+ AAuth.Server.Verification.AAuthVerificationResult: public string ? Tenant { get ; init ; }
```

Public owners: `AAuth.Server.Verification.AAuthVerificationResult`, `AAuth.Server.Verification`.

### src/AAuth/Server/Verification/IssuerTrust.cs

Concept/decision: [signatures](#signatures). Source: [IssuerTrust.cs](../../../src/AAuth/Server/Verification/IssuerTrust.cs).

```diff
- AAuth.Server.Verification.IssuerTrust: public static bool IsTrusted ( IReadOnlyCollection < string > ? set , Func < string , bool > ? policy , string id )
- AAuth.Server.Verification: public static class IssuerTrust
```

Public owners: `AAuth.Server.Verification.IssuerTrust`, `AAuth.Server.Verification`.

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
+ AAuth.Tokens.AgentIssuanceContext: public static async Task < AgentIssuanceContext > VerifyAsync ( string agentToken , string ? subagentToken , string ? upstreamToken , string personServer , TokenVerifier verifier , MetadataClient metadata , JwksClient jwks , Func < string , CancellationToken , ValueTask < bool > > isTrustedAuthTokenIssuer , CancellationToken cancellationToken = default , TokenCredential ? agentTokenCredential = null )
+ AAuth.Tokens.AgentIssuanceContext: public void ValidateResourceContext ( JsonObject resource )
```

Public owners: `AAuth.Tokens.AgentIssuanceContext`, `AAuth.Tokens`.

### src/AAuth/Tokens/AgentTokenBuilder.cs

Concept/decision: [tokens](#tokens). Source: [AgentTokenBuilder.cs](../../../src/AAuth/Tokens/AgentTokenBuilder.cs).

```diff
- AAuth.Tokens.AgentTokenBuilder: public required IAAuthKey Key { get ; init ; }
- AAuth.Tokens.AgentTokenBuilder: public string Build ( )
+ AAuth.Tokens.AgentTokenBuilder: public async ValueTask < string > BuildAsync ( CancellationToken cancellationToken = default )
+ AAuth.Tokens.AgentTokenBuilder: public required IAAuthSigner Key { get ; init ; }
```

Public owners: `AAuth.Tokens.AgentTokenBuilder`, `AAuth.Tokens`.

### src/AAuth/Tokens/AuthTokenBuilder.cs

Concept/decision: [tokens](#tokens). Source: [AuthTokenBuilder.cs](../../../src/AAuth/Tokens/AuthTokenBuilder.cs).

```diff
- AAuth.Tokens.AuthTokenBuilder: public JsonObject ? Act { get ; init ; }
- AAuth.Tokens.AuthTokenBuilder: public MissionClaim ? Mission { get ; init ; }
- AAuth.Tokens.AuthTokenBuilder: public required IAAuthKey Key { get ; init ; }
- AAuth.Tokens.AuthTokenBuilder: public required string Agent { get ; init ; }
- AAuth.Tokens.AuthTokenBuilder: public string ? Subject { get ; init ; }
- AAuth.Tokens.AuthTokenBuilder: public string Build ( )
+ AAuth.Tokens.AuthTokenBuilder: public async ValueTask < string > BuildAsync ( CancellationToken cancellationToken = default )
+ AAuth.Tokens.AuthTokenBuilder: public required IAAuthSigner Key { get ; init ; }
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
+ AAuth.Tokens.PersonTokenBuilder: public async ValueTask < string > BuildAsync ( CancellationToken cancellationToken = default )
+ AAuth.Tokens.PersonTokenBuilder: public const string PersonDwk = "aauth-person.json" ;
+ AAuth.Tokens.PersonTokenBuilder: public const string TokenType = "aa-person+jwt" ;
+ AAuth.Tokens.PersonTokenBuilder: public required DateTimeOffset AgentTokenExpiresAt { get ; init ; }
+ AAuth.Tokens.PersonTokenBuilder: public required IAAuthKey ConfirmationKey { get ; init ; }
+ AAuth.Tokens.PersonTokenBuilder: public required IAAuthSigner Key { get ; init ; }
+ AAuth.Tokens.PersonTokenBuilder: public required string Audience { get ; init ; }
+ AAuth.Tokens.PersonTokenBuilder: public required string Issuer { get ; init ; }
+ AAuth.Tokens.PersonTokenBuilder: public required string KeyId { get ; init ; }
+ AAuth.Tokens.PersonTokenBuilder: public required string Subject { get ; init ; }
+ AAuth.Tokens.PersonTokenBuilder: public string ? MissionS256 { get ; init ; }
+ AAuth.Tokens.PersonTokenBuilder: public string ? Tenant { get ; init ; }
+ AAuth.Tokens.PersonTokenBuilder: public string ? TokenId { get ; init ; }
+ AAuth.Tokens: public sealed class PersonTokenBuilder
```

Public owners: `AAuth.Tokens.PersonTokenBuilder`, `AAuth.Tokens`.

### src/AAuth/Tokens/ResourceTokenBuilder.cs

Concept/decision: [tokens](#tokens). Source: [ResourceTokenBuilder.cs](../../../src/AAuth/Tokens/ResourceTokenBuilder.cs).

```diff
- AAuth.Tokens.ResourceTokenBuilder: public MissionClaim ? Mission { get ; init ; }
- AAuth.Tokens.ResourceTokenBuilder: public required IAAuthKey Key { get ; init ; }
- AAuth.Tokens.ResourceTokenBuilder: public required string Agent { get ; init ; }
- AAuth.Tokens.ResourceTokenBuilder: public string Build ( )
+ AAuth.Tokens.ResourceTokenBuilder: public async ValueTask < string > BuildAsync ( CancellationToken cancellationToken = default )
+ AAuth.Tokens.ResourceTokenBuilder: public required IAAuthSigner Key { get ; init ; }
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
- AAuth.Tokens.TokenVerifier: public Func < DateTimeOffset > Clock { get ; init ; } = ( ) => DateTimeOffset . UtcNow
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
+ AAuth.Tokens.TokenVerifier: public TimeProvider TimeProvider { get ; init ; } = TimeProvider . System
+ AAuth.Tokens.TokenVerifier: public TimeSpan ClockSkew { get ; init ; } = TimeSpan . FromSeconds ( 60 )
+ AAuth.Tokens.TokenVerifier: public TokenVerifier WithLocalIssuer ( string issuer , AAuthSigningKeySet keys )
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
+ AAuth.Tokens.UpstreamTokenValidator: public async Task < UpstreamTokenValidationResult > ValidateAsync ( string upstreamToken , string intermediary , string expectedPersonServer , Func < string , CancellationToken , ValueTask < bool > > isTrustedAuthTokenIssuer , CancellationToken ct = default )
```

Public owners: `AAuth.Tokens.UpstreamTokenValidationResult`, `AAuth.Tokens.UpstreamTokenValidator`, `AAuth.Tokens`.
