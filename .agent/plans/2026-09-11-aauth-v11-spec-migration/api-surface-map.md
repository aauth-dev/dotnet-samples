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

Baseline `v0.10.0-alpha.1`; 26 changed public-source files, 35 added/replacement declarations, 9 removed/replaced declarations.

Generated from all current SDK source files, including untracked additions, and the baseline tree. Public/protected declarations include containing namespaces/types, overload parameters, required members, attributes, optional defaults, primary constructors and interface members. Compiler-synthesized/inherited members are represented by their source declarations, not expanded. Unchanged signatures in changed files are listed by containing type as behavior-review entries; the concept table above supplies their entry point, ownership, callers and tests. No source file is excluded by guessed file role.

### samples/GuidedTour/TourSession.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [TourSession.cs](../../../samples/GuidedTour/TourSession.cs).

Public signatures unchanged (57); behavior reviewed under sample-runtime.

Public owners: `GuidedTour.TourSession`, `GuidedTour`.

### samples/MockAccessServers/Federated/Program.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [Program.cs](../../../samples/MockAccessServers/Federated/Program.cs).

Public signatures unchanged (1); behavior reviewed under sample-runtime.

Public owners: `Federated`.

### samples/MockResourceServers/Inbox/Program.cs

Concept/decision: [sample-runtime](#sample-runtime). Source: [Program.cs](../../../samples/MockResourceServers/Inbox/Program.cs).

Public signatures unchanged (1); behavior reviewed under sample-runtime.

Public owners: `Inbox`.

### src/AAuth.R3/R3AccessTokenEndpoint.cs

Concept/decision: [r3](#r3). Source: [R3AccessTokenEndpoint.cs](../../../src/AAuth.R3/R3AccessTokenEndpoint.cs).

Public signatures unchanged (24); behavior reviewed under r3.

Public owners: `AAuth.R3.R3AccessTokenEndpointOptions`, `AAuth.R3.R3AccessTokenEndpoint`, `AAuth.R3`.

### src/AAuth/AAuthConstants.cs

Concept/decision: [server-contracts](#server-contracts). Source: [AAuthConstants.cs](../../../src/AAuth/AAuthConstants.cs).

```diff
- AAuth.AAuthConstants.AccessModes: public const string AAuthAccessToken = "aauth-access-token" ;
+ AAuth.AAuthConstants.AccessModes: public const string PersonToken = "person-token" ;
+ AAuth.AAuthConstants.AccessModes: public const string SessionToken = "session-token" ;
```

Public owners: `AAuth.AAuthConstants.AccessModes`, `AAuth.AAuthConstants.DwkFiles`, `AAuth.AAuthConstants.Headers`, `AAuth.AAuthConstants.Schemes`, `AAuth.AAuthConstants.TokenTypes`, `AAuth.AAuthConstants`, `AAuth`.

### src/AAuth/Access/AAuthAccessServerEndpoints.cs

Concept/decision: [consent](#consent). Source: [AAuthAccessServerEndpoints.cs](../../../src/AAuth/Access/AAuthAccessServerEndpoints.cs).

Public signatures unchanged (16); behavior reviewed under consent.

Public owners: `AAuth.Access.AAuthAccessServerEndpoints`, `AAuth.Access.AAuthAccessServerOptions`, `AAuth.Access`.

### src/AAuth/Access/AccessServerClient.cs

Concept/decision: [consent](#consent). Source: [AccessServerClient.cs](../../../src/AAuth/Access/AccessServerClient.cs).

Public signatures unchanged (3); behavior reviewed under consent.

Public owners: `AAuth.Access.AccessServerClient`, `AAuth.Access`.

### src/AAuth/Agent/TokenExchangeClient.cs

Concept/decision: [agent-clients](#agent-clients). Source: [TokenExchangeClient.cs](../../../src/AAuth/Agent/TokenExchangeClient.cs).

Public signatures unchanged (5); behavior reviewed under agent-clients.

Public owners: `AAuth.Agent.TokenExchangeClient`, `AAuth.Agent`.

### src/AAuth/DependencyInjection/AAuthResourceOptions.cs

Concept/decision: [di](#di). Source: [AAuthResourceOptions.cs](../../../src/AAuth/DependencyInjection/AAuthResourceOptions.cs).

```diff
- AAuth.AAuthResourceOptions: public TimeSpan MaxFutureSkew { get ; set ; } = TimeSpan . FromSeconds ( 5 )
```

Public owners: `AAuth.AAuthResourceOptions`, `AAuth`.

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

### src/AAuth/HttpSig/AAuthVerifier.cs

Concept/decision: [signatures](#signatures). Source: [AAuthVerifier.cs](../../../src/AAuth/HttpSig/AAuthVerifier.cs).

```diff
- AAuth.HttpSig.AAuthVerifier: public TimeSpan MaxFutureSkew { get ; init ; } = TimeSpan . FromSeconds ( 5 )
```

Public owners: `AAuth.HttpSig.AAuthVerificationException`, `AAuth.HttpSig.AAuthVerifier`, `AAuth.HttpSig`.

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

Public signatures unchanged (23); behavior reviewed under consent.

Public owners: `AAuth.Person.AAuthPersonServerEndpoints`, `AAuth.Person.AAuthPersonServerOptions`, `AAuth.Person`.

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
```

Public owners: `AAuth.Server.Metadata.AAuthPersonServerMetadataOptions`, `AAuth.Server.Metadata`.

### src/AAuth/Server/Metadata/WellKnownEndpoints.cs

Concept/decision: [server-contracts](#server-contracts). Source: [WellKnownEndpoints.cs](../../../src/AAuth/Server/Metadata/WellKnownEndpoints.cs).

Public signatures unchanged (23); behavior reviewed under server-contracts.

Public owners: `AAuth.Server.Metadata.AAuthResourceMetadataOptions`, `AAuth.Server.Metadata.WellKnownEndpoints`, `AAuth.Server.Metadata`.

### src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs

Concept/decision: [signatures](#signatures). Source: [AAuthVerificationMiddleware.cs](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs).

Public signatures unchanged (14); behavior reviewed under signatures.

Public owners: `AAuth.Server.Verification.AAuthVerificationMiddleware`, `AAuth.Server.Verification.VerificationResult`, `AAuth.Server.Verification`.

### src/AAuth/Server/Verification/AAuthVerificationOptions.cs

Concept/decision: [signatures](#signatures). Source: [AAuthVerificationOptions.cs](../../../src/AAuth/Server/Verification/AAuthVerificationOptions.cs).

```diff
- AAuth.Server.Verification.AAuthVerificationOptions: public TimeSpan MaxFutureSkew { get ; init ; } = TimeSpan . FromSeconds ( 5 )
```

Public owners: `AAuth.Server.Verification.AAuthVerificationOptions`, `AAuth.Server.Verification`.
