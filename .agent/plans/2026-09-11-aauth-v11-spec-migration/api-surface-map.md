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