# AAuth .NET SDK Documentation

This is the documentation for the AAuth .NET SDK (`AAuth` NuGet package). It covers agent-side signing, server-side verification, all four signing modes, and all resource access workflows.

- [Interactive Protocol Explorer](https://explorer.aauth.dev/)
- [AAuth Protocol Specification](../aauth-spec/v01/draft-hardt-oauth-aauth-protocol.md)

## Getting Started

- [Getting Started](getting-started.md) — Install, generate a key, make your first signed request
- [Protocol Concepts](concepts.md) — The four participants (Agent, Resource, Person Server, Access Server), three layers, and how the SDK maps to them
- [Glossary & Acronyms](glossary.md) — Every acronym and short protocol term used across the repo, with expansions

## Signing Modes

[Compare signing modes →](https://explorer.aauth.dev/signing/compare)

- [Overview](signing-modes/overview.md) — When to use each mode
- [Pseudonymous (hwk)](signing-modes/pseudonymous-hwk.md)
- [Agent Identity (jwks_uri)](signing-modes/agent-identity-jwks-uri.md)
- [Agent Token (jwt)](signing-modes/agent-token-jwt.md)
- [Key Rotation (jkt-jwt)](signing-modes/key-rotation-jkt-jwt.md)

## Workflows

[Compare access workflows →](https://explorer.aauth.dev/access/compare)

- [Identity-Based Access](workflows/identity-based-access.md)
- [Resource-Managed Access](workflows/resource-managed-access.md)
- [PS-Asserted Access](workflows/ps-asserted-access.md)
- [Federated Access](workflows/federated-access.md)
- [Bootstrap & Enrollment](workflows/bootstrap-enrollment.md)
- [Deferred Consent](workflows/deferred-consent.md)
- [Call Chaining](workflows/call-chaining.md)
- [Mission-Governed Access](workflows/mission-governed-access.md)

## Server Implementation

- [Verification Middleware](server/verification-middleware.md) — HTTP signature + JWT issuer verification
- [Challenge Middleware](server/challenge-middleware.md) — Auto-challenge for auth token upgrade
- [Authentication and Authorization](server/authn-authz.md) — authN/authZ pipeline + minimal-API and MVC wiring
- [Authorization Policies](server/authorization-policies.md) — Scope-based `[Authorize]` integration
- [Resource Metadata](server/resource-metadata.md)
- [Token Issuance](server/token-issuance.md)
- [Replay Detection](server/replay-detection.md)
- [Multi-Scheme Verification](server/multi-scheme-verification.md)
- [Mission Governance](server/mission-governance.md) — PS-side mission policy seams

## Advanced Topics

- [Missions](advanced/missions.md)
- [Mission Governance Clients](advanced/mission-governance-clients.md) — propose, permission, audit, interaction
- [Clarification Chat](advanced/clarification-chat.md) — answering a server's follow-up questions
- [Interaction Chaining](advanced/interaction-chaining.md)
- [Platform Attestation](advanced/platform-attestation.md)
- [Key Management](advanced/key-management.md)
- [Error Handling](advanced/error-handling.md)
- [Observability](advanced/observability.md) — OpenTelemetry Activity tracing

## Reference

- [Configuration](reference/configuration.md)
- [Dependency Injection](reference/dependency-injection.md)

## API Map

### `AAuth.Crypto` — Key management

| Type | Purpose |
|------|---------|
| `AAuthKey` | Ed25519 key generation, JWK import/export, thumbprints |
| `EcdsaAAuthKey` | P-256 ECDSA key (for interop scenarios) |
| `IKeyStore` | Key storage interface (implement for custom backends) |
| `FileKeyStore` | Built-in `IKeyStore` — on-disk persistence (`~/.aauth/keys/`) |
| `InMemoryKeyStore` | Built-in `IKeyStore` — in-memory (testing/ephemeral) |
| `IAAuthKey` | Key abstraction (implement for custom key backends) |

### `AAuth.HttpSig` — Signing and verification

| Type | Purpose |
|------|---------|
| `AAuthClientBuilder` | Fluent builder → configured `HttpClient` with signing |
| `AAuthClientBuilder.SelfIssuing(key)` | Fluent factory for self-hosted services (self-issued identity) |
| `AAuthClientBuilder.Enrolled(key)` | Fluent factory for AP-enrolled agents |
| `.WithPersonServer()` | Sets PS for both token `ps` claim and challenge handling |
| `app.MapAAuthResource()` | Unified resource pipeline (well-known + verification + challenge) |
| `AAuthSigningHandler` | `DelegatingHandler` that signs outbound requests (RFC 9421) |
| `AAuthVerifier` | Server-side signature verification |
| `AAuthVerificationMiddleware` | ASP.NET middleware — HTTP sig + JWT issuer verification |
| `SignatureKeyHeader` / `SignatureKeyParser` | Format/parse the `Signature-Key` header |
| `HwkSignatureKeyProvider` | `sig=hwk` — inline public key |
| `JwksUriSignatureKeyProvider` | `sig=jwks_uri` — JWKS-discoverable identity |
| `JwtSignatureKeyProvider` | `sig=jwt` — agent/auth token inline |
| `JktJwtSignatureKeyProvider` | `sig=jkt-jwt` — key rotation mode |
| `BootstrapBuilder` | Fluent builder for AP enrollment (CLI/desktop agents) |
| `ChallengeHandlingOptions` | Options for automatic 401 challenge handling |
| `InteractionHandlingOptions` | Options for deferred/interaction handling |

### `AAuth.Agent` — Client-side three-party flow

| Type | Purpose |
|------|---------|
| `AAuthTokenHolder` | Holds current carrier token (agent or auth) |
| `ChallengeHandler` | `DelegatingHandler` — intercepts 401, exchanges with PS |
| `InteractionHandler` | `DelegatingHandler` — handles 202 deferred/interaction |
| `TokenExchangeClient` | Sends signed `POST /token` to the Person Server |
| `DeferredPoller` | Polls the pending URL until auth_token or timeout |
| `AgentProviderClient` | Enrols with an Agent Provider (CLI/desktop agents; hosted services self-issue) |
| `Mission` / `AAuthMissionHeader` | Mission state + the `AAuth-Mission` header helpers |
| `MissionForwardingHandler` | `DelegatingHandler` that forwards mission context downstream |
| `AAuthGovernanceClient` | Facade bundling the four PS governance clients |
| `MissionClient` | Propose missions at the PS `mission_endpoint` |
| `PermissionClient` | Request permission at the PS `permission_endpoint` |
| `AuditClient` | Record actions at the PS `audit_endpoint` |
| `InteractionClient` | Reach the user via the PS `interaction_endpoint` |
| `MissionProposal` / `MissionTool` | Mission proposal body + a declared tool |
| `PermissionRequest` / `PermissionResult` | Permission request + grant/deny result |
| `AuditRecord` | Audit entry (requires a mission) |
| `InteractionRequest` / `InteractionResult` | Interaction request + typed terminal result |
| `GovernanceOptions` | Deferral callbacks shared by the governance clients |
| `ClarificationExchange` / `ClarificationResponse` | Drive a clarification chat; respond / update / cancel |
| `AAuthCapabilitiesHeader` | Helpers for the `AAuth-Capabilities` request header |
| `IInteractionPresenter` | Surface interaction URLs to the user |
| `IPlatformAttestor` / `NoopAttestor` | Platform attestation hook + built-in no-op implementation |
| `ITokenRefresher` | Pluggable agent-token refresh strategy |
| `AgentProviderTokenRefresher` | Built-in `ITokenRefresher` that refreshes via an Agent Provider |
| `SelfIssuedTokenRefresher` | Built-in `ITokenRefresher` for hosted services that self-issue tokens |

### `AAuth.Tokens` — Token builders and verification

| Type | Purpose |
|------|---------|
| `AgentTokenBuilder` | Builds `aa-agent+jwt` (agent identity + DWK) |
| `ResourceTokenBuilder` | Builds `aa-resource+jwt` (401 challenge payload) |
| `AuthTokenBuilder` | Builds `aa-auth+jwt` (person delegation proof) |
| `TokenVerifier` | EdDSA JWT verification with claim checks and JWKS resolution |
| `MissionClaim` | The `mission` claim (`approver` + `s256`) carried in tokens |

### `AAuth.Discovery` — Metadata and JWKS

| Type | Purpose |
|------|---------|
| `MetadataClient` | Cached fetcher for `/.well-known/aauth-*.json` |
| `JwksClient` | Cached fetcher for JWKS endpoints |
| `ServerMetadata` / `ResourceMetadata` | Parsed metadata models |

### `AAuth.Headers` — Protocol headers

| Type | Purpose |
|------|---------|
| `AAuthRequirementHeader` | Format/parse the `AAuth-Requirement` challenge header |
| `Interaction` | Interaction URL + code from 202 responses |
| `ClarificationRequirement` | Typed `requirement=clarification` projection (untrusted question) |

> The `AAuthCapabilitiesHeader` and `AAuthMissionHeader` types live in the `AAuth.Agent` namespace (alongside `Mission` and `MissionForwardingHandler`), not in `AAuth.Headers`.

### `AAuth.Server.Verification` — Verification middleware

| Type | Purpose |
|------|---------|
| `AAuthVerificationMiddleware` | HTTP sig PoP + JWT issuer verification middleware |
| `AAuthAuthenticationHandler` | Maps `AAuthVerificationResult` to `ClaimsPrincipal` |
| `AAuthVerificationResult` | Typed verification result in `HttpContext.Features` |
| `AAuthLevel` | Pseudonymous / Identified / Authorized |

### `AAuth.Server.Challenge` — Auto-challenge middleware

| Type | Purpose |
|------|---------|
| `AAuthChallengeMiddleware` | Auto-challenge: issues 401 with resource token |

### `AAuth.Server.Governance` — PS-side mission governance

| Type | Purpose |
|------|---------|
| `GovernanceEndpoints` | Parse governance request bodies + emit `mission_terminated` |
| `IMissionStore` / `InMemoryMissionStore` | Persist missions (verbatim blob + state) |
| `IMissionLog` / `InMemoryMissionLog` | Ordered mission log + prior-consent lookup |
| `IPermissionDecider` | PS policy seam for the permission endpoint |
| `IAuditSink` | PS sink for audit records |
| `IInteractionRelay` | PS user-channel seam for interactions |
| `StoredMission` / `MissionLogEntry` | Persisted mission + log entry records |
| `PermissionDecision` / `PermissionOutcome` / `PermissionDecisionReason` | Typed permission decision vocabulary |

### `AAuth.Server.Authorization` — Scope authorization

| Type | Purpose |
|------|---------|
| `AAuthScopeRequirement` | ASP.NET Core authorization requirement for scopes |
| `AAuthScopeHandler` | Evaluates scope requirements against verified scopes |

### `AAuth.Server.Metadata` — Well-known endpoints

| Type | Purpose |
|------|---------|
| `WellKnownEndpoints` | `MapAAuthResourceWellKnown()` for ASP.NET minimal APIs |

### `AAuth.Server.CallChaining` — Delegation routing

| Type | Purpose |
|------|---------|
| `CallChainingHandler` | Multi-hop delegation routing for resource-as-agent |

### `AAuth.Server` — Resource server utilities

| Type | Purpose |
|------|---------|
| `RevocationEndpoint` | Token revocation endpoint |
| `IJtiStore` / `InMemoryJtiStore` | Replay detection (JTI tracking) |
| `IOpaqueTokenStore` | Opaque token storage abstraction |

### `AAuth` — Diagnostics

| Type | Purpose |
|------|---------|
| `AAuthDiagnostics` | Shared `ActivitySource` + tag key constants for OTel tracing |

### `Microsoft.Extensions.DependencyInjection` / `Microsoft.AspNetCore.Builder` — ASP.NET Core integration

| Type | Purpose |
|------|---------|
| `AAuthAgentServiceCollectionExtensions` | `services.AddAAuthAgent(...)` |
| `AAuthResourceServiceCollectionExtensions` | `services.AddAAuthResource(...)` |
| `AAuthDiscoveryServiceCollectionExtensions` | `services.AddAAuthDiscovery(...)` |
| `AAuthGovernanceServiceCollectionExtensions` | `services.AddAAuthGovernance()` |
| `AAuthApplicationBuilderExtensions` | `app.UseAAuthVerification()` |

> These extension methods live in the conventional `Microsoft.Extensions.DependencyInjection` and `Microsoft.AspNetCore.Builder` namespaces so they surface automatically in ASP.NET Core projects. The associated options records (`AAuthAgentOptions`, `AAuthResourceOptions`, `AAuthDiscoveryOptions`, etc.) live in the root `AAuth` namespace.

### `AAuth.Errors` — Error types

| Type | Purpose |
|------|---------|
| `SignatureError` / `SignatureErrorCode` | Signature verification failures |
| `TokenErrorResponse` / `TokenErrorCode` | Token validation failures |
| `AAuthTokenExchangeException` | Structured PS token-endpoint errors |
| `PollingErrorException` / `PollingErrorCode` | Deferred polling failures |

### `AAuth.Identifiers` — AAuth URI parsing

| Type | Purpose |
|------|---------|
| `AgentId` | Parse/validate `aauth:` agent identifiers |
| `ServerId` | Parse/validate server identifiers |

## Samples

- [`SampleApp`](../samples/SampleApp/) — Golden example: one page per signing mode (hwk, jwks_uri, jkt-jwt, jwt)
- [`GuidedTour`](../samples/GuidedTour/) — Interactive Blazor walkthrough of all flows
- [`AgentConsole`](../samples/AgentConsole/) — CLI agent demonstrating signing modes
- [`MockResourceServers`](../samples/MockResourceServers/) — Profile, Calendar, Trips, and Wallet resource servers with verification middleware
