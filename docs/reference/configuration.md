# Configuration Reference

All configurable options across the AAuth .NET SDK, grouped by component.

## Signature Verification

### AAuthVerifier

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `MaxAge` | `TimeSpan` | 60 seconds | Signature validity window for `created`, in both directions: older is `invalid_signature`, further ahead is `clock_skew` |
| `TimeProvider` | `TimeProvider` | System | Clock source (override for testing) |

### AAuthServerOptions (via UseAAuth)

The single `UseAAuth` pipeline middleware. Defaults to the DI-registered resource
metadata (issuer + first signing key); a typical resource sets only trust.

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Trust` | `AAuthTrustOptions` | `new()` (open) | Auth-token, person-token and agent-token issuer trust; see [AAuthTrustOptions](#aauthtrustoptions). Unset rules accept any *verifiable* issuer (the spec default). Endpoints can replace it with `.RequireAAuth(scope, trust: policy)`. |
| `AccessServer` | `string?` | `null` | Resource-token audience for four-party (federated) resources: the resource's own Access Server. When `null` the audience is the PS that issued the presented person token (three-party). |
| `ResourceIdentifier` | `string?` | DI metadata issuer | Override the resource identifier used for `aud` checks and challenges. |
| `ResourceSigningKeys` | `AAuthSigningKeySet?` | DI metadata signing keys | Override the challenge signing keys; resource tokens are signed with the set's active key. |

> `AAuthVerificationOptions` and `ChallengeOptions` are the low-level building
> blocks `UseAAuth` configures from each endpoint's `.RequireAAuth(...)` /
> `.RequireAAuthSignature(...)` requirement; use them directly only for custom
> pipelines. `UseAAuthVerification(o => ...)`, `UseAAuthChallenge(o => ...)` and
> `UseAAuthIntermediary(verify => ..., challenge => ...)` take configure delegates:
> each starts from `services.Configure<TOptions>(...)` registrations (verification
> also seeds `EgressPolicy` from the registered `MetadataClient`), then applies the
> delegate for that pipeline.

### AAuthVerificationOptions (via UseAAuthVerification)

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `EgressPolicy` | `AAuthEgressPolicy` | `Production` | URL/identifier admission policy for metadata and JWKS fetches. |
| `ResourceIdentifier` | `string?` | `AddAAuthResource` `Issuer` | Resource's own identifier; auth-token and person-token `aud` must equal it. With no identifier, auth and person tokens are rejected (`invalid_request`). |
| `AcceptedSchemes` | `IReadOnlyList<string>` | `["jwt"]` | Schemes accepted by this verification role; generic signing is an explicit opt-in. |
| `SignatureLabel` | `string` | `"sig"` | Matching dictionary member selected from all three signature fields. |
| `RequiredComponents` | `IReadOnlyCollection<string>` | `[]` | Additional required covered components. |
| `RequireBodyCoverage` | `bool` | `false` | Require body-bearing requests to cover `content-type` and `content-digest`; missing coverage fails with `invalid_input` and `required_input`. |
| `GenericSignatureKeys` | `bool` | `false` | Use generic Signature Keys failure status policy instead of AAuth's 401 profile. |
| `Trust` | `AAuthTrustOptions` | `new()` (open) | Agent Provider, auth-token issuer and person-token issuer trust; see [AAuthTrustOptions](#aauthtrustoptions). |
| `ExpectedAuthTokenDwk` | `string?` | `aauth-person.json` | Auth-token `dwk` pin. `AddAAuthResource` with `AccessServer` derives `aauth-access.json`; set `null` only for explicit mixed PS/AS deployments with a `TokenDwk`-aware trust policy. |
| `ExpectedAccount` | `Func<HttpContext,string?>?` | `null` | Optional account selector; when it returns a value, verified auth/person tokens must be bound to that account. |
| `ClockSkew` | `TimeSpan` | 30 seconds | Tolerance for optional future `iat` checks. `exp` has zero tolerance and is rejected when it is not in the future. |
| `TimeProvider` | `TimeProvider` | System | Clock source for all time-dependent checks. Inject for deterministic testing. |

> Startup diagnostics do not change runtime trust policy:
>
> - **Open-trust warning** — when issuer verification is on and no auth-token
>   trust policy is configured (no set, no predicate, no `AAuthTrust.Any`), the
>   resource accepts any verifiable Person Server and a `Warning` is logged at
>   startup. The same warning fires for an open PS (no `Trust.AccessServers`
>   policy) or open AS (no `Trust.PersonServers` policy); any explicit policy
>   suppresses it.
>   - *False positive on signature-only resources:* a `UseAAuth` resource whose
>     endpoints are **all** `RequireAAuthSignature` (no auth-token endpoints) still
>     logs this warning — the SDK can't know at startup that no auth-token endpoint
>     exists. It is benign; silence it by assigning
>     `Trust.AuthTokenIssuers.Predicate = AAuthTrust.Any`.
> JWT issuer verification cannot be disabled. Trust policies narrow the set of
> verified issuers; they never replace signature verification.

> **Development loopback.** `AAuthEgressPolicy.ForDevelopmentLoopback(...)`
> admits only exact `localhost` or `127.0.0.1` origins (with or without an
> explicit port) from the list supplied. The SDK logs a warning when such a
> policy is active and rejects AAuth role/discovery registrations that use it in
> a Production host environment. `AAuthEgressPolicy.Production` rejects loopback
> issuers, identifiers and metadata URLs.

### AAuthTrustOptions

The single trust declaration for a resource, Person Server or Access Server.
Decision order: `Policy`, then an `IAAuthTrustPolicy` registered in DI, then the
per-party rules.

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `AuthTokenIssuers` | `AAuthTrustRule` | open | Auth-token issuers (Person Servers and Access Servers). |
| `PersonServers` | `AAuthTrustRule` | open | Person-token issuers at a resource; brokered Person Servers at an Access Server. Falls back to `AuthTokenIssuers` when not configured. |
| `AgentProviders` | `AAuthTrustRule` | open | Agent Providers issuing `aa-agent+jwt`. |
| `AccessServers` | `AAuthTrustRule` | open | Access Servers a Person Server federates to. |
| `Policy` | `IAAuthTrustPolicy?` | `null` | Replaces the rules and any DI-registered policy. |

### AAuthTrustRule

Every configured part must accept (AND). Nothing configured ⇒ any verifiable
counterparty is trusted (the spec default).

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Allowed` | `IReadOnlySet<string>?` | `null` | Allow-list. `null` ⇒ no list; empty ⇒ deny all. |
| `Predicate` | `Func<string, bool>?` | `null` | Synchronous predicate over the identifier. Assign `AAuthTrust.Any` to declare open trust explicitly and suppress the open-trust startup warning. |
| `PredicateAsync` | `Func<AAuthTrustContext, CancellationToken, ValueTask<bool>>?` | `null` | Asynchronous predicate with the request and services. |

A resource's own identity, keys, verification and metadata are registered with
`AddAAuthResource`; see [AAuthResourceOptions](#aauthresourceoptions-addaauthresource).

### AAuthPersonServerOptions (via AddAAuthPersonServer)

Register with `AddAAuthPersonServer(configure: …)` or bind from `AAuth:PersonServer`
with `AddAAuthPersonServer(configuration.GetSection(…))`. `Issuer` and a signing
key are validated at startup (`OptionsValidationException`).

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Issuer` | `string` | — (validated) | HTTPS URL of this PS (`iss` of minted person and auth tokens) |
| `SigningKeys` | `AAuthSigningKeySet` | empty | Signing keys published at the PS JWKS; tokens are signed with the active key. Set this or `KeyHandle` |
| `KeyHandle` | `string?` | `null` | Handle in the registered `IKeyStore` to load the signing key from when `SigningKeys` is empty |
| `KeyId` | `string?` | `null` | `kid` for the key loaded from `KeyHandle` (default: its JWK thumbprint) |
| `MatchIssuerHost` | `bool` | `false` | Serve this instance only for requests whose `Host` is the issuer's authority; set it when several roles or instances share one host |
| `EgressPolicy` | `AAuthEgressPolicy` | `Production` | *Code-only.* Egress policy for the PS's outbound fetches (metadata, JWKS, federation) |
| `TimeProvider` | `TimeProvider` | System | *Code-only.* Clock for issuance, pending expiry and verification |
| `TokenPath` | `string` | `/token` | Auth token endpoint path (`auth_token_endpoint`) |
| `PersonTokenPath` | `string` | `/person` | Person token endpoint path (`person_token_endpoint`) |
| `RevocationPath` | `string` | `/revoke` | Revocation endpoint path (`revocation_endpoint`) |
| `ConfigureRevocation` | `Action<AAuthRevocationOptions>?` | `null` | *Code-only.* Adjusts the mapped revocation endpoint |
| `PendingPathPrefix` | `string` | `/pending` | Deferred-consent poll path prefix |
| `DefaultScope` | `string` | `""` | Scope assumed when the resource token omits one |
| `ScopesSupported` | `IReadOnlyList<string>?` | `null` | Scopes advertised as `scopes_supported` in PS metadata |
| `PairwiseSubjectSecrets` | `IDictionary<string,string>` | empty | Versioned HMAC secrets for the default pairwise person-token `sub` deriver. Production requires a durable configured secret; Development/test use an ephemeral secret with a warning |
| `ActivePairwiseSubjectKeyId` | `string?` | `null` | Key id in `PairwiseSubjectSecrets` used for new derived subjects; existing enrollments keep their stored key id and subject |
| `InteractionPath` | `string` | `/interaction` | Path the host maps for the consent page |
| `ResourceInteractionSessions` | `BrowserConsentSessions?` | `null` (per-PS default) | *Code-only.* Browser sessions for resource-interaction chaining under `{InteractionPath}/resource` |
| `UnsignedPathPrefixes` | `IReadOnlyCollection<string>?` | `null` | Extra path prefixes the mapper's signature verification skips (the PS's own browser pages) |
| `TriageClarificationAsync` | `Func<PersonPendingEntry, ClarificationRequirement, CancellationToken, Task<ClarificationResponse?>>?` | `null` | *Code-only.* Answers an Access Server's clarification locally; `null` forwards it to the agent |
| `CollapsedFederation` | `IList<AAuthCollapsedFederationDeclaration>` | empty | Explicit PS-AS collapse declarations: a verified resource issuer may use a linked local AS role whose issuer must match `ExpectedAccessServerIssuer`. Use the builder's `UseCollocatedAccessServer(...)` helpers or mutate the list in code. |
| `InteractionEndpointPath` | `string?` | `null` (`/mission-interaction` with `.WithGovernance()`) | Signed §Interaction Endpoint path, advertised as issuer + path when set. It never falls back to `InteractionPath` |
| `MissionPath` | `string?` | `null` (`/mission` with `.WithGovernance()`) | Mission endpoint path, advertised as issuer + path |
| `PermissionPath` | `string?` | `null` (`/permission` with `.WithGovernance()`) | Permission endpoint path, advertised as issuer + path |
| `AuditPath` | `string?` | `null` (`/audit` with `.WithGovernance()`) | Audit endpoint path, advertised as issuer + path |
| `Trust` | `AAuthTrustOptions` | `new()` (open) | `Trust.AccessServers` governs the AS URLs the PS will federate to. Unconfigured ⇒ federate to the AS named in a verified resource token's `aud` (the spec default); `Allowed` empty ⇒ three-party only (four-party disabled); non-empty ⇒ restrict to the listed Access Servers. Upstream auth tokens from an AS are accepted only when `Trust.AccessServers` is configured and accepts the issuer. |

The seams (`IIdentityClaimsAsserter`, `IPersonPendingStore`, `TokenVerifier`, and
the `IJtiStore` token inventory) resolve per instance: first the builder's `Use*`
helper, then an unkeyed DI registration, then the SDK default. The helper also
resolves the `IMissionStore` / `IMissionLog` mission primitives when a request
carries `mission_s256`. See
[Person Server and Access Server Registration](dependency-injection.md#person-server-and-access-server-registration)
and [Token Issuance → One-Call Person Server](../server/token-issuance.md#one-call-person-server-mapaauthpersonserver).

Payment settlement is a seam, not a settable options property: register an
`IAAuthPaymentSettler` with `UsePaymentSettler(...)` to handle AS `402`
federation challenges, and optionally replace the default
`InMemoryAAuthBillingRelationshipCache` with `UseBillingRelationshipCache(...)`.

### AAuthCollapsedFederationDeclaration

`CollapsedFederation` entries use this shape:

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `ResourceIssuer` | `string` | required | Verified resource issuer that chose the collocated AS. |
| `AccessServerName` | `string` | default AS role name | Linked local Access Server role instance. |
| `ExpectedAccessServerIssuer` | `string` | required (`UseCollocatedAccessServer` defaults to the PS issuer) | Issuer the linked AS role must use; mismatches fail closed. |

### AAuthAccessServerOptions (via AddAAuthAccessServer)

Register with `AddAAuthAccessServer(configure: …)` or bind from `AAuth:AccessServer`.
An `IAccessPolicy` is required (`UsePolicy` or a DI registration).

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Issuer` | `string` | — (validated) | HTTPS URL of this AS (`iss` of minted auth tokens) |
| `SigningKeys` | `AAuthSigningKeySet` | empty | Signing keys published at the AS JWKS. Set this or `KeyHandle` |
| `KeyHandle` | `string?` | `null` | Handle in the registered `IKeyStore` to load the signing key from when `SigningKeys` is empty |
| `KeyId` | `string?` | `null` | `kid` for the key loaded from `KeyHandle` (default: its JWK thumbprint) |
| `MatchIssuerHost` | `bool` | `false` | Serve this instance only for requests whose `Host` is the issuer's authority |
| `EgressPolicy` | `AAuthEgressPolicy` | `Production` | *Code-only.* Egress policy for the AS's outbound fetches |
| `TimeProvider` | `TimeProvider` | System | *Code-only.* Clock for issuance, pending expiry and verification |
| `TokenPath` | `string` | `/token` | Auth token endpoint path (`auth_token_endpoint`) |
| `RevocationPath` | `string` | `/revoke` | Revocation endpoint path (`revocation_endpoint`) |
| `ConfigureRevocation` | `Action<AAuthRevocationOptions>?` | `null` | *Code-only.* Adjusts the mapped revocation endpoint |
| `DeriveAgentClaims` | `Func<string, JsonObject?>?` | `null` | *Code-only.* Baseline policy claims derived from the verified agent id. Use it only for facts about the agent; identity claims about the person (`roles`, `groups`, `tenant`) come from the PS through the §Claims Required push |
| `PendingPathPrefix` | `string` | `/pending` | Deferred-decision poll path prefix |
| `DefaultScope` | `string` | `""` | Scope assumed when the resource token omits one |
| `InteractionLoginPath` | `string` | `/interaction/login` | Browser entry point for interactive policies |
| `Trust` | `AAuthTrustOptions` | `new()` (open) | `Trust.PersonServers` governs the Person Servers this AS brokers for |

## Token Builders

### ResourceTokenBuilder

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `EgressPolicy` | `AAuthEgressPolicy` | `Production` | URL/identifier admission policy for issuer, audience and PS URLs. |
| `Issuer` | `string` | required | Resource issuer (`iss`) |
| `Audience` | `string` | required | PS issuer for three-party or AS issuer for four-party (`aud`) |
| `PersonServer` | `string` | required | Person Server copied from the presented token (`ps`) |
| `Subject` | `string` | required | Directed subject copied from the presented token (`sub`) |
| `PresentedJti` | `string` | required | `jti` of the presented person/auth token (`presented_jti`) |
| `AgentJkt` | `string` | required | JWK thumbprint of the agent signing key (`agent_jkt`) |
| `Key` | `IAAuthSigner` | required | Resource signing key |
| `KeyId` | `string` | required | JWT header `kid` |
| `Scope` | `string?` | `null` | Requested scopes, space-separated |
| `Account` | `string?` | `null` | Optional account binding |
| `ScopeDescriptions` | `IReadOnlyDictionary<string,string>?` | `null` | Descriptions used to validate and advertise requested scopes |
| `PersonServerScopesSupported` | `IReadOnlyCollection<string>?` | `null` | PS-advertised scopes used to validate requested scopes |
| `MissionS256` | `string?` | `null` | Mission reference copied from the presented token |
| `Tenant` | `string?` | `null` | Tenant copied from the presented token |
| `LoginHint` | `string?` | `null` | Optional authorization hint |
| `Interaction` | `Interaction?` | `null` | Optional interaction requirement embedded in the resource token |
| `Lifetime` | `TimeSpan` | 5 minutes | Token validity duration; SDK producers reject values over 5 minutes |
| `IssuedAt` | `DateTimeOffset?` | Now | Override issuance timestamp |
| `TokenId` | `string?` | Auto (GUID) | Custom `jti` value |

### AuthTokenBuilder

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `EgressPolicy` | `AAuthEgressPolicy` | `Production` | URL/identifier admission policy for issuer, audience and PS URLs. |
| `Issuer` | `string` | required | PS or AS issuer (`iss`) |
| `Audience` | `string` | required | Resource identifier (`aud`) |
| `PersonServer` | `string` | required | Person Server identifier (`ps`) |
| `Subject` | `string` | required | Directed subject (`sub`) |
| `AgentConfirmationKey` | `IAAuthKey` | required | Agent/sub-agent confirmation key (`cnf.jwk`) |
| `AgentTokenExpiresAt` | `DateTimeOffset` | required | Expiry from the verified source agent token |
| `AuthorizationExpiresAt` | `DateTimeOffset?` | `null` | Additional verified presented/parent/upstream/mission ceiling |
| `TimeProvider` | `TimeProvider` | System | Issuance and expiration clock |
| `Key` | `IAAuthSigner` | required | PS/AS signing key |
| `KeyId` | `string` | required | JWT header `kid` |
| `Dwk` | `string` | `"aauth-person.json"` | Discovery well-known path; use `"aauth-access.json"` for AS-issued four-party auth tokens |
| `Scope` | `string?` | `null` | Granted scopes, space-separated |
| `Account` | `string?` | `null` | Optional account binding |
| `Roles` | `IReadOnlyList<string>?` | `null` | Optional enterprise roles claim |
| `Groups` | `IReadOnlyList<string>?` | `null` | Optional enterprise groups claim |
| `MissionS256` | `string?` | `null` | Mission reference copied from the resource token |
| `Tenant` | `string?` | `null` | Optional tenant claim |
| `Lifetime` | `TimeSpan` | 1 hour | Positive requested lifetime, at most one hour, capped by verified ceilings |
| `IssuedAt` | `DateTimeOffset?` | Now | Override issuance timestamp |
| `TokenId` | `string?` | Auto (GUID) | Custom `jti` value |
| `AdditionalClaims` | `IReadOnlyDictionary<string,JsonNode?>?` | `null` | Extra identity claims; reserved claim names are rejected |

### AgentTokenBuilder

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `EgressPolicy` | `AAuthEgressPolicy` | `Production` | URL/identifier admission policy for issuer and PS URLs. |
| `Issuer` | `string` | required | Agent Provider issuer (`iss`) |
| `Subject` | `string` | required | Agent identifier (`sub`) |
| `KeyId` | `string` | required | JWT header `kid` |
| `Key` | `IAAuthSigner` | required | JWT signing key |
| `ConfirmationKey` | `IAAuthKey?` | `null` | Optional separate confirmation key; when `null`, `Key` is also the confirmation key |
| `PersonServer` | `string?` | `null` | Optional Person Server URL (`ps`) |
| `ParentAgent` | `string?` | `null` | Optional parent agent identifier for a sub-agent token |
| `Lifetime` | `TimeSpan` | 1 hour | Token validity duration; SDK producers reject values over 24 hours |
| `IssuedAt` | `DateTimeOffset?` | Now | Override issuance timestamp |
| `TokenId` | `string?` | Auto (GUID) | Custom `jti` value |
| `AdditionalClaims` | `IReadOnlyDictionary<string,JsonNode?>?` | `null` | Extra claims; required-claim collisions are rejected |

### PersonTokenBuilder

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `EgressPolicy` | `AAuthEgressPolicy` | `Production` | URL/identifier admission policy for issuer and audience URLs. |
| `Issuer` | `string` | required | Person Server issuer (`iss`) |
| `Audience` | `string` | required | Resource identifier (`aud`) |
| `Subject` | `string` | required | Directed person subject (`sub`) |
| `ConfirmationKey` | `IAAuthKey` | required | Agent/sub-agent confirmation key (`cnf.jwk`) |
| `AgentTokenExpiresAt` | `DateTimeOffset` | required | Expiry from the verified source agent token |
| `AuthorizationExpiresAt` | `DateTimeOffset?` | `null` | Additional upstream/mission ceiling |
| `Key` | `IAAuthSigner` | required | PS signing key |
| `KeyId` | `string` | required | JWT header `kid` |
| `MissionS256` | `string?` | `null` | Optional mission reference |
| `Tenant` | `string?` | `null` | Optional tenant claim |
| `Lifetime` | `TimeSpan` | 1 hour | Positive requested lifetime, at most one hour, capped by verified ceilings |
| `IssuedAt` | `DateTimeOffset?` | Now | Override issuance timestamp |
| `TokenId` | `string?` | Auto (GUID) | Custom `jti` value |
| `TimeProvider` | `TimeProvider` | System | Issuance and expiration clock |

## Token Verification

### TokenVerifier

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `EgressPolicy` | `AAuthEgressPolicy` | `Production` | URL/identifier admission policy for metadata/JWKS fetches. |
| `TimeProvider` | `TimeProvider` | System | Clock source |
| `ClockSkew` | `TimeSpan` | 60 seconds | Tolerance for optional future `iat` checks. `exp` has zero tolerance and is rejected when it is not in the future. |
| `LocalIssuerKeys` | `Func<string,string,IAAuthKey?>?` | `null` | Optional local key resolver by issuer and `kid`; used by servers to verify their own issued tokens without fetching their own JWKS. |

## Deferred Consent (Polling)

### DeferredPollerOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `MaxTotalWait` | `TimeSpan` | 5 minutes | Maximum time to poll before timeout |
| `DefaultPollInterval` | `TimeSpan` | 5 seconds | Base interval between polls |
| `MinPollInterval` | `TimeSpan` | zero | Optional minimum interval floor |
| `PreferWaitSeconds` | `int?` | `null` | Send `Prefer: wait=N` header (long-poll) |
| `OnPoll` | `Action<HttpResponseMessage>?` | `null` | Callback after each poll response |

Server `Retry-After` headers override `DefaultPollInterval`; `Retry-After: 0`
is immediate unless an app explicitly configures a non-zero `MinPollInterval`.
The agent's challenge and interaction handlers take the same polling settings; see
[ChallengeHandlingOptions](#challengehandlingoptions-withchallengehandling) and
[InteractionHandlingOptions](#interactionhandlingoptions-withinteractionhandling).

### DeferredExchangeOptions (internal)

Internal transport options shared by token exchange and governance clients. They
are listed for source inventory completeness; configure public clients through
`TokenExchangeClientOptions`, `ChallengeHandlingOptions`, `InteractionHandlingOptions`
or `GovernanceOptions`.

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `OnInteractionRequired` | `Func<Interaction,CancellationToken,Task>?` | `null` | Relay an interaction URL/code to the user. |
| `OnClarificationRequired` | `Func<ClarificationRequirement,CancellationToken,Task<ClarificationResponse>>?` | `null` | Answer a clarification question during deferred exchange. |
| `MaxClarificationRounds` | `int` | 5 | Clarification rounds before aborting. |
| `PollerOptions` | `DeferredPollerOptions?` | `null` | Optional polling tuning. |
| `RequireInteractionCallback` | `bool` | `false` | When true, unhandled interaction requirements become token-endpoint errors. |
| `OnPolledResponse` | `Func<HttpResponseMessage,CancellationToken,Task>?` | `null` | Optional callback after each interaction-branch poll response. |

## Discovery

### MetadataClient

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `http` | `HttpClient?` | `null` | Optional HTTP client for fetching documents; supplied transports require an explicit transport contract |
| `cacheTtl` | `TimeSpan?` | `null` (5 minutes) | Cache entry lifetime |
| `timeProvider` | `TimeProvider?` | System | Clock source for cache expiration |

Methods:

- `BuildUrl(issuer, dwk)` — constructs `.well-known/{dwk}` URL from issuer
- `FetchAsync(url)` — fetches and caches the JSON document
- `Invalidate(url)` — evicts a cached entry

## Resource Metadata

`ResourceMetadata.FromJson(...)` parses the typed resource fields agents consume,
including `AdditionalSignatureComponents` from
`additional_signature_components`.

### AAuthResourceMetadataOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `EgressPolicy` | `AAuthEgressPolicy` | `Production` | URL/identifier admission policy for metadata URLs. |
| `Issuer` | `string` | required | Resource canonical URL |
| `AccessServer` | `string?` | `null` | Runtime four-party Access Server issuer; not emitted as resource metadata. |
| `SigningKeys` | `AAuthSigningKeySet?` | `null` | Signing keys published at the JWKS; required when issuing resource tokens or making signed calls, optional for verification-only resources. |
| `AccessMode` | `string?` | `null` | Advisory `access_mode`: `agent-token`, `person-token`, resource-managed `session-token` (`AAuth-Access`), `auth-token`, or `per-call`. Runtime challenges remain authoritative. |
| `Name` | `string?` | `null` | Human-readable resource name (`name`) |
| `Description` | `string?` | `null` | Markdown resource description (`description`) |
| `LogoUri` | `string?` | `null` | `logo_uri` |
| `LogoDarkUri` | `string?` | `null` | `logo_dark_uri` |
| `DocumentationUri` | `string?` | `null` | `documentation_uri` |
| `TosUri` | `string?` | `null` | `tos_uri` |
| `PolicyUri` | `string?` | `null` | `policy_uri` |
| `ScopeDescriptions` | `IReadOnlyDictionary<string,string>?` | `null` | Scope → description |
| `SignatureWindow` | `int?` | `null` | Advertised signature validity (seconds) |
| `AdditionalSignatureComponents` | `IReadOnlyList<string>?` | `null` | Emits `additional_signature_components`; agents must cover these components on first request |
| `AuthorizationEndpoint` | `string?` | `null` | Resource's proactive authorization endpoint URL; not the PS/AS resource-token recipient (draft-11 removed `PersonServerAudience`; the recipient is `AccessServer` or the presented token's PS) |
| `RevocationEndpoint` | `string?` | `null` | Revocation endpoint URL |
| `AdditionalMetadata` | `IReadOnlyDictionary<string,JsonNode?>?` | `null` | Extension members merged into the resource well-known document; typed fields win on collision. |

### AAuthAgentMetadataOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `EgressPolicy` | `AAuthEgressPolicy` | `Production` | URL/identifier admission policy for metadata URLs. |
| `Issuer` | `string` | `""` (required) | Agent/Agent Provider issuer (`issuer`) |
| `SigningKeys` | `AAuthSigningKeySet` | empty (required) | Signing keys published at the JWKS. |
| `Name` | `string?` | `null` | Human-readable name (`name`) |
| `Description` | `string?` | `null` | Markdown description (`description`) |
| `LogoUri` | `string?` | `null` | `logo_uri` |
| `LogoDarkUri` | `string?` | `null` | `logo_dark_uri` |
| `DocumentationUri` | `string?` | `null` | `documentation_uri` |
| `TosUri` | `string?` | `null` | `tos_uri` |
| `PolicyUri` | `string?` | `null` | `policy_uri` |
| `CallbackEndpoint` | `string?` | `null` | Optional `callback_endpoint` |
| `EventEndpoint` | `string?` | `null` | Optional Events inbox endpoint (`event_endpoint`) |
| `LocalhostCallbackAllowed` | `bool` | `false` | Emits `localhost_callback_allowed` when true. |

### AAuthPersonServerMetadataOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `EgressPolicy` | `AAuthEgressPolicy` | `Production` | URL/identifier admission policy for metadata URLs. |
| `Issuer` | `string` | required | Person Server issuer (`issuer`) |
| `AuthTokenEndpoint` | `string` | required | `auth_token_endpoint` |
| `PersonTokenEndpoint` | `string` | required | `person_token_endpoint` |
| `SigningKeys` | `AAuthSigningKeySet` | required | Signing keys published at the JWKS. |
| `Name` | `string?` | `null` | Human-readable name (`name`) |
| `Description` | `string?` | `null` | Markdown description (`description`) |
| `LogoUri` | `string?` | `null` | `logo_uri` |
| `LogoDarkUri` | `string?` | `null` | `logo_dark_uri` |
| `DocumentationUri` | `string?` | `null` | `documentation_uri` |
| `TosUri` | `string?` | `null` | `tos_uri` |
| `PolicyUri` | `string?` | `null` | `policy_uri` |
| `MissionEndpoint` | `string?` | `null` | Optional `mission_endpoint` |
| `PermissionEndpoint` | `string?` | `null` | Optional `permission_endpoint` |
| `AuditEndpoint` | `string?` | `null` | Optional `audit_endpoint` |
| `InteractionEndpoint` | `string?` | `null` | Optional `interaction_endpoint` |
| `RevocationEndpoint` | `string?` | `null` | Optional `revocation_endpoint` |
| `ScopesSupported` | `IReadOnlyList<string>?` | `null` | Optional `scopes_supported` |

### AAuthAccessServerMetadataOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `EgressPolicy` | `AAuthEgressPolicy` | `Production` | URL/identifier admission policy for metadata URLs. |
| `Issuer` | `string` | required | Access Server issuer (`issuer`) |
| `AuthTokenEndpoint` | `string` | required | `auth_token_endpoint` |
| `SigningKeys` | `AAuthSigningKeySet` | required | Signing keys published at the JWKS. |
| `Name` | `string?` | `null` | Human-readable name (`name`) |
| `Description` | `string?` | `null` | Markdown description (`description`) |
| `LogoUri` | `string?` | `null` | `logo_uri` |
| `LogoDarkUri` | `string?` | `null` | `logo_dark_uri` |
| `DocumentationUri` | `string?` | `null` | `documentation_uri` |
| `TosUri` | `string?` | `null` | `tos_uri` |
| `PolicyUri` | `string?` | `null` | `policy_uri` |
| `RevocationEndpoint` | `string?` | `null` | Optional `revocation_endpoint` |

## Signing Keys

### Key interfaces

`IAAuthKey` is a key's public identity (algorithm, public JWK, thumbprint,
verification). `IAAuthSigner : IAAuthKey` adds
`ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken)`;
every signing API (token builders' `BuildAsync`, `NamingJwtBuilder.BuildAsync`,
`AAuthSigningHandler`) takes an `IAAuthSigner` and awaits it, so a remote HSM or
KMS signer does not block a thread. `IAAuthExportableKey : IAAuthSigner` adds
`ToPrivateJwk()`. The built-in `AAuthKey` (Ed25519) and `EcdsaAAuthKey` (ES256)
are local, exportable keys; the concrete types also keep a synchronous
`Sign(byte[])`. See [Key Management](../advanced/key-management.md).

### AAuthSigningKeySet

An issuer's signing keys. The JWKS publishes every key in the set; new tokens
are signed with the active key (`Active` returns its `kid` and signer together).
Construct with `new AAuthSigningKeySet(kid, signer)` for a single key, or
`new AAuthSigningKeySet(activeKid)` and add keys. Rotate a running server with
`Add` (publish) → `Activate` (sign with it) → `Remove` (retire the old key after
its tokens expire); no restart is needed.

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Count` | `int` | 0 | Number of published keys |
| `KeyIds` | `IReadOnlyList<string>` | empty | Published key ids, in insertion order |
| `ActiveKeyId` | `string` | First key added | Key id new tokens are signed with |

The indexer (`set["kid"] = signer`) adds or replaces a key; `TryGetSigner`
looks one up. The active key cannot be removed.

## Key Storage

### FileKeyStore (File-Based)

| Property/Method | Description |
|----------------|-------------|
| `Directory` | Storage directory path |
| `Default()` | Creates store at `~/.aauth/keys/` |
| `LoadOrCreate(name)` | Load key or generate new Ed25519 key |

### DefaultSignatureKeyResolver

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `jwksClient` | `JwksClient?` | null | Client for fetching JWKS endpoints |

## Signing (Agent-Side)

### AAuthSigningHandler

A `DelegatingHandler` constructed with an `IAAuthSigner` that signs with the
private key and an `ISignatureKeyProvider` supplying the `Signature-Key` header
value. The provider does not supply the private key. The constructor also accepts
an optional `TimeProvider` for deterministic tests.

Configure `Label` (default `"sig"`) to match the provider's signature label,
`Capabilities` to declare outbound capabilities (for code, prefer
`AAuthConstants.Capabilities.Interaction`, `.Clarification` and `.Payment`), and
`OnSignatureBase` to inspect the canonical signed input. Per-request
`AdditionalComponentsKey` selects extra covered components. The handler validates
that the provider's `Signature-Key` member uses the same label as `Label`;
mismatches fail locally instead of emitting invalid wire output. Prefer
`AAuthClientBuilder` for ordinary client composition.

The signer never future-dates the RFC 9421 `created` parameter. To avoid a
duplicate replay tuple, a second request with the same signing key, method,
authority and path waits until the next wall-clock second. Cancellation while
waiting cancels the request before it is sent. Each delay emits the
`aauth.signing.created_wait` metric.

### ISignatureKeyProvider Implementations

| Provider | Constructor Parameters |
|----------|----------------------|
| `HwkSignatureKeyProvider` | `IAAuthKey key, string label = "sig"` |
| `JwksUriSignatureKeyProvider` | `string id, string dwk, string kid, string label = "sig"` |
| `JwksSignatureKeyProvider` | `string url, string kid, string label = "sig"` |
| `JwtSignatureKeyProvider` | `Func<string> tokenFactory, string label = "sig"` |
| `JktJwtSignatureKeyProvider` | `Func<string> namingJwtFactory, string label = "sig"` |

`JwksUriSignatureKeyProvider` discovers role metadata from `id` and `dwk`;
it does not accept a direct JWKS URL. `JktJwtSignatureKeyProvider` supplies the
naming JWT only. Its `AAuthSigningHandler` must use the ephemeral key named by
that JWT, while the durable key signs the naming JWT itself. `label` selects
the matching dictionary member across all three signature fields.

### AAuthClientOptions (AddAAuthClient)

Generic Signature Keys `HttpClient` registration options. Use `AddAAuthAgent`
for AAuth authorization flows.

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `KeyHandle` | `string?` | `null` | Signing key handle in the registered `IKeyStore`; set exactly one of `KeyHandle` or `Signer`. |
| `Signer` | `IAAuthSigner?` | `null` | *Code-only.* Signing key; set exactly one of `Signer` or `KeyHandle`. |
| `SignatureKeyProvider` | `ISignatureKeyProvider?` | `null` | *Code-only.* Signature-Key carrier scheme; required. |
| `Capabilities` | `string[]?` | `null` | Optional `AAuth-Capabilities` values sent on every request. |

## Dependency Injection Options

### AAuthAgentOptions (AddAAuthAgent)

Named options, validated when the host starts. Members marked *code-only* are
delegates or instances; every other member binds from configuration, such as
`AAuth:Agents:<name>`.

| Property | Type | Required | Description |
|----------|------|:--------:|-------------|
| `KeyHandle` | `string?` | One key | Signing key handle in the registered `IKeyStore` |
| `Signer` | `IAAuthSigner?` | One key | *Code-only.* Signing key (must have private component) |
| `AgentToken` | `string?` | One identity source | Already-held agent JWT; no implicit enrollment |
| `AgentTokenFactory` | `Func<string>?` | One identity source | *Code-only.* Returns the current agent JWT |
| `TokenRefresher` | `ITokenRefresher?` | One identity source | *Code-only.* Auto-refresh before token expiry; can renew an already-held agent token |
| `TokenRefreshThreshold` | `TimeSpan?` | No | Refresh window before `exp`; property default is `null`, resolved by builders/handlers to the draft-11 five-minute effective default |
| `SelfIssued` | `AAuthSelfIssuedAgentOptions` | One identity source | Self-issued identity (keys below) |
| `AgentProvider` | `AAuthAgentProviderOptions` | One identity source | Enrolled identity (keys below); requires `KeyHandle` |
| `JwksUri` | `AAuthJwksUriIdentityOptions` | One identity source | Server identity (keys below) |
| `SignatureKeyProvider` | `ISignatureKeyProvider?` | One identity source | *Code-only.* Generic signing only; cannot combine with AAuth authorization flows |
| `PersonServer` | `string?` | No | Person Server URL; enables `401` challenge handling (default: the token's `ps` claim) |
| `HandleChallenges` | `bool?` | No | Override the challenge-handling default |
| `Challenge` | `ChallengeHandlingOptions` | No | PS interaction/clarification callbacks and polling |
| `HandleInteractions` | `bool?` | No | Override the interaction-handling default (on when an `Interaction` callback is set) |
| `Interaction` | `InteractionHandlingOptions` | No | Resource `202` interaction/approval callbacks and polling |
| `Capabilities` | `string[]?` | No | `AAuth-Capabilities` on every signed request; entries must be Structured Field tokens |
| `Mission` | `Mission?` | No | *Code-only.* The agent's approved mission |
| `UpstreamTokenProvider` | `Func<string?>?` | No | *Code-only.* Upstream auth token to chain |
| `ChainFromHttpContext` | `bool` | No | Chain the current request's verified upstream auth token |
| `EnableResourceManagedAccess` | `bool` | No | Capture and replay `AAuth-Access` (resource-managed) |
| `AAuthAccessStore` | `IAAuthAccessStore?` | No | *Code-only.* Per-origin `AAuth-Access` store (default in-memory) |
| `EgressPolicy` | `AAuthEgressPolicy?` | No | *Code-only.* Egress policy; property default is `null`, resolved by builders/handlers to `Production` unless development loopback origins are configured |
| `DevelopmentLoopbackOrigins` | `string[]?` | No | Loopback origins a development agent may call |
| `InnerHandler` | `HttpMessageHandler?` | No | *Code-only.* Transport under the signer |
| `TransportContract` | `AAuthTransportContract?` | No | *Code-only.* Egress guarantee of `InnerHandler` |
| `OnSignatureBase` | `Action<HttpRequestMessage, string>?` | No | *Code-only.* Observes each signature base |
| `TokenCache` | `IAAuthTokenCache?` | No | *Code-only.* Cache of person and auth tokens (default: the agent's keyed in-memory cache) |

The identity-source objects bind as nested sections:

| Key | Type | Description |
|-----|------|-------------|
| `SelfIssued:Issuer` | `string?` | Agent token issuer: the agent's own server identifier |
| `SelfIssued:Subject` | `string?` | Agent identifier (`sub`) |
| `SelfIssued:KeyId` | `string?` | `kid` of the signing key (default: its JWK thumbprint) |
| `AgentProvider:RefreshEndpoint` | `string?` | Agent Provider refresh endpoint that renews the enrolled agent token |
| `JwksUri:Id` | `string?` | Server identifier whose metadata names the JWKS |
| `JwksUri:Dwk` | `string?` | Well-known document name for metadata discovery |
| `JwksUri:KeyId` | `string?` | `kid` of the signing key in that JWKS |

Nested identity option classes expose these properties:

| Type | Property | Type | Default | Description |
|------|----------|------|---------|-------------|
| `AAuthSelfIssuedAgentOptions` | `Issuer` | `string?` | `null` | Agent token issuer: the agent's own server identifier. |
| `AAuthSelfIssuedAgentOptions` | `Subject` | `string?` | `null` | Agent identifier (`sub`). |
| `AAuthSelfIssuedAgentOptions` | `KeyId` | `string?` | `null` | `kid` of the signing key (default: its JWK thumbprint). |
| `AAuthAgentProviderOptions` | `RefreshEndpoint` | `string?` | `null` | Agent Provider refresh endpoint that renews the enrolled agent token. |
| `AAuthJwksUriIdentityOptions` | `Id` | `string?` | `null` | Server identifier whose metadata names the JWKS. |
| `AAuthJwksUriIdentityOptions` | `Dwk` | `string?` | `null` | Well-known document name for metadata discovery. |
| `AAuthJwksUriIdentityOptions` | `KeyId` | `string?` | `null` | `kid` of the signing key in that JWKS. |

`AddAAuthAgent` requires exactly one key and exactly one identity source.
Omitting credentials does not select HWK. `PersonServer`, challenge handling,
`Mission` and call chaining require an agent-token identity (an agent token,
`SelfIssued` or `AgentProvider`), so a generic provider cannot be combined with
PS challenge handling or resource-managed AAuth authorization. See
[Dependency Injection](dependency-injection.md#aauthagentoptions) for every
rule. The MockAgentProvider sample also accepts
`AgentProvider:KeyDirectory` for isolated persisted AP signing keys; its default
remains `~/.aauth/ap-keys`.

### AAuthResourceOptions (AddAAuthResource)

Register with `AddAAuthResource(configure: …)` or bind from `AAuth:Resource`.

| Property | Type | Required | Description |
|----------|------|:--------:|-------------|
| `Issuer` | `string` | Yes | Resource canonical URL |
| `AccessServer` | `string?` | No | Access Server issuer for four-party resources. When set, challenges use it as the resource-token `aud` and auth-token verification defaults to AS-issued `aauth-access.json` tokens from that issuer. |
| `SigningKeys` | `AAuthSigningKeySet` | Conditional | Signing keys published at the JWKS (tokens are signed with the active key); required when issuing resource tokens or making signed calls, optional for verification-only resources |
| `KeyHandle` | `string?` | No | Handle in the registered `IKeyStore` to load the signing key from when `SigningKeys` is empty |
| `KeyId` | `string?` | No | `kid` for the key loaded from `KeyHandle` (default: its JWK thumbprint) |
| `EgressPolicy` | `AAuthEgressPolicy` | No | *Code-only.* Egress policy for outbound metadata and JWKS fetches (default `Production`) |
| `MaxSignatureAge` | `TimeSpan` | No | Signature validity window for inbound `created`, both directions (default 60 seconds) |
| `TimeProvider` | `TimeProvider` | No | *Code-only.* Clock for signature and token checks (default System) |
| `EnableReplayDetection` | `bool` | No | Request replay detection keyed by key thumbprint and signature base (default `true`) |
| `EnableResourceManagedAccess` | `bool` | No | Registers an in-memory `IOpaqueTokenStore` for §Resource-Managed Authorization unless one exists (default `false`) |
| `KeyResolver` | `ISignatureKeyResolver?` | No | *Code-only.* Custom signature key resolver (default `DefaultSignatureKeyResolver`) |
| `Name` | `string?` | No | Resource display name (`name`) |
| `Description` | `string?` | No | Markdown description (`description`) for consent display |
| `LogoUri` | `string?` | No | `logo_uri` |
| `LogoDarkUri` | `string?` | No | `logo_dark_uri` |
| `DocumentationUri` | `string?` | No | `documentation_uri` |
| `TosUri` | `string?` | No | `tos_uri` |
| `PolicyUri` | `string?` | No | `policy_uri` |
| `ScopeDescriptions` | `Dictionary<string, string>?` | No | Scope descriptions for metadata |
| `SignatureWindow` | `int?` | No | Advertised signature validity (seconds) |
| `AdditionalSignatureComponents` | `IReadOnlyList<string>?` | No | Emits `additional_signature_components` in resource metadata |
| `AccessMode` | `string?` | No | Advisory `access_mode`: `agent-token`, `person-token`, resource-managed `session-token` (`AAuth-Access`), `auth-token`, or R3's `per-call` |
| `AuthorizationEndpoint` | `string?` | No | Resource's proactive authorization endpoint URL; not the PS/AS resource-token recipient (draft-11 removed `PersonServerAudience`; the recipient is `AccessServer` or the presented token's PS) |
| `RevocationEndpoint` | `string?` | No | Revocation endpoint URL |
| `ConfigureRevocation` | `Action<AAuthRevocationOptions>?` | No | *Code-only.* Adjusts the endpoint mapped by `MapAAuthResourceRevocation` |
| `AdditionalMetadata` | `Dictionary<string, JsonNode?>?` | No | *Code-only.* Extension members merged into the resource well-known document |

### AAuthDiscoveryOptions (AddAAuthDiscovery)

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `EgressPolicy` | `AAuthEgressPolicy` | `Production` | Egress policy for the shared `MetadataClient` and `JwksClient` |
| `MaxCacheEntries` | `int` | 1024 | Entry cap for each discovery cache |
| `MaxCacheAge` | `TimeSpan` | 24 hours | Upper bound (at most 24 hours) on any cached entry's freshness, whatever the server's cache headers say |
| `MetadataCacheTtl` | `TimeSpan` | 5 minutes | Metadata document cache lifetime |
| `JwksCacheTtl` | `TimeSpan` | 1 hour | JWKS cache lifetime |
| `JwksMinRefreshInterval` | `TimeSpan` | 1 minute | Minimum interval between JWKS fetches (rate limit) |

### ChallengeHandlingOptions (WithChallengeHandling)

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `OnInteractionRequired` | `Func<Interaction, CancellationToken, Task>?` | null | Deferred consent callback |
| `OnClarificationRequired` | `Func<ClarificationRequirement, CancellationToken, Task<ClarificationResponse>>?` | null | Answers PS clarification questions; declares the `clarification` capability |
| `MaxClarificationRounds` | `int` | 5 | Clarification rounds before giving up |
| `PollingTimeout` | `TimeSpan` | 5 minutes | Max deferred polling time |
| `DefaultPollInterval` | `TimeSpan` | 5 seconds | Poll interval (overridden by Retry-After) |
| `PreferWaitSeconds` | `int?` | null | Sends `Prefer: wait=N` to long-poll |
| `MinPollInterval` | `TimeSpan` | zero | Optional minimum delay between polls |
| `OnPoll` | `Action<HttpResponseMessage>?` | null | Per-poll callback (logging/progress) |
| `Capabilities` | `IList<string>?` | null | Capabilities sent to the PS (null = infer) |
| `Prompt` | `string?` | null | OIDC `prompt` sent to the PS |
| `AdditionalSignatureComponents` | `IReadOnlyDictionary<string, IReadOnlyList<string>>?` | null | Per-origin extra covered components to seed |

Call `AddResourceMetadata(ResourceMetadata metadata)` to seed
`AdditionalSignatureComponents` from parsed resource metadata. The helper uses
the metadata issuer's origin (`scheme://host[:port]`) and the typed
`ResourceMetadata.AdditionalSignatureComponents` field so the first request can
cover resource-required components without an `invalid_input` retry.

### InteractionHandlingOptions (WithInteractionHandling)

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `OnInteractionRequired` | `Func<Interaction, CancellationToken, Task>?` | null | Resource interaction callback; declares the `interaction` capability |
| `OnApprovalPending` | `Func<CancellationToken, Task>?` | null | Approval polling callback |
| `PollingTimeout` | `TimeSpan` | 5 minutes | Max polling time |
| `DefaultPollInterval` | `TimeSpan` | 5 seconds | Poll interval (overridden by Retry-After) |
| `PreferWaitSeconds` | `int?` | null | Sends `Prefer: wait=N` to long-poll |
| `MinPollInterval` | `TimeSpan` | zero | Optional minimum delay between polls |
| `OnPoll` | `Action<HttpResponseMessage>?` | null | Per-poll callback |

### TokenExchangeClientOptions

Primitive client options for direct `TokenExchangeClient` construction. Builder
and DI paths set these from shared services.

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `VerifyAuthTokenSignature` | `bool` | `true` | Verify returned auth-token issuer signatures through metadata/JWKS before accepting them. Structural/context checks always run. |
| `JwksClient` | `JwksClient?` | `null` | Cached JWKS client for returned auth-token verification; direct callers can pass a shared instance. |

### ChallengeOptions (UseAAuthChallenge)

Low-level server challenge middleware options. `UseAAuth` and
`MapAAuthResource` configure these from the resource registration and endpoint
metadata for ordinary applications.

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `EgressPolicy` | `AAuthEgressPolicy` | `Production` | URL/identifier admission policy for derived challenge endpoints. |
| `AccessMode` | `AAuthAccessMode` | `RequireAuthToken` | Challenge/pass-through behavior: auth-token, person-token, agent-token, resource-managed, or identity. |
| `ResourceSigningKeys` | `AAuthSigningKeySet?` | `null` | Resource signing keys; required when issuing resource-token challenges. |
| `ResourceIdentifier` | `string?` | `null` | Resource issuer/identifier used as resource-token `iss`. |
| `RequestedAccount` | `Func<HttpContext,string?>?` | `null` | Optional account selector for account-bound challenges. |
| `AccessServer` | `string?` | `null` | Four-party Access Server issuer; when null, the resource-token audience is the presented person token's PS. |
| `DefaultScopes` | `string?` | `null` | Space-separated default scopes requested in resource tokens. |
| `ScopeDescriptions` | `IReadOnlyDictionary<string,string>?` | `null` | Scope descriptions copied into resource-token interaction details. |

### AAuthResourcePipelineOptions (MapAAuthResource)

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `AccountSelector` | `Func<HttpContext,string?>?` | `null` | Selects the resource account for account-bound challenges and verification. |
| `AccessMode` | `AAuthAccessMode` | `RequireAuthToken` | Pipeline access gate: identity, person-token, auth-token, agent-token, or resource-managed pass-through. |
| `Trust` | `AAuthTrustOptions` | `new()` (open) | Trust applied by the unified resource pipeline. |
| `DefaultScopes` | `string?` | `null` | Default scopes to request in resource tokens. |

### AAuthResourceManagedOptions (AddAAuthResourceManaged)

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `ConsentUrl` | `string` | required | Absolute consent URL advertised in `requirement=interaction`; must not include query or fragment. |
| `PollPath` | `string` | `/pending` | Deferred-response `Location` path prefix; `MapAAuthInteractionPoll` serves `{PollPath}/{code}`. |
| `TokenTtl` | `TimeSpan` | 30 minutes | Lifetime of issued opaque `AAuth-Access` tokens. |
| `CodeTtl` | `TimeSpan` | 10 minutes | Lifetime of pending interaction codes. |

### AAuthRevocationOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `IsAcceptedIssuer` | `Func<string,bool>?` | `null` (deny) | Verified server identities this endpoint accepts revocations from. Assign `AAuthTrust.Any` for any verified issuer. |
| `MaxTokenLifetime` | `TimeSpan` | 24 hours | Latest accepted `exp`, bounding unseen revocation retention. |
| `Limits` | `RevocationLimits?` | `new()` | Per-issuer entry/rate limits; `null` disables them. |
| `DeferAfter` | `TimeSpan` | 20 seconds | Hold an in-progress cascade before answering `202` with a pending URL. |
| `ReportDownstream` | `bool` | `true` | Include downstream cascade results in successful responses. |
| `RevokeGrantAsync` | `Func<TokenGrant,CancellationToken,Task<RevocationDownstreamError?>>?` | `null` | Generic endpoint hook for downstream revocation; role endpoints use their registered revocation service. |

### AAuthHeldInvocationOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `PathPrefix` | `string` | `/aauth/held` | Held-invocation poll path prefix. |
| `PendingLifetime` | `TimeSpan` | 10 minutes | Default lifetime for an unexecuted held invocation. |
| `TimeProvider` | `TimeProvider` | System | Clock for pending expiry. |

### CallChainingOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `AgentKey` | `IAAuthSigner` | required | Resource's own agent signing key for downstream requests. |
| `SignatureKeyProvider` | `ISignatureKeyProvider` | required | Produces the downstream `Signature-Key`, usually a `JwtSignatureKeyProvider` over the resource's agent token. |
| `HttpClientFactory` | `Func<HttpClient>?` | `null` | Optional signed client factory for downstream token endpoints. |

### GovernanceOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `OnInteractionRequired` | `Func<Interaction,CancellationToken,Task>?` | `null` | Handles PS governance `requirement=interaction`. |
| `OnClarificationRequired` | `Func<ClarificationRequirement,CancellationToken,Task<ClarificationResponse>>?` | `null` | Handles governance clarification rounds. |
| `MaxClarificationRounds` | `int` | 5 | Clarification rounds before aborting. |
| `PollerOptions` | `DeferredPollerOptions?` | `null` | Optional deferred-response polling overrides. |

### AAuthGovernancePipelineOptions (MapAAuthGovernance)

Controls PS governance route mapping. The mapper composes `RoutePrefix` with
each endpoint path and collapses duplicate slashes at the seam.

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `EgressPolicy` | `AAuthEgressPolicy` | `Production` | URL/identifier admission policy for governance endpoints. |
| `TimeProvider` | `TimeProvider` | System | Clock for deferred governance expiry and mission `expires_at` checks. |
| `RoutePrefix` | `string` | `""` | Prefix prepended to every governance path, for example `/governance`. |
| `PermissionPath` | `string` | `/permission` | Permission endpoint path. |
| `AuditPath` | `string` | `/audit` | Audit endpoint path. |
| `InteractionEndpointPath` | `string` | `/mission-interaction` | Signed interaction endpoint path; distinct from browser consent paths. |
| `MissionPath` | `string` | `/mission` | Mission creation/action endpoint path. |
| `PendingPath` | `string` | `/governance-pending` | Deferred governance poll path prefix; the mapper appends `/{id}`. |
| `InteractionUrl` | `string?` | `null` | Optional browser-facing interaction URL included in deferred governance requirements. |
| `PersonServer` | `string?` | `null` | PS identifier recorded on missions and pending approvals; null derives from the request origin. |

### AAuthFederationOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `TransportContract` | `AAuthTransportContract?` | `null` | Transport admission guarantee for federation-specific HTTP clients. |

### R3AccessTokenEndpointOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `EgressPolicy` | `AAuthEgressPolicy` | `Production` | URL/identifier policy for R3 document fetches. |
| `FetchTransportContract` | `AAuthTransportContract?` | `null` | Admission guarantee for custom R3 fetch transport. |
| `Issuer` | `string` | required | AS issuer for R3 auth tokens. |
| `SigningKeys` | `AAuthSigningKeySet` | required | AS signing keys. |
| `TokenPath` | `string` | `/token` | R3 AS token endpoint path. |
| `Trust` | `AAuthTrustOptions` | `new()` (open) | Person Servers this R3 AS will broker for. |
| `FetchAndVerifyAsync` | `Func<HttpContext,string,string,string,CancellationToken,Task<byte[]>>?` | `null` | Custom signed R3 document fetch/verification callback. |
| `FetchHttpMessageHandler` | `HttpMessageHandler?` | `null` | Handler for default signed R3 document fetches. |
| `AuditSink` | `IR3AuditSink` | required | Durable audit persistence required before token release. |
| `TimeProvider` | `TimeProvider` | System | Clock for issuance and pending consent. |
| `VocabularySchemas` | `R3VocabularySchemas` | Standard | Accepted R3 vocabularies. |
| `OperationValidator` | `IR3OperationValidator?` | `null` | Validates referenced operations against authoritative definitions. |
| `AuthoritativeDefinitions` | `IR3AuthoritativeDefinitionProvider?` | `null` | Supplies resource-defined operation inventories. |
| `IsOperationAllowed` | `Func<R3OperationIdentity,bool>?` | `null` | AS policy for outright operation grants. |
| `IsProposalAllowed` | `Func<R3ProposalDocument,bool>?` | `null` | AS policy for concrete per-call proposals. |
| `IsScopeAllowed` | `Func<string,string,bool>?` | `null` | AS policy for non-R3 scopes. |
| `IsPerCallOperation` | `Func<R3OperationIdentity,bool>?` | `null` | Marks operations that require per-call approval. |
| `RequireProposalConsent` | `bool` | `false` | Parks per-call proposals behind human consent. |
| `BrowserConsent` | `BrowserConsentSessions?` | `null` | Browser session helper for proposal consent. |
| `ConsentPath` | `string` | `/interaction/consent` | Browser consent path for per-call proposals. |
| `PendingPath` | `string` | `/pending` | Poll path used after per-call proposal consent. |

### AAuthEventsOptions and AAuthSubscriptionEndpointOptions

| Type | Property | Type | Default | Description |
|------|----------|------|---------|-------------|
| `AAuthEventsOptions` | `EgressPolicy` | `AAuthEgressPolicy` | `Production` | URL/identifier policy for Events metadata/JWKS. |
| `AAuthEventsOptions` | `TimeProvider` | `TimeProvider` | System | Clock for Events token verification. |
| `AAuthEventsOptions` | `InnerHandler` | `HttpMessageHandler?` | `null` | Optional Events transport. |
| `AAuthEventsOptions` | `TransportContract` | `AAuthTransportContract?` | `null` | Admission guarantee for `InnerHandler`. |
| `AAuthSubscriptionEndpointOptions` | `Resource` | `string?` | registered resource issuer | Resource identifier for protected subscription registration. |
| `AAuthSubscriptionEndpointOptions` | `Operation` | `string` | `""` | Operation name authorized by the subscribe token/ticket. |
| `AAuthSubscriptionEndpointOptions` | `ProtectedChannel` | `bool` | `false` | Whether registration requires a protected ticket. |
| `AAuthSubscriptionEndpointOptions` | `ValidateParameters` | `Func<JsonObject,bool>?` | `null` | Validates optional registration parameters; omitted body is accepted only when this is `null`. |
| `AAuthSubscriptionEndpointOptions` | `SubscriptionLifetime` | `TimeSpan?` | `null` | Optional server-side subscription lifetime. |

## Extensibility Patterns

Every decision point accepts the same forms. The SDK resolves them in one order:

1. a per-request override (agent: `HttpRequestMessage.Options`) or a
   per-endpoint override (server: endpoint metadata);
2. an instance or delegate on the options or builder;
3. a DI service keyed by the agent or server instance name, then an unkeyed one;
4. the SDK default.

Configuration binding sets only data; it ignores the *code-only* delegate and
instance members.

| Decision | Data (configuration) | Delegate or instance | DI service | Per-request or per-endpoint |
|----------|----------------------|----------------------|------------|-----------------------------|
| Issuer trust | `Trust:<Party>:Allowed` | `Trust.<Party>.Predicate` / `PredicateAsync`, `Trust.Policy` | `IAAuthTrustPolicy` | `.RequireAAuth(scope, trust: policy)` |
| Agent signing key | `KeyHandle` (loaded from `IKeyStore`) | `Signer` | `IKeyStore` | — |
| User interaction | `HandleInteractions` | `Interaction.OnInteractionRequired`, `Challenge.OnInteractionRequired` | `IAAuthInteractionHandler` | `AAuthRequestOptions.InteractionHandler` |
| Clarification | `Challenge:MaxClarificationRounds` | `Challenge.OnClarificationRequired` | `IAAuthClarificationHandler` | `AAuthRequestOptions.ClarificationHandler` |
| Token cache | — | `TokenCache` | `IAAuthTokenCache` (keyed) | — |
| PS/AS seams | — | builder `Use*` helpers | the seam interface | — |

Issuer trust, in all four forms:

```csharp
// Data: an allow-list; binds from Trust:AuthTokenIssuers:Allowed:0.
app.UseAAuth(o => o.Trust.AuthTokenIssuers.Allowed = new HashSet<string> { "https://ps.example" });

// Delegate: a predicate over the issuer, with the request and services.
app.UseAAuth(o => o.Trust.AuthTokenIssuers.PredicateAsync = (context, ct) =>
    ValueTask.FromResult(context.Issuer.StartsWith("https://ps.", StringComparison.Ordinal)));

// DI service: used when the options set no Policy.
services.AddSingleton<IAAuthTrustPolicy, PartnerTrustPolicy>();

// Per endpoint: replaces the resource-wide trust for this route only.
app.MapGet("/admin", () => "ok").RequireAAuth("admin", trust: new PartnerTrustPolicy());

public sealed class PartnerTrustPolicy : IAAuthTrustPolicy
{
    public ValueTask<bool> IsTrustedAsync(AAuthTrustContext context, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(context.Issuer == "https://ps.partner.example");
}
```

### Multi-tenant hosts

A resource serving several tenants resolves each tenant's Person Server from the
request. An agent host creates one caller-owned agent per tenant and reuses it,
because the agent holds that tenant's token cache:

```csharp
var tenantPersonServers = new Dictionary<string, string>
{
    ["a.example"] = "https://ps.a.example",
    ["b.example"] = "https://ps.b.example",
};
app.UseAAuth(o => o.Trust.AuthTokenIssuers.PredicateAsync = (context, ct) =>
    ValueTask.FromResult(context.HttpContext is { } http
        && tenantPersonServers.TryGetValue(http.Request.Host.Host, out var expected)
        && context.Issuer == expected));

using var tenantAgent = factory.Create(new AAuthAgentDescriptor("tenant-a")
{
    Signer = key,
    AgentToken = agentToken,
    PersonServer = tenantPersonServers["a.example"],
});
```

### KMS or HSM signer

A signer whose private key never leaves a KMS or HSM implements `IAAuthSigner`
and awaits the remote call in `SignAsync`. Register it as the agent's `Signer`,
or return it from a custom `IKeyStore` so `KeyHandle` loads it:

```csharp
// Your KMS SDK adapter is registered as IKmsClient.
services.AddAAuthAgent("calendar", o =>
{
    o.SelfIssued.Issuer = "https://agent.example";
    o.SelfIssued.Subject = "aauth:calendar@agent.example";
});
services.AddOptions<AAuthAgentOptions>("calendar")
    .Configure<IKmsClient>((o, kms) => o.Signer = new KmsSigner(kms, "agent-key"));

public interface IKmsClient
{
    JsonObject GetPublicJwk(string keyName);
    Task<byte[]> SignAsync(string keyName, byte[] data, CancellationToken cancellationToken);
}

public sealed class KmsSigner(IKmsClient kms, string keyName) : IAAuthSigner
{
    private readonly IAAuthKey _public = KeyFactory.FromPublicJwk(kms.GetPublicJwk(keyName));

    public string Algorithm => _public.Algorithm;
    public bool HasPrivateKey => true;
    public bool Verify(byte[] data, byte[] signature) => _public.Verify(data, signature);
    public JsonObject ToPublicJwk() => _public.ToPublicJwk();
    public string ComputeJwkThumbprint() => _public.ComputeJwkThumbprint();

    public async ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
        => await kms.SignAsync(keyName, data.ToArray(), cancellationToken);
}
```

## JSON Configuration Keys (samples)

The SDK's configuration overloads bind a whole section: `AddAAuthPersonServer`
from `AAuth:PersonServer`, `AddAAuthAccessServer` from `AAuth:AccessServer`, and
`AddAAuthResource` from `AAuth:Resource` (each extension class exposes a
`ConfigurationSection` constant). `AddAAuthAgent(name, section)` binds the section
you pass; the convention is `AAuth:Agents:<name>`. The keys are the option property names, such as
`AAuth:PersonServer:Issuer`, `AAuth:PersonServer:KeyHandle`,
`AAuth:PersonServer:Trust:AccessServers:Allowed:0` or
`AAuth:Agents:calendar:AgentProvider:RefreshEndpoint`.

The shipped samples bind a few `AAuth:*` keys from `appsettings.json` /
environment variables / command line. These are conventions of the samples (not
SDK-required), shown here as a reference for wiring your own hosts.

| Key | Type | Used by | Description |
|-----|------|---------|-------------|
| `AAuth:Issuer` | `string` | Profile/Calendar/Trips/Wallet/Inbox, MockPersonServer, Concierge | The host's own canonical URL (resource/PS `iss`). |
| `AAuth:SignatureWindow` | `int` (seconds) | Profile/Calendar/Trips/Wallet/Inbox, MockPersonServer | Max HTTP-signature age accepted; default `60`. |
| `AAuth:TrustedPersonServers` | `string[]` | Calendar/Trips | Allow-list mapped to the resource pipeline's `Trust.AuthTokenIssuers.Allowed` (`app.UseAAuth(o => o.Trust.AuthTokenIssuers.Allowed = …)`). The SDK default for an unset list is open (accept any *verifiable* PS, namespaced by `iss`), but these samples default to `http://localhost:5100`; an empty array denies all auth tokens (deny-all kill-switch). |
| `AAuth:LocalKeyHandle` | `string` | agent samples | Key handle in the `IKeyStore` for the agent's signing key. |
| `AAuth:ApRefreshEndpoint` | `string` | agent samples | Agent Provider refresh endpoint for enrolled agents. |
| `AAuth:PersonServer` | `string` | Concierge | Downstream Person Server URL (a sample value, not the SDK's `AAuth:PersonServer` options section). |
| `AAuth:Downstream` | `string` | Concierge | Downstream resource URL. |
| `AAuth:AgentId` | `string` | Concierge | The agent identifier this host signs as. |
| `AAuth:Agents:aria` | `AAuthAgentOptions` section | SampleApp | Aria, the self-issued agent every page uses: `PersonServer`, `SelfIssued:Issuer` / `Subject` / `KeyId`, polling budgets. The key is generated at startup. |

## Further Reading

- [Getting Started](../getting-started.md) — minimal setup
- [Error Handling](../advanced/error-handling.md) — all error codes
- [Verification Middleware](../server/verification-middleware.md) — server setup
