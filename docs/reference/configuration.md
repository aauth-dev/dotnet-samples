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
| `ResourceIdentifier` | `string?` | `AddAAuthResource` `Issuer` | Resource's own identifier; auth-token and person-token `aud` must equal it. With no identifier, auth and person tokens are rejected (`invalid_request`). |
| `AcceptedSchemes` | `IReadOnlyList<string>` | `["jwt"]` | Schemes accepted by this verification role; generic signing is an explicit opt-in. |
| `SignatureLabel` | `string` | `"sig"` | Matching dictionary member selected from all three signature fields. |
| `RequiredComponents` | `IReadOnlyCollection<string>` | `[]` | Additional required covered components. |
| `GenericSignatureKeys` | `bool` | `false` | Use generic Signature Keys failure status policy instead of AAuth's 401 profile. |
| `Trust` | `AAuthTrustOptions` | `new()` (open) | Agent Provider, auth-token issuer and person-token issuer trust; see [AAuthTrustOptions](#aauthtrustoptions). |
| `ExpectedAuthTokenDwk` | `string?` | `aauth-person.json` | Auth-token `dwk` pin. `AddAAuthResource` with `AccessServer` derives `aauth-access.json`; set `null` only for explicit mixed PS/AS deployments with a `TokenDwk`-aware trust policy. |
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
| `InteractionEndpointPath` | `string?` | `null` | §Interaction Endpoint path, advertised as issuer + path |
| `MissionPath` | `string?` | `null` | Mission endpoint path, advertised as issuer + path |
| `PermissionPath` | `string?` | `null` | Permission endpoint path, advertised as issuer + path |
| `AuditPath` | `string?` | `null` | Audit endpoint path, advertised as issuer + path |
| `Trust` | `AAuthTrustOptions` | `new()` (open) | `Trust.AccessServers` governs the AS URLs the PS will federate to. Unconfigured ⇒ federate to the AS named in a verified resource token's `aud` (the spec default); `Allowed` empty ⇒ three-party only (four-party disabled); non-empty ⇒ restrict to the listed Access Servers. Upstream auth tokens from an AS are accepted only when `Trust.AccessServers` is configured and accepts the issuer. |

The seams (`IIdentityClaimsAsserter`, `IPersonPendingStore`, `TokenVerifier`, and
the `IJtiStore` token inventory) resolve per instance: first the builder's `Use*`
helper, then an unkeyed DI registration, then the SDK default. The helper also
resolves the `IMissionStore` / `IMissionLog` mission primitives when a request
carries `mission_s256`. See
[Person Server and Access Server Registration](dependency-injection.md#person-server-and-access-server-registration)
and [Token Issuance → One-Call Person Server](../server/token-issuance.md#one-call-person-server-mapaauthpersonserver).

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
| `DeriveAgentClaims` | `Func<string, JsonObject?>?` | `null` | *Code-only.* Baseline policy claims derived from the verified agent id (demo convention; production uses the §Claims Required push) |
| `PendingPathPrefix` | `string` | `/pending` | Deferred-decision poll path prefix |
| `DefaultScope` | `string` | `""` | Scope assumed when the resource token omits one |
| `InteractionLoginPath` | `string` | `/interaction/login` | Browser entry point for interactive policies |
| `Trust` | `AAuthTrustOptions` | `new()` (open) | `Trust.PersonServers` governs the Person Servers this AS brokers for |

## Token Builders

### ResourceTokenBuilder

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Lifetime` | `TimeSpan` | 5 minutes | Token validity duration |
| `IssuedAt` | `DateTimeOffset?` | Now | Override issuance timestamp |
| `TokenId` | `string?` | Auto (UUID) | Custom jti value |

### AuthTokenBuilder

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `AgentTokenExpiresAt` | `DateTimeOffset` | Required | Expiry from the verified source agent token |
| `AuthorizationExpiresAt` | `DateTimeOffset?` | None | Additional verified presented/parent/upstream/mission ceiling |
| `TimeProvider` | `TimeProvider` | System | Issuance and expiration clock |
| `Lifetime` | `TimeSpan` | 1 hour | Positive requested lifetime, at most one hour, capped by verified ceilings |
| `Dwk` | `string` | `"aauth-person.json"` | Discovery well-known path |
| `IssuedAt` | `DateTimeOffset?` | Now | Override issuance timestamp |
| `TokenId` | `string?` | Auto (UUID) | Custom jti value |

### AgentTokenBuilder

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Lifetime` | `TimeSpan` | 1 hour | Token validity duration |
| `IssuedAt` | `DateTimeOffset?` | Now | Override issuance timestamp |
| `TokenId` | `string?` | Auto (UUID) | Custom jti value |

## Token Verification

### TokenVerifier

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `TimeProvider` | `TimeProvider` | System | Clock source |
| `ClockSkew` | `TimeSpan` | 60 seconds | Tolerance for optional future `iat` checks. `exp` has zero tolerance and is rejected when it is not in the future. |

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

| Property | Type | Required | Description |
|----------|------|:--------:|-------------|
| `Issuer` | `string` | Yes | Resource canonical URL |
| `SigningKeys` | `AAuthSigningKeySet?` | Conditional | Signing keys published at the JWKS (tokens are signed with the active key); required when issuing resource tokens or making signed calls, optional for verification-only resources |
| `Name` | `string?` | No | Human-readable resource name (`name`) |
| `ScopeDescriptions` | `IReadOnlyDictionary<string, string>?` | No | Scope → description |
| `SignatureWindow` | `int?` | No | Advertised signature validity (seconds) |
| `AdditionalSignatureComponents` | `IReadOnlyList<string>?` | No | Emits `additional_signature_components`; agents must cover these components on first request |
| `AuthorizationEndpoint` | `string?` | No | Resource's proactive authorization endpoint URL; not the PS/AS resource-token recipient (draft-11 removed `PersonServerAudience`; the recipient is `AccessServer` or the presented token's PS) |
| `RevocationEndpoint` | `string?` | No | Revocation endpoint URL |

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
`Capabilities` to declare outbound capabilities, and `OnSignatureBase` to inspect
the canonical signed input. Per-request `AdditionalComponentsKey` selects extra
covered components. The handler validates that the provider's `Signature-Key`
member uses the same label as `Label`; mismatches fail locally instead of
emitting invalid wire output. Prefer `AAuthClientBuilder` for ordinary client
composition.

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
| `TokenRefreshThreshold` | `TimeSpan?` | No | Refresh window before `exp` (default 5 minutes) |
| `SelfIssued` | `AAuthSelfIssuedAgentOptions` | One identity source | Self-issued identity (keys below) |
| `AgentProvider` | `AAuthAgentProviderOptions` | One identity source | Enrolled identity (keys below); requires `KeyHandle` |
| `JwksUri` | `AAuthJwksUriIdentityOptions` | One identity source | Server identity (keys below) |
| `SignatureKeyProvider` | `ISignatureKeyProvider?` | One identity source | *Code-only.* Generic signing only; cannot combine with AAuth authorization flows |
| `PersonServer` | `string?` | No | Person Server URL; enables `401` challenge handling (default: the token's `ps` claim) |
| `HandleChallenges` | `bool?` | No | Override the challenge-handling default |
| `Challenge` | `ChallengeHandlingOptions` | No | PS interaction/clarification callbacks and polling |
| `HandleInteractions` | `bool?` | No | Override the interaction-handling default (on when an `Interaction` callback is set) |
| `Interaction` | `InteractionHandlingOptions` | No | Resource `202` interaction/approval callbacks and polling |
| `Capabilities` | `string[]?` | No | `AAuth-Capabilities` on every signed request |
| `Mission` | `Mission?` | No | *Code-only.* The agent's approved mission |
| `UpstreamTokenProvider` | `Func<string?>?` | No | *Code-only.* Upstream auth token to chain |
| `ChainFromHttpContext` | `bool` | No | Chain the current request's verified upstream auth token |
| `EnableResourceManagedAccess` | `bool` | No | Capture and replay `AAuth-Access` (resource-managed) |
| `AAuthAccessStore` | `IAAuthAccessStore?` | No | *Code-only.* Per-origin `AAuth-Access` store (default in-memory) |
| `EgressPolicy` | `AAuthEgressPolicy?` | No | *Code-only.* Egress policy (default `Production`) |
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
| `AccessMode` | `string?` | No | Advisory `access_mode`: `agent-token`, `person-token`, `session-token`, `auth-token`, or R3's `per-call` |
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
