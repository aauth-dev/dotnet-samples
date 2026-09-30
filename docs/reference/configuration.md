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
| `ResourceIdentifier` | `string?` | `null` | Resource's own identifier for `aud` checks. When `null`, audience validation is skipped. |
| `AcceptedSchemes` | `IReadOnlyList<string>` | `["jwt"]` | Schemes accepted by this verification role; generic signing is an explicit opt-in. |
| `SignatureLabel` | `string` | `"sig"` | Matching dictionary member selected from all three signature fields. |
| `RequiredComponents` | `IReadOnlyCollection<string>` | `[]` | Additional required covered components. |
| `GenericSignatureKeys` | `bool` | `false` | Use generic Signature Keys failure status policy instead of AAuth's 401 profile. |
| `Trust` | `AAuthTrustOptions` | `new()` (open) | Agent Provider, auth-token issuer and person-token issuer trust; see [AAuthTrustOptions](#aauthtrustoptions). |
| `ClockSkew` | `TimeSpan` | 30 seconds | Tolerance applied to `exp`/`iat` checks |
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

### AAuthResourceOptions (via AddAAuthResource)

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Issuer` | `string` | — (required) | HTTPS issuer URL for this resource |
| `SigningKeys` | `AAuthSigningKeySet` | `new()` | Signing keys published at the JWKS; tokens are signed with the active key |
| `KeyHandle` | `string?` | `null` | Handle in the registered `IKeyStore` to load the signing key from when `SigningKeys` is empty |
| `KeyId` | `string?` | `null` | `kid` for the key loaded from `KeyHandle` (default: its JWK thumbprint) |
| `Name` | `string?` | `null` | Human-readable resource name (`name`) |
| `ScopeDescriptions` | `Dictionary<string, string>?` | `null` | Scope → description map for metadata |
| `SignatureWindow` | `int?` | `null` | Advertised signature validity (seconds) |
| `AuthorizationEndpoint` | `string?` | `null` | Resource's proactive authorization endpoint URL; not the PS/AS resource-token recipient (draft-11 removed `PersonServerAudience`; the recipient is `AccessServer` or the presented token's PS) |
| `RevocationEndpoint` | `string?` | `null` | Revocation endpoint URL |

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
| `TokenPath` | `string` | `/token` | Auth token endpoint path (`auth_token_endpoint`) |
| `PersonTokenPath` | `string` | `/person` | Person token endpoint path (`person_token_endpoint`) |
| `PendingPathPrefix` | `string` | `/pending` | Deferred-consent poll path prefix |
| `DefaultScope` | `string` | `""` | Scope assumed when the resource token omits one |
| `InteractionPath` | `string` | `/interaction` | Path the host maps for the consent page |
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
| `TokenPath` | `string` | `/token` | Auth token endpoint path (`auth_token_endpoint`) |
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
| `ClockSkew` | `TimeSpan` | 60 seconds | Tolerance for exp/iat validation |

## Deferred Consent (Polling)

### DeferredPollerOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `MaxTotalWait` | `TimeSpan` | 5 minutes | Maximum time to poll before timeout |
| `DefaultPollInterval` | `TimeSpan` | 5 seconds | Base interval between polls |
| `MinPollInterval` | `TimeSpan` | 100ms | Minimum interval floor |
| `PreferWaitSeconds` | `int?` | `null` | Send `Prefer: wait=N` header (long-poll) |
| `OnPoll` | `Action<HttpResponseMessage>?` | `null` | Callback after each poll response |

Server `Retry-After` headers override `DefaultPollInterval` (clamped to `MinPollInterval`).

### ChallengeHandlingOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `OnInteractionRequired` | `Func<Interaction, CancellationToken, Task>?` | `null` | Callback for 202+interaction |
| `PollingTimeout` | `TimeSpan` | 5 minutes | Maximum polling time |
| `DefaultPollInterval` | `TimeSpan` | 5 seconds | Interval between polls |
| `PreferWaitSeconds` | `int?` | `null` | `Prefer: wait=N` header value |
| `MinPollInterval` | `TimeSpan` | 100ms | Minimum poll interval floor |
| `OnPoll` | `Action<HttpResponseMessage>?` | `null` | Callback after each poll |

### InteractionHandlingOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `OnInteractionRequired` | `Func<string, string, CancellationToken, Task>?` | `null` | Callback for 202+interaction (URL, code) |
| `OnApprovalPending` | `Func<CancellationToken, Task>?` | `null` | Callback for 202+approval |
| `PollingTimeout` | `TimeSpan` | 5 minutes | Maximum polling time |
| `DefaultPollInterval` | `TimeSpan` | 5 seconds | Interval between polls |
| `PreferWaitSeconds` | `int?` | `null` | `Prefer: wait=N` header value |
| `MinPollInterval` | `TimeSpan` | 100ms | Minimum poll interval floor |
| `OnPoll` | `Action<HttpResponseMessage>?` | `null` | Callback after each poll |

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

### AAuthResourceMetadataOptions

| Property | Type | Required | Description |
|----------|------|:--------:|-------------|
| `Issuer` | `string` | Yes | Resource canonical URL |
| `SigningKeys` | `AAuthSigningKeySet?` | Conditional | Signing keys published at the JWKS (tokens are signed with the active key); required when issuing resource tokens or making signed calls, optional for verification-only resources |
| `Name` | `string?` | No | Human-readable resource name (`name`) |
| `ScopeDescriptions` | `IReadOnlyDictionary<string, string>?` | No | Scope → description |
| `SignatureWindow` | `int?` | No | Advertised signature validity (seconds) |
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
covered components. Prefer `AAuthClientBuilder` for ordinary client composition.

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

| Property | Type | Required | Description |
|----------|------|:--------:|-------------|
| `Key` | `IAAuthSigner` | Yes | Agent signing key (must have private component) |
| `PersonServer` | `string?` | No | Person Server URL; with `TokenRefresher`, enables 401 challenge handling |
| `OnInteractionRequired` | `Func<Interaction, CancellationToken, Task>?` | No | PS interaction during token exchange (deferred consent) |
| `OnResourceInteraction` | `Func<string, string, CancellationToken, Task>?` | No | Resource `202` + `requirement=interaction` (URL + code) |
| `OnApprovalPending` | `Func<CancellationToken, Task>?` | No | Resource `202` + `requirement=approval` |
| `AgentToken` | `string?` | One credential source | Already-held agent JWT; no implicit enrollment |
| `SignatureKeyProvider` | `ISignatureKeyProvider?` | Explicit generic source | Generic signing only; cannot combine with agent credentials or AAuth authorization flows |
| `TokenRefresher` | `ITokenRefresher?` | One credential source | Auto-refresh before token expiry; can renew an already-held agent token |
| `PollingTimeout` | `TimeSpan` | No | Max deferred polling time (default 5 minutes) |

`AddAAuthAgent` requires `AgentToken`, `TokenRefresher`, or an explicit generic
`SignatureKeyProvider`. Omitting credentials does not select HWK. A generic
provider cannot be combined with PS challenge handling or resource-managed
AAuth authorization. The MockAgentProvider sample also accepts
`AgentProvider:KeyDirectory` for isolated persisted AP signing keys; its default
remains `~/.aauth/ap-keys`.

### AAuthResourceOptions (AddAAuthResource)

| Property | Type | Required | Description |
|----------|------|:--------:|-------------|
| `Issuer` | `string` | Yes | Resource canonical URL |
| `SigningKeys` | `AAuthSigningKeySet` | Conditional | Signing keys published at the JWKS (tokens are signed with the active key); required when issuing resource tokens or making signed calls, optional for verification-only resources |
| `KeyHandle` | `string?` | No | Handle in the registered `IKeyStore` to load the signing key from when `SigningKeys` is empty |
| `KeyId` | `string?` | No | `kid` for the key loaded from `KeyHandle` (default: its JWK thumbprint) |
| `Name` | `string?` | No | Resource display name (`name`) |
| `ScopeDescriptions` | `Dictionary<string, string>?` | No | Scope descriptions for metadata |
| `SignatureWindow` | `int?` | No | Advertised signature validity (seconds) |
| `AuthorizationEndpoint` | `string?` | No | Resource's proactive authorization endpoint URL; not the PS/AS resource-token recipient (draft-11 removed `PersonServerAudience`; the recipient is `AccessServer` or the presented token's PS) |
| `RevocationEndpoint` | `string?` | No | Revocation endpoint URL |

### AAuthDiscoveryOptions (AddAAuthDiscovery)

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `MetadataCacheTtl` | `TimeSpan` | 5 minutes | Metadata document cache lifetime |
| `JwksCacheTtl` | `TimeSpan` | 1 hour | JWKS cache lifetime |
| `JwksMinRefreshInterval` | `TimeSpan` | 1 minute | Minimum interval between JWKS fetches (rate limit) |

### ChallengeHandlingOptions (WithChallengeHandling)

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `OnInteractionRequired` | `Func<Interaction, CancellationToken, Task>?` | null | Deferred consent callback |
| `PollingTimeout` | `TimeSpan` | 5 minutes | Max deferred polling time |
| `DefaultPollInterval` | `TimeSpan` | 5 seconds | Poll interval (overridden by Retry-After) |
| `PreferWaitSeconds` | `int?` | null | Sends `Prefer: wait=N` to long-poll |
| `MinPollInterval` | `TimeSpan` | 100 ms | Minimum delay between polls |
| `OnPoll` | `Action<HttpResponseMessage>?` | null | Per-poll callback (logging/progress) |
| `Capabilities` | `IList<string>?` | null | Capabilities sent to the PS (null = infer) |
| `Prompt` | `string?` | null | OIDC `prompt` sent to the PS |
| `AdditionalSignatureComponents` | `IReadOnlyDictionary<string, IReadOnlyList<string>>?` | null | Per-origin extra covered components to seed |

### InteractionHandlingOptions (WithInteractionHandling)

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `OnInteractionRequired` | `Func<string, string, CancellationToken, Task>?` | null | Interaction URL + code callback |
| `OnApprovalPending` | `Func<CancellationToken, Task>?` | null | Approval polling callback |
| `PollingTimeout` | `TimeSpan` | 5 minutes | Max polling time |

## JSON Configuration Keys (samples)

The SDK's configuration overloads bind a whole section: `AddAAuthPersonServer`
from `AAuth:PersonServer`, `AddAAuthAccessServer` from `AAuth:AccessServer`, and
`AddAAuthResource` from `AAuth:Resource` (each extension class exposes a
`ConfigurationSection` constant). The keys are the option property names, such as
`AAuth:PersonServer:Issuer`, `AAuth:PersonServer:KeyHandle` or
`AAuth:PersonServer:Trust:AccessServers:Allowed:0`.

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
| `AAuth:SelfIssuer` / `AAuth:SelfAgentId` | `string` | SampleApp | Self-issued agent issuer / identifier. |

## Further Reading

- [Getting Started](../getting-started.md) — minimal setup
- [Error Handling](../advanced/error-handling.md) — all error codes
- [Verification Middleware](../server/verification-middleware.md) — server setup
