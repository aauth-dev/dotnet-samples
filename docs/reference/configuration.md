# Configuration Reference

All configurable options across the AAuth .NET SDK, grouped by component.

## Signature Verification

### AAuthVerifier

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `MaxAge` | `TimeSpan` | 60 seconds | Maximum signature age before rejection |
| `MaxFutureSkew` | `TimeSpan` | 5 seconds | Clock skew tolerance into the future |
| `Clock` | `Func<DateTimeOffset>` | `UtcNow` | Clock source (override for testing) |

### AAuthVerificationOptions (via UseAAuthVerification)

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `ResourceIdentifier` | `string?` | `null` | Resource's own identifier for `aud` checks. When `null`, audience validation is skipped. |
| `RequireIssuerVerification` | `bool` | `true` | When `true`, verifies JWT signatures against the issuer's published JWKS via metadata discovery. |
| `TrustedAgentProviderIssuers` | `IReadOnlySet<string>?` | `null` | Optional allow-list of trusted AP issuers (null = any) |
| `TrustedAuthTokenIssuers` | `IReadOnlySet<string>?` | `null` | Fail-closed allow-list of trusted auth token (PS/AS) issuers. When `null` or empty, **every** auth token is rejected — set the issuers you trust to honor PS-asserted tokens. |
| `MaxActDepth` | `int` | `10` | Maximum delegation chain depth for nested `act` claims |
| `ClockSkew` | `TimeSpan` | 30 seconds | Tolerance applied to `exp`/`iat` checks |
| `MaxFutureSkew` | `TimeSpan` | 5 seconds | Maximum allowed skew into the future for HTTP signature timestamps |
| `Clock` | `Func<DateTimeOffset>?` | `null` (UtcNow) | Clock source for all time-dependent checks. Inject for deterministic testing. |

### AAuthResourceOptions (via AddAAuthResource)

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Issuer` | `string` | — (required) | HTTPS issuer URL for this resource |
| `SigningKeys` | `Dictionary<string, AAuthKey>` | `{}` | Key-id → signing key map |
| `Name` | `string?` | `null` | Human-readable resource name (`name`) |
| `ScopeDescriptions` | `Dictionary<string, string>?` | `null` | Scope → description map for metadata |
| `SignatureWindow` | `int?` | `null` | Advertised signature validity (seconds) |
| `AuthorizationEndpoint` | `string?` | `null` | AS authorization URL |
| `RevocationEndpoint` | `string?` | `null` | Revocation endpoint URL |

### AAuthPersonServerOptions (via MapAAuthPersonServer)

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Issuer` | `string` | — (required) | HTTPS URL of this PS (`iss` of minted auth tokens) |
| `SigningKeys` | `IReadOnlyDictionary<string, AAuthKey>` | — (required) | Key-id → signing key map (published at the PS JWKS) |
| `TokenPath` | `string` | `/token` | Token endpoint path |
| `PendingPathPrefix` | `string` | `/pending` | Deferred-consent poll path prefix |
| `DefaultScope` | `string` | `""` | Scope assumed when the resource token omits one |
| `InteractionPath` | `string` | `/interaction` | Path the host maps for the consent page |
| `TrustedAccessServers` | `IReadOnlyCollection<string>?` | `null` | AS URLs the PS will federate to; `null`/empty ⇒ three-party only |

The helper resolves `IIdentityClaimsAsserter` and `IPersonPendingStore` from DI
(and the `IMissionStore` / `IMissionLog` mission primitives when a request carries
a `mission` claim). See
[Token Issuance → One-Call Person Server](../server/token-issuance.md#one-call-person-server-mapaauthpersonserver).

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
| `Lifetime` | `TimeSpan` | 1 hour | Token validity duration |
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
| `Clock` | `Func<DateTimeOffset>` | `UtcNow` | Clock source |
| `ClockSkew` | `TimeSpan` | 30 seconds | Tolerance for exp/iat validation |
| `MaxActDepth` | `int` | 10 | Maximum delegation chain depth |

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
| `http` | `HttpClient` | — (required) | HTTP client for fetching documents |
| `cacheTtl` | `TimeSpan?` | null (no expiry) | Cache entry lifetime |
| `clock` | `Func<DateTimeOffset>?` | `UtcNow` | Clock source for cache expiration |

Methods:

- `BuildUrl(issuer, dwk)` — constructs `.well-known/{dwk}` URL from issuer
- `FetchAsync(url)` — fetches and caches the JSON document
- `Invalidate(url)` — evicts a cached entry

## Resource Metadata

### AAuthResourceMetadataOptions

| Property | Type | Required | Description |
|----------|------|:--------:|-------------|
| `Issuer` | `string` | Yes | Resource canonical URL |
| `SigningKeys` | `IReadOnlyDictionary<string, AAuthKey>` | Yes | Key-id → signing key map |
| `Name` | `string?` | No | Human-readable resource name (`name`) |
| `ScopeDescriptions` | `IReadOnlyDictionary<string, string>?` | No | Scope → description |
| `SignatureWindow` | `int?` | No | Advertised signature validity (seconds) |
| `AuthorizationEndpoint` | `string?` | No | AS authorization URL |
| `RevocationEndpoint` | `string?` | No | Revocation endpoint URL |

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

Standard `DelegatingHandler` — no configurable options. Requires an `ISignatureKeyProvider` to supply the signing key and Signature-Key header value.

### ISignatureKeyProvider Implementations

| Provider | Constructor Parameters |
|----------|----------------------|
| `HwkSignatureKeyProvider` | `IAAuthKey key` |
| `JwksUriSignatureKeyProvider` | `string uri, string kid` |
| `JwtSignatureKeyProvider` | `Func<string> tokenFactory` |
| `JktJwtSignatureKeyProvider` | `IAAuthKey ephemeralKey, Func<string> namingJwtFactory` |

## Dependency Injection Options

### AAuthAgentOptions (AddAAuthAgent)

| Property | Type | Required | Description |
|----------|------|:--------:|-------------|
| `Key` | `IAAuthKey` | Yes | Agent signing key (must have private component) |
| `PersonServer` | `string?` | No | Person Server URL; with `TokenRefresher`, enables 401 challenge handling |
| `OnInteractionRequired` | `Func<Interaction, CancellationToken, Task>?` | No | PS interaction during token exchange (deferred consent) |
| `OnResourceInteraction` | `Func<string, string, CancellationToken, Task>?` | No | Resource `202` + `requirement=interaction` (URL + code) |
| `OnApprovalPending` | `Func<CancellationToken, Task>?` | No | Resource `202` + `requirement=approval` |
| `TokenRefresher` | `ITokenRefresher?` | No | Auto-refresh before token expiry (JWT identity); omit for HWK |
| `PollingTimeout` | `TimeSpan` | No | Max deferred polling time (default 5 minutes) |

### AAuthResourceOptions (AddAAuthResource)

| Property | Type | Required | Description |
|----------|------|:--------:|-------------|
| `Issuer` | `string` | Yes | Resource canonical URL |
| `SigningKeys` | `Dictionary<string, AAuthKey>` | Yes | Key-id → signing key map |
| `Name` | `string?` | No | Resource display name (`name`) |
| `ScopeDescriptions` | `Dictionary<string, string>?` | No | Scope descriptions for metadata |
| `SignatureWindow` | `int?` | No | Advertised signature validity (seconds) |
| `AuthorizationEndpoint` | `string?` | No | AS authorization URL |
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

The shipped samples bind a few `AAuth:*` keys from `appsettings.json` /
environment variables / command line. These are conventions of the samples (not
SDK-required), shown here as a reference for wiring your own hosts.

| Key | Type | Used by | Description |
|-----|------|---------|-------------|
| `AAuth:Issuer` | `string` | Profile/Calendar/Trips/Wallet, MockPersonServer, Concierge | The host's own canonical URL (resource/PS `iss`). |
| `AAuth:SignatureWindow` | `int` (seconds) | Profile/Calendar/Trips/Wallet, MockPersonServer | Max HTTP-signature age accepted; default `60`. |
| `AAuth:TrustedPersonServers` | `string[]` | Calendar/Trips | Fail-closed allow-list mapped to `AAuthVerificationOptions.TrustedAuthTokenIssuers`. When unset, defaults to `http://localhost:5100`; an empty array rejects all auth tokens. |
| `AAuth:LocalKeyHandle` | `string` | agent samples | Key handle in the `IKeyStore` for the agent's signing key. |
| `AAuth:ApRefreshEndpoint` | `string` | agent samples | Agent Provider refresh endpoint for enrolled agents. |
| `AAuth:PersonServer` | `string` | Concierge | Downstream Person Server URL. |
| `AAuth:Downstream` | `string` | Concierge | Downstream resource URL. |
| `AAuth:AgentId` | `string` | Concierge | The agent identifier this host signs as. |
| `AAuth:SelfIssuer` / `AAuth:SelfAgentId` | `string` | SampleApp | Self-issued agent issuer / identifier. |

## Further Reading

- [Getting Started](../getting-started.md) — minimal setup
- [Error Handling](../advanced/error-handling.md) — all error codes
- [Verification Middleware](../server/verification-middleware.md) — server setup
