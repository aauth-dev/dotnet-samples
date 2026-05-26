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
| `TrustedAuthTokenIssuers` | `IReadOnlySet<string>?` | `null` | Optional allow-list of trusted auth token issuers (null = any) |
| `MaxActDepth` | `int` | `10` | Maximum delegation chain depth for nested `act` claims |
| `ClockSkew` | `TimeSpan` | 30 seconds | Tolerance applied to `exp`/`iat` checks |
| `MaxFutureSkew` | `TimeSpan` | 5 seconds | Maximum allowed skew into the future for HTTP signature timestamps |
| `Clock` | `Func<DateTimeOffset>?` | `null` (UtcNow) | Clock source for all time-dependent checks. Inject for deterministic testing. |

### AAuthResourceOptions (via AddAAuthResource)

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Issuer` | `string` | — (required) | HTTPS issuer URL for this resource |
| `SigningKeys` | `Dictionary<string, AAuthKey>` | `{}` | Key-id → signing key map |
| `MaxSignatureAge` | `TimeSpan` | 60 seconds | Maximum allowed age of inbound signatures |
| `MaxFutureSkew` | `TimeSpan` | 5 seconds | Future skew tolerance for signature timestamps |
| `Clock` | `Func<DateTimeOffset>?` | `null` (UtcNow) | Clock source (threaded to `AAuthVerifier`) |
| `EnableReplayDetection` | `bool` | `true` | Enable JTI-based replay detection |
| `KeyResolver` | `ISignatureKeyResolver?` | `null` | Custom key resolver (null = default) |

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
| `OnInteractionRequired` | `Func<AAuthInteraction, CancellationToken, Task>?` | `null` | Callback for 202+interaction |
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
| `ClientName` | `string?` | No | Human-readable resource name |
| `ScopeDescriptions` | `IReadOnlyDictionary<string, string>?` | No | Scope → description |
| `SignatureWindow` | `int?` | No | Advertised signature validity (seconds) |
| `AuthorizationEndpoint` | `string?` | No | AS authorization URL |
| `RevocationEndpoint` | `string?` | No | Revocation endpoint URL |

## Key Storage

### KeyStore (File-Based)

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
| `Key` | `IAAuthKey` | Yes | Agent signing key |
| `AgentToken` | `string?` | No | Agent token JWT (enables jwt mode) |
| `PersonServer` | `string?` | No | Person Server URL (enables challenge handling) |
| `OnInteractionRequired` | `Func<..., Task>?` | No | Callback for deferred consent interaction |
| `OnResourceInteraction` | `Func<..., Task>?` | No | Callback for resource-managed interaction |
| `OnApprovalPending` | `Func<CancellationToken, Task>?` | No | Callback during approval polling |
| `TokenRefresher` | `ITokenRefresher?` | No | Custom token refresh logic |
| `PollingTimeout` | `TimeSpan?` | No | Max deferred polling time (default: 5 min) |

### AAuthResourceOptions (AddAAuthResource)

| Property | Type | Required | Description |
|----------|------|:--------:|-------------|
| `Issuer` | `string` | Yes | Resource canonical URL |
| `SigningKeys` | `List<(string Kid, IAAuthKey Key)>` | Yes | Signing key pairs |
| `MaxSignatureAge` | `TimeSpan?` | No | Override verifier MaxAge |
| `EnableReplayDetection` | `bool` | No | Register `IJtiStore` (default: false) |
| `KeyResolver` | `ISignatureKeyResolver?` | No | Custom resolver |
| `ClientName` | `string?` | No | Resource display name |
| `ScopeDescriptions` | `Dictionary<string, string>?` | No | Scope descriptions for metadata |

### AAuthDiscoveryOptions (AddAAuthDiscovery)

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `MetadataCacheTtl` | `TimeSpan` | 5 minutes | Metadata document cache lifetime |
| `JwksCacheTtl` | `TimeSpan` | 1 hour | JWKS cache lifetime |
| `JwksMinRefreshInterval` | `TimeSpan` | 1 minute | Minimum time between JWKS fetches (spec: ≥1 min) |

### ChallengeHandlingOptions (WithChallengeHandling)

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `OnInteractionRequired` | `Func<AAuthInteraction, CancellationToken, Task>?` | null | Deferred consent callback |
| `PollingTimeout` | `TimeSpan` | 5 minutes | Max deferred polling time |
| `DefaultPollInterval` | `TimeSpan` | 5 seconds | Poll interval (overridden by Retry-After) |

### InteractionHandlingOptions (WithInteractionHandling)

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `OnInteractionRequired` | `Func<string, string, CancellationToken, Task>?` | null | Interaction URL + code callback |
| `OnApprovalPending` | `Func<CancellationToken, Task>?` | null | Approval polling callback |
| `PollingTimeout` | `TimeSpan` | 5 minutes | Max polling time |

## Further Reading

- [Getting Started](../getting-started.md) — minimal setup
- [Error Handling](../advanced/error-handling.md) — all error codes
- [Verification Middleware](../server/verification-middleware.md) — server setup
