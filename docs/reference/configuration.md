# Configuration Reference

All configurable options across the AAuth .NET SDK, grouped by component.

## Signature Verification

### AAuthVerifier

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `MaxAge` | `TimeSpan` | 60 seconds | Maximum signature age before rejection |
| `MaxFutureSkew` | `TimeSpan` | 5 seconds | Clock skew tolerance into the future |
| `Clock` | `Func<DateTimeOffset>` | `UtcNow` | Clock source (override for testing) |

### AAuthVerificationMiddleware (via UseAAuthVerification)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `verifier` | `AAuthVerifier?` | `new()` | Verifier instance with timing config |
| `jtiStore` | `IJtiStore?` | `null` | Replay detection store (null = disabled) |
| `resolver` | `ISignatureKeyResolver?` | `null` | Multi-scheme resolver (null = inline key only) |

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
| `DefaultPollInterval` | `TimeSpan` | 1 second | Base interval between polls |
| `MinPollInterval` | `TimeSpan` | 100ms | Minimum interval floor |

Server `Retry-After` headers override `DefaultPollInterval` (clamped to `MinPollInterval`).

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
| `keyLookup` | `IKeyLookup?` | null | hwk thumbprint resolver |

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

## Further Reading

- [Getting Started](../getting-started.md) — minimal setup
- [Error Handling](../advanced/error-handling.md) — all error codes
- [Verification Middleware](../server/verification-middleware.md) — server setup
