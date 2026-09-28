# Configuration Reference

All configurable options across the AAuth .NET SDK, grouped by component.

## Signature Verification

### AAuthVerifier

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `MaxAge` | `TimeSpan` | 60 seconds | Signature validity window for `created`, in both directions: older is `invalid_signature`, further ahead is `clock_skew` |
| `Clock` | `Func<DateTimeOffset>` | `UtcNow` | Clock source (override for testing) |

### AAuthServerOptions (via UseAAuth)

The single `UseAAuth` pipeline middleware. Defaults to the DI-registered resource
metadata (issuer + first signing key); a typical resource sets only trust.

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `TrustedAuthTokenIssuers` | `IReadOnlySet<string>?` | `null` | Allow-list of trusted auth token (PS/AS) issuers. `null` ⇒ accept any *verifiable* auth-token issuer (the spec default — the JWT signature still verifies against the issuer's JWKS); empty ⇒ deny all; non-empty ⇒ restrict to the listed issuers. AND-composed with `IsTrustedAuthTokenIssuer`. |
| `IsTrustedAuthTokenIssuer` | `Func<string, bool>?` | `null` | Optional predicate AND-composed with `TrustedAuthTokenIssuers` (each only narrows). Assign `AAuthTrust.Any` to trust any verifiable issuer explicitly and suppress the open-trust startup warning. |
| `AccessServer` | `string?` | `null` | Resource-token audience for four-party (federated) resources: the resource's own Access Server. When `null` the audience is the PS that issued the presented person token (three-party). |
| `TrustedAgentProviderIssuers` | `IReadOnlySet<string>?` | `null` | Allow-list of trusted Agent Provider issuers (for `aa-agent+jwt`). `null` ⇒ accept any verifiable Agent Provider; empty ⇒ deny all; non-empty ⇒ restrict. AND-composed with `IsTrustedAgentProviderIssuer`. |
| `IsTrustedAgentProviderIssuer` | `Func<string, bool>?` | `null` | Optional predicate AND-composed with `TrustedAgentProviderIssuers`. Assign `AAuthTrust.Any` to trust any verifiable Agent Provider explicitly. |
| `ResourceIdentifier` | `string?` | DI metadata issuer | Override the resource identifier used for `aud` checks and challenges. |
| `ResourceSigningKey` | `IAAuthKey?` | DI metadata first key | Override the challenge signing key. |
| `ResourceKeyId` | `string?` | DI metadata first kid | Override the challenge key id. |

> `AAuthVerificationOptions` and `ChallengeOptions` are the low-level building
> blocks `UseAAuth` configures from each endpoint's `.RequireAAuth(...)` /
> `.RequireAAuthSignature(...)` requirement; use them directly only for custom
> pipelines.

### AAuthVerificationOptions (via UseAAuthVerification)

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `ResourceIdentifier` | `string?` | `null` | Resource's own identifier for `aud` checks. When `null`, audience validation is skipped. |
| `AcceptedSchemes` | `IReadOnlyList<string>` | `["jwt"]` | Schemes accepted by this verification role; generic signing is an explicit opt-in. |
| `SignatureLabel` | `string` | `"sig"` | Matching dictionary member selected from all three signature fields. |
| `RequiredComponents` | `IReadOnlyCollection<string>` | `[]` | Additional required covered components. |
| `GenericSignatureKeys` | `bool` | `false` | Use generic Signature Keys failure status policy instead of AAuth's 401 profile. |
| `TrustedAgentProviderIssuers` | `IReadOnlySet<string>?` | `null` | Optional allow-list of trusted AP issuers. `null` ⇒ any verifiable AP; empty ⇒ deny all; non-empty ⇒ restrict. AND-composed with `IsTrustedAgentProviderIssuer`. |
| `IsTrustedAgentProviderIssuer` | `Func<string, bool>?` | `null` | Optional predicate AND-composed with `TrustedAgentProviderIssuers`; assign `AAuthTrust.Any` for explicit open trust. |
| `TrustedAuthTokenIssuers` | `IReadOnlySet<string>?` | `null` | Allow-list of trusted auth token (PS/AS) issuers. `null` ⇒ accept any *verifiable* PS (the spec default); empty ⇒ deny all PS-asserted tokens; non-empty ⇒ restrict to the listed issuers. AND-composed with `IsTrustedAuthTokenIssuer`. |
| `IsTrustedAuthTokenIssuer` | `Func<string, bool>?` | `null` | Optional predicate AND-composed with `TrustedAuthTokenIssuers` (each only narrows). Assign `AAuthTrust.Any` to trust any verifiable issuer explicitly and suppress the open-trust startup warning. |
| `ClockSkew` | `TimeSpan` | 30 seconds | Tolerance applied to `exp`/`iat` checks |
| `Clock` | `Func<DateTimeOffset>?` | `null` (UtcNow) | Clock source for all time-dependent checks. Inject for deterministic testing. |

> Startup diagnostics do not change runtime trust policy:
>
> - **Open-trust warning** — when issuer verification is on and no auth-token
>   trust policy is configured (no set, no predicate, no `AAuthTrust.Any`), the
>   resource accepts any verifiable Person Server and a `Warning` is logged at
>   startup. The same warning fires for an open PS (no `TrustedAccessServers` /
>   `IsTrustedAccessServer`) or open AS (no `TrustedPersonServers` /
>   `IsTrustedPersonServer`); any explicit policy suppresses it.
>   - *False positive on signature-only resources:* a `UseAAuth` resource whose
>     endpoints are **all** `RequireAAuthSignature` (no auth-token endpoints) still
>     logs this warning — the SDK can't know at startup that no auth-token endpoint
>     exists. It is benign; silence it by assigning
>     `IsTrustedAuthTokenIssuer = AAuthTrust.Any`.
> JWT issuer verification cannot be disabled. Trust policies narrow the set of
> verified issuers; they never replace signature verification.

### AAuthResourceOptions (via AddAAuthResource)

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Issuer` | `string` | — (required) | HTTPS issuer URL for this resource |
| `SigningKeys` | `Dictionary<string, IAAuthKey>` | `{}` | Key-id to signing key map |
| `Name` | `string?` | `null` | Human-readable resource name (`name`) |
| `ScopeDescriptions` | `Dictionary<string, string>?` | `null` | Scope → description map for metadata |
| `SignatureWindow` | `int?` | `null` | Advertised signature validity (seconds) |
| `AuthorizationEndpoint` | `string?` | `null` | Resource's proactive authorization endpoint URL; not the PS/AS resource-token recipient (draft-11 removed `PersonServerAudience`; the recipient is `AccessServer` or the presented token's PS) |
| `RevocationEndpoint` | `string?` | `null` | Revocation endpoint URL |

### AAuthPersonServerOptions (via MapAAuthPersonServer)

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Issuer` | `string` | — (required) | HTTPS URL of this PS (`iss` of minted person and auth tokens) |
| `SigningKeys` | `IReadOnlyDictionary<string, IAAuthKey>` | Required | Key-id to signing key map (published at the PS JWKS) |
| `TokenPath` | `string` | `/token` | Auth token endpoint path (`auth_token_endpoint`) |
| `PersonTokenPath` | `string` | `/person` | Person token endpoint path (`person_token_endpoint`) |
| `PendingPathPrefix` | `string` | `/pending` | Deferred-consent poll path prefix |
| `DefaultScope` | `string` | `""` | Scope assumed when the resource token omits one |
| `InteractionPath` | `string` | `/interaction` | Path the host maps for the consent page |
| `TrustedAccessServers` | `IReadOnlyCollection<string>?` | `null` | AS URLs the PS will federate to. `null` ⇒ federate to the AS named in a verified resource token's `aud` (the spec default); empty ⇒ three-party only (four-party disabled); non-empty ⇒ restrict to the listed Access Servers. AND-composed with `IsTrustedAccessServer`. |
| `IsTrustedAccessServer` | `Func<string, bool>?` | `null` | Optional predicate AND-composed with `TrustedAccessServers`; assign `AAuthTrust.Any` to federate to any verifiable AS explicitly. |

The helper resolves `IIdentityClaimsAsserter` and `IPersonPendingStore` from DI
(and the `IMissionStore` / `IMissionLog` mission primitives when a request carries
`mission_s256`). See
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
| `Clock` | `Func<DateTimeOffset>` | `UtcNow` | Clock source |
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
| `SigningKeys` | `IReadOnlyDictionary<string, IAAuthKey>?` | Conditional | Key-id to signing key map; required when issuing resource tokens or making signed calls, optional for verification-only resources |
| `Name` | `string?` | No | Human-readable resource name (`name`) |
| `ScopeDescriptions` | `IReadOnlyDictionary<string, string>?` | No | Scope → description |
| `SignatureWindow` | `int?` | No | Advertised signature validity (seconds) |
| `AuthorizationEndpoint` | `string?` | No | Resource's proactive authorization endpoint URL; not the PS/AS resource-token recipient (draft-11 removed `PersonServerAudience`; the recipient is `AccessServer` or the presented token's PS) |
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

A `DelegatingHandler` constructed with an `IAAuthKey` containing the private
signing key and an `ISignatureKeyProvider` supplying the `Signature-Key` header
value. The provider does not supply the private key. The constructor also accepts
an optional clock for deterministic tests.

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
| `Key` | `IAAuthKey` | Yes | Agent signing key (must have private component) |
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
| `SigningKeys` | `Dictionary<string, IAAuthKey>` | Conditional | Key-id to signing key map; required when issuing resource tokens or making signed calls, optional for verification-only resources |
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

The shipped samples bind a few `AAuth:*` keys from `appsettings.json` /
environment variables / command line. These are conventions of the samples (not
SDK-required), shown here as a reference for wiring your own hosts.

| Key | Type | Used by | Description |
|-----|------|---------|-------------|
| `AAuth:Issuer` | `string` | Profile/Calendar/Trips/Wallet/Inbox, MockPersonServer, Concierge | The host's own canonical URL (resource/PS `iss`). |
| `AAuth:SignatureWindow` | `int` (seconds) | Profile/Calendar/Trips/Wallet/Inbox, MockPersonServer | Max HTTP-signature age accepted; default `60`. |
| `AAuth:TrustedPersonServers` | `string[]` | Calendar/Trips | Allow-list mapped to the resource pipeline's `TrustedAuthTokenIssuers` (`app.UseAAuth(o => o.TrustedAuthTokenIssuers = …)`). The SDK default for an unset list is open (accept any *verifiable* PS, namespaced by `iss`), but these samples default to `http://localhost:5100`; an empty array denies all auth tokens (deny-all kill-switch). |
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
