# Verification Middleware

`AAuthVerificationMiddleware` performs HTTP signature verification (RFC 9421 PoP) and JWT issuer signature verification in a single pass.

> For how verification fits into the full authN/authZ pipeline and the
> minimal-API vs classic-MVC wiring, see
> [Authentication and Authorization](authn-authz.md).

## Registration

```csharp
using AAuth.DependencyInjection;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server;

// Required services
builder.Services.AddSingleton(new AAuthVerifier());
builder.Services.AddSingleton(sp => new MetadataClient(httpClient));
builder.Services.AddSingleton(sp => new JwksClient(httpClient));

var app = builder.Build();

app.UseAAuthVerification(new AAuthVerificationOptions
{
    ResourceIdentifier = "https://resource.example",
    RequireIssuerVerification = true,
});
```

## What It Verifies

1. **HTTP Signature (RFC 9421)**: Validates `Signature`, `Signature-Input`, and `Signature-Key` headers. Confirms covered components (`@method`, `@authority`, `@path`, `signature-key`) match the request.

2. **Signature-Key Resolution**: Parses the scheme (`jwt`, `hwk`, `jkt-jwt`, `jwks_uri`) and resolves the public key accordingly.

3. **JWT Issuer Verification** (when `RequireIssuerVerification = true`): Fetches the issuer's JWKS via metadata discovery and verifies the token's signature against the issuer's published keys.

## Options

```csharp
public sealed class AAuthVerificationOptions
{
    // The resource's own identifier (used for audience checks).
    // When null, audience validation is skipped entirely.
    public string? ResourceIdentifier { get; init; }

    // Whether to verify JWT signatures against the issuer's JWKS (default: true)
    public bool RequireIssuerVerification { get; init; } = true;

    // Optional allow-list of trusted agent provider issuers
    public IReadOnlySet<string>? TrustedAgentProviderIssuers { get; init; }

    // Fail-closed allow-list of trusted auth token issuers (Person Servers).
    // When issuer verification is on, an auth token is accepted only if its
    // `iss` is in this set. null/empty = reject ALL PS-asserted tokens.
    public IReadOnlySet<string>? TrustedAuthTokenIssuers { get; init; }

    // Maximum depth of nested act claims (default: 10)
    public int MaxActDepth { get; init; } = 10;

    // Tolerance for exp/iat validation (default: 30s)
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromSeconds(30);

    // Maximum future skew for HTTP signature timestamps (default: 5s)
    public TimeSpan MaxFutureSkew { get; init; } = TimeSpan.FromSeconds(5);

    // Clock source for all time checks (null = UtcNow; inject for testing)
    public Func<DateTimeOffset>? Clock { get; init; }
}
```

### Behavior by Configuration

| `RequireIssuerVerification` | `ResourceIdentifier` | Effect |
|:--:|:--:|:--|
| `true` | set | Full verification: HTTP sig + JWT issuer JWKS + aud + PoP + act.sub |
| `true` | `null` | Verifies JWT issuer sig + PoP, but skips `aud` check |
| `false` | any | HTTP signature only — no JWT issuer verification |

> **Auth-token issuer trust is fail-closed.** When `RequireIssuerVerification`
> is `true`, a PS-asserted (auth) token is accepted only when its `iss` appears
> in `TrustedAuthTokenIssuers`. If that set is `null` or empty, **every** auth
> token is rejected with `401`. Declare the Person Servers this resource trusts:
>
> ```csharp
> app.UseAAuthVerification(new AAuthVerificationOptions
> {
>     ResourceIdentifier = "https://api.example.com",
>     RequireIssuerVerification = true,
>     TrustedAuthTokenIssuers = new HashSet<string> { "https://person.example.com" },
> });
> ```
>
> Signature-only flows (`hwk` / `jkt-jwt` / `jwks_uri`) carry no `iss`
> assertion and are unaffected by this allow-list.

### Subject namespacing by asserting PS

The canonical user identity is the **`(iss, sub)` pair**: the same `sub` value
asserted by two different Person Servers denotes two different users. Every
PS-asserted identity claim the handler emits (`NameIdentifier`, `Role`,
`aauth:group`) carries `Claim.Issuer == iss` for provenance, and a composite
`aauth:sub_iss` (`{iss}|{sub}`) claim is surfaced so resources can match a local
user record on the full key rather than on `sub` alone.

Use `UseWhen` to give each access mode its own **isolated verification pipeline**.
This is the pattern used in the WhoAmI sample: every signing mode has a dedicated
path-segment branch with its own verification (and, for three-party endpoints, its
own challenge) options. Each branch is self-contained, so there is no single shared
verification step with negative path matching:

```csharp
// Pseudonymous (hwk) — signature only, no JWT verification
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/hwk"),
    branch => branch.UseAAuthVerification(new AAuthVerificationOptions
    {
        RequireIssuerVerification = false,
    }));

// Agent identity (jwks_uri) — verifies key against published JWKS
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/jwks-uri"),
    branch => branch.UseAAuthVerification(new AAuthVerificationOptions
    {
        RequireIssuerVerification = false,
    }));

// Three-party (jwt) — full issuer + audience verification, plus a per-endpoint
// challenge requesting the scope this branch protects.
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/jwt"),
    branch =>
    {
        branch.UseAAuthVerification(new AAuthVerificationOptions
        {
            ResourceIdentifier = "https://resource.example",
            RequireIssuerVerification = true,
        });
        branch.UseAAuthChallenge(new ChallengeOptions
        {
            AccessMode = AAuthAccessMode.RequireAuthToken,
            ResourceSigningKey = resourceKey,
            ResourceKeyId = "key-1",
            ResourceIdentifier = "https://resource.example",
            DefaultScopes = "whoami",
        });
    });
```

Declare more specific segments (for example `/jwt/admin`) before the general
`/jwt` branch so segment matching stays unambiguous. After the branches,
`UseAuthentication`/`UseAuthorization` run globally and per-endpoint policies
decide what each route requires.

See `samples/WhoAmI` for the complete working example.

## Verification Result

After successful verification, the middleware stores an `AAuthVerificationResult` in `HttpContext.Features`:

```csharp
app.MapGet("/protected", (HttpContext ctx) =>
{
    var result = ctx.GetAAuthVerification()!;
    // result.Level: Pseudonymous | Identified | Authorized
    // result.Scheme: "jwt" | "hwk" | "jkt-jwt" | "jwks_uri"
    // result.Agent: agent identifier
    // result.Scopes: granted scopes (auth tokens only)
    // result.Roles: enterprise roles from the auth token (IReadOnlySet<string>)
    // result.Groups: enterprise groups from the auth token (IReadOnlySet<string>)
    // result.IssuerVerified: whether JWKS verification passed
    // result.Jkt: key thumbprint
});
```

`Roles` and `Groups` are populated from the verified auth token's `roles` and
`groups` claims and are empty for signature-only or agent-token requests. The
authentication handler maps `Roles` to the standard `ClaimTypes.Role` claim and
emits one `aauth:group` claim per group.

## Error Responses

On verification failure, the middleware returns `401 Unauthorized` with a `Signature-Error` header:

| Error Code | Meaning |
|------------|---------|
| `invalid_request` | Missing required signature headers |
| `invalid_input` | Covered components don't match the required set (see the `required_input` parameter) |
| `invalid_signature` | Signature verification failed |
| `unsupported_algorithm` | Signature algorithm not supported |
| `invalid_key` | Signature key malformed or unusable |
| `unknown_key` | Referenced key could not be resolved |
| `invalid_jwt` | JWT parsing/issuer verification failed |
| `expired_jwt` | Token JWT expired |

## OpenTelemetry Integration

When `Activity.Current` is present, the middleware enriches it with tags. See [Observability](../advanced/observability.md).

## Call Chaining Verification

When verifying auth tokens from call-chaining scenarios, the middleware validates the nested `act` chain:

- `act.sub` must match the HTTP request signer's agent identity
- Nested `act` depth cannot exceed `MaxActDepth` (default 10)
- Each nested level must contain a `sub` field

The `UpstreamAuthTokenFeature` is set on the HttpContext when a valid auth token is verified, making the upstream token available to downstream `WithCallChaining(httpContext)` calls:

```csharp
app.UseAAuthVerification(new AAuthVerificationOptions
{
    ResourceIdentifier = "https://orchestrator.example",
    RequireIssuerVerification = true,
    MaxActDepth = 5,              // limit chain depth for this resource
    ClockSkew = TimeSpan.FromSeconds(60), // generous skew for distributed systems
});

app.MapGet("/", async (HttpContext ctx) =>
{
    // Middleware verified the auth token and set the feature.
    // WithCallChaining reads the upstream token from it automatically.
    using var client = new AAuthClientBuilder(myKey)
        .WithTokenRefresh(refreshFunc)
        .WithCallChaining(ctx)
        .Build();

    return await client.GetStringAsync("https://downstream.example");
});
```
