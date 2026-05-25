# Verification Middleware

`AAuthVerificationMiddleware` performs HTTP signature verification (RFC 9421 PoP) and JWT issuer signature verification in a single pass.

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
public class AAuthVerificationOptions
{
    // The resource's own identifier (used for audience checks).
    // When null, audience validation is skipped entirely.
    public string? ResourceIdentifier { get; set; }

    // Whether to verify JWT signatures against the issuer's JWKS (default: true)
    public bool RequireIssuerVerification { get; set; } = true;

    // Optional allow-list of trusted agent provider issuers
    public IReadOnlySet<string>? TrustedAgentProviderIssuers { get; set; }

    // Optional allow-list of trusted auth token issuers (PS/AS)
    public IReadOnlySet<string>? TrustedAuthTokenIssuers { get; set; }
}
```

### Behavior by Configuration

| `RequireIssuerVerification` | `ResourceIdentifier` | Effect |
|:--:|:--:|:--|
| `true` | set | Full verification: HTTP sig + JWT issuer JWKS + aud + PoP + act.sub |
| `true` | `null` | Verifies JWT issuer sig + PoP, but skips `aud` check |
| `false` | any | HTTP signature only — no JWT issuer verification |

## Per-Path Configuration

Use `UseWhen` to apply different verification options per endpoint path. This is the pattern used in the WhoAmI sample where each signing mode has a dedicated endpoint:

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

// Three-party (jwt) — full issuer + audience verification
app.UseWhen(
    ctx => !ctx.Request.Path.StartsWithSegments("/.well-known")
        && !ctx.Request.Path.StartsWithSegments("/hwk")
        && !ctx.Request.Path.StartsWithSegments("/jwks-uri"),
    branch => branch.UseAAuthVerification(new AAuthVerificationOptions
    {
        ResourceIdentifier = "https://resource.example",
        RequireIssuerVerification = true,
    }));
```

See `samples/WhoAmI` for the complete working example.

## Verification Result

After successful verification, the middleware stores an `AAuthVerificationResult` in `HttpContext.Features`:

```csharp
app.MapGet("/protected", (HttpContext ctx) =>
{
    var result = ctx.Features.Get<AAuthVerificationResult>()!;
    // result.Level: Pseudonymous | Identified | Authorized
    // result.Scheme: "jwt" | "hwk" | "jkt-jwt" | "jwks_uri"
    // result.Agent: agent identifier
    // result.Scopes: granted scopes (auth tokens only)
    // result.IssuerVerified: whether JWKS verification passed
    // result.Jkt: key thumbprint
});
```

## Error Responses

On verification failure, the middleware returns `401 Unauthorized` with a `Signature-Error` header:

| Error Code | Meaning |
|------------|---------|
| `invalid_request` | Missing required signature headers |
| `invalid_signature` | Signature verification failed |
| `invalid_jwt` | JWT parsing/issuer verification failed |
| `expired` | Token or signature timestamp expired |

## OpenTelemetry Integration

When `Activity.Current` is present, the middleware enriches it with tags. See [Observability](../advanced/observability.md).
