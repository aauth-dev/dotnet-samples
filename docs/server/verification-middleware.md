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
    // The resource's own identifier (used for audience checks)
    public string? ResourceIdentifier { get; set; }

    // Whether to verify JWT signatures against the issuer's JWKS (default: true)
    public bool RequireIssuerVerification { get; set; } = true;

    // Optional allow-list of trusted agent provider issuers
    public IReadOnlySet<string>? TrustedAgentProviderIssuers { get; set; }

    // Optional allow-list of trusted auth token issuers (PS/AS)
    public IReadOnlySet<string>? TrustedAuthTokenIssuers { get; set; }
}
```

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
