# Verification Middleware

> [Signature Verification](https://explorer.aauth.dev/foundations/signatures) | [Error Codes](https://explorer.aauth.dev/foundations/errors)

## Overview

Every AAuth request carries an HTTP signature (RFC 9421). The `AAuthVerificationMiddleware` validates the signature and extracts the parsed key information, making it available to downstream handlers.

## Setup

### DI Extension (Recommended)

```csharp
using AAuth.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAAuthResource(options =>
{
    options.Issuer = "https://resource.example";
    options.MaxSignatureAge = TimeSpan.FromSeconds(60);
    options.EnableReplayDetection = true;
});

var app = builder.Build();

app.UseAAuthVerification();
app.MapAAuthWellKnown(); // serves /.well-known/aauth-resource.json
```

### Manual Setup (Advanced)

```csharp
using AAuth.HttpSig;
using AAuth.Server;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.UseAAuthVerification(
    verifier: new AAuthVerifier
    {
        MaxAge = TimeSpan.FromSeconds(60),
        MaxFutureSkew = TimeSpan.FromSeconds(5)
    },
    jtiStore: new InMemoryJtiStore(),
    resolver: new DefaultSignatureKeyResolver(
        jwksClient: new JwksClient(new HttpClient())));
```

## AAuthVerifier Configuration

| Property | Default | Description |
|----------|---------|-------------|
| `MaxAge` | 60 seconds | Maximum age of a signature before rejection |
| `MaxFutureSkew` | 5 seconds | Tolerance for clock skew into the future |
| `Clock` | `DateTimeOffset.UtcNow` | Clock function (override for testing) |

## Accessing Parsed Key Info

After the middleware runs, the parsed signature key info is stored in `HttpContext.Items`:

```csharp
app.MapGet("/data", (HttpContext context) =>
{
    var keyInfo = context.Items[AAuthVerificationMiddleware.ContextItemKey]
        as SignatureKeyParser.ParsedSignatureKeyInfo;

    // keyInfo.Scheme — "hwk", "jwks_uri", "jwt", or "jkt_jwt"
    // keyInfo.Jkt — the agent's key thumbprint
    // keyInfo.ConfirmationKey — the resolved public key
    // keyInfo.Jwt — raw JWT (for jwt/jkt_jwt schemes)
    // keyInfo.JwksUri — URI (for jwks_uri scheme)
    // keyInfo.Kid — key ID (for jwks_uri scheme)
    
    return Results.Ok(new { scheme = keyInfo?.Scheme, jkt = keyInfo?.Jkt });
});
```

## Error Responses — Signature-Error Header

When verification fails, the middleware returns 401 with the `Signature-Error` header:

```http
HTTP/1.1 401 Unauthorized
Signature-Error: invalid_signature
```

Error codes (from `SignatureErrorCode`):

| Code | Wire Value | Meaning |
|------|-----------|---------|
| `InvalidRequest` | `invalid_request` | Missing required headers |
| `InvalidInput` | `invalid_input` | Malformed Signature-Input |
| `InvalidSignature` | `invalid_signature` | Signature bytes don't match |
| `UnsupportedAlgorithm` | `unsupported_algorithm` | Algorithm not supported |
| `InvalidKey` | `invalid_key` | Key material is malformed |
| `UnknownKey` | `unknown_key` | Key not found (jwks_uri: kid not in JWKS) |
| `InvalidJwt` | `invalid_jwt` | Agent token fails validation |
| `ExpiredJwt` | `expired_jwt` | Agent token `exp` has passed |

## Combining with Token Challenges

Typically you validate the signature first (middleware), then challenge for a resource token in the endpoint:

```csharp
app.UseAAuthVerification(verifier: new AAuthVerifier());

app.MapGet("/protected", (HttpContext context) =>
{
    var keyInfo = context.Items[AAuthVerificationMiddleware.ContextItemKey]
        as SignatureKeyParser.ParsedSignatureKeyInfo;

    if (keyInfo is null) return Results.Unauthorized();

    // Issue a challenge if no auth token presented
    var authHeader = context.Request.Headers.Authorization.FirstOrDefault();
    if (authHeader is null)
    {
        var resourceToken = new ResourceTokenBuilder { ... }.Build();
        context.Response.Headers["WWW-Authenticate"] = $"AAuth resource_token={resourceToken}";
        return Results.Unauthorized();
    }

    return Results.Ok("Access granted");
});
```

## Further Reading

- [Multi-Scheme Verification](multi-scheme-verification.md) — handling all four signing modes
- [Replay Detection](replay-detection.md) — preventing signature reuse
- [Resource Metadata](resource-metadata.md) — advertising verification capabilities
