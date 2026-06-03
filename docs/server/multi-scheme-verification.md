# Multi-Scheme Verification

> [Signature-Key Schemes](https://explorer.aauth.dev/foundations/schemes)

## Overview

Resources must handle all four signing modes (hwk, jwks_uri, jwt, jkt_jwt). The `ISignatureKeyResolver` interface resolves the `Signature-Key` header into a verified public key regardless of scheme.

## ISignatureKeyResolver Interface

```csharp
namespace AAuth.HttpSig;

public interface ISignatureKeyResolver
{
    Task<SignatureKeyResolution> ResolveAsync(
        SignatureKeyParser.ParsedSignatureKeyInfo info,
        CancellationToken ct = default);
}

public sealed class SignatureKeyResolution
{
    public required IAAuthKey PublicKey { get; init; }
    public required SignatureKeyParser.ParsedSignatureKeyInfo Info { get; init; }
}
```

## DefaultSignatureKeyResolver

Handles all four schemes out of the box:

```csharp
using AAuth;

// DI extension (recommended) — registers resolver automatically
builder.Services.AddAAuthResource(options =>
{
    options.Issuer = "https://resource.example";
});

app.UseAAuthVerification();
```

<details>
<summary>Manual Setup</summary>

```csharp
using AAuth.HttpSig;
using AAuth.Discovery;
using AAuth.Server.Verification;

// Register required services
builder.Services.AddSingleton(new AAuthVerifier());
builder.Services.AddSingleton(sp => new JwksClient(new HttpClient()));
builder.Services.AddSingleton(sp => new MetadataClient(new HttpClient()));

app.UseAAuthVerification(new AAuthVerificationOptions
{
    RequireIssuerVerification = true,
});
```

</details>

### Resolution Logic by Scheme

| Scheme | How Key Is Resolved |
|--------|-------------------|
| `hwk` | Extracts inline public key from `Signature-Key` header (`jwk` parameter) |
| `jwks_uri` | Fetches JWKS from the declared URI, finds key by `kid` |
| `jwt` | Extracts `cnf.jwk` from agent token, fetches AP's JWKS to verify token signature |
| `jkt_jwt` | Extracts `cnf.jwk` from naming JWT delegation to ephemeral key |

## HWK — Inline Public Key

For `hwk` (pseudonymous) mode, the agent sends its full public key inline in the
`Signature-Key` header as a base64url-encoded JWK. The resource extracts the key
directly — no pre-registration or key lookup is required.

## ParsedSignatureKeyInfo

After resolution, the parsed info is available via `HttpContext.Items[AAuthVerificationMiddleware.ParsedInfoItemKey]`:

```csharp
public sealed class ParsedSignatureKeyInfo
{
    public required string Scheme { get; init; }     // "hwk", "jwks_uri", "jwt", "jkt_jwt"
    public IAAuthKey? ConfirmationKey { get; init; } // resolved public key
    public string? Jkt { get; init; }                // key thumbprint
    public string? JwksUri { get; init; }            // declared JWKS URI (jwks_uri scheme)
    public string? Kid { get; init; }                // key ID (jwks_uri scheme)
    public string? Jwt { get; init; }                // raw agent token (jwt/jkt_jwt schemes)
    public JsonObject? Header { get; init; }         // parsed JWT header
    public JsonObject? Payload { get; init; }        // parsed JWT payload (claims)
}
```

## Custom Resolver

For non-standard schemes or additional validation:

```csharp
// Sample implementation — not part of the SDK.
// Implements AAuth.HttpSig.ISignatureKeyResolver by wrapping the SDK's
// DefaultSignatureKeyResolver and consulting an application-provided
// IPolicyService (also not part of the SDK).
public sealed class PolicyEnforcingResolver : ISignatureKeyResolver
{
    private readonly DefaultSignatureKeyResolver _inner;
    private readonly IPolicyService _policy;

    public PolicyEnforcingResolver(DefaultSignatureKeyResolver inner, IPolicyService policy)
    {
        _inner = inner;
        _policy = policy;
    }

    public async Task<SignatureKeyResolution> ResolveAsync(
        SignatureKeyParser.ParsedSignatureKeyInfo info, CancellationToken ct)
    {
        // Resolve key normally
        var resolution = await _inner.ResolveAsync(info, ct);

        // Apply additional policy (e.g., deny certain agent providers)
        if (info.Jwt is not null)
        {
            var iss = info.Payload?["iss"]?.GetValue<string>();
            if (!await _policy.IsAllowedIssuerAsync(iss, ct))
                throw new AAuthVerificationException("Agent provider not allowed");
        }

        return resolution;
    }
}
```

## Further Reading

- [Verification Middleware](verification-middleware.md) — where the resolver is wired in
- [Signing Modes Overview](../signing-modes/overview.md) — agent-side perspective on each mode
