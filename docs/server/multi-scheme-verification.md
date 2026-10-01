# Multi-Scheme Verification

> [Signature-Key Schemes](https://explorer.aauth.dev/foundations/schemes)

## Overview

AAuth resources accept the `jwt` signature scheme by default. Generic Signature
Keys endpoints explicitly opt into other schemes; they do not become AAuth
resource access modes. The resolver supplies typed verified context, not merely
a parsed public key. Companion token types require explicit verifier registration.

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

Supports the six schemes subject to the endpoint's explicit policy:

```csharp
using AAuth;

// DI extension (recommended) — registers resolver automatically
builder.Services.AddAAuthResource(options =>
{
    options.Issuer = "https://resource.example";
});

// Auth-token and person-token `aud` is checked against the Issuer above.
app.UseAAuthVerification();
```

<details>
<summary>Manual Setup</summary>

```csharp
using AAuth.Server.Verification;

// AddAAuthResource registers the verifier, the discovery clients, and the
// DefaultSignatureKeyResolver that resolves the supported schemes — no manual
// HttpClient/discovery wiring.
builder.Services.AddAAuthResource(options => options.Issuer = "https://resource.example");

app.UseAAuthVerification(options =>
    options.AcceptedSchemes = ["jwt", "hwk", "jkt-jwt", "jwks_uri", "jwks", "self-jwt"]);
```

</details>

### Resolution Logic by Scheme

| Scheme | How Key Is Resolved |
|--------|-------------------|
| `hwk` | Validates structured public JWK members and computes the thumbprint locally |
| `jwks_uri` | Discovers exact id/dwk metadata, validates issuer, follows jwks_uri and selects kid |
| `jwks` | Fetches the exact direct url and selects kid |
| `self-jwt` | Validates the registered assertion type; issuer key verifies JWT and HTTP, with no cnf |
| `jwt` | Extracts `cnf.jwk` from agent token, fetches AP's JWKS to verify token signature |
| `jkt-jwt` | Self-anchored (Signature Keys draft-09 section 3.5): derives the durable key from header `jwk`, checks the thumbprint issuer, verifies the naming JWT, then returns ephemeral `cnf.jwk` |

## HWK — Inline Public Key

For `hwk` (pseudonymous) mode, the agent sends its full public key inline in the
`Signature-Key` header as structured public JWK members. The resource extracts the key
directly — no pre-registration or key lookup is required.

## ParsedSignatureKeyInfo

After resolution, the parsed info is available via `HttpContext.Items[AAuthVerificationMiddleware.ParsedInfoItemKey]`:

```csharp
public sealed class ParsedSignatureKeyInfo
{
    public required string Scheme { get; init; }     // "hwk", "jwks_uri", "jwt", "jkt-jwt"
    public IAAuthKey? ConfirmationKey { get; init; } // resolved public key
    public string? Jkt { get; init; }                // key thumbprint
    public string? JwksUri { get; init; }            // declared JWKS URI (jwks_uri scheme)
    public string? Kid { get; init; }                // key ID (jwks_uri scheme)
    public string? Jwt { get; init; }                // raw agent token (jwt/jkt-jwt schemes)
    public JsonObject? Header { get; init; }         // parsed JWT header
    public JsonObject? Payload { get; init; }        // parsed JWT payload (claims)
}
```

## Custom Resolver

For non-standard schemes or additional validation:

```csharp
// Sample implementation — not part of the SDK.
// Implements AAuth.HttpSig.ISignatureKeyResolver by wrapping the SDK's
// DefaultSignatureKeyResolver and attaching typed context for later
// authorization. Do not deny trusted-but-unauthorized issuers from the resolver:
// resolver failures are signature failures (401 Signature-Error). Authorization
// policy failures after successful verification should be 403.
public sealed class PolicyEnforcingResolver : ISignatureKeyResolver
{
    private readonly DefaultSignatureKeyResolver _inner;

    public PolicyEnforcingResolver(DefaultSignatureKeyResolver inner) => _inner = inner;

    public Task<SignatureKeyResolution> ResolveAsync(
        SignatureKeyParser.ParsedSignatureKeyInfo info, CancellationToken ct)
    {
        // Resolve key normally
        var resolutionTask = _inner.ResolveAsync(info, ct);

        // Record context for an ASP.NET authorization policy that can return 403.
        if (info.Jwt is not null)
        {
            var iss = info.Payload?["iss"]?.GetValue<string>();
            // Attach `iss` to a request feature or claims transformation in real code.
        }

        return resolutionTask;
    }
}
```

Register a custom resolver through `AddAAuthResource` — set `o.KeyResolver` and the
SDK uses it instead of the default (it is registered via `TryAdd`, so your resolver
wins). Keep trust and authorization decisions in `AAuthTrustOptions`,
`IAAuthTrustPolicy` or ASP.NET authorization policies so unauthorized but
well-formed identities return `403`, not `401 Signature-Error`:

```csharp
builder.Services.AddAAuthResource(options =>
{
    options.Issuer = "https://resource.example";
    options.KeyResolver = issuerPolicyResolver;
});
```

## Further Reading

- [Verification Middleware](verification-middleware.md) — where the resolver is wired in
- [Signing Modes Overview](../signing-modes/overview.md) — agent-side perspective on each mode
