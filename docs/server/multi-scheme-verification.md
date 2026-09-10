---
title: Multi-Scheme Verification
description: Resolve and verify supported Signature Keys carriers under explicit role policy.
---

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

app.UseAAuthVerification();
```

<details>
<summary>Manual Setup</summary>

```csharp
using AAuth.Server.Verification;

// AddAAuthResource registers the verifier, the discovery clients, and the
// DefaultSignatureKeyResolver that resolves all four schemes — no manual
// HttpClient/discovery wiring.
builder.Services.AddAAuthResource(options => options.Issuer = "https://resource.example");

app.UseAAuthVerification(new AAuthVerificationOptions
{
    AcceptedSchemes = ["jwt", "hwk", "jkt-jwt", "jwks_uri", "jwks", "self-jwt"],
});
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
| `jkt-jwt` | Self-anchored (Signature Keys draft-08 section 3.5): derives the durable key from header `jwk`, checks the thumbprint issuer, verifies the naming JWT, then returns ephemeral `cnf.jwk` |

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
// DefaultSignatureKeyResolver and consulting an application-provided
// asynchronous issuer-admission callback (host-owned).
public sealed class PolicyEnforcingResolver : ISignatureKeyResolver
{
    private readonly DefaultSignatureKeyResolver _inner;
    private readonly Func<string?, CancellationToken, Task<bool>> _isAllowedIssuer;

    public PolicyEnforcingResolver(DefaultSignatureKeyResolver inner,
        Func<string?, CancellationToken, Task<bool>> isAllowedIssuer)
    {
        _inner = inner;
        _isAllowedIssuer = isAllowedIssuer;
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
            if (!await _isAllowedIssuer(iss, ct))
                throw new AAuthVerificationException("Agent provider not allowed");
        }

        return resolution;
    }
}
```

Register a custom resolver through `AddAAuthResource` — set `o.KeyResolver` and the
SDK uses it instead of the default (it is registered via `TryAdd`, so your resolver
wins):

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
