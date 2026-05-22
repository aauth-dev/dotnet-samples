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
using AAuth.HttpSig;
using AAuth.Discovery;

var resolver = new DefaultSignatureKeyResolver(
    jwksClient: new JwksClient(new HttpClient()),  // fetches JWKS for jwks_uri and jwt schemes
    keyLookup: myKeyLookup                         // resolves hwk thumbprints to stored keys
);

app.UseAAuthVerification(
    verifier: new AAuthVerifier(),
    resolver: resolver);
```

### Resolution Logic by Scheme

| Scheme | How Key Is Resolved |
|--------|-------------------|
| `hwk` | Calls `IKeyLookup.FindByThumbprintAsync(jkt)` — resource must know the key |
| `jwks_uri` | Fetches JWKS from the declared URI, finds key by `kid` |
| `jwt` | Extracts `cnf.jwk` from agent token, fetches AP's JWKS to verify token signature |
| `jkt_jwt` | Resolves durable key via `IKeyLookup`, verifies JWT delegation to ephemeral key |

## IKeyLookup — HWK Key Resolution

For `hwk` mode, the resource must already know the agent's public key. Implement `IKeyLookup`:

```csharp
namespace AAuth.HttpSig;

public interface IKeyLookup
{
    Task<IAAuthKey?> FindByThumbprintAsync(string jkt, CancellationToken ct = default);
}
```

Example implementation:

```csharp
public sealed class DatabaseKeyLookup : IKeyLookup
{
    private readonly IKeyRepository _repo;

    public DatabaseKeyLookup(IKeyRepository repo) => _repo = repo;

    public async Task<IAAuthKey?> FindByThumbprintAsync(string jkt, CancellationToken ct)
    {
        var keyData = await _repo.GetByThumbprintAsync(jkt, ct);
        if (keyData is null) return null;
        return AAuthKey.FromJwk(keyData.PublicJwk);
    }
}
```

If `IKeyLookup` is not provided and an `hwk` request arrives, verification fails with `SignatureErrorCode.UnknownKey`.

## ParsedSignatureKeyInfo

After resolution, the parsed info is available via `HttpContext.Items[AAuthVerificationMiddleware.ContextItemKey]`:

```csharp
public sealed class ParsedSignatureKeyInfo
{
    public required string Scheme { get; init; }     // "hwk", "jwks_uri", "jwt", "jkt_jwt"
    public AAuthKey? ConfirmationKey { get; init; }  // resolved public key
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
