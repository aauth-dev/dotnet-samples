# Replay Detection

> [Signature Security](https://explorer.aauth.dev/foundations/signatures)

## Overview

HTTP signatures have a `created` timestamp and a unique `nonce` parameter, but a valid signature could still be replayed within its validity window. The `IJtiStore` interface prevents replay by tracking seen token IDs (`jti` claims) and rejecting duplicates.

## IJtiStore Interface

```csharp
namespace AAuth.Server;

public interface IJtiStore
{
    /// Returns true if recorded successfully (first time seen), false if duplicate.
    Task<bool> TryRecordAsync(string jti, DateTimeOffset expiration, CancellationToken ct = default);

    /// Mark a jti as revoked (prevents future use even if not yet expired).
    Task RevokeAsync(string jti, CancellationToken ct = default);

    /// Check if a jti has been explicitly revoked.
    Task<bool> IsRevokedAsync(string jti, CancellationToken ct = default);
}
```

## Built-in: InMemoryJtiStore

Thread-safe, in-process implementation. Suitable for single-instance deployments and testing.

```csharp
using AAuth.DependencyInjection;

// DI extension (recommended) — registers IJtiStore automatically
builder.Services.AddAAuthResource(options =>
{
    options.Issuer = "https://resource.example";
    options.EnableReplayDetection = true;
});
```

<details>
<summary>Manual Setup</summary>

```csharp
using AAuth.Server;
using AAuth.DependencyInjection;

builder.Services.AddSingleton(new AAuthVerifier());
builder.Services.AddSingleton<IJtiStore>(new InMemoryJtiStore());

var app = builder.Build();
app.UseAAuthVerification(new AAuthVerificationOptions
{
    RequireIssuerVerification = false,
});

// Optional: periodic cleanup of expired entries
var jtiStore = app.Services.GetRequiredService<IJtiStore>() as InMemoryJtiStore;
var timer = new PeriodicTimer(TimeSpan.FromMinutes(10));
_ = Task.Run(async () =>
{
    while (await timer.WaitForNextTickAsync())
        jtiStore?.Cleanup();
});
```

</details>

## Custom Implementations

For distributed deployments, implement `IJtiStore` against a shared store. The example below is a sample sketch (not part of the SDK) showing how to implement `IJtiStore` against Redis using `IDatabase` from the `StackExchange.Redis` package (also not part of the SDK):

```csharp
// Sample implementation — not part of the SDK.
// Implements AAuth.Server.IJtiStore using a Redis IDatabase (StackExchange.Redis).
public sealed class RedisJtiStore : IJtiStore
{
    private readonly IDatabase _redis;

    public RedisJtiStore(IDatabase redis) => _redis = redis;

    public async Task<bool> TryRecordAsync(string jti, DateTimeOffset expiration, CancellationToken ct)
    {
        var ttl = expiration - DateTimeOffset.UtcNow;
        if (ttl <= TimeSpan.Zero) return false;

        // SET NX with TTL — returns true only if key didn't exist
        return await _redis.StringSetAsync($"jti:{jti}", "1", ttl, When.NotExists);
    }

    public async Task RevokeAsync(string jti, CancellationToken ct)
    {
        await _redis.StringSetAsync($"jti:revoked:{jti}", "1", TimeSpan.FromHours(24));
    }

    public async Task<bool> IsRevokedAsync(string jti, CancellationToken ct)
    {
        return await _redis.KeyExistsAsync($"jti:revoked:{jti}");
    }
}
```

## Revocation Endpoint

The SDK provides a pre-built revocation endpoint for token revocation:

```csharp
using AAuth.Server;

app.MapAAuthRevocationEndpoint(jtiStore, path: "/revoke");
```

This maps `POST /revoke` accepting form-encoded data:

```
Content-Type: application/x-www-form-urlencoded

token=token-id-to-revoke
```

The endpoint calls `jtiStore.RevokeAsync(token)` and returns `200 OK`.

Advertise it in resource metadata:

```csharp
app.MapAAuthResourceWellKnown(new AAuthResourceMetadataOptions
{
    // ...
    RevocationEndpoint = "https://resource.example/revoke"
});
```

## How It Fits Together

```
Request arrives → Middleware verifies signature
                → Middleware checks jti via IJtiStore.TryRecordAsync()
                → If duplicate → 401 + Signature-Error: invalid_request
                → If new → stores jti with expiration, passes to handler
```

## Further Reading

- [Verification Middleware](verification-middleware.md)
- [Token Issuance](token-issuance.md) — token builders auto-generate `jti` values
- [Error Handling](../advanced/error-handling.md)
