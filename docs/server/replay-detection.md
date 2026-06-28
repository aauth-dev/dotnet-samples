# Replay Detection

> [Signature Security](https://explorer.aauth.dev/foundations/signatures)

## Overview

An auth token (and a `jkt-jwt` naming JWT) is a **reusable** proof-of-possession
credential: the agent re-signs and presents it on every request, so replay
protection cannot live on the token itself. Per the spec's §Freshness and Replay,
the `created` timestamp is the primary defense — a captured signature is unusable
once its validity window (default 60 s) closes — and a verifier MAY additionally
reject a captured signature *replayed within* that window. This profile defines no
nonce mechanism.

The verification middleware implements that optional defense by recording the
**verified signature** for the freshness window via `IJtiStore`. The signature
cryptographically binds the spec's replay tuple `(signing-key-thumbprint, created,
@method, @authority, @path)` **plus** the covered `signature-key` (the carrier), so
an exact captured-signature replay collides and is rejected, while legitimately
distinct requests — a fresh `created`, a different carrier, a different path —
never do. **Reusing the same auth token across requests is always accepted.** The
token `jti` is used only for revocation and audit, never to make a token
single-use.

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

> The middleware passes the per-request **signature** to `TryRecordAsync` (the
> replay key) and the carrier token's **`jti`** to `RevokeAsync` /
> `IsRevokedAsync` (revocation). The `jti` parameter name is historical — a custom
> store should treat the recorded value as an opaque key.

## Built-in: InMemoryJtiStore

Thread-safe, in-process implementation. Suitable for single-instance deployments and testing.

```csharp
using AAuth;

// DI extension (recommended) — registers IJtiStore automatically
builder.Services.AddAAuthResource(options =>
{
    options.Issuer = "https://resource.example";
    options.EnableReplayDetection = true;
});
```

<details>
<summary>Override the JTI store (building block)</summary>

```csharp
using AAuth.Server;

// AddAAuthResource registers InMemoryJtiStore by default (via TryAdd), so
// register your own IJtiStore first to override it.
builder.Services.AddSingleton<IJtiStore>(new InMemoryJtiStore());
builder.Services.AddAAuthResource(options => options.Issuer = "https://resource.example");

var app = builder.Build();

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
