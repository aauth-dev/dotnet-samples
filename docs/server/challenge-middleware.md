# Challenge Middleware

`AAuthChallengeMiddleware` automatically issues 401 challenges with resource tokens when an agent presents only an agent token but the resource requires an auth token.

## Registration

```csharp
using AAuth.DependencyInjection;
using AAuth.Server;

// Must be registered AFTER UseAAuthVerification
app.UseAAuthChallenge(new ChallengeOptions
{
    AccessMode = AAuthAccessMode.RequireAuthToken,
});
```

## Access Modes

```csharp
public enum AAuthAccessMode
{
    // Accept any verified identity without requiring auth token
    IdentityOnly,

    // Require auth token — issue 401 challenge if only agent token present
    RequireAuthToken,
}
```

## How It Works

1. `UseAAuthVerification` runs first and stores `AAuthVerificationResult` in features
2. If `AccessMode` is `RequireAuthToken` and the token is an agent token (not auth token):
   - Middleware mints a resource token (`aa-resource+jwt`) scoped to the request
   - Returns `401 Unauthorized` with `AAuth-Requirement: requirement=auth-token; resource-token="<jwt>"`
3. The agent's `ChallengeHandler` catches the 401, exchanges the resource token at its PS, and retries

## Challenge Options

```csharp
public sealed class ChallengeOptions
{
    // How to handle access decisions
    public AAuthAccessMode AccessMode { get; init; } = AAuthAccessMode.RequireAuthToken;

    // Resource signing key for minting resource tokens
    public AAuthKey? ResourceSigningKey { get; init; }

    // Key identifier for the resource signing key (kid in the resource token header)
    public string? ResourceKeyId { get; init; }

    // Resource identifier (used as iss in the resource token)
    public string? ResourceIdentifier { get; init; }

    // Explicit audience for resource tokens (e.g. the AS URL in a four-party flow).
    // When null, audience is resolved from the agent token's ps claim (three-party).
    public string? PersonServerAudience { get; init; }

    // Default scopes to request in the resource token (space-separated)
    public string? DefaultScopes { get; init; }

    // Allowed Signature-Key schemes (null = allow all)
    public IReadOnlySet<string>? AllowedSignatureKeySchemes { get; init; }
}
```

## Typical Pipeline

```csharp
app.UseAAuthVerification(new AAuthVerificationOptions
{
    ResourceIdentifier = "https://resource.example",
    RequireIssuerVerification = true,
});

app.UseAAuthChallenge(new ChallengeOptions
{
    AccessMode = AAuthAccessMode.RequireAuthToken,
});

// Endpoints below here see only authorized requests
app.MapGet("/data", (HttpContext ctx) =>
{
    var result = ctx.Features.Get<AAuthVerificationResult>()!;
    // result.Level == AAuthLevel.Authorized
});
```
