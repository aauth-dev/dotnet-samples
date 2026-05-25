# Challenge Middleware

`AAuthChallengeMiddleware` automatically issues 401 challenges with resource tokens when an agent presents only an agent token but the resource requires an auth token.

## Registration

```csharp
using AAuth.DependencyInjection;
using AAuth.Server;

// Must be registered AFTER UseAAuthFullVerification
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

1. `UseAAuthFullVerification` runs first and stores `AAuthVerificationResult` in features
2. If `AccessMode` is `RequireAuthToken` and the token is an agent token (not auth token):
   - Middleware mints a resource token (`aa-resource+jwt`) scoped to the request
   - Returns `401 Unauthorized` with `AAuth-Requirement: requirement=auth-token; resource-token="<jwt>"`
3. The agent's `ChallengeHandler` catches the 401, exchanges the resource token at its PS, and retries

## Challenge Options

```csharp
public class ChallengeOptions
{
    // How to handle access decisions
    public AAuthAccessMode AccessMode { get; set; } = AAuthAccessMode.RequireAuthToken;

    // Resource signing key for minting resource tokens
    public IAAuthKey? ResourceKey { get; set; }

    // Resource identifier (audience in resource tokens)
    public string? ResourceIdentifier { get; set; }

    // Scopes to request in the challenge
    public string? RequiredScope { get; set; }

    // Allowed Signature-Key schemes (null = allow all)
    public IReadOnlyList<string>? AllowedSchemes { get; set; }
}
```

## Typical Pipeline

```csharp
app.UseAAuthFullVerification(new FullVerificationOptions
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
