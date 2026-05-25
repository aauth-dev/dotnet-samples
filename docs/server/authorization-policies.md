# Authorization Policies

The AAuth SDK integrates with ASP.NET Core's authorization system via `AAuthScopeRequirement` and `AAuthScopeHandler`.

## Registration

```csharp
using AAuth.DependencyInjection;

builder.Services.AddAuthorization();
builder.Services.AddAAuthAuthorization();
```

`AddAAuthAuthorization()` registers:
- `AAuthAuthenticationHandler` as the default authentication scheme
- `AAuthScopeHandler` as an `IAuthorizationHandler`

## Scope-Based Policies

Define policies that require specific AAuth scopes:

```csharp
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("ReadData", policy =>
        policy.Requirements.Add(new AAuthScopeRequirement("data:read")));

    options.AddPolicy("WriteData", policy =>
        policy.Requirements.Add(new AAuthScopeRequirement("data:write")));
});
```

Apply via `[Authorize]` or endpoint metadata:

```csharp
app.MapGet("/data", [Authorize("ReadData")] () => Results.Ok("data"));

// Or in controllers:
[Authorize("ReadData")]
public IActionResult GetData() => Ok("data");
```

## AAuthAuthenticationHandler

The authentication handler reads `AAuthVerificationResult` from `HttpContext.Features` (set by `UseAAuthVerification`) and maps it to a `ClaimsPrincipal`:

| Claim | Source |
|-------|--------|
| `sub` | `AAuthVerificationResult.Subject` |
| `agent` | `AAuthVerificationResult.Agent` |
| `scope` | Each scope as a separate claim |
| `iss` | `AAuthVerificationResult.Issuer` |
| `level` | `AAuthVerificationResult.Level` |

## AAuthLevel

The verification level is available in both the feature and claims:

```csharp
public enum AAuthLevel
{
    Pseudonymous,  // hwk scheme — key-only identity
    Identified,    // jwt/jwks_uri — agent identity known
    Authorized,    // aa-auth+jwt — full PS/AS authorization
}
```

## Complete Example

```csharp
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton(new AAuthVerifier());
builder.Services.AddSingleton(sp => new MetadataClient(httpClient));
builder.Services.AddSingleton(sp => new JwksClient(httpClient));
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("DataRead", policy =>
        policy.Requirements.Add(new AAuthScopeRequirement("data:read")));
});
builder.Services.AddAAuthAuthorization();

var app = builder.Build();
app.UseAAuthVerification();
app.UseAAuthChallenge(new ChallengeOptions
{
    AccessMode = AAuthAccessMode.RequireAuthToken,
});
app.UseAuthorization();

app.MapGet("/data", [Authorize("DataRead")] () => Results.Ok("protected data"));
app.Run();
```
