# Authorization Policies

The AAuth SDK integrates with ASP.NET Core's authorization system via `AAuthScopeRequirement`, `AAuthScopeHandler`, role claims, and a set of convenience policy registrations.

## Registration

```csharp
using AAuth.DependencyInjection;

builder.Services.AddAAuthAuthentication();
builder.Services.AddAAuthAuthorization();
```

`AddAAuthAuthentication()` registers:
- `AAuthAuthenticationHandler` as the default authentication scheme

`AddAAuthAuthorization()` registers:
- `AAuthScopeHandler` as an `IAuthorizationHandler`
- Built-in policies: `AAuth.Authenticated`, `AAuth.Identified`, `AAuth.Authorized`

## Scope-Based Policies

Use the `AddAAuthScopePolicy` convenience helper to register a named policy that
requires a specific scope. It binds the `AAuth` authentication scheme and adds an
`AAuthScopeRequirement`:

```csharp
builder.Services.AddAAuthScopePolicy("AAuth.Scope.data:read", "data:read");
builder.Services.AddAAuthScopePolicy("AAuth.Scope.data:write", "data:write");
```

`AAuthScopeHandler` requires **both** of the following — a verified scope alone is
not sufficient:

- `AAuthVerificationResult.Level == AAuthLevel.Authorized` (the request presented a
  verified auth token, not just an agent token), **and**
- the required scope is present in `AAuthVerificationResult.Scopes`.

Because of the level check, a signature-only or agent-token-only (PoP) request can
never satisfy a scope policy, even if it somehow carried a matching scope claim.

Apply via `[Authorize]` or endpoint metadata:

```csharp
app.MapGet("/data", () => Results.Ok("data"))
    .RequireAuthorization("AAuth.Scope.data:read");

// Or in controllers:
[Authorize("AAuth.Scope.data:read")]
public IActionResult GetData() => Ok("data");
```

To build a policy by hand instead of using the helper, add the requirement directly
(remember to also bind the `AAuth` scheme so the claims are available):

```csharp
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("ReadData", policy =>
        policy.AddAuthenticationSchemes(AAuthAuthenticationHandler.SchemeName)
            .AddRequirements(new AAuthScopeRequirement("data:read")));
```

## Role-Based Policies

Enterprise roles asserted in the auth token's `roles` claim are mapped to the
standard `System.Security.Claims.ClaimTypes.Role` claim, so they work with the
built-in ASP.NET Core `RequireRole` / `[Authorize(Roles = ...)]`. Use
`AddAAuthRolePolicy` to register a named policy that requires the
`AAuthLevel.Authorized` level **and** a specific role:

```csharp
builder.Services.AddAAuthRolePolicy("AAuth.Role.admin", "admin");

app.MapGet("/admin", () => Results.Ok("admin data"))
    .RequireAuthorization("AAuth.Role.admin");
```

> **Role assertion is the PS's decision.** A role policy enforces a role that
> the Person Server *may* assert in the auth token (the protocol leaves it
> discretionary). The challenge a resource emits only names the requested
> *scope*, not a role. If the PS issues a valid auth token for the requested
> scope but withholds the role, the role policy returns a `403` with no
> automatic step-up — insufficient-role re-challenge is out of scope. Design
> role-gated endpoints so that the PS is expected to assert the role for the
> agents that should reach them.

Groups asserted in the auth token's `groups` claim are emitted as one
`aauth:group` claim each (`AAuthAuthenticationHandler.GroupClaimType`) and exposed
as `AAuthVerificationResult.Groups`. They are available for custom policies or
auditing but are not enforced by a built-in helper.

## AAuthAuthenticationHandler

The authentication handler reads `AAuthVerificationResult` from `HttpContext.Features` (set by `UseAAuthVerification`) and maps it to a `ClaimsPrincipal`:

| Claim | Source |
|-------|--------|
| `System.Security.Claims.ClaimTypes.NameIdentifier` (`sub`) | `AAuthVerificationResult.Subject` |
| `aauth:agent` | `AAuthVerificationResult.Agent` |
| `aauth:scope` | One claim per scope in `AAuthVerificationResult.Scopes` |
| `aauth:issuer` | `AAuthVerificationResult.Issuer` |
| `aauth:level` | `AAuthVerificationResult.Level` (`AAuthLevel` enum, serialized as string) |
| `aauth:scheme` | `AAuthVerificationResult.Scheme` (`hwk`, `jwks_uri`, `jwt`, `jkt-jwt`) |
| `aauth:jkt` | `AAuthVerificationResult.Jkt` (JWK thumbprint of the signing key) |
| `aauth:act_sub` | `AAuthVerificationResult.ActorSubject` (intermediary in call-chaining) |
| `System.Security.Claims.ClaimTypes.Role` | One claim per role in `AAuthVerificationResult.Roles` |
| `aauth:group` | One claim per group in `AAuthVerificationResult.Groups` |

Claim type constants are exposed as `public const string` fields on `AAuthAuthenticationHandler` (for example `AAuthAuthenticationHandler.ScopeClaimType` and `AAuthAuthenticationHandler.GroupClaimType`). Roles use the standard framework `ClaimTypes.Role` so `RequireRole` works out of the box.

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
builder.Services.AddAAuthAuthentication();
builder.Services.AddAAuthAuthorization();
builder.Services.AddAAuthScopePolicy("AAuth.Scope.data:read", "data:read");
builder.Services.AddAAuthRolePolicy("AAuth.Role.admin", "admin");

var app = builder.Build();
app.UseAAuthVerification();
app.UseAAuthChallenge(new ChallengeOptions
{
    AccessMode = AAuthAccessMode.RequireAuthToken,
    ResourceSigningKey = resourceKey,
    ResourceKeyId = "key-1",
    ResourceIdentifier = "https://resource.example",
    DefaultScopes = "data:read",
});
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/data", () => Results.Ok("protected data"))
    .RequireAuthorization("AAuth.Scope.data:read");
app.Run();
```
