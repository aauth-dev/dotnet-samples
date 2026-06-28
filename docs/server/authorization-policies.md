# Authorization Policies

The AAuth SDK integrates with ASP.NET Core's authorization system via `AAuthScopeRequirement`, `AAuthScopeHandler`, role claims, and a set of convenience policy registrations.

> For the end-to-end authN/authZ pipeline and how to wire AAuth up in both
> minimal-API and classic-MVC hosting styles, see
> [Authentication and Authorization](authn-authz.md).

## Registration

```csharp
using AAuth;

builder.Services.AddAAuthAuthentication();
builder.Services.AddAAuthAuthorization();
```

`AddAAuthAuthentication()` registers:
- `AAuthAuthenticationHandler` as the default authentication scheme

`AddAAuthAuthorization()` registers:
- `AAuthScopeHandler` as an `IAuthorizationHandler`
- Built-in policies: `AAuth.Authenticated`, `AAuth.Identified`, `AAuth.Authorized`

## Scope-Based Policies

Protect a minimal-API endpoint with `.RequireAAuth(scope: ...)`. It attaches the
verification and challenge metadata and an inline authorization policy in one call
— there is no named policy string to keep in sync:

```csharp
app.MapGet("/data", () => Results.Ok("data"))
    .RequireAAuth(scope: "data:read");
```

`.RequireAAuth(scope: ...)` enforces an `AAuthScopeRequirement`, which requires
**both** of the following — a verified scope alone is not sufficient:

- `AAuthVerificationResult.Level == AAuthLevel.Authorized` (the request presented a
  verified auth token, not just an agent token), **and**
- the required scope is present in `AAuthVerificationResult.Scopes`.

Because of the level check, a signature-only or agent-token-only (PoP) request can
never satisfy a scope requirement, even if it somehow carried a matching scope claim.

### Named policies (building block)

MVC controllers and other call sites that can't use the per-route `.RequireAAuth`
extension bind the same requirement through a named policy. Build it by hand with
`AAuthScopeRequirement` (remember to also bind the `AAuth` scheme so the claims are
available):

```csharp
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("ReadData", policy =>
        policy.AddAuthenticationSchemes(AAuthAuthenticationHandler.SchemeName)
            .AddRequirements(new AAuthScopeRequirement("data:read")));

// Reference it from a controller:
[Authorize("ReadData")]
public IActionResult GetData() => Ok("data");
```

The `AddAAuthScopePolicy(name, scope)` helper is a shortcut for the same
registration. Prefer `.RequireAAuth(scope: ...)` for minimal-API endpoints; reach
for named policies only where the endpoint extension is unavailable.

## Role-Based Policies

Enterprise roles asserted in the auth token's `roles` claim are mapped to the
standard `System.Security.Claims.ClaimTypes.Role` claim, so they work with the
built-in ASP.NET Core `RequireRole` / `[Authorize(Roles = ...)]`. On a minimal-API
endpoint, require a role with `.RequireAAuth(role: ...)` — it enforces the
`AAuthLevel.Authorized` level **and** the named role (and a scope too when both are
supplied):

```csharp
app.MapGet("/admin", () => Results.Ok("admin data"))
    .RequireAAuth(scope: "data:read", role: "admin");
```

For MVC controllers, register a named role policy (by hand, or with the
`AddAAuthRolePolicy(name, role)` helper) and reference it from `[Authorize]`.

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

> **Roles and groups are namespaced by the asserting PS.** Every PS-asserted
> identity claim (`NameIdentifier`, `Role`, `aauth:group`) carries
> `Claim.Issuer == iss`, and the canonical user key is the `(iss, sub)` pair
> surfaced as the composite `aauth:sub_iss` claim
> (`AAuthAuthenticationHandler.SubjectIssuerClaimType`). A role named `admin`
> asserted by `https://ps-a.example` is therefore distinct from the same role
> asserted by `https://ps-b.example`. Issuer trust is fail-closed: the
> verification middleware only honors auth tokens whose `iss` is in
> `AAuthVerificationOptions.TrustedAuthTokenIssuers` (see
> [verification-middleware.md](verification-middleware.md)).

## AAuthAuthenticationHandler

The authentication handler reads `AAuthVerificationResult` from `HttpContext.Features` (set by the verification middleware that `UseAAuth` runs) and maps it to a `ClaimsPrincipal`:

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

// One call: verifier, discovery clients (pooled handler), JTI store, and metadata.
builder.Services.AddAAuthResource(o =>
{
    o.Issuer = "https://resource.example";
    o.SigningKeys["key-1"] = resourceKey;
});
builder.Services.AddAAuthAuthentication();
builder.Services.AddAAuthAuthorization();

var app = builder.Build();

app.MapAAuthWellKnown();

app.UseRouting();
app.UseAAuth(o => o.TrustedAuthTokenIssuers = trustedPersonServers);
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/data", () => Results.Ok("protected data"))
    .RequireAAuth(scope: "data:read");
app.MapGet("/admin", () => Results.Ok("admin data"))
    .RequireAAuth(scope: "data:read", role: "admin");
app.Run();
```
