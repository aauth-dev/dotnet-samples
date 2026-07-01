# Authentication and Authorization

How the AAuth SDK turns a verified request into an ASP.NET Core `ClaimsPrincipal`
and enforces access, plus how to wire it up in both hosting styles — minimal APIs
and classic MVC controllers.

This page ties together two adjacent topics:

- [Verification Middleware](verification-middleware.md) — proof-of-possession and
  token verification (the authN *input*).
- [Authorization Policies](authorization-policies.md) — scope, role, and level
  policies (the authZ *rules*).

## Pipeline at a glance

AAuth runs as ordered layers. The order matters: each layer consumes what the
previous one produced.

1. **Routing** (`UseRouting`) — resolves the matched endpoint so the next layer can
   read its `.RequireAAuth(...)` / `.RequireAAuthSignature(...)` metadata.
2. **AAuth** (`UseAAuth`) — the single AAuth middleware. For each matched endpoint
   it verifies the HTTP signature (RFC 9421) and, for auth-token endpoints, the auth
   token against the issuer's JWKS, then returns a `401` resource-token challenge
   when only an agent token is presented. It writes an `AAuthVerificationResult` to
   `HttpContext.Features`. (Internally it runs the verification and challenge
   middleware described in [Verification Middleware](verification-middleware.md) and
   [Challenge Middleware](challenge-middleware.md).)
3. **Authentication + authorization** (`UseAuthentication` / `UseAuthorization`) —
   `AAuthAuthenticationHandler` maps the verification result to a
   `ClaimsPrincipal`; each route's `.RequireAAuth(...)` policy then decides access.

```mermaid
flowchart LR
    req([request]) --> route["UseRouting<br/>(resolve endpoint)"]
    route --> aauth["UseAAuth<br/>(verify + challenge<br/>per matched endpoint)"]
    aauth --> authn["UseAuthentication<br/>(Features → Principal)"]
    authn --> authz["UseAuthorization<br/>(policy check)"]
    authz --> ep([endpoint])
```

> **Well-known endpoints pass through.** Map `app.MapAAuthWellKnown()` to serve the
> metadata document and JWKS. They carry no `.RequireAAuth(...)` metadata, so
> `UseAAuth` lets them through unverified — no AAuth signature required.

## Authentication (authN)

`AAuthAuthenticationHandler` is the bridge from verification to identity. It reads
`AAuthVerificationResult` from `HttpContext.Features` and produces a
`ClaimsPrincipal`. Register it with `AddAAuthAuthentication()`.

### Level mapping

The verification *level* records how strongly the caller is identified:

```csharp
public enum AAuthLevel
{
    Pseudonymous,  // hwk scheme — key-only identity
    Identified,    // jwt / jwks_uri — agent identity known
    Authorized,    // aa-auth+jwt — full PS/AS authorization
}
```

- **Pseudonymous** — the request proved possession of a key (`hwk`/`jkt-jwt`) but
  carries no agent identity.
- **Identified** — the agent's identity is verified (`jwt`/`jwks_uri`), but no PS
  has authorized access.
- **Authorized** — a verified `aa-auth+jwt` is present; the PS/AS has authorized
  the agent for the asserted scope.

### Claim mapping and PS namespacing

The handler maps the verification result to claims (see
[Authorization Policies](authorization-policies.md#aauthauthenticationhandler) for
the full table). The identity claims asserted by a Person Server — `sub`
(`NameIdentifier`), each `role`, and each `aauth:group` — carry
`Claim.Issuer == iss`, the asserting PS. The canonical user key is therefore the
`(iss, sub)` pair, surfaced as the composite `aauth:sub_iss` claim
(`AAuthAuthenticationHandler.SubjectIssuerClaimType`).

> **`sub` alone is not an identity.** The same `sub` asserted by two different
> Person Servers is two different users. Key your application records on
> `(iss, sub)` (or the `aauth:sub_iss` claim), never on `sub` alone. Issuer trust
> is open by default — an unset `AAuthVerificationOptions.TrustedAuthTokenIssuers`
> honors any *verifiable* Person Server (namespaced by `iss`); set the list (or
> the `IsTrustedAuthTokenIssuer` predicate) to restrict which issuers are honored.

## Authorization (authZ)

Register the handlers and built-in policies with `AddAAuthAuthorization()`, then
protect each route with `.RequireAAuth(...)`:

```csharp
builder.Services.AddAAuthAuthentication();
builder.Services.AddAAuthAuthorization();

// ...
app.MapGet("/data", handler).RequireAAuth(scope: "data:read");
app.MapGet("/admin", handler).RequireAAuth(scope: "data:read", role: "admin");
```

`.RequireAAuth(...)` attaches the verification/challenge metadata and an inline
authorization policy in one call — there is no named policy string to keep in sync.
`AddAAuthAuthorization()` also registers the built-in level policies
`AAuth.Authenticated`, `AAuth.Identified`, and `AAuth.Authorized`.

Scope and role requirements both require `AAuthLevel.Authorized` — a signature-only
or agent-token-only request can never satisfy them, even if it carried a matching
scope claim. See [Authorization Policies](authorization-policies.md) for the scope
handler semantics and the role/group discussion.

## Wiring style 1 — Minimal APIs

This is what the [Calendar sample](../../samples/MockResourceServers/Calendar/) uses.
One `AddAAuthResource` registration, one `UseAAuth` pipeline, and per-endpoint
`.RequireAAuth(...)`.

```csharp
var builder = WebApplication.CreateBuilder(args);

// One call: verifier, discovery clients (pooled handler), JTI store, and the
// published metadata.
builder.Services.AddAAuthResource(o =>
{
    o.Issuer = resourceUrl;
    o.SigningKeys["calendar-1"] = resourceKey;
    o.ScopeDescriptions = new()
    {
        ["calendar.read"] = "See your calendar events",
        ["calendar.write"] = "Add and change calendar events",
    };
});
builder.Services.AddAAuthAuthentication();
builder.Services.AddAAuthAuthorization();

var app = builder.Build();

// Well-known metadata + JWKS from the DI metadata (no signature required).
app.MapAAuthWellKnown();

// One declarative pipeline. Resource-level config is trust only; key and issuer
// default from the DI metadata.
app.UseRouting();
app.UseAAuth(o => o.TrustedAuthTokenIssuers = trustedPersonServers);
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/events", (HttpContext ctx) => Results.Ok(/* ... */))
    .RequireAAuth(scope: "calendar.read");

app.MapGet("/events/admin", (HttpContext ctx) => Results.Ok(/* ... */))
    .RequireAAuth(scope: "calendar.read", role: "calendar.owner");

app.Run();
```

`MapGroup` organizes endpoints under a shared prefix; attach `.RequireAAuth(...)`
to each endpoint in the group:

```csharp
var admin = app.MapGroup("/admin");
admin.MapGet("/profile", () => Results.Ok(/* ... */)).RequireAAuth(scope: "calendar.write");
admin.MapPost("/profile", () => Results.Ok(/* ... */)).RequireAAuth(scope: "calendar.write");
```

## Wiring style 2 — Classic MVC controllers

Controllers can't use the per-route `.RequireAAuth(...)` extension (it targets
minimal-API endpoints), so the MVC style composes the building-block verification
and challenge middleware directly and binds scope/role requirements through named
policies referenced by `[Authorize]`. Service registration still uses
`AddAAuthResource`.

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddAAuthResource(o =>
{
    o.Issuer = resourceUrl;
    o.SigningKeys["key-1"] = resourceKey;
});
builder.Services.AddAAuthAuthentication();
builder.Services.AddAAuthAuthorization();
builder.Services.AddAAuthScopePolicy("AAuth.Scope.data:read", "data:read");
builder.Services.AddAAuthRolePolicy("AAuth.Role.admin", "admin");

var app = builder.Build();

app.MapAAuthWellKnown();

app.UseAAuthVerification(new AAuthVerificationOptions
{
    ResourceIdentifier = resourceUrl,
    RequireIssuerVerification = true,
    TrustedAuthTokenIssuers = trustedPersonServers,
});
app.UseAAuthChallenge(challengeOptions);

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.Run();
```

```csharp
[ApiController]
[Route("data")]
public sealed class DataController : ControllerBase
{
    // Scope policy: requires Authorized level + the `data:read` scope.
    [HttpGet]
    [Authorize("AAuth.Scope.data:read")]
    public IActionResult Get() => Ok(/* ... */);

    // Role policy: requires Authorized level + the `admin` role.
    [HttpDelete("{id}")]
    [Authorize("AAuth.Role.admin")]
    public IActionResult Delete(string id) => NoContent();

    // Roles also work with the framework's RequireRole / Roles syntax,
    // because AAuth maps the `roles` claim to ClaimTypes.Role.
    [HttpPost]
    [Authorize(Roles = "admin")]
    public IActionResult Create() => Created(string.Empty, null);
}
```

> **Roles are PS-namespaced here too.** `[Authorize(Roles = "admin")]` matches a
> role asserted by *any* trusted PS. If you need to bind a role to a specific
> issuer, enforce it in a custom policy that inspects `Claim.Issuer` or the
> `(iss, sub)` pair from `AAuthVerificationResult`.

## Reading the verified identity in handlers

Both styles expose the same data. From the `ClaimsPrincipal`:

```csharp
var subIss = User.FindFirst(AAuthAuthenticationHandler.SubjectIssuerClaimType)?.Value; // "iss|sub"
var issuer = User.FindFirst(ClaimTypes.NameIdentifier)?.Issuer;                         // asserting PS
```

Or directly from the verification feature:

```csharp
var result = HttpContext.Features.Get<AAuthVerificationResult>();
// result.Level, result.Subject, result.Issuer, result.Scopes, result.Roles, result.Groups
```

## Further Reading

- [Verification Middleware](verification-middleware.md) — PoP + token verification
- [Authorization Policies](authorization-policies.md) — scope/role/level policies
- [Challenge Middleware](challenge-middleware.md) — emitting 401 resource-token challenges
- [Token Issuance](token-issuance.md) — building and verifying tokens
