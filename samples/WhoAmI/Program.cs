using AAuth.Crypto;
using AAuth;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server;

var builder = WebApplication.CreateBuilder(args);

// -----------------------------------------------------------------------
// Configure the resource's own signing key and identity.
// -----------------------------------------------------------------------
// The resource is "self-issued" for the sample: a freshly generated key on
// startup, served via /.well-known/jwks.json. A production resource would
// load a stable key from secure storage.
var resourceKey = AAuthKey.Generate();
const string ResourceKid = "whoami-1";

// Scope + role taxonomy this resource recognises.
//   whoami        — basic profile read (three-party baseline)
//   whoami:admin  — elevated profile access (step-up scope)
//   whoami-admin  — RBAC role asserted by the PS
const string ScopeWhoami = "whoami";
const string ScopeWhoamiAdmin = "whoami:admin";
const string RoleWhoamiAdmin = "whoami-admin";

var resourceUrl = builder.Configuration["AAuth:Issuer"] ?? "http://localhost:5000";
var signatureWindowSeconds = builder.Configuration.GetValue<int?>("AAuth:SignatureWindow") ?? 60;

// Person Server(s) this resource trusts to assert user identity. Fail-closed:
// an auth token from any other issuer is rejected at verification. The demo
// trusts the local MockPersonServer; override via `AAuth:TrustedPersonServers`.
var trustedPersonServers = new HashSet<string>(
    builder.Configuration.GetSection("AAuth:TrustedPersonServers").Get<string[]>()
        ?? new[] { "http://localhost:5100" });

// Access Server for the four-party (federated) flow. The resource issues a
// resource token whose `aud` is this AS (not the PS); the PS federates to the
// AS, which mints the auth token (iss = AS, dwk = aauth-access.json). The
// resource trusts the AS as the auth-token issuer for the /federated branch.
// Override via `AAuth:AccessServer`.
var accessServerUrl = builder.Configuration["AAuth:AccessServer"] ?? "http://localhost:5500";
var trustedAccessServers = new HashSet<string> { accessServerUrl };

builder.Services.AddSingleton(resourceKey);
builder.Services.AddSingleton(new AAuthVerifier
{
    MaxAge = TimeSpan.FromSeconds(signatureWindowSeconds),
});
builder.Services.AddSingleton<IJtiStore, InMemoryJtiStore>();
builder.Services.AddSingleton<MetadataClient>(sp =>
    new MetadataClient(sp.GetRequiredService<IHttpClientFactory>().CreateClient("aauth-metadata")));
builder.Services.AddSingleton<JwksClient>(sp =>
    new JwksClient(sp.GetRequiredService<IHttpClientFactory>().CreateClient("aauth-jwks")));
builder.Services.AddSingleton<ISignatureKeyResolver>(sp =>
    new DefaultSignatureKeyResolver(sp.GetRequiredService<JwksClient>()));
builder.Services.AddHttpClient("aauth-metadata");
builder.Services.AddHttpClient("aauth-jwks");

// -----------------------------------------------------------------------
// Layer 2: authentication scheme + authorization policies.
// The AAuth handler maps the verification result (written to Features by the
// verification middleware) into a ClaimsPrincipal, then scope/role/level
// policies enforce access per endpoint.
// -----------------------------------------------------------------------
builder.Services.AddAAuthAuthentication();
builder.Services.AddAAuthAuthorization();
builder.Services.AddAAuthScopePolicy("AAuth.Scope.whoami", ScopeWhoami);
builder.Services.AddAAuthScopePolicy("AAuth.Scope.whoami:admin", ScopeWhoamiAdmin);
builder.Services.AddAAuthRolePolicy("AAuth.Role.whoami-admin", RoleWhoamiAdmin);

var app = builder.Build();

// -----------------------------------------------------------------------
// Well-known endpoints: served BEFORE the verification middleware so the
// metadata document and JWKS are reachable without an AAuth signature.
// -----------------------------------------------------------------------
app.MapAAuthResourceWellKnown(new AAuthResourceMetadataOptions
{
    Issuer = resourceUrl,
    ClientName = "WhoAmI Demo",
    SigningKeys = new Dictionary<string, AAuthKey> { [ResourceKid] = resourceKey },
    ScopeDescriptions = new Dictionary<string, string>
    {
        [ScopeWhoami] = "See basic profile information",
        [ScopeWhoamiAdmin] = "See and manage administrative profile information",
    },
    SignatureWindow = signatureWindowSeconds,
});

// Verification options shared by the pseudonymous / identity flows (no issuer
// check — these schemes carry no auth-token issuer to verify).
static AAuthVerificationOptions SignatureOnly() => new()
{
    RequireIssuerVerification = false,
};

// Verification options for the three-party JWT flows (full issuer verification
// via JWKS discovery, audience bound to this resource).
AAuthVerificationOptions FullVerification() => new()
{
    ResourceIdentifier = resourceUrl,
    RequireIssuerVerification = true,
    TrustedAuthTokenIssuers = trustedPersonServers,
};

// Challenge options for a three-party endpoint requesting a specific scope.
// When only an agent token is presented, the middleware returns a 401 with a
// resource token (aud = agent token's `ps`) requesting `scope`.
ChallengeOptions ChallengeForScope(string scope) => new()
{
    AccessMode = AAuthAccessMode.RequireAuthToken,
    ResourceSigningKey = resourceKey,
    ResourceKeyId = ResourceKid,
    ResourceIdentifier = resourceUrl,
    DefaultScopes = scope,
};

// Verification options for the four-party (federated) flow. The auth token is
// issued by the AS (iss = AS, dwk = aauth-access.json), so the AS is the
// trusted auth-token issuer here — not the PS.
AAuthVerificationOptions FederatedVerification() => new()
{
    ResourceIdentifier = resourceUrl,
    RequireIssuerVerification = true,
    TrustedAuthTokenIssuers = trustedAccessServers,
};

// Challenge options for a four-party endpoint: the resource token's `aud` is
// the AS (via PersonServerAudience), which routes the PS to federate to the AS
// rather than asserting access itself.
ChallengeOptions ChallengeForFederated(string scope) => new()
{
    AccessMode = AAuthAccessMode.RequireAuthToken,
    ResourceSigningKey = resourceKey,
    ResourceKeyId = ResourceKid,
    ResourceIdentifier = resourceUrl,
    PersonServerAudience = accessServerUrl,
    DefaultScopes = scope,
};

// -----------------------------------------------------------------------
// Isolated verification pipelines — one branch per access mode. Each branch
// is self-contained: the most specific paths (/jwt/admin, /jwt/roles) are
// declared before the general /jwt branch so segment matching stays
// unambiguous without negative path matching.
// -----------------------------------------------------------------------

// /hwk — pseudonymous: HTTP signature only, no JWT issuer check.
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/hwk"),
    branch => branch.UseAAuthVerification(SignatureOnly()));

// /jkt-jwt — pseudonymous with key delegation via naming JWT.
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/jkt-jwt"),
    branch => branch.UseAAuthVerification(SignatureOnly()));

// /jwks-uri — agent identity: signature verified against published JWKS.
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/jwks-uri"),
    branch => branch.UseAAuthVerification(SignatureOnly()));

// /jwt/admin — three-party elevated: full verification + challenge for the
// elevated `whoami:admin` scope.
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/jwt/admin"),
    branch =>
    {
        branch.UseAAuthVerification(FullVerification());
        branch.UseAAuthChallenge(ChallengeForScope(ScopeWhoamiAdmin));
    });

// /jwt/roles — three-party RBAC: full verification + challenge for the base
// `whoami` scope; the role is enforced from the auth token's `roles` claim.
//
// DEPENDENCY: the challenge only asks the PS for the `whoami` scope — roles
// are asserted at the PS's discretion (the spec says a PS MAY assert roles).
// If a spec-compliant PS issues a `whoami` auth token WITHOUT the
// `whoami-admin` role, the role policy below returns an unrecoverable 403:
// there is no automatic step-up re-challenge (insufficient-scope/role
// step-up, spec G7, is out of scope for this sample). The mock PS asserts
// the role only for `aauth:demo@...` agents, so a non-admin agent
// deliberately hits that 403 path.
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/jwt/roles"),
    branch =>
    {
        branch.UseAAuthVerification(FullVerification());
        branch.UseAAuthChallenge(ChallengeForScope(ScopeWhoami));
    });

// /jwt — three-party baseline: full verification + challenge for `whoami`.
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/jwt")
        && !ctx.Request.Path.StartsWithSegments("/jwt/admin")
        && !ctx.Request.Path.StartsWithSegments("/jwt/roles"),
    branch =>
    {
        branch.UseAAuthVerification(FullVerification());
        branch.UseAAuthChallenge(ChallengeForScope(ScopeWhoami));
    });

// /federated — four-party baseline: the challenge issues a resource token with
// `aud` = the AS, the PS federates to the AS, and the AS-issued auth token
// (dwk = aauth-access.json) is verified against the AS's JWKS.
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/federated"),
    branch =>
    {
        branch.UseAAuthVerification(FederatedVerification());
        branch.UseAAuthChallenge(ChallengeForFederated(ScopeWhoami));
    });

// Layer 2 runs globally; per-endpoint policies decide what is required.
app.UseAuthentication();
app.UseAuthorization();

// -----------------------------------------------------------------------
// GET / — Flow index. No AAuth required; lists the isolated access modes.
// -----------------------------------------------------------------------
app.MapGet("/", () => Results.Ok(new
{
    resource = "WhoAmI Demo",
    flows = new[]
    {
        new { path = "/hwk", mode = "pseudonymous", auth = "signature only" },
        new { path = "/jkt-jwt", mode = "pseudonymous (key delegation)", auth = "signature only" },
        new { path = "/jwks-uri", mode = "agent-identity", auth = "AAuth.Identified" },
        new { path = "/jwt", mode = "three-party", auth = "AAuth.Scope.whoami" },
        new { path = "/jwt/admin", mode = "three-party (step-up)", auth = "AAuth.Scope.whoami:admin" },
        new { path = "/jwt/roles", mode = "three-party (RBAC)", auth = "AAuth.Role.whoami-admin" },
        new { path = "/federated", mode = "four-party", auth = "AAuth.Scope.whoami" },
    },
}));

// -----------------------------------------------------------------------
// GET /hwk — Pseudonymous access (no agent identity known).
// -----------------------------------------------------------------------
app.MapGet("/hwk", (HttpContext ctx) =>
{
    var parsed = ctx.GetAAuthParsedKey()!;

    return Results.Ok(new
    {
        mode = "pseudonymous",
        scheme = "hwk",
        jkt = parsed.Jkt,
        note = "Resource sees key thumbprint only — agent identity unknown.",
    });
});

// -----------------------------------------------------------------------
// GET /jkt-jwt — Pseudonymous access with key delegation.
// The naming JWT proves delegation from a hardware-backed durable key to
// an ephemeral signing key. The resource identifies the agent by the
// durable key's JWK thumbprint (jkt).
// -----------------------------------------------------------------------
app.MapGet("/jkt-jwt", (HttpContext ctx) =>
{
    var parsed = ctx.GetAAuthParsedKey()!;

    return Results.Ok(new
    {
        mode = "pseudonymous",
        scheme = "jkt-jwt",
        jkt = parsed.Jkt,
        note = "Delegation from hardware-backed key via naming JWT — agent known by durable key thumbprint.",
    });
});

// -----------------------------------------------------------------------
// GET /jwks-uri — Agent Identity access (agent's key verified via JWKS).
// Requires the Identified level policy: a verified agent identity.
// -----------------------------------------------------------------------
app.MapGet("/jwks-uri", (HttpContext ctx) =>
{
    var parsed = ctx.GetAAuthParsedKey()!;

    return Results.Ok(new
    {
        mode = "agent-identity",
        scheme = "jwks_uri",
        jwks_uri = parsed.JwksUri,
        kid = parsed.Kid,
        note = "Resource verified agent's key via JWKS URI — full cryptographic identity.",
    });
}).RequireAuthorization("AAuth.Identified");

// -----------------------------------------------------------------------
// GET /jwt — Three-party baseline access.
//
// The verification + challenge middleware have already:
//   - Verified the HTTP signature and JWT issuer signature (JWKS discovery)
//   - Verified cnf.jwk PoP binding, act.sub, and aud
//   - Challenged any agent token with a resource token for scope `whoami`
// The scope policy requires an Authorized auth token carrying `whoami`.
// -----------------------------------------------------------------------
app.MapGet("/jwt", (HttpContext ctx) =>
{
    var result = ctx.GetAAuthVerification()!;
    var parsed = ctx.GetAAuthParsedKey()!;

    return Results.Ok(new
    {
        mode = "three-party",
        scheme = "jwt",
        agent = result.Agent,
        sub = result.Subject,
        scope = result.Scopes,
        iss = result.Issuer,
        // The canonical user identity is the (iss, sub) pair: the same `sub`
        // asserted by a different Person Server is a different user.
        userKey = result.Issuer is null ? null : $"{result.Issuer}|{result.Subject}",
        act = parsed.Payload?["act"],
    });
}).RequireAuthorization("AAuth.Scope.whoami");

// -----------------------------------------------------------------------
// GET /jwt/admin — Three-party elevated access (step-up scope).
// Requires an auth token carrying the elevated `whoami:admin` scope.
// -----------------------------------------------------------------------
app.MapGet("/jwt/admin", (HttpContext ctx) =>
{
    var result = ctx.GetAAuthVerification()!;

    return Results.Ok(new
    {
        mode = "three-party",
        scheme = "jwt",
        access = "admin",
        agent = result.Agent,
        sub = result.Subject,
        scope = result.Scopes,
        iss = result.Issuer,
    });
}).RequireAuthorization("AAuth.Scope.whoami:admin");

// -----------------------------------------------------------------------
// GET /jwt/roles — Three-party RBAC access.
// Requires the `whoami-admin` role asserted by the PS in the auth token's
// `roles` claim (mapped to the standard ASP.NET role claim).
// -----------------------------------------------------------------------
app.MapGet("/jwt/roles", (HttpContext ctx) =>
{
    var result = ctx.GetAAuthVerification()!;

    return Results.Ok(new
    {
        mode = "three-party",
        scheme = "jwt",
        access = "rbac",
        agent = result.Agent,
        sub = result.Subject,
        roles = result.Roles,
        groups = result.Groups,
        iss = result.Issuer,
    });
}).RequireAuthorization("AAuth.Role.whoami-admin");

// -----------------------------------------------------------------------
// GET /federated — Four-party (federated) access.
//
// The verification + challenge middleware have already:
//   - Challenged any agent token with a resource token whose `aud` is the AS
//   - Verified the AS-issued auth token (iss = AS, dwk = aauth-access.json)
//     against the AS's JWKS, plus cnf.jwk PoP, act.sub, and aud
// The scope policy requires an Authorized auth token carrying `whoami`.
// -----------------------------------------------------------------------
app.MapGet("/federated", (HttpContext ctx) =>
{
    var result = ctx.GetAAuthVerification()!;
    var parsed = ctx.GetAAuthParsedKey()!;

    return Results.Ok(new
    {
        mode = "four-party",
        scheme = "jwt",
        agent = result.Agent,
        sub = result.Subject,
        scope = result.Scopes,
        // In four-party the auth-token issuer is the Access Server, not the PS.
        iss = result.Issuer,
        userKey = result.Issuer is null ? null : $"{result.Issuer}|{result.Subject}",
        act = parsed.Payload?["act"],
    });
}).RequireAuthorization("AAuth.Scope.whoami");

app.Run();

// Marker type for `WebApplicationFactory<WhoAmI.Entry>` in the
// integration tests. Avoids the ambiguity between the implicit `Program`
// type emitted by top-level statements in this sample and the one emitted
// by the `MockPersonServer` sample when both are referenced from a single
// test assembly.
namespace WhoAmI
{
    /// <summary>Marker type for <c>WebApplicationFactory&lt;T&gt;</c>.</summary>
    public sealed class Entry
    {
        private Entry() { }
    }
}
