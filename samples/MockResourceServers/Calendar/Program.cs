using AAuth.Crypto;
using AAuth;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.Challenge;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;

// ---------------------------------------------------------------------------
// Calendar — Aria's core user-data resource server (PS-Asserted / three-party).
//
// The Calendar service holds the traveller's events. Aria must present a
// person-scoped auth token (issued by the user's Person Server) to read or
// change them. This is the three-party flow: the resource challenges an agent
// token with a resource token (aud = PS), the agent exchanges it at the PS for
// an auth token, and the resource verifies that token's issuer via JWKS.
//
//   PATH            SCOPE / ROLE            DEMONSTRATES
//   /events         calendar.read           baseline three-party read
//   /events/write   calendar.write          step-up scope (a second consent)
//   /events/admin   role calendar.owner     RBAC by a PS-asserted role
//
// /events/admin enforces a role the PS asserts in the auth token's `roles`
// claim. If the PS issues a token WITHOUT that role, the policy returns an
// unrecoverable 403 — there is no automatic step-up re-challenge in this sample.
// ---------------------------------------------------------------------------

var builder = WebApplication.CreateBuilder(args);

var resourceKey = AAuthKey.Generate();
const string ResourceKid = "calendar-1";

// Scope + role taxonomy this resource recognises.
const string ScopeRead = "calendar.read";
const string ScopeWrite = "calendar.write";
const string RoleOwner = "calendar.owner";

var resourceUrl = builder.Configuration["AAuth:Issuer"] ?? "http://localhost:5001";
var signatureWindowSeconds = builder.Configuration.GetValue<int?>("AAuth:SignatureWindow") ?? 60;

// Person Server(s) this resource trusts to assert user identity. Fail-closed:
// an auth token from any other issuer is rejected at verification.
var trustedPersonServers = new HashSet<string>(
    builder.Configuration.GetSection("AAuth:TrustedPersonServers").Get<string[]>()
        ?? new[] { "http://localhost:5100" });

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

builder.Services.AddAAuthAuthentication();
builder.Services.AddAAuthAuthorization();
builder.Services.AddAAuthScopePolicy("AAuth.Scope.calendar.read", ScopeRead);
builder.Services.AddAAuthScopePolicy("AAuth.Scope.calendar.write", ScopeWrite);
builder.Services.AddAAuthRolePolicy("AAuth.Role.calendar.owner", RoleOwner);

var app = builder.Build();

app.MapAAuthResourceWellKnown(new AAuthResourceMetadataOptions
{
    Issuer = resourceUrl,
    Name = "Aria Calendar",
    SigningKeys = new Dictionary<string, AAuthKey> { [ResourceKid] = resourceKey },
    ScopeDescriptions = new Dictionary<string, string>
    {
        [ScopeRead] = "See your calendar events",
        [ScopeWrite] = "Add and change calendar events",
    },
    SignatureWindow = signatureWindowSeconds,
});

// Full issuer verification: discover the auth-token issuer's JWKS, bind `aud`
// to this resource, and trust only the configured Person Servers.
AAuthVerificationOptions FullVerification() => new()
{
    ResourceIdentifier = resourceUrl,
    RequireIssuerVerification = true,
    TrustedAuthTokenIssuers = trustedPersonServers,
};

// Challenge options requesting a specific scope. When only an agent token is
// presented, the middleware returns a 401 with a resource token (aud = the
// agent token's `ps`) requesting `scope`.
ChallengeOptions ChallengeForScope(string scope) => new()
{
    AccessMode = AAuthAccessMode.RequireAuthToken,
    ResourceSigningKey = resourceKey,
    ResourceKeyId = ResourceKid,
    ResourceIdentifier = resourceUrl,
    DefaultScopes = scope,
};

// Isolated pipelines. Declare the more specific /events/write and /events/admin
// before the general /events so segment matching stays unambiguous.
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/events/write"),
    branch =>
    {
        branch.UseAAuthVerification(FullVerification());
        branch.UseAAuthChallenge(ChallengeForScope(ScopeWrite));
    });
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/events/admin"),
    branch =>
    {
        branch.UseAAuthVerification(FullVerification());
        // The role is enforced from the auth token's `roles` claim; the
        // challenge only requests the base read scope.
        branch.UseAAuthChallenge(ChallengeForScope(ScopeRead));
    });
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/events")
        && !ctx.Request.Path.StartsWithSegments("/events/write")
        && !ctx.Request.Path.StartsWithSegments("/events/admin"),
    branch =>
    {
        branch.UseAAuthVerification(FullVerification());
        branch.UseAAuthChallenge(ChallengeForScope(ScopeRead));
    });

app.UseAuthentication();
app.UseAuthorization();

// GET / — Flow index. No AAuth required.
app.MapGet("/", () => Results.Ok(new
{
    resource = "Aria Calendar",
    accessMode = "three-party",
    flows = new[]
    {
        new { path = "/events", auth = "AAuth.Scope.calendar.read" },
        new { path = "/events/write", auth = "AAuth.Scope.calendar.write" },
        new { path = "/events/admin", auth = "AAuth.Role.calendar.owner" },
    },
}));

// GET /events — three-party baseline read. Requires an auth token carrying
// `calendar.read`.
app.MapGet("/events", (HttpContext ctx) =>
{
    var result = ctx.GetAAuthVerification()!;
    var parsed = ctx.GetAAuthParsedKey()!;

    return Results.Ok(new
    {
        accessMode = "three-party",
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
}).RequireAuthorization("AAuth.Scope.calendar.read");

// GET /events/write — step-up scope. Requires the elevated `calendar.write`.
app.MapGet("/events/write", (HttpContext ctx) =>
{
    var result = ctx.GetAAuthVerification()!;

    return Results.Ok(new
    {
        accessMode = "three-party",
        scheme = "jwt",
        access = "write",
        agent = result.Agent,
        sub = result.Subject,
        scope = result.Scopes,
        iss = result.Issuer,
    });
}).RequireAuthorization("AAuth.Scope.calendar.write");

// GET /events/admin — RBAC. Requires the `calendar.owner` role asserted by the
// PS in the auth token's `roles` claim (mapped to the ASP.NET role claim).
app.MapGet("/events/admin", (HttpContext ctx) =>
{
    var result = ctx.GetAAuthVerification()!;

    return Results.Ok(new
    {
        accessMode = "three-party",
        scheme = "jwt",
        access = "admin",
        agent = result.Agent,
        sub = result.Subject,
        roles = result.Roles,
        groups = result.Groups,
        iss = result.Issuer,
    });
}).RequireAuthorization("AAuth.Role.calendar.owner");

app.Run();

// Marker type for `WebApplicationFactory<Calendar.Entry>` in integration tests.
namespace Calendar
{
    /// <summary>Marker type for <c>WebApplicationFactory&lt;T&gt;</c>.</summary>
    public sealed class Entry
    {
        private Entry() { }
    }
}
