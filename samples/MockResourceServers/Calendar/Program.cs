using AAuth.Crypto;
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

// One DI call: verifier, discovery clients (pooled handler), JTI store, and the
// published metadata — no manual HttpClient/discovery wiring.
builder.Services.AddAAuthResource(o =>
{
    o.Issuer = resourceUrl;
    o.SigningKeys[ResourceKid] = resourceKey;
    o.MaxSignatureAge = TimeSpan.FromSeconds(signatureWindowSeconds);
    o.SignatureWindow = signatureWindowSeconds;
    o.Name = "Aria Calendar";
    o.ScopeDescriptions = new Dictionary<string, string>
    {
        [ScopeRead] = "See your calendar events",
        [ScopeWrite] = "Add and change calendar events",
    };
});
builder.Services.AddAAuthAuthentication();
builder.Services.AddAAuthAuthorization();

var app = builder.Build();

// Well-known metadata + JWKS from the DI-registered resource metadata.
app.MapAAuthWellKnown();

// One declarative pipeline: per-route scope/role lives on the endpoint
// (.RequireAAuth(...)); this single post-routing middleware verifies and
// challenges each matched endpoint from its metadata. Trust only the configured
// Person Servers (fail-closed).
app.UseRouting();
app.UseAAuth(o => o.TrustedAuthTokenIssuers = trustedPersonServers);

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
}).RequireAAuth(scope: ScopeRead);

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
}).RequireAAuth(scope: ScopeWrite);

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
}).RequireAAuth(scope: ScopeRead, role: RoleOwner);

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
