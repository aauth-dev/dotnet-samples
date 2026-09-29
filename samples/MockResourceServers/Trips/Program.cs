using AAuth;
using AAuth.Crypto;
using AAuth.Server.Verification;

// ---------------------------------------------------------------------------
// Trips — Aria's mission-governed resource server (three-party, mission-aware).
//
// The Trips service lets Aria plan and book travel. It is *mission-aware*: the
// agent's person token names the mission as mission_s256, the resource token it
// issues copies it, so the agent's Person Server can govern the exchange
// against the human-approved mission.
//
//   PATH          SCOPE          DEMONSTRATES
//   /trips        trips.read      in-mission scope — granted silently when the
//                                 mission's intent covers reading trips
//   /trips/book   trips.book      out-of-mission scope — falls outside the
//                                 mission intent, so the PS must PROMPT the user
//                                 before issuing the auth token
//
// The contrast between /trips (silent) and /trips/book (prompt) is the whole
// point: it shows how a mission's approved scope gates which exchanges are
// silent versus which require a fresh consent.
// ---------------------------------------------------------------------------

var builder = WebApplication.CreateBuilder(args);

var resourceKey = AAuthKey.Generate();
const string ResourceKid = "trips-1";

const string ScopeRead = "trips.read";
const string ScopeBook = "trips.book";

var resourceUrl = builder.Configuration["AAuth:Issuer"] ?? "http://localhost:5002";
var signatureWindowSeconds = builder.Configuration.GetValue<int?>("AAuth:SignatureWindow") ?? 60;

var trustedPersonServers = new HashSet<string>(
    builder.Configuration.GetSection("AAuth:TrustedPersonServers").Get<string[]>()
        ?? new[] { "http://localhost:5100" });

// One DI call: verifier, discovery clients (pooled handler), JTI store, and the
// published metadata — no manual HttpClient/discovery wiring.
builder.Services.AddAAuthResource(o =>
{
    o.EgressPolicy = SampleEgress.Policy;
    o.Issuer = resourceUrl;
    o.RevocationEndpoint = $"{resourceUrl}/revoke";
    o.SigningKeys[ResourceKid] = resourceKey;
    o.MaxSignatureAge = TimeSpan.FromSeconds(signatureWindowSeconds);
    o.SignatureWindow = signatureWindowSeconds;
    o.Name = "Aria Trips";
    o.Description = "**Aria Trips** books travel and manages itineraries on your behalf.";
    o.AccessMode = AAuthConstants.AccessModes.AuthToken;
    o.ScopeDescriptions = new Dictionary<string, string>
    {
        [ScopeRead] = "See your trips and itineraries",
        [ScopeBook] = "Book travel on your behalf",
    };
});
builder.Services.AddAAuthAuthentication();
builder.Services.AddAAuthAuthorization();

var app = builder.Build();

// Well-known metadata + JWKS from the DI-registered resource metadata.
app.MapAAuthWellKnown();
// Revocations are keyed by (verified caller, jti); only the trusted PSes issue
// the tokens this resource accepts, so only they may revoke here.
AAuth.Server.RevocationEndpoint.MapAAuthRevocationEndpoint(app,
    app.Services.GetRequiredService<AAuth.Server.IJtiStore>(), options =>
        options.IsAcceptedIssuer = trustedPersonServers.Contains);

// One declarative pipeline. Mission-aware: the issued resource token copies the
// presented person token's mission_s256, so the PS governs the exchange. Trust
// only the configured Person Servers.
app.UseRouting();
app.UseAAuth(o => o.Trust.AuthTokenIssuers.Allowed = trustedPersonServers);

app.UseAuthentication();
app.UseAuthorization();

// GET / — Flow index. No AAuth required.
app.MapGet("/", () => Results.Ok(new
{
    resource = "Aria Trips",
    accessMode = "three-party (mission-aware)",
    flows = new[]
    {
        new { path = "/trips", auth = "AAuth.Scope.trips.read" },
        new { path = "/trips/book", auth = "AAuth.Scope.trips.book" },
    },
}));

// GET /trips — mission-aware read. With a mission, the issued resource token
// carries mission_s256 and the PS governs the exchange; the resulting auth
// token carries it back, surfaced here. An agent without a mission still gets
// baseline `trips.read` access (mission_s256 = null).
app.MapGet("/trips", (HttpContext ctx) =>
{
    var result = ctx.GetAAuthVerification()!;

    return Results.Ok(new
    {
        accessMode = "three-party",
        scheme = "jwt",
        access = "mission",
        ps = result.PersonServer,
        sub = result.Subject,
        scope = result.Scopes,
        iss = result.Issuer,
        mission_s256 = result.MissionS256,
    });
}).RequireAAuth(scope: ScopeRead);

// GET /trips/book — out-of-mission elevated scope. Identical mission mechanics,
// but it requires `trips.book`. When the agent operates under a mission whose
// intent does not cover booking, the PS cannot silently approve and must prompt
// the user before issuing the auth token.
app.MapGet("/trips/book", (HttpContext ctx) =>
{
    var result = ctx.GetAAuthVerification()!;

    return Results.Ok(new
    {
        accessMode = "three-party",
        scheme = "jwt",
        access = "mission-elevated",
        ps = result.PersonServer,
        sub = result.Subject,
        scope = result.Scopes,
        iss = result.Issuer,
        mission_s256 = result.MissionS256,
    });
}).RequireAAuth(scope: ScopeBook);

app.Run();

// Marker type for `WebApplicationFactory<Trips.Entry>` in integration tests.
namespace Trips
{
    /// <summary>Marker type for <c>WebApplicationFactory&lt;T&gt;</c>.</summary>
    public sealed class Entry
    {
        private Entry() { }
    }
}
