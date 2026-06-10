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
// Trips — Aria's mission-governed resource server (three-party, mission-aware).
//
// The Trips service lets Aria plan and book travel. It is *mission-aware*: when
// the agent sends a signed AAuth-Mission header, the resource token it issues
// carries the mission object (approver + s256), so the agent's Person Server
// can govern the exchange against the human-approved mission.
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
builder.Services.AddAAuthScopePolicy("AAuth.Scope.trips.read", ScopeRead);
builder.Services.AddAAuthScopePolicy("AAuth.Scope.trips.book", ScopeBook);

var app = builder.Build();

app.MapAAuthResourceWellKnown(new AAuthResourceMetadataOptions
{
    Issuer = resourceUrl,
    ClientName = "Aria Trips",
    Description = "**Aria Trips** books travel and manages itineraries on your behalf.",
    AccessMode = AAuthConstants.AccessModes.AuthToken,
    SigningKeys = new Dictionary<string, AAuthKey> { [ResourceKid] = resourceKey },
    ScopeDescriptions = new Dictionary<string, string>
    {
        [ScopeRead] = "See your trips and itineraries",
        [ScopeBook] = "Book travel on your behalf",
    },
    SignatureWindow = signatureWindowSeconds,
});

AAuthVerificationOptions FullVerification() => new()
{
    ResourceIdentifier = resourceUrl,
    RequireIssuerVerification = true,
    TrustedAuthTokenIssuers = trustedPersonServers,
};

// Mission-aware challenge: when the agent sends a signed AAuth-Mission header,
// the issued resource token carries the mission object (approver + s256), so
// the agent's PS governs the token exchange against that mission.
ChallengeOptions ChallengeForMission(string scope) => new()
{
    AccessMode = AAuthAccessMode.RequireAuthToken,
    ResourceSigningKey = resourceKey,
    ResourceKeyId = ResourceKid,
    ResourceIdentifier = resourceUrl,
    DefaultScopes = scope,
    MissionAware = true,
};

// Declare the more specific /trips/book before the general /trips.
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/trips/book"),
    branch =>
    {
        branch.UseAAuthVerification(FullVerification());
        branch.UseAAuthChallenge(ChallengeForMission(ScopeBook));
    });
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/trips")
        && !ctx.Request.Path.StartsWithSegments("/trips/book"),
    branch =>
    {
        branch.UseAAuthVerification(FullVerification());
        branch.UseAAuthChallenge(ChallengeForMission(ScopeRead));
    });

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
// carries the mission object and the PS governs the exchange; the resulting
// auth token echoes the mission claim back, surfaced here. An agent without a
// mission still gets baseline `trips.read` access (mission = null).
app.MapGet("/trips", (HttpContext ctx) =>
{
    var result = ctx.GetAAuthVerification()!;
    var parsed = ctx.GetAAuthParsedKey()!;
    var mission = parsed.Payload?["mission"];

    return Results.Ok(new
    {
        accessMode = "three-party",
        scheme = "jwt",
        access = "mission",
        agent = result.Agent,
        sub = result.Subject,
        scope = result.Scopes,
        iss = result.Issuer,
        mission,
        missionAware = true,
        act = parsed.Payload?["act"],
    });
}).RequireAuthorization("AAuth.Scope.trips.read");

// GET /trips/book — out-of-mission elevated scope. Identical mission mechanics,
// but it requires `trips.book`. When the agent operates under a mission whose
// intent does not cover booking, the PS cannot silently approve and must prompt
// the user before issuing the auth token.
app.MapGet("/trips/book", (HttpContext ctx) =>
{
    var result = ctx.GetAAuthVerification()!;
    var parsed = ctx.GetAAuthParsedKey()!;
    var mission = parsed.Payload?["mission"];

    return Results.Ok(new
    {
        accessMode = "three-party",
        scheme = "jwt",
        access = "mission-elevated",
        agent = result.Agent,
        sub = result.Subject,
        scope = result.Scopes,
        iss = result.Issuer,
        mission,
        missionAware = true,
        act = parsed.Payload?["act"],
    });
}).RequireAuthorization("AAuth.Scope.trips.book");

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
