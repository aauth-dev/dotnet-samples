using AAuth.Crypto;
using AAuth;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.CallChaining;
using AAuth.Server.Challenge;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
using GuidedTour;
using GuidedTour.Components;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.Configure<TourOptions>(builder.Configuration.GetSection("GuidedTour"));

// Self-issued agent identity: the GuidedTour server is a hosted service, so
// it acts as its own AP for non-Bootstrap flows (spec §Self-Hosted Agents).
// The key is shared across sessions so the well-known JWKS stays in sync.
var tourKey = AAuthKey.Generate();
const string TourKid = "tour";
var tourUrl = builder.Configuration["GuidedTour:SelfIssuer"] ?? "http://localhost:5400";
builder.Services.AddSingleton(new TourAgentIdentity(tourKey, TourKid, tourUrl));

builder.Services.AddScoped<TourSession>();

var app = builder.Build();

// Publish agent metadata + JWKS so verifiers (the Aria resource servers, Concierge) can
// discover the tour's signing key when it self-issues agent tokens.
app.MapAAuthAgentWellKnown(new AAuthAgentMetadataOptions
{
    Issuer = tourUrl,
    ClientName = "Guided Tour Demo",
    SigningKeys = new Dictionary<string, AAuthKey> { [TourKid] = tourKey },
});

app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();

namespace GuidedTour
{
    /// <summary>Marker type for <c>WebApplicationFactory</c>-based tests.</summary>
    public sealed class Entry { private Entry() { } }

    /// <summary>
    /// Shared self-issued agent identity for non-Bootstrap flows.
    /// Registered as singleton so the JWKS endpoint and TourSession stay in sync.
    /// </summary>
    public sealed record TourAgentIdentity(AAuthKey Key, string KeyId, string Issuer);
}
