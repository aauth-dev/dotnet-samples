using AAuth.Crypto;
using AAuth;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.CallChaining;
using AAuth.Server.Challenge;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
using SampleApp;
using SampleApp.Components;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Register enrollment as a singleton — needed only by the JWKS URI page
// which demos AP-issued identity verified via the AP's JWKS endpoint.
builder.Services.AddSingleton<EnrollmentService>();

// -----------------------------------------------------------------------
// Self-issued agent identity: SampleApp is a hosted service with a stable
// URL, so it is its own AP (spec §Self-Hosted Agents). The signing key and
// metadata are used by JWT, Deferred, and CallChain pages.
// -----------------------------------------------------------------------
var selfIssuedKey = AAuthKey.Generate();
const string SelfIssuedKid = "sample-app-1";
var sampleAppUrl = builder.Configuration["AAuth:SelfIssuer"] ?? "http://localhost:5240";
var sampleAppAgentId = builder.Configuration["AAuth:SelfAgentId"] ?? "aauth:sample-app@localhost";
builder.Services.AddSingleton(new SelfIssuedIdentity(selfIssuedKey, SelfIssuedKid, sampleAppUrl, sampleAppAgentId));
// Resource metadata for the federated-worker scenario, published by MapAAuthWellKnown.
builder.Services.AddAAuthResource(options =>
{
    options.EgressPolicy = SampleEgress.Policy;
    options.Issuer = sampleAppUrl;
    options.SigningKeys[SelfIssuedKid] = selfIssuedKey;
    options.ScopeDescriptions = new(FederatedWorkerScenario.ScopeDescriptions);
});

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
}

// Publish agent metadata + JWKS so verifiers can discover our signing key.
app.MapAAuthAgentWellKnown(options =>
{
    options.EgressPolicy = SampleEgress.Policy;
    options.Issuer = sampleAppUrl;
    options.Name = "SampleApp Demo";
    options.SigningKeys = new AAuthSigningKeySet { [SelfIssuedKid] = selfIssuedKey };
});

app.UseAntiforgery();
app.MapAAuthWellKnown();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
