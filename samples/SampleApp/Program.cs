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
// Walkthrough agents are created per session; each owns its signed client and typed clients.
builder.Services.AddAAuthAgentFactory();

// -----------------------------------------------------------------------
// Aria, the self-issued agent: SampleApp is a hosted service with a stable
// URL, so it is its own AP (spec §Self-Hosted Agents). Its identity, Person
// Server and polling budgets bind from AAuth:Agents:aria; the key is
// generated here. Pages resolve the agent by name and never build clients.
// -----------------------------------------------------------------------
var selfIssuedKey = AAuthKey.Generate();
var aria = builder.Configuration.GetSection("AAuth:Agents:" + SampleAgents.Aria);
var selfIssuedKid = aria["SelfIssued:KeyId"]!;
var sampleAppUrl = aria["SelfIssued:Issuer"]!;
var sampleAppAgentId = aria["SelfIssued:Subject"]!;
builder.Services.AddSingleton(new SelfIssuedIdentity(selfIssuedKey, selfIssuedKid, sampleAppUrl, sampleAppAgentId));
builder.Services.AddAAuthAgent(SampleAgents.Aria, aria, options =>
{
    options.Signer = selfIssuedKey;
    options.EgressPolicy = SampleEgress.Policy;
});
builder.Services.AddSingleton<SampleAgents>();
// Resource metadata for the federated-worker scenario, published by MapAAuthWellKnown.
builder.Services.AddAAuthResource(options =>
{
    options.EgressPolicy = SampleEgress.Policy;
    options.Issuer = sampleAppUrl;
    options.SigningKeys[selfIssuedKid] = selfIssuedKey;
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
    options.SigningKeys = new AAuthSigningKeySet { [selfIssuedKid] = selfIssuedKey };
});

app.UseAntiforgery();
app.MapAAuthWellKnown();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
