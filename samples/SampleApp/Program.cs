using AAuth.DependencyInjection;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server;
using SampleApp;
using SampleApp.Components;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Register enrollment as a singleton — it runs once (like a provisioning step)
// and caches the key + metadata for the app's lifetime.
builder.Services.AddSingleton<EnrollmentService>();
builder.Services.AddHttpClient();

// AAuth server-side services for the mini resource endpoint demo.
builder.Services.AddSingleton(new AAuthVerifier());
builder.Services.AddSingleton(sp =>
    new MetadataClient(sp.GetRequiredService<IHttpClientFactory>().CreateClient()));
builder.Services.AddSingleton(sp =>
    new JwksClient(sp.GetRequiredService<IHttpClientFactory>().CreateClient()));

// ASP.NET Core authorization policies for scope-based access control.
builder.Services.AddAuthorization();
builder.Services.AddAAuthAuthorization();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
}

app.UseAntiforgery();

// AAuth verification + challenge middleware for the /api/* resource endpoints.
// These run before authorization so the AAuthVerificationResult is available
// in HttpContext.Features for the authentication handler.
app.UseWhen(ctx => ctx.Request.Path.StartsWithSegments("/api"), branch =>
{
    branch.UseAAuthFullVerification(new FullVerificationOptions
    {
        ResourceIdentifier = builder.Configuration["AAuth:ResourceId"] ?? "http://localhost:5010",
        RequireIssuerVerification = false, // demo mode: skip JWKS fetch
    });
    branch.UseAAuthChallenge(new ChallengeOptions
    {
        AccessMode = AAuthAccessMode.RequireAuthToken,
    });
});

app.UseAuthorization();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

// Mini resource endpoints demonstrating server-side AAuth features.
app.MapResourceEndpoints();

app.Run();
