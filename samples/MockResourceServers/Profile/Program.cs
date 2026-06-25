using AAuth.Crypto;
using AAuth;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;

// ---------------------------------------------------------------------------
// Profile — Aria's identity-based resource server (Identity-Based access mode).
//
// The Profile service is where Aria (the AI travel assistant) reads who the
// caller is, with NO Person Server involved. The resource decides access from
// the signature alone, so every endpoint here is "signature only" (no JWT
// issuer verification, no scope). The three endpoints differ only in HOW the
// agent presents its key — i.e. the RFC 9421 Signature-Key *scheme*:
//
//   PATH            SCHEME      WHAT THE RESOURCE LEARNS
//   /pseudonymous   hwk         a key thumbprint only — caller is a pseudonym
//   /identified     jwks_uri    a named, verifiable agent identity (via JWKS)
//   /anchored       jkt-jwt     a durable key's thumbprint, via a self-issued
//                               naming JWT delegating to an ephemeral key
//                               (self-anchored, draft-05 §3.4)
//
// The path names describe the *outcome* (what the resource concludes); the
// scheme identifiers (hwk / jwks_uri / jkt-jwt) are the unchanged protocol
// names from the Signature-Key header.
// ---------------------------------------------------------------------------

var builder = WebApplication.CreateBuilder(args);

// The resource is "self-issued" for the sample: a freshly generated key on
// startup, served via /.well-known/jwks.json. A production resource would load
// a stable key from secure storage.
var resourceKey = AAuthKey.Generate();
const string ResourceKid = "profile-1";

var resourceUrl = builder.Configuration["AAuth:Issuer"] ?? "http://localhost:5000";
var signatureWindowSeconds = builder.Configuration.GetValue<int?>("AAuth:SignatureWindow") ?? 60;

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

// Authentication scheme + the Identified policy (a verified agent identity).
builder.Services.AddAAuthAuthentication();
builder.Services.AddAAuthAuthorization();

var app = builder.Build();

// Well-known endpoints: served BEFORE verification so metadata + JWKS are
// reachable without an AAuth signature.
app.MapAAuthResourceWellKnown(new AAuthResourceMetadataOptions
{
    Issuer = resourceUrl,
    Name = "Aria Profile",
    SigningKeys = new Dictionary<string, AAuthKey> { [ResourceKid] = resourceKey },
    SignatureWindow = signatureWindowSeconds,
});

// Identity-based verification: HTTP signature only, no JWT issuer check (these
// schemes carry no auth-token issuer to verify).
static AAuthVerificationOptions SignatureOnly() => new()
{
    RequireIssuerVerification = false,
};

// One isolated verification pipeline per path — no prefix disambiguation needed
// because each path is a distinct first segment.
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/pseudonymous"),
    branch => branch.UseAAuthVerification(SignatureOnly()));
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/identified"),
    branch => branch.UseAAuthVerification(SignatureOnly()));
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/anchored"),
    branch => branch.UseAAuthVerification(SignatureOnly()));

app.UseAuthentication();
app.UseAuthorization();

// GET / — Flow index. No AAuth required; lists the identity flows.
app.MapGet("/", () => Results.Ok(new
{
    resource = "Aria Profile",
    accessMode = "identity-based",
    flows = new[]
    {
        new { path = "/pseudonymous", scheme = "hwk", auth = "signature only" },
        new { path = "/identified", scheme = "jwks_uri", auth = "AAuth.Identified" },
        new { path = "/anchored", scheme = "jkt-jwt", auth = "signature only" },
    },
}));

// GET /pseudonymous — scheme=hwk. Pseudonymous access: the agent presents an
// inline public key, so the resource sees only its thumbprint (jkt). Identity
// is unknown — useful for accountable, rate-limited access by key.
app.MapGet("/pseudonymous", (HttpContext ctx) =>
{
    var parsed = ctx.GetAAuthParsedKey()!;

    return Results.Ok(new
    {
        signingMode = "pseudonymous",
        scheme = "hwk",
        jkt = parsed.Jkt,
        note = "Resource sees key thumbprint only — agent identity unknown.",
    });
});

// GET /identified — scheme=jwks_uri. Agent-identity access: the resource fetches
// the agent's public key from its published JWKS URI and learns a named,
// verifiable identity. Requires the Identified policy.
app.MapGet("/identified", (HttpContext ctx) =>
{
    var parsed = ctx.GetAAuthParsedKey()!;

    return Results.Ok(new
    {
        signingMode = "agent-identity",
        scheme = "jwks_uri",
        jwks_uri = parsed.JwksUri,
        kid = parsed.Kid,
        note = "Resource verified agent's key via JWKS URI — full cryptographic identity.",
    });
}).RequireAuthorization("AAuth.Identified");

// GET /anchored — scheme=jkt-jwt. Key-rotation access: a naming JWT (signed by
// the agent's durable enrollment key) names an ephemeral signing key. The
// resource identifies the agent by the durable key's thumbprint (jkt), so the
// agent can rotate its signing key without re-enrolling.
app.MapGet("/anchored", (HttpContext ctx) =>
{
    var parsed = ctx.GetAAuthParsedKey()!;

    return Results.Ok(new
    {
        // Per spec, jkt-jwt yields PSEUDONYMOUS access: the resource learns only
        // the durable key's thumbprint, not a named identity (§Signing Modes —
        // "scheme=jkt-jwt (delegation from a hardware-backed key)" maps to the
        // pseudonym identity type). The `/anchored` path name describes the key
        // mechanism; the `signingMode` reflects the spec identity type.
        signingMode = "pseudonymous",
        scheme = "jkt-jwt",
        jkt = parsed.Jkt,
        note = "Ephemeral key anchored to a durable enrollment key via naming JWT — agent known by durable key thumbprint.",
    });
});

app.Run();

// Marker type for `WebApplicationFactory<Profile.Entry>` in integration tests.
namespace Profile
{
    /// <summary>Marker type for <c>WebApplicationFactory&lt;T&gt;</c>.</summary>
    public sealed class Entry
    {
        private Entry() { }
    }
}
