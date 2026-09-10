using AAuth.Crypto;
using AAuth.Server.Verification;

// ---------------------------------------------------------------------------
// Profile: Aria's Generic Signature Keys demonstration resource.
//
// The Profile service is where Aria (the AI travel assistant) reads who the
// caller is, with no PS/AS authorization exchange. Routes explicitly admit
// generic signing schemes without an auth-token or scope requirement.
// JWT issuer verification still applies when an agent JWT is presented;
// naming JWTs verify their durable-key delegation. The endpoints illustrate
// different Signature-Key schemes:
//
//   PATH            SCHEME      WHAT THE RESOURCE LEARNS
//   /pseudonymous   hwk         a key thumbprint only — caller is a pseudonym
//   /identified     jwks/jwks_uri/jwt  a verified key-discovery or agent identity
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
    o.Name = "Aria Profile";
});
builder.Services.AddAAuthAuthentication();
builder.Services.AddAAuthAuthorization();

var app = builder.Build();

// Well-known metadata + JWKS from the DI-registered resource metadata.
app.MapAAuthWellKnown();
AAuth.Server.RevocationEndpoint.MapAAuthRevocationEndpoint(app,
    app.Services.GetRequiredService<AAuth.Server.IJtiStore>(), options => options.AllowTokenIssuer = true);

// Each protected endpoint declares RequireGenericSignature admission.
// The pipeline verifies HTTP proof and any JWT assertion without starting
// a PS/AS authorization exchange.
app.UseRouting();
app.UseAAuth();

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
        new { path = "/identified", scheme = "jwks", auth = "AAuth.Identified" },
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
}).RequireGenericSignature();

// GET /identified: admitted key discovery or a verified agent JWT.
// Generic discovery identifies the verified server/key URL; an agent JWT
// additionally attests the agent identifier and its confirmation key.
app.MapGet("/identified", (HttpContext ctx) =>
{
    var parsed = ctx.GetAAuthParsedKey()!;
    var verified = ctx.GetAAuthVerification()!;

    return Results.Ok(new
    {
        signingMode = "agent-identity",
        scheme = parsed.Scheme,
        identifier = parsed.Scheme == "jwt" ? verified.Agent : parsed.Identifier,
        jwks_uri = parsed.JwksUri,
        kid = parsed.Kid,
        note = parsed.Scheme == "jwt"
            ? "Verified agent JWT and confirmation-key HTTP proof; no PS/AS authorization exchange."
            : "Generic Signature Keys identity from admitted key discovery; not an AAuth resource access mode.",
    });
}).RequireGenericSignature(identified: true);

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
}).RequireGenericSignature();

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
