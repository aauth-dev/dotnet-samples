using System.Text.Json.Nodes;
using AAuth;
using AAuth.Crypto;
using AAuth.DependencyInjection;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Tokens;

var builder = WebApplication.CreateBuilder(args);

// -----------------------------------------------------------------------
// Configure the resource's own signing key and identity.
// -----------------------------------------------------------------------
// The resource is "self-issued" for the sample: a freshly generated key on
// startup, served via /.well-known/jwks.json. A production resource would
// load a stable key from secure storage.
var resourceKey = AAuthKey.Generate();
const string ResourceKid = "whoami-1";
const string ResourceScope = "whoami";
var resourceUrl = builder.Configuration["AAuth:Issuer"] ?? "http://localhost:5000";
var signatureWindowSeconds = builder.Configuration.GetValue<int?>("AAuth:SignatureWindow") ?? 60;

builder.Services.AddSingleton(resourceKey);
builder.Services.AddSingleton(new AAuthVerifier
{
    MaxAge = TimeSpan.FromSeconds(signatureWindowSeconds),
});
builder.Services.AddSingleton(new TokenVerifier());
builder.Services.AddSingleton<IJtiStore, InMemoryJtiStore>();
builder.Services.AddSingleton<MetadataClient>(sp =>
    new MetadataClient(sp.GetRequiredService<IHttpClientFactory>().CreateClient("aauth-metadata")));
builder.Services.AddSingleton<JwksClient>(sp =>
    new JwksClient(sp.GetRequiredService<IHttpClientFactory>().CreateClient("aauth-jwks")));
builder.Services.AddSingleton<ISignatureKeyResolver>(sp =>
    new DefaultSignatureKeyResolver(sp.GetRequiredService<JwksClient>()));
builder.Services.AddHttpClient("aauth-metadata");
builder.Services.AddHttpClient("aauth-jwks");

var app = builder.Build();

// -----------------------------------------------------------------------
// Well-known endpoints: served BEFORE the verification middleware so the
// metadata document and JWKS are reachable without an AAuth signature.
// -----------------------------------------------------------------------
app.MapAAuthResourceWellKnown(new AAuthResourceMetadataOptions
{
    Issuer = resourceUrl,
    ClientName = "WhoAmI Demo",
    SigningKeys = new Dictionary<string, AAuthKey> { [ResourceKid] = resourceKey },
    ScopeDescriptions = new Dictionary<string, string>
    {
        [ResourceScope] = "See basic profile information",
    },
    SignatureWindow = signatureWindowSeconds,
});

// -----------------------------------------------------------------------
// Per-path middleware: each access mode gets the correct verification level.
// -----------------------------------------------------------------------

// /hwk — pseudonymous: only HTTP signature verification, no JWT issuer check.
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/hwk"),
    branch => branch.UseAAuthVerification(new AAuthVerificationOptions
    {
        RequireIssuerVerification = false,
    }));

// /jkt-jwt — pseudonymous with key delegation: HTTP signature verified against
// the ephemeral key bound in the naming JWT. No issuer check needed.
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/jkt-jwt"),
    branch => branch.UseAAuthVerification(new AAuthVerificationOptions
    {
        RequireIssuerVerification = false,
    }));

// /jwks-uri — agent identity: HTTP signature verified against published JWKS.
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/jwks-uri"),
    branch => branch.UseAAuthVerification(new AAuthVerificationOptions
    {
        RequireIssuerVerification = false,
    }));

// /jwt and / — three-party: FULL issuer verification via JWKS discovery.
app.UseWhen(
    ctx => !ctx.Request.Path.StartsWithSegments("/.well-known")
        && !ctx.Request.Path.StartsWithSegments("/hwk")
        && !ctx.Request.Path.StartsWithSegments("/jkt-jwt")
        && !ctx.Request.Path.StartsWithSegments("/jwks-uri"),
    branch => branch.UseAAuthVerification(new AAuthVerificationOptions
    {
        ResourceIdentifier = resourceUrl,
        RequireIssuerVerification = true,
    }));

// -----------------------------------------------------------------------
// GET /hwk — Pseudonymous access (no agent identity known).
// -----------------------------------------------------------------------
app.MapGet("/hwk", (HttpContext ctx) =>
{
    var parsed = ctx.GetAAuthParsedKey()!;

    return Results.Ok(new
    {
        mode = "pseudonymous",
        scheme = "hwk",
        jkt = parsed.Jkt,
        note = "Resource sees key thumbprint only — agent identity unknown.",
    });
});

// -----------------------------------------------------------------------
// GET /jkt-jwt — Pseudonymous access with key delegation.
// The naming JWT proves delegation from a hardware-backed durable key to
// an ephemeral signing key. The resource identifies the agent by the
// durable key's JWK thumbprint (jkt).
// -----------------------------------------------------------------------
app.MapGet("/jkt-jwt", (HttpContext ctx) =>
{
    var parsed = ctx.GetAAuthParsedKey()!;

    return Results.Ok(new
    {
        mode = "pseudonymous",
        scheme = "jkt-jwt",
        jkt = parsed.Jkt,
        note = "Delegation from hardware-backed key via naming JWT — agent known by durable key thumbprint.",
    });
});

// -----------------------------------------------------------------------
// GET /jwks-uri — Agent Identity access (agent's key verified via JWKS).
// -----------------------------------------------------------------------
app.MapGet("/jwks-uri", (HttpContext ctx) =>
{
    var parsed = ctx.GetAAuthParsedKey()!;

    return Results.Ok(new
    {
        mode = "agent-identity",
        scheme = "jwks_uri",
        jwks_uri = parsed.JwksUri,
        kid = parsed.Kid,
        note = "Resource verified agent's key via JWKS URI — full cryptographic identity.",
    });
});

// -----------------------------------------------------------------------
// GET / — Three-party JWT access (full issuer verification by middleware).
//
// The middleware has already:
//   - Verified the HTTP signature
//   - Verified the JWT issuer signature via JWKS discovery
//   - Verified cnf.jwk PoP binding
//   - Verified act.sub matches the signing agent
//   - Verified aud matches this resource's identifier
//
// Flow:
//   - Agent token → 401 challenge with resource token
//   - Auth token → return verified claims (including act chain)
// -----------------------------------------------------------------------
app.MapGet("/", async (
    HttpContext ctx,
    AAuthKey resourceSigningKey,
    TokenVerifier tokenVerifier,
    MetadataClient metadata,
    JwksClient jwks) =>
{
    var parsed = ctx.GetAAuthParsedKey()!;
    var tokenType = ctx.GetAAuthTokenType();

    if (tokenType == AAuthTokenType.AgentToken)
    {
        return await ChallengeWithResourceToken(ctx, parsed, tokenVerifier, resourceSigningKey, resourceUrl, metadata, jwks);
    }

    if (tokenType == AAuthTokenType.AuthToken)
    {
        // Middleware already verified signature, aud, cnf.jwk, and act.sub.
        // Just return the verified claims.
        var result = ctx.GetAAuthVerification()!;
        return Results.Ok(new
        {
            mode = "three-party",
            scheme = "jwt",
            agent = result.Agent,
            sub = result.Subject,
            scope = result.Scopes,
            iss = result.Issuer,
            act = parsed.Payload?["act"],
        });
    }

    return Results.Json(
        new { error = "unsupported_token_type", tokenType = tokenType.ToString() },
        statusCode: StatusCodes.Status401Unauthorized);
});

app.Run();

// -----------------------------------------------------------------------
// Helper handlers
// -----------------------------------------------------------------------
static async Task<IResult> ChallengeWithResourceToken(
    HttpContext ctx,
    SignatureKeyParser.ParsedSignatureKeyInfo parsed,
    TokenVerifier verifier,
    AAuthKey resourceKey,
    string resourceIssuer,
    MetadataClient metadata,
    JwksClient jwks)
{
    // §Agent Token Verification: verify JWT signature against the issuer's
    // JWKS discovered via {iss}/.well-known/{dwk}. The middleware already
    // verified that cnf.jwk matches the HTTP signing key (step 5).
    AAuth.Tokens.TokenVerifier.VerifiedToken agentToken;
    try
    {
        agentToken = await verifier.VerifyWithJwksAsync(
            parsed.Jwt!, metadata, jwks,
            AgentTokenBuilder.TokenType,
            AgentTokenBuilder.AgentDwk,
            expectedAudience: null);
    }
    catch (TokenVerificationException ex)
    {
        return Results.Json(new { error = "invalid_agent_token", detail = ex.Message },
            statusCode: StatusCodes.Status401Unauthorized);
    }

    var agentId = (string?)agentToken.Payload["sub"] ?? "unknown";
    var personServer = (string?)agentToken.Payload["ps"];
    if (string.IsNullOrEmpty(personServer))
    {
        // Identity-based fallback when the agent did not advertise a PS:
        // return 200 with whatever the agent token tells us about itself.
        return Results.Ok(new
        {
            mode = "identity-based",
            agent = agentId,
            iss = agentToken.Issuer,
        });
    }

    var resourceToken = new ResourceTokenBuilder
    {
        Issuer = resourceIssuer,
        Audience = personServer,
        Agent = agentId,
        AgentJkt = parsed.ConfirmationKey!.ComputeJwkThumbprint(),
        Key = resourceKey,
        KeyId = ResourceKid,
        Scope = ResourceScope,
    }.Build();

    return ctx.ChallengeAAuth(resourceToken);
}

// Marker type for `WebApplicationFactory<WhoAmI.Entry>` in the
// integration tests. Avoids the ambiguity between the implicit `Program`
// type emitted by top-level statements in this sample and the one emitted
// by the `MockPersonServer` sample when both are referenced from a single
// test assembly.
namespace WhoAmI
{
    /// <summary>Marker type for <c>WebApplicationFactory&lt;T&gt;</c>.</summary>
    public sealed class Entry
    {
        private Entry() { }
    }
}
