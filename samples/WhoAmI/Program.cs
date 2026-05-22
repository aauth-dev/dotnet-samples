using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Headers;
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
builder.Services.AddSingleton<MetadataClient>(sp =>
    new MetadataClient(sp.GetRequiredService<IHttpClientFactory>().CreateClient("aauth-metadata")));
builder.Services.AddSingleton<JwksClient>(sp =>
    new JwksClient(sp.GetRequiredService<IHttpClientFactory>().CreateClient("aauth-jwks")));
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

// All other endpoints require an AAuth signature. UseWhen scopes the
// middleware so that /.well-known/* discovery endpoints remain reachable
// without a signature (they are mapped above but routing matches them
// after middleware runs, so a blanket UseAAuthVerification would 401 them).
app.UseWhen(
    ctx => !ctx.Request.Path.StartsWithSegments("/.well-known"),
    branch => branch.UseAAuthVerification());

// -----------------------------------------------------------------------
// GET / — the WhoAmI endpoint.
//
// Flow:
//   1. AAuthVerificationMiddleware ensures the request is signed and exposes
//      the parsed scheme info via HttpContext.Items.
//   2. Dispatch on Signature-Key scheme:
//      - jwt with aa-agent+jwt: challenge (three-party) or identity-accept
//      - jwt with aa-auth+jwt: verify auth token, return claims
//      - hwk: pseudonymous identity-based access (return key thumbprint)
//      - jwks_uri: agent identity-based access (return agent URI + kid)
// -----------------------------------------------------------------------
app.MapGet("/", async (
    HttpContext ctx,
    AAuthKey resourceSigningKey,
    TokenVerifier tokenVerifier,
    MetadataClient metadata,
    JwksClient jwks) =>
{
    var parsed = (SignatureKeyParser.ParsedSignatureKeyInfo)ctx.Items[
        AAuthVerificationMiddleware.ContextItemKey]!;

    // ── Pseudonymous mode (hwk): identity-based accept ──────────────
    // The resource knows a specific key signed this request but nothing
    // about the agent's identity. Accept with key-level claims.
    if (parsed.Scheme == "hwk")
    {
        return Results.Ok(new
        {
            mode = "pseudonymous",
            scheme = "hwk",
            jkt = parsed.Jkt,
            note = "Resource sees key thumbprint only — agent identity unknown.",
        });
    }

    // ── Agent Identity mode (jwks_uri): identity-based accept ───────
    // The resource discovered and verified the agent's public key from
    // a JWKS endpoint. The URI serves as the agent's identity.
    if (parsed.Scheme == "jwks_uri")
    {
        return Results.Ok(new
        {
            mode = "agent-identity",
            scheme = "jwks_uri",
            jwks_uri = parsed.JwksUri,
            kid = parsed.Kid,
            note = "Resource verified agent's key via JWKS URI — full cryptographic identity.",
        });
    }

    // ── Agent Token / Auth Token mode (jwt) ─────────────────────────
    var typ = (string?)parsed.Header?["typ"];

    if (typ == AgentTokenBuilder.TokenType)
    {
        return await ChallengeWithResourceToken(ctx, parsed, tokenVerifier, resourceSigningKey, resourceUrl, metadata, jwks);
    }

    if (typ == AuthTokenBuilder.TokenType)
    {
        return await ReturnClaims(parsed, tokenVerifier, metadata, jwks, resourceUrl);
    }

    return Results.Json(
        new { error = "unsupported_token_type", typ },
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

    ctx.Response.Headers[AAuthRequirementHeader.Name] =
        AAuthRequirementHeader.FormatAuthToken(resourceToken);
    return Results.Json(new { error = "auth_token_required" },
        statusCode: StatusCodes.Status401Unauthorized);
}

static async Task<IResult> ReturnClaims(
    SignatureKeyParser.ParsedSignatureKeyInfo parsed,
    TokenVerifier verifier,
    MetadataClient metadata,
    JwksClient jwks,
    string resourceIssuer)
{
    AAuth.Tokens.TokenVerifier.VerifiedToken authToken;
    try
    {
        authToken = await verifier.VerifyWithJwksAsync(
            parsed.Jwt!,
            metadata,
            jwks,
            expectedType: AuthTokenBuilder.TokenType,
            expectedDwk: AuthTokenBuilder.PersonDwk,
            expectedAudience: resourceIssuer);
    }
    catch (TokenVerificationException ex)
    {
        return Results.Json(new { error = "invalid_auth_token", detail = ex.Message },
            statusCode: StatusCodes.Status401Unauthorized);
    }

    // cnf.jwk binding: the auth token's cnf.jwk MUST equal the key that
    // signed the HTTP request.
    var authCnf = authToken.Payload["cnf"]?["jwk"] as JsonObject;
    if (authCnf is null)
    {
        return Results.Json(new { error = "invalid_auth_token", detail = "missing cnf.jwk" },
            statusCode: StatusCodes.Status401Unauthorized);
    }

    AAuthKey authKey;
    try
    {
        authKey = AAuthKey.FromJwk(authCnf);
    }
    catch (Exception ex) when (ex is ArgumentException or FormatException)
    {
        return Results.Json(new { error = "invalid_auth_token", detail = $"malformed cnf.jwk: {ex.Message}" },
            statusCode: StatusCodes.Status401Unauthorized);
    }
    if (authKey.ComputeJwkThumbprint() != parsed.ConfirmationKey!.ComputeJwkThumbprint())
    {
        return Results.Json(new { error = "invalid_auth_token", detail = "cnf.jwk does not match request signing key" },
            statusCode: StatusCodes.Status401Unauthorized);
    }

    return Results.Ok(new
    {
        mode = "three-party",
        agent = (string?)authToken.Payload["agent"],
        sub = (string?)authToken.Payload["sub"],
        scope = (string?)authToken.Payload["scope"],
        iss = authToken.Issuer,
    });
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
