using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Tokens;

var builder = WebApplication.CreateBuilder(args);

// -----------------------------------------------------------------------
// Person Server configuration.
//
// For demo purposes the PS generates a fresh Ed25519 signing key on start.
// A production PS would load a stable key from secure storage. Configure
// the issuer URL through `AAuth:Issuer`; default matches launchSettings
// (http://localhost:5100). The issuer URL is also pinned to the value the
// agent puts in its agent token's `ps` claim, so it must match what
// callers configure.
// -----------------------------------------------------------------------
var psKey = AAuthKey.Generate();
const string PsKid = "ps-1";
const string PsScope = "whoami";
var psIssuer = builder.Configuration["AAuth:Issuer"] ?? "http://localhost:5100";
var signatureWindowSeconds = builder.Configuration.GetValue<int?>("AAuth:SignatureWindow") ?? 60;

builder.Services.AddSingleton(psKey);
builder.Services.AddSingleton(new AAuthVerifier
{
    MaxAge = TimeSpan.FromSeconds(signatureWindowSeconds),
});

var app = builder.Build();

// -----------------------------------------------------------------------
// Well-known endpoints — served BEFORE the verification middleware so the
// metadata document and JWKS are reachable without an AAuth signature.
// -----------------------------------------------------------------------

// JWKS (reused from the shared resource helper — same shape).
app.MapAAuthResourceWellKnown(new AAuthResourceMetadataOptions
{
    Issuer = psIssuer,
    ClientName = "Mock Person Server",
    SigningKeys = new Dictionary<string, AAuthKey> { [PsKid] = psKey },
    ScopeDescriptions = new Dictionary<string, string>
    {
        [PsScope] = "Issue AAuth auth tokens for WhoAmI",
    },
    SignatureWindow = signatureWindowSeconds,
});

// PS-specific metadata document. The shared helper publishes
// /.well-known/aauth-resource.json; the PS spec additionally requires
// /.well-known/aauth-person.json with a `token_endpoint`.
var personMetadata = new JsonObject
{
    ["issuer"] = psIssuer,
    ["jwks_uri"] = $"{psIssuer.TrimEnd('/')}/.well-known/jwks.json",
    ["token_endpoint"] = $"{psIssuer.TrimEnd('/')}/token",
};
app.MapGet("/.well-known/aauth-person.json",
    () => Results.Json(personMetadata, contentType: "application/json"));

// All other endpoints require an AAuth signature.
app.UseWhen(
    ctx => !ctx.Request.Path.StartsWithSegments("/.well-known"),
    branch => branch.UseAAuthVerification());

// -----------------------------------------------------------------------
// POST /token — the exchange endpoint.
//
// Flow:
//   1. AAuthVerificationMiddleware validates the RFC 9421 signature and
//      exposes the parsed carrier token (the agent's aa-agent+jwt) via
//      HttpContext.Items.
//   2. We read `resource_token` from the request body.
//   3. We mint an aa-auth+jwt whose:
//        - iss = this PS
//        - aud = the resource_token's iss (the resource)
//        - agent = agent identifier from the agent token
//        - cnf.jwk = the agent's confirmation key (binds PoP)
//   4. We return { "auth_token": "..." }.
//
// This mock does NOT verify the resource_token's signature — a production
// PS would fetch the resource's JWKS and verify it. Sufficient for the
// demo and for exercising the agent's three-party retry path.
// -----------------------------------------------------------------------
app.MapPost("/token", async (HttpContext ctx) =>
{
    var parsed = (SignatureKeyParser.ParsedSignatureKey)ctx.Items[
        AAuthVerificationMiddleware.ContextItemKey]!;

    // Only an agent token may exchange — refuse anything else.
    var typ = (string?)parsed.Header["typ"];
    if (typ != AgentTokenBuilder.TokenType)
    {
        return Results.Json(
            new { error = "invalid_carrier_token", detail = $"expected {AgentTokenBuilder.TokenType}, got {typ}" },
            statusCode: StatusCodes.Status401Unauthorized);
    }

    var agentId = (string?)parsed.Payload["sub"];
    if (string.IsNullOrEmpty(agentId))
    {
        return Results.Json(new { error = "invalid_carrier_token", detail = "missing sub" },
            statusCode: StatusCodes.Status401Unauthorized);
    }

    JsonObject? body;
    try
    {
        body = await ctx.Request.ReadFromJsonAsync<JsonObject>();
    }
    catch (System.Text.Json.JsonException)
    {
        return Results.Json(new { error = "invalid_request", detail = "body is not valid JSON" },
            statusCode: StatusCodes.Status400BadRequest);
    }

    var resourceTokenJwt = (string?)body?["resource_token"];
    if (string.IsNullOrEmpty(resourceTokenJwt))
    {
        return Results.Json(new { error = "invalid_request", detail = "missing resource_token" },
            statusCode: StatusCodes.Status400BadRequest);
    }

    // Decode the resource token's `iss` claim — that's the resource URL
    // and becomes the auth token's `aud`.
    string audience;
    try
    {
        var segments = resourceTokenJwt.Split('.');
        if (segments.Length != 3)
        {
            throw new FormatException("not a compact JWT");
        }
        var payload = (JsonObject?)JsonNode.Parse(
            Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(segments[1]))
            ?? throw new FormatException("payload is not a JSON object");
        audience = (string?)payload["iss"]
            ?? throw new FormatException("resource_token missing iss");
    }
    catch (Exception ex) when (ex is FormatException or System.Text.Json.JsonException)
    {
        return Results.Json(new { error = "invalid_request", detail = $"malformed resource_token: {ex.Message}" },
            statusCode: StatusCodes.Status400BadRequest);
    }

    var authToken = new AuthTokenBuilder
    {
        Issuer = psIssuer,
        Audience = audience,
        Agent = agentId,
        AgentConfirmationKey = parsed.ConfirmationKey,
        Key = psKey,
        KeyId = PsKid,
        Subject = "pairwise-sub",
        Scope = PsScope,
    }.Build();

    return Results.Ok(new { auth_token = authToken });
});

app.Run();

// Marker type for `WebApplicationFactory<MockPersonServer.Entry>` in the
// integration tests. We don't expose `public partial class Program;` here
// because the WhoAmI sample already declares its own global `Program`, and
// adding both project references to a test assembly would make `Program`
// ambiguous. A dedicated, namespaced marker sidesteps that.
namespace MockPersonServer
{
    /// <summary>Marker type for <c>WebApplicationFactory&lt;T&gt;</c>.</summary>
    public sealed class Entry
    {
        private Entry() { }
    }
}
