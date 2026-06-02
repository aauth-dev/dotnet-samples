using System.Text.Json.Nodes;
using AAuth;
using AAuth.Crypto;
using AAuth.DependencyInjection;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Tokens;
using MockAccessServer;

var builder = WebApplication.CreateBuilder(args);

// -----------------------------------------------------------------------
// Access Server (AS) configuration — the fourth party in federated access.
//
// In four-party (federated) access the resource issues a resource token
// whose `aud` is the AS (not the Person Server). The PS does not assert
// access itself; it federates to the AS by POSTing the resource token (and
// the agent token) to the AS `token_endpoint`. The AS evaluates policy and,
// when allowed, mints the `aa-auth+jwt` auth token — distinguished from a
// PS-issued one by `dwk = aauth-access.json`.
//
// For demo purposes the AS generates a fresh Ed25519 signing key on start.
// A production AS would load a stable key from secure storage. Configure
// the issuer URL through `AAuth:Issuer`; default matches launchSettings
// (http://localhost:5500).
//
// Phase 1 policy is a hard-coded "allow" stub. The pluggable `IAccessPolicy`
// seam (and the Keycloak-backed policy engine) arrive in later phases.
// -----------------------------------------------------------------------
var asKey = AAuthKey.Generate();
const string AsKid = "as-1";
const string AsScope = "whoami";
var asIssuer = builder.Configuration["AAuth:Issuer"] ?? "http://localhost:5500";
var signatureWindowSeconds = builder.Configuration.GetValue<int?>("AAuth:SignatureWindow") ?? 60;

// Person Servers this AS will broker for. The PS authenticates to the AS
// via an HTTP Sig using the `jwks_uri` scheme; we resolve its key from that
// URI during signature verification and additionally pin the URI's host to
// this trusted set (pre-established trust). An empty/missing set trusts any
// validly-signed caller (demo-friendly default).
var trustedPersonServers = builder.Configuration
    .GetSection("MockAccessServer:TrustedPersonServers")
    .Get<string[]>() ?? ["http://localhost:5100"];
var trustedPsHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
foreach (var ps in trustedPersonServers)
{
    if (Uri.TryCreate(ps, UriKind.Absolute, out var psUri))
    {
        trustedPsHosts.Add(psUri.Authority);
    }
}

builder.Services.AddSingleton(asKey);
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
// Well-known endpoints — served BEFORE the verification middleware so the
// AS metadata document and JWKS are reachable without an AAuth signature.
// `MapAAuthAccessServerWellKnown` publishes /.well-known/aauth-access.json
// and the JWKS at /.well-known/jwks.json.
// -----------------------------------------------------------------------
app.MapAAuthAccessServerWellKnown(new AAuthAccessServerMetadataOptions
{
    Issuer = asIssuer,
    TokenEndpoint = $"{asIssuer.TrimEnd('/')}/token",
    SigningKeys = new Dictionary<string, AAuthKey> { [AsKid] = asKey },
});

// All other endpoints require an AAuth signature. The PS signs with the
// `jwks_uri` scheme (RequireIssuerVerification=false — that scheme carries
// no issuer/token of its own; the request signature only proves the PS
// possesses the key advertised at its jwks_uri).
app.UseWhen(
    ctx => !ctx.Request.Path.StartsWithSegments("/.well-known"),
    branch => branch.UseAAuthVerification(new AAuthVerificationOptions
    {
        RequireIssuerVerification = false,
    }));

// -----------------------------------------------------------------------
// POST /token — the AS token endpoint (§"AS Token Endpoint").
//
// Flow:
//   1. AAuthVerificationMiddleware validates the RFC 9421 signature. The PS
//      authenticates via the `jwks_uri` scheme; the parsed key exposes the
//      PS's jwks_uri so we can pin trust to a known Person Server.
//   2. We read `agent_token` and `resource_token` from the JSON body.
//   3. We verify the agent token (typ=aa-agent+jwt, dwk=aauth-agent.json)
//      against the agent issuer's JWKS, extracting the agent id (`sub`) and
//      its confirmation key (`cnf.jwk`).
//   4. We verify the resource token (§"Resource Token Verification") with
//      `aud` = this AS, binding it to the agent + its key. The verified
//      resource `iss` becomes the auth token's `aud`.
//   5. We evaluate access policy (Phase 1: a hard-coded allow stub).
//   6. We mint an `aa-auth+jwt` with `dwk = aauth-access.json`, `iss` = this
//      AS, `aud` = the resource, bound to the agent's key, and return it.
// -----------------------------------------------------------------------
app.MapPost("/token", async (HttpContext ctx) =>
{
    var parsed = ctx.GetAAuthParsedKey()!;

    // The PS authenticates with the jwks_uri scheme. Reject any other carrier.
    if (parsed.Scheme != AAuthConstants.Schemes.JwksUri)
    {
        return Results.Json(
            new { error = "invalid_carrier", detail = $"expected jwks_uri scheme, got {parsed.Scheme}" },
            statusCode: StatusCodes.Status401Unauthorized);
    }

    // Pin the caller to a trusted Person Server (pre-established trust).
    if (trustedPsHosts.Count > 0)
    {
        var jwksUri = parsed.JwksUri;
        if (string.IsNullOrEmpty(jwksUri)
            || !Uri.TryCreate(jwksUri, UriKind.Absolute, out var psUri)
            || !trustedPsHosts.Contains(psUri.Authority))
        {
            return Results.Json(
                new { error = "untrusted_person_server", detail = $"jwks_uri '{jwksUri}' is not a trusted Person Server" },
                statusCode: StatusCodes.Status403Forbidden);
        }
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

    var agentTokenJwt = (string?)body?["agent_token"];
    if (string.IsNullOrEmpty(agentTokenJwt))
    {
        return Results.Json(new { error = "invalid_request", detail = "missing agent_token" },
            statusCode: StatusCodes.Status400BadRequest);
    }

    var resourceTokenJwt = (string?)body?["resource_token"];
    if (string.IsNullOrEmpty(resourceTokenJwt))
    {
        return Results.Json(new { error = "invalid_request", detail = "missing resource_token" },
            statusCode: StatusCodes.Status400BadRequest);
    }

    var tokenVerifier = app.Services.GetRequiredService<TokenVerifier>();
    var metadataClient = app.Services.GetRequiredService<MetadataClient>();
    var jwksClient = app.Services.GetRequiredService<JwksClient>();

    // Step 3 — verify the agent token and extract the agent id + key.
    string agentId;
    AAuthKey agentConfirmationKey;
    try
    {
        var verifiedAgentToken = await tokenVerifier.VerifyWithJwksAsync(
            agentTokenJwt,
            metadataClient,
            jwksClient,
            AgentTokenBuilder.TokenType,
            AgentTokenBuilder.AgentDwk,
            expectedAudience: null);

        agentId = (string?)verifiedAgentToken.Payload["sub"]
            ?? throw new TokenVerificationException("agent_token missing sub");

        var cnfJwk = verifiedAgentToken.Payload["cnf"]?["jwk"] as JsonObject
            ?? throw new TokenVerificationException("agent_token missing cnf.jwk");
        agentConfirmationKey = AAuthKey.FromJwk(cnfJwk);
    }
    catch (TokenVerificationException ex)
    {
        return Results.Json(new { error = "invalid_agent_token", detail = ex.Message },
            statusCode: StatusCodes.Status401Unauthorized);
    }

    // Step 4 — verify the resource token. `aud` MUST be this AS (that is what
    // distinguishes four-party from three-party). The verified `iss` is the
    // resource and becomes the auth token's `aud`; the verified `scope` is
    // echoed into the issued auth token.
    string audience;
    var requestedScope = AsScope;
    try
    {
        var verifiedResourceToken = await tokenVerifier.VerifyResourceTokenAsync(
            resourceTokenJwt,
            expectedAudience: asIssuer,
            expectedAgentId: agentId,
            expectedAgentJkt: agentConfirmationKey.ComputeJwkThumbprint(),
            metadataClient,
            jwksClient);

        audience = (string?)verifiedResourceToken.Payload["iss"]
            ?? throw new TokenVerificationException("resource_token missing iss");
        var scopeClaim = (string?)verifiedResourceToken.Payload["scope"];
        if (!string.IsNullOrWhiteSpace(scopeClaim))
        {
            requestedScope = scopeClaim;
        }
    }
    catch (TokenVerificationException ex)
    {
        var expired = ex.Message.Contains("expired", StringComparison.OrdinalIgnoreCase);
        return Results.Json(
            new
            {
                error = expired ? "expired_resource_token" : "invalid_resource_token",
                detail = ex.Message,
            },
            statusCode: StatusCodes.Status401Unauthorized);
    }

    // Step 5 — access policy. Phase 1 ships a hard-coded allow stub; the
    // pluggable IAccessPolicy seam (and Keycloak-backed decisions, including
    // consent bubble-up via 202) arrive in later phases.
    // (allow)

    // Step 6 — mint the auth token (dwk = aauth-access.json).
    var authToken = new AuthTokenBuilder
    {
        Issuer = asIssuer,
        Audience = audience,
        Agent = agentId,
        AgentConfirmationKey = agentConfirmationKey,
        Key = asKey,
        KeyId = AsKid,
        Subject = "pairwise-sub",
        Scope = requestedScope,
        Dwk = AuthTokenBuilder.AccessDwk,
    }.Build();

    return Results.Ok(new { auth_token = authToken, expires_in = 3600 });
});

app.Run();

// Marker type for `WebApplicationFactory<MockAccessServer.Entry>` in the
// integration tests, matching the MockPersonServer pattern.
namespace MockAccessServer
{
    /// <summary>Marker type for <c>WebApplicationFactory&lt;T&gt;</c>.</summary>
    public sealed class Entry
    {
        private Entry() { }
    }
}
