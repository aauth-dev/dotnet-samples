using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// ── Configuration ───────────────────────────────────────────────────────────
var issuer = app.Configuration["AgentProvider:Issuer"] ?? "http://localhost:5301";
var keyId = app.Configuration["AgentProvider:KeyId"] ?? "ap-key-1";

// AP signing key — persisted so restarting keeps issued tokens verifiable.
var keyStore = new KeyStore(Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
    ".aauth", "ap-keys"));
var apKey = keyStore.LoadOrCreate(keyId);

Console.WriteLine($"Mock Agent Provider running at: {issuer}");
Console.WriteLine($"AP signing key id: {keyId}");
Console.WriteLine($"AP JWK thumbprint: {apKey.ComputeJwkThumbprint()}");
Console.WriteLine();

// ── In-memory agent registry ────────────────────────────────────────────────
var agents = new ConcurrentDictionary<string, AgentRecord>();

// ── Well-known metadata + JWKS ──────────────────────────────────────────────
app.MapGet("/.well-known/aauth-agent.json", () => Results.Json(new JsonObject
{
    ["issuer"] = issuer,
    ["jwks_uri"] = $"{issuer}/.well-known/jwks.json",
    ["enrol_endpoint"] = $"{issuer}/enrol",
    ["refresh_endpoint"] = $"{issuer}/refresh",
    ["client_name"] = "Mock Agent Provider",
    ["localhost_callback_allowed"] = true,
}, contentType: "application/json"));

app.MapGet("/.well-known/jwks.json", () =>
{
    var keys = new JsonArray();

    // AP's own signing key (for agent token verification)
    var apJwk = apKey.ToPublicJwk();
    apJwk["kid"] = keyId;
    apJwk["use"] = "sig";
    apJwk["alg"] = AAuthKey.Algorithm;
    keys.Add(apJwk);

    // Enrolled agent keys (for jwks_uri scheme identity-based access)
    foreach (var (_, record) in agents)
    {
        var agentJwk = record.PublicKey.ToPublicJwk();
        agentJwk["kid"] = record.KeyId;
        agentJwk["use"] = "sig";
        agentJwk["alg"] = AAuthKey.Algorithm;
        keys.Add(agentJwk);
    }

    return Results.Json(new JsonObject { ["keys"] = keys }, contentType: "application/json");
});

// ── POST /enrol — register a new agent ──────────────────────────────────────
app.MapPost("/enrol", async (HttpContext ctx) =>
{
    JsonObject? body;
    try
    {
        body = await ctx.Request.ReadFromJsonAsync<JsonObject>(ctx.RequestAborted);
    }
    catch
    {
        return Results.BadRequest(new { error = "invalid_request", error_description = "Body must be JSON" });
    }
    if (body is null)
        return Results.BadRequest(new { error = "invalid_request" });

    var agentId = (string?)body["agent_id"];
    if (string.IsNullOrEmpty(agentId))
        return Results.BadRequest(new { error = "invalid_request", error_description = "agent_id is required" });

    var jwk = body["jwk"] as JsonObject;
    if (jwk is null)
        return Results.BadRequest(new { error = "invalid_request", error_description = "jwk (public key) is required" });

    // Parse agent's public key
    AAuthKey agentKey;
    try
    {
        agentKey = AAuthKey.FromJwk(jwk);
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = "invalid_key", error_description = ex.Message });
    }

    // Optional: person server URL
    var ps = (string?)body["ps"];

    // Generate a key id for the agent
    var agentKeyId = $"{agentId}:{Guid.NewGuid():N}"[..32];

    // Register
    var record = new AgentRecord(agentId, agentKey, agentKeyId, DateTimeOffset.UtcNow, ps);
    agents[agentId] = record;

    // Issue agent token
    var agentToken = IssueAgentToken(record);

    Console.WriteLine($"[ENROL] {agentId} → kid={agentKeyId}");

    return Results.Json(new JsonObject
    {
        ["agent_token"] = agentToken,
        ["key_id"] = agentKeyId,
        ["expires_in"] = 3600,
    });
});

// ── POST /refresh — refresh an agent token ──────────────────────────────────
app.MapPost("/refresh", async (HttpContext ctx) =>
{
    JsonObject? body;
    try
    {
        body = await ctx.Request.ReadFromJsonAsync<JsonObject>(ctx.RequestAborted);
    }
    catch
    {
        return Results.BadRequest(new { error = "invalid_request" });
    }
    if (body is null)
        return Results.BadRequest(new { error = "invalid_request" });

    var currentToken = (string?)body["agent_token"];
    if (string.IsNullOrEmpty(currentToken))
        return Results.BadRequest(new { error = "invalid_request", error_description = "agent_token is required" });

    // Decode the token to find the agent
    var segments = currentToken.Split('.');
    if (segments.Length != 3)
        return Results.BadRequest(new { error = "invalid_grant", error_description = "Malformed token" });

    JsonObject payload;
    try
    {
        var payloadBytes = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(segments[1]);
        payload = System.Text.Json.Nodes.JsonNode.Parse(payloadBytes) as JsonObject
            ?? throw new Exception();
    }
    catch
    {
        return Results.BadRequest(new { error = "invalid_grant", error_description = "Cannot decode token" });
    }

    var sub = (string?)payload["sub"];
    if (string.IsNullOrEmpty(sub) || !agents.TryGetValue(sub, out var record))
        return Results.Json(new JsonObject { ["error"] = "invalid_grant", ["error_description"] = "Unknown agent" }, statusCode: 400);

    // Issue fresh token
    var newToken = IssueAgentToken(record);
    Console.WriteLine($"[REFRESH] {sub}");

    return Results.Json(new JsonObject
    {
        ["agent_token"] = newToken,
        ["expires_in"] = 3600,
    });
});

// ── GET /agents — list registered agents (dev tool) ─────────────────────────
app.MapGet("/agents", () =>
{
    var list = new JsonArray();
    foreach (var (id, record) in agents)
    {
        list.Add(new JsonObject
        {
            ["agent_id"] = id,
            ["key_id"] = record.KeyId,
            ["registered_at"] = record.RegisteredAt.ToString("o"),
        });
    }
    return Results.Json(new JsonObject { ["agents"] = list });
});

app.Run();

// ── Helpers ─────────────────────────────────────────────────────────────────
string IssueAgentToken(AgentRecord record)
{
    return new AgentTokenBuilder
    {
        Issuer = issuer,
        Subject = record.AgentId,
        KeyId = keyId,
        Key = apKey,
        ConfirmationKey = record.PublicKey,
        PersonServer = record.PersonServer,
    }.Build();
}

// ── Types ───────────────────────────────────────────────────────────────────
record AgentRecord(string AgentId, AAuthKey PublicKey, string KeyId, DateTimeOffset RegisteredAt, string? PersonServer);
