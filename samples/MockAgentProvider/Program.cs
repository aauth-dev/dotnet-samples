using System.Collections.Concurrent;
using System.Linq;
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

    // AP's own signing key only (for verifying agent token JWTs).
    // Per spec, this JWKS does NOT contain enrolled agent keys —
    // those are served at per-agent endpoints below.
    var apJwk = apKey.ToPublicJwk();
    apJwk["kid"] = keyId;
    apJwk["use"] = "sig";
    apJwk["alg"] = AAuthKey.Algorithm;
    keys.Add(apJwk);

    return Results.Json(new JsonObject { ["keys"] = keys }, contentType: "application/json");
});

// Per-agent JWKS endpoint: serves the enrolled agent's public key.
// This is the URI agents use in Signature-Key: sig=jwks_uri;uri="...";kid="..."
// for identity-based access. Separating it from the AP's own JWKS keeps
// token-verification keys distinct from agent-identity keys (per spec).
app.MapGet("/agents/{agentId}/jwks.json", (string agentId) =>
{
    if (!agents.TryGetValue(agentId, out var record))
        return Results.NotFound();

    var agentJwk = record.PublicKey.ToPublicJwk();
    agentJwk["kid"] = record.KeyId;
    agentJwk["use"] = "sig";
    agentJwk["alg"] = AAuthKey.Algorithm;

    return Results.Json(new JsonObject { ["keys"] = new JsonArray { agentJwk } }, contentType: "application/json");
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

    // Idempotent enrollment: if the same agent_id re-enrolls with the same
    // key, keep the existing kid so the AP's JWKS stays stable (per spec,
    // keys are long-lived and the kid is a stable reference). Only generate
    // a new kid when the key actually changes or the agent is new.
    string agentKeyId;
    if (agents.TryGetValue(agentId, out var existing)
        && existing.PublicKey.ComputeJwkThumbprint() == agentKey.ComputeJwkThumbprint())
    {
        agentKeyId = existing.KeyId;
    }
    else
    {
        agentKeyId = $"{agentId}:{Guid.NewGuid():N}"[..32];
    }

    // Register (or update ps/timestamp)
    var record = new AgentRecord(agentId, agentKey, agentKeyId, DateTimeOffset.UtcNow, ps);
    agents[agentId] = record;

    // Issue agent token
    var agentToken = IssueAgentToken(record);

    Console.WriteLine($"[ENROL] {agentId} → kid={agentKeyId}");

    return Results.Json(new JsonObject
    {
        ["agent_token"] = agentToken,
        ["key_id"] = agentKeyId,
        ["jwks_uri"] = $"{issuer}/agents/{agentId}/jwks.json",
        ["expires_in"] = 3600,
    });
});

// ── POST /refresh — refresh an agent token ──────────────────────────────────
// Per spec: the refresh request is HTTP-signed with the durable key (hwk scheme).
// The AP verifies the signature and identifies the agent by key thumbprint.
app.MapPost("/refresh", (HttpContext ctx) =>
{
    // Extract Signature-Key header — agent must sign with hwk scheme
    var signatureKeyHeader = ctx.Request.Headers["Signature-Key"].FirstOrDefault();
    if (string.IsNullOrEmpty(signatureKeyHeader))
        return Results.Json(new JsonObject { ["error"] = "invalid_request", ["error_description"] = "Missing Signature-Key header — refresh must be signed" }, statusCode: 401);

    // Parse the hwk scheme to get the agent's public key
    AAuth.HttpSig.SignatureKeyParser.ParsedSignatureKeyInfo parsedKey;
    try
    {
        parsedKey = AAuth.HttpSig.SignatureKeyParser.ParseAny(signatureKeyHeader);
    }
    catch
    {
        return Results.Json(new JsonObject { ["error"] = "invalid_request", ["error_description"] = "Cannot parse Signature-Key header" }, statusCode: 400);
    }

    if (parsedKey.Scheme != "hwk" || parsedKey.ConfirmationKey is null)
        return Results.Json(new JsonObject { ["error"] = "invalid_request", ["error_description"] = "Refresh requires hwk scheme with inline key" }, statusCode: 400);

    // Verify the HTTP signature
    var sigInput = ctx.Request.Headers["Signature-Input"].FirstOrDefault();
    var sigHeader = ctx.Request.Headers["Signature"].FirstOrDefault();
    if (string.IsNullOrEmpty(sigInput) || string.IsNullOrEmpty(sigHeader))
        return Results.Json(new JsonObject { ["error"] = "invalid_signature", ["error_description"] = "Missing signature headers" }, statusCode: 401);

    var verifier = new AAuth.HttpSig.AAuthVerifier { MaxAge = TimeSpan.FromSeconds(120) };
    try
    {
        verifier.Verify(
            ctx.Request.Method,
            ctx.Request.Host.ToString(),
            ctx.Request.Path,
            signatureKeyHeader,
            sigInput,
            sigHeader,
            parsedKey.ConfirmationKey);
    }
    catch (AAuth.HttpSig.AAuthVerificationException ex)
    {
        return Results.Json(new JsonObject { ["error"] = "invalid_signature", ["error_description"] = ex.Message }, statusCode: 401);
    }

    // Look up agent by key thumbprint
    var thumbprint = parsedKey.ConfirmationKey.ComputeJwkThumbprint();
    var record = agents.Values.FirstOrDefault(a => a.PublicKey.ComputeJwkThumbprint() == thumbprint);
    if (record is null)
        return Results.Json(new JsonObject { ["error"] = "invalid_grant", ["error_description"] = "No enrolled agent matches this key" }, statusCode: 400);

    // Issue fresh token
    var newToken = IssueAgentToken(record);
    Console.WriteLine($"[REFRESH] {record.AgentId} (verified by key thumbprint)");

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
