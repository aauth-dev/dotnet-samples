using System.Linq;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Tokens;
using AAuth.Events;
using AAuth.HttpSig;
using AAuth.Samples.Events;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAAuthEvents();
var app = builder.Build();

// ── Configuration ───────────────────────────────────────────────────────────
var issuer = app.Configuration["AgentProvider:Issuer"] ?? "http://localhost:5301";
var keyId = app.Configuration["AgentProvider:KeyId"] ?? "ap-key-1";

// AP signing key — persisted so restarting keeps issued tokens verifiable.
var keyStore = new FileKeyStore(app.Configuration["AgentProvider:KeyDirectory"] ?? Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
    ".aauth", "ap-keys"));
var apKey = keyStore.LoadOrCreate(keyId);
var eventStore = new SqliteEventStore(app.Configuration["Events:Database"] ?? Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".aauth", "ap-events.db"));
using var eventHttp = new SampleHttpClient();
var eventProtocol = new EventsProtocol(eventHttp, app.Services.GetServices<ISignatureTokenVerifier>());
app.MapLocalEventProvider(issuer, apKey, keyId, eventProtocol, eventStore);

Console.WriteLine($"Mock Agent Provider running at: {issuer}");
Console.WriteLine($"AP signing key id: {keyId}");
Console.WriteLine($"AP JWK thumbprint: {apKey.ComputeJwkThumbprint()}");
Console.WriteLine();

var agents = new SampleAgentRegistry(app.Configuration["AgentProvider:Database"] ?? Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".aauth", "ap-agents.db"));
app.MapSampleAgentEnrollment(issuer, apKey, keyId, SampleEgress.Policy, agents);

// ── Well-known metadata + JWKS ──────────────────────────────────────────────
app.MapGet("/.well-known/aauth-agent.json", () => Results.Json(new JsonObject
{
    ["issuer"] = issuer,
    ["jwks_uri"] = $"{issuer}/.well-known/jwks.json",
    ["enrol_endpoint"] = $"{issuer}/enrol",
    ["refresh_endpoint"] = $"{issuer}/refresh",
    ["event_endpoint"] = $"{issuer}/events",
    ["name"] = "Mock Agent Provider",
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
    apJwk["alg"] = AAuthKey.Ed25519Algorithm;
    keys.Add(apJwk);

    return Results.Json(new JsonObject { ["keys"] = keys }, contentType: "application/json");
});

// Per-agent JWKS endpoint: serves the enrolled agent's public key.
// Generic direct-key demonstration: Signature-Key: sig=jwks;url="...";kid="..."
// for identity-based access. Separating it from the AP's own JWKS keeps
// token-verification keys distinct from agent-identity keys (per spec).
app.MapGet("/agents/{agentId}/jwks.json", (string agentId) =>
{
    var record = agents.Find(agentId);
    if (record is null)
        return Results.NotFound();

    var agentJwk = record.PublicKey.ToPublicJwk();
    agentJwk["kid"] = record.KeyId;
    agentJwk["use"] = "sig";
    agentJwk["alg"] = record.PublicKey.Algorithm;

    return Results.Json(new JsonObject { ["keys"] = new JsonArray { agentJwk } }, contentType: "application/json");
});

// ── POST /refresh — refresh an agent token ──────────────────────────────────
// Per spec: supports both single-key (hwk) and two-key (jkt-jwt) refresh.
// - hwk: AP verifies signature against durable key, looks up agent by thumbprint.
// - jkt-jwt: AP verifies naming JWT (signed by durable key), verifies HTTP sig
//   against ephemeral key, issues token with ephemeral key as cnf.jwk.
app.MapPost("/refresh", (HttpContext ctx) =>
{
    IResult SignatureFailure(AAuth.Errors.SignatureErrorCode code, string message)
    {
        ctx.Response.Headers[AAuth.Errors.SignatureError.HeaderName] = code == AAuth.Errors.SignatureErrorCode.InvalidInput
            ? AAuth.Errors.SignatureError.Format(code, requiredInput: AAuth.HttpSig.AAuthSigningHandler.CoveredComponents.ToArray())
            : AAuth.Errors.SignatureError.Format(code);
        if (code == AAuth.Errors.SignatureErrorCode.UnsupportedScheme)
            ctx.Response.Headers["Accept-Signature-Scheme"] = "hwk, jkt-jwt";
        return AAuth.Server.AAuthProblemDetails.Create("invalid_signature", message, statusCode: 401);
    }

    // Extract Signature-Key header — agent must sign the refresh request
    var signatureKeyHeader = ctx.Request.Headers["Signature-Key"].FirstOrDefault();
    if (string.IsNullOrEmpty(signatureKeyHeader))
        return SignatureFailure(AAuth.Errors.SignatureErrorCode.InvalidInput, "Missing Signature-Key header - refresh must be signed");

    // Parse the scheme
    AAuth.HttpSig.SignatureKeyParser.ParsedSignatureKeyInfo parsedKey;
    try
    {
        parsedKey = AAuth.HttpSig.SignatureKeyParser.ParseAny(signatureKeyHeader);
    }
    catch
    {
        return SignatureFailure(AAuth.Errors.SignatureErrorCode.InvalidInput, "Cannot parse Signature-Key header");
    }

    if (parsedKey.Scheme is not ("hwk" or "jkt-jwt"))
        return SignatureFailure(AAuth.Errors.SignatureErrorCode.UnsupportedScheme, "Refresh requires hwk or jkt-jwt scheme");

    // Verify the HTTP signature
    var sigInput = ctx.Request.Headers["Signature-Input"].FirstOrDefault();
    var sigHeader = ctx.Request.Headers["Signature"].FirstOrDefault();
    if (string.IsNullOrEmpty(sigInput) || string.IsNullOrEmpty(sigHeader))
        return SignatureFailure(AAuth.Errors.SignatureErrorCode.InvalidInput, "Missing signature headers");

    // Determine the signing key and the durable key for enrollment lookup
    IAAuthKey signingKey;
    IAAuthKey? ephemeralKey = null;
    SampleAgentRecord? record;

    if (parsedKey.Scheme == "hwk")
    {
        // Single-key: the signing key IS the durable key
        if (parsedKey.ConfirmationKey is null)
            return SignatureFailure(AAuth.Errors.SignatureErrorCode.InvalidKey, "hwk scheme missing inline key");
        signingKey = parsedKey.ConfirmationKey;

        var thumbprint = signingKey.ComputeJwkThumbprint();
        record = agents.FindByKey(thumbprint);
    }
    else // jkt-jwt
    {
        AAuth.HttpSig.NamingTokenVerifier.VerifiedNamingToken naming;
        try { naming = AAuth.HttpSig.NamingTokenVerifier.Verify(parsedKey.Jwt!, DateTimeOffset.UtcNow, TimeSpan.Zero); }
        catch (AAuth.HttpSig.AAuthVerificationException exception)
        {
            return SignatureFailure(exception.Code, exception.Message);
        }
        record = agents.FindByKey(naming.DurableKey.ComputeJwkThumbprint());
        signingKey = naming.ConfirmationKey;
        ephemeralKey = naming.ConfirmationKey;
    }

    // Verify the HTTP message signature
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
            signingKey);
    }
    catch (AAuth.HttpSig.AAuthVerificationException ex)
    {
        return SignatureFailure(ex.Code, ex.Message);
    }

    if (record is null)
    {
        // For hwk: look up was done above but might be null
        var thumbprint = signingKey.ComputeJwkThumbprint();
        record = agents.FindByKey(thumbprint);
    }
    if (record is null)
        return AAuth.Server.AAuthProblemDetails.Create("invalid_grant", "No enrolled agent matches this key", statusCode: 400);

    // Issue fresh token — for two-key refresh, use the ephemeral key as cnf.jwk
    string newToken;
    if (ephemeralKey is not null)
    {
        // Two-key: agent token's cnf.jwk is the NEW ephemeral key
        var twoKeyRecord = record with { PublicKey = ephemeralKey };
        newToken = IssueAgentToken(twoKeyRecord);
        Console.WriteLine($"[REFRESH] {record.AgentId} (two-key: verified durable key, new ephemeral key)");
    }
    else
    {
        newToken = IssueAgentToken(record);
        Console.WriteLine($"[REFRESH] {record.AgentId} (single-key: verified by key thumbprint)");
    }

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
    foreach (var record in agents.List())
    {
        list.Add(new JsonObject
        {
            ["agent_id"] = record.AgentId,
            ["key_id"] = record.KeyId,
            ["registered_at"] = record.RegisteredAt.ToString("o"),
        });
    }
    return Results.Json(new JsonObject { ["agents"] = list });
});

app.Run();

// ── Helpers ─────────────────────────────────────────────────────────────────
string IssueAgentToken(SampleAgentRecord record)
{
    return new AgentTokenBuilder
    {
        EgressPolicy = SampleEgress.Policy,
        Issuer = issuer,
        Subject = record.AgentId,
        KeyId = keyId,
        Key = apKey,
        ConfirmationKey = record.PublicKey,
        PersonServer = record.PersonServer,
    }.Build();
}

namespace MockAgentProvider
{
    public sealed class Entry { }
}
