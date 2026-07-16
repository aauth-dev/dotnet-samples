using System.Collections.Concurrent;
using System.Linq;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Events.Discovery;
using AAuth.Events.Http;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using MockAgentProvider.Events;

var builder = WebApplication.CreateBuilder(args);

// ── Configuration ───────────────────────────────────────────────────────────
var issuer = builder.Configuration["AgentProvider:Issuer"] ?? "http://localhost:5301";
var keyId = builder.Configuration["AgentProvider:KeyId"] ?? "ap-key-1";
var eventEndpointRoute =
    builder.Configuration["AgentProvider:Events:EventEndpointRoute"] ?? "/events";
var bookingsResource =
    builder.Configuration["AgentProvider:Events:BookingsResourceUrl"] ?? "http://localhost:5005";
var subscribeTokenLifetimeSeconds = builder.Configuration.GetValue(
    "AgentProvider:Events:SubscribeTokenLifetimeSeconds", 300);
var subscriptionLifetimeSeconds = builder.Configuration.GetValue(
    "AgentProvider:Events:SubscriptionLifetimeSeconds", 3600);
var subscriptionMaxUses = builder.Configuration.GetValue<long?>(
    "AgentProvider:Events:SubscriptionMaxUses");
if (subscribeTokenLifetimeSeconds <= 0)
    throw new InvalidOperationException(
        "AgentProvider:Events:SubscribeTokenLifetimeSeconds must be positive.");
if (subscriptionLifetimeSeconds <= 0)
    throw new InvalidOperationException(
        "AgentProvider:Events:SubscriptionLifetimeSeconds must be positive.");
if (subscriptionMaxUses is <= 0)
    throw new InvalidOperationException(
        "AgentProvider:Events:SubscriptionMaxUses must be positive.");
if (!eventEndpointRoute.StartsWith('/'))
    throw new InvalidOperationException(
        "AgentProvider:Events:EventEndpointRoute must start with '/'.");
var eventEndpoint = new Uri(
    new Uri(issuer.TrimEnd('/') + "/", UriKind.Absolute),
    eventEndpointRoute.TrimStart('/')).AbsoluteUri;

// AP signing key — persisted so restarting keeps issued tokens verifiable.
var keyStore = new FileKeyStore(Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
    ".aauth", "ap-keys"));
var apKey = keyStore.LoadOrCreate(keyId);

Console.WriteLine($"Mock Agent Provider running at: {issuer}");
Console.WriteLine($"AP signing key id: {keyId}");
Console.WriteLine($"AP JWK thumbprint: {apKey.ComputeJwkThumbprint()}");
Console.WriteLine("[SAMPLE ONLY] Events acquisition/poll/ACK use a non-normative transport.");
Console.WriteLine("[SAMPLE ONLY] Events inbox storage is in-memory and non-durable; not production.");
Console.WriteLine();

// ── In-memory agent registry ────────────────────────────────────────────────
var agents = new ConcurrentDictionary<string, AgentRecord>();
// Sample-only, non-durable inbox. Production APs must provide durable storage.
var eventStore = new SampleAgentProviderEventStore();
var eventPolicy = new DefaultEventsUrlPolicy();
var eventResolver = new EventsJwtKeyResolver(
    EventsHttpClientFactory.Create(eventPolicy), eventPolicy);
builder.Services.AddSingleton<IEventsUrlPolicy>(eventPolicy);
builder.Services.AddSingleton(eventResolver);
builder.Services.AddSingleton<AAuthKey>(apKey);
builder.Services.AddAAuthEventsAgentProvider(
    eventStore,
    options =>
    {
        options.JwtKeyResolver = eventResolver;
        options.HttpMessageVerifier = new EventsHttpMessageVerifier();
    });

var app = builder.Build();

// ── Well-known metadata + JWKS ──────────────────────────────────────────────
app.MapGet("/.well-known/aauth-agent.json", () =>
{
    var metadata = new JsonObject
    {
        ["issuer"] = issuer,
        ["jwks_uri"] = $"{issuer}/.well-known/jwks.json",
        ["enrol_endpoint"] = $"{issuer}/enrol",
        ["refresh_endpoint"] = $"{issuer}/refresh",
        ["name"] = "Mock Agent Provider",
        ["localhost_callback_allowed"] = true,
    };
    AAuthEventsMetadata.AddEventEndpoint(metadata, eventEndpoint);
    return Results.Json(metadata, contentType: "application/json");
});

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
// Per spec: supports both single-key (hwk) and two-key (jkt-jwt) refresh.
// - hwk: AP verifies signature against durable key, looks up agent by thumbprint.
// - jkt-jwt: AP verifies naming JWT (signed by durable key), verifies HTTP sig
//   against ephemeral key, issues token with ephemeral key as cnf.jwk.
app.MapPost("/refresh", (HttpContext ctx) =>
{
    // Extract Signature-Key header — agent must sign the refresh request
    var signatureKeyHeader = ctx.Request.Headers["Signature-Key"].FirstOrDefault();
    if (string.IsNullOrEmpty(signatureKeyHeader))
        return Results.Json(new JsonObject { ["error"] = "invalid_request", ["error_description"] = "Missing Signature-Key header — refresh must be signed" }, statusCode: 401);

    // Parse the scheme
    AAuth.HttpSig.SignatureKeyParser.ParsedSignatureKeyInfo parsedKey;
    try
    {
        parsedKey = AAuth.HttpSig.SignatureKeyParser.ParseAny(signatureKeyHeader);
    }
    catch
    {
        return Results.Json(new JsonObject { ["error"] = "invalid_request", ["error_description"] = "Cannot parse Signature-Key header" }, statusCode: 400);
    }

    if (parsedKey.Scheme is not ("hwk" or "jkt-jwt"))
        return Results.Json(new JsonObject { ["error"] = "invalid_request", ["error_description"] = "Refresh requires hwk or jkt-jwt scheme" }, statusCode: 400);

    // Verify the HTTP signature
    var sigInput = ctx.Request.Headers["Signature-Input"].FirstOrDefault();
    var sigHeader = ctx.Request.Headers["Signature"].FirstOrDefault();
    if (string.IsNullOrEmpty(sigInput) || string.IsNullOrEmpty(sigHeader))
        return Results.Json(new JsonObject { ["error"] = "invalid_signature", ["error_description"] = "Missing signature headers" }, statusCode: 401);

    // Determine the signing key and the durable key for enrollment lookup
    IAAuthKey signingKey;
    AAuthKey? ephemeralKey = null;
    AgentRecord? record;

    if (parsedKey.Scheme == "hwk")
    {
        // Single-key: the signing key IS the durable key
        if (parsedKey.ConfirmationKey is null)
            return Results.Json(new JsonObject { ["error"] = "invalid_request", ["error_description"] = "hwk scheme missing inline key" }, statusCode: 400);
        signingKey = parsedKey.ConfirmationKey;

        var thumbprint = signingKey.ComputeJwkThumbprint();
        record = agents.Values.FirstOrDefault(a => a.PublicKey.ComputeJwkThumbprint() == thumbprint);
    }
    else // jkt-jwt
    {
        // Two-key refresh (draft-hardt-httpbis-signature-key-05 §3.4): the durable
        // key is embedded in the naming JWT header jwk, the issuer is that key's
        // own thumbprint URN, and cnf.jwk is the ephemeral key that signed the
        // HTTP request. Verification is self-anchored, then bound to enrolment.
        if (parsedKey.ConfirmationKey is null || parsedKey.Jwt is null ||
            parsedKey.Header is null || parsedKey.Payload is null)
            return Results.Json(new JsonObject { ["error"] = "invalid_request", ["error_description"] = "jkt-jwt scheme missing required fields" }, statusCode: 400);

        // §3.4 step 2: check the naming JWT typ.
        var typ = (string?)parsedKey.Header["typ"];
        if (typ != AAuth.AAuthConstants.TokenTypes.JktS256Jwt)
            return Results.Json(new JsonObject { ["error"] = "invalid_request", ["error_description"] = $"Unexpected naming JWT typ '{typ}'" }, statusCode: 400);

        // §3.4 step 4: extract the durable key from the header jwk.
        if (parsedKey.Header["jwk"] is not JsonObject durableJwk)
            return Results.Json(new JsonObject { ["error"] = "invalid_request", ["error_description"] = "Naming JWT header missing durable jwk" }, statusCode: 400);
        var durableKey = AAuthKey.FromJwk(durableJwk);
        var durableThumbprint = durableKey.ComputeJwkThumbprint();

        // §3.4 steps 5-7: the issuer must equal the durable key's thumbprint URN.
        var iss = (string?)parsedKey.Payload["iss"];
        if (iss != AAuth.AAuthConstants.JktThumbprintUrnPrefix + durableThumbprint)
            return Results.Json(new JsonObject { ["error"] = "invalid_grant", ["error_description"] = "Naming JWT iss does not match the durable key thumbprint" }, statusCode: 401);

        // §3.4 step 8: verify the naming JWT signature against the header jwk.
        var namingJwtParts = parsedKey.Jwt.Split('.');
        if (namingJwtParts.Length != 3)
            return Results.Json(new JsonObject { ["error"] = "invalid_request", ["error_description"] = "Naming JWT is not a valid compact JWS" }, statusCode: 400);

        var signingInputBytes = System.Text.Encoding.ASCII.GetBytes(namingJwtParts[0] + "." + namingJwtParts[1]);
        var namingSig = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(namingJwtParts[2]);
        if (!durableKey.Verify(signingInputBytes, namingSig))
            return Results.Json(new JsonObject { ["error"] = "invalid_signature", ["error_description"] = "Naming JWT signature verification failed against the durable key" }, statusCode: 401);

        // AP-layer binding (bootstrap §Two-Key Refresh): look up the enrolment by
        // the durable key's thumbprint and confirm it is the enrolled durable key.
        record = agents.Values.FirstOrDefault(a => a.PublicKey.ComputeJwkThumbprint() == durableThumbprint);
        if (record is null)
            return Results.Json(new JsonObject { ["error"] = "invalid_grant", ["error_description"] = "No enrolled agent matches the durable key thumbprint in the naming JWT" }, statusCode: 400);

        // §3.4 step 9: validate naming JWT expiration.
        var exp = (long?)parsedKey.Payload?["exp"];
        if (exp is null || DateTimeOffset.UtcNow.ToUnixTimeSeconds() > exp.Value)
            return Results.Json(new JsonObject { ["error"] = "invalid_grant", ["error_description"] = "Naming JWT has expired" }, statusCode: 401);

        // §3.4 steps 10-11: the ephemeral key (cnf.jwk) signs the HTTP request.
        signingKey = parsedKey.ConfirmationKey;
        ephemeralKey = signingKey as AAuthKey ?? AAuthKey.FromJwk(parsedKey.Payload!["cnf"]!["jwk"]!.AsObject());
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
        return Results.Json(new JsonObject { ["error"] = "invalid_signature", ["error_description"] = ex.Message }, statusCode: 401);
    }

    if (record is null)
    {
        // For hwk: look up was done above but might be null
        var thumbprint = signingKey.ComputeJwkThumbprint();
        record = agents.Values.FirstOrDefault(a => a.PublicKey.ComputeJwkThumbprint() == thumbprint);
    }
    if (record is null)
        return Results.Json(new JsonObject { ["error"] = "invalid_grant", ["error_description"] = "No enrolled agent matches this key" }, statusCode: 400);

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

// Normative Events AP delivery endpoint (resource-to-AP).
app.MapAAuthEventEndpoint(eventEndpointRoute);
// Non-normative sample-only AP-to-agent acquisition, polling, and ACK.
app.MapSampleAgentEventEndpoints(
    agents,
    apKey,
    keyId,
    issuer,
    bookingsResource,
    TimeSpan.FromSeconds(subscribeTokenLifetimeSeconds),
    TimeSpan.FromSeconds(subscriptionLifetimeSeconds),
    subscriptionMaxUses,
    eventStore);

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
internal record AgentRecord(string AgentId, AAuthKey PublicKey, string KeyId, DateTimeOffset RegisteredAt, string? PersonServer);
