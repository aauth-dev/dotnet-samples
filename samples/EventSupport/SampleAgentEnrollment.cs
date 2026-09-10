using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Server.Verification;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace AAuth.Samples.Events;

public static class SampleAgentEnrollment
{
    public static void MapSampleAgentEnrollment(this IEndpointRouteBuilder routes, string issuer, IAAuthKey key,
        string keyId, AAuthEgressPolicy policy, SampleAgentRegistry registry)
    {
        policy.ValidateIdentifier(issuer);
        routes.MapPost("/enrol", async (HttpContext context) =>
        {
            if (context.Request.ContentLength > 65536) return Results.StatusCode(413);
            context.Request.EnableBuffering(65536, 65536);
            var authenticated = false;
            var middleware = new AAuthVerificationMiddleware(_ => { authenticated = true; return Task.CompletedTask; },
                new AAuthVerifier { MaxAge = TimeSpan.FromMinutes(2) }, new DefaultSignatureKeyResolver(), null, null,
                options: new AAuthVerificationOptions { AcceptedSchemes = ["hwk"], RequiredComponents = ["content-type", "content-digest"] });
            try { await middleware.InvokeAsync(context); }
            catch (IOException) { return Results.StatusCode(413); }
            if (!authenticated) return Results.Empty;
            try
            {
                var body = await context.Request.ReadFromJsonAsync<JsonObject>(context.RequestAborted);
                if (body is null || body["jwk"] is not JsonObject jwk) return Results.BadRequest();
                var publicKey = KeyFactory.FromPublicJwk(jwk);
                if (publicKey.ComputeJwkThumbprint() != context.Features.Get<AAuthVerificationResult>()?.Jkt)
                    return Results.StatusCode(403);
                var personServer = (string?)body["ps"];
                if (personServer is not null && !policy.IsValidIdentifier(personServer)) return Results.BadRequest();
                var record = registry.Enrol(issuer, (string?)body["agent_id"], publicKey, personServer);
                if (record is null) return AAuthProblemDetails.Create("invalid_request",
                    "Identity is provider-assigned; key replacement and Person Server changes require authorized reprovisioning.", statusCode: 409);
                var token = new AgentTokenBuilder { Issuer = issuer, Subject = record.AgentId, Key = key, KeyId = keyId,
                    ConfirmationKey = record.PublicKey, PersonServer = record.PersonServer, EgressPolicy = policy }.Build();
                return Results.Json(new { agent_id = record.AgentId, agent_token = token, key_id = record.KeyId,
                    jwks_uri = issuer + "/agents/" + Uri.EscapeDataString(record.AgentId) + "/jwks.json", expires_in = 3600 });
            }
            catch (Exception exception) when (exception is JsonException or InvalidOperationException or JwkValidationException)
            { return Results.BadRequest(); }
        });
    }
}