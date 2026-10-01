using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Events;
using AAuth.Server;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.Samples.Events;

public static class LocalEventProvider
{
    /// <summary>Requires <c>AddAAuthEvents</c> and a registered <see cref="IAgentProviderEventStore"/>.</summary>
    public static void MapLocalEventProvider(this IEndpointRouteBuilder routes, string issuer, IAAuthSigner key,
        string keyId)
    {
        var protocol = routes.ServiceProvider.GetRequiredService<EventsProtocol>();
        var store = routes.ServiceProvider.GetRequiredService<IAgentProviderEventStore>();
        routes.MapAAuthEventEndpoint("/events");
        routes.MapPost("/local/events/subscribe", async (HttpContext context) =>
        {
            var assertion = await protocol.VerifyRequestAsync(context, AgentTokenBuilder.TokenType);
            if (assertion is null) return Results.Empty;
            if (assertion.Token.Issuer != issuer) return Results.StatusCode(403);
            JsonObject? request;
            try { request = await context.Request.ReadFromJsonAsync<JsonObject>(context.RequestAborted); }
            catch (JsonException) { return Results.BadRequest(); }
            if (request is null || request.Any(member => member.Key is not ("resource" or "max_uses"))
                || request["resource"] is not JsonValue resourceValue || !resourceValue.TryGetValue<string>(out var resource)
                || !protocol.TokenVerifier.EgressPolicy.IsValidIdentifier(resource)) return Results.BadRequest();
            long? maximum = null;
            if (request.ContainsKey("max_uses"))
            {
                if (request["max_uses"] is not JsonValue value || !value.TryGetValue<long>(out var count) || count <= 0) return Results.BadRequest();
                maximum = count;
            }
            var eid = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
            var agent = EventsTokens.RequireText(assertion.Token.Payload, "sub");
            var jwt = await new SubscribeTokenBuilder
            {
                Issuer = issuer, Subject = agent, Audience = resource, Eid = eid, Key = key,
                KeyId = keyId, ConfirmationKey = assertion.HttpSigningKey, MaxUses = maximum,
                Verifier = protocol.TokenVerifier
            }.BuildAsync(context.RequestAborted);
            try { store.Create(new(eid, agent, resource, protocol.TokenVerifier.TimeProvider.GetUtcNow().AddHours(1), maximum)); }
            catch (Exception exception) when (exception is not OperationCanceledException)
            { return AAuthProblemDetails.Create("temporarily_unavailable", statusCode: 503); }
            return Results.Json(new { subscribe_token = jwt, eid });
        });

        routes.MapGet("/local/events/inbox", async (HttpContext context) =>
        {
            var assertion = await protocol.VerifyRequestAsync(context, AgentTokenBuilder.TokenType);
            if (assertion is null) return Results.Empty;
            if (assertion.Token.Issuer != issuer) return Results.StatusCode(403);
            var limit = 100;
            if (context.Request.Query.TryGetValue("limit", out var requestedLimit)
                && (!int.TryParse(requestedLimit, out limit) || limit is < 1 or > 100)) return Results.BadRequest();
            var after = context.Request.Query["after"].FirstOrDefault();
            return Results.Json(store.Pending(EventsTokens.RequireText(assertion.Token.Payload, "sub"), limit, after), SqliteEventStore.InboxJson);
        });

        routes.MapPost("/local/events/inbox/{receipt}/ack", async (HttpContext context, string receipt) =>
        {
            var assertion = await protocol.VerifyRequestAsync(context, AgentTokenBuilder.TokenType);
            if (assertion is null) return Results.Empty;
            if (assertion.Token.Issuer != issuer) return Results.StatusCode(403);
            return store.Acknowledge(EventsTokens.RequireText(assertion.Token.Payload, "sub"), receipt)
                ? Results.NoContent() : Results.NotFound();
        });
    }
}