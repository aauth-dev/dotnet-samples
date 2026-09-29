using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Events;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace AAuth.Samples.Events;

public sealed class BookingsEvents(string issuer, IAAuthKey key, string keyId, EventsProtocol protocol, SqliteEventStore store)
{
    public const string Operation = "receiveReservationAvailable";
    public const string EventType = "reservation.available";

    public object IssueTicket(TokenVerifier.VerifiedToken authorization)
    {
        var ticket = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        var account = authorization.Account;
        var state = store.EnsureState(Operation, account, "availability-v1");
        var cnf = authorization.Payload["cnf"]?["jwk"] as JsonObject
            ?? throw new InvalidOperationException("auth token missing cnf.jwk");
        store.IssueTicket(new(ticket, KeyFactory.FromJwk(cnf).ComputeJwkThumbprint(), Operation,
            account, state, protocol.TokenVerifier.TimeProvider.GetUtcNow().AddMinutes(5)));
        return new { subscribe_url = issuer + "/events/subscriptions/" + ticket,
            event_types = new[] { EventType }, operation = Operation, account };
    }

    public void Map(IEndpointRouteBuilder routes)
    {
        routes.MapGet("/asyncapi.json", () => Results.Json(Document()));
        routes.MapAAuthSubscriptionEndpoint("/events/subscriptions/public", issuer, Operation, false, protocol, store, Validate);
        routes.MapAAuthSubscriptionEndpoint("/events/subscriptions/{ticket}", issuer, Operation, true, protocol, store, Validate);
        routes.MapPost("/local/events/{eid}/notify", async (HttpContext context, string eid) =>
        {
            var assertion = await protocol.VerifyRequestAsync(context, AgentTokenBuilder.TokenType);
            if (assertion is null) return Results.Empty;
            var subscription = store.FindNotification(assertion.Token.Issuer, eid);
            if (subscription is null) return Results.NotFound();
            if (subscription.Agent != EventsTokens.RequireText(assertion.Token.Payload, "sub")) return Results.StatusCode(403);
            if (context.Request.Query.TryGetValue("account", out var account) && account != subscription.Account)
                return Results.StatusCode(403);
            var receipt = store.DeliveryReceipt(subscription);
            if (receipt is not null) return Results.Content(receipt, "application/json", statusCode: 202);
            if (store.Find(subscription.Provider, eid, protocol.TokenVerifier.TimeProvider.GetUtcNow()) is null) return Results.NotFound();
            var envelope = store.PrepareDelivery(subscription.Provider, eid, () =>
            {
                var builder = new EventTokenBuilder { Issuer = issuer, Audience = subscription.Agent, Eid = eid,
                    Key = key, KeyId = keyId, Verifier = protocol.TokenVerifier };
                return new EventEnvelope(builder.Build(), eid, builder.Jti, issuer, subscription.Agent, protocol.TokenVerifier.TimeProvider.GetUtcNow().AddMinutes(5),
                    System.Text.Encoding.UTF8.GetBytes(new JsonObject { ["event_type"] = EventType,
                        ["reservation_id"] = "dining-lumiere-001", ["account"] = subscription.Account }.ToJsonString()));
            });
            var endpoint = await protocol.ResolveEventEndpointAsync(subscription.Provider, context.RequestAborted);
            using var response = await protocol.SendAsync(HttpMethod.Post, endpoint, key, envelope.Token, true, envelope.Body, context.RequestAborted);
            if (!response.IsSuccessStatusCode) return Results.StatusCode((int)response.StatusCode);
            JsonObject? status = null;
            if (response.Content.Headers.ContentLength != 0)
                status = await response.Content.ReadFromJsonAsync<JsonObject>(context.RequestAborted);
            receipt = new JsonObject { ["status"] = "accepted", ["remaining_uses"] = status?["remaining_uses"]?.DeepClone(),
                ["signature_scheme"] = "self-jwt", ["event_token"] = envelope.Token, ["payload"] = JsonNode.Parse(envelope.Body) }.ToJsonString();
            receipt = store.RecordDelivery(subscription, receipt, status?["remaining_uses"]?.GetValue<long>() == 0);
            return Results.Content(receipt, "application/json", statusCode: 202);
        });
    }

    private static bool Validate(JsonObject parameters) => parameters.Count == 1
        && parameters["event_types"] is JsonArray types && types.Count == 1
        && types[0] is JsonValue type && type.TryGetValue<string>(out var name) && name == EventType;

    public JsonObject Document() => new()
    {
        ["asyncapi"] = "3.0.0", ["info"] = new JsonObject { ["title"] = "Bookings Events", ["version"] = "1.0.0" },
        ["channels"] = new JsonObject
        {
            ["publicAvailability"] = Channel("/events/subscriptions/public", false),
            ["reservationAvailability"] = Channel("/events/subscriptions/{subscriptionTicket}", true)
        },
        ["operations"] = new JsonObject
        {
            [Operation + "Public"] = new JsonObject { ["action"] = "receive",
                ["channel"] = new JsonObject { ["$ref"] = "#/channels/publicAvailability" },
                ["security"] = new JsonArray(new JsonObject { ["aauth_subscribe"] = new JsonArray() }) },
            [Operation] = new JsonObject { ["action"] = "receive", ["channel"] = new JsonObject { ["$ref"] = "#/channels/reservationAvailability" } }
        },
        ["components"] = new JsonObject
        {
            ["securitySchemes"] = new JsonObject { ["aauth_subscribe"] = new JsonObject { ["type"] = "http", ["scheme"] = "aauth-subscribe" } },
            ["messages"] = new JsonObject { ["ReservationAvailable"] = new JsonObject
            {
                ["contentType"] = "application/json",
                ["payload"] = new JsonObject { ["type"] = "object", ["required"] = new JsonArray("event_type", "reservation_id"),
                    ["properties"] = new JsonObject { ["event_type"] = new JsonObject { ["type"] = "string", ["const"] = EventType },
                        ["reservation_id"] = new JsonObject { ["type"] = "string" }, ["account"] = new JsonObject { ["type"] = new JsonArray("string", "null") } } }
            } },
            ["schemas"] = new JsonObject { ["SubscriptionParameters"] = new JsonObject { ["type"] = "object",
                ["additionalProperties"] = false, ["required"] = new JsonArray("event_types"),
                ["properties"] = new JsonObject { ["event_types"] = new JsonObject { ["type"] = "array", ["minItems"] = 1, ["maxItems"] = 1,
                    ["items"] = new JsonObject { ["type"] = "string", ["const"] = EventType } } } } }
        }
    };

    private static JsonObject Channel(string address, bool ticket)
    {
        var channel = new JsonObject { ["address"] = address,
            ["messages"] = new JsonObject { ["available"] = new JsonObject { ["$ref"] = "#/components/messages/ReservationAvailable" } },
            ["x-subscription-schema"] = new JsonObject { ["$ref"] = "#/components/schemas/SubscriptionParameters" } };
        if (ticket)
        {
            channel["description"] = "Obtain the single-use subscription URL from an authorized Bookings search or confirmation response.";
            channel["parameters"] = new JsonObject { ["subscriptionTicket"] = new JsonObject { ["description"] = "Single-use ticket bound to agent, operation, account and resource state." } };
        }
        return channel;
    }
}