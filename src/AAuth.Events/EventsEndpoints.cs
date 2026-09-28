using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace AAuth.Events;

public static class EventsEndpoints
{
    public static IEndpointConventionBuilder MapAAuthEventEndpoint(this IEndpointRouteBuilder routes,
        string path, EventsProtocol protocol, IAgentProviderEventStore store) => routes.MapPost(path, async (HttpContext context) =>
    {
        var assertion = await protocol.VerifyRequestAsync(context, EventsTokens.EventType).ConfigureAwait(false);
        if (assertion is null) return Results.Empty;
        using var body = new MemoryStream();
        await context.Request.Body.CopyToAsync(body, context.RequestAborted).ConfigureAwait(false);
        var token = assertion.Token;
        var envelope = new EventEnvelope(assertion.CompactToken, EventsTokens.RequireText(token.Payload, "eid"),
            token.Jti, token.Issuer, EventsTokens.RequireText(token.Payload, "aud"), token.ExpiresAt, body.ToArray());
        EventAcceptance acceptance;
        try { acceptance = store.Accept(envelope, protocol.TokenVerifier.Clock()); }
        catch (Exception exception) when (exception is not OperationCanceledException)
        { return AAuthProblemDetails.Create("temporarily_unavailable", "Durable event acceptance failed.", statusCode: 503); }
        if (acceptance.StatusCode != 202)
            return AAuthProblemDetails.Create("event_rejected", statusCode: acceptance.StatusCode);
        return acceptance.RemainingUses is { } remaining
            ? Results.Json(new { remaining_uses = remaining }, statusCode: 202)
            : Results.StatusCode(202);
    });

    public static IEndpointConventionBuilder MapAAuthSubscriptionEndpoint(this IEndpointRouteBuilder routes,
        string path, string resource, string operation, bool protectedChannel, EventsProtocol protocol,
        IResourceEventStore store, Func<JsonObject, bool> validateParameters,
        TimeSpan? subscriptionLifetime = null) => routes.MapPost(path, async (HttpContext context) =>
    {
        var assertion = await protocol.VerifyRequestAsync(context, EventsTokens.SubscribeType, resource).ConfigureAwait(false);
        if (assertion is null) return Results.Empty;
        JsonObject? parameters;
        try { parameters = await context.Request.ReadFromJsonAsync<JsonObject>(context.RequestAborted).ConfigureAwait(false); }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException)
        { return AAuthProblemDetails.Create("invalid_request", "Invalid subscription JSON.", statusCode: 400); }
        if (parameters is null || !validateParameters(parameters))
            return AAuthProblemDetails.Create("invalid_request", "Subscription parameters do not match the channel schema.", statusCode: 400);
        var ticket = protectedChannel ? context.Request.RouteValues["ticket"] as string : null;
        if (protectedChannel && string.IsNullOrWhiteSpace(ticket)) return Results.NotFound();
        var token = assertion.Token;
        await protocol.ResolveEventEndpointAsync(token.Issuer, context.RequestAborted).ConfigureAwait(false);
        var subscription = new ResourceSubscription(EventsTokens.RequireText(token.Payload, "eid"), token.Issuer,
            EventsTokens.RequireText(token.Payload, "sub"), operation, null, "public",
            protocol.TokenVerifier.Clock().Add(subscriptionLifetime ?? TimeSpan.FromHours(1)),
            assertion.HttpSigningKey.ComputeJwkThumbprint());
        RegistrationResult registration;
        try { registration = store.Register(subscription, ticket, protocol.TokenVerifier.Clock()); }
        catch (Exception exception) when (exception is not OperationCanceledException)
        { return AAuthProblemDetails.Create("temporarily_unavailable", "Durable registration failed.", statusCode: 503); }
        return registration.StatusCode == 200
            ? Results.Json(new { eid = subscription.Eid, account = registration.Subscription!.Account,
                expires_at = registration.Subscription.ExpiresAt })
            : AAuthProblemDetails.Create("registration_rejected", statusCode: registration.StatusCode);
    });
}