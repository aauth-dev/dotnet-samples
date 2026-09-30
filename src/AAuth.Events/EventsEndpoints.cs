using System.Text.Json;
using System.Text.Json.Nodes;
using AAuth.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.Events;

/// <summary>Describes a subscription channel mapped by <see cref="EventsEndpoints.MapAAuthSubscriptionEndpoint"/>.</summary>
public sealed class AAuthSubscriptionEndpointOptions
{
    /// <summary>The resource identifier subscribe tokens must name; defaults to the registered resource's issuer.</summary>
    public string? Resource { get; set; }

    /// <summary>The operation the channel delivers.</summary>
    public string Operation { get; set; } = "";

    /// <summary>Whether the channel is ticket-protected (the route carries <c>{ticket}</c>).</summary>
    public bool ProtectedChannel { get; set; }

    /// <summary>Validates the subscription parameters against the channel schema.</summary>
    public Func<JsonObject, bool>? ValidateParameters { get; set; }

    /// <summary>How long a registration lasts. Default one hour.</summary>
    public TimeSpan? SubscriptionLifetime { get; set; }
}

public static class EventsEndpoints
{
    /// <summary>
    /// Map an Agent Provider event endpoint. Resolves the <see cref="EventsProtocol"/> (from
    /// <see cref="EventsServiceExtensions.AddAAuthEvents"/>) and <see cref="IAgentProviderEventStore"/> from DI.
    /// </summary>
    public static IEndpointConventionBuilder MapAAuthEventEndpoint(this IEndpointRouteBuilder routes,
        string path) => routes.MapPost(path, async (HttpContext context, [FromServices] EventsProtocol protocol, [FromServices] IAgentProviderEventStore store) =>
    {
        var assertion = await protocol.VerifyRequestAsync(context, EventsTokens.EventType).ConfigureAwait(false);
        if (assertion is null) return Results.Empty;
        using var body = new MemoryStream();
        await context.Request.Body.CopyToAsync(body, context.RequestAborted).ConfigureAwait(false);
        var token = assertion.Token;
        var envelope = new EventEnvelope(assertion.CompactToken, EventsTokens.RequireText(token.Payload, "eid"),
            token.Jti, token.Issuer, EventsTokens.RequireText(token.Payload, "aud"), token.ExpiresAt, body.ToArray());
        EventAcceptance acceptance;
        try { acceptance = store.Accept(envelope, protocol.TokenVerifier.TimeProvider.GetUtcNow()); }
        catch (Exception exception) when (exception is not OperationCanceledException)
        { return AAuthProblemDetails.Create("temporarily_unavailable", "Durable event acceptance failed.", statusCode: 503); }
        if (acceptance.StatusCode != 202)
            return AAuthProblemDetails.Create("event_rejected", statusCode: acceptance.StatusCode);
        return acceptance.RemainingUses is { } remaining
            ? Results.Json(new { remaining_uses = remaining }, statusCode: 202)
            : Results.StatusCode(202);
    });

    /// <summary>
    /// Map a resource subscription endpoint. Resolves the <see cref="EventsProtocol"/> and
    /// <see cref="IResourceEventStore"/> from DI; <paramref name="configure"/> describes the channel.
    /// </summary>
    public static IEndpointConventionBuilder MapAAuthSubscriptionEndpoint(this IEndpointRouteBuilder routes,
        string path, Action<AAuthSubscriptionEndpointOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        var channel = new AAuthSubscriptionEndpointOptions();
        configure(channel);
        var resource = channel.Resource
            ?? routes.ServiceProvider.GetService<Microsoft.Extensions.Options.IOptions<AAuth.AAuthResourceOptions>>()?.Value.Issuer
            ?? throw new InvalidOperationException("AAuthSubscriptionEndpointOptions.Resource is required without AddAAuthResource.");
        ArgumentException.ThrowIfNullOrEmpty(channel.Operation);
        var validateParameters = channel.ValidateParameters
            ?? throw new InvalidOperationException("AAuthSubscriptionEndpointOptions.ValidateParameters is required.");
        return routes.MapSubscriptionCore(path, resource, channel.Operation, channel.ProtectedChannel, validateParameters,
            channel.SubscriptionLifetime);
    }

    private static IEndpointConventionBuilder MapSubscriptionCore(this IEndpointRouteBuilder routes,
        string path, string resource, string operation, bool protectedChannel,
        Func<JsonObject, bool> validateParameters,
        TimeSpan? subscriptionLifetime) => routes.MapPost(path, async (HttpContext context, [FromServices] EventsProtocol protocol, [FromServices] IResourceEventStore store) =>
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
            protocol.TokenVerifier.TimeProvider.GetUtcNow().Add(subscriptionLifetime ?? TimeSpan.FromHours(1)),
            assertion.HttpSigningKey.ComputeJwkThumbprint());
        RegistrationResult registration;
        try { registration = store.Register(subscription, ticket, protocol.TokenVerifier.TimeProvider.GetUtcNow()); }
        catch (Exception exception) when (exception is not OperationCanceledException)
        { return AAuthProblemDetails.Create("temporarily_unavailable", "Durable registration failed.", statusCode: 503); }
        return registration.StatusCode == 200
            ? Results.Json(new { eid = subscription.Eid, account = registration.Subscription!.Account,
                expires_at = registration.Subscription.ExpiresAt })
            : AAuthProblemDetails.Create("registration_rejected", statusCode: registration.StatusCode);
    });
}