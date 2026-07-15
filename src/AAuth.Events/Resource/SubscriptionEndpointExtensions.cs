using System.Net.Http;
using AAuth.Events.Http;
using AAuth.Events.Resource;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.AspNetCore.Builder;

/// <summary>Endpoint adapters for public and protected Events registration.</summary>
public static class SubscriptionEndpointExtensions
{
    /// <summary>Maps a channel according to its public/protected descriptor.</summary>
    public static RouteHandlerBuilder MapAAuthSubscriptionRegistration(
        this IEndpointRouteBuilder endpoints,
        SubscriptionChannel channel,
        IAAuthSubscriptionRegistrationHandler handler)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(channel);
        ArgumentNullException.ThrowIfNull(handler);
        Func<HttpContext, Task<IResult>> callback =
            context => InvokeAsync(context, channel, handler);
        return endpoints.MapPost(channel.EndpointPattern, callback);
    }

    /// <summary>Maps a public subscription registration endpoint.</summary>
    public static RouteHandlerBuilder MapAAuthPublicSubscription(
        this IEndpointRouteBuilder endpoints,
        SubscriptionChannel channel,
        IAAuthSubscriptionRegistrationHandler handler)
    {
        ArgumentNullException.ThrowIfNull(channel);
        if (channel.IsProtected)
            throw new ArgumentException("The channel is protected.", nameof(channel));
        return endpoints.MapAAuthSubscriptionRegistration(channel, handler);
    }

    /// <summary>Maps a protected subscription registration endpoint.</summary>
    public static RouteHandlerBuilder MapAAuthProtectedSubscription(
        this IEndpointRouteBuilder endpoints,
        SubscriptionChannel channel,
        IAAuthSubscriptionRegistrationHandler handler)
    {
        if (channel is null || !channel.IsProtected)
            throw new ArgumentException("The channel must be protected.", nameof(channel));
        return endpoints.MapAAuthSubscriptionRegistration(channel, handler);
    }

    /// <summary>Alias for <see cref="MapAAuthSubscriptionRegistration"/>.</summary>
    public static RouteHandlerBuilder MapAAuthSubscription(
        this IEndpointRouteBuilder endpoints,
        SubscriptionChannel channel,
        IAAuthSubscriptionRegistrationHandler handler) =>
        endpoints.MapAAuthSubscriptionRegistration(channel, handler);

    /// <summary>Alias for <see cref="MapAAuthPublicSubscription"/>.</summary>
    public static RouteHandlerBuilder MapAAuthPublicSubscriptionEndpoint(
        this IEndpointRouteBuilder endpoints,
        SubscriptionChannel channel,
        IAAuthSubscriptionRegistrationHandler handler) =>
        endpoints.MapAAuthPublicSubscription(channel, handler);

    /// <summary>Alias for <see cref="MapAAuthProtectedSubscription"/>.</summary>
    public static RouteHandlerBuilder MapAAuthProtectedSubscriptionEndpoint(
        this IEndpointRouteBuilder endpoints,
        SubscriptionChannel channel,
        IAAuthSubscriptionRegistrationHandler handler) =>
        endpoints.MapAAuthProtectedSubscription(channel, handler);

    /// <summary>Alias for <see cref="MapAAuthSubscriptionRegistration"/>.</summary>
    public static RouteHandlerBuilder MapAAuthSubscriptionEndpoint(
        this IEndpointRouteBuilder endpoints,
        SubscriptionChannel channel,
        IAAuthSubscriptionRegistrationHandler handler) =>
        endpoints.MapAAuthSubscriptionRegistration(channel, handler);

    private static async Task<IResult> InvokeAsync(
        HttpContext context,
        SubscriptionChannel channel,
        IAAuthSubscriptionRegistrationHandler handler)
    {
        var values = context.Request.RouteValues.ToDictionary(
            pair => pair.Key, pair => pair.Value?.ToString(), StringComparer.Ordinal);
        values.TryGetValue(channel.TicketRouteValueName, out var ticket);
        if (channel.IsProtected && string.IsNullOrWhiteSpace(ticket))
        {
            return Results.Json(
                new { error = "malformed", error_description = "A protected subscription ticket is required." },
                statusCode: StatusCodes.Status400BadRequest);
        }

        var verifier = context.RequestServices.GetService<SubscriptionRegistrationVerifier>();
        if (verifier is null)
            return Results.StatusCode(StatusCodes.Status500InternalServerError);
        HttpRequestMessage message;
        try
        {
            message = await CreateMessageAsync(
                context, verifier.MaxBodyBytes, context.RequestAborted).ConfigureAwait(false);
        }
        catch (EventsVerificationException ex)
        {
            return Results.Json(new { error = ex.Error.Code.ToString(), error_description = ex.Error.Detail },
                statusCode: VerificationStatus(ex.Error.Code));
        }
        try
        {
            var endpoint = new SubscriptionEndpointContext(channel, values, ticket);
            SubscriptionRegistrationVerification verification;
            try
            {
                verification = await verifier.VerifyAsync(
                    message,
                    channel.ResourceAudience,
                    wirePath: null,
                    context.RequestAborted).ConfigureAwait(false);
            }
            catch (EventsVerificationException ex)
            {
                return Results.Json(new { error = ex.Error.Code.ToString(), error_description = ex.Error.Detail },
                    statusCode: VerificationStatus(ex.Error.Code));
            }

            var result = await handler.RegisterAsync(
                endpoint, verification.Registration, verification.Preferences, context.RequestAborted)
                .ConfigureAwait(false);
            if (result is null)
                return Results.StatusCode(StatusCodes.Status500InternalServerError);
            if (result.Status == SubscriptionRegistrationStatus.Accepted)
            {
                if (result.SelectedEventTypes is null ||
                    result.SelectedEventTypes.Any(type => !channel.AllowedEventTypes.Contains(type, StringComparer.Ordinal)))
                    return Results.Json(new { error = "invalid_registration", error_description = "Selected event types are not allowed by this channel." },
                        statusCode: StatusCodes.Status400BadRequest);
                return Results.Json(new { event_types = result.SelectedEventTypes }, statusCode: StatusCodes.Status200OK);
            }
            return Results.Json(new { error = result.Status.ToString().ToLowerInvariant(), error_description = result.Detail },
                statusCode: (int)result.Status);
        }
        finally
        {
            message.Dispose();
        }
    }

    private static async Task<HttpRequestMessage> CreateMessageAsync(
        HttpContext context, int maxBodyBytes, CancellationToken cancellationToken)
    {
        var request = context.Request;
        var uri = new Uri($"{request.Scheme}://{request.Host}{request.PathBase}{request.Path}{request.QueryString}");
        var message = new HttpRequestMessage(new HttpMethod(request.Method), uri);
        foreach (var header in request.Headers)
            if (!string.Equals(header.Key, "Content-Length", StringComparison.OrdinalIgnoreCase))
                message.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());

        using var output = new MemoryStream();
        var buffer = new byte[81920];
        var total = 0;
        while (true)
        {
            var read = await request.Body.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (read == 0) break;
            if (read > maxBodyBytes - total)
                throw new EventsVerificationException(
                    EventsVerificationErrorCode.BodyTooLarge,
                    $"Request body exceeds the {maxBodyBytes} byte limit.");
            output.Write(buffer, 0, read);
            total += read;
        }
        var bytes = output.ToArray();
        if (bytes.Length != 0 || request.ContentType is not null || request.ContentLength is > 0)
        {
            message.Content = new ByteArrayContent(bytes);
            if (!string.IsNullOrWhiteSpace(request.ContentType))
                message.Content.Headers.TryAddWithoutValidation("Content-Type", request.ContentType);
        }
        return message;
    }

    private static int VerificationStatus(EventsVerificationErrorCode code) =>
        code switch
        {
            EventsVerificationErrorCode.WrongAudience or EventsVerificationErrorCode.WrongResource
                => StatusCodes.Status403Forbidden,
            EventsVerificationErrorCode.InvalidSignature or EventsVerificationErrorCode.UnknownKey
                or EventsVerificationErrorCode.ExpiredToken or EventsVerificationErrorCode.InvalidToken
                => StatusCodes.Status401Unauthorized,
            _ => StatusCodes.Status400BadRequest,
        };
}
