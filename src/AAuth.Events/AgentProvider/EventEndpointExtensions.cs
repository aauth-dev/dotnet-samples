using System.Net.Http;
using System.Text.Json;
using AAuth.Events;
using AAuth.Events.AgentProvider;
using AAuth.Events.Http;
using AAuth.Events.Tokens;
using AAuth.HttpSig;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.AspNetCore.Builder;

/// <summary>Options for the Agent Provider event endpoint.</summary>
public sealed class AAuthEventsAgentProviderEndpointOptions
{
    /// <summary>Maximum event payload size.</summary>
    public int MaxBodyBytes { get; set; } = AAuthEventsConstants.DefaultMaxBodyBytes;
    /// <summary>Discovery-backed Events JWT resolver.</summary>
    public EventsJwtKeyResolver? JwtKeyResolver { get; set; }
    /// <summary>Events event HTTP profile verifier.</summary>
    public EventsHttpMessageVerifier? HttpMessageVerifier { get; set; }
    /// <summary>Receipt clock used after envelope verification.</summary>
    public Func<DateTimeOffset> Clock { get; set; } = static () => DateTimeOffset.UtcNow;
}

/// <summary>Maps the AAuth Events AP delivery endpoint.</summary>
public static class EventEndpointExtensions
{
    /// <summary>
    /// Maps a POST endpoint that verifies an event envelope and delegates all
    /// subscription lookup, replay, expiry, authorization, and use accounting to
    /// one durable store operation.
    /// </summary>
    public static IEndpointConventionBuilder MapAAuthEventEndpoint(
        this IEndpointRouteBuilder endpoints,
        string pattern = "/events",
        Action<AAuthEventsAgentProviderEndpointOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        var registered = endpoints.ServiceProvider.GetService<
            Microsoft.Extensions.DependencyInjection.AAuthEventsAgentProviderOptions>();
        var options = endpoints.ServiceProvider.GetService<AAuthEventsAgentProviderEndpointOptions>()
            ?? new AAuthEventsAgentProviderEndpointOptions
            {
                JwtKeyResolver = registered?.JwtKeyResolver,
                HttpMessageVerifier = registered?.HttpMessageVerifier,
                MaxBodyBytes = registered?.MaxBodyBytes ?? AAuthEventsConstants.DefaultMaxBodyBytes,
                Clock = registered?.Clock ?? (() => DateTimeOffset.UtcNow),
            };
        if (configure is not null)
        {
            var configured = new AAuthEventsAgentProviderEndpointOptions
            {
                MaxBodyBytes = options.MaxBodyBytes,
                JwtKeyResolver = options.JwtKeyResolver,
                HttpMessageVerifier = options.HttpMessageVerifier,
                Clock = options.Clock,
            };
            configure(configured);
            options = configured;
        }

        var store = endpoints.ServiceProvider.GetRequiredService<IAAuthAgentProviderEventStore>();
        var resolver = options.JwtKeyResolver
            ?? endpoints.ServiceProvider.GetService<EventsJwtKeyResolver>()
            ?? throw new InvalidOperationException(
                "MapAAuthEventEndpoint requires an EventsJwtKeyResolver in DI or endpoint options.");
        var verifier = options.HttpMessageVerifier
            ?? endpoints.ServiceProvider.GetService<EventsHttpMessageVerifier>()
            ?? new EventsHttpMessageVerifier { MaxBodyBytes = options.MaxBodyBytes };

        return endpoints.MapPost(pattern, context =>
            HandleAsync(context, store, resolver, verifier, options.Clock));
    }

    /// <summary>Maps an endpoint with explicitly supplied verification services.</summary>
    public static IEndpointConventionBuilder MapAAuthEventEndpoint(
        this IEndpointRouteBuilder endpoints,
        string pattern,
        EventsJwtKeyResolver resolver,
        EventsHttpMessageVerifier verifier)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(endpoints);
        var store = endpoints.ServiceProvider.GetRequiredService<IAAuthAgentProviderEventStore>();
        return endpoints.MapPost(pattern, context =>
            HandleAsync(context, store, resolver, verifier, static () => DateTimeOffset.UtcNow));
    }

    private static async Task HandleAsync(
        HttpContext context,
        IAAuthAgentProviderEventStore store,
        EventsJwtKeyResolver resolver,
        EventsHttpMessageVerifier verifier,
        Func<DateTimeOffset> clock)
    {
        try
        {
            using var request = await ToHttpRequestMessageAsync(context, context.RequestAborted)
                .ConfigureAwait(false);
            var resolution = await resolver.ResolveRequestAsync(
                request, EventsTokenKind.Event, expectedAudience: null, context.RequestAborted)
                .ConfigureAwait(false);
            var verified = await verifier.VerifyAsync(
                request,
                resolution.HttpSignatureKey,
                EventsHttpProfile.EventJson,
                cancellationToken: context.RequestAborted).ConfigureAwait(false);
            var claims = EventTokenClaims.Read(resolution.VerifiedToken);
            var compactToken = SignatureKeyHeader.GetJwt(verified.SignatureKey)
                ?? throw new EventsVerificationException(
                    EventsVerificationErrorCode.InvalidToken,
                    "Signature-Key does not contain a compact event token.");
            var digest = EventsRequestBody.GetSha256Digest(request);
            var contentType = request.Content?.Headers.ContentType?.ToString();
            var incoming = new IncomingEvent(
                compactToken,
                claims,
                verified.Body,
                contentType,
                digest,
                clock());

            // This is deliberately the only store call. The store owns the
            // transaction that checks resource/audience/expiry and increments uses.
            var result = await store.AcceptEventAsync(incoming, context.RequestAborted)
                .ConfigureAwait(false);
            await WriteResultAsync(context.Response, result, context.RequestAborted)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            throw;
        }
        catch (EventsVerificationException ex)
        {
            await WriteStatusAsync(context.Response, MapVerificationStatus(ex.Error), context.RequestAborted)
                .ConfigureAwait(false);
        }
        catch (FormatException ex)
        {
            await WriteStatusAsync(context.Response, StatusCodes.Status400BadRequest, context.RequestAborted)
                .ConfigureAwait(false);
            _ = ex;
        }
    }

    private static async Task WriteResultAsync(
        HttpResponse response,
        EventAcceptanceResult result,
        CancellationToken cancellationToken)
    {
        var status = result.Outcome switch
        {
            EventAcceptanceOutcome.Accepted or EventAcceptanceOutcome.AlreadyAccepted =>
                StatusCodes.Status202Accepted,
            EventAcceptanceOutcome.UnknownSubscription or EventAcceptanceOutcome.ExpiredSubscription =>
                StatusCodes.Status404NotFound,
            EventAcceptanceOutcome.WrongResource or EventAcceptanceOutcome.WrongAudience =>
                StatusCodes.Status403Forbidden,
            EventAcceptanceOutcome.Exhausted => StatusCodes.Status429TooManyRequests,
            _ => StatusCodes.Status500InternalServerError,
        };
        response.StatusCode = status;
        if (status != StatusCodes.Status202Accepted || result.RemainingUses is null)
            return;

        response.ContentType = "application/json";
        await response.WriteAsync(
            JsonSerializer.Serialize(new { remaining_uses = result.RemainingUses.Value }),
            cancellationToken).ConfigureAwait(false);
    }

    private static Task WriteStatusAsync(
        HttpResponse response,
        int status,
        CancellationToken cancellationToken)
    {
        response.StatusCode = status;
        return Task.CompletedTask;
    }

    private static int MapVerificationStatus(EventsVerificationError error)
    {
        if (error.Code is EventsVerificationErrorCode.WrongAudience or EventsVerificationErrorCode.WrongResource)
            return StatusCodes.Status403Forbidden;
        if (error.Code is EventsVerificationErrorCode.MalformedRequest or
            EventsVerificationErrorCode.BodyTooLarge or
            EventsVerificationErrorCode.InvalidContentDigest or
            EventsVerificationErrorCode.ContentDigestMismatch)
            return StatusCodes.Status400BadRequest;
        if (error.Code == EventsVerificationErrorCode.InvalidToken &&
            (error.Detail.Contains("malformed", StringComparison.OrdinalIgnoreCase) ||
             error.Detail.Contains("missing", StringComparison.OrdinalIgnoreCase) ||
             error.Detail.Contains("compact", StringComparison.OrdinalIgnoreCase)))
            return StatusCodes.Status400BadRequest;
        return StatusCodes.Status401Unauthorized;
    }

    private static async Task<HttpRequestMessage> ToHttpRequestMessageAsync(
        HttpContext context,
        CancellationToken cancellationToken)
    {
        var request = context.Request;
        var uri = new Uri(
            $"{request.Scheme}://{request.Host}{request.PathBase}{request.Path}{request.QueryString}",
            UriKind.Absolute);
        var message = new HttpRequestMessage(new HttpMethod(request.Method), uri);
        foreach (var header in request.Headers)
            if (!message.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray()))
                message.Content ??= new StreamContent(Stream.Null);

        if (request.ContentLength is not null ||
            request.Headers.ContainsKey("Transfer-Encoding") ||
            request.Headers.ContainsKey("Content-Type") ||
            request.Headers.ContainsKey("Content-Digest"))
        {
            message.Content = new StreamContent(request.Body);
            foreach (var header in request.Headers)
            {
                if (header.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) ||
                    header.Key.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase))
                    continue;
                message.Content.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
            }
        }
        await Task.CompletedTask.ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return message;
    }
}
