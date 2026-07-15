using System;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Discovery;
using AAuth.Errors;
using AAuth.Events.Http;

namespace AAuth.Events.Discovery;

/// <summary>Resolves the current AP event endpoint from agent metadata.</summary>
public sealed class EventEndpointResolver
{
    private readonly MetadataClient _metadata;
    private readonly IEventsUrlPolicy _policy;

    /// <summary>
    /// Creates a resolver using the Events no-redirect transport and default
    /// metadata cache.
    /// </summary>
    public EventEndpointResolver(
        IEventsUrlPolicy? urlPolicy = null,
        HttpMessageHandler? innerHandler = null,
        TimeSpan? cacheTtl = null,
        Func<DateTimeOffset>? clock = null)
    {
        _policy = urlPolicy ?? new DefaultEventsUrlPolicy();
        _metadata = new MetadataClient(
            EventsHttpClientFactory.Create(_policy, innerHandler),
            cacheTtl,
            clock);
    }

    /// <summary>
    /// Creates a resolver around a metadata client. The supplied client should
    /// use <see cref="EventsHttpClientFactory"/>; endpoint policy is still
    /// checked before a value is returned.
    /// </summary>
    public EventEndpointResolver(MetadataClient metadataClient, IEventsUrlPolicy? urlPolicy = null)
    {
        _metadata = metadataClient ?? throw new ArgumentNullException(nameof(metadataClient));
        _policy = urlPolicy ?? new DefaultEventsUrlPolicy();
    }

    /// <summary>Resolves the AP endpoint advertised by current agent metadata.</summary>
    /// <remarks>
    /// The endpoint is deliberately read from metadata on every cache miss; no
    /// endpoint copied from a subscribe token is accepted by this API.
    /// </remarks>
    public async Task<Uri> ResolveAsync(
        string agentProviderIssuer,
        CancellationToken cancellationToken = default)
    {
        var issuer = ValidateIssuer(agentProviderIssuer);
        Uri metadataUrl;
        try
        {
            metadataUrl = MetadataClient.BuildUrl(issuer, AAuthEventsConstants.AgentDwk);
        }
        catch (ArgumentException exception)
        {
            throw DiscoveryFailure("The agent provider issuer is invalid.", exception);
        }

        JsonObject document;
        try
        {
            document = await _metadata.FetchAsync(metadataUrl, cancellationToken).ConfigureAwait(false);
        }
        catch (EventsVerificationException)
        {
            throw;
        }
        catch (AAuthMetadataException exception)
        {
            throw DiscoveryFailure("Agent provider metadata issuer verification failed.", exception);
        }
        catch (HttpRequestException exception)
        {
            throw DiscoveryFailure("Agent provider metadata could not be fetched.", exception);
        }
        catch (JsonException exception)
        {
            throw DiscoveryFailure("Agent provider metadata is not valid JSON.", exception);
        }
        catch (InvalidOperationException exception)
        {
            throw DiscoveryFailure("Agent provider metadata is malformed.", exception);
        }

        var issuerNode = document["issuer"];
        if (issuerNode is not JsonValue issuerValue ||
            !issuerValue.TryGetValue<string>(out var claimedIssuer))
        {
            throw DiscoveryFailure("Agent provider metadata must contain a string issuer.");
        }

        var expectedIssuer = new Uri(issuer).GetLeftPart(UriPartial.Authority);
        if (!string.Equals(claimedIssuer, expectedIssuer, StringComparison.Ordinal))
        {
            throw DiscoveryFailure(
                $"Agent provider metadata issuer '{claimedIssuer ?? "(none)"}' does not match '{expectedIssuer}'.");
        }

        var endpointNode = document[AAuthEventsConstants.EventEndpointMetadata];
        if (endpointNode is not JsonValue endpointValue ||
            !endpointValue.TryGetValue<string>(out var endpointText))
        {
            throw DiscoveryFailure(
                $"Agent provider metadata must contain one string '{AAuthEventsConstants.EventEndpointMetadata}'.");
        }

        Uri endpoint;
        try
        {
            if (string.IsNullOrWhiteSpace(endpointText) ||
                !Uri.TryCreate(endpointText, UriKind.Absolute, out var parsedEndpoint))
            {
                throw DiscoveryFailure("The advertised event endpoint is not an absolute URL.");
            }

            endpoint = parsedEndpoint;
            await _policy.EnsureAllowedAsync(endpoint, cancellationToken).ConfigureAwait(false);
            AAuthEventsMetadata.ValidateEventEndpoint(endpointText);
        }
        catch (EventsMetadataException exception)
        {
            throw DiscoveryFailure("The advertised event endpoint is invalid.", exception);
        }
        catch (EventsVerificationException)
        {
            throw;
        }

        return endpoint;
    }

    /// <summary>Invalidates cached metadata for an agent provider issuer.</summary>
    public void Invalidate(string agentProviderIssuer)
    {
        var issuer = ValidateIssuer(agentProviderIssuer);
        _metadata.Invalidate(MetadataClient.BuildUrl(issuer, AAuthEventsConstants.AgentDwk));
    }

    /// <summary>Invalidates cached metadata for a metadata URL.</summary>
    public void Invalidate(Uri metadataUrl)
    {
        ArgumentNullException.ThrowIfNull(metadataUrl);
        _metadata.Invalidate(metadataUrl);
    }

    private static string ValidateIssuer(string issuer)
    {
        if (string.IsNullOrWhiteSpace(issuer) ||
            !Uri.TryCreate(issuer, UriKind.Absolute, out var uri) ||
            uri.UserInfo.Length != 0 ||
            (uri.Scheme != Uri.UriSchemeHttps &&
             !(uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback)))
        {
            throw DiscoveryFailure("The agent provider issuer must be an absolute trusted URL.");
        }

        return uri.GetLeftPart(UriPartial.Authority).TrimEnd('/');
    }

    private static EventsVerificationException DiscoveryFailure(
        string detail,
        Exception? inner = null) =>
        new(EventsVerificationErrorCode.MetadataFailure, detail, inner);
}
