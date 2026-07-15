using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;

namespace AAuth.Events.Discovery;

/// <summary>Composes and validates AAuth Events discovery metadata.</summary>
public static class AAuthEventsMetadata
{
    /// <summary>
    /// Adds an <c>event_endpoint</c> member to an already composed metadata
    /// document. Existing typed metadata members are never replaced.
    /// </summary>
    /// <param name="metadata">The caller-owned metadata document.</param>
    /// <param name="eventEndpoint">The absolute endpoint advertised by the AP.</param>
    /// <returns>The same metadata document, for fluent composition.</returns>
    /// <exception cref="EventsMetadataException">
    /// Thrown when the endpoint is malformed or conflicts with an existing value.
    /// </exception>
    public static JsonObject AddEventEndpoint(JsonObject metadata, string eventEndpoint)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        var endpoint = ValidateEventEndpoint(eventEndpoint);

        if (metadata.TryGetPropertyValue(AAuthEventsConstants.EventEndpointMetadata, out var existing))
        {
            if (existing is not JsonValue value ||
                !value.TryGetValue<string>(out var existingEndpoint) ||
                !string.Equals(existingEndpoint, endpoint.AbsoluteUri, StringComparison.Ordinal))
            {
                throw new EventsMetadataException(
                    $"Metadata contains a conflicting '{AAuthEventsConstants.EventEndpointMetadata}' value.");
            }

            return metadata;
        }

        metadata[AAuthEventsConstants.EventEndpointMetadata] = endpoint.AbsoluteUri;
        return metadata;
    }

    /// <summary>Alias for <see cref="AddEventEndpoint"/>.</summary>
    public static JsonObject ComposeAgentMetadata(JsonObject metadata, string eventEndpoint) =>
        AddEventEndpoint(metadata, eventEndpoint);

    /// <summary>
    /// Returns a new ordinal vocabulary map containing the AsyncAPI discovery
    /// entry. The input map is never mutated.
    /// </summary>
    /// <param name="existing">Existing caller-owned vocabulary entries.</param>
    /// <param name="endpoint">The absolute AsyncAPI document endpoint.</param>
    public static IReadOnlyDictionary<string, string> WithAsyncApiVocabulary(
        IReadOnlyDictionary<string, string>? existing,
        string endpoint)
    {
        var validatedEndpoint = ValidateVocabularyEndpoint(endpoint);
        var result = new Dictionary<string, string>(StringComparer.Ordinal);

        if (existing is not null)
        {
            foreach (var pair in existing)
            {
                if (string.IsNullOrWhiteSpace(pair.Key) ||
                    string.IsNullOrWhiteSpace(pair.Value))
                {
                    throw new EventsMetadataException(
                        "R3 vocabulary names and discovery endpoints must not be blank.");
                }

                if (!result.TryAdd(pair.Key, pair.Value))
                {
                    throw new EventsMetadataException($"Duplicate vocabulary '{pair.Key}'.");
                }
            }
        }

        if (result.TryGetValue(AAuthEventsConstants.AsyncApiVocabulary, out var current))
        {
            if (!string.Equals(current, validatedEndpoint, StringComparison.Ordinal))
            {
                throw new EventsMetadataException(
                    $"The AsyncAPI vocabulary already points to '{current}'.");
            }
        }
        else
        {
            result.Add(AAuthEventsConstants.AsyncApiVocabulary, validatedEndpoint);
        }

        return result;
    }

    /// <summary>
    /// Serializes a complete, caller-composed vocabulary map as the value of
    /// <c>r3_vocabularies</c>.
    /// </summary>
    public static JsonObject ToVocabulariesJson(IReadOnlyDictionary<string, string> vocabularies)
    {
        ArgumentNullException.ThrowIfNull(vocabularies);
        var result = new JsonObject();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var pair in vocabularies)
        {
            if (string.IsNullOrWhiteSpace(pair.Key) ||
                string.IsNullOrWhiteSpace(pair.Value) ||
                !seen.Add(pair.Key))
            {
                throw new EventsMetadataException(
                    "R3 vocabulary names and discovery endpoints must be non-empty and unique.");
            }

            result[pair.Key] = pair.Value;
        }

        return result;
    }

    /// <summary>Serializes one AsyncAPI vocabulary entry.</summary>
    public static JsonObject ToVocabulariesJson(string endpoint) =>
        ToVocabulariesJson(WithAsyncApiVocabulary(null, endpoint));

    /// <summary>Validates an Events endpoint without making a network request.</summary>
    public static Uri ValidateEventEndpoint(string endpoint)
    {
        if (string.IsNullOrWhiteSpace(endpoint) ||
            !Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) ||
            uri.UserInfo.Length != 0 ||
            (uri.Scheme != Uri.UriSchemeHttps &&
             !(uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback)))
        {
            throw new EventsMetadataException(
                "Events discovery endpoints must be absolute HTTPS URLs, except loopback HTTP URLs.");
        }

        return uri;
    }

    private static string ValidateVocabularyEndpoint(string endpoint)
    {
        if (string.IsNullOrWhiteSpace(endpoint) ||
            !Uri.TryCreate(endpoint, UriKind.RelativeOrAbsolute, out _))
        {
            throw new EventsMetadataException(
                "R3 vocabulary discovery endpoints must be valid, non-empty URI values.");
        }

        return endpoint;
    }
}

/// <summary>Typed failure raised for malformed or conflicting Events metadata.</summary>
public sealed class EventsMetadataException : Exception
{
    /// <summary>Creates a metadata composition failure.</summary>
    public EventsMetadataException(string message)
        : base(message)
    {
    }
}
