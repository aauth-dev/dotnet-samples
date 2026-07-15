using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace AAuth.Events.Discovery;

/// <summary>Validates only the AAuth declarations in an AsyncAPI 3 document.</summary>
public static class AsyncApiAAuthValidator
{
    /// <summary>Validates a parsed AsyncAPI document.</summary>
    public static AsyncApiAAuthValidationResult Validate(JsonObject document)
    {
        ArgumentNullException.ThrowIfNull(document);
        var diagnostics = new List<AsyncApiAAuthDiagnostic>();

        if (!StringEquals(document["asyncapi"], AAuthEventsConstants.AsyncApiVersion))
        {
            diagnostics.Add(Error(
                AsyncApiAAuthDiagnosticCode.InvalidRootVersion,
                "asyncapi must be 3.0.0.",
                "$.asyncapi"));
        }

        var schemes = (document["components"] as JsonObject)?["securitySchemes"] as JsonObject;
        var subscribeScheme = schemes?[AAuthEventsConstants.SubscribeSecurityScheme] as JsonObject;
        if (subscribeScheme is null)
        {
            diagnostics.Add(Error(
                AsyncApiAAuthDiagnosticCode.MissingSubscribeSecurityScheme,
                "components.securitySchemes.aauth_subscribe is required.",
                "$.components.securitySchemes.aauth_subscribe"));
        }
        else
        {
            if (!StringEquals(subscribeScheme["type"], AAuthEventsConstants.SubscribeSecuritySchemeType))
            {
                diagnostics.Add(Error(
                    AsyncApiAAuthDiagnosticCode.WrongSubscribeSecurityScheme,
                    "aauth_subscribe.type must be http.",
                    "$.components.securitySchemes.aauth_subscribe.type"));
            }

            if (!StringEquals(subscribeScheme["scheme"], AAuthEventsConstants.SubscribeSecuritySchemeName))
            {
                diagnostics.Add(Error(
                    AsyncApiAAuthDiagnosticCode.WrongSubscribeSecurityScheme,
                    "aauth_subscribe.scheme must be aauth-subscribe.",
                    "$.components.securitySchemes.aauth_subscribe.scheme"));
            }
        }

        if (document["operations"] is JsonObject operations)
        {
            var channels = document["channels"] as JsonObject;
            foreach (var (name, node) in operations)
            {
                if (node is not JsonObject operation)
                {
                    diagnostics.Add(Error(
                        AsyncApiAAuthDiagnosticCode.MalformedOperation,
                        "Each operation must be an object.",
                        $"$.operations.{name}"));
                    continue;
                }

                var channel = ResolveChannel(operation["channel"], channels);
                var channelPath = $"$.operations.{name}.channel";
                if (channel is null)
                {
                    diagnostics.Add(Error(
                        AsyncApiAAuthDiagnosticCode.MissingChannel,
                        "Each operation must reference a channel object.",
                        channelPath));
                    continue;
                }

                var isProtected = IsProtectedChannel(channel);
                var security = operation["security"];
                if (isProtected)
                {
                    if (security is not null && security is not JsonArray { Count: 0 })
                    {
                        diagnostics.Add(Error(
                            AsyncApiAAuthDiagnosticCode.ProtectedOperationSecured,
                            "Protected-ticket operations must not declare a security requirement.",
                            $"$.operations.{name}.security"));
                    }

                    if (!HasProtectedTicketAnnotation(channel))
                    {
                        diagnostics.Add(Error(
                            AsyncApiAAuthDiagnosticCode.MissingProtectedTicketAnnotation,
                            "Protected-ticket channels must describe the prior authenticated call.",
                            "$.channels"));
                    }
                }
                else if (!HasSubscribeSecurityRequirement(security))
                {
                    diagnostics.Add(Error(
                        AsyncApiAAuthDiagnosticCode.PublicOperationSecurityMissing,
                        "Public operations must declare security: - aauth_subscribe: [].",
                        $"$.operations.{name}.security"));
                }
            }
        }

        return new AsyncApiAAuthValidationResult(diagnostics);
    }

    /// <summary>Validates an AsyncAPI document encoded as JSON.</summary>
    public static AsyncApiAAuthValidationResult Validate(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return new AsyncApiAAuthValidationResult(new[]
            {
                Error(AsyncApiAAuthDiagnosticCode.InvalidDocument, "The document is empty.", "$"),
            });
        }

        try
        {
            var document = JsonNode.Parse(json) as JsonObject;
            return document is null
                ? new AsyncApiAAuthValidationResult(new[]
                {
                    Error(AsyncApiAAuthDiagnosticCode.InvalidDocument, "The document must be a JSON object.", "$"),
                })
                : Validate(document);
        }
        catch (JsonException exception)
        {
            return new AsyncApiAAuthValidationResult(new[]
            {
                Error(AsyncApiAAuthDiagnosticCode.InvalidDocument, exception.Message, "$"),
            });
        }
    }

    /// <summary>Throws a typed exception when the AAuth declarations are invalid.</summary>
    public static void EnsureValid(JsonObject document)
    {
        var result = Validate(document);
        if (!result.IsValid)
        {
            throw new AsyncApiAAuthValidationException(result);
        }
    }

    private static JsonObject? ResolveChannel(JsonNode? node, JsonObject? channels)
    {
        if (node is JsonObject inline)
        {
            if (inline["$ref"] is JsonValue referenceValue &&
                referenceValue.TryGetValue<string>(out var inlineReference) &&
                channels is not null &&
                inlineReference.StartsWith("#/channels/", StringComparison.Ordinal))
            {
                return channels[inlineReference["#/channels/".Length..]] as JsonObject;
            }

            return inline;
        }
        if (node is not JsonValue value ||
            !value.TryGetValue<string>(out var reference) ||
            !reference.StartsWith("#/channels/", StringComparison.Ordinal) ||
            channels is null)
            return null;
        var name = reference["#/channels/".Length..];
        return channels[name] as JsonObject;
    }

    private static bool IsProtectedChannel(JsonObject channel)
    {
        var address = StringValue(channel["address"]);
        return address?.Contains('{', StringComparison.Ordinal) == true ||
               channel["parameters"] is JsonObject parameters && parameters.Count > 0;
    }

    private static bool HasProtectedTicketAnnotation(JsonObject channel)
    {
        if (channel["x-aauth-protected-ticket"] is JsonValue marker &&
            marker.TryGetValue<bool>(out var marked) && marked)
            return true;

        var description = StringValue(channel["description"]);
        if (string.IsNullOrWhiteSpace(description))
            return false;

        var text = description.ToLowerInvariant();
        return (text.Contains("ticket", StringComparison.Ordinal) ||
                text.Contains("subscription url", StringComparison.Ordinal)) &&
               (text.Contains("prior", StringComparison.Ordinal) ||
                text.Contains("previous", StringComparison.Ordinal) ||
                text.Contains("authenticated", StringComparison.Ordinal) ||
                text.Contains("authorized", StringComparison.Ordinal));
    }

    private static bool HasSubscribeSecurityRequirement(JsonNode? security)
    {
        if (security is not JsonArray requirements || requirements.Count == 0)
            return false;

        foreach (var requirement in requirements)
        {
            if (requirement is JsonObject map &&
                map.TryGetPropertyValue(AAuthEventsConstants.SubscribeSecurityScheme, out var scopes) &&
                (scopes is null || scopes is JsonArray))
                return true;
        }

        return false;
    }

    private static bool StringEquals(JsonNode? node, string expected) =>
        node is JsonValue value &&
        value.TryGetValue<string>(out var actual) &&
        string.Equals(actual, expected, StringComparison.Ordinal);

    private static string? StringValue(JsonNode? node) =>
        node is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;

    private static AsyncApiAAuthDiagnostic Error(
        AsyncApiAAuthDiagnosticCode code,
        string message,
        string path) => new(code, message, path);
}

/// <summary>Stable diagnostic categories produced by the focused validator.</summary>
public enum AsyncApiAAuthDiagnosticCode
{
    InvalidDocument,
    InvalidRootVersion,
    MissingSubscribeSecurityScheme,
    WrongSubscribeSecurityScheme,
    MalformedOperation,
    MissingChannel,
    PublicOperationSecurityMissing,
    ProtectedOperationSecured,
    MissingProtectedTicketAnnotation,
}

/// <summary>A typed AsyncAPI AAuth validation diagnostic.</summary>
public sealed record AsyncApiAAuthDiagnostic(
    AsyncApiAAuthDiagnosticCode Code,
    string Message,
    string Path);

/// <summary>Result of focused AsyncAPI AAuth declaration validation.</summary>
public sealed class AsyncApiAAuthValidationResult
{
    /// <summary>Creates a validation result.</summary>
    public AsyncApiAAuthValidationResult(IReadOnlyList<AsyncApiAAuthDiagnostic> diagnostics)
    {
        Diagnostics = diagnostics ?? throw new ArgumentNullException(nameof(diagnostics));
    }

    /// <summary>Whether all required AAuth declarations are valid.</summary>
    public bool IsValid => Diagnostics.Count == 0;

    /// <summary>Structured validation diagnostics.</summary>
    public IReadOnlyList<AsyncApiAAuthDiagnostic> Diagnostics { get; }

    /// <summary>Alias for <see cref="Diagnostics"/>.</summary>
    public IReadOnlyList<AsyncApiAAuthDiagnostic> Errors => Diagnostics;

    /// <summary>Alias for <see cref="IsValid"/>.</summary>
    public bool Success => IsValid;
}

/// <summary>Thrown by <see cref="AsyncApiAAuthValidator.EnsureValid"/>.</summary>
public sealed class AsyncApiAAuthValidationException : Exception
{
    /// <summary>Creates a validation exception.</summary>
    public AsyncApiAAuthValidationException(AsyncApiAAuthValidationResult result)
        : base("The AsyncAPI document does not contain valid AAuth declarations.")
    {
        Result = result ?? throw new ArgumentNullException(nameof(result));
    }

    /// <summary>The failed validation result.</summary>
    public AsyncApiAAuthValidationResult Result { get; }
}
