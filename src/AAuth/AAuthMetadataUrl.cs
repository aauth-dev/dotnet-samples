using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json.Nodes;
using AAuth.Discovery;

namespace AAuth;

internal enum AAuthUrlKind
{
    Endpoint,
    Jwks,
    Informational,
    Callback,
}

internal static class AAuthMetadataUrl
{
    private static readonly IReadOnlyDictionary<string, AAuthUrlKind> FieldRules =
        new Dictionary<string, AAuthUrlKind>(StringComparer.Ordinal)
        {
            ["jwks_uri"] = AAuthUrlKind.Jwks,
            ["auth_token_endpoint"] = AAuthUrlKind.Endpoint,
            ["person_token_endpoint"] = AAuthUrlKind.Endpoint,
            ["authorization_endpoint"] = AAuthUrlKind.Endpoint,
            ["mission_endpoint"] = AAuthUrlKind.Endpoint,
            ["mission_control_endpoint"] = AAuthUrlKind.Endpoint,
            ["permission_endpoint"] = AAuthUrlKind.Endpoint,
            ["audit_endpoint"] = AAuthUrlKind.Endpoint,
            ["callback_endpoint"] = AAuthUrlKind.Callback,
            ["interaction_endpoint"] = AAuthUrlKind.Endpoint,
            ["revocation_endpoint"] = AAuthUrlKind.Endpoint,
            ["event_endpoint"] = AAuthUrlKind.Endpoint,
            ["logo_uri"] = AAuthUrlKind.Informational,
            ["logo_dark_uri"] = AAuthUrlKind.Informational,
            ["documentation_uri"] = AAuthUrlKind.Informational,
            ["tos_uri"] = AAuthUrlKind.Informational,
            ["policy_uri"] = AAuthUrlKind.Informational,
        };

    internal static IEnumerable<string> ReservedMetadataFields => FieldRules.Keys.Concat([
        "issuer",
        "name",
        "description",
        "access_mode",
        "scope_descriptions",
        "signature_window",
        AAuthConstants.MetadataFields.AdditionalSignatureComponents,
        "scopes_supported",
        "localhost_callback_allowed",
    ]);

    internal static void ValidateField(AAuthEgressPolicy policy, string field, JsonNode? node, string metadataIdentifier)
    {
        if (!FieldRules.TryGetValue(field, out var kind)) return;
        if (node is not JsonValue value || !value.TryGetValue<string>(out var url) || string.IsNullOrWhiteSpace(url))
            throw new HttpRequestException($"Metadata {field} must be a nonempty URL string.");
        Validate(policy, url, kind, metadataIdentifier);
    }

    internal static void ValidateDocument(AAuthEgressPolicy policy, JsonObject document, string metadataIdentifier)
    {
        foreach (var (field, node) in document)
        {
            ValidateField(policy, field, node, metadataIdentifier);
        }
        if (document.TryGetPropertyValue("localhost_callback_allowed", out var callbackAllowed)
            && (callbackAllowed is not JsonValue value || !value.TryGetValue<bool>(out _)))
        {
            throw new HttpRequestException("Metadata localhost_callback_allowed must be a JSON boolean.");
        }
    }

    internal static void ValidateOptional(AAuthEgressPolicy policy, string? value, AAuthUrlKind kind,
        string metadataIdentifier, string propertyName)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        try
        {
            Validate(policy, value, kind, metadataIdentifier);
        }
        catch (Exception exception) when (exception is HttpRequestException or ArgumentException)
        {
            throw new InvalidOperationException($"{propertyName} must be a valid {kind.ToString().ToLowerInvariant()} URL.", exception);
        }
    }

    internal static void ValidateRequired(AAuthEgressPolicy policy, string? value, AAuthUrlKind kind,
        string metadataIdentifier, string propertyName)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new InvalidOperationException($"{propertyName} must be set.");
        ValidateOptional(policy, value, kind, metadataIdentifier, propertyName);
    }

    internal static void Validate(AAuthEgressPolicy policy, string value, AAuthUrlKind kind, string metadataIdentifier)
    {
        if (kind == AAuthUrlKind.Jwks)
        {
            policy.ValidateJwksUrl(value, metadataIdentifier);
            return;
        }

        var uri = policy.ValidateUrl(value, endpoint: kind is AAuthUrlKind.Endpoint or AAuthUrlKind.Callback);
        if (kind == AAuthUrlKind.Informational && uri.Scheme != "https")
            throw new HttpRequestException("Informational metadata URLs must use HTTPS.");
    }

    internal static void ValidatePath(string? path, string propertyName, List<string> failures)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            failures.Add($"{propertyName} must not be empty.");
            return;
        }
        if (!path.StartsWith("/", StringComparison.Ordinal) || path.Contains('?') || path.Contains('#')
            || path.Contains('\\') || path.Any(character => character <= 32 || character >= 127))
        {
            failures.Add($"{propertyName} must be an app-rooted path without query, fragment, backslash or control characters.");
        }
    }

    internal static void ValidateDerivedEndpoint(AAuthEgressPolicy policy, string issuer, string? path,
        string propertyName, List<string> failures)
    {
        ValidatePath(path, propertyName, failures);
        if (string.IsNullOrWhiteSpace(path)) return;
        try
        {
            Validate(policy, issuer.TrimEnd('/') + "/" + path.TrimStart('/'), AAuthUrlKind.Endpoint, issuer);
        }
        catch (Exception exception) when (exception is HttpRequestException or ArgumentException or InvalidOperationException)
        {
            failures.Add($"{propertyName} derives an invalid endpoint URL: {exception.Message}");
        }
    }
}
