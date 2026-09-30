using System;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Discovery;

/// <summary>
/// Parsed Person Server or Access Server metadata document.
/// Agent-side model for discovered endpoints.
/// </summary>
public sealed class ServerMetadata
{
    /// <summary>The issuer URL.</summary>
    public required string Issuer { get; init; }

    /// <summary>JWKS URI for key resolution.</summary>
    public required string JwksUri { get; init; }

    /// <summary>Optional human-readable name (<c>name</c>).</summary>
    public string? Name { get; init; }

    /// <summary>
    /// Optional Markdown <c>description</c> for display to users. Server-supplied,
    /// untrusted content: consumers MUST sanitize it before display.
    /// </summary>
    public string? Description { get; init; }

    /// <summary>Optional logo URL (<c>logo_uri</c>).</summary>
    public string? LogoUri { get; init; }

    /// <summary>Optional dark-background logo URL (<c>logo_dark_uri</c>).</summary>
    public string? LogoDarkUri { get; init; }

    /// <summary>Optional developer-documentation URL (<c>documentation_uri</c>).</summary>
    public string? DocumentationUri { get; init; }

    /// <summary>Optional terms-of-service URL (<c>tos_uri</c>).</summary>
    public string? TosUri { get; init; }

    /// <summary>Optional privacy-policy URL (<c>policy_uri</c>).</summary>
    public string? PolicyUri { get; init; }

    /// <summary>Auth token endpoint (<c>auth_token_endpoint</c>, required for PS/AS).</summary>
    public string? AuthTokenEndpoint { get; init; }

    /// <summary>Person token endpoint (<c>person_token_endpoint</c>, required for PS).</summary>
    public string? PersonTokenEndpoint { get; init; }

    /// <summary>Revocation endpoint (optional).</summary>
    public string? RevocationEndpoint { get; init; }

    /// <summary>Mission endpoint (optional, PS only) — §Person Server Metadata.</summary>
    public string? MissionEndpoint { get; init; }

    /// <summary>
    /// Permission endpoint (optional, PS only). Where agents request permission
    /// for actions not governed by a remote resource (§Permission Endpoint).
    /// </summary>
    public string? PermissionEndpoint { get; init; }

    /// <summary>
    /// Audit endpoint (optional, PS only). Where agents log actions performed
    /// within a mission context (§Audit Endpoint).
    /// </summary>
    public string? AuditEndpoint { get; init; }

    /// <summary>Interaction endpoint (optional, PS only) — §Interaction Endpoint.</summary>
    public string? InteractionEndpoint { get; init; }

    /// <summary>Parse a metadata JSON document into a <see cref="ServerMetadata"/>.</summary>
    public static ServerMetadata FromJson(JsonObject doc)
    {
        ArgumentNullException.ThrowIfNull(doc);
        return new ServerMetadata
        {
            Issuer = (string?)doc["issuer"] ?? throw new InvalidOperationException("Metadata missing 'issuer'."),
            JwksUri = (string?)doc["jwks_uri"] ?? throw new InvalidOperationException("Metadata missing 'jwks_uri'."),
            Name = (string?)doc["name"],
            Description = (string?)doc["description"],
            LogoUri = (string?)doc["logo_uri"],
            LogoDarkUri = (string?)doc["logo_dark_uri"],
            DocumentationUri = (string?)doc["documentation_uri"],
            TosUri = (string?)doc["tos_uri"],
            PolicyUri = (string?)doc["policy_uri"],
            AuthTokenEndpoint = (string?)doc["auth_token_endpoint"],
            PersonTokenEndpoint = (string?)doc["person_token_endpoint"],
            RevocationEndpoint = (string?)doc["revocation_endpoint"],
            MissionEndpoint = (string?)doc["mission_endpoint"],
            PermissionEndpoint = (string?)doc["permission_endpoint"],
            AuditEndpoint = (string?)doc["audit_endpoint"],
            InteractionEndpoint = (string?)doc["interaction_endpoint"],
        };
    }
}

/// <summary>
/// Parsed resource metadata document. Agent-side model.
/// </summary>
public sealed class ResourceMetadata
{
    /// <summary>The resource issuer URL.</summary>
    public required string Issuer { get; init; }

    /// <summary>
    /// JWKS URI for key resolution. Optional in draft-02: REQUIRED only when the
    /// resource issues resource tokens or makes signed calls; an identity-only
    /// resource that only verifies agent signatures MAY omit it (§Resource Metadata).
    /// </summary>
    public string? JwksUri { get; init; }

    /// <summary>
    /// The credential flow the resource expects — one of <c>agent-token</c>,
    /// <c>person-token</c>, <c>session-token</c>, <c>auth-token</c>, or R3's <c>per-call</c> (see
    /// <see cref="AAuthConstants.AccessModes"/>). Advisory: the runtime
    /// <c>AAuth-Requirement</c> remains authoritative. <see langword="null"/> when
    /// the document omits it or carries an unrecognized value, both of which
    /// agents treat as no declaration (§Resource Metadata).
    /// </summary>
    public string? AccessMode { get; init; }

    /// <summary>Human-readable name (<c>name</c>).</summary>
    public string? Name { get; init; }

    /// <summary>
    /// Optional Markdown <c>description</c> for display to users (e.g. at a consent
    /// screen). Server-supplied, untrusted: consumers MUST sanitize before display.
    /// </summary>
    public string? Description { get; init; }

    /// <summary>Optional logo URL (<c>logo_uri</c>).</summary>
    public string? LogoUri { get; init; }

    /// <summary>Optional dark-background logo URL (<c>logo_dark_uri</c>).</summary>
    public string? LogoDarkUri { get; init; }

    /// <summary>Optional developer-documentation URL (<c>documentation_uri</c>).</summary>
    public string? DocumentationUri { get; init; }

    /// <summary>Optional terms-of-service URL (<c>tos_uri</c>).</summary>
    public string? TosUri { get; init; }

    /// <summary>Optional privacy-policy URL (<c>policy_uri</c>).</summary>
    public string? PolicyUri { get; init; }

    /// <summary>Scope descriptions map.</summary>
    public JsonObject? ScopeDescriptions { get; init; }

    /// <summary>Signature window in seconds.</summary>
    public int? SignatureWindow { get; init; }

    /// <summary>
    /// Additional HTTP message components that agents must cover when signing
    /// requests to this resource (<c>additional_signature_components</c>).
    /// </summary>
    public IReadOnlyList<string>? AdditionalSignatureComponents { get; init; }

    /// <summary>Resource-owned proactive authorization endpoint, not the PS/AS resource-token recipient.</summary>
    public string? AuthorizationEndpoint { get; init; }

    /// <summary>Revocation endpoint.</summary>
    public string? RevocationEndpoint { get; init; }

    /// <summary>Parse a resource metadata JSON document.</summary>
    public static ResourceMetadata FromJson(JsonObject doc)
    {
        ArgumentNullException.ThrowIfNull(doc);
        return new ResourceMetadata
        {
            Issuer = (string?)doc["issuer"] ?? throw new InvalidOperationException("Metadata missing 'issuer'."),
            JwksUri = (string?)doc["jwks_uri"],
            AccessMode = (string?)doc["access_mode"] is { } mode && IsKnownAccessMode(mode) ? mode : null,
            Name = (string?)doc["name"],
            Description = (string?)doc["description"],
            LogoUri = (string?)doc["logo_uri"],
            LogoDarkUri = (string?)doc["logo_dark_uri"],
            DocumentationUri = (string?)doc["documentation_uri"],
            TosUri = (string?)doc["tos_uri"],
            PolicyUri = (string?)doc["policy_uri"],
            ScopeDescriptions = doc["scope_descriptions"] as JsonObject,
            SignatureWindow = (int?)doc["signature_window"],
            AdditionalSignatureComponents = ParseAdditionalSignatureComponents(doc),
            AuthorizationEndpoint = (string?)doc["authorization_endpoint"],
            RevocationEndpoint = (string?)doc["revocation_endpoint"],
        };
    }

    private static IReadOnlyList<string>? ParseAdditionalSignatureComponents(JsonObject doc)
    {
        if (!doc.TryGetPropertyValue(AAuthConstants.MetadataFields.AdditionalSignatureComponents, out var node)
            || node is null)
        {
            return null;
        }
        if (node is not JsonArray array)
        {
            throw new InvalidOperationException("Metadata 'additional_signature_components' must be an array of strings.");
        }

        var components = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in array)
        {
            if (item is null)
            {
                throw new InvalidOperationException("Metadata 'additional_signature_components' must contain only strings.");
            }

            string? raw;
            try
            {
                raw = item.GetValue<string>();
            }
            catch (InvalidOperationException ex)
            {
                throw new InvalidOperationException(
                    "Metadata 'additional_signature_components' must contain only strings.", ex);
            }

            var component = raw.Trim().ToLowerInvariant();
            if (component.Length == 0)
            {
                throw new InvalidOperationException(
                    "Metadata 'additional_signature_components' must not contain blank values.");
            }
            if (seen.Add(component))
            {
                components.Add(component);
            }
        }

        return components;
    }

    private static bool IsKnownAccessMode(string mode) => mode is AAuthConstants.AccessModes.AgentToken
        or AAuthConstants.AccessModes.PersonToken or AAuthConstants.AccessModes.SessionToken
        or AAuthConstants.AccessModes.AuthToken or AAuthConstants.AccessModes.PerCall;
}

/// <summary>
/// Extension methods on <see cref="MetadataClient"/> for typed metadata fetching.
/// </summary>
public static class MetadataClientExtensions
{
    /// <summary>Fetch and parse resource metadata.</summary>
    public static async Task<ResourceMetadata> FetchResourceMetadataAsync(
        this MetadataClient client, string issuer, CancellationToken ct = default)
    {
        var url = client.GetUrl(issuer, AAuthConstants.DwkFiles.Resource);
        var doc = await client.FetchAsync(url, ct);
        return ResourceMetadata.FromJson(doc);
    }

    /// <summary>Fetch and parse Person Server metadata.</summary>
    public static async Task<ServerMetadata> FetchPersonServerMetadataAsync(
        this MetadataClient client, string issuer, CancellationToken ct = default)
    {
        var url = client.GetUrl(issuer, AAuthConstants.DwkFiles.Person);
        var doc = await client.FetchAsync(url, ct);
        return ServerMetadata.FromJson(doc);
    }

    /// <summary>Fetch and parse Access Server metadata.</summary>
    public static async Task<ServerMetadata> FetchAccessServerMetadataAsync(
        this MetadataClient client, string issuer, CancellationToken ct = default)
    {
        var url = client.GetUrl(issuer, AAuthConstants.DwkFiles.Access);
        var doc = await client.FetchAsync(url, ct);
        return ServerMetadata.FromJson(doc);
    }
}
