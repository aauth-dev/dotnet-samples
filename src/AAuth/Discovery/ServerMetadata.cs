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

    /// <summary>Token endpoint (required for PS/AS).</summary>
    public string? TokenEndpoint { get; init; }

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
            TokenEndpoint = (string?)doc["token_endpoint"],
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
    /// <c>aauth-access-token</c>, or <c>auth-token</c> (see
    /// <see cref="AAuthConstants.AccessModes"/>). Advisory: the runtime
    /// <c>AAuth-Requirement</c> remains authoritative. <see langword="null"/> when
    /// the document omits it, which the spec treats as the <c>agent-token</c>
    /// default (§Resource Metadata).
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

    /// <summary>Authorization endpoint (for resource-initiated flows).</summary>
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
            AccessMode = (string?)doc["access_mode"],
            Name = (string?)doc["name"],
            Description = (string?)doc["description"],
            LogoUri = (string?)doc["logo_uri"],
            LogoDarkUri = (string?)doc["logo_dark_uri"],
            DocumentationUri = (string?)doc["documentation_uri"],
            TosUri = (string?)doc["tos_uri"],
            PolicyUri = (string?)doc["policy_uri"],
            ScopeDescriptions = doc["scope_descriptions"] as JsonObject,
            SignatureWindow = (int?)doc["signature_window"],
            AuthorizationEndpoint = (string?)doc["authorization_endpoint"],
            RevocationEndpoint = (string?)doc["revocation_endpoint"],
        };
    }
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
        var url = MetadataClient.BuildUrl(issuer, AAuthConstants.DwkFiles.Resource);
        var doc = await client.FetchAsync(url, ct);
        return ResourceMetadata.FromJson(doc);
    }

    /// <summary>Fetch and parse Person Server metadata.</summary>
    public static async Task<ServerMetadata> FetchPersonServerMetadataAsync(
        this MetadataClient client, string issuer, CancellationToken ct = default)
    {
        var url = MetadataClient.BuildUrl(issuer, AAuthConstants.DwkFiles.Person);
        var doc = await client.FetchAsync(url, ct);
        return ServerMetadata.FromJson(doc);
    }

    /// <summary>Fetch and parse Access Server metadata.</summary>
    public static async Task<ServerMetadata> FetchAccessServerMetadataAsync(
        this MetadataClient client, string issuer, CancellationToken ct = default)
    {
        var url = MetadataClient.BuildUrl(issuer, AAuthConstants.DwkFiles.Access);
        var doc = await client.FetchAsync(url, ct);
        return ServerMetadata.FromJson(doc);
    }
}
