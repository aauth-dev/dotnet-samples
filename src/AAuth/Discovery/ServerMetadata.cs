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

    /// <summary>Token endpoint (required for PS/AS).</summary>
    public string? TokenEndpoint { get; init; }

    /// <summary>Revocation endpoint (optional).</summary>
    public string? RevocationEndpoint { get; init; }

    /// <summary>Mission endpoint (optional, PS only).</summary>
    public string? MissionEndpoint { get; init; }

    /// <summary>Interaction endpoint (optional, PS only).</summary>
    public string? InteractionEndpoint { get; init; }

    /// <summary>Parse a metadata JSON document into a <see cref="ServerMetadata"/>.</summary>
    public static ServerMetadata FromJson(JsonObject doc)
    {
        ArgumentNullException.ThrowIfNull(doc);
        return new ServerMetadata
        {
            Issuer = (string?)doc["issuer"] ?? throw new InvalidOperationException("Metadata missing 'issuer'."),
            JwksUri = (string?)doc["jwks_uri"] ?? throw new InvalidOperationException("Metadata missing 'jwks_uri'."),
            TokenEndpoint = (string?)doc["token_endpoint"],
            RevocationEndpoint = (string?)doc["revocation_endpoint"],
            MissionEndpoint = (string?)doc["mission_endpoint"],
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

    /// <summary>JWKS URI for key resolution.</summary>
    public required string JwksUri { get; init; }

    /// <summary>Human-readable name.</summary>
    public string? ClientName { get; init; }

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
            JwksUri = (string?)doc["jwks_uri"] ?? throw new InvalidOperationException("Metadata missing 'jwks_uri'."),
            ClientName = (string?)doc["client_name"],
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
