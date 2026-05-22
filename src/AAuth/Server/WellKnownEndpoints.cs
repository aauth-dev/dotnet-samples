using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace AAuth.Server;

/// <summary>
/// Extension methods that map AAuth well-known endpoints onto an ASP.NET Core
/// <see cref="IEndpointRouteBuilder"/>. Resource server role.
/// </summary>
public static class WellKnownEndpoints
{
    /// <summary>Map both the resource metadata and JWKS endpoints.</summary>
    public static IEndpointRouteBuilder MapAAuthResourceWellKnown(
        this IEndpointRouteBuilder endpoints,
        AAuthResourceMetadataOptions options)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();

        endpoints.MapGet("/.well-known/aauth-resource.json", () => Results.Json(
            BuildResourceMetadata(options),
            contentType: "application/json"));

        endpoints.MapGet("/.well-known/jwks.json", () => Results.Json(
            BuildJwks(options.SigningKeys),
            contentType: "application/json"));

        return endpoints;
    }


    private static JsonObject BuildResourceMetadata(AAuthResourceMetadataOptions options)
    {
        var doc = new JsonObject
        {
            ["issuer"] = options.Issuer,
            ["jwks_uri"] = $"{options.Issuer.TrimEnd('/')}/.well-known/jwks.json",
        };
        if (!string.IsNullOrEmpty(options.ClientName))
        {
            doc["client_name"] = options.ClientName;
        }
        if (options.ScopeDescriptions is { Count: > 0 })
        {
            var scopes = new JsonObject();
            foreach (var (k, v) in options.ScopeDescriptions)
            {
                scopes[k] = v;
            }
            doc["scope_descriptions"] = scopes;
        }
        if (options.SignatureWindow is { } window)
        {
            doc["signature_window"] = window;
        }
        if (!string.IsNullOrEmpty(options.AuthorizationEndpoint))
        {
            doc["authorization_endpoint"] = options.AuthorizationEndpoint;
        }
        if (!string.IsNullOrEmpty(options.RevocationEndpoint))
        {
            doc["revocation_endpoint"] = options.RevocationEndpoint;
        }
        return doc;
    }

    internal static JsonObject BuildJwks(IReadOnlyDictionary<string, AAuthKey> signingKeys)
    {
        var keys = new JsonArray();
        foreach (var (kid, key) in signingKeys)
        {
            var jwk = key.ToPublicJwk();
            jwk["kid"] = kid;
            jwk["use"] = "sig";
            jwk["alg"] = AAuthKey.Algorithm;
            keys.Add(jwk);
        }
        return new JsonObject { ["keys"] = keys };
    }
}

/// <summary>
/// Static configuration consumed by <see cref="WellKnownEndpoints.MapAAuthResourceWellKnown"/>.
/// </summary>
public sealed class AAuthResourceMetadataOptions
{
    /// <summary>HTTPS URL of this resource (<c>issuer</c>).</summary>
    public required string Issuer { get; init; }

    /// <summary>Signing keys served via the JWKS endpoint, keyed by <c>kid</c>.</summary>
    public required IReadOnlyDictionary<string, AAuthKey> SigningKeys { get; init; }

    /// <summary>Optional human-readable name (<c>client_name</c>).</summary>
    public string? ClientName { get; init; }

    /// <summary>Optional scope description map (<c>scope_descriptions</c>).</summary>
    public IReadOnlyDictionary<string, string>? ScopeDescriptions { get; init; }

    /// <summary>Optional signature-window override (<c>signature_window</c>, seconds).</summary>
    public int? SignatureWindow { get; init; }

    /// <summary>Optional authorization endpoint (§2, resource-initiated flow).</summary>
    public string? AuthorizationEndpoint { get; init; }

    /// <summary>Optional revocation endpoint.</summary>
    public string? RevocationEndpoint { get; init; }

    /// <summary>Throw if any required field is unset/invalid.</summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Issuer))
        {
            throw new InvalidOperationException("Issuer must be set.");
        }
        if (!AAuthUrl.IsHttpsOrLoopback(Issuer))
        {
            // Spec mandates https. We additionally accept http://localhost
            // and http://127.0.0.1 so WebApplicationFactory tests (which
            // bind plain HTTP) can still configure a sensible issuer.
            throw new InvalidOperationException("Issuer must be an absolute https:// URL (or http://localhost).");
        }
        if (SigningKeys is null || SigningKeys.Count == 0)
        {
            throw new InvalidOperationException("At least one signing key must be supplied.");
        }
    }
}
