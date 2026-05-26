using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
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

        RegisterJwksKeys(endpoints, options.SigningKeys);
        return endpoints;
    }

    /// <summary>Map the agent metadata and JWKS endpoints (<c>/.well-known/aauth-agent.json</c>).</summary>
    /// <remarks>
    /// If <see cref="MapAAuthResourceWellKnown"/> has already been called (which maps
    /// <c>/.well-known/jwks.json</c>), the JWKS endpoint is not re-registered.
    /// Otherwise, this method also maps the JWKS endpoint with the agent's signing keys.
    /// </remarks>
    public static IEndpointRouteBuilder MapAAuthAgentWellKnown(
        this IEndpointRouteBuilder endpoints,
        AAuthAgentMetadataOptions options)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();

        endpoints.MapGet("/.well-known/aauth-agent.json", () => Results.Json(
            BuildAgentMetadata(options),
            contentType: "application/json"));

        RegisterJwksKeys(endpoints, options.SigningKeys);
        return endpoints;
    }

    /// <summary>Map the person server metadata and JWKS endpoints (<c>/.well-known/aauth-person.json</c>).</summary>
    /// <remarks>
    /// If <see cref="MapAAuthResourceWellKnown"/> has already been called (which maps
    /// <c>/.well-known/jwks.json</c>), the JWKS endpoint is not re-registered.
    /// Otherwise, this method also maps the JWKS endpoint with the PS's signing keys.
    /// </remarks>
    public static IEndpointRouteBuilder MapAAuthPersonServerWellKnown(
        this IEndpointRouteBuilder endpoints,
        AAuthPersonServerMetadataOptions options)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();

        endpoints.MapGet("/.well-known/aauth-person.json", () => Results.Json(
            BuildPersonServerMetadata(options),
            contentType: "application/json"));

        RegisterJwksKeys(endpoints, options.SigningKeys);
        return endpoints;
    }

    /// <summary>Map the access server metadata and JWKS endpoints (<c>/.well-known/aauth-access.json</c>).</summary>
    /// <remarks>
    /// If <see cref="MapAAuthResourceWellKnown"/> has already been called (which maps
    /// <c>/.well-known/jwks.json</c>), the JWKS endpoint is not re-registered.
    /// Otherwise, this method also maps the JWKS endpoint with the AS's signing keys.
    /// </remarks>
    public static IEndpointRouteBuilder MapAAuthAccessServerWellKnown(
        this IEndpointRouteBuilder endpoints,
        AAuthAccessServerMetadataOptions options)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();

        endpoints.MapGet("/.well-known/aauth-access.json", () => Results.Json(
            BuildAccessServerMetadata(options),
            contentType: "application/json"));

        RegisterJwksKeys(endpoints, options.SigningKeys);
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

    private static JsonObject BuildAgentMetadata(AAuthAgentMetadataOptions options)
    {
        var doc = new JsonObject
        {
            ["issuer"] = options.Issuer,
            ["jwks_uri"] = $"{options.Issuer.TrimEnd('/')}/.well-known/jwks.json",
        };
        if (!string.IsNullOrEmpty(options.ClientName))
            doc["client_name"] = options.ClientName;
        if (!string.IsNullOrEmpty(options.LogoUri))
            doc["logo_uri"] = options.LogoUri;
        if (!string.IsNullOrEmpty(options.CallbackEndpoint))
            doc["callback_endpoint"] = options.CallbackEndpoint;
        if (!string.IsNullOrEmpty(options.LoginEndpoint))
            doc["login_endpoint"] = options.LoginEndpoint;
        return doc;
    }

    private static JsonObject BuildPersonServerMetadata(AAuthPersonServerMetadataOptions options)
    {
        var doc = new JsonObject
        {
            ["issuer"] = options.Issuer,
            ["token_endpoint"] = options.TokenEndpoint,
            ["jwks_uri"] = $"{options.Issuer.TrimEnd('/')}/.well-known/jwks.json",
        };
        if (!string.IsNullOrEmpty(options.MissionEndpoint))
            doc["mission_endpoint"] = options.MissionEndpoint;
        if (!string.IsNullOrEmpty(options.PermissionEndpoint))
            doc["permission_endpoint"] = options.PermissionEndpoint;
        if (!string.IsNullOrEmpty(options.AuditEndpoint))
            doc["audit_endpoint"] = options.AuditEndpoint;
        if (!string.IsNullOrEmpty(options.InteractionEndpoint))
            doc["interaction_endpoint"] = options.InteractionEndpoint;
        if (!string.IsNullOrEmpty(options.RevocationEndpoint))
            doc["revocation_endpoint"] = options.RevocationEndpoint;
        if (options.ScopesSupported is { Count: > 0 })
        {
            var arr = new JsonArray();
            foreach (var s in options.ScopesSupported)
                arr.Add(s);
            doc["scopes_supported"] = arr;
        }
        return doc;
    }

    private static JsonObject BuildAccessServerMetadata(AAuthAccessServerMetadataOptions options)
    {
        var doc = new JsonObject
        {
            ["issuer"] = options.Issuer,
            ["token_endpoint"] = options.TokenEndpoint,
            ["jwks_uri"] = $"{options.Issuer.TrimEnd('/')}/.well-known/jwks.json",
        };
        if (!string.IsNullOrEmpty(options.RevocationEndpoint))
            doc["revocation_endpoint"] = options.RevocationEndpoint;
        return doc;
    }

    private static readonly ConditionalWeakTable<IEndpointRouteBuilder, SharedJwksState> _jwksState = new();

    private static void RegisterJwksKeys(IEndpointRouteBuilder endpoints, IReadOnlyDictionary<string, AAuthKey> signingKeys)
    {
        var state = _jwksState.GetOrCreateValue(endpoints);
        lock (state)
        {
            // Merge keys (first registration of a given kid wins).
            foreach (var (kid, key) in signingKeys)
            {
                state.Keys.TryAdd(kid, key);
            }

            // Register the JWKS endpoint only once. The endpoint closure captures
            // `state` so it serves the merged key set at request time.
            if (!state.EndpointRegistered)
            {
                state.EndpointRegistered = true;
                endpoints.MapGet("/.well-known/jwks.json", () => Results.Json(
                    BuildJwks(state.Keys),
                    contentType: "application/json"));
            }
        }
    }

    private sealed class SharedJwksState
    {
        public Dictionary<string, AAuthKey> Keys { get; } = new();
        public bool EndpointRegistered { get; set; }
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
