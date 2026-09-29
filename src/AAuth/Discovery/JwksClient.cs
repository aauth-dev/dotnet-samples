using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;

namespace AAuth.Discovery;

/// <summary>
/// Fetches, caches, and rate-limits JWKS documents. Resolves a public
/// <see cref="AAuthKey"/> by <c>kid</c>.
/// </summary>
/// <remarks>
/// Implements the AAuth spec recommendation that JWKS fetches be rate-limited
/// (no more than once per minute per issuer and per direct JWKS URL) and cached. A miss on
/// <c>kid</c> triggers a refresh only if the last fetch is older than the
/// rate-limit window.
/// </remarks>
public sealed class JwksClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly DiscoveryCache<Dictionary<string, JsonObject>> _cache;
    public AAuthEgressPolicy Policy { get; }

    /// <summary>Create a JWKS client.</summary>
    /// <param name="http">HttpClient used for fetches.</param>
    /// <param name="cacheTtl">Cache TTL. Default 1 hour.</param>
    /// <param name="minRefreshInterval">Minimum interval between refresh fetches. Default 1 minute.</param>
    /// <param name="timeProvider">Time source for cache freshness.</param>
    public JwksClient(
        HttpClient? http = null,
        TimeSpan? cacheTtl = null,
        TimeSpan? minRefreshInterval = null,
        TimeProvider? timeProvider = null,
        int maxCacheEntries = 1024,
        TimeSpan? maxCacheAge = null,
        AAuthEgressPolicy? policy = null,
        AAuthTransportContract? transportContract = null)
    {
        _cache = new(cacheTtl ?? TimeSpan.FromHours(1), minRefreshInterval ?? TimeSpan.FromMinutes(1),
            timeProvider ?? TimeProvider.System, maxCacheEntries, maxCacheAge);
        _ownsHttp = http is null;
        http ??= AAuthHttpTransport.CreateClient(policy);
        if (transportContract is { } contract)
            AAuthHttpTransport.AttachPolicy(http, policy ?? AAuthEgressPolicy.Production, contract);
        Policy = AAuthHttpTransport.GetPolicy(http);
        if (policy is not null && !ReferenceEquals(policy, Policy))
            throw new InvalidOperationException("Discovery policy must match the injected client's registered policy.");
        _http = http;
    }

    /// <summary>Dispose internally created HTTP resources; injected clients remain caller-owned.</summary>
    public void Dispose()
    {
        if (_ownsHttp) _http.Dispose();
    }

    /// <summary>Resolve a key by <c>kid</c> from the JWKS at <paramref name="jwksUri"/>.</summary>
    /// <returns>The public key, or null if no key matches.</returns>
    public Task<IAAuthKey?> ResolveKeyAsync(Uri jwksUri, string kid, CancellationToken cancellationToken = default) =>
        ResolveAsync(jwksUri, kid, null, false, cancellationToken);

    /// <summary>Resolve discovered keys with the exact issuer validated by metadata discovery, preserving its attempt floor across URL changes.</summary>
    public Task<IAAuthKey?> ResolveKeyAsync(Uri jwksUri, string kid, string issuer, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        return ResolveAsync(jwksUri, kid, issuer, false, cancellationToken);
    }

    /// <summary>
    /// Force a single JWKS refresh and resolve <paramref name="kid"/> from the
    /// fresh document — for the <em>silent re-keying</em> case where the issuer
    /// rotated key material under an unchanged <c>kid</c> and the cached key now
    /// fails signature verification. The once-per-minute rate-limit floor still
    /// applies: when the last fetch is within the refresh window the cached key is
    /// returned unchanged (no fetch), so a flood of bad-signature tokens cannot
    /// hammer the <c>jwks_uri</c>.
    /// </summary>
    /// <returns>The freshly-resolved key, or <see langword="null"/> if absent.</returns>
    public Task<IAAuthKey?> ForceRefreshKeyAsync(
        Uri jwksUri, string kid, CancellationToken cancellationToken = default) =>
        ResolveAsync(jwksUri, kid, null, true, cancellationToken);

    /// <summary>Refresh discovered keys subject to both the exact metadata-validated issuer's floor and the URL floor.</summary>
    public Task<IAAuthKey?> ForceRefreshKeyAsync(
        Uri jwksUri, string kid, string issuer, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        return ResolveAsync(jwksUri, kid, issuer, true, cancellationToken);
    }

    private async Task<IAAuthKey?> ResolveAsync(Uri jwksUri, string kid, string? issuer, bool force,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(jwksUri);
        ArgumentException.ThrowIfNullOrEmpty(kid);
        if (issuer is null) Policy.ValidateUrl(jwksUri.OriginalString);
        else Policy.ValidateJwksUrl(jwksUri.OriginalString, issuer);
        var keys = await _cache.GetAsync(jwksUri.AbsoluteUri, keys => force || !keys.ContainsKey(kid),
            () => FetchAsync(jwksUri, CancellationToken.None), cancellationToken, issuer).ConfigureAwait(false);
        return keys.TryGetValue(kid, out var key) ? KeyFactory.FromPublicJwk(key) : null;
    }

    private async Task<DiscoveryResponse<Dictionary<string, JsonObject>>> FetchAsync(Uri jwksUri, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, jwksUri);
        using var response = await AAuthHttpTransport.SendAsync(_http, request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        try
        {
            var doc = await response.Content.ReadFromJsonAsync<JsonNode>(cancellationToken).ConfigureAwait(false) as JsonObject
                ?? throw new AAuth.HttpSig.AAuthVerificationException(AAuth.Errors.SignatureErrorCode.InvalidKey, $"JWKS at {jwksUri} is not a JSON object.");

            var keys = new Dictionary<string, JsonObject>(StringComparer.Ordinal);
            if (doc["keys"] is not JsonArray array)
                throw new AAuth.HttpSig.AAuthVerificationException(AAuth.Errors.SignatureErrorCode.InvalidKey, "JWKS keys must be an array.");
            foreach (var node in array)
            {
                if (node is not JsonObject jwk)
                    throw new AAuth.HttpSig.AAuthVerificationException(AAuth.Errors.SignatureErrorCode.InvalidKey, "JWKS entries must be objects.");
                if (!jwk.TryGetPropertyValue("kid", out var kidNode)) continue;
                if (kidNode is not JsonValue kidValue || !kidValue.TryGetValue<string>(out var kid))
                    throw new AAuth.HttpSig.AAuthVerificationException(AAuth.Errors.SignatureErrorCode.InvalidKey, "JWK kid must be a string.");
                keys[kid] = jwk;
            }

            return _cache.Response(keys, response);
        }
        catch (Exception exception) when (exception is System.Text.Json.JsonException or ArgumentException)
        {
            throw new AAuth.HttpSig.AAuthVerificationException(AAuth.Errors.SignatureErrorCode.InvalidKey, "JWKS is not a valid key document.", exception);
        }
    }

    /// <summary>Discard cached keys without clearing attempt floors or failure backoff.</summary>
    public void ClearCache() => _cache.Invalidate();
}
