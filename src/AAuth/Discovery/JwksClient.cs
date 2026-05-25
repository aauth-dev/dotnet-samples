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
/// (no more than once per minute per <c>jwks_uri</c>) and cached. A miss on
/// <c>kid</c> triggers a refresh only if the last fetch is older than the
/// rate-limit window.
/// </remarks>
public sealed class JwksClient
{
    private readonly HttpClient _http;
    private readonly TimeSpan _cacheTtl;
    private readonly TimeSpan _minRefreshInterval;
    private readonly Func<DateTimeOffset> _clock;
    private readonly ConcurrentDictionary<Uri, CacheEntry> _cache = new();

    /// <summary>Create a JWKS client.</summary>
    /// <param name="http">HttpClient used for fetches.</param>
    /// <param name="cacheTtl">Cache TTL. Default 1 hour.</param>
    /// <param name="minRefreshInterval">Minimum interval between refresh fetches. Default 1 minute.</param>
    /// <param name="clock">Clock injection point.</param>
    public JwksClient(
        HttpClient http,
        TimeSpan? cacheTtl = null,
        TimeSpan? minRefreshInterval = null,
        Func<DateTimeOffset>? clock = null)
    {
        ArgumentNullException.ThrowIfNull(http);
        _http = http;
        _cacheTtl = cacheTtl ?? TimeSpan.FromHours(1);
        _minRefreshInterval = minRefreshInterval ?? TimeSpan.FromMinutes(1);
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>Resolve a key by <c>kid</c> from the JWKS at <paramref name="jwksUri"/>.</summary>
    /// <returns>The public key, or null if no key matches.</returns>
    public async Task<IAAuthKey?> ResolveKeyAsync(Uri jwksUri, string kid, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(jwksUri);
        ArgumentException.ThrowIfNullOrEmpty(kid);

        var now = _clock();
        var entry = _cache.GetValueOrDefault(jwksUri);
        if (entry is null || now > entry.Expiry)
        {
            entry = await FetchAsync(jwksUri, cancellationToken).ConfigureAwait(false);
        }
        else if (!entry.Keys.ContainsKey(kid) && now - entry.FetchedAt > _minRefreshInterval)
        {
            // Unknown kid + we haven't refreshed too recently: try once more.
            entry = await FetchAsync(jwksUri, cancellationToken).ConfigureAwait(false);
        }

        return entry.Keys.TryGetValue(kid, out var key) ? key : null;
    }

    private async Task<CacheEntry> FetchAsync(Uri jwksUri, CancellationToken cancellationToken)
    {
        using var response = await _http.GetAsync(jwksUri, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var doc = await response.Content.ReadFromJsonAsync<JsonObject>(cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"JWKS at {jwksUri} is not a JSON object.");

        var now = _clock();
        var keys = new Dictionary<string, IAAuthKey>(StringComparer.Ordinal);
        if (doc["keys"] is JsonArray array)
        {
            foreach (var node in array)
            {
                if (node is not JsonObject jwk) { continue; }
                if ((string?)jwk["kid"] is not { } kid) { continue; }

                var key = KeyFactory.TryFromJwk(jwk);
                if (key is null) { continue; }

                keys[kid] = key;
            }
        }

        var entry = new CacheEntry(keys, now, now + _cacheTtl);
        _cache[jwksUri] = entry;
        return entry;
    }

    /// <summary>Clear all cached JWKS entries, forcing the next resolve to fetch fresh.</summary>
    public void ClearCache() => _cache.Clear();

    private sealed record CacheEntry(
        IReadOnlyDictionary<string, IAAuthKey> Keys,
        DateTimeOffset FetchedAt,
        DateTimeOffset Expiry);
}
