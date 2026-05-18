using System;
using System.Collections.Concurrent;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Discovery;

/// <summary>
/// Fetches and caches well-known metadata documents
/// (<c>aauth-resource.json</c>, <c>aauth-person.json</c>, <c>aauth-agent.json</c>,
/// <c>aauth-access.json</c>).
/// </summary>
/// <remarks>
/// In-memory cache with a configurable TTL. Resource servers and agents
/// share this client to avoid repeated network round-trips to discover
/// counterparties. No revocation, no negative caching — keep it simple
/// until a real cache strategy is needed.
/// </remarks>
public sealed class MetadataClient
{
    private readonly HttpClient _http;
    private readonly TimeSpan _cacheTtl;
    private readonly Func<DateTimeOffset> _clock;
    private readonly ConcurrentDictionary<Uri, CacheEntry> _cache = new();

    /// <summary>Create a metadata client.</summary>
    /// <param name="http">HttpClient used for fetches; left undisposed.</param>
    /// <param name="cacheTtl">Cache TTL. Default 5 minutes.</param>
    /// <param name="clock">Clock injection point.</param>
    public MetadataClient(HttpClient http, TimeSpan? cacheTtl = null, Func<DateTimeOffset>? clock = null)
    {
        ArgumentNullException.ThrowIfNull(http);
        _http = http;
        _cacheTtl = cacheTtl ?? TimeSpan.FromMinutes(5);
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Build the metadata URL for a given issuer base and well-known suffix.
    /// </summary>
    /// <param name="issuer">Issuer URL (e.g. <c>https://resource.example</c>).</param>
    /// <param name="dwk">Well-known suffix (e.g. <c>aauth-resource.json</c>).</param>
    public static Uri BuildUrl(string issuer, string dwk)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentException.ThrowIfNullOrEmpty(dwk);
        if (!Uri.TryCreate(issuer, UriKind.Absolute, out var baseUri))
        {
            throw new ArgumentException("Issuer must be an absolute URL.", nameof(issuer));
        }
        var trimmed = baseUri.GetLeftPart(UriPartial.Authority).TrimEnd('/');
        return new Uri($"{trimmed}/.well-known/{dwk}");
    }

    /// <summary>Fetch metadata, returning a cached document when fresh.</summary>
    public async Task<JsonObject> FetchAsync(Uri url, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(url);
        var now = _clock();
        if (_cache.TryGetValue(url, out var entry) && now < entry.Expiry)
        {
            return entry.Document;
        }

        using var response = await _http.GetAsync(url, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var doc = await response.Content.ReadFromJsonAsync<JsonObject>(cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Metadata at {url} is not a JSON object.");

        _cache[url] = new CacheEntry(doc, now + _cacheTtl);
        return doc;
    }

    /// <summary>Discard any cached entry for <paramref name="url"/>.</summary>
    public void Invalidate(Uri url) => _cache.TryRemove(url, out _);

    private sealed record CacheEntry(JsonObject Document, DateTimeOffset Expiry);
}
