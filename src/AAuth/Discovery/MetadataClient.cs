using System;
using System.Collections.Concurrent;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Errors;

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
    /// <remarks>
    /// Returns a deep clone of the cached document so callers cannot
    /// mutate the shared cache entry.
    /// </remarks>
    public async Task<JsonObject> FetchAsync(Uri url, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(url);
        var now = _clock();
        if (_cache.TryGetValue(url, out var entry) && now < entry.Expiry)
        {
            return CloneObject(entry.Document);
        }

        using var response = await _http.GetAsync(url, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var doc = await response.Content.ReadFromJsonAsync<JsonObject>(cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Metadata at {url} is not a JSON object.");

        // §Metadata Documents (draft-02): the document's `issuer` MUST match the
        // URL it was fetched from (the URL minus the `/.well-known/{dwk}` suffix).
        // Reject on mismatch — only verified documents are ever cached.
        VerifyIssuer(url, doc);

        _cache[url] = new CacheEntry(doc, now + _cacheTtl);
        return CloneObject(doc);
    }

    /// <summary>Discard any cached entry for <paramref name="url"/>.</summary>
    public void Invalidate(Uri url) => _cache.TryRemove(url, out _);

    // §Metadata Documents (draft-02): verify the document's `issuer` matches the
    // origin it was retrieved from, preventing host-poisoned metadata (an attacker
    // serving a document that claims another origin's `issuer`, whose `jwks_uri` a
    // permissive verifier would then trust for the impersonated issuer). AAuth
    // server identifiers are scheme + host only (§Server Identifiers), so the
    // expected issuer is the fetch URL's authority and the well-known path drops out.
    private static void VerifyIssuer(Uri url, JsonObject doc)
    {
        var expectedIssuer = url.GetLeftPart(UriPartial.Authority);

        string? claimedIssuer = null;
        if (doc.TryGetPropertyValue("issuer", out var node)
            && node is JsonValue value
            && value.TryGetValue<string>(out var issuer))
        {
            claimedIssuer = issuer;
        }

        if (string.IsNullOrEmpty(claimedIssuer)
            || !string.Equals(claimedIssuer, expectedIssuer, StringComparison.Ordinal))
        {
            throw new AAuthMetadataException(url, claimedIssuer, expectedIssuer);
        }
    }

    private static JsonObject CloneObject(JsonObject source) =>
        (JsonObject)source.DeepClone();

    private sealed record CacheEntry(JsonObject Document, DateTimeOffset Expiry);
}
