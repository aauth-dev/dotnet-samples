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
/// Bounded per-URI cache with single-flight fetches, failure backoff, a one-minute
/// attempt floor, and a hard maximum age. Cached documents are cloned on return.
/// </remarks>
public sealed class MetadataClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly DiscoveryCache<JsonObject> _cache;
    public AAuthEgressPolicy Policy { get; }

    /// <summary>Create a metadata client.</summary>
    /// <param name="http">HttpClient used for fetches; left undisposed.</param>
    /// <param name="cacheTtl">Cache TTL. Default 5 minutes.</param>
    /// <param name="clock">Clock injection point.</param>
    public MetadataClient(HttpClient? http = null, TimeSpan? cacheTtl = null, Func<DateTimeOffset>? clock = null,
        AAuthEgressPolicy? policy = null, AAuthTransportContract? transportContract = null,
        int maxCacheEntries = 1024, TimeSpan? maxCacheAge = null)
    {
        _cache = new(cacheTtl ?? TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(1),
            clock ?? (() => DateTimeOffset.UtcNow), maxCacheEntries, maxCacheAge);
        _ownsHttp = http is null;
        http ??= AAuthHttpTransport.CreateClient(policy);
        if (transportContract is { } contract)
            AAuthHttpTransport.AttachPolicy(http, policy ?? AAuthEgressPolicy.Production, contract);
        Policy = AAuthHttpTransport.GetPolicy(http);
        if (policy is not null && !ReferenceEquals(policy, Policy))
            throw new InvalidOperationException("Discovery policy must match the injected client's registered policy.");
        _http = http;
    }

    /// <summary>Dispose the internally created transport; injected clients remain caller-owned.</summary>
    public void Dispose()
    {
        if (_ownsHttp) _http.Dispose();
    }

    /// <summary>
    /// Build the metadata URL for a given issuer base and well-known suffix.
    /// </summary>
    /// <param name="issuer">Issuer URL (e.g. <c>https://resource.example</c>).</param>
    /// <param name="dwk">Well-known suffix (e.g. <c>aauth-resource.json</c>).</param>
    public static Uri BuildUrl(string issuer, string dwk, AAuthEgressPolicy? policy = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentException.ThrowIfNullOrEmpty(dwk);
        (policy ?? AAuthEgressPolicy.Production).ValidateIdentifier(issuer);
        if (dwk is "." or ".." || dwk.Any(character => !char.IsAsciiLetterOrDigit(character)
            && character is not ('.' or '-' or '_')))
            throw new ArgumentException("Invalid well-known document name.", nameof(dwk));
        return new Uri($"{issuer}/.well-known/{dwk}");
    }

    public Uri GetUrl(string issuer, string dwk) => BuildUrl(issuer, dwk, Policy);

    /// <summary>Fetch metadata, returning a cached document when fresh.</summary>
    /// <remarks>
    /// Returns a deep clone of the cached document so callers cannot
    /// mutate the shared cache entry.
    /// </remarks>
    public async Task<JsonObject> FetchAsync(Uri url, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(url);
        Policy.ValidateUrl(url.OriginalString);
        var separator = url.OriginalString.IndexOf("/.well-known/", StringComparison.Ordinal);
        if (separator < 0) throw new ArgumentException("Metadata URL must use the well-known discovery path.", nameof(url));
        var expectedIssuer = url.OriginalString[..separator];
        if (GetUrl(expectedIssuer, url.OriginalString[(separator + 13)..]).OriginalString != url.OriginalString)
            throw new ArgumentException("Invalid exact metadata URL.", nameof(url));
        var document = await _cache.GetAsync(url.OriginalString, _ => false,
            () => FetchDocumentAsync(url, expectedIssuer), cancellationToken).ConfigureAwait(false);
        return CloneObject(document);
    }

    private async Task<DiscoveryResponse<JsonObject>> FetchDocumentAsync(Uri url, string expectedIssuer)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        using var response = await AAuthHttpTransport.SendAsync(_http, request).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var doc = await response.Content.ReadFromJsonAsync<JsonNode>().ConfigureAwait(false) as JsonObject
            ?? throw new AAuth.HttpSig.AAuthVerificationException(SignatureErrorCode.InvalidKey, $"Metadata at {url} is not a JSON object.");

        // §Metadata Documents (draft-02): the document's `issuer` MUST match the
        // URL it was fetched from (the URL minus the `/.well-known/{dwk}` suffix).
        // Reject on mismatch — only verified documents are ever cached.
        VerifyIssuer(url, expectedIssuer, doc);
        if (doc["jwks_uri"] is JsonValue jwks && jwks.TryGetValue<string>(out var jwksUrl))
            Policy.ValidateJwksUrl(jwksUrl, expectedIssuer);
        foreach (var field in new[] { "token_endpoint", "authorization_endpoint", "mission_endpoint", "callback_endpoint", "interaction_endpoint", "revocation_endpoint", "event_endpoint" })
            if (doc[field] is JsonValue endpoint && endpoint.TryGetValue<string>(out var endpointUrl))
                Policy.ValidateUrl(endpointUrl, endpoint: true);
        return _cache.Response(doc, response);
    }

    /// <summary>Discard any cached entry for <paramref name="url"/>.</summary>
    public void Invalidate(Uri url) => _cache.Invalidate(url.OriginalString);

    // §Metadata Documents (draft-02): verify the document's `issuer` matches the
    // origin it was retrieved from, preventing host-poisoned metadata (an attacker
    // serving a document that claims another origin's `issuer`, whose `jwks_uri` a
    // permissive verifier would then trust for the impersonated issuer). AAuth
    // server identifiers are scheme + host only (§Server Identifiers), so the
    // expected issuer is the fetch URL's authority and the well-known path drops out.
    private void VerifyIssuer(Uri url, string expectedIssuer, JsonObject doc)
    {
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
        Policy.ValidateIdentifier(claimedIssuer);
    }

    private static JsonObject CloneObject(JsonObject source) =>
        (JsonObject)source.DeepClone();

}
