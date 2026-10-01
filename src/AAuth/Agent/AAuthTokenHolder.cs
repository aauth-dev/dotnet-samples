using System;
using System.Threading.Tasks;

namespace AAuth.Agent;

/// <summary>
/// The agent token slot (<see cref="Current"/>, <see cref="Update"/>) and the carrier tokens
/// (person token, auth token) the challenge handler obtained, kept in an <see cref="IAAuthTokenCache"/>
/// keyed by what each was obtained for. Thread-safe; share a cache to reuse carriers across clients.
/// </summary>
public sealed class AAuthTokenHolder
{
    // volatile gives us release/acquire semantics on the reference write so
    // a parallel reader running on a different thread observes Update()'s
    // value without needing a full memory barrier. Reference writes are
    // atomic on .NET; volatile only adds ordering.
    private volatile string _current;
    private readonly IAAuthTokenCache _cache;
    private static readonly System.Net.Http.HttpRequestOptionsKey<string> SourceToken = new("AAuth.CarrierSourceToken");
    internal static readonly TimeSpan CarrierRefreshMargin = TimeSpan.FromMinutes(5);

    /// <summary>Create the holder with an initial token (typically the agent token).</summary>
    public AAuthTokenHolder(string initialToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(initialToken);
        _current = initialToken;
        _cache = new InMemoryAAuthTokenCache();
    }

    /// <summary>
    /// Create the holder without an initial token. The first call to
    /// <see cref="TokenRefreshHandler"/> will acquire the token lazily.
    /// </summary>
    public AAuthTokenHolder() : this((IAAuthTokenCache?)null)
    {
    }

    /// <summary>Create an empty holder whose carriers live in <paramref name="cache"/>.</summary>
    public AAuthTokenHolder(IAAuthTokenCache? cache)
    {
        _current = string.Empty;
        _cache = cache ?? new InMemoryAAuthTokenCache();
    }

    /// <summary>Returns <c>true</c> when a token has been set.</summary>
    public bool HasToken => _current.Length > 0;

    /// <summary>Return the current carrier token.</summary>
    public string Current => _current;

    public string SelectForRequest(System.Net.Http.HttpRequestMessage request, string agentToken, string signingKeyThumbprint)
    {
        request.Options.Set(SourceToken, agentToken);
        // Only the cache answers: a cleared cache (sign-out) must never fall back to Current.
        return Key(request, agentToken, signingKeyThumbprint) is { } key
            && _cache.Get(key) is { } cached
            && IsUsable(cached)
            ? cached : agentToken;
    }

    /// <summary>Set the carrier token. Subsequent signed requests use this value.</summary>
    public void Update(string token)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);
        _current = token;
    }

    // Single-flight per key: a concurrent request for the same key reuses this acquisition. The
    // result also becomes Current, for hand-composed pipelines that sign with the holder's latest
    // carrier; SelectForRequest never reads it.
    internal async Task<string> AcquireAsync(System.Net.Http.HttpRequestMessage request, string? presented,
        Func<System.Threading.CancellationToken, Task<string>> acquire, System.Threading.CancellationToken cancellationToken)
    {
        request.Options.TryGetValue(SourceToken, out var agentToken);
        var key = agentToken is not null
            && request.Options.TryGetValue(AAuth.HttpSig.AAuthSigningHandler.SigningKeyContext, out var signingKey)
                ? Key(request, agentToken, signingKey.ComputeJwkThumbprint()) : null;
        string token;
        if (key is not null && request.Options.TryGetValue(AAuthRequestOptions.InteractionHandler, out _))
        {
            // A per-request interaction handler owns this request's consent. Another request's
            // in-flight acquisition would never call it, so reuse only a finished token.
            token = _cache.Get(key) is { } cached && cached != presented
                ? cached : await acquire(cancellationToken).ConfigureAwait(false);
            _cache.Set(key, token, ExpiresAt(token));
        }
        else
        {
            token = key is not null
                ? await _cache.AcquireAsync(key, presented, acquire, cancellationToken).ConfigureAwait(false)
                : await acquire(cancellationToken).ConfigureAwait(false);
        }
        if (!IsUsable(token))
        {
            token = await acquire(cancellationToken).ConfigureAwait(false);
            if (!IsUsable(token))
            {
                throw new AAuth.Tokens.TokenVerificationException(
                    "Acquired carrier token expires within the refresh margin.");
            }
        }
        _current = token;
        return token;
    }

    private static AAuthTokenCacheKey? Key(System.Net.Http.HttpRequestMessage request, string agentToken, string thumbprint)
    {
        var audience = request.Options.TryGetValue(AAuthRequestOptions.ResourceIdentifier, out var resource)
            ? resource : request.RequestUri?.GetLeftPart(UriPartial.Authority);
        if (string.IsNullOrEmpty(agentToken) || audience is null) return null;
        request.Options.TryGetValue(MissionForwardingHandler.UpstreamAuthorization, out var upstream);
        return new(agentToken, upstream, AAuthRequestOptions.GetMissionS256(request), audience,
            AAuthRequestOptions.GetAccount(request), thumbprint);
    }

    internal static DateTimeOffset ExpiresAt(string token)
        => (long?)TokenRefreshHandler.ReadPayloadUnsafe(token)["exp"] is { } exp
            ? DateTimeOffset.FromUnixTimeSeconds(exp) : DateTimeOffset.MinValue;

    internal static bool IsUsable(string token)
        => ExpiresAt(token) > DateTimeOffset.UtcNow + CarrierRefreshMargin;
}
