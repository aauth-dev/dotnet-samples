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
    private sealed record Carrier(string Token, string? Upstream, string? Mission, string? AgentToken = null);
    private volatile Carrier _carrier;
    private readonly IAAuthTokenCache _cache;
    private static readonly System.Net.Http.HttpRequestOptionsKey<string> SourceToken = new("AAuth.CarrierSourceToken");

    /// <summary>Create the holder with an initial token (typically the agent token).</summary>
    public AAuthTokenHolder(string initialToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(initialToken);
        _carrier = new(initialToken, null, null);
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
        _carrier = new(string.Empty, null, null);
        _cache = cache ?? new InMemoryAAuthTokenCache();
    }

    /// <summary>Returns <c>true</c> when a token has been set.</summary>
    public bool HasToken => _carrier.Token.Length > 0;

    /// <summary>Return the current carrier token.</summary>
    public string Current => _carrier.Token;

    public string SelectForRequest(System.Net.Http.HttpRequestMessage request, string agentToken, string signingKeyThumbprint)
    {
        request.Options.Set(SourceToken, agentToken);
        if (Key(request, agentToken, signingKeyThumbprint) is { } key && _cache.Get(key) is { } cached)
            return cached;
        var carrier = _carrier;
        var token = carrier.Token;
        if (string.IsNullOrEmpty(token)) return agentToken;
        if (carrier.AgentToken is not null && carrier.AgentToken != agentToken) return agentToken;
        request.Options.TryGetValue(MissionForwardingHandler.UpstreamAuthorization, out var upstream);
        if (!string.Equals(carrier.Upstream, upstream, StringComparison.Ordinal)
            || !string.Equals(carrier.Mission, AAuthRequestOptions.GetMissionS256(request), StringComparison.Ordinal))
            return agentToken;
        var payload = TokenRefreshHandler.ReadPayloadUnsafe(token);
        var audience = request.Options.TryGetValue(AAuthRequestOptions.ResourceIdentifier, out var resource)
            ? resource : request.RequestUri?.GetLeftPart(UriPartial.Authority);
        // A person token never carries `account` (#person-tokens); the account binds at the resource token.
        var personToken = (string?)AAuth.Tokens.TokenVerifier.DecodeJsonSegment(token.Split('.')[0], "header")["typ"] == AAuth.Tokens.PersonTokenBuilder.TokenType;
        if ((!personToken && !AAuth.Tokens.AccountBinding.Matches(AAuthRequestOptions.GetAccount(request), AAuth.Tokens.AccountBinding.Read(payload)))
            || (string?)payload["aud"] != audience
            || (long?)payload["exp"] is not { } expiration || expiration <= DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            || AAuth.HttpSig.SignatureKeyParser.Confirmation(payload).ComputeJwkThumbprint() != signingKeyThumbprint)
            return agentToken;
        return token;
    }

    /// <summary>Set the carrier token. Subsequent signed requests use this value.</summary>
    public void Update(string token)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);
        _carrier = new(token, null, null);
    }

    // Single-flight per key: a concurrent request for the same key reuses this acquisition. The
    // result also becomes Current, for pipelines that sign with the holder's latest carrier.
    internal async Task<string> AcquireAsync(System.Net.Http.HttpRequestMessage request, string? presented,
        Func<System.Threading.CancellationToken, Task<string>> acquire, System.Threading.CancellationToken cancellationToken)
    {
        request.Options.TryGetValue(SourceToken, out var agentToken);
        var token = agentToken is not null
            && request.Options.TryGetValue(AAuth.HttpSig.AAuthSigningHandler.SigningKeyContext, out var signingKey)
            && Key(request, agentToken, signingKey.ComputeJwkThumbprint()) is { } key
                ? await _cache.AcquireAsync(key, presented, acquire, cancellationToken).ConfigureAwait(false)
                : await acquire(cancellationToken).ConfigureAwait(false);
        request.Options.TryGetValue(MissionForwardingHandler.UpstreamAuthorization, out var upstream);
        _carrier = new(token, upstream, AAuthRequestOptions.GetMissionS256(request), agentToken);
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
}
