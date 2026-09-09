using System;

namespace AAuth.Agent;

/// <summary>
/// Mutable single-value carrier-token holder shared between an
/// <see cref="HttpSig.AAuthSigningHandler"/> and a <see cref="ChallengeHandler"/>.
/// Lets the challenge handler swap the active carrier token (agent token →
/// auth token) without rebuilding the HttpClient pipeline.
/// </summary>
/// <remarks>
/// Not thread-safe by design. The current sample agents are single-threaded.
/// If concurrent requests through the same agent pipeline are ever needed,
/// replace the field with an <see cref="System.Threading.Interlocked"/>
/// or <c>AsyncLocal&lt;T&gt;</c> approach so an in-flight exchange does not
/// race with parallel signed requests.
/// </remarks>
public sealed class AAuthTokenHolder
{
    // volatile gives us release/acquire semantics on the reference write so
    // a parallel reader running on a different thread observes Update()'s
    // value without needing a full memory barrier. Reference writes are
    // atomic on .NET; volatile only adds ordering.
    private sealed record Carrier(string Token, string? Upstream, string? Mission, string? AgentToken = null);
    private volatile Carrier _carrier;
    private static readonly System.Net.Http.HttpRequestOptionsKey<string> SourceToken = new("AAuth.CarrierSourceToken");

    /// <summary>Create the holder with an initial token (typically the agent token).</summary>
    public AAuthTokenHolder(string initialToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(initialToken);
        _carrier = new(initialToken, null, null);
    }

    /// <summary>
    /// Create the holder without an initial token. The first call to
    /// <see cref="TokenRefreshHandler"/> will acquire the token lazily.
    /// </summary>
    public AAuthTokenHolder()
    {
        _carrier = new(string.Empty, null, null);
    }

    /// <summary>Returns <c>true</c> when a token has been set.</summary>
    public bool HasToken => _carrier.Token.Length > 0;

    /// <summary>Return the current carrier token.</summary>
    public string Current => _carrier.Token;

    public string SelectForRequest(System.Net.Http.HttpRequestMessage request, string agentToken, string signingKeyThumbprint)
    {
        request.Options.Set(SourceToken, agentToken);
        var carrier = _carrier;
        var token = carrier.Token;
        if (string.IsNullOrEmpty(token)) return agentToken;
        if (carrier.AgentToken is not null && carrier.AgentToken != agentToken) return agentToken;
        request.Options.TryGetValue(MissionForwardingHandler.UpstreamAuthorization, out var upstream);
        if (!string.Equals(carrier.Upstream, upstream, StringComparison.Ordinal)
            || !string.Equals(carrier.Mission, MissionHeader(request), StringComparison.Ordinal))
            return agentToken;
        var payload = TokenRefreshHandler.ReadPayloadUnsafe(token);
        var agent = TokenRefreshHandler.ReadPayloadUnsafe(agentToken);
        var audience = request.Options.TryGetValue(AAuthRequestOptions.ResourceIdentifier, out var resource)
            ? resource : request.RequestUri?.GetLeftPart(UriPartial.Authority);
        if (!AAuth.Tokens.AccountBinding.Matches(AAuthRequestOptions.GetAccount(request), AAuth.Tokens.AccountBinding.Read(payload))
            || (string?)payload["aud"] != audience
            || (string?)payload["agent"] != (string?)agent["sub"]
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

    internal void UpdateFromExchange(string token, System.Net.Http.HttpRequestMessage request)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);
        request.Options.TryGetValue(MissionForwardingHandler.UpstreamAuthorization, out var upstream);
        request.Options.TryGetValue(SourceToken, out var agentToken);
        _carrier = new(token, upstream, MissionHeader(request), agentToken);
    }

    private static string? MissionHeader(System.Net.Http.HttpRequestMessage request)
        => request.Headers.TryGetValues(AAuthMissionHeader.Name, out var values) ? string.Join(",", values) : null;
}
