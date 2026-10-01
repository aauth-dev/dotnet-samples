using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Agent;

/// <summary>
/// DelegatingHandler for call-chaining intermediaries: attaches the upstream
/// token (the person or auth token the calling agent presented) to each
/// downstream request so the challenge handler sends it as <c>upstream_token</c>
/// and routes to the PS it names. The intermediary sends no mission of its own;
/// the PS copies the upstream <c>mission_s256</c> (§Call Chaining).
/// </summary>
public sealed class MissionForwardingHandler : DelegatingHandler
{
    internal static readonly HttpRequestOptionsKey<string?> UpstreamAuthorization = new("AAuth.UpstreamAuthorization");
    private readonly System.Func<string?> _upstreamTokenProvider;

    /// <summary>Creates the handler.</summary>
    /// <param name="upstreamTokenProvider">Delegate returning the upstream token, or null if unavailable.</param>
    public MissionForwardingHandler(System.Func<string?> upstreamTokenProvider)
    {
        _upstreamTokenProvider = upstreamTokenProvider ?? throw new System.ArgumentNullException(nameof(upstreamTokenProvider));
    }

    /// <inheritdoc/>
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        request.Options.Set(UpstreamAuthorization,
            request.Options.TryGetValue(AAuthRequestOptions.UpstreamToken, out var explicitToken) ? explicitToken : _upstreamTokenProvider());
        return base.SendAsync(request, cancellationToken);
    }
}
