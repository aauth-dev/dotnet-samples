using System;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Discovery;
using AAuth.Headers;

namespace AAuth.Server.CallChaining;

/// <summary>
/// Enables a resource to act as an agent for downstream resources
/// (call-chaining): exchanges a downstream resource token at the person server
/// the upstream token names, carrying the upstream token as <c>upstream_token</c>
/// and the token presented downstream as <c>presented_token</c>.
/// </summary>
/// <remarks>
/// Routing (§Call Chaining): the upstream person token's <c>iss</c>, or the
/// upstream auth token's <c>ps</c>.
/// </remarks>
public sealed class CallChainingHandler
{
    private readonly TokenExchangeClient _exchangeClient;
    private readonly CallChainingOptions _options;

    /// <summary>Create the call-chaining handler.</summary>
    /// <param name="exchangeClient">Exchange client configured with the resource's agent identity.</param>
    /// <param name="options">Call-chaining configuration.</param>
    public CallChainingHandler(TokenExchangeClient exchangeClient, CallChainingOptions options)
    {
        ArgumentNullException.ThrowIfNull(exchangeClient);
        ArgumentNullException.ThrowIfNull(options);
        _exchangeClient = exchangeClient;
        _options = options;
    }

    /// <summary>
    /// Exchange the <paramref name="resourceToken"/> at the upstream token's
    /// person server, including <paramref name="upstreamToken"/>.
    /// </summary>
    /// <param name="upstreamToken">
    /// The person or auth token this resource's caller presented. Included as
    /// <c>upstream_token</c>; it also selects the person server.
    /// </param>
    /// <param name="resourceToken">
    /// The resource token issued by the downstream resource's challenge.
    /// </param>
    /// <param name="presentedToken">
    /// The token this intermediary presented to the downstream resource (the
    /// resource token's <c>presented_jti</c>), sent as <c>presented_token</c>.
    /// </param>
    /// <param name="onInteractionRequired">
    /// Optional callback invoked when the downstream PS returns <c>202</c>
    /// with an interaction requirement. When <see langword="null"/> and a 202
    /// is received, the call throws.
    /// </param>
    /// <param name="pollerOptions">Optional polling cadence/timeout override.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="account">Optional account the downstream request is for.</param>
    /// <returns>The auth token for the downstream resource.</returns>
    public async Task<string> ExchangeForDownstreamAsync(
        string upstreamToken,
        string resourceToken,
        string presentedToken,
        Func<Interaction, CancellationToken, Task>? onInteractionRequired = null,
        DeferredPollerOptions? pollerOptions = null,
        CancellationToken cancellationToken = default,
        string? account = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(upstreamToken);
        ArgumentException.ThrowIfNullOrEmpty(resourceToken);
        ArgumentException.ThrowIfNullOrEmpty(presentedToken);

        var targetServer = CallChainingRouter.ResolveDownstreamServer(upstreamToken, _exchangeClient.EgressPolicy);

        return await _exchangeClient.ExchangeAsync(
            targetServer,
            resourceToken,
            new TokenExchangeRequest
            {
                OnInteractionRequired = onInteractionRequired,
                PollerOptions = pollerOptions,
                UpstreamToken = upstreamToken,
                PresentedToken = presentedToken,
                Account = account,
            },
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Determine the downstream person server from the upstream token.</summary>
    internal static string ResolveDownstreamServer(string upstreamToken)
        => CallChainingRouter.ResolveDownstreamServer(upstreamToken);
}
