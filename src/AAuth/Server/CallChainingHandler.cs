using System;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Discovery;
using AAuth.Headers;
using AAuth.HttpSig;

namespace AAuth.Server;

/// <summary>
/// Helper that performs a single downstream token-exchange when a
/// resource is acting as an agent (call chaining). Routes the exchange
/// to the correct PS/AS via <see cref="CallChainingRouter"/> and includes
/// the inbound <c>upstream_token</c> in the request body so the downstream
/// PS/AS can build the nested <c>act</c> claim per §Upstream Token
/// Verification.
/// </summary>
/// <remarks>
/// <para>
/// Most callers should prefer
/// <c>AAuthClientBuilder.WithCallChaining(...)</c>, which composes this
/// helper into the normal challenge / signing / interaction pipeline.
/// This class remains available for callers that want to drive the
/// exchange step manually.
/// </para>
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
    /// Exchange the <paramref name="resourceToken"/> at the downstream PS/AS,
    /// including the <paramref name="upstreamAuthToken"/> to preserve the
    /// delegation chain.
    /// </summary>
    /// <param name="upstreamAuthToken">
    /// The auth token received by this resource from its caller. Included as
    /// <c>upstream_token</c> in the POST body so the downstream PS/AS can
    /// construct a nested <c>act</c> chain.
    /// </param>
    /// <param name="resourceToken">
    /// The resource token issued by the downstream resource's challenge.
    /// </param>
    /// <param name="onInteractionRequired">
    /// Optional callback invoked when the downstream PS returns
    /// <c>202 Accepted</c> with <c>requirement=interaction</c>. Wires the
    /// spec's polling state machine (§Polling for Asynchronous Results,
    /// which explicitly covers call-chaining exchanges) into the helper.
    /// When <see langword="null"/> a deferred response surfaces as an exception.
    /// </param>
    /// <param name="pollerOptions">Optional polling cadence/timeout override.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The chained auth token for the downstream resource.</returns>
    public async Task<string> ExchangeForDownstreamAsync(
        string upstreamAuthToken,
        string resourceToken,
        Func<AAuthInteraction, CancellationToken, Task>? onInteractionRequired = null,
        DeferredPollerOptions? pollerOptions = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(upstreamAuthToken);
        ArgumentException.ThrowIfNullOrEmpty(resourceToken);

        // Determine the downstream PS/AS endpoint from the upstream auth token.
        var targetServer = CallChainingRouter.ResolveDownstreamServer(upstreamAuthToken);

        return await _exchangeClient.ExchangeAsync(
            targetServer,
            resourceToken,
            onInteractionRequired,
            pollerOptions,
            upstreamToken: upstreamAuthToken,
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Determine which PS/AS to send the downstream token request to,
    /// based on the upstream auth token's claims. Forwards to
    /// <see cref="CallChainingRouter.ResolveDownstreamServer(string)"/>;
    /// retained for source compatibility with existing conformance tests.
    /// </summary>
    internal static string ResolveDownstreamServer(string upstreamAuthToken)
        => CallChainingRouter.ResolveDownstreamServer(upstreamAuthToken);
}

