using System;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Headers;

namespace AAuth.Agent;

/// <summary>
/// <see cref="DelegatingHandler"/> that auto-handles AAuth 401 challenges.
/// On a <c>401</c> with <c>AAuth-Requirement: requirement=auth-token</c>,
/// extracts the resource token, exchanges it at the agent's PS, swaps the
/// carrier token in the shared <see cref="AAuthTokenHolder"/>, and retries
/// the original request once.
/// </summary>
/// <remarks>
/// Sits <em>above</em> <see cref="HttpSig.AAuthSigningHandler"/> in the
/// handler chain so the retry re-signs through the same pipeline. The
/// signing handler reads the carrier token via the holder, so a single
/// pipeline transparently transitions from agent-token to auth-token
/// signing across the challenge. The exchange itself runs through a
/// <em>separate</em> signed pipeline configured by the caller — it must
/// always sign with the agent token, never with the (not-yet-issued) auth
/// token. See <see cref="TokenExchangeClient"/>.
/// </remarks>
public sealed class ChallengeHandler : DelegatingHandler
{
    private readonly TokenExchangeClient _exchange;
    private readonly AAuthTokenHolder _holder;
    private readonly string? _personServer;
    private readonly Func<AAuthInteraction, CancellationToken, Task>? _onInteractionRequired;
    private readonly DeferredPollerOptions? _pollerOptions;
    private readonly Func<string?>? _upstreamTokenProvider;

    /// <summary>Create the challenge handler.</summary>
    /// <param name="exchange">Token exchange client (configured with the agent token).</param>
    /// <param name="holder">Shared carrier-token holder used by the signer.</param>
    /// <param name="personServer">
    /// PS issuer URL where resource tokens are exchanged. Ignored when
    /// <paramref name="upstreamTokenProvider"/> returns a non-null value
    /// — call chaining routes per <see cref="Server.CallChainingRouter"/>.
    /// </param>
    /// <param name="onInteractionRequired">
    /// Optional callback invoked when the PS returns <c>202 + requirement=interaction</c>
    /// during the embedded exchange. Hosts wire this to "display URL to user" UI.
    /// When <see langword="null"/>, a deferred PS response surfaces as an exception.
    /// </param>
    /// <param name="pollerOptions">Optional polling cadence/timeout override.</param>
    /// <param name="upstreamTokenProvider">
    /// Optional provider invoked per challenge that supplies the inbound
    /// (caller's) auth token. When it returns a non-null value the embedded
    /// exchange is treated as a call-chaining exchange: the destination
    /// PS/AS is resolved via <see cref="Server.CallChainingRouter"/> and the
    /// returned token is passed as <c>upstream_token</c> in the request body.
    /// </param>
    public ChallengeHandler(
        TokenExchangeClient exchange,
        AAuthTokenHolder holder,
        string? personServer,
        Func<AAuthInteraction, CancellationToken, Task>? onInteractionRequired = null,
        DeferredPollerOptions? pollerOptions = null,
        Func<string?>? upstreamTokenProvider = null)
    {
        ArgumentNullException.ThrowIfNull(exchange);
        ArgumentNullException.ThrowIfNull(holder);
        if (personServer is null && upstreamTokenProvider is null)
            throw new ArgumentException(
                "Either personServer or upstreamTokenProvider must be supplied.",
                nameof(personServer));

        _exchange = exchange;
        _holder = holder;
        _personServer = personServer;
        _onInteractionRequired = onInteractionRequired;
        _pollerOptions = pollerOptions;
        _upstreamTokenProvider = upstreamTokenProvider;
    }

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

        if (response.StatusCode != HttpStatusCode.Unauthorized)
        {
            return response;
        }

        if (!response.Headers.TryGetValues(AAuthRequirementHeader.Name, out var values))
        {
            return response;
        }

        AAuthRequirementHeader.ParsedRequirement? requirement = null;
        // The header MAY appear more than once; parse each value
        // independently and pick the first auth-token requirement we
        // recognise. Concatenating with ',' and re-parsing would only work
        // if AAuthRequirementHeader.Parse spoke full RFC 9651 dictionary
        // grammar, which it deliberately doesn't.
        foreach (var raw in values)
        {
            if (string.IsNullOrWhiteSpace(raw)) { continue; }
            try
            {
                var candidate = AAuthRequirementHeader.Parse(raw);
                if (candidate.Requirement == AAuthRequirementHeader.AuthTokenRequirement
                    && candidate.ResourceToken is not null)
                {
                    requirement = candidate;
                    break;
                }
            }
            catch (FormatException)
            {
                // Skip malformed individual values; another header line may
                // still carry a usable requirement.
            }
        }

        if (requirement is null)
        {
            return response;
        }

        // Got an auth-token challenge. Exchange and retry.
        using var activity = AAuthDiagnostics.Source.StartActivity("AAuth.ChallengeExchange");

        // Call-chaining path: when the host has surfaced an inbound auth
        // token, send it as upstream_token and route the exchange per
        // §Call Chaining instead of using the static personServer.
        var upstreamToken = _upstreamTokenProvider?.Invoke();
        var targetServer = upstreamToken is not null
            ? Server.CallChainingRouter.ResolveDownstreamServer(upstreamToken)
            : _personServer
                ?? throw new InvalidOperationException(
                    "ChallengeHandler has no personServer and the upstream token provider returned null.");

        var authToken = await _exchange
            .ExchangeAsync(targetServer, requirement.ResourceToken!,
                _onInteractionRequired, _pollerOptions,
                upstreamToken: upstreamToken, cancellationToken)
            .ConfigureAwait(false);
        _holder.Update(authToken);

        // Clone the original request to retry — HttpRequestMessage is
        // single-use, and the signing handler downstream will re-sign with
        // the new carrier token (read via the holder) when the clone is
        // sent. Note: the original request body, if any, is forwarded
        // verbatim; streaming bodies that are not re-readable will fail
        // here, which is a known limitation.
        response.Dispose();
        var retry = await CloneAsync(request, cancellationToken).ConfigureAwait(false);
        var result = await base.SendAsync(retry, cancellationToken).ConfigureAwait(false);
        // Reassign the response's RequestMessage to the caller-owned
        // original so diagnostics (EnsureSuccessStatusCode, loggers) keep
        // working, then dispose the short-lived clone. This avoids both
        // (a) retaining the cloned ByteArrayContent on the response until
        // GC and (b) handing callers a response backed by a disposed
        // request — the trade-off of the previous `using` placement.
        result.RequestMessage = request;
        retry.Dispose();
        return result;
    }

    private static async Task<HttpRequestMessage> CloneAsync(
        HttpRequestMessage source, CancellationToken cancellationToken)
    {
        var clone = new HttpRequestMessage(source.Method, source.RequestUri)
        {
            Version = source.Version,
            VersionPolicy = source.VersionPolicy,
        };

        if (source.Content is not null)
        {
            var bytes = await source.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
            var content = new ByteArrayContent(bytes);
            foreach (var header in source.Content.Headers)
            {
                content.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
            clone.Content = content;
        }

        foreach (var header in source.Headers)
        {
            // Strip prior signature headers so the signer re-emits them.
            if (header.Key is "Signature" or "Signature-Input" or "Signature-Key")
            {
                continue;
            }
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        // HttpRequestMessage.Options copying is intentionally omitted —
        // AAuth headers and the retry semantics here do not depend on
        // request options, and the HttpRequestOptions API on .NET 10 has
        // no public bulk-copy helper. Revisit if a future phase plumbs
        // request-scoped state through options.

        return clone;
    }
}
