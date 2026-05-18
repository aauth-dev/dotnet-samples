using System;
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
    private readonly string _personServer;

    /// <summary>Create the challenge handler.</summary>
    /// <param name="exchange">Token exchange client (configured with the agent token).</param>
    /// <param name="holder">Shared carrier-token holder used by the signer.</param>
    /// <param name="personServer">PS issuer URL where resource tokens are exchanged.</param>
    public ChallengeHandler(
        TokenExchangeClient exchange,
        AAuthTokenHolder holder,
        string personServer)
    {
        ArgumentNullException.ThrowIfNull(exchange);
        ArgumentNullException.ThrowIfNull(holder);
        ArgumentException.ThrowIfNullOrEmpty(personServer);

        _exchange = exchange;
        _holder = holder;
        _personServer = personServer;
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

        AAuthRequirementHeader.ParsedRequirement requirement;
        try
        {
            // The header MAY appear more than once; concatenate per RFC 9651
            // (== RFC 8941 §1). The aggregate is also a valid dictionary —
            // the agent re-parses the joined form.
            requirement = AAuthRequirementHeader.Parse(string.Join(", ", values));
        }
        catch (FormatException)
        {
            return response;
        }

        if (requirement.Requirement != AAuthRequirementHeader.AuthTokenRequirement
            || requirement.ResourceToken is null)
        {
            return response;
        }

        // Got an auth-token challenge. Exchange and retry.
        var authToken = await _exchange
            .ExchangeAsync(_personServer, requirement.ResourceToken, cancellationToken)
            .ConfigureAwait(false);
        _holder.Update(authToken);

        // Clone the original request to retry — HttpRequestMessage is
        // single-use, and the signing handler downstream will re-sign with
        // the new carrier token (read via the holder) when the clone is
        // sent. Note: the original request body, if any, is forwarded
        // verbatim; streaming bodies that are not re-readable will fail
        // here, which is a known limitation tracked for Phase 3.
        response.Dispose();
        using var retry = await CloneAsync(request, cancellationToken).ConfigureAwait(false);
        return await base.SendAsync(retry, cancellationToken).ConfigureAwait(false);
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
