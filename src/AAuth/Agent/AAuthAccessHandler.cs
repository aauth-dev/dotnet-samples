using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Headers;

namespace AAuth.Agent;

/// <summary>
/// <see cref="DelegatingHandler"/> that drives the agent side of the
/// resource-managed (two-party) <c>AAuth-Access</c> flow
/// (§AAuth-Access Response Header, §Resource-Managed Authorization).
/// </summary>
/// <remarks>
/// <para>
/// Placed <b>outer</b> of <c>AAuthSigningHandler</c> and <b>inner</b> of
/// <c>InteractionHandler</c> in the pipeline. Before forwarding a request it sets
/// <c>Authorization: AAuth &lt;token68&gt;</c> from the per-origin store when one
/// is held; the signer then automatically covers the <c>authorization</c>
/// component (binding the opaque token to the signature). After a response it
/// captures any <c>AAuth-Access</c> header and updates the store, supporting
/// rolling refresh (the resource MAY return a new value on any response).
/// </para>
/// <para>
/// Because it sits inside the interaction handler, it also observes the terminal
/// <c>200</c> produced by the <c>202 → poll → 200</c> handshake, capturing the
/// <c>AAuth-Access</c> the resource issues once authorization completes.
/// </para>
/// </remarks>
public sealed class AAuthAccessHandler : DelegatingHandler
{
    private readonly IAAuthAccessStore _store;

    /// <summary>Create the handler over the given per-origin token store.</summary>
    public AAuthAccessHandler(IAAuthAccessStore store)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
    }

    /// <inheritdoc/>
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var origin = GetOrigin(request.RequestUri);

        // Replay: present the stored opaque token for this origin, unless the
        // caller already set an Authorization header itself. The signer covers
        // `authorization` automatically once it is present.
        if (origin is not null
            && request.Headers.Authorization is null
            && _store.TryGet(origin, out var stored)
            && AAuthAccessHeader.IsValidToken68(stored))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue(
                AAuthAccessHeader.AuthorizationScheme, stored);
        }

        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

        // Capture: a response MAY carry a (possibly new) AAuth-Access token.
        if (origin is not null
            && response.Headers.TryGetValues(AAuthAccessHeader.Name, out var values))
        {
            // Per spec (§AAuth-Access), reject more than one credential: exactly
            // one header value, and it must be a valid token68. Anything else is
            // ignored rather than stored.
            string? single = null;
            var count = 0;
            foreach (var value in values)
            {
                single = value;
                count++;
                if (count > 1)
                {
                    break;
                }
            }

            if (count == 1 && AAuthAccessHeader.TryParseAccess(single, out var token))
            {
                _store.Set(origin, token); // last-writer-wins (rolling refresh)
            }
        }

        return response;
    }

    // Normalize the request target to an origin key: lowercase scheme + authority
    // (host[:port]). Query and path are irrelevant — the token is per resource.
    private static string? GetOrigin(Uri? uri)
    {
        if (uri is null || !uri.IsAbsoluteUri)
        {
            return null;
        }

        return $"{uri.Scheme.ToLowerInvariant()}://{uri.Authority.ToLowerInvariant()}";
    }
}
