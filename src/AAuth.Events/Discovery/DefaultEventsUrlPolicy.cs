using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Events.Http;

namespace AAuth.Events.Discovery;

/// <summary>Default Events URL policy: HTTPS, safe address literals, and trust callback.</summary>
public sealed class DefaultEventsUrlPolicy : IEventsUrlPolicy
{
    private readonly Func<Uri, CancellationToken, ValueTask<bool>>? _trust;

    /// <summary>Creates a policy with an optional application trust callback.</summary>
    public DefaultEventsUrlPolicy(
        Func<Uri, CancellationToken, ValueTask<bool>>? trustCallback = null)
    {
        _trust = trustCallback;
    }

    /// <summary>Creates a policy using a synchronous trust callback.</summary>
    public DefaultEventsUrlPolicy(Func<Uri, bool> trustCallback)
        : this(trustCallback is null
            ? null
            : (uri, _) => new ValueTask<bool>(trustCallback(uri)))
    {
    }

    /// <inheritdoc />
    public async ValueTask<bool> IsAllowedAsync(Uri uri, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(uri);
        if (!uri.IsAbsoluteUri || uri.UserInfo.Length != 0 ||
            (uri.Scheme != Uri.UriSchemeHttps &&
             !(uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback)))
            return false;

        if (IPAddress.TryParse(uri.Host.Trim('[', ']'), out var address) &&
            !IPAddress.IsLoopback(address) && IsPrivateOrLinkLocal(address))
            return false;

        cancellationToken.ThrowIfCancellationRequested();
        return _trust is null || await _trust(uri, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask EnsureAllowedAsync(Uri uri, CancellationToken cancellationToken = default)
    {
        if (!await IsAllowedAsync(uri, cancellationToken).ConfigureAwait(false))
            throw new EventsVerificationException(
                EventsVerificationErrorCode.UrlPolicyRejected,
                $"Outbound URL is not trusted: {uri}");
    }

    private static bool IsPrivateOrLinkLocal(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            return b[0] == 10 || b[0] == 127 || b[0] == 0 ||
                   (b[0] == 172 && b[1] is >= 16 and <= 31) ||
                   (b[0] == 192 && b[1] == 168) ||
                   (b[0] == 169 && b[1] == 254);
        }
        var v6 = address.GetAddressBytes();
        return (v6[0] & 0xfe) == 0xfc || (v6[0] == 0xfe && (v6[1] & 0xc0) == 0x80);
    }
}
