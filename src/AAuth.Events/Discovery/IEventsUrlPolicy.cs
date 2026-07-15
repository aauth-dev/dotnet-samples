using System;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Events.Discovery;

/// <summary>Trust decision applied before every Events outbound request.</summary>
public interface IEventsUrlPolicy
{
    /// <summary>Returns whether a URL is permitted for network access.</summary>
    ValueTask<bool> IsAllowedAsync(Uri uri, CancellationToken cancellationToken = default);

    /// <summary>Checks a URL and throws a typed failure when it is rejected.</summary>
    async ValueTask EnsureAllowedAsync(Uri uri, CancellationToken cancellationToken = default)
    {
        if (!await IsAllowedAsync(uri, cancellationToken).ConfigureAwait(false))
            throw new AAuth.Events.Http.EventsVerificationException(
                AAuth.Events.Http.EventsVerificationErrorCode.UrlPolicyRejected,
                $"Outbound URL is not trusted: {uri}");
    }
}
