using System;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace AAuth.Person;

/// <summary>
/// Authorization guard for the PS approval/consent decision
/// (§PS Approval Endpoint Authentication). When the PS approval/consent endpoint
/// is reachable beyond a single-user local deployment, the PS MUST authenticate
/// the approving party before acting on a consent or denial decision — an
/// unauthenticated endpoint lets a remote party consent on the user's behalf,
/// breaking the agent-person binding invariant.
/// </summary>
/// <remarks>
/// <para>The PS does not own the browser consent page — the host maps it and
/// records the verdict (via <see cref="IPersonPendingStore"/> or the governance
/// deferred-consent store). The host calls
/// <see cref="IsAuthorizedAsync"/> before recording a verdict, supplying its own
/// authentication delegate (an operator session cookie, a signed operator
/// request, or an equivalent out-of-band channel).</para>
/// <para>A loopback-only deployment is exempt (OS-level access control on the
/// loopback interface). When the request is not from loopback and no authenticator
/// is supplied, the decision is denied (default-deny).</para>
/// </remarks>
public static class PsApprovalGuard
{
    /// <summary>
    /// Whether the approving party may act on a consent/denial decision. A loopback
    /// request is exempt; a non-loopback request MUST be authenticated by
    /// <paramref name="authenticator"/>. When <paramref name="authenticator"/> is
    /// <see langword="null"/> a non-loopback request is denied (default-deny).
    /// </summary>
    /// <param name="context">The incoming approval/consent request.</param>
    /// <param name="authenticator">
    /// App-supplied delegate returning <see langword="true"/> when the approving
    /// party is authenticated. Not consulted for loopback requests.
    /// </param>
    public static async ValueTask<bool> IsAuthorizedAsync(
        HttpContext context,
        Func<HttpContext, ValueTask<bool>>? authenticator)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (IsLoopback(context))
        {
            return true;
        }

        if (authenticator is null)
        {
            return false;
        }

        return await authenticator(context).ConfigureAwait(false);
    }

    /// <summary>
    /// Whether the request originates from the loopback interface — its remote IP
    /// is a loopback address, or equals the server's local IP (same host). A
    /// request with no connection remote IP is treated as <em>not</em> loopback so
    /// the default-deny path applies unless an authenticator allows it.
    /// </summary>
    public static bool IsLoopback(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var remote = context.Connection.RemoteIpAddress;
        if (remote is null)
        {
            return false;
        }

        if (IPAddress.IsLoopback(remote))
        {
            return true;
        }

        var local = context.Connection.LocalIpAddress;
        return local is not null && remote.Equals(local);
    }
}
