using System;

namespace AAuth;

/// <summary>
/// Shared URL validation helpers used by token builders, well-known endpoint
/// validation, and sample wiring.
/// </summary>
/// <remarks>
/// The AAuth spec requires <c>https://</c> for issuer/audience/PS URLs.
/// For local development the loopback <c>http://localhost</c> / <c>http://127.0.0.1</c>
/// hosts are also accepted so the WhoAmI and AgentConsole samples can run
/// against the default Kestrel HTTP binding without a dev certificate. Production
/// resources MUST still serve over HTTPS — there is no environment switch here;
/// the loopback exemption is purely a function of <see cref="Uri.IsLoopback"/>.
/// </remarks>
internal static class AAuthUrl
{
    /// <summary>
    /// True when <paramref name="value"/> is an absolute URL with scheme
    /// <c>https</c>, or an absolute <c>http</c> URL pointing at a loopback host.
    /// </summary>
    public static bool IsHttpsOrLoopback(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            return false;
        }
        if (uri.Scheme == Uri.UriSchemeHttps)
        {
            return true;
        }
        return uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback;
    }
}
