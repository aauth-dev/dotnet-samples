using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Agent;

/// <summary>
/// Context passed to <see cref="ITokenRefresher"/> containing everything
/// needed to refresh the agent token without external state tracking.
/// </summary>
public sealed record TokenRefreshContext
{
    /// <summary>The current (expiring) agent token.</summary>
    public required string CurrentToken { get; init; }

    /// <summary>
    /// Token issuer URL (from the <c>iss</c> claim). For AP-enrolled agents this is the
    /// Agent Provider URL; for self-issued agents this is the service's own URL.
    /// </summary>
    public required string Issuer { get; init; }

    /// <summary>Agent identifier (extracted from the token's <c>sub</c> claim).</summary>
    public required string AgentId { get; init; }

    /// <summary>Key ID used for signing.</summary>
    public required string KeyId { get; init; }
}

/// <summary>
/// Consumer-implemented token refresh strategy. The SDK calls this when the
/// current token's <c>exp</c> claim is within the refresh threshold. The SDK
/// takes the returned token and updates the pipeline automatically.
/// </summary>
public interface ITokenRefresher
{
    /// <summary>
    /// Refresh the agent token. Returns the new compact JWT.
    /// </summary>
    Task<string> RefreshAsync(TokenRefreshContext context, CancellationToken cancellationToken);
}
