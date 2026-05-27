using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;

namespace AAuth.Agent;

/// <summary>
/// Built-in <see cref="ITokenRefresher"/> that refreshes agent tokens via an
/// Agent Provider's refresh endpoint. Wraps <see cref="AgentProviderClient"/>.
/// </summary>
/// <remarks>
/// Use this for agents enrolled with an AP that need automatic token refresh.
/// The AP identifies the agent by verifying the HTTP signature against the
/// enrolled key (looked up by thumbprint).
/// </remarks>
public sealed class AgentProviderTokenRefresher : ITokenRefresher
{
    private readonly AgentProviderClient _client;
    private readonly string _refreshEndpoint;

    /// <summary>Create a refresher that delegates to an Agent Provider.</summary>
    /// <param name="http">HttpClient for AP communication (reused across refreshes).</param>
    /// <param name="keyStore">Key store containing the agent's durable signing key.</param>
    /// <param name="refreshEndpoint">The AP's refresh/token endpoint URL.</param>
    public AgentProviderTokenRefresher(HttpClient http, IKeyStore keyStore, string refreshEndpoint)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(keyStore);
        ArgumentException.ThrowIfNullOrEmpty(refreshEndpoint);
        _client = new AgentProviderClient(http, keyStore);
        _refreshEndpoint = refreshEndpoint;
    }

    /// <inheritdoc/>
    public Task<string> RefreshAsync(TokenRefreshContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        return _client.RefreshAsync(_refreshEndpoint, context.KeyId, cancellationToken);
    }
}
