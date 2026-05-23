using System;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Headers;

namespace AAuth.DependencyInjection;

/// <summary>
/// Options for configuring an AAuth agent via <see cref="AAuthAgentServiceCollectionExtensions.AddAAuthAgent"/>.
/// </summary>
public sealed class AAuthAgentOptions
{
    /// <summary>The agent's signing key (must have private component).</summary>
    public IAAuthKey Key { get; set; } = null!;

    /// <summary>The agent token JWT. Required for challenge handling.</summary>
    public string? AgentToken { get; set; }

    /// <summary>
    /// Person Server URL. When set, enables automatic 401 challenge handling.
    /// If null but <see cref="AgentToken"/> contains a <c>ps</c> claim, that is used.
    /// </summary>
    public string? PersonServer { get; set; }

    /// <summary>
    /// Callback invoked when the PS requires user interaction during token exchange.
    /// </summary>
    public Func<AAuthInteraction, CancellationToken, Task>? OnInteractionRequired { get; set; }

    /// <summary>
    /// Callback invoked when a resource returns 202 + requirement=interaction.
    /// Receives the user-facing URL and code.
    /// </summary>
    public Func<string, string, CancellationToken, Task>? OnResourceInteraction { get; set; }

    /// <summary>
    /// Callback invoked when a resource returns 202 + requirement=approval.
    /// </summary>
    public Func<CancellationToken, Task>? OnApprovalPending { get; set; }

    /// <summary>
    /// Token refresher. When set, the SDK auto-refreshes before expiry.
    /// </summary>
    public ITokenRefresher? TokenRefresher { get; set; }

    /// <summary>
    /// Polling timeout for deferred responses. Default: 5 minutes.
    /// </summary>
    public TimeSpan PollingTimeout { get; set; } = TimeSpan.FromMinutes(5);
}
