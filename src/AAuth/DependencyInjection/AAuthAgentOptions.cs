using System;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Headers;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth;

/// <summary>
/// Options for configuring an AAuth agent via <see cref="AAuthAgentServiceCollectionExtensions.AddAAuthAgent"/>.
/// </summary>
public sealed class AAuthAgentOptions
{
    /// <summary>The agent's signing key (must have private component).</summary>
    public IAAuthKey Key { get; set; } = null!;

    /// <summary>
    /// Person Server URL. When set together with <see cref="TokenRefresher"/>,
    /// enables automatic 401 challenge handling with lazy token acquisition.
    /// </summary>
    public string? PersonServer { get; set; }

    /// <summary>
    /// Callback invoked when the PS requires user interaction during token exchange.
    /// </summary>
    public Func<Interaction, CancellationToken, Task>? OnInteractionRequired { get; set; }

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

    /// <summary>
    /// Enable the resource-managed (two-party) <c>AAuth-Access</c> opaque-token
    /// flow: capture <c>AAuth-Access</c> response headers and replay them as
    /// <c>Authorization: AAuth &lt;token68&gt;</c>, bound to the signature
    /// (§AAuth-Access Response Header). Usually paired with
    /// <see cref="OnResourceInteraction"/> so the resource's interaction handshake
    /// is driven automatically.
    /// </summary>
    public bool EnableResourceManagedAccess { get; set; }

    /// <summary>
    /// Optional per-origin <see cref="IAAuthAccessStore"/> for the resource-managed
    /// flow. When <see langword="null"/> (default) an in-memory store is used.
    /// </summary>
    public IAAuthAccessStore? AAuthAccessStore { get; set; }
}
