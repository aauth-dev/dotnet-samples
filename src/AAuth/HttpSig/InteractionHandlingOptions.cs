using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.HttpSig;

/// <summary>
/// Options for configuring interaction and approval handling on <see cref="AAuthClientBuilder"/>.
/// </summary>
public sealed class InteractionHandlingOptions
{
    /// <summary>
    /// Callback invoked when the server returns <c>202</c> with
    /// <c>requirement=interaction</c>. Receives the <see cref="AAuth.Headers.Interaction"/>
    /// (<see cref="AAuth.Headers.InteractionSource.Resource"/>); show
    /// <see cref="AAuth.Headers.Interaction.BuildUserUrl"/> to the user. A request's
    /// <see cref="AAuth.Agent.AAuthRequestOptions.InteractionHandler"/> overrides it.
    /// </summary>
    public Func<AAuth.Headers.Interaction, CancellationToken, Task>? OnInteractionRequired { get; set; }

    /// <summary>
    /// Callback invoked when the server returns <c>202</c> with
    /// <c>requirement=approval</c>. No user-facing URL is provided —
    /// the agent simply waits for approval to be granted externally.
    /// </summary>
    public Func<CancellationToken, Task>? OnApprovalPending { get; set; }

    /// <summary>
    /// Maximum time to poll a deferred response before timing out.
    /// Default: 5 minutes.
    /// </summary>
    public TimeSpan PollingTimeout { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Default poll interval when no <c>Retry-After</c> header is present.
    /// Default: 5 seconds.
    /// </summary>
    public TimeSpan DefaultPollInterval { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// When set, sends a <c>Prefer: wait=N</c> header on each poll request.
    /// When <see langword="null"/> (default), no <c>Prefer</c> header is sent.
    /// </summary>
    public int? PreferWaitSeconds { get; set; }

    /// <summary>
    /// Minimum delay between polls regardless of server's <c>Retry-After</c>.
    /// Default: zero, so <c>Retry-After: 0</c> is immediate.
    /// </summary>
    public TimeSpan MinPollInterval { get; set; } = TimeSpan.Zero;

    /// <summary>
    /// Optional callback invoked after each poll response.
    /// </summary>
    public Action<System.Net.Http.HttpResponseMessage>? OnPoll { get; set; }
}
