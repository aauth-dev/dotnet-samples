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
    /// <c>requirement=interaction</c>. Receives the user-facing URL and code.
    /// The agent should present these to the user (browser redirect, QR, etc.).
    /// </summary>
    public Func<string, string, CancellationToken, Task>? OnInteractionRequired { get; set; }

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
    /// Prevents runaway polling. Default: 100 ms.
    /// </summary>
    public TimeSpan MinPollInterval { get; set; } = TimeSpan.FromMilliseconds(100);

    /// <summary>
    /// Optional callback invoked after each poll response.
    /// </summary>
    public Action<System.Net.Http.HttpResponseMessage>? OnPoll { get; set; }
}
