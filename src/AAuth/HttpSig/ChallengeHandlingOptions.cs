using System;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Headers;

namespace AAuth.HttpSig;

/// <summary>
/// Options for configuring challenge handling on <see cref="AAuthClientBuilder"/>.
/// </summary>
public sealed class ChallengeHandlingOptions
{
    /// <summary>
    /// Optional callback invoked when the PS returns <c>202 + requirement=interaction</c>
    /// during token exchange. The caller should display the interaction URL to the user.
    /// When <see langword="null"/>, a deferred PS response surfaces as an exception.
    /// </summary>
    public Func<AAuthInteraction, CancellationToken, Task>? OnInteractionRequired { get; set; }

    /// <summary>
    /// Maximum time to poll a deferred PS response before timing out.
    /// Default: 5 minutes.
    /// </summary>
    public TimeSpan PollingTimeout { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Default poll interval when no <c>Retry-After</c> header is present.
    /// Per spec, default is 5 seconds.
    /// </summary>
    public TimeSpan DefaultPollInterval { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// When set, sends a <c>Prefer: wait=N</c> header on each poll request,
    /// signalling to the server that the client is willing to long-poll for
    /// up to N seconds. Per RFC 7240 §4.3. When <see langword="null"/>
    /// (default), no <c>Prefer</c> header is sent.
    /// </summary>
    public int? PreferWaitSeconds { get; set; }
}
