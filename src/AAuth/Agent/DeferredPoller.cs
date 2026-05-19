using System;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Agent;

/// <summary>
/// Configuration for <see cref="DeferredPoller"/>.
/// </summary>
public sealed record DeferredPollerOptions
{
    /// <summary>Hard upper bound on total polling time.</summary>
    public TimeSpan MaxTotalWait { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Interval to wait between polls when the server does NOT send a
    /// <c>Retry-After</c> header. The spec example uses <c>Retry-After: 0</c>
    /// for immediate first poll, then leaves cadence to the agent.
    /// </summary>
    public TimeSpan DefaultPollInterval { get; init; } = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Minimum delay between polls — clamps a tiny <c>Retry-After: 0</c>
    /// from runaway tight-looping if the server is broken. Set to
    /// <see cref="TimeSpan.Zero"/> to honour the server verbatim.
    /// </summary>
    public TimeSpan MinPollInterval { get; init; } = TimeSpan.FromMilliseconds(100);
}

/// <summary>
/// Polls a deferred-response pending URL until it reaches a terminal state.
/// Used after a server returns <c>202 Accepted</c> with a <c>Location</c>
/// header and (typically) <c>AAuth-Requirement: requirement=interaction</c>
/// to wait for the user to complete out-of-band action. See
/// <see href="https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/">draft-hardt-oauth-aauth-protocol §Deferred Responses</see>.
/// </summary>
/// <remarks>
/// <para>The poller is transport-agnostic: it does not assume what kind of
/// terminal payload sits behind the pending URL. Callers parse the final
/// successful response themselves.</para>
/// <para>The supplied <see cref="HttpClient"/> is expected to be configured
/// with the agent's <see cref="HttpSig.AAuthSigningHandler"/> so each GET
/// to the pending URL is signed — the PS will reject otherwise.</para>
/// </remarks>
public sealed class DeferredPoller
{
    private readonly HttpClient _signedClient;
    private readonly DeferredPollerOptions _options;

    /// <summary>Optional hook fired after every poll, for tracing/UI.</summary>
    public Action<HttpResponseMessage>? OnPoll { get; init; }

    /// <summary>Create a poller.</summary>
    /// <param name="signedClient">HttpClient pre-wired with the agent's signing handler.</param>
    /// <param name="options">Polling cadence/timeout configuration.</param>
    public DeferredPoller(HttpClient signedClient, DeferredPollerOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(signedClient);
        _signedClient = signedClient;
        _options = options ?? new DeferredPollerOptions();
    }

    /// <summary>
    /// Poll <paramref name="pendingUrl"/> until the server returns a
    /// non-<c>202</c> response or the configured timeout elapses.
    /// </summary>
    /// <param name="pendingUrl">Absolute pending URL (the <c>Location</c> value).</param>
    /// <param name="cancellationToken">Caller cancellation.</param>
    /// <returns>The terminal <see cref="HttpResponseMessage"/>. Caller disposes.</returns>
    /// <exception cref="TimeoutException">Total wait budget exhausted.</exception>
    public async Task<HttpResponseMessage> PollAsync(
        Uri pendingUrl,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pendingUrl);
        if (!pendingUrl.IsAbsoluteUri)
        {
            throw new ArgumentException("Pending URL must be absolute.", nameof(pendingUrl));
        }

        var stopwatch = Stopwatch.StartNew();
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (stopwatch.Elapsed >= _options.MaxTotalWait)
            {
                throw new TimeoutException(
                    $"Deferred poll exceeded {_options.MaxTotalWait.TotalSeconds:0.##}s without a terminal response.");
            }

            using var request = new HttpRequestMessage(HttpMethod.Get, pendingUrl);
            var response = await _signedClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
            try
            {
                OnPoll?.Invoke(response);
            }
            catch
            {
                response.Dispose();
                throw;
            }

            if (response.StatusCode != HttpStatusCode.Accepted)
            {
                return response;
            }

            var delay = ComputeDelay(response.Headers.RetryAfter);
            response.Dispose();

            // Don't exceed the overall wait budget on the upcoming sleep.
            var remaining = _options.MaxTotalWait - stopwatch.Elapsed;
            if (remaining <= TimeSpan.Zero)
            {
                throw new TimeoutException(
                    $"Deferred poll exceeded {_options.MaxTotalWait.TotalSeconds:0.##}s without a terminal response.");
            }
            if (delay > remaining)
            {
                delay = remaining;
            }
            if (delay > TimeSpan.Zero)
            {
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private TimeSpan ComputeDelay(RetryConditionHeaderValue? retryAfter)
    {
        if (retryAfter is null)
        {
            return _options.DefaultPollInterval;
        }

        TimeSpan delay;
        if (retryAfter.Delta is { } delta)
        {
            delay = delta;
        }
        else if (retryAfter.Date is { } date)
        {
            delay = date - DateTimeOffset.UtcNow;
            if (delay < TimeSpan.Zero) { delay = TimeSpan.Zero; }
        }
        else
        {
            delay = _options.DefaultPollInterval;
        }

        return delay < _options.MinPollInterval ? _options.MinPollInterval : delay;
    }

    internal static bool TryParseRetryAfterSeconds(string? value, out int seconds)
    {
        seconds = 0;
        return !string.IsNullOrEmpty(value)
            && int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out seconds);
    }
}
