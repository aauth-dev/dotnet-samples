using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using Xunit;

namespace AAuth.Tests.Agent;

public class DeferredPollerTests
{
    private static readonly Uri PendingUrl = new("https://ps.example/pending/abc");

    [Fact]
    public void DefaultPollInterval_Is5Seconds()
    {
        var options = new DeferredPollerOptions();
        Assert.Equal(TimeSpan.FromSeconds(5), options.DefaultPollInterval);
    }

    [Fact]
    public async Task PollAsync_ReturnsFirstNon202Response()
    {
        var handler = new ScriptedHandler(
            r => Respond(HttpStatusCode.Accepted, retryAfter: TimeSpan.Zero),
            r => Respond(HttpStatusCode.OK, body: "{\"auth_token\":\"abc\"}"));
        using var client = new HttpClient(handler);
        var poller = new DeferredPoller(client, new DeferredPollerOptions
        {
            DefaultPollInterval = TimeSpan.FromMilliseconds(10),
            MinPollInterval = TimeSpan.Zero,
        });

        using var terminal = await poller.PollAsync(PendingUrl);

        Assert.Equal(HttpStatusCode.OK, terminal.StatusCode);
        Assert.Equal(2, handler.CallCount);
    }

    [Fact]
    public async Task PollAsync_HonoursRetryAfterDelta()
    {
        var observed = new List<DateTimeOffset>();
        var handler = new ScriptedHandler(
            r => { observed.Add(DateTimeOffset.UtcNow); return Respond(HttpStatusCode.Accepted, retryAfter: TimeSpan.FromMilliseconds(150)); },
            r => { observed.Add(DateTimeOffset.UtcNow); return Respond(HttpStatusCode.OK, body: "{}"); });
        using var client = new HttpClient(handler);
        var poller = new DeferredPoller(client, new DeferredPollerOptions
        {
            DefaultPollInterval = TimeSpan.FromMilliseconds(10),
            MinPollInterval = TimeSpan.Zero,
        });

        using var terminal = await poller.PollAsync(PendingUrl);

        Assert.Equal(HttpStatusCode.OK, terminal.StatusCode);
        Assert.True(observed[1] - observed[0] >= TimeSpan.FromMilliseconds(120),
            $"Expected >=120ms delay, observed {(observed[1] - observed[0]).TotalMilliseconds}ms.");
    }

    [Fact]
    public async Task PollAsync_TimesOut_WhenServerKeepsReturning202()
    {
        var handler = new ScriptedHandler(r => Respond(HttpStatusCode.Accepted, retryAfter: TimeSpan.FromMilliseconds(10)));
        using var client = new HttpClient(handler);
        var poller = new DeferredPoller(client, new DeferredPollerOptions
        {
            MaxTotalWait = TimeSpan.FromMilliseconds(50),
            DefaultPollInterval = TimeSpan.FromMilliseconds(10),
            MinPollInterval = TimeSpan.Zero,
        });

        await Assert.ThrowsAsync<TimeoutException>(() => poller.PollAsync(PendingUrl));
    }

    [Fact]
    public async Task PollAsync_RaisesCancellation()
    {
        var handler = new ScriptedHandler(r => Respond(HttpStatusCode.Accepted, retryAfter: TimeSpan.FromMilliseconds(100)));
        using var client = new HttpClient(handler);
        var poller = new DeferredPoller(client, new DeferredPollerOptions
        {
            MaxTotalWait = TimeSpan.FromSeconds(10),
            DefaultPollInterval = TimeSpan.FromMilliseconds(100),
            MinPollInterval = TimeSpan.Zero,
        });
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => poller.PollAsync(PendingUrl, cts.Token));
    }

    [Fact]
    public async Task PollAsync_FiresOnPoll_ForEachAttempt()
    {
        var observed = new List<HttpStatusCode>();
        var handler = new ScriptedHandler(
            r => Respond(HttpStatusCode.Accepted, retryAfter: TimeSpan.Zero),
            r => Respond(HttpStatusCode.Accepted, retryAfter: TimeSpan.Zero),
            r => Respond(HttpStatusCode.OK, body: "{}"));
        using var client = new HttpClient(handler);
        var poller = new DeferredPoller(client, new DeferredPollerOptions
        {
            DefaultPollInterval = TimeSpan.FromMilliseconds(1),
            MinPollInterval = TimeSpan.Zero,
        })
        {
            OnPoll = r => observed.Add(r.StatusCode),
        };

        using var terminal = await poller.PollAsync(PendingUrl);

        Assert.Equal(new[]
        {
            HttpStatusCode.Accepted,
            HttpStatusCode.Accepted,
            HttpStatusCode.OK,
        }, observed);
    }

    [Fact]
    public async Task PollAsync_ThrowsTimeout_BeforeSleepingPastBudget()
    {
        // MaxTotalWait is enforced before backing off — a large Retry-After must not
        // cause the poller to sleep well past the budget before timing out.
        var handler = new ScriptedHandler(
            r => Respond(HttpStatusCode.Accepted, retryAfter: TimeSpan.FromSeconds(30)));
        using var client = new HttpClient(handler);
        var poller = new DeferredPoller(client, new DeferredPollerOptions
        {
            MaxTotalWait = TimeSpan.FromMilliseconds(50),
            DefaultPollInterval = TimeSpan.FromMilliseconds(10),
            MinPollInterval = TimeSpan.Zero,
        });

        var sw = System.Diagnostics.Stopwatch.StartNew();
        await Assert.ThrowsAsync<TimeoutException>(() => poller.PollAsync(PendingUrl));
        sw.Stop();

        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5),
            $"Expected fast timeout (clamped to budget), but waited {sw.Elapsed.TotalSeconds:0.##}s.");
    }

    private static HttpResponseMessage Respond(
        HttpStatusCode status,
        TimeSpan? retryAfter = null,
        string? body = null)
    {
        var msg = new HttpResponseMessage(status);
        if (body is not null)
        {
            msg.Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json");
        }
        if (retryAfter is { } delta)
        {
            msg.Headers.RetryAfter = new RetryConditionHeaderValue(delta);
        }
        return msg;
    }

    private sealed class ScriptedHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage>[] _script;
        public int CallCount { get; private set; }

        public ScriptedHandler(params Func<HttpRequestMessage, HttpResponseMessage>[] script)
        {
            _script = script;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // The last script entry is reused if the poller keeps coming back.
            var idx = Math.Min(CallCount, _script.Length - 1);
            var step = _script[idx];
            CallCount++;
            return Task.FromResult(step(request));
        }
    }
}
