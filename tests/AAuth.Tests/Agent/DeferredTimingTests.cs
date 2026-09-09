using System.Net;
using System.Net.Http.Headers;
using AAuth.Agent;
using AAuth.Discovery;
using System.Text.Json.Nodes;

namespace AAuth.Tests.Agent;

public class DeferredTimingTests
{
    private static readonly Uri Pending = new("https://ps.example/pending/1");

    [Fact]
    public async Task SlowDownPersistsAcrossOrdinary202And503()
    {
        var clock = new PollClock();
        using var handler = new DeferredExchangeTests.SequenceHandler(
            _ => Response(HttpStatusCode.TooManyRequests, TimeSpan.Zero),
            _ => Response(HttpStatusCode.Accepted, TimeSpan.Zero),
            _ => Response(HttpStatusCode.TooManyRequests, TimeSpan.Zero),
            _ => Response(HttpStatusCode.Accepted, TimeSpan.Zero),
            _ => Response(HttpStatusCode.ServiceUnavailable, TimeSpan.FromSeconds(2)),
            _ => Response(HttpStatusCode.OK));
        using var http = new InProcessHttpClient(handler);
        using var result = await new DeferredPoller(http, clock.Options()).PollAsync(Pending);
        Assert.Equal(new[] { 5d, 5d, 10d, 10d, 12d }, clock.Delays.Select(delay => delay.TotalSeconds));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExchangeHonorsInitialRetryAfterBeforeFirstGet(bool date)
    {
        var clock = new PollClock();
        var started = clock.GetUtcNow();
        using var handler = new DeferredExchangeTests.SequenceHandler(
            _ =>
            {
                var response = DeferredExchangeTests.Pending("requirement=approval");
                response.Headers.RetryAfter = date ? new RetryConditionHeaderValue(started.AddSeconds(7))
                    : new RetryConditionHeaderValue(TimeSpan.FromSeconds(7));
                return response;
            },
            _ =>
            {
                Assert.Equal(started.AddSeconds(7), clock.GetUtcNow());
                return Response(HttpStatusCode.OK);
            });
        using var http = new InProcessHttpClient(handler);
        using var result = await new DeferredExchange(http, new MetadataClient(http)).PostAsync(
            new Uri("https://ps.example/token"), new JsonObject(),
            new DeferredExchangeOptions { PollerOptions = clock.Options() }, CancellationToken.None);
    }

    [Fact]
    public async Task RetryAfterBeyondBudgetDoesNotSendAnotherRequest()
    {
        var clock = new PollClock();
        using var handler = new DeferredExchangeTests.SequenceHandler(_ => Response(HttpStatusCode.Accepted, TimeSpan.FromSeconds(30)));
        using var http = new InProcessHttpClient(handler);
        await Assert.ThrowsAsync<TimeoutException>(() => new DeferredPoller(http,
            clock.Options() with { MaxTotalWait = TimeSpan.FromSeconds(4) }).PollAsync(Pending));
        Assert.Single(handler.Methods);
        Assert.Equal(TimeSpan.FromSeconds(4), Assert.Single(clock.Delays));
    }

    [Theory]
    [InlineData("default", 5)]
    [InlineData("past", 0)]
    [InlineData("date", 7)]
    public async Task PollerUsesClockForDefaultAndDate(string mode, int expected)
    {
        var clock = new PollClock();
        using var handler = new DeferredExchangeTests.SequenceHandler(
            _ =>
            {
                var response = Response(HttpStatusCode.Accepted);
                if (mode != "default") response.Headers.RetryAfter = new RetryConditionHeaderValue(clock.GetUtcNow().AddSeconds(mode == "past" ? -5 : 7));
                return response;
            },
            _ => Response(HttpStatusCode.OK));
        using var http = new InProcessHttpClient(handler);
        using var result = await new DeferredPoller(http, clock.Options()).PollAsync(Pending);
        Assert.Equal(expected, clock.Delays.Sum(delay => delay.TotalSeconds));
    }

    [Fact]
    public async Task ExchangeBackoffPersistsThroughNewInteraction()
    {
        var clock = new PollClock();
        var callbacks = 0;
        using var handler = new DeferredExchangeTests.SequenceHandler(
            _ => DeferredExchangeTests.Pending("requirement=approval"),
            _ => Response(HttpStatusCode.TooManyRequests, TimeSpan.Zero),
            _ => DeferredExchangeTests.Pending("requirement=interaction; url=\"https://ps.example/consent\"; code=\"ONE\""),
            _ => Response(HttpStatusCode.OK));
        using var http = new InProcessHttpClient(handler);
        using var result = await new DeferredExchange(http, new MetadataClient(http)).PostAsync(
            new Uri("https://ps.example/token"), new JsonObject(), new DeferredExchangeOptions
            {
                PollerOptions = clock.Options(),
                OnInteractionRequired = (_, _) => { callbacks++; return Task.CompletedTask; },
            }, CancellationToken.None);
        Assert.Equal(1, callbacks);
        Assert.Equal(new[] { 5d, 5d }, clock.Delays.Select(delay => delay.TotalSeconds));
    }

    [Fact]
    public async Task CancellationDuringInitialDelaySendsNoGet()
    {
        var clock = new PollClock();
        using var cancellation = new CancellationTokenSource();
        using var handler = new DeferredExchangeTests.SequenceHandler(_ =>
        {
            var response = DeferredExchangeTests.Pending("requirement=approval");
            response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(10));
            return response;
        });
        using var http = new InProcessHttpClient(handler);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new DeferredExchange(http, new MetadataClient(http)).PostAsync(
            new Uri("https://ps.example/token"), new JsonObject(), new DeferredExchangeOptions
            {
                PollerOptions = clock.Options() with
                {
                    DelayAsync = (_, token) => { cancellation.Cancel(); token.ThrowIfCancellationRequested(); return Task.CompletedTask; },
                },
            }, cancellation.Token));
        Assert.Equal(new[] { "POST" }, handler.Methods);
    }

    [Fact]
    public async Task InteractionHandlerHonorsInitialDateAndPersistentBackoff()
    {
        var clock = new PollClock();
        var options = clock.Options();
        using var handler = new DeferredExchangeTests.SequenceHandler(
            _ =>
            {
                var response = DeferredExchangeTests.Pending(null);
                response.Headers.RetryAfter = new RetryConditionHeaderValue(clock.GetUtcNow().AddSeconds(3));
                return response;
            },
            _ => Response(HttpStatusCode.TooManyRequests, TimeSpan.Zero),
            _ => DeferredExchangeTests.Pending(null),
            _ => Response(HttpStatusCode.OK));
        using var http = new InProcessHttpClient(new InteractionHandler(minPollInterval: TimeSpan.Zero)
        {
            EgressPolicy = TestEgress.Policy, TransportContract = AAuthTransportContract.InProcessOnly,
            TimeProvider = clock, DelayAsync = options.DelayAsync, InnerHandler = handler,
        });
        using var result = await http.PostAsync("https://ps.example/token", null);
        Assert.Equal(new[] { 3d, 5d, 5d }, clock.Delays.Select(delay => delay.TotalSeconds));
    }

    [Theory]
    [InlineData("poll")]
    [InlineData("exchange-callback")]
    [InlineData("handler-callback")]
    [InlineData("handler-poll")]
    public async Task VirtualDeadlineBoundsNonCooperativeWork(string path)
    {
        var clock = new PollClock();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var completion = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var handler = new BlockingHandler(path.Contains("callback", StringComparison.Ordinal), entered, completion);
        using var http = path.StartsWith("handler", StringComparison.Ordinal)
            ? new InProcessHttpClient(new InteractionHandler(
                onInteractionRequired: (_, _, _) => { entered.TrySetResult(); return completion.Task; },
                pollingTimeout: TimeSpan.FromSeconds(10), minPollInterval: TimeSpan.Zero)
            {
                EgressPolicy = TestEgress.Policy, TransportContract = AAuthTransportContract.InProcessOnly,
                TimeProvider = clock, DelayAsync = clock.Options().DelayAsync, InnerHandler = handler,
            })
            : new InProcessHttpClient(handler);
        Task<HttpResponseMessage> pending = path switch
        {
            "poll" => new DeferredPoller(http, clock.Options() with { MaxTotalWait = TimeSpan.FromSeconds(10) }).PollAsync(Pending),
            "exchange-callback" => new DeferredExchange(http, new MetadataClient(http)).PostAsync(
                new Uri("https://ps.example/token"), new JsonObject(), new DeferredExchangeOptions
                {
                    PollerOptions = clock.Options() with { MaxTotalWait = TimeSpan.FromSeconds(10) },
                    OnInteractionRequired = (_, _) => { entered.TrySetResult(); return completion.Task; },
                }, CancellationToken.None),
            _ => http.PostAsync("https://ps.example/token", null),
        };
        await entered.Task;
        clock.Advance(TimeSpan.FromSeconds(10));
        try
        {
            if (path == "exchange-callback")
                await Assert.ThrowsAsync<AAuthInteractionTimeoutException>(() => pending);
            else
                await Assert.ThrowsAsync<TimeoutException>(() => pending);
        }
        finally { completion.TrySetResult(Response(HttpStatusCode.OK)); }
    }

    private sealed class BlockingHandler(bool interaction, TaskCompletionSource entered,
        TaskCompletionSource<HttpResponseMessage> completion) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method == HttpMethod.Post)
                return Task.FromResult(DeferredExchangeTests.Pending(interaction
                    ? "requirement=interaction; url=\"https://ps.example/consent\"; code=\"ONE\"" : null));
            entered.TrySetResult();
            return completion.Task;
        }
    }

    internal static HttpResponseMessage Response(HttpStatusCode status, TimeSpan? retry = null)
    {
        var response = DeferredExchangeTests.Json(status, "{}");
        if (retry is { } delta) response.Headers.RetryAfter = new RetryConditionHeaderValue(delta);
        return response;
    }

    internal sealed class PollClock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 9, 9, 0, 0, 0, TimeSpan.Zero);
        private readonly List<PollTimer> _timers = new();
        public List<TimeSpan> Delays { get; } = new();
        public override DateTimeOffset GetUtcNow() => _now;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => _now.Ticks;
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new PollTimer(this, callback, state);
            _timers.Add(timer);
            timer.Change(dueTime, period);
            return timer;
        }
        public void Advance(TimeSpan delay)
        {
            var target = _now + delay;
            while (_timers.Where(timer => timer.Due <= target).OrderBy(timer => timer.Due).FirstOrDefault() is { } timer)
            {
                _now = timer.Due;
                timer.Fire();
            }
            _now = target;
        }
        public DeferredPollerOptions Options() => new()
        {
            TimeProvider = this,
            MinPollInterval = TimeSpan.Zero,
            DelayAsync = (delay, token) =>
            {
                token.ThrowIfCancellationRequested();
                Delays.Add(delay);
                Advance(delay);
                return Task.CompletedTask;
            },
        };

        private sealed class PollTimer(PollClock clock, TimerCallback callback, object? state) : ITimer
        {
            public DateTimeOffset Due { get; private set; } = DateTimeOffset.MaxValue;
            private TimeSpan _period;
            public bool Change(TimeSpan dueTime, TimeSpan period)
            {
                Due = dueTime == Timeout.InfiniteTimeSpan ? DateTimeOffset.MaxValue : clock.GetUtcNow() + dueTime;
                _period = period;
                return true;
            }
            public void Fire()
            {
                Due = _period > TimeSpan.Zero ? Due + _period : DateTimeOffset.MaxValue;
                callback(state);
            }
            public void Dispose() => Due = DateTimeOffset.MaxValue;
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }
}