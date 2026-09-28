using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Errors;
using Xunit;

namespace AAuth.Conformance.Errors;

/// <summary>
/// Conformance tests for polling error handling per §Polling Error Codes.
/// </summary>
public class PollingErrorTests
{
    [Fact(DisplayName = "§Polling Errors — slow_down (429) increases interval by 5s")]
    public async Task SlowDown_IncreasesInterval()
    {
        int callCount = 0;
        var delays = new List<TimeSpan>();
        var handler = new MockHandler(req =>
        {
            callCount++;
            if (callCount <= 2)
            {
                // Return slow_down twice
                var resp = new HttpResponseMessage((HttpStatusCode)429);
                resp.Content = new StringContent("{\"error\":\"slow_down\"}", Encoding.UTF8, "application/json");
                return resp;
            }
            // Then succeed
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"auth_token\":\"tok\"}", Encoding.UTF8, "application/json"),
            };
        });

        var client = new InProcessHttpClient(handler);
        var poller = new DeferredPoller(client, new DeferredPollerOptions
        {
            MaxTotalWait = TimeSpan.FromSeconds(30),
            DefaultPollInterval = TimeSpan.FromMilliseconds(10),
            MinPollInterval = TimeSpan.FromMilliseconds(1),
            DelayAsync = (delay, cancellationToken) =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                delays.Add(delay);
                return Task.CompletedTask;
            },
        });

        var result = await poller.PollAsync(new Uri("http://localhost/pending/x"));

        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
        Assert.Collection(delays,
            delay => Assert.Equal(TimeSpan.FromMilliseconds(5_010), delay),
            delay => Assert.Equal(TimeSpan.FromMilliseconds(10_010), delay));
        Assert.Equal(3, callCount);
    }

    [Fact(DisplayName = "§Polling Errors — invalid_code (410) aborts without retry")]
    public async Task InvalidCode_AbortsImmediately()
    {
        int callCount = 0;
        var handler = new MockHandler(_ =>
        {
            callCount++;
            var resp = new HttpResponseMessage(HttpStatusCode.Gone);
            resp.Content = new StringContent("{\"error\":\"invalid_code\"}", Encoding.UTF8, "application/json");
            return resp;
        });

        var client = new InProcessHttpClient(handler);
        var poller = new DeferredPoller(client, new DeferredPollerOptions
        {
            MaxTotalWait = TimeSpan.FromSeconds(5),
            DefaultPollInterval = TimeSpan.FromMilliseconds(10),
        });

        var ex = await Assert.ThrowsAsync<PollingErrorException>(
            () => poller.PollAsync(new Uri("http://localhost/pending/x")));
        Assert.Equal(PollingErrorCode.InvalidCode, ex.ErrorCode);
        Assert.Equal(410, ex.StatusCode);
        Assert.Equal(1, callCount); // No retry
    }

    [Fact(DisplayName = "§Polling Errors — denied (403) surfaces typed exception")]
    public async Task Denied_SurfacesTypedException()
    {
        var handler = new MockHandler(_ =>
        {
            var resp = new HttpResponseMessage(HttpStatusCode.Forbidden);
            resp.Content = new StringContent("{\"error\":\"denied\"}", Encoding.UTF8, "application/json");
            return resp;
        });

        var client = new InProcessHttpClient(handler);
        var poller = new DeferredPoller(client);

        var ex = await Assert.ThrowsAsync<PollingErrorException>(
            () => poller.PollAsync(new Uri("http://localhost/pending/x")));
        Assert.Equal(PollingErrorCode.Denied, ex.ErrorCode);
        Assert.Equal(403, ex.StatusCode);
    }

    [Fact(DisplayName = "§Polling Errors — expired (408) surfaces typed exception")]
    public async Task Expired_SurfacesTypedException()
    {
        var handler = new MockHandler(_ =>
        {
            var resp = new HttpResponseMessage(HttpStatusCode.RequestTimeout);
            resp.Content = new StringContent("{\"error\":\"expired\"}", Encoding.UTF8, "application/json");
            return resp;
        });

        var client = new InProcessHttpClient(handler);
        var poller = new DeferredPoller(client);

        var ex = await Assert.ThrowsAsync<PollingErrorException>(
            () => poller.PollAsync(new Uri("http://localhost/pending/x")));
        Assert.Equal(PollingErrorCode.Expired, ex.ErrorCode);
    }

    [Theory(DisplayName = "§Polling Errors — all codes parse correctly")]
    [InlineData("denied", PollingErrorCode.Denied)]
    [InlineData("abandoned", PollingErrorCode.Abandoned)]
    [InlineData("expired", PollingErrorCode.Expired)]
    [InlineData("revoked", PollingErrorCode.Revoked)]
    [InlineData("invalid_code", PollingErrorCode.InvalidCode)]
    [InlineData("slow_down", PollingErrorCode.SlowDown)]
    [InlineData("server_error", PollingErrorCode.ServerError)]
    public void ParsesAllPollingCodes(string wireCode, PollingErrorCode expected)
    {
        Assert.True(PollingErrorException.TryParseCode(wireCode, out var result));
        Assert.Equal(expected, result);
    }

    private sealed class MockHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _handler;
        public MockHandler(Func<HttpRequestMessage, HttpResponseMessage> handler) => _handler = handler;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(_handler(request));
    }
}
