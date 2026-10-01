using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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

    [Theory(DisplayName = "§Polling Errors — each terminal code reaches the agent as its own typed outcome with detail")]
    [InlineData("denied", 403, PollingErrorCode.Denied)]
    [InlineData("abandoned", 403, PollingErrorCode.Abandoned)]
    [InlineData("expired", 408, PollingErrorCode.Expired)]
    [InlineData("revoked", 403, PollingErrorCode.Revoked)]
    [InlineData("invalid_code", 410, PollingErrorCode.InvalidCode)]
    [InlineData("server_error", 500, PollingErrorCode.ServerError)]
    public async Task TerminalCodes_AreDistinctWithDetail(string wire, int status, PollingErrorCode expected)
    {
        var handler = new MockHandler(_ => new HttpResponseMessage((HttpStatusCode)status)
        {
            Content = new StringContent($"{{\"error\":\"{wire}\",\"detail\":\"why {wire}\"}}", Encoding.UTF8, "application/problem+json"),
        });
        var poller = new DeferredPoller(new InProcessHttpClient(handler));

        var ex = await Assert.ThrowsAsync<PollingErrorException>(
            () => poller.PollAsync(new Uri("http://localhost/pending/x")));

        Assert.Equal(expected, ex.ErrorCode);
        Assert.Equal(status, ex.StatusCode);
        Assert.Equal($"why {wire}", ex.Detail);
        Assert.Contains($"why {wire}", ex.Message);
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

    [Theory(DisplayName = "§Polling Errors — registered codes own their registered statuses")]
    [InlineData(PollingErrorCode.Denied, 403)]
    [InlineData(PollingErrorCode.Abandoned, 403)]
    [InlineData(PollingErrorCode.Expired, 408)]
    [InlineData(PollingErrorCode.Revoked, 403)]
    [InlineData(PollingErrorCode.InvalidCode, 410)]
    [InlineData(PollingErrorCode.SlowDown, 429)]
    [InlineData(PollingErrorCode.ServerError, 500)]
    public void PollingStatus_IsClosedTable(PollingErrorCode code, int expectedStatus)
        => Assert.Equal(expectedStatus, AAuth.Server.AAuthProblemDetails.PollingStatus(code));

    [Theory(DisplayName = "§Polling Errors — unregistered polling codes are not parsed")]
    [InlineData("unknown_pending")]
    [InlineData("unknown_interaction")]
    [InlineData("request_withdrawn")]
    [InlineData("policy_error")]
    public void UnknownPollingCodes_AreNotParsed(string wireCode)
        => Assert.False(PollingErrorException.TryParseCode(wireCode, out _));

    [Fact(DisplayName = "§Polling Errors — SDK src does not emit removed v10/v02 codes")]
    public void RemovedCodes_DoNotAppearInSrc()
    {
        var root = FindRepositoryRoot();
        var forbidden = new[]
        {
            "unknown_pending",
            "unknown_interaction",
            "request_withdrawn",
            "untrusted_person_server",
            "untrusted_access_server",
            "policy_error",
            "policy_unavailable",
        };
        var matches = Directory.EnumerateFiles(Path.Combine(root, "src"), "*.cs", SearchOption.AllDirectories)
            .SelectMany(path => File.ReadLines(path).Select((line, index) => new { path, line, index }))
            .Where(hit => forbidden.Any(code => hit.line.Contains(code, StringComparison.Ordinal)))
            .Select(hit => $"{Path.GetRelativePath(root, hit.path)}:{hit.index + 1}:{hit.line.Trim()}")
            .ToArray();

        Assert.Empty(matches);
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, "src", "AAuth")))
                return directory.FullName;
            directory = directory.Parent;
        }
        throw new DirectoryNotFoundException("Could not locate repository root containing src/AAuth.");
    }

    private sealed class MockHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _handler;
        public MockHandler(Func<HttpRequestMessage, HttpResponseMessage> handler) => _handler = handler;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(_handler(request));
    }
}
