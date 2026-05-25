using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace AAuth.Conformance.Observability;

/// <summary>
/// Conformance tests for Gap 7 (Prefer: wait=N header on deferred poll requests)
/// and Gap 8 (OpenTelemetry-compatible Activity diagnostics).
/// </summary>
public class PreferWaitHeaderTests
{
    /// <summary>
    /// When <see cref="DeferredPollerOptions.PreferWaitSeconds"/> is set,
    /// every poll request MUST include a <c>Prefer: wait=N</c> header.
    /// </summary>
    [Fact]
    public async Task Poll_WithPreferWaitSeconds_SendsPreferHeader()
    {
        var preferValue = 30;
        var capturedHeaders = new List<string?>();

        // Stub handler that captures incoming request headers and returns
        // 200 (terminal) on the first poll to keep the test short.
        var stub = new StubHandler(req =>
        {
            capturedHeaders.Add(req.Headers.TryGetValues("Prefer", out var vals)
                ? string.Join(",", vals)
                : null);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"auth_token\":\"test\"}", System.Text.Encoding.UTF8, "application/json"),
            };
        });

        var client = new HttpClient(stub) { BaseAddress = new Uri("https://ps.example/") };
        var poller = new DeferredPoller(client, new DeferredPollerOptions
        {
            PreferWaitSeconds = preferValue,
        });

        var result = await poller.PollAsync(new Uri("https://ps.example/pending/123"));

        Assert.Single(capturedHeaders);
        Assert.Equal($"wait={preferValue}", capturedHeaders[0]);
    }

    /// <summary>
    /// When <see cref="DeferredPollerOptions.PreferWaitSeconds"/> is null (default),
    /// no <c>Prefer</c> header is sent.
    /// </summary>
    [Fact]
    public async Task Poll_WithoutPreferWaitSeconds_DoesNotSendPreferHeader()
    {
        var capturedHeaders = new List<string?>();

        var stub = new StubHandler(req =>
        {
            capturedHeaders.Add(req.Headers.Contains("Prefer") ? "PRESENT" : null);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"auth_token\":\"test\"}", System.Text.Encoding.UTF8, "application/json"),
            };
        });

        var client = new HttpClient(stub) { BaseAddress = new Uri("https://ps.example/") };
        var poller = new DeferredPoller(client, new DeferredPollerOptions());

        await poller.PollAsync(new Uri("https://ps.example/pending/123"));

        Assert.Single(capturedHeaders);
        Assert.Null(capturedHeaders[0]);
    }

    /// <summary>
    /// Multiple poll iterations all include the <c>Prefer: wait=N</c> header.
    /// </summary>
    [Fact]
    public async Task Poll_MultiplePollIterations_AllContainPreferHeader()
    {
        var callCount = 0;
        var capturedHeaders = new List<string?>();

        var stub = new StubHandler(req =>
        {
            capturedHeaders.Add(req.Headers.TryGetValues("Prefer", out var vals)
                ? string.Join(",", vals)
                : null);
            callCount++;
            if (callCount < 3)
            {
                return new HttpResponseMessage(HttpStatusCode.Accepted);
            }
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"auth_token\":\"done\"}", System.Text.Encoding.UTF8, "application/json"),
            };
        });

        var client = new HttpClient(stub) { BaseAddress = new Uri("https://ps.example/") };
        var poller = new DeferredPoller(client, new DeferredPollerOptions
        {
            PreferWaitSeconds = 15,
            DefaultPollInterval = TimeSpan.FromMilliseconds(1),
            MinPollInterval = TimeSpan.Zero,
        });

        await poller.PollAsync(new Uri("https://ps.example/pending/456"));

        Assert.Equal(3, capturedHeaders.Count);
        Assert.All(capturedHeaders, h => Assert.Equal("wait=15", h));
    }

    /// <summary>
    /// <c>PreferWaitSeconds = 0</c> sends <c>Prefer: wait=0</c> (server can
    /// interpret as "respond immediately if nothing ready").
    /// </summary>
    [Fact]
    public async Task Poll_PreferWaitZero_SendsWaitZero()
    {
        var capturedHeaders = new List<string?>();

        var stub = new StubHandler(req =>
        {
            capturedHeaders.Add(req.Headers.TryGetValues("Prefer", out var vals)
                ? string.Join(",", vals)
                : null);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json"),
            };
        });

        var client = new HttpClient(stub) { BaseAddress = new Uri("https://ps.example/") };
        var poller = new DeferredPoller(client, new DeferredPollerOptions
        {
            PreferWaitSeconds = 0,
        });

        await poller.PollAsync(new Uri("https://ps.example/pending/789"));

        Assert.Single(capturedHeaders);
        Assert.Equal("wait=0", capturedHeaders[0]);
    }

    // ── Stub infrastructure ────────────────────────────────────────────────

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _handler;

        public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> handler)
            => _handler = handler;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(_handler(request));
    }
}
