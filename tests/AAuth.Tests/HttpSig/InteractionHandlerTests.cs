using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Tokens;
using Xunit;

namespace AAuth.Tests.HttpSig;

public class InteractionHandlerTests
{
    private readonly AAuthKey _key = AAuthKey.Generate();

    [Fact]
    public async Task Interaction_PollsUntilSuccess()
    {
        string? capturedUrl = null;
        string? capturedCode = null;
        var handler = new ScriptedHandler(
            _ => Make202Interaction("https://ps.example/interact", "ABC123", "https://ps.example/pending/1"),
            _ => new HttpResponseMessage(HttpStatusCode.Accepted)
            {
                Headers = { Location = new Uri("https://ps.example/pending/1"), RetryAfter = new RetryConditionHeaderValue(TimeSpan.Zero) },
                Content = new StringContent(""),
            },
            _ => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"result\":\"done\"}"),
            });

        var interactionHandler = new InteractionHandler(
            onInteractionRequired: (url, code, ct) =>
            {
                capturedUrl = url;
                capturedCode = code;
                return Task.CompletedTask;
            },
            pollingTimeout: TimeSpan.FromSeconds(10))
        {
            InnerHandler = handler,
        };

        using var client = new HttpClient(interactionHandler);
        var response = await client.GetAsync("https://resource.example/api");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(capturedUrl);
        Assert.Contains("ABC123", capturedUrl);
        Assert.Equal("ABC123", capturedCode);
        Assert.Equal(3, handler.CallCount);
    }

    [Fact]
    public async Task Approval_PollsUntilSuccess()
    {
        var approvalCalled = false;
        var handler = new ScriptedHandler(
            _ => Make202Approval("https://ps.example/pending/2"),
            _ => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"result\":\"approved\"}"),
            });

        var interactionHandler = new InteractionHandler(
            onApprovalPending: ct =>
            {
                approvalCalled = true;
                return Task.CompletedTask;
            },
            pollingTimeout: TimeSpan.FromSeconds(10))
        {
            InnerHandler = handler,
        };

        using var client = new HttpClient(interactionHandler);
        var response = await client.GetAsync("https://resource.example/api");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(approvalCalled);
    }

    [Fact]
    public async Task Interaction_ThrowsWhenNoCallback()
    {
        var handler = new ScriptedHandler(
            _ => Make202Interaction("https://ps.example/interact", "CODE", "https://ps.example/pending/3"));

        var interactionHandler = new InteractionHandler(
            onInteractionRequired: null,
            pollingTimeout: TimeSpan.FromSeconds(5))
        {
            InnerHandler = handler,
        };

        using var client = new HttpClient(interactionHandler);
        await Assert.ThrowsAsync<AAuthInteractionDeniedException>(
            () => client.GetAsync("https://resource.example/api"));
    }

    [Fact]
    public async Task BacksOff_On429()
    {
        var pollTimes = new List<DateTimeOffset>();
        var handler = new ScriptedHandler(
            _ => Make202Interaction("https://ps.example/interact", "CODE", "https://ps.example/pending/4"),
            _ =>
            {
                pollTimes.Add(DateTimeOffset.UtcNow);
                return new HttpResponseMessage((HttpStatusCode)429);
            },
            _ =>
            {
                pollTimes.Add(DateTimeOffset.UtcNow);
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{}"),
                };
            });

        var interactionHandler = new InteractionHandler(
            onInteractionRequired: (_, _, _) => Task.CompletedTask,
            pollingTimeout: TimeSpan.FromSeconds(30))
        {
            InnerHandler = handler,
        };

        using var client = new HttpClient(interactionHandler);
        var response = await client.GetAsync("https://resource.example/api");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        // After 429, the delay should be at least 5s (default) + 5s (backoff) = 10s
        // We check that it took at least 4s (accounting for scheduling jitter)
        if (pollTimes.Count == 2)
        {
            var gap = pollTimes[1] - pollTimes[0];
            Assert.True(gap >= TimeSpan.FromSeconds(4),
                $"Expected >= 4s backoff, got {gap.TotalSeconds:F2}s");
        }
    }

    [Fact]
    public async Task TimesOut_WhenPollKeepsReturning202()
    {
        var handler = new ScriptedHandler(
            _ => Make202Interaction("https://ps.example/interact", "CODE", "https://ps.example/pending/5"),
            _ => new HttpResponseMessage(HttpStatusCode.Accepted)
            {
                Headers = { Location = new Uri("https://ps.example/pending/5"), RetryAfter = new RetryConditionHeaderValue(TimeSpan.Zero) },
                Content = new StringContent(""),
            });

        var interactionHandler = new InteractionHandler(
            onInteractionRequired: (_, _, _) => Task.CompletedTask,
            pollingTimeout: TimeSpan.FromMilliseconds(50))
        {
            InnerHandler = handler,
        };

        using var client = new HttpClient(interactionHandler);
        await Assert.ThrowsAsync<TimeoutException>(
            () => client.GetAsync("https://resource.example/api"));
    }

    [Fact]
    public void Builder_WithInteractionHandling_BuildsClient()
    {
        using var client = new AAuthClientBuilder(_key)
            .UseHwk()
            .WithInteractionHandling(opts =>
            {
                opts.OnInteractionRequired = (_, _, _) => Task.CompletedTask;
            })
            .WithInnerHandler(new OkHandler())
            .Build();

        Assert.NotNull(client);
    }

    [Fact]
    public async Task Builder_WithInteractionHandling_AddsCapability()
    {
        var capturedRequest = (HttpRequestMessage?)null;
        var handler = new CapturingHandler(r => capturedRequest = r);

        using var client = new AAuthClientBuilder(_key)
            .UseHwk()
            .WithInteractionHandling()
            .WithInnerHandler(handler)
            .Build();

        await client.GetAsync("https://resource.example/api");
        Assert.NotNull(capturedRequest);
        Assert.True(capturedRequest!.Headers.Contains("AAuth-Capabilities"));
        var caps = string.Join(",", capturedRequest.Headers.GetValues("AAuth-Capabilities"));
        Assert.Contains("interaction", caps);
    }

    private static HttpResponseMessage Make202Interaction(string interactUrl, string code, string pendingUrl)
    {
        var headerValue = AAuthInteraction.Format(interactUrl, code);
        var response = new HttpResponseMessage(HttpStatusCode.Accepted)
        {
            Headers =
            {
                Location = new Uri(pendingUrl),
                RetryAfter = new RetryConditionHeaderValue(TimeSpan.Zero),
            },
            Content = new StringContent(""),
        };
        response.Headers.TryAddWithoutValidation(AAuthRequirementHeader.Name, headerValue);
        return response;
    }

    private static HttpResponseMessage Make202Approval(string pendingUrl)
    {
        var response = new HttpResponseMessage(HttpStatusCode.Accepted)
        {
            Headers =
            {
                Location = new Uri(pendingUrl),
                RetryAfter = new RetryConditionHeaderValue(TimeSpan.Zero),
            },
            Content = new StringContent(""),
        };
        response.Headers.TryAddWithoutValidation(AAuthRequirementHeader.Name, "requirement=approval");
        return response;
    }

    private sealed class ScriptedHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage>[] _script;
        public int CallCount { get; private set; }

        public ScriptedHandler(params Func<HttpRequestMessage, HttpResponseMessage>[] script)
            => _script = script;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var idx = Math.Min(CallCount, _script.Length - 1);
            CallCount++;
            return Task.FromResult(_script[idx](request));
        }
    }

    private sealed class OkHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
    }

    private sealed class CapturingHandler : HttpMessageHandler
    {
        private readonly Action<HttpRequestMessage> _onRequest;
        public CapturingHandler(Action<HttpRequestMessage> onRequest) => _onRequest = onRequest;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            _onRequest(request);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }
}
