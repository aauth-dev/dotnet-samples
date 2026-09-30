using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Headers;
using AAuth.HttpSig;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AAuth.Tests.Agent;

/// <summary>R0 resolution of the resource interaction handler, and capability inference.</summary>
public class InteractionHandlerResolutionTests
{
    private readonly AAuthKey _key = AAuthKey.Generate();

    [Theory]
    [InlineData("request")]
    [InlineData("explicit")]
    [InlineData("keyed")]
    [InlineData("unkeyed")]
    public async Task PerRequest_BeatsExplicit_BeatsKeyed_BeatsUnkeyed(string winner)
    {
        var seen = new ConcurrentQueue<string>();
        var services = new ServiceCollection();
        if (winner is "keyed" or "explicit" or "request")
            services.AddKeyedSingleton<IAAuthInteractionHandler>("agent", new Recorder("keyed", seen));
        services.AddSingleton<IAAuthInteractionHandler>(new Recorder("unkeyed", seen));
        services.AddAAuthAgent("agent", options =>
        {
            Configure(options, new DeferringResource());
            if (winner is "explicit" or "request")
                options.Interaction.OnInteractionRequired = new Recorder("explicit", seen).OnInteractionRequiredAsync;
        });
        await using var provider = services.BuildServiceProvider();
        var agent = provider.GetRequiredService<IAAuthAgentFactory>().Get("agent");

        using var request = new HttpRequestMessage(HttpMethod.Get, "https://resource.example/user-a");
        if (winner == "request") request.Options.Set(AAuthRequestOptions.InteractionHandler, new Recorder("request", seen));
        using var response = await agent.HttpClient.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal([winner], seen.ToArray());
    }

    [Fact]
    public async Task WithoutAHandler_TheInteractionCapabilityIsNotDeclared()
    {
        var resource = new DeferringResource();
        var services = new ServiceCollection();
        services.AddAAuthAgent("agent", options =>
        {
            Configure(options, resource);
            options.HandleInteractions = true;
        });
        await using var provider = services.BuildServiceProvider();
        var client = provider.GetRequiredService<IAAuthAgentFactory>().Get("agent").HttpClient;

        using (var plain = new HttpRequestMessage(HttpMethod.Get, "https://resource.example/ok"))
            (await client.SendAsync(plain)).Dispose();
        Assert.DoesNotContain("interaction", resource.Capabilities.Single());

        using (var routed = new HttpRequestMessage(HttpMethod.Get, "https://resource.example/ok"))
        {
            routed.Options.Set(AAuthRequestOptions.InteractionHandler, new Recorder("request", new()));
            (await client.SendAsync(routed)).Dispose();
        }
        Assert.Contains("interaction", resource.Capabilities.Last());
    }

    [Fact]
    public async Task OneAgent_RoutesConcurrentRequests_ToEachUsersHandler()
    {
        var resource = new DeferringResource { Gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously) };
        var services = new ServiceCollection();
        services.AddAAuthAgent("agent", options =>
        {
            Configure(options, resource);
            options.HandleInteractions = true;
        });
        await using var provider = services.BuildServiceProvider();
        var client = provider.GetRequiredService<IAAuthAgentFactory>().Get("agent").HttpClient;
        var alice = new ConcurrentQueue<string>();
        var bob = new ConcurrentQueue<string>();

        async Task<HttpStatusCode> SendAsync(string user, ConcurrentQueue<string> seen)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://resource.example/" + user);
            request.Options.Set(AAuthRequestOptions.InteractionHandler, new Recorder(user, seen));
            using var response = await client.SendAsync(request);
            return response.StatusCode;
        }
        var first = SendAsync("alice", alice);
        var second = SendAsync("bob", bob);
        await resource.BothDeferred.Task.WaitAsync(TimeSpan.FromSeconds(10));
        resource.Gate.SetResult();

        Assert.Equal([HttpStatusCode.OK, HttpStatusCode.OK], await Task.WhenAll(first, second));
        Assert.Equal(["alice:code-alice"], alice.ToArray());
        Assert.Equal(["bob:code-bob"], bob.ToArray());
    }

    private void Configure(AAuthAgentOptions options, DeferringResource resource)
    {
        options.Signer = _key;
        options.SignatureKeyProvider = new HwkSignatureKeyProvider(_key);
        options.EgressPolicy = TestEgress.Policy;
        options.InnerHandler = resource;
        options.TransportContract = AAuthTransportContract.InProcessOnly;
        options.Interaction.MinPollInterval = TimeSpan.Zero;
    }

    private sealed class Recorder(string name, ConcurrentQueue<string> seen) : IAAuthInteractionHandler
    {
        public Task OnInteractionRequiredAsync(Interaction interaction, CancellationToken cancellationToken)
        {
            Assert.Equal(InteractionSource.Resource, interaction.Source);
            seen.Enqueue(name is "alice" or "bob" ? name + ":" + interaction.Code : name);
            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// <c>/ok</c> answers 200. Any other path answers <c>202 + requirement=interaction</c> with a
    /// code naming the path, then 200 when its pending URL is polled.
    /// </summary>
    private sealed class DeferringResource : HttpMessageHandler
    {
        private int _deferred;

        public List<string> Capabilities { get; } = [];
        public TaskCompletionSource? Gate { get; init; }
        public TaskCompletionSource BothDeferred { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath.Trim('/');
            if (path == "ok")
            {
                lock (Capabilities)
                    Capabilities.Add(request.Headers.TryGetValues(AAuthCapabilitiesHeader.Name, out var values)
                        ? string.Join(",", values) : "");
                return new HttpResponseMessage(HttpStatusCode.OK);
            }
            if (path.StartsWith("pending/", StringComparison.Ordinal))
            {
                if (Gate is not null) await Gate.Task.WaitAsync(cancellationToken);
                return new HttpResponseMessage(HttpStatusCode.OK);
            }
            if (Interlocked.Increment(ref _deferred) == 2) BothDeferred.TrySetResult();
            var response = new HttpResponseMessage(HttpStatusCode.Accepted);
            response.Headers.Location = new Uri("https://resource.example/pending/" + path);
            response.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.Zero);
            response.Headers.TryAddWithoutValidation(AAuthRequirementHeader.Name,
                Interaction.Format("https://resource.example/consent", "code-" + path));
            return response;
        }
    }
}
