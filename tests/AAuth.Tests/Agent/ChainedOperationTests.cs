using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Discovery;
using AAuth.Errors;
using AAuth.Headers;
using AAuth.Server.CallChaining;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AAuth.Tests.Agent;

/// <summary>
/// §Interaction Chaining with <see cref="AAuthChainedOperation{TResult}"/>: the intermediary keeps
/// polling the downstream pending URL with GET (§Polling with GET) while it answers its caller with
/// its own 202, and never re-sends the downstream request.
/// </summary>
public class ChainedOperationTests
{
    private const string PsUrl = "http://localhost:5555";
    private static readonly Interaction First = new("http://localhost:5555/interaction", "FIRST");
    private static readonly Interaction Second = new("http://localhost:5555/interaction", "SECOND");

    [Fact]
    public async Task CompletesWithoutInteraction_ReturnsCompletedOperation()
    {
        var operation = await AAuthChainedOperation<string>.StartAsync(
            (_, _) => Task.FromResult("done"), DateTimeOffset.UtcNow.AddMinutes(5));

        Assert.True(operation.Completion.IsCompletedSuccessfully);
        Assert.Equal("done", await operation.Completion);
        Assert.Null(operation.Interaction);
    }

    [Fact]
    public async Task ParksOnInteraction_ThenCompletesInBackground()
    {
        var release = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var operation = await AAuthChainedOperation<string>.StartAsync(async (interactions, ct) =>
        {
            await interactions.OnInteractionRequiredAsync(First, ct);
            return await release.Task.WaitAsync(ct);
        }, DateTimeOffset.UtcNow.AddMinutes(5));

        Assert.False(operation.Completion.IsCompleted);
        Assert.Equal(new AAuthChainedInteractionSnapshot(1, First), operation.Interaction);

        release.SetResult("done");
        Assert.Equal("done", await operation.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task NewDownstreamInteraction_BumpsVersion_SameOneDoesNot()
    {
        var release = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        IAAuthInteractionHandler? handler = null;
        var operation = await AAuthChainedOperation<string>.StartAsync(async (interactions, ct) =>
        {
            handler = interactions;
            await interactions.OnInteractionRequiredAsync(First, ct);
            return await release.Task.WaitAsync(ct);
        }, DateTimeOffset.UtcNow.AddMinutes(5));

        await handler!.OnInteractionRequiredAsync(First with { Source = InteractionSource.PersonServer }, default);
        Assert.Equal(1, operation.Interaction!.Version);
        await handler.OnInteractionRequiredAsync(Second, default);
        Assert.Equal(new AAuthChainedInteractionSnapshot(2, Second), operation.Interaction);
        release.SetResult("done");
        await operation.Completion;
    }

    [Fact]
    public async Task Cancel_StopsTheOperation_AndMapsToExpired()
    {
        var operation = await AAuthChainedOperation<string>.StartAsync(async (interactions, ct) =>
        {
            await interactions.OnInteractionRequiredAsync(First, ct);
            await Task.Delay(Timeout.Infinite, ct);
            return "unreachable";
        }, DateTimeOffset.UtcNow.AddMinutes(5));

        operation.Cancel();
        var failure = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(StatusCodes.Status408RequestTimeout,
            ((IStatusCodeHttpResult)AAuthChainedInteractions.PollingFailure(failure)!).StatusCode);
        operation.Cancel();
    }

    [Fact]
    public async Task ExpiredOperation_IsCancelled()
    {
        var operation = await AAuthChainedOperation<string>.StartAsync(async (_, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            return "unreachable";
        }, DateTimeOffset.UtcNow.AddSeconds(-1));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task FarFutureExpiry_DoesNotThrow()
    {
        var operation = await AAuthChainedOperation<string>.StartAsync(
            (_, _) => Task.FromResult("done"), DateTimeOffset.MaxValue);
        Assert.Equal("done", await operation.Completion);
    }

    [Fact]
    public async Task RequestWithOwnInteractionHandler_DoesNotJoinAnotherRequestsAcquisition()
    {
        // Two inbound requests chain the same upstream token. The first is parked on downstream
        // consent; the second must run its own acquisition so its own handler can see its 202.
        var holder = new AAuthTokenHolder();
        var key = AAuth.Crypto.AAuthKey.Generate();
        var token = $"e30.{Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(
            $"{{\"exp\":{DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()}}}")}.c2ln";
        HttpRequestMessage Request()
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "https://calendar.example/events");
            holder.SelectForRequest(request, "agent-token", key.ComputeJwkThumbprint());
            request.Options.Set(AAuth.HttpSig.AAuthSigningHandler.SigningKeyContext, key);
            request.Options.Set(AAuthRequestOptions.InteractionHandler, new AAuthChainedOperationProbe());
            return request;
        }

        var parked = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var first = holder.AcquireAsync(Request(), null, _ => parked.Task, default);
        var second = holder.AcquireAsync(Request(), null, _ => Task.FromResult(token), default);

        Assert.Equal(token, await second.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.False(first.IsCompleted);
        parked.SetResult(token);
        await first;
    }

    private sealed class AAuthChainedOperationProbe : IAAuthInteractionHandler
    {
        public Task OnInteractionRequiredAsync(Interaction interaction, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    [Fact]
    public async Task DownstreamExchange_PostsOnce_ThenPollsLocationWithGet()
    {
        var ps = new DeferredPersonServer();
        var http = new InProcessHttpClient(ps);
        var exchange = new TokenExchangeClient(http, new MetadataClient(http));

        var operation = await AAuthChainedOperation<string>.StartAsync(
            (interactions, ct) => exchange.ExchangeAsync(PsUrl, TestTokens.Resource, new TokenExchangeRequest
            {
                PresentedToken = "presented",
                OnInteractionRequired = interactions.OnInteractionRequiredAsync,
                PollerOptions = new DeferredPollerOptions { MinPollInterval = TimeSpan.Zero },
            }, ct),
            DateTimeOffset.UtcNow.AddMinutes(5));

        // The caller can be answered with the intermediary's own 202 while the
        // downstream exchange keeps polling.
        Assert.False(operation.Completion.IsCompleted);
        Assert.Equal("CONSENT", operation.Interaction!.Downstream.Code);
        await ps.Polled.Task.WaitAsync(TimeSpan.FromSeconds(5));
        ps.Approve();

        // The fake auth token fails verification; what matters is how it was reached.
        await Assert.ThrowsAnyAsync<Exception>(() => operation.Completion.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(1, ps.TokenPosts);
        Assert.True(ps.PendingGets >= 2);
        Assert.Equal(0, ps.OtherRequests);
    }

    [Theory]
    [InlineData(PollingErrorCode.Expired, 408, "expired")]
    [InlineData(PollingErrorCode.Revoked, 403, "revoked")]
    [InlineData(PollingErrorCode.Abandoned, 403, "abandoned")]
    [InlineData(PollingErrorCode.ServerError, 500, "server_error")]
    [InlineData(PollingErrorCode.InvalidCode, 408, "expired")]
    public async Task PollingFailure_MapsDownstreamPollingErrors(PollingErrorCode code, int status, string error)
    {
        var result = AAuthChainedInteractions.PollingFailure(new PollingErrorException(code, 400, detail: "why"))!;
        var (actualStatus, body) = await ExecuteAsync(result);
        Assert.Equal(status, actualStatus);
        Assert.Equal(error, (string?)body["error"]);
        Assert.Equal("why", (string?)body["detail"]);
    }

    [Fact]
    public async Task PollingFailure_KeepsDeniedDetail()
    {
        var denied = new AAuthInteractionDeniedException("The AAuth request was denied: no",
            new PollingErrorException(PollingErrorCode.Denied, 403, detail: "no"));
        var (status, body) = await ExecuteAsync(AAuthChainedInteractions.PollingFailure(denied)!);
        Assert.Equal(403, status);
        Assert.Equal("denied", (string?)body["error"]);
        Assert.Equal("no", (string?)body["detail"]);
        Assert.Null(AAuthChainedInteractions.PollingFailure(new InvalidOperationException()));
    }

    [Fact]
    public void Rekey_IssuesNewCode_KeepsIdAndPendingUrl()
    {
        var entry = AAuthChainedInteractions.Park("http://localhost:5200", "/pending", "/chain-interaction", First,
            "op", new JsonObject(), DateTimeOffset.UtcNow.AddMinutes(5));
        var rekeyed = AAuthChainedInteractions.Rekey(entry, Second);

        Assert.NotEqual(entry.Code, rekeyed.Code);
        Assert.Equal(entry.Id, rekeyed.Id);
        Assert.Equal(entry.PendingUrl, rekeyed.PendingUrl);
        Assert.Equal(entry.InteractionUrl, rekeyed.InteractionUrl);
        Assert.Equal(Second, rekeyed.DownstreamInteraction);
    }

    private static async Task<(int Status, JsonObject Body)> ExecuteAsync(IResult result)
    {
        var context = new DefaultHttpContext();
        context.RequestServices = new ServiceCollection()
            .AddLogging().AddOptions().BuildServiceProvider();
        context.Response.Body = new System.IO.MemoryStream();
        await result.ExecuteAsync(context);
        context.Response.Body.Position = 0;
        return (context.Response.StatusCode, (JsonObject)(await JsonNode.ParseAsync(context.Response.Body))!);
    }

    /// <summary>
    /// A PS whose token endpoint defers with requirement=interaction and whose pending URL stays
    /// pending until <see cref="Approve"/>, then returns an auth token. Counts every request.
    /// </summary>
    private sealed class DeferredPersonServer : HttpMessageHandler
    {
        private volatile bool _approved;
        public int TokenPosts;
        public int PendingGets;
        public int OtherRequests;
        public TaskCompletionSource Polled { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void Approve() => _approved = true;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path.Contains("well-known", StringComparison.Ordinal))
                return Task.FromResult(Json(HttpStatusCode.OK, new JsonObject
                {
                    ["issuer"] = PsUrl,
                    ["auth_token_endpoint"] = $"{PsUrl}/token",
                }));
            if (path == "/token" && request.Method == HttpMethod.Post)
            {
                Interlocked.Increment(ref TokenPosts);
                return Task.FromResult(Pending(withInteraction: true));
            }
            if (path == "/pending/1" && request.Method == HttpMethod.Get && request.Content is null)
            {
                if (Interlocked.Increment(ref PendingGets) >= 2) Polled.TrySetResult();
                return Task.FromResult(_approved
                    ? Json(HttpStatusCode.OK, new JsonObject { ["auth_token"] = "fake-auth-token" })
                    : Pending(withInteraction: false));
            }
            Interlocked.Increment(ref OtherRequests);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadRequest));
        }

        private static HttpResponseMessage Pending(bool withInteraction)
        {
            var response = Json(HttpStatusCode.Accepted, new JsonObject { ["status"] = "pending" });
            response.Headers.Location = new Uri($"{PsUrl}/pending/1");
            response.Headers.TryAddWithoutValidation("Retry-After", "0");
            response.Headers.TryAddWithoutValidation("Cache-Control", "no-store");
            if (withInteraction)
                response.Headers.TryAddWithoutValidation(AAuthRequirementHeader.Name,
                    Interaction.Format("http://localhost:5555/interaction", "CONSENT", TestEgress.Policy));
            return response;
        }

        private static HttpResponseMessage Json(HttpStatusCode status, JsonObject body) => new(status)
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
        };
    }
}
