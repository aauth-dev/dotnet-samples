using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Tests.Agent;

public class TokenRefreshHandlerTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CancellationDuringRefreshDoesNotPublishToken(bool initialAcquisition)
    {
        var original = BuildAgentToken(TimeSpan.FromSeconds(20));
        var replacement = BuildAgentToken(TimeSpan.FromHours(1));
        var holder = initialAcquisition ? new AAuthTokenHolder() : new AAuthTokenHolder(original);
        using var cancellation = new CancellationTokenSource();
        var refresher = new CallbackRefresher((_, _) =>
        {
            cancellation.Cancel();
            return Task.FromResult(replacement);
        });
        using var client = new InProcessHttpClient(new TokenRefreshHandler(holder, refresher, _key.ComputeJwkThumbprint())
            { InnerHandler = new OkHandler() });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.GetAsync("https://resource.example", cancellation.Token));
        Assert.Equal(initialAcquisition ? string.Empty : original, holder.Current);
    }

    [Theory]
    [InlineData("personal", true)]
    [InlineData("work", false)]
    [InlineData(null, false)]
    public async Task Refresh_PreservesExactAccount(string? replacementAccount, bool accepted)
    {
        string Token(string? account, int seconds) => new AuthTokenBuilder
        {
            Issuer = "https://ps.example", Audience = "https://resource.example", Agent = "aauth:test@example.com",
            AgentConfirmationKey = _key, Key = _key, KeyId = "ps-1", Subject = "person",
            AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10), Lifetime = TimeSpan.FromSeconds(seconds), Account = account,
        }.Build();
        var original = Token("personal", 20);
        var replacement = Token(replacementAccount, 120);
        var holder = new AAuthTokenHolder(original);
        var refresher = new CallbackRefresher((context, _) =>
        {
            Assert.Equal("personal", context.Account);
            return Task.FromResult(replacement);
        });
        using var client = new InProcessHttpClient(new TokenRefreshHandler(holder, refresher, _key.ComputeJwkThumbprint())
            { InnerHandler = new OkHandler() });
        if (accepted)
        {
            using var response = await client.GetAsync("https://resource.example/data");
            Assert.Equal(replacement, holder.Current);
        }
        else
        {
            await Assert.ThrowsAsync<TokenVerificationException>(() => client.GetAsync("https://resource.example/data"));
            Assert.Equal(original, holder.Current);
        }
    }

    private readonly AAuthKey _key = AAuthKey.Generate();

    private string BuildAgentToken(TimeSpan lifetime)
    {
        return new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://ap.example",
            Subject = "aauth:test@example.com",
            KeyId = "k1",
            Key = _key,
            PersonServer = "https://ps.example",
            Lifetime = lifetime,
        }.Build();
    }

    [Fact]
    public async Task DoesNotRefresh_WhenTokenNotNearExpiry()
    {
        var token = BuildAgentToken(TimeSpan.FromHours(1));
        var holder = new AAuthTokenHolder(token);
        var refresher = new CountingRefresher(token);

        var handler = new TokenRefreshHandler(holder, refresher, "k1", TimeSpan.FromSeconds(60))
        {
            InnerHandler = new OkHandler(),
        };
        using var client = new InProcessHttpClient(handler);

        await client.GetAsync("https://resource.example/api");
        Assert.Equal(0, refresher.CallCount);
    }

    [Fact]
    public async Task Refreshes_WhenTokenNearExpiry()
    {
        // Token that expires in 30s (threshold is 60s)
        var expiringToken = BuildAgentToken(TimeSpan.FromSeconds(30));
        var freshToken = BuildAgentToken(TimeSpan.FromHours(1));
        var holder = new AAuthTokenHolder(expiringToken);
        var refresher = new CountingRefresher(freshToken);

        var handler = new TokenRefreshHandler(holder, refresher, "k1", TimeSpan.FromSeconds(60))
        {
            InnerHandler = new OkHandler(),
        };
        using var client = new InProcessHttpClient(handler);

        await client.GetAsync("https://resource.example/api");
        Assert.Equal(1, refresher.CallCount);
        Assert.Equal(freshToken, holder.Current);
    }

    [Fact]
    public async Task Refresh_PassesCorrectContext()
    {
        var expiringToken = BuildAgentToken(TimeSpan.FromSeconds(10));
        TokenRefreshContext? captured = null;
        var refresher = new CallbackRefresher((ctx, _) =>
        {
            captured = ctx;
            return Task.FromResult(ctx.CurrentToken);
        });

        var holder = new AAuthTokenHolder(expiringToken);
        var handler = new TokenRefreshHandler(holder, refresher, "my-kid", TimeSpan.FromSeconds(60))
        {
            InnerHandler = new OkHandler(),
        };
        using var client = new InProcessHttpClient(handler);

        await client.GetAsync("https://resource.example/api");
        Assert.NotNull(captured);
        Assert.Equal("https://ap.example", captured!.Issuer);
        Assert.Equal("aauth:test@example.com", captured.AgentId);
        Assert.Equal("my-kid", captured.SigningKeyThumbprint);
        Assert.Equal(expiringToken, captured.CurrentToken);
    }

    [Fact]
    public async Task ConcurrentRequests_OnlyRefreshOnce()
    {
        var expiringToken = BuildAgentToken(TimeSpan.FromSeconds(5));
        var freshToken = BuildAgentToken(TimeSpan.FromHours(1));
        var refresher = new SlowRefresher(freshToken, delay: TimeSpan.FromMilliseconds(100));
        var holder = new AAuthTokenHolder(expiringToken);

        var handler = new TokenRefreshHandler(holder, refresher, "k1", TimeSpan.FromSeconds(60))
        {
            InnerHandler = new OkHandler(),
        };
        using var client = new InProcessHttpClient(handler);

        var tasks = new Task[5];
        for (int i = 0; i < 5; i++)
            tasks[i] = client.GetAsync("https://resource.example/api");

        await Task.WhenAll(tasks);
        Assert.Equal(1, refresher.CallCount);
    }

    [Fact]
    public void ReadPayloadUnsafe_ParsesValidToken()
    {
        var token = BuildAgentToken(TimeSpan.FromHours(1));
        var payload = TokenRefreshHandler.ReadPayloadUnsafe(token);
        Assert.Equal("https://ap.example", (string?)payload["iss"]);
        Assert.Equal("aauth:test@example.com", (string?)payload["sub"]);
    }

    [Fact]
    public void ReadExpClaim_ReturnsExpiry()
    {
        var token = BuildAgentToken(TimeSpan.FromHours(1));
        var exp = TokenRefreshHandler.ReadExpClaim(token);
        Assert.NotNull(exp);
        Assert.True(exp!.Value > DateTimeOffset.UtcNow);
        Assert.True(exp.Value < DateTimeOffset.UtcNow.AddHours(2));
    }

    private sealed class CountingRefresher : ITokenRefresher
    {
        private readonly string _returnToken;
        public int CallCount;

        public CountingRefresher(string returnToken) => _returnToken = returnToken;

        public Task<string> RefreshAsync(TokenRefreshContext context, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref CallCount);
            return Task.FromResult(_returnToken);
        }
    }

    private sealed class CallbackRefresher : ITokenRefresher
    {
        private readonly Func<TokenRefreshContext, CancellationToken, Task<string>> _func;
        public CallbackRefresher(Func<TokenRefreshContext, CancellationToken, Task<string>> func) => _func = func;
        public Task<string> RefreshAsync(TokenRefreshContext context, CancellationToken cancellationToken)
            => _func(context, cancellationToken);
    }

    private sealed class SlowRefresher : ITokenRefresher
    {
        private readonly string _returnToken;
        private readonly TimeSpan _delay;
        public int CallCount;

        public SlowRefresher(string returnToken, TimeSpan delay)
        {
            _returnToken = returnToken;
            _delay = delay;
        }

        public async Task<string> RefreshAsync(TokenRefreshContext context, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref CallCount);
            await Task.Delay(_delay, cancellationToken);
            return _returnToken;
        }
    }

    private sealed class OkHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
    }
}
