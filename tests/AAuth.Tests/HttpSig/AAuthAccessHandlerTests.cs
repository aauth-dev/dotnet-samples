using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AAuth;
using AAuth.Agent;
using AAuth.Crypto;
using Xunit;

namespace AAuth.Tests.HttpSig;

public class AAuthAccessHandlerTests
{
    [Fact]
    public async Task AccountSwitchAndOtherKey_DoNotReuseCredentials()
    {
        var key = AAuthKey.Generate();
        var store = new InMemoryAAuthAccessStore();
        var inner = new ProgrammableHandler(index => index == 0 ? Ok("personal-token") : Ok());
        using var client = BuildClient(key, store, inner);
        foreach (var account in new string?[] { "personal", "work", null, "personal" })
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://resource.example/messages");
            if (account is not null) request.Options.Set(AAuthRequestOptions.Account, account);
            await client.SendAsync(request);
        }
        Assert.Null(inner.Requests[1].Headers.Authorization);
        Assert.Null(inner.Requests[2].Headers.Authorization);
        Assert.Equal("personal-token", inner.Requests[3].Headers.Authorization?.Parameter);
        using var otherClient = BuildClient(AAuthKey.Generate(), store, inner);
        using var other = new HttpRequestMessage(HttpMethod.Get, "https://resource.example/messages");
        other.Options.Set(AAuthRequestOptions.Account, "personal");
        await otherClient.SendAsync(other);
        Assert.Null(inner.Requests[4].Headers.Authorization);
    }

    private sealed class ProgrammableHandler : HttpMessageHandler
    {
        private readonly Func<int, HttpResponseMessage> _responder;
        public List<HttpRequestMessage> Requests { get; } = new();

        public ProgrammableHandler(Func<int, HttpResponseMessage> responder) => _responder = responder;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var index = Requests.Count;
            Requests.Add(request);
            return Task.FromResult(_responder(index));
        }
    }

    private static HttpResponseMessage Ok(string? accessToken = null)
    {
        var resp = new HttpResponseMessage(HttpStatusCode.OK);
        if (accessToken is not null)
        {
            resp.Headers.TryAddWithoutValidation("AAuth-Access", accessToken);
        }

        return resp;
    }

    private static HttpClient BuildClient(AAuthKey key, IAAuthAccessStore store, ProgrammableHandler inner)
        => new AAuthClientBuilder(key)
            .UseHwk()
            .WithResourceManagedAccess(store)
            .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(inner, AAuth.Discovery.AAuthTransportContract.InProcessOnly)
            .Build();

    [Fact]
    public async Task CapturesAccessToken_FromResponse()
    {
        var key = AAuthKey.Generate();
        var store = new InMemoryAAuthAccessStore();
        var inner = new ProgrammableHandler(i => i == 0 ? Ok("token-abc") : Ok());
        using var client = BuildClient(key, store, inner);

        await client.GetAsync("https://resource.example/messages");

        Assert.True(store.TryGet("https://resource.example", out var token, signingKeyThumbprint: key.ComputeJwkThumbprint()));
        Assert.Equal("token-abc", token);
    }

    [Fact]
    public async Task ReplaysAccessToken_AsAuthorizationAAuth_OnNextRequest()
    {
        var key = AAuthKey.Generate();
        var store = new InMemoryAAuthAccessStore();
        var inner = new ProgrammableHandler(i => i == 0 ? Ok("token-abc") : Ok());
        using var client = BuildClient(key, store, inner);

        await client.GetAsync("https://resource.example/messages");
        await client.GetAsync("https://resource.example/messages");

        var second = inner.Requests[1];
        Assert.NotNull(second.Headers.Authorization);
        Assert.Equal("AAuth", second.Headers.Authorization!.Scheme);
        Assert.Equal("token-abc", second.Headers.Authorization.Parameter);
    }

    [Fact]
    public async Task SignatureCovers_AuthorizationComponent_WhenTokenPresented()
    {
        var key = AAuthKey.Generate();
        var store = new InMemoryAAuthAccessStore();
        var inner = new ProgrammableHandler(i => i == 0 ? Ok("token-abc") : Ok());
        using var client = BuildClient(key, store, inner);

        await client.GetAsync("https://resource.example/messages"); // capture
        await client.GetAsync("https://resource.example/messages"); // replay + sign

        var second = inner.Requests[1];
        var sigInput = string.Join(",", second.Headers.GetValues("Signature-Input"));
        Assert.Contains("\"authorization\"", sigInput);
    }

    [Fact]
    public async Task FirstRequest_HasNoAuthorization_AndDoesNotCoverIt()
    {
        var key = AAuthKey.Generate();
        var store = new InMemoryAAuthAccessStore();
        var inner = new ProgrammableHandler(i => i == 0 ? Ok("token-abc") : Ok());
        using var client = BuildClient(key, store, inner);

        await client.GetAsync("https://resource.example/messages");

        var first = inner.Requests[0];
        Assert.Null(first.Headers.Authorization);
        var sigInput = string.Join(",", first.Headers.GetValues("Signature-Input"));
        Assert.DoesNotContain("\"authorization\"", sigInput);
    }

    [Fact]
    public async Task RollingRefresh_SwitchesToNewToken()
    {
        var key = AAuthKey.Generate();
        var store = new InMemoryAAuthAccessStore();
        // call 0 -> token-1, call 1 -> token-2, call 2 -> none
        var inner = new ProgrammableHandler(i => i switch
        {
            0 => Ok("token-1"),
            1 => Ok("token-2"),
            _ => Ok(),
        });
        using var client = BuildClient(key, store, inner);

        await client.GetAsync("https://resource.example/messages"); // -> token-1
        await client.GetAsync("https://resource.example/messages"); // replays token-1, -> token-2
        await client.GetAsync("https://resource.example/messages"); // replays token-2

        Assert.Equal("token-1", inner.Requests[1].Headers.Authorization!.Parameter);
        Assert.Equal("token-2", inner.Requests[2].Headers.Authorization!.Parameter);
        Assert.True(store.TryGet("https://resource.example", out var token, signingKeyThumbprint: key.ComputeJwkThumbprint()));
        Assert.Equal("token-2", token);
    }

    [Fact]
    public async Task MultipleAccessHeaders_AreRejected_NotStored()
    {
        var key = AAuthKey.Generate();
        var store = new InMemoryAAuthAccessStore();
        var inner = new ProgrammableHandler(_ =>
        {
            var resp = new HttpResponseMessage(HttpStatusCode.OK);
            resp.Headers.TryAddWithoutValidation("AAuth-Access", "token-1");
            resp.Headers.TryAddWithoutValidation("AAuth-Access", "token-2");
            return resp;
        });
        using var client = BuildClient(key, store, inner);

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            client.GetAsync("https://resource.example/messages"));

        Assert.False(store.TryGet("https://resource.example", out _, signingKeyThumbprint: key.ComputeJwkThumbprint()));
    }

    [Fact]
    public async Task InvalidToken68_InResponse_IsNotStored()
    {
        var key = AAuthKey.Generate();
        var store = new InMemoryAAuthAccessStore();
        var inner = new ProgrammableHandler(_ => Ok("not a token"));
        using var client = BuildClient(key, store, inner);

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            client.GetAsync("https://resource.example/messages"));

        Assert.False(store.TryGet("https://resource.example", out _, signingKeyThumbprint: key.ComputeJwkThumbprint()));
    }

    [Fact]
    public async Task DoesNotOverride_CallerSuppliedAuthorization()
    {
        var key = AAuthKey.Generate();
        var store = new InMemoryAAuthAccessStore();
        store.Set("https://resource.example", "stored-token");
        var inner = new ProgrammableHandler(_ => Ok());
        using var client = BuildClient(key, store, inner);

        using var request = new HttpRequestMessage(HttpMethod.Get, "https://resource.example/messages");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "external");
        await client.SendAsync(request);

        Assert.Equal("Bearer", inner.Requests[0].Headers.Authorization!.Scheme);
        Assert.Equal("external", inner.Requests[0].Headers.Authorization!.Parameter);
    }
}
