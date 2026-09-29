using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Server.CallChaining;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Conformance.AuthTokens;

/// <summary>
/// Conformance tests for call chaining (§Call Chaining): the upstream_token and
/// presented_token parameters of a downstream token request, and routing to the
/// person server the upstream token names.
/// </summary>
public class CallChainingTests
{
    // ── upstream_token Exchange ─────────────────────────────────────────────

    [Fact(DisplayName = "§CallChaining — upstream_token and presented_token included in POST body")]
    public async Task UpstreamTokenIncludedInPostBody()
    {
        JsonObject? capturedBody = null;
        var handler = new MockTokenEndpointHandler(req => capturedBody = JsonNode.Parse(req)?.AsObject());
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();

        var httpClient = new InProcessHttpClient(handler) { BaseAddress = new Uri("http://localhost:5555") };
        var metadataClient = new MetadataClient(new InProcessHttpClient(new MockMetadataHandler()));
        var exchangeClient = new TokenExchangeClient(httpClient, metadataClient);

        var resourceToken = await BuildResourceTokenAsync();
        var presentedToken = await BuildPersonTokenAsync(psKey, agentKey, "http://localhost:5555");
        var upstreamToken = await BuildAuthTokenAsync(psKey, agentKey, "http://localhost:5555", "http://localhost:5555");

        await Assert.ThrowsAsync<TokenVerificationException>(() => exchangeClient.ExchangeAsync(
            "http://localhost:5555",
            resourceToken,
            new TokenExchangeRequest
            {
                PresentedToken = presentedToken,
                UpstreamToken = upstreamToken,
            }));

        Assert.NotNull(capturedBody);
        Assert.Equal(resourceToken, (string?)capturedBody!["resource_token"]);
        Assert.Equal(presentedToken, (string?)capturedBody["presented_token"]);
        Assert.Equal(upstreamToken, (string?)capturedBody["upstream_token"]);
    }

    [Fact(DisplayName = "§CallChaining — upstream_token omitted when null")]
    public async Task UpstreamTokenOmittedWhenNull()
    {
        JsonObject? capturedBody = null;
        var handler = new MockTokenEndpointHandler(req => capturedBody = JsonNode.Parse(req)?.AsObject());

        var httpClient = new InProcessHttpClient(handler) { BaseAddress = new Uri("http://localhost:5555") };
        var metadataClient = new MetadataClient(new InProcessHttpClient(new MockMetadataHandler()));
        var exchangeClient = new TokenExchangeClient(httpClient, metadataClient);

        await Assert.ThrowsAsync<TokenVerificationException>(async () => await exchangeClient.ExchangeAsync(
            "http://localhost:5555",
            await BuildResourceTokenAsync(),
            await BuildPersonTokenAsync(AAuthKey.Generate(), AAuthKey.Generate(), "http://localhost:5555")));

        Assert.NotNull(capturedBody);
        Assert.Null(capturedBody!["upstream_token"]);
        Assert.NotNull(capturedBody["presented_token"]);
    }

    [Fact(DisplayName = "§PS Token Endpoint — an auth token request without presented_token is refused locally")]
    public async Task PresentedTokenRequired()
    {
        var called = false;
        var handler = new MockTokenEndpointHandler(_ => called = true);
        var httpClient = new InProcessHttpClient(handler) { BaseAddress = new Uri("http://localhost:5555") };
        var exchangeClient = new TokenExchangeClient(httpClient, new MetadataClient(new InProcessHttpClient(new MockMetadataHandler())));

        await Assert.ThrowsAsync<ArgumentException>(async () => await exchangeClient.ExchangeAsync(
            "http://localhost:5555", await BuildResourceTokenAsync(), new TokenExchangeRequest()));
        Assert.False(called);
    }

    [Fact(DisplayName = "§CallChaining — an auth token carries no act delegation chain")]
    public async Task AuthTokenBuilderEmitsNoAct()
    {
        var payload = DecodePayload(await BuildAuthTokenAsync(AAuthKey.Generate(), AAuthKey.Generate(), "http://localhost:5555", "http://localhost:5555"));
        Assert.Null(payload["act"]);
        Assert.Null(payload["agent"]);
    }

    // ── Routing Logic ───────────────────────────────────────────────────────

    [Fact(DisplayName = "§CallChaining — an upstream auth token routes to its ps, not its iss")]
    public async Task RoutesToAuthTokenPersonServer()
    {
        var token = await BuildAuthTokenAsync(AAuthKey.Generate(), AAuthKey.Generate(), "http://localhost:5300", "http://localhost:8888");

        var server = CallChainingRouter.ResolveDownstreamServer(token, TestEgress.Policy);
        Assert.Equal("http://localhost:8888", server);
    }

    [Fact(DisplayName = "§CallChaining — an upstream person token routes to its iss")]
    public async Task RoutesToPersonTokenIssuer()
    {
        var token = await BuildPersonTokenAsync(AAuthKey.Generate(), AAuthKey.Generate(), "http://localhost:5555");

        var server = CallChainingRouter.ResolveDownstreamServer(token, TestEgress.Policy);
        Assert.Equal("http://localhost:5555", server);
    }

    [Theory(DisplayName = "§CallChaining — rejects an upstream token naming a non-https person server")]
    [InlineData(PersonTokenBuilder.TokenType, "iss")]
    [InlineData(AuthTokenBuilder.TokenType, "ps")]
    public void RejectsNonHttpsPersonServer(string typ, string claim)
    {
        var header = new JsonObject { ["alg"] = "Ed25519", ["typ"] = typ, ["kid"] = "k1" };
        var payload = new JsonObject
        {
            ["iss"] = "https://ps.example",
            ["ps"] = "https://ps.example",
            ["aud"] = "http://localhost:6000",
            [claim] = "http://external-server.com",
        };
        var token = EncodeUnsignedJwt(header, payload);

        Assert.Throws<InvalidOperationException>(() =>
            CallChainingHandler.ResolveDownstreamServer(token));
    }

    [Fact(DisplayName = "§CallChaining — an agent or resource token is not an upstream token")]
    public void RejectsOtherTokenTypes()
    {
        foreach (var typ in new[] { AgentTokenBuilder.TokenType, ResourceTokenBuilder.TokenType })
        {
            var token = EncodeUnsignedJwt(new JsonObject { ["alg"] = "Ed25519", ["typ"] = typ, ["kid"] = "k1" },
                new JsonObject { ["iss"] = "https://ps.example", ["ps"] = "https://ps.example" });
            Assert.Throws<InvalidOperationException>(() => CallChainingRouter.ResolveDownstreamServer(token));
        }
    }

    // ── AuthTokenBuilder uses Key.Algorithm ─────────────────────────────────

    [Fact(DisplayName = "§CallChaining — AuthTokenBuilder uses Key.Algorithm (ES256)")]
    public async Task AuthTokenBuilderUsesKeyAlgorithm()
    {
        var ecKey = EcdsaAAuthKey.Generate();
        var agentKey = AAuthKey.Generate();

        var token = await new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
            Issuer = "http://localhost:5555",
            Audience = "http://localhost:6000",
            PersonServer = "http://localhost:5555",
            AgentConfirmationKey = agentKey,
            Key = ecKey,
            KeyId = "ec-1",
            Subject = "user-1",
            Scope = "read",
        }.BuildAsync();

        var header = DecodeHeader(token);
        Assert.Equal("ES256", (string?)header["alg"]);

        var verifier = new TokenVerifier { EgressPolicy = TestEgress.Policy };
        var result = verifier.Verify(token, ecKey, AuthTokenBuilder.TokenType, AuthTokenBuilder.PersonDwk);
        Assert.Equal("http://localhost:5555", result.Issuer);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static async Task<string> BuildResourceTokenAsync()
    {
        var key = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        return await new ResourceTokenBuilder
        {
            ScopeDescriptions = TestScopeDefinitions.Resource,
            EgressPolicy = TestEgress.Policy,
            Issuer = "http://localhost:6000",
            Audience = "http://localhost:5555",
            PersonServer = "http://localhost:5555",
            Subject = "user-1",
            PresentedJti = "person-token-1",
            AgentJkt = agentKey.ComputeJwkThumbprint(),
            Key = key,
            KeyId = "res-1",
            Scope = "read",
        }.BuildAsync();
    }

    private static ValueTask<string> BuildPersonTokenAsync(AAuthKey psKey, AAuthKey agentKey, string issuer) => new PersonTokenBuilder
    {
        EgressPolicy = TestEgress.Policy,
        Issuer = issuer,
        Audience = "http://localhost:6000",
        Subject = "user-1",
        ConfirmationKey = agentKey,
        AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
        Key = psKey,
        KeyId = "ps-1",
    }.BuildAsync();

    private static async Task<string> BuildAuthTokenAsync(AAuthKey key, AAuthKey agentKey, string issuer, string personServer)
    {
        return await new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
            Issuer = issuer,
            Dwk = issuer == personServer ? AuthTokenBuilder.PersonDwk : AuthTokenBuilder.AccessDwk,
            Audience = "http://localhost:6000",
            PersonServer = personServer,
            AgentConfirmationKey = agentKey,
            Key = key,
            KeyId = "ps-1",
            Subject = "user-1",
            Scope = "read",
        }.BuildAsync();
    }

    private static string EncodeUnsignedJwt(JsonObject header, JsonObject payload)
    {
        var h = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToJsonString()));
        var p = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload.ToJsonString()));
        return $"{h}.{p}.fake-sig";
    }

    private static JsonObject DecodePayload(string jwt)
    {
        var segments = jwt.Split('.');
        var json = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(segments[1]));
        return JsonNode.Parse(json)!.AsObject();
    }

    private static JsonObject DecodeHeader(string jwt)
    {
        var segments = jwt.Split('.');
        var json = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(segments[0]));
        return JsonNode.Parse(json)!.AsObject();
    }

    /// <summary>Mock handler that returns metadata with an auth_token_endpoint.</summary>
    private sealed class MockMetadataHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            var metadata = new JsonObject
            {
                ["issuer"] = "http://localhost:5555",
                ["auth_token_endpoint"] = "http://localhost:5555/token",
            };
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(metadata.ToJsonString(), Encoding.UTF8, "application/json"),
            });
        }
    }

    /// <summary>Mock handler that captures the POST body and returns a fake auth token response.</summary>
    private sealed class MockTokenEndpointHandler : HttpMessageHandler
    {
        private readonly Action<string> _onBody;
        public MockTokenEndpointHandler(Action<string> onBody) => _onBody = onBody;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            if (request.RequestUri?.AbsolutePath == "/.well-known/aauth-person.json")
            {
                var metadata = new JsonObject
                {
                    ["issuer"] = "http://localhost:5555",
                    ["auth_token_endpoint"] = "http://localhost:5555/token",
                };
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(metadata.ToJsonString(), Encoding.UTF8, "application/json"),
                };
            }

            var body = await request.Content!.ReadAsStringAsync(ct);
            _onBody(body);

            var response = new JsonObject { ["auth_token"] = "fake-auth-token" };
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(response.ToJsonString(), Encoding.UTF8, "application/json"),
            };
        }
    }
}
