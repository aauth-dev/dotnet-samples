using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.CallChaining;
using AAuth.Server.Challenge;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Conformance.AuthTokens;

/// <summary>
/// Conformance tests for call-chaining (Gap 11): upstream_token exchange,
/// act chain construction, routing logic, and TokenVerifier nested act validation.
/// </summary>
public class CallChainingTests
{
    // ── upstream_token Exchange ─────────────────────────────────────────────

    [Fact(DisplayName = "§CallChaining — upstream_token included in POST body when provided")]
    public async Task UpstreamTokenIncludedInPostBody()
    {
        // Capture what the exchange client sends.
        JsonObject? capturedBody = null;
        var handler = new MockTokenEndpointHandler(req =>
        {
            capturedBody = JsonNode.Parse(req)?.AsObject();
        });
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("http://localhost:5555") };
        var metadataClient = new MetadataClient(new HttpClient(new MockMetadataHandler()));
        var exchangeClient = new TokenExchangeClient(httpClient, metadataClient);

        var resourceToken = BuildResourceToken();
        var upstreamToken = BuildAuthToken(psKey, agentKey, "agent-1", "http://localhost:5555");

        await exchangeClient.ExchangeAsync(
            "http://localhost:5555",
            resourceToken,
            new TokenExchangeRequest
            {
                UpstreamToken = upstreamToken,
            });

        Assert.NotNull(capturedBody);
        Assert.Equal(resourceToken, (string?)capturedBody!["resource_token"]);
        Assert.Equal(upstreamToken, (string?)capturedBody["upstream_token"]);
    }

    [Fact(DisplayName = "§CallChaining — upstream_token omitted when null")]
    public async Task UpstreamTokenOmittedWhenNull()
    {
        JsonObject? capturedBody = null;
        var handler = new MockTokenEndpointHandler(req =>
        {
            capturedBody = JsonNode.Parse(req)?.AsObject();
        });

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("http://localhost:5555") };
        var metadataClient = new MetadataClient(new HttpClient(new MockMetadataHandler()));
        var exchangeClient = new TokenExchangeClient(httpClient, metadataClient);

        await exchangeClient.ExchangeAsync(
            "http://localhost:5555",
            BuildResourceToken());

        Assert.NotNull(capturedBody);
        Assert.Null(capturedBody!["upstream_token"]);
    }

    // ── Act Chain Construction ──────────────────────────────────────────────

    [Fact(DisplayName = "§CallChaining — AuthTokenBuilder nests upstream act in delegation chain")]
    public void AuthTokenBuilderNestsUpstreamAct()
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();

        // Simulate upstream auth token's act: { sub: "upstream-agent" }
        var upstreamAct = new JsonObject { ["sub"] = "upstream-agent" };

        var token = new AuthTokenBuilder
        {
            Issuer = "http://localhost:5555",
            Audience = "http://localhost:6000",
            Agent = "resource-as-agent",
            AgentConfirmationKey = agentKey,
            Key = psKey,
            KeyId = "ps-1",
            Subject = "user-1",
            Scope = "read",
            UpstreamAct = upstreamAct,
        }.Build();

        // Decode and verify the act chain.
        var payload = DecodePayload(token);
        var act = payload["act"] as JsonObject;
        Assert.NotNull(act);
        Assert.Equal("resource-as-agent", (string?)act!["sub"]);

        // Nested act from upstream.
        var nestedAct = act["act"] as JsonObject;
        Assert.NotNull(nestedAct);
        Assert.Equal("upstream-agent", (string?)nestedAct!["sub"]);
    }

    [Fact(DisplayName = "§CallChaining — AuthTokenBuilder without UpstreamAct produces flat act")]
    public void AuthTokenBuilderWithoutUpstreamActProducesFlatAct()
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();

        var token = new AuthTokenBuilder
        {
            Issuer = "http://localhost:5555",
            Audience = "http://localhost:6000",
            Agent = "my-agent",
            AgentConfirmationKey = agentKey,
            Key = psKey,
            KeyId = "ps-1",
            Subject = "user-1",
            Scope = "read",
        }.Build();

        var payload = DecodePayload(token);
        var act = payload["act"] as JsonObject;
        Assert.NotNull(act);
        Assert.Equal("my-agent", (string?)act!["sub"]);
        Assert.Null(act["act"]); // No nesting.
    }

    [Fact(DisplayName = "§CallChaining — three-level act chain verified by TokenVerifier")]
    public void ThreeLevelActChainVerified()
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();

        // Level 1: original agent
        var level1Act = new JsonObject { ["sub"] = "original-agent" };
        // Level 2: intermediate resource — wraps level 1
        var level2Act = new JsonObject { ["sub"] = "intermediate-resource", ["act"] = level1Act };

        var token = new AuthTokenBuilder
        {
            Issuer = "http://localhost:5555",
            Audience = "http://localhost:7000",
            Agent = "final-resource",
            AgentConfirmationKey = agentKey,
            Key = psKey,
            KeyId = "ps-1",
            Subject = "user-1",
            Scope = "read",
            UpstreamAct = level2Act,
        }.Build();

        // Verify: TokenVerifier validates act chain depth.
        var verifier = new TokenVerifier();
        var result = verifier.VerifyAuthToken(
            token, psKey, "http://localhost:7000", agentKey,
            expectedAgentId: "final-resource");

        Assert.Equal("http://localhost:5555", result.Issuer);

        // Validate the full chain: final-resource → intermediate-resource → original-agent.
        var payload = DecodePayload(token);
        var act = payload["act"]!.AsObject();
        Assert.Equal("final-resource", (string?)act["sub"]);
        var nested1 = act["act"]!.AsObject();
        Assert.Equal("intermediate-resource", (string?)nested1["sub"]);
        var nested2 = nested1["act"]!.AsObject();
        Assert.Equal("original-agent", (string?)nested2["sub"]);
    }

    [Fact(DisplayName = "§CallChaining — act chain exceeding max depth rejected")]
    public void ActChainExceedingMaxDepthRejected()
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();

        // Build a deeply nested act chain (depth > 10).
        JsonObject deepAct = new JsonObject { ["sub"] = "deep-0" };
        for (int i = 1; i <= 11; i++)
        {
            deepAct = new JsonObject { ["sub"] = $"deep-{i}", ["act"] = deepAct };
        }

        var token = new AuthTokenBuilder
        {
            Issuer = "http://localhost:5555",
            Audience = "http://localhost:7000",
            Agent = "surface-agent",
            AgentConfirmationKey = agentKey,
            Key = psKey,
            KeyId = "ps-1",
            Subject = "user-1",
            Scope = "read",
            UpstreamAct = deepAct,
        }.Build();

        var verifier = new TokenVerifier();
        Assert.Throws<TokenVerificationException>(() =>
            verifier.VerifyAuthToken(token, psKey, "http://localhost:7000", agentKey,
                expectedAgentId: "surface-agent"));
    }

    // ── Routing Logic ───────────────────────────────────────────────────────

    [Fact(DisplayName = "§CallChaining — routes to mission.approver when present")]
    public void RoutesToMissionApprover()
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();

        // Build auth token with mission.approver.
        var token = BuildAuthTokenWithMission(psKey, agentKey, "http://localhost:8888");

        var server = CallChainingHandler.ResolveDownstreamServer(token);
        Assert.Equal("http://localhost:8888", server);
    }

    [Fact(DisplayName = "§CallChaining — routes to iss when no mission")]
    public void RoutesToIssWhenNoMission()
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();

        var token = BuildAuthToken(psKey, agentKey, "agent-1", "http://localhost:5555");

        var server = CallChainingHandler.ResolveDownstreamServer(token);
        Assert.Equal("http://localhost:5555", server);
    }

    [Fact(DisplayName = "§CallChaining — rejects non-https iss in upstream token")]
    public void RejectsNonHttpsIss()
    {
        // Manually build a token with http (non-localhost) iss.
        var header = new JsonObject { ["alg"] = "EdDSA", ["typ"] = "aa-auth+jwt", ["kid"] = "k1" };
        var payload = new JsonObject
        {
            ["iss"] = "http://external-server.com",
            ["aud"] = "http://localhost:6000",
            ["agent"] = "agent-1",
            ["act"] = new JsonObject { ["sub"] = "agent-1" },
        };
        var token = EncodeUnsignedJwt(header, payload);

        Assert.Throws<InvalidOperationException>(() =>
            CallChainingHandler.ResolveDownstreamServer(token));
    }

    // ── AuthTokenBuilder uses Key.Algorithm ─────────────────────────────────

    [Fact(DisplayName = "§CallChaining — AuthTokenBuilder uses Key.Algorithm (ES256)")]
    public void AuthTokenBuilderUsesKeyAlgorithm()
    {
        var ecKey = EcdsaAAuthKey.Generate();
        var agentKey = AAuthKey.Generate();

        var token = new AuthTokenBuilder
        {
            Issuer = "http://localhost:5555",
            Audience = "http://localhost:6000",
            Agent = "ec-agent",
            AgentConfirmationKey = agentKey,
            Key = ecKey,
            KeyId = "ec-1",
            Subject = "user-1",
            Scope = "read",
        }.Build();

        var header = DecodeHeader(token);
        Assert.Equal("ES256", (string?)header["alg"]);

        // Verify with the EC key.
        var verifier = new TokenVerifier();
        var result = verifier.Verify(token, ecKey, AuthTokenBuilder.TokenType, AuthTokenBuilder.PersonDwk);
        Assert.Equal("http://localhost:5555", result.Issuer);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static string BuildResourceToken()
    {
        var key = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        return new ResourceTokenBuilder
        {
            Issuer = "http://localhost:6000",
            Audience = "http://localhost:5555",
            Agent = "agent-1",
            AgentJkt = agentKey.ComputeJwkThumbprint(),
            Key = key,
            KeyId = "res-1",
            Scope = "read",
        }.Build();
    }

    private static string BuildAuthToken(AAuthKey psKey, AAuthKey agentKey, string agent, string issuer)
    {
        return new AuthTokenBuilder
        {
            Issuer = issuer,
            Audience = "http://localhost:6000",
            Agent = agent,
            AgentConfirmationKey = agentKey,
            Key = psKey,
            KeyId = "ps-1",
            Subject = "user-1",
            Scope = "read",
        }.Build();
    }

    private static string BuildAuthTokenWithMission(AAuthKey psKey, AAuthKey agentKey, string approverUrl)
    {
        // Build manually since AuthTokenBuilder doesn't have mission support yet.
        var header = new JsonObject
        {
            ["alg"] = "EdDSA",
            ["typ"] = "aa-auth+jwt",
            ["kid"] = "ps-1",
        };
        var now = DateTimeOffset.UtcNow;
        var payload = new JsonObject
        {
            ["iss"] = "http://localhost:5555",
            ["dwk"] = "aauth-person.json",
            ["aud"] = "http://localhost:6000",
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["agent"] = "agent-1",
            ["act"] = new JsonObject { ["sub"] = "agent-1" },
            ["cnf"] = new JsonObject { ["jwk"] = agentKey.ToPublicJwk() },
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = now.AddMinutes(60).ToUnixTimeSeconds(),
            ["sub"] = "user-1",
            ["scope"] = "read",
            ["mission"] = new JsonObject { ["approver"] = approverUrl },
        };
        return SignJwt(header, payload, psKey);
    }

    private static string SignJwt(JsonObject header, JsonObject payload, IAAuthKey key)
    {
        var h = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToJsonString()));
        var p = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload.ToJsonString()));
        var sig = key.Sign(Encoding.ASCII.GetBytes($"{h}.{p}"));
        return $"{h}.{p}.{Base64UrlEncoder.Encode(sig)}";
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

    /// <summary>Mock handler that returns metadata with a token_endpoint.</summary>
    private sealed class MockMetadataHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            var metadata = new JsonObject
            {
                ["issuer"] = "http://localhost:5555",
                ["token_endpoint"] = "http://localhost:5555/token",
            };
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(metadata.ToJsonString(), Encoding.UTF8, "application/json"),
            });
        }
    }

    /// <summary>Mock handler that captures the POST body and returns a valid auth token response.</summary>
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
                    ["token_endpoint"] = "http://localhost:5555/token",
                };
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(metadata.ToJsonString(), Encoding.UTF8, "application/json"),
                };
            }

            // Token endpoint — capture body and return a fake auth_token.
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
