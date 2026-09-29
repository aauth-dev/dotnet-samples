using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server.Governance;
using AAuth.Server.Verification;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.Conformance.Missions;

public class GovernancePendingSignatureTests
{
    [Theory]
    [InlineData("agent", "GET")]
    [InlineData("issuer", "GET")]
    [InlineData("key", "GET")]
    [InlineData("unsigned", "GET")]
    [InlineData("agent", "DELETE")]
    [InlineData("issuer", "DELETE")]
    [InlineData("key", "DELETE")]
    [InlineData("unsigned", "DELETE")]
    public async Task MappedPendingRouteRequiresOriginalVerifiedSigner(string difference, string method)
    {
        var issuerKey = AAuthKey.Generate();
        var ownerKey = AAuthKey.Generate();
        using var discovery = new InProcessHttpClient(new DiscoveryHandler(issuerKey));
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddAAuthGovernance();
        builder.Services.AddAAuthDeferredConsent();
        builder.Services.AddSingleton<IMissionApprover>(new PromptApprover());
        builder.Services.AddSingleton(new AAuthVerifier());
        builder.Services.AddSingleton(new TokenVerifier { EgressPolicy = TestEgress.Policy });
        builder.Services.AddSingleton(new MetadataClient(discovery));
        builder.Services.AddSingleton(new JwksClient(discovery));
        await using var app = builder.Build();
        app.UseAAuthVerification(new AAuthVerificationOptions
        {
            EgressPolicy = TestEgress.Policy, ResourceIdentifier = "https://ps.example", AcceptedSchemes = ["jwt"],
        });
        app.MapAAuthGovernance(options => options.PersonServer = "https://ps.example");
        await app.StartAsync();

        async Task<HttpClient> ClientAsync(IAAuthSigner key, string issuer, string agent)
        {
            var token = await new AgentTokenBuilder
            {
                EgressPolicy = TestEgress.Policy, Issuer = issuer, Subject = agent,
                Key = issuerKey, KeyId = "key", ConfirmationKey = key,
            }.BuildAsync();
            return new InProcessHttpClient(new AAuthSigningHandler(key, new JwtSignatureKeyProvider(() => token))
            {
                InnerHandler = app.GetTestServer().CreateHandler(),
            });
        }

        using var owner = await ClientAsync(ownerKey, "https://agent.example", "aauth:owner@agent.example");
        using var parked = await owner.PostAsJsonAsync("https://ps.example/mission", new { description = "Private mission" });
        Assert.Equal(HttpStatusCode.Accepted, parked.StatusCode);
        var pending = new Uri(new Uri("https://ps.example"), parked.Headers.Location!);
        await app.Services.GetRequiredService<IDeferredConsentStore>().ResolveAsync(pending.Segments.Last(), true);
        using var attacker = difference == "unsigned" ? app.GetTestServer().CreateClient()
            : await ClientAsync(difference == "key" ? AAuthKey.Generate() : ownerKey,
                difference == "issuer" ? "https://foreign.example" : "https://agent.example",
                difference == "agent" ? "aauth:other@agent.example" : difference == "issuer" ? "aauth:owner@foreign.example" : "aauth:owner@agent.example");
        using var attack = new HttpRequestMessage(new HttpMethod(method), pending);
        using var rejected = await attacker.SendAsync(attack);
        Assert.Equal(difference == "unsigned" ? HttpStatusCode.Unauthorized : HttpStatusCode.NotFound, rejected.StatusCode);
        using var delivered = await owner.GetAsync(pending);
        Assert.Equal(HttpStatusCode.OK, delivered.StatusCode);
        Assert.Equal("aauth:owner@agent.example", Mission.FromApprovalResponse(await delivered.Content.ReadAsByteArrayAsync(), "https://ps.example").Agent);
    }

    private sealed class PromptApprover : IMissionApprover
    {
        public Task<MissionApprovalDecision> ApproveAsync(MissionApprovalContext context, CancellationToken cancellationToken = default)
            => Task.FromResult(MissionApprovalDecision.Defer());
    }

    private sealed class DiscoveryHandler(IAAuthKey key) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var issuer = request.RequestUri!.GetLeftPart(UriPartial.Authority);
            var jwk = key.ToPublicJwk();
            jwk["kid"] = "key";
            var body = request.RequestUri.AbsolutePath.EndsWith("/keys", StringComparison.Ordinal)
                ? new JsonObject { ["keys"] = new JsonArray(jwk) }
                : new JsonObject { ["issuer"] = issuer, ["jwks_uri"] = issuer + "/keys" };
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(body) });
        }
    }
}