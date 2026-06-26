using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using AAuth;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.R3.Model;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.R3.Tests;

public class ResourceR3Tests
{
    [Fact]
    public void Metadata_AddsR3Vocabularies()
    {
        var doc = R3Metadata.CreateResourceMetadata(
            R3TestData.ResourceIssuer,
            $"{R3TestData.ResourceIssuer}/.well-known/jwks.json",
            $"{R3TestData.ResourceIssuer}/authorize");

        var vocabularies = Assert.IsType<JsonArray>(doc["r3_vocabularies"]);
        Assert.Contains(vocabularies, node => (string?)node == Vocabulary.Mcp);
    }

    [Fact]
    public async Task DocumentEndpoint_VerifiesSignatureAndTrustsOnlyConfiguredAsOrPs()
    {
        var asKey = AAuthKey.Generate();
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var untrustedKey = AAuthKey.Generate();
        var bytes = R3TestData.Document().ToUtf8Bytes();
        var discovery = new StaticJsonHandler()
            .AddJson("https://as.test/.well-known/jwks.json", R3TestData.Jwks("as-1", asKey))
            .AddJson("https://ps.test/.well-known/jwks.json", R3TestData.Jwks("ps-1", psKey))
            .AddJson("https://agent.test/.well-known/jwks.json", R3TestData.Jwks("agent-1", agentKey))
            .AddJson("https://other.test/.well-known/jwks.json", R3TestData.Jwks("other-1", untrustedKey));

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new JwksClient(new HttpClient(discovery)));
        var app = builder.Build();
        app.MapR3Document("/r3/doc", _ => bytes, fetcher =>
            fetcher.JwksUri is not null
            && (fetcher.JwksUri.Authority == "as.test" || fetcher.JwksUri.Authority == "ps.test"));
        await app.StartAsync();
        try
        {
            Assert.Equal(HttpStatusCode.OK, (await SignedGet(app, asKey, "https://as.test/.well-known/jwks.json", "as-1")).StatusCode);
            Assert.Equal(HttpStatusCode.OK, (await SignedGet(app, psKey, "https://ps.test/.well-known/jwks.json", "ps-1")).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await SignedGet(app, agentKey, "https://agent.test/.well-known/jwks.json", "agent-1")).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await SignedGet(app, untrustedKey, "https://other.test/.well-known/jwks.json", "other-1")).StatusCode);

            using var unsigned = app.GetTestClient();
            unsigned.BaseAddress = new Uri(R3TestData.ResourceIssuer);
            Assert.Equal(HttpStatusCode.Unauthorized, (await unsigned.GetAsync("/r3/doc")).StatusCode);
        }
        finally
        {
            await app.DisposeAsync();
        }
    }

    [Fact]
    public async Task FetchClient_SignsWithJwksUriAndRejectsHashMismatch()
    {
        var asKey = AAuthKey.Generate();
        var bytes = R3TestData.Document().ToUtf8Bytes();
        var s256 = R3Hash.ComputeS256(bytes);
        var discovery = new StaticJsonHandler()
            .AddJson("https://as.test/.well-known/jwks.json", R3TestData.Jwks("as-1", asKey));

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new JwksClient(new HttpClient(discovery)));
        var app = builder.Build();
        app.MapR3Document("/r3/doc", _ => bytes, fetcher => fetcher.JwksUri?.Authority == "as.test");
        await app.StartAsync();
        try
        {
            var client = R3FetchClient.Create(asKey, "https://as.test/.well-known/jwks.json", "as-1", app.GetTestServer().CreateHandler());

            var fetched = await client.FetchAndVerifyAsync($"{R3TestData.ResourceIssuer}/r3/doc", s256);

            Assert.Equal(bytes, fetched);
            await Assert.ThrowsAsync<R3HashMismatchException>(() =>
                client.FetchAndVerifyAsync($"{R3TestData.ResourceIssuer}/r3/doc", "tampered"));
        }
        finally
        {
            await app.DisposeAsync();
        }
    }

    [Fact]
    public void Enforcement_GrantsChallengesRejectsAndDigestMatchesProposalRetry()
    {
        var claims = new R3ClaimReader.AuthTokenClaims(
            "https://resource.test/r3/doc",
            "doc-hash",
            R3Grant.Mcp("search_trip_options"),
            R3Grant.Mcp("book_trip"));
        var store = new R3ProposalStore();
        var enforcement = new R3Enforcement(store, new Uri(R3TestData.ResourceIssuer));
        var parameters = new Dictionary<string, R3Parameter>
        {
            ["itinerary_id"] = R3Parameter.Inline(JsonValue.Create("it-123")!),
            ["total_usd"] = R3Parameter.Inline(JsonValue.Create(1200)!),
        };

        Assert.Equal(R3EnforcementDecisionKind.Granted,
            enforcement.Evaluate(claims, "search_trip_options").Kind);
        Assert.Equal(R3EnforcementDecisionKind.Rejected,
            enforcement.Evaluate(claims, "cancel_trip").Kind);

        var conditional = enforcement.Evaluate(claims, "book_trip", parameters, (tool, _) =>
            new R3Display { Summary = $"Approve {tool}", Detail = "Concrete itinerary." });
        Assert.Equal(R3EnforcementDecisionKind.Conditional, conditional.Kind);
        Assert.True(store.TryGet(conditional.ProposalS256!, out _));

        Assert.Equal(R3EnforcementDecisionKind.Granted,
            enforcement.Evaluate(claims, "book_trip", parameters, approvedProposalS256: conditional.ProposalS256).Kind);

        var tampered = new Dictionary<string, R3Parameter>(parameters)
        {
            ["total_usd"] = R3Parameter.Inline(JsonValue.Create(1300)!),
        };
        Assert.Equal(R3EnforcementDecisionKind.Rejected,
            enforcement.Evaluate(claims, "book_trip", tampered, approvedProposalS256: conditional.ProposalS256).Kind);
    }

    private static async Task<HttpResponseMessage> SignedGet(WebApplication app, AAuthKey key, string jwksUri, string kid)
    {
        using var client = new AAuthClientBuilder(key)
            .UseJwksUri(jwksUri, kid)
            .WithInnerHandler(app.GetTestServer().CreateHandler())
            .Build();
        client.BaseAddress = new Uri(R3TestData.ResourceIssuer);
        return await client.GetAsync("/r3/doc");
    }
}
