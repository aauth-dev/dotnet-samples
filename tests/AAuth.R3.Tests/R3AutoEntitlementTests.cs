using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.R3.Tests;

public class R3AutoEntitlementTests
{
    private const string As = "https://as.test";
    private const string Ps = "https://ps.test";
    private const string OtherPs = "https://ps2.test";

    [Fact(DisplayName = "minting an R3 resource token entitles its aud and ps")]
    public async Task Minting_EntitlesAudAndPs()
    {
        var entitlements = new InMemoryR3DocumentEntitlements();
        var s256 = R3Hash.ComputeS256(R3TestData.Document().ToUtf8Bytes());

        await Challenge(entitlements).BuildResourceTokenAsync(Presented(Ps), agentJkt: "agent-jkt",
            r3Uri: R3TestData.ResourceIssuer + "/r3/doc", r3S256: s256, scope: null);

        Assert.True(await entitlements.IsEntitledAsync(R3TestData.ResourceIssuer + "/r3/doc", s256, As));
        Assert.True(await entitlements.IsEntitledAsync(R3TestData.ResourceIssuer + "/r3/doc", s256, Ps));
        Assert.False(await entitlements.IsEntitledAsync(R3TestData.ResourceIssuer + "/r3/doc", s256, OtherPs));
    }

    [Fact(DisplayName = "a Person Server not named by a minted token cannot read the document until entitled")]
    public async Task ThirdSigner_Rejected_UntilHostEntitles()
    {
        var bytes = R3TestData.Document().ToUtf8Bytes();
        var s256 = R3Hash.ComputeS256(bytes);
        var asKey = AAuthKey.Generate();
        var psKey = AAuthKey.Generate();
        var otherKey = AAuthKey.Generate();
        var discovery = new StaticJsonHandler()
            .AddJson($"{As}/.well-known/aauth-access.json", R3TestData.Metadata(As, "aauth-access.json"))
            .AddJson($"{As}/.well-known/jwks.json", R3TestData.Jwks("as-1", asKey))
            .AddJson($"{Ps}/.well-known/aauth-person.json", R3TestData.Metadata(Ps, "aauth-person.json"))
            .AddJson($"{Ps}/.well-known/jwks.json", R3TestData.Jwks("ps-1", psKey))
            .AddJson($"{OtherPs}/.well-known/aauth-person.json", R3TestData.Metadata(OtherPs, "aauth-person.json"))
            .AddJson($"{OtherPs}/.well-known/jwks.json", R3TestData.Jwks("ps-2", otherKey));

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new JwksClient(new InProcessHttpClient(discovery)));
        builder.Services.AddSingleton(new MetadataClient(new InProcessHttpClient(discovery)));
        builder.Services.AddAAuthR3Documents(_ => new R3DocumentReaderPolicy(As, [Ps, OtherPs]));
        await using var app = builder.Build();
        app.MapR3Document("/r3/doc", _ => bytes);
        await app.StartAsync();
        var entitlements = app.Services.GetRequiredService<IR3DocumentEntitlements>();

        await Challenge(entitlements).BuildResourceTokenAsync(Presented(Ps), agentJkt: "agent-jkt",
            r3Uri: R3TestData.ResourceIssuer + "/r3/doc", r3S256: s256, scope: null);

        Assert.Equal(bytes, await FetchAsync(app, asKey, As, "aauth-access.json", "as-1", s256));
        Assert.Equal(bytes, await FetchAsync(app, psKey, Ps, "ps-1", s256));
        await Assert.ThrowsAnyAsync<HttpRequestException>(() => FetchAsync(app, otherKey, OtherPs, "ps-2", s256));

        await entitlements.EntitleAsync(R3TestData.ResourceIssuer + "/r3/doc", s256, OtherPs, "host-token", DateTimeOffset.UtcNow.AddMinutes(5));
        Assert.Equal(bytes, await FetchAsync(app, otherKey, OtherPs, "ps-2", s256));
    }

    private static R3Challenge Challenge(IR3DocumentEntitlements entitlements) => new()
    {
        ResourceIssuer = R3TestData.ResourceIssuer,
        Audience = As,
        Key = AAuthKey.Generate(),
        KeyId = R3TestData.ResourceKid,
        Entitlements = entitlements,
        OperationValidator = NoopOperationValidator.Instance,
    };

    private static TokenVerifier.VerifiedToken Presented(string personServer) => new(new JsonObject(), new JsonObject
    {
        ["sub"] = "person-1",
        ["jti"] = "person-token-1",
        ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
    }, personServer, PersonTokenBuilder.TokenType);

    private static async Task<byte[]> FetchAsync(WebApplication app, AAuthKey key, string issuer, string dwk, string kid, string s256)
    {
        using var client = R3FetchClient.Create(key, issuer, dwk, kid,
            app.GetTestServer().CreateHandler(), transportContract: AAuthTransportContract.InProcessOnly);
        return await client.FetchAndVerifyAsync($"{R3TestData.ResourceIssuer}/r3/doc", s256, R3TestData.ResourceIssuer);
    }

    private static Task<byte[]> FetchAsync(WebApplication app, AAuthKey key, string personServer, string kid, string s256) =>
        FetchAsync(app, key, personServer, "aauth-person.json", kid, s256);
}
