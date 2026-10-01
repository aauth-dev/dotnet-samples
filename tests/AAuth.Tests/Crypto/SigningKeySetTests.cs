using System.Net.Http.Json;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Server;
using AAuth.Server.Challenge;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.Tests.Crypto;

public class SigningKeySetTests
{
    private const string Resource = "https://resource.example";
    private const string Ps = "https://ps.example";

    [Fact(DisplayName = "the first key added is active until another is activated")]
    public void FirstKeyIsActive_UntilActivated()
    {
        var k1 = AAuthKey.Generate();
        var k2 = AAuthKey.Generate();
        var keys = new AAuthSigningKeySet { ["k1"] = k1, ["k2"] = k2 };

        Assert.Equal(("k1", (IAAuthSigner)k1), keys.Active);
        keys.Activate("k2");
        Assert.Equal("k2", keys.ActiveKeyId);
        Assert.Same(k2, keys.Active.Signer);
        Assert.Equal(["k1", "k2"], keys.KeyIds);
    }

    [Fact(DisplayName = "a named active key must be added before use")]
    public void NamedActive_MustBeAdded()
    {
        var keys = new AAuthSigningKeySet(active: "k2").Add("k1", AAuthKey.Generate());
        Assert.Throws<InvalidOperationException>(() => keys.Active);
        keys.Add("k2", AAuthKey.Generate());
        Assert.Equal("k2", keys.ActiveKeyId);
    }

    [Fact(DisplayName = "invalid rotations are rejected")]
    public void InvalidRotations_Throw()
    {
        var keys = new AAuthSigningKeySet("k1", AAuthKey.Generate());
        Assert.Throws<InvalidOperationException>(() => new AAuthSigningKeySet().Active);
        Assert.Throws<ArgumentException>(() => keys.Add("k1", AAuthKey.Generate()));
        Assert.Throws<InvalidOperationException>(() => keys.Activate("missing"));
        Assert.Throws<InvalidOperationException>(() => keys.Remove("k1"));
        Assert.False(keys.Remove("missing"));
    }

    [Fact(DisplayName = "the indexer replaces a key in place")]
    public void Indexer_Replaces()
    {
        var replacement = AAuthKey.Generate();
        var keys = new AAuthSigningKeySet { ["k1"] = AAuthKey.Generate() };
        keys["k1"] = replacement;
        Assert.Single(keys);
        Assert.True(keys.TryGetSigner("k1", out var signer));
        Assert.Same(replacement, signer);
    }

    [Fact(DisplayName = "the JWKS publishes every kid and follows rotation without a restart")]
    public async Task Jwks_PublishesAllKids_AndFollowsRotation()
    {
        var keys = new AAuthSigningKeySet { ["k1"] = AAuthKey.Generate(), ["k2"] = AAuthKey.Generate() };
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        await using var app = builder.Build();
        app.MapAAuthResourceWellKnown(new AAuthResourceMetadataOptions { Issuer = Resource, SigningKeys = keys });
        await app.StartAsync();
        var client = app.GetTestClient();

        Assert.Equal(["k1", "k2"], await KidsAsync(client));

        keys.Add("k3", AAuthKey.Generate()).Activate("k3");
        keys.Remove("k1");
        Assert.Equal(["k2", "k3"], await KidsAsync(client));
    }

    [Fact(DisplayName = "tokens are signed with the active kid and rotation takes effect immediately")]
    public async Task Tokens_SignedWithActiveKid()
    {
        var k1 = AAuthKey.Generate();
        var k2 = AAuthKey.Generate();
        var keys = new AAuthSigningKeySet { ["k1"] = k1, ["k2"] = k2 };
        var options = new ChallengeOptions { ResourceIdentifier = Resource, ResourceSigningKeys = keys };
        var presented = Presented();
        var scopes = new Dictionary<string, string> { ["read"] = "Read" };

        var first = await AAuthChallengeMiddleware.BuildResourceTokenAsync(options, presented, "read", scopeDescriptions: scopes);
        keys.Activate("k2");
        var second = await AAuthChallengeMiddleware.BuildResourceTokenAsync(options, presented, "read", scopeDescriptions: scopes);

        Assert.Equal("k1", KidOf(first));
        Assert.Equal("k2", KidOf(second));
        var verifier = new TokenVerifier();
        verifier.Verify(first, k1, ResourceTokenBuilder.TokenType, ResourceTokenBuilder.ResourceDwk, Ps);
        verifier.Verify(second, k2, ResourceTokenBuilder.TokenType, ResourceTokenBuilder.ResourceDwk, Ps);
    }

    [Fact(DisplayName = "a local issuer verifies with every published key and stops after removal")]
    public async Task LocalIssuer_FollowsPublishedKeys()
    {
        var k1 = AAuthKey.Generate();
        var keys = new AAuthSigningKeySet("k1", k1);
        var verifier = new TokenVerifier().WithLocalIssuer(Ps, keys);
        var agent = AAuthKey.Generate();
        var jwt = await new PersonTokenBuilder
        {
            Issuer = Ps, Audience = Resource, Subject = "person-1", ConfirmationKey = agent,
            AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(30), Key = k1, KeyId = "k1",
        }.BuildAsync();

        keys.Add("k2", AAuthKey.Generate()).Activate("k2");
        Assert.Same(k1, verifier.LocalIssuerKeys!(Ps, "k1"));

        keys.Remove("k1");
        Assert.Null(verifier.LocalIssuerKeys!(Ps, "k1"));
        Assert.NotNull(verifier.LocalIssuerKeys!(Ps, "k2"));
        Assert.Equal("k1", KidOf(jwt));
    }

    private static async Task<string[]> KidsAsync(HttpClient client)
    {
        var jwks = await client.GetFromJsonAsync<JsonObject>("/.well-known/jwks.json");
        return jwks!["keys"]!.AsArray().Select(key => (string)key!["kid"]!).ToArray();
    }

    private static string KidOf(string jwt) =>
        (string)JsonNode.Parse(Base64UrlEncoder.DecodeBytes(jwt.Split('.')[0]))!["kid"]!;

    private static AAuthVerifiedAssertion Presented()
    {
        var agent = AAuthKey.Generate();
        var token = new TokenVerifier.VerifiedToken(new JsonObject(), new JsonObject
        {
            ["sub"] = "person-1",
            ["jti"] = "person-token-1",
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
        }, Ps, PersonTokenBuilder.TokenType);
        return new AAuthVerifiedAssertion("presented", token, agent);
    }
}
