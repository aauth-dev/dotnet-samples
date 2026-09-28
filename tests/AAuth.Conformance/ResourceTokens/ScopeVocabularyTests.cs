using AAuth.Crypto;
using AAuth.Tokens;

namespace AAuth.Conformance.ResourceTokens;

public class ScopeVocabularyTests
{
    [Theory]
    [InlineData("catalog.read email", true)]
    [InlineData("catalog.read", true)]
    [InlineData("email", true)]
    [InlineData("catalog.write", false)]
    [InlineData("openid", false)]
    [InlineData("catalog.empty", false)]
    public void IssuanceRequiresDeclaredResourceAndIdentityScopes(string scope, bool allowed)
    {
        var key = AAuthKey.Generate();
        var builder = new ResourceTokenBuilder
        {
            Issuer = "https://catalog.test", Audience = "https://as.test", PersonServer = "https://ps.test",
            Subject = "person-1", PresentedJti = "person-token-1",
            AgentJkt = key.ComputeJwkThumbprint(), Key = key, KeyId = "key", Scope = scope,
            ScopeDescriptions = new Dictionary<string, string> { ["catalog.read"] = "Read catalog", ["catalog.empty"] = "" },
            PersonServerScopesSupported = ["email"],
        };
        if (allowed) Assert.NotEmpty(builder.Build());
        else Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    [Fact]
    public void MissingVocabularyCannotAuthorizeEvenFamiliarScopeNames()
    {
        Assert.Throws<InvalidOperationException>(() => ResourceTokenBuilder.ValidateScopes("read", null, null));
        Assert.Throws<InvalidOperationException>(() => ResourceTokenBuilder.ValidateScopes("email", null, null));
        ResourceTokenBuilder.ValidateScopes(null, null, null);
    }
}