using System;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Tokens;
using Xunit;

namespace AAuth.Conformance.AuthTokens;

/// <summary>
/// Conformance tests for auth token scope narrowing per §Auth Token scope rules.
/// Auth token scope MUST be a subset of the resource token's scope.
/// </summary>
public class ScopeNarrowingTests
{
    private const string Iss = "https://ps.example";
    private const string Aud = "https://resource.example";
    private const string Kid = "ps-1";

    private static async Task<(string Jwt, AAuthKey PsKey, AAuthKey AgentKey)> BuildWithScopeAsync(string scope)
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var jwt = await new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
            Issuer = Iss,
            Audience = Aud,
            PersonServer = Iss,
            AgentConfirmationKey = agentKey,
            Key = psKey,
            KeyId = Kid,
            Subject = "sub",
            Scope = scope,
        }.BuildAsync();
        return (jwt, psKey, agentKey);
    }

    [Fact(DisplayName = "§Auth Token scope — accepts equal scope")]
    public async Task Accepts_EqualScope()
    {
        var (jwt, psKey, agentKey) = await BuildWithScopeAsync("read write");
        var verifier = new TokenVerifier { EgressPolicy = TestEgress.Policy };
        var result = verifier.VerifyAuthToken(jwt, psKey, Aud, agentKey,
            expectedMaxScope: "read write");
        Assert.NotNull(result);
    }

    [Fact(DisplayName = "§Auth Token scope — accepts narrowed scope")]
    public async Task Accepts_NarrowedScope()
    {
        var (jwt, psKey, agentKey) = await BuildWithScopeAsync("read");
        var verifier = new TokenVerifier { EgressPolicy = TestEgress.Policy };
        var result = verifier.VerifyAuthToken(jwt, psKey, Aud, agentKey,
            expectedMaxScope: "read write admin");
        Assert.NotNull(result);
    }

    [Fact(DisplayName = "§Auth Token scope — rejects broadened scope")]
    public async Task Rejects_BroadenedScope()
    {
        var (jwt, psKey, agentKey) = await BuildWithScopeAsync("read write admin");
        var verifier = new TokenVerifier { EgressPolicy = TestEgress.Policy };
        Assert.Throws<TokenVerificationException>(() =>
            verifier.VerifyAuthToken(jwt, psKey, Aud, agentKey,
                expectedMaxScope: "read write"));
    }

    [Fact(DisplayName = "§Auth Token scope — null expectedMaxScope skips check")]
    public async Task Accepts_WhenNoMaxScopeSpecified()
    {
        var (jwt, psKey, agentKey) = await BuildWithScopeAsync("anything whatever");
        var verifier = new TokenVerifier { EgressPolicy = TestEgress.Policy };
        var result = verifier.VerifyAuthToken(jwt, psKey, Aud, agentKey,
            expectedMaxScope: null);
        Assert.NotNull(result);
    }
}
