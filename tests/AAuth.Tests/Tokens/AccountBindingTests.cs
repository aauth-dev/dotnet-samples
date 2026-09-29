using System;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Tests.Tokens;

public class AccountBindingTests
{
    [Fact]
    public void CachedCarrierTracksRefreshedSourceAndRequestBindings()
    {
        var key = AAuthKey.Generate();
        string AgentToken() => new AgentTokenBuilder
        {
            Issuer = "https://ap.example", Subject = "aauth:agent@ap.example", Key = key, KeyId = "agent-key",
        }.Build();
        var original = AgentToken();
        var refreshed = AgentToken();
        var auth = new AuthTokenBuilder
        {
            Issuer = "https://ps.example", Audience = "https://resource.example", PersonServer = "https://ps.example",
            Key = key, KeyId = "ps-key", AgentConfirmationKey = key, AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10),
            Subject = "person", Account = "personal",
        }.Build();
        var holder = new AAuth.Agent.AAuthTokenHolder();
        using var request = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Get, "https://resource.example/data");
        request.Options.Set(AAuth.Agent.AAuthRequestOptions.Account, "personal");
        request.Options.Set(AAuth.Agent.AAuthRequestOptions.MissionS256, "mission-a");
        Assert.Equal(original, holder.SelectForRequest(request, original, key.ComputeJwkThumbprint()));
        holder.UpdateFromExchange(auth, request);
        Assert.Equal(auth, holder.SelectForRequest(request, original, key.ComputeJwkThumbprint()));
        Assert.Equal(refreshed, holder.SelectForRequest(request, refreshed, key.ComputeJwkThumbprint()));
        Assert.Equal(original, holder.SelectForRequest(request, original, "other-key"));
        request.Options.Set(AAuth.Agent.AAuthRequestOptions.Account, "work");
        Assert.Equal(original, holder.SelectForRequest(request, original, key.ComputeJwkThumbprint()));
        request.Options.Set(AAuth.Agent.AAuthRequestOptions.Account, "personal");
        request.Options.Set(AAuth.Agent.AAuthRequestOptions.MissionS256, "mission-b");
        Assert.Equal(original, holder.SelectForRequest(request, original, key.ComputeJwkThumbprint()));
    }

    [Fact]
    public void CachedCarrier_IsNotSharedAcrossUpstreamPeopleOrConcurrentAccounts()
    {
        var key = AAuthKey.Generate();
        var agent = new AgentTokenBuilder
        {
            Issuer = "https://ap.example", Subject = "aauth:agent@ap.example", Key = key, KeyId = "agent-key",
        }.Build();
        var auth = new AuthTokenBuilder
        {
            Issuer = "https://ps.example", Audience = "https://resource.example", PersonServer = "https://ps.example",
            Key = key, KeyId = "ps-key", AgentConfirmationKey = key, AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10),
            Subject = "person-a", Account = "personal",
        }.Build();
        var holder = new AAuth.Agent.AAuthTokenHolder();
        System.Net.Http.HttpRequestMessage Request(string account, string? upstream)
        {
            var request = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Get, "https://resource.example/data");
            request.Options.Set(AAuth.Agent.AAuthRequestOptions.Account, account);
            request.Options.Set(AAuth.Agent.MissionForwardingHandler.UpstreamAuthorization, upstream);
            return request;
        }
        using (var obtained = Request("personal", "upstream-person-a"))
        {
            holder.SelectForRequest(obtained, agent, key.ComputeJwkThumbprint());
            holder.UpdateFromExchange(auth, obtained);
        }

        // Another person's call chain (a different upstream token) never gets person A's token.
        using (var otherPerson = Request("personal", "upstream-person-b"))
            Assert.Equal(agent, holder.SelectForRequest(otherPerson, agent, key.ComputeJwkThumbprint()));
        using (var direct = Request("personal", null))
            Assert.Equal(agent, holder.SelectForRequest(direct, agent, key.ComputeJwkThumbprint()));

        // Concurrent requests for different accounts each see only their own binding.
        System.Threading.Tasks.Parallel.For(0, 200, i =>
        {
            var account = i % 2 == 0 ? "personal" : "work";
            using var request = Request(account, "upstream-person-a");
            Assert.Equal(account == "personal" ? auth : agent, holder.SelectForRequest(request, agent, key.ComputeJwkThumbprint()));
        });
    }

    [Fact]
    public void MissionIntent_AccountlessEntryIsNotAWildcard()
    {
        var script = new MockPersonServer.MissionConsentScript();
        script.SeedInScope("https://resource.example", "read");
        var policy = new MockPersonServer.MissionPolicyStore();
        policy.Record("mission", "test", [], script.InScopeSnapshot());
        Assert.True(policy.IsInScope("mission", "https://resource.example", "read"));
        Assert.False(policy.IsInScope("mission", "https://resource.example", "read", "personal"));
        script.SeedInScope("https://resource.example", "read", "personal");
        policy.Record("mission", "test", [], script.InScopeSnapshot());
        Assert.True(policy.IsInScope("mission", "https://resource.example", "read", "personal"));
        Assert.False(policy.IsInScope("mission", "https://resource.example", "read", "work"));
        Assert.NotEqual(MockPersonServer.MissionConsentScript.ScopeKey("https://resource.example", "read|x", "y"),
            MockPersonServer.MissionConsentScript.ScopeKey("https://resource.example", "read", "x|y"));
    }

    [Theory]
    [InlineData(null, "personal", false)]
    [InlineData("personal", null, false)]
    [InlineData("personal", "work", false)]
    [InlineData("personal", "personal", true)]
    public void CachedAuthToken_IsSelectedOnlyForMatchingAccount(string? tokenAccount, string? requestedAccount, bool reused)
    {
        var issuerKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var agentToken = new AgentTokenBuilder
        {
            Issuer = "https://ap.example", Subject = "aauth:demo@ap.example",
            Key = issuerKey, KeyId = "ap1", ConfirmationKey = agentKey,
        }.Build();
        var authToken = new AuthTokenBuilder
        {
            Issuer = "https://ps.example", Audience = "https://resource.example",
            PersonServer = "https://ps.example", AgentConfirmationKey = agentKey,
            AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
            Key = issuerKey, KeyId = "ps1", Subject = "person", Account = tokenAccount,
        }.Build();
        var holder = new AAuth.Agent.AAuthTokenHolder(authToken);
        using var request = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Get, "https://resource.example/data");
        if (requestedAccount is not null) request.Options.Set(AAuth.Agent.AAuthRequestOptions.Account, requestedAccount);
        Assert.Equal(reused ? authToken : agentToken, holder.SelectForRequest(request, agentToken, agentKey.ComputeJwkThumbprint()));
        Assert.Equal(agentToken, holder.SelectForRequest(request, agentToken, "another-key"));
        request.RequestUri = new Uri("https://other-resource.example/data");
        Assert.Equal(agentToken, holder.SelectForRequest(request, agentToken, agentKey.ComputeJwkThumbprint()));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("work")]
    public void CachedPersonToken_IsSelectedForAnyAccount(string? requestedAccount)
    {
        // A person token never carries `account`; the resource token it earns binds the account.
        var issuerKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var agentToken = new AgentTokenBuilder
        {
            Issuer = "https://ap.example", Subject = "aauth:demo@ap.example",
            Key = issuerKey, KeyId = "ap1", ConfirmationKey = agentKey,
        }.Build();
        var personToken = new PersonTokenBuilder
        {
            Issuer = "https://ps.example", Audience = "https://resource.example", Subject = "person",
            ConfirmationKey = agentKey, AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
            Key = issuerKey, KeyId = "ps1",
        }.Build();
        var holder = new AAuth.Agent.AAuthTokenHolder(personToken);
        using var request = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Get, "https://resource.example/data");
        if (requestedAccount is not null) request.Options.Set(AAuth.Agent.AAuthRequestOptions.Account, requestedAccount);
        Assert.Equal(personToken, holder.SelectForRequest(request, agentToken, agentKey.ComputeJwkThumbprint()));
    }

    [Theory]
    [InlineData(null, "agent", "key", false)]
    [InlineData("work", "agent", "key", false)]
    [InlineData("personal", "other", "key", false)]
    [InlineData("personal", "agent", "other", false)]
    [InlineData("personal", "agent", "key", true)]
    public async System.Threading.Tasks.Task PriorConsent_IsolatesAccountAgentAndKey(string? account, string agent, string key, bool expected)
    {
        var log = new AAuth.Server.Governance.InMemoryMissionLog();
        await log.AppendAsync(new AAuth.Server.Governance.MissionLogEntry("mission", AAuth.Server.Governance.MissionLogEntryKind.Token, DateTimeOffset.UtcNow)
        {
            Resource = "https://resource.example", Scope = "read", Granted = true,
            Account = "personal", AgentId = "agent", AgentKeyThumbprint = "key",
        });
        Assert.Equal(expected, await log.HasPriorConsentAsync("mission", "https://resource.example", "read",
            account: account, agentId: agent, agentKeyThumbprint: key));
    }

    [Theory]
    [InlineData(null, null, true)]
    [InlineData("personal", "personal", true)]
    [InlineData("personal", "work", false)]
    [InlineData("personal", null, false)]
    [InlineData(null, "personal", false)]
    [InlineData("Personal", "personal", false)]
    public void AuthToken_RequiresExactIndependentExpectation(string? actual, string? expected, bool accepted)
    {
        var issuer = AAuthKey.Generate();
        var agent = AAuthKey.Generate();
        var jwt = new AuthTokenBuilder
        {
            Issuer = "https://ps.example", Audience = "https://resource.example",
            PersonServer = "https://ps.example", AgentConfirmationKey = agent,
            AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
            Key = issuer, KeyId = "ps1", Subject = "person", Account = actual,
        }.Build();
        var payload = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(jwt.Split('.')[1]))!.AsObject();
        Assert.Equal(actual is not null, payload.ContainsKey("account"));
        var verifier = new TokenVerifier();
        TokenVerifier.VerifiedToken Verify() => verifier.VerifyAuthToken(jwt, issuer,
            "https://resource.example", agent,
            accountExpectation: new AccountExpectation(expected));
        if (accepted) Assert.Equal(actual, Verify().Account);
        else Assert.Throws<TokenVerificationException>(Verify);
    }

    [Theory]
    [InlineData("{\"account\":null}")]
    [InlineData("{\"account\":23}")]
    [InlineData("{\"account\":[]}")]
    [InlineData("{\"account\":{}}")]
    [InlineData("{\"account\":\"\"}")]
    [InlineData("""{"account":" "}""")]
    [InlineData("{\"account\":\"a\\nb\"}")]
    public void Read_RejectsMalformedClaim(string json)
    {
        Assert.False(AccountBinding.TryRead(JsonNode.Parse(json)!.AsObject(), out _));
    }
}