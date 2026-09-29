using System;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Conformance.ResourceTokens;

/// <summary>
/// Issuer-side conformance for an <c>aa-resource+jwt</c> per
/// draft-hardt-oauth-aauth-protocol-01 §Resource Token Structure.
/// </summary>
public class ResourceTokenStructureTests
{
    private const string Iss = "https://resource.example";
    private const string Aud = "https://ps.example";

    private static async Task<(string Jwt, JsonObject Header, JsonObject Payload)> BuildAsync()
    {
        var key = AAuthKey.Generate();
        var jwt = await new ResourceTokenBuilder
        {
            ScopeDescriptions = TestScopeDefinitions.Resource,
            EgressPolicy = TestEgress.Policy,
            Issuer = Iss,
            Audience = Aud,
            PersonServer = Aud,
            Subject = "person-1",
            PresentedJti = "person-token-1",
            AgentJkt = "thumb",
            Key = key,
            KeyId = "r1",
            Scope = "whoami",
        }.BuildAsync();
        var parts = jwt.Split('.');
        var header = (JsonObject)JsonNode.Parse(Base64UrlEncoder.Decode(parts[0]))!;
        var payload = (JsonObject)JsonNode.Parse(Base64UrlEncoder.Decode(parts[1]))!;
        return (jwt, header, payload);
    }

    [Fact(DisplayName = "§Resource Token Structure — header.typ MUST be aa-resource+jwt")]
    public async Task HeaderTyp_IsResourceTokenMediaType()
    {
        var (_, header, _) = await BuildAsync();
        Assert.Equal("aa-resource+jwt", (string?)header["typ"]);
    }

    [Fact(DisplayName = "§Resource Token Structure — header.alg MUST be Ed25519")]
    public async Task HeaderAlg_IsEd25519()
    {
        var (_, header, _) = await BuildAsync();
        Assert.Equal("Ed25519", (string?)header["alg"]);
    }

    [Fact(DisplayName = "§Resource Token Structure — payload.dwk MUST equal 'aauth-resource.json'")]
    public async Task PayloadDwk_IsResourceWellKnownName()
    {
        var (_, _, payload) = await BuildAsync();
        Assert.Equal("aauth-resource.json", (string?)payload["dwk"]);
    }

    [Fact(DisplayName = "§Resource Token Structure — payload.iss MUST be the resource URL")]
    public async Task PayloadIss_IsResourceUrl()
    {
        var (_, _, payload) = await BuildAsync();
        Assert.Equal(Iss, (string?)payload["iss"]);
    }

    [Fact(DisplayName = "§Resource Token Structure — payload.aud MUST be the PS/AS URL")]
    public async Task PayloadAud_IsPsOrAsUrl()
    {
        var (_, _, payload) = await BuildAsync();
        Assert.Equal(Aud, (string?)payload["aud"]);
    }

    [Fact(DisplayName = "§Resource Token Structure — payload names the presented token (ps, sub, presented_jti) and no agent")]
    public async Task PayloadNamesPresentedToken()
    {
        var (_, _, payload) = await BuildAsync();
        Assert.Equal(Aud, (string?)payload["ps"]);
        Assert.Equal("person-1", (string?)payload["sub"]);
        Assert.Equal("person-token-1", (string?)payload["presented_jti"]);
        Assert.False(payload.ContainsKey("agent"));
    }

    [Theory(DisplayName = "§Resource Token Structure — builder requires ps, sub and presented_jti")]
    [InlineData("ps")]
    [InlineData("sub")]
    [InlineData("presented_jti")]
    public async Task Builder_RequiresPresentedTokenClaims(string missing)
    {
        var b = new ResourceTokenBuilder
        {
            ScopeDescriptions = TestScopeDefinitions.Resource,
            EgressPolicy = TestEgress.Policy,
            Issuer = Iss,
            Audience = Aud,
            PersonServer = missing == "ps" ? "" : Aud,
            Subject = missing == "sub" ? "" : "person-1",
            PresentedJti = missing == "presented_jti" ? "" : "person-token-1",
            AgentJkt = "t",
            Key = AAuthKey.Generate(),
            KeyId = "r",
        };
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await b.BuildAsync());
    }

    [Fact(DisplayName = "§Resource Token Structure — payload.agent_jkt MUST be the agent JWK thumbprint")]
    public async Task PayloadAgentJkt_IsPresent()
    {
        var (_, _, payload) = await BuildAsync();
        Assert.Equal("thumb", (string?)payload["agent_jkt"]);
    }

    [Fact(DisplayName = "§Resource Token Structure — payload MUST include iat, exp, jti")]
    public async Task TemporalAndIdClaims_Present()
    {
        var (_, _, payload) = await BuildAsync();
        Assert.NotNull(payload["iat"]);
        Assert.NotNull(payload["exp"]);
        Assert.NotNull(payload["jti"]);
    }

    [Fact(DisplayName = "§Resource Token Structure — Lifetime SHOULD NOT exceed 5 minutes")]
    public async Task Lifetime_FiveMinuteCap()
    {
        var key = AAuthKey.Generate();
        var b = new ResourceTokenBuilder
        {
            ScopeDescriptions = TestScopeDefinitions.Resource,
            EgressPolicy = TestEgress.Policy,
            Issuer = Iss,
            Audience = Aud,
            PersonServer = Aud,
            Subject = "person-1",
            PresentedJti = "person-token-1",
            AgentJkt = "t",
            Key = key,
            KeyId = "r",
            Lifetime = TimeSpan.FromHours(1),
        };
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await b.BuildAsync());
    }

    [Fact(DisplayName = "§Resource Token Structure — iss MUST be https://")]
    public async Task Issuer_MustBeHttps()
    {
        var key = AAuthKey.Generate();
        var b = new ResourceTokenBuilder
        {
            ScopeDescriptions = TestScopeDefinitions.Resource,
            EgressPolicy = TestEgress.Policy,
            Issuer = "http://insecure.example",
            Audience = Aud,
            PersonServer = Aud,
            Subject = "person-1",
            PresentedJti = "person-token-1",
            AgentJkt = "t",
            Key = key,
            KeyId = "r",
        };
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await b.BuildAsync());
    }
}
