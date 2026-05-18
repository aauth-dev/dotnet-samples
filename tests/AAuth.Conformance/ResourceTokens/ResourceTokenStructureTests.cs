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
    private const string Agent = "aauth:alice@ap.example";

    private static (string Jwt, JsonObject Header, JsonObject Payload) Build()
    {
        var key = AAuthKey.Generate();
        var jwt = new ResourceTokenBuilder
        {
            Issuer = Iss,
            Audience = Aud,
            Agent = Agent,
            AgentJkt = "thumb",
            Key = key,
            KeyId = "r1",
            Scope = "whoami",
        }.Build();
        var parts = jwt.Split('.');
        var header = (JsonObject)JsonNode.Parse(Base64UrlEncoder.Decode(parts[0]))!;
        var payload = (JsonObject)JsonNode.Parse(Base64UrlEncoder.Decode(parts[1]))!;
        return (jwt, header, payload);
    }

    [Fact(DisplayName = "§Resource Token Structure — header.typ MUST be aa-resource+jwt")]
    public void HeaderTyp_IsResourceTokenMediaType()
    {
        var (_, header, _) = Build();
        Assert.Equal("aa-resource+jwt", (string?)header["typ"]);
    }

    [Fact(DisplayName = "§Resource Token Structure — header.alg MUST be EdDSA")]
    public void HeaderAlg_IsEdDsa()
    {
        var (_, header, _) = Build();
        Assert.Equal("EdDSA", (string?)header["alg"]);
    }

    [Fact(DisplayName = "§Resource Token Structure — payload.dwk MUST equal 'aauth-resource.json'")]
    public void PayloadDwk_IsResourceWellKnownName()
    {
        var (_, _, payload) = Build();
        Assert.Equal("aauth-resource.json", (string?)payload["dwk"]);
    }

    [Fact(DisplayName = "§Resource Token Structure — payload.iss MUST be the resource URL")]
    public void PayloadIss_IsResourceUrl()
    {
        var (_, _, payload) = Build();
        Assert.Equal(Iss, (string?)payload["iss"]);
    }

    [Fact(DisplayName = "§Resource Token Structure — payload.aud MUST be the PS/AS URL")]
    public void PayloadAud_IsPsOrAsUrl()
    {
        var (_, _, payload) = Build();
        Assert.Equal(Aud, (string?)payload["aud"]);
    }

    [Fact(DisplayName = "§Resource Token Structure — payload.agent MUST identify the agent")]
    public void PayloadAgent_IsPresent()
    {
        var (_, _, payload) = Build();
        Assert.Equal(Agent, (string?)payload["agent"]);
    }

    [Fact(DisplayName = "§Resource Token Structure — payload.agent_jkt MUST be the agent JWK thumbprint")]
    public void PayloadAgentJkt_IsPresent()
    {
        var (_, _, payload) = Build();
        Assert.Equal("thumb", (string?)payload["agent_jkt"]);
    }

    [Fact(DisplayName = "§Resource Token Structure — payload MUST include iat, exp, jti")]
    public void TemporalAndIdClaims_Present()
    {
        var (_, _, payload) = Build();
        Assert.NotNull(payload["iat"]);
        Assert.NotNull(payload["exp"]);
        Assert.NotNull(payload["jti"]);
    }

    [Fact(DisplayName = "§Resource Token Structure — Lifetime SHOULD NOT exceed 5 minutes")]
    public void Lifetime_FiveMinuteCap()
    {
        var key = AAuthKey.Generate();
        var b = new ResourceTokenBuilder
        {
            Issuer = Iss,
            Audience = Aud,
            Agent = Agent,
            AgentJkt = "t",
            Key = key,
            KeyId = "r",
            Lifetime = TimeSpan.FromHours(1),
        };
        Assert.Throws<InvalidOperationException>(() => b.Build());
    }

    [Fact(DisplayName = "§Resource Token Structure — iss MUST be https://")]
    public void Issuer_MustBeHttps()
    {
        var key = AAuthKey.Generate();
        var b = new ResourceTokenBuilder
        {
            Issuer = "http://insecure.example",
            Audience = Aud,
            Agent = Agent,
            AgentJkt = "t",
            Key = key,
            KeyId = "r",
        };
        Assert.Throws<InvalidOperationException>(() => b.Build());
    }
}
