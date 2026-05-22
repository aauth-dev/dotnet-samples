using System;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Conformance.AuthTokens;

/// <summary>
/// Issuer-side conformance for an <c>aa-auth+jwt</c> per
/// draft-hardt-oauth-aauth-protocol-01 §Auth Token Structure.
/// </summary>
public class AuthTokenStructureTests
{
    private const string Iss = "https://ps.example";
    private const string Aud = "https://resource.example";
    private const string Agent = "aauth:alice@ap.example";
    private const string Kid = "ps-1";

    private static AAuthKey NewKey() => AAuthKey.Generate();

    private static string BuildToken(AAuthKey signingKey, AAuthKey agentKey,
        string? subject = "pairwise-sub", string? scope = "whoami") => new AuthTokenBuilder
    {
        Issuer = Iss,
        Audience = Aud,
        Agent = Agent,
        AgentConfirmationKey = agentKey,
        Key = signingKey,
        KeyId = Kid,
        Subject = subject,
        Scope = scope,
    }.Build();

    private static (JsonObject Header, JsonObject Payload) Decode(string jwt)
    {
        var parts = jwt.Split('.');
        Assert.Equal(3, parts.Length);
        var header = (JsonObject)JsonNode.Parse(Base64UrlEncoder.Decode(parts[0]))!;
        var payload = (JsonObject)JsonNode.Parse(Base64UrlEncoder.Decode(parts[1]))!;
        return (header, payload);
    }

    // -- Header --

    [Fact(DisplayName = "§Auth Token Structure — header.alg MUST NOT be 'none'")]
    public void HeaderAlg_NeverNone()
    {
        var (header, _) = Decode(BuildToken(NewKey(), NewKey()));
        Assert.NotEqual("none", ((string?)header["alg"])?.ToLowerInvariant());
    }

    [Fact(DisplayName = "§Auth Token Structure — header.alg is EdDSA")]
    public void HeaderAlg_IsEdDsa()
    {
        var (header, _) = Decode(BuildToken(NewKey(), NewKey()));
        Assert.Equal("EdDSA", (string?)header["alg"]);
    }

    [Fact(DisplayName = "§Auth Token Structure — header.typ MUST be aa-auth+jwt")]
    public void HeaderTyp_IsAuthTokenMediaType()
    {
        var (header, _) = Decode(BuildToken(NewKey(), NewKey()));
        Assert.Equal("aa-auth+jwt", (string?)header["typ"]);
    }

    [Fact(DisplayName = "§Auth Token Structure — header.kid MUST be present")]
    public void HeaderKid_IsPresent()
    {
        var (header, _) = Decode(BuildToken(NewKey(), NewKey()));
        Assert.Equal(Kid, (string?)header["kid"]);
    }

    // -- Required payload claims --

    [Fact(DisplayName = "§Auth Token Structure — payload.iss MUST be the PS/AS URL")]
    public void PayloadIss_IsIssuerUrl()
    {
        var (_, payload) = Decode(BuildToken(NewKey(), NewKey()));
        Assert.Equal(Iss, (string?)payload["iss"]);
    }

    [Fact(DisplayName = "§Auth Token Structure — payload.dwk MUST be 'aauth-person.json' or 'aauth-access.json'")]
    public void PayloadDwk_IsValidValue()
    {
        var (_, payload) = Decode(BuildToken(NewKey(), NewKey()));
        var dwk = (string?)payload["dwk"];
        Assert.Contains(dwk, new[] { "aauth-person.json", "aauth-access.json" });
    }

    [Fact(DisplayName = "§Auth Token Structure — payload.aud MUST be the resource URL")]
    public void PayloadAud_IsResourceUrl()
    {
        var (_, payload) = Decode(BuildToken(NewKey(), NewKey()));
        Assert.Equal(Aud, (string?)payload["aud"]);
    }

    [Fact(DisplayName = "§Auth Token Structure — payload.jti MUST be unique per token")]
    public void PayloadJti_IsUniquePerToken()
    {
        var psKey = NewKey();
        var agentKey = NewKey();
        var (_, a) = Decode(BuildToken(psKey, agentKey));
        var (_, b) = Decode(BuildToken(psKey, agentKey));
        Assert.NotEqual((string?)a["jti"], (string?)b["jti"]);
    }

    [Fact(DisplayName = "§Auth Token Structure — payload.agent MUST be the agent identifier")]
    public void PayloadAgent_IsPresent()
    {
        var (_, payload) = Decode(BuildToken(NewKey(), NewKey()));
        Assert.Equal(Agent, (string?)payload["agent"]);
    }

    [Fact(DisplayName = "§Auth Token Structure — payload.cnf.jwk MUST embed the agent public key")]
    public void PayloadCnfJwk_EmbedsAgentPublicKey()
    {
        var agentKey = NewKey();
        var (_, payload) = Decode(BuildToken(NewKey(), agentKey));
        var jwk = payload["cnf"]?["jwk"]?.AsObject();
        Assert.NotNull(jwk);
        Assert.Equal("OKP", (string?)jwk["kty"]);
        Assert.Equal("Ed25519", (string?)jwk["crv"]);
        Assert.Equal(Base64UrlEncoder.Encode(agentKey.PublicKeyBytes), (string?)jwk["x"]);
        Assert.Null(jwk["d"]); // private MUST NOT leak
    }

    [Fact(DisplayName = "§Auth Token Structure — payload.act MUST be present with act.sub = agent")]
    public void PayloadAct_IsPresentWithAgentSub()
    {
        var (_, payload) = Decode(BuildToken(NewKey(), NewKey()));
        var act = payload["act"]?.AsObject();
        Assert.NotNull(act);
        Assert.Equal(Agent, (string?)act["sub"]);
    }

    [Fact(DisplayName = "§Auth Token Structure — payload.iat MUST be set")]
    public void PayloadIat_IsSet()
    {
        var (_, payload) = Decode(BuildToken(NewKey(), NewKey()));
        Assert.NotNull(payload["iat"]);
    }

    [Fact(DisplayName = "§Auth Token Structure — payload.exp MUST be set and ≤ 1 hour from iat")]
    public void PayloadExp_IsSetAndBounded()
    {
        var (_, payload) = Decode(BuildToken(NewKey(), NewKey()));
        var iat = (long)payload["iat"]!;
        var exp = (long)payload["exp"]!;
        Assert.True(exp > iat);
        Assert.True(exp - iat <= 3600, "Auth token lifetime MUST NOT exceed 1 hour.");
    }

    [Fact(DisplayName = "§Auth Token Structure — at least one of sub or scope MUST be present")]
    public void AtLeastOneOfSubOrScope()
    {
        // With sub
        var (_, p1) = Decode(BuildToken(NewKey(), NewKey(), subject: "user1", scope: null));
        Assert.NotNull(p1["sub"]);

        // With scope
        var (_, p2) = Decode(BuildToken(NewKey(), NewKey(), subject: null, scope: "read"));
        Assert.NotNull(p2["scope"]);
    }

    [Fact(DisplayName = "§Auth Token Structure — builder rejects missing both sub and scope")]
    public void Builder_RejectsMissingBothSubAndScope()
    {
        var psKey = NewKey();
        var agentKey = NewKey();
        Assert.Throws<InvalidOperationException>(() => new AuthTokenBuilder
        {
            Issuer = Iss,
            Audience = Aud,
            Agent = Agent,
            AgentConfirmationKey = agentKey,
            Key = psKey,
            KeyId = Kid,
            Subject = null,
            Scope = null,
        }.Build());
    }

    [Fact(DisplayName = "§Auth Token Structure — Lifetime MUST NOT exceed 1 hour")]
    public void Lifetime_RejectsBeyondOneHour()
    {
        var psKey = NewKey();
        var agentKey = NewKey();
        Assert.Throws<InvalidOperationException>(() => new AuthTokenBuilder
        {
            Issuer = Iss,
            Audience = Aud,
            Agent = Agent,
            AgentConfirmationKey = agentKey,
            Key = psKey,
            KeyId = Kid,
            Subject = "sub",
            Lifetime = TimeSpan.FromHours(1.01),
        }.Build());
    }

    [Fact(DisplayName = "§Auth Token Structure — dwk = aauth-access.json when issued by AS")]
    public void Dwk_AccessServerVariant()
    {
        var jwt = new AuthTokenBuilder
        {
            Issuer = "https://as.example",
            Audience = Aud,
            Agent = Agent,
            AgentConfirmationKey = NewKey(),
            Key = NewKey(),
            KeyId = "as-1",
            Subject = "sub",
            Dwk = AuthTokenBuilder.AccessDwk,
        }.Build();
        var (_, payload) = Decode(jwt);
        Assert.Equal("aauth-access.json", (string?)payload["dwk"]);
    }
}
