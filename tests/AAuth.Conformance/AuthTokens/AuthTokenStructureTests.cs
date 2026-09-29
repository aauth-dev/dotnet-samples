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
    private const string Kid = "ps-1";

    private static AAuthKey NewKey() => AAuthKey.Generate();

    private static ValueTask<string> BuildTokenAsync(AAuthKey signingKey, AAuthKey agentKey,
        string subject = "pairwise-sub", string? scope = "whoami",
        System.Collections.Generic.IReadOnlyDictionary<string, JsonNode?>? additionalClaims = null) => new AuthTokenBuilder
    {
        EgressPolicy = TestEgress.Policy,
        AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
        Issuer = Iss,
        Audience = Aud,
        PersonServer = Iss,
        AgentConfirmationKey = agentKey,
        Key = signingKey,
        KeyId = Kid,
        Subject = subject,
        Scope = scope,
        AdditionalClaims = additionalClaims,
    }.BuildAsync();

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
    public async Task HeaderAlg_NeverNone()
    {
        var (header, _) = Decode(await BuildTokenAsync(NewKey(), NewKey()));
        Assert.NotEqual("none", ((string?)header["alg"])?.ToLowerInvariant());
    }

    [Fact(DisplayName = "§Auth Token Structure — header.alg is Ed25519")]
    public async Task HeaderAlg_IsEd25519()
    {
        var (header, _) = Decode(await BuildTokenAsync(NewKey(), NewKey()));
        Assert.Equal("Ed25519", (string?)header["alg"]);
    }

    [Fact(DisplayName = "§Auth Token Structure — header.typ MUST be aa-auth+jwt")]
    public async Task HeaderTyp_IsAuthTokenMediaType()
    {
        var (header, _) = Decode(await BuildTokenAsync(NewKey(), NewKey()));
        Assert.Equal("aa-auth+jwt", (string?)header["typ"]);
    }

    [Fact(DisplayName = "§Auth Token Structure — header.kid MUST be present")]
    public async Task HeaderKid_IsPresent()
    {
        var (header, _) = Decode(await BuildTokenAsync(NewKey(), NewKey()));
        Assert.Equal(Kid, (string?)header["kid"]);
    }

    // -- Required payload claims --

    [Fact(DisplayName = "§Auth Token Structure — payload.iss MUST be the PS/AS URL")]
    public async Task PayloadIss_IsIssuerUrl()
    {
        var (_, payload) = Decode(await BuildTokenAsync(NewKey(), NewKey()));
        Assert.Equal(Iss, (string?)payload["iss"]);
    }

    [Fact(DisplayName = "§Auth Token Structure — payload.dwk MUST be 'aauth-person.json' or 'aauth-access.json'")]
    public async Task PayloadDwk_IsValidValue()
    {
        var (_, payload) = Decode(await BuildTokenAsync(NewKey(), NewKey()));
        var dwk = (string?)payload["dwk"];
        Assert.Contains(dwk, new[] { "aauth-person.json", "aauth-access.json" });
    }

    [Fact(DisplayName = "§Auth Token Structure — payload.aud MUST be the resource URL")]
    public async Task PayloadAud_IsResourceUrl()
    {
        var (_, payload) = Decode(await BuildTokenAsync(NewKey(), NewKey()));
        Assert.Equal(Aud, (string?)payload["aud"]);
    }

    [Fact(DisplayName = "§Auth Token Structure — payload.jti MUST be unique per token")]
    public async Task PayloadJti_IsUniquePerToken()
    {
        var psKey = NewKey();
        var agentKey = NewKey();
        var (_, a) = Decode(await BuildTokenAsync(psKey, agentKey));
        var (_, b) = Decode(await BuildTokenAsync(psKey, agentKey));
        Assert.NotEqual((string?)a["jti"], (string?)b["jti"]);
    }

    [Fact(DisplayName = "§Auth Token Structure — payload names the person (ps, sub) and no agent")]
    public async Task PayloadNamesPersonNotAgent()
    {
        var (_, payload) = Decode(await BuildTokenAsync(NewKey(), NewKey()));
        Assert.Equal(Iss, (string?)payload["ps"]);
        Assert.Equal("pairwise-sub", (string?)payload["sub"]);
        Assert.False(payload.ContainsKey("agent"));
    }

    [Fact(DisplayName = "§Auth Token Structure — payload.cnf.jwk MUST embed the agent public key")]
    public async Task PayloadCnfJwk_EmbedsAgentPublicKey()
    {
        var agentKey = NewKey();
        var (_, payload) = Decode(await BuildTokenAsync(NewKey(), agentKey));
        var jwk = payload["cnf"]?["jwk"]?.AsObject();
        Assert.NotNull(jwk);
        Assert.Equal("OKP", (string?)jwk["kty"]);
        Assert.Equal("Ed25519", (string?)jwk["crv"]);
        Assert.Equal(Base64UrlEncoder.Encode(agentKey.PublicKeyBytes), (string?)jwk["x"]);
        Assert.Null(jwk["d"]); // private MUST NOT leak
    }

    [Fact(DisplayName = "§Auth Token Structure — payload carries no act delegation chain")]
    public async Task PayloadAct_Omitted()
    {
        var (_, payload) = Decode(await BuildTokenAsync(NewKey(), NewKey()));
        Assert.Null(payload["act"]);
    }

    [Theory(DisplayName = "§Auth Token Structure — agent, act and mission are reserved and cannot be injected")]
    [InlineData("agent")]
    [InlineData("act")]
    [InlineData("mission")]
    [InlineData("ps")]
    [InlineData("mission_s256")]
    public async Task ReservedClaims_RejectedInAdditionalClaims(string claim)
    {
        Assert.True(AuthTokenBuilder.IsReservedClaim(claim));
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await BuildTokenAsync(NewKey(), NewKey(),
            additionalClaims: new System.Collections.Generic.Dictionary<string, JsonNode?> { [claim] = "x" }));
    }

    [Fact(DisplayName = "§Auth Token Structure — payload.iat MUST be set")]
    public async Task PayloadIat_IsSet()
    {
        var (_, payload) = Decode(await BuildTokenAsync(NewKey(), NewKey()));
        Assert.NotNull(payload["iat"]);
    }

    [Fact(DisplayName = "§Auth Token Structure — payload.exp MUST be set and ≤ 1 hour from iat")]
    public async Task PayloadExp_IsSetAndBounded()
    {
        var (_, payload) = Decode(await BuildTokenAsync(NewKey(), NewKey()));
        var iat = (long)payload["iat"]!;
        var exp = (long)payload["exp"]!;
        Assert.True(exp > iat);
        Assert.True(exp - iat <= 3600, "Auth token lifetime MUST NOT exceed 1 hour.");
    }

    [Fact(DisplayName = "§Auth Token Structure — sub is REQUIRED, scope is OPTIONAL")]
    public async Task SubRequired_ScopeOptional()
    {
        var (_, payload) = Decode(await BuildTokenAsync(NewKey(), NewKey(), subject: "user1", scope: null));
        Assert.Equal("user1", (string?)payload["sub"]);
        Assert.False(payload.ContainsKey("scope"));
    }

    [Theory(DisplayName = "§Auth Token Structure — builder rejects a missing sub or ps")]
    [InlineData("sub")]
    [InlineData("ps")]
    public async Task Builder_RejectsMissingSubjectOrPersonServer(string missing)
    {
        var psKey = NewKey();
        var agentKey = NewKey();
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
            Issuer = Iss,
            Audience = Aud,
            PersonServer = missing == "ps" ? "" : Iss,
            AgentConfirmationKey = agentKey,
            Key = psKey,
            KeyId = Kid,
            Subject = missing == "sub" ? "" : "sub",
            Scope = "read",
        }.BuildAsync());
    }

    [Fact(DisplayName = "§Auth Token Structure — Lifetime MUST NOT exceed 1 hour")]
    public async Task Lifetime_RejectsBeyondOneHour()
    {
        var psKey = NewKey();
        var agentKey = NewKey();
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await new AuthTokenBuilder
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
            Lifetime = TimeSpan.FromHours(1.01),
        }.BuildAsync());
    }

    [Fact(DisplayName = "§Auth Token Structure — dwk = aauth-access.json when issued by AS")]
    public async Task Dwk_AccessServerVariant()
    {
        var jwt = await new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
            Issuer = "https://as.example",
            Audience = Aud,
            PersonServer = Iss,
            AgentConfirmationKey = NewKey(),
            Key = NewKey(),
            KeyId = "as-1",
            Subject = "sub",
            Dwk = AuthTokenBuilder.AccessDwk,
        }.BuildAsync();
        var (_, payload) = Decode(jwt);
        Assert.Equal("aauth-access.json", (string?)payload["dwk"]);
    }
}
