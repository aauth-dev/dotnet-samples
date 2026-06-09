using AAuth;
using AAuth.Tokens;
using Xunit;

namespace AAuth.Tests;

public class AAuthConstantsTests
{
    [Fact]
    public void TokenType_AgentToken_MatchesBuilder()
    {
        Assert.Equal(AgentTokenBuilder.TokenType, AAuthConstants.TokenTypes.AgentToken);
    }

    [Fact]
    public void TokenType_AuthToken_MatchesBuilder()
    {
        Assert.Equal(AuthTokenBuilder.TokenType, AAuthConstants.TokenTypes.AuthToken);
    }

    [Fact]
    public void TokenType_ResourceToken_MatchesBuilder()
    {
        Assert.Equal(ResourceTokenBuilder.TokenType, AAuthConstants.TokenTypes.ResourceToken);
    }

    [Fact]
    public void TokenType_JktS256Jwt_IsSpecValue()
    {
        // draft-hardt-httpbis-signature-key-04 §3.4 Table 1.
        Assert.Equal("jkt-s256+jwt", AAuthConstants.TokenTypes.JktS256Jwt);
    }

    [Fact]
    public void JktThumbprintUrnPrefix_IsSpecValue()
    {
        // draft-hardt-httpbis-signature-key-04 §3.4 Table 1.
        Assert.Equal("urn:jkt:sha-256:", AAuthConstants.JktThumbprintUrnPrefix);
    }

    [Fact]
    public void DwkFiles_Agent_MatchesBuilder()
    {
        Assert.Equal(AgentTokenBuilder.AgentDwk, AAuthConstants.DwkFiles.Agent);
    }

    [Fact]
    public void DwkFiles_Person_MatchesBuilder()
    {
        Assert.Equal(AuthTokenBuilder.PersonDwk, AAuthConstants.DwkFiles.Person);
    }

    [Fact]
    public void DwkFiles_Access_MatchesBuilder()
    {
        Assert.Equal(AuthTokenBuilder.AccessDwk, AAuthConstants.DwkFiles.Access);
    }

    [Fact]
    public void DwkFiles_Resource_MatchesBuilder()
    {
        Assert.Equal(ResourceTokenBuilder.ResourceDwk, AAuthConstants.DwkFiles.Resource);
    }

    [Fact]
    public void Headers_SignatureKey_MatchesExisting()
    {
        Assert.Equal(AAuth.HttpSig.SignatureKeyHeader.Name, AAuthConstants.Headers.SignatureKey);
    }

    [Fact]
    public void Headers_AAuthRequirement_MatchesExisting()
    {
        Assert.Equal(AAuth.Headers.AAuthRequirementHeader.Name, AAuthConstants.Headers.AAuthRequirement);
    }

    [Fact]
    public void Schemes_AreProtocolValues()
    {
        Assert.Equal("jwt", AAuthConstants.Schemes.Jwt);
        Assert.Equal("hwk", AAuthConstants.Schemes.Hwk);
        Assert.Equal("jkt-jwt", AAuthConstants.Schemes.JktJwt);
        Assert.Equal("jwks_uri", AAuthConstants.Schemes.JwksUri);
    }
}
