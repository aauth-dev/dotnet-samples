using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Headers;
using AAuth.R3.Model;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;

namespace AAuth.R3.Tests;

public class TokenClaimTests
{
    [Fact]
    public void AuthClaims_RoundTripThroughAdditionalClaims()
    {
        var issuerKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var claims = R3AuthClaims.AuthToken(
            "https://resource.test/r3/doc",
            "abc123",
            R3Grant.Mcp("search_trip_options", "hold_itinerary"),
            R3Grant.Mcp("book_trip"));

        var jwt = new AuthTokenBuilder
        {
            Issuer = "https://as.test",
            Audience = "https://resource.test",
            Agent = R3TestData.AgentId,
            AgentConfirmationKey = agentKey,
            Key = issuerKey,
            KeyId = "as-1",
            Dwk = AuthTokenBuilder.AccessDwk,
            Subject = "pairwise-sub",
            AdditionalClaims = claims,
        }.Build();
        var payload = (JsonObject)JsonNode.Parse(Base64UrlEncoder.DecodeBytes(jwt.Split('.')[1]))!;

        var parsed = R3ClaimReader.ReadAuthToken(payload);

        Assert.Equal("https://resource.test/r3/doc", parsed.Uri);
        Assert.True(parsed.Granted.Contains("search_trip_options"));
        Assert.True(parsed.Conditional!.Contains("book_trip"));
    }

    [Fact]
    public void ResourceClaims_RejectOneSidedPair()
    {
        Assert.Throws<InvalidOperationException>(() => R3AuthClaims.ValidateResourcePair(new JsonObject
        {
            [R3AuthClaims.UriClaim] = "https://resource.test/r3/doc",
        }));
        Assert.Throws<InvalidOperationException>(() => R3ClaimReader.ReadResourceDocument(new JsonObject
        {
            [R3AuthClaims.S256Claim] = "abc123",
        }));
    }

    [Fact]
    public async Task R3Challenge_HandSignedResourceTokenPassesTokenVerifier()
    {
        var resourceKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var r3Uri = "https://resource.test/r3/doc";
        var r3S256 = "abc123";
        var token = new R3Challenge
        {
            ResourceIssuer = R3TestData.ResourceIssuer,
            Audience = R3TestData.AsIssuer,
            Key = resourceKey,
            KeyId = R3TestData.ResourceKid,
        }.BuildResourceToken(R3TestData.AgentId, agentKey.ComputeJwkThumbprint(), r3Uri, r3S256);

        var handler = new StaticJsonHandler()
            .AddJson($"{R3TestData.ResourceIssuer}/.well-known/aauth-resource.json",
                R3TestData.Metadata(R3TestData.ResourceIssuer, ResourceTokenBuilder.ResourceDwk))
            .AddJson($"{R3TestData.ResourceIssuer}/.well-known/jwks.json",
                R3TestData.Jwks(R3TestData.ResourceKid, resourceKey));
        var http = new HttpClient(handler);
        var verified = await new TokenVerifier().VerifyResourceTokenAsync(
            token,
            R3TestData.AsIssuer,
            R3TestData.AgentId,
            agentKey.ComputeJwkThumbprint(),
            new MetadataClient(http),
            new JwksClient(http));

        Assert.Equal(ResourceTokenBuilder.TokenType, (string?)verified.Header["typ"]);
        Assert.Equal(ResourceTokenBuilder.ResourceDwk, (string?)verified.Payload["dwk"]);
        Assert.Equal(r3Uri, (string?)verified.Payload[R3AuthClaims.UriClaim]);
        Assert.Equal(r3S256, (string?)verified.Payload[R3AuthClaims.S256Claim]);
    }

    [Fact]
    public void ChallengeHeader_CarriesResourceToken()
    {
        var resourceKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var token = new R3Challenge
        {
            ResourceIssuer = R3TestData.ResourceIssuer,
            Audience = R3TestData.AsIssuer,
            Key = resourceKey,
            KeyId = R3TestData.ResourceKid,
        }.BuildResourceToken(R3TestData.AgentId, agentKey.ComputeJwkThumbprint(), "https://resource.test/r3/doc", "abc123");

        var parsed = AAuthRequirementHeader.Parse(AAuthRequirementHeader.FormatAuthToken(token));

        Assert.Equal("auth-token", parsed.Requirement);
        Assert.Equal(token, parsed.ResourceToken);
    }
}
