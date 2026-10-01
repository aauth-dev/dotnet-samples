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
    private static readonly string ValidS256 = Base64UrlEncoder.Encode(new byte[32]);

    [Theory]
    [InlineData("r3_uri", "null")]
    [InlineData("r3_s256", "null")]
    [InlineData("r3_uri", "123")]
    [InlineData("r3_s256", "[]")]
    public void ResourceClaims_RejectPresentMalformedValues(string field, string json)
    {
        var payload = new JsonObject { [field] = JsonNode.Parse(json) };
        Assert.Throws<InvalidOperationException>(() => R3ClaimReader.ReadResourceDocument(payload));
        Assert.Throws<InvalidOperationException>(() => R3AuthClaims.ValidateResourcePair(payload));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void EmptyGrantedClaimsRoundTripWithoutAuthorizingUnlistedOperations(bool perCall)
    {
        var payload = new JsonObject(R3AuthClaims.AuthToken("https://resource.test/r3/doc", ValidS256,
            R3Grant.Mcp(), perCall ? R3Grant.Mcp("book") : null));
        var claims = R3ClaimReader.ReadAuthToken(payload);
        Assert.Empty(claims.Granted.Operations);
        var enforcement = new R3Enforcement(new R3ProposalStore(), new Uri(R3TestData.ResourceIssuer));
        Assert.Equal(R3EnforcementDecisionKind.Rejected, enforcement.Evaluate(claims, R3OperationIdentity.Mcp("unlisted")).Kind);
        Assert.Equal(perCall ? R3EnforcementDecisionKind.PerCall : R3EnforcementDecisionKind.Rejected,
            enforcement.Evaluate(claims, R3OperationIdentity.Mcp("book"), new Dictionary<string, R3Parameter>()).Kind);
    }

    [Fact]
    public void Draft11WireNames_PerCallClaimAndNoDocumentVersion()
    {
        var claims = R3AuthClaims.AuthToken("https://resource.test/r3/doc", ValidS256, R3Grant.Mcp("a"), R3Grant.Mcp("b"));
        Assert.Contains("r3_per_call", claims.Keys);
        Assert.DoesNotContain("r3_conditional", claims.Keys);

        var legacy = new JsonObject(R3AuthClaims.AuthToken("https://resource.test/r3/doc", ValidS256, R3Grant.Mcp("a")))
        {
            ["r3_conditional"] = JsonNode.Parse("{\"vocabulary\":\"urn:aauth:vocabulary:mcp\",\"operations\":[{\"tool\":\"b\"}]}"),
        };
        Assert.Null(R3ClaimReader.ReadAuthToken(legacy).PerCall);

        var document = R3Document.Mcp([R3Operation.Mcp("a")]);
        var proposal = new R3ProposalDocument
        {
            Vocabulary = Vocabulary.Mcp,
            Operations = [R3Operation.Mcp("b")],
            Parameters = new Dictionary<string, R3Parameter>(),
        };
        Assert.False(JsonNode.Parse(document.ToUtf8Bytes())!.AsObject().ContainsKey("version"));
        Assert.False(JsonNode.Parse(proposal.ToUtf8Bytes())!.AsObject().ContainsKey("version"));
    }

    [Fact]
    public async Task AuthClaims_RoundTripThroughAdditionalClaims()
    {
        var issuerKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var claims = R3AuthClaims.AuthToken(
            "https://resource.test/r3/doc",
            ValidS256,
            R3Grant.Mcp("search_trip_options", "hold_itinerary"),
            R3Grant.Mcp("book_trip"));

        var jwt = await new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
            Issuer = "https://as.test",
            Audience = "https://resource.test",
            PersonServer = R3TestData.PsIssuer,
            AgentConfirmationKey = agentKey,
            Key = issuerKey,
            KeyId = "as-1",
            Dwk = AuthTokenBuilder.AccessDwk,
            Subject = "pairwise-sub",
            AdditionalClaims = claims,
        }.BuildAsync();
        var payload = (JsonObject)JsonNode.Parse(Base64UrlEncoder.DecodeBytes(jwt.Split('.')[1]))!;

        var parsed = R3ClaimReader.ReadAuthToken(payload);

        Assert.Equal("https://resource.test/r3/doc", parsed.Uri);
        Assert.True(parsed.Granted.Contains(R3OperationIdentity.Mcp("search_trip_options")));
        Assert.True(parsed.PerCall!.Contains(R3OperationIdentity.Mcp("book_trip")));
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

    [Theory]
    [InlineData("http://resource.test/r3/doc", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("https://resource.test/r3/doc", "hash")]
    public void ResourceClaims_RejectNonHttpsUriAndMalformedDigest(string uri, string s256)
    {
        Assert.Throws<InvalidOperationException>(() => R3AuthClaims.ResourceDocument(uri, s256));
        Assert.Throws<InvalidOperationException>(() => R3AuthClaims.ValidateResourcePair(new JsonObject
        {
            [R3AuthClaims.UriClaim] = uri,
            [R3AuthClaims.S256Claim] = s256,
        }));
    }

    [Fact]
    public void AuthClaims_AllowLoopbackOnlyWithExplicitDevelopmentPolicy()
    {
        var payload = new JsonObject
        {
            [R3AuthClaims.UriClaim] = "http://localhost:5005/r3/doc",
            [R3AuthClaims.S256Claim] = ValidS256,
            [R3AuthClaims.GrantedClaim] = JsonNode.Parse("{\"vocabulary\":\"urn:aauth:vocabulary:mcp\",\"operations\":[]}"),
        };

        Assert.Throws<InvalidOperationException>(() => R3ClaimReader.ReadAuthToken(payload));
        var claims = R3ClaimReader.ReadAuthToken(payload, egressPolicy: TestEgress.Policy);

        Assert.Equal("http://localhost:5005/r3/doc", claims.Uri);
    }

    [Fact]
    public async Task R3Challenge_HandSignedResourceTokenPassesTokenVerifier()
    {
        var resourceKey = AAuthKey.Generate();
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var r3Uri = "https://resource.test/r3/doc";
        var r3S256 = Base64UrlEncoder.Encode(new byte[32]);
        var mission = R3Hash.ComputeS256("mission"u8);
        var presented = R3TestData.VerifyPersonToken(await R3TestData.PersonTokenAsync(psKey, agentKey, mission), psKey, agentKey);
        var token = await R3TestData.ResourceTokenAsync(resourceKey, presented, agentKey, r3Uri, r3S256);

        var handler = new StaticJsonHandler()
            .AddJson($"{R3TestData.ResourceIssuer}/.well-known/aauth-resource.json",
                R3TestData.Metadata(R3TestData.ResourceIssuer, ResourceTokenBuilder.ResourceDwk))
            .AddJson($"{R3TestData.ResourceIssuer}/.well-known/jwks.json",
                R3TestData.Jwks(R3TestData.ResourceKid, resourceKey));
        var http = new InProcessHttpClient(handler);
        var verified = await new TokenVerifier { EgressPolicy = TestEgress.Policy }.VerifyResourceTokenAsync(
            token,
            R3TestData.AsIssuer,
            agentKey.ComputeJwkThumbprint(),
            new MetadataClient(http),
            new JwksClient(http),
            expectedPersonServer: R3TestData.PsIssuer);

        Assert.Equal(ResourceTokenBuilder.TokenType, (string?)verified.Header["typ"]);
        Assert.Equal(ResourceTokenBuilder.ResourceDwk, (string?)verified.Payload["dwk"]);
        Assert.Equal(r3Uri, (string?)verified.Payload[R3AuthClaims.UriClaim]);
        Assert.Equal(r3S256, (string?)verified.Payload[R3AuthClaims.S256Claim]);
        Assert.Equal(R3TestData.PersonSubject, verified.Subject);
        Assert.Equal(presented.Jti, (string?)verified.Payload["presented_jti"]);
        Assert.Equal(mission, verified.MissionS256);
    }

    [Fact]
    public async Task ChallengeHeader_CarriesResourceToken()
    {
        var resourceKey = AAuthKey.Generate();
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var presented = R3TestData.VerifyPersonToken(await R3TestData.PersonTokenAsync(psKey, agentKey), psKey, agentKey);
        var token = await R3TestData.ResourceTokenAsync(resourceKey, presented, agentKey, "https://resource.test/r3/doc", ValidS256);

        var parsed = AAuthRequirementHeader.Parse(AAuthRequirementHeader.FormatAuthToken(token));

        Assert.Equal("auth-token", parsed.Requirement);
        Assert.Equal(token, parsed.ResourceToken);
    }
}
