using System.Net;
using AAuth.Headers;
using LiveWhoAmITest;
using Xunit;

namespace AAuth.Tests;

public sealed class LiveInteropValidationTests
{
    [Fact]
    public void SignatureChallengeRequiresUnauthorizedAndJwtScheme()
    {
        Assert.True(LiveInteropValidation.IsSignatureChallenge(HttpStatusCode.Unauthorized, ["jwt"]));
        Assert.True(LiveInteropValidation.IsSignatureChallenge(HttpStatusCode.Unauthorized, ["hwk, jwt"]));
        Assert.False(LiveInteropValidation.IsSignatureChallenge(HttpStatusCode.OK, ["jwt"]));
        Assert.False(LiveInteropValidation.IsSignatureChallenge(HttpStatusCode.Unauthorized, ["hwk"]));
        Assert.False(LiveInteropValidation.IsSignatureChallenge(HttpStatusCode.Unauthorized, ["jkt-jwt"]));
    }

    [Theory]
    [InlineData(HttpStatusCode.NoContent, "{}")]
    [InlineData(HttpStatusCode.OK, "not-json")]
    [InlineData(HttpStatusCode.OK, "{}")]
    [InlineData(HttpStatusCode.OK, "{\"iss\":\"https://agent.example\",\"sub\":\"wrong\",\"ps\":\"https://ps.example\"}")]
    [InlineData(HttpStatusCode.OK, "{\"iss\":123,\"sub\":\"aauth:test@agent.example\",\"ps\":\"https://ps.example\"}")]
    [InlineData(HttpStatusCode.OK, "{\"iss\":\"https://agent.example\",\"sub\":{},\"ps\":\"https://ps.example\"}")]
    [InlineData(HttpStatusCode.OK, "{\"iss\":\"https://agent.example\",\"sub\":\"aauth:test@agent.example\",\"ps\":[]}")]
    public void AgentIdentityRejectsWrongStatusOrPayload(HttpStatusCode status, string body)
        => Assert.False(LiveInteropValidation.IsAgentIdentityResponse(status, body,
            "https://agent.example", "aauth:test@agent.example", "https://ps.example"));

    [Fact]
    public void AgentIdentityAcceptsExactExpectedPayload()
        => Assert.True(LiveInteropValidation.IsAgentIdentityResponse(HttpStatusCode.OK,
            "{\"iss\":\"https://agent.example\",\"sub\":\"aauth:test@agent.example\",\"ps\":\"https://ps.example\"}",
            "https://agent.example", "aauth:test@agent.example", "https://ps.example"));

    [Theory]
    [InlineData("requirement=auth-token")]
    [InlineData("requirement=auth-token; resource-token=\"eyJ9.e30.c2ln\"")]
    [InlineData("requirement=agent-token")]
    public void PersonTokenChallengeRejectsOtherRequirements(string header)
        => Assert.False(LiveInteropValidation.IsPersonTokenChallenge(HttpStatusCode.Unauthorized,
            AAuthRequirementHeader.Parse(header)));

    [Fact]
    public void PersonTokenChallengeRequiresUnauthorized()
    {
        var requirement = AAuthRequirementHeader.Parse("requirement=person-token");

        Assert.True(LiveInteropValidation.IsPersonTokenChallenge(HttpStatusCode.Unauthorized, requirement));
        Assert.False(LiveInteropValidation.IsPersonTokenChallenge(HttpStatusCode.OK, requirement));
        Assert.False(LiveInteropValidation.IsPersonTokenChallenge(HttpStatusCode.Unauthorized, null));
    }

    [Theory]
    [InlineData(HttpStatusCode.NoContent, "")]
    [InlineData(HttpStatusCode.OK, "not-json")]
    [InlineData(HttpStatusCode.OK, "{}")]
    [InlineData(HttpStatusCode.OK, "{\"iss\":\"https://ps.example\"}")]
    [InlineData(HttpStatusCode.OK, "{\"sub\":\"person\"}")]
    [InlineData(HttpStatusCode.OK, "{\"iss\":123,\"sub\":\"person\"}")]
    [InlineData(HttpStatusCode.OK, "{\"iss\":\"https://ps.example\",\"sub\":{}}")]
    public void AuthorizedIdentityRejectsWrongStatusOrPayload(HttpStatusCode status, string body)
        => Assert.False(LiveInteropValidation.IsAuthorizedIdentityResponse(status, body));

    [Fact]
    public void AuthorizedIdentityAcceptsIssuerAndSubject()
        => Assert.True(LiveInteropValidation.IsAuthorizedIdentityResponse(HttpStatusCode.OK,
            "{\"iss\":\"https://ps.example\",\"sub\":\"person\"}"));
}
