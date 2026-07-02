using System.Net;
using System.Net.Http.Json;
using AAuth.R3.Model;

namespace AAuth.R3.Tests;

public class AgentR3RequestTests
{
    [Fact]
    public void CreateBody_CarriesR3OperationsForPostAuthorize()
    {
        var body = R3Request.CreateBody(R3Request.CreateMcpOperations("search_trip_options", "book_trip"));
        var operations = body["r3_operations"]!;

        Assert.Equal(Vocabulary.Mcp, (string?)operations["vocabulary"]);
        Assert.Equal("search_trip_options", (string?)operations["operations"]![0]!["tool"]);
    }

    [Fact]
    public async Task PostAuthorize_SendsOperationsAndChallengeFallbackIsReadable()
    {
        var handler = new CaptureAuthorizeHandler();
        using var http = new HttpClient(handler);

        var response = await R3Request.PostAuthorizeAsync(
            http,
            "https://resource.test/authorize",
            R3Operations.Mcp("book_trip"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("\"r3_operations\"", handler.Body);
        var challenge = R3Request.ReadChallenge(response);
        Assert.NotNull(challenge);
        Assert.Equal("resource.jwt", challenge!.ResourceToken);
    }

    [Fact]
    public void ReadChallenge_UsesFirstAAuthRequirementHeaderValue()
    {
        using var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
        response.Headers.TryAddWithoutValidation("AAuth-Requirement", [
            "requirement=auth-token; resource-token=\"first.jwt\"",
            "requirement=auth-token; resource-token=\"second.jwt\"",
        ]);

        var challenge = R3Request.ReadChallenge(response);

        Assert.NotNull(challenge);
        Assert.Equal("first.jwt", challenge!.ResourceToken);
    }

    private sealed class CaptureAuthorizeHandler : HttpMessageHandler
    {
        public string Body { get; private set; } = "";

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            Body = await request.Content!.ReadAsStringAsync(cancellationToken);
            var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
            response.Headers.TryAddWithoutValidation("AAuth-Requirement", "requirement=auth-token; resource-token=\"resource.jwt\"");
            return response;
        }
    }
}
