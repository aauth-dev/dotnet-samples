using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using AAuth.Errors;
using AAuth.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AAuth.Tests.Server;

public class AAuthProblemDetailsTests
{
    [Theory]
    [InlineData(PollingErrorCode.Denied, "denied", 403)]
    [InlineData(PollingErrorCode.Abandoned, "abandoned", 403)]
    [InlineData(PollingErrorCode.Expired, "expired", 408)]
    [InlineData(PollingErrorCode.Revoked, "revoked", 403)]
    [InlineData(PollingErrorCode.InvalidCode, "invalid_code", 410)]
    [InlineData(PollingErrorCode.SlowDown, "slow_down", 429)]
    [InlineData(PollingErrorCode.ServerError, "server_error", 500)]
    public async Task PollingHelper_OwnsRegisteredStatus(PollingErrorCode code, string wire, int status)
    {
        var (actualStatus, error) = await ExecuteAsync(AAuthProblemDetails.Polling(code));
        Assert.Equal((status, wire), (actualStatus, error));
        Assert.Equal(status, AAuthProblemDetails.PollingStatus(code));
    }

    [Theory]
    [InlineData(TokenErrorCode.InvalidRequest, "invalid_request", 400)]
    [InlineData(TokenErrorCode.InvalidResourceToken, "invalid_resource_token", 400)]
    [InlineData(TokenErrorCode.ExpiredResourceToken, "expired_resource_token", 400)]
    [InlineData(TokenErrorCode.RevokedResourceToken, "revoked_resource_token", 400)]
    [InlineData(TokenErrorCode.InvalidPresentedToken, "invalid_presented_token", 400)]
    [InlineData(TokenErrorCode.ExpiredPresentedToken, "expired_presented_token", 400)]
    [InlineData(TokenErrorCode.RevokedPresentedToken, "revoked_presented_token", 400)]
    [InlineData(TokenErrorCode.InvalidUpstreamToken, "invalid_upstream_token", 400)]
    [InlineData(TokenErrorCode.ExpiredUpstreamToken, "expired_upstream_token", 400)]
    [InlineData(TokenErrorCode.RevokedUpstreamToken, "revoked_upstream_token", 400)]
    [InlineData(TokenErrorCode.InvalidSubagentToken, "invalid_subagent_token", 400)]
    [InlineData(TokenErrorCode.ExpiredSubagentToken, "expired_subagent_token", 400)]
    [InlineData(TokenErrorCode.RevokedSubagentToken, "revoked_subagent_token", 400)]
    [InlineData(TokenErrorCode.ClockSkew, "clock_skew", 400)]
    [InlineData(TokenErrorCode.UserUnreachable, "user_unreachable", 403)]
    [InlineData(TokenErrorCode.AsUnreachable, "as_unreachable", 502)]
    [InlineData(TokenErrorCode.ServerError, "server_error", 500)]
    public async Task TokenEndpointHelper_OwnsRegisteredStatus(TokenErrorCode code, string wire, int status)
    {
        var (actualStatus, error) = await ExecuteAsync(AAuthProblemDetails.TokenEndpoint(code));
        Assert.Equal((status, wire), (actualStatus, error));
        Assert.Equal(status, AAuthProblemDetails.TokenEndpointStatus(code));
    }

    private static async Task<(int Status, string? Error)> ExecuteAsync(IResult result)
    {
        var context = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection().AddLogging().BuildServiceProvider(),
        };
        context.Response.Body = new MemoryStream();
        await result.ExecuteAsync(context);
        context.Response.Body.Position = 0;
        var body = await new StreamReader(context.Response.Body).ReadToEndAsync();
        return (context.Response.StatusCode, body.Length == 0 ? null : (string?)JsonNode.Parse(body)?["error"]);
    }

    [Theory]
    [InlineData(400, "bad request")]
    [InlineData(401, null)]
    [InlineData(403, "")]
    [InlineData(429, "slow down")]
    [InlineData(500, "server failure")]
    public async Task Writer_PreservesStatusHeadersAndExtensions(int status, string? detail)
    {
        var extensions = new Dictionary<string, object?>
        {
            ["type"] = "https://example.test/problems/custom",
            ["mission_status"] = "terminated",
            ["error"] = "cannot_override",
            ["detail"] = "cannot_override",
        };
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        await using var app = builder.Build();
        app.MapGet("/problem", async (HttpContext context) =>
        {
            context.Response.Headers.RetryAfter = "5";
            context.Response.Headers.CacheControl = "no-store";
            await AAuthProblemDetails.WriteAsync(context, "server_error", detail, status, extensions);
        });
        await app.StartAsync();
        using var client = app.GetTestClient();
        var response = await client.GetAsync("/problem");
        Assert.Equal((HttpStatusCode)status, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal(TimeSpan.FromSeconds(5), response.Headers.RetryAfter?.Delta);
        Assert.True(response.Headers.CacheControl?.NoStore);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("server_error", (string?)body!["error"]);
        Assert.Equal(detail, (string?)body["detail"]);
        Assert.Equal(detail is not null, body.ContainsKey("detail"));
        Assert.Equal("terminated", (string?)body["mission_status"]);
        Assert.Equal("https://example.test/problems/custom", (string?)body["type"]);
        Assert.False(body.ContainsKey("error_description"));
        Assert.Equal("cannot_override", extensions["error"]);
        Assert.Equal("cannot_override", extensions["detail"]);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void Create_RequiresError(string? error)
        => Assert.ThrowsAny<ArgumentException>(() => AAuthProblemDetails.Create(error!));

    [Theory]
    [InlineData(200)]
    [InlineData(302)]
    [InlineData(600)]
    public void Create_RequiresErrorStatus(int status)
        => Assert.Throws<ArgumentOutOfRangeException>(() => AAuthProblemDetails.Create("denied", statusCode: status));

    [Fact]
    public async Task SignatureFailure_WritesBodyless401AndAcceptHeaders()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        await using var app = builder.Build();
        app.MapGet("/signature", () => AAuthProblemDetails.SignatureFailure(
            SignatureErrorCode.UnsupportedScheme,
            acceptedSchemes: ["jwt"],
            acceptedAlgorithms: ["Ed25519"]));
        await app.StartAsync();

        using var response = await app.GetTestClient().GetAsync("/signature");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("error=unsupported_scheme", response.Headers.GetValues(SignatureError.HeaderName).Single());
        Assert.Equal("jwt", response.Headers.GetValues("Accept-Signature-Scheme").Single());
        Assert.Equal("Ed25519", response.Headers.GetValues("Accept-Signature-Alg").Single());
        Assert.Empty(await response.Content.ReadAsByteArrayAsync());
    }

    [Fact]
    public async Task ProblemDetails403_DoesNotWriteSignatureHeaders()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        await using var app = builder.Build();
        app.MapGet("/denied", () => AAuthProblemDetails.Create("denied", statusCode: StatusCodes.Status403Forbidden));
        await app.StartAsync();

        using var response = await app.GetTestClient().GetAsync("/denied");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.False(response.Headers.Contains(SignatureError.HeaderName));
        Assert.False(response.Headers.Contains("Accept-Signature-Scheme"));
        Assert.False(response.Headers.Contains("Accept-Signature-Alg"));
    }
}