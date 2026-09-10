using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using AAuth.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Xunit;

namespace AAuth.Tests.Server;

public class AAuthProblemDetailsTests
{
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
}