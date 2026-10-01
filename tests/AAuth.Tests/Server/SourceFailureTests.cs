using System;
using System.IO;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AAuth.Server;
using AAuth.Tokens;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AAuth.Tests.Server;

public class SourceFailureTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);

    private static TokenRegistration Source(string jti, int secondsLeft, TokenCredential? credential) =>
        new TokenRegistration(new TokenKey("https://issuer.example", jti), Now.AddSeconds(secondsLeft)) { Credential = credential };

    private static async Task<(int Status, string? Header, string? Error)> RunAsync(IResult result)
    {
        var context = new DefaultHttpContext { RequestServices = new ServiceCollection().AddLogging().BuildServiceProvider() };
        context.Response.Body = new MemoryStream();
        await result.ExecuteAsync(context);
        context.Response.Body.Position = 0;
        var text = await new StreamReader(context.Response.Body).ReadToEndAsync();
        var error = text.Length == 0 ? null : (string?)JsonNode.Parse(text)?["error"];
        return (context.Response.StatusCode, context.Response.Headers["Signature-Error"].ToString() is { Length: > 0 } h ? h : null, error);
    }

    [Theory]
    [InlineData(TokenCredential.Presented, "expired_presented_token")]
    [InlineData(TokenCredential.Upstream, "expired_upstream_token")]
    [InlineData(TokenCredential.Subagent, "expired_subagent_token")]
    [InlineData(TokenCredential.Agent, "expired_agent_token")]
    public async Task ExpiredParameterToken_IsNamed(TokenCredential credential, string error)
    {
        var result = await RunAsync(AAuthProblemDetails.SourceExpired(
            [Source("live", 60, null), Source("gone", 0, credential)], Now));

        Assert.Equal((400, null, error), result);
    }

    [Fact]
    public async Task ExpiredSignatureKeyToken_IsExpiredJwt()
    {
        var result = await RunAsync(AAuthProblemDetails.SourceExpired(
            [Source("agent", -1, null), Source("presented", -1, TokenCredential.Presented)], Now));

        Assert.Equal((401, "error=expired_jwt", null), result);
    }

    [Fact]
    public async Task NoExpiredSource_UsesCallerFallback()
    {
        var fallback = AAuthProblemDetails.Create("mission_terminated", statusCode: 403);

        var result = await RunAsync(AAuthProblemDetails.SourceExpired([Source("live", 60, null)], Now, fallback));

        Assert.Equal((403, null, "mission_terminated"), result);
    }
}
