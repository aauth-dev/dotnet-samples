using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AAuth;
using AAuth.Crypto;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Server.Verification;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace AAuth.Conformance.ResourceTokens;

/// <summary>
/// End-to-end conformance for the resource-managed (two-party) <c>AAuth-Access</c>
/// flow over a real ASP.NET Core pipeline (§AAuth-Access Response Header,
/// §Resource-Managed Authorization, §Authorization Endpoint Request): a signed
/// agent calls the proactive <c>authorization_endpoint</c>, the resource issues
/// an opaque token, the agent captures and replays it as
/// <c>Authorization: AAuth</c> (bound to its signature), and the resource
/// resolves it. Identity-based (hwk) signing, no PS/AS.
/// </summary>
public class ResourceManagedFlowTests : IAsyncLifetime
{
    private const string ResourceBase = "http://localhost";

    private readonly AAuthKey _agentKey = AAuthKey.Generate();
    // Resource-side mint/validate seam (distinct from the agent's replay store).
    private readonly InMemoryOpaqueTokenStore _resourceStore = new();
    private IHost? _host;

    public async Task InitializeAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new AAuthVerifier());
        var app = builder.Build();

        // Two-party: HTTP-signature-only verification (no issuer / PS).
        app.UseAAuthVerification(AAuthVerificationOptions.SignatureOnly());

        // Proactive authorization_endpoint: authorize on identity, issue a token.
        app.MapAAuthAuthorizationEndpoint("/authorize", async (ctx, req) =>
        {
            var info = new OpaqueTokenInfo
            {
                AgentJkt = ctx.GetAAuthVerification()?.Jkt ?? "unknown",
                Scope = req.Scope,
                Expiration = DateTimeOffset.UtcNow.AddMinutes(10),
            };
            await ctx.IssueAAuthAccessAsync(_resourceStore, info);
            return Results.Ok(new { authorized = true });
        });

        // Protected resource: requires a resolved opaque token.
        app.MapGet("/messages", async (HttpContext ctx) =>
        {
            var info = await ctx.ResolveAAuthAccessAsync(_resourceStore);
            if (info is null)
            {
                return Results.Json(new { error = "unauthorized" }, statusCode: StatusCodes.Status401Unauthorized);
            }

            return Results.Ok(new { messages = new[] { "trip confirmation" }, scope = info.Scope });
        });

        await app.StartAsync();
        _host = app;
    }

    public async Task DisposeAsync()
    {
        if (_host is not null)
        {
            await _host.StopAsync();
            _host.Dispose();
        }
    }

    private HttpClient BuildAgent()
        => new AAuthClientBuilder(_agentKey)
            .UseHwk()
            .WithResourceManagedAccess() // default in-memory agent store
            .WithInnerHandler(_host!.GetTestServer().CreateHandler())
            .Build();

    [Fact(DisplayName = "§Authorization Endpoint Request — proactive issue → agent replay → resource resolve")]
    public async Task ProactiveAuthorize_IssuesAndAgentReplays()
    {
        using var client = BuildAgent();

        // 1. Proactive POST authorization_endpoint → resource issues AAuth-Access;
        //    the agent's AAuthAccessHandler captures it.
        var authResp = await client.PostAsJsonAsync($"{ResourceBase}/authorize", new { scope = "inbox.read" });
        Assert.Equal(HttpStatusCode.OK, authResp.StatusCode);
        Assert.True(authResp.Headers.Contains(AAuthConstants.Headers.AAuthAccess));

        // 2. GET /messages → agent replays Authorization: AAuth (bound to its
        //    signature) → resource resolves the opaque token.
        var msgResp = await client.GetAsync($"{ResourceBase}/messages");
        Assert.Equal(HttpStatusCode.OK, msgResp.StatusCode);
        var body = await msgResp.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("inbox.read", (string?)body!["scope"]);
    }

    [Fact(DisplayName = "§Resource-Managed Authorization — request without an opaque token is unauthorized")]
    public async Task WithoutToken_IsUnauthorized()
    {
        using var client = BuildAgent();

        // No prior authorization → no token to replay → resource rejects.
        var msgResp = await client.GetAsync($"{ResourceBase}/messages");
        Assert.Equal(HttpStatusCode.Unauthorized, msgResp.StatusCode);
    }

    [Fact(DisplayName = "§Authorization Endpoint Request — missing scope is rejected")]
    public async Task AuthorizationEndpoint_MissingScope_Returns400()
    {
        using var client = BuildAgent();

        var resp = await client.PostAsJsonAsync($"{ResourceBase}/authorize", new { });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }
}
