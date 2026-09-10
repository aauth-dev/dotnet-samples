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
    private readonly InMemoryInteractionPendingStore _pendingStore = new();
    private IHost? _host;

    public async Task InitializeAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new AAuthVerifier());
        builder.Services.AddSingleton<IOpaqueTokenStore>(_resourceStore);
        builder.Services.AddSingleton<IInteractionPendingStore>(_pendingStore);
        builder.Services.AddSingleton(new AAuthResourceManagedOptions());
        var app = builder.Build();

        // Two-party: HTTP-signature-only verification (no issuer / PS).
        app.UseAAuthVerification(AAuthVerificationOptions.Generic());
        app.MapAAuthInteractionPoll("/pending/{code}");

        // Proactive authorization_endpoint: authorize on identity, issue a token.
        app.MapAAuthAuthorizationEndpoint("/authorize", async (ctx, req) =>
        {
            if (req.Account is not null && req.Account is not ("personal" or "work"))
                return AAuthProblemDetails.Create("invalid_account", statusCode: 400);
            var info = new OpaqueTokenInfo
            {
                Account = req.Account,
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
            var info = await ctx.ResolveAAuthAccessAsync(_resourceStore,
                expectedAccount: ctx.Request.Query.TryGetValue("account", out var account) ? account.ToString() : null);
            if (info is null)
            {
                return AAuthProblemDetails.Create("unauthorized", statusCode: StatusCodes.Status401Unauthorized);
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
            .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(_host!.GetTestServer().CreateHandler(), AAuth.Discovery.AAuthTransportContract.InProcessOnly)
            .Build();

    [Theory]
    [InlineData("null")]
    [InlineData("42")]
    [InlineData("[]")]
    [InlineData("{}")]
    [InlineData("\"\"")]
    [InlineData("\"missing\"")]
    public async Task AuthorizationEndpoint_MalformedOrUnknownAccountCannotIssue(string account)
    {
        using var client = BuildAgent();
        using var response = await client.PostAsJsonAsync(ResourceBase + "/authorize", new JsonObject
        {
            ["scope"] = "inbox.read", ["account"] = JsonNode.Parse(account),
        });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(response.Headers.Contains(AAuthConstants.Headers.AAuthAccess));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AccountGrant_DirectAndDeferredCannotCrossAccounts(bool deferred)
    {
        using var client = BuildAgent();
        using var request = new HttpRequestMessage(deferred ? HttpMethod.Get : HttpMethod.Post, ResourceBase + "/authorize");
        request.Options.Set(AAuth.Agent.AAuthRequestOptions.Account, "personal");
        if (deferred)
        {
            var entry = _pendingStore.Park("inbox.read", _agentKey.ComputeJwkThumbprint(), TimeSpan.FromMinutes(5), "personal");
            _pendingStore.Approve(entry.Code);
            request.RequestUri = new Uri(ResourceBase + "/pending/" + entry.Code);
        }
        else request.Content = JsonContent.Create(new { scope = "inbox.read", account = "personal" });
        using var issued = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, issued.StatusCode);
        var token = issued.Headers.GetValues(AAuthConstants.Headers.AAuthAccess).Single();
        Assert.Equal("personal", (await _resourceStore.ValidateAsync(token))!.Account);
        foreach (var account in new string?[] { "personal", "work", null })
        {
            using var execution = new HttpRequestMessage(HttpMethod.Get, ResourceBase + "/messages" + (account is null ? "" : "?account=" + account));
            execution.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("AAuth", token);
            using var response = await client.SendAsync(execution);
            Assert.Equal(account == "personal" ? HttpStatusCode.OK : HttpStatusCode.Unauthorized, response.StatusCode);
        }
    }

    [Fact(DisplayName = "§Authorization Endpoint Request — proactive issue → agent replay → resource resolve")]
    public async Task ProactiveAuthorize_IssuesAndAgentReplays()
    {
        using var client = BuildAgent();

        // 1. Proactive POST authorization_endpoint → resource issues AAuth-Access;
        //    the agent's AAuthAccessHandler captures it.
        var authResp = await client.PostAsJsonAsync($"{ResourceBase}/authorize", new { scope = "inbox.read" });
        Assert.Equal(HttpStatusCode.OK, authResp.StatusCode);
        Assert.Equal("application/json", authResp.Content.Headers.ContentType?.MediaType);
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
        Assert.Equal("application/problem+json", resp.Content.Headers.ContentType?.MediaType);
        var body = await resp.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_request", (string?)body!["error"]);
        Assert.Equal("scope is required", (string?)body["detail"]);
        Assert.False(body.ContainsKey("error_description"));
    }

    [Fact]
    public async Task InteractionPoll_OtherAgent_ReturnsDeniedProblem()
    {
        var entry = _pendingStore.Park("inbox.read", "another-agent", TimeSpan.FromMinutes(5));
        using var client = BuildAgent();
        var response = await client.GetAsync($"{ResourceBase}/pending/{entry.Code}");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("denied", (string?)body!["error"]);
        Assert.Equal("interaction belongs to a different agent", (string?)body["detail"]);
        Assert.False(response.Headers.Contains(AAuthConstants.Headers.AAuthAccess));
        Assert.NotNull(_pendingStore.Get(entry.Code));
    }

    [Fact]
    public async Task InteractionPoll_PendingThenApproved_PreservesSuccessHeaders()
    {
        var entry = _pendingStore.Park("inbox.read", _agentKey.ComputeJwkThumbprint(), TimeSpan.FromMinutes(5));
        using var client = BuildAgent();
        var pending = await client.GetAsync($"{ResourceBase}/pending/{entry.Code}");
        Assert.Equal(HttpStatusCode.Accepted, pending.StatusCode);
        Assert.Equal("application/json", pending.Content.Headers.ContentType?.MediaType);
        Assert.Equal(TimeSpan.FromSeconds(1), pending.Headers.RetryAfter?.Delta);
        Assert.True(pending.Headers.CacheControl?.NoStore);
        Assert.False(pending.Headers.Contains(AAuthConstants.Headers.AAuthAccess));

        _pendingStore.Approve(entry.Code);
        var approved = await client.GetAsync($"{ResourceBase}/pending/{entry.Code}");
        Assert.Equal(HttpStatusCode.OK, approved.StatusCode);
        Assert.Equal("application/json", approved.Content.Headers.ContentType?.MediaType);
        Assert.True(approved.Headers.Contains(AAuthConstants.Headers.AAuthAccess));

        var consumed = await client.GetAsync($"{ResourceBase}/pending/{entry.Code}");
        Assert.Equal(HttpStatusCode.Gone, consumed.StatusCode);
        Assert.Equal("application/problem+json", consumed.Content.Headers.ContentType?.MediaType);
        var body = await consumed.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("expired", (string?)body!["error"]);
        Assert.False(body.ContainsKey("detail"));
    }

    [Theory]
    [InlineData("{", "application/json", HttpStatusCode.BadRequest, "malformed JSON body")]
    [InlineData("scope=inbox.read", "text/plain", HttpStatusCode.UnsupportedMediaType, "Content-Type must be application/json")]
    public async Task AuthorizationEndpoint_InvalidBody_ReturnsProblemDetails(
        string content, string contentType, HttpStatusCode status, string detail)
    {
        using var client = BuildAgent();
        using var response = await client.PostAsync($"{ResourceBase}/authorize",
            new StringContent(content, System.Text.Encoding.UTF8, contentType));
        Assert.Equal(status, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_request", (string?)body!["error"]);
        Assert.Equal(detail, (string?)body["detail"]);
        Assert.False(body.ContainsKey("error_description"));
    }
}
