using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Headers;
using AAuth.Server;
using AAuth.Server.Verification;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Xunit;

namespace AAuth.Conformance.ResourceTokens;

/// <summary>
/// §Deferred Delivery: a resource that holds the invocation behind a 202 runs it
/// once, retains its result per auth-token jti until that token's exp, and
/// answers a repeated presentation from the retained result.
/// </summary>
public sealed class HeldInvocationTests
{
    private static readonly AAuthKey AgentKey = AAuthKey.Generate();
    private static readonly string ResourceToken = new ResourceTokenBuilder
    {
        Issuer = "https://resource.example", Audience = "https://ps.example", PersonServer = "https://ps.example",
        Subject = "person-1", PresentedJti = "person-jti", AgentJkt = AgentKey.ComputeJwkThumbprint(),
        Key = AgentKey, KeyId = "resource-key", Scope = "orders.write",
        ScopeDescriptions = new Dictionary<string, string> { ["orders.write"] = "Place orders" },
    }.Build();

    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Now;
    }

    // Stands in for verification: headers name the token type, jti, exp, key and scope.
    private static async Task<(WebApplication App, HttpClient Client, Func<int> Executions)> StartAsync(Clock clock)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var app = builder.Build();
        var held = new AAuthHeldInvocations(timeProvider: clock);
        var executions = 0;
        app.Use(async (context, next) =>
        {
            var type = context.Request.Headers["Test-Token"].ToString();
            var jkt = context.Request.Headers["Test-Jkt"].ToString();
            context.Features.Set(new AAuthVerificationResult
            {
                Level = AAuthLevel.Identified, Scheme = "jwt", IssuerVerified = true,
                TokenType = type == "auth" ? AAuthTokenType.AuthToken : AAuthTokenType.PersonToken,
                Jkt = jkt.Length > 0 ? jkt : AgentKey.ComputeJwkThumbprint(),
                Scopes = new HashSet<string>(context.Request.Headers["Test-Scope"].ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries)),
            });
            if (type == "auth")
            {
                var payload = new JsonObject
                {
                    ["jti"] = context.Request.Headers["Test-Jti"].ToString(),
                    ["exp"] = long.Parse(context.Request.Headers["Test-Exp"].ToString()),
                };
                context.Features.Set(new AAuthVerifiedAssertion("auth.token.jwt",
                    new TokenVerifier.VerifiedToken(new JsonObject(), payload, "https://ps.example", AuthTokenBuilder.TokenType), AgentKey));
            }
            await next();
        });
        app.MapPost("/orders", () => held.Hold(ResourceToken, ["orders.write"], (_, _) =>
            Task.FromResult(HeldInvocationResult.Json(new { order = ++executions }, StatusCodes.Status201Created))));
        app.MapAAuthHeldInvocations(held);
        await app.StartAsync();
        return (app, app.GetTestClient(), () => executions);
    }

    private static HttpRequestMessage Poll(Uri location, Clock clock, string jti, string? jkt = null, string scope = "orders.write",
        TimeSpan? lifetime = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, location);
        request.Headers.Add("Test-Token", "auth");
        request.Headers.Add("Test-Jti", jti);
        request.Headers.Add("Test-Exp", (clock.Now + (lifetime ?? TimeSpan.FromMinutes(5))).ToUnixTimeSeconds().ToString());
        request.Headers.Add("Test-Scope", scope);
        if (jkt is not null) request.Headers.Add("Test-Jkt", jkt);
        return request;
    }

    [Fact(DisplayName = "§Deferred Delivery — a 202 carries Location and requirement=auth-token; a poll without an auth token keeps holding")]
    public async Task Hold_AnswersPendingUntilAuthToken()
    {
        var clock = new Clock();
        var (app, client, executions) = await StartAsync(clock);
        await using var _ = app;

        using var held = await client.PostAsJsonAsync("/orders", new { item = "hotel" });
        Assert.Equal(HttpStatusCode.Accepted, held.StatusCode);
        var requirement = AAuthRequirementHeader.Parse(Assert.Single(held.Headers.GetValues(AAuthRequirementHeader.Name)));
        Assert.Equal(AAuthRequirementHeader.AuthTokenRequirement, requirement.Requirement);
        Assert.Equal(ResourceToken, requirement.ResourceToken);

        using var person = await client.GetAsync(held.Headers.Location);
        Assert.Equal(HttpStatusCode.Accepted, person.StatusCode);
        Assert.Equal(0, executions());
    }

    [Fact(DisplayName = "§Deferred Delivery — the invocation runs once; the same auth token gets the retained result until its exp")]
    public async Task RepeatedAuthToken_ReturnsRetainedResult()
    {
        var clock = new Clock();
        var (app, client, executions) = await StartAsync(clock);
        await using var _ = app;
        using var held = await client.PostAsJsonAsync("/orders", new { item = "hotel" });
        var location = held.Headers.Location!;

        using var first = await client.SendAsync(Poll(location, clock, "auth-1"));
        using var repeat = await client.SendAsync(Poll(location, clock, "auth-1"));
        using var other = await client.SendAsync(Poll(location, clock, "auth-2"));

        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        Assert.Equal(HttpStatusCode.Created, repeat.StatusCode);
        Assert.Equal(await first.Content.ReadAsStringAsync(), await repeat.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.Gone, other.StatusCode);
        Assert.Equal(1, executions());

        clock.Now += TimeSpan.FromMinutes(6);
        using var afterExpiry = await client.SendAsync(Poll(location, clock, "auth-1"));
        Assert.Equal(HttpStatusCode.Gone, afterExpiry.StatusCode);
        Assert.Equal(1, executions());
    }

    [Fact(DisplayName = "§Deferred Delivery — concurrent polls with the same auth token execute once")]
    public async Task ConcurrentPolls_ExecuteOnce()
    {
        var clock = new Clock();
        var (app, client, executions) = await StartAsync(clock);
        await using var _ = app;
        using var held = await client.PostAsJsonAsync("/orders", new { item = "hotel" });

        var polls = new List<Task<HttpResponseMessage>>();
        for (var i = 0; i < 8; i++) polls.Add(client.SendAsync(Poll(held.Headers.Location!, clock, "auth-1")));
        var responses = await Task.WhenAll(polls);

        Assert.All(responses, response => Assert.Equal(HttpStatusCode.Created, response.StatusCode));
        Assert.Equal(1, executions());
    }

    [Theory(DisplayName = "§Deferred Delivery — a foreign key or an under-scoped auth token does not run the invocation")]
    [InlineData("key")]
    [InlineData("scope")]
    public async Task ForeignKeyOrMissingScope_DoesNotExecute(string variant)
    {
        var clock = new Clock();
        var (app, client, executions) = await StartAsync(clock);
        await using var _ = app;
        using var held = await client.PostAsJsonAsync("/orders", new { item = "hotel" });

        using var response = await client.SendAsync(variant == "key"
            ? Poll(held.Headers.Location!, clock, "auth-1", jkt: AAuthKey.Generate().ComputeJwkThumbprint())
            : Poll(held.Headers.Location!, clock, "auth-1", scope: "orders.read"));

        Assert.Equal(variant == "key" ? HttpStatusCode.NotFound : HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(0, executions());
        using var owner = await client.SendAsync(Poll(held.Headers.Location!, clock, "auth-2"));
        Assert.Equal(HttpStatusCode.Created, owner.StatusCode);
    }
}
