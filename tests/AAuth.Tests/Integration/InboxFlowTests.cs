using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AAuth;
using AAuth.Crypto;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace AAuth.Tests.Integration;

/// <summary>
/// End-to-end resource-managed (two-party) flow against the shipped
/// <c>samples/MockResourceServers/Inbox</c> server, hosted in-process via
/// <see cref="WebApplicationFactory{TEntryPoint}"/>. Exercises both spec entry
/// points (§AAuth-Access Response Header, §Resource-Managed Authorization,
/// §Authorization Endpoint Request): the reactive <c>GET /messages</c> consent
/// handshake and the proactive <c>POST /authorize</c> path, each ending with the
/// agent replaying the opaque token bound to its signature.
/// </summary>
public class InboxFlowTests : IAsyncLifetime
{
    private const string Base = "http://localhost";

    private readonly AAuthKey _agentKey = AAuthKey.Generate();
    private WebApplicationFactory<Inbox.Entry>? _inbox;

    public Task InitializeAsync()
    {
        _inbox = new WebApplicationFactory<Inbox.Entry>().WithWebHostBuilder(b =>
        {
            b.UseSetting("AAuth:Issuer", Base);
        });
        _inbox.CreateClient();
        return Task.CompletedTask;
    }

    public Task DisposeAsync()
    {
        _inbox?.Dispose();
        return Task.CompletedTask;
    }

    // Build an agent that drives the consent handshake, approving at the Inbox's
    // own consent page when interaction is required.
    private HttpClient BuildAgent()
    {
        var approver = _inbox!.CreateClient(); // plain browser-style client
        return new AAuthClientBuilder(_agentKey)
            .UseHwk()
            .WithResourceManagedAccess()
            .WithInteractionHandling(opts =>
            {
                opts.OnInteractionRequired = async (url, code, ct) =>
                {
                    // Simulate the user approving at the Inbox consent page.
                    var form = new FormUrlEncodedContent(
                        new[] { new KeyValuePair<string, string>("code", code) });
                    var resp = await approver.PostAsync("/consent/approve", form, ct);
                    resp.EnsureSuccessStatusCode();
                };
                opts.DefaultPollInterval = TimeSpan.FromMilliseconds(50);
                opts.MinPollInterval = TimeSpan.FromMilliseconds(10);
            })
            .WithInnerHandler(_inbox.Server.CreateHandler())
            .Build();
    }

    [Fact]
    public async Task Reactive_Messages_ConsentThenReplay()
    {
        using var agent = BuildAgent();

        // 1. GET /messages → 202 interaction → approve → poll → 200 (complete),
        //    the agent captures the issued AAuth-Access.
        var first = await agent.GetAsync($"{Base}/messages");
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        // 2. GET /messages → replays Authorization: AAuth (signed) → 200 + messages.
        var second = await agent.GetAsync($"{Base}/messages");
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        var body = await second.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("inbox.read", (string?)body!["scope"]);
        Assert.NotNull(body["messages"]);
    }

    [Fact]
    public async Task Proactive_Authorize_ConsentThenReplay()
    {
        using var agent = BuildAgent();

        // 1. POST /authorize { scope } → 202 interaction → approve → poll → 200.
        var auth = await agent.PostAsJsonAsync($"{Base}/authorize", new { scope = "inbox.read" });
        Assert.Equal(HttpStatusCode.OK, auth.StatusCode);

        // 2. GET /messages → replays the captured token → 200 + messages.
        var messages = await agent.GetAsync($"{Base}/messages");
        Assert.Equal(HttpStatusCode.OK, messages.StatusCode);
        var body = await messages.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("inbox.read", (string?)body!["scope"]);
    }

    [Fact]
    public async Task Authorize_NonJsonContentType_Returns415()
    {
        using var agent = BuildAgent();

        // A signed POST that passes verification but carries a non-JSON body must
        // fail cleanly (415), not surface ReadFromJsonAsync's InvalidOperationException
        // as a 500.
        using var content = new StringContent("scope=inbox.read", System.Text.Encoding.UTF8, "text/plain");
        var resp = await agent.PostAsync($"{Base}/authorize", content);

        Assert.Equal(HttpStatusCode.UnsupportedMediaType, resp.StatusCode);
    }

    [Fact]
    public async Task WellKnown_AdvertisesAccessModeAndAuthorizationEndpoint()
    {
        using var client = _inbox!.CreateClient();

        var doc = await client.GetFromJsonAsync<JsonObject>("/.well-known/aauth-resource.json");

        Assert.Equal("aauth-access-token", (string?)doc!["access_mode"]);
        Assert.Equal($"{Base}/authorize", (string?)doc["authorization_endpoint"]);
    }
}
