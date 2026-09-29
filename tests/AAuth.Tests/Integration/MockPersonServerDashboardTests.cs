using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.HttpSig;
using AAuth.Tokens;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using MockPersonServer;
using Xunit;

namespace AAuth.Tests.Integration;

/// <summary>The MockPersonServer consent dashboard (#user-interaction, #ps-approval-endpoint-auth).</summary>
public class MockPersonServerDashboardTests : IClassFixture<MockPersonServerConsentTests.ConsentFactory>
{
    private const string PsIssuer = "https://ps.test";
    private readonly MockPersonServerConsentTests.ConsentFactory _factory;

    public MockPersonServerDashboardTests(MockPersonServerConsentTests.ConsentFactory factory) => _factory = factory;

    [Fact]
    public async Task Requests_RequireSignIn()
    {
        using var browser = Browser();
        using var response = await browser.GetAsync("/dashboard/requests");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        using var page = await browser.GetAsync("/dashboard");
        Assert.Contains("class='primary demo-login'", await page.Content.ReadAsStringAsync());
        Assert.Contains("script-src 'nonce-", string.Join(";", page.Headers.GetValues("Content-Security-Policy")));
    }

    [Fact]
    public async Task Decisions_RequireTheCsrfToken()
    {
        var parked = await ParkAsync();
        var dashboard = await SignInAsync();

        using var missing = await dashboard.Client.PostAsync($"/dashboard/requests/{parked.Id}/approve", null);
        Assert.Equal(HttpStatusCode.Forbidden, missing.StatusCode);
        using var wrong = new HttpRequestMessage(HttpMethod.Post, $"/dashboard/requests/{parked.Id}/approve");
        wrong.Headers.Add(ConsentDashboardSessions.CsrfHeader, "not-the-token");
        using var rejected = await dashboard.Client.SendAsync(wrong);
        Assert.Equal(HttpStatusCode.Forbidden, rejected.StatusCode);
        Assert.Equal(ConsentStatus.Pending, _factory.Services.GetRequiredService<ConsentRegistry>().Find(parked.Id)!.Status);
    }

    [Fact]
    public async Task Approve_ResolvesPoll_AndTheOldLinkIsInvalid()
    {
        var parked = await ParkAsync();
        var dashboard = await SignInAsync();

        var listing = await dashboard.ListAsync("agent", parked.Code);
        Assert.Equal(parked.Id, (string?)listing["highlight"]);
        Assert.False((bool)listing["settled"]!);
        var group = listing["pending"]!.AsArray().Single(g => (string?)g!["key"] == parked.AgentId)!;
        var record = group["records"]!.AsArray().Single(r => (string?)r!["id"] == parked.Id)!;
        Assert.True((bool)record["decidable"]!);
        Assert.Equal(ResourceStub.Url, (string?)record["resource"]);
        Assert.Equal("calendar.read", (string?)record["scope"]);

        using var decided = await dashboard.DecideAsync(parked.Id, "approve");
        Assert.Equal(HttpStatusCode.OK, decided.StatusCode);
        await Assert.ThrowsAsync<HttpRequestException>(() => TestConsentBrowser.DecideAsync(parked.Browser,
            "/interaction?code=" + parked.Code, "/interaction/approve"));
        using var poll = await parked.Agent.GetAsync(parked.PendingPath);
        Assert.Equal(HttpStatusCode.OK, poll.StatusCode);
        using var again = await dashboard.DecideAsync(parked.Id, "deny");
        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);

        var history = (await dashboard.ListAsync("none"))["history"]!.AsArray()
            .SelectMany(g => g!["records"]!.AsArray()).Single(r => (string?)r!["id"] == parked.Id)!;
        Assert.Equal("Delivered", (string?)history["status"]);
        Assert.Equal("Dashboard", (string?)history["decided_by"]);

        // The old link still names the request, which has nothing left to decide.
        var linked = await dashboard.ListAsync("none", parked.Code);
        Assert.Equal(parked.Id, (string?)linked["highlight"]);
        Assert.True((bool)linked["settled"]!);
    }

    [Fact]
    public async Task Deny_MakesPollDenied()
    {
        var parked = await ParkAsync();
        var dashboard = await SignInAsync();

        using var decided = await dashboard.DecideAsync(parked.Id, "deny");
        Assert.Equal(HttpStatusCode.OK, decided.StatusCode);
        using var poll = await parked.Agent.GetAsync(parked.PendingPath);
        Assert.Equal(HttpStatusCode.Forbidden, poll.StatusCode);
        Assert.Equal("denied", (string?)(await poll.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
    }

    [Fact]
    public async Task UnknownCodeHighlight_IsSettled()
    {
        var dashboard = await SignInAsync();
        var listing = await dashboard.ListAsync("none", "ABCDEFGHJKMNPQRSTVWXYZ0123");
        Assert.Null(listing["highlight"]);
        Assert.True((bool)listing["settled"]!);
    }

    [Fact]
    public async Task MissionCreationAndPermission_AreDecidedOnTheDashboard()
    {
        var agent = await AgentAsync();
        var dashboard = await SignInAsync();
        await ScriptAsync(dashboard.Client, new JsonObject { ["reset"] = true, ["interactive"] = true });

        using var proposed = await agent.PostAsJsonAsync("/mission", new JsonObject { ["description"] = "Plan the team offsite" });
        Assert.Equal(HttpStatusCode.Accepted, proposed.StatusCode);
        var missionId = proposed.Headers.Location!.OriginalString.Split('/').Last();
        var creation = (await dashboard.ListAsync("mission"))["pending"]!.AsArray()
            .SelectMany(g => g!["records"]!.AsArray()).Single(r => (string?)r!["id"] == missionId)!;
        Assert.Equal("MissionCreation", (string?)creation["kind"]);
        Assert.Equal("Plan the team offsite", (string?)creation["mission"]);
        using var approveMission = await dashboard.DecideAsync(missionId, "approve");
        Assert.Equal(HttpStatusCode.OK, approveMission.StatusCode);
        using var approval = await agent.GetAsync(proposed.Headers.Location);
        Assert.Equal(HttpStatusCode.OK, approval.StatusCode);
        var s256 = (string)(await approval.Content.ReadFromJsonAsync<JsonObject>())!["s256"]!;

        using var asked = await agent.PostAsJsonAsync("/permission", new JsonObject
        {
            ["action"] = "SendEmail", ["mission_s256"] = s256,
        });
        Assert.Equal(HttpStatusCode.Accepted, asked.StatusCode);
        var permissionId = asked.Headers.Location!.OriginalString.Split('/').Last();
        var byMission = (await dashboard.ListAsync("mission"))["pending"]!.AsArray()
            .Single(g => (string?)g!["mission_s256"] == s256)!;
        Assert.Equal("Plan the team offsite", (string?)byMission["label"]);
        using var approvePermission = await dashboard.DecideAsync(permissionId, "approve");
        Assert.Equal(HttpStatusCode.OK, approvePermission.StatusCode);
        using var granted = await agent.GetAsync(asked.Headers.Location);
        Assert.Equal(HttpStatusCode.OK, granted.StatusCode);
        Assert.Equal("granted", (string?)(await granted.Content.ReadFromJsonAsync<JsonObject>())!["permission"]);

        await ScriptAsync(dashboard.Client, new JsonObject { ["reset"] = true });
    }

    private sealed record Dashboard(HttpClient Client, string Csrf)
    {
        public async Task<JsonObject> ListAsync(string group, string? code = null)
        {
            var query = "/dashboard/requests?group=" + group + (code is null ? "" : "&code=" + code);
            using var response = await Client.GetAsync(query);
            var body = await response.Content.ReadAsStringAsync();
            Assert.True(response.IsSuccessStatusCode, body);
            return JsonNode.Parse(body)!.AsObject();
        }

        public Task<HttpResponseMessage> DecideAsync(string id, string action)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, $"/dashboard/requests/{id}/{action}");
            request.Headers.Add(ConsentDashboardSessions.CsrfHeader, Csrf);
            return Client.SendAsync(request);
        }
    }

    private HttpClient Browser() =>
        _factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new System.Uri(PsIssuer) });

    private async Task<Dashboard> SignInAsync()
    {
        var browser = Browser();
        var signIn = await browser.GetStringAsync("/dashboard");
        using var signedIn = await browser.PostAsync("/dashboard/sign-in", new FormUrlEncodedContent(new System.Collections.Generic.Dictionary<string, string>
        {
            ["sign_in"] = "demo", ["csrf"] = TestConsentBrowser.Field(signIn, "csrf"),
        }));
        var page = await signedIn.Content.ReadAsStringAsync();
        Assert.True(signedIn.IsSuccessStatusCode, page);
        var csrf = Regex.Match(page, "name=csrf content='([^']+)'");
        Assert.True(csrf.Success, page);
        return new Dashboard(browser, csrf.Groups[1].Value);
    }

    private static async Task ScriptAsync(HttpClient client, JsonObject body)
    {
        using var response = await client.PostAsJsonAsync("/admin/mission-script", body);
        Assert.True(response.IsSuccessStatusCode);
    }

    private Task<HttpClient> AgentAsync() => Task.FromResult(Agent(AAuthKey.Generate(), out _).Client);

    private (HttpClient Client, string AgentId) Agent(AAuthKey agentKey, out string agentId)
    {
        agentId = "aauth:dashboard-" + System.Guid.NewGuid().ToString("N") + "@ap.example";
        var agentToken = new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://ap.example",
            Subject = agentId,
            KeyId = "demo",
            Key = ResourceStub.ApKey,
            ConfirmationKey = agentKey,
            PersonServer = PsIssuer,
        }.Build();
        return (new InProcessHttpClient(new AAuthSigningHandler(agentKey, () => agentToken)
        {
            InnerHandler = _factory.Server.CreateHandler(),
        })
        { BaseAddress = new System.Uri(PsIssuer) }, agentId);
    }

    private async Task<Parked> ParkAsync()
    {
        var agentKey = AAuthKey.Generate();
        var (agent, agentId) = Agent(agentKey, out _);
        using var initial = await agent.PostAsJsonAsync("/token", await PersonTokenFlow.TokenRequestAsync(agent, agentKey));
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
        var interaction = AAuth.Headers.Interaction.FromRequirement(
            AAuth.Headers.AAuthRequirementHeader.Parse(string.Join(", ", initial.Headers.GetValues("AAuth-Requirement"))))!;
        var pendingPath = initial.Headers.Location!.OriginalString;
        return new Parked(pendingPath.Split('/').Last(), agentId, interaction.Code, pendingPath, agent, Browser());
    }

    private sealed record Parked(string Id, string AgentId, string Code, string PendingPath, HttpClient Agent, HttpClient Browser);
}
