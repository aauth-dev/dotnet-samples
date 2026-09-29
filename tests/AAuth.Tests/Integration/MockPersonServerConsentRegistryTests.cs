using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.HttpSig;
using AAuth.Tokens;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using MockPersonServer;
using Xunit;

namespace AAuth.Tests.Integration;

/// <summary>
/// The MockPersonServer consent registry and the shared decision service behind
/// the per-request link and the dashboard.
/// </summary>
public class MockPersonServerConsentRegistryTests : IClassFixture<MockPersonServerConsentTests.ConsentFactory>
{
    private const string PsIssuer = "https://ps.test";
    private readonly MockPersonServerConsentTests.ConsentFactory _factory;

    public MockPersonServerConsentRegistryTests(MockPersonServerConsentTests.ConsentFactory factory) => _factory = factory;

    private ConsentRegistry Registry => _factory.Services.GetRequiredService<ConsentRegistry>();
    private PersonConsentDecisions Decisions => _factory.Services.GetRequiredService<PersonConsentDecisions>();

    [Fact]
    public async Task ParkedRequest_IsPending_ThenApprovedByLink_ThenDelivered()
    {
        var parked = await ParkAsync();
        var record = Registry.Find(parked.Id)!;
        Assert.Equal(ConsentKind.Token, record.Kind);
        Assert.Equal(ConsentStatus.Pending, record.Status);
        Assert.True(record.IsDecidable);
        Assert.Equal(ResourceStub.Url, record.Resource);
        Assert.Equal(parked.AgentId, record.AgentId);
        Assert.Same(record, Registry.FindPendingByCode(parked.Code));

        using var approve = await TestConsentBrowser.DecideAsync(parked.Browser,
            "/interaction?code=" + parked.Code, "/interaction/approve");
        Assert.Equal(HttpStatusCode.OK, approve.StatusCode);
        Assert.Equal(ConsentStatus.Approved, record.Status);
        Assert.Equal(ConsentDecider.Link, record.DecidedBy);
        Assert.Null(Registry.FindPendingByCode(parked.Code));

        using var poll = await parked.Agent.GetAsync(parked.PendingPath);
        Assert.Equal(HttpStatusCode.OK, poll.StatusCode);
        Assert.Equal(ConsentStatus.Delivered, record.Status);
    }

    [Fact]
    public async Task DashboardApprove_ResolvesPoll_AndConsumesTheCode()
    {
        var parked = await ParkAsync();

        Assert.Equal(ConsentOutcome.Applied, await Decisions.DecideAsync(parked.Id, approve: true, ConsentDecider.Dashboard, CancellationToken.None));

        var record = Registry.Find(parked.Id)!;
        Assert.Equal(ConsentDecider.Dashboard, record.DecidedBy);
        // Before the agent polls, the old code no longer opens the consent page.
        await Assert.ThrowsAsync<HttpRequestException>(() => TestConsentBrowser.DecideAsync(parked.Browser,
            "/interaction?code=" + parked.Code, "/interaction/deny"));
        using var poll = await parked.Agent.GetAsync(parked.PendingPath);
        Assert.Equal(HttpStatusCode.OK, poll.StatusCode);
        Assert.False(string.IsNullOrEmpty((string?)(await poll.Content.ReadFromJsonAsync<JsonObject>())!["auth_token"]));
        Assert.Equal(ConsentOutcome.AlreadyDecided,
            await Decisions.DecideAsync(parked.Id, approve: false, ConsentDecider.Dashboard, CancellationToken.None));
    }

    [Fact]
    public async Task DashboardDeny_MakesPollDenied()
    {
        var parked = await ParkAsync();

        Assert.Equal(ConsentOutcome.Applied, await Decisions.DecideAsync(parked.Id, approve: false, ConsentDecider.Dashboard, CancellationToken.None));

        using var poll = await parked.Agent.GetAsync(parked.PendingPath);
        Assert.Equal(HttpStatusCode.Forbidden, poll.StatusCode);
        Assert.Equal(ConsentStatus.Denied, Registry.Find(parked.Id)!.Status);
    }

    [Fact]
    public async Task LinkAndDashboardDecisions_ApplyOnce()
    {
        var parked = await ParkAsync();
        var dashboard = ConsentOutcome.Unknown;

        // The page is open (decision session created) when the dashboard decides.
        using var link = await TestConsentBrowser.DecideAsync(parked.Browser,
            "/interaction?code=" + parked.Code, "/interaction/deny",
            _ => dashboard = Decisions.DecideAsync(parked.Id, approve: true, ConsentDecider.Dashboard, CancellationToken.None)
                .GetAwaiter().GetResult());

        Assert.Equal(ConsentOutcome.Applied, dashboard);
        Assert.Equal(HttpStatusCode.BadRequest, link.StatusCode);
        Assert.Equal(ConsentStatus.Approved, Registry.Find(parked.Id)!.Status);
    }

    [Fact]
    public void MissionPermissionPark_IsListedWithItsMission()
    {
        var entry = _factory.Services.GetRequiredService<MissionPendingStore>().Add(new MissionPendingEntry
        {
            Kind = MissionPendingKind.Permission,
            AgentId = "aauth:tool@ap.example",
            S256 = "mission-s256",
            PersonServer = PsIssuer,
            Action = "send_email",
        });

        var record = Registry.Find(entry.Id)!;
        Assert.Equal(ConsentKind.Permission, record.Kind);
        Assert.Equal("mission-s256", record.MissionS256);
        Assert.Equal("send_email", record.Action);
        Assert.Equal(ConsentStatus.Pending, record.Status);
        Assert.Contains(record, Registry.Snapshot());
    }

    [Fact]
    public async Task AdminReset_ClearsTheRegistry()
    {
        var parked = await ParkAsync();
        Assert.NotNull(Registry.Find(parked.Id));

        using var reset = await parked.Browser.PostAsync("/admin/reset", null);
        Assert.True(reset.IsSuccessStatusCode);
        Assert.Null(Registry.Find(parked.Id));
    }

    private async Task<Parked> ParkAsync()
    {
        var agentKey = AAuthKey.Generate();
        var agentId = "aauth:registry-" + System.Guid.NewGuid().ToString("N") + "@ap.example";
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
        var agent = new InProcessHttpClient(new AAuthSigningHandler(agentKey, () => agentToken)
        {
            InnerHandler = _factory.Server.CreateHandler(),
        })
        { BaseAddress = new System.Uri(PsIssuer) };
        var browser = _factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new System.Uri(PsIssuer) });

        using var initial = await agent.PostAsJsonAsync("/token", await PersonTokenFlow.TokenRequestAsync(agent, agentKey));
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
        var interaction = AAuth.Headers.Interaction.FromRequirement(
            AAuth.Headers.AAuthRequirementHeader.Parse(string.Join(", ", initial.Headers.GetValues("AAuth-Requirement"))))!;
        var pendingPath = initial.Headers.Location!.OriginalString;
        return new Parked(pendingPath.Split('/').Last(), agentId, interaction.Code, pendingPath, agent, browser);
    }

    private sealed record Parked(string Id, string AgentId, string Code, string PendingPath, HttpClient Agent, HttpClient Browser);
}
