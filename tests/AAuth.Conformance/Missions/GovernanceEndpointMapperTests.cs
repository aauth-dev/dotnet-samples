using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AAuth;
using AAuth.Agent;
using AAuth.Server.Governance;
using AAuth.Server.Verification;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace AAuth.Conformance.Missions;

/// <summary>
/// Conformance for the PS governance endpoint mapper
/// (<c>MapAAuthGovernance</c>) over a real in-process host (AAuth protocol
/// §Permission Endpoint, §Audit Endpoint, §Interaction Endpoint, §Mission Status
/// Errors). The mapper drives the registered seams; <c>AddAAuthGovernance</c>
/// supplies conservative defaults.
/// </summary>
public class GovernanceEndpointMapperTests : IAsyncLifetime
{
    private const string Ps = "https://ps.example";
    private const string MissionPs = Ps;

    private IHost? _host;
    private string _missionS256 = string.Empty;

    public async Task InitializeAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddAAuthGovernance();
        builder.Services.AddRouting();

        var app = builder.Build();
        app.Use(async (context, next) =>
        {
            if (!context.Request.Headers.ContainsKey("Test-No-Identity"))
                context.Features.Set(new AAuthVerificationResult
                {
                    Level = AAuthLevel.Identified, Scheme = "jwt", IssuerVerified = true,
                    TokenType = AAuthTokenType.AgentToken,
                    Agent = context.Request.Headers["Test-Agent"].FirstOrDefault() ?? "aauth:assistant@agent.example",
                    AgentPersonServer = context.Request.Headers["Test-Agent-PS"].FirstOrDefault() is { } ps
                        ? (ps == "absent" ? null : ps) : Ps,
                    CoveredComponents = new HashSet<string> { "@method", "@authority", "@path", "signature-key", "content-type", "content-digest" },
                });
            await next();
        });
        app.MapAAuthGovernance(options => options.PersonServer = Ps);

        // Seed an active mission with one pre-approved tool ("WebSearch").
        var store = app.Services.GetRequiredService<IMissionStore>();
        var (blob, s256) = BuildMission("aauth:assistant@agent.example", "WebSearch");
        _missionS256 = s256;
        await store.SaveAsync(new StoredMission(s256, MissionPs, "aauth:assistant@agent.example", blob));

        await app.StartAsync();
        _host = app;
    }

    public async Task DisposeAsync()
    {
        if (_host is not null) { await _host.StopAsync(); _host.Dispose(); }
    }

    private HttpClient Client() => _host!.GetTestServer().CreateClient();

    [Fact(DisplayName = "§Permission Endpoint — a pre-approved tool is granted by the default decider")]
    public async Task Permission_ApprovedTool_Granted()
    {
        using var client = Client();
        var body = new JsonObject { ["action"] = "WebSearch", ["mission_s256"] = _missionS256 };

        var response = await client.PostAsync("https://localhost/permission", JsonContent(body));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        var json = await ReadJson(response);
        Assert.Equal("granted", (string?)json?["permission"]);
    }

    [Fact(DisplayName = "§Permission Endpoint — an out-of-scope action is denied (no user channel in the mapper)")]
    public async Task Permission_OutOfScope_Denied()
    {
        using var client = Client();
        var body = new JsonObject { ["action"] = "SendEmail", ["mission_s256"] = _missionS256 };

        var response = await client.PostAsync("https://localhost/permission", JsonContent(body));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJson(response);
        Assert.Equal("denied", (string?)json?["permission"]);
    }

    [Theory(DisplayName = "§Agent Governance — absent or foreign agent-token ps is rejected only on governance endpoints")]
    [InlineData("absent")]
    [InlineData("https://other-ps.example")]
    public async Task Permission_AgentTokenPsMustNameThisPersonServer(string agentPs)
    {
        using var client = Client();
        client.DefaultRequestHeaders.Add("Test-Agent-PS", agentPs);
        var body = new JsonObject { ["action"] = "WebSearch" };

        var response = await client.PostAsync("https://localhost/permission", JsonContent(body));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var json = await ReadJson(response);
        Assert.Equal("invalid_request", (string?)json?["error"]);
    }

    [Fact(DisplayName = "§Permission Endpoint — missing action is a 400")]
    public async Task Permission_MissingAction_BadRequest()
    {
        using var client = Client();
        var body = new JsonObject { ["mission_s256"] = _missionS256 };

        var response = await client.PostAsync("https://localhost/permission", JsonContent(body));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var json = await ReadJson(response);
        Assert.Equal("invalid_request", (string?)json!["error"]);
        Assert.False(json.ContainsKey("detail"));
        Assert.False(json.ContainsKey("error_description"));
    }

    [Fact(DisplayName = "§Audit Endpoint — a valid record is acknowledged with 201 Created")]
    public async Task Audit_Valid_Created()
    {
        using var client = Client();
        var body = new JsonObject { ["mission_s256"] = _missionS256, ["action"] = "WebSearch" };

        var response = await client.PostAsync("https://localhost/audit", JsonContent(body));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Fact(DisplayName = "§Interaction Endpoint — a question returns an answer field")]
    public async Task Interaction_Question_ReturnsAnswer()
    {
        using var client = Client();
        var body = new JsonObject
        {
            ["type"] = "question",
            ["question"] = "Refundable?",
            ["mission_s256"] = _missionS256,
        };

        var response = await client.PostAsync("https://localhost/mission-interaction", JsonContent(body));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJson(response);
        Assert.NotNull(json?["answer"]);
    }

    [Fact(DisplayName = "§Mission Status Errors — permission on a terminated mission is 403 mission_terminated")]
    public async Task Permission_TerminatedMission_Forbidden()
    {
        // Terminate the seeded mission, then request permission under it.
        var store = _host!.Services.GetRequiredService<IMissionStore>();
        var (blob, s256) = BuildMission("aauth:assistant@agent.example", "WebSearch");
        await store.SaveAsync(new StoredMission(s256, MissionPs, "aauth:assistant@agent.example", blob));
        await store.TerminateAsync(MissionPs, s256, AAuthConstants.MissionTerminationReasons.Revoked);

        using var client = Client();
        var body = new JsonObject { ["action"] = "WebSearch", ["mission_s256"] = s256 };

        var response = await client.PostAsync("https://localhost/permission", JsonContent(body));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var json = await ReadJson(response);
        Assert.Equal("mission_terminated", (string?)json?["error"]);
        Assert.Equal("terminated", (string?)json?["mission_status"]);
        Assert.Equal("revoked", (string?)json?["termination_reason"]);
        Assert.False(json!.ContainsKey("detail"));
        Assert.False(response.Headers.Contains("Signature-Error"));
    }

    [Theory]
    [InlineData("permission")]
    [InlineData("audit")]
    [InlineData("mission-interaction")]
    public async Task UnknownMission_IsRejectedBeforePolicy(string endpoint)
    {
        using var client = Client();
        var body = new JsonObject
        {
            ["mission_s256"] = Mission.ComputeS256(Encoding.UTF8.GetBytes("unknown mission")),
            ["action"] = "WebSearch",
            ["type"] = "question",
            ["question"] = "Refundable?",
        };

        using var response = await client.PostAsync("https://localhost/" + endpoint, JsonContent(body));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("mission_not_found", (string?)(await ReadJson(response))?["error"]);
        Assert.False(response.Headers.Contains("Signature-Error"));
    }

    [Theory]
    [InlineData("permission", "foreign")]
    [InlineData("audit", "foreign")]
    [InlineData("mission-interaction", "foreign")]
    [InlineData("permission", "anonymous")]
    [InlineData("audit", "anonymous")]
    [InlineData("mission-interaction", "anonymous")]
    [InlineData("permission", "terminated")]
    [InlineData("audit", "terminated")]
    [InlineData("mission-interaction", "terminated")]
    [InlineData("permission", "expired")]
    [InlineData("audit", "expired")]
    [InlineData("mission-interaction", "expired")]
    [InlineData("mission-action", "foreign")]
    [InlineData("mission-action", "terminated")]
    [InlineData("mission-action", "expired")]
    public async Task MissionAuthorization_RejectsInvalidContext(string endpoint, string scenario)
    {
        using var client = Client();
        if (scenario == "foreign") client.DefaultRequestHeaders.Add("Test-Agent", "aauth:foreign@agent.example");
        if (scenario == "anonymous") client.DefaultRequestHeaders.Add("Test-No-Identity", "true");
        var store = _host!.Services.GetRequiredService<IMissionStore>();
        if (scenario == "terminated")
            await store.TerminateAsync(MissionPs, _missionS256, AAuthConstants.MissionTerminationReasons.Revoked);
        if (scenario == "expired")
            await store.SaveAsync((await store.GetAsync(MissionPs, _missionS256))! with { ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1) });
        var body = new JsonObject
        {
            ["mission_s256"] = _missionS256, ["action"] = endpoint == "mission-action" ? "update" : "WebSearch",
            ["type"] = "question", ["question"] = "Refundable?", ["description"] = "Also a hotel",
        };
        var path = endpoint == "mission-action" ? "mission/" + _missionS256 : endpoint;
        using var response = await client.PostAsync("https://localhost/" + path, JsonContent(body));
        // A foreign mission is indistinguishable from a missing one (§Mission Endpoint Errors).
        Assert.Equal(scenario == "foreign" ? HttpStatusCode.NotFound : HttpStatusCode.Forbidden, response.StatusCode);
        var expected = scenario is "terminated" or "expired" ? "mission_terminated"
            : scenario == "anonymous" ? "invalid_request" : "mission_not_found";
        var rejected = await ReadJson(response);
        Assert.Equal(expected, (string?)rejected?["error"]);
        if (scenario is "terminated" or "expired")
        {
            Assert.Equal("terminated", (string?)rejected?["mission_status"]);
            Assert.Equal(scenario == "expired" ? "expired" : "revoked", (string?)rejected?["termination_reason"]);
        }
        Assert.False(response.Headers.Contains("Signature-Error"));
        Assert.Empty(await _host!.Services.GetRequiredService<IMissionLog>().ReadAsync(_missionS256));
    }

    [Fact(DisplayName = "§Mission Endpoint Errors — absent, foreign-agent and foreign-PS missions are indistinguishable")]
    public async Task MissionNotFound_ResponsesAreIdentical_AndNoS256Preload()
    {
        var spy = new SpyMissionStore();
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddAAuthGovernance();
        builder.Services.AddSingleton<IMissionStore>(spy);
        builder.Services.AddRouting();
        var app = builder.Build();
        app.Use(async (context, next) =>
        {
            context.Features.Set(new AAuthVerificationResult
            {
                Level = AAuthLevel.Identified, Scheme = "jwt", IssuerVerified = true,
                TokenType = AAuthTokenType.AgentToken,
                Agent = "aauth:assistant@agent.example",
                AgentPersonServer = Ps,
                CoveredComponents = new HashSet<string> { "@method", "@authority", "@path", "signature-key", "content-type", "content-digest" },
            });
            await next();
        });
        app.MapAAuthGovernance(options => options.PersonServer = Ps);
        await app.StartAsync();
        await using var _ = app;
        using var client = app.GetTestServer().CreateClient();
        var absentS256 = Mission.ComputeS256(Encoding.UTF8.GetBytes("absent"));
        var foreignAgentS256 = Mission.ComputeS256(Encoding.UTF8.GetBytes("foreign-agent"));
        var foreignPsS256 = Mission.ComputeS256(Encoding.UTF8.GetBytes("foreign-ps"));
        await spy.SaveAsync(new StoredMission(foreignAgentS256, Ps, "aauth:other@agent.example", ReadOnlyMemory<byte>.Empty));
        await spy.SaveAsync(new StoredMission(foreignPsS256, "https://other-ps.example", "aauth:assistant@agent.example", ReadOnlyMemory<byte>.Empty));

        var absent = await CaptureNotFoundAsync(client, absentS256);
        var foreignAgent = await CaptureNotFoundAsync(client, foreignAgentS256);
        var foreignPs = await CaptureNotFoundAsync(client, foreignPsS256);

        Assert.Equal(absent, foreignAgent);
        Assert.Equal(absent, foreignPs);
        Assert.Equal(0, spy.S256OnlyLookups);
    }

    private static async Task<(HttpStatusCode Status, string? ContentType, string Body, string Headers)> CaptureNotFoundAsync(
        HttpClient client, string s256)
    {
        using var response = await client.PostAsync("https://localhost/permission",
            JsonContent(new JsonObject { ["action"] = "WebSearch", ["mission_s256"] = s256 }));
        return (response.StatusCode, response.Content.Headers.ContentType?.MediaType,
            await response.Content.ReadAsStringAsync(),
            string.Join("\n", response.Headers.Select(h => h.Key + ":" + string.Join(",", h.Value)).Order(StringComparer.Ordinal)));
    }

    private static (byte[] Blob, string S256) BuildMission(string agent, params string[] approvedTools)
    {
        var tools = new JsonArray();
        foreach (var name in approvedTools)
        {
            tools.Add(new JsonObject { ["name"] = name });
        }
        var blob = new JsonObject
        {
            ["agent"] = agent,
            ["approved_at"] = "2026-04-07T14:30:00Z",
            ["description"] = "# Plan a trip",
            ["approved_tools"] = tools,
        };
        var bytes = Encoding.UTF8.GetBytes(blob.ToJsonString());
        return (bytes, Mission.ComputeS256(bytes));
    }

    private static StringContent JsonContent(JsonObject body)
        => new(body.ToJsonString(), Encoding.UTF8, "application/json");

    private static async Task<JsonObject?> ReadJson(HttpResponseMessage response)
        => JsonNode.Parse(await response.Content.ReadAsStringAsync()) as JsonObject;

    private sealed class SpyMissionStore : IMissionStore
    {
        private readonly InMemoryMissionStore _inner = new();
        public int S256OnlyLookups { get; private set; }

        public Task SaveAsync(StoredMission mission, CancellationToken ct = default)
            => _inner.SaveAsync(mission, ct);

        public Task<StoredMission?> GetAsync(string personServer, string s256, CancellationToken ct = default)
            => _inner.GetAsync(personServer, s256, ct);

        public Task TerminateAsync(string personServer, string s256, string terminationReason, CancellationToken ct = default)
            => _inner.TerminateAsync(personServer, s256, terminationReason, ct);

        public Task<StoredMission?> GetAsync(string s256, CancellationToken ct = default)
        {
            S256OnlyLookups++;
            return _inner.GetAsync(s256, ct);
        }

        public Task SetStateAsync(string s256, MissionState state, CancellationToken ct = default)
            => _inner.SetStateAsync(s256, state, ct);
    }
}
