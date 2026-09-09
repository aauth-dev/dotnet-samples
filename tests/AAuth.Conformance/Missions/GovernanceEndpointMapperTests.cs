using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
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
    private const string Approver = Ps;

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
                });
            await next();
        });
        app.MapAAuthGovernance();

        // Seed an active mission with one pre-approved tool ("WebSearch").
        var store = app.Services.GetRequiredService<IMissionStore>();
        var (blob, s256) = BuildMission("aauth:assistant@agent.example", "WebSearch");
        _missionS256 = s256;
        await store.SaveAsync(new StoredMission(s256, Approver, "aauth:assistant@agent.example", blob));

        await app.StartAsync();
        _host = app;
    }

    public async Task DisposeAsync()
    {
        if (_host is not null) { await _host.StopAsync(); _host.Dispose(); }
    }

    private HttpClient Client() => _host!.GetTestServer().CreateClient();

    private JsonObject MissionClaim() => new()
    {
        ["approver"] = Approver,
        ["s256"] = _missionS256,
    };

    [Fact(DisplayName = "§Permission Endpoint — a pre-approved tool is granted by the default decider")]
    public async Task Permission_ApprovedTool_Granted()
    {
        using var client = Client();
        var body = new JsonObject { ["action"] = "WebSearch", ["mission"] = MissionClaim() };

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
        var body = new JsonObject { ["action"] = "SendEmail", ["mission"] = MissionClaim() };

        var response = await client.PostAsync("https://localhost/permission", JsonContent(body));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJson(response);
        Assert.Equal("denied", (string?)json?["permission"]);
    }

    [Fact(DisplayName = "§Permission Endpoint — missing action is a 400")]
    public async Task Permission_MissingAction_BadRequest()
    {
        using var client = Client();
        var body = new JsonObject { ["mission"] = MissionClaim() };

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
        var body = new JsonObject { ["mission"] = MissionClaim(), ["action"] = "WebSearch" };

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
            ["mission"] = MissionClaim(),
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
        await store.SetStateAsync(_missionS256, MissionState.Terminated);

        using var client = Client();
        var body = new JsonObject { ["action"] = "WebSearch", ["mission"] = MissionClaim() };

        var response = await client.PostAsync("https://localhost/permission", JsonContent(body));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var json = await ReadJson(response);
        Assert.Equal("mission_terminated", (string?)json?["error"]);
        Assert.Equal("terminated", (string?)json?["mission_status"]);
        Assert.False(json!.ContainsKey("detail"));
        Assert.False(response.Headers.Contains("Signature-Error"));

        // Restore active state so test ordering does not affect other cases.
        await store.SetStateAsync(_missionS256, MissionState.Active);
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
            ["mission"] = new JsonObject
            {
                ["approver"] = Approver,
                ["s256"] = Mission.ComputeS256(Encoding.UTF8.GetBytes("unknown mission")),
            },
            ["action"] = "WebSearch",
            ["type"] = "question",
            ["question"] = "Refundable?",
        };

        using var response = await client.PostAsync("https://localhost/" + endpoint, JsonContent(body));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("invalid_mission", (string?)(await ReadJson(response))?["error"]);
        Assert.False(response.Headers.Contains("Signature-Error"));
    }

    [Theory]
    [InlineData("permission", "foreign")]
    [InlineData("audit", "foreign")]
    [InlineData("mission-interaction", "foreign")]
    [InlineData("permission", "approver")]
    [InlineData("audit", "approver")]
    [InlineData("mission-interaction", "approver")]
    [InlineData("permission", "anonymous")]
    [InlineData("audit", "anonymous")]
    [InlineData("mission-interaction", "anonymous")]
    [InlineData("permission", "terminated")]
    [InlineData("audit", "terminated")]
    [InlineData("mission-interaction", "terminated")]
    public async Task MissionAuthorization_RejectsInvalidContext(string endpoint, string scenario)
    {
        using var client = Client();
        if (scenario == "foreign") client.DefaultRequestHeaders.Add("Test-Agent", "aauth:foreign@agent.example");
        if (scenario == "anonymous") client.DefaultRequestHeaders.Add("Test-No-Identity", "true");
        if (scenario == "terminated")
            await _host!.Services.GetRequiredService<IMissionStore>().SetStateAsync(_missionS256, MissionState.Terminated);
        var reference = MissionClaim();
        if (scenario == "approver") reference["approver"] = "https://foreign.example";
        var body = new JsonObject
        {
            ["mission"] = reference, ["action"] = "WebSearch", ["type"] = "question", ["question"] = "Refundable?",
        };
        using var response = await client.PostAsync("https://localhost/" + endpoint, JsonContent(body));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var expected = scenario == "terminated" ? "mission_terminated"
            : scenario == "anonymous" ? "invalid_carrier_token" : "invalid_mission";
        Assert.Equal(expected, (string?)(await ReadJson(response))?["error"]);
        Assert.False(response.Headers.Contains("Signature-Error"));
        Assert.Empty(await _host!.Services.GetRequiredService<IMissionLog>().ReadAsync(_missionS256));
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
            ["approver"] = Approver,
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
}
