using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Server.Governance;
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
        var json = await ReadJson(response);
        Assert.Equal("mission_terminated", (string?)json?["error"]);

        // Restore active state so test ordering does not affect other cases.
        await store.SetStateAsync(_missionS256, MissionState.Active);
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
