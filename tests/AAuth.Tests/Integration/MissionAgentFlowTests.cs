using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Agent.Governance;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Errors;
using AAuth.HttpSig;
using AAuth.Server.Governance;
using AAuth.Tokens;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AAuth.Tests.Integration;

/// <summary>
/// End-to-end Consent-Matrix coverage for the mission-governance MockPersonServer
/// (Phase 6a). Each test drives the shipped SDK governance clients
/// (<see cref="MissionClient"/>, <see cref="TokenExchangeClient"/>,
/// <see cref="PermissionClient"/>, <see cref="AuditClient"/>,
/// <see cref="InteractionClient"/>) against the in-process PS and asserts both the
/// agent-observable outcome and the recorded mission-log decision reason.
///
/// The three-gate model (§Agent Token Request): a mission token request is silent
/// when the (resource, scope) is within the approved intent (gate 2a) or already
/// consented earlier in the mission (gate 2b), otherwise the user is prompted
/// (gate 2c). A permission request is silent for a pre-approved tool, else prompts
/// (§Permission Endpoint). User decisions are scripted via <c>/admin/mission-script</c>.
/// </summary>
public class MissionAgentFlowTests : IClassFixture<WebApplicationFactory<MockPersonServer.Entry>>, IDisposable
{
    private const string PsIssuer = "https://ps.test";
    private const string ResourceUrl = "https://trips.test";
    private const string ApIssuer = "https://ap.example";

    private readonly WebApplicationFactory<MockPersonServer.Entry> _factory;

    public MissionAgentFlowTests(WebApplicationFactory<MockPersonServer.Entry> factory)
    {
        _factory = factory.WithWebHostBuilder(b =>
        {
            b.UseSetting("AAuth:Issuer", PsIssuer);
            b.ConfigureServices(ResourceStub.WireDiscovery);
        });
    }

    public void Dispose() => _factory.Dispose();

    // ---- Mission creation (rows 1-2) -----------------------------------

    [Fact]
    public async Task Row01_MissionApproved_ReturnsActiveMission()
    {
        var agent = NewAgent();
        await ScriptAsync(agent, new JsonObject { ["reset"] = true });

        var mission = await ProposeMissionAsync(agent, "row01 research mission");

        Assert.Equal(PsIssuer, mission.Approver);
        Assert.Equal(agent.AgentId, mission.Agent);
        Assert.False(string.IsNullOrEmpty(mission.S256));
    }

    [Fact]
    public async Task Row02_MissionDenied_Aborts()
    {
        var agent = NewAgent();
        await ScriptAsync(agent, new JsonObject { ["reset"] = true, ["approveMission"] = false });

        var proposal = new MissionProposal("row02 rejected mission");
        await Assert.ThrowsAsync<HttpRequestException>(
            () => MissionClientFor(agent).ProposeAsync(proposal));
    }

    // ---- Token gate (rows 3-8) -----------------------------------------

    [Fact]
    public async Task Row03_TokenInScope_SilentGrant()
    {
        var agent = NewAgent();
        await ScriptAsync(agent, new JsonObject
        {
            ["reset"] = true,
            ["inScope"] = new JsonArray(InScope(ResourceUrl, "trips.read")),
        });
        var mission = await ProposeMissionAsync(agent, "row03 in-scope mission");

        var token = await ExchangeAsync(agent, mission, "trips.read", new TokenExchangeRequest());

        Assert.False(string.IsNullOrEmpty(token));
        await AssertTokenReasonAsync(mission, "trips.read", granted: true, reason: "InScope");
    }

    [Fact]
    public async Task Row04_TokenRepeat_PriorConsentSilentGrant()
    {
        var agent = NewAgent();
        await ScriptAsync(agent, new JsonObject { ["reset"] = true, ["approveToken"] = true });
        var mission = await ProposeMissionAsync(agent, "row04 prior-consent mission");

        // First out-of-scope request: prompted then approved -> recorded as prior consent.
        _ = await ExchangeAsync(agent, mission, "trips.book", Promptable());
        // Second request for the same (resource, scope): now silent via prior consent.
        var token = await ExchangeAsync(agent, mission, "trips.book", new TokenExchangeRequest());

        Assert.False(string.IsNullOrEmpty(token));
        await AssertTokenReasonAsync(mission, "trips.book", granted: true, reason: "PriorConsent");
    }

    [Fact]
    public async Task Row05_TokenOutOfScope_PromptThenIssue()
    {
        var agent = NewAgent();
        await ScriptAsync(agent, new JsonObject { ["reset"] = true, ["approveToken"] = true });
        var mission = await ProposeMissionAsync(agent, "row05 out-of-scope approve mission");

        var prompted = false;
        var options = new TokenExchangeRequest
        {
            OnInteractionRequired = (_, _) => { prompted = true; return Task.CompletedTask; },
        };
        var token = await ExchangeAsync(agent, mission, "trips.book", options);

        Assert.True(prompted);
        Assert.False(string.IsNullOrEmpty(token));
        await AssertTokenReasonAsync(mission, "trips.book", granted: true, reason: "OutOfScope");
    }

    [Fact]
    public async Task Row06_TokenOutOfScope_PromptThenDeny()
    {
        var agent = NewAgent();
        await ScriptAsync(agent, new JsonObject { ["reset"] = true, ["approveToken"] = false });
        var mission = await ProposeMissionAsync(agent, "row06 out-of-scope deny mission");

        await Assert.ThrowsAsync<AAuthInteractionDeniedException>(
            () => ExchangeAsync(agent, mission, "trips.book", Promptable()));
        await AssertTokenReasonAsync(mission, "trips.book", granted: false, reason: "OutOfScope");
    }

    [Fact]
    public async Task Row07_TokenClarification_RoundThenIssue()
    {
        var agent = NewAgent();
        await ScriptAsync(agent, new JsonObject
        {
            ["reset"] = true,
            ["approveToken"] = true,
            ["requireClarification"] = true,
        });
        var mission = await ProposeMissionAsync(agent, "row07 clarification mission");

        var asked = false;
        var options = new TokenExchangeRequest
        {
            OnInteractionRequired = (_, _) => Task.CompletedTask,
            OnClarificationRequired = (_, _) =>
            {
                asked = true;
                return Task.FromResult(ClarificationResponse.Respond("The mission needs admin scope to read roles."));
            },
        };
        var token = await ExchangeAsync(agent, mission, "trips.book", options);

        Assert.True(asked);
        Assert.False(string.IsNullOrEmpty(token));
        await AssertTokenReasonAsync(mission, "trips.book", granted: true, reason: "OutOfScope");
        var entries = await ReadLogAsync(mission);
        Assert.Contains(entries, e => e.Kind == MissionLogEntryKind.Clarification);
    }

    [Fact]
    public async Task Row08_TokenClarification_CancelViaDelete()
    {
        var agent = NewAgent();
        await ScriptAsync(agent, new JsonObject
        {
            ["reset"] = true,
            ["approveToken"] = true,
            ["requireClarification"] = true,
        });
        var mission = await ProposeMissionAsync(agent, "row08 clarification cancel mission");

        var options = new TokenExchangeRequest
        {
            OnInteractionRequired = (_, _) => Task.CompletedTask,
            OnClarificationRequired = (_, _) => Task.FromResult(ClarificationResponse.Cancel()),
        };

        await Assert.ThrowsAsync<AAuthClarificationCancelledException>(
            () => ExchangeAsync(agent, mission, "trips.book", options));

        var entries = await ReadLogAsync(mission);
        Assert.Contains(entries, e => e.Kind == MissionLogEntryKind.Clarification && e.Detail == "cancelled");
        // No token was issued for this (resource, scope).
        Assert.DoesNotContain(entries, e => e.Kind == MissionLogEntryKind.Token && e.Granted == true);
    }

    // ---- Permission gate (rows 9-11) -----------------------------------

    [Fact]
    public async Task Row09_PermissionApprovedTool_SilentGrant()
    {
        var agent = NewAgent();
        await ScriptAsync(agent, new JsonObject { ["reset"] = true });
        var mission = await ProposeMissionAsync(agent, "row09 approved-tool mission", "send_email");

        var result = await PermissionClientFor(agent)
            .RequestAsync(new MissionAction("send_email"), mission);

        Assert.True(result.IsGranted);
        Assert.Equal(PermissionGrant.Granted, result.Grant);
    }

    [Fact]
    public async Task Row10_PermissionNonPreApproved_PromptThenGrant()
    {
        var agent = NewAgent();
        await ScriptAsync(agent, new JsonObject { ["reset"] = true, ["approvePermission"] = true });
        var mission = await ProposeMissionAsync(agent, "row10 prompt-grant mission", "send_email");

        var request = new PermissionRequest(new MissionAction("delete_file"))
        {
            Mission = new MissionClaim(mission.Approver, mission.S256),
        };
        var result = await PermissionClientFor(agent).RequestAsync(request);

        Assert.True(result.IsGranted);
        await AssertPermissionReasonAsync(mission, "delete_file", granted: true);
    }

    [Fact]
    public async Task Row11_PermissionNonPreApproved_PromptThenDeny()
    {
        var agent = NewAgent();
        await ScriptAsync(agent, new JsonObject { ["reset"] = true, ["approvePermission"] = false });
        var mission = await ProposeMissionAsync(agent, "row11 prompt-deny mission", "send_email");

        var request = new PermissionRequest(new MissionAction("delete_file"))
        {
            Mission = new MissionClaim(mission.Approver, mission.S256),
        };
        var result = await PermissionClientFor(agent).RequestAsync(request);

        Assert.False(result.IsGranted);
        Assert.Equal(PermissionGrant.Denied, result.Grant);
        await AssertPermissionReasonAsync(mission, "delete_file", granted: false);
    }

    // ---- Termination (row 12) ------------------------------------------

    [Fact]
    public async Task Row12_TerminationMidFlow_RejectsWithMissionTerminated()
    {
        var agent = NewAgent();
        await ScriptAsync(agent, new JsonObject
        {
            ["reset"] = true,
            ["inScope"] = new JsonArray(InScope(ResourceUrl, "trips.read")),
        });
        var mission = await ProposeMissionAsync(agent, "row12 terminated mission");

        // Terminate the mission, then attempt a token request.
        using var terminate = await agent.Plain.PostAsJsonAsync("/admin/mission-terminate",
            new JsonObject { ["s256"] = mission.S256 });
        Assert.True(terminate.IsSuccessStatusCode);

        await Assert.ThrowsAsync<AAuthMissionTerminatedException>(
            () => ExchangeAsync(agent, mission, "trips.read", new TokenExchangeRequest()));
    }

    // ---- Helpers -------------------------------------------------------

    private sealed record Agent(string AgentId, AAuthKey AgentKey, HttpClient Signed, HttpClient Plain, MetadataClient Metadata);

    private Agent NewAgent(string? agentId = null)
    {
        agentId ??= $"aauth:demo@ap.example";
        var agentKey = AAuthKey.Generate();
        var agentToken = new AgentTokenBuilder
        {
            Issuer = ApIssuer,
            Subject = agentId,
            KeyId = "demo",
            Key = agentKey,
            PersonServer = PsIssuer,
        }.Build();
        var signing = new AAuthSigningHandler(agentKey, () => agentToken)
        {
            InnerHandler = _factory.Server.CreateHandler(),
        };
        var signed = new HttpClient(signing) { BaseAddress = new Uri(PsIssuer) };
        var plain = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(PsIssuer),
        });
        var metadata = new MetadataClient(new HttpClient(_factory.Server.CreateHandler()));
        return new Agent(agentId, agentKey, signed, plain, metadata);
    }

    private MissionClient MissionClientFor(Agent agent) => new(agent.Signed, agent.Metadata, PsIssuer);

    private PermissionClient PermissionClientFor(Agent agent) => new(agent.Signed, agent.Metadata, PsIssuer);

    private async Task ScriptAsync(Agent agent, JsonObject body)
    {
        using var response = await agent.Plain.PostAsJsonAsync("/admin/mission-script", body);
        Assert.True(response.IsSuccessStatusCode,
            $"Status={(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
    }

    private async Task<Mission> ProposeMissionAsync(Agent agent, string description, params string[] tools)
    {
        var proposal = new MissionProposal(description)
        {
            Tools = tools.Select(t => new MissionTool(t)).ToArray(),
        };
        return await MissionClientFor(agent).ProposeAsync(proposal);
    }

    private async Task<string> ExchangeAsync(Agent agent, Mission mission, string scope, TokenExchangeRequest options)
    {
        var resourceToken = new ResourceTokenBuilder
        {
            Issuer = ResourceUrl,
            Audience = PsIssuer,
            Agent = agent.AgentId,
            AgentJkt = agent.AgentKey.ComputeJwkThumbprint(),
            Key = ResourceStub.Key,
            KeyId = ResourceStub.Kid,
            Scope = scope,
            Mission = new MissionClaim(mission.Approver, mission.S256),
        }.Build();

        var exchange = new TokenExchangeClient(agent.Signed, agent.Metadata);
        return await exchange.ExchangeAsync(PsIssuer, resourceToken, options);
    }

    private static TokenExchangeRequest Promptable() => new()
    {
        OnInteractionRequired = (_, _) => Task.CompletedTask,
    };

    private static JsonObject InScope(string resource, string scope)
        => new() { ["resource"] = resource, ["scope"] = scope };

    private async Task<IReadOnlyList<MissionLogEntry>> ReadLogAsync(Mission mission)
    {
        var log = _factory.Services.GetRequiredService<IMissionLog>();
        return await log.ReadAsync(mission.S256);
    }

    private async Task AssertTokenReasonAsync(Mission mission, string scope, bool granted, string reason)
    {
        var entries = await ReadLogAsync(mission);
        var entry = entries.LastOrDefault(e =>
            e.Kind == MissionLogEntryKind.Token && e.Scope == scope);
        Assert.NotNull(entry);
        Assert.Equal(granted, entry!.Granted);
        Assert.Equal(reason, entry.Detail);
    }

    private async Task AssertPermissionReasonAsync(Mission mission, string action, bool granted)
    {
        var entries = await ReadLogAsync(mission);
        var entry = entries.LastOrDefault(e =>
            e.Kind == MissionLogEntryKind.Permission && e.Action == action);
        Assert.NotNull(entry);
        Assert.Equal(granted, entry!.Granted);
    }
}
