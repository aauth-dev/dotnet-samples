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
    // Must match the identity ResourceStub serves metadata/JWKS for: the PS now
    // verifies a fetched metadata document's `issuer` against its origin
    // (§Metadata Documents), so the resource token's `iss` and the stub's
    // served `issuer` must agree.
    private const string ResourceUrl = ResourceStub.Url;
    private const string ApIssuer = "https://ap.example";

    private readonly WebApplicationFactory<MockPersonServer.Entry> _factory;

    public MissionAgentFlowTests(WebApplicationFactory<MockPersonServer.Entry> factory)
    {
        _factory = factory.WithWebHostBuilder(b =>
        {
            b.UseSetting("AAuth:Issuer", PsIssuer);
            b.UseIsolatedDemoConsent();
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
        var mission = await ProposeMissionAsync(agent, "row09 approved-tool mission", "add_to_calendar");

        var result = await PermissionClientFor(agent)
            .RequestAsync(new MissionAction("add_to_calendar"), mission);

        Assert.True(result.IsGranted);
        Assert.Equal(PermissionGrant.Granted, result.Grant);
    }

    [Fact]
    public async Task Row10_PermissionNonPreApproved_PromptThenGrant()
    {
        var agent = NewAgent();
        await ScriptAsync(agent, new JsonObject { ["reset"] = true, ["approvePermission"] = true });
        var mission = await ProposeMissionAsync(agent, "row10 prompt-grant mission", "add_to_calendar");

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
        var mission = await ProposeMissionAsync(agent, "row11 prompt-deny mission", "add_to_calendar");

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

    [Theory]
    [InlineData("permission", "foreign")]
    [InlineData("audit", "foreign")]
    [InlineData("mission-interaction", "foreign")]
    [InlineData("permission", "unknown")]
    [InlineData("audit", "unknown")]
    [InlineData("mission-interaction", "unknown")]
    [InlineData("permission", "approver")]
    [InlineData("audit", "approver")]
    [InlineData("mission-interaction", "approver")]
    [InlineData("permission", "terminated")]
    [InlineData("audit", "terminated")]
    [InlineData("mission-interaction", "terminated")]
    public async Task Governance_SignedInvalidMissionCannotAct(string endpoint, string scenario)
    {
        var owner = NewAgent();
        await ScriptAsync(owner, new JsonObject { ["reset"] = true });
        var mission = await ProposeMissionAsync(owner, "ownership regression", "WebSearch");
        var before = (await ReadLogAsync(mission)).Count;
        var caller = scenario == "foreign" ? NewAgent("aauth:foreign@ap.example") : owner;
        if (scenario == "terminated")
            await _factory.Services.GetRequiredService<IMissionStore>().SetStateAsync(mission.S256, MissionState.Terminated);
        var body = new JsonObject
        {
            ["mission"] = new JsonObject
            {
                ["approver"] = scenario == "approver" ? "https://foreign.example" : mission.Approver,
                ["s256"] = scenario == "unknown" ? Mission.ComputeS256("unknown"u8.ToArray()) : mission.S256,
            },
            ["action"] = "WebSearch", ["type"] = "completion", ["summary"] = "Complete",
        };
        using var response = await caller.Signed.PostAsJsonAsync("/" + endpoint, body);
        Assert.Equal(System.Net.HttpStatusCode.Forbidden, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal(scenario == "terminated" ? "mission_terminated" : "invalid_mission", (string?)result?["error"]);
        Assert.False(response.Headers.Contains("Signature-Error"));
        Assert.Equal(before, (await ReadLogAsync(mission)).Count);
        Assert.Equal(scenario == "terminated" ? MissionState.Terminated : MissionState.Active,
            (await _factory.Services.GetRequiredService<IMissionStore>().GetAsync(mission.S256))!.State);
    }

    [Fact]
    public async Task PermissionPending_TerminatedMissionCannotReleaseLateApproval()
    {
        var owner = NewAgent();
        await ScriptAsync(owner, new JsonObject { ["reset"] = true });
        var mission = await ProposeMissionAsync(owner, "Late permission approval");
        await ScriptAsync(owner, new JsonObject { ["interactive"] = true });
        using var initial = await owner.Signed.PostAsJsonAsync("/permission", new JsonObject
        {
            ["action"] = "SendEmail", ["mission"] = new JsonObject { ["approver"] = mission.Approver, ["s256"] = mission.S256 },
        });
        Assert.Equal(System.Net.HttpStatusCode.Accepted, initial.StatusCode);
        await _factory.Services.GetRequiredService<IMissionStore>().SetStateAsync(mission.S256, MissionState.Terminated);
        var id = initial.Headers.Location!.ToString().Split('/').Last();
        Assert.True(_factory.Services.GetRequiredService<MockPersonServer.MissionPendingStore>().Get(id)!.Decide(true));
        using var response = await owner.Signed.GetAsync(initial.Headers.Location);
        Assert.Equal(System.Net.HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("mission_terminated", (string?)(await response.Content.ReadFromJsonAsync<JsonObject>())?["error"]);
        Assert.DoesNotContain(await ReadLogAsync(mission), entry => entry.Kind == MissionLogEntryKind.Permission && entry.Granted == true);
    }

    [Fact]
    public async Task MissionConsent_RendersUntrustedMarkdownAsEncodedText()
    {
        const string untrusted = "<img src=x onerror=alert(1)><script>private()</script> [unsafe](javascript:alert(1))";
        var agent = NewAgent();
        await ScriptAsync(agent, new JsonObject { ["reset"] = true, ["interactive"] = true });
        using var response = await agent.Signed.PostAsJsonAsync("/mission", new JsonObject { ["description"] = untrusted });
        Assert.Equal(System.Net.HttpStatusCode.Accepted, response.StatusCode);
        var interaction = AAuth.Headers.Interaction.FromRequirement(AAuth.Headers.AAuthRequirementHeader.Parse(
            response.Headers.GetValues("AAuth-Requirement").Single()), TestEgress.Policy)!;
        var inspected = false;
        using var approved = await AAuth.Testing.TestConsentBrowser.DecideAsync(agent.Plain, interaction.BuildUserUrl(), "/interaction/approve", html =>
        {
            inspected = true;
            Assert.Contains(System.Net.WebUtility.HtmlEncode(untrusted), html);
            Assert.DoesNotContain("<img src=x", html);
            Assert.DoesNotContain("<script>private", html);
            Assert.DoesNotContain("href=\"javascript:", html);
        });
        Assert.True(inspected);
        Assert.True(approved.IsSuccessStatusCode);
    }

    // ---- Helpers -------------------------------------------------------

    private sealed record Agent(string AgentId, AAuthKey AgentKey, HttpClient Signed, HttpClient Plain, MetadataClient Metadata);

    private Agent NewAgent(string? agentId = null)
    {
        agentId ??= $"aauth:demo@ap.example";
        var agentKey = AAuthKey.Generate();
        var agentToken = new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = ApIssuer,
            Subject = agentId,
            KeyId = "demo",
            Key = ResourceStub.ApKey,
            ConfirmationKey = agentKey,
            PersonServer = PsIssuer,
        }.Build();
        var signing = new AAuthSigningHandler(agentKey, () => agentToken)
        {
            InnerHandler = _factory.Server.CreateHandler(),
        };
        var signed = new InProcessHttpClient(signing) { BaseAddress = new Uri(PsIssuer) };
        var plain = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(PsIssuer),
        });
        var metadata = new MetadataClient(new InProcessHttpClient(_factory.Server.CreateHandler()));
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
            ScopeDescriptions = TestScopeDefinitions.Resource,
            EgressPolicy = TestEgress.Policy,
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
