using System;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Agent.Governance;
using AAuth.Server.Governance;
using Xunit;

namespace AAuth.Conformance.Missions;

/// <summary>
/// Conformance for the PS-side governance seams (AAuth protocol §PS Governance
/// Endpoints, §Mission Log, §Mission Status Errors): request parsers, the
/// mission store, the ordered mission log with prior-consent lookup, and the
/// <c>mission_terminated</c> response helper.
/// </summary>
public class GovernanceServerTests
{
    private const string S256 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    // ---- §Request parsers ----

    [Fact(DisplayName = "§Permission Request — parser maps JSON to PermissionRequest")]
    public void ParsePermission_MapsFields()
    {
        var body = new JsonObject
        {
            ["action"] = "SendEmail",
            ["description"] = "Send the itinerary",
            ["parameters"] = new JsonObject { ["to"] = "user@example.com" },
            ["mission"] = new JsonObject { ["approver"] = "https://ps.example", ["s256"] = S256 },
        };

        var request = GovernanceEndpoints.ParsePermission(body);

        Assert.Equal("SendEmail", request.Action.Name);
        Assert.Equal("Send the itinerary", request.Description);
        Assert.Equal("user@example.com", (string?)request.Parameters!["to"]);
        Assert.Equal(S256, request.Mission!.S256);
    }

    [Fact(DisplayName = "§Permission Request — missing action throws")]
    public void ParsePermission_MissingAction_Throws()
        => Assert.Throws<FormatException>(() =>
            GovernanceEndpoints.ParsePermission(new JsonObject { ["description"] = "x" }));

    [Fact(DisplayName = "§Audit Request — parser requires mission and action")]
    public void ParseAudit_MapsFields()
    {
        var body = new JsonObject
        {
            ["mission"] = new JsonObject { ["approver"] = "https://ps.example", ["s256"] = S256 },
            ["action"] = "WebSearch",
            ["result"] = new JsonObject { ["status"] = "completed" },
        };

        var record = GovernanceEndpoints.ParseAudit(body);

        Assert.Equal(S256, record.Mission.S256);
        Assert.Equal("WebSearch", record.Action.Name);
        Assert.Equal("completed", (string?)record.Result!["status"]);
    }

    [Fact(DisplayName = "§Audit Request — missing mission throws")]
    public void ParseAudit_MissingMission_Throws()
        => Assert.Throws<FormatException>(() =>
            GovernanceEndpoints.ParseAudit(new JsonObject { ["action"] = "WebSearch" }));

    [Theory(DisplayName = "§Interaction Request — parser maps each type")]
    [InlineData("interaction", InteractionType.Interaction)]
    [InlineData("payment", InteractionType.Payment)]
    [InlineData("question", InteractionType.Question)]
    [InlineData("completion", InteractionType.Completion)]
    public void ParseInteraction_MapsType(string wire, InteractionType expected)
    {
        var request = GovernanceEndpoints.ParseInteraction(new JsonObject { ["type"] = wire });
        Assert.Equal(expected, request.Type);
    }

    [Fact(DisplayName = "§Interaction Request — unknown type throws")]
    public void ParseInteraction_UnknownType_Throws()
        => Assert.Throws<FormatException>(() =>
            GovernanceEndpoints.ParseInteraction(new JsonObject { ["type"] = "bogus" }));

    [Fact(DisplayName = "§Interaction Request — parser maps max_wait when present")]
    public void ParseInteraction_MapsMaxWait()
    {
        var request = GovernanceEndpoints.ParseInteraction(new JsonObject
        {
            ["type"] = "interaction",
            ["url"] = "https://resource.example/i",
            ["code"] = "A1B2C3D4",
            ["max_wait"] = 45,
        });

        Assert.Equal(45, request.MaxWait);
    }

    [Fact(DisplayName = "§Interaction Request — max_wait round-trips through the request body")]
    public void InteractionRequest_SerializesMaxWait()
    {
        var body = new InteractionRequest(InteractionType.Interaction)
        {
            Url = "https://resource.example/i",
            Code = "A1B2C3D4",
            MaxWait = 30,
        }.ToJsonObject();

        Assert.Equal(30, (int?)body["max_wait"]);
    }

    [Fact(DisplayName = "§Mission Creation — proposal parser maps description and tools")]
    public void ParseMissionProposal_MapsFields()
    {
        var body = new JsonObject
        {
            ["description"] = "# Plan a trip",
            ["tools"] = new JsonArray
            {
                new JsonObject { ["name"] = "WebSearch", ["description"] = "Search" },
            },
        };

        var proposal = GovernanceEndpoints.ParseMissionProposal(body);

        Assert.Equal("# Plan a trip", proposal.Description);
        Assert.Single(proposal.Tools);
        Assert.Equal("WebSearch", proposal.Tools[0].Name);
    }

    // ---- §Mission Status Errors ----

    [Fact(DisplayName = "§Mission Status Errors — helper emits the spec 403 body")]
    public void MissionTerminatedBody_MatchesSpec()
    {
        var body = GovernanceEndpoints.MissionTerminatedBody();
        Assert.Equal(403, GovernanceEndpoints.MissionTerminatedStatus);
        Assert.Equal("mission_terminated", (string?)body["error"]);
        Assert.Equal("terminated", (string?)body["mission_status"]);
    }

    // ---- §Mission Approval / §Mission Management (store) ----

    [Fact(DisplayName = "§Mission store — stores verbatim blob bytes and state transitions")]
    public async Task MissionStore_StoresBlobAndState()
    {
        var store = new InMemoryMissionStore();
        var blob = System.Text.Encoding.UTF8.GetBytes("{\"approver\":\"https://ps.example\"}");
        await store.SaveAsync(new StoredMission(S256, "https://ps.example", "aauth:a@x.example", blob));

        var loaded = await store.GetAsync(S256);
        Assert.NotNull(loaded);
        Assert.Equal(MissionState.Active, loaded!.State);
        Assert.True(blob.AsSpan().SequenceEqual(loaded.Blob.Span));

        await store.SetStateAsync(S256, MissionState.Terminated);
        var terminated = await store.GetAsync(S256);
        Assert.Equal(MissionState.Terminated, terminated!.State);
    }

    [Fact(DisplayName = "§Mission store — absent mission returns null")]
    public async Task MissionStore_Absent_ReturnsNull()
        => Assert.Null(await new InMemoryMissionStore().GetAsync("nope"));

    // ---- §Mission Log ----

    [Fact(DisplayName = "§Mission Log — entries are appended and read in order")]
    public async Task MissionLog_PreservesOrder()
    {
        var log = new InMemoryMissionLog();
        var now = DateTimeOffset.UtcNow;
        await log.AppendAsync(new MissionLogEntry(S256, MissionLogEntryKind.Token, now) { Detail = "first" });
        await log.AppendAsync(new MissionLogEntry(S256, MissionLogEntryKind.Permission, now) { Detail = "second" });
        await log.AppendAsync(new MissionLogEntry(S256, MissionLogEntryKind.Audit, now) { Detail = "third" });

        var entries = await log.ReadAsync(S256);

        Assert.Equal(new[] { "first", "second", "third" }, entries.Select(e => e.Detail));
    }

    [Fact(DisplayName = "§Mission Log — prior consent keyed by (s256, resource, scope)")]
    public async Task MissionLog_PriorConsent()
    {
        var log = new InMemoryMissionLog();
        await log.AppendAsync(new MissionLogEntry(S256, MissionLogEntryKind.Token, DateTimeOffset.UtcNow)
        {
            Resource = "https://calendar.example",
            Scope = "read",
            Granted = true,
        });

        Assert.True(await log.HasPriorConsentAsync(S256, "https://calendar.example", "read"));
        Assert.False(await log.HasPriorConsentAsync(S256, "https://calendar.example", "write"));
        Assert.False(await log.HasPriorConsentAsync(S256, "https://mail.example", "read"));
    }

    [Fact(DisplayName = "§Mission Log — a denied token entry does not count as prior consent")]
    public async Task MissionLog_DeniedNotConsent()
    {
        var log = new InMemoryMissionLog();
        await log.AppendAsync(new MissionLogEntry(S256, MissionLogEntryKind.Token, DateTimeOffset.UtcNow)
        {
            Resource = "https://calendar.example",
            Scope = "read",
            Granted = false,
        });

        Assert.False(await log.HasPriorConsentAsync(S256, "https://calendar.example", "read"));
    }

    // ---- §Permission Endpoint (decider seam) ----

    [Fact(DisplayName = "§Permission Endpoint — decider is invoked with mission + log context")]
    public async Task PermissionDecider_ReceivesContext()
    {
        var store = new InMemoryMissionStore();
        var log = new InMemoryMissionLog();
        var blob = System.Text.Encoding.UTF8.GetBytes("{}");
        await store.SaveAsync(new StoredMission(S256, "https://ps.example", "aauth:a@x.example", blob));
        await log.AppendAsync(new MissionLogEntry(S256, MissionLogEntryKind.Token, DateTimeOffset.UtcNow)
        {
            Resource = "https://calendar.example",
            Scope = "read",
            Granted = true,
        });

        var decider = new StubDecider();
        var request = new PermissionRequest(new MissionAction("SendEmail"))
        {
            Mission = new AAuth.Tokens.MissionClaim("https://ps.example", S256),
        };
        var mission = await store.GetAsync(S256);
        var entries = await log.ReadAsync(S256);

        var decision = await decider.DecideAsync(new PermissionDecisionContext(request, mission, entries));

        Assert.Equal(PermissionOutcome.Prompt, decision.Outcome);
        Assert.Equal(PermissionDecisionReason.OutOfScope, decision.Reason);
        Assert.Same(request, decider.LastContext!.Request);
        Assert.Equal(S256, decider.LastContext.Mission!.S256);
        Assert.Single(decider.LastContext.Log);
    }

    private sealed class StubDecider : IPermissionDecider
    {
        public PermissionDecisionContext? LastContext { get; private set; }

        public Task<PermissionDecision> DecideAsync(PermissionDecisionContext context, System.Threading.CancellationToken ct = default)
        {
            LastContext = context;
            return Task.FromResult(new PermissionDecision(
                PermissionOutcome.Prompt, PermissionDecisionReason.OutOfScope));
        }
    }
}
