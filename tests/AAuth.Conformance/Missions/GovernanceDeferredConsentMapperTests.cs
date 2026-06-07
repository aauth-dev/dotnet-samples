using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth;
using AAuth.Agent;
using AAuth.Agent.Governance;
using AAuth.Server.Governance;
using AAuth.Server.Verification;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace AAuth.Conformance.Missions;

/// <summary>
/// Conformance for the governance mapper's mission-creation endpoint and
/// deferred-consent (<c>202</c> poll) flow (AAuth protocol §Mission Creation,
/// §Mission Approval, §Deferred Consent). The mapper maps <c>mission_endpoint</c>
/// via <see cref="IMissionApprover"/> and, when <c>AddAAuthDeferredConsent</c> is
/// called, resolves a <c>Prompt</c> outcome by parking the request and answering
/// <c>202</c> with a poll <c>Location</c>.
/// </summary>
public class GovernanceDeferredConsentMapperTests
{
    private const string Ps = "https://ps.example";
    private const string Agent = "aauth:assistant@agent.example";

    // Build a host with the mapper, a stub that marks every request as carrying a
    // verified agent token, and the supplied governance seam overrides.
    private static async Task<IHost> BuildHostAsync(Action<IServiceCollection>? configure = null)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddAAuthGovernance();
        builder.Services.AddRouting();
        configure?.Invoke(builder.Services);

        var app = builder.Build();

        // Stand in for the verification middleware: present a verified agent token.
        app.Use(async (ctx, next) =>
        {
            ctx.Features.Set(new AAuthVerificationResult
            {
                Level = AAuthLevel.Identified,
                Scheme = "jwt",
                TokenType = AAuthTokenType.AgentToken,
                Agent = Agent,
            });
            await next();
        });

        app.MapAAuthGovernance(o =>
        {
            o.Approver = Ps;
            o.InteractionUrl = Ps + "/interaction";
        });

        await app.StartAsync();
        return app;
    }

    private static StringContent JsonContent(JsonObject body)
        => new(body.ToJsonString(), Encoding.UTF8, "application/json");

    private static async Task<JsonObject?> ReadJson(HttpResponseMessage response)
        => JsonNode.Parse(await response.Content.ReadAsStringAsync()) as JsonObject;

    [Fact(DisplayName = "§Mission Creation — the default approver approves and returns a verifiable blob")]
    public async Task Mission_DefaultApprover_ReturnsApprovedBlob()
    {
        using var host = await BuildHostAsync();
        using var client = host.GetTestServer().CreateClient();

        var body = new JsonObject
        {
            ["description"] = "# Plan a trip",
            ["tools"] = new JsonArray { new JsonObject { ["name"] = "WebSearch" } },
        };
        var response = await client.PostAsync("https://localhost/mission", JsonContent(body));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.Contains("AAuth-Mission"));

        var bytes = await response.Content.ReadAsByteArrayAsync();
        var mission = Mission.FromApprovalBytes(bytes);
        Assert.Equal(Ps, mission.Approver);
        Assert.Equal(Agent, mission.Agent);
        Assert.Contains(mission.ApprovedTools, t => t.Name == "WebSearch");

        // The mission is persisted and verifiable by its s256.
        var store = host.Services.GetRequiredService<IMissionStore>();
        var stored = await store.GetAsync(mission.S256);
        Assert.NotNull(stored);

        await host.StopAsync();
    }

    [Fact(DisplayName = "§Mission Creation — an agentless request is rejected (401 invalid_carrier_token)")]
    public async Task Mission_NoAgentToken_Unauthorized()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddAAuthGovernance();
        builder.Services.AddRouting();
        var app = builder.Build();
        app.MapAAuthGovernance();   // no agent-token stub middleware
        await app.StartAsync();

        using var client = app.GetTestServer().CreateClient();
        var response = await client.PostAsync("https://localhost/mission",
            JsonContent(new JsonObject { ["description"] = "# Plan a trip" }));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        await app.StopAsync();
        ((IDisposable)app).Dispose();
    }

    [Fact(DisplayName = "§Mission Creation — a declining approver yields 403 access_denied")]
    public async Task Mission_DecliningApprover_Forbidden()
    {
        using var host = await BuildHostAsync(s =>
            s.AddSingleton<IMissionApprover>(new StubApprover(MissionApprovalDecision.Decline("not now"))));
        using var client = host.GetTestServer().CreateClient();

        var response = await client.PostAsync("https://localhost/mission",
            JsonContent(new JsonObject { ["description"] = "# Plan a trip" }));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var json = await ReadJson(response);
        Assert.Equal("access_denied", (string?)json?["error"]);
        await host.StopAsync();
    }

    [Fact(DisplayName = "§Deferred Consent — a prompting approver parks the mission and answers 202 with a poll Location")]
    public async Task Mission_Prompt_Parks202_ThenApprovalCompletes()
    {
        using var host = await BuildHostAsync(s =>
        {
            s.AddAAuthDeferredConsent();
            s.AddSingleton<IMissionApprover>(new StubApprover(MissionApprovalDecision.Defer()));
        });
        using var client = host.GetTestServer().CreateClient();

        var response = await client.PostAsync("https://localhost/mission",
            JsonContent(new JsonObject { ["description"] = "# Plan a trip" }));

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        var location = response.Headers.Location!.ToString();
        Assert.Contains("/governance-pending/", location);
        Assert.True(response.Headers.Contains("AAuth-Requirement"));

        // The user has not decided yet — the poll holds at 202.
        using var pendingPoll = await client.GetAsync("https://localhost" + location);
        Assert.Equal(HttpStatusCode.Accepted, pendingPoll.StatusCode);

        // The user approves at the PS consent page (resolve the parked entry).
        var id = location[(location.LastIndexOf('/') + 1)..];
        var consent = host.Services.GetRequiredService<IDeferredConsentStore>();
        await consent.ResolveAsync(id, approved: true);

        using var done = await client.GetAsync("https://localhost" + location);
        Assert.Equal(HttpStatusCode.OK, done.StatusCode);
        Assert.True(done.Headers.Contains("AAuth-Mission"));
        var mission = Mission.FromApprovalBytes(await done.Content.ReadAsByteArrayAsync());
        Assert.Equal(Agent, mission.Agent);

        await host.StopAsync();
    }

    [Fact(DisplayName = "§Deferred Consent — a declined mission poll resolves to 403 access_denied")]
    public async Task Mission_Prompt_Declined_Forbidden()
    {
        using var host = await BuildHostAsync(s =>
        {
            s.AddAAuthDeferredConsent();
            s.AddSingleton<IMissionApprover>(new StubApprover(MissionApprovalDecision.Defer()));
        });
        using var client = host.GetTestServer().CreateClient();

        var response = await client.PostAsync("https://localhost/mission",
            JsonContent(new JsonObject { ["description"] = "# Plan a trip" }));
        var location = response.Headers.Location!.ToString();
        var id = location[(location.LastIndexOf('/') + 1)..];

        var consent = host.Services.GetRequiredService<IDeferredConsentStore>();
        await consent.ResolveAsync(id, approved: false);

        using var done = await client.GetAsync("https://localhost" + location);
        Assert.Equal(HttpStatusCode.Forbidden, done.StatusCode);
        var json = await ReadJson(done);
        Assert.Equal("access_denied", (string?)json?["error"]);

        await host.StopAsync();
    }

    [Fact(DisplayName = "§Deferred Consent — a prompting permission parks and resolves to a granted decision")]
    public async Task Permission_Prompt_Parks202_ThenGrant()
    {
        using var host = await BuildHostAsync(s =>
        {
            s.AddAAuthDeferredConsent();
            s.AddSingleton<IPermissionDecider>(new StubDecider(
                new PermissionDecision(PermissionOutcome.Prompt, PermissionDecisionReason.OutOfScope)));
        });
        using var client = host.GetTestServer().CreateClient();

        var response = await client.PostAsync("https://localhost/permission",
            JsonContent(new JsonObject { ["action"] = "SendEmail" }));

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        var location = response.Headers.Location!.ToString();
        var id = location[(location.LastIndexOf('/') + 1)..];

        var consent = host.Services.GetRequiredService<IDeferredConsentStore>();
        await consent.ResolveAsync(id, approved: true);

        using var done = await client.GetAsync("https://localhost" + location);
        Assert.Equal(HttpStatusCode.OK, done.StatusCode);
        var json = await ReadJson(done);
        Assert.Equal("granted", (string?)json?["permission"]);

        await host.StopAsync();
    }

    [Fact(DisplayName = "§Deferred Consent — a declined permission poll resolves to a denied decision (200, not access_denied)")]
    public async Task Permission_Prompt_Declined_ReturnsDenied()
    {
        using var host = await BuildHostAsync(s =>
        {
            s.AddAAuthDeferredConsent();
            s.AddSingleton<IPermissionDecider>(new StubDecider(
                new PermissionDecision(PermissionOutcome.Prompt, PermissionDecisionReason.OutOfScope)));
        });
        using var client = host.GetTestServer().CreateClient();

        var response = await client.PostAsync("https://localhost/permission",
            JsonContent(new JsonObject { ["action"] = "SendEmail" }));
        var location = response.Headers.Location!.ToString();
        var id = location[(location.LastIndexOf('/') + 1)..];

        var consent = host.Services.GetRequiredService<IDeferredConsentStore>();
        await consent.ResolveAsync(id, approved: false);

        using var done = await client.GetAsync("https://localhost" + location);
        Assert.Equal(HttpStatusCode.OK, done.StatusCode);
        var json = await ReadJson(done);
        Assert.Equal("denied", (string?)json?["permission"]);

        await host.StopAsync();
    }

    [Fact(DisplayName = "§Deferred Consent — without the store a prompting permission falls back to a denial")]
    public async Task Permission_Prompt_NoStore_Denied()
    {
        using var host = await BuildHostAsync(s =>
            s.AddSingleton<IPermissionDecider>(new StubDecider(
                new PermissionDecision(PermissionOutcome.Prompt, PermissionDecisionReason.OutOfScope))));
        using var client = host.GetTestServer().CreateClient();

        var response = await client.PostAsync("https://localhost/permission",
            JsonContent(new JsonObject { ["action"] = "SendEmail" }));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJson(response);
        Assert.Equal("denied", (string?)json?["permission"]);

        await host.StopAsync();
    }

    [Fact(DisplayName = "§Interaction Response — a pending interaction relay parks and answers 202 with a poll Location, then completes")]
    public async Task Interaction_PendingRelay_Parks202_ThenCompletes()
    {
        using var host = await BuildHostAsync(s =>
        {
            s.AddAAuthDeferredConsent();
            s.AddSingleton<IInteractionRelay>(new StubRelay(new InteractionRelayResult { Pending = true }));
        });
        using var client = host.GetTestServer().CreateClient();

        var body = new JsonObject
        {
            ["type"] = "interaction",
            ["url"] = "https://booking.example/confirm",
            ["code"] = "X7K2-M9P4",
        };
        var response = await client.PostAsync("https://localhost/mission-interaction", JsonContent(body));

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        var location = response.Headers.Location!.ToString();
        Assert.Contains("/governance-pending/", location);

        // The user has not completed the interaction yet — the poll holds at 202.
        using var pendingPoll = await client.GetAsync("https://localhost" + location);
        Assert.Equal(HttpStatusCode.Accepted, pendingPoll.StatusCode);

        // The user completes the interaction at the resource's interaction URL.
        var id = location[(location.LastIndexOf('/') + 1)..];
        var consent = host.Services.GetRequiredService<IDeferredConsentStore>();
        await consent.ResolveAsync(id, approved: true);

        using var done = await client.GetAsync("https://localhost" + location);
        Assert.Equal(HttpStatusCode.OK, done.StatusCode);
        var json = await ReadJson(done);
        Assert.Equal("ok", (string?)json?["status"]);

        await host.StopAsync();
    }

    [Fact(DisplayName = "§Interaction Response — a pending payment relay also parks and answers 202")]
    public async Task Interaction_PendingPayment_Parks202()
    {
        using var host = await BuildHostAsync(s =>
        {
            s.AddAAuthDeferredConsent();
            s.AddSingleton<IInteractionRelay>(new StubRelay(new InteractionRelayResult { Pending = true }));
        });
        using var client = host.GetTestServer().CreateClient();

        var body = new JsonObject
        {
            ["type"] = "payment",
            ["url"] = "https://pay.example/checkout",
            ["code"] = "PAY-9931",
        };
        var response = await client.PostAsync("https://localhost/mission-interaction", JsonContent(body));

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Contains("/governance-pending/", response.Headers.Location!.ToString());

        await host.StopAsync();
    }

    [Fact(DisplayName = "§Interaction Response — a non-pending interaction relay resolves synchronously (200, no poll)")]
    public async Task Interaction_NotPending_Returns200()
    {
        using var host = await BuildHostAsync(s =>
        {
            s.AddAAuthDeferredConsent();
            s.AddSingleton<IInteractionRelay>(new StubRelay(new InteractionRelayResult { Pending = false }));
        });
        using var client = host.GetTestServer().CreateClient();

        var body = new JsonObject
        {
            ["type"] = "interaction",
            ["url"] = "https://booking.example/confirm",
            ["code"] = "X7K2-M9P4",
        };
        var response = await client.PostAsync("https://localhost/mission-interaction", JsonContent(body));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Null(response.Headers.Location);
        var json = await ReadJson(response);
        Assert.Equal("ok", (string?)json?["status"]);

        await host.StopAsync();
    }

    [Fact(DisplayName = "§Interaction Response — without the deferred store a pending relay falls back to a synchronous 200")]
    public async Task Interaction_PendingRelay_NoStore_Returns200()
    {
        using var host = await BuildHostAsync(s =>
            s.AddSingleton<IInteractionRelay>(new StubRelay(new InteractionRelayResult { Pending = true })));
        using var client = host.GetTestServer().CreateClient();

        var body = new JsonObject
        {
            ["type"] = "interaction",
            ["url"] = "https://booking.example/confirm",
            ["code"] = "X7K2-M9P4",
        };
        var response = await client.PostAsync("https://localhost/mission-interaction", JsonContent(body));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Null(response.Headers.Location);
        var json = await ReadJson(response);
        Assert.Equal("ok", (string?)json?["status"]);

        await host.StopAsync();
    }

    private sealed class StubApprover(MissionApprovalDecision decision) : IMissionApprover
    {
        public Task<MissionApprovalDecision> ApproveAsync(MissionApprovalContext context, CancellationToken ct = default)
            => Task.FromResult(decision);
    }

    private sealed class StubDecider(PermissionDecision decision) : IPermissionDecider
    {
        public Task<PermissionDecision> DecideAsync(PermissionDecisionContext context, CancellationToken ct = default)
            => Task.FromResult(decision);
    }

    private sealed class StubRelay(InteractionRelayResult result) : IInteractionRelay
    {
        public Task<InteractionRelayResult> RelayAsync(InteractionRequest request, CancellationToken ct = default)
            => Task.FromResult(result);
    }
}
