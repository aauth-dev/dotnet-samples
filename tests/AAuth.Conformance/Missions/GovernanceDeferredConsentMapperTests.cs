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
            if (ctx.Request.Headers.ContainsKey("Test-Unauthenticated"))
            {
                await next();
                return;
            }
            ctx.Features.Set(new AAuthVerificationResult
            {
                Level = AAuthLevel.Identified,
                Scheme = "jwt",
                IssuerVerified = true,
                Issuer = ctx.Request.Headers["Test-Issuer"].FirstOrDefault() ?? "https://agent.example",
                Jkt = ctx.Request.Headers["Test-Key"].FirstOrDefault() ?? "verified-key",
                TokenType = AAuthTokenType.AgentToken,
                Agent = ctx.Request.Headers["Test-Agent"].FirstOrDefault() ?? Agent,
            });
            await next();
        });

        app.MapAAuthGovernance(o =>
        {
            o.PersonServer = Ps;
            o.InteractionUrl = Ps + "/interaction";
        });

        await app.StartAsync();
        return app;
    }

    private static StringContent JsonContent(JsonObject body)
        => new(body.ToJsonString(), Encoding.UTF8, "application/json");

    private static async Task<JsonObject?> ReadJson(HttpResponseMessage response)
        => JsonNode.Parse(await response.Content.ReadAsStringAsync()) as JsonObject;

    [Theory]
    [InlineData("Test-Agent", "aauth:foreign@agent.example", "GET")]
    [InlineData("Test-Issuer", "https://foreign.example", "GET")]
    [InlineData("Test-Key", "foreign-key", "GET")]
    [InlineData("Test-Agent", "aauth:foreign@agent.example", "DELETE")]
    [InlineData("Test-Issuer", "https://foreign.example", "DELETE")]
    [InlineData("Test-Key", "foreign-key", "DELETE")]
    [InlineData("Test-Unauthenticated", "true", "GET")]
    [InlineData("Test-Unauthenticated", "true", "DELETE")]
    public async Task Pending_ForeignOwnerCannotConsumeOrCancel(string header, string value, string method)
    {
        using var host = await BuildHostAsync(services =>
        {
            services.AddAAuthDeferredConsent();
            services.AddSingleton<IMissionApprover>(new StubApprover(MissionApprovalDecision.Defer()));
        });
        using var client = host.GetTestServer().CreateClient();
        using var parked = await client.PostAsync("https://localhost/mission",
            JsonContent(new JsonObject { ["description"] = "Owner-bound consent" }));
        var location = "https://localhost" + parked.Headers.Location;
        var id = parked.Headers.Location!.ToString().Split('/').Last();
        var store = host.Services.GetRequiredService<IDeferredConsentStore>();
        await store.ResolveAsync(id, true);
        using var foreign = new HttpRequestMessage(new HttpMethod(method), location);
        foreign.Headers.Add(header, value);
        using var rejected = await client.SendAsync(foreign);
        Assert.Equal(HttpStatusCode.NotFound, rejected.StatusCode);
        using var legitimate = await client.GetAsync(location);
        Assert.Equal(HttpStatusCode.OK, legitimate.StatusCode);
        using var replay = await client.GetAsync(location);
        Assert.Equal(HttpStatusCode.Gone, replay.StatusCode);
    }

    [Fact(DisplayName = "§Mission Approval — governance hosted without a PS omits person_tokens")]
    public async Task Mission_WithoutPersonServer_OmitsPersonTokens()
    {
        using var host = await BuildHostAsync();
        using var client = host.GetTestServer().CreateClient();

        using var created = await client.PostAsync("https://localhost/mission", JsonContent(new JsonObject
        {
            ["description"] = "Resources without a PS",
            ["resources"] = new JsonArray("https://whoami.example"),
        }));

        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        var body = await ReadJson(created);
        Assert.False(body!.ContainsKey("person_tokens"));
        var mission = Mission.FromApprovalResponse(System.Text.Encoding.UTF8.GetBytes(body.ToJsonString()), Ps);
        Assert.Equal(new[] { "https://whoami.example" }, mission.ApprovedResources);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Permission_Deferred_RevalidatesMissionBeforeDelivery(bool changedOwner)
    {
        using var host = await BuildHostAsync(services =>
        {
            services.AddAAuthDeferredConsent();
            services.AddSingleton<IPermissionDecider>(new StubDecider(
                new PermissionDecision(PermissionOutcome.Prompt, PermissionDecisionReason.OutOfScope)));
        });
        using var client = host.GetTestServer().CreateClient();
        using var created = await client.PostAsync("https://localhost/mission",
            JsonContent(new JsonObject { ["description"] = "Deferred permission ownership" }));
        var approvalBytes = await created.Content.ReadAsByteArrayAsync();
        var mission = Mission.FromApprovalResponse(approvalBytes, Ps);
        using var parked = await client.PostAsync("https://localhost/permission", JsonContent(new JsonObject
        {
            ["action"] = "SendEmail",
            ["mission_s256"] = mission.S256,
        }));
        Assert.Equal(HttpStatusCode.Accepted, parked.StatusCode);
        var location = "https://localhost" + parked.Headers.Location;
        var missions = host.Services.GetRequiredService<IMissionStore>();
        if (changedOwner)
            await missions.SaveAsync(new StoredMission(mission.S256, Ps, "aauth:foreign@agent.example", mission.RawBytes));
        else
            await missions.SetStateAsync(mission.S256, MissionState.Terminated);
        await host.Services.GetRequiredService<IDeferredConsentStore>().ResolveAsync(
            parked.Headers.Location!.ToString().Split('/').Last(), true);
        using var rejected = await client.GetAsync(location);
        // §Mission Status Errors: a foreign mission is indistinguishable from a missing one.
        Assert.Equal(changedOwner ? HttpStatusCode.NotFound : HttpStatusCode.Forbidden, rejected.StatusCode);
        Assert.Equal(changedOwner ? "mission_not_found" : "mission_terminated", (string?)(await ReadJson(rejected))?["error"]);
        Assert.Empty(await host.Services.GetRequiredService<IMissionLog>().ReadAsync(mission.S256));
        using var replay = await client.GetAsync(location);
        Assert.Equal(HttpStatusCode.Gone, replay.StatusCode);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Pending_FirstDecisionWins_ExactlyOneDelivery(bool approved)
    {
        using var host = await BuildHostAsync(services =>
        {
            services.AddAAuthDeferredConsent();
            services.AddSingleton<IMissionApprover>(new StubApprover(MissionApprovalDecision.Defer()));
        });
        using var client = host.GetTestServer().CreateClient();
        using var parked = await client.PostAsync("https://localhost/mission",
            JsonContent(new JsonObject { ["description"] = "Single decision" }));
        var location = "https://localhost" + parked.Headers.Location;
        var store = host.Services.GetRequiredService<IDeferredConsentStore>();
        var id = parked.Headers.Location!.ToString().Split('/').Last();
        await store.ResolveAsync(id, approved);
        await store.ResolveAsync(id, !approved);
        var responses = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => client.GetAsync(location)));
        Assert.Single(responses, response => response.StatusCode == (approved ? HttpStatusCode.OK : HttpStatusCode.Forbidden));
        Assert.Equal(7, responses.Count(response => response.StatusCode == HttpStatusCode.Gone));
        foreach (var response in responses) response.Dispose();
    }

    [Fact]
    public async Task Pending_CancelCannotBeApprovedLater()
    {
        using var host = await BuildHostAsync(services =>
        {
            services.AddAAuthDeferredConsent();
            services.AddSingleton<IMissionApprover>(new StubApprover(MissionApprovalDecision.Defer()));
        });
        using var client = host.GetTestServer().CreateClient();
        using var parked = await client.PostAsync("https://localhost/mission",
            JsonContent(new JsonObject { ["description"] = "Cancelled mission" }));
        var location = "https://localhost" + parked.Headers.Location;
        using var cancelled = await client.DeleteAsync(location);
        Assert.Equal(HttpStatusCode.NoContent, cancelled.StatusCode);
        await host.Services.GetRequiredService<IDeferredConsentStore>().ResolveAsync(
            parked.Headers.Location!.ToString().Split('/').Last(), true);
        using var replay = await client.GetAsync(location);
        Assert.Equal(HttpStatusCode.Gone, replay.StatusCode);
    }

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
        Assert.False(response.Headers.Contains("AAuth-Mission"));

        var bytes = await response.Content.ReadAsByteArrayAsync();
        var envelope = JsonNode.Parse(bytes)!.AsObject();
        Assert.NotNull((string?)envelope["s256"]);
        Assert.NotNull((string?)envelope["mission"]);
        var mission = Mission.FromApprovalResponse(bytes, Ps);
        Assert.Equal(Ps, mission.PersonServer);
        Assert.Equal(Agent, mission.Agent);
        Assert.Contains(mission.ApprovedTools, t => t.Name == "WebSearch");

        // The mission is persisted and verifiable by its s256.
        var store = host.Services.GetRequiredService<IMissionStore>();
        var stored = await store.GetAsync(mission.S256);
        Assert.NotNull(stored);

        await host.StopAsync();
    }

    [Fact(DisplayName = "§Mission Creation — an agentless request is rejected (403 invalid_carrier_token)")]
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

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        await app.StopAsync();
        ((IDisposable)app).Dispose();
    }

    [Fact(DisplayName = "§Mission Creation — a declining approver yields 403 denied")]
    public async Task Mission_DecliningApprover_Forbidden()
    {
        using var host = await BuildHostAsync(s =>
            s.AddSingleton<IMissionApprover>(new StubApprover(MissionApprovalDecision.Decline("not now"))));
        using var client = host.GetTestServer().CreateClient();

        var response = await client.PostAsync("https://localhost/mission",
            JsonContent(new JsonObject { ["description"] = "# Plan a trip" }));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var json = await ReadJson(response);
        Assert.Equal("denied", (string?)json?["error"]);
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
        var mission = Mission.FromApprovalResponse(await done.Content.ReadAsByteArrayAsync(), Ps);
        Assert.Equal(Agent, mission.Agent);

        await host.StopAsync();
    }

    [Fact(DisplayName = "§Deferred Consent — a declined mission poll resolves to 403 denied")]
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
        Assert.Equal("denied", (string?)json?["error"]);

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

    [Fact(DisplayName = "§Deferred Consent — a declined permission poll resolves to a denied decision (200, not denied)")]
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

    [Theory]
    [InlineData("interaction")]
    [InlineData("payment")]
    public async Task Interaction_DeclinedDecisionIsTerminalDenial(string type)
    {
        using var host = await BuildHostAsync(services =>
        {
            services.AddAAuthDeferredConsent();
            services.AddSingleton<IInteractionRelay>(new StubRelay(new InteractionRelayResult { Pending = true }));
        });
        using var client = host.GetTestServer().CreateClient();
        using var parked = await client.PostAsync("https://localhost/mission-interaction", JsonContent(new JsonObject
        {
            ["type"] = type, ["url"] = Ps + "/consent", ["code"] = "CODE",
        }));
        Assert.Equal(HttpStatusCode.Accepted, parked.StatusCode);
        var location = "https://localhost" + parked.Headers.Location;
        await host.Services.GetRequiredService<IDeferredConsentStore>().ResolveAsync(
            parked.Headers.Location!.ToString().Split('/').Last(), false);
        using var denied = await client.GetAsync(location);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        Assert.Equal("denied", (string?)(await ReadJson(denied))?["error"]);
        using var replay = await client.GetAsync(location);
        Assert.Equal(HttpStatusCode.Gone, replay.StatusCode);
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

    [Fact(DisplayName = "§Interaction Endpoint Errors — an unavailable relay returns 424 interaction_unavailable (non-terminal)")]
    public async Task Interaction_Unavailable_Returns424()
    {
        using var host = await BuildHostAsync(s =>
        {
            s.AddAAuthDeferredConsent();
            s.AddSingleton<IInteractionRelay>(new StubRelay(new InteractionRelayResult { Unavailable = true }));
        });
        using var client = host.GetTestServer().CreateClient();

        var body = new JsonObject
        {
            ["type"] = "interaction",
            ["url"] = "https://booking.example/confirm",
            ["code"] = "X7K2-M9P4",
        };
        var response = await client.PostAsync("https://localhost/mission-interaction", JsonContent(body));

        Assert.Equal(HttpStatusCode.FailedDependency, response.StatusCode); // 424
        var json = await ReadJson(response);
        Assert.Equal("interaction_unavailable", (string?)json?["error"]);

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

    [Fact(DisplayName = "§Mission Completion — a completion reviewed asynchronously parks 202, then terminates the mission on accept")]
    public async Task Completion_PendingRelay_Parks202_ThenTerminates()
    {
        const string s256 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        using var host = await BuildHostAsync(s =>
        {
            s.AddAAuthDeferredConsent();
            s.AddSingleton<IInteractionRelay>(new StubRelay(new InteractionRelayResult { Pending = true }));
        });
        var missionStore = host.Services.GetRequiredService<IMissionStore>();
        await missionStore.SaveAsync(new StoredMission(s256, Ps, Agent, new byte[] { 1, 2, 3 }));
        using var client = host.GetTestServer().CreateClient();

        var body = new JsonObject
        {
            ["action"] = "completion",
            ["summary"] = "# Booked the refundable option",
        };
        var response = await client.PostAsync("https://localhost/mission/" + s256, JsonContent(body));

        // §Interaction Response: "The PS returns a deferred response while the user reviews."
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        var location = response.Headers.Location!.ToString();
        Assert.Contains("/governance-pending/", location);

        // The mission stays active while the user reviews.
        using var pendingPoll = await client.GetAsync("https://localhost" + location);
        Assert.Equal(HttpStatusCode.Accepted, pendingPoll.StatusCode);
        Assert.Equal(MissionState.Active, (await missionStore.GetAsync(s256))!.State);

        // The user accepts the summary; the poll terminates the mission.
        var id = location[(location.LastIndexOf('/') + 1)..];
        var consent = host.Services.GetRequiredService<IDeferredConsentStore>();
        await consent.ResolveAsync(id, approved: true);

        using var done = await client.GetAsync("https://localhost" + location);
        Assert.Equal(HttpStatusCode.OK, done.StatusCode);
        var json = await ReadJson(done);
        Assert.Equal("terminated", (string?)json?["mission_status"]);
        Assert.Equal(MissionState.Terminated, (await missionStore.GetAsync(s256))!.State);

        await host.StopAsync();
    }

    [Fact(DisplayName = "§Mission Completion — a reviewed completion the user does not accept keeps the mission active")]
    public async Task Completion_PendingRelay_FollowUp_StaysActive()
    {
        const string s256 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        using var host = await BuildHostAsync(s =>
        {
            s.AddAAuthDeferredConsent();
            s.AddSingleton<IInteractionRelay>(new StubRelay(new InteractionRelayResult { Pending = true }));
        });
        var missionStore = host.Services.GetRequiredService<IMissionStore>();
        await missionStore.SaveAsync(new StoredMission(s256, Ps, Agent, new byte[] { 1, 2, 3 }));
        using var client = host.GetTestServer().CreateClient();

        var body = new JsonObject
        {
            ["action"] = "completion",
            ["summary"] = "# Draft itinerary",
        };
        var response = await client.PostAsync("https://localhost/mission/" + s256, JsonContent(body));
        var location = response.Headers.Location!.ToString();

        var id = location[(location.LastIndexOf('/') + 1)..];
        var consent = host.Services.GetRequiredService<IDeferredConsentStore>();
        await consent.ResolveAsync(id, approved: false);

        using var done = await client.GetAsync("https://localhost" + location);
        Assert.Equal(HttpStatusCode.OK, done.StatusCode);
        var json = await ReadJson(done);
        Assert.Equal("active", (string?)json?["mission_status"]);
        Assert.Equal(MissionState.Active, (await missionStore.GetAsync(s256))!.State);

        await host.StopAsync();
    }

    [Fact(DisplayName = "§Mission Completion — without the deferred store a completion resolves synchronously off the relay's Accepted result")]
    public async Task Completion_NoStore_ResolvesSynchronously()
    {
        const string s256 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        using var host = await BuildHostAsync(s =>
            s.AddSingleton<IInteractionRelay>(new StubRelay(new InteractionRelayResult { Accepted = true })));
        var missionStore = host.Services.GetRequiredService<IMissionStore>();
        await missionStore.SaveAsync(new StoredMission(s256, Ps, Agent, new byte[] { 1, 2, 3 }));
        using var client = host.GetTestServer().CreateClient();

        var body = new JsonObject
        {
            ["action"] = "completion",
            ["summary"] = "# Done",
        };
        var response = await client.PostAsync("https://localhost/mission/" + s256, JsonContent(body));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Null(response.Headers.Location);
        var json = await ReadJson(response);
        Assert.Equal("terminated", (string?)json?["mission_status"]);
        Assert.Equal(MissionState.Terminated, (await missionStore.GetAsync(s256))!.State);

        await host.StopAsync();
    }

    [Fact(DisplayName = "§Interaction Endpoint — completion is no longer an interaction type")]
    public async Task Completion_AtInteractionEndpoint_Rejected()
    {
        const string s256 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        using var host = await BuildHostAsync(s =>
            s.AddSingleton<IInteractionRelay>(new StubRelay(new InteractionRelayResult { Accepted = true })));
        var missionStore = host.Services.GetRequiredService<IMissionStore>();
        await missionStore.SaveAsync(new StoredMission(s256, Ps, Agent, new byte[] { 1, 2, 3 }));
        using var client = host.GetTestServer().CreateClient();

        var response = await client.PostAsync("https://localhost/mission-interaction", JsonContent(new JsonObject
        {
            ["type"] = "completion", ["summary"] = "# Done", ["mission_s256"] = s256,
        }));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(MissionState.Active, (await missionStore.GetAsync(s256))!.State);
        await host.StopAsync();
    }

    [Theory(DisplayName = "§Mission Update — an update is logged and returns its s256; a foreign mission is not found")]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MissionUpdate_OwnedMissionOnly(bool foreign)
    {
        const string s256 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        using var host = await BuildHostAsync();
        await host.Services.GetRequiredService<IMissionStore>().SaveAsync(new StoredMission(
            s256, Ps, foreign ? "aauth:foreign@agent.example" : Agent, new byte[] { 1, 2, 3 }));
        using var client = host.GetTestServer().CreateClient();

        var response = await client.PostAsync("https://localhost/mission/" + s256, JsonContent(new JsonObject
        {
            ["action"] = "update", ["description"] = "Also book a hotel.",
        }));

        if (foreign)
        {
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            Assert.Equal("mission_not_found", (string?)(await ReadJson(response))?["error"]);
        }
        else
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.False(string.IsNullOrEmpty((string?)(await ReadJson(response))?["s256"]));
            Assert.Contains(await host.Services.GetRequiredService<IMissionLog>().ReadAsync(s256),
                entry => entry.Kind == MissionLogEntryKind.Update);
        }
        await host.StopAsync();
    }

    [Fact(DisplayName = "§Interaction Endpoint — AddAAuthInteractionRelay wires a delegate relay used for a question")]
    public async Task DelegateInteractionRelay_AnswersQuestion()
    {
        using var host = await BuildHostAsync(s =>
            s.AddAAuthInteractionRelay((req, ct) =>
                Task.FromResult(new InteractionRelayResult { Answer = "Yes, the refundable option." })));
        using var client = host.GetTestServer().CreateClient();

        var body = new JsonObject
        {
            ["type"] = "question",
            ["question"] = "# Which option?",
        };
        var response = await client.PostAsync("https://localhost/mission-interaction", JsonContent(body));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJson(response);
        Assert.Equal("Yes, the refundable option.", (string?)json?["answer"]);

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
