using System;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth;
using AAuth.Agent;
using AAuth.Agent.Governance;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Errors;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Conformance.Missions;

/// <summary>
/// Conformance for the bundled governance facade (AAuth protocol
/// §PS Governance Endpoints). <see cref="AAuthGovernanceClient"/> exposes the
/// mission / permission / audit / interaction clients over a single signed
/// channel, and <see cref="AAuthClientBuilder.BuildGovernance"/> wires one from
/// the same signed exchange pipeline used for token exchange.
/// </summary>
public class GovernanceFacadeTests
{
    private const string Ps = "http://localhost:5555";

    private static readonly MissionClaim TestMission =
        new(Ps, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

    private static AAuthGovernanceClient BuildFacade(HttpMessageHandler handler)
        => new(
            new InProcessHttpClient(handler) { BaseAddress = new Uri(Ps) },
            new MetadataClient(new InProcessHttpClient(handler)),
            Ps);

    [Fact(DisplayName = "§PS Governance Endpoints — facade exposes all four governance clients")]
    public void Facade_Ctor_ExposesFourClients()
    {
        var facade = BuildFacade(new FacadeHandler());

        Assert.NotNull(facade.Mission);
        Assert.NotNull(facade.Permission);
        Assert.NotNull(facade.Audit);
        Assert.NotNull(facade.Interaction);
    }

    [Fact(DisplayName = "§PS Governance Endpoints — null signed client is rejected")]
    public void Facade_Ctor_NullSignedClient_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new AAuthGovernanceClient(null!, new MetadataClient(), Ps));
    }

    [Fact(DisplayName = "§PS Governance Endpoints — facade clients share one signed channel and work end-to-end")]
    public async Task Facade_SubClients_AreFunctional()
    {
        var handler = new FacadeHandler();
        var facade = BuildFacade(handler);

        var mission = await facade.Mission.ProposeAsync(new MissionProposal("# Plan a trip")
        {
            Tools = new[] { new MissionTool("WebSearch", "Search the web") },
        });
        Assert.Equal("aauth:assistant@agent.example", mission.Agent);

        var permission = await facade.Permission.RequestAsync(
            new PermissionRequest(new MissionAction("SendEmail")) { Mission = TestMission });
        Assert.True(permission.IsGranted);

        await facade.Audit.RecordAsync(new AuditRecord(TestMission, new MissionAction("WebSearch")));
        Assert.True(handler.AuditCalled);

        var answer = await facade.Interaction.AskQuestionAsync("Refundable option?");
        Assert.Equal("Yes, go ahead.", answer);
    }

    [Fact(DisplayName = "§PS Governance Endpoints - BuildGovernance wires an agent-JWT facade")]
    public void BuildGovernance_WithSigningMode_ReturnsWiredFacade()
    {
        using var facade = AAuthClientBuilder.SelfIssuing(AAuthKey.Generate())
            .As("https://agent.example", "aauth:assistant@agent.example")
            .WithPersonServer(Ps)
            .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(new FacadeHandler(), AAuth.Discovery.AAuthTransportContract.InProcessOnly)
            .BuildGovernance();

        Assert.NotNull(facade.Mission);
        Assert.NotNull(facade.Permission);
        Assert.NotNull(facade.Audit);
        Assert.NotNull(facade.Interaction);
    }

    [Fact(DisplayName = "§PS Governance Endpoints - BuildGovernance requires an agent JWT source")]
    public void BuildGovernance_NoSigningMode_Throws()
    {
        var builder = new AAuthClientBuilder(AAuthKey.Generate());

        var ex = Assert.Throws<InvalidOperationException>(() => builder.BuildGovernance());
        Assert.Contains("agent JWT source", ex.Message);
    }

    [Theory]
    [InlineData("completion")]
    [InlineData("/permission")]
    [InlineData("/audit")]
    [InlineData("/interaction")]
    [InlineData("callback")]
    [InlineData("clarification-terminal")]
    public async Task Session_TerminationPreventsFurtherActions(string source)
    {
        var handler = new FacadeHandler();
        using var facade = BuildFacade(handler);
        var session = await facade.ProposeMissionAsync(new MissionProposal("Lifecycle"));
        if (source == "completion")
            Assert.True(await session.ProposeCompletionAsync("Done"));
        else
        {
            handler.TerminalPath = source;
            await Assert.ThrowsAsync<AAuthMissionTerminatedException>(() => source switch
            {
                "/permission" => session.RequestPermissionAsync(new MissionAction("SendEmail")),
                "/audit" => session.RecordAuditAsync(new MissionAction("WebSearch")),
                "callback" => session.AskQuestionAsync("Continue?", options: new GovernanceOptions
                {
                    OnInteractionRequired = (_, _) => throw new AAuthMissionTerminatedException("terminated"),
                }),
                "clarification-terminal" => session.AskQuestionAsync("Continue?", options: new GovernanceOptions
                {
                    OnClarificationRequired = (_, _) => Task.FromResult(ClarificationResponse.Respond("Continue")),
                }),
                _ => session.AskQuestionAsync("Continue?"),
            });
        }
        Assert.Equal(MissionState.Terminated, session.Mission.State);
        var calls = handler.Calls;
        await Assert.ThrowsAsync<AAuthMissionTerminatedException>(() => session.RequestPermissionAsync(new MissionAction("WebSearch")));
        await Assert.ThrowsAsync<AAuthMissionTerminatedException>(() => session.RecordAuditAsync(new MissionAction("WebSearch")));
        await Assert.ThrowsAsync<AAuthMissionTerminatedException>(() => session.AskQuestionAsync("Again?"));
        await Assert.ThrowsAsync<AAuthMissionTerminatedException>(() => session.RelayInteractionAsync(Ps + "/consent", "CODE"));
        await Assert.ThrowsAsync<AAuthMissionTerminatedException>(() => session.RelayPaymentAsync(Ps + "/pay", "CODE"));
        await Assert.ThrowsAsync<AAuthMissionTerminatedException>(() => session.ProposeCompletionAsync("Again"));
        Assert.Equal(calls, handler.Calls);
    }

    /// <summary>Minimal PS mock serving the governance endpoints for the facade.</summary>
    private sealed class FacadeHandler : HttpMessageHandler
    {
        public bool AuditCalled { get; private set; }
        public string? TerminalPath { get; set; }
        public int Calls { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            Calls++;
            var path = request.RequestUri!.AbsolutePath;

            if (TerminalPath == "clarification-terminal")
            {
                if (request.Method == HttpMethod.Post && path == "/pending")
                    return Json(HttpStatusCode.Forbidden, new JsonObject { ["error"] = "mission_terminated", ["mission_status"] = "terminated" });
                var pending = Json(HttpStatusCode.Accepted, new JsonObject { ["status"] = "pending", ["clarification"] = "Continue?" });
                pending.Headers.Location = new Uri(Ps + "/pending");
                pending.Headers.TryAddWithoutValidation("AAuth-Requirement", "requirement=clarification");
                return pending;
            }
            if (path == TerminalPath)
                return Json(HttpStatusCode.Forbidden, new JsonObject { ["error"] = "mission_terminated", ["mission_status"] = "terminated" });
            if (TerminalPath == "callback" && path == "/interaction")
            {
                var pending = Json(HttpStatusCode.Accepted, new JsonObject { ["status"] = "pending" });
                pending.Headers.Location = new Uri(Ps + "/pending");
                pending.Headers.TryAddWithoutValidation("AAuth-Requirement", $"requirement=interaction; url=\"{Ps}/consent\"; code=\"CODE\"");
                return pending;
            }

            if (path == "/.well-known/aauth-person.json")
            {
                return Json(HttpStatusCode.OK, new JsonObject
                {
                    ["issuer"] = Ps,
                    ["jwks_uri"] = Ps + "/jwks",
                    ["auth_token_endpoint"] = Ps + "/token",
                    ["mission_endpoint"] = Ps + "/mission",
                    ["permission_endpoint"] = Ps + "/permission",
                    ["audit_endpoint"] = Ps + "/audit",
                    ["interaction_endpoint"] = Ps + "/interaction",
                });
            }

            switch (path)
            {
                case "/mission":
                {
                    var blob = new JsonObject
                    {
                        ["approver"] = Ps,
                        ["agent"] = "aauth:assistant@agent.example",
                        ["approved_at"] = "2026-04-07T14:30:00Z",
                        ["description"] = "# Plan a trip",
                        ["approved_tools"] = new JsonArray
                        {
                            new JsonObject { ["name"] = "WebSearch", ["description"] = "Search the web" },
                        },
                    };
                    var bytes = Encoding.UTF8.GetBytes(blob.ToJsonString());
                    var s256 = Base64UrlEncoder.Encode(SHA256.HashData(bytes));
                    var resp = new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new ByteArrayContent(bytes),
                    };
                    resp.Content.Headers.ContentType =
                        new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
                    resp.Headers.TryAddWithoutValidation(
                        "AAuth-Mission", $"approver=\"{Ps}\"; s256=\"{s256}\"");
                    return resp;
                }

                case "/permission":
                    return Json(HttpStatusCode.OK, new JsonObject { ["permission"] = "granted" });

                case "/audit":
                    AuditCalled = true;
                    return new HttpResponseMessage(HttpStatusCode.Created);

                case "/interaction":
                {
                    var body = JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct))?.AsObject();
                    return (string?)body?["type"] == "question"
                        ? Json(HttpStatusCode.OK, new JsonObject { ["answer"] = "Yes, go ahead." })
                        : new HttpResponseMessage(HttpStatusCode.OK);
                }

                default:
                    return new HttpResponseMessage(HttpStatusCode.NotFound);
            }
        }

        private static HttpResponseMessage Json(HttpStatusCode status, JsonObject body)
            => new(status)
            {
                Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
            };
    }
}
