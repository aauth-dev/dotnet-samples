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
            new HttpClient(handler) { BaseAddress = new Uri(Ps) },
            new MetadataClient(new HttpClient(handler)),
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
            new AAuthGovernanceClient(null!, new MetadataClient(new HttpClient()), Ps));
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
            new PermissionRequest("SendEmail") { Mission = TestMission });
        Assert.True(permission.IsGranted);

        await facade.Audit.RecordAsync(new AuditRecord(TestMission, "WebSearch"));
        Assert.True(handler.AuditCalled);

        var answer = await facade.Interaction.AskQuestionAsync("Refundable option?");
        Assert.Equal("Yes, go ahead.", answer);
    }

    [Fact(DisplayName = "§PS Governance Endpoints — BuildGovernance wires a facade from a signing mode")]
    public void BuildGovernance_WithSigningMode_ReturnsWiredFacade()
    {
        var facade = new AAuthClientBuilder(AAuthKey.Generate())
            .UseHwk()
            .WithPersonServer(Ps)
            .WithInnerHandler(new FacadeHandler())
            .BuildGovernance();

        Assert.NotNull(facade.Mission);
        Assert.NotNull(facade.Permission);
        Assert.NotNull(facade.Audit);
        Assert.NotNull(facade.Interaction);
    }

    [Fact(DisplayName = "§PS Governance Endpoints — BuildGovernance requires an explicit signing mode")]
    public void BuildGovernance_NoSigningMode_Throws()
    {
        var builder = new AAuthClientBuilder(AAuthKey.Generate());

        var ex = Assert.Throws<InvalidOperationException>(() => builder.BuildGovernance());
        Assert.Contains("signing mode", ex.Message);
    }

    /// <summary>Minimal PS mock serving the governance endpoints for the facade.</summary>
    private sealed class FacadeHandler : HttpMessageHandler
    {
        public bool AuditCalled { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;

            if (path == "/.well-known/aauth-person.json")
            {
                return Json(HttpStatusCode.OK, new JsonObject
                {
                    ["issuer"] = Ps,
                    ["jwks_uri"] = Ps + "/jwks",
                    ["token_endpoint"] = Ps + "/token",
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
