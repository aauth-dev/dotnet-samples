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
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Conformance.Missions;

/// <summary>
/// Conformance for the bound governance client and <see cref="MissionSession"/>
/// (AAuth protocol §Mission Creation, §Mission Approval, §Permission Endpoint,
/// §Audit Endpoint, §Interaction Endpoint). A client bound to a Person Server
/// exposes <see cref="AAuthGovernanceClient.ProposeMissionAsync"/>, which returns a
/// session that auto-threads the mission claim (<c>{approver, s256}</c>) and PS
/// into every subsequent governed call.
/// </summary>
public class GovernanceClientBuilderTests
{
    private const string Ps = "http://localhost:5557";

    private static AAuthGovernanceClient BuildBound(SessionHandler handler)
        => AAuthGovernanceClient.Create(
            new HttpClient(handler) { BaseAddress = new Uri(Ps) },
            new MetadataClient(new HttpClient(handler)),
            personServer: Ps);

    [Fact(DisplayName = "§Mission Creation — Create factory binds the Person Server")]
    public void Create_BindsPersonServer()
    {
        var client = BuildBound(new SessionHandler());
        Assert.Equal(Ps, client.PersonServer);
    }

    [Fact(DisplayName = "§Mission Creation — BuildGovernance binds WithPersonServer URL")]
    public void BuildGovernance_BindsPersonServer()
    {
        var client = new AAuthClientBuilder(AAuthKey.Generate())
            .UseHwk()
            .WithPersonServer(Ps)
            .WithInnerHandler(new SessionHandler())
            .BuildGovernance();

        Assert.Equal(Ps, client.PersonServer);
    }

    [Fact(DisplayName = "§Mission Creation — ProposeMissionAsync requires a bound PS")]
    public async Task ProposeMissionAsync_Unbound_Throws()
    {
        var unbound = new AAuthGovernanceClient(
            new HttpClient(new SessionHandler()) { BaseAddress = new Uri(Ps) },
            new MetadataClient(new HttpClient(new SessionHandler())));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => unbound.ProposeMissionAsync(new MissionProposal("# Plan")));
        Assert.Contains("bound Person Server", ex.Message);
    }

    [Fact(DisplayName = "§Mission Approval — ProposeMissionAsync returns a session over the approved mission")]
    public async Task ProposeMissionAsync_ReturnsSession()
    {
        var client = BuildBound(new SessionHandler());

        var session = await client.ProposeMissionAsync(new MissionProposal("# Plan a trip")
        {
            Tools = new[] { new MissionTool("WebSearch", "Search the web") },
        });

        Assert.Equal(Ps, session.PersonServer);
        Assert.Equal("aauth:assistant@agent.example", session.Mission.Agent);
        Assert.NotEmpty(session.Mission.S256);
    }

    [Fact(DisplayName = "§Permission Endpoint — session threads the mission claim into permission requests")]
    public async Task Session_Permission_ThreadsMissionClaim()
    {
        var handler = new SessionHandler();
        var client = BuildBound(handler);
        var session = await client.ProposeMissionAsync(new MissionProposal("# Plan a trip"));

        var result = await session.RequestPermissionAsync("SendEmail");

        Assert.True(result.IsGranted);
        Assert.Equal(session.Mission.S256, (string?)handler.LastPermissionBody?["mission"]?["s256"]);
        Assert.Equal(Ps, (string?)handler.LastPermissionBody?["mission"]?["approver"]);
    }

    [Fact(DisplayName = "§Permission Endpoint — a pre-approved tool short-circuits to granted")]
    public async Task Session_Permission_PreApprovedTool_ShortCircuits()
    {
        var handler = new SessionHandler();
        var client = BuildBound(handler);
        var session = await client.ProposeMissionAsync(new MissionProposal("# Plan a trip")
        {
            Tools = new[] { new MissionTool("WebSearch", "Search the web") },
        });

        var result = await session.RequestPermissionAsync("WebSearch");

        Assert.True(result.IsGranted);
        // Pre-approved tools never reach the PS permission endpoint.
        Assert.Null(handler.LastPermissionBody);
    }

    [Fact(DisplayName = "§Audit Endpoint — session threads the mission claim into audit records")]
    public async Task Session_Audit_ThreadsMissionClaim()
    {
        var handler = new SessionHandler();
        var client = BuildBound(handler);
        var session = await client.ProposeMissionAsync(new MissionProposal("# Plan a trip"));

        await session.RecordAuditAsync("WebSearch", description: "Looked up flights");

        Assert.Equal(session.Mission.S256, (string?)handler.LastAuditBody?["mission"]?["s256"]);
        Assert.Equal("WebSearch", (string?)handler.LastAuditBody?["action"]);
    }

    [Fact(DisplayName = "§Interaction Endpoint — session asks a question and returns the answer")]
    public async Task Session_AskQuestion_ReturnsAnswer()
    {
        var handler = new SessionHandler();
        var client = BuildBound(handler);
        var session = await client.ProposeMissionAsync(new MissionProposal("# Plan a trip"));

        var answer = await session.AskQuestionAsync("Refundable option?");

        Assert.Equal("Yes, go ahead.", answer);
        Assert.Equal(session.Mission.S256, (string?)handler.LastInteractionBody?["mission"]?["s256"]);
    }

    [Fact(DisplayName = "§Interaction Endpoint — session proposes completion and observes termination")]
    public async Task Session_ProposeCompletion_Terminates()
    {
        var handler = new SessionHandler();
        var client = BuildBound(handler);
        var session = await client.ProposeMissionAsync(new MissionProposal("# Plan a trip"));

        var terminated = await session.ProposeCompletionAsync("All booked.");

        Assert.True(terminated);
        Assert.Equal("completion", (string?)handler.LastInteractionBody?["type"]);
    }

    /// <summary>PS mock that serves the governance endpoints and captures request bodies.</summary>
    private sealed class SessionHandler : HttpMessageHandler
    {
        public JsonObject? LastPermissionBody { get; private set; }
        public JsonObject? LastAuditBody { get; private set; }
        public JsonObject? LastInteractionBody { get; private set; }

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
                    var proposal = await ReadBody(request, ct);
                    var description = (string?)proposal?["description"] ?? "# Mission";
                    var tools = proposal?["tools"] as JsonArray ?? new JsonArray();
                    var blob = new JsonObject
                    {
                        ["approver"] = Ps,
                        ["agent"] = "aauth:assistant@agent.example",
                        ["approved_at"] = "2026-04-07T14:30:00Z",
                        ["description"] = description,
                        ["approved_tools"] = tools.DeepClone(),
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
                    LastPermissionBody = await ReadBody(request, ct);
                    return Json(HttpStatusCode.OK, new JsonObject { ["permission"] = "granted" });

                case "/audit":
                    LastAuditBody = await ReadBody(request, ct);
                    return new HttpResponseMessage(HttpStatusCode.Created);

                case "/interaction":
                {
                    LastInteractionBody = await ReadBody(request, ct);
                    var type = (string?)LastInteractionBody?["type"];
                    return type switch
                    {
                        "question" => Json(HttpStatusCode.OK, new JsonObject { ["answer"] = "Yes, go ahead." }),
                        "completion" => Json(HttpStatusCode.OK, new JsonObject { ["mission_status"] = "terminated" }),
                        _ => new HttpResponseMessage(HttpStatusCode.OK),
                    };
                }

                default:
                    return new HttpResponseMessage(HttpStatusCode.NotFound);
            }
        }

        private static async Task<JsonObject?> ReadBody(HttpRequestMessage request, CancellationToken ct)
        {
            if (request.Content is null)
            {
                return null;
            }
            var raw = await request.Content.ReadAsStringAsync(ct);
            return string.IsNullOrWhiteSpace(raw) ? null : JsonNode.Parse(raw) as JsonObject;
        }

        private static HttpResponseMessage Json(HttpStatusCode status, JsonObject body)
            => new(status)
            {
                Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
            };
    }
}
