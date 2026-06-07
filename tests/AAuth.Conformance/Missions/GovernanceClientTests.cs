using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Agent.Governance;
using AAuth.Discovery;
using AAuth.Errors;
using AAuth.Headers;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Conformance.Missions;

/// <summary>
/// Conformance for the agent-side PS governance clients (AAuth protocol
/// §PS Governance Endpoints, §Mission Creation, §Permission Endpoint,
/// §Audit Endpoint, §Interaction Endpoint, §Person Server Metadata).
/// </summary>
public class GovernanceClientTests
{
    private const string Ps = "http://localhost:5555";

    private static readonly MissionClaim TestMission =
        new("http://localhost:5555", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

    private static (HttpClient signed, MetadataClient metadata) Build(HttpMessageHandler handler)
        => (new HttpClient(handler) { BaseAddress = new Uri(Ps) },
            new MetadataClient(new HttpClient(handler)));

    // ---- §Person Server Metadata ----

    [Fact(DisplayName = "§Person Server Metadata — all four governance endpoints are parsed")]
    public void ServerMetadata_ParsesGovernanceEndpoints()
    {
        var doc = new JsonObject
        {
            ["issuer"] = Ps,
            ["jwks_uri"] = Ps + "/jwks",
            ["token_endpoint"] = Ps + "/token",
            ["mission_endpoint"] = Ps + "/mission",
            ["permission_endpoint"] = Ps + "/permission",
            ["audit_endpoint"] = Ps + "/audit",
            ["interaction_endpoint"] = Ps + "/interaction",
        };

        var metadata = ServerMetadata.FromJson(doc);

        Assert.Equal(Ps + "/mission", metadata.MissionEndpoint);
        Assert.Equal(Ps + "/permission", metadata.PermissionEndpoint);
        Assert.Equal(Ps + "/audit", metadata.AuditEndpoint);
        Assert.Equal(Ps + "/interaction", metadata.InteractionEndpoint);
    }

    // ---- §Mission Creation / §Mission Approval ----

    [Fact(DisplayName = "§Mission Approval — ProposeAsync returns an approved mission and verifies s256")]
    public async Task MissionClient_Propose_ReturnsApprovedMission()
    {
        var handler = new GovernanceHandler();
        var (signed, metadata) = Build(handler);
        var client = new MissionClient(signed, metadata, Ps);

        var mission = await client.ProposeAsync(new MissionProposal("# Plan a trip")
        {
            Tools = new[] { new MissionTool("WebSearch", "Search the web") },
        });

        Assert.Equal("aauth:assistant@agent.example", mission.Agent);
        Assert.Single(mission.ApprovedTools);
        Assert.Equal("WebSearch", mission.ApprovedTools[0].Name);
        Assert.True(mission.VerifyS256(handler.MissionS256));
    }

    [Fact(DisplayName = "§Mission Approval — s256 header mismatch throws")]
    public async Task MissionClient_S256Mismatch_Throws()
    {
        var handler = new GovernanceHandler { TamperMissionHeaderS256 = true };
        var (signed, metadata) = Build(handler);
        var client = new MissionClient(signed, metadata, Ps);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.ProposeAsync(new MissionProposal("# Plan a trip")));
    }

    [Fact(DisplayName = "§Mission Creation — 202 clarification review resolves to an approved mission")]
    public async Task MissionClient_ClarificationReview_ResolvesToMission()
    {
        var handler = new GovernanceHandler { MissionNeedsClarification = true };
        var (signed, metadata) = Build(handler);
        var client = new MissionClient(signed, metadata, Ps);

        ClarificationRequirement? seen = null;
        var mission = await client.ProposeAsync(new MissionProposal("# Plan a trip"),
            new GovernanceOptions
            {
                OnClarificationRequired = (clarification, _) =>
                {
                    seen = clarification;
                    return Task.FromResult(ClarificationResponse.Respond("2 adults, $5k budget."));
                },
            });

        Assert.NotNull(seen);
        Assert.Equal("aauth:assistant@agent.example", mission.Agent);
        Assert.Equal("2 adults, $5k budget.", handler.LastClarificationResponse);
    }

    // ---- §Permission Endpoint ----

    [Fact(DisplayName = "§Permission Response — granted is parsed")]
    public async Task PermissionClient_Granted()
    {
        var handler = new GovernanceHandler();
        var (signed, metadata) = Build(handler);
        var client = new PermissionClient(signed, metadata, Ps);

        var result = await client.RequestAsync(new PermissionRequest(new MissionAction("SendEmail"))
        {
            Description = "Send the itinerary",
            Mission = TestMission,
        });

        Assert.True(result.IsGranted);
    }

    [Fact(DisplayName = "§Permission Response — denied carries a reason")]
    public async Task PermissionClient_Denied()
    {
        var handler = new GovernanceHandler { PermissionDenied = true };
        var (signed, metadata) = Build(handler);
        var client = new PermissionClient(signed, metadata, Ps);

        var result = await client.RequestAsync(new PermissionRequest(new MissionAction("DeleteAll")));

        Assert.Equal(PermissionGrant.Denied, result.Grant);
        Assert.Equal("Out of scope.", result.Reason);
    }

    [Fact(DisplayName = "§Permission Endpoint — approved_tools short-circuit avoids the PS call")]
    public async Task PermissionClient_ApprovedTool_ShortCircuits()
    {
        var handler = new GovernanceHandler();
        var (signed, metadata) = Build(handler);
        var client = new PermissionClient(signed, metadata, Ps);

        var mission = new Mission
        {
            Approver = Ps,
            Agent = "aauth:assistant@agent.example",
            ApprovedAt = DateTimeOffset.UtcNow,
            Description = "x",
            S256 = "abc",
            ApprovedTools = new[] { new MissionTool("WebSearch") },
        };

        var result = await client.RequestAsync(new MissionAction("WebSearch"), mission);

        Assert.True(result.IsGranted);
        Assert.False(handler.PermissionCalled);
    }

    [Fact(DisplayName = "§Mission Status Errors — permission 403 mission_terminated throws")]
    public async Task PermissionClient_MissionTerminated_Throws()
    {
        var handler = new GovernanceHandler { MissionTerminated = true };
        var (signed, metadata) = Build(handler);
        var client = new PermissionClient(signed, metadata, Ps);

        var ex = await Assert.ThrowsAsync<AAuthMissionTerminatedException>(() =>
            client.RequestAsync(new PermissionRequest(new MissionAction("SendEmail")) { Mission = TestMission }));

        Assert.Equal("terminated", ex.MissionStatus);
    }

    // ---- §Audit Endpoint ----

    [Fact(DisplayName = "§Audit Response — 201 acknowledges the record")]
    public async Task AuditClient_Records()
    {
        var handler = new GovernanceHandler();
        var (signed, metadata) = Build(handler);
        var client = new AuditClient(signed, metadata, Ps);

        await client.RecordAsync(new AuditRecord(TestMission, new MissionAction("WebSearch"))
        {
            Description = "Searched for flights",
        });

        Assert.True(handler.AuditCalled);
    }

    [Fact(DisplayName = "§Mission Status Errors — audit 403 mission_terminated throws")]
    public async Task AuditClient_MissionTerminated_Throws()
    {
        var handler = new GovernanceHandler { MissionTerminated = true };
        var (signed, metadata) = Build(handler);
        var client = new AuditClient(signed, metadata, Ps);

        await Assert.ThrowsAsync<AAuthMissionTerminatedException>(() =>
            client.RecordAsync(new AuditRecord(TestMission, new MissionAction("WebSearch"))));
    }

    [Fact(DisplayName = "§Audit Response — a non-201 acknowledgment is rejected (F3)")]
    public async Task AuditClient_Non201_Throws()
    {
        // The spec requires the PS to acknowledge with 201 Created; a 200 OK
        // (or any other 2xx) must not be treated as success.
        var handler = new GovernanceHandler { AuditStatus = HttpStatusCode.OK };
        var (signed, metadata) = Build(handler);
        var client = new AuditClient(signed, metadata, Ps);

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            client.RecordAsync(new AuditRecord(TestMission, new MissionAction("WebSearch"))));
    }

    // ---- §Interaction Endpoint ----

    [Fact(DisplayName = "§Interaction Response — question returns the user's answer")]
    public async Task InteractionClient_Question_ReturnsAnswer()
    {
        var handler = new GovernanceHandler();
        var (signed, metadata) = Build(handler);
        var client = new InteractionClient(signed, metadata, Ps);

        var answer = await client.AskQuestionAsync("Refundable option?");

        Assert.Equal("Yes, go ahead.", answer);
    }

    [Fact(DisplayName = "§Interaction Response — completion terminates the mission")]
    public async Task InteractionClient_Completion_Terminates()
    {
        var handler = new GovernanceHandler();
        var (signed, metadata) = Build(handler);
        var client = new InteractionClient(signed, metadata, Ps);

        var terminated = await client.ProposeCompletionAsync("# Done", TestMission);

        Assert.True(terminated);
        Assert.Equal("completion", handler.LastInteractionType);
    }

    /// <summary>Configurable PS mock for the governance endpoints.</summary>
    private sealed class GovernanceHandler : HttpMessageHandler
    {
        public bool PermissionDenied { get; init; }
        public bool MissionTerminated { get; init; }
        public bool TamperMissionHeaderS256 { get; init; }
        public bool MissionNeedsClarification { get; init; }
        public HttpStatusCode AuditStatus { get; init; } = HttpStatusCode.Created;

        public bool PermissionCalled { get; private set; }
        public bool AuditCalled { get; private set; }
        public string? LastInteractionType { get; private set; }
        public string? LastClarificationResponse { get; private set; }
        public string MissionS256 { get; private set; } = "";

        private bool _missionClarified;

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

            if (MissionTerminated)
            {
                return Json(HttpStatusCode.Forbidden, new JsonObject
                {
                    ["error"] = "mission_terminated",
                    ["mission_status"] = "terminated",
                });
            }

            // §Clarification Chat during mission review.
            if (path == "/pending/m" && request.Method == HttpMethod.Post)
            {
                var crBody = JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct))?.AsObject();
                LastClarificationResponse = (string?)crBody?["clarification_response"];
                _missionClarified = true;
                return new HttpResponseMessage(HttpStatusCode.OK);
            }

            switch (path)
            {
                case "/mission" when MissionNeedsClarification && !_missionClarified:
                case "/pending/m" when MissionNeedsClarification && !_missionClarified:
                {
                    var clarify = Json(HttpStatusCode.Accepted, new JsonObject
                    {
                        ["status"] = "pending",
                        ["clarification"] = "How many travelers and what budget?",
                    });
                    clarify.Headers.Location = new Uri(Ps + "/pending/m");
                    clarify.Headers.TryAddWithoutValidation(
                        AAuth.Headers.AAuthRequirementHeader.Name, "requirement=clarification");
                    return clarify;
                }

                case "/mission":
                case "/pending/m":
                {
                    // Return the mission blob verbatim and the AAuth-Mission header
                    // whose s256 is SHA-256 over the exact body bytes (§Mission Approval).
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
                    MissionS256 = Base64UrlEncoder.Encode(SHA256.HashData(bytes));
                    var headerS256 = TamperMissionHeaderS256 ? "tampered-value" : MissionS256;

                    var resp = new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new ByteArrayContent(bytes),
                    };
                    resp.Content.Headers.ContentType =
                        new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
                    resp.Headers.TryAddWithoutValidation(
                        "AAuth-Mission", $"approver=\"{Ps}\"; s256=\"{headerS256}\"");
                    return resp;
                }

                case "/permission":
                {
                    PermissionCalled = true;
                    return PermissionDenied
                        ? Json(HttpStatusCode.OK, new JsonObject
                        {
                            ["permission"] = "denied",
                            ["reason"] = "Out of scope.",
                        })
                        : Json(HttpStatusCode.OK, new JsonObject { ["permission"] = "granted" });
                }

                case "/audit":
                    AuditCalled = true;
                    return new HttpResponseMessage(AuditStatus);

                case "/interaction":
                {
                    var body = JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct))?.AsObject();
                    LastInteractionType = (string?)body?["type"];
                    return LastInteractionType switch
                    {
                        "question" => Json(HttpStatusCode.OK, new JsonObject { ["answer"] = "Yes, go ahead." }),
                        "completion" => new HttpResponseMessage(HttpStatusCode.OK),
                        _ => new HttpResponseMessage(HttpStatusCode.OK),
                    };
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
