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

    private const string TestMissionS256 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    private static Mission ApprovedMission(IReadOnlyList<MissionTool>? tools = null, MissionState state = MissionState.Active) => new()
    {
        PersonServer = Ps,
        Agent = "aauth:assistant@agent.example",
        ApprovedAt = DateTimeOffset.UtcNow,
        Description = "x",
        S256 = TestMissionS256,
        State = state,
        ApprovedTools = tools ?? Array.Empty<MissionTool>(),
    };

    private static (HttpClient signed, MetadataClient metadata) Build(HttpMessageHandler handler)
        => (new InProcessHttpClient(handler) { BaseAddress = new Uri(Ps) },
            new MetadataClient(new InProcessHttpClient(handler)));

    // ---- §Person Server Metadata ----

    [Fact(DisplayName = "§Person Server Metadata — all four governance endpoints are parsed")]
    public void ServerMetadata_ParsesGovernanceEndpoints()
    {
        var doc = new JsonObject
        {
            ["issuer"] = Ps,
            ["jwks_uri"] = Ps + "/jwks",
            ["auth_token_endpoint"] = Ps + "/token",
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
        Assert.Equal(Ps, mission.PersonServer);
        Assert.Single(mission.ApprovedTools);
        Assert.Equal("WebSearch", mission.ApprovedTools[0].Name);
        Assert.True(mission.VerifyS256(handler.MissionS256));
        Assert.Equal(new[] { "interaction" }, mission.Capabilities);
    }

    [Fact(DisplayName = "§Mission Approval — envelope s256 mismatch throws")]
    public async Task MissionClient_S256Mismatch_Throws()
    {
        var handler = new GovernanceHandler { Envelope = "tampered-s256" };
        var (signed, metadata) = Build(handler);
        var client = new MissionClient(signed, metadata, Ps);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.ProposeAsync(new MissionProposal("# Plan a trip")));
    }

    [Theory(DisplayName = "§Mission Approval — a malformed approval envelope throws")]
    [InlineData("missing-s256")]
    [InlineData("missing-mission")]
    [InlineData("mission-not-base64url")]
    [InlineData("not-an-object")]
    public async Task MissionClient_MalformedApprovalEnvelope_Throws(string envelope)
    {
        var handler = new GovernanceHandler { Envelope = envelope };
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
                PollerOptions = new DeferredPollerOptions
                {
                    DefaultPollInterval = TimeSpan.Zero,
                    MinPollInterval = TimeSpan.Zero,
                },
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
            MissionS256 = TestMissionS256,
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

        var mission = ApprovedMission(new[] { new MissionTool("WebSearch") });

        var result = await client.RequestAsync(new MissionAction("WebSearch"), mission);

        Assert.True(result.IsGranted);
        Assert.False(handler.PermissionCalled);
    }

    [Theory]
    [InlineData("WebSearch")]
    [InlineData("SendEmail")]
    public async Task PermissionClient_TerminatedMissionNeverGrants(string action)
    {
        var handler = new GovernanceHandler();
        var (signed, metadata) = Build(handler);
        var client = new PermissionClient(signed, metadata, Ps);
        var mission = ApprovedMission(new[] { new MissionTool("WebSearch") }, MissionState.Terminated);
        await Assert.ThrowsAsync<AAuthMissionTerminatedException>(() => client.RequestAsync(new MissionAction(action), mission));
        Assert.False(handler.PermissionCalled);
    }

    [Fact(DisplayName = "§Mission Status Errors — permission 403 mission_terminated throws")]
    public async Task PermissionClient_MissionTerminated_Throws()
    {
        var handler = new GovernanceHandler { MissionTerminated = true };
        var (signed, metadata) = Build(handler);
        var client = new PermissionClient(signed, metadata, Ps);

        var ex = await Assert.ThrowsAsync<AAuthMissionTerminatedException>(() =>
            client.RequestAsync(new PermissionRequest(new MissionAction("SendEmail")) { MissionS256 = TestMissionS256 }));

        Assert.Equal("terminated", ex.MissionStatus);
    }

    // ---- §Audit Endpoint ----

    [Fact(DisplayName = "§Audit Response — 201 acknowledges the record")]
    public async Task AuditClient_Records()
    {
        var handler = new GovernanceHandler();
        var (signed, metadata) = Build(handler);
        var client = new AuditClient(signed, metadata, Ps);

        await client.RecordAsync(new AuditRecord(TestMissionS256, new MissionAction("WebSearch"))
        {
            Description = "Searched for flights",
        });

        Assert.True(handler.AuditCalled);
        Assert.Equal(TestMissionS256, (string?)handler.LastAuditBody!["mission_s256"]);
        Assert.Null(handler.LastAuditBody["mission"]);
    }

    [Fact(DisplayName = "§Mission Status Errors — audit 403 mission_terminated throws")]
    public async Task AuditClient_MissionTerminated_Throws()
    {
        var handler = new GovernanceHandler { MissionTerminated = true };
        var (signed, metadata) = Build(handler);
        var client = new AuditClient(signed, metadata, Ps);

        await Assert.ThrowsAsync<AAuthMissionTerminatedException>(() =>
            client.RecordAsync(new AuditRecord(TestMissionS256, new MissionAction("WebSearch"))));
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
            client.RecordAsync(new AuditRecord(TestMissionS256, new MissionAction("WebSearch"))));
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

    [Fact(DisplayName = "§Mission Completion — completion is posted to {mission_endpoint}/{s256} and terminates the mission")]
    public async Task MissionClient_Completion_Terminates()
    {
        var handler = new GovernanceHandler();
        var (signed, metadata) = Build(handler);
        var client = new MissionClient(signed, metadata, Ps);

        var terminated = await client.CompleteAsync(ApprovedMission(), "# Done");

        Assert.True(terminated);
        Assert.Equal("/mission/" + TestMissionS256, handler.LastMissionActionPath);
        Assert.Equal("completion", (string?)handler.LastMissionActionBody!["action"]);
        Assert.Equal("# Done", (string?)handler.LastMissionActionBody["summary"]);
    }

    [Fact(DisplayName = "§Mission Completion — a declined completion leaves the mission active")]
    public async Task MissionClient_CompletionDeclined_StaysActive()
    {
        var handler = new GovernanceHandler { CompletionStatus = "active" };
        var (signed, metadata) = Build(handler);
        var client = new MissionClient(signed, metadata, Ps);

        Assert.False(await client.CompleteAsync(ApprovedMission(), "# Done"));
    }

    [Fact(DisplayName = "§Mission Update — update is posted to {mission_endpoint}/{s256} and returns the update s256")]
    public async Task MissionClient_Update_ReturnsS256()
    {
        var handler = new GovernanceHandler();
        var (signed, metadata) = Build(handler);
        var client = new MissionClient(signed, metadata, Ps);

        var s256 = await client.UpdateAsync(ApprovedMission(), "Also book a hotel.");

        Assert.Equal("update-s256", s256);
        Assert.Equal("/mission/" + TestMissionS256, handler.LastMissionActionPath);
        Assert.Equal("update", (string?)handler.LastMissionActionBody!["action"]);
        Assert.Equal("Also book a hotel.", (string?)handler.LastMissionActionBody["description"]);
    }

    [Fact(DisplayName = "§Mission Status Errors — a mission action on a terminated mission throws")]
    public async Task MissionClient_ActionOnTerminatedMission_Throws()
    {
        var handler = new GovernanceHandler { MissionTerminated = true };
        var (signed, metadata) = Build(handler);
        var client = new MissionClient(signed, metadata, Ps);

        await Assert.ThrowsAsync<AAuthMissionTerminatedException>(() =>
            client.UpdateAsync(ApprovedMission(), "More work"));
    }

    /// <summary>Configurable PS mock for the governance endpoints.</summary>
    private sealed class GovernanceHandler : HttpMessageHandler
    {
        public bool PermissionDenied { get; init; }
        public bool MissionTerminated { get; init; }
        public string? Envelope { get; init; }
        public bool MissionNeedsClarification { get; init; }
        public HttpStatusCode AuditStatus { get; init; } = HttpStatusCode.Created;
        public string CompletionStatus { get; init; } = "terminated";

        public bool PermissionCalled { get; private set; }
        public bool AuditCalled { get; private set; }
        public JsonObject? LastAuditBody { get; private set; }
        public string? LastInteractionType { get; private set; }
        public string? LastClarificationResponse { get; private set; }
        public string? LastMissionActionPath { get; private set; }
        public JsonObject? LastMissionActionBody { get; private set; }
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
                    ["auth_token_endpoint"] = Ps + "/token",
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
                case not null when path.StartsWith("/mission/", StringComparison.Ordinal):
                {
                    LastMissionActionPath = path;
                    LastMissionActionBody = JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct))?.AsObject();
                    return (string?)LastMissionActionBody?["action"] == "update"
                        ? Json(HttpStatusCode.OK, new JsonObject { ["s256"] = "update-s256" })
                        : Json(HttpStatusCode.OK, new JsonObject { ["mission_status"] = CompletionStatus });
                }

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
                    // §Mission Approval: the envelope carries the blob base64url-encoded
                    // and its s256 = SHA-256 over the exact blob bytes.
                    var blob = new JsonObject
                    {
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
                    var envelope = new JsonObject
                    {
                        ["s256"] = Envelope == "tampered-s256" ? "tampered-value" : MissionS256,
                        ["mission"] = Envelope == "mission-not-base64url" ? "%%%" : Base64UrlEncoder.Encode(bytes),
                        ["capabilities"] = new JsonArray("interaction"),
                    };
                    if (Envelope == "missing-s256") envelope.Remove("s256");
                    if (Envelope == "missing-mission") envelope.Remove("mission");
                    var resp = new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(Envelope == "not-an-object" ? "[]" : envelope.ToJsonString(),
                            Encoding.UTF8, "application/json"),
                    };
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
                    LastAuditBody = JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct))?.AsObject();
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
