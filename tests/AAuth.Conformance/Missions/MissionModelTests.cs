using System;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using AAuth.Agent;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Conformance.Missions;

/// <summary>
/// Conformance tests for the mission blob model and the approval envelope
/// (§Mission Approval, §Mission Management).
/// </summary>
public class MissionModelTests
{
    private const string Ps = "https://ps.example";

    private const string Blob = """
        {
          "agent": "aauth:assistant@agent.example",
          "approved_at": "2026-04-07T14:30:00Z",
          "description": "# Plan Japan Vacation\n\nPlan and book a trip.",
          "approved_tools": [
            { "name": "WebSearch", "description": "Search the web" },
            { "name": "Read", "description": "Read files and web pages" }
          ],
          "approved_resources": [ "https://trips.example" ]
        }
        """;

    private static byte[] Envelope(string blob, JsonObject? extra = null)
    {
        var bytes = Encoding.UTF8.GetBytes(blob);
        var envelope = new JsonObject
        {
            ["s256"] = Mission.ComputeS256(bytes),
            ["mission"] = Base64UrlEncoder.Encode(bytes),
        };
        foreach (var (name, value) in extra ?? new JsonObject()) envelope[name] = value?.DeepClone();
        return Encoding.UTF8.GetBytes(envelope.ToJsonString());
    }

    [Fact(DisplayName = "§Mission Approval — mission blob parses required fields")]
    public void FromBlob_ParsesRequiredFields()
    {
        var mission = Mission.FromBlob(Encoding.UTF8.GetBytes(Blob), Ps);

        Assert.Equal(Ps, mission.PersonServer);
        Assert.Equal("aauth:assistant@agent.example", mission.Agent);
        Assert.Equal(
            new DateTimeOffset(2026, 4, 7, 14, 30, 0, TimeSpan.Zero),
            mission.ApprovedAt);
        Assert.StartsWith("# Plan Japan Vacation", mission.Description);
        Assert.Equal(new[] { "https://trips.example" }, mission.ApprovedResources.ToArray());
    }

    [Fact(DisplayName = "§Mission Approval — approved_tools parse into MissionTool list")]
    public void FromBlob_ParsesApprovedTools()
    {
        var mission = Mission.FromBlob(Encoding.UTF8.GetBytes(Blob), Ps);

        Assert.Equal(2, mission.ApprovedTools.Count);
        Assert.Equal("WebSearch", mission.ApprovedTools[0].Name);
        Assert.Equal("Search the web", mission.ApprovedTools[0].Description);
        Assert.Equal("Read", mission.ApprovedTools[1].Name);
    }

    [Fact(DisplayName = "§Mission Approval — envelope capabilities and person_tokens are session members, not blob fields")]
    public void FromApprovalResponse_ParsesSessionMembers()
    {
        var mission = Mission.FromApprovalResponse(Envelope(Blob, new JsonObject
        {
            ["capabilities"] = new JsonArray("interaction", "payment"),
            ["person_tokens"] = new JsonObject { ["https://trips.example"] = "person.token.value" },
        }), Ps);

        Assert.Equal(new[] { "interaction", "payment" }, mission.Capabilities.ToArray());
        Assert.Equal("person.token.value", mission.PersonTokens["https://trips.example"]);
        // The digest covers the blob only.
        Assert.Equal(Mission.ComputeS256(Encoding.UTF8.GetBytes(Blob)), mission.S256);
    }

    [Fact(DisplayName = "§Mission Management — a new mission defaults to active state")]
    public void FromBlob_DefaultsToActive()
    {
        var mission = Mission.FromBlob(Encoding.UTF8.GetBytes(Blob), Ps);

        Assert.Equal(MissionState.Active, mission.State);
    }

    [Fact(DisplayName = "§Mission Approval — optional fields default to empty when absent")]
    public void FromApprovalResponse_OptionalFieldsDefaultEmpty()
    {
        const string minimal = """
            {
              "agent": "aauth:assistant@agent.example",
              "approved_at": "2026-04-07T14:30:00Z",
              "description": "Minimal mission"
            }
            """;

        var mission = Mission.FromApprovalResponse(Envelope(minimal), Ps);

        Assert.Empty(mission.ApprovedTools);
        Assert.Empty(mission.ApprovedResources);
        Assert.Empty(mission.Capabilities);
        Assert.Empty(mission.PersonTokens);
        Assert.Null(mission.ExpiresAt);
    }

    [Theory(DisplayName = "§Mission Approval — missing required field throws")]
    [InlineData("{ \"approved_at\": \"2026-04-07T14:30:00Z\", \"description\": \"d\" }")]
    [InlineData("{ \"agent\": \"a\", \"description\": \"d\" }")]
    [InlineData("{ \"agent\": \"a\", \"approved_at\": \"2026-04-07T14:30:00Z\" }")]
    [InlineData("{ \"agent\": \"a\", \"approved_at\": \"2026-04-07T14:30:00Z\", \"description\": \"d\", \"expires_at\": \"not-a-date\" }")]
    public void FromBlob_MissingRequiredField_Throws(string body)
    {
        Assert.Throws<InvalidOperationException>(
            () => Mission.FromBlob(Encoding.UTF8.GetBytes(body), Ps));
    }

    [Fact(DisplayName = "§Mission Approval — empty blob throws")]
    public void FromBlob_EmptyBody_Throws()
    {
        Assert.Throws<ArgumentException>(() => Mission.FromBlob(ReadOnlySpan<byte>.Empty, Ps));
    }
}
