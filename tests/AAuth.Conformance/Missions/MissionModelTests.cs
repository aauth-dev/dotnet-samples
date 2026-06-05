using System;
using System.Linq;
using System.Text;
using AAuth.Agent;
using Xunit;

namespace AAuth.Conformance.Missions;

/// <summary>
/// Conformance tests for the mission blob model (§Mission Approval, §Mission Management).
/// </summary>
public class MissionModelTests
{
    private const string ApprovalBody = """
        {
          "approver": "https://ps.example",
          "agent": "aauth:assistant@agent.example",
          "approved_at": "2026-04-07T14:30:00Z",
          "description": "# Plan Japan Vacation\n\nPlan and book a trip.",
          "approved_tools": [
            { "name": "WebSearch", "description": "Search the web" },
            { "name": "Read", "description": "Read files and web pages" }
          ],
          "capabilities": [ "interaction", "payment" ]
        }
        """;

    [Fact(DisplayName = "§Mission Approval — mission blob parses required fields")]
    public void FromApprovalBytes_ParsesRequiredFields()
    {
        var mission = Mission.FromApprovalBytes(Encoding.UTF8.GetBytes(ApprovalBody));

        Assert.Equal("https://ps.example", mission.Approver);
        Assert.Equal("aauth:assistant@agent.example", mission.Agent);
        Assert.Equal(
            new DateTimeOffset(2026, 4, 7, 14, 30, 0, TimeSpan.Zero),
            mission.ApprovedAt);
        Assert.StartsWith("# Plan Japan Vacation", mission.Description);
    }

    [Fact(DisplayName = "§Mission Approval — approved_tools parse into MissionTool list")]
    public void FromApprovalBytes_ParsesApprovedTools()
    {
        var mission = Mission.FromApprovalBytes(Encoding.UTF8.GetBytes(ApprovalBody));

        Assert.Equal(2, mission.ApprovedTools.Count);
        Assert.Equal("WebSearch", mission.ApprovedTools[0].Name);
        Assert.Equal("Search the web", mission.ApprovedTools[0].Description);
        Assert.Equal("Read", mission.ApprovedTools[1].Name);
    }

    [Fact(DisplayName = "§Mission Approval — capabilities parse into string list")]
    public void FromApprovalBytes_ParsesCapabilities()
    {
        var mission = Mission.FromApprovalBytes(Encoding.UTF8.GetBytes(ApprovalBody));

        Assert.Equal(new[] { "interaction", "payment" }, mission.Capabilities.ToArray());
    }

    [Fact(DisplayName = "§Mission Management — a new mission defaults to active state")]
    public void FromApprovalBytes_DefaultsToActive()
    {
        var mission = Mission.FromApprovalBytes(Encoding.UTF8.GetBytes(ApprovalBody));

        Assert.Equal(MissionState.Active, mission.State);
    }

    [Fact(DisplayName = "§Mission Approval — optional fields default to empty when absent")]
    public void FromApprovalBytes_OptionalFieldsDefaultEmpty()
    {
        const string minimal = """
            {
              "approver": "https://ps.example",
              "agent": "aauth:assistant@agent.example",
              "approved_at": "2026-04-07T14:30:00Z",
              "description": "Minimal mission"
            }
            """;

        var mission = Mission.FromApprovalBytes(Encoding.UTF8.GetBytes(minimal));

        Assert.Empty(mission.ApprovedTools);
        Assert.Empty(mission.Capabilities);
    }

    [Theory(DisplayName = "§Mission Approval — missing required field throws")]
    [InlineData("{ \"agent\": \"a\", \"approved_at\": \"2026-04-07T14:30:00Z\", \"description\": \"d\" }")]
    [InlineData("{ \"approver\": \"https://ps.example\", \"approved_at\": \"2026-04-07T14:30:00Z\", \"description\": \"d\" }")]
    [InlineData("{ \"approver\": \"https://ps.example\", \"agent\": \"a\", \"description\": \"d\" }")]
    [InlineData("{ \"approver\": \"https://ps.example\", \"agent\": \"a\", \"approved_at\": \"2026-04-07T14:30:00Z\" }")]
    public void FromApprovalBytes_MissingRequiredField_Throws(string body)
    {
        Assert.Throws<InvalidOperationException>(
            () => Mission.FromApprovalBytes(Encoding.UTF8.GetBytes(body)));
    }

    [Fact(DisplayName = "§Mission Approval — empty body throws")]
    public void FromApprovalBytes_EmptyBody_Throws()
    {
        Assert.Throws<ArgumentException>(() => Mission.FromApprovalBytes(ReadOnlySpan<byte>.Empty));
    }
}
