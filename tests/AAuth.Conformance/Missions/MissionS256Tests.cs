using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using AAuth.Agent;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Conformance.Missions;

/// <summary>
/// Conformance tests for the mission <c>s256</c> identity (§Mission Approval):
/// base64url(SHA-256(exact mission blob bytes)), stored verbatim with no
/// re-serialization, and matched against the approval envelope's <c>s256</c>.
/// </summary>
public class MissionS256Tests
{
    private const string Ps = "https://ps.example";

    private static readonly byte[] Body = Encoding.UTF8.GetBytes("""
        {
          "agent": "aauth:assistant@agent.example",
          "approved_at": "2026-04-07T14:30:00Z",
          "description": "Plan a trip"
        }
        """);

    [Fact(DisplayName = "§Mission Approval — s256 is base64url(SHA-256(blob bytes))")]
    public void S256_MatchesSha256OfBodyBytes()
    {
        var mission = Mission.FromBlob(Body, Ps);

        var expected = Base64UrlEncoder.Encode(SHA256.HashData(Body));
        Assert.Equal(expected, mission.S256);
    }

    [Fact(DisplayName = "§Mission Approval — stored RawBytes are verbatim (no re-serialization)")]
    public void RawBytes_AreVerbatim()
    {
        var mission = Mission.FromApprovalResponse(Encoding.UTF8.GetBytes(new JsonObject
        {
            ["s256"] = Base64UrlEncoder.Encode(SHA256.HashData(Body)),
            ["mission"] = Base64UrlEncoder.Encode(Body),
        }.ToJsonString()), Ps);

        Assert.Equal(Body, mission.RawBytes.ToArray());
    }

    [Fact(DisplayName = "§Mission Approval — an envelope whose s256 does not match the blob is rejected")]
    public void Envelope_RejectsMismatchedS256()
    {
        Assert.Throws<System.InvalidOperationException>(() => Mission.FromApprovalResponse(Encoding.UTF8.GetBytes(new JsonObject
        {
            ["s256"] = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes("other"))),
            ["mission"] = Base64UrlEncoder.Encode(Body),
        }.ToJsonString()), Ps));
    }

    [Fact(DisplayName = "§Mission Approval — VerifyS256 accepts the matching hash")]
    public void VerifyS256_AcceptsMatchingHash()
    {
        var mission = Mission.FromBlob(Body, Ps);

        Assert.True(mission.VerifyS256(mission.S256));
        Assert.True(mission.VerifyS256(Base64UrlEncoder.Encode(SHA256.HashData(Body))));
    }

    [Fact(DisplayName = "§Mission Approval — VerifyS256 rejects a non-matching hash")]
    public void VerifyS256_RejectsNonMatchingHash()
    {
        var mission = Mission.FromBlob(Body, Ps);

        Assert.False(mission.VerifyS256("not-the-hash"));
        Assert.False(mission.VerifyS256(""));
    }

    [Fact(DisplayName = "§Mission Approval — whitespace differences change the s256")]
    public void S256_IsSensitiveToByteDifferences()
    {
        var compact = Encoding.UTF8.GetBytes(
            "{\"agent\":\"aauth:assistant@agent.example\"," +
            "\"approved_at\":\"2026-04-07T14:30:00Z\",\"description\":\"Plan a trip\"}");

        var fromPretty = Mission.FromBlob(Body, Ps);
        var fromCompact = Mission.FromBlob(compact, Ps);

        // Same logical content, different bytes — different identity. This is why
        // the agent MUST store the blob verbatim and never re-serialize.
        Assert.NotEqual(fromPretty.S256, fromCompact.S256);
    }
}
