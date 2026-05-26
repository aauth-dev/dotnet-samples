using System;
using System.Text;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Server;
using AAuth.Tokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Conformance.CallChaining;

/// <summary>
/// Conformance tests for <see cref="CallChainingRouter.ResolveDownstreamServer"/>
/// covering all routing rules per §Call Chaining.
/// </summary>
public class CallChainingRouterTests
{
    [Fact(DisplayName = "§Routing — mission.approver present → returns approver URL")]
    public void MissionApproverPresent_ReturnsApproverUrl()
    {
        var token = BuildTokenWithPayload(new JsonObject
        {
            ["iss"] = "https://ps.example",
            ["aud"] = "https://resource.example",
            ["agent"] = "agent-1",
            ["act"] = new JsonObject { ["sub"] = "agent-1" },
            ["mission"] = new JsonObject { ["approver"] = "https://mission-ps.example" },
        });

        var result = CallChainingRouter.ResolveDownstreamServer(token);

        Assert.Equal("https://mission-ps.example", result);
    }

    [Fact(DisplayName = "§Routing — no mission, iss is PS → returns iss")]
    public void NoMission_ReturnsIss()
    {
        var token = BuildTokenWithPayload(new JsonObject
        {
            ["iss"] = "https://ps.example",
            ["aud"] = "https://resource.example",
            ["agent"] = "agent-1",
            ["act"] = new JsonObject { ["sub"] = "agent-1" },
        });

        var result = CallChainingRouter.ResolveDownstreamServer(token);

        Assert.Equal("https://ps.example", result);
    }

    [Fact(DisplayName = "§Routing — no mission, iss is AS → returns iss")]
    public void NoMission_IssIsAs_ReturnsIss()
    {
        var token = BuildTokenWithPayload(new JsonObject
        {
            ["iss"] = "https://as.resource.example",
            ["aud"] = "https://resource.example",
            ["agent"] = "agent-1",
            ["act"] = new JsonObject { ["sub"] = "agent-1" },
        });

        var result = CallChainingRouter.ResolveDownstreamServer(token);

        Assert.Equal("https://as.resource.example", result);
    }

    [Fact(DisplayName = "§Routing — invalid mission.approver (http non-loopback) → throws")]
    public void InvalidApprover_HttpNonLoopback_Throws()
    {
        var token = BuildTokenWithPayload(new JsonObject
        {
            ["iss"] = "https://ps.example",
            ["aud"] = "https://resource.example",
            ["agent"] = "agent-1",
            ["act"] = new JsonObject { ["sub"] = "agent-1" },
            ["mission"] = new JsonObject { ["approver"] = "http://evil.example" },
        });

        var ex = Assert.Throws<InvalidOperationException>(
            () => CallChainingRouter.ResolveDownstreamServer(token));
        Assert.Contains("mission.approver", ex.Message);
    }

    [Fact(DisplayName = "§Routing — empty mission.approver → throws (fail-fast, no fallthrough)")]
    public void EmptyApprover_Throws()
    {
        var token = BuildTokenWithPayload(new JsonObject
        {
            ["iss"] = "https://ps.example",
            ["aud"] = "https://resource.example",
            ["agent"] = "agent-1",
            ["act"] = new JsonObject { ["sub"] = "agent-1" },
            ["mission"] = new JsonObject { ["approver"] = "" },
        });

        var ex = Assert.Throws<InvalidOperationException>(
            () => CallChainingRouter.ResolveDownstreamServer(token));
        Assert.Contains("mission.approver", ex.Message);
        Assert.Contains("empty", ex.Message);
    }

    [Fact(DisplayName = "§Routing — whitespace-only mission.approver → throws (fail-fast)")]
    public void WhitespaceApprover_Throws()
    {
        var token = BuildTokenWithPayload(new JsonObject
        {
            ["iss"] = "https://ps.example",
            ["aud"] = "https://resource.example",
            ["agent"] = "agent-1",
            ["act"] = new JsonObject { ["sub"] = "agent-1" },
            ["mission"] = new JsonObject { ["approver"] = "   " },
        });

        var ex = Assert.Throws<InvalidOperationException>(
            () => CallChainingRouter.ResolveDownstreamServer(token));
        Assert.Contains("mission.approver", ex.Message);
    }

    [Fact(DisplayName = "§Routing — missing iss → throws")]
    public void MissingIss_Throws()
    {
        var token = BuildTokenWithPayload(new JsonObject
        {
            ["aud"] = "https://resource.example",
            ["agent"] = "agent-1",
            ["act"] = new JsonObject { ["sub"] = "agent-1" },
        });

        var ex = Assert.Throws<InvalidOperationException>(
            () => CallChainingRouter.ResolveDownstreamServer(token));
        Assert.Contains("iss", ex.Message);
    }

    [Fact(DisplayName = "§Routing — malformed JWT (not 3 segments) → throws")]
    public void MalformedJwt_Throws()
    {
        Assert.Throws<InvalidOperationException>(
            () => CallChainingRouter.ResolveDownstreamServer("not.a.valid.jwt.at.all"));
    }

    [Fact(DisplayName = "§Routing — loopback iss (dev scenario) → accepted")]
    public void LoopbackIss_Accepted()
    {
        var token = BuildTokenWithPayload(new JsonObject
        {
            ["iss"] = "http://localhost:5000",
            ["aud"] = "http://localhost:6000",
            ["agent"] = "agent-1",
            ["act"] = new JsonObject { ["sub"] = "agent-1" },
        });

        var result = CallChainingRouter.ResolveDownstreamServer(token);

        Assert.Equal("http://localhost:5000", result);
    }

    [Fact(DisplayName = "§Routing — loopback mission.approver (dev scenario) → accepted")]
    public void LoopbackApprover_Accepted()
    {
        var token = BuildTokenWithPayload(new JsonObject
        {
            ["iss"] = "https://ps.example",
            ["aud"] = "https://resource.example",
            ["agent"] = "agent-1",
            ["act"] = new JsonObject { ["sub"] = "agent-1" },
            ["mission"] = new JsonObject { ["approver"] = "http://127.0.0.1:8080" },
        });

        var result = CallChainingRouter.ResolveDownstreamServer(token);

        Assert.Equal("http://127.0.0.1:8080", result);
    }

    [Fact(DisplayName = "§Routing — non-https iss (non-loopback) → throws")]
    public void NonHttpsIss_NonLoopback_Throws()
    {
        var token = BuildTokenWithPayload(new JsonObject
        {
            ["iss"] = "http://external-server.com",
            ["aud"] = "https://resource.example",
            ["agent"] = "agent-1",
            ["act"] = new JsonObject { ["sub"] = "agent-1" },
        });

        var ex = Assert.Throws<InvalidOperationException>(
            () => CallChainingRouter.ResolveDownstreamServer(token));
        Assert.Contains("iss", ex.Message);
    }

    [Fact(DisplayName = "§Routing — null/empty token → throws ArgumentException")]
    public void NullToken_Throws()
    {
        Assert.Throws<ArgumentException>(
            () => CallChainingRouter.ResolveDownstreamServer(""));
    }

    [Fact(DisplayName = "§Routing — mission object present without approver key → falls through to iss")]
    public void MissionWithoutApproverKey_FallsToIss()
    {
        var token = BuildTokenWithPayload(new JsonObject
        {
            ["iss"] = "https://ps.example",
            ["aud"] = "https://resource.example",
            ["agent"] = "agent-1",
            ["act"] = new JsonObject { ["sub"] = "agent-1" },
            ["mission"] = new JsonObject { ["s256"] = "abc123" },
        });

        var result = CallChainingRouter.ResolveDownstreamServer(token);

        Assert.Equal("https://ps.example", result);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static string BuildTokenWithPayload(JsonObject payload)
    {
        var header = new JsonObject
        {
            ["alg"] = "EdDSA",
            ["typ"] = "aa-auth+jwt",
            ["kid"] = "test-1",
        };

        var h = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToJsonString()));
        var p = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload.ToJsonString()));
        // Signature not needed — router only decodes payload.
        return $"{h}.{p}.fake-signature";
    }
}
