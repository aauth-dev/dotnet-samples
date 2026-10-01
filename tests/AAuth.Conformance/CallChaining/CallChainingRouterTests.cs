using System;
using System.Text;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.CallChaining;
using AAuth.Server.Challenge;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
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
    private const string PersonTyp = "aa-person+jwt";
    private const string AuthTyp = "aa-auth+jwt";

    [Fact(DisplayName = "§Routing — auth token → returns its ps claim")]
    public void AuthToken_ReturnsPs()
    {
        var token = BuildTokenWithPayload(AuthTyp, new JsonObject
        {
            ["iss"] = "https://ps.example",
            ["aud"] = "https://resource.example",
            ["ps"] = "https://ps.example",
            ["sub"] = "person-1",
        });

        var result = CallChainingRouter.ResolveDownstreamServer(token, TestEgress.Policy);

        Assert.Equal("https://ps.example", result);
    }

    [Fact(DisplayName = "§Routing — person token → returns its iss")]
    public void PersonToken_ReturnsIss()
    {
        var token = BuildTokenWithPayload(PersonTyp, new JsonObject
        {
            ["iss"] = "https://ps.example",
            ["aud"] = "https://resource.example",
            ["sub"] = "person-1",
        });

        var result = CallChainingRouter.ResolveDownstreamServer(token, TestEgress.Policy);

        Assert.Equal("https://ps.example", result);
    }

    [Fact(DisplayName = "§Routing — AS-issued auth token → returns ps, not the AS iss")]
    public void AuthToken_IssuedByAs_ReturnsPsNotIss()
    {
        var token = BuildTokenWithPayload(AuthTyp, new JsonObject
        {
            ["iss"] = "https://as.resource.example",
            ["aud"] = "https://resource.example",
            ["ps"] = "https://ps.example",
            ["sub"] = "person-1",
        });

        var result = CallChainingRouter.ResolveDownstreamServer(token, TestEgress.Policy);

        Assert.Equal("https://ps.example", result);
    }

    [Fact(DisplayName = "§Routing — invalid ps (http non-loopback) → throws")]
    public void InvalidPs_HttpNonLoopback_Throws()
    {
        var token = BuildTokenWithPayload(AuthTyp, new JsonObject
        {
            ["iss"] = "https://ps.example",
            ["aud"] = "https://resource.example",
            ["ps"] = "http://evil.example",
            ["sub"] = "person-1",
        });

        var ex = Assert.Throws<InvalidOperationException>(
            () => CallChainingRouter.ResolveDownstreamServer(token, TestEgress.Policy));
        Assert.Contains("person server", ex.Message);
    }

    [Fact(DisplayName = "§Routing — empty ps → throws (fail-fast, no fallthrough to iss)")]
    public void EmptyPs_Throws()
    {
        var token = BuildTokenWithPayload(AuthTyp, new JsonObject
        {
            ["iss"] = "https://ps.example",
            ["aud"] = "https://resource.example",
            ["ps"] = "",
            ["sub"] = "person-1",
        });

        var ex = Assert.Throws<InvalidOperationException>(
            () => CallChainingRouter.ResolveDownstreamServer(token, TestEgress.Policy));
        Assert.Contains("person server", ex.Message);
    }

    [Fact(DisplayName = "§Routing — whitespace-only ps → throws (fail-fast)")]
    public void WhitespacePs_Throws()
    {
        var token = BuildTokenWithPayload(AuthTyp, new JsonObject
        {
            ["iss"] = "https://ps.example",
            ["aud"] = "https://resource.example",
            ["ps"] = "   ",
            ["sub"] = "person-1",
        });

        var ex = Assert.Throws<InvalidOperationException>(
            () => CallChainingRouter.ResolveDownstreamServer(token, TestEgress.Policy));
        Assert.Contains("person server", ex.Message);
    }

    [Fact(DisplayName = "§Routing — person token missing iss → throws")]
    public void MissingIss_Throws()
    {
        var token = BuildTokenWithPayload(PersonTyp, new JsonObject
        {
            ["aud"] = "https://resource.example",
            ["sub"] = "person-1",
        });

        var ex = Assert.Throws<InvalidOperationException>(
            () => CallChainingRouter.ResolveDownstreamServer(token, TestEgress.Policy));
        Assert.Contains("person server", ex.Message);
    }

    [Fact(DisplayName = "§Routing — auth token missing ps does not fall back to iss")]
    public void AuthTokenMissingPs_Throws()
    {
        var token = BuildTokenWithPayload(AuthTyp, new JsonObject
        {
            ["iss"] = "https://ps.example",
            ["aud"] = "https://resource.example",
            ["sub"] = "person-1",
        });

        Assert.Throws<InvalidOperationException>(
            () => CallChainingRouter.ResolveDownstreamServer(token, TestEgress.Policy));
    }

    [Fact(DisplayName = "§Routing — agent token is not an upstream token → throws")]
    public void AgentToken_Throws()
    {
        var token = BuildTokenWithPayload("aa-agent+jwt", new JsonObject
        {
            ["iss"] = "https://ap.example",
            ["sub"] = "aauth:agent@ap.example",
            ["ps"] = "https://ps.example",
        });

        var ex = Assert.Throws<InvalidOperationException>(
            () => CallChainingRouter.ResolveDownstreamServer(token, TestEgress.Policy));
        Assert.Contains("person token or an auth token", ex.Message);
    }

    [Fact(DisplayName = "§Routing — malformed JWT (not 3 segments) → throws")]
    public void MalformedJwt_Throws()
    {
        Assert.Throws<InvalidOperationException>(
            () => CallChainingRouter.ResolveDownstreamServer("not.a.valid.jwt.at.all", TestEgress.Policy));
    }

    [Fact(DisplayName = "§Routing — loopback person token iss (dev scenario) → accepted")]
    public void LoopbackIss_Accepted()
    {
        var token = BuildTokenWithPayload(PersonTyp, new JsonObject
        {
            ["iss"] = "http://localhost:5000",
            ["aud"] = "http://localhost:6000",
            ["sub"] = "person-1",
        });

        var result = CallChainingRouter.ResolveDownstreamServer(token, TestEgress.Policy);

        Assert.Equal("http://localhost:5000", result);
    }

    [Fact(DisplayName = "§Routing — loopback auth token ps (dev scenario) → accepted")]
    public void LoopbackPs_Accepted()
    {
        var token = BuildTokenWithPayload(AuthTyp, new JsonObject
        {
            ["iss"] = "https://ps.example",
            ["aud"] = "https://resource.example",
            ["ps"] = "http://127.0.0.1:8080",
            ["sub"] = "person-1",
        });

        var result = CallChainingRouter.ResolveDownstreamServer(token, TestEgress.Policy);

        Assert.Equal("http://127.0.0.1:8080", result);
    }

    [Fact(DisplayName = "§Routing — non-https person token iss (non-loopback) → throws")]
    public void NonHttpsIss_NonLoopback_Throws()
    {
        var token = BuildTokenWithPayload(PersonTyp, new JsonObject
        {
            ["iss"] = "http://external-server.com",
            ["aud"] = "https://resource.example",
            ["sub"] = "person-1",
        });

        var ex = Assert.Throws<InvalidOperationException>(
            () => CallChainingRouter.ResolveDownstreamServer(token, TestEgress.Policy));
        Assert.Contains("person server", ex.Message);
    }

    [Fact(DisplayName = "§Routing — null/empty token → throws ArgumentException")]
    public void NullToken_Throws()
    {
        Assert.Throws<ArgumentException>(
            () => CallChainingRouter.ResolveDownstreamServer("", TestEgress.Policy));
    }

    [Fact(DisplayName = "§Routing — mission_s256 does not affect routing → returns ps")]
    public void MissionS256_DoesNotAffectRouting()
    {
        var token = BuildTokenWithPayload(AuthTyp, new JsonObject
        {
            ["iss"] = "https://as.resource.example",
            ["aud"] = "https://resource.example",
            ["ps"] = "https://ps.example",
            ["sub"] = "person-1",
            ["mission_s256"] = "abc123",
        });

        var result = CallChainingRouter.ResolveDownstreamServer(token, TestEgress.Policy);

        Assert.Equal("https://ps.example", result);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static string BuildTokenWithPayload(string typ, JsonObject payload)
    {
        var header = new JsonObject
        {
            ["alg"] = "Ed25519",
            ["typ"] = typ,
            ["kid"] = "test-1",
        };

        var h = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToJsonString()));
        var p = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload.ToJsonString()));
        // Signature not needed — router only decodes payload.
        return $"{h}.{p}.fake-signature";
    }
}
