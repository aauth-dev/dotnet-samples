using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth;
using AAuth.Agent;
using AAuth.Discovery;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.CallChaining;
using AAuth.Server.Challenge;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace AAuth.Conformance.HttpSignatures;

/// <summary>
/// Conformance tests for <see cref="AAuthChallengeMiddleware"/>:
/// verifies auto-challenge when auth token is required (Gaps 3 and 4).
/// </summary>
public class ChallengeMiddlewareTests : IAsyncLifetime
{
    // ── Test fixtures ──────────────────────────────────────────────────────

    private const string ApIssuer = "http://localhost:5555";
    private const string PsIssuer = "http://localhost:5555";
    private const string ResourceId = "http://localhost:5000";
    private const string AgentId = "aauth:test@ap.example";
    private const string ResourceKid = "resource-key-1";
    private const string ResourceScope = "data:read";

    private static readonly DateTimeOffset FixedClock = DateTimeOffset.UtcNow;

    private readonly AAuthKey _apKey = AAuthKey.Generate();
    private readonly AAuthKey _psKey = AAuthKey.Generate();
    private readonly AAuthKey _agentKey = AAuthKey.Generate();
    private readonly AAuthKey _resourceKey = AAuthKey.Generate();

    private IHost? _challengeHost;
    private IHost? _identityOnlyHost;
    private IHost? _schemeFilterHost;
    private IHost? _agentTokenRequiredHost;
    private IHost? _metadataHost;

    public async Task InitializeAsync()
    {
        // Start a mock metadata/JWKS server for AP and PS.
        _metadataHost = await StartMetadataServer();

        // Start the resource server with RequireAuthToken mode.
        _challengeHost = await StartResourceServer(new ChallengeOptions
        {
            AccessMode = AAuthAccessMode.RequireAuthToken,
            ResourceSigningKey = _resourceKey,
            ResourceKeyId = ResourceKid,
            ResourceIdentifier = ResourceId,
            DefaultScopes = ResourceScope,
            // PersonServerAudience left null — resolved from agent token's `ps` claim.
        });

        // Start a resource server with IdentityOnly mode.
        _identityOnlyHost = await StartResourceServer(new ChallengeOptions
        {
            AccessMode = AAuthAccessMode.IdentityOnly,
        });

        // Start a resource server with scheme filter (only allow jwt).
        _schemeFilterHost = await StartResourceServer(new ChallengeOptions
        {
            AccessMode = AAuthAccessMode.RequireAuthToken,
            ResourceSigningKey = _resourceKey,
            ResourceKeyId = ResourceKid,
            ResourceIdentifier = ResourceId,
            DefaultScopes = ResourceScope,
            AllowedSignatureKeySchemes = new HashSet<string> { "jwt" },
        });

        // Start a resource server with AgentTokenRequired mode (§Agent Token Required).
        _agentTokenRequiredHost = await StartResourceServer(new ChallengeOptions
        {
            AccessMode = AAuthAccessMode.AgentTokenRequired,
        });
    }

    public async Task DisposeAsync()
    {
        if (_challengeHost is not null) { await _challengeHost.StopAsync(); _challengeHost.Dispose(); }
        if (_identityOnlyHost is not null) { await _identityOnlyHost.StopAsync(); _identityOnlyHost.Dispose(); }
        if (_schemeFilterHost is not null) { await _schemeFilterHost.StopAsync(); _schemeFilterHost.Dispose(); }
        if (_agentTokenRequiredHost is not null) { await _agentTokenRequiredHost.StopAsync(); _agentTokenRequiredHost.Dispose(); }
        if (_metadataHost is not null) { await _metadataHost.StopAsync(); _metadataHost.Dispose(); }
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private async Task<IHost> StartMetadataServer()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var app = builder.Build();

        // AP metadata
        app.MapGet("/.well-known/aauth-agent.json", () => Results.Json(new
        {
            issuer = ApIssuer,
            jwks_uri = $"{ApIssuer}/.well-known/ap-jwks.json",
        }));

        // PS metadata
        app.MapGet("/.well-known/aauth-person.json", () => Results.Json(new
        {
            issuer = PsIssuer,
            jwks_uri = $"{PsIssuer}/.well-known/ps-jwks.json",
            token_endpoint = $"{PsIssuer}/token",
        }));

        // AP JWKS
        app.MapGet("/.well-known/ap-jwks.json", () =>
        {
            var jwk = _apKey.ToPublicJwk();
            jwk["kid"] = "ap-key-1";
            jwk["use"] = "sig";
            return Results.Json(new JsonObject { ["keys"] = new JsonArray { jwk } });
        });

        // PS JWKS
        app.MapGet("/.well-known/ps-jwks.json", () =>
        {
            var jwk = _psKey.ToPublicJwk();
            jwk["kid"] = "ps-key-1";
            jwk["use"] = "sig";
            return Results.Json(new JsonObject { ["keys"] = new JsonArray { jwk } });
        });

        await app.StartAsync();
        return app;
    }

    private async Task<IHost> StartResourceServer(ChallengeOptions challengeOptions)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new AAuthVerifier { Clock = () => FixedClock });
        builder.Services.AddSingleton<HttpClient>(_metadataHost!.GetTestClient());
        builder.Services.AddSingleton(sp =>
            new MetadataClient(sp.GetRequiredService<HttpClient>()));
        builder.Services.AddSingleton(sp =>
            new JwksClient(sp.GetRequiredService<HttpClient>()));

        var app = builder.Build();
        app.UseAAuthVerification(new AAuthVerificationOptions
        {
            ResourceIdentifier = ResourceId,
            RequireIssuerVerification = true,
            TrustedAuthTokenIssuers = new HashSet<string> { PsIssuer },
        });
        app.UseAAuthChallenge(challengeOptions);
        app.MapGet("/protected", () => Results.Ok("hello"));
        await app.StartAsync();
        return app;
    }

    private string BuildAgentToken(string? personServer = PsIssuer)
    {
        return new AgentTokenBuilder
        {
            Issuer = ApIssuer,
            Subject = AgentId,
            Key = _apKey,
            KeyId = "ap-key-1",
            ConfirmationKey = _agentKey,
            IssuedAt = FixedClock,
            PersonServer = personServer,
        }.Build();
    }

    private string BuildAuthToken()
    {
        return new AuthTokenBuilder
        {
            Issuer = PsIssuer,
            Audience = ResourceId,
            Agent = AgentId,
            AgentConfirmationKey = _agentKey,
            Key = _psKey,
            KeyId = "ps-key-1",
            Subject = "pairwise-sub",
            Scope = ResourceScope,
            IssuedAt = FixedClock,
        }.Build();
    }

    private async Task<HttpRequestMessage> SignRequest(string token)
    {
        var capture = new CaptureHandler();
        var provider = new JwtSignatureKeyProvider(() => token);
        var handler = new AAuthSigningHandler(_agentKey, provider, () => FixedClock)
        {
            InnerHandler = capture,
        };
        using var client = new HttpClient(handler);
        await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, "http://localhost:5000/protected"));
        return capture.Captured!;
    }

    private async Task<HttpResponseMessage> SendSigned(IHost host, string token)
    {
        var signed = await SignRequest(token);
        var relay = new HttpRequestMessage(HttpMethod.Get, "/protected");
        foreach (var h in signed.Headers)
            relay.Headers.TryAddWithoutValidation(h.Key, h.Value);
        relay.Headers.Host = "localhost:5000";
        return await host.GetTestClient().SendAsync(relay);
    }

    private sealed class CaptureHandler : HttpMessageHandler
    {
        public HttpRequestMessage? Captured { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            Captured = request;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }

    // ── Tests ──────────────────────────────────────────────────────────────

    [Fact(DisplayName = "§Challenge — RequireAuthToken challenges agent token with resource token")]
    public async Task ChallengesAgentTokenWithResourceToken()
    {
        var token = BuildAgentToken();
        var response = await SendSigned(_challengeHost!, token);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.True(response.Headers.Contains(AAuthRequirementHeader.Name));

        var headerValue = string.Join(",", response.Headers.GetValues(AAuthRequirementHeader.Name));
        var parsed = AAuthRequirementHeader.Parse(headerValue);
        Assert.Equal(AAuthRequirementHeader.AuthTokenRequirement, parsed.Requirement);
        Assert.NotNull(parsed.ResourceToken);
        Assert.NotEmpty(parsed.ResourceToken);
    }

    [Fact(DisplayName = "§Challenge — resource token contains correct claims")]
    public async Task ResourceTokenHasCorrectClaims()
    {
        var token = BuildAgentToken();
        var response = await SendSigned(_challengeHost!, token);

        var headerValue = string.Join(",", response.Headers.GetValues(AAuthRequirementHeader.Name));
        var parsed = AAuthRequirementHeader.Parse(headerValue);

        // Decode the resource token and verify claims.
        var parts = parsed.ResourceToken!.Split('.');
        Assert.Equal(3, parts.Length);

        var headerJson = JsonNode.Parse(Base64UrlDecode(parts[0]))!.AsObject();
        var payloadJson = JsonNode.Parse(Base64UrlDecode(parts[1]))!.AsObject();

        Assert.Equal(ResourceTokenBuilder.TokenType, (string?)headerJson["typ"]);
        Assert.Equal(ResourceKid, (string?)headerJson["kid"]);
        Assert.Equal(ResourceId, (string?)payloadJson["iss"]);
        Assert.Equal(PsIssuer, (string?)payloadJson["aud"]);
        Assert.Equal(AgentId, (string?)payloadJson["agent"]);
        Assert.Equal(ResourceScope, (string?)payloadJson["scope"]);
        Assert.NotNull((string?)payloadJson["agent_jkt"]);
    }

    [Fact(DisplayName = "§Challenge — auth token passes through to endpoint")]
    public async Task AuthTokenPassesThrough()
    {
        var token = BuildAuthToken();
        var response = await SendSigned(_challengeHost!, token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact(DisplayName = "§Challenge — IdentityOnly passes agent token through")]
    public async Task IdentityOnlyPassesAgentToken()
    {
        var token = BuildAgentToken();
        var response = await SendSigned(_identityOnlyHost!, token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact(DisplayName = "§Challenge — IdentityOnly passes auth token through")]
    public async Task IdentityOnlyPassesAuthToken()
    {
        var token = BuildAuthToken();
        var response = await SendSigned(_identityOnlyHost!, token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact(DisplayName = "§Agent Token Required — passes an agent token through")]
    public async Task AgentTokenRequired_PassesAgentToken()
    {
        var token = BuildAgentToken();
        var response = await SendSigned(_agentTokenRequiredHost!, token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact(DisplayName = "§Agent Token Required — passes an auth token through (identity established)")]
    public async Task AgentTokenRequired_PassesAuthToken()
    {
        var token = BuildAuthToken();
        var response = await SendSigned(_agentTokenRequiredHost!, token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact(DisplayName = "§Agent Token Required — challenges a non-agent-token credential with a bare requirement=agent-token")]
    public async Task AgentTokenRequired_ChallengesHwkWithBareAgentToken()
    {
        // hwk is a valid pseudonymous scheme but not an AAuth agent token; the
        // resource specifically wants an agent token, so it challenges.
        var capture = new CaptureHandler();
        var provider = new HwkSignatureKeyProvider(_agentKey);
        var handler = new AAuthSigningHandler(_agentKey, provider, () => FixedClock)
        {
            InnerHandler = capture,
        };
        using var client = new HttpClient(handler);
        await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, "http://localhost:5000/protected"));

        var signed = capture.Captured!;
        var relay = new HttpRequestMessage(HttpMethod.Get, "/protected");
        foreach (var h in signed.Headers)
            relay.Headers.TryAddWithoutValidation(h.Key, h.Value);
        relay.Headers.Host = "localhost:5000";

        var response = await _agentTokenRequiredHost!.GetTestClient().SendAsync(relay);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.True(response.Headers.Contains(AAuthRequirementHeader.Name));
        var headerValue = string.Join(",", response.Headers.GetValues(AAuthRequirementHeader.Name));
        var parsed = AAuthRequirementHeader.Parse(headerValue);
        Assert.Equal(AAuthRequirementHeader.AgentTokenRequirement, parsed.Requirement);
        Assert.Null(parsed.ResourceToken);
    }

    [Fact(DisplayName = "§Challenge — scheme filter rejects unlisted scheme")]
    public async Task SchemeFilterRejectsUnlistedScheme()
    {
        // Use hwk scheme (not in the allowed list for schemeFilterHost).
        var capture = new CaptureHandler();
        var provider = new HwkSignatureKeyProvider(_agentKey);
        var handler = new AAuthSigningHandler(_agentKey, provider, () => FixedClock)
        {
            InnerHandler = capture,
        };
        using var client = new HttpClient(handler);
        await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, "http://localhost:5000/protected"));

        var signed = capture.Captured!;
        var relay = new HttpRequestMessage(HttpMethod.Get, "/protected");
        foreach (var h in signed.Headers)
            relay.Headers.TryAddWithoutValidation(h.Key, h.Value);
        relay.Headers.Host = "localhost:5000";

        var response = await _schemeFilterHost!.GetTestClient().SendAsync(relay);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.True(response.Headers.Contains("AAuth-Error"));
    }

    [Fact(DisplayName = "§Challenge — scheme filter allows listed scheme")]
    public async Task SchemeFilterAllowsListedScheme()
    {
        // jwt scheme is allowed for schemeFilterHost.
        var token = BuildAuthToken();
        var response = await SendSigned(_schemeFilterHost!, token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact(DisplayName = "§Challenge — no ps claim returns 401 without resource token")]
    public async Task NoPsClaimReturns401WithoutResourceToken()
    {
        // Build agent token without ps claim.
        var token = BuildAgentToken(personServer: null);
        var response = await SendSigned(_challengeHost!, token);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        // Should NOT have a resource token since we can't resolve audience.
        Assert.False(response.Headers.Contains(AAuthRequirementHeader.Name));
        Assert.True(response.Headers.Contains("AAuth-Error"));
    }

    [Fact(DisplayName = "§Challenge — explicit PersonServerAudience overrides ps claim")]
    public async Task ExplicitAudienceOverridesPsClaim()
    {
        const string explicitAud = "http://localhost:9999";

        // Start a resource with explicit PersonServerAudience.
        var host = await StartResourceServer(new ChallengeOptions
        {
            AccessMode = AAuthAccessMode.RequireAuthToken,
            ResourceSigningKey = _resourceKey,
            ResourceKeyId = ResourceKid,
            ResourceIdentifier = ResourceId,
            DefaultScopes = ResourceScope,
            PersonServerAudience = explicitAud,
        });

        try
        {
            var token = BuildAgentToken(personServer: PsIssuer);
            var response = await SendSigned(host, token);

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            var headerValue = string.Join(",", response.Headers.GetValues(AAuthRequirementHeader.Name));
            var parsed = AAuthRequirementHeader.Parse(headerValue);

            // Decode the resource token to check audience.
            var parts = parsed.ResourceToken!.Split('.');
            var payloadJson = JsonNode.Parse(Base64UrlDecode(parts[1]))!.AsObject();
            Assert.Equal(explicitAud, (string?)payloadJson["aud"]);
        }
        finally
        {
            await host.StopAsync();
            host.Dispose();
        }
    }

    private static byte[] Base64UrlDecode(string input)
    {
        var padded = input.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        return Convert.FromBase64String(padded);
    }

    // ── Mission-aware resource (§Terminology, §Missions) ─────────────────

    private const string MissionApprover = PsIssuer;
    private const string MissionS256 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    private async Task<HttpResponseMessage> SendSignedWithMission(
        IHost host, string token, string? missionHeader)
    {
        var capture = new CaptureHandler();
        var provider = new JwtSignatureKeyProvider(() => token);
        var handler = new AAuthSigningHandler(_agentKey, provider, () => FixedClock)
        {
            InnerHandler = capture,
        };
        using var client = new HttpClient(handler);
        var outbound = new HttpRequestMessage(HttpMethod.Get, "http://localhost:5000/protected");
        if (missionHeader is not null)
            outbound.Headers.TryAddWithoutValidation(AAuthMissionHeader.Name, missionHeader);
        await client.SendAsync(outbound);
        var signed = capture.Captured!;

        var relay = new HttpRequestMessage(HttpMethod.Get, "/protected");
        foreach (var h in signed.Headers)
            relay.Headers.TryAddWithoutValidation(h.Key, h.Value);
        relay.Headers.Host = "localhost:5000";
        return await host.GetTestClient().SendAsync(relay);
    }

    private static JsonObject DecodeResourceTokenPayload(HttpResponseMessage response)
    {
        var headerValue = string.Join(",", response.Headers.GetValues(AAuthRequirementHeader.Name));
        var parsed = AAuthRequirementHeader.Parse(headerValue);
        var parts = parsed.ResourceToken!.Split('.');
        return JsonNode.Parse(Base64UrlDecode(parts[1]))!.AsObject();
    }

    [Fact(DisplayName = "§Missions — mission-aware resource copies AAuth-Mission into the resource token")]
    public async Task MissionAwareResourceCopiesMissionClaim()
    {
        var host = await StartResourceServer(new ChallengeOptions
        {
            AccessMode = AAuthAccessMode.RequireAuthToken,
            ResourceSigningKey = _resourceKey,
            ResourceKeyId = ResourceKid,
            ResourceIdentifier = ResourceId,
            DefaultScopes = ResourceScope,
            MissionAware = true,
        });
        try
        {
            var token = BuildAgentToken();
            var missionHeader = AAuthMissionHeader.FormatStructured(MissionApprover, MissionS256);
            var response = await SendSignedWithMission(host, token, missionHeader);

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            var payload = DecodeResourceTokenPayload(response);
            var mission = Assert.IsType<JsonObject>(payload["mission"]);
            Assert.Equal(MissionApprover, (string?)mission["approver"]);
            Assert.Equal(MissionS256, (string?)mission["s256"]);
        }
        finally
        {
            await host.StopAsync();
            host.Dispose();
        }
    }

    [Fact(DisplayName = "§Missions — mission-aware resource omits the mission claim when no header is present")]
    public async Task MissionAwareResourceOmitsMissionWhenHeaderAbsent()
    {
        var host = await StartResourceServer(new ChallengeOptions
        {
            AccessMode = AAuthAccessMode.RequireAuthToken,
            ResourceSigningKey = _resourceKey,
            ResourceKeyId = ResourceKid,
            ResourceIdentifier = ResourceId,
            DefaultScopes = ResourceScope,
            MissionAware = true,
        });
        try
        {
            var token = BuildAgentToken();
            var response = await SendSignedWithMission(host, token, missionHeader: null);

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            var payload = DecodeResourceTokenPayload(response);
            Assert.False(payload.ContainsKey("mission"));
        }
        finally
        {
            await host.StopAsync();
            host.Dispose();
        }
    }

    [Fact(DisplayName = "§Missions — non-mission-aware resource ignores the AAuth-Mission header")]
    public async Task NonMissionAwareResourceIgnoresMissionHeader()
    {
        // _challengeHost is configured WITHOUT MissionAware — the mission header
        // must be ignored (opt-in only), so no mission claim is emitted.
        var token = BuildAgentToken();
        var missionHeader = AAuthMissionHeader.FormatStructured(MissionApprover, MissionS256);
        var response = await SendSignedWithMission(_challengeHost!, token, missionHeader);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var payload = DecodeResourceTokenPayload(response);
        Assert.False(payload.ContainsKey("mission"));
    }
}
