using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Person;
using AAuth.Server;
using AAuth.Server.Governance;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.Conformance.CallChaining;

public class ReusableChainingTests
{
    [Theory]
    [InlineData("agent")]
    [InlineData("subject")]
    [InlineData("scope")]
    [InlineData("mission")]
    public async Task ReusableBuilderExchangesAgainWhenUpstreamAuthorizationChanges(string changed)
    {
        using var reservation = new TcpListener(IPAddress.Loopback, 0);
        reservation.Start();
        var origin = "http://127.0.0.1:" + ((IPEndPoint)reservation.LocalEndpoint).Port;
        reservation.Stop();
        var egress = AAuthEgressPolicy.ForDevelopmentLoopback(origin);
        var issuerKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        const string agentId = "aauth:intermediary@ap.test";
        var agentToken = new AgentTokenBuilder
        {
            EgressPolicy = egress, Issuer = origin, Subject = agentId, Key = issuerKey, KeyId = "key",
            ConfirmationKey = agentKey, PersonServer = origin,
        }.Build();
        var asserter = new Asserter();
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseKestrel().UseUrls(origin);
        builder.Services.AddSingleton(new MetadataClient(policy: egress));
        builder.Services.AddSingleton(new JwksClient(policy: egress));
        builder.Services.AddSingleton(new TokenVerifier { EgressPolicy = egress });
        builder.Services.AddSingleton(new AAuthVerifier());
        builder.Services.AddSingleton<UpstreamTokenValidator>();
        builder.Services.AddSingleton<IIdentityClaimsAsserter>(asserter);
        builder.Services.AddSingleton<IPersonPendingStore, InMemoryPersonPendingStore>();
        builder.Services.AddAAuthGovernance();
        builder.Services.AddSingleton<IMissionTokenConsent, Consent>();
        await using var app = builder.Build();
        app.MapAAuthPersonServer(new AAuthPersonServerOptions
        {
            Issuer = origin, EgressPolicy = egress, SigningKeys = new Dictionary<string, IAAuthKey> { ["key"] = issuerKey },
            UnsignedPathPrefixes = ["/data"],
        });
        foreach (var dwk in new[] { AAuthConstants.DwkFiles.Agent, AAuthConstants.DwkFiles.Resource })
            app.MapGet("/.well-known/" + dwk, () => Results.Json(new { issuer = origin, jwks_uri = origin + "/.well-known/jwks.json" }));
        var challenges = 0;
        app.MapGet("/data", (HttpContext context) =>
        {
            var parsed = SignatureKeyParser.Parse(context.Request.Headers["Signature-Key"]!);
            if ((string?)parsed.Header?["typ"] == AuthTokenBuilder.TokenType)
                return Results.Text(parsed.Jwt!);
            challenges++;
            var resource = new ResourceTokenBuilder
            {
                EgressPolicy = egress, Issuer = origin, Audience = origin, Agent = agentId,
                AgentJkt = agentKey.ComputeJwkThumbprint(), Key = issuerKey, KeyId = "key",
                Scope = "read", ScopeDescriptions = TestScopeDefinitions.Resource,
                Mission = context.Request.Headers.ContainsKey(AAuthMissionHeader.Name)
                    ? new MissionClaim(origin, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") : null,
            }.Build();
            context.Response.Headers[AAuthRequirementHeader.Name] = AAuthRequirementHeader.FormatAuthToken(resource);
            return Results.StatusCode(401);
        });
        await app.StartAsync();
        await app.Services.GetRequiredService<IMissionStore>().SaveAsync(new StoredMission(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", origin, "aauth:caller-a@origin.test", ReadOnlyMemory<byte>.Empty));
        string Upstream(bool second) => new AuthTokenBuilder
        {
            EgressPolicy = egress, Issuer = origin, Audience = origin, Key = issuerKey, KeyId = "key",
            Agent = second && changed == "agent" ? "aauth:caller-b@origin.test" : "aauth:caller-a@origin.test",
            Subject = second && changed == "subject" ? "person-b" : "person-a",
            Scope = second && changed == "scope" ? "limited" : "read",
            Mission = second && changed == "mission" ? new MissionClaim(origin, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") : null,
            AgentConfirmationKey = agentKey, AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(2),
        }.Build();
        var current = Upstream(false);
        using var client = new AAuthClientBuilder(agentKey).UseJwt(agentToken).WithCallChaining(() => current)
            .WithEgressPolicy(egress).Build();
        var first = await client.GetStringAsync(origin + "/data");
        Assert.Equal(first, await client.GetStringAsync(origin + "/data"));
        Assert.Equal(1, challenges);
        current = Upstream(true);
        var second = await client.GetStringAsync(origin + "/data");
        Assert.Equal(2, challenges);
        Assert.NotEqual(first, second);
        var payload = TokenVerifier.DecodeJsonSegment(second.Split('.')[1], "payload");
        Assert.Equal(changed == "agent" ? "aauth:caller-b@origin.test" : "aauth:caller-a@origin.test", (string?)payload["act"]?["agent"]);
        Assert.Equal(changed == "mission", payload["mission"] is not null);
        Assert.Equal(2, asserter.Calls);
    }

    private sealed class Asserter : IIdentityClaimsAsserter
    {
        public int Calls { get; private set; }
        public Task<IdentityAssertion> AssertAsync(IdentityAssertionRequest request, CancellationToken cancellationToken = default)
        {
            Calls++;
            return Task.FromResult(IdentityAssertion.Assert("downstream-" + request.UpstreamAuthorization?.Subject));
        }
    }

    private sealed class Consent : IMissionTokenConsent
    {
        public Task<MissionTokenConsentDecision> ReviewAsync(MissionTokenConsentContext context, CancellationToken cancellationToken = default)
            => Task.FromResult(MissionTokenConsentDecision.Grant());
    }
}