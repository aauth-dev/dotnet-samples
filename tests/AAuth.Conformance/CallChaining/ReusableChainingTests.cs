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
    [InlineData("key")]
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
        var agentToken = await new AgentTokenBuilder
        {
            EgressPolicy = egress, Issuer = origin, Subject = agentId, Key = issuerKey, KeyId = "key",
            ConfirmationKey = agentKey, PersonServer = origin,
        }.BuildAsync();
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
        builder.Services.AddAAuthPersonServer(configure: o =>
        {
            o.Issuer = origin;
            o.EgressPolicy = egress;
            o.SigningKeys = new AAuthSigningKeySet { ["key"] = issuerKey };
            o.UnsignedPathPrefixes = ["/data"];
        });
        await using var app = builder.Build();
        app.MapAAuthPersonServer();
        foreach (var dwk in new[] { AAuthConstants.DwkFiles.Agent, AAuthConstants.DwkFiles.Resource })
            app.MapGet("/.well-known/" + dwk, () => Results.Json(new { issuer = origin, jwks_uri = origin + "/.well-known/jwks.json" }));
        const string mission = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        var challenges = 0;
        app.MapGet("/data", async (HttpContext context) =>
        {
            var parsed = SignatureKeyParser.Parse(context.Request.Headers["Signature-Key"]!);
            var typ = (string?)parsed.Header?["typ"];
            if (typ == AuthTokenBuilder.TokenType)
                return Results.Text(parsed.Jwt!);
            if (typ != PersonTokenBuilder.TokenType)
            {
                context.Response.Headers[AAuthRequirementHeader.Name] = AAuthRequirementHeader.FormatPersonToken();
                return Results.StatusCode(401);
            }
            // §Resource Token Structure: name the presented person token.
            challenges++;
            var person = parsed.Payload!;
            var resource = await new ResourceTokenBuilder
            {
                EgressPolicy = egress, Issuer = origin, Audience = origin,
                PersonServer = (string)person["iss"]!, Subject = (string)person["sub"]!, PresentedJti = (string)person["jti"]!,
                MissionS256 = (string?)person["mission_s256"],
                AgentJkt = agentKey.ComputeJwkThumbprint(), Key = issuerKey, KeyId = "key",
                Scope = "read", ScopeDescriptions = TestScopeDefinitions.Resource,
            }.BuildAsync();
            context.Response.Headers[AAuthRequirementHeader.Name] = AAuthRequirementHeader.FormatAuthToken(resource);
            return Results.StatusCode(401);
        });
        await app.StartAsync();
        await app.Services.GetRequiredService<IMissionStore>().SaveAsync(new StoredMission(
            mission, origin, "aauth:caller-a@origin.test", ReadOnlyMemory<byte>.Empty));
        var callerKey = AAuthKey.Generate();
        ValueTask<string> UpstreamAsync(bool second) => new AuthTokenBuilder
        {
            EgressPolicy = egress, Issuer = origin, Audience = origin, PersonServer = origin, Key = issuerKey, KeyId = "key",
            Subject = second && changed == "subject" ? "person-b" : "person-a",
            Scope = second && changed == "scope" ? "limited" : "read",
            MissionS256 = second && changed == "mission" ? mission : null,
            AgentConfirmationKey = second && changed == "key" ? AAuthKey.Generate() : callerKey,
            AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(2),
        }.BuildAsync();
        var current = await UpstreamAsync(false);
        using var client = new AAuthClientBuilder(agentKey).UseJwt(agentToken).WithCallChaining(() => current)
            .WithEgressPolicy(egress).Build();
        var first = await client.GetStringAsync(origin + "/data");
        Assert.Equal(first, await client.GetStringAsync(origin + "/data"));
        Assert.Equal(1, challenges);
        Assert.Equal(2, asserter.Calls);
        current = await UpstreamAsync(true);
        var second = await client.GetStringAsync(origin + "/data");
        Assert.Equal(2, challenges);
        Assert.NotEqual(first, second);
        var payload = TokenVerifier.DecodeJsonSegment(second.Split('.')[1], "payload");
        Assert.Null(payload["act"]);
        Assert.Equal(changed == "subject" ? "downstream-person-b" : "downstream-person-a", (string?)payload["sub"]);
        Assert.Equal(changed == "mission" ? mission : null, (string?)payload["mission_s256"]);
        Assert.Equal(4, asserter.Calls);
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