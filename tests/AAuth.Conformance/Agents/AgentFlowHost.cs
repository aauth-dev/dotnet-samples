using System.Net;
using System.Net.Sockets;
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

namespace AAuth.Conformance.Agents;

/// <summary>
/// A loopback PS that is also the agent provider and a resource (<c>/data</c>). The resource
/// answers an auth token by echoing it, so a test reads what the PS issued.
/// </summary>
internal sealed class AgentFlowHost : IAsyncDisposable
{
    public const string Mission = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    private readonly WebApplication _app;
    private readonly AAuthKey _issuerKey;

    private AgentFlowHost(WebApplication app, string origin, AAuthKey issuerKey, ConsentScript consent)
    {
        _app = app;
        Origin = origin;
        _issuerKey = issuerKey;
        Consent = consent;
    }

    public string Origin { get; }
    public AAuthEgressPolicy Egress => AAuthEgressPolicy.ForDevelopmentLoopback(Origin);
    public ConsentScript Consent { get; }

    public static async Task<AgentFlowHost> StartAsync()
    {
        using var reservation = new TcpListener(IPAddress.Loopback, 0);
        reservation.Start();
        var origin = "http://127.0.0.1:" + ((IPEndPoint)reservation.LocalEndpoint).Port;
        reservation.Stop();
        var egress = AAuthEgressPolicy.ForDevelopmentLoopback(origin);
        var issuerKey = AAuthKey.Generate();
        var consent = new ConsentScript();
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseKestrel().UseUrls(origin);
        builder.Services.AddSingleton(new MetadataClient(policy: egress));
        builder.Services.AddSingleton(new JwksClient(policy: egress));
        builder.Services.AddSingleton(new TokenVerifier { EgressPolicy = egress });
        builder.Services.AddSingleton(new AAuthVerifier());
        builder.Services.AddSingleton<UpstreamTokenValidator>();
        builder.Services.AddSingleton<IIdentityClaimsAsserter>(new Asserter());
        builder.Services.AddSingleton<IPersonPendingStore, InMemoryPersonPendingStore>();
        builder.Services.AddAAuthGovernance();
        builder.Services.AddSingleton<IMissionTokenConsent>(consent);
        builder.Services.AddAAuthPersonServer(configure: o =>
        {
            o.Issuer = origin;
            o.EgressPolicy = egress;
            o.SigningKeys = new AAuthSigningKeySet { ["key"] = issuerKey };
            o.UnsignedPathPrefixes = ["/data"];
        });
        var app = builder.Build();
        app.MapAAuthPersonServer();
        foreach (var dwk in new[] { AAuthConstants.DwkFiles.Agent, AAuthConstants.DwkFiles.Resource })
            app.MapGet("/.well-known/" + dwk, () => Results.Json(new { issuer = origin, jwks_uri = origin + "/.well-known/jwks.json" }));
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
            var person = parsed.Payload!;
            var resource = await new ResourceTokenBuilder
            {
                EgressPolicy = egress, Issuer = origin, Audience = origin,
                PersonServer = (string)person["iss"]!, Subject = (string)person["sub"]!, PresentedJti = (string)person["jti"]!,
                MissionS256 = (string?)person["mission_s256"],
                AgentJkt = KeyFactory.FromPublicJwk((System.Text.Json.Nodes.JsonObject)person["cnf"]!["jwk"]!).ComputeJwkThumbprint(),
                Key = issuerKey, KeyId = "key", Scope = "read", ScopeDescriptions = TestScopeDefinitions.Resource,
            }.BuildAsync();
            context.Response.Headers[AAuthRequirementHeader.Name] = AAuthRequirementHeader.FormatAuthToken(resource);
            return Results.StatusCode(401);
        });
        await app.StartAsync();
        return new AgentFlowHost(app, origin, issuerKey, consent);
    }

    /// <summary>An agent token this host issues as agent provider, naming it as the Person Server.</summary>
    public ValueTask<string> AgentTokenAsync(IAAuthKey agentKey, string agentId) => new AgentTokenBuilder
    {
        EgressPolicy = Egress, Issuer = Origin, Subject = agentId, Key = _issuerKey, KeyId = "key",
        ConfirmationKey = agentKey, PersonServer = Origin,
    }.BuildAsync();

    /// <summary>An upstream auth token for an intermediary chaining on behalf of <paramref name="person"/>.</summary>
    public ValueTask<string> UpstreamAsync(string person, string? mission = null) => new AuthTokenBuilder
    {
        EgressPolicy = Egress, Issuer = Origin, Audience = Origin, PersonServer = Origin, Key = _issuerKey, KeyId = "key",
        Subject = person, Scope = "read", MissionS256 = mission, AgentConfirmationKey = AAuthKey.Generate(),
        AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(2),
    }.BuildAsync();

    public Task SaveMissionAsync(string agentId) => _app.Services.GetRequiredService<IMissionStore>()
        .SaveAsync(new StoredMission(Mission, Origin, agentId, ReadOnlyMemory<byte>.Empty));

    public AAuth.Agent.Mission ApprovedMission(string agentId) => new()
    {
        PersonServer = Origin, Agent = agentId, ApprovedAt = DateTimeOffset.UtcNow, Description = "Plan the offsite",
        S256 = Mission,
    };

    public static System.Text.Json.Nodes.JsonObject Claims(string token)
        => TokenVerifier.DecodeJsonSegment(token.Split('.')[1], "payload");

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();

    private sealed class Asserter : IIdentityClaimsAsserter
    {
        public Task<IdentityAssertion> AssertAsync(IdentityAssertionRequest request, CancellationToken cancellationToken = default)
            => Task.FromResult(IdentityAssertion.Assert(request.UpstreamAuthorization?.Subject is { } upstream
                ? "downstream-" + upstream : "person"));
    }

    /// <summary>Grants mission tokens, after one clarification round when <see cref="Clarify"/> is set.</summary>
    public sealed class ConsentScript : IMissionTokenConsent
    {
        public bool Clarify { get; set; }

        public Task<MissionTokenConsentDecision> ReviewAsync(MissionTokenConsentContext context, CancellationToken cancellationToken = default)
            => Task.FromResult(Clarify && context.ClarificationHistory is not { Count: > 0 }
                ? MissionTokenConsentDecision.Clarify("Why does the offsite need this?")
                : MissionTokenConsentDecision.Grant());
    }
}
