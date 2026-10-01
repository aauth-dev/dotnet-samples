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
/// A loopback PS that is also the agent provider and a resource (<c>/data</c>, served on
/// <see cref="Origin"/> and, as a second resource, on <see cref="SecondOrigin"/>). The resource
/// answers an auth token by echoing it, so a test reads what the PS issued.
/// </summary>
internal sealed class AgentFlowHost : IAsyncDisposable
{
    public const string Mission = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    private readonly WebApplication _app;
    private readonly AAuthKey _issuerKey;
    private readonly Counter _posts;
    private readonly IJtiStore _inventory;
    private readonly IPersonResourceEnrollmentStore _enrollments;

    private AgentFlowHost(WebApplication app, string origin, string secondOrigin, AAuthKey issuerKey, ConsentScript consent,
        Counter posts, IJtiStore inventory, IPersonResourceEnrollmentStore enrollments)
    {
        _app = app;
        Origin = origin;
        SecondOrigin = secondOrigin;
        _issuerKey = issuerKey;
        Consent = consent;
        _posts = posts;
        _inventory = inventory;
        _enrollments = enrollments;
    }

    public string Origin { get; }
    public string SecondOrigin { get; }
    public AAuthEgressPolicy Egress => AAuthEgressPolicy.ForDevelopmentLoopback(Origin, SecondOrigin);
    public ConsentScript Consent { get; }

    /// <summary>POSTs the Person Server received: person token requests and exchanges.</summary>
    public int PersonServerPosts => _posts.Value;

    /// <summary>Requests the <c>/data</c> resource received.</summary>
    public int DataRequests => _posts.Data;

    /// <summary>Hold every Person Server POST until the returned source completes.</summary>
    public TaskCompletionSource HoldPersonServer() => _posts.Hold = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public static async Task<AgentFlowHost> StartAsync()
    {
        var origin = ReserveOrigin();
        var secondOrigin = ReserveOrigin();
        var egress = AAuthEgressPolicy.ForDevelopmentLoopback(origin, secondOrigin);
        var posts = new Counter();
        var issuerKey = AAuthKey.Generate();
        var inventory = new InMemoryJtiStore();
        var enrollments = new InMemoryPersonResourceEnrollmentStore();
        var consent = new ConsentScript();
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseKestrel().UseUrls(origin, secondOrigin);
        builder.Services.AddSingleton(new MetadataClient(policy: egress));
        builder.Services.AddSingleton(new JwksClient(policy: egress));
        builder.Services.AddSingleton(new TokenVerifier { EgressPolicy = egress });
        builder.Services.AddSingleton(new AAuthVerifier());
        builder.Services.AddSingleton<UpstreamTokenValidator>();
        builder.Services.AddSingleton<IIdentityClaimsAsserter>(new Asserter());
        builder.Services.AddSingleton<IPersonPendingStore, InMemoryPersonPendingStore>();
        builder.Services.AddSingleton<IPersonResourceEnrollmentStore>(enrollments);
        builder.Services.AddAAuthGovernance();
        builder.Services.AddSingleton<IMissionTokenConsent>(consent);
        builder.Services.AddAAuthPersonServer(configure: o =>
        {
            o.Issuer = origin;
            o.EgressPolicy = egress;
            o.SigningKeys = new AAuthSigningKeySet { ["key"] = issuerKey };
            o.UnsignedPathPrefixes = ["/data"];
        }).UseTokenInventory(inventory);
        var app = builder.Build();
        app.Use(async (context, next) =>
        {
            if (context.Request.Path == "/data") posts.CountData();
            if (HttpMethods.IsPost(context.Request.Method))
            {
                posts.Increment();
                if (posts.Hold is { } hold) await hold.Task;
            }
            await next(context);
        });
        app.MapAAuthPersonServer();
        foreach (var dwk in new[] { AAuthConstants.DwkFiles.Agent, AAuthConstants.DwkFiles.Resource })
            app.MapGet("/.well-known/" + dwk, (HttpContext context) =>
            {
                var self = OriginOf(context);
                return Results.Json(new { issuer = self, jwks_uri = self + "/.well-known/jwks.json" });
            });
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
                EgressPolicy = egress, Issuer = OriginOf(context), Audience = (string)person["iss"]!,
                PersonServer = (string)person["iss"]!, Subject = (string)person["sub"]!, PresentedJti = (string)person["jti"]!,
                MissionS256 = (string?)person["mission_s256"],
                AgentJkt = KeyFactory.FromPublicJwk((System.Text.Json.Nodes.JsonObject)person["cnf"]!["jwk"]!).ComputeJwkThumbprint(),
                Key = issuerKey, KeyId = "key", Scope = "read", ScopeDescriptions = TestScopeDefinitions.Resource,
            }.BuildAsync();
            context.Response.Headers[AAuthRequirementHeader.Name] = AAuthRequirementHeader.FormatAuthToken(resource);
            return Results.StatusCode(401);
        });
        await app.StartAsync();
        return new AgentFlowHost(app, origin, secondOrigin, issuerKey, consent, posts, inventory, enrollments);
    }

    private static string ReserveOrigin()
    {
        using var reservation = new TcpListener(IPAddress.Loopback, 0);
        reservation.Start();
        var origin = "http://127.0.0.1:" + ((IPEndPoint)reservation.LocalEndpoint).Port;
        reservation.Stop();
        return origin;
    }

    private static string OriginOf(HttpContext context) => context.Request.Scheme + "://" + context.Request.Host;

    private sealed class Counter
    {
        private int _value;
        private int _data;
        public int Value => Volatile.Read(ref _value);
        public int Data => Volatile.Read(ref _data);
        public volatile TaskCompletionSource? Hold;
        public void Increment() => Interlocked.Increment(ref _value);
        public void CountData() => Interlocked.Increment(ref _data);
    }

    /// <summary>An agent token this host issues as agent provider, naming it as the Person Server.</summary>
    public ValueTask<string> AgentTokenAsync(IAAuthKey agentKey, string agentId) => new AgentTokenBuilder
    {
        EgressPolicy = Egress, Issuer = Origin, Subject = agentId, Key = _issuerKey, KeyId = "key",
        ConfirmationKey = agentKey, PersonServer = Origin,
    }.BuildAsync();

    /// <summary>An upstream auth token for an intermediary chaining on behalf of <paramref name="person"/>.</summary>
    public async ValueTask<string> UpstreamAsync(string person, string? mission = null)
    {
        var token = await new AuthTokenBuilder
    {
        EgressPolicy = Egress, Issuer = Origin, Audience = Origin, PersonServer = Origin, Key = _issuerKey, KeyId = "key",
        Subject = person, Scope = "read", MissionS256 = mission, AgentConfirmationKey = AAuthKey.Generate(),
        AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(2),
        }.BuildAsync();
        await UpstreamProvenanceTestSupport.RecordAsync(_inventory, token, Origin);
        await _enrollments.RecordAsync(new PersonResourceEnrollment(
            Origin, new AAuthPersonKey(person), Origin, person, "test", DateTimeOffset.UtcNow));
        return token;
    }

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
            => Task.FromResult(IdentityAssertion.Assert(request.PersonKey ?? new AAuthPersonKey("chain-person"), request.UpstreamAuthorization?.Subject is { } upstream
                ? "downstream-" + upstream : "person"));
    }

    /// <summary>
    /// Grants mission tokens, after one clarification round when <see cref="Clarify"/> is set and
    /// after <see cref="Delay"/> (a slow reviewer).
    /// </summary>
    public sealed class ConsentScript : IMissionTokenConsent
    {
        public bool Clarify { get; set; }
        public TimeSpan Delay { get; set; }

        public async Task<MissionTokenConsentDecision> ReviewAsync(MissionTokenConsentContext context, CancellationToken cancellationToken = default)
        {
            if (Delay > TimeSpan.Zero) await Task.Delay(Delay, cancellationToken);
            return Clarify && context.ClarificationHistory is not { Count: > 0 }
                ? MissionTokenConsentDecision.Clarify("Why does the offsite need this?")
                : MissionTokenConsentDecision.Grant();
        }
    }
}
