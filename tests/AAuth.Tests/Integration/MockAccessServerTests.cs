using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Tokens;
using AAuth.Access;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace AAuth.Tests.Integration;

/// <summary>
/// Manual PS-to-AS exercise for the shipped <c>samples/MockAccessServers/Federated/</c>
/// sample (four-party / federated access). These stand in for the real PS
/// federation client (which arrives in a later phase): the test hand-signs
/// the PS-to-AS <c>POST /token</c> request with the <c>jwks_uri</c> scheme,
/// supplies the agent + resource tokens in the body, and asserts the AS
/// mints a verifiable <c>aa-auth+jwt</c> with <c>dwk = aauth-access.json</c>.
/// </summary>
public class MockAccessServerTests : IDisposable
{
    private const string AsIssuer = "https://as.test";
    private const string PsIssuer = "https://ps.test";
    private const string ApIssuer = "https://ap.example";
    private const string ResourceUrl = "https://wallet.test";
    private const string AgentId = "aauth:demo@ap.example";

    private const string PsKid = "ps-1";
    private const string ApKid = "ap-1";
    private const string ResourceKid = "wallet-1";

    private static readonly AAuthKey PsKey = AAuthKey.Generate();
    private static readonly AAuthKey ApKey = AAuthKey.Generate();
    private static readonly AAuthKey ResourceKey = AAuthKey.Generate();
    private static readonly AAuthKey AccessRoleKey = AAuthKey.Generate();

    private readonly WebApplicationFactory<Federated.Entry> _factory;

    public MockAccessServerTests()
    {
        _factory = CreateFactory();
    }

    // Build a fully-isolated AS host. Each test gets its own factory with all
    // configuration applied in a single WithWebHostBuilder pass, so per-test
    // settings (e.g. AccessServer:RequireClaims) can never bleed across the
    // suite. (A shared IClassFixture + chained WithWebHostBuilder leaked config
    // between tests under some orderings — the base-config tests intermittently
    // saw another test's RequireClaims.)
    private static WebApplicationFactory<Federated.Entry> CreateFactory(
        Action<IWebHostBuilder>? extra = null)
        => new WebApplicationFactory<Federated.Entry>().WithWebHostBuilder(b =>
        {
            b.UseSetting("AAuth:Issuer", AsIssuer);
            b.UseIsolatedDemoConsent();
            b.UseSetting("MockAccessServer:TrustedPersonServers:0", PsIssuer);
            b.ConfigureServices(WireDiscovery);
            extra?.Invoke(b);
        });

    public void Dispose() => _factory.Dispose();

    [Theory]
    [InlineData("aauth-agent.json", false, false)]
    [InlineData("aauth-resource.json", false, false)]
    [InlineData("aauth-access.json", false, false)]
    [InlineData("aauth-agent.json", true, false)]
    [InlineData("aauth-resource.json", true, false)]
    [InlineData("aauth-access.json", true, false)]
    [InlineData("aauth-agent.json", false, true)]
    [InlineData("aauth-resource.json", false, true)]
    [InlineData("aauth-access.json", false, true)]
    public async Task CollocatedRolesCannotActAsPersonServer(string role, bool sharedKey, bool spoofPersonRole)
    {
        var policy = new ClaimTrackingPolicy();
        var discoveryTime = new FakeTimeProvider(DateTimeOffset.UtcNow);
        using var factory = CreateFactory(builder => builder.ConfigureTestServices(services =>
        {
            services.RemoveAllKeyed<IAccessPolicy>(AAuthAccessServerBuilder.DefaultName);
            services.AddKeyedSingleton<IAccessPolicy>(AAuthAccessServerBuilder.DefaultName, policy);
            services.RemoveAll<MetadataClient>();
            services.RemoveAll<JwksClient>();
            services.AddSingleton(new MetadataClient(new InProcessHttpClient(new StubDiscoveryHandler(sharedKey))));
            services.AddSingleton(new JwksClient(new InProcessHttpClient(new StubDiscoveryHandler(sharedKey)), timeProvider: discoveryTime));
        }));
        var roleKey = sharedKey ? PsKey : role switch
        {
            "aauth-agent.json" => ApKey, "aauth-resource.json" => ResourceKey, _ => AccessRoleKey,
        };
        using var attacker = new AAuthClientBuilder(roleKey)
            .UseJwksUri(PsIssuer, spoofPersonRole ? AuthTokenBuilder.PersonDwk : role, PsKid)
            .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(factory.Server.CreateHandler(), AAuthTransportContract.InProcessOnly).Build();
        attacker.BaseAddress = new Uri(AsIssuer);
        var agentKey = AAuthKey.Generate();
        var body = new JsonObject { ["agent_token"] = await BuildAgentTokenAsync(agentKey), ["resource_token"] = await BuildResourceTokenAsync(agentKey, AsIssuer), ["presented_token"] = await BuildPersonTokenAsync(agentKey) };
        var expectedStatus = spoofPersonRole ? HttpStatusCode.Unauthorized : HttpStatusCode.Forbidden;
        using var tokenAttack = await attacker.PostAsJsonAsync("/token", body);
        Assert.Equal(expectedStatus, tokenAttack.StatusCode);
        Assert.Empty(policy.Requests);
        Assert.DoesNotContain("auth_token", await tokenAttack.Content.ReadAsStringAsync());

        discoveryTime.Advance(TimeSpan.FromMinutes(1));
        using var person = BuildPsSignedClient(factory);
        using var parked = await person.PostAsJsonAsync("/token", body);
        Assert.Equal(HttpStatusCode.Accepted, parked.StatusCode);
        Assert.Single(policy.Requests);
        Assert.Equal(PsIssuer, policy.Requests[0].PersonServerIssuer);
        using var pollAttack = await attacker.GetAsync(parked.Headers.Location);
        Assert.Equal(expectedStatus, pollAttack.StatusCode);
        using var claimsAttack = await attacker.PostAsJsonAsync(parked.Headers.Location, new JsonObject
        {
            ["email"] = "attacker@example.test",
        });
        Assert.Equal(expectedStatus, claimsAttack.StatusCode);
        Assert.Single(policy.Requests);
        using var completion = await person.PostAsJsonAsync(parked.Headers.Location, new JsonObject
        {
            ["email"] = "legitimate@example.test",
        });
        Assert.Equal(HttpStatusCode.OK, completion.StatusCode);
        Assert.Equal(2, policy.Requests.Count);
        Assert.Equal("legitimate@example.test", (string?)policy.Requests[1].Claims?["email"]);
    }

    private sealed class ClaimTrackingPolicy : IAccessPolicy
    {
        public List<AccessPolicyRequest> Requests { get; } = [];
        public Task<AccessDecision> EvaluateAsync(AccessPolicyRequest request, CancellationToken cancellationToken = default)
        {
            Requests.Add(request);
            return Task.FromResult(request.Claims?["email"] is null ? AccessDecision.NeedsClaims(["email"]) : AccessDecision.Allow());
        }
    }

    [Fact]
    public async Task WrongSignerSchemeReturns401Negotiation()
    {
        using var client = new AAuthClientBuilder(PsKey).UseHwk()
            .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(_factory.Server.CreateHandler(), AAuth.Discovery.AAuthTransportContract.InProcessOnly).Build();
        using var response = await client.PostAsJsonAsync(AsIssuer + "/token", new { });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("error=unsupported_scheme", response.Headers.GetValues("Signature-Error").Single());
        Assert.Equal("jwks_uri", response.Headers.GetValues("Accept-Signature-Scheme").Single());
    }

    [Theory]
    [InlineData("act")]
    [InlineData("mission")]
    [InlineData("account")]
    [InlineData("exp")]
    public async Task Token_RejectsProtocolOwnedClaimRequests(string claim)
    {
        using var factory = CreateFactory(builder => builder.UseSetting("AccessServer:RequireClaims:0", claim));
        using var client = BuildPsSignedClient(factory);
        var key = AAuthKey.Generate();
        using var response = await client.PostAsJsonAsync("/token", new JsonObject
        {
            ["agent_token"] = await BuildAgentTokenAsync(key),
            ["resource_token"] = await BuildResourceTokenAsync(key, AsIssuer),
            ["presented_token"] = await BuildPersonTokenAsync(key),
        });
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("policy_error", (string?)body!["error"]);
        Assert.Null(body["auth_token"]);
    }

    [Theory]
    [InlineData("act")]
    [InlineData("mission")]
    [InlineData("account")]
    public async Task ClaimsPush_RejectsProtocolOwnedClaims(string claim)
    {
        using var factory = CreateFactory(builder => builder.UseSetting("AccessServer:RequireClaims:0", "email"));
        using var client = BuildPsSignedClient(factory);
        var key = AAuthKey.Generate();
        using var pending = await client.PostAsJsonAsync("/token", new JsonObject
        {
            ["agent_token"] = await BuildAgentTokenAsync(key),
            ["resource_token"] = await BuildResourceTokenAsync(key, AsIssuer),
            ["presented_token"] = await BuildPersonTokenAsync(key),
        });
        Assert.Equal(HttpStatusCode.Accepted, pending.StatusCode);
        using var response = await client.PostAsJsonAsync(pending.Headers.Location, new JsonObject
        {
            ["email"] = "user@example.test", [claim] = "injected",
        });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null((await response.Content.ReadFromJsonAsync<JsonObject>())!["auth_token"]);
    }

    [Fact]
    public async Task AccessMetadata_AdvertisesTokenEndpoint()
    {
        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(AsIssuer),
        });

        var doc = await client.GetFromJsonAsync<JsonObject>("/.well-known/aauth-access.json");

        Assert.NotNull(doc);
        Assert.Equal(AsIssuer, (string?)doc!["issuer"]);
        Assert.Equal($"{AsIssuer}/.well-known/jwks.json", (string?)doc["jwks_uri"]);
        Assert.Equal($"{AsIssuer}/token", (string?)doc["auth_token_endpoint"]);
        Assert.False(doc.ContainsKey("token_endpoint"));
    }

    [Fact]
    public async Task Token_MintsAccessAuthToken_BoundToAgentKey()
    {
        var agentKey = AAuthKey.Generate();
        var agentToken = await BuildAgentTokenAsync(agentKey);
        var resourceToken = await BuildResourceTokenAsync(agentKey, audience: AsIssuer);

        using var http = BuildPsSignedClient();
        var response = await http.PostAsJsonAsync("/token", new JsonObject
        {
            ["agent_token"] = agentToken,
            ["resource_token"] = resourceToken,
            ["presented_token"] = await BuildPersonTokenAsync(agentKey),
        });

        Assert.True(response.IsSuccessStatusCode,
            $"Status={(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        var authTokenJwt = (string?)body!["auth_token"];
        Assert.False(string.IsNullOrEmpty(authTokenJwt));

        var segments = authTokenJwt!.Split('.');
        Assert.Equal(3, segments.Length);
        var header = (JsonObject)JsonNode.Parse(
            Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(segments[0]))!;
        var payload = (JsonObject)JsonNode.Parse(
            Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(segments[1]))!;

        Assert.Equal(AuthTokenBuilder.TokenType, (string?)header["typ"]);
        // The four-party discriminator: dwk = aauth-access.json (not aauth-person.json).
        Assert.Equal(AuthTokenBuilder.AccessDwk, (string?)payload["dwk"]);
        Assert.Equal(AsIssuer, (string?)payload["iss"]);
        Assert.Equal(ResourceUrl, (string?)payload["aud"]);
        Assert.Equal(PsIssuer, (string?)payload["ps"]);
        Assert.Equal(PersonSubject, (string?)payload["sub"]);
        Assert.Null(payload["agent"]);
        Assert.Equal("wallet.read", (string?)payload["scope"]);

        // cnf.jwk binds to the agent's key.
        var cnfJwk = payload["cnf"]?["jwk"] as JsonObject;
        Assert.NotNull(cnfJwk);
        Assert.Equal(agentKey.ComputeJwkThumbprint(), AAuthKey.FromJwk(cnfJwk!).ComputeJwkThumbprint());
    }

    [Fact]
    public async Task Token_RejectsResourceTokenForDifferentAudience()
    {
        // A resource token whose aud is the PS (three-party) must NOT be
        // accepted by the AS — the AS only mints when aud = its own issuer.
        var agentKey = AAuthKey.Generate();
        var agentToken = await BuildAgentTokenAsync(agentKey);
        var resourceToken = await BuildResourceTokenAsync(agentKey, audience: PsIssuer);

        using var http = BuildPsSignedClient();
        var response = await http.PostAsJsonAsync("/token", new JsonObject
        {
            ["agent_token"] = agentToken,
            ["resource_token"] = resourceToken,
            ["presented_token"] = await BuildPersonTokenAsync(agentKey),
        });

        // §Token Endpoint Error Codes: a resource_token that fails verification
        // (here, aud mismatch) is a 400 invalid_resource_token, not a 401 — 401 is
        // reserved for request-signature failures carrying a Signature-Error header.
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_resource_token", (string?)body!["error"]);
        Assert.False(string.IsNullOrWhiteSpace((string?)body["detail"]));
        Assert.False(body.ContainsKey("error_description"));
        Assert.False(response.Headers.Contains("Signature-Error"));
    }

    [Fact]
    public async Task Token_RejectsUntrustedPersonServer()
    {
        // A request whose jwks_uri host is resolvable (signature verifies) but
        // not in the trusted-PS set is refused by the trust check (403).
        var agentKey = AAuthKey.Generate();
        var agentToken = await BuildAgentTokenAsync(agentKey);
        var resourceToken = await BuildResourceTokenAsync(agentKey, audience: AsIssuer);

        using var http = new AAuthClientBuilder(PsKey)
            .UseJwksUri("https://other-ps.test", AAuthConstants.DwkFiles.Person, PsKid)
            .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(_factory.Server.CreateHandler(), AAuth.Discovery.AAuthTransportContract.InProcessOnly)
            .Build();
        http.BaseAddress = new Uri(AsIssuer);

        var response = await http.PostAsJsonAsync("/token", new JsonObject
        {
            ["agent_token"] = agentToken,
            ["resource_token"] = resourceToken,
            ["presented_token"] = await BuildPersonTokenAsync(agentKey),
        });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Token_GrantsElevatedScope_ForAdminAgent()
    {
        // The default stub policy grants wallet.charge to an admin agent
        // (the demo convention: the exact agent id "aauth:demo@ap.example").
        var agentKey = AAuthKey.Generate();
        var agentToken = await BuildAgentTokenAsync(agentKey, AgentId);
        var resourceToken = await BuildResourceTokenAsync(agentKey, audience: AsIssuer, agent: AgentId, scope: "wallet.charge");

        using var http = BuildPsSignedClient();
        var response = await http.PostAsJsonAsync("/token", new JsonObject
        {
            ["agent_token"] = agentToken,
            ["resource_token"] = resourceToken,
            ["presented_token"] = await BuildPersonTokenAsync(agentKey),
        });

        Assert.True(response.IsSuccessStatusCode,
            $"Status={(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        var payload = (JsonObject)JsonNode.Parse(
            Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(
                ((string?)body!["auth_token"])!.Split('.')[1]))!;
        Assert.Equal("wallet.charge", (string?)payload["scope"]);
    }

    [Fact]
    public async Task Token_DeniesElevatedScope_ForNonAdminAgent()
    {
        // A non-admin agent requesting wallet.charge is denied by the stub
        // policy (no wallet.payer role) → 403 denied.
        const string GuestId = "aauth:guest@ap.example";
        var agentKey = AAuthKey.Generate();
        var agentToken = await BuildAgentTokenAsync(agentKey, GuestId);
        var resourceToken = await BuildResourceTokenAsync(agentKey, audience: AsIssuer, agent: GuestId, scope: "wallet.charge");

        using var http = BuildPsSignedClient();
        var response = await http.PostAsJsonAsync("/token", new JsonObject
        {
            ["agent_token"] = agentToken,
            ["resource_token"] = resourceToken,
            ["presented_token"] = await BuildPersonTokenAsync(agentKey),
        });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("denied", (string?)body!["error"]);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.False(string.IsNullOrWhiteSpace((string?)body["detail"]));
        Assert.False(response.Headers.Contains("Signature-Error"));
    }

    [Fact]
    public async Task ClaimsPush_FromTrustedPersonServer_MintsAuthToken()
    {
        // §Claims Required: with a configured claim requirement the stub policy
        // parks a requirement=claims, the PS pushes a directed sub + the claim,
        // and the AS mints the auth token asserting it.
        using var factory = CreateFactory(b =>
            b.UseSetting("AccessServer:RequireClaims:0", "email"));

        var agentKey = AAuthKey.Generate();
        using var http = BuildPsSignedClient(factory);
        var token = await http.PostAsJsonAsync("/token", new JsonObject
        {
            ["agent_token"] = await BuildAgentTokenAsync(agentKey),
            ["resource_token"] = await BuildResourceTokenAsync(agentKey, audience: AsIssuer),
            ["presented_token"] = await BuildPersonTokenAsync(agentKey),
        });

        Assert.Equal(HttpStatusCode.Accepted, token.StatusCode);
        var pendingPath = token.Headers.Location!.OriginalString;
        var requirement = await token.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("email", (string?)requirement!["required_claims"]?[0]);

        var push = await http.PostAsJsonAsync(pendingPath, new JsonObject
        {
            ["email"] = "demo@person.example",
        });

        Assert.True(push.IsSuccessStatusCode,
            $"Status={(int)push.StatusCode} {await push.Content.ReadAsStringAsync()}");
        var body = await push.Content.ReadFromJsonAsync<JsonObject>();
        var payload = (JsonObject)JsonNode.Parse(
            Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(
                ((string?)body!["auth_token"])!.Split('.')[1]))!;
        // §Claims Required: sub is the presented token's, never a pushed claim.
        Assert.Equal(PersonSubject, (string?)payload["sub"]);
        Assert.Equal("demo@person.example", (string?)payload["email"]);
    }

    [Fact]
    public async Task ClaimsPush_FromUntrustedPersonServer_IsRejected()
    {
        // F2: the pending push re-pins the caller. A different (untrusted)
        // Person Server cannot push a sub/claims into another PS's entry.
        using var factory = CreateFactory(b =>
            b.UseSetting("AccessServer:RequireClaims:0", "email"));

        var agentKey = AAuthKey.Generate();
        using var trusted = BuildPsSignedClient(factory);
        var token = await trusted.PostAsJsonAsync("/token", new JsonObject
        {
            ["agent_token"] = await BuildAgentTokenAsync(agentKey),
            ["resource_token"] = await BuildResourceTokenAsync(agentKey, audience: AsIssuer),
            ["presented_token"] = await BuildPersonTokenAsync(agentKey),
        });
        Assert.Equal(HttpStatusCode.Accepted, token.StatusCode);
        var pendingPath = token.Headers.Location!.OriginalString;

        using var attacker = new AAuthClientBuilder(PsKey)
            .UseJwksUri("https://other-ps.test", AAuthConstants.DwkFiles.Person, PsKid)
            .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(factory.Server.CreateHandler(), AAuth.Discovery.AAuthTransportContract.InProcessOnly)
            .Build();
        attacker.BaseAddress = new Uri(AsIssuer);

        var push = await attacker.PostAsJsonAsync(pendingPath, new JsonObject
        {
            ["email"] = "evil@attacker.example",
        });

        Assert.Equal(HttpStatusCode.Forbidden, push.StatusCode);
        var body = await push.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("untrusted_person_server", (string?)body!["error"]);
    }

    [Fact]
    public async Task Token_MissingAgentToken_ReturnsProblemDetails()
    {
        using var http = BuildPsSignedClient();
        var response = await http.PostAsJsonAsync("/token", new JsonObject());
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_request", (string?)body!["error"]);
        Assert.Equal("agent_token, resource_token and presented_token are required", (string?)body["detail"]);
    }

    // -- helpers ---------------------------------------------------------

    private HttpClient BuildPsSignedClient()
    {
        var http = new AAuthClientBuilder(PsKey)
            .UseJwksUri(PsIssuer, AAuthConstants.DwkFiles.Person, PsKid)
            .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(_factory.Server.CreateHandler(), AAuth.Discovery.AAuthTransportContract.InProcessOnly)
            .Build();
        http.BaseAddress = new Uri(AsIssuer);
        return http;
    }

    private static HttpClient BuildPsSignedClient(WebApplicationFactory<Federated.Entry> factory)
    {
        var http = new AAuthClientBuilder(PsKey)
            .UseJwksUri(PsIssuer, AAuthConstants.DwkFiles.Person, PsKid)
            .WithEgressPolicy(TestEgress.Policy).WithInnerHandler(factory.Server.CreateHandler(), AAuth.Discovery.AAuthTransportContract.InProcessOnly)
            .Build();
        http.BaseAddress = new Uri(AsIssuer);
        return http;
    }

    private static ValueTask<string> BuildAgentTokenAsync(AAuthKey agentKey) =>
        new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = ApIssuer,
            Subject = AgentId,
            KeyId = ApKid,
            Key = ApKey,                  // AP signs the token.
            ConfirmationKey = agentKey,   // bound to the agent's key (cnf.jwk).
            PersonServer = PsIssuer,
        }.BuildAsync();

    private static ValueTask<string> BuildAgentTokenAsync(AAuthKey agentKey, string agent) =>
        new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = ApIssuer,
            Subject = agent,
            KeyId = ApKid,
            Key = ApKey,
            ConfirmationKey = agentKey,
            PersonServer = PsIssuer,
        }.BuildAsync();

    private const string PersonSubject = "person-1";
    private const string PersonJti = "person-jti-1";

    // The person token the PS presented to the resource (§PS-to-AS Token Request).
    private static ValueTask<string> BuildPersonTokenAsync(AAuthKey agentKey) =>
        new PersonTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = PsIssuer,
            Audience = ResourceUrl,
            Subject = PersonSubject,
            TokenId = PersonJti,
            ConfirmationKey = agentKey,
            AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            Key = PsKey,
            KeyId = PsKid,
        }.BuildAsync();

    private static ValueTask<string> BuildResourceTokenAsync(AAuthKey agentKey, string audience, string agent, string scope) =>
        new ResourceTokenBuilder
        {
            ScopeDescriptions = TestScopeDefinitions.Resource,
            EgressPolicy = TestEgress.Policy,
            Issuer = ResourceUrl,
            Audience = audience,
            PersonServer = PsIssuer,
            Subject = PersonSubject,
            PresentedJti = PersonJti,
            AgentJkt = agentKey.ComputeJwkThumbprint(),
            Key = ResourceKey,
            KeyId = ResourceKid,
            Scope = scope,
        }.BuildAsync();

    private static ValueTask<string> BuildResourceTokenAsync(AAuthKey agentKey, string audience) =>
        BuildResourceTokenAsync(agentKey, audience, AgentId, "wallet.read");

    /// <summary>
    /// Replace the AS's discovery clients so that, in-process, it can resolve:
    /// the PS's JWKS (HTTP-signature key), the AP's agent metadata + JWKS
    /// (agent-token verification), and the resource's metadata + JWKS
    /// (resource-token verification).
    /// </summary>
    private static void WireDiscovery(IServiceCollection services)
    {
        services.RemoveAll<MetadataClient>();
        services.RemoveAll<JwksClient>();
        services.AddSingleton(new MetadataClient(new InProcessHttpClient(new StubDiscoveryHandler())));
        services.AddSingleton(new JwksClient(new InProcessHttpClient(new StubDiscoveryHandler())));
    }

    private sealed class StubDiscoveryHandler(bool sharedRoleKeys = false) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var uri = request.RequestUri!;
            var key = $"{uri.Host}{uri.AbsolutePath}";
            string? json = key switch
            {
                "ps.test/.well-known/aauth-person.json" => Metadata(PsIssuer),
                "ps.test/.well-known/aauth-agent.json" => Metadata(PsIssuer, "/agent-keys"),
                "ps.test/.well-known/aauth-resource.json" => Metadata(PsIssuer, "/resource-keys"),
                "ps.test/.well-known/aauth-access.json" => Metadata(PsIssuer, "/access-keys"),
                "ps.test/agent-keys" => Jwks(sharedRoleKeys ? PsKey : ApKey, PsKid),
                "ps.test/resource-keys" => Jwks(sharedRoleKeys ? PsKey : ResourceKey, PsKid),
                "ps.test/access-keys" => Jwks(sharedRoleKeys ? PsKey : AccessRoleKey, PsKid),
                "other-ps.test/.well-known/aauth-person.json" => Metadata("https://other-ps.test"),
                "ps.test/.well-known/jwks.json" => Jwks(PsKey, PsKid),
                "other-ps.test/.well-known/jwks.json" => Jwks(PsKey, PsKid),
                "ap.example/.well-known/aauth-agent.json" => Metadata(ApIssuer),
                "ap.example/.well-known/jwks.json" => Jwks(ApKey, ApKid),
                "wallet.test/.well-known/aauth-resource.json" => Metadata(ResourceUrl),
                "wallet.test/.well-known/jwks.json" => Jwks(ResourceKey, ResourceKid),
                _ => null,
            };

            if (json is null)
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            });
        }

        private static string Metadata(string issuer, string path = "/.well-known/jwks.json") => new JsonObject
        {
            ["issuer"] = issuer,
            ["jwks_uri"] = issuer + path,
        }.ToJsonString();

        private static string Jwks(AAuthKey key, string kid)
        {
            var jwk = key.ToPublicJwk();
            jwk["kid"] = kid;
            jwk["use"] = "sig";
            jwk["alg"] = AAuthKey.Ed25519Algorithm;
            return new JsonObject { ["keys"] = new JsonArray(jwk) }.ToJsonString();
        }
    }
}
