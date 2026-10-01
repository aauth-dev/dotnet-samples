using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Tokens;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AAuth.Tests.Integration;

/// <summary>
/// Unit-tests for the shipped <c>samples/MockPersonServer/</c> sample.
///
/// These exercise the same endpoints the agent's <see cref="TokenExchangeClient"/>
/// will hit at runtime, without spinning up Calendar. The integration tests
/// in <see cref="CalendarFlowTests"/> exercise the same sample in the full
/// three-party flow alongside Calendar.
/// </summary>
public class MockPersonServerTests : IClassFixture<WebApplicationFactory<MockPersonServer.Entry>>, IDisposable
{
    private const string PsIssuer = "https://ps.test";
    private readonly WebApplicationFactory<MockPersonServer.Entry> _factory;

    public MockPersonServerTests(WebApplicationFactory<MockPersonServer.Entry> factory)
    {
        // WithWebHostBuilder returns a NEW factory instance owned by this
        // test class; the xUnit-managed fixture only owns the original.
        // Dispose it explicitly in Dispose to release the in-memory host.
        _factory = factory.WithWebHostBuilder(b =>
        {
            b.UseSetting("AAuth:Issuer", PsIssuer);
            b.UseIsolatedDemoConsent();
            b.ConfigureServices(ResourceStub.WireDiscovery);
        });
    }

    public void Dispose() => _factory.Dispose();

    [Fact]
    public async Task PersonMetadata_AdvertisesTokenEndpoint()
    {
        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(PsIssuer),
        });

        var doc = await client.GetFromJsonAsync<JsonObject>("/.well-known/aauth-person.json");

        Assert.NotNull(doc);
        Assert.Equal(PsIssuer, (string?)doc!["issuer"]);
        Assert.Equal($"{PsIssuer}/.well-known/jwks.json", (string?)doc["jwks_uri"]);
        Assert.Equal($"{PsIssuer}/token", (string?)doc["auth_token_endpoint"]);
        Assert.Equal($"{PsIssuer}/person", (string?)doc["person_token_endpoint"]);
        Assert.False(doc.ContainsKey("token_endpoint"));
    }

    [Fact]
    public async Task Jwks_PublishesAtLeastOneSigningKey()
    {
        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(PsIssuer),
        });

        var jwks = await client.GetFromJsonAsync<JsonObject>("/.well-known/jwks.json");

        Assert.NotNull(jwks);
        var keys = jwks!["keys"] as JsonArray;
        Assert.NotNull(keys);
        Assert.NotEmpty(keys!);
        var key = (JsonObject)keys![0]!;
        Assert.Equal(AAuthKey.Ed25519Algorithm, (string?)key["alg"]);
        Assert.Equal("sig", (string?)key["use"]);
        Assert.False(string.IsNullOrEmpty((string?)key["kid"]));
    }

    [Fact]
    public async Task Token_MintsAuthToken_BoundToAgentKey()
    {
        var agentKey = AAuthKey.Generate();
        var agentToken = await new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://ap.example",
            Subject = "aauth:demo@ap.example",
            KeyId = "demo",
            Key = ResourceStub.ApKey,
            ConfirmationKey = agentKey,
            PersonServer = PsIssuer,
        }.BuildAsync();

        // Sign the POST /token request with the agent's key + agent token.
        var signing = new AAuthSigningHandler(agentKey, () => agentToken)
        {
            InnerHandler = _factory.Server.CreateHandler(),
        };
        using var http = new InProcessHttpClient(signing)
        {
            BaseAddress = new Uri(PsIssuer),
        };

        // §Person Token Endpoint: the agent first learns who it acts for at the
        // resource; the resource then names that person token in presented_jti.
        const string ResourceUrl = ResourceStub.Url;
        var personToken = await PersonTokenFlow.RequestAsync(http, ResourceUrl);
        var person = PersonTokenFlow.Payload(personToken);
        Assert.Equal(PsIssuer, (string?)person["iss"]);
        Assert.Equal(ResourceUrl, (string?)person["aud"]);
        Assert.Null(person["scope"]);
        var resourceToken = await PersonTokenFlow.ResourceTokenAsync(personToken, agentKey);

        var response = await http.PostAsJsonAsync("/token", PersonTokenFlow.Body(resourceToken, personToken));

        Assert.True(response.IsSuccessStatusCode,
            $"Status={(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        var authTokenJwt = (string?)body!["auth_token"];
        Assert.False(string.IsNullOrEmpty(authTokenJwt));

        // Decode and assert spec-mandated claim shape.
        var segments = authTokenJwt!.Split('.');
        Assert.Equal(3, segments.Length);
        var header = (JsonObject)JsonNode.Parse(
            Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(segments[0]))!;
        var payload = (JsonObject)JsonNode.Parse(
            Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(segments[1]))!;

        Assert.Equal(AuthTokenBuilder.TokenType, (string?)header["typ"]);
        Assert.Equal(AAuthKey.Ed25519Algorithm, (string?)header["alg"]);
        Assert.Equal(PsIssuer, (string?)payload["iss"]);
        Assert.Equal(PsIssuer, (string?)payload["ps"]);
        Assert.Equal(ResourceUrl, (string?)payload["aud"]);
        Assert.Equal((string?)person["sub"], (string?)payload["sub"]);
        Assert.Null(payload["agent"]);
        Assert.Equal(AuthTokenBuilder.PersonDwk, (string?)payload["dwk"]);
        Assert.True((long)payload["exp"]! <= (long)person["exp"]!);

        // cnf.jwk binds to the agent's key.
        var cnfJwk = payload["cnf"]?["jwk"] as JsonObject;
        Assert.NotNull(cnfJwk);
        var boundKey = AAuthKey.FromJwk(cnfJwk!);
        Assert.Equal(agentKey.ComputeJwkThumbprint(), boundKey.ComputeJwkThumbprint());
    }

    [Fact]
    public async Task Token_RejectsAuthTokenAsCarrier()
    {
        // Posting /token signed with an auth token (not an agent token)
        // must be refused — only agents may exchange.
        var agentKey = AAuthKey.Generate();
        var psKey = AAuthKey.Generate();
        var authTokenAsCarrier = await new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = System.DateTimeOffset.UtcNow.AddHours(1),
            Issuer = "https://ps.example",
            Audience = "https://calendar.test",
            PersonServer = "https://ps.example",
            AgentConfirmationKey = agentKey,
            Key = psKey,
            KeyId = "ps-x",
            Subject = "pairwise",
            Scope = "calendar.read",
        }.BuildAsync();

        var signing = new AAuthSigningHandler(agentKey, () => authTokenAsCarrier)
        {
            InnerHandler = _factory.Server.CreateHandler(),
        };
        using var http = new InProcessHttpClient(signing)
        {
            BaseAddress = new Uri(PsIssuer),
        };

        var response = await http.PostAsJsonAsync("/token",
            new JsonObject { ["resource_token"] = "irrelevant" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.True(response.Headers.Contains("Signature-Error"));
    }

    [Fact]
    public async Task Token_RejectsMissingResourceToken()
    {
        var agentKey = AAuthKey.Generate();
        var agentToken = await new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://ap.example",
            Subject = "aauth:demo@ap.example",
            KeyId = "demo",
            Key = ResourceStub.ApKey,
            ConfirmationKey = agentKey,
            PersonServer = PsIssuer,
        }.BuildAsync();

        var signing = new AAuthSigningHandler(agentKey, () => agentToken)
        {
            InnerHandler = _factory.Server.CreateHandler(),
        };
        using var http = new InProcessHttpClient(signing)
        {
            BaseAddress = new Uri(PsIssuer),
        };

        var response = await http.PostAsJsonAsync("/token", new JsonObject());

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_request", (string?)body!["error"]);
    }

    [Fact]
    public async Task Token_RejectsForgedResourceToken()
    {
        // A resource token signed by a key the resource's published JWKS
        // does not hold must be rejected at /token (Phase 10, §G9): the PS
        // now verifies the resource token's signature before minting.
        var agentKey = AAuthKey.Generate();
        var agentToken = await new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://ap.example",
            Subject = "aauth:demo@ap.example",
            KeyId = "demo",
            Key = ResourceStub.ApKey,
            ConfirmationKey = agentKey,
            PersonServer = PsIssuer,
        }.BuildAsync();

        var signing = new AAuthSigningHandler(agentKey, () => agentToken)
        {
            InnerHandler = _factory.Server.CreateHandler(),
        };
        using var http = new InProcessHttpClient(signing) { BaseAddress = new Uri(PsIssuer) };

        // Signed with a freshly generated key — NOT ResourceStub.Key — but
        // carrying the published kid, so the PS resolves the genuine key and
        // the signature check fails.
        var personToken = await PersonTokenFlow.RequestAsync(http, ResourceStub.Url);
        var forged = await PersonTokenFlow.ResourceTokenAsync(personToken, agentKey, key: AAuthKey.Generate());

        var response = await http.PostAsJsonAsync("/token", PersonTokenFlow.Body(forged, personToken));

        // §Token Endpoint Error Codes: invalid_resource_token is a 400 (a bad token
        // in the body), not a 401 — 401 is reserved for request-signature failures
        // carrying a Signature-Error header (§Authentication Errors).
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_resource_token", (string?)body!["error"]);
    }

    [Fact]
    public async Task Token_RejectsTamperedResourceToken()
    {
        // Mutate the payload of a genuine resource token after signing; the
        // signature no longer matches → rejected at /token.
        var agentKey = AAuthKey.Generate();
        var agentToken = await new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://ap.example",
            Subject = "aauth:demo@ap.example",
            KeyId = "demo",
            Key = ResourceStub.ApKey,
            ConfirmationKey = agentKey,
            PersonServer = PsIssuer,
        }.BuildAsync();

        var signing = new AAuthSigningHandler(agentKey, () => agentToken)
        {
            InnerHandler = _factory.Server.CreateHandler(),
        };
        using var http = new InProcessHttpClient(signing) { BaseAddress = new Uri(PsIssuer) };

        var personToken = await PersonTokenFlow.RequestAsync(http, ResourceStub.Url);
        var genuine = await PersonTokenFlow.ResourceTokenAsync(personToken, agentKey);

        // Tamper: flip the scope to a privileged one without re-signing.
        var segments = genuine.Split('.');
        var payload = (JsonObject)JsonNode.Parse(
            Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(segments[1]))!;
        payload["scope"] = "calendar.write";
        segments[1] = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(
            payload.ToJsonString());
        var tampered = string.Join('.', segments);

        var response = await http.PostAsJsonAsync("/token", PersonTokenFlow.Body(tampered, personToken));

        // §Token Endpoint Error Codes: invalid_resource_token is a 400 (a bad token
        // in the body), not a 401 — 401 is reserved for request-signature failures
        // carrying a Signature-Error header (§Authentication Errors).
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_resource_token", (string?)body!["error"]);
    }

    [Fact]
    public async Task Token_RequiresPresentedToken()
    {
        var agentKey = AAuthKey.Generate();
        using var http = await SignedAgentAsync(agentKey);
        var personToken = await PersonTokenFlow.RequestAsync(http, ResourceStub.Url);
        var response = await http.PostAsJsonAsync("/token",
            new JsonObject { ["resource_token"] = await PersonTokenFlow.ResourceTokenAsync(personToken, agentKey) });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_request", (string?)(await response.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
    }

    [Theory]
    [InlineData("sub")]
    [InlineData("presented_jti")]
    [InlineData("ps")]
    public async Task Token_RejectsResourceTokenThatDoesNotPairWithPresentedToken(string claim)
    {
        var agentKey = AAuthKey.Generate();
        using var http = await SignedAgentAsync(agentKey);
        var personToken = await PersonTokenFlow.RequestAsync(http, ResourceStub.Url);
        var resourceToken = await PersonTokenFlow.ResourceTokenAsync(personToken, agentKey, mutate: claim);
        var response = await http.PostAsJsonAsync("/token", PersonTokenFlow.Body(resourceToken, personToken));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_resource_token", (string?)(await response.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
    }

    [Fact]
    public async Task Token_RejectsAgentTokenAsPresentedToken()
    {
        var agentKey = AAuthKey.Generate();
        var signedAgent = await SignedAgentWithTokenAsync(agentKey);
        using var http = signedAgent.Client;
        var agentToken = signedAgent.AgentToken;
        var personToken = await PersonTokenFlow.RequestAsync(http, ResourceStub.Url);
        var response = await http.PostAsJsonAsync("/token",
            PersonTokenFlow.Body(await PersonTokenFlow.ResourceTokenAsync(personToken, agentKey), agentToken));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_presented_token", (string?)(await response.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("ftp://calendar.test")]
    [InlineData("https://calendar.test/?q=1")]
    public async Task PersonToken_RejectsInvalidResource(string? resource)
    {
        using var http = await SignedAgentAsync(AAuthKey.Generate());
        var response = await http.PostAsJsonAsync("/person", new JsonObject { ["resource"] = resource });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_request", (string?)(await response.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
    }

    [Fact]
    public async Task PersonToken_RejectsUnknownMission()
    {
        using var http = await SignedAgentAsync(AAuthKey.Generate());
        var response = await http.PostAsJsonAsync("/person", new JsonObject
        {
            ["resource"] = ResourceStub.Url,
            ["mission_s256"] = Mission.ComputeS256(System.Text.Encoding.UTF8.GetBytes("{}")),
        });
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("mission_not_found", (string?)(await response.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
    }

    private async Task<InProcessHttpClient> SignedAgentAsync(AAuthKey agentKey) => (await SignedAgentWithTokenAsync(agentKey)).Client;

    private async Task<(InProcessHttpClient Client, string AgentToken)> SignedAgentWithTokenAsync(AAuthKey agentKey)
    {
        var token = await new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://ap.example",
            Subject = "aauth:demo@ap.example",
            KeyId = "demo",
            Key = ResourceStub.ApKey,
            ConfirmationKey = agentKey,
            PersonServer = PsIssuer,
        }.BuildAsync();
        return (new InProcessHttpClient(new AAuthSigningHandler(agentKey, () => token)
        {
            InnerHandler = _factory.Server.CreateHandler(),
        })
        { BaseAddress = new Uri(PsIssuer) }, token);
    }
}

/// <summary>
/// The draft-11 agent side of a three-party grant against the MockPersonServer:
/// obtain a person token, have the (stub) resource issue a resource token naming
/// it, and send both to the auth token endpoint.
/// </summary>
internal static class PersonTokenFlow
{
    public static async Task<string> RequestAsync(HttpClient signedAgent, string resource, string? missionS256 = null)
    {
        var body = new JsonObject { ["resource"] = resource };
        if (missionS256 is not null) body["mission_s256"] = missionS256;
        using var response = await signedAgent.PostAsJsonAsync("/person", body);
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, $"person token: {(int)response.StatusCode} {text}");
        return (string)JsonNode.Parse(text)!["person_token"]!;
    }

    public static JsonObject Payload(string jwt) =>
        JsonNode.Parse(Base64UrlEncoder.DecodeBytes(jwt.Split('.')[1]))!.AsObject();

    public static async Task<string> ResourceTokenAsync(string personToken, AAuthKey agentKey, string? account = null,
        string scope = "calendar.read", AAuthKey? key = null, string? mutate = null)
    {
        var person = Payload(personToken);
        return await new ResourceTokenBuilder
        {
            Account = account,
            ScopeDescriptions = TestScopeDefinitions.Resource,
            EgressPolicy = TestEgress.Policy,
            Issuer = (string)person["aud"]!,
            Audience = (string)person["iss"]!,
            PersonServer = mutate == "ps" ? "https://other-ps.test" : (string)person["iss"]!,
            Subject = mutate == "sub" ? "someone-else" : (string)person["sub"]!,
            PresentedJti = mutate == "presented_jti" ? "other-jti" : (string)person["jti"]!,
            MissionS256 = (string?)person["mission_s256"],
            Tenant = (string?)person["tenant"],
            AgentJkt = agentKey.ComputeJwkThumbprint(),
            Key = key ?? ResourceStub.Key,
            KeyId = ResourceStub.Kid,
            Scope = scope,
        }.BuildAsync();
    }

    public static JsonObject Body(string resourceToken, string presentedToken) =>
        new() { ["resource_token"] = resourceToken, ["presented_token"] = presentedToken };

    /// <summary>Person token, then the paired token request body, for one agent client.</summary>
    public static async Task<JsonObject> TokenRequestAsync(HttpClient signedAgent, AAuthKey agentKey, string? account = null)
    {
        var personToken = await RequestAsync(signedAgent, ResourceStub.Url);
        return Body(await ResourceTokenAsync(personToken, agentKey, account), personToken);
    }
}

/// <summary>
/// Consent-gated MockPS scenarios: tests against an instance configured
/// with <c>MockPersonServer:RequireConsent=true</c>, exercising the
/// 202 → admin consent → 200 pending loop.
/// </summary>
public class MockPersonServerConsentTests : IClassFixture<MockPersonServerConsentTests.ConsentFactory>
{
    private const string PsIssuer = "https://ps.test";
    private const string ResourceUrl = "https://calendar.test";
    private readonly ConsentFactory _factory;

    public MockPersonServerConsentTests(ConsentFactory factory)
    {
        _factory = factory;
    }

    public sealed class ConsentFactory : WebApplicationFactory<MockPersonServer.Entry>
    {
        protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
        {
            builder.UseSetting("AAuth:Issuer", PsIssuer);
            builder.UseIsolatedDemoConsent();
            builder.UseSetting("MockPersonServer:RequireConsent", "true");
            builder.ConfigureServices(ResourceStub.WireDiscovery);
        }
    }

    [Theory]
    [InlineData(false, "GET")]
    [InlineData(false, "DELETE")]
    [InlineData(true, "GET")]
    [InlineData(true, "DELETE")]
    public async Task MissionAndPermissionPendingBindOwnerKeyAndRetainCancellation(bool permission, string method)
    {
        var key = AAuthKey.Generate();
        var (owner, _, _) = await BuildSignedAgentClientAsync(key);
        using var signedOwner = owner;
        var entry = _factory.Services.GetRequiredService<MockPersonServer.MissionPendingStore>().Add(new MockPersonServer.MissionPendingEntry
        {
            Kind = permission ? MockPersonServer.MissionPendingKind.Permission : MockPersonServer.MissionPendingKind.Mission,
            AgentId = "aauth:demo@ap.example", OwnerIssuer = "https://ap.example",
            OwnerKeyThumbprint = key.ComputeJwkThumbprint(), S256 = "test", PersonServer = PsIssuer,
        });
        var path = (permission ? "/permission-pending/" : "/mission-create-pending/") + entry.Id;
        var (attacker, _, _) = await BuildSignedAgentClientAsync(AAuthKey.Generate());
        using var signedAttacker = attacker;
        using var foreign = await attacker.SendAsync(new HttpRequestMessage(new HttpMethod(method), path));
        Assert.Equal(HttpStatusCode.Gone, foreign.StatusCode);
        var body = await foreign.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_code", (string?)body?["error"]);
        using var cancel = await owner.DeleteAsync(path);
        Assert.Equal(HttpStatusCode.NoContent, cancel.StatusCode);
        using var replay = await owner.GetAsync(path);
        Assert.Equal(HttpStatusCode.Gone, replay.StatusCode);
        Assert.False(entry.Decide(true));
    }

    [Fact]
    public async Task Token_Returns202WithInteractionRequirement_WhenConsentMissing()
    {
        var agentKey = AAuthKey.Generate();
        var (signedClient, _, _) = await BuildSignedAgentClientAsync(agentKey, "aauth:demo@ap.example");
        using var response = await signedClient.PostAsJsonAsync("/token",
            await PersonTokenFlow.TokenRequestAsync(signedClient, agentKey));

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.NotNull(response.Headers.Location);
        Assert.True(response.Headers.TryGetValues("AAuth-Requirement", out var values));
        var parsed = AAuth.Headers.AAuthRequirementHeader.Parse(string.Join(", ", values!));
        var interaction = AAuth.Headers.Interaction.FromRequirement(parsed);
        Assert.NotNull(interaction);
        Assert.StartsWith($"{PsIssuer}/interaction", interaction!.Url);
        Assert.False(string.IsNullOrEmpty(interaction.Code));
    }

    [Fact]
    public async Task Pending_FlipsFrom202To200_AfterAdminConsent()
    {
        var agentKey = AAuthKey.Generate();
        var agentId = "aauth:demo@ap.example";
        var (signedClient, plainHttp, _) = await BuildSignedAgentClientAsync(agentKey, agentId);
        using var initial = await signedClient.PostAsJsonAsync("/token",
            await PersonTokenFlow.TokenRequestAsync(signedClient, agentKey));
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
        var pendingPath = initial.Headers.Location!.OriginalString;

        // First poll: still pending.
        using var pending1 = await signedClient.GetAsync(pendingPath);
        Assert.Equal(HttpStatusCode.Accepted, pending1.StatusCode);

        // Simulate the user clicking "Approve".
        using var admin = await plainHttp.PostAsJsonAsync("/admin/consent", new JsonObject
        {
            ["agent"] = agentId,
            ["resource"] = ResourceUrl,
            ["scope"] = "calendar.read",
            ["key"] = agentKey.ComputeJwkThumbprint(),
        });
        Assert.True(admin.IsSuccessStatusCode);

        // Next poll: terminal 200 + auth_token.
        using var pending2 = await signedClient.GetAsync(pendingPath);
        Assert.Equal(HttpStatusCode.OK, pending2.StatusCode);
        var body = await pending2.Content.ReadFromJsonAsync<JsonObject>();
        Assert.False(string.IsNullOrEmpty((string?)body!["auth_token"]));
    }

    [Fact]
    public async Task Pending_ReturnsImmediate200_WhenConsentPreRecorded()
    {
        var agentKey = AAuthKey.Generate();
        var agentId = "aauth:pre@ap.example";
        var (signedClient, plainHttp, _) = await BuildSignedAgentClientAsync(agentKey, agentId);

        // Pre-record consent before any exchange.
        using var admin = await plainHttp.PostAsJsonAsync("/admin/consent", new JsonObject
        {
            ["agent"] = agentId,
            ["resource"] = ResourceUrl,
            ["scope"] = "calendar.read",
            ["key"] = agentKey.ComputeJwkThumbprint(),
        });
        Assert.True(admin.IsSuccessStatusCode);

        using var response = await signedClient.PostAsJsonAsync("/token",
            await PersonTokenFlow.TokenRequestAsync(signedClient, agentKey));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.False(string.IsNullOrEmpty((string?)body!["auth_token"]));
    }

    [Fact]
    public async Task Interaction_GetRendersConsentForm_ThenPostApproveFlipsPending()
    {
        var agentKey = AAuthKey.Generate();
        var agentId = "aauth:browser@ap.example";
        var (signedClient, plainHttp, _) = await BuildSignedAgentClientAsync(agentKey, agentId);
        // Agent → 202 with interaction URL + code.
        using var initial = await signedClient.PostAsJsonAsync("/token",
            await PersonTokenFlow.TokenRequestAsync(signedClient, agentKey));
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
        Assert.True(initial.Headers.TryGetValues("AAuth-Requirement", out var reqValues));
        var parsed = AAuth.Headers.AAuthRequirementHeader.Parse(string.Join(", ", reqValues!));
        var interaction = AAuth.Headers.Interaction.FromRequirement(parsed);
        Assert.NotNull(interaction);

        // User's browser → GET /interaction?code=…  renders a consent form.
        using var page = await plainHttp.GetAsync($"/interaction?code={interaction!.Code}");
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        var html = await page.Content.ReadAsStringAsync();
        Assert.Contains("Demo sign-in", html);
        Assert.DoesNotContain("/interaction/approve", html);

        // User's browser → POST /interaction/approve consumes the code.
        using var approve = await TestConsentBrowser.DecideAsync(plainHttp,
            "/interaction?code=" + interaction.Code, "/interaction/approve");
        Assert.True(approve.IsSuccessStatusCode);

        // Agent's next poll → 200 + auth_token.
        var pendingPath = initial.Headers.Location!.OriginalString;
        using var pending = await signedClient.GetAsync(pendingPath);
        Assert.Equal(HttpStatusCode.OK, pending.StatusCode);
        var body = await pending.Content.ReadFromJsonAsync<JsonObject>();
        Assert.False(string.IsNullOrEmpty((string?)body!["auth_token"]));
    }

    [Fact]
    public async Task Interaction_ConsentPage_AttributesAgentAssertedContentApartFromResource()
    {
        var agentKey = AAuthKey.Generate();
        var (signedClient, plainHttp, _) = await BuildSignedAgentClientAsync(agentKey, "aauth:browser@ap.example");
        var request = await PersonTokenFlow.TokenRequestAsync(signedClient, agentKey);
        request["justification"] = "Trust me <script>alert(1)</script>";
        request["platform"] = AAuthConstants.Platforms.Mobile;
        request["device"] = "Pixel 8 (App)";
        using var initial = await signedClient.PostAsJsonAsync("/token", request);
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
        var interaction = AAuth.Headers.Interaction.FromRequirement(
            AAuth.Headers.AAuthRequirementHeader.Parse(string.Join(", ", initial.Headers.GetValues("AAuth-Requirement"))));

        string? html = null;
        using var approve = await TestConsentBrowser.DecideAsync(plainHttp,
            "/interaction?code=" + interaction!.Code, "/interaction/approve", page => html = page);

        Assert.NotNull(html);
        var resource = html!.IndexOf("<section class=resource-asserted>", StringComparison.Ordinal);
        var agent = html.IndexOf("<section class=agent-asserted>", StringComparison.Ordinal);
        Assert.True(resource >= 0 && agent >= 0);
        var agentSection = html[agent..html.IndexOf("</section>", agent, StringComparison.Ordinal)];
        Assert.Contains("The agent says (not verified)", agentSection);
        Assert.Contains("Trust me &lt;script&gt;alert(1)&lt;/script&gt;", agentSection);
        Assert.Contains(AAuthConstants.Platforms.Mobile, agentSection);
        Assert.Contains("Pixel 8 (App)", agentSection);
        Assert.DoesNotContain("<script>", html);
        var resourceSection = html[resource..html.IndexOf("</section>", resource, StringComparison.Ordinal)];
        Assert.Contains(ResourceUrl, resourceSection);
        Assert.DoesNotContain("Trust me", resourceSection);
    }

    [Fact]
    public async Task Interaction_PostApproveWithCodeAlone_Returns401()
    {
        var (_, plainHttp, _) = await BuildSignedAgentClientAsync();
        using var resp = await plainHttp.PostAsync(
            "/interaction/approve",
            new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("code", "definitely-not-a-real-id"),
            }));
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Pending_Returns403Denied_AfterDeny()
    {
        // Verifies the deny path: POST /interaction/deny marks the
        // pending entry as denied (rather than removing it), and the
        // subsequent /pending/{id} poll surfaces a deterministic 403
        // with body { error: "denied" }. This is what
        // AAuthInteractionDeniedException is keyed off in the SDK.
        var agentKey = AAuthKey.Generate();
        var agentId = "aauth:denier@ap.example";
        var (signedClient, plainHttp, _) = await BuildSignedAgentClientAsync(agentKey, agentId);
        using var initial = await signedClient.PostAsJsonAsync("/token",
            await PersonTokenFlow.TokenRequestAsync(signedClient, agentKey));
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
        var parsed = AAuth.Headers.AAuthRequirementHeader.Parse(
            string.Join(", ", initial.Headers.GetValues("AAuth-Requirement")));
        var interaction = AAuth.Headers.Interaction.FromRequirement(parsed);
        Assert.NotNull(interaction);

        // User's browser → POST /interaction/deny.
        using var deny = await TestConsentBrowser.DecideAsync(plainHttp,
            "/interaction?code=" + interaction!.Code, "/interaction/deny");
        Assert.True(deny.IsSuccessStatusCode);

        // Agent's next poll → 403 denied (not 404 / not 202).
        var pendingPath = initial.Headers.Location!.OriginalString;
        using var pending = await signedClient.GetAsync(pendingPath);
        Assert.Equal(HttpStatusCode.Forbidden, pending.StatusCode);
        var body = await pending.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("denied", (string?)body!["error"]);
    }

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------
    private async Task<(HttpClient Signed, HttpClient Plain, string AgentToken)> BuildSignedAgentClientAsync(
        AAuthKey? agentKey = null, string agentId = "aauth:demo@ap.example")
    {
        agentKey ??= AAuthKey.Generate();
        var agentToken = await new AgentTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            Issuer = "https://ap.example",
            Subject = agentId,
            KeyId = "demo",
            Key = ResourceStub.ApKey,
            ConfirmationKey = agentKey,
            PersonServer = PsIssuer,
        }.BuildAsync();
        var signing = new AAuthSigningHandler(agentKey, () => agentToken)
        {
            InnerHandler = _factory.Server.CreateHandler(),
        };
        var signed = new InProcessHttpClient(signing) { BaseAddress = new Uri(PsIssuer) };
        var plain = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(PsIssuer),
        });
        return (signed, plain, agentToken);
    }

    [Theory]
    [InlineData("work", false)]
    [InlineData(null, false)]
    [InlineData("personal", true)]
    public async Task AccountConsent_RequiresExactAccountAndKey(string? switchedAccount, bool switchKey)
    {
        var key = AAuthKey.Generate();
        var agentId = "aauth:account-" + Guid.NewGuid().ToString("N") + "@ap.example";
        var (client, browser, _) = await BuildSignedAgentClientAsync(key, agentId);
        using var signed = client;
        using var consentBrowser = browser;
        using var initial = await client.PostAsJsonAsync("/token", await PersonTokenFlow.TokenRequestAsync(client, key, "personal"));
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
        var interaction = AAuth.Headers.Interaction.FromRequirement(AAuth.Headers.AAuthRequirementHeader.Parse(initial.Headers.GetValues("AAuth-Requirement").Single()))!;
        using var approve = await TestConsentBrowser.DecideAsync(browser, interaction.BuildUserUrl(), "/interaction/approve");
        Assert.Equal(HttpStatusCode.OK, approve.StatusCode);
        using var granted = await client.GetAsync(initial.Headers.Location);
        Assert.Equal(HttpStatusCode.OK, granted.StatusCode);
        var token = (string)(await granted.Content.ReadFromJsonAsync<JsonObject>())!["auth_token"]!;
        var payload = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(token.Split('.')[1]))!.AsObject();
        Assert.Equal("personal", (string?)payload["account"]);
        using var renewed = await client.PostAsJsonAsync("/token", await PersonTokenFlow.TokenRequestAsync(client, key, "personal"));
        Assert.Equal(HttpStatusCode.OK, renewed.StatusCode);

        var selectedKey = switchKey ? AAuthKey.Generate() : key;
        var (other, _, _) = await BuildSignedAgentClientAsync(selectedKey, agentId);
        using var switched = other;
        using var pending = await other.PostAsJsonAsync("/token", await PersonTokenFlow.TokenRequestAsync(other, selectedKey, switchedAccount));
        Assert.Equal(HttpStatusCode.Accepted, pending.StatusCode);
        Assert.DoesNotContain("auth_token", await pending.Content.ReadAsStringAsync());
        var nextInteraction = AAuth.Headers.Interaction.FromRequirement(AAuth.Headers.AAuthRequirementHeader.Parse(pending.Headers.GetValues("AAuth-Requirement").Single()))!;
        using var denied = await TestConsentBrowser.DecideAsync(browser, nextInteraction.BuildUserUrl(), "/interaction/deny");
        Assert.Equal(HttpStatusCode.OK, denied.StatusCode);
        using var polled = await other.GetAsync(pending.Headers.Location);
        Assert.Equal(HttpStatusCode.Forbidden, polled.StatusCode);
        using var again = await other.PostAsJsonAsync("/token", await PersonTokenFlow.TokenRequestAsync(other, selectedKey, switchedAccount));
        Assert.Equal(HttpStatusCode.Accepted, again.StatusCode);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("42")]
    [InlineData("{}")]
    [InlineData("\"\"")]
    public async Task SignedMalformedAccount_IsRejectedByPersonServer(string malformed)
    {
        var key = AAuthKey.Generate();
        var (client, _, _) = await BuildSignedAgentClientAsync(key);
        using var signed = client;
        var personToken = await PersonTokenFlow.RequestAsync(client, ResourceStub.Url);
        var segments = (await PersonTokenFlow.ResourceTokenAsync(personToken, key)).Split('.');
        var payload = JsonNode.Parse(Base64UrlEncoder.DecodeBytes(segments[1]))!.AsObject();
        payload["account"] = JsonNode.Parse(malformed);
        var input = segments[0] + "." + Base64UrlEncoder.Encode(System.Text.Encoding.UTF8.GetBytes(payload.ToJsonString()));
        var token = input + "." + Base64UrlEncoder.Encode(ResourceStub.Key.Sign(System.Text.Encoding.ASCII.GetBytes(input)));
        using var response = await client.PostAsJsonAsync("/token", PersonTokenFlow.Body(token, personToken));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_resource_token", (string?)(await response.Content.ReadFromJsonAsync<JsonObject>())!["error"]);
    }
}

/// <summary>
/// Shared in-process stub for the resource (Calendar) whose well-known
/// metadata + JWKS the MockPersonServer now fetches to verify the
/// resource token before minting an auth token (Phase 10, §G9).
/// </summary>
internal static class ResourceStub
{
    public const string Url = "https://calendar.test";
    public const string Host = "calendar.test";
    public const string Kid = "calendar-1";
    public static readonly AAuthKey Key = AAuthKey.Generate();
    public static readonly AAuthKey ApKey = AAuthKey.Generate();

    /// <summary>
    /// Replace the PS's discovery clients so that resource-token
    /// verification resolves <see cref="Url"/>'s JWKS in-process.
    /// </summary>
    public static void WireDiscovery(IServiceCollection services)
    {
        services.RemoveAll<MetadataClient>();
        services.RemoveAll<JwksClient>();
        services.AddSingleton(new MetadataClient(new InProcessHttpClient(new StubResourceHandler(Key, Kid, Url))));
        services.AddSingleton(new JwksClient(new InProcessHttpClient(new StubResourceHandler(Key, Kid, Url))));
    }

    private sealed class StubResourceHandler : HttpMessageHandler
    {
        private readonly string _metadataJson;
        private readonly string _jwksJson;

        public StubResourceHandler(AAuthKey key, string kid, string issuer)
        {
            _metadataJson = new JsonObject
            {
                ["issuer"] = issuer,
                ["jwks_uri"] = $"{issuer}/.well-known/jwks.json",
            }.ToJsonString();

            var jwk = key.ToPublicJwk();
            jwk["kid"] = kid;
            jwk["use"] = "sig";
            jwk["alg"] = AAuthKey.Ed25519Algorithm;
            _jwksJson = new JsonObject
            {
                ["keys"] = new JsonArray(jwk),
            }.ToJsonString();
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath;
            string json;
            if (request.RequestUri.Host == "ap.example")
            {
                var jwk = ApKey.ToPublicJwk();
                jwk["kid"] = "demo";
                json = path == "/.well-known/aauth-agent.json"
                    ? new JsonObject { ["issuer"] = "https://ap.example", ["jwks_uri"] = "https://ap.example/.well-known/jwks.json" }.ToJsonString()
                    : new JsonObject { ["keys"] = new JsonArray(jwk) }.ToJsonString();
            }
            else if (path == "/.well-known/aauth-resource.json")
                json = _metadataJson;
            else if (path == "/.well-known/jwks.json")
                json = _jwksJson;
            else
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json"),
            });
        }
    }
}
