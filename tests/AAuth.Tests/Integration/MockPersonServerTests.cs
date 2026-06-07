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
using Xunit;

namespace AAuth.Tests.Integration;

/// <summary>
/// Unit-tests for the shipped <c>samples/MockPersonServer/</c> sample.
///
/// These exercise the same endpoints the agent's <see cref="TokenExchangeClient"/>
/// will hit at runtime, without spinning up WhoAmI. The integration tests
/// in <see cref="WhoAmIFlowTests"/> exercise the same sample in the full
/// three-party flow alongside WhoAmI.
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
        Assert.Equal($"{PsIssuer}/token", (string?)doc["token_endpoint"]);
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
        Assert.Equal(AAuthKey.Algorithm, (string?)key["alg"]);
        Assert.Equal("sig", (string?)key["use"]);
        Assert.False(string.IsNullOrEmpty((string?)key["kid"]));
    }

    [Fact]
    public async Task Token_MintsAuthToken_BoundToAgentKey()
    {
        var agentKey = AAuthKey.Generate();
        var agentToken = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:demo@ap.example",
            KeyId = "demo",
            Key = agentKey,
            PersonServer = PsIssuer,
        }.Build();

        // Sign the POST /token request with the agent's key + agent token.
        var signing = new AAuthSigningHandler(agentKey, () => agentToken)
        {
            InnerHandler = _factory.Server.CreateHandler(),
        };
        using var http = new HttpClient(signing)
        {
            BaseAddress = new Uri(PsIssuer),
        };

        // A resource_token with the resource as `iss`. The mock PS reads
        // `iss` and uses it as the auth-token's `aud`; it does NOT verify
        // the signature, so we can hand-craft a minimal one.
        const string ResourceUrl = ResourceStub.Url;
        var resourceToken = new ResourceTokenBuilder
        {
            Issuer = ResourceUrl,
            Audience = PsIssuer,
            Agent = "aauth:demo@ap.example",
            AgentJkt = agentKey.ComputeJwkThumbprint(),
            Key = ResourceStub.Key,
            KeyId = ResourceStub.Kid,
            Scope = "whoami",
        }.Build();

        var response = await http.PostAsJsonAsync("/token",
            new JsonObject { ["resource_token"] = resourceToken });

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
        Assert.Equal(AAuthKey.Algorithm, (string?)header["alg"]);
        Assert.Equal(PsIssuer, (string?)payload["iss"]);
        Assert.Equal(ResourceUrl, (string?)payload["aud"]);
        Assert.Equal("aauth:demo@ap.example", (string?)payload["agent"]);
        Assert.Equal(AuthTokenBuilder.PersonDwk, (string?)payload["dwk"]);

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
        var authTokenAsCarrier = new AuthTokenBuilder
        {
            Issuer = "https://ps.example",
            Audience = "https://whoami.test",
            Agent = "aauth:demo@ap.example",
            AgentConfirmationKey = agentKey,
            Key = psKey,
            KeyId = "ps-x",
            Subject = "pairwise",
            Scope = "whoami",
        }.Build();

        var signing = new AAuthSigningHandler(agentKey, () => authTokenAsCarrier)
        {
            InnerHandler = _factory.Server.CreateHandler(),
        };
        using var http = new HttpClient(signing)
        {
            BaseAddress = new Uri(PsIssuer),
        };

        var response = await http.PostAsJsonAsync("/token",
            new JsonObject { ["resource_token"] = "irrelevant" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_carrier_token", (string?)body!["error"]);
    }

    [Fact]
    public async Task Token_RejectsMissingResourceToken()
    {
        var agentKey = AAuthKey.Generate();
        var agentToken = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:demo@ap.example",
            KeyId = "demo",
            Key = agentKey,
            PersonServer = PsIssuer,
        }.Build();

        var signing = new AAuthSigningHandler(agentKey, () => agentToken)
        {
            InnerHandler = _factory.Server.CreateHandler(),
        };
        using var http = new HttpClient(signing)
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
        var agentToken = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:demo@ap.example",
            KeyId = "demo",
            Key = agentKey,
            PersonServer = PsIssuer,
        }.Build();

        var signing = new AAuthSigningHandler(agentKey, () => agentToken)
        {
            InnerHandler = _factory.Server.CreateHandler(),
        };
        using var http = new HttpClient(signing) { BaseAddress = new Uri(PsIssuer) };

        // Signed with a freshly generated key — NOT ResourceStub.Key — but
        // carrying the published kid, so the PS resolves the genuine key and
        // the signature check fails.
        var forged = new ResourceTokenBuilder
        {
            Issuer = ResourceStub.Url,
            Audience = PsIssuer,
            Agent = "aauth:demo@ap.example",
            AgentJkt = agentKey.ComputeJwkThumbprint(),
            Key = AAuthKey.Generate(),
            KeyId = ResourceStub.Kid,
            Scope = "whoami",
        }.Build();

        var response = await http.PostAsJsonAsync("/token",
            new JsonObject { ["resource_token"] = forged });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_resource_token", (string?)body!["error"]);
    }

    [Fact]
    public async Task Token_RejectsTamperedResourceToken()
    {
        // Mutate the payload of a genuine resource token after signing; the
        // signature no longer matches → rejected at /token.
        var agentKey = AAuthKey.Generate();
        var agentToken = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:demo@ap.example",
            KeyId = "demo",
            Key = agentKey,
            PersonServer = PsIssuer,
        }.Build();

        var signing = new AAuthSigningHandler(agentKey, () => agentToken)
        {
            InnerHandler = _factory.Server.CreateHandler(),
        };
        using var http = new HttpClient(signing) { BaseAddress = new Uri(PsIssuer) };

        var genuine = new ResourceTokenBuilder
        {
            Issuer = ResourceStub.Url,
            Audience = PsIssuer,
            Agent = "aauth:demo@ap.example",
            AgentJkt = agentKey.ComputeJwkThumbprint(),
            Key = ResourceStub.Key,
            KeyId = ResourceStub.Kid,
            Scope = "whoami",
        }.Build();

        // Tamper: flip the scope to a privileged one without re-signing.
        var segments = genuine.Split('.');
        var payload = (JsonObject)JsonNode.Parse(
            Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(segments[1]))!;
        payload["scope"] = "whoami:admin";
        segments[1] = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(
            payload.ToJsonString());
        var tampered = string.Join('.', segments);

        var response = await http.PostAsJsonAsync("/token",
            new JsonObject { ["resource_token"] = tampered });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_resource_token", (string?)body!["error"]);
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
    private const string ResourceUrl = "https://whoami.test";
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
            builder.UseSetting("MockPersonServer:RequireConsent", "true");
            builder.ConfigureServices(ResourceStub.WireDiscovery);
        }
    }

    [Fact]
    public async Task Token_Returns202WithInteractionRequirement_WhenConsentMissing()
    {
        var agentKey = AAuthKey.Generate();
        var (signedClient, _, _) = BuildSignedAgentClient(agentKey, "aauth:demo@ap.example");
        var resourceToken = BuildResourceToken("aauth:demo@ap.example", agentKey);

        using var response = await signedClient.PostAsJsonAsync("/token",
            new JsonObject { ["resource_token"] = resourceToken });

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
        var (signedClient, plainHttp, _) = BuildSignedAgentClient(agentKey, agentId);
        var resourceToken = BuildResourceToken(agentId, agentKey);

        using var initial = await signedClient.PostAsJsonAsync("/token",
            new JsonObject { ["resource_token"] = resourceToken });
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
            ["scope"] = "whoami",
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
        var (signedClient, plainHttp, _) = BuildSignedAgentClient(agentKey, agentId);

        // Pre-record consent before any exchange.
        using var admin = await plainHttp.PostAsJsonAsync("/admin/consent", new JsonObject
        {
            ["agent"] = agentId,
            ["resource"] = ResourceUrl,
            ["scope"] = "whoami",
        });
        Assert.True(admin.IsSuccessStatusCode);

        var resourceToken = BuildResourceToken(agentId, agentKey);
        using var response = await signedClient.PostAsJsonAsync("/token",
            new JsonObject { ["resource_token"] = resourceToken });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.False(string.IsNullOrEmpty((string?)body!["auth_token"]));
    }

    [Fact]
    public async Task Interaction_GetRendersConsentForm_ThenPostApproveFlipsPending()
    {
        var agentKey = AAuthKey.Generate();
        var agentId = "aauth:browser@ap.example";
        var (signedClient, plainHttp, _) = BuildSignedAgentClient(agentKey, agentId);
        var resourceToken = BuildResourceToken(agentId, agentKey);

        // Agent → 202 with interaction URL + code.
        using var initial = await signedClient.PostAsJsonAsync("/token",
            new JsonObject { ["resource_token"] = resourceToken });
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
        Assert.True(initial.Headers.TryGetValues("AAuth-Requirement", out var reqValues));
        var parsed = AAuth.Headers.AAuthRequirementHeader.Parse(string.Join(", ", reqValues!));
        var interaction = AAuth.Headers.Interaction.FromRequirement(parsed);
        Assert.NotNull(interaction);

        // User's browser → GET /interaction?code=…  renders a consent form.
        using var page = await plainHttp.GetAsync($"/interaction?code={interaction!.Code}");
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        var html = await page.Content.ReadAsStringAsync();
        Assert.Contains("/interaction/approve", html);
        Assert.Contains(agentId, html);
        Assert.Contains(ResourceUrl, html);

        // User's browser → POST /interaction/approve consumes the code.
        using var approve = await plainHttp.PostAsync(
            "/interaction/approve",
            new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("code", interaction.Code),
            }));
        Assert.True(approve.IsSuccessStatusCode);

        // Agent's next poll → 200 + auth_token.
        var pendingPath = initial.Headers.Location!.OriginalString;
        using var pending = await signedClient.GetAsync(pendingPath);
        Assert.Equal(HttpStatusCode.OK, pending.StatusCode);
        var body = await pending.Content.ReadFromJsonAsync<JsonObject>();
        Assert.False(string.IsNullOrEmpty((string?)body!["auth_token"]));
    }

    [Fact]
    public async Task Interaction_PostApproveWithUnknownCode_Returns404()
    {
        var (_, plainHttp, _) = BuildSignedAgentClient();
        using var resp = await plainHttp.PostAsync(
            "/interaction/approve",
            new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("code", "definitely-not-a-real-id"),
            }));
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
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
        var (signedClient, plainHttp, _) = BuildSignedAgentClient(agentKey, agentId);
        var resourceToken = BuildResourceToken(agentId, agentKey);

        using var initial = await signedClient.PostAsJsonAsync("/token",
            new JsonObject { ["resource_token"] = resourceToken });
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);
        var parsed = AAuth.Headers.AAuthRequirementHeader.Parse(
            string.Join(", ", initial.Headers.GetValues("AAuth-Requirement")));
        var interaction = AAuth.Headers.Interaction.FromRequirement(parsed);
        Assert.NotNull(interaction);

        // User's browser → POST /interaction/deny.
        using var deny = await plainHttp.PostAsync(
            "/interaction/deny",
            new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("code", interaction!.Code),
            }));
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
    private (HttpClient Signed, HttpClient Plain, string AgentToken) BuildSignedAgentClient(
        AAuthKey? agentKey = null, string agentId = "aauth:demo@ap.example")
    {
        agentKey ??= AAuthKey.Generate();
        var agentToken = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = agentId,
            KeyId = "demo",
            Key = agentKey,
            PersonServer = PsIssuer,
        }.Build();
        var signing = new AAuthSigningHandler(agentKey, () => agentToken)
        {
            InnerHandler = _factory.Server.CreateHandler(),
        };
        var signed = new HttpClient(signing) { BaseAddress = new Uri(PsIssuer) };
        var plain = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(PsIssuer),
        });
        return (signed, plain, agentToken);
    }

    private static string BuildResourceToken(string agent, AAuthKey agentKey)
        => new ResourceTokenBuilder
        {
            Issuer = ResourceUrl,
            Audience = PsIssuer,
            Agent = agent,
            AgentJkt = agentKey.ComputeJwkThumbprint(),
            Key = ResourceStub.Key,
            KeyId = ResourceStub.Kid,
            Scope = "whoami",
        }.Build();
}

/// <summary>
/// Shared in-process stub for the resource (WhoAmI) whose well-known
/// metadata + JWKS the MockPersonServer now fetches to verify the
/// resource token before minting an auth token (Phase 10, §G9).
/// </summary>
internal static class ResourceStub
{
    public const string Url = "https://whoami.test";
    public const string Host = "whoami.test";
    public const string Kid = "whoami-1";
    public static readonly AAuthKey Key = AAuthKey.Generate();

    /// <summary>
    /// Replace the PS's discovery clients so that resource-token
    /// verification resolves <see cref="Url"/>'s JWKS in-process.
    /// </summary>
    public static void WireDiscovery(IServiceCollection services)
    {
        services.RemoveAll<MetadataClient>();
        services.RemoveAll<JwksClient>();
        services.AddSingleton(new MetadataClient(new HttpClient(new StubResourceHandler(Key, Kid, Url))));
        services.AddSingleton(new JwksClient(new HttpClient(new StubResourceHandler(Key, Kid, Url))));
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
            jwk["alg"] = AAuthKey.Algorithm;
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
            if (path == "/.well-known/aauth-resource.json")
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
