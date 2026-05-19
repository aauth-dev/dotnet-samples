using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.HttpSig;
using AAuth.Tokens;
using Microsoft.AspNetCore.Mvc.Testing;
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
public class MockPersonServerTests : IClassFixture<WebApplicationFactory<MockPersonServer.Entry>>
{
    private const string PsIssuer = "https://ps.test";
    private readonly WebApplicationFactory<MockPersonServer.Entry> _factory;

    public MockPersonServerTests(WebApplicationFactory<MockPersonServer.Entry> factory)
    {
        _factory = factory.WithWebHostBuilder(b =>
        {
            b.UseSetting("AAuth:Issuer", PsIssuer);
        });
    }

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
        const string ResourceUrl = "https://whoami.test";
        var resourceToken = new ResourceTokenBuilder
        {
            Issuer = ResourceUrl,
            Audience = PsIssuer,
            Agent = "aauth:demo@ap.example",
            AgentJkt = agentKey.ComputeJwkThumbprint(),
            Key = AAuthKey.Generate(),
            KeyId = "whoami-1",
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
}
