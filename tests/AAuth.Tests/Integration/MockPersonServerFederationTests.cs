using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
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
/// Four-party (federated) tests for <c>samples/MockPersonServer/</c>. When a
/// resource token's <c>aud</c> is an Access Server rather than the PS itself,
/// the PS must forward a signed PS→AS request via
/// <see cref="AccessServerClient"/> and return the AS-issued auth token
/// (gaps G1/G3/G7). When <c>aud</c> is the PS, the existing three-party path
/// (the "collapsed" PS+AS) must keep working unchanged.
/// </summary>
public class MockPersonServerFederationTests
{
    private const string PsIssuer = "https://ps.test";
    private const string AsIssuer = "https://as.test";
    private const string ResourceUrl = ResourceStub.Url;
    private const string AsKid = "as-fed-1";
    private const string AgentId = "aauth:demo@ap.example";

    private static readonly AAuthKey AsKey = AAuthKey.Generate();

    [Fact]
    public async Task Token_FederatesToAccessServer_WhenResourceAudIsAs()
    {
        var agentKey = AAuthKey.Generate();
        using var factory = BuildFactory(agentKey, AgentId, scope: "whoami");
        using var http = BuildSignedAgentClient(factory, agentKey, AgentId);

        // Resource token audience is the ACCESS SERVER, not the PS → federate.
        var resourceToken = BuildResourceToken(AgentId, agentKey, audience: AsIssuer, scope: "whoami");

        using var response = await http.PostAsJsonAsync("/token",
            new JsonObject { ["resource_token"] = resourceToken });

        Assert.True(response.IsSuccessStatusCode,
            $"Status={(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        var authTokenJwt = (string?)body!["auth_token"];
        Assert.False(string.IsNullOrEmpty(authTokenJwt));

        // The returned token was minted by the AS, not the PS: iss=AS, dwk=access.
        var payload = DecodePayload(authTokenJwt!);
        Assert.Equal(AsIssuer, (string?)payload["iss"]);
        Assert.Equal(ResourceUrl, (string?)payload["aud"]);
        Assert.Equal(AuthTokenBuilder.AccessDwk, (string?)payload["dwk"]);
        Assert.Equal(AgentId, (string?)payload["agent"]);
    }

    [Fact]
    public async Task Token_Rejects_WhenAccessServerNotTrusted()
    {
        var agentKey = AAuthKey.Generate();
        using var factory = BuildFactory(agentKey, AgentId, scope: "whoami");
        using var http = BuildSignedAgentClient(factory, agentKey, AgentId);

        // aud is some other Access Server the PS has no federation trust with.
        var resourceToken = BuildResourceToken(AgentId, agentKey,
            audience: "https://untrusted-as.test", scope: "whoami");

        using var response = await http.PostAsJsonAsync("/token",
            new JsonObject { ["resource_token"] = resourceToken });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("untrusted_access_server", (string?)body!["error"]);
    }

    [Fact]
    public async Task Token_StillMintsDirectly_WhenResourceAudIsPs()
    {
        // Three-party (collapsed PS+AS) path must remain intact even when the
        // PS is configured for federation.
        var agentKey = AAuthKey.Generate();
        using var factory = BuildFactory(agentKey, AgentId, scope: "whoami");
        using var http = BuildSignedAgentClient(factory, agentKey, AgentId);

        var resourceToken = BuildResourceToken(AgentId, agentKey, audience: PsIssuer, scope: "whoami");

        using var response = await http.PostAsJsonAsync("/token",
            new JsonObject { ["resource_token"] = resourceToken });

        Assert.True(response.IsSuccessStatusCode,
            $"Status={(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        var authTokenJwt = (string?)body!["auth_token"];
        Assert.False(string.IsNullOrEmpty(authTokenJwt));
        var payload = DecodePayload(authTokenJwt!);
        // Minted by the PS itself: iss=PS, dwk=person.
        Assert.Equal(PsIssuer, (string?)payload["iss"]);
        Assert.Equal(AuthTokenBuilder.PersonDwk, (string?)payload["dwk"]);
    }

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------
    private static WebApplicationFactory<MockPersonServer.Entry> BuildFactory(
        AAuthKey agentKey, string agentId, string scope)
    {
        return new WebApplicationFactory<MockPersonServer.Entry>().WithWebHostBuilder(b =>
        {
            b.UseSetting("AAuth:Issuer", PsIssuer);
            b.UseSetting("MockPersonServer:TrustedAccessServers:0", AsIssuer);
            b.ConfigureServices(services =>
            {
                // Discovery (resource + AS metadata/JWKS) resolves in-process.
                services.RemoveAll<MetadataClient>();
                services.RemoveAll<JwksClient>();
                services.AddSingleton(new MetadataClient(
                    new HttpClient(new FederatedStub(agentKey, agentId, scope))));
                services.AddSingleton(new JwksClient(
                    new HttpClient(new FederatedStub(agentKey, agentId, scope))));

                // Route the PS→AS federation transport at the same in-process AS.
                services.AddHttpClient("aauth-federation")
                    .ConfigurePrimaryHttpMessageHandler(() => new FederatedStub(agentKey, agentId, scope));
            });
        });
    }

    private static HttpClient BuildSignedAgentClient(
        WebApplicationFactory<MockPersonServer.Entry> factory, AAuthKey agentKey, string agentId)
    {
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
            InnerHandler = factory.Server.CreateHandler(),
        };
        return new HttpClient(signing) { BaseAddress = new Uri(PsIssuer) };
    }

    private static string BuildResourceToken(string agent, AAuthKey agentKey, string audience, string scope)
        => new ResourceTokenBuilder
        {
            Issuer = ResourceUrl,
            Audience = audience,
            Agent = agent,
            AgentJkt = agentKey.ComputeJwkThumbprint(),
            Key = ResourceStub.Key,
            KeyId = ResourceStub.Kid,
            Scope = scope,
        }.Build();

    private static JsonObject DecodePayload(string jwt)
    {
        var segments = jwt.Split('.');
        return (JsonObject)JsonNode.Parse(
            Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(segments[1]))!;
    }

    /// <summary>
    /// In-process stub for BOTH the resource (whoami.test) and the Access
    /// Server (as.test): serves their well-known metadata + JWKS for discovery,
    /// and mints a valid Access-Server auth token on <c>POST {as}/token</c>.
    /// </summary>
    private sealed class FederatedStub : HttpMessageHandler
    {
        private readonly AAuthKey _agentKey;
        private readonly string _agentId;
        private readonly string _scope;

        public FederatedStub(AAuthKey agentKey, string agentId, string scope)
        {
            _agentKey = agentKey;
            _agentId = agentId;
            _scope = scope;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var uri = request.RequestUri!;
            var key = $"{uri.Host}{uri.AbsolutePath}";

            if (request.Method == HttpMethod.Post && key == "as.test/token")
            {
                var authToken = new AuthTokenBuilder
                {
                    Issuer = AsIssuer,
                    Audience = ResourceUrl,
                    Agent = _agentId,
                    AgentConfirmationKey = _agentKey,
                    Key = AsKey,
                    KeyId = AsKid,
                    Dwk = AuthTokenBuilder.AccessDwk,
                    Scope = _scope,
                    Subject = "pairwise-sub",
                }.Build();
                return Task.FromResult(Json(new JsonObject
                {
                    ["auth_token"] = authToken,
                    ["expires_in"] = 3600,
                }));
            }

            string? json = key switch
            {
                "whoami.test/.well-known/aauth-resource.json" => new JsonObject
                {
                    ["issuer"] = ResourceUrl,
                    ["jwks_uri"] = $"{ResourceUrl}/.well-known/jwks.json",
                }.ToJsonString(),
                "whoami.test/.well-known/jwks.json" => Jwks(ResourceStub.Key, ResourceStub.Kid),
                "as.test/.well-known/aauth-access.json" => new JsonObject
                {
                    ["issuer"] = AsIssuer,
                    ["jwks_uri"] = $"{AsIssuer}/.well-known/jwks.json",
                    ["token_endpoint"] = $"{AsIssuer}/token",
                }.ToJsonString(),
                "as.test/.well-known/jwks.json" => Jwks(AsKey, AsKid),
                _ => null,
            };

            return Task.FromResult(json is null
                ? new HttpResponseMessage(HttpStatusCode.NotFound)
                : new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(json, Encoding.UTF8, "application/json"),
                });
        }

        private static HttpResponseMessage Json(JsonObject body) =>
            new(HttpStatusCode.OK)
            {
                Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
            };

        private static string Jwks(AAuthKey key, string kid)
        {
            var jwk = key.ToPublicJwk();
            jwk["kid"] = kid;
            jwk["use"] = "sig";
            jwk["alg"] = AAuthKey.Algorithm;
            return new JsonObject { ["keys"] = new JsonArray(jwk) }.ToJsonString();
        }
    }
}
