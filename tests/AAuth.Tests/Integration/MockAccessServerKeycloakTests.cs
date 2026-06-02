using System;
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
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Http;
using Xunit;

namespace AAuth.Tests.Integration;

/// <summary>
/// Exercises the AS's interactive Keycloak policy (Phase 4 Step B). The AS is
/// configured with <c>PolicyProvider=keycloak</c> and a stub Keycloak handler
/// so CI stays pure-.NET. The flow under test:
///   1. PS POSTs <c>/token</c> → AS returns <c>202 requirement=interaction</c>
///      with a <c>Location: /pending/{id}</c> and an <c>AAuth-Requirement</c>.
///   2. The user's browser completes <c>/interaction/callback</c> (the AS
///      exchanges the code and asks Keycloak for the uma-ticket decision).
///   3. The PS polls <c>/pending/{id}</c> → <c>200 auth_token</c> (allow) or
///      <c>403 access_denied</c> (deny), mirroring the PS deferred shape.
/// The stub Keycloak grants <c>whoami</c> to anyone and <c>whoami:admin</c>
/// only when the claim_token carries the <c>whoami-admin</c> role.
/// </summary>
public class MockAccessServerKeycloakTests
{
    private const string AsIssuer = "https://as.test";
    private const string PsIssuer = "https://ps.test";
    private const string ApIssuer = "https://ap.test";
    private const string ResourceUrl = "https://whoami.test";
    private const string AdminAgentId = "aauth:demo@ap.test";  // admin by demo convention.
    private const string GuestAgentId = "aauth:guest@ap.test"; // non-admin.

    private const string PsKid = "ps-1";
    private const string ApKid = "ap-1";
    private const string ResourceKid = "whoami-1";

    private static readonly AAuthKey PsKey = AAuthKey.Generate();
    private static readonly AAuthKey ApKey = AAuthKey.Generate();
    private static readonly AAuthKey ResourceKey = AAuthKey.Generate();

    [Fact]
    public async Task InteractiveFlow_GrantsWhoami_AfterKeycloakLogin()
    {
        using var factory = BuildFactory();

        // 1. PS POSTs /token → expect 202 requirement=interaction.
        var pendingPath = await StartInteractionAsync(factory, GuestAgentId, "whoami");

        // 2. The user completes the Keycloak login/consent round-trip.
        await CompleteCallbackAsync(factory, pendingPath);

        // 3. The PS polls the pending URL → 200 auth_token.
        using var signed = BuildPsSignedClient(factory);
        var poll = await signed.GetAsync(pendingPath);
        Assert.True(poll.IsSuccessStatusCode,
            $"Status={(int)poll.StatusCode} {await poll.Content.ReadAsStringAsync()}");

        var body = await poll.Content.ReadFromJsonAsync<JsonObject>();
        var payload = DecodePayload((string?)body!["auth_token"]);
        Assert.Equal(AuthTokenBuilder.AccessDwk, (string?)payload["dwk"]);
        Assert.Equal(AsIssuer, (string?)payload["iss"]);
        Assert.Equal(ResourceUrl, (string?)payload["aud"]);
        Assert.Equal("whoami", (string?)payload["scope"]);
    }

    [Fact]
    public async Task InteractiveFlow_GrantsAdminScope_ForAdminAgent()
    {
        using var factory = BuildFactory();

        var pendingPath = await StartInteractionAsync(factory, AdminAgentId, "whoami:admin");
        await CompleteCallbackAsync(factory, pendingPath);

        using var signed = BuildPsSignedClient(factory);
        var poll = await signed.GetAsync(pendingPath);
        Assert.True(poll.IsSuccessStatusCode,
            $"Status={(int)poll.StatusCode} {await poll.Content.ReadAsStringAsync()}");

        var body = await poll.Content.ReadFromJsonAsync<JsonObject>();
        var payload = DecodePayload((string?)body!["auth_token"]);
        Assert.Equal("whoami:admin", (string?)payload["scope"]);
    }

    [Fact]
    public async Task InteractiveFlow_DeniesAdminScope_ForNonAdminAgent()
    {
        using var factory = BuildFactory();

        // Guest agent requesting the elevated scope: Keycloak denies because
        // the claim_token carries no whoami-admin role.
        var pendingPath = await StartInteractionAsync(factory, GuestAgentId, "whoami:admin");
        await CompleteCallbackAsync(factory, pendingPath);

        using var signed = BuildPsSignedClient(factory);
        var poll = await signed.GetAsync(pendingPath);

        Assert.Equal(HttpStatusCode.Forbidden, poll.StatusCode);
        var body = await poll.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("access_denied", (string?)body!["error"]);
    }

    [Fact]
    public async Task Token_ReturnsInteractionRequirement_BeforeLogin()
    {
        using var factory = BuildFactory();

        var agentKey = AAuthKey.Generate();
        using var signed = BuildPsSignedClient(factory);
        var response = await signed.PostAsJsonAsync("/token", new JsonObject
        {
            ["agent_token"] = BuildAgentToken(agentKey, GuestAgentId),
            ["resource_token"] = BuildResourceToken(agentKey, AsIssuer, GuestAgentId, "whoami"),
        });

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.True(response.Headers.Contains("AAuth-Requirement"));
        Assert.NotNull(response.Headers.Location);
        Assert.StartsWith("/pending/", response.Headers.Location!.OriginalString);
    }

    // -- flow helpers ----------------------------------------------------

    private static async Task<string> StartInteractionAsync(
        WebApplicationFactory<MockAccessServer.Entry> factory, string agentId, string scope)
    {
        var agentKey = AAuthKey.Generate();
        using var signed = BuildPsSignedClient(factory);
        var response = await signed.PostAsJsonAsync("/token", new JsonObject
        {
            ["agent_token"] = BuildAgentToken(agentKey, agentId),
            ["resource_token"] = BuildResourceToken(agentKey, AsIssuer, agentId, scope),
        });

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.NotNull(response.Headers.Location);
        return response.Headers.Location!.OriginalString;
    }

    private static async Task CompleteCallbackAsync(
        WebApplicationFactory<MockAccessServer.Entry> factory, string pendingPath)
    {
        var id = pendingPath["/pending/".Length..];
        using var browser = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(AsIssuer),
            AllowAutoRedirect = false,
        });
        var callback = await browser.GetAsync($"/interaction/callback?code=fake-auth-code&state={id}");
        Assert.True(callback.IsSuccessStatusCode,
            $"callback Status={(int)callback.StatusCode} {await callback.Content.ReadAsStringAsync()}");
    }

    private static WebApplicationFactory<MockAccessServer.Entry> BuildFactory() =>
        new WebApplicationFactory<MockAccessServer.Entry>().WithWebHostBuilder(b =>
        {
            b.UseSetting("AAuth:Issuer", AsIssuer);
            b.UseSetting("MockAccessServer:TrustedPersonServers:0", PsIssuer);
            b.UseSetting("AccessServer:PolicyProvider", "keycloak");
            b.UseSetting("AccessServer:Keycloak:Authority", "http://localhost:18080/realms/aauth");
            b.UseSetting("AccessServer:Keycloak:ClientId", "aauth-access-server");
            b.UseSetting("AccessServer:Keycloak:ClientSecret", "test-secret");
            b.UseSetting("AccessServer:Keycloak:ResourceName", "whoami");
            b.ConfigureServices(services =>
            {
                WireDiscovery(services);
                services.AddHttpClient("keycloak")
                    .ConfigurePrimaryHttpMessageHandler(() => new StubKeycloakHandler());
            });
        });

    private static HttpClient BuildPsSignedClient(WebApplicationFactory<MockAccessServer.Entry> factory)
    {
        var http = new AAuthClientBuilder(PsKey)
            .UseJwksUri($"{PsIssuer}/.well-known/jwks.json", PsKid)
            .WithInnerHandler(factory.Server.CreateHandler())
            .Build();
        http.BaseAddress = new Uri(AsIssuer);
        return http;
    }

    // -- token builders --------------------------------------------------

    private static string BuildAgentToken(AAuthKey agentKey, string agent) =>
        new AgentTokenBuilder
        {
            Issuer = ApIssuer,
            Subject = agent,
            KeyId = ApKid,
            Key = ApKey,
            ConfirmationKey = agentKey,
            PersonServer = PsIssuer,
        }.Build();

    private static string BuildResourceToken(AAuthKey agentKey, string audience, string agent, string scope) =>
        new ResourceTokenBuilder
        {
            Issuer = ResourceUrl,
            Audience = audience,
            Agent = agent,
            AgentJkt = agentKey.ComputeJwkThumbprint(),
            Key = ResourceKey,
            KeyId = ResourceKid,
            Scope = scope,
        }.Build();

    private static JsonObject DecodePayload(string? jwt) =>
        (JsonObject)JsonNode.Parse(
            Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(jwt!.Split('.')[1]))!;

    // -- stubs -----------------------------------------------------------

    private static void WireDiscovery(IServiceCollection services)
    {
        services.RemoveAll<MetadataClient>();
        services.RemoveAll<JwksClient>();
        services.AddSingleton(new MetadataClient(new HttpClient(new StubDiscoveryHandler())));
        services.AddSingleton(new JwksClient(new HttpClient(new StubDiscoveryHandler())));
    }

    private sealed class StubDiscoveryHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var uri = request.RequestUri!;
            var key = $"{uri.Host}{uri.AbsolutePath}";
            string? json = key switch
            {
                "ps.test/.well-known/jwks.json" => Jwks(PsKey, PsKid),
                "ap.test/.well-known/aauth-agent.json" => Metadata(ApIssuer),
                "ap.test/.well-known/jwks.json" => Jwks(ApKey, ApKid),
                "whoami.test/.well-known/aauth-resource.json" => Metadata(ResourceUrl),
                "whoami.test/.well-known/jwks.json" => Jwks(ResourceKey, ResourceKid),
                _ => null,
            };

            if (json is null)
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            });
        }

        private static string Metadata(string issuer) => new JsonObject
        {
            ["issuer"] = issuer,
            ["jwks_uri"] = $"{issuer}/.well-known/jwks.json",
        }.ToJsonString();

        private static string Jwks(AAuthKey key, string kid)
        {
            var jwk = key.ToPublicJwk();
            jwk["kid"] = kid;
            jwk["use"] = "sig";
            jwk["alg"] = AAuthKey.Algorithm;
            return new JsonObject { ["keys"] = new JsonArray(jwk) }.ToJsonString();
        }
    }

    /// <summary>
    /// Stand-in for Keycloak's token endpoint. Handles the authorization-code
    /// exchange (returns a fake access token) and the <c>uma-ticket</c>
    /// decision request (grants <c>whoami</c>; grants <c>whoami:admin</c> only
    /// when the pushed claim_token carries the <c>whoami-admin</c> role).
    /// </summary>
    private sealed class StubKeycloakHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var form = await ParseFormAsync(request, cancellationToken);
            var grantType = form.GetValueOrDefault("grant_type");

            if (grantType == "authorization_code")
            {
                return Json(HttpStatusCode.OK, new JsonObject { ["access_token"] = "fake-user-token" });
            }

            if (grantType == "urn:ietf:params:oauth:grant-type:uma-ticket")
            {
                var permission = form.GetValueOrDefault("permission") ?? "";
                var elevated = permission.Contains(":", StringComparison.Ordinal);
                var hasAdminRole = HasAdminRole(form.GetValueOrDefault("claim_token"));
                return (!elevated || hasAdminRole)
                    ? Json(HttpStatusCode.OK, new JsonObject { ["result"] = true })
                    : Json(HttpStatusCode.Forbidden, new JsonObject { ["error"] = "access_denied" });
            }

            return new HttpResponseMessage(HttpStatusCode.BadRequest);
        }

        private static bool HasAdminRole(string? claimTokenB64)
        {
            if (string.IsNullOrEmpty(claimTokenB64))
            {
                return false;
            }

            try
            {
                var json = Encoding.UTF8.GetString(Convert.FromBase64String(claimTokenB64));
                var roles = JsonNode.Parse(json)?["roles"] as JsonArray;
                if (roles is null)
                {
                    return false;
                }

                foreach (var role in roles)
                {
                    if ((string?)role == "whoami-admin")
                    {
                        return true;
                    }
                }
            }
            catch (FormatException)
            {
                return false;
            }

            return false;
        }

        private static async Task<Dictionary<string, string>> ParseFormAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(cancellationToken);
            var result = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var pair in body.Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var idx = pair.IndexOf('=', StringComparison.Ordinal);
                if (idx < 0)
                {
                    continue;
                }

                var k = Uri.UnescapeDataString(pair[..idx]);
                var v = Uri.UnescapeDataString(pair[(idx + 1)..]);
                result[k] = v;
            }

            return result;
        }

        private static HttpResponseMessage Json(HttpStatusCode status, JsonObject body) =>
            new(status)
            {
                Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
            };
    }
}
