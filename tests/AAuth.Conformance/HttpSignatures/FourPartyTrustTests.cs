using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace AAuth.Conformance.HttpSignatures;

public sealed class FourPartyTrustTests
{
    private const string ResourceIssuer = "http://localhost:5200";
    private const string PersonServerIssuer = "http://localhost:5100";
    private const string AccessServerIssuer = "http://localhost:5500";
    private const string OtherAccessServerIssuer = "http://localhost:5501";
    private const string Scope = "bookings.read";

    private readonly AAuthKey _resourceKey = AAuthKey.Generate();
    private readonly AAuthKey _personServerKey = AAuthKey.Generate();
    private readonly AAuthKey _accessServerKey = AAuthKey.Generate();
    private readonly AAuthKey _otherAccessServerKey = AAuthKey.Generate();
    private readonly AAuthKey _agentKey = AAuthKey.Generate();

    [Fact(DisplayName = "R02 — four-party resource rejects PS-issued auth token and accepts AS-issued token")]
    public async Task FourPartyResource_RejectsPersonDwkAndAcceptsAccessDwk()
    {
        await using var app = await StartResourceAsync(accessServer: AccessServerIssuer);

        using var personResponse = await SendSignedAsync(app, await BuildAuthTokenAsync(
            issuer: PersonServerIssuer,
            issuerKey: _personServerKey,
            keyId: "ps-1",
            dwk: AuthTokenBuilder.PersonDwk));
        using var accessResponse = await SendSignedAsync(app, await BuildAuthTokenAsync(
            issuer: AccessServerIssuer,
            issuerKey: _accessServerKey,
            keyId: "as-1",
            dwk: AuthTokenBuilder.AccessDwk));

        Assert.Equal(HttpStatusCode.Unauthorized, personResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, accessResponse.StatusCode);
    }

    [Fact(DisplayName = "R02 — three-party resource rejects AS-DWK auth token from unrelated AS")]
    public async Task ThreePartyResource_RejectsAccessDwkFromUnrelatedAccessServer()
    {
        await using var app = await StartResourceAsync(accessServer: null);

        using var response = await SendSignedAsync(app, await BuildAuthTokenAsync(
            issuer: OtherAccessServerIssuer,
            issuerKey: _otherAccessServerKey,
            keyId: "other-as-1",
            dwk: AuthTokenBuilder.AccessDwk));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact(DisplayName = "R02 — AAuthTrust.Any with AccessServer fails startup")]
    public async Task AccessServer_WithAAuthTrustAny_FailsStartup()
    {
        var builder = CreateResourceBuilder(AccessServerIssuer);
        await using var app = builder.Build();
        app.UseRouting();

        var exception = Assert.Throws<InvalidOperationException>(() =>
            app.UseAAuth(options => options.Trust.AuthTokenIssuers.Predicate = AAuthTrust.Any));

        Assert.Contains("AAuthTrust.Any", exception.Message, StringComparison.Ordinal);
    }

    private async Task<WebApplication> StartResourceAsync(string? accessServer)
    {
        var builder = CreateResourceBuilder(accessServer);
        var app = builder.Build();
        app.UseRouting();
        app.UseAAuth();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet("/protected", () => Results.Ok("ok")).RequireAAuth(Scope);
        await app.StartAsync();
        return app;
    }

    private WebApplicationBuilder CreateResourceBuilder(string? accessServer)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddAAuthResource(options =>
        {
            options.EgressPolicy = TestEgress.Policy;
            options.Issuer = ResourceIssuer;
            options.AccessServer = accessServer;
            options.SigningKeys = new AAuthSigningKeySet("resource-1", _resourceKey);
        });
        var discovery = new MetadataHandler(
            (PersonServerIssuer, AuthTokenBuilder.PersonDwk, "ps-1", _personServerKey),
            (AccessServerIssuer, AuthTokenBuilder.AccessDwk, "as-1", _accessServerKey),
            (OtherAccessServerIssuer, AuthTokenBuilder.AccessDwk, "other-as-1", _otherAccessServerKey));
        var http = new InProcessHttpClient(discovery);
        builder.Services.AddSingleton(new MetadataClient(http, policy: TestEgress.Policy,
            transportContract: AAuthTransportContract.InProcessOnly));
        builder.Services.AddSingleton(new JwksClient(http, policy: TestEgress.Policy,
            transportContract: AAuthTransportContract.InProcessOnly));
        builder.Services.AddAAuthAuthentication();
        builder.Services.AddAAuthAuthorization();
        return builder;
    }

    private async Task<string> BuildAuthTokenAsync(string issuer, AAuthKey issuerKey, string keyId, string dwk)
        => await new AuthTokenBuilder
        {
            EgressPolicy = TestEgress.Policy,
            AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            Issuer = issuer,
            Audience = ResourceIssuer,
            PersonServer = PersonServerIssuer,
            AgentConfirmationKey = _agentKey,
            Key = issuerKey,
            KeyId = keyId,
            Scope = Scope,
            Subject = "subject",
            Dwk = dwk,
        }.BuildAsync();

    private async Task<HttpResponseMessage> SendSignedAsync(WebApplication app, string jwt)
    {
        using var client = new AAuthClientBuilder(_agentKey)
            .UseJwt(jwt)
            .WithEgressPolicy(TestEgress.Policy)
            .WithInnerHandler(app.GetTestServer().CreateHandler(), AAuthTransportContract.InProcessOnly)
            .Build();
        client.BaseAddress = new Uri(ResourceIssuer);
        return await client.GetAsync("/protected");
    }

    private sealed class MetadataHandler(params (string Issuer, string Dwk, string Kid, AAuthKey Key)[] roles) : HttpMessageHandler
    {
        private readonly Dictionary<(string Issuer, string Dwk), (string Kid, AAuthKey Key)> _roles = BuildRoles(roles);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var issuer = request.RequestUri!.GetLeftPart(UriPartial.Authority);
            var path = request.RequestUri.AbsolutePath;
            foreach (var ((roleIssuer, dwk), (kid, key)) in _roles)
            {
                if (issuer == roleIssuer && path.EndsWith(dwk, StringComparison.Ordinal))
                {
                    return JsonResponse(new JsonObject
                    {
                        ["issuer"] = roleIssuer,
                        ["jwks_uri"] = $"{roleIssuer}/.well-known/{kid}-jwks.json",
                    });
                }
                if (issuer == roleIssuer && path.EndsWith($"{kid}-jwks.json", StringComparison.Ordinal))
                {
                    var jwk = key.ToPublicJwk();
                    jwk["kid"] = kid;
                    jwk["use"] = "sig";
                    jwk["alg"] = AAuthKey.Ed25519Algorithm;
                    return JsonResponse(new JsonObject { ["keys"] = new JsonArray { jwk } });
                }
            }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        private static Dictionary<(string Issuer, string Dwk), (string Kid, AAuthKey Key)> BuildRoles(
            IEnumerable<(string Issuer, string Dwk, string Kid, AAuthKey Key)> roles)
        {
            var result = new Dictionary<(string Issuer, string Dwk), (string Kid, AAuthKey Key)>();
            foreach (var role in roles)
            {
                result[(role.Issuer, role.Dwk)] = (role.Kid, role.Key);
            }
            return result;
        }

        private static Task<HttpResponseMessage> JsonResponse(JsonObject json)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json.ToJsonString(), System.Text.Encoding.UTF8, "application/json"),
            });
    }
}
