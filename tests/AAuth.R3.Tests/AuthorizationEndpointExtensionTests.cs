using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.HttpSig;
using AAuth.R3.Model;
using AAuth.Server;
using AAuth.Server.Verification;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.R3.Tests;

public class AuthorizationEndpointExtensionTests
{
    [Fact]
    public async Task R3OperationsWithoutScope_AreRoutedToRegisteredExtension()
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var discovery = new StaticJsonHandler()
            .AddJson($"{R3TestData.PsIssuer}/.well-known/aauth-person.json",
                R3TestData.Metadata(R3TestData.PsIssuer, AAuthConstants.DwkFiles.Person))
            .AddJson($"{R3TestData.PsIssuer}/.well-known/jwks.json",
                R3TestData.Jwks(R3TestData.PsKid, psKey));

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new AAuthVerifier());
        builder.Services.AddSingleton(new MetadataClient(new InProcessHttpClient(discovery),
            policy: TestEgress.Policy, transportContract: AAuthTransportContract.InProcessOnly));
        builder.Services.AddSingleton(new JwksClient(new InProcessHttpClient(discovery),
            policy: TestEgress.Policy, transportContract: AAuthTransportContract.InProcessOnly));
        builder.Services.AddAAuthR3AuthorizationEndpoint();
        var app = builder.Build();
        app.UseAAuthVerification(options =>
        {
            options.EgressPolicy = TestEgress.Policy;
            options.AcceptedSchemes = [AAuthConstants.Schemes.Jwt];
            options.ResourceIdentifier = R3TestData.ResourceIssuer;
            options.Trust.PersonServers.Allowed = new HashSet<string> { R3TestData.PsIssuer };
        });
        app.MapAAuthAuthorizationEndpoint("/authorize", (_, request) =>
        {
            var operations = request.GetR3Operations();
            return Task.FromResult<IResult>(Results.Json(new
            {
                scope = request.Scope,
                vocabulary = operations?.Vocabulary,
                operation = operations?.Operations.Single().Id,
            }));
        });
        await app.StartAsync();
        try
        {
            var personToken = await R3TestData.PersonTokenAsync(psKey, agentKey);
            using var client = new InProcessHttpClient(new AAuthSigningHandler(agentKey, () => personToken)
            {
                InnerHandler = app.GetTestServer().CreateHandler(),
            })
            {
                BaseAddress = new Uri(R3TestData.ResourceIssuer),
            };

            using var response = await client.PostAsJsonAsync("/authorize",
                R3Request.CreateBody(R3Operations.OpenApi("searchAvailability")));

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var body = await response.Content.ReadFromJsonAsync<JsonObject>();
            Assert.Null(body!["scope"]);
            Assert.Equal(Vocabulary.OpenApi, (string?)body["vocabulary"]);
            Assert.Equal("searchAvailability", (string?)body["operation"]);
        }
        finally
        {
            await app.StopAsync();
        }
    }

    [Fact]
    public async Task R3OperationsWithoutScope_KeepScopeRequiredWhenExtensionIsNotRegistered()
    {
        var psKey = AAuthKey.Generate();
        var agentKey = AAuthKey.Generate();
        var discovery = new StaticJsonHandler()
            .AddJson($"{R3TestData.PsIssuer}/.well-known/aauth-person.json",
                R3TestData.Metadata(R3TestData.PsIssuer, AAuthConstants.DwkFiles.Person))
            .AddJson($"{R3TestData.PsIssuer}/.well-known/jwks.json",
                R3TestData.Jwks(R3TestData.PsKid, psKey));

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new AAuthVerifier());
        builder.Services.AddSingleton(new MetadataClient(new InProcessHttpClient(discovery),
            policy: TestEgress.Policy, transportContract: AAuthTransportContract.InProcessOnly));
        builder.Services.AddSingleton(new JwksClient(new InProcessHttpClient(discovery),
            policy: TestEgress.Policy, transportContract: AAuthTransportContract.InProcessOnly));
        var app = builder.Build();
        app.UseAAuthVerification(options =>
        {
            options.EgressPolicy = TestEgress.Policy;
            options.AcceptedSchemes = [AAuthConstants.Schemes.Jwt];
            options.ResourceIdentifier = R3TestData.ResourceIssuer;
            options.Trust.PersonServers.Allowed = new HashSet<string> { R3TestData.PsIssuer };
        });
        app.MapAAuthAuthorizationEndpoint("/authorize", (_, _) =>
            Task.FromResult<IResult>(Results.Ok()));
        await app.StartAsync();
        try
        {
            var personToken = await R3TestData.PersonTokenAsync(psKey, agentKey);
            using var client = new InProcessHttpClient(new AAuthSigningHandler(agentKey, () => personToken)
            {
                InnerHandler = app.GetTestServer().CreateHandler(),
            })
            {
                BaseAddress = new Uri(R3TestData.ResourceIssuer),
            };

            using var response = await client.PostAsJsonAsync("/authorize",
                R3Request.CreateBody(R3Operations.OpenApi("searchAvailability")));

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            var body = await response.Content.ReadFromJsonAsync<JsonObject>();
            Assert.Equal("invalid_request", (string?)body!["error"]);
            Assert.Equal("scope is required", (string?)body["detail"]);
        }
        finally
        {
            await app.StopAsync();
        }
    }
}
