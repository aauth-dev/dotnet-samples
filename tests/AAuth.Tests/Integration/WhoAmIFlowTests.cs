using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Tokens;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;

namespace AAuth.Tests.Integration;

/// <summary>
/// Three-party autonomous-flow integration test:
///   AgentConsole-style client → WhoAmI resource → MockPersonServer → WhoAmI.
///
/// Both servers are the shipped <c>samples/WhoAmI</c> and
/// <c>samples/MockPersonServer</c> projects, hosted in-process via
/// <see cref="WebApplicationFactory{TEntryPoint}"/>. A
/// <see cref="MultiHostHandler"/> demuxes outbound HTTP by host name so a
/// single signing pipeline can talk to both servers.
/// </summary>
public class WhoAmIFlowTests : IAsyncLifetime
{
    private const string WhoAmIHost = "whoami.test";
    private const string PsHost = "ps.test";
    private static readonly string WhoAmIIssuer = $"https://{WhoAmIHost}";
    private static readonly string PsIssuer = $"https://{PsHost}";

    private WebApplicationFactory<WhoAmI.Entry>? _whoAmI;
    private WebApplicationFactory<MockPersonServer.Entry>? _ps;

    public Task InitializeAsync()
    {
        _ps = new WebApplicationFactory<MockPersonServer.Entry>().WithWebHostBuilder(b =>
        {
            b.UseSetting("AAuth:Issuer", PsIssuer);
        });
        // Force the host to start so Server is available.
        _ps.CreateClient();
        var psHandler = _ps.Server.CreateHandler();

        _whoAmI = new WebApplicationFactory<WhoAmI.Entry>().WithWebHostBuilder(b =>
        {
            b.UseSetting("AAuth:Issuer", WhoAmIIssuer);
            b.ConfigureServices(services =>
            {
                // Replace the metadata/JWKS clients with versions that talk
                // to the in-process PS over its TestServer handler instead
                // of making real network calls.
                services.RemoveAll<MetadataClient>();
                services.RemoveAll<JwksClient>();
                services.AddSingleton(new MetadataClient(new HttpClient(psHandler)));
                services.AddSingleton(new JwksClient(new HttpClient(psHandler)));
            });
        });
        _whoAmI.CreateClient();
        return Task.CompletedTask;
    }

    public Task DisposeAsync()
    {
        _ps?.Dispose();
        _whoAmI?.Dispose();
        return Task.CompletedTask;
    }

    [Fact]
    public async Task IdentityBasedFlow_ReturnsClaimsWithoutExchange()
    {
        // Agent token with no PS — WhoAmI returns 200 directly.
        var agentKey = AAuthKey.Generate();
        var agentToken = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:demo@ap.example",
            KeyId = "demo",
            Key = agentKey,
        }.Build();

        var holder = new AAuthTokenHolder(agentToken);
        using var client = BuildAgentClient(agentKey, holder, personServer: null);

        var response = await client.GetAsync($"{WhoAmIIssuer}/");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("identity-based", (string?)body!["mode"]);
        Assert.Equal("aauth:demo@ap.example", (string?)body["agent"]);
    }

    [Fact]
    public async Task ThreePartyFlow_ExchangesAndReturnsClaims()
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

        var holder = new AAuthTokenHolder(agentToken);
        using var client = BuildAgentClient(agentKey, holder, personServer: PsIssuer);

        var response = await client.GetAsync($"{WhoAmIIssuer}/");
        var rawBody = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, $"Status={(int)response.StatusCode}, Body={rawBody}");
        var body = JsonNode.Parse(rawBody) as JsonObject;
        Assert.Equal("aauth:demo@ap.example", (string?)body!["agent"]);
        Assert.Equal("pairwise-sub", (string?)body["sub"]);

        // Holder should now carry the auth token, not the agent token.
        Assert.NotEqual(agentToken, holder.Current);
    }

    [Fact]
    public async Task ThreePartyChallenge_Returns401WithResourceToken()
    {
        // Send only through the signing pipeline (no ChallengeHandler) so we
        // can inspect the raw 401 + AAuth-Requirement response that WhoAmI
        // emits before the agent would retry. This guards against silent
        // regressions in the 401 shape that the happy-path three-party test
        // would mask.
        var agentKey = AAuthKey.Generate();
        var agentToken = new AgentTokenBuilder
        {
            Issuer = "https://ap.example",
            Subject = "aauth:demo@ap.example",
            KeyId = "demo",
            Key = agentKey,
            PersonServer = PsIssuer,
        }.Build();

        var holder = new AAuthTokenHolder(agentToken);
        // BuildAgentClient with personServer:null gives us the signing
        // pipeline without the auto-retry challenge handler.
        using var client = BuildAgentClient(agentKey, holder, personServer: null);

        var response = await client.GetAsync($"{WhoAmIIssuer}/");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.True(response.Headers.TryGetValues(AAuthRequirementHeader.Name, out var values),
            "401 response is missing the AAuth-Requirement header.");
        var requirement = AAuthRequirementHeader.Parse(string.Join(", ", values!));
        Assert.Equal(AAuthRequirementHeader.AuthTokenRequirement, requirement.Requirement);
        Assert.NotNull(requirement.ResourceToken);

        // Decode the resource_token payload and assert the spec-mandated
        // claim shape: iss=resource, aud=ps, agent + agent_jkt bound to the
        // signing key.
        var payloadSegment = requirement.ResourceToken!.Split('.')[1];
        var payload = (JsonObject)JsonNode.Parse(
            Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(payloadSegment))!;
        Assert.Equal(WhoAmIIssuer, (string?)payload["iss"]);
        Assert.Equal(PsIssuer, (string?)payload["aud"]);
        Assert.Equal("aauth:demo@ap.example", (string?)payload["agent"]);
        Assert.Equal(agentKey.ComputeJwkThumbprint(), (string?)payload["agent_jkt"]);
        Assert.Equal(ResourceTokenBuilder.ResourceDwk, (string?)payload["dwk"]);
    }

    // -------------------------------------------------------------------
    // Agent pipeline
    // -------------------------------------------------------------------

    private HttpClient BuildAgentClient(AAuthKey agentKey, AAuthTokenHolder holder, string? personServer)
    {
        // Both the resource pipeline and the exchange pipeline route through
        // the same multi-host handler so they hit the right in-process server.
        HttpMessageHandler RoutingHandler() => new MultiHostHandler(new Dictionary<string, HttpMessageHandler>
        {
            [WhoAmIHost] = _whoAmI!.Server.CreateHandler(),
            [PsHost] = _ps!.Server.CreateHandler(),
        });

        HttpMessageHandler resourceInner = new AAuthSigningHandler(agentKey, () => holder.Current)
        {
            InnerHandler = RoutingHandler(),
        };

        if (personServer is not null)
        {
            // Exchange pipeline always signs with the agent token (the value
            // captured here at construction), not the post-exchange auth token.
            var agentTokenAtConstruction = holder.Current;
            var exchangeSigning = new AAuthSigningHandler(agentKey, () => agentTokenAtConstruction)
            {
                InnerHandler = RoutingHandler(),
            };
            var exchangeHttp = new HttpClient(exchangeSigning);
            var metadata = new MetadataClient(new HttpClient(RoutingHandler()));
            var exchange = new TokenExchangeClient(exchangeHttp, metadata);
            resourceInner = new ChallengeHandler(exchange, holder, personServer)
            {
                InnerHandler = resourceInner,
            };
        }

        return new HttpClient(resourceInner);
    }

    // -------------------------------------------------------------------
    // Multi-host routing handler
    // -------------------------------------------------------------------

    private sealed class MultiHostHandler : HttpMessageHandler
    {
        private readonly Dictionary<string, HttpMessageHandler> _byHost;

        public MultiHostHandler(Dictionary<string, HttpMessageHandler> byHost)
        {
            _byHost = byHost;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var host = request.RequestUri!.Host;
            if (!_byHost.TryGetValue(host, out var inner))
            {
                throw new InvalidOperationException($"No in-process server for host '{host}'.");
            }
            // HttpMessageInvoker exposes SendAsync over a handler without
            // owning it (we keep the underlying handlers alive for reuse).
            return new HttpMessageInvoker(inner, disposeHandler: false)
                .SendAsync(request, cancellationToken);
        }
    }
}
