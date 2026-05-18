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
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace AAuth.Tests.Integration;

/// <summary>
/// Three-party autonomous-flow integration test:
///   AgentConsole-style client → WhoAmI resource → MockPS → WhoAmI.
///
/// Both servers run in-process behind <see cref="TestServer"/> / WebApplicationFactory.
/// A <see cref="MultiHostHandler"/> demuxes outbound HTTP by host name so a
/// single signing pipeline can talk to both servers.
/// </summary>
public class WhoAmIFlowTests : IAsyncLifetime
{
    private const string WhoAmIHost = "whoami.test";
    private const string PsHost = "ps.test";
    private static readonly string WhoAmIIssuer = $"https://{WhoAmIHost}";
    private static readonly string PsIssuer = $"https://{PsHost}";

    private WebApplicationFactory<Program>? _whoAmI;
    private IHost? _ps;
    private AAuthKey? _psKey;

    public async Task InitializeAsync()
    {
        _psKey = AAuthKey.Generate();
        _ps = await StartMockPsAsync(_psKey);
        var psHandler = _ps.GetTestServer().CreateHandler();

        _whoAmI = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
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
    }

    public async Task DisposeAsync()
    {
        if (_ps is not null)
        {
            await _ps.StopAsync();
            _ps.Dispose();
        }
        _whoAmI?.Dispose();
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
            [PsHost] = _ps!.GetTestServer().CreateHandler(),
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
    // Mock Person Server
    //
    // TODO(Phase 3 §3.1): once `samples/MockPersonServer/` ships, replace
    // this in-process mock with the shared sample binary (or its
    // WebApplicationFactory) so the integration test exercises shipped
    // sample code rather than a private duplicate.
    // -------------------------------------------------------------------

    private static async Task<IHost> StartMockPsAsync(AAuthKey psKey)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(psKey);
        builder.Services.AddSingleton(new AAuthVerifier());
        var app = builder.Build();

        const string PsKid = "ps-1";

        // Well-known endpoints — unsigned.
        app.MapAAuthResourceWellKnown(new AAuthResourceMetadataOptions
        {
            Issuer = PsIssuer,
            SigningKeys = new Dictionary<string, AAuthKey> { [PsKid] = psKey },
        });
        // PS metadata advertises the token endpoint.
        app.MapGet("/.well-known/aauth-person.json", () => Results.Json(new JsonObject
        {
            ["issuer"] = PsIssuer,
            ["jwks_uri"] = $"{PsIssuer}/.well-known/jwks.json",
            ["token_endpoint"] = $"{PsIssuer}/token",
        }));

        // Skip signature verification on /.well-known so metadata / JWKS
        // are reachable to unsigned discovery requests.
        app.UseWhen(
            ctx => !ctx.Request.Path.StartsWithSegments("/.well-known"),
            branch => branch.UseAAuthVerification());

        app.MapPost("/token", async (HttpContext ctx) =>
        {
            // The middleware exposes the parsed agent token; we trust the
            // payload's `sub` for the agent identifier. We don't fully
            // verify the resource_token here (cross-server JWKS fetch would
            // be a more elaborate test); we just mint an auth token bound
            // to the agent's cnf.jwk.
            var parsed = (SignatureKeyParser.ParsedSignatureKey)ctx.Items[
                AAuthVerificationMiddleware.ContextItemKey]!;
            var agentId = (string?)parsed.Payload["sub"] ?? "unknown";

            var body = await ctx.Request.ReadFromJsonAsync<JsonObject>();
            var resourceTokenJwt = (string?)body?["resource_token"];
            if (resourceTokenJwt is null)
            {
                ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
                return Results.Json(new { error = "missing resource_token" });
            }

            // Read the resource token's iss claim — that becomes the auth
            // token's aud. (resource_token: iss=resource, aud=PS.
            //  auth_token:     iss=PS,       aud=resource.)
            var payloadSegment = resourceTokenJwt.Split('.')[1];
            var payload = (JsonObject)JsonNode.Parse(
                Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(payloadSegment))!;
            var audience = (string?)payload["iss"]
                ?? throw new InvalidOperationException("resource_token missing iss");

            var authToken = new AuthTokenBuilder
            {
                Issuer = PsIssuer,
                Audience = audience,
                Agent = agentId,
                AgentConfirmationKey = parsed.ConfirmationKey,
                Key = psKey,
                KeyId = PsKid,
                Subject = "pairwise-sub",
                Scope = "whoami",
            }.Build();

            return Results.Ok(new { auth_token = authToken });
        });

        await app.StartAsync();
        return app;
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
