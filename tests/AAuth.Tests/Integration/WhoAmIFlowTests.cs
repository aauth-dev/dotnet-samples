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
    private const string ApHost = "ap.test";
    private static readonly string WhoAmIIssuer = $"https://{WhoAmIHost}";
    private static readonly string PsIssuer = $"https://{PsHost}";
    private static readonly string ApIssuer = $"https://{ApHost}";

    // AP signing key — all test agent tokens are signed by this key,
    // and verification discovers it via the AP's JWKS.
    private static readonly AAuthKey ApKey = AAuthKey.Generate();
    private const string ApKeyId = "ap-test-key";

    private WebApplicationFactory<WhoAmI.Entry>? _whoAmI;
    private WebApplicationFactory<MockPersonServer.Entry>? _ps;

    public Task InitializeAsync()
    {
        _ps = new WebApplicationFactory<MockPersonServer.Entry>().WithWebHostBuilder(b =>
        {
            b.UseSetting("AAuth:Issuer", PsIssuer);
            b.ConfigureServices(services =>
            {
                // The PS verifies the resource token per §"Resource Token
                // Verification", which discovers the issuing resource's JWKS.
                // Route the PS's discovery to the in-process WhoAmI (resolved
                // lazily — _whoAmI is built after this factory).
                services.RemoveAll<MetadataClient>();
                services.RemoveAll<JwksClient>();
                var psDiscovery = new MultiHostHandler(new Dictionary<string, HttpMessageHandler>
                {
                    [WhoAmIHost] = new LazyHostHandler(() => _whoAmI!.Server.CreateHandler()),
                });
                services.AddSingleton(new MetadataClient(new HttpClient(psDiscovery)));
                services.AddSingleton(new JwksClient(new HttpClient(psDiscovery)));
            });
        });
        // Force the host to start so Server is available.
        _ps.CreateClient();
        var psHandler = _ps.Server.CreateHandler();

        _whoAmI = new WebApplicationFactory<WhoAmI.Entry>().WithWebHostBuilder(b =>
        {
            b.UseSetting("AAuth:Issuer", WhoAmIIssuer);
            b.UseSetting("AAuth:TrustedPersonServers:0", PsIssuer);
            b.ConfigureServices(services =>
            {
                // Replace the metadata/JWKS clients with versions that can
                // reach both the in-process PS and the stub AP for agent
                // token verification (JWKS discovery).
                services.RemoveAll<MetadataClient>();
                services.RemoveAll<JwksClient>();
                var discoveryHandler = new MultiHostHandler(new Dictionary<string, HttpMessageHandler>
                {
                    [PsHost] = psHandler,
                    [ApHost] = new StubApHandler(ApKey, ApKeyId, ApIssuer),
                });
                services.AddSingleton(new MetadataClient(new HttpClient(discoveryHandler)));
                services.AddSingleton(new JwksClient(new HttpClient(discoveryHandler)));
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
    public async Task FlowIndex_ReturnsAvailableFlows()
    {
        // The root path is now an unauthenticated index listing the isolated
        // access modes — no AAuth signature required.
        using var client = _whoAmI!.CreateClient();

        var response = await client.GetAsync("/");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("WhoAmI Demo", (string?)body!["resource"]);
        var flows = body["flows"]!.AsArray();
        var paths = flows.Select(f => (string?)f!["path"]).ToList();
        Assert.Contains("/jwt", paths);
        Assert.Contains("/jwt/admin", paths);
        Assert.Contains("/jwt/roles", paths);
    }

    [Fact]
    public async Task ThreePartyFlow_ExchangesAndReturnsClaims()
    {
        var agentKey = AAuthKey.Generate();
        var agentToken = new AgentTokenBuilder
        {
            Issuer = ApIssuer,
            Subject = "aauth:demo@ap.test",
            KeyId = ApKeyId,
            Key = ApKey,
            ConfirmationKey = agentKey,
            PersonServer = PsIssuer,
        }.Build();

        var holder = new AAuthTokenHolder(agentToken);
        using var client = BuildAgentClient(agentKey, holder, personServer: PsIssuer);

        var response = await client.GetAsync($"{WhoAmIIssuer}/jwt");
        var rawBody = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, $"Status={(int)response.StatusCode}, Body={rawBody}");
        var body = JsonNode.Parse(rawBody) as JsonObject;
        Assert.Equal("aauth:demo@ap.test", (string?)body!["agent"]);
        Assert.Equal("pairwise-sub", (string?)body["sub"]);
        Assert.Contains("whoami", body["scope"]!.AsArray().Select(s => (string?)s));

        // Holder should now carry the auth token, not the agent token.
        Assert.NotEqual(agentToken, holder.Current);
    }

    [Fact]
    public async Task ThreePartyFlow_RejectsAuthTokenFromNonAllowlistedIssuer()
    {
        // §G8 fail-closed: the resource only honors PS-asserted (auth) tokens
        // whose issuer it explicitly trusts. Stand up a dedicated PS + WhoAmI
        // pair where the WhoAmI's TrustedPersonServers points at a different
        // PS, so the genuine auth token minted by our PS (iss = PsIssuer) is
        // rejected at the final resource call even though the exchange
        // (including resource-token verification) succeeds.
        WebApplicationFactory<WhoAmI.Entry>? negWhoAmI = null;
        using var negPs = new WebApplicationFactory<MockPersonServer.Entry>().WithWebHostBuilder(b =>
        {
            b.UseSetting("AAuth:Issuer", PsIssuer);
            b.ConfigureServices(services =>
            {
                // PS verifies the resource token → reach the paired WhoAmI.
                services.RemoveAll<MetadataClient>();
                services.RemoveAll<JwksClient>();
                var psDiscovery = new MultiHostHandler(new Dictionary<string, HttpMessageHandler>
                {
                    [WhoAmIHost] = new LazyHostHandler(() => negWhoAmI!.Server.CreateHandler()),
                });
                services.AddSingleton(new MetadataClient(new HttpClient(psDiscovery)));
                services.AddSingleton(new JwksClient(new HttpClient(psDiscovery)));
            });
        });
        negPs.CreateClient();

        using var whoAmI = new WebApplicationFactory<WhoAmI.Entry>().WithWebHostBuilder(b =>
        {
            b.UseSetting("AAuth:Issuer", WhoAmIIssuer);
            b.UseSetting("AAuth:TrustedPersonServers:0", "https://other-ps.test");
            b.ConfigureServices(services =>
            {
                services.RemoveAll<MetadataClient>();
                services.RemoveAll<JwksClient>();
                var discoveryHandler = new MultiHostHandler(new Dictionary<string, HttpMessageHandler>
                {
                    [PsHost] = negPs.Server.CreateHandler(),
                    [ApHost] = new StubApHandler(ApKey, ApKeyId, ApIssuer),
                });
                services.AddSingleton(new MetadataClient(new HttpClient(discoveryHandler)));
                services.AddSingleton(new JwksClient(new HttpClient(discoveryHandler)));
            });
        });
        whoAmI.CreateClient();
        negWhoAmI = whoAmI;

        var agentKey = AAuthKey.Generate();
        var agentToken = new AgentTokenBuilder
        {
            Issuer = ApIssuer,
            Subject = "aauth:demo@ap.test",
            KeyId = ApKeyId,
            Key = ApKey,
            ConfirmationKey = agentKey,
            PersonServer = PsIssuer,
        }.Build();

        var holder = new AAuthTokenHolder(agentToken);

        HttpMessageHandler RoutingHandler() => new MultiHostHandler(new Dictionary<string, HttpMessageHandler>
        {
            [WhoAmIHost] = whoAmI.Server.CreateHandler(),
            [PsHost] = negPs.Server.CreateHandler(),
        });

        var agentTokenAtConstruction = holder.Current;
        var exchangeSigning = new AAuthSigningHandler(agentKey, () => agentTokenAtConstruction)
        {
            InnerHandler = RoutingHandler(),
        };
        var exchange = new TokenExchangeClient(
            new HttpClient(exchangeSigning),
            new MetadataClient(new HttpClient(RoutingHandler())));
        var resourceSigning = new AAuthSigningHandler(agentKey, () => holder.Current)
        {
            InnerHandler = RoutingHandler(),
        };
        var challenge = new ChallengeHandler(exchange, holder, PsIssuer)
        {
            InnerHandler = resourceSigning,
        };
        using var client = new HttpClient(challenge);

        // The exchange succeeds (PS mints a real auth token), but the resource
        // rejects it because its issuer is not in TrustedPersonServers.
        var response = await client.GetAsync($"{WhoAmIIssuer}/jwt");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task AdminScopeFlow_IssuesElevatedScope()
    {
        var agentKey = AAuthKey.Generate();
        var agentToken = new AgentTokenBuilder
        {
            Issuer = ApIssuer,
            Subject = "aauth:demo@ap.test",
            KeyId = ApKeyId,
            Key = ApKey,
            ConfirmationKey = agentKey,
            PersonServer = PsIssuer,
        }.Build();

        var holder = new AAuthTokenHolder(agentToken);
        using var client = BuildAgentClient(agentKey, holder, personServer: PsIssuer);

        var response = await client.GetAsync($"{WhoAmIIssuer}/jwt/admin");
        var rawBody = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, $"Status={(int)response.StatusCode}, Body={rawBody}");
        var body = JsonNode.Parse(rawBody) as JsonObject;
        Assert.Equal("admin", (string?)body!["access"]);
        Assert.Contains("whoami:admin", body["scope"]!.AsArray().Select(s => (string?)s));
    }

    [Fact]
    public async Task RoleFlow_ReturnsAssertedRoles()
    {
        var agentKey = AAuthKey.Generate();
        var agentToken = new AgentTokenBuilder
        {
            Issuer = ApIssuer,
            Subject = "aauth:demo@ap.test",
            KeyId = ApKeyId,
            Key = ApKey,
            ConfirmationKey = agentKey,
            PersonServer = PsIssuer,
        }.Build();

        var holder = new AAuthTokenHolder(agentToken);
        using var client = BuildAgentClient(agentKey, holder, personServer: PsIssuer);

        var response = await client.GetAsync($"{WhoAmIIssuer}/jwt/roles");
        var rawBody = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, $"Status={(int)response.StatusCode}, Body={rawBody}");
        var body = JsonNode.Parse(rawBody) as JsonObject;
        Assert.Equal("rbac", (string?)body!["access"]);
        Assert.Contains("whoami-admin", body["roles"]!.AsArray().Select(s => (string?)s));
    }

    [Fact]
    public async Task RoleFlow_Returns403_WhenAgentLacksRole()
    {
        // A non-admin demo agent (the mock PS only asserts the whoami-admin
        // role for `aauth:demo@...` agents) completes the three-party flow
        // and receives a valid auth token WITHOUT the role. The role policy
        // on /jwt/roles must therefore reject it with 403 — exercising
        // role-based DENIAL, not just the success path.
        var agentKey = AAuthKey.Generate();
        var agentToken = new AgentTokenBuilder
        {
            Issuer = ApIssuer,
            Subject = "aauth:guest@ap.test",
            KeyId = ApKeyId,
            Key = ApKey,
            ConfirmationKey = agentKey,
            PersonServer = PsIssuer,
        }.Build();

        var holder = new AAuthTokenHolder(agentToken);
        using var client = BuildAgentClient(agentKey, holder, personServer: PsIssuer);

        var response = await client.GetAsync($"{WhoAmIIssuer}/jwt/roles");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

        // The agent DID complete the exchange (the 403 is an authorization
        // decision on a valid auth token, not an authentication failure).
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
            Issuer = ApIssuer,
            Subject = "aauth:demo@ap.test",
            KeyId = ApKeyId,
            Key = ApKey,
            ConfirmationKey = agentKey,
            PersonServer = PsIssuer,
        }.Build();

        var holder = new AAuthTokenHolder(agentToken);
        // BuildAgentClient with personServer:null gives us the signing
        // pipeline without the auto-retry challenge handler.
        using var client = BuildAgentClient(agentKey, holder, personServer: null);

        var response = await client.GetAsync($"{WhoAmIIssuer}/jwt");

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
        Assert.Equal("aauth:demo@ap.test", (string?)payload["agent"]);
        Assert.Equal(agentKey.ComputeJwkThumbprint(), (string?)payload["agent_jkt"]);
        Assert.Equal(ResourceTokenBuilder.ResourceDwk, (string?)payload["dwk"]);
        Assert.Equal("whoami", (string?)payload["scope"]);
    }

    [Fact]
    public async Task ThreePartyUserConsentFlow_WaitsForApproval()
    {
        // Spin up a second PS instance configured with RequireConsent=true
        // so the autonomous-path tests in this class keep working in their
        // existing shared factory and only this test pays the consent-gate
        // setup cost.
        WebApplicationFactory<WhoAmI.Entry>? consentWhoAmI = null;
        using var consentPs = new WebApplicationFactory<MockPersonServer.Entry>().WithWebHostBuilder(b =>
        {
            b.UseSetting("AAuth:Issuer", PsIssuer);
            b.UseSetting("MockPersonServer:RequireConsent", "true");
            b.ConfigureServices(services =>
            {
                // The PS verifies the resource token, so its discovery must
                // reach the consent-mode WhoAmI (resolved lazily).
                services.RemoveAll<MetadataClient>();
                services.RemoveAll<JwksClient>();
                var psDiscovery = new MultiHostHandler(new Dictionary<string, HttpMessageHandler>
                {
                    [WhoAmIHost] = new LazyHostHandler(() => consentWhoAmI!.Server.CreateHandler()),
                });
                services.AddSingleton(new MetadataClient(new HttpClient(psDiscovery)));
                services.AddSingleton(new JwksClient(new HttpClient(psDiscovery)));
            });
        });
        consentPs.CreateClient();
        var consentPsHandler = consentPs.Server.CreateHandler();

        // Need a WhoAmI variant whose JWKS/metadata clients point at the
        // consent-mode PS rather than the shared autonomous one.
        using var whoAmI = new WebApplicationFactory<WhoAmI.Entry>().WithWebHostBuilder(b =>
        {
            b.UseSetting("AAuth:Issuer", WhoAmIIssuer);
            b.UseSetting("AAuth:TrustedPersonServers:0", PsIssuer);
            b.ConfigureServices(services =>
            {
                services.RemoveAll<MetadataClient>();
                services.RemoveAll<JwksClient>();
                var discoveryHandler = new MultiHostHandler(new Dictionary<string, HttpMessageHandler>
                {
                    [PsHost] = consentPsHandler,
                    [ApHost] = new StubApHandler(ApKey, ApKeyId, ApIssuer),
                });
                services.AddSingleton(new MetadataClient(new HttpClient(discoveryHandler)));
                services.AddSingleton(new JwksClient(new HttpClient(discoveryHandler)));
            });
        });
        whoAmI.CreateClient();
        consentWhoAmI = whoAmI;

        var agentKey = AAuthKey.Generate();
        const string AgentId = "aauth:consent@ap.test";
        var agentToken = new AgentTokenBuilder
        {
            Issuer = ApIssuer,
            Subject = AgentId,
            KeyId = ApKeyId,
            Key = ApKey,
            ConfirmationKey = agentKey,
            PersonServer = PsIssuer,
        }.Build();

        // Routing handler so the agent's single signed pipeline can reach
        // both the consent-PS and the consent-aware WhoAmI by host name.
        HttpMessageHandler RoutingHandler() => new MultiHostHandler(new Dictionary<string, HttpMessageHandler>
        {
            [WhoAmIHost] = whoAmI.Server.CreateHandler(),
            [PsHost] = consentPsHandler,
        });

        var holder = new AAuthTokenHolder(agentToken);

        // The interaction callback simulates the user clicking "Approve"
        // at the PS's real /interaction page: POST the code (= pending id)
        // to /interaction/approve as a form, exactly as the HTML form in
        // the user's browser would. Once consent lands, the next poll on
        // /pending/{id} returns 200 + auth_token.
        Func<AAuthInteraction, CancellationToken, Task> approveAsUser =
            async (interaction, ct) =>
            {
                Assert.NotNull(interaction.Code);
                Assert.StartsWith($"{PsIssuer}/interaction", interaction.Url);

                using var browser = new HttpClient(consentPsHandler, disposeHandler: false);
                using var resp = await browser.PostAsync(
                    $"{PsIssuer}/interaction/approve",
                    new FormUrlEncodedContent(new[]
                    {
                        new KeyValuePair<string, string>("code", interaction.Code),
                    }), ct);
                Assert.True(resp.IsSuccessStatusCode,
                    $"/interaction/approve failed: {(int)resp.StatusCode}");
            };

        // Build a signed pipeline that funnels deferred-PS responses through
        // ChallengeHandler → TokenExchangeClient (deferred-aware overload).
        var agentTokenAtConstruction = holder.Current;
        var exchangeSigning = new AAuthSigningHandler(agentKey, () => agentTokenAtConstruction)
        {
            InnerHandler = RoutingHandler(),
        };
        var exchangeHttp = new HttpClient(exchangeSigning);
        var metadata = new MetadataClient(new HttpClient(RoutingHandler()));
        var exchange = new TokenExchangeClient(exchangeHttp, metadata);

        var pollerOptions = new DeferredPollerOptions
        {
            MaxTotalWait = TimeSpan.FromSeconds(10),
            DefaultPollInterval = TimeSpan.FromMilliseconds(20),
            MinPollInterval = TimeSpan.Zero,
        };
        var resourceSigning = new AAuthSigningHandler(agentKey, () => holder.Current)
        {
            InnerHandler = RoutingHandler(),
        };
        var challenge = new ChallengeHandler(exchange, holder, PsIssuer, approveAsUser, pollerOptions)
        {
            InnerHandler = resourceSigning,
        };
        using var client = new HttpClient(challenge);

        var response = await client.GetAsync($"{WhoAmIIssuer}/jwt");
        var rawBody = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode,
            $"Status={(int)response.StatusCode}, Body={rawBody}");
        var body = JsonNode.Parse(rawBody) as JsonObject;
        Assert.Equal(AgentId, (string?)body!["agent"]);
        Assert.Equal("pairwise-sub", (string?)body["sub"]);

        // Carrier swapped to the post-exchange auth token, just like the
        // autonomous flow.
        Assert.NotEqual(agentToken, holder.Current);
    }

    [Fact]
    public async Task ThreePartyUserConsentFlow_ThrowsAAuthInteractionDenied_WhenUserDenies()
    {
        // Same plumbing as the approval test, but the interaction
        // callback simulates the user clicking Deny instead of Approve.
        // The PS marks the pending entry as denied and the agent's
        // next /pending/{id} poll receives 403 + access_denied. The
        // SDK must surface that as AAuthInteractionDeniedException
        // rather than a generic HttpRequestException.
        WebApplicationFactory<WhoAmI.Entry>? consentWhoAmI = null;
        using var consentPs = new WebApplicationFactory<MockPersonServer.Entry>().WithWebHostBuilder(b =>
        {
            b.UseSetting("AAuth:Issuer", PsIssuer);
            b.UseSetting("MockPersonServer:RequireConsent", "true");
            b.ConfigureServices(services =>
            {
                // The PS verifies the resource token, so its discovery must
                // reach the consent-mode WhoAmI (resolved lazily).
                services.RemoveAll<MetadataClient>();
                services.RemoveAll<JwksClient>();
                var psDiscovery = new MultiHostHandler(new Dictionary<string, HttpMessageHandler>
                {
                    [WhoAmIHost] = new LazyHostHandler(() => consentWhoAmI!.Server.CreateHandler()),
                });
                services.AddSingleton(new MetadataClient(new HttpClient(psDiscovery)));
                services.AddSingleton(new JwksClient(new HttpClient(psDiscovery)));
            });
        });
        consentPs.CreateClient();
        var consentPsHandler = consentPs.Server.CreateHandler();

        using var whoAmI = new WebApplicationFactory<WhoAmI.Entry>().WithWebHostBuilder(b =>
        {
            b.UseSetting("AAuth:Issuer", WhoAmIIssuer);
            b.ConfigureServices(services =>
            {
                services.RemoveAll<MetadataClient>();
                services.RemoveAll<JwksClient>();
                var discoveryHandler = new MultiHostHandler(new Dictionary<string, HttpMessageHandler>
                {
                    [PsHost] = consentPsHandler,
                    [ApHost] = new StubApHandler(ApKey, ApKeyId, ApIssuer),
                });
                services.AddSingleton(new MetadataClient(new HttpClient(discoveryHandler)));
                services.AddSingleton(new JwksClient(new HttpClient(discoveryHandler)));
            });
        });
        whoAmI.CreateClient();
        consentWhoAmI = whoAmI;

        var agentKey = AAuthKey.Generate();
        const string AgentId = "aauth:denier@ap.test";
        var agentToken = new AgentTokenBuilder
        {
            Issuer = ApIssuer,
            Subject = AgentId,
            KeyId = ApKeyId,
            Key = ApKey,
            ConfirmationKey = agentKey,
            PersonServer = PsIssuer,
        }.Build();

        HttpMessageHandler RoutingHandler() => new MultiHostHandler(new Dictionary<string, HttpMessageHandler>
        {
            [WhoAmIHost] = whoAmI.Server.CreateHandler(),
            [PsHost] = consentPsHandler,
        });

        var holder = new AAuthTokenHolder(agentToken);

        Func<AAuthInteraction, CancellationToken, Task> denyAsUser =
            async (interaction, ct) =>
            {
                using var browser = new HttpClient(consentPsHandler, disposeHandler: false);
                using var resp = await browser.PostAsync(
                    $"{PsIssuer}/interaction/deny",
                    new FormUrlEncodedContent(new[]
                    {
                        new KeyValuePair<string, string>("code", interaction.Code),
                    }), ct);
                Assert.True(resp.IsSuccessStatusCode,
                    $"/interaction/deny failed: {(int)resp.StatusCode}");
            };

        var agentTokenAtConstruction = holder.Current;
        var exchangeSigning = new AAuthSigningHandler(agentKey, () => agentTokenAtConstruction)
        {
            InnerHandler = RoutingHandler(),
        };
        var exchangeHttp = new HttpClient(exchangeSigning);
        var metadata = new MetadataClient(new HttpClient(RoutingHandler()));
        var exchange = new TokenExchangeClient(exchangeHttp, metadata);

        var pollerOptions = new DeferredPollerOptions
        {
            MaxTotalWait = TimeSpan.FromSeconds(10),
            DefaultPollInterval = TimeSpan.FromMilliseconds(20),
            MinPollInterval = TimeSpan.Zero,
        };
        var resourceSigning = new AAuthSigningHandler(agentKey, () => holder.Current)
        {
            InnerHandler = RoutingHandler(),
        };
        var challenge = new ChallengeHandler(exchange, holder, PsIssuer, denyAsUser, pollerOptions)
        {
            InnerHandler = resourceSigning,
        };
        using var client = new HttpClient(challenge);

        await Assert.ThrowsAsync<AAuthInteractionDeniedException>(
            () => client.GetAsync($"{WhoAmIIssuer}/jwt"));

        // Carrier did NOT swap — the agent never received an auth token.
        Assert.Equal(agentToken, holder.Current);
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

    private sealed class LazyHostHandler : HttpMessageHandler
    {
        private readonly Func<HttpMessageHandler> _resolve;

        public LazyHostHandler(Func<HttpMessageHandler> resolve)
        {
            _resolve = resolve;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return new HttpMessageInvoker(_resolve(), disposeHandler: false)
                .SendAsync(request, cancellationToken);
        }
    }

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

    // -------------------------------------------------------------------
    // Stub AP handler — serves metadata + JWKS for agent token verification
    // -------------------------------------------------------------------

    private sealed class StubApHandler : HttpMessageHandler
    {
        private readonly string _metadataJson;
        private readonly string _jwksJson;
        private readonly string _issuer;

        public StubApHandler(AAuthKey apKey, string keyId, string issuer)
        {
            _issuer = issuer;
            _metadataJson = new JsonObject
            {
                ["issuer"] = issuer,
                ["jwks_uri"] = $"{issuer}/.well-known/jwks.json",
                ["enrol_endpoint"] = $"{issuer}/enrol",
            }.ToJsonString();

            var jwk = apKey.ToPublicJwk();
            jwk["kid"] = keyId;
            jwk["use"] = "sig";
            jwk["alg"] = AAuthKey.Algorithm;
            _jwksJson = new JsonObject
            {
                ["keys"] = new System.Text.Json.Nodes.JsonArray(jwk)
            }.ToJsonString();
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath;
            string json;
            if (path == "/.well-known/aauth-agent.json")
                json = _metadataJson;
            else if (path == "/.well-known/jwks.json")
                json = _jwksJson;
            else
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));

            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json"),
            };
            return Task.FromResult(response);
        }
    }
}
