using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Nodes;
using AAuth;
using AAuth.Crypto;
using AAuth.Discovery;
using AAuth.Headers;
using AAuth.HttpSig;
using AAuth.Server;
using AAuth.Server.Verification;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace AAuth.Conformance.ResourceTokens;

public class AuthorizationEndpointTests : IAsyncLifetime
{
    private const string ApIssuer = "https://ap.test";
    private const string PsIssuer = "https://ps.test";
    private const string ResourceIssuer = "https://resource.test";
    private const string AgentId = "aauth:test@ap.test";

    private readonly AAuthKey _agentKey = AAuthKey.Generate();
    private readonly AAuthKey _apKey = AAuthKey.Generate();
    private readonly AAuthKey _psKey = AAuthKey.Generate();
    private IHost? _host;

    public async Task InitializeAsync()
    {
        var discovery = new StaticJsonHandler()
            .AddJson($"{ApIssuer}/.well-known/aauth-agent.json", Metadata(ApIssuer))
            .AddJson($"{ApIssuer}/.well-known/jwks.json", Jwks("ap-1", _apKey))
            .AddJson($"{PsIssuer}/.well-known/aauth-person.json", Metadata(PsIssuer))
            .AddJson($"{PsIssuer}/.well-known/jwks.json", Jwks("ps-1", _psKey));

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new AAuthVerifier());
        builder.Services.AddSingleton(new MetadataClient(new InProcessHttpClient(discovery),
            policy: TestEgress.Policy, transportContract: AAuthTransportContract.InProcessOnly));
        builder.Services.AddSingleton(new JwksClient(new InProcessHttpClient(discovery),
            policy: TestEgress.Policy, transportContract: AAuthTransportContract.InProcessOnly));
        var app = builder.Build();
        app.UseRouting();
        app.UseAAuth(options =>
        {
            options.ResourceIdentifier = ResourceIssuer;
            options.Trust.AgentProviders.Allowed = new HashSet<string> { ApIssuer };
            options.Trust.AuthTokenIssuers.Allowed = new HashSet<string> { PsIssuer };
            options.Trust.PersonServers.Allowed = new HashSet<string> { PsIssuer };
        });
        app.MapAAuthAuthorizationEndpoint("/authorize", (_, request) =>
            Task.FromResult<IResult>(Results.Json(new { accepted = true, scope = request.Scope, account = request.Account })));
        await app.StartAsync();
        _host = app;
    }

    public async Task DisposeAsync()
    {
        if (_host is not null)
        {
            await _host.StopAsync();
            _host.Dispose();
        }
    }

    [Theory]
    [InlineData("agent")]
    [InlineData("auth")]
    public async Task AuthorizationEndpoint_ChallengesNonPersonAAuthTokens(string tokenKind)
    {
        using var response = await Signed(tokenKind).PostAsJsonAsync("/authorize", new { scope = "inbox.read" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(response.Headers.Contains("Signature-Error"));
        Assert.Equal(AAuthRequirementHeader.PersonTokenRequirement,
            AAuthRequirementHeader.Parse(response.Headers.GetValues(AAuthRequirementHeader.Name).Single()).Requirement);
    }

    [Fact]
    public async Task AuthorizationEndpoint_ChallengesUnsignedCallerForPersonToken()
    {
        using var response = await _host!.GetTestClient().PostAsJsonAsync("/authorize", new { scope = "inbox.read" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(response.Headers.Contains("Signature-Error"));
        Assert.Equal(AAuthRequirementHeader.PersonTokenRequirement,
            AAuthRequirementHeader.Parse(response.Headers.GetValues(AAuthRequirementHeader.Name).Single()).Requirement);
    }

    [Fact]
    public async Task AuthorizationEndpoint_AcceptsPersonToken()
    {
        using var response = await Signed("person").PostAsJsonAsync("/authorize", new { scope = "inbox.read", account = "work" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("inbox.read", (string?)body!["scope"]);
        Assert.Equal("work", (string?)body["account"]);
    }

    [Theory]
    [InlineData("{", "application/json", "malformed JSON body")]
    [InlineData("scope=inbox.read", "text/plain", "Content-Type must be application/json")]
    public async Task AuthorizationEndpoint_InvalidBody_Returns400InvalidRequest(string content, string contentType, string detail)
    {
        using var response = await Signed("person").PostAsync("/authorize",
            new StringContent(content, Encoding.UTF8, contentType));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_request", (string?)body!["error"]);
        Assert.Equal(detail, (string?)body["detail"]);
    }

    [Fact]
    public async Task AuthorizationEndpoint_MissingScope_Returns400InvalidRequest()
    {
        using var response = await Signed("person").PostAsJsonAsync("/authorize", new { account = "work" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("invalid_request", (string?)body!["error"]);
    }

    // §Account Binding: a malformed `account` never reaches the handler, even with a
    // verified person token.
    [Theory]
    [InlineData("\"\"")]
    [InlineData("\"bad\\u0000account\"")]
    [InlineData("42")]
    [InlineData("[]")]
    [InlineData("{}")]
    public async Task AuthorizationEndpoint_MalformedAccount_Returns400(string account)
    {
        using var response = await Signed("person").PostAsJsonAsync("/authorize", new JsonObject
        {
            ["scope"] = "inbox.read",
            ["account"] = JsonNode.Parse(account),
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(response.Headers.Contains(AAuthConstants.Headers.AAuthAccess));
    }

    private HttpClient Signed(string tokenKind)
    {
        var token = tokenKind switch
        {
            "agent" => AgentTokenAsync().AsTask().GetAwaiter().GetResult(),
            "auth" => AuthTokenAsync().AsTask().GetAwaiter().GetResult(),
            "person" => PersonTokenAsync().AsTask().GetAwaiter().GetResult(),
            _ => throw new ArgumentOutOfRangeException(nameof(tokenKind)),
        };
        var signing = new AAuthSigningHandler(_agentKey, () => token)
        {
            InnerHandler = _host!.GetTestServer().CreateHandler(),
        };
        return new InProcessHttpClient(signing) { BaseAddress = new Uri(ResourceIssuer) };
    }

    private ValueTask<string> AgentTokenAsync() => new AgentTokenBuilder
    {
        EgressPolicy = TestEgress.Policy,
        Issuer = ApIssuer,
        Subject = AgentId,
        Key = _apKey,
        KeyId = "ap-1",
        ConfirmationKey = _agentKey,
    }.BuildAsync();

    private ValueTask<string> PersonTokenAsync() => new PersonTokenBuilder
    {
        EgressPolicy = TestEgress.Policy,
        Issuer = PsIssuer,
        Audience = ResourceIssuer,
        Subject = "person-1",
        ConfirmationKey = _agentKey,
        AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
        Key = _psKey,
        KeyId = "ps-1",
    }.BuildAsync();

    private ValueTask<string> AuthTokenAsync() => new AuthTokenBuilder
    {
        EgressPolicy = TestEgress.Policy,
        Issuer = PsIssuer,
        Audience = ResourceIssuer,
        PersonServer = PsIssuer,
        Subject = "person-1",
        Scope = "inbox.read",
        AgentConfirmationKey = _agentKey,
        AgentTokenExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
        Key = _psKey,
        KeyId = "ps-1",
    }.BuildAsync();

    private static JsonObject Metadata(string issuer) => new()
    {
        ["issuer"] = issuer,
        ["jwks_uri"] = $"{issuer}/.well-known/jwks.json",
    };

    private static JsonObject Jwks(string kid, AAuthKey key)
    {
        var jwk = key.ToPublicJwk();
        jwk["kid"] = kid;
        jwk["use"] = "sig";
        jwk["alg"] = AAuthKey.Ed25519Algorithm;
        return new JsonObject { ["keys"] = new JsonArray(jwk) };
    }

    private sealed class StaticJsonHandler : HttpMessageHandler
    {
        private readonly Dictionary<string, JsonObject> _json = new(StringComparer.Ordinal);

        public StaticJsonHandler AddJson(string url, JsonObject json)
        {
            _json[url] = json;
            return this;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(_json.TryGetValue(request.RequestUri!.ToString(), out var json)
                ? new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(json.ToJsonString(), Encoding.UTF8, "application/json"),
                }
                : new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }
}
