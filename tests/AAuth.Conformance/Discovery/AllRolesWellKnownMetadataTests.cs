using System.Collections.Generic;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace AAuth.Conformance.Discovery;

/// <summary>
/// Conformance tests for all four AAuth well-known metadata endpoints.
/// Verifies agent, person server, and access server metadata helpers
/// alongside the existing resource metadata helper.
/// </summary>
public class AllRolesWellKnownMetadataTests : IAsyncLifetime
{
    private const string AgentIssuer = "https://agent.example";
    private const string PsIssuer = "https://ps.example";
    private const string AsIssuer = "https://as.example";
    private const string AgentKid = "agent-1";
    private const string PsKid = "ps-1";
    private const string AsKid = "as-1";
    private const string ResourceKid = "res-1";

    private IHost? _agentHost;
    private IHost? _psHost;
    private IHost? _asHost;
    private IHost? _combinedHost;

    private readonly AAuthKey _agentKey = AAuthKey.Generate();
    private readonly AAuthKey _psKey = AAuthKey.Generate();
    private readonly AAuthKey _asKey = AAuthKey.Generate();
    private readonly AAuthKey _resourceKey = AAuthKey.Generate();

    public async Task InitializeAsync()
    {
        // Standalone agent host
        var agentApp = WebApplication.CreateBuilder();
        agentApp.WebHost.UseTestServer();
        var a = agentApp.Build();
        a.MapAAuthAgentWellKnown(new AAuthAgentMetadataOptions
        {
            Issuer = AgentIssuer,
            ClientName = "Test Agent",
            SigningKeys = new Dictionary<string, AAuthKey> { [AgentKid] = _agentKey },
            CallbackEndpoint = $"{AgentIssuer}/callback",
        });
        await a.StartAsync();
        _agentHost = a;

        // Standalone PS host
        var psApp = WebApplication.CreateBuilder();
        psApp.WebHost.UseTestServer();
        var p = psApp.Build();
        p.MapAAuthPersonServerWellKnown(new AAuthPersonServerMetadataOptions
        {
            Issuer = PsIssuer,
            TokenEndpoint = $"{PsIssuer}/token",
            SigningKeys = new Dictionary<string, AAuthKey> { [PsKid] = _psKey },
            MissionEndpoint = $"{PsIssuer}/mission",
            ScopesSupported = new[] { "whoami", "data.read" },
        });
        await p.StartAsync();
        _psHost = p;

        // Standalone AS host
        var asApp = WebApplication.CreateBuilder();
        asApp.WebHost.UseTestServer();
        var s = asApp.Build();
        s.MapAAuthAccessServerWellKnown(new AAuthAccessServerMetadataOptions
        {
            Issuer = AsIssuer,
            TokenEndpoint = $"{AsIssuer}/token",
            SigningKeys = new Dictionary<string, AAuthKey> { [AsKid] = _asKey },
            RevocationEndpoint = $"{AsIssuer}/revoke",
        });
        await s.StartAsync();
        _asHost = s;

        // Combined host: resource + agent with DIFFERENT keys (tests JWKS merging)
        var combinedApp = WebApplication.CreateBuilder();
        combinedApp.WebHost.UseTestServer();
        var c = combinedApp.Build();
        c.MapAAuthResourceWellKnown(new AAuthResourceMetadataOptions
        {
            Issuer = AgentIssuer,
            SigningKeys = new Dictionary<string, AAuthKey> { [ResourceKid] = _resourceKey },
        });
        c.MapAAuthAgentWellKnown(new AAuthAgentMetadataOptions
        {
            Issuer = AgentIssuer,
            SigningKeys = new Dictionary<string, AAuthKey> { [AgentKid] = _agentKey },
        });
        await c.StartAsync();
        _combinedHost = c;
    }

    public async Task DisposeAsync()
    {
        foreach (var h in new[] { _agentHost, _psHost, _asHost, _combinedHost })
        {
            if (h is not null) { await h.StopAsync(); h.Dispose(); }
        }
    }

    // --- Agent Metadata ---

    [Fact(DisplayName = "§Discovery — aauth-agent.json has 'issuer'")]
    public async Task AgentMetadata_HasIssuer()
    {
        var doc = await Get(_agentHost!, "/.well-known/aauth-agent.json");
        Assert.Equal(AgentIssuer, (string?)doc["issuer"]);
    }

    [Fact(DisplayName = "§Discovery — aauth-agent.json has 'jwks_uri'")]
    public async Task AgentMetadata_HasJwksUri()
    {
        var doc = await Get(_agentHost!, "/.well-known/aauth-agent.json");
        Assert.Equal($"{AgentIssuer}/.well-known/jwks.json", (string?)doc["jwks_uri"]);
    }

    [Fact(DisplayName = "§Discovery — aauth-agent.json MAY include 'client_name'")]
    public async Task AgentMetadata_OptionalClientName()
    {
        var doc = await Get(_agentHost!, "/.well-known/aauth-agent.json");
        Assert.Equal("Test Agent", (string?)doc["client_name"]);
    }

    [Fact(DisplayName = "§Discovery — aauth-agent.json MAY include 'callback_endpoint'")]
    public async Task AgentMetadata_OptionalCallbackEndpoint()
    {
        var doc = await Get(_agentHost!, "/.well-known/aauth-agent.json");
        Assert.Equal($"{AgentIssuer}/callback", (string?)doc["callback_endpoint"]);
    }

    [Fact(DisplayName = "§Discovery — standalone agent JWKS endpoint serves keys")]
    public async Task AgentJwks_ServesKeys()
    {
        var doc = await Get(_agentHost!, "/.well-known/jwks.json");
        var keys = doc["keys"] as JsonArray;
        Assert.NotNull(keys);
        Assert.NotEmpty(keys!);
        var jwk = (JsonObject)keys![0]!;
        Assert.Equal(AgentKid, (string?)jwk["kid"]);
        Assert.Null(jwk["d"]);
    }

    // --- Person Server Metadata ---

    [Fact(DisplayName = "§Discovery — aauth-person.json has 'issuer'")]
    public async Task PsMetadata_HasIssuer()
    {
        var doc = await Get(_psHost!, "/.well-known/aauth-person.json");
        Assert.Equal(PsIssuer, (string?)doc["issuer"]);
    }

    [Fact(DisplayName = "§Discovery — aauth-person.json has 'token_endpoint'")]
    public async Task PsMetadata_HasTokenEndpoint()
    {
        var doc = await Get(_psHost!, "/.well-known/aauth-person.json");
        Assert.Equal($"{PsIssuer}/token", (string?)doc["token_endpoint"]);
    }

    [Fact(DisplayName = "§Discovery — aauth-person.json has 'jwks_uri'")]
    public async Task PsMetadata_HasJwksUri()
    {
        var doc = await Get(_psHost!, "/.well-known/aauth-person.json");
        Assert.Equal($"{PsIssuer}/.well-known/jwks.json", (string?)doc["jwks_uri"]);
    }

    [Fact(DisplayName = "§Discovery — aauth-person.json MAY include 'mission_endpoint'")]
    public async Task PsMetadata_OptionalMissionEndpoint()
    {
        var doc = await Get(_psHost!, "/.well-known/aauth-person.json");
        Assert.Equal($"{PsIssuer}/mission", (string?)doc["mission_endpoint"]);
    }

    [Fact(DisplayName = "§Discovery — aauth-person.json MAY include 'scopes_supported'")]
    public async Task PsMetadata_OptionalScopesSupported()
    {
        var doc = await Get(_psHost!, "/.well-known/aauth-person.json");
        var scopes = doc["scopes_supported"] as JsonArray;
        Assert.NotNull(scopes);
        Assert.Equal(2, scopes!.Count);
        Assert.Equal("whoami", (string?)scopes[0]);
        Assert.Equal("data.read", (string?)scopes[1]);
    }

    [Fact(DisplayName = "§Discovery — standalone PS JWKS endpoint serves keys")]
    public async Task PsJwks_ServesKeys()
    {
        var doc = await Get(_psHost!, "/.well-known/jwks.json");
        var keys = doc["keys"] as JsonArray;
        Assert.NotNull(keys);
        Assert.NotEmpty(keys!);
        Assert.Equal(PsKid, (string?)((JsonObject)keys![0]!)["kid"]);
    }

    // --- Access Server Metadata ---

    [Fact(DisplayName = "§Discovery — aauth-access.json has 'issuer'")]
    public async Task AsMetadata_HasIssuer()
    {
        var doc = await Get(_asHost!, "/.well-known/aauth-access.json");
        Assert.Equal(AsIssuer, (string?)doc["issuer"]);
    }

    [Fact(DisplayName = "§Discovery — aauth-access.json has 'token_endpoint'")]
    public async Task AsMetadata_HasTokenEndpoint()
    {
        var doc = await Get(_asHost!, "/.well-known/aauth-access.json");
        Assert.Equal($"{AsIssuer}/token", (string?)doc["token_endpoint"]);
    }

    [Fact(DisplayName = "§Discovery — aauth-access.json has 'jwks_uri'")]
    public async Task AsMetadata_HasJwksUri()
    {
        var doc = await Get(_asHost!, "/.well-known/aauth-access.json");
        Assert.Equal($"{AsIssuer}/.well-known/jwks.json", (string?)doc["jwks_uri"]);
    }

    [Fact(DisplayName = "§Discovery — aauth-access.json MAY include 'revocation_endpoint'")]
    public async Task AsMetadata_OptionalRevocationEndpoint()
    {
        var doc = await Get(_asHost!, "/.well-known/aauth-access.json");
        Assert.Equal($"{AsIssuer}/revoke", (string?)doc["revocation_endpoint"]);
    }

    [Fact(DisplayName = "§Discovery — standalone AS JWKS endpoint serves keys")]
    public async Task AsJwks_ServesKeys()
    {
        var doc = await Get(_asHost!, "/.well-known/jwks.json");
        var keys = doc["keys"] as JsonArray;
        Assert.NotNull(keys);
        Assert.NotEmpty(keys!);
        Assert.Equal(AsKid, (string?)((JsonObject)keys![0]!)["kid"]);
    }

    // --- Combined Host (Resource + Agent) ---

    [Fact(DisplayName = "§Discovery — combined host serves resource metadata")]
    public async Task CombinedHost_ResourceMetadata()
    {
        var doc = await Get(_combinedHost!, "/.well-known/aauth-resource.json");
        Assert.Equal(AgentIssuer, (string?)doc["issuer"]);
    }

    [Fact(DisplayName = "§Discovery — combined host serves agent metadata")]
    public async Task CombinedHost_AgentMetadata()
    {
        var doc = await Get(_combinedHost!, "/.well-known/aauth-agent.json");
        Assert.Equal(AgentIssuer, (string?)doc["issuer"]);
        Assert.Equal($"{AgentIssuer}/.well-known/jwks.json", (string?)doc["jwks_uri"]);
    }

    [Fact(DisplayName = "§Discovery — combined host JWKS merges keys from all helpers")]
    public async Task CombinedHost_JwksMergesKeys()
    {
        var doc = await Get(_combinedHost!, "/.well-known/jwks.json");
        var keys = doc["keys"] as JsonArray;
        Assert.NotNull(keys);
        // Should contain BOTH the resource key and the agent key
        Assert.Equal(2, keys!.Count);
        var kids = new HashSet<string>();
        foreach (var k in keys)
            kids.Add((string?)((JsonObject)k!)["kid"] ?? "");
        Assert.Contains(ResourceKid, kids);
        Assert.Contains(AgentKid, kids);
    }

    // --- Validation Tests ---

    [Fact(DisplayName = "§Discovery — agent metadata requires issuer")]
    public void AgentMetadata_RequiresIssuer()
    {
        Assert.Throws<InvalidOperationException>(() =>
            new AAuthAgentMetadataOptions
            {
                Issuer = "",
                SigningKeys = new Dictionary<string, AAuthKey> { ["k"] = AAuthKey.Generate() },
            }.Validate());
    }

    [Fact(DisplayName = "§Discovery — PS metadata requires token_endpoint")]
    public void PsMetadata_RequiresTokenEndpoint()
    {
        Assert.Throws<InvalidOperationException>(() =>
            new AAuthPersonServerMetadataOptions
            {
                Issuer = "https://ps.example",
                TokenEndpoint = "",
                SigningKeys = new Dictionary<string, AAuthKey> { ["k"] = AAuthKey.Generate() },
            }.Validate());
    }

    [Fact(DisplayName = "§Discovery — AS metadata requires token_endpoint")]
    public void AsMetadata_RequiresTokenEndpoint()
    {
        Assert.Throws<InvalidOperationException>(() =>
            new AAuthAccessServerMetadataOptions
            {
                Issuer = "https://as.example",
                TokenEndpoint = "",
                SigningKeys = new Dictionary<string, AAuthKey> { ["k"] = AAuthKey.Generate() },
            }.Validate());
    }

    private static async Task<JsonObject> Get(IHost host, string path)
    {
        using var client = host.GetTestServer().CreateClient();
        var doc = await client.GetFromJsonAsync<JsonObject>($"http://localhost{path}");
        Assert.NotNull(doc);
        return doc!;
    }
}
