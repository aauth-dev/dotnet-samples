using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Server;
using AAuth.Server.Authorization;
using AAuth.Server.CallChaining;
using AAuth.Server.Challenge;
using AAuth.Server.Metadata;
using AAuth.Server.Verification;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace AAuth.Conformance.Discovery;

/// <summary>
/// Conformance for resource well-known metadata + JWKS per
/// draft-hardt-oauth-aauth-protocol-01 §Discovery.
/// </summary>
public class WellKnownMetadataTests : IAsyncLifetime
{
    private const string Issuer = "https://resource.example";
    private const string Kid = "k1";

    private IHost? _host;
    private AAuthKey _key = AAuthKey.Generate();

    public async Task InitializeAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var app = builder.Build();
        app.MapAAuthResourceWellKnown(new AAuthResourceMetadataOptions
        {
            Issuer = Issuer,
            Name = "Conformance Demo",
            DocumentationUri = $"{Issuer}/docs",
            SigningKeys = new AAuthSigningKeySet { [Kid] = _key },
            ScopeDescriptions = new Dictionary<string, string> { ["whoami"] = "See your basic profile." },
            SignatureWindow = 90,
            AdditionalSignatureComponents = new[] { "content-type", "@query" },
            AdditionalMetadata = new Dictionary<string, JsonNode?>
            {
                ["r3_vocabularies"] = new JsonObject { ["urn:aauth:vocabulary:mcp"] = $"{Issuer}/mcp" },
            },
        });
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

    [Fact(DisplayName = "§Discovery — /.well-known/aauth-resource.json includes 'issuer'")]
    public async Task ResourceMetadata_HasIssuer()
    {
        var doc = await Get("/.well-known/aauth-resource.json");
        Assert.Equal(Issuer, (string?)doc["issuer"]);
    }

    [Fact(DisplayName = "§Discovery — resource metadata includes 'jwks_uri'")]
    public async Task ResourceMetadata_HasJwksUri()
    {
        var doc = await Get("/.well-known/aauth-resource.json");
        Assert.Equal($"{Issuer}/.well-known/jwks.json", (string?)doc["jwks_uri"]);
    }

    [Fact(DisplayName = "§Discovery — resource metadata MAY include 'name'")]
    public async Task ResourceMetadata_OptionalName()
    {
        var doc = await Get("/.well-known/aauth-resource.json");
        Assert.Equal("Conformance Demo", (string?)doc["name"]);
    }

    [Fact(DisplayName = "§Discovery — resource metadata MAY include 'documentation_uri'")]
    public async Task ResourceMetadata_OptionalDocumentationUri()
    {
        var doc = await Get("/.well-known/aauth-resource.json");
        Assert.Equal($"{Issuer}/docs", (string?)doc["documentation_uri"]);
    }

    [Fact(DisplayName = "§Discovery — resource metadata MAY include 'scope_descriptions'")]
    public async Task ResourceMetadata_OptionalScopeDescriptions()
    {
        var doc = await Get("/.well-known/aauth-resource.json");
        var scopes = doc["scope_descriptions"] as JsonObject;
        Assert.NotNull(scopes);
        Assert.Equal("See your basic profile.", (string?)scopes!["whoami"]);
    }

    [Fact(DisplayName = "§Discovery — resource metadata MAY include 'signature_window'")]
    public async Task ResourceMetadata_OptionalSignatureWindow()
    {
        var doc = await Get("/.well-known/aauth-resource.json");
        Assert.Equal(90, (int?)doc["signature_window"]);
    }

    [Fact(DisplayName = "§Discovery — resource metadata MAY include 'additional_signature_components'")]
    public async Task ResourceMetadata_OptionalAdditionalSignatureComponents()
    {
        var doc = await Get("/.well-known/aauth-resource.json");
        var components = doc["additional_signature_components"] as JsonArray;

        Assert.NotNull(components);
        Assert.Equal(new[] { "content-type", "@query" }, components!.Select(component => (string?)component).ToArray());
    }

    [Fact(DisplayName = "§Discovery — JWKS exposes the resource's signing key by kid")]
    public async Task Jwks_ContainsSigningKey()
    {
        var doc = await Get("/.well-known/jwks.json");
        var keys = doc["keys"] as JsonArray;
        Assert.NotNull(keys);
        Assert.NotEmpty(keys!);
        var jwk = (JsonObject)keys![0]!;
        Assert.Equal("OKP", (string?)jwk["kty"]);
        Assert.Equal("Ed25519", (string?)jwk["crv"]);
        Assert.Equal(Kid, (string?)jwk["kid"]);
        Assert.Equal("sig", (string?)jwk["use"]);
        Assert.Equal("Ed25519", (string?)jwk["alg"]);
        // JWKS MUST NOT include the private 'd' parameter.
        Assert.Null(jwk["d"]);
    }

    [Fact(DisplayName = "§Discovery — resource metadata merges AdditionalMetadata extension members")]
    public async Task ResourceMetadata_MergesAdditionalMetadata()
    {
        var doc = await Get("/.well-known/aauth-resource.json");
        var vocabs = doc["r3_vocabularies"] as JsonObject;
        Assert.NotNull(vocabs);
        Assert.Equal($"{Issuer}/mcp", (string?)vocabs!["urn:aauth:vocabulary:mcp"]);
    }

    [Theory(DisplayName = "§Discovery — AdditionalMetadata MUST NOT shadow typed fields")]
    [InlineData("issuer")]
    [InlineData("additional_signature_components")]
    [InlineData("logo_uri")]
    public void ResourceMetadata_AdditionalMetadataShadowingFailsStartup(string field)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var app = builder.Build();

        Assert.Throws<InvalidOperationException>(() => app.MapAAuthResourceWellKnown(new AAuthResourceMetadataOptions
        {
            Issuer = Issuer,
            SigningKeys = new AAuthSigningKeySet { [Kid] = AAuthKey.Generate() },
            AdditionalMetadata = new Dictionary<string, JsonNode?> { [field] = "https://attacker.example" },
        }));
    }

    [Theory(DisplayName = "§Discovery — producer metadata URL fields fail closed")]
    [InlineData("https://resource.example/authorize?x=1", null)]
    [InlineData("https://resource.example/authorize#frag", null)]
    [InlineData(null, "http://attacker.example/logo.png")]
    public void ResourceMetadata_InvalidTypedUrlFailsStartup(string? authorizationEndpoint, string? logoUri)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var app = builder.Build();

        Assert.Throws<InvalidOperationException>(() => app.MapAAuthResourceWellKnown(new AAuthResourceMetadataOptions
        {
            Issuer = Issuer,
            SigningKeys = new AAuthSigningKeySet { [Kid] = AAuthKey.Generate() },
            AuthorizationEndpoint = authorizationEndpoint,
            LogoUri = logoUri,
        }));
    }

    private async Task<JsonObject> Get(string path)
    {
        using var client = _host!.GetTestServer().CreateClient();
        var doc = await client.GetFromJsonAsync<JsonObject>($"http://localhost{path}");
        Assert.NotNull(doc);
        return doc!;
    }
}
