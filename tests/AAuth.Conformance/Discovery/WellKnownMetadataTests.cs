using System;
using System.Collections.Generic;
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
            ClientName = "Conformance Demo",
            SigningKeys = new Dictionary<string, AAuthKey> { [Kid] = _key },
            ScopeDescriptions = new Dictionary<string, string> { ["whoami"] = "See your basic profile." },
            SignatureWindow = 90,
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

    [Fact(DisplayName = "§Discovery — resource metadata MAY include 'client_name'")]
    public async Task ResourceMetadata_OptionalClientName()
    {
        var doc = await Get("/.well-known/aauth-resource.json");
        Assert.Equal("Conformance Demo", (string?)doc["client_name"]);
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
        Assert.Equal("EdDSA", (string?)jwk["alg"]);
        // JWKS MUST NOT include the private 'd' parameter.
        Assert.Null(jwk["d"]);
    }

    private async Task<JsonObject> Get(string path)
    {
        using var client = _host!.GetTestServer().CreateClient();
        var doc = await client.GetFromJsonAsync<JsonObject>($"http://localhost{path}");
        Assert.NotNull(doc);
        return doc!;
    }
}
