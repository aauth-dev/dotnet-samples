using System.Collections.Generic;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Server.Metadata;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace AAuth.Conformance.Discovery;

/// <summary>
/// Conformance for the draft-02 resource-metadata additions: the advisory
/// <c>access_mode</c> field and the relaxed (conditional) <c>jwks_uri</c>.
/// </summary>
public class ResourceAccessModeMetadataTests
{
    private const string Issuer = "https://resource.example";

    [Fact(DisplayName = "§Resource Metadata — emits access_mode when configured")]
    public async Task EmitsAccessMode()
    {
        var doc = await FetchMetadata(new AAuthResourceMetadataOptions
        {
            Issuer = Issuer,
            SigningKeys = new Dictionary<string, AAuthKey> { ["k1"] = AAuthKey.Generate() },
            AccessMode = AAuthConstants.AccessModes.AuthToken,
        });

        Assert.Equal("auth-token", (string?)doc["access_mode"]);
        Assert.Equal($"{Issuer}/.well-known/jwks.json", (string?)doc["jwks_uri"]);
    }

    [Fact(DisplayName = "§Resource Metadata — identity-only resource omits jwks_uri")]
    public async Task IdentityOnlyOmitsJwksUri()
    {
        var doc = await FetchMetadata(new AAuthResourceMetadataOptions
        {
            Issuer = Issuer,
            // No signing keys: a resource that only verifies agent signatures.
            AccessMode = AAuthConstants.AccessModes.AgentToken,
        });

        Assert.False(doc.ContainsKey("jwks_uri"));
        Assert.Equal("agent-token", (string?)doc["access_mode"]);
    }

    [Fact(DisplayName = "§Resource Metadata — access_mode omitted when not configured")]
    public async Task OmitsAccessModeWhenUnset()
    {
        var doc = await FetchMetadata(new AAuthResourceMetadataOptions
        {
            Issuer = Issuer,
            SigningKeys = new Dictionary<string, AAuthKey> { ["k1"] = AAuthKey.Generate() },
        });

        Assert.False(doc.ContainsKey("access_mode"));
    }

    private static async Task<JsonObject> FetchMetadata(AAuthResourceMetadataOptions options)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var app = builder.Build();
        app.MapAAuthResourceWellKnown(options);
        await app.StartAsync();
        try
        {
            var client = app.GetTestClient();
            var doc = await client.GetFromJsonAsync<JsonObject>("/.well-known/aauth-resource.json");
            return doc!;
        }
        finally
        {
            await app.StopAsync();
            if (app is System.IDisposable d) { d.Dispose(); }
        }
    }
}
