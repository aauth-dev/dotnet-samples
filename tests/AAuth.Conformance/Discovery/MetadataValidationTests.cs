using System.Net;
using System.Text.Json.Nodes;
using AAuth.Discovery;
using AAuth.Errors;
using AAuth.HttpSig;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;

namespace AAuth.Conformance.Discovery;

public class MetadataValidationTests
{
    private const string Issuer = "https://resource.example";

    [Theory(DisplayName = "§Discovery — consumer metadata URL fields fail closed")]
    [InlineData("authorization_endpoint", "https://resource.example/authorize?x=1")]
    [InlineData("revocation_endpoint", "https://resource.example/revoke#fragment")]
    [InlineData("logo_uri", "http://attacker.example/logo.png")]
    [InlineData("permission_endpoint", "http://attacker.example/permission")]
    public async Task ConsumerRejectsInvalidMetadataUrls(string field, string value)
    {
        await using var app = await StartMetadataHostAsync(new JsonObject
        {
            ["issuer"] = Issuer,
            ["jwks_uri"] = $"{Issuer}/.well-known/jwks.json",
            [field] = value,
        });
        using var client = new MetadataClient(app.GetTestClient(), policy: AAuthEgressPolicy.Production,
            transportContract: AAuthTransportContract.InProcessOnly);

        var exception = await Assert.ThrowsAsync<AAuthVerificationException>(() =>
            client.FetchAsync(new Uri($"{Issuer}/.well-known/aauth-resource.json")));
        Assert.Equal(SignatureErrorCode.InvalidKey, exception.Code);
    }

    [Fact(DisplayName = "§Discovery — consumer requires localhost_callback_allowed to be boolean")]
    public async Task ConsumerRejectsNonBooleanLocalhostCallbackAllowed()
    {
        await using var app = await StartMetadataHostAsync(new JsonObject
        {
            ["issuer"] = Issuer,
            ["jwks_uri"] = $"{Issuer}/.well-known/jwks.json",
            ["localhost_callback_allowed"] = "false",
        });
        using var client = new MetadataClient(app.GetTestClient(), policy: AAuthEgressPolicy.Production,
            transportContract: AAuthTransportContract.InProcessOnly);

        await Assert.ThrowsAsync<AAuthVerificationException>(() =>
            client.FetchAsync(new Uri($"{Issuer}/.well-known/aauth-agent.json")));
    }

    private static async Task<WebApplication> StartMetadataHostAsync(JsonObject document)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var app = builder.Build();
        app.MapGet("/.well-known/aauth-resource.json", () => Results.Json(document));
        app.MapGet("/.well-known/aauth-agent.json", () => Results.Json(document));
        app.MapGet("/.well-known/jwks.json", () => Results.Json(new JsonObject { ["keys"] = new JsonArray() }));
        await app.StartAsync();
        return app;
    }
}
