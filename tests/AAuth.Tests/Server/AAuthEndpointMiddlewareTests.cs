using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using AAuth.Crypto;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Xunit;

namespace AAuth.Tests.Server;

public class AAuthEndpointMiddlewareTests
{
    private static WebApplicationBuilder NewBuilder()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Services.AddAAuthResource(o =>
        {
            o.Issuer = "https://resource.example";
            o.SigningKeys["k1"] = AAuthKey.Generate();
        });
        builder.Services.AddAAuthAuthentication();
        builder.Services.AddAAuthAuthorization();
        return builder;
    }

    [Fact]
    public async Task ProtectedEndpoint_WithoutSignature_DoesNotServe()
    {
        var builder = NewBuilder();
        var app = builder.Build();
        app.UseRouting();
        app.UseAAuth();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet("/secret", () => "data").RequireAAuthSignature();
        await app.StartAsync();

        using var client = app.GetTestClient();
        var resp = await client.GetAsync("/secret");

        // Fail-closed: a signature-protected endpoint never serves an unsigned
        // request (verification rejects it).
        Assert.NotEqual(HttpStatusCode.OK, resp.StatusCode);
        await app.StopAsync();
    }

    [Fact]
    public async Task UnprotectedEndpoint_ServesWithoutSignature()
    {
        var builder = NewBuilder();
        var app = builder.Build();
        app.UseRouting();
        app.UseAAuth();
        app.MapGet("/public", () => "ok"); // no RequireAAuth* metadata → passes through
        await app.StartAsync();

        using var client = app.GetTestClient();
        var resp = await client.GetAsync("/public");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        await app.StopAsync();
    }

    [Fact]
    public async Task UseAAuth_WithoutUseRouting_FailsClosed()
    {
        var builder = NewBuilder();
        var app = builder.Build();
        // Intentionally omit app.UseRouting() before UseAAuth().
        app.UseAAuth();
        app.MapGet("/secret", () => "data").RequireAAuthSignature();
        await app.StartAsync();

        using var client = app.GetTestClient();
        var resp = await client.GetAsync("/secret");

        // Fail-closed either way: the guard throws (500) when routing has not run,
        // or routing ran and verification rejected the unsigned request — never 200.
        Assert.NotEqual(HttpStatusCode.OK, resp.StatusCode);
        await app.StopAsync();
    }
}
