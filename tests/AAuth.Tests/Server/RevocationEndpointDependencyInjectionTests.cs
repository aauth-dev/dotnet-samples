using System.Net;
using System.Net.Http.Json;
using AAuth.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.Tests.Server;

public class RevocationEndpointDependencyInjectionTests
{
    [Fact(DisplayName = "the revocation endpoint requires a registered IJtiStore")]
    public async Task RequiresRegisteredStore()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        await using var app = builder.Build();

        var failure = Assert.Throws<InvalidOperationException>(() => app.MapAAuthRevocationEndpoint());
        Assert.Contains(nameof(IJtiStore), failure.Message, StringComparison.Ordinal);
    }

    [Fact(DisplayName = "the revocation endpoint maps over the DI store at the configured path")]
    public async Task MapsOverDiStore()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton<IJtiStore>(new InMemoryJtiStore());
        await using var app = builder.Build();
        app.MapAAuthRevocationEndpoint("/tokens/revoke", options => options.IsAcceptedIssuer = AAuthTrust.Any);
        await app.StartAsync();

        // No verified caller: answered by the endpoint (not 404), which refuses the unsigned request.
        using var response = await app.GetTestClient().PostAsJsonAsync("/tokens/revoke", new { jti = "t-1", exp = 1 });
        Assert.NotEqual(HttpStatusCode.NotFound, response.StatusCode);
        Assert.False(response.IsSuccessStatusCode);
    }
}
