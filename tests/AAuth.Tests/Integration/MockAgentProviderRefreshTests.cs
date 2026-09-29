using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;
using AAuth.Discovery;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace AAuth.Tests.Integration;

/// <summary>The sample AP's refresh endpoint reports signature failures as 401 + <c>Signature-Error</c>.</summary>
public sealed class MockAgentProviderRefreshTests : System.IDisposable
{
    private readonly string _home = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ap-refresh-" + System.Guid.NewGuid().ToString("N"));
    private readonly WebApplicationFactory<MockAgentProvider.Entry> _factory;

    public MockAgentProviderRefreshTests() => _factory = new WebApplicationFactory<MockAgentProvider.Entry>().WithWebHostBuilder(builder =>
    {
        builder.UseSetting("AgentProvider:KeyDirectory", System.IO.Path.Combine(_home, "keys"));
        builder.UseSetting("AgentProvider:Database", System.IO.Path.Combine(_home, "agents.db"));
        builder.UseSetting("Events:Database", System.IO.Path.Combine(_home, "events.db"));
    });

    public void Dispose()
    {
        _factory.Dispose();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        if (System.IO.Directory.Exists(_home)) System.IO.Directory.Delete(_home, recursive: true);
    }

    [Fact]
    public async Task UnsignedRefresh_IsInvalidInput()
    {
        using var response = await _factory.CreateClient().PostAsync("/refresh", null);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.StartsWith("error=invalid_input", response.Headers.GetValues("Signature-Error").Single());
    }

    [Fact]
    public async Task UnsupportedScheme_NegotiatesHwkAndJktJwt()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/refresh");
        request.Headers.TryAddWithoutValidation("Signature-Key",
            AAuth.HttpSig.SignatureKeyHeader.FormatJwksUri("https://other.example", "aauth-agent.json", "k1"));
        using var response = await _factory.CreateClient().SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("error=unsupported_scheme", response.Headers.GetValues("Signature-Error").Single());
        Assert.Equal("hwk, jkt-jwt", response.Headers.GetValues("Accept-Signature-Scheme").Single());
    }

    [Fact]
    public async Task TamperedSignature_IsInvalidSignature()
    {
        using var client = new AAuthClientBuilder(AAuthKey.Generate()).UseHwk().WithEgressPolicy(TestEgress.Policy)
            .WithInnerHandler(new TamperSignature { InnerHandler = _factory.Server.CreateHandler() }, AAuthTransportContract.InProcessOnly)
            .Build();
        using var response = await client.PostAsync(_factory.Server.BaseAddress + "refresh", null);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("error=invalid_signature", response.Headers.GetValues("Signature-Error").Single());
    }

    private sealed class TamperSignature : DelegatingHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var signature = request.Headers.GetValues("Signature").Single();
            var colon = signature.IndexOf(':') + 1;
            var tampered = signature[..colon] + (signature[colon] == 'A' ? 'B' : 'A') + signature[(colon + 1)..];
            request.Headers.Remove("Signature");
            request.Headers.TryAddWithoutValidation("Signature", tampered);
            return base.SendAsync(request, cancellationToken);
        }
    }
}
