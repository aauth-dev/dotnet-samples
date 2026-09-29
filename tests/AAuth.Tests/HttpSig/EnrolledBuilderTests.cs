using System;
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.HttpSig;
using Xunit;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace AAuth.Tests.HttpSig;

public class EnrolledBuilderTests
{
    [Fact]
    public void BootstrapEnrollmentHasConcreteKeyBoundaryButEnrolledRefreshDoesNot()
    {
        Assert.Equal(typeof(AAuthKey), typeof(BootstrapBuilder).GetMethod("WithKey")!.GetParameters()[0].ParameterType);
        Assert.Equal(typeof(AAuthKey), typeof(AgentProviderClient).GetMethod("EnrolWithKeyAsync")!.GetParameters()[3].ParameterType);
        Assert.Equal(typeof(AAuthKey), typeof(EnrollResult).GetProperty("Key")!.PropertyType);
        using var client = AAuthClientBuilder.Enrolled(EcdsaAAuthKey.Generate())
            .RefreshingFrom("https://ap.example/refresh", "local-handle").Build();
        Assert.NotNull(client);
    }

    [Fact]
    public async Task ActualAgentProviderPublishesEnrolledEs256KeyAfterRestart()
    {
        var directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ap-es256-" + Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(directory);
        var key = EcdsaAAuthKey.Generate();
        string? jwksUri = null;
        string? keyId = null;
        try
        {
            for (var restart = 0; restart < 2; restart++)
            {
                using var host = new WebApplicationFactory<MockAgentProvider.Entry>().WithWebHostBuilder(builder =>
                {
                    builder.UseSetting("AgentProvider:Issuer", "http://localhost:5301");
                    builder.UseSetting("AgentProvider:KeyDirectory", System.IO.Path.Combine(directory, "keys"));
                    builder.UseSetting("AgentProvider:Database", System.IO.Path.Combine(directory, "agents.db"));
                    builder.UseSetting("Events:Database", System.IO.Path.Combine(directory, "events.db"));
                });
                using var client = host.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("http://localhost:5301") });
                if (restart == 0)
                {
                    using var request = new HttpRequestMessage(HttpMethod.Post, "http://localhost:5301/enrol")
                    {
                        Content = JsonContent.Create(new { jwk = key.ToPublicJwk() }),
                    };
                    request.Options.Set(AAuthSigningHandler.AdditionalComponentsKey, new[] { "content-type", "content-digest" });
                    using var signer = new AAuthSigningHandler(key, new HwkSignatureKeyProvider(key));
                    await signer.SignAsync(request);
                    using var enrolled = await client.SendAsync(request);
                    Assert.Equal(HttpStatusCode.OK, enrolled.StatusCode);
                    var enrollment = (await enrolled.Content.ReadFromJsonAsync<JsonObject>())!;
                    jwksUri = (string)enrollment["jwks_uri"]!;
                    keyId = (string)enrollment["key_id"]!;
                }
                var document = (await client.GetFromJsonAsync<JsonObject>(jwksUri))!;
                var published = Assert.Single(document["keys"]!.AsArray())!.AsObject();
                Assert.Equal("ES256", (string?)published["alg"]);
                Assert.Equal(keyId, (string?)published["kid"]);
                var resolved = KeyFactory.FromPublicJwk(published);
                Assert.Equal(key.ComputeJwkThumbprint(), resolved.ComputeJwkThumbprint());
                Assert.True(resolved.Verify("published-key-proof"u8.ToArray(), key.Sign("published-key-proof"u8.ToArray())));
            }
        }
        finally { System.IO.Directory.Delete(directory, true); }
    }

    private readonly AAuthKey _key = AAuthKey.Generate();
    private const string RefreshEndpoint = "http://localhost:5200/refresh";
    private const string LocalKeyHandle = "my-agent-key";
    private const string PersonServer = "http://localhost:5100";

    [Fact]
    public void Enrolled_throws_on_null_key()
    {
        Assert.Throws<ArgumentNullException>(() => AAuthClientBuilder.Enrolled(null!));
    }

    [Fact]
    public void RefreshingFrom_throws_on_null_endpoint()
    {
        var builder = AAuthClientBuilder.Enrolled(_key);
        Assert.Throws<ArgumentNullException>(() => builder.RefreshingFrom(null!, LocalKeyHandle));
    }

    [Fact]
    public void RefreshingFrom_throws_on_empty_endpoint()
    {
        var builder = AAuthClientBuilder.Enrolled(_key);
        Assert.Throws<ArgumentException>(() => builder.RefreshingFrom("", LocalKeyHandle));
    }

    [Fact]
    public void RefreshingFrom_throws_on_null_keyHandle()
    {
        var builder = AAuthClientBuilder.Enrolled(_key);
        Assert.Throws<ArgumentNullException>(() => builder.RefreshingFrom(RefreshEndpoint, null!));
    }

    [Fact]
    public void RefreshingFrom_throws_on_empty_keyHandle()
    {
        var builder = AAuthClientBuilder.Enrolled(_key);
        Assert.Throws<ArgumentException>(() => builder.RefreshingFrom(RefreshEndpoint, ""));
    }

    [Fact]
    public void Build_throws_without_RefreshingFrom()
    {
        var builder = AAuthClientBuilder.Enrolled(_key);
        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    [Fact]
    public void Enrolled_with_RefreshingFrom_builds_client()
    {
        // This builds a client with token refresh configured (will attempt refresh on first request)
        using var client = AAuthClientBuilder.Enrolled(_key)
            .RefreshingFrom(RefreshEndpoint, LocalKeyHandle)
            .WithKeyStore(new InMemoryKeyStore(_key))
            .Build();

        Assert.NotNull(client);
    }

    [Fact]
    public void Enrolled_with_challenge_handling_builds_client()
    {
        using var client = AAuthClientBuilder.Enrolled(_key)
            .RefreshingFrom(RefreshEndpoint, LocalKeyHandle)
            .WithKeyStore(new InMemoryKeyStore(_key))
            .WithChallengeHandling(PersonServer)
            .Build();

        Assert.NotNull(client);
    }

    [Fact]
    public void Enrolled_with_two_key_mode_requires_explicit_rotating_key_pipeline()
    {
        var builder = AAuthClientBuilder.Enrolled(_key)
            .RefreshingFrom(RefreshEndpoint, LocalKeyHandle)
            .WithKeyStore(new InMemoryKeyStore(_key))
            .WithRefreshMode(RefreshMode.TwoKey);

        var error = Assert.Throws<InvalidOperationException>(() => builder.Build());
        Assert.Contains("RefreshTwoKeyAsync", error.Message);
    }

    [Fact]
    public void WithKeyStore_throws_on_null()
    {
        var builder = AAuthClientBuilder.Enrolled(_key);
        Assert.Throws<ArgumentNullException>(() => builder.WithKeyStore(null!));
    }

    /// <summary>Simple in-memory key store for testing.</summary>
    private sealed class InMemoryKeyStore : IKeyStore
    {
        private readonly AAuthKey _key;
        public InMemoryKeyStore(AAuthKey key) => _key = key;
        public Task<IAAuthSigner?> LoadAsync(string handle, System.Threading.CancellationToken ct = default)
            => Task.FromResult<IAAuthSigner?>(_key);
        public Task StoreAsync(string handle, IAAuthSigner key, System.Threading.CancellationToken ct = default)
            => Task.CompletedTask;
        public Task DeleteAsync(string handle, System.Threading.CancellationToken ct = default)
            => Task.CompletedTask;
        public Task<string[]> ListAsync(System.Threading.CancellationToken ct = default)
            => Task.FromResult(Array.Empty<string>());
    }
}
