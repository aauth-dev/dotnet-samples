using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Agent.Governance;
using AAuth.Crypto;
using AAuth.HttpSig;
using AAuth.Tokens;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Xunit;

namespace AAuth.Tests.DependencyInjection;

public class AAuthAgentDITests
{
    private readonly AAuthKey _key = AAuthKey.Generate();

    private ValueTask<string> AgentTokenAsync(string? ps = "https://ps.example") => new AgentTokenBuilder
    {
        EgressPolicy = TestEgress.Policy, Issuer = "https://ap.example", Subject = "aauth:test@example.com",
        KeyId = "k1", Key = _key, ConfirmationKey = _key, PersonServer = ps,
    }.BuildAsync();

    [Fact]
    public async Task AddAAuthAgent_IsLazy_AndSignsWithTheAgentToken()
    {
        var capture = new CaptureHandler();
        var token = await AgentTokenAsync();
        var services = new ServiceCollection();
        services.AddAAuthAgent("calendar", options =>
        {
            options.Signer = _key;
            options.AgentToken = token;
            options.EgressPolicy = TestEgress.Policy;
            options.InnerHandler = capture;
            options.TransportContract = AAuth.Discovery.AAuthTransportContract.InProcessOnly;
        });
        var composed = false;
        services.AddAAuthAgent("never-resolved", options => composed = true);

        await using var provider = services.BuildServiceProvider();
        var agent = provider.GetRequiredService<IAAuthAgentFactory>().Get("calendar");
        using var response = await agent.HttpClient.GetAsync("https://resource.example/events");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains(token, capture.SignatureKey);
        Assert.False(composed);
    }

    [Fact]
    public async Task AddAAuthAgent_KeyHandle_ResolvesThroughTheKeyStore()
    {
        var capture = new CaptureHandler();
        var store = new InMemoryKeyStore();
        await store.StoreAsync("agent-key", _key);
        var services = new ServiceCollection();
        services.AddSingleton<IKeyStore>(store);
        services.AddAAuthAgent("signer", options =>
        {
            options.KeyHandle = "agent-key";
            options.SignatureKeyProvider = new HwkSignatureKeyProvider(_key);
            options.EgressPolicy = TestEgress.Policy;
            options.InnerHandler = capture;
            options.TransportContract = AAuth.Discovery.AAuthTransportContract.InProcessOnly;
        });

        await using var provider = services.BuildServiceProvider();
        using var client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("signer");
        using var response = await client.GetAsync("https://resource.example/");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.StartsWith("sig=hwk", capture.SignatureKey);
    }

    [Fact]
    public void AddAAuthAgent_BindsEveryScalarFromItsSection()
    {
        var values = new Dictionary<string, string?>();
        var expected = new List<(string Path, object Value)>();
        foreach (var (path, property) in Scalars(typeof(AAuthAgentOptions), ""))
        {
            var (raw, value) = Sample(property.PropertyType);
            var target = Nullable.GetUnderlyingType(property.PropertyType) ?? property.PropertyType;
            if (target == typeof(string[]) || target == typeof(IList<string>)) values[$"AAuth:Agents:calendar:{path}:0"] = raw;
            else values[$"AAuth:Agents:calendar:{path}"] = raw;
            expected.Add((path, value));
        }
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(values).Build();
        var services = new ServiceCollection();
        services.AddAAuthAgent("calendar", configuration.GetSection("AAuth:Agents:calendar"));
        using var provider = services.BuildServiceProvider();

        // Every scalar is set, so the sources conflict; read the bound values before validation.
        var options = new AAuthAgentOptions();
        foreach (var setup in provider.GetServices<IConfigureOptions<AAuthAgentOptions>>())
            if (setup is IConfigureNamedOptions<AAuthAgentOptions> named) named.Configure("calendar", options);

        Assert.NotEmpty(expected);
        foreach (var (path, value) in expected)
        {
            var bound = Read(options, path);
            if (value is string[] array) Assert.Equal(array, ((IEnumerable<string>)bound!).ToArray());
            else Assert.Equal(value, bound);
        }
    }

    [Theory]
    [InlineData("missing", "Configure an identity source")]
    [InlineData("conflict", "Conflicting identity sources")]
    [InlineData("no-key", "Set Signer or KeyHandle")]
    [InlineData("generic-flow", "require an agent-token identity")]
    public async Task ValidateOnStart_FailsOnMissingOrConflictingSources(string scenario, string message)
    {
        var token = await AgentTokenAsync();
        var builder = Host.CreateApplicationBuilder();
        builder.Services.AddAAuthAgent("agent", options =>
        {
            options.Signer = scenario == "no-key" ? null : _key;
            switch (scenario)
            {
                case "conflict":
                    options.AgentToken = token;
                    options.SelfIssued.Issuer = "https://agent.example";
                    options.SelfIssued.Subject = "aauth:agent@agent.example";
                    break;
                case "no-key":
                    options.AgentToken = token;
                    break;
                case "generic-flow":
                    options.SignatureKeyProvider = new HwkSignatureKeyProvider(_key);
                    options.PersonServer = "https://ps.example";
                    break;
            }
        });
        using var host = builder.Build();

        var failure = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync());
        Assert.Contains(failure.Failures, entry => entry.Contains(message, StringComparison.Ordinal));
    }

    [Fact]
    public async Task WithGovernance_RegistersAKeyedGovernanceClient()
    {
        var token = await AgentTokenAsync();
        var services = new ServiceCollection();
        services.AddAAuthAgent("missions", options =>
        {
            options.Signer = _key;
            options.AgentToken = token;
            options.PersonServer = "https://ps.example";
        }).WithGovernance();

        await using var provider = services.BuildServiceProvider();

        Assert.NotNull(provider.GetRequiredKeyedService<AAuthGovernanceClient>("missions"));
    }

    [Fact]
    public async Task WithAgentProvider_ProvisionsAKeyedAgentProviderClient()
    {
        var store = new InMemoryKeyStore();
        await store.StoreAsync("agent-key", _key);
        var services = new ServiceCollection();
        services.AddSingleton<IKeyStore>(store);
        services.AddAAuthAgent("enrolled", options => options.KeyHandle = "agent-key")
            .WithAgentProvider(provider => provider.RefreshEndpoint = "https://ap.example/refresh");

        await using var provider = services.BuildServiceProvider();

        Assert.NotNull(provider.GetRequiredKeyedService<AgentProviderClient>("enrolled"));
        Assert.Equal("https://ap.example/refresh",
            provider.GetRequiredService<IOptionsMonitor<AAuthAgentOptions>>().Get("enrolled").AgentProvider.RefreshEndpoint);
    }

    private static IEnumerable<(string Path, PropertyInfo Property)> Scalars(Type type, string prefix)
    {
        foreach (var property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance).Where(p => p.CanWrite))
        {
            var target = Nullable.GetUnderlyingType(property.PropertyType) ?? property.PropertyType;
            var path = prefix + property.Name;
            if (target == typeof(string) || target == typeof(bool) || target == typeof(int) || target == typeof(TimeSpan)
                || target == typeof(string[]) || target == typeof(IList<string>))
                yield return (path, property);
            else if (target.Name.EndsWith("Options", StringComparison.Ordinal))
                foreach (var nested in Scalars(target, path + ":"))
                    yield return nested;
        }
    }

    private static (string Raw, object Value) Sample(Type type)
    {
        var target = Nullable.GetUnderlyingType(type) ?? type;
        if (target == typeof(bool)) return ("true", true);
        if (target == typeof(int)) return ("7", 7);
        if (target == typeof(TimeSpan)) return ("00:00:42", TimeSpan.FromSeconds(42));
        if (target == typeof(string[]) || target == typeof(IList<string>)) return ("https://item.example", new[] { "https://item.example" });
        return ("https://value.example", "https://value.example");
    }

    private static object? Read(object instance, string path)
    {
        object? current = instance;
        foreach (var segment in path.Split(':'))
            current = current!.GetType().GetProperty(segment)!.GetValue(current);
        return current;
    }

    private sealed class CaptureHandler : HttpMessageHandler
    {
        public string SignatureKey { get; private set; } = "";

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            SignatureKey = string.Join(",", request.Headers.GetValues("Signature-Key"));
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }
}
