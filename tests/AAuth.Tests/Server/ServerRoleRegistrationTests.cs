using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using AAuth.Access;
using AAuth.Crypto;
using AAuth.Person;
using AAuth.Server;
using AAuth.Server.Governance;
using AAuth.Server.Metadata;
using AAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AAuth.Tests.Server;

internal static class RoleHost
{
    public const string Ps = "http://localhost:5100";
    public const string OtherPs = "http://localhost:5555";
    public const string As = "http://localhost:5500";
    public const string Resource = "http://localhost:5000";

    public static WebApplicationBuilder Builder(string environment = "Development", IDictionary<string, string?>? config = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = environment });
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        if (config is not null) builder.Configuration.AddInMemoryCollection(config);
        return builder;
    }

    public static void PersonServer(AAuthPersonServerOptions options, string issuer = Ps, string kid = "ps-1")
    {
        options.EgressPolicy = TestEgress.Policy;
        options.Issuer = issuer;
        options.SigningKeys = new AAuthSigningKeySet(kid, AAuthKey.Generate());
    }

    public static void AccessServer(AAuthAccessServerOptions options)
    {
        options.EgressPolicy = TestEgress.Policy;
        options.Issuer = As;
        options.SigningKeys = new AAuthSigningKeySet("as-1", AAuthKey.Generate());
    }

    public static HttpClient Client(WebApplication app, string origin)
    {
        var client = app.GetTestClient();
        client.BaseAddress = new Uri(origin);
        return client;
    }
}

internal sealed class AllowAll : IAccessPolicy
{
    public Task<AccessDecision> EvaluateAsync(AccessPolicyRequest request, CancellationToken cancellationToken = default)
        => Task.FromResult(AccessDecision.Allow());
}

internal sealed class NamedAsserter : IIdentityClaimsAsserter
{
    public Task<IdentityAssertion> AssertAsync(IdentityAssertionRequest request, CancellationToken cancellationToken = default)
        => Task.FromResult(IdentityAssertion.Assert("named"));
}

internal sealed class CapturingLoggerProvider : ILoggerProvider
{
    public ConcurrentQueue<(LogLevel Level, string Message)> Entries { get; } = new();
    public ILogger CreateLogger(string categoryName) => new Logger(this);
    public void Dispose() { }

    private sealed class Logger(CapturingLoggerProvider owner) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => owner.Entries.Enqueue((logLevel, formatter(state, exception)));
    }
}

public class PersonServerRegistrationTests
{
    private const string Name = AAuthPersonServerBuilder.DefaultName;

    [Fact(DisplayName = "the Person Server registers its defaults and identity")]
    public async Task Defaults_Resolved()
    {
        var builder = RoleHost.Builder();
        builder.Services.AddAAuthPersonServer(configure: options => RoleHost.PersonServer(options));
        await using var app = builder.Build();
        var services = app.Services;

        Assert.IsType<InMemoryPersonPendingStore>(services.GetRequiredKeyedService<IPersonPendingStore>(Name));
        Assert.IsType<DefaultIdentityClaimsAsserter>(services.GetRequiredKeyedService<IIdentityClaimsAsserter>(Name));
        Assert.IsType<InMemoryJtiStore>(services.GetRequiredKeyedService<IJtiStore>(Name));
        Assert.Same(TestEgress.Policy, services.GetRequiredKeyedService<TokenVerifier>(Name).EgressPolicy);
        Assert.IsType<InMemoryMissionStore>(services.GetRequiredService<IMissionStore>());
        var identity = services.GetRequiredKeyedService<IAAuthServerIdentity>(Name);
        Assert.Equal(RoleHost.Ps, identity.Issuer);
        Assert.Equal(AuthTokenBuilder.PersonDwk, identity.Dwk);
        Assert.Equal("ps-1", identity.SigningKeys.ActiveKeyId);
        Assert.Equal($"{RoleHost.Ps}/mission", identity.Url("/mission"));
    }

    [Fact(DisplayName = "builder helpers replace each seam, ahead of DI registrations")]
    public async Task BuilderHelpers_ReplaceSeams()
    {
        var pending = new InMemoryPersonPendingStore();
        var inventory = new InMemoryJtiStore();
        var verifier = new TokenVerifier();
        var builder = RoleHost.Builder();
        builder.Services.AddSingleton<IIdentityClaimsAsserter>(new DefaultIdentityClaimsAsserter("di"));
        builder.Services.AddAAuthPersonServer(configure: options => RoleHost.PersonServer(options))
            .UsePendingStore(pending).UseClaimsAsserter<NamedAsserter>().UseTokenInventory(inventory).UseTokenVerifier(verifier);
        await using var app = builder.Build();

        Assert.Same(pending, app.Services.GetRequiredKeyedService<IPersonPendingStore>(Name));
        Assert.IsType<NamedAsserter>(app.Services.GetRequiredKeyedService<IIdentityClaimsAsserter>(Name));
        Assert.Same(inventory, app.Services.GetRequiredKeyedService<IJtiStore>(Name));
        Assert.Same(verifier, app.Services.GetRequiredKeyedService<TokenVerifier>(Name));
    }

    [Fact(DisplayName = "unkeyed DI registrations replace the defaults")]
    public async Task DiRegistrations_ReplaceDefaults()
    {
        var pending = new InMemoryPersonPendingStore();
        var asserter = new NamedAsserter();
        var builder = RoleHost.Builder();
        builder.Services.AddAAuthPersonServer(configure: options => RoleHost.PersonServer(options));
        builder.Services.AddSingleton<IPersonPendingStore>(pending);
        builder.Services.AddSingleton<IIdentityClaimsAsserter>(asserter);
        await using var app = builder.Build();

        Assert.Same(pending, app.Services.GetRequiredKeyedService<IPersonPendingStore>(Name));
        Assert.Same(asserter, app.Services.GetRequiredKeyedService<IIdentityClaimsAsserter>(Name));
    }

    [Theory(DisplayName = "startup validation fails fast on a missing issuer or key")]
    [InlineData("issuer", "Issuer must be an absolute https URL")]
    [InlineData("key", "needs a signing key")]
    public async Task Validation_FailsFast(string missing, string message)
    {
        var builder = RoleHost.Builder();
        builder.Services.AddAAuthPersonServer(configure: options =>
        {
            options.EgressPolicy = TestEgress.Policy;
            if (missing != "issuer") options.Issuer = RoleHost.Ps;
            if (missing != "key") options.SigningKeys = new AAuthSigningKeySet("ps-1", AAuthKey.Generate());
        });
        await using var app = builder.Build();

        var failure = await Assert.ThrowsAsync<OptionsValidationException>(() => app.StartAsync());
        Assert.Contains(failure.Failures, text => text.Contains(message, StringComparison.Ordinal));
    }

    [Fact(DisplayName = "a key handle loads the signing key from the registered key store")]
    public async Task KeyHandle_LoadsFromKeyStore()
    {
        var store = new InMemoryKeyStore();
        var key = AAuthKey.Generate();
        await store.StoreAsync("ps-key", key);
        var builder = RoleHost.Builder();
        builder.Services.AddSingleton<IKeyStore>(store);
        builder.Services.AddAAuthPersonServer(configure: options =>
        {
            options.EgressPolicy = TestEgress.Policy;
            options.Issuer = RoleHost.Ps;
            options.KeyHandle = "ps-key";
            options.KeyId = "ps-7";
        });
        await using var app = builder.Build();
        app.MapAAuthPersonServer();
        await app.StartAsync();

        var jwks = await RoleHost.Client(app, RoleHost.Ps).GetFromJsonAsync<JsonObject>("/.well-known/jwks.json");
        var published = Assert.Single(jwks!["keys"]!.AsArray());
        Assert.Equal("ps-7", (string?)published!["kid"]);
        Assert.Equal(key.ComputeJwkThumbprint(), KeyFactory.FromPublicJwk(Public(published)).ComputeJwkThumbprint());
    }

    [Fact(DisplayName = "the Person Server binds from AAuth:PersonServer")]
    public async Task Binds_FromConfiguration()
    {
        var builder = RoleHost.Builder(config: new Dictionary<string, string?>
        {
            ["AAuth:PersonServer:Issuer"] = RoleHost.Ps,
            ["AAuth:PersonServer:TokenPath"] = "/auth-token",
            ["AAuth:PersonServer:KeyHandle"] = "ps-key",
            ["AAuth:PersonServer:KeyId"] = "ps-9",
            ["AAuth:PersonServer:MissionPath"] = "/mission",
            ["AAuth:PersonServer:MatchIssuerHost"] = "true",
            ["AAuth:PersonServer:Trust:AccessServers:Allowed:0"] = RoleHost.As,
        });
        builder.Services.AddAAuthPersonServer(builder.Configuration.GetSection(AAuthPersonServerServiceCollectionExtensions.ConfigurationSection),
            configure: options => options.EgressPolicy = TestEgress.Policy);
        await using var app = builder.Build();

        var options = app.Services.GetRequiredService<IOptionsMonitor<AAuthPersonServerOptions>>().Get(Name);
        Assert.Equal(RoleHost.Ps, options.Issuer);
        Assert.Equal("/auth-token", options.TokenPath);
        Assert.Equal(("ps-key", "ps-9"), (options.KeyHandle, options.KeyId));
        Assert.Equal("/mission", options.MissionPath);
        Assert.True(options.MatchIssuerHost);
        Assert.Contains(RoleHost.As, options.Trust.AccessServers.Allowed!);
    }

    [Theory(DisplayName = "in-memory defaults warn outside Development only")]
    [InlineData("Production", true)]
    [InlineData("Development", false)]
    public async Task InMemoryDefaults_WarnOutsideDevelopment(string environment, bool warns)
    {
        var logs = new CapturingLoggerProvider();
        var builder = RoleHost.Builder(environment);
        builder.Logging.AddProvider(logs);
        builder.Services.AddAAuthPersonServer(configure: options => RoleHost.PersonServer(options));
        await using var app = builder.Build();
        app.MapAAuthPersonServer();

        var warned = logs.Entries.Where(entry => entry.Level == LogLevel.Warning && entry.Message.Contains("in-memory", StringComparison.Ordinal))
            .Select(entry => entry.Message).ToArray();
        Assert.Equal(warns, warned.Any(message => message.Contains(nameof(InMemoryPersonPendingStore), StringComparison.Ordinal)));
        Assert.Equal(warns, warned.Any(message => message.Contains(nameof(InMemoryJtiStore), StringComparison.Ordinal)));
    }

    [Fact(DisplayName = "metadata advertises governance endpoints derived from the issuer")]
    public async Task Metadata_DerivesEndpointUrls()
    {
        var builder = RoleHost.Builder();
        builder.Services.AddAAuthPersonServer(configure: options =>
        {
            RoleHost.PersonServer(options);
            options.MissionPath = "/mission";
            options.PermissionPath = "/permission";
            options.AuditPath = "/audit";
            options.InteractionEndpointPath = "/mission-interaction";
        }).WithGovernance();
        await using var app = builder.Build();
        app.MapAAuthPersonServer();
        await app.StartAsync();

        var metadata = await RoleHost.Client(app, RoleHost.Ps).GetFromJsonAsync<JsonObject>("/.well-known/aauth-person.json");
        Assert.Equal($"{RoleHost.Ps}/mission", (string?)metadata!["mission_endpoint"]);
        Assert.Equal($"{RoleHost.Ps}/permission", (string?)metadata["permission_endpoint"]);
        Assert.Equal($"{RoleHost.Ps}/audit", (string?)metadata["audit_endpoint"]);
        Assert.Equal($"{RoleHost.Ps}/mission-interaction", (string?)metadata["interaction_endpoint"]);
    }

    [Fact(DisplayName = "mapping an unregistered Person Server fails clearly")]
    public async Task Map_Unregistered_Throws()
    {
        await using var app = RoleHost.Builder().Build();
        var failure = Assert.Throws<InvalidOperationException>(() => app.MapAAuthPersonServer("missing"));
        Assert.Contains("AddAAuthPersonServer", failure.Message, StringComparison.Ordinal);
    }

    private static JsonObject Public(JsonNode jwk)
    {
        var copy = jwk.DeepClone().AsObject();
        copy.Remove("kid");
        copy.Remove("use");
        return copy;
    }
}

public class AccessServerRegistrationTests
{
    private const string Name = AAuthAccessServerBuilder.DefaultName;

    [Fact(DisplayName = "startup fails clearly without an IAccessPolicy")]
    public async Task MissingPolicy_FailsAtStart()
    {
        var builder = RoleHost.Builder();
        builder.Services.AddAAuthAccessServer(configure: RoleHost.AccessServer);
        await using var app = builder.Build();

        var failure = await Assert.ThrowsAsync<OptionsValidationException>(() => app.StartAsync());
        Assert.Contains(failure.Failures, text => text.Contains(nameof(IAccessPolicy), StringComparison.Ordinal));
    }

    [Fact(DisplayName = "a builder policy satisfies validation and the pending store defaults to in-memory")]
    public async Task UsePolicy_AndPendingDefault()
    {
        var builder = RoleHost.Builder();
        builder.Services.AddAAuthAccessServer(configure: RoleHost.AccessServer).UsePolicy<AllowAll>();
        await using var app = builder.Build();
        app.MapAAuthAccessServer();
        await app.StartAsync();

        Assert.IsType<AllowAll>(app.Services.GetRequiredKeyedService<IAccessPolicy>(Name));
        Assert.IsType<InMemoryAccessPendingStore>(app.Services.GetRequiredKeyedService<IAccessPendingStore>(Name));
        Assert.Equal(AuthTokenBuilder.AccessDwk, app.Services.GetRequiredKeyedService<IAAuthServerIdentity>(Name).Dwk);
    }

    [Fact(DisplayName = "an unkeyed DI policy satisfies validation")]
    public async Task DiPolicy_Satisfies()
    {
        var builder = RoleHost.Builder();
        builder.Services.AddSingleton<IAccessPolicy, AllowAll>();
        builder.Services.AddAAuthAccessServer(configure: RoleHost.AccessServer);
        await using var app = builder.Build();
        await app.StartAsync();

        Assert.IsType<AllowAll>(app.Services.GetRequiredKeyedService<IAccessPolicy>(Name));
    }

    [Fact(DisplayName = "the Access Server binds from AAuth:AccessServer")]
    public async Task Binds_FromConfiguration()
    {
        var builder = RoleHost.Builder(config: new Dictionary<string, string?>
        {
            ["AAuth:AccessServer:Issuer"] = RoleHost.As,
            ["AAuth:AccessServer:TokenPath"] = "/as-token",
            ["AAuth:AccessServer:DefaultScope"] = "wallet.read",
            ["AAuth:AccessServer:Trust:PersonServers:Allowed:0"] = RoleHost.Ps,
        });
        builder.Services.AddAAuthAccessServer(builder.Configuration.GetSection(AAuthAccessServerServiceCollectionExtensions.ConfigurationSection),
                configure: options =>
                {
                    options.EgressPolicy = TestEgress.Policy;
                    options.SigningKeys = new AAuthSigningKeySet("as-1", AAuthKey.Generate());
                })
            .UsePolicy<AllowAll>();
        await using var app = builder.Build();

        var options = app.Services.GetRequiredService<IOptionsMonitor<AAuthAccessServerOptions>>().Get(Name);
        Assert.Equal((RoleHost.As, "/as-token", "wallet.read"), (options.Issuer, options.TokenPath, options.DefaultScope));
        Assert.Contains(RoleHost.Ps, options.Trust.PersonServers.Allowed!);
    }
}

public class ResourceRegistrationTests
{
    [Fact(DisplayName = "the resource registers a TokenVerifier with its egress policy and clock")]
    public void TokenVerifier_UsesRolePolicy()
    {
        var clock = new Microsoft.Extensions.Time.Testing.FakeTimeProvider();
        var services = new ServiceCollection();
        services.AddAAuthResource(options =>
        {
            options.Issuer = RoleHost.Resource;
            options.EgressPolicy = TestEgress.Policy;
            options.TimeProvider = clock;
        });
        using var provider = services.BuildServiceProvider();

        var verifier = provider.GetRequiredService<TokenVerifier>();
        Assert.Same(TestEgress.Policy, verifier.EgressPolicy);
        Assert.Same(clock, verifier.TimeProvider);
    }

    [Fact(DisplayName = "the resource binds from AAuth:Resource")]
    public void Binds_FromConfiguration()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["AAuth:Resource:Issuer"] = RoleHost.Resource,
            ["AAuth:Resource:Name"] = "Calendar",
            ["AAuth:Resource:ScopeDescriptions:calendar.read"] = "Read your calendar",
            ["AAuth:Resource:SignatureWindow"] = "30",
        }).Build();
        var services = new ServiceCollection();
        services.AddAAuthResource(configuration.GetSection(AAuthResourceServiceCollectionExtensions.ConfigurationSection),
            options => options.EgressPolicy = TestEgress.Policy);
        using var provider = services.BuildServiceProvider();

        var metadata = provider.GetRequiredService<AAuthResourceMetadataOptions>();
        Assert.Equal((RoleHost.Resource, "Calendar", 30), (metadata.Issuer, metadata.Name, metadata.SignatureWindow));
        Assert.Equal("Read your calendar", metadata.ScopeDescriptions!["calendar.read"]);
        Assert.Equal(RoleHost.Resource, provider.GetRequiredService<IOptions<AAuthResourceOptions>>().Value.Issuer);
    }

    [Fact(DisplayName = "a resource key handle loads from the registered key store")]
    public async Task KeyHandle_Loads()
    {
        var store = new InMemoryKeyStore();
        await store.StoreAsync("resource-key", AAuthKey.Generate());
        var services = new ServiceCollection();
        services.AddSingleton<IKeyStore>(store);
        services.AddAAuthResource(options =>
        {
            options.Issuer = RoleHost.Resource;
            options.EgressPolicy = TestEgress.Policy;
            options.KeyHandle = "resource-key";
            options.KeyId = "r-1";
        });
        using var provider = services.BuildServiceProvider();

        Assert.Equal("r-1", provider.GetRequiredService<AAuthResourceMetadataOptions>().SigningKeys!.ActiveKeyId);
    }
}

public class CoHostedRolesTests
{
    [Fact(DisplayName = "two Person Servers, an Access Server and a resource share one host")]
    public async Task CoHostedRoles_AreIsolated()
    {
        var builder = RoleHost.Builder();
        builder.Services.AddAAuthResource(options =>
        {
            options.Issuer = RoleHost.Resource;
            options.EgressPolicy = TestEgress.Policy;
            options.SigningKeys = new AAuthSigningKeySet("resource-1", AAuthKey.Generate());
        });
        builder.Services.AddAAuthPersonServer("tenant-a", options =>
        {
            RoleHost.PersonServer(options, RoleHost.Ps, "ps-a");
            options.MatchIssuerHost = true;
        });
        builder.Services.AddAAuthPersonServer("tenant-b", options =>
        {
            RoleHost.PersonServer(options, RoleHost.OtherPs, "ps-b");
            options.MatchIssuerHost = true;
        }).UseClaimsAsserter<NamedAsserter>();
        builder.Services.AddAAuthAccessServer(configure: options =>
        {
            RoleHost.AccessServer(options);
            options.MatchIssuerHost = true;
        }).UsePolicy<AllowAll>();
        await using var app = builder.Build();
        app.MapAAuthWellKnown();
        app.MapAAuthPersonServer("tenant-a");
        app.MapAAuthPersonServer("tenant-b");
        app.MapAAuthAccessServer();
        await app.StartAsync();

        Assert.Equal(RoleHost.Ps, await IssuerAsync(app, RoleHost.Ps, "aauth-person.json"));
        Assert.Equal(RoleHost.OtherPs, await IssuerAsync(app, RoleHost.OtherPs, "aauth-person.json"));
        Assert.Equal(RoleHost.As, await IssuerAsync(app, RoleHost.As, "aauth-access.json"));
        Assert.Equal(RoleHost.Resource, await IssuerAsync(app, RoleHost.Resource, "aauth-resource.json"));

        Assert.Equal(["ps-a"], await KidsAsync(app, RoleHost.Ps));
        Assert.Equal(["ps-b"], await KidsAsync(app, RoleHost.OtherPs));
        Assert.Equal(["as-1"], await KidsAsync(app, RoleHost.As));
        Assert.Equal(["resource-1"], await KidsAsync(app, RoleHost.Resource));

        // Seams are per instance: tenant-b has its own asserter and pending store.
        Assert.IsType<DefaultIdentityClaimsAsserter>(app.Services.GetRequiredKeyedService<IIdentityClaimsAsserter>("tenant-a"));
        Assert.IsType<NamedAsserter>(app.Services.GetRequiredKeyedService<IIdentityClaimsAsserter>("tenant-b"));
        Assert.NotSame(app.Services.GetRequiredKeyedService<IPersonPendingStore>("tenant-a"),
            app.Services.GetRequiredKeyedService<IPersonPendingStore>("tenant-b"));

        // Each role's signed token endpoint answers on its own host only.
        using var unsigned = await RoleHost.Client(app, RoleHost.OtherPs).PostAsync("/token", JsonContent.Create(new JsonObject()));
        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, unsigned.StatusCode);
        using var resourceHost = await RoleHost.Client(app, RoleHost.Resource).PostAsync("/token", JsonContent.Create(new JsonObject()));
        Assert.Equal(System.Net.HttpStatusCode.NotFound, resourceHost.StatusCode);
    }

    private static async Task<string?> IssuerAsync(WebApplication app, string origin, string dwk)
        => (string?)(await RoleHost.Client(app, origin).GetFromJsonAsync<JsonObject>($"/.well-known/{dwk}"))!["issuer"];

    private static async Task<string[]> KidsAsync(WebApplication app, string origin)
    {
        var jwks = await RoleHost.Client(app, origin).GetFromJsonAsync<JsonObject>("/.well-known/jwks.json");
        return jwks!["keys"]!.AsArray().Select(key => (string)key!["kid"]!).ToArray();
    }
}
