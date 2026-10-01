using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Server;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.Tests.Server;

/// <summary>
/// The single trust seam: rules compose by AND, unset means open (the spec default),
/// an empty allow-list denies, and an explicit or DI-registered policy replaces the
/// rules. DI policies may take scoped dependencies inside and outside a request.
/// </summary>
public class AAuthTrustPolicyTests
{
    private const string Id = "https://ps.example";
    private static readonly IServiceProvider NoServices = new ServiceCollection().BuildServiceProvider();

    private static ValueTask<bool> Trusted(AAuthTrustOptions trust, string issuer, AAuthTrustedParty party = AAuthTrustedParty.AuthTokenIssuer)
        => trust.IsTrustedAsync(issuer, party, NoServices);

    [Fact(DisplayName = "unset rules are open (spec default) and report unconfigured")]
    public async Task UnsetRules_AreOpen()
    {
        var trust = new AAuthTrustOptions();
        Assert.True(await Trusted(trust, Id));
        Assert.False(trust.IsConfigured(AAuthTrustedParty.AuthTokenIssuer, NoServices));
    }

    [Fact(DisplayName = "an empty allow-list denies all")]
    public async Task EmptyAllowList_Denies()
    {
        var trust = new AAuthTrustOptions { AuthTokenIssuers = { Allowed = new HashSet<string>() } };
        Assert.False(await Trusted(trust, Id));
        Assert.True(trust.IsConfigured(AAuthTrustedParty.AuthTokenIssuer));
    }

    [Fact(DisplayName = "allow-list AND sync predicate AND async predicate")]
    public async Task RuleParts_ComposeByAnd()
    {
        var allowAsync = true;
        var trust = new AAuthTrustOptions
        {
            AuthTokenIssuers =
            {
                Allowed = new HashSet<string> { Id, "https://other.example" },
                Predicate = id => id == Id,
                PredicateAsync = (_, _) => ValueTask.FromResult(allowAsync),
            },
        };
        Assert.True(await Trusted(trust, Id));
        Assert.False(await Trusted(trust, "https://other.example"));   // predicate narrows
        Assert.False(await Trusted(trust, "https://third.example"));   // allow-list narrows
        allowAsync = false;
        Assert.False(await Trusted(trust, Id));                        // async predicate narrows
    }

    [Fact(DisplayName = "AAuthTrust.Any is explicit open trust")]
    public async Task Any_IsConfiguredOpenTrust()
    {
        var trust = new AAuthTrustOptions { AuthTokenIssuers = { Predicate = AAuthTrust.Any } };
        Assert.True(await Trusted(trust, "https://anything.example"));
        Assert.True(trust.IsConfigured(AAuthTrustedParty.AuthTokenIssuer));
    }

    [Fact(DisplayName = "person-token trust falls back to auth-token issuers until configured")]
    public async Task PersonServers_FallBackToAuthTokenIssuers()
    {
        var trust = new AAuthTrustOptions { AuthTokenIssuers = { Allowed = new HashSet<string> { Id } } };
        Assert.False(await Trusted(trust, "https://ps2.example", AAuthTrustedParty.PersonServer));

        trust.PersonServers.Allowed = new HashSet<string> { "https://ps2.example" };
        Assert.True(await Trusted(trust, "https://ps2.example", AAuthTrustedParty.PersonServer));
        Assert.False(await Trusted(trust, Id, AAuthTrustedParty.PersonServer));
    }

    [Fact(DisplayName = "the async predicate receives the request, token type and party")]
    public async Task AsyncPredicate_SeesContext()
    {
        AAuthTrustContext? seen = null;
        var trust = new AAuthTrustOptions
        {
            AgentProviders = { PredicateAsync = (context, _) => { seen = context; return ValueTask.FromResult(true); } },
        };
        var http = new DefaultHttpContext();
        Assert.True(await trust.IsTrustedAsync(Id, AAuthTrustedParty.AgentProvider, NoServices, http, "aa-agent+jwt"));
        Assert.Same(http, seen!.HttpContext);
        Assert.Equal("aa-agent+jwt", seen.TokenType);
        Assert.Equal(AAuthTrustedParty.AgentProvider, seen.Party);
    }

    [Fact(DisplayName = "an explicit policy replaces the rules and any DI policy")]
    public async Task ExplicitPolicy_BeatsRulesAndDi()
    {
        var services = new ServiceCollection().AddSingleton<IAAuthTrustPolicy>(new FixedPolicy(true)).BuildServiceProvider();
        var trust = new AAuthTrustOptions
        {
            AuthTokenIssuers = { Allowed = new HashSet<string> { Id } },
            Policy = new FixedPolicy(false),
        };
        Assert.False(await trust.IsTrustedAsync(Id, AAuthTrustedParty.AuthTokenIssuer, services));
    }

    [Fact(DisplayName = "a DI policy replaces the rules and resolves scoped dependencies in a request")]
    public async Task DiPolicy_ScopedDependency_InRequest()
    {
        var root = Services();
        using var scope = root.CreateScope();
        var http = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        scope.ServiceProvider.GetRequiredService<Allowed>().Issuers.Add(Id);
        var trust = new AAuthTrustOptions { AuthTokenIssuers = { Allowed = new HashSet<string>() } };

        Assert.True(trust.IsConfigured(AAuthTrustedParty.AuthTokenIssuer, root));
        Assert.True(await trust.IsTrustedAsync(Id, AAuthTrustedParty.AuthTokenIssuer, http.RequestServices, http));
        Assert.False(await trust.IsTrustedAsync("https://other.example", AAuthTrustedParty.AuthTokenIssuer, http.RequestServices, http));
    }

    [Fact(DisplayName = "a DI policy resolves scoped dependencies from a background scope")]
    public async Task DiPolicy_ScopedDependency_InBackgroundScope()
    {
        var root = Services();
        using var first = root.CreateScope();
        using var second = root.CreateScope();
        first.ServiceProvider.GetRequiredService<Allowed>().Issuers.Add(Id);
        var trust = new AAuthTrustOptions();

        Assert.True(await trust.IsTrustedAsync(Id, AAuthTrustedParty.AuthTokenIssuer, first.ServiceProvider));
        Assert.False(await trust.IsTrustedAsync(Id, AAuthTrustedParty.AuthTokenIssuer, second.ServiceProvider));
    }

    private static ServiceProvider Services() => new ServiceCollection()
        .AddScoped<Allowed>()
        .AddScoped<IAAuthTrustPolicy, ScopedPolicy>()
        .BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });

    private sealed class Allowed
    {
        public HashSet<string> Issuers { get; } = [];
    }

    private sealed class ScopedPolicy(Allowed allowed) : IAAuthTrustPolicy
    {
        public ValueTask<bool> IsTrustedAsync(AAuthTrustContext context, CancellationToken cancellationToken = default)
            => ValueTask.FromResult(allowed.Issuers.Contains(context.Issuer));
    }

    private sealed class FixedPolicy(bool result) : IAAuthTrustPolicy
    {
        public ValueTask<bool> IsTrustedAsync(AAuthTrustContext context, CancellationToken cancellationToken = default)
            => ValueTask.FromResult(result);
    }
}
