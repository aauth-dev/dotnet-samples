using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace AAuth.Server;

/// <summary>The counterparty role a trust decision is about.</summary>
public enum AAuthTrustedParty
{
    /// <summary>A Person Server or Access Server issuing auth tokens.</summary>
    AuthTokenIssuer,

    /// <summary>A Person Server issuing person tokens, or brokered by an Access Server.</summary>
    PersonServer,

    /// <summary>An Agent Provider issuing agent tokens.</summary>
    AgentProvider,

    /// <summary>An Access Server a Person Server federates to.</summary>
    AccessServer,
}

/// <summary>What a trust decision is about, and where it is being made.</summary>
public sealed class AAuthTrustContext
{
    /// <summary>Create a trust context.</summary>
    public AAuthTrustContext(string issuer, AAuthTrustedParty party, IServiceProvider services)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentNullException.ThrowIfNull(services);
        Issuer = issuer;
        Party = party;
        Services = services;
    }

    /// <summary>The verified issuer (or server identifier) being evaluated.</summary>
    public string Issuer { get; }

    /// <summary>The role the issuer plays in this decision.</summary>
    public AAuthTrustedParty Party { get; }

    /// <summary>The <c>typ</c> of the token being verified, when there is one.</summary>
    public string? TokenType { get; init; }

    /// <summary>The current request, or <see langword="null"/> outside a request.</summary>
    public HttpContext? HttpContext { get; init; }

    /// <summary>Request services in a request, otherwise a scope created for the decision.</summary>
    public IServiceProvider Services { get; }
}

/// <summary>
/// Decides whether a verified counterparty is trusted. Register one in DI, set
/// <see cref="AAuthTrustOptions.Policy"/>, or attach one to an endpoint with
/// <c>RequireAAuth(trust:)</c>; otherwise the rules on <see cref="AAuthTrustOptions"/> apply.
/// </summary>
public interface IAAuthTrustPolicy
{
    /// <summary>Whether <see cref="AAuthTrustContext.Issuer"/> is trusted in its role.</summary>
    ValueTask<bool> IsTrustedAsync(AAuthTrustContext context, CancellationToken cancellationToken = default);
}

/// <summary>
/// Trust for one counterparty role. Every configured part must accept (AND). With
/// nothing configured, any cryptographically verifiable counterparty is trusted,
/// which is the AAuth default. An empty <see cref="Allowed"/> set denies all.
/// </summary>
public sealed class AAuthTrustRule
{
    /// <summary>Allow-list of identifiers. <see langword="null"/> means no list.</summary>
    public IReadOnlySet<string>? Allowed { get; set; }

    /// <summary>Synchronous predicate over the identifier; see <see cref="AAuthTrust.Any"/>.</summary>
    public Func<string, bool>? Predicate { get; set; }

    /// <summary>Asynchronous predicate with the full context (request, services).</summary>
    public Func<AAuthTrustContext, CancellationToken, ValueTask<bool>>? PredicateAsync { get; set; }

    /// <summary>Whether any part of this rule is set.</summary>
    public bool IsConfigured => Allowed is not null || Predicate is not null || PredicateAsync is not null;

    /// <summary>Evaluate the rule for <paramref name="context"/>.</summary>
    public async ValueTask<bool> EvaluateAsync(AAuthTrustContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (Allowed is not null && !Allowed.Contains(context.Issuer)) return false;
        if (Predicate is not null && !Predicate(context.Issuer)) return false;
        return PredicateAsync is null || await PredicateAsync(context, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>
/// The single trust declaration for one role instance (resource, Person Server,
/// Access Server). Decision order: <see cref="Policy"/>, then an
/// <see cref="IAAuthTrustPolicy"/> registered in DI, then the per-party rules.
/// </summary>
public sealed class AAuthTrustOptions
{
    internal static readonly IServiceProvider NoServices = new ServiceCollection().BuildServiceProvider();
    /// <summary>Auth-token issuers (Person Servers and Access Servers).</summary>
    public AAuthTrustRule AuthTokenIssuers { get; set; } = new();

    /// <summary>
    /// Person Servers: person-token issuers at a resource, brokered Person Servers
    /// at an Access Server. When not configured, <see cref="AuthTokenIssuers"/> applies.
    /// </summary>
    public AAuthTrustRule PersonServers { get; set; } = new();

    /// <summary>Agent Providers issuing agent tokens.</summary>
    public AAuthTrustRule AgentProviders { get; set; } = new();

    /// <summary>Access Servers a Person Server federates to.</summary>
    public AAuthTrustRule AccessServers { get; set; } = new();

    /// <summary>A policy that replaces the rules and any DI-registered policy.</summary>
    public IAAuthTrustPolicy? Policy { get; set; }

    /// <summary>The rule that governs <paramref name="party"/>.</summary>
    public AAuthTrustRule RuleFor(AAuthTrustedParty party) => party switch
    {
        AAuthTrustedParty.AuthTokenIssuer => AuthTokenIssuers,
        AAuthTrustedParty.PersonServer => PersonServers.IsConfigured ? PersonServers : AuthTokenIssuers,
        AAuthTrustedParty.AgentProvider => AgentProviders,
        AAuthTrustedParty.AccessServer => AccessServers,
        _ => throw new ArgumentOutOfRangeException(nameof(party)),
    };

    /// <summary>
    /// Whether trust for <paramref name="party"/> is stated explicitly, by a rule,
    /// <see cref="Policy"/>, or a DI-registered policy in <paramref name="services"/>.
    /// </summary>
    public bool IsConfigured(AAuthTrustedParty party, IServiceProvider? services = null)
        => Policy is not null || RuleFor(party).IsConfigured
            || services?.GetService<IServiceProviderIsService>()?.IsService(typeof(IAAuthTrustPolicy)) == true;

    /// <summary>
    /// Decide trust for <paramref name="issuer"/>. <paramref name="services"/> should
    /// be request services in a request, or a scope created for background work.
    /// </summary>
    public ValueTask<bool> IsTrustedAsync(
        string issuer,
        AAuthTrustedParty party,
        IServiceProvider services,
        HttpContext? httpContext = null,
        string? tokenType = null,
        CancellationToken cancellationToken = default)
        => IsTrustedAsync(new AAuthTrustContext(issuer, party, services)
        {
            HttpContext = httpContext,
            TokenType = tokenType,
        }, cancellationToken);

    /// <summary>Decide trust for <paramref name="context"/>.</summary>
    public ValueTask<bool> IsTrustedAsync(AAuthTrustContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        return AAuthSeams.Resolve<IAAuthTrustPolicy>(context.Services, name: null, Policy, () => new RulePolicy(this))
            .IsTrustedAsync(context, cancellationToken);
    }

    private sealed class RulePolicy(AAuthTrustOptions options) : IAAuthTrustPolicy
    {
        public ValueTask<bool> IsTrustedAsync(AAuthTrustContext context, CancellationToken cancellationToken = default)
            => options.RuleFor(context.Party).EvaluateAsync(context, cancellationToken);
    }
}
