using System;
using AAuth.Agent.Governance;
using AAuth.Server.Governance;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registers the PS-side governance seams (§PS Governance Endpoints, §Mission
/// Log). The storage seams default to in-memory implementations and the
/// policy/user-channel seams (<see cref="AAuth.Server.Governance.IPermissionDecider"/>,
/// <see cref="AAuth.Server.Governance.IAuditSink"/>,
/// <see cref="AAuth.Server.Governance.IInteractionRelay"/>) default to conservative
/// no-op implementations, all via <c>TryAdd</c> so a PS overrides only what it needs.
/// </summary>
public static class AAuthGovernanceServiceCollectionExtensions
{
    /// <summary>
    /// Register the default mission storage seams —
    /// <see cref="AAuth.Server.Governance.InMemoryMissionStore"/> and
    /// <see cref="AAuth.Server.Governance.InMemoryMissionLog"/> — plus default no-op
    /// policy/user-channel seams (<see cref="AAuth.Server.Governance.DefaultPermissionDecider"/>,
    /// <see cref="AAuth.Server.Governance.DefaultAuditSink"/>,
    /// <see cref="AAuth.Server.Governance.DefaultInteractionRelay"/>) as singletons.
    /// Every seam is registered with <c>TryAdd</c> so a PS overrides only what it
    /// needs — register your own <see cref="AAuth.Server.Governance.IPermissionDecider"/>
    /// (and friends) before or after this call to take over the policy.
    /// </summary>
    public static IServiceCollection AddAAuthGovernance(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddSingleton<IMissionStore, InMemoryMissionStore>();
        services.TryAddSingleton<IMissionLog, InMemoryMissionLog>();
        services.TryAddSingleton<IMissionApprover, DefaultMissionApprover>();
        services.TryAddSingleton<IPermissionDecider, DefaultPermissionDecider>();
        services.TryAddSingleton<IAuditSink, DefaultAuditSink>();
        services.TryAddSingleton<IInteractionRelay, DefaultInteractionRelay>();
        services.TryAddSingleton<IMissionTokenConsent, DefaultMissionTokenConsent>();
        return services;
    }

    /// <summary>
    /// Register an <see cref="AAuth.Server.Governance.IInteractionRelay"/> backed by a
    /// delegate, so a PS can supply its user channel with a lambda instead of a full
    /// class (§Interaction Endpoint). Replaces any relay registered earlier (including
    /// the no-op <see cref="AAuth.Server.Governance.DefaultInteractionRelay"/>).
    /// </summary>
    public static IServiceCollection AddAAuthInteractionRelay(
        this IServiceCollection services,
        Func<InteractionRequest, CancellationToken, Task<InteractionRelayResult>> relay)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(relay);
        services.RemoveAll<IInteractionRelay>();
        services.AddSingleton<IInteractionRelay>(new DelegateInteractionRelay(relay));
        return services;
    }

    /// <summary>
    /// Opt the governance mapper into the deferred-consent (<c>202</c> poll) flow
    /// for <see cref="AAuth.Server.Governance.PermissionOutcome.Prompt"/> /
    /// <see cref="AAuth.Server.Governance.MissionApprovalOutcome.Prompt"/> outcomes
    /// (§Deferred Consent). Registers the default in-memory
    /// <see cref="AAuth.Server.Governance.IDeferredConsentStore"/> via <c>TryAdd</c>.
    /// Without this call a <c>Prompt</c> outcome is resolved synchronously (a
    /// permission denial / a mission decline), since the mapper has no user channel.
    /// The PS still owns the browser consent page that resolves parked entries.
    /// </summary>
    public static IServiceCollection AddAAuthDeferredConsent(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddSingleton<IDeferredConsentStore, InMemoryDeferredConsentStore>();
        return services;
    }
}
