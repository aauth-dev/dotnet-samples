using System;
using AAuth.Server.Governance;
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
        services.TryAddSingleton<IPermissionDecider, DefaultPermissionDecider>();
        services.TryAddSingleton<IAuditSink, DefaultAuditSink>();
        services.TryAddSingleton<IInteractionRelay, DefaultInteractionRelay>();
        return services;
    }
}
