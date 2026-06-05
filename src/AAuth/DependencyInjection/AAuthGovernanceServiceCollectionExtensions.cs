using System;
using AAuth.Server.Governance;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registers the PS-side governance seams (§PS Governance Endpoints, §Mission
/// Log). The storage seams default to in-memory implementations; the
/// policy/user-channel seams (<see cref="AAuth.Server.Governance.IPermissionDecider"/>,
/// <see cref="AAuth.Server.Governance.IAuditSink"/>,
/// <see cref="AAuth.Server.Governance.IInteractionRelay"/>) are supplied by the PS.
/// </summary>
public static class AAuthGovernanceServiceCollectionExtensions
{
    /// <summary>
    /// Register the default mission storage seams —
    /// <see cref="AAuth.Server.Governance.InMemoryMissionStore"/> and
    /// <see cref="AAuth.Server.Governance.InMemoryMissionLog"/> — as singletons.
    /// Uses <c>TryAdd</c> so a PS can register durable implementations first.
    /// </summary>
    public static IServiceCollection AddAAuthGovernance(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddSingleton<IMissionStore, InMemoryMissionStore>();
        services.TryAddSingleton<IMissionLog, InMemoryMissionLog>();
        return services;
    }
}
