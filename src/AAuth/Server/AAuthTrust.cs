using System;

namespace AAuth.Server;

/// <summary>
/// Well-known trust predicates for <see cref="AAuthTrustRule.Predicate"/>.
/// </summary>
/// <remarks>
/// With no rule, policy or DI-registered <see cref="IAAuthTrustPolicy"/>, a
/// counterparty is trusted as long as it is cryptographically verifiable: the AAuth
/// spec default (PS-asserted access accepts any verifiable Person Server,
/// namespaced by issuer).
/// <para>
/// <see cref="Any"/> is the explicit "I intend to trust any verifiable
/// counterparty" marker. It behaves like leaving the rule unset, but it states
/// intent in code (and is greppable for audit), and it suppresses the startup
/// warning that fires when an auth-token pipeline has no trust configured.
/// </para>
/// </remarks>
public static class AAuthTrust
{
    /// <summary>
    /// A trust predicate that accepts every issuer, e.g.
    /// <c>o.Trust.AuthTokenIssuers.Predicate = AAuthTrust.Any;</c>.
    /// </summary>
    public static readonly Func<string, bool> Any = _ => true;
}
