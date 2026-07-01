using System;

namespace AAuth.Server;

/// <summary>
/// Well-known trust-policy delegates for AAuth verification options.
/// </summary>
/// <remarks>
/// Trust on every AAuth server options object is expressed as an optional static
/// allow-list <em>and</em> an optional <see cref="Func{T, TResult}"/> policy
/// predicate, composed by AND (each only narrows). When both are unset the
/// counterparty is accepted as long as it is cryptographically verifiable — the
/// AAuth spec default (PS-asserted access accepts any verifiable Person Server,
/// namespaced by issuer).
/// <para>
/// <see cref="Any"/> is the explicit "I intend to trust any verifiable
/// counterparty" marker. Assigning it is behaviourally identical to leaving the
/// policy <c>null</c>, but it states intent in code (and is greppable for audit),
/// and it suppresses the startup warning that fires when an auth-token pipeline
/// has no trust policy configured.
/// </para>
/// </remarks>
public static class AAuthTrust
{
    /// <summary>
    /// A trust predicate that accepts every issuer. Use as an explicit,
    /// auditable "trust any verifiable counterparty" marker, e.g.
    /// <c>o.IsTrustedAuthTokenIssuer = AAuthTrust.Any;</c>.
    /// </summary>
    public static readonly Func<string, bool> Any = _ => true;
}
