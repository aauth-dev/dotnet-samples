using System;
using System.Collections.Generic;
using System.Linq;

namespace AAuth.Server.Verification;

/// <summary>
/// Shared trust-decision for AAuth issuer / counterparty allow-lists.
/// </summary>
/// <remarks>
/// Implements the single trust model used by every PS/AS trust-list: a static
/// allow-list AND an optional policy predicate, each of which only narrows.
/// <list type="bullet">
/// <item><description><paramref name="set"/> <c>null</c> ⇒ no set constraint;
/// any verifiable counterparty passes the set clause.</description></item>
/// <item><description><paramref name="set"/> empty ⇒ deny-all (membership test is
/// always false) — a deliberate kill-switch.</description></item>
/// <item><description><paramref name="policy"/> <c>null</c> ⇒ no policy
/// constraint.</description></item>
/// </list>
/// Both <c>null</c> ⇒ accept any verifiable counterparty (the spec default).
/// Callers MUST pass <c>null</c> (never an empty collection) when the option was
/// unset, and a normalized <paramref name="id"/> matching the set's normalization.
/// </remarks>
internal static class IssuerTrust
{
    /// <summary>
    /// Evaluate whether <paramref name="id"/> is trusted under the allow-list and
    /// policy. See the type remarks for the null/empty semantics.
    /// </summary>
    public static bool IsTrusted(IReadOnlyCollection<string>? set, Func<string, bool>? policy, string id)
        => (set is null || set.Contains(id))
        && (policy is null || policy(id));
}
