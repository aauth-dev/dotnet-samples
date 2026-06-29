using System;
using System.Collections.Generic;
using AAuth.Server;
using AAuth.Server.Verification;
using Xunit;

namespace AAuth.Tests.Server;

/// <summary>
/// Unit coverage for the shared trust-decision used by every PS/AS allow-list
/// (<see cref="IssuerTrust.IsTrusted"/>) and the <see cref="AAuthTrust.Any"/>
/// sentinel: <c>null</c> set ⇒ open, empty set ⇒ deny-all, predicate AND-composes.
/// </summary>
public class IssuerTrustTests
{
    private const string Id = "https://ps.example";

    [Fact(DisplayName = "open by default: null set + null policy accepts any id")]
    public void NullSet_NullPolicy_IsOpen()
        => Assert.True(IssuerTrust.IsTrusted(set: null, policy: null, Id));

    [Fact(DisplayName = "empty set denies all (kill-switch), even with no policy")]
    public void EmptySet_DeniesAll()
        => Assert.False(IssuerTrust.IsTrusted(new HashSet<string>(), policy: null, Id));

    [Fact(DisplayName = "non-empty set: member accepted, non-member rejected")]
    public void Set_MembershipDecides()
    {
        var set = new HashSet<string> { Id };
        Assert.True(IssuerTrust.IsTrusted(set, policy: null, Id));
        Assert.False(IssuerTrust.IsTrusted(set, policy: null, "https://other.example"));
    }

    [Fact(DisplayName = "policy alone decides when set is null")]
    public void Policy_DecidesWhenSetNull()
    {
        Assert.True(IssuerTrust.IsTrusted(set: null, id => id == Id, Id));
        Assert.False(IssuerTrust.IsTrusted(set: null, id => id == Id, "https://other.example"));
    }

    [Fact(DisplayName = "set AND policy: both must pass (each only narrows)")]
    public void Set_And_Policy_Compose_With_And()
    {
        var set = new HashSet<string> { Id };
        Assert.True(IssuerTrust.IsTrusted(set, _ => true, Id));
        Assert.False(IssuerTrust.IsTrusted(set, _ => false, Id));          // policy narrows
        Assert.False(IssuerTrust.IsTrusted(set, _ => true, "https://x.example")); // set narrows
    }

    [Fact(DisplayName = "AAuthTrust.Any accepts every issuer and suppresses no narrowing")]
    public void Any_AcceptsEverything()
    {
        Assert.True(AAuthTrust.Any("https://anything.example"));
        Assert.True(IssuerTrust.IsTrusted(set: null, AAuthTrust.Any, "https://anything.example"));
    }
}
