using System;
using System.Net;
using System.Threading.Tasks;
using AAuth.Person;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace AAuth.Conformance.Person;

/// <summary>
/// Conformance for the §PS Approval Endpoint Authentication guard: a non-loopback
/// approval/consent decision MUST be authenticated; a loopback-only deployment is
/// exempt; default-deny applies when no authenticator is supplied.
/// </summary>
public class PsApprovalGuardTests
{
    private static HttpContext ContextFrom(IPAddress? remote, IPAddress? local = null)
    {
        var ctx = new DefaultHttpContext();
        ctx.Connection.RemoteIpAddress = remote;
        ctx.Connection.LocalIpAddress = local;
        return ctx;
    }

    [Fact(DisplayName = "§PS Approval Endpoint Authentication — loopback is exempt (bypass)")]
    public async Task Loopback_IsExempt()
    {
        var ctx = ContextFrom(IPAddress.Loopback);

        // No authenticator supplied: loopback still passes.
        Assert.True(await PsApprovalGuard.IsAuthorizedAsync(ctx, authenticator: null));
        Assert.True(PsApprovalGuard.IsLoopback(ctx));
    }

    [Fact(DisplayName = "§PS Approval Endpoint Authentication — IPv6 loopback is exempt")]
    public async Task IPv6Loopback_IsExempt()
    {
        var ctx = ContextFrom(IPAddress.IPv6Loopback);
        Assert.True(await PsApprovalGuard.IsAuthorizedAsync(ctx, authenticator: null));
    }

    [Fact(DisplayName = "§PS Approval Endpoint Authentication — externally reachable + no authenticator is denied")]
    public async Task ExternalNoAuthenticator_DefaultDeny()
    {
        var ctx = ContextFrom(IPAddress.Parse("203.0.113.7"));

        Assert.False(PsApprovalGuard.IsLoopback(ctx));
        Assert.False(await PsApprovalGuard.IsAuthorizedAsync(ctx, authenticator: null));
    }

    [Fact(DisplayName = "§PS Approval Endpoint Authentication — externally reachable defers to the app authenticator")]
    public async Task External_ConsultsAuthenticator()
    {
        var ctx = ContextFrom(IPAddress.Parse("203.0.113.7"));

        Assert.True(await PsApprovalGuard.IsAuthorizedAsync(ctx, _ => ValueTask.FromResult(true)));
        Assert.False(await PsApprovalGuard.IsAuthorizedAsync(ctx, _ => ValueTask.FromResult(false)));
    }

    [Fact(DisplayName = "§PS Approval Endpoint Authentication — no remote IP is treated as not-loopback (fails closed)")]
    public async Task NoRemoteIp_IsNotLoopback()
    {
        var ctx = ContextFrom(remote: null);

        Assert.False(PsApprovalGuard.IsLoopback(ctx));
        Assert.False(await PsApprovalGuard.IsAuthorizedAsync(ctx, authenticator: null));
    }
}
