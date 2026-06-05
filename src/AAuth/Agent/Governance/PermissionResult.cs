using System;
using System.Text.Json.Nodes;

namespace AAuth.Agent.Governance;

/// <summary>The PS's decision on a permission request (§Permission Response).</summary>
public enum PermissionGrant
{
    /// <summary>The agent MAY proceed with the action.</summary>
    Granted,

    /// <summary>The agent MUST NOT proceed.</summary>
    Denied,
}

/// <summary>
/// The result of a permission request (§Permission Response). When
/// <see cref="Grant"/> is <see cref="PermissionGrant.Denied"/> the
/// <see cref="Reason"/> MAY carry a Markdown explanation.
/// </summary>
/// <param name="Grant">Whether the action is granted or denied.</param>
/// <param name="Reason">Optional Markdown reason (typically present on denial).</param>
public sealed record PermissionResult(PermissionGrant Grant, string? Reason = null)
{
    /// <summary>Whether the action was granted.</summary>
    public bool IsGranted => Grant == PermissionGrant.Granted;

    /// <summary>Parse a <c>{permission, reason?}</c> response body.</summary>
    internal static PermissionResult FromJson(JsonObject body)
    {
        ArgumentNullException.ThrowIfNull(body);
        var permission = (string?)body["permission"];
        var grant = permission switch
        {
            "granted" => PermissionGrant.Granted,
            "denied" => PermissionGrant.Denied,
            _ => throw new InvalidOperationException(
                $"Permission response has an unexpected 'permission' value: {permission ?? "(null)"}"),
        };
        return new PermissionResult(grant, (string?)body["reason"]);
    }
}
