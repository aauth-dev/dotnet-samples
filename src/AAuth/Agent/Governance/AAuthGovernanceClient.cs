using System;
using System.Net.Http;
using AAuth.Discovery;

namespace AAuth.Agent.Governance;

/// <summary>
/// Bundles the PS governance clients (mission, permission, audit, interaction)
/// over a single signed <see cref="HttpClient"/> and a shared
/// <see cref="MetadataClient"/>, so callers don't have to wire each client
/// individually. Build one with <see cref="AAuthClientBuilder.BuildGovernance"/>
/// or construct it directly.
/// </summary>
/// <remarks>
/// The supplied <see cref="HttpClient"/> MUST be wired with an
/// <see cref="HttpSig.AAuthSigningHandler"/> configured with the agent token, so
/// every governance request is signed.
/// </remarks>
public sealed class AAuthGovernanceClient
{
    /// <summary>Propose and approve missions at the PS <c>mission_endpoint</c>.</summary>
    public MissionClient Mission { get; }

    /// <summary>Request permission for actions at the PS <c>permission_endpoint</c>.</summary>
    public PermissionClient Permission { get; }

    /// <summary>Record actions at the PS <c>audit_endpoint</c>.</summary>
    public AuditClient Audit { get; }

    /// <summary>Reach the user via the PS <c>interaction_endpoint</c>.</summary>
    public InteractionClient Interaction { get; }

    /// <summary>Create the facade over a signed client and metadata client.</summary>
    /// <param name="signedClient">HttpClient wired with an <see cref="HttpSig.AAuthSigningHandler"/>.</param>
    /// <param name="metadata">Metadata client for resolving the PS governance endpoints.</param>
    public AAuthGovernanceClient(HttpClient signedClient, MetadataClient metadata)
    {
        ArgumentNullException.ThrowIfNull(signedClient);
        ArgumentNullException.ThrowIfNull(metadata);
        Mission = new MissionClient(signedClient, metadata);
        Permission = new PermissionClient(signedClient, metadata);
        Audit = new AuditClient(signedClient, metadata);
        Interaction = new InteractionClient(signedClient, metadata);
    }
}
