using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Discovery;

namespace AAuth.Agent.Governance;

/// <summary>
/// Bundles the PS governance clients (mission, permission, audit, interaction)
/// over a single signed <see cref="HttpClient"/> and a shared
/// <see cref="MetadataClient"/>, so callers don't have to wire each client
/// individually. Build one with <see cref="AAuthClientBuilder.BuildGovernance()"/>,
/// the <see cref="Create"/> factory, or construct it directly.
/// </summary>
/// <remarks>
/// The supplied <see cref="HttpClient"/> MUST be wired with an
/// <see cref="HttpSig.AAuthSigningHandler"/> configured with the agent token, so
/// every governance request is signed.
/// <para>
/// The client is always bound to a Person Server (via
/// <see cref="AAuthClientBuilder.WithPersonServer"/>, the <see cref="Create"/>
/// factory, or the constructor), so individual calls never re-supply it.
/// <see cref="ProposeMissionAsync"/> returns a <see cref="MissionSession"/> that
/// auto-threads the mission claim and PS into every subsequent call.
/// </para>
/// </remarks>
public sealed class AAuthGovernanceClient
{
    private readonly string _personServer;
    private readonly GovernanceOptions? _defaultOptions;

    /// <summary>Propose and approve missions at the PS <c>mission_endpoint</c>.</summary>
    public MissionClient Mission { get; }

    /// <summary>Request permission for actions at the PS <c>permission_endpoint</c>.</summary>
    public PermissionClient Permission { get; }

    /// <summary>Record actions at the PS <c>audit_endpoint</c>.</summary>
    public AuditClient Audit { get; }

    /// <summary>Reach the user via the PS <c>interaction_endpoint</c>.</summary>
    public InteractionClient Interaction { get; }

    /// <summary>
    /// The Person Server this client is bound to. Every governed call targets it,
    /// and <see cref="ProposeMissionAsync"/> returns a <see cref="MissionSession"/>
    /// that auto-threads the mission claim and PS into subsequent calls.
    /// </summary>
    public string PersonServer => _personServer;

    /// <summary>
    /// Create the facade bound to a Person Server with default governance options.
    /// </summary>
    /// <param name="signedClient">HttpClient wired with an <see cref="HttpSig.AAuthSigningHandler"/>.</param>
    /// <param name="metadata">Metadata client for resolving the PS governance endpoints.</param>
    /// <param name="personServer">The PS URL this client targets. REQUIRED.</param>
    /// <param name="defaultOptions">Default deferred-handling options applied when a call omits its own.</param>
    public AAuthGovernanceClient(
        HttpClient signedClient,
        MetadataClient metadata,
        string personServer,
        GovernanceOptions? defaultOptions = null)
    {
        ArgumentNullException.ThrowIfNull(signedClient);
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentException.ThrowIfNullOrEmpty(personServer);
        _personServer = personServer;
        _defaultOptions = defaultOptions;
        Mission = new MissionClient(signedClient, metadata, personServer);
        Permission = new PermissionClient(signedClient, metadata, personServer);
        Audit = new AuditClient(signedClient, metadata, personServer);
        Interaction = new InteractionClient(signedClient, metadata, personServer);
    }

    /// <summary>
    /// Static factory mirroring the SDK's other <c>Create</c>/<c>Build</c> entry
    /// points. Equivalent to the constructor.
    /// </summary>
    /// <param name="signedClient">HttpClient wired with an <see cref="HttpSig.AAuthSigningHandler"/>.</param>
    /// <param name="metadata">Metadata client for resolving the PS governance endpoints.</param>
    /// <param name="personServer">The PS URL this client targets. REQUIRED.</param>
    /// <param name="defaultOptions">Default deferred-handling options applied when a call omits its own.</param>
    public static AAuthGovernanceClient Create(
        HttpClient signedClient,
        MetadataClient metadata,
        string personServer,
        GovernanceOptions? defaultOptions = null)
        => new(signedClient, metadata, personServer, defaultOptions);

    /// <summary>
    /// Propose a mission to the bound Person Server (§Mission Creation,
    /// §Mission Approval) and return a <see cref="MissionSession"/> that
    /// auto-threads the mission claim and PS into subsequent governed calls.
    /// </summary>
    public async Task<MissionSession> ProposeMissionAsync(
        MissionProposal proposal,
        GovernanceOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(proposal);
        var mission = await Mission.ProposeAsync(
            proposal, options ?? _defaultOptions, cancellationToken).ConfigureAwait(false);
        return new MissionSession(this, _personServer, mission, _defaultOptions);
    }
}
