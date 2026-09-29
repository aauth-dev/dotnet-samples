using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Agent;
using AAuth.Agent.Governance;

namespace AAuth.Server.Governance;

/// <summary>The governance decision a deferred consent resolves (§Deferred Consent).</summary>
public enum DeferredConsentKind
{
    /// <summary>A mission proposal awaiting the user's approval (§Mission Creation).</summary>
    MissionCreation,

    /// <summary>A permission request awaiting the user's decision (§Permission Endpoint).</summary>
    Permission,

    /// <summary>
    /// An <c>interaction</c> / <c>payment</c> relay awaiting the user's completion
    /// (§Interaction Response). The PS relays it to the user and the agent polls
    /// until the user completes the interaction.
    /// </summary>
    Interaction,

    /// <summary>
    /// A <c>completion</c> summary the user is reviewing (§Interaction Response:
    /// "The PS returns a deferred response while the user reviews."). The agent
    /// polls until the user accepts (the PS terminates the mission) or responds
    /// with follow-up questions (the mission stays active).
    /// </summary>
    Completion,
}

/// <summary>
/// A governance decision parked for the user (§Deferred Consent). When the PS
/// cannot decide synchronously, <c>MapAAuthGovernance</c> parks the request here,
/// answers <c>202 Accepted</c> with a poll <c>Location</c>, and resolves the
/// parked entry once the user decides (typically from the PS's browser consent
/// page, which calls <see cref="IDeferredConsentStore.ResolveAsync"/>).
/// </summary>
public sealed class DeferredConsent
{
    /// <summary>The opaque pending id (assigned by the store on park).</summary>
    public string Id { get; set; } = string.Empty;
    public string Code { get; } = AAuth.Headers.InteractionCode.Generate(26);
    public DateTimeOffset ExpiresAt { get; init; } = DateTimeOffset.UtcNow.AddMinutes(10);

    /// <summary>Which governance decision this entry resolves.</summary>
    public required DeferredConsentKind Kind { get; init; }

    /// <summary>The agent the request was made by.</summary>
    public string Agent { get; init; } = string.Empty;
    public string? OwnerIssuer { get; init; }
    public string? OwnerKeyThumbprint { get; init; }
    public DeferredState Lifecycle { get; } = new();

    /// <summary>HTTPS identifier of the PS that approves the mission.</summary>
    public string PersonServer { get; init; } = string.Empty;

    /// <summary>The proposal (set when <see cref="Kind"/> is <see cref="DeferredConsentKind.MissionCreation"/>).</summary>
    public MissionProposal? Proposal { get; init; }

    /// <summary>The approver's mission <c>expires_at</c>, applied when the user approves a parked proposal.</summary>
    public DateTimeOffset? MissionExpiresAt { get; init; }

    /// <summary>The permission request (set when <see cref="Kind"/> is <see cref="DeferredConsentKind.Permission"/>).</summary>
    public PermissionRequest? Permission { get; init; }

    /// <summary>The interaction request (set when <see cref="Kind"/> is <see cref="DeferredConsentKind.Interaction"/>).</summary>
    public InteractionRequest? Interaction { get; init; }

    /// <summary>
    /// The user's decision: <see langword="null"/> while pending,
    /// <see langword="true"/> on approval, <see langword="false"/> on decline.
    /// </summary>
    public bool? Decision { get; set; }
}

/// <summary>
/// PS-side persistence seam for deferred (user-driven) governance consents
/// (§Deferred Consent). The SDK supplies the contract and an in-memory default
/// (<see cref="InMemoryDeferredConsentStore"/>); a production PS swaps in durable
/// storage. Registering this seam (via <c>AddAAuthDeferredConsent</c>) opts the
/// governance mapper into the <c>202</c> poll flow for <c>Prompt</c> outcomes.
/// </summary>
public interface IDeferredConsentStore
{
    /// <summary>Park a pending consent, assigning and returning its <see cref="DeferredConsent.Id"/>.</summary>
    Task<DeferredConsent> ParkAsync(DeferredConsent consent, CancellationToken ct = default);

    /// <summary>Look up a parked consent by id. Returns <see langword="null"/> when absent.</summary>
    Task<DeferredConsent?> GetAsync(string id, CancellationToken ct = default);
    Task<DeferredConsent?> GetByCodeAsync(string code, CancellationToken ct = default);

    /// <summary>Record the user's decision on a parked consent. No-op when absent.</summary>
    Task ResolveAsync(string id, bool approved, CancellationToken ct = default);

    /// <summary>Remove a parked consent (after it has been resolved and consumed).</summary>
    Task RemoveAsync(string id, CancellationToken ct = default);
}
