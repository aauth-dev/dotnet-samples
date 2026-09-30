using AAuth.Person;
using Microsoft.Extensions.DependencyInjection;

namespace MockPersonServer;

public enum ConsentOutcome
{
    Applied,
    AlreadyDecided,
    Expired,
    Unknown,
    NotDecidable,
    Refused,
}

/// <summary>
/// The one place a PS consent decision mutates state (Q15). The per-request link
/// (<c>/interaction/approve|deny</c>) and the dashboard both decide through it.
/// </summary>
public sealed class PersonConsentDecisions(ConsentStore consent,
    [FromKeyedServices(AAuthPersonServerBuilder.DefaultName)] IIdentityClaimsAsserter asserter, ConsentRegistry registry)
{
    /// <summary>Decide a mission-governance request. The caller holds the entry's lifecycle gate.</summary>
    public ConsentOutcome ApplyHeld(MissionPendingEntry entry, bool approve, ConsentDecider by)
    {
        if (entry.Decision is not null) return ConsentOutcome.AlreadyDecided;
        entry.Decision = approve;
        registry.MarkDecided(entry.Id, by);
        return ConsentOutcome.Applied;
    }

    /// <summary>Decide a PS token request. The caller holds the entry's lifecycle gate.</summary>
    public async Task<ConsentOutcome> ApplyHeldAsync(PersonPendingEntry entry, bool approve, ConsentDecider by,
        CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        if (!approve)
        {
            if (entry.AwaitingResourceInteraction
                || entry.Status is PersonPendingStatus.Allowed or PersonPendingStatus.Denied or PersonPendingStatus.Withdrawn
                || entry.PendingExpiresAt <= now)
                return ConsentOutcome.AlreadyDecided;
            entry.Status = PersonPendingStatus.Denied;
            entry.DenyReason = "the user denied this request";
            entry.FederationConsent?.TrySetResult(IdentityAssertion.Deny(entry.DenyReason));
            registry.MarkDecided(entry.Id, by);
            return ConsentOutcome.Applied;
        }

        if (entry.AwaitingResourceInteraction || entry.Status != PersonPendingStatus.Pending || entry.PendingExpiresAt <= now)
            return ConsentOutcome.AlreadyDecided;
        // An out-of-scope mission token request resolves by marking the SDK-owned
        // pending decision allowed; a plain three-party request records standing consent.
        if (!entry.MissionGate)
            consent.Grant(entry.ConsentAgentId, entry.ResourceUrl, entry.Scope, entry.Account, entry.ResourceKeyThumbprint);
        var asserted = await asserter.AssertAsync(new IdentityAssertionRequest
        {
            ResourceUrl = entry.ResourceUrl, Scope = entry.Scope, AgentId = entry.ConsentAgentId,
            Account = entry.Account, AgentKeyThumbprint = entry.ResourceKeyThumbprint,
            MissionS256 = entry.MissionS256, RequiredClaims = entry.RequiredIdentityClaims,
            ResourceContext = entry.ResourceContext, AgentAsserted = entry.AgentAsserted, InteractionId = entry.Id,
        }, cancellationToken);
        if (asserted.Kind != IdentityAssertionKind.Assert) return ConsentOutcome.Refused;
        cancellationToken.ThrowIfCancellationRequested();
        entry.Subject = asserted.Subject!;
        entry.Tenant = asserted.Tenant;
        entry.Roles = asserted.Roles;
        entry.Groups = asserted.Groups;
        entry.AdditionalClaims = asserted.AdditionalClaims;
        if (entry.FederationConsent is { } consentCompletion) consentCompletion.TrySetResult(asserted);
        else entry.Status = PersonPendingStatus.Allowed;
        registry.MarkDecided(entry.Id, by);
        return ConsentOutcome.Applied;
    }

    /// <summary>
    /// Decide a request out-of-band (the dashboard). Takes the entry's lifecycle
    /// gate, so a concurrent link decision resolves exactly once, and consumes the
    /// interaction code on success (#interaction-code-format).
    /// </summary>
    public async Task<ConsentOutcome> DecideAsync(string id, bool approve, ConsentDecider by, CancellationToken cancellationToken)
    {
        if (registry.Find(id) is not { } record) return ConsentOutcome.Unknown;
        await record.Lifecycle.Gate.WaitAsync(cancellationToken);
        try
        {
            if (!record.IsDecidable)
                return record.Status switch
                {
                    ConsentStatus.Expired => ConsentOutcome.Expired,
                    ConsentStatus.Pending => ConsentOutcome.NotDecidable,
                    _ => ConsentOutcome.AlreadyDecided,
                };
            var outcome = record.PersonEntry is { } person
                ? await ApplyHeldAsync(person, approve, by, cancellationToken)
                : ApplyHeld(record.MissionEntry!, approve, by);
            if (outcome == ConsentOutcome.Applied) record.Browser.Consume();
            return outcome;
        }
        finally { record.Lifecycle.Gate.Release(); }
    }
}
