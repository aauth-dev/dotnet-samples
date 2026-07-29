using System;
using AAuth.Events.Tokens;
using AAuth.Tokens;

namespace AAuth.Events.Agent;

/// <summary>
/// An event token verified against its resource and local agent context.
/// </summary>
/// <remarks>
/// <see cref="Payload"/> is not authenticated by this envelope. It is exposed
/// separately as <see cref="UnauthenticatedEventPayload"/> and may be used
/// only for display or relevance decisions.
/// </remarks>
public sealed record VerifiedAgentEvent
{
    /// <summary>Creates a verified agent event.</summary>
    public VerifiedAgentEvent(
        EventTokenClaims claims,
        string compactToken,
        string idempotencyKey,
        object context,
        UnauthenticatedEventPayload? payload = null,
        TokenVerifier.VerifiedToken? verifiedToken = null)
    {
        Claims = claims ?? throw new ArgumentNullException(nameof(claims));
        CompactToken = !string.IsNullOrEmpty(compactToken)
            ? compactToken
            : throw new ArgumentException("Token must not be empty.", nameof(compactToken));
        IdempotencyKey = !string.IsNullOrEmpty(idempotencyKey)
            ? idempotencyKey
            : throw new ArgumentException("Idempotency key must not be empty.", nameof(idempotencyKey));
        Context = context ?? throw new ArgumentNullException(nameof(context));
        Payload = payload;
        VerifiedToken = verifiedToken;
    }

    /// <summary>Verified typed event claims.</summary>
    public EventTokenClaims Claims { get; }

    /// <summary>The exact compact token whose signature was verified.</summary>
    public string CompactToken { get; }

    /// <summary>Alias for <see cref="CompactToken"/>.</summary>
    public string Token => CompactToken;

    /// <summary>The core verified token projection, retained for advanced policy code.</summary>
    public TokenVerifier.VerifiedToken? VerifiedToken { get; }

    /// <summary>SHA-256 idempotency key for the exact compact token.</summary>
    public string IdempotencyKey { get; }

    /// <summary>Application-owned context associated with the local <c>eid</c>.</summary>
    public object Context { get; }

    /// <summary>Optional payload, explicitly not authenticated by the event token.</summary>
    public UnauthenticatedEventPayload? Payload { get; }
}

/// <summary>Outcome of agent event verification and local policy checks.</summary>
public enum AgentEventVerificationStatus
{
    /// <summary>The token, context, and deduplication check all succeeded.</summary>
    Verified,
    /// <summary>The token was valid but no local context exists for its <c>eid</c>.</summary>
    UnknownContext,
    /// <summary>The exact compact token was already recorded.</summary>
    Duplicate,
}

/// <summary>Typed, non-throwing outcome for context and replay decisions.</summary>
public sealed record AgentEventVerificationResult
{
    internal AgentEventVerificationResult(
        AgentEventVerificationStatus status,
        EventTokenClaims claims,
        string compactToken,
        string idempotencyKey,
        VerifiedAgentEvent? @event,
        string? detail)
    {
        Status = status;
        Claims = claims;
        CompactToken = compactToken;
        IdempotencyKey = idempotencyKey;
        Event = @event;
        Detail = detail;
    }

    /// <summary>Verification outcome.</summary>
    public AgentEventVerificationStatus Status { get; }
    /// <summary>Verified claims, including for a non-actionable unknown context.</summary>
    public EventTokenClaims Claims { get; }
    /// <summary>The exact compact token.</summary>
    public string CompactToken { get; }
    /// <summary>SHA-256 key derived from <see cref="CompactToken"/> bytes.</summary>
    public string IdempotencyKey { get; }
    /// <summary>Actionable event, present only when <see cref="Status"/> is Verified.</summary>
    public VerifiedAgentEvent? Event { get; }
    /// <summary>Optional human-readable non-actionable detail.</summary>
    public string? Detail { get; }
    /// <summary>Whether callers may act on <see cref="Event"/>.</summary>
    public bool IsActionable => Status == AgentEventVerificationStatus.Verified && Event is not null;
}
