using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AAuth.Events.Http;
using AAuth.Events.Tokens;
using AAuth.Tokens;

namespace AAuth.Events.Agent;

/// <summary>Application-owned lookup of the agent's local event contexts.</summary>
public interface IEventContextLookup
{
    /// <summary>
    /// Looks up a local context by subscription <c>eid</c>.
    /// </summary>
    ValueTask<EventContextLookupResult> FindAsync(
        string eid,
        CancellationToken cancellationToken = default);
}

/// <summary>Result of an application-owned local event-context lookup.</summary>
public sealed record EventContextLookupResult(bool Found, object? Context)
{
    /// <summary>Creates an unknown-context result.</summary>
    public static EventContextLookupResult Unknown { get; } = new(false, null);

    /// <summary>Creates a known-context result.</summary>
    public static EventContextLookupResult Known(object context) =>
        new(true, context ?? throw new ArgumentNullException(nameof(context)));
}

/// <summary>Adapter for application delegates used as event-context lookups.</summary>
public sealed class DelegateEventContextLookup : IEventContextLookup
{
    private readonly Func<string, CancellationToken, ValueTask<object?>> _lookup;

    /// <summary>Creates an adapter around an asynchronous lookup delegate.</summary>
    public DelegateEventContextLookup(
        Func<string, CancellationToken, ValueTask<object?>> lookup)
    {
        _lookup = lookup ?? throw new ArgumentNullException(nameof(lookup));
    }

    /// <summary>Creates an adapter around a synchronous lookup delegate.</summary>
    public DelegateEventContextLookup(Func<string, object?> lookup)
        : this((eid, _) => ValueTask.FromResult(lookup(eid)))
    {
        ArgumentNullException.ThrowIfNull(lookup);
    }

    /// <inheritdoc />
    public async ValueTask<EventContextLookupResult> FindAsync(
        string eid,
        CancellationToken cancellationToken = default)
    {
        var context = await _lookup(eid, cancellationToken).ConfigureAwait(false);
        return context is null ? EventContextLookupResult.Unknown : EventContextLookupResult.Known(context);
    }
}

/// <summary>
/// Verifies resource-issued event tokens for one agent without defining an
/// AP-to-agent transport.
/// </summary>
/// <remarks>
/// The resolver authenticates the resource issuer key, Events type and dwk,
/// audience, and temporal claims. This class then checks application-owned
/// local context and atomically applies replay deduplication. It does not
/// authenticate, parse, or validate an event payload schema.
/// </remarks>
public sealed class EventTokenVerifier
{
    private readonly EventsJwtKeyResolver _keyResolver;
    private readonly string _expectedAudience;
    private readonly IEventContextLookup _contextLookup;
    private readonly IEventDeduplicator _deduplicator;

    /// <summary>Creates an event verifier with application-owned context lookup.</summary>
    public EventTokenVerifier(
        EventsJwtKeyResolver keyResolver,
        string expectedAudience,
        IEventContextLookup contextLookup,
        IEventDeduplicator? deduplicator = null)
    {
        _keyResolver = keyResolver ?? throw new ArgumentNullException(nameof(keyResolver));
        _expectedAudience = !string.IsNullOrWhiteSpace(expectedAudience)
            ? expectedAudience
            : throw new ArgumentException("Expected audience must not be empty.", nameof(expectedAudience));
        _contextLookup = contextLookup ?? throw new ArgumentNullException(nameof(contextLookup));
        _deduplicator = deduplicator ?? new InMemoryEventDeduplicator();
    }

    /// <summary>Creates an event verifier from an asynchronous context delegate.</summary>
    public EventTokenVerifier(
        EventsJwtKeyResolver keyResolver,
        string expectedAudience,
        Func<string, CancellationToken, ValueTask<object?>> contextLookup,
        IEventDeduplicator? deduplicator = null)
        : this(
            keyResolver,
            expectedAudience,
            new DelegateEventContextLookup(contextLookup),
            deduplicator)
    {
    }

    /// <summary>Creates an event verifier from a synchronous context delegate.</summary>
    public EventTokenVerifier(
        EventsJwtKeyResolver keyResolver,
        string expectedAudience,
        Func<string, object?> contextLookup,
        IEventDeduplicator? deduplicator = null)
        : this(
            keyResolver,
            expectedAudience,
            new DelegateEventContextLookup(contextLookup),
            deduplicator)
    {
    }

    /// <summary>Verifies an event token and applies context and replay policy.</summary>
    /// <returns>
    /// A typed non-actionable result for unknown contexts or exact replays.
    /// Cryptographic and token-policy failures throw
    /// <see cref="EventsVerificationException"/>.
    /// </returns>
    public async Task<AgentEventVerificationResult> VerifyAsync(
        string compactToken,
        UnauthenticatedEventPayload? payload = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var resolution = await _keyResolver.ResolveEventAsync(
            compactToken,
            _expectedAudience,
            cancellationToken).ConfigureAwait(false);
        EventTokenClaims claims;
        try
        {
            claims = EventTokenClaims.Read(resolution.VerifiedToken);
        }
        catch (TokenVerificationException ex)
        {
            throw new EventsVerificationException(
                EventsVerificationErrorCode.InvalidToken,
                ex.Message,
                ex);
        }

        var idempotencyKey = ComputeIdempotencyKey(compactToken);
        var contextResult = await _contextLookup.FindAsync(
            claims.Eid,
            cancellationToken).ConfigureAwait(false);
        if (!contextResult.Found || contextResult.Context is null)
        {
            return new AgentEventVerificationResult(
                AgentEventVerificationStatus.UnknownContext,
                claims,
                compactToken,
                idempotencyKey,
                @event: null,
                "No local context exists for the event eid.");
        }

        if (!await _deduplicator.TryRecordAsync(idempotencyKey, cancellationToken)
                .ConfigureAwait(false))
        {
            return new AgentEventVerificationResult(
                AgentEventVerificationStatus.Duplicate,
                claims,
                compactToken,
                idempotencyKey,
                @event: null,
                "The exact compact event token was already recorded.");
        }

        var verifiedEvent = new VerifiedAgentEvent(
            claims,
            compactToken,
            idempotencyKey,
            contextResult.Context,
            payload,
            resolution.VerifiedToken);
        return new AgentEventVerificationResult(
            AgentEventVerificationStatus.Verified,
            claims,
            compactToken,
            idempotencyKey,
            verifiedEvent,
            detail: null);
    }

    /// <summary>Alias for <see cref="VerifyAsync"/>.</summary>
    public Task<AgentEventVerificationResult> TryVerifyAsync(
        string compactToken,
        UnauthenticatedEventPayload? payload = null,
        CancellationToken cancellationToken = default) =>
        VerifyAsync(compactToken, payload, cancellationToken);

    /// <summary>
    /// Computes the default key from the exact compact-token UTF-8 bytes.
    /// </summary>
    public static string ComputeIdempotencyKey(string compactToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(compactToken);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(compactToken)));
    }
}
