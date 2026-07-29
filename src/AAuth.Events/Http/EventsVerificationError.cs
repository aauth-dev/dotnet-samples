using System;

namespace AAuth.Events.Http;

/// <summary>Exhaustive categories for failures while verifying an Events request.</summary>
public enum EventsVerificationErrorCode
{
    MalformedRequest,
    InvalidToken,
    ExpiredToken,
    UnsupportedAlgorithm,
    InvalidSignature,
    UnknownKey,
    MissingCoveredComponent,
    UnexpectedCoveredComponent,
    BodyTooLarge,
    InvalidContentDigest,
    ContentDigestMismatch,
    MetadataFailure,
    UrlPolicyRejected,
    WrongAudience,
    WrongResource,
}

/// <summary>A typed Events verification failure.</summary>
public sealed record EventsVerificationError(EventsVerificationErrorCode Code, string Detail)
{
    public override string ToString() => $"{Code}: {Detail}";
}

/// <summary>Exception carrying a typed Events verification failure.</summary>
public sealed class EventsVerificationException : Exception
{
    public EventsVerificationException(EventsVerificationError error)
        : base((error ?? throw new ArgumentNullException(nameof(error))).Detail)
    {
        Error = error;
    }

    public EventsVerificationException(EventsVerificationErrorCode code, string detail, Exception? inner = null)
        : base(detail, inner)
    {
        Error = new EventsVerificationError(code, detail);
    }

    /// <summary>The structured failure.</summary>
    public EventsVerificationError Error { get; }
}
