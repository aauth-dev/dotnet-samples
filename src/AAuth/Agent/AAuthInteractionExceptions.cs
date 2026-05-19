using System;

namespace AAuth.Agent;

/// <summary>
/// Thrown when a deferred AAuth interaction terminates with explicit
/// user denial. Surfaced when the PS responds to a pending-URL poll
/// with <c>403</c> and a body containing <c>error: "access_denied"</c>.
/// </summary>
/// <remarks>
/// Distinct from a generic <see cref="System.Net.Http.HttpRequestException"/>
/// so callers (UIs, retry policies, tests) can react to denial without
/// having to inspect status codes. A bare <c>404</c> on the pending URL
/// is treated as "unknown / expired" — a different failure mode and
/// still surfaces as <see cref="System.Net.Http.HttpRequestException"/>.
/// </remarks>
public sealed class AAuthInteractionDeniedException : Exception
{
    public AAuthInteractionDeniedException(string message)
        : base(message) { }

    public AAuthInteractionDeniedException(string message, Exception innerException)
        : base(message, innerException) { }
}

/// <summary>
/// Thrown when a deferred AAuth interaction exhausts its polling budget
/// without ever resolving to a terminal response — the user neither
/// approved nor denied within the time window.
/// </summary>
/// <remarks>
/// Wraps the underlying <see cref="TimeoutException"/> from
/// <see cref="DeferredPoller"/> so callers can distinguish "user walked
/// away" from "user explicitly denied" (<see cref="AAuthInteractionDeniedException"/>)
/// and from transport errors.
/// </remarks>
public sealed class AAuthInteractionTimeoutException : Exception
{
    public AAuthInteractionTimeoutException(string message)
        : base(message) { }

    public AAuthInteractionTimeoutException(string message, Exception innerException)
        : base(message, innerException) { }
}
