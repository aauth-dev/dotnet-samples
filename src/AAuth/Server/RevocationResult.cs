using System.Collections.Generic;
using System.Net;
using AAuth.Errors;

namespace AAuth.Server;

/// <summary>A revocation endpoint's answer (§Token Revocation, Revocation Response).</summary>
public sealed record RevocationResult
{
    public required HttpStatusCode StatusCode { get; init; }

    /// <summary>The <c>error</c> member of a non-<c>200</c> response, if it carried one.</summary>
    public string? Error { get; init; }

    /// <summary>The recipient's <c>downstream</c> report; empty when the body was empty or omitted it.</summary>
    public IReadOnlyList<RevocationDownstreamResult> Downstream { get; init; } = [];

    /// <summary>
    /// <see langword="null"/> when the recipient recorded the revocation; otherwise
    /// <see cref="RevocationDownstreamError.RevocationUnsupported"/> for <c>unsupported_iss</c>, or
    /// <see cref="RevocationDownstreamError.RevocationUnavailable"/> for any other failure or an unparseable body.
    /// </summary>
    public RevocationDownstreamError? Failure { get; init; }
}

/// <summary>One <c>downstream</c> entry: the recipient revoked at, and why it did not succeed (absent on success).</summary>
public sealed record RevocationDownstreamResult(string Recipient, RevocationDownstreamError? Error);
