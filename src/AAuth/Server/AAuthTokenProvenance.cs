using System;

namespace AAuth.Server;

/// <summary>
/// Server-side provenance recorded with a PS-issued or PS-federated token grant.
/// </summary>
public sealed record AAuthTokenProvenance(
    string TokenType,
    string Audience,
    string Subject,
    string PersonServer,
    UpstreamCallerRecord Caller)
{
    /// <summary>The upstream token this token was issued from, when call chaining.</summary>
    public TokenKey? UpstreamToken { get; init; }

    /// <summary>The presented person token used to mint an auth token or federated AS auth token.</summary>
    public TokenKey? PresentedToken { get; init; }
}

/// <summary>The original calling agent identified from the PS token inventory.</summary>
public sealed record UpstreamCallerRecord(
    string AgentIssuer,
    string AgentId,
    TokenKey AgentToken,
    TokenKey AgentPersonBinding);
