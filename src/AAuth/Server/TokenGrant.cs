using System;

namespace AAuth.Server;

public sealed record TokenGrant(TokenKey Token, string Resource, DateTimeOffset ExpiresAt)
{
    /// <summary>PS provenance recorded atomically with this grant, when the issuer is a PS.</summary>
    public AAuthTokenProvenance? Provenance { get; init; }
}