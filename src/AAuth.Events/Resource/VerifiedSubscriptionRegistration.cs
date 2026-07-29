using AAuth.Crypto;

namespace AAuth.Events.Resource;

/// <summary>
/// Authorization facts extracted only after subscribe-token and HTTP
/// signature verification has succeeded.
/// </summary>
public sealed record VerifiedSubscriptionRegistration(
    string ApIssuer,
    string AgentSubject,
    string ResourceAudience,
    string Eid,
    long? MaxUses,
    IAAuthKey ApSigningKey,
    IAAuthKey HttpSignatureKey,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    string ApKeyId,
    string SignatureKeyToken)
{
    /// <summary>Alias for the AP issuer.</summary>
    public string Issuer => ApIssuer;
    /// <summary>Alias for the agent subject.</summary>
    public string Subject => AgentSubject;
    /// <summary>Alias for the resource audience.</summary>
    public string Audience => ResourceAudience;
    /// <summary>Unix issue time.</summary>
    public long IssuedAtUnixSeconds => IssuedAt.ToUnixTimeSeconds();
    /// <summary>Unix expiry time.</summary>
    public long ExpiresAtUnixSeconds => ExpiresAt.ToUnixTimeSeconds();
}
