namespace AAuth.Server.Verification;

/// <summary>
/// Authorization level determined by the type of AAuth credential presented.
/// </summary>
public enum AAuthLevel
{
    /// <summary>
    /// Pseudonymous — key-based identity only (hwk scheme). The resource
    /// sees a key thumbprint but nothing about the agent's identity.
    /// </summary>
    Pseudonymous,

    /// <summary>
    /// Identified — agent identity established via agent token (jwt or jwks_uri scheme)
    /// but no person/access authorization token present.
    /// </summary>
    Identified,

    /// <summary>
    /// Authorized — full authorization via auth token (aa-auth+jwt). The agent
    /// has been authorized by a Person Server or Access Server on behalf of a subject.
    /// </summary>
    Authorized,
}
