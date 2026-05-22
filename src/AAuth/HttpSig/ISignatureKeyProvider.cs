namespace AAuth.HttpSig;

/// <summary>
/// Strategy for producing the <c>Signature-Key</c> header value.
/// Implementations correspond to the AAuth signing modes: jwt, hwk, jwks_uri, jkt-jwt.
/// </summary>
public interface ISignatureKeyProvider
{
    /// <summary>
    /// Produce the <c>Signature-Key</c> header value for the current request.
    /// Called once per signed request.
    /// </summary>
    string GetSignatureKeyHeader();
}
