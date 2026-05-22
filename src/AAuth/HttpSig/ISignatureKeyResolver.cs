using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;

namespace AAuth.HttpSig;

/// <summary>
/// Result of resolving a Signature-Key header to a public key for verification.
/// </summary>
public sealed class SignatureKeyResolution
{
    /// <summary>The resolved public key to verify the HTTP signature.</summary>
    public required IAAuthKey PublicKey { get; init; }

    /// <summary>The parsed scheme info (for downstream inspection).</summary>
    public required SignatureKeyParser.ParsedSignatureKeyInfo Info { get; init; }
}

/// <summary>
/// Resolves the public key for HTTP signature verification from a parsed
/// <c>Signature-Key</c> header. Implementations dispatch based on scheme.
/// </summary>
public interface ISignatureKeyResolver
{
    /// <summary>Resolve the signing key from the parsed Signature-Key info.</summary>
    /// <exception cref="AAuthVerificationException">If the key cannot be resolved.</exception>
    Task<SignatureKeyResolution> ResolveAsync(
        SignatureKeyParser.ParsedSignatureKeyInfo info, CancellationToken ct = default);
}
