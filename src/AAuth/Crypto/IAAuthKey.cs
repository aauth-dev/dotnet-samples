using System.Text.Json.Nodes;

namespace AAuth.Crypto;

/// <summary>
/// The public identity of an AAuth key: algorithm, public JWK, thumbprint and
/// signature verification. Signing lives on <see cref="IAAuthSigner"/>, and
/// private-key export on <see cref="IAAuthExportableKey"/>.
/// </summary>
public interface IAAuthKey
{
    /// <summary>The JOSE <c>alg</c> value (e.g. "Ed25519", "ES256").</summary>
    string Algorithm { get; }

    /// <summary>True if this instance can sign (holds or reaches private key material).</summary>
    bool HasPrivateKey { get; }

    /// <summary>Verify a signature against this key's public component.</summary>
    bool Verify(byte[] data, byte[] signature);

    /// <summary>Export the public half as a JWK JSON document.</summary>
    JsonObject ToPublicJwk();

    /// <summary>Compute the RFC 7638 JWK thumbprint, base64url-encoded (no padding).</summary>
    string ComputeJwkThumbprint();
}
