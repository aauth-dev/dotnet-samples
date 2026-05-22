using System.Text.Json.Nodes;

namespace AAuth.Crypto;

/// <summary>
/// Abstraction over AAuth signing keys. Enables plugging in different
/// algorithms (Ed25519, ECDSA P-256) and key storage backends (software,
/// hardware, cloud KMS).
/// </summary>
public interface IAAuthKey
{
    /// <summary>The JOSE <c>alg</c> value (e.g. "EdDSA", "ES256").</summary>
    string Algorithm { get; }

    /// <summary>True if this instance can sign (holds private key material).</summary>
    bool HasPrivateKey { get; }

    /// <summary>Sign the given data.</summary>
    byte[] Sign(byte[] data);

    /// <summary>Verify a signature against this key's public component.</summary>
    bool Verify(byte[] data, byte[] signature);

    /// <summary>Export the public half as a JWK JSON document.</summary>
    JsonObject ToPublicJwk();

    /// <summary>Export both halves as a JWK (includes <c>d</c>). Throws if public-only.</summary>
    JsonObject ToPrivateJwk();

    /// <summary>Compute the RFC 7638 JWK thumbprint, base64url-encoded (no padding).</summary>
    string ComputeJwkThumbprint();
}
