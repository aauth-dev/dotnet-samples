using System.Text.Json.Nodes;

namespace AAuth.Crypto;

/// <summary>
/// A key that can sign. Signing is asynchronous so that remote and
/// non-exportable keys (cloud KMS, HSM, OS credential stores) can be used
/// without sync-over-async. Local keys complete synchronously.
/// </summary>
public interface IAAuthSigner : IAAuthKey
{
    /// <summary>Sign <paramref name="data"/> with the private key.</summary>
    ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default);
}

/// <summary>
/// A signer whose private key material can be exported as a JWK. Only
/// persistence that writes private keys (for example <see cref="FileKeyStore"/>)
/// needs this.
/// </summary>
public interface IAAuthExportableKey : IAAuthSigner
{
    /// <summary>Export both halves as a JWK (includes <c>d</c>). Throws if public-only.</summary>
    JsonObject ToPrivateJwk();
}
