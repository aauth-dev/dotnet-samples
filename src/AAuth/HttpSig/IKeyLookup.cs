using System.Threading;
using System.Threading.Tasks;
using AAuth.Crypto;

namespace AAuth.HttpSig;

/// <summary>
/// Resolves a public key by its JWK thumbprint. Used by the verification
/// middleware for the <c>hwk</c> (pseudonymous) signing mode where the
/// Signature-Key header only carries a thumbprint, not the key itself.
/// </summary>
/// <remarks>
/// Applications that accept <c>hwk</c>-signed requests must register an
/// implementation (e.g. backed by an enrollment database). If no
/// <see cref="IKeyLookup"/> is registered and an <c>hwk</c> request arrives,
/// the middleware returns <c>unknown_key</c>.
/// </remarks>
public interface IKeyLookup
{
    /// <summary>Find a public key by its base64url JWK thumbprint.</summary>
    /// <returns>The key, or null if no key is registered for this thumbprint.</returns>
    Task<IAAuthKey?> FindByThumbprintAsync(string jkt, CancellationToken ct = default);
}
