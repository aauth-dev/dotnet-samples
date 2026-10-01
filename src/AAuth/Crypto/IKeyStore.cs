using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Crypto;

/// <summary>
/// Abstraction for storing and retrieving agent signing keys. Consumers plug
/// in OS credential stores, Azure Key Vault, etc. A store may return
/// non-exportable signers.
/// </summary>
public interface IKeyStore
{
    /// <summary>Load a signer by identifier. Returns null if not found.</summary>
    Task<IAAuthSigner?> LoadAsync(string handle, CancellationToken ct = default);

    /// <summary>Store a signer. Overwrites if already present.</summary>
    Task StoreAsync(string handle, IAAuthSigner key, CancellationToken ct = default);

    /// <summary>Delete a key by identifier.</summary>
    Task DeleteAsync(string handle, CancellationToken ct = default);

    /// <summary>List all stored key identifiers.</summary>
    Task<string[]> ListAsync(CancellationToken ct = default);
}
