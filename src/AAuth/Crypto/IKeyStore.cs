using System.Threading;
using System.Threading.Tasks;

namespace AAuth.Crypto;

/// <summary>
/// Abstraction for storing and retrieving agent keys. Consumers plug in
/// OS credential store, Azure Key Vault, etc.
/// </summary>
public interface IKeyStore
{
    /// <summary>Load a key by identifier. Returns null if not found.</summary>
    Task<IAAuthKey?> LoadAsync(string keyId, CancellationToken ct = default);

    /// <summary>Store a key. Overwrites if already present.</summary>
    Task StoreAsync(string keyId, IAAuthKey key, CancellationToken ct = default);

    /// <summary>Delete a key by identifier.</summary>
    Task DeleteAsync(string keyId, CancellationToken ct = default);

    /// <summary>List all stored key identifiers.</summary>
    Task<string[]> ListAsync(CancellationToken ct = default);
}
