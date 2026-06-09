# Key Management

> [Cryptographic Keys](https://explorer.aauth.dev/foundations/keys)

## Overview

AAuth agents need persistent signing keys. The SDK provides two built-in storage backends and an interface for custom implementations.

## IKeyStore Interface (Crypto Namespace)

The `IKeyStore` interface defines async key storage for agent workflows (enrollment, token refresh). The SDK ships two built-in implementations: `InMemoryKeyStore` and `FileKeyStore`.

> **Note:** For AP-enrolled agents, the `handle` parameter passed to `IKeyStore` methods is the `LocalKeyHandle` returned by `EnrolAsync` (defaults to the durable key's JWK thumbprint). It is a purely local identifier — not an AP-assigned value. The AP identifies the agent at refresh time from the HTTP signature, never from this string.

```csharp
namespace AAuth.Crypto;

public interface IKeyStore
{
    Task<IAAuthKey?> LoadAsync(string handle, CancellationToken ct = default);
    Task StoreAsync(string handle, IAAuthKey key, CancellationToken ct = default);
    Task DeleteAsync(string handle, CancellationToken ct = default);
    Task<string[]> ListAsync(CancellationToken ct = default);
}
```

### InMemoryKeyStore (implements IKeyStore)

In-process storage for testing. Keys are lost when the process exits:

```csharp
var keyStore = new InMemoryKeyStore();
await keyStore.StoreAsync("my-agent-key", AAuthKey.Generate());
var key = await keyStore.LoadAsync("my-agent-key");
```

## FileKeyStore (implements IKeyStore, Crypto Namespace)

File-based storage. Default location: `~/.aauth/keys/`

```csharp
namespace AAuth.Crypto;

public sealed class FileKeyStore : IKeyStore
{
    public string Directory { get; }

    public FileKeyStore(string directory);
    public static FileKeyStore Default();          // ~/.aauth/keys/

    // Synchronous convenience methods
    public void Save(string name, AAuthKey key);
    public AAuthKey Load(string name);
    public bool Exists(string name);
    public AAuthKey LoadOrCreate(string name);  // generates if missing

    // IKeyStore async interface (explicit implementation)
    // LoadAsync, StoreAsync, DeleteAsync, ListAsync
}
```

### Usage

```csharp
using AAuth.Crypto;

// Default location (~/.aauth/keys/)
var store = FileKeyStore.Default();

// Or custom directory
var store = new FileKeyStore("/opt/myapp/keys");

// Load or generate on first run
var agentKey = store.LoadOrCreate("agent-signing-key");

// Check existence
if (store.Exists("agent-signing-key"))
{
    var key = store.Load("agent-signing-key");
}
```

### File Format

Keys are stored as JWK JSON files:

```
~/.aauth/keys/
├── agent-signing-key.json    // { "kty": "OKP", "crv": "Ed25519", "x": "...", "d": "..." }
└── backup-key.json
```

## Choosing a Backend

| Implementation | Use Case | Thread-Safe | Async |
|----------------|----------|:-----------:|:-----:|
| `InMemoryKeyStore` | Unit tests, ephemeral agents | Yes | Yes |
| `FileKeyStore` | CLI tools, dev environments | No | No |
| Custom `IKeyStore` impl | Production (KMS, HSM, Vault) | You decide | Yes |

## Custom Backend Example

The following `AzureKeyVaultStore` is a **sample implementation of the SDK's `AAuth.Crypto.IKeyStore` interface** — it is not shipped with the SDK. It depends on `SecretClient`, `KeyVaultSecret`, and `RequestFailedException` from the `Azure.Security.KeyVault.Secrets` / `Azure` NuGet packages, which are likewise not part of the AAuth SDK.

```csharp
// Sample implementation of AAuth.Crypto.IKeyStore — not part of the SDK.
public sealed class AzureKeyVaultStore : IKeyStore
{
    private readonly SecretClient _client;

    public AzureKeyVaultStore(SecretClient client) => _client = client;

    // Spec: 'handle' is agent-chosen, never leaves the agent.
    // It is distinct from the AP-published kid (AgentTokenKid) and
    // the JWK thumbprint used for cryptographic identity.
    public async Task<IAAuthKey?> LoadAsync(string handle, CancellationToken ct)
    {
        try
        {
            var secret = await _client.GetSecretAsync(handle, cancellationToken: ct);
            return AAuthKey.FromJwkJson(secret.Value.Value);
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            return null;
        }
    }

    public async Task StoreAsync(string handle, IAAuthKey key, CancellationToken ct)
    {
        var jwk = ((AAuthKey)key).ToPrivateJwk().ToJsonString();
        await _client.SetSecretAsync(new KeyVaultSecret(handle, jwk), ct);
    }

    public async Task DeleteAsync(string handle, CancellationToken ct)
    {
        await _client.StartDeleteSecretAsync(handle, ct);
    }

    public async Task<string[]> ListAsync(CancellationToken ct)
    {
        var keys = new List<string>();
        await foreach (var prop in _client.GetPropertiesOfSecretsAsync(ct))
            keys.Add(prop.Name);
        return keys.ToArray();
    }
}
```

## Key Rotation

For key rotation with continuity, use the `jkt-jwt` signing mode:

1. Generate new key, store in `IKeyStore`
2. Create a delegation JWT from old key to new key
3. Use `JktJwtSignatureKeyProvider` — resource sees the same identity

See [Key Rotation (jkt-jwt)](../signing-modes/key-rotation-jkt-jwt.md) for details.

## Security Considerations

- Never expose private keys in logs or error messages
- Use file permissions (600) for `FileKeyStore` directory
- Prefer KMS/HSM backends for production workloads
- Rotate keys periodically (jkt-jwt enables seamless rotation)

## Further Reading

- [Key Rotation (jkt-jwt)](../signing-modes/key-rotation-jkt-jwt.md)
- [Bootstrap & Enrollment](../workflows/bootstrap-enrollment.md) — keys generated during enrollment
- [Platform Attestation](platform-attestation.md) — hardware-bound keys
