# Key Management

> [Cryptographic Keys](https://explorer.aauth.dev/foundations/keys)

## Overview

AAuth agents need persistent signing keys. The SDK provides two built-in storage backends and an interface for custom implementations.

## IKeyStore (Agent Namespace)

Async key storage for agent workflows (enrollment, token operations):

```csharp
namespace AAuth.Agent;

public interface IKeyStore
{
    Task<IAAuthKey?> LoadAsync(string keyId, CancellationToken ct = default);
    Task StoreAsync(string keyId, IAAuthKey key, CancellationToken ct = default);
    Task DeleteAsync(string keyId, CancellationToken ct = default);
    Task<string[]> ListAsync(CancellationToken ct = default);
}
```

### InMemoryKeyStore

In-process storage for testing. Keys are lost when the process exits:

```csharp
var keyStore = new InMemoryKeyStore();
await keyStore.StoreAsync("my-agent-key", AAuthKey.Generate());
var key = await keyStore.LoadAsync("my-agent-key");
```

## KeyStore (Crypto Namespace)

File-based synchronous storage. Default location: `~/.aauth/keys/`

```csharp
namespace AAuth.Crypto;

public sealed class KeyStore
{
    public string Directory { get; }

    public KeyStore(string directory);
    public static KeyStore Default();          // ~/.aauth/keys/
    public void Save(string name, AAuthKey key);
    public AAuthKey Load(string name);
    public bool Exists(string name);
    public AAuthKey LoadOrCreate(string name);  // generates if missing
}
```

### Usage

```csharp
using AAuth.Crypto;

// Default location (~/.aauth/keys/)
var store = KeyStore.Default();

// Or custom directory
var store = new KeyStore("/opt/myapp/keys");

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

| Backend | Use Case | Thread-Safe | Async |
|---------|----------|:-----------:|:-----:|
| `InMemoryKeyStore` | Unit tests, ephemeral agents | Yes | Yes |
| `KeyStore` | CLI tools, dev environments | No | No |
| Custom `IKeyStore` | Production (KMS, HSM, Vault) | You decide | Yes |

## Custom Backend Example

```csharp
public sealed class AzureKeyVaultStore : IKeyStore
{
    private readonly SecretClient _client;

    public AzureKeyVaultStore(SecretClient client) => _client = client;

    public async Task<IAAuthKey?> LoadAsync(string keyId, CancellationToken ct)
    {
        try
        {
            var secret = await _client.GetSecretAsync(keyId, cancellationToken: ct);
            return AAuthKey.FromJwk(secret.Value.Value);
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            return null;
        }
    }

    public async Task StoreAsync(string keyId, IAAuthKey key, CancellationToken ct)
    {
        var jwk = ((AAuthKey)key).ExportJwk(includePrivate: true);
        await _client.SetSecretAsync(new KeyVaultSecret(keyId, jwk), ct);
    }

    public async Task DeleteAsync(string keyId, CancellationToken ct)
    {
        await _client.StartDeleteSecretAsync(keyId, ct);
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

For key rotation with continuity, use the `jkt_jwt` signing mode:

1. Generate new key, store in `IKeyStore`
2. Create a delegation JWT from old key to new key
3. Use `JktJwtSignatureKeyProvider` — resource sees the same identity

See [Key Rotation (jkt_jwt)](../signing-modes/key-rotation-jkt-jwt.md) for details.

## Security Considerations

- Never expose private keys in logs or error messages
- Use file permissions (600) for `KeyStore` directory
- Prefer KMS/HSM backends for production workloads
- Rotate keys periodically (jkt_jwt enables seamless rotation)

## Further Reading

- [Key Rotation (jkt_jwt)](../signing-modes/key-rotation-jkt-jwt.md)
- [Bootstrap & Enrollment](../workflows/bootstrap-enrollment.md) — keys generated during enrollment
- [Platform Attestation](platform-attestation.md) — hardware-bound keys
