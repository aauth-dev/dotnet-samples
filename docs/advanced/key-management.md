# Key Management

> [Cryptographic Keys](https://explorer.aauth.dev/foundations/keys)

## Overview

AAuth agents need persistent signing keys. The SDK provides two built-in storage backends and an interface for custom implementations.

## Key Interfaces (Crypto Namespace)

The SDK separates a key's public identity from the ability to sign with it:

| Interface | Adds | Implemented by |
|-----------|------|----------------|
| `IAAuthKey` | Public identity: `Algorithm`, `ToPublicJwk()`, `ComputeJwkThumbprint()`, `Verify(...)` | Every key, including public-only keys used for verification |
| `IAAuthSigner : IAAuthKey` | `ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken)` | Any key that can sign, local or remote |
| `IAAuthExportableKey : IAAuthSigner` | `ToPrivateJwk()` | Local keys whose private half lives in process memory |

Signing is asynchronous so that a signer backed by an HSM, a cloud KMS, or a
platform keychain can make its remote call without blocking a thread. Token
builders (`BuildAsync`), `NamingJwtBuilder.BuildAsync`, and the HTTP signing
handler all await `IAAuthSigner.SignAsync`.

`AAuthKey` (Ed25519) and `EcdsaAAuthKey` (ES256) are the built-in local,
exportable keys. Their private halves are in memory, so the concrete types also
keep a synchronous `Sign(byte[])` and `ToPrivateJwk()` for code that holds the
concrete type. A non-exportable key implements only `IAAuthSigner` and
delegates `SignAsync` to the device or service that holds the private key.

## IKeyStore Interface (Crypto Namespace)

The `IKeyStore` interface defines async key storage for agent workflows (enrollment, token refresh). The SDK ships two built-in implementations: `InMemoryKeyStore` and `FileKeyStore`.

> **Note:** For AP-enrolled agents, the `handle` parameter passed to `IKeyStore` methods is the `LocalKeyHandle` returned by `EnrolAsync` (defaults to the durable key's JWK thumbprint). It is a purely local identifier — not an AP-assigned value. The AP identifies the agent at refresh time from the HTTP signature, never from this string.

```csharp
namespace AAuth.Crypto;

public interface IKeyStore
{
    Task<IAAuthSigner?> LoadAsync(string handle, CancellationToken ct = default);
    Task StoreAsync(string handle, IAAuthSigner key, CancellationToken ct = default);
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
var customStore = new FileKeyStore("/opt/myapp/keys");

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

The following `AzureKeyVaultStore` is an illustrative external integration,
not shipped or compiled by this repository. It requires
`Azure.Security.KeyVault.Secrets` and `Azure.Core`. It stores exportable
Ed25519 software keys as secrets and reloads private bytes into the process;
it is not an HSM or remote-signing implementation. Non-exportable keys require
an `IAAuthSigner` implementation that delegates `SignAsync` to the secure device.

```csharp
// Sample implementation of AAuth.Crypto.IKeyStore — not part of the SDK.
public sealed class AzureKeyVaultStore : IKeyStore
{
    private readonly SecretClient _client;

    public AzureKeyVaultStore(SecretClient client) => _client = client;

    // Spec: 'handle' is agent-chosen, never leaves the agent.
    // It is distinct from the AP-published kid (AgentTokenKid) and
    // the JWK thumbprint used for cryptographic identity.
    public async Task<IAAuthSigner?> LoadAsync(string handle, CancellationToken ct)
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

    public async Task StoreAsync(string handle, IAAuthSigner key, CancellationToken ct)
    {
        var exportable = key as IAAuthExportableKey
            ?? throw new ArgumentException("Only exportable keys can be stored as secrets.", nameof(key));
        var jwk = exportable.ToPrivateJwk().ToJsonString();
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

## Issuer Signing Key Rotation

Servers that sign tokens (resources, Person Servers, Access Servers, and
issuer revocation endpoints) take their keys as an `AAuthSigningKeySet`. The
set's JWKS publishes every key it holds, and new tokens are signed with the
active key only. Rotation is live: the host keeps the same set instance and
changes it in three steps, with no restart.

```csharp
// Share one set with the host options, for example
// AAuthPersonServerOptions.SigningKeys or ChallengeOptions.ResourceSigningKeys.
var issuerKeys = new AAuthSigningKeySet("key-1", AAuthKey.Generate());

// 1. Publish the new key. The JWKS lists key-1 and key-2; tokens are still signed with key-1.
issuerKeys.Add("key-2", AAuthKey.Generate());

// 2. After verifiers have refreshed their cached JWKS, sign new tokens with key-2.
issuerKeys.Activate("key-2");

// 3. After the last token signed with key-1 has expired, stop publishing key-1.
issuerKeys.Remove("key-1");
```

Until `Activate` is called, the first key added is active. The active key cannot
be removed; activate another key first. Readers always see a consistent
snapshot, so requests in flight during a change sign with either the old or the
new active key, never a mix.

## Security Considerations

- Never expose private keys in logs or error messages
- Use file permissions (600) for `FileKeyStore` directory
- Prefer KMS/HSM backends for production workloads
- Rotate keys periodically (jkt-jwt enables seamless rotation)

## Further Reading

- [Key Rotation (jkt-jwt)](../signing-modes/key-rotation-jkt-jwt.md)
- [Bootstrap & Enrollment](../workflows/bootstrap-enrollment.md) — keys generated during enrollment
- [Platform Attestation](platform-attestation.md) — hardware-bound keys
