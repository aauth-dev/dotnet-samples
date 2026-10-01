# Pseudonymous Signatures (sig=hwk)

## Overview

The signer proves possession of a key without asserting an issuer identity.
Public JWK members are carried as structured string parameters. This is a
generic Signature Keys scheme, not an AAuth resource-access credential.
AAuth agents present agent, person or auth tokens using `sig=jwt`.

## When to Use

- Rate-limiting by key (no identity needed)
- Anonymous but accountable access
- Simplest mode — just needs a keypair, no Agent Provider

## Code Example

```csharp
using AAuth.Crypto;
using AAuth;

var key = AAuthKey.Generate();

using var client = new AAuthClientBuilder(key)
    .UseHwk()
    .Build();

var response = await client.GetAsync("https://resource.example/data");
```

<details>
<summary>Manual Setup</summary>

```csharp
using AAuth.HttpSig;

var provider = new HwkSignatureKeyProvider(key);
var handler = new AAuthSigningHandler(key, provider)
{
    InnerHandler = new HttpClientHandler()
};
using var client = new HttpClient(handler);
```

</details>

## What the Resource Sees

- `Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="<public-key>";alg="Ed25519"`
- The agent sends its full public key inline — the resource extracts it directly
- Useful for rate-limiting: same thumbprint = same key = same client

## Verification

The verifier reconstructs the public JWK from `kty`, `crv`, `x` and `alg`, plus
`y` for ES256. `kid`, private material and the former `jkt`/`jwk` encoding are
rejected. Thumbprints are computed using RFC 7638 and do not include `alg`.

## Further Reading

- [Pseudonymous Demo](https://explorer.aauth.dev/signing/pseudonymous)
- [Schemes](https://explorer.aauth.dev/foundations/schemes)
