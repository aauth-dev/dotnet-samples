# Pseudonymous Access (sig=hwk)

## Overview

The agent proves it holds a specific key without disclosing its identity. The full public key is sent inline (base64url-encoded JWK) along with the JWK thumbprint. See [live demo](https://explorer.aauth.dev/signing/pseudonymous).

## When to Use

- Rate-limiting by key (no identity needed)
- Anonymous but accountable access
- Simplest mode — just needs a keypair, no Agent Provider

## Code Example

```csharp
using AAuth.Crypto;
using AAuth.HttpSig;

var key = AAuthKey.Generate();

using var client = new AAuthClientBuilder(key)
    .UseHwk()
    .Build();

var response = await client.GetAsync("https://resource.example/data");
```

<details>
<summary>Manual Setup</summary>

```csharp
var provider = new HwkSignatureKeyProvider(key);
var handler = new AAuthSigningHandler(key, provider)
{
    InnerHandler = new HttpClientHandler()
};
using var client = new HttpClient(handler);
```

</details>

## What the Resource Sees

- `Signature-Key: sig=hwk;jkt="<thumbprint>";jwk="<base64url-encoded-public-JWK>"`
- The agent sends its full public key inline — the resource extracts it directly
- Useful for rate-limiting: same thumbprint = same key = same client

## Verification

The resource extracts the inline public key from the `Signature-Key` header's `jwk`
parameter (base64url-decoded JWK). No pre-registration or key lookup is required —
the key is self-contained in each request.

## Further Reading

- [Pseudonymous Demo](https://explorer.aauth.dev/signing/pseudonymous)
- [Schemes](https://explorer.aauth.dev/foundations/schemes)
