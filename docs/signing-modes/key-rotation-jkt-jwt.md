# Key Rotation (sig=jkt-jwt)

## Overview

Two-key delegation where a durable (hardware-backed) key issues a naming JWT that delegates to an ephemeral signing key. Used for bootstrap key rotation. See [Signature-Key schemes](https://explorer.aauth.dev/foundations/schemes).

## When to Use

- Rotating from an old key to a new one without re-enrolling
- Hardware-backed durable keys that delegate to software ephemeral keys
- Bootstrap refresh scenarios

## Code Example

```csharp
using AAuth.Crypto;
using AAuth.HttpSig;

var durableKey = AAuthKey.Generate();    // long-lived, possibly hardware-backed
var ephemeralKey = AAuthKey.Generate();  // short-lived signing key

// namingJwt: signed by durableKey, contains ephemeralKey's thumbprint in claims
var provider = new JktJwtSignatureKeyProvider(ephemeralKey, () => namingJwt);
var handler = new AAuthSigningHandler(ephemeralKey, provider)
{
    InnerHandler = new HttpClientHandler()
};
```

## What the Resource Sees

- `Signature-Key: sig=jkt-jwt;jkt="<ephemeral-thumbprint>";jwt="<naming-jwt>"`
- Resource verifies: naming JWT signature (durable key) + request signature (ephemeral key)
- Confirms: `jkt` parameter matches `cnf.jwk` thumbprint in naming JWT

## Verification

Delegation chain:

1. Durable key signs a naming JWT containing the ephemeral key's thumbprint
2. Ephemeral key signs the actual HTTP request
3. Resource verifies both: naming JWT proves delegation, request signature proves possession

## Further Reading

- [Signature-Key Schemes](https://explorer.aauth.dev/foundations/schemes)
- [Bootstrap](../workflows/bootstrap-enrollment.md)
