# Pseudonymous Access (sig=hwk)

## Overview

The agent proves it holds a specific key without disclosing its identity. The resource sees only a JWK thumbprint. See [live demo](https://explorer.aauth.dev/signing/pseudonymous).

## When to Use

- Rate-limiting by key (no identity needed)
- Anonymous but accountable access
- Simplest mode — just needs a keypair, no Agent Provider

## Code Example

```csharp
using AAuth.Crypto;
using AAuth.HttpSig;

var key = AAuthKey.Generate();
var provider = new HwkSignatureKeyProvider(key);
var handler = new AAuthSigningHandler(key, provider)
{
    InnerHandler = new HttpClientHandler()
};

using var client = new HttpClient(handler);
var response = await client.GetAsync("https://resource.example/data");
```

## What the Resource Sees

- `Signature-Key: sig=hwk;jkt="<base64url-sha256-thumbprint>"`
- The resource can verify the signature but learns nothing about who the agent is
- Useful for rate-limiting: same thumbprint = same key = same client

## Verification

Resource must register an `IKeyLookup` to resolve thumbprints to known keys. Without `IKeyLookup`, the middleware returns `unknown_key` error.

```csharp
builder.Services.AddSingleton<IKeyLookup>(new MyKeyLookup());
```

## Further Reading

- [Pseudonymous Demo](https://explorer.aauth.dev/signing/pseudonymous)
- [Schemes](https://explorer.aauth.dev/foundations/schemes)
