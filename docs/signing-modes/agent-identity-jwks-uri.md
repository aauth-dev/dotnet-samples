# Agent Identity (sig=jwks_uri)

## Overview

The agent references its JWKS endpoint and key ID. The resource fetches the public key to verify. See [live demo](https://explorer.aauth.dev/signing/identity). This replaces API keys with cryptographic identity.

## When to Use

- Access control by agent identity (the resource knows WHO is calling)
- Replacing static API keys with verifiable cryptographic identity
- Requires an Agent Provider that hosts the JWKS endpoint

## Code Example

```csharp
using AAuth.Crypto;
using AAuth.HttpSig;

var key = AAuthKey.Generate();
var jwksUri = "https://ap.example/.well-known/jwks.json";
var kid = "my-key-1";
var provider = new JwksUriSignatureKeyProvider(jwksUri, kid);
var handler = new AAuthSigningHandler(key, provider)
{
    InnerHandler = new HttpClientHandler()
};

using var client = new HttpClient(handler);
var response = await client.GetAsync("https://resource.example/data");
```

## What the Resource Sees

- `Signature-Key: sig=jwks_uri;uri="https://ap.example/.well-known/jwks.json";kid="my-key-1"`
- Resource fetches the JWKS, finds the key by `kid`, verifies the signature
- Resource learns: full agent identifier + verifiable public key

## Verification

Resource needs a `JwksClient` in DI (handles caching + rate-limiting).

```csharp
builder.Services.AddSingleton(new JwksClient(new HttpClient()));
```

The `DefaultSignatureKeyResolver` handles JWKS fetch automatically. URI MUST be `https` (loopback allowed for dev).

## Further Reading

- [Agent Identity Demo](https://explorer.aauth.dev/signing/identity)
- [Schemes](https://explorer.aauth.dev/foundations/schemes)
