# Getting Started

## Prerequisites

- [.NET 10+](https://dotnet.microsoft.com/download) SDK

## Install

```bash
dotnet add package AAuth
```

Or, if working within this repository, add a project reference:

```bash
dotnet add reference src/AAuth/AAuth.csproj
```

## Generate a Key

```csharp
using AAuth.Crypto;

var key = AAuthKey.Generate(); // Ed25519 keypair
var publicJwk = key.ToPublicJwk(); // Export for registration
var thumbprint = key.ComputeJwkThumbprint(); // JWK thumbprint (S256)
```

## Make Your First Signed Request

The simplest mode is pseudonymous (HWK) — no Agent Provider needed:

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
// Request is signed with HTTP Message Signatures (RFC 9421)
// Resource sees: Signature-Key: sig=hwk;jkt="<thumbprint>"
```

## What Just Happened?

- `AAuthKey.Generate()` created an Ed25519 keypair.
- `HwkSignatureKeyProvider` produces the `Signature-Key: sig=hwk;jkt="..."` header.
- `AAuthSigningHandler` signs the request per RFC 9421 covering `@method`, `@authority`, `@path`, and `signature-key`.
- The resource verifies the signature and sees a pseudonymous key thumbprint.

## Next Steps

- [Signing Modes Overview](signing-modes/overview.md) — choose the right mode for your use case
- [Identity-Based Access](workflows/identity-based-access.md) — simplest workflow
- [PS-Asserted Access](workflows/ps-asserted-access.md) — full authorization flow
- [Protocol Concepts](concepts.md) — understand the full picture

## Protocol Reference

Explore the interactive protocol specification at <https://explorer.aauth.dev/>.
