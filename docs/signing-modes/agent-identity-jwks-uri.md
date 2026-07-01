# Agent Identity (sig=jwks_uri)

## Overview

The agent references its JWKS endpoint and key ID. The resource fetches the public key to verify. See [live demo](https://explorer.aauth.dev/signing/identity). This replaces API keys with cryptographic identity.

## When to Use

- Access control by agent identity (the resource knows WHO is calling)
- Replacing static API keys with verifiable cryptographic identity
- Requires a JWKS endpoint — either self-hosted (hosted services) or published by an Agent Provider (CLI/desktop agents)

## Code Example

**Hosted service (self-hosted JWKS):**

```csharp
using AAuth.Crypto;
using AAuth;

var key = AAuthKey.Generate();

// Hosted services publish their own JWKS at a stable URL.
// The resource fetches this URL to verify the agent's signature.
using var client = new AAuthClientBuilder(key)
    .UseJwksUri("https://my-service.example/.well-known/jwks.json", "svc-key-1")
    .Build();

var response = await client.GetAsync("https://resource.example/data");
```

**CLI/Desktop agent (AP-enrolled):**

```csharp
using AAuth.Agent;
using AAuth.Crypto;
using AAuth;

var key = AAuthKey.Generate();

// The jwks_uri comes from the AP's enrollment response — it points
// to the per-agent JWKS endpoint where the AP publishes this agent's key.
// "my-key-1" is the AP-published kid (EnrollResult.AgentTokenKid).
// The AP chooses this value — there is no valid fallback if the AP didn't provide it.
using var client = new AAuthClientBuilder(key)
    .UseJwksUri("https://ap.example/agents/aauth:myapp@ap.example/jwks.json", "my-key-1")
    .Build();

var response = await client.GetAsync("https://resource.example/data");
```

<details>
<summary>Manual Setup</summary>

```csharp
var provider = new JwksUriSignatureKeyProvider(
    "https://ap.example/agents/aauth:myapp@ap.example/jwks.json", "my-key-1");
var handler = new AAuthSigningHandler(key, provider)
{
    InnerHandler = new HttpClientHandler()
};
using var client = new HttpClient(handler);
```

</details>

## What the Resource Sees

- `Signature-Key: sig=jwks_uri;uri="https://ap.example/agents/aauth:myapp@ap.example/jwks.json";kid="my-key-1"`
- Resource fetches the JWKS, finds the key by `kid`, verifies the signature
- Resource learns: full agent identifier + verifiable public key

## Verification

`AddAAuthResource` registers the discovery clients — a pooled `JwksClient`
(caching + rate-limiting) — so no manual `HttpClient` wiring is needed.

```csharp
builder.Services.AddAAuthResource(o =>
{
    o.Issuer = resourceUrl;
    o.SigningKeys[ResourceKid] = resourceKey;
});
```

The `DefaultSignatureKeyResolver` then fetches the agent's JWKS automatically. URI MUST be `https` (loopback allowed for dev).

## Further Reading

- [Agent Identity Demo](https://explorer.aauth.dev/signing/identity)
- [Schemes](https://explorer.aauth.dev/foundations/schemes)
