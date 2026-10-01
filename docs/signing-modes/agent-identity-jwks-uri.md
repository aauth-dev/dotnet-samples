# Server Identity (sig=jwks_uri)

## Overview

The signer presents `id`, `dwk` and `kid`. The verifier fetches
`{id}/.well-known/{dwk}`, verifies its `issuer` equals `id`, then follows the
metadata's `jwks_uri` and selects only the matching key. PS/AS server signers
use this scheme; AAuth agents MUST use `jwt` for resource, PS and AS requests
(`#keying-material`, L2179-L2196). Use this page for generic Signature-Key or
server-to-server signing only.

## When to Use

- PS/AS/AP/resource server requests with an explicit signer identifier and role metadata
- Generic server signing where the receiver explicitly admits the metadata-discovery scheme with `RequireGenericSignature()`
- Requires matching issuer metadata and a JWKS endpoint; an AAuth agent instead presents its agent, person or auth JWT under `sig=jwt`

## Code Example

**Hosted service (self-hosted JWKS):**

```csharp
using AAuth.Crypto;
using AAuth;

var key = AAuthKey.Generate();

// Hosted services publish their own JWKS at a stable URL.
// A generic endpoint fetches this URL to verify the server's signature.
using var client = new AAuthClientBuilder(key)
    .UseJwksUri("https://my-service.example", "service-configuration", "svc-key-1")
    .Build();

var response = await client.GetAsync("https://generic.example/data");
```

**Generic Direct JWKS Demonstration:**

```csharp
using AAuth.Agent;
using AAuth.Crypto;
using AAuth;

var key = AAuthKey.Generate();

// The JWKS URL comes from the generic trust arrangement — for example a
// metadata document or an AP enrollment response for a non-AAuth demo.
// "my-key-1" is the AP-published kid (EnrollResult.AgentTokenKid).
// The AP chooses this value — there is no valid fallback if the AP didn't provide it.
using var client = new AAuthClientBuilder(key)
    .UseJwks("https://ap.example/agents/aauth:myapp@ap.example/jwks.json", "my-key-1")
    .Build();

var response = await client.GetAsync("https://generic.example/data");
```

<details>
<summary>Manual Setup</summary>

```csharp
using AAuth.HttpSig;

var provider = new JwksSignatureKeyProvider(
    "https://ap.example/agents/aauth:myapp@ap.example/jwks.json", "my-key-1");
var handler = new AAuthSigningHandler(key, provider)
{
    InnerHandler = new HttpClientHandler()
};
using var client = new HttpClient(handler);
```

</details>

## What the Resource Sees

- `Signature-Key: sig=jwks_uri;id="https://my-service.example";dwk="service-configuration";kid="svc-key-1"`
- Metadata issuer verification binds the signer identity before key resolution.
- Direct `jwks` instead uses `url` and `kid`; its identity is the exact key URL.

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

The resolver fetches keys only after URL/metadata admission. Production requires
HTTPS public destinations. Development loopback origins must be individually
configured; they are not automatically allowed. A resource accepting this generic scheme must explicitly configure its accepted
schemes and generic Signature Keys profile, for example with
`RequireGenericSignature()`. `AddAAuthResource` alone retains the AAuth JWT
default.

## Further Reading

- [Agent Identity Demo](https://explorer.aauth.dev/signing/identity)
- [Schemes](https://explorer.aauth.dev/foundations/schemes)
