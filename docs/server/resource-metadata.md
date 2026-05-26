# Resource Metadata

> [Discovery](https://explorer.aauth.dev/foundations/discovery)

## Overview

Resources publish a `.well-known/aauth-resource.json` document so agents can discover signing requirements, token endpoints, and public keys. The SDK provides `WellKnownEndpoints.MapAAuthResourceWellKnown()` to serve this automatically.

## Setup

```csharp
using AAuth.DependencyInjection;

builder.Services.AddAAuthResource(options =>
{
    options.Issuer = "https://resource.example";
    options.SigningKeys = new() { ["key-1"] = signingKey };
    options.ClientName = "My Resource API";
    options.ScopeDescriptions = new()
    {
        ["read"] = "Read access to your data",
        ["write"] = "Write access to your data"
    };
});

var app = builder.Build();
app.MapAAuthWellKnown(); // serves /.well-known/aauth-resource.json
```

<details>
<summary>Manual Setup</summary>

```csharp
using AAuth.Server;
using AAuth.Crypto;

var signingKey = AAuthKey.Generate();

var app = builder.Build();

app.MapAAuthResourceWellKnown(new AAuthResourceMetadataOptions
{
    Issuer = "https://resource.example",
    SigningKeys = new Dictionary<string, AAuthKey> { ["key-1"] = signingKey },
    ClientName = "My Resource API",
    ScopeDescriptions = new Dictionary<string, string>
    {
        ["read"] = "Read access to your data",
        ["write"] = "Write access to your data"
    },
    SignatureWindow = 60,
    AuthorizationEndpoint = "https://as.example/authorize",
    RevocationEndpoint = "https://resource.example/revoke"
});
```

</details>

## AAuthResourceMetadataOptions

| Property | Required | Description |
|----------|:--------:|-------------|
| `Issuer` | Yes | The resource's canonical URL (used as `iss` in resource tokens) |
| `SigningKeys` | Yes | Dictionary of key-id → `AAuthKey` used to sign resource tokens |
| `ClientName` | No | Human-readable name for the resource |
| `ScopeDescriptions` | No | Scope → description map (displayed during consent) |
| `SignatureWindow` | No | Signature validity window in seconds (advertised to agents) |
| `AuthorizationEndpoint` | No | URL of the Access Server's authorization endpoint |
| `RevocationEndpoint` | No | URL of the revocation endpoint |

## Published Endpoint

The extension maps `GET /.well-known/aauth-resource.json` returning:

```json
{
  "issuer": "https://resource.example",
  "client_name": "My Resource API",
  "jwks": {
    "keys": [{ "kid": "key-1", "kty": "OKP", "crv": "Ed25519", "x": "..." }]
  },
  "scope_descriptions": {
    "read": "Read access to your data",
    "write": "Write access to your data"
  },
  "signature_window": 60,
  "authorization_endpoint": "https://as.example/authorize",
  "revocation_endpoint": "https://resource.example/revoke"
}
```

## Agent-Side Discovery

Agents use `MetadataClient` to fetch and cache this document:

```csharp
using AAuth.Discovery;

var metadata = new MetadataClient(new HttpClient(), cacheTtl: TimeSpan.FromMinutes(15));
var url = MetadataClient.BuildUrl("https://resource.example", "aauth-resource.json");
var doc = await metadata.FetchAsync(url);
// doc["issuer"], doc["jwks"], etc.
```

## Further Reading

- [Configuration Reference](../reference/configuration.md)
- [Verification Middleware](verification-middleware.md)
