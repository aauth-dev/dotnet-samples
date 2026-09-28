# Resource Metadata

> [Discovery](https://explorer.aauth.dev/foundations/discovery)

## Overview

Resources publish a `.well-known/aauth-resource.json` document so agents can discover signing requirements, token endpoints, and public keys. The SDK serves it automatically: register the resource with `AddAAuthResource(...)` and map `app.MapAAuthWellKnown()`.

## Setup

```csharp
using AAuth;

builder.Services.AddAAuthResource(options =>
{
    options.Issuer = "https://resource.example";
    options.SigningKeys = new() { ["key-1"] = signingKey };
    options.Name = "My Resource API";
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
<summary>Manual Setup (building block)</summary>

> `AddAAuthResource(...)` + `app.MapAAuthWellKnown()` is the preferred setup for
> the common case. Use `MapAAuthResourceWellKnown(...)` directly when the host
> manages metadata separately from the resource service registration.
> `RevocationEndpoint` is also available through `AAuthResourceOptions`; it does
> not require the manual mapper.

```csharp
using AAuth.Server.Metadata;
using AAuth.Crypto;

var signingKey = AAuthKey.Generate();

var app = builder.Build();

app.MapAAuthResourceWellKnown(new AAuthResourceMetadataOptions
{
    Issuer = "https://resource.example",
    SigningKeys = new Dictionary<string, IAAuthKey> { ["key-1"] = signingKey },
    Name = "My Resource API",
    DocumentationUri = "https://docs.resource.example",
    ScopeDescriptions = new Dictionary<string, string>
    {
        ["read"] = "Read access to your data",
        ["write"] = "Write access to your data"
    },
    SignatureWindow = 60,
    AuthorizationEndpoint = "https://resource.example/authorize",
    RevocationEndpoint = "https://resource.example/revoke"
});
```

</details>

## AAuthResourceMetadataOptions

| Property | Required | Description |
|----------|:--------:|-------------|
| `Issuer` | Yes | The resource's canonical URL (used as `iss` in resource tokens) |
| `SigningKeys` | Conditional | Key-id to `IAAuthKey` map; required to issue resource tokens or make signed calls, optional for verification-only resources |
| `Name` | No | Human-readable name for the resource (`name`) |
| `DocumentationUri` | No | Developer-documentation URL (`documentation_uri`) |
| `ScopeDescriptions` | No | Scope → description map (displayed during consent) |
| `SignatureWindow` | No | Signature validity window in seconds (advertised to agents) |
| `AuthorizationEndpoint` | No | Resource's proactive authorization endpoint URL; not the PS/AS resource-token recipient (draft-11 removed `PersonServerAudience`; the recipient is `AccessServer` or the presented token's PS) |
| `RevocationEndpoint` | No | URL of the revocation endpoint |

## Published Endpoint

The extension maps `GET /.well-known/aauth-resource.json` returning:

```json
{
  "issuer": "https://resource.example",
  "name": "My Resource API",
  "documentation_uri": "https://docs.resource.example",
  "jwks_uri": "https://resource.example/.well-known/jwks.json",
  "scope_descriptions": {
    "read": "Read access to your data",
    "write": "Write access to your data"
  },
  "signature_window": 60,
  "authorization_endpoint": "https://resource.example/authorize",
  "revocation_endpoint": "https://resource.example/revoke"
}
```

The keys themselves are served separately at `/.well-known/jwks.json` (also mapped by `MapAAuthWellKnown()` / `MapAAuthResourceWellKnown()`).

The `authorization_endpoint` belongs to the resource's proactive authorization
flow. `AccessServer` on the challenge options instead selects the resource
token's recipient: the resource's AS for federation, or the PS that issued the
presented person token when the option is unset. It does not change this
metadata endpoint.

## Agent-Side Discovery

Agents use `MetadataClient` to fetch and cache this document:

```csharp
using AAuth.Discovery;

using var metadata = new MetadataClient(cacheTtl: TimeSpan.FromMinutes(15));
var url = MetadataClient.BuildUrl("https://resource.example", "aauth-resource.json");
var doc = await metadata.FetchAsync(url);
// doc["issuer"], doc["jwks_uri"], etc.
```

Without an injected client, `MetadataClient` owns and disposes its admitted
production transport. An injected client must carry an explicit transport
policy contract and remains caller-owned; a plain `new HttpClient()` is not an
admitted discovery transport.

## Further Reading

- [Configuration Reference](../reference/configuration.md)
- [Verification Middleware](verification-middleware.md)
