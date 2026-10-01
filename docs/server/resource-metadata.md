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
<summary>All metadata fields</summary>

> `AddAAuthResource(...)` + `app.MapAAuthWellKnown()` is the only public way to
> publish resource metadata; the lower-level mapper is internal. Fields without a
> typed `AAuthResourceOptions` property go through `AdditionalMetadata`.
> `RevocationEndpoint` is also available through `AAuthResourceOptions`;
> map the endpoint itself with `MapAAuthResourceRevocation`.

```csharp
using AAuth;
using AAuth.Crypto;

var signingKey = AAuthKey.Generate();

builder.Services.AddAAuthResource(options =>
{
    options.Issuer = "https://resource.example";
    options.SigningKeys["key-1"] = signingKey;
    options.Name = "My Resource API";
    options.Description = "Calendar and document APIs";
    options.AccessMode = AAuthConstants.AccessModes.AuthToken;
    options.ScopeDescriptions = new Dictionary<string, string>
    {
        ["read"] = "Read access to your data",
        ["write"] = "Write access to your data"
    };
    options.SignatureWindow = 60;
    options.AdditionalSignatureComponents = new[] { "content-type", "content-digest" };
    options.AuthorizationEndpoint = "https://resource.example/authorize";
    options.RevocationEndpoint = "https://resource.example/revoke";
    options.DocumentationUri = "https://docs.resource.example";
    options.LogoUri = "https://resource.example/logo.svg";
    options.TosUri = "https://resource.example/terms";
    options.PolicyUri = "https://resource.example/privacy";
    options.AdditionalMetadata = new()
    {
        ["support_uri"] = "https://resource.example/support"
    };
});

var app = builder.Build();
app.MapAAuthWellKnown();
```

</details>

## AAuthResourceMetadataOptions

| Property | Required | Description |
|----------|:--------:|-------------|
| `Issuer` | Yes | The resource's canonical URL (used as `iss` in resource tokens) |
| `SigningKeys` | Conditional | `AAuthSigningKeySet`: every key is published at the JWKS and tokens are signed with the active key; required to issue resource tokens or make signed calls, optional for verification-only resources |
| `Name` | No | Human-readable name for the resource (`name`) |
| `Description` | No | Human-readable Markdown/plain description (`description`) |
| `LogoUri` | No | Light-mode logo URL (`logo_uri`) |
| `LogoDarkUri` | No | Dark-mode logo URL (`logo_dark_uri`) |
| `DocumentationUri` | No | Developer-documentation URL (`documentation_uri`) |
| `TosUri` | No | Terms-of-service URL (`tos_uri`) |
| `PolicyUri` | No | Privacy/security policy URL (`policy_uri`) |
| `ScopeDescriptions` | No | Scope → description map (displayed during consent) |
| `SignatureWindow` | No | Signature validity window in seconds (advertised to agents) |
| `AdditionalSignatureComponents` | No | Additional HTTP signature components agents must cover, emitted as `additional_signature_components` |
| `AccessMode` | No | Advisory `access_mode`: `agent-token`, `person-token`, `session-token` (resource-managed / `AAuth-Access`), `auth-token`, or R3 `per-call` |
| `AuthorizationEndpoint` | No | Resource's proactive authorization endpoint URL; not the PS/AS resource-token recipient (draft-11 removed `PersonServerAudience`; the recipient is `AccessServer` or the presented token's PS) |
| `RevocationEndpoint` | No | URL of the revocation endpoint |
| `AdditionalMetadata` | No | Extension members merged into the well-known document. It cannot shadow typed fields. |

## Published Endpoint

The extension maps `GET /.well-known/aauth-resource.json` returning:

```json
{
  "issuer": "https://resource.example",
  "name": "My Resource API",
  "description": "Calendar and document APIs",
  "access_mode": "auth-token",
  "documentation_uri": "https://docs.resource.example",
  "logo_uri": "https://resource.example/logo.svg",
  "tos_uri": "https://resource.example/terms",
  "policy_uri": "https://resource.example/privacy",
  "jwks_uri": "https://resource.example/.well-known/jwks.json",
  "scope_descriptions": {
    "read": "Read access to your data",
    "write": "Write access to your data"
  },
  "signature_window": 60,
  "additional_signature_components": ["content-type", "content-digest"],
  "authorization_endpoint": "https://resource.example/authorize",
  "revocation_endpoint": "https://resource.example/revoke"
}
```

The keys themselves are served separately at `/.well-known/jwks.json` (also mapped by `MapAAuthWellKnown()`).

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
