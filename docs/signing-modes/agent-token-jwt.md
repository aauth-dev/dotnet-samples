# Agent Token (sig=jwt)

## Overview

The agent presents its full agent token inline. The resource (or Person Server) learns the agent's identity, issuer, and Person Server URL. See [federated demo](https://explorer.aauth.dev/access/federated). Required for all Person Server flows.

## When to Use

- Three-party flows (PS-asserted, federated) — REQUIRED by spec
- When the resource needs to discover the agent's Person Server (from the `ps` claim)
- When the resource needs verified agent identity with issuer attestation

**Prerequisite:** Agent must have an `aa-agent+jwt` — either self-issued (hosted services that publish their own JWKS) or obtained from an Agent Provider (CLI/desktop agents that enrol).

## Code Example

**Hosted service (self-issued):**

```csharp
using AAuth.Crypto;
using AAuth.HttpSig;
using AAuth.Tokens;

var key = AAuthKey.Generate();

using var client = new AAuthClientBuilder(key)
    .WithTokenRefresh((ctx, ct) => Task.FromResult(new AgentTokenBuilder
    {
        Issuer = "https://my-service.example",
        Subject = "aauth:my-service@my-service.example",
        KeyId = "svc-key-1",
        Key = key,
        PersonServer = "https://ps.example",
    }.Build()))
    .WithChallengeHandling("https://ps.example")
    .Build();

var response = await client.GetAsync("https://resource.example/data");
```

**CLI/Desktop agent (AP-enrolled):**

```csharp
using AAuth.Agent;
using AAuth.Crypto;
using AAuth.HttpSig;

var keyStore = KeyStore.Default();
var key = await keyStore.LoadAsync(configuration["AAuth:KeyId"]!);
var apRefreshEndpoint = configuration["AAuth:ApRefreshEndpoint"]!;

using var client = new AAuthClientBuilder(key!)
    .WithTokenRefresh(async (ctx, ct) =>
    {
        var apClient = new AgentProviderClient(new HttpClient(), keyStore);
        return await apClient.RefreshAsync(apRefreshEndpoint, ctx.KeyId, ct);
    })
    .WithChallengeHandling("https://ps.example")
    .Build();

var response = await client.GetAsync("https://resource.example/data");
```

<details>
<summary>Manual Setup</summary>

```csharp
var provider = new JwtSignatureKeyProvider(() => agentToken);
var handler = new AAuthSigningHandler(key, provider)
{
    InnerHandler = new HttpClientHandler()
};
using var client = new HttpClient(handler);
```

</details>

## What the Resource Sees

- `Signature-Key: sig=jwt;jwt="eyJhbGciOi..."`
- Resource decodes the JWT: finds `iss` (agent's own URL or AP), `sub` (agent ID), `cnf.jwk` (bound key), optionally `ps` (Person Server URL)
- Resource verifies: JWT signature (against issuer's JWKS via `{iss}/.well-known/aauth-agent.json`) + request signature (against `cnf.jwk`)

## Verification

When the resource sees a `ps` claim, it can issue a resource token challenging the agent to get authorization from that PS. This is the entry point to PS-asserted and federated access.

## Further Reading

- [Call Chaining](../workflows/call-chaining.md) — multi-hop delegation with `UseJwt` and `upstream_token`
- [Federated Demo](https://explorer.aauth.dev/access/federated)
- [PS-Asserted Access](../workflows/ps-asserted-access.md)
- [Bootstrap](../workflows/bootstrap-enrollment.md)
