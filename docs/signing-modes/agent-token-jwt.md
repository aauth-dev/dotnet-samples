# Agent Token (sig=jwt)

## Overview

The agent presents its full agent token inline. The resource (or Person Server) learns the agent's identity, issuer, and Person Server URL. See [federated demo](https://explorer.aauth.dev/access/federated). Required for all Person Server flows.

## When to Use

- Three-party flows (PS-asserted, federated) — REQUIRED by spec
- When the resource needs to discover the agent's Person Server (from the `ps` claim)
- When the resource needs verified agent identity with issuer attestation

**Prerequisite:** Agent must have enrolled with an Agent Provider to obtain an `aa-agent+jwt`.

## Code Example

```csharp
using AAuth.Crypto;
using AAuth.HttpSig;

var key = AAuthKey.Generate();
// agentToken obtained from AgentProviderClient.EnrolAsync()
var provider = new JwtSignatureKeyProvider(() => agentToken);
var handler = new AAuthSigningHandler(key, provider)
{
    InnerHandler = new HttpClientHandler()
};

using var client = new HttpClient(handler);
var response = await client.GetAsync("https://resource.example/data");
```

## What the Resource Sees

- `Signature-Key: sig=jwt;jwt="eyJhbGciOi..."`
- Resource decodes the JWT: finds `iss` (AP), `sub` (agent ID), `cnf.jwk` (bound key), optionally `ps` (Person Server URL)
- Resource verifies: JWT signature (against AP's JWKS) + request signature (against `cnf.jwk`)

## Verification

When the resource sees a `ps` claim, it can issue a resource token challenging the agent to get authorization from that PS. This is the entry point to PS-asserted and federated access.

## Further Reading

- [Federated Demo](https://explorer.aauth.dev/access/federated)
- [PS-Asserted Access](../workflows/ps-asserted-access.md)
- [Bootstrap](../workflows/bootstrap-enrollment.md)
