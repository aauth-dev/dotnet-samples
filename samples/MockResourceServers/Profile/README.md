# Profile — Identity-Based resource server

Aria's identity service. The **Profile** server decides access from the HTTP
signature alone — there is **no Person Server** and **no scope**. Every endpoint
is "signature only"; the three paths differ only in *how* the agent presents its
key (the RFC 9421 `Signature-Key` scheme).

> **Sample only — not part of the AAuth SDK.**

Port: `http://localhost:5000` (override with `--AAuth:Issuer`).

## Endpoints

| Path | `Signature-Key` scheme | What the resource learns | `signingMode` | Policy |
|------|------------------------|--------------------------|---------------|--------|
| `/` | _(index)_ | — | — | none |
| `/pseudonymous` | `hwk` | a key thumbprint (`jkt`) only — identity unknown | `pseudonymous` | none |
| `/identified` | `jwks_uri` | a named, verifiable agent identity (key via JWKS) | `agent-identity` | `AAuth.Identified` |
| `/anchored` | `jkt-jwt` | an ephemeral key anchored to a durable enrollment key | `pseudonymous` | none |

The path name describes the **outcome** the resource concludes; the `scheme` is
the unchanged protocol identifier. Per the spec, `jkt-jwt` is a key-rotation
variant of presenting a hardware-backed key, so it yields **pseudonymous**
access — the `/anchored` path reports `signingMode = "pseudonymous"`.

`/.well-known/aauth-resource.json` and `/.well-known/jwks.json` are served
without a signature.

## Running

```bash
dotnet run --project samples/MockResourceServers/Profile
```

## With AgentConsole

AgentConsole maps each signing mode to the matching Profile path automatically
when the URL has no path:

```bash
# Pseudonymous (hwk) → /pseudonymous
dotnet run --project samples/AgentConsole -- http://localhost:5000 \
  --ap http://localhost:5301 --signing-mode hwk

# Agent identity (jwks_uri) → /identified
dotnet run --project samples/AgentConsole -- http://localhost:5000 \
  --ap http://localhost:5301 --signing-mode jwks_uri

# Key rotation (jkt-jwt) → /anchored
dotnet run --project samples/AgentConsole -- http://localhost:5000 \
  --ap http://localhost:5301 --signing-mode jkt-jwt
```

See [Mock Resource Servers](../README.md) for the suite overview and the
signing-mode ↔ path table.
