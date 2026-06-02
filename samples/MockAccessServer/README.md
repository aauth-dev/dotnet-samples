# Mock Access Server

A minimal AAuth Access Server (AS) for the four-party (federated) access demo and integration tests.

> **Sample only — not part of the AAuth SDK.** This project illustrates how an Access Server can be built on top of the SDK; it is not a supported runtime component.

## What it does

The Access Server is the fourth party in **federated access**. In this mode the
resource issues a resource token whose `aud` is the AS (not the Person Server).
The PS does not assert access itself — it *federates* to the AS by POSTing the
resource token (and the agent token) to the AS `token_endpoint`. The AS
evaluates policy and mints the auth token.

- Serves AS discovery metadata at `/.well-known/aauth-access.json` (with `token_endpoint`).
- Serves its signing JWKS at `/.well-known/jwks.json`.
- On `POST /token` (signed by the PS via the `jwks_uri` scheme):
  1. Verifies the RFC 9421 signature and pins the caller's `jwks_uri` host to a
     trusted Person Server (`MockAccessServer:TrustedPersonServers`).
  2. Reads `agent_token` and `resource_token` from the JSON body.
  3. Verifies the agent token (`typ=aa-agent+jwt`, `dwk=aauth-agent.json`)
     against the agent issuer's JWKS, extracting the agent id and its
     confirmation key.
  4. Verifies the resource token per §Resource Token Verification with
     `aud` = this AS — the discriminator that distinguishes four-party from
     three-party.
  5. Evaluates access policy (**Phase 1: a hard-coded allow stub**).
  6. Mints an `aa-auth+jwt` with `dwk = aauth-access.json`, `iss` = this AS,
     `aud` = the resource, bound to the agent's key.

The auth token's `dwk = aauth-access.json` is what tells a resource the token
came from an AS rather than a PS (`aauth-person.json`).

## Run

```bash
dotnet run --project samples/MockAccessServer
# → http://localhost:5500
```

## Configuration

| Key | Default | Purpose |
| --- | --- | --- |
| `AAuth:Issuer` | `http://localhost:5500` | AS issuer / metadata `issuer` and JWKS host. |
| `AAuth:SignatureWindow` | `60` | Max age (seconds) for the RFC 9421 signature. |
| `MockAccessServer:TrustedPersonServers` | `[http://localhost:5100]` | Person Servers allowed to federate (matched by `jwks_uri` host). |

## Scope

Phase 1 ships the on-the-wire AS baseline only: a hard-coded **allow** policy.
The pluggable policy seam (`IAccessPolicy`), the Keycloak-backed policy engine,
and consent bubble-up from the AS arrive in later phases.
