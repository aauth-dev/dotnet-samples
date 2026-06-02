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
  5. Evaluates access policy through a pluggable `IAccessPolicy`:
     - `stub` (default) — a hard-coded allow policy that denies elevated
       (`:`-qualified) scopes to non-admin agents.
     - `keycloak` — delegates the decision to Keycloak. The AS redirects the
       user through an interactive Keycloak login, then asks Keycloak for an
       authorization decision (UMA `uma-ticket` grant). Until the user logs in,
       `POST /token` returns `202` with `requirement=interaction`.
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
| `AccessServer:PolicyProvider` | `stub` | Policy engine: `stub` or `keycloak`. |
| `AccessServer:Keycloak:Authority` | `http://localhost:8080/realms/aauth` | Keycloak realm (OIDC issuer). |
| `AccessServer:Keycloak:ClientId` | `aauth-access-server` | Confidential client the AS authenticates as. |
| `AccessServer:Keycloak:ClientSecret` | — | Client secret for the AS client. |
| `AccessServer:Keycloak:ResourceServerAudience` | _(client id)_ | UMA audience for the `uma-ticket` grant. |
| `AccessServer:Keycloak:ResourceName` | `whoami` | Keycloak authorization resource backing the WhoAmI scopes. |

## Keycloak policy engine (four-party demo)

The `keycloak` provider makes Keycloak the policy decision point: the AS adapter
does the AAuth crypto, while Keycloak handles the interactive user login and the
authorization decision.

The realm import at `keycloak/realm-aauth.json` defines:

- Client `aauth-access-server` (confidential, authorization services enabled).
- Resource `whoami` with scopes `whoami` and `whoami:admin`.
- Base scope `whoami` granted to any authenticated user.
- Elevated scope `whoami:admin` granted only to users with the `whoami-admin`
  realm role.
- Two login users: `demo`/`demo` (has `whoami-admin`) and `guest`/`guest`.

Run the whole four-party demo (Keycloak + WhoAmI + PS + AP + AS) with:

```bash
make demo-federated
```

Then, in a second terminal, drive the agent:

```bash
make agent-federated
```

The agent prints a Keycloak login URL; open it, log in as `demo` (or `guest`),
and the four-party flow completes.

`make agent-federated` first clears the AgentConsole enrollment cache (the
MockAgentProvider keeps its agent registry in memory, so the cache goes stale
when the AP restarts). Run `make agent-reset` to clear it manually.

## Scope

This sample ships the on-the-wire AS baseline plus a pluggable policy seam
(`IAccessPolicy`) with a `stub` and a Keycloak-backed interactive provider.
