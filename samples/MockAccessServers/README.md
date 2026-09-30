# Mock Access Servers

The **Access Server (AS)** is the fourth party in AAuth's four-party (federated)
flows. A resource issues a resource token whose `aud` is an AS (not the Person
Server); the PS federates to the AS, which evaluates policy and mints the
`aa-auth+jwt` (`dwk = aauth-access.json`, `iss` = AS).

> **Samples only — not part of the AAuth SDK.** These projects show how an Access
> Server can be built on the SDK host helpers; they are not supported runtime
> components.

This suite runs **two sample access servers** (scope-based Wallet plus R3 resources,
mirroring [MockResourceServers/](../MockResourceServers/)):

| Server | Port | Authorizes | Model |
|--------|------|-----------|-------|
| [**Federated**](Federated/) | 5500 | Wallet | Scope- and role-based policy (stub or Keycloak); the classic four-party payment gate |
| [**R3**](R3/) | 5501 | Bookings, Travel Catalog | Rich Resource Requests — fetches + hash-verifies the resource's R3 document, validates operations against the sample resources' authoritative OpenAPI definitions, splits `r3_granted` vs `r3_per_call` **by its own policy**, and mints R3 auth tokens |

## Federated (:5500)

The reference federated AS. On `POST /token` it verifies the PS's RFC 9421
signature, verifies the agent and resource tokens, evaluates a pluggable
`IAccessPolicy` (`stub` by default, or `keycloak`), and mints the auth token. The
whole pipeline ships as the SDK helper `MapAAuthAccessServer`. See
[Federated/README.md](Federated/README.md) and the
[Federated Access workflow](../../docs/workflows/federated-access.md).

## R3 (:5501)

The dedicated Access Server for [Rich Resource Requests](../../docs/workflows/rich-resource-requests.md).
On `POST /token` (via `MapR3AccessTokenEndpoint`) it:

1. Verifies the PS caller against its Person-Server trust list (unset ⇒ open, an
   explicit list narrows; empty denies all).
2. Verifies the agent and resource tokens.
3. Fetches the resource's R3 document **AS-signed**, and rejects it unless the bytes
   hash to the token's `r3_s256`.
4. Validates the document's operations against the authoritative OpenAPI
   definitions for the sample resources it guards (Bookings plus the merged
   Travel Catalog definition).
5. Splits the document's operations into `r3_granted` and `r3_per_call` **by its
   own policy** (`R3AccessServer:PerCallOperations`, per r3 §Auth Token
   Extensions — the AS decides, not the resource).
6. Audits issuance atomically, then mints the R3 auth token.

## Running

Both servers are started by `make demo` (Federated with the stub policy). For the
live Keycloak policy engine behind the Federated AS, use `make demo-keycloak`.

```bash
dotnet run --project samples/MockAccessServers/Federated   # → :5500
dotnet run --project samples/MockAccessServers/R3          # → :5501
```

See [Samples overview](../README.md) for the full suite.
