# Wallet — Federated (four-party) resource server

Aria's bank. The **Wallet** has its **own Access Server** that enforces payment
policy. Aria cannot get a token from the user's Person Server directly — the
resource token's `aud` is the Access Server, so the PS federates to the AS, which
evaluates policy and mints the auth token (`iss` = AS, `dwk = aauth-access.json`).

> **Sample only — not part of the AAuth SDK.**

Port: `http://localhost:5003`. Trusts the Access Server at
`http://localhost:5500` (override via `AAuth:AccessServer`).

## Endpoints

| Path | Scope | Policy (enforced by the Access Server) | `accessMode` |
|------|-------|----------------------------------------|--------------|
| `/` | _(index)_ | — | — |
| `/wallet` | `wallet.read` | view balance + cards — any authenticated user | `four-party` |
| `/wallet/charge` | `wallet.charge` | initiate a payment — **only** users carrying the `wallet.payer` role | `four-party` |

`/wallet/charge` is where the four-party model earns its keep: a real-world
"only an authorized payer can spend money" gate, decided by the bank's own
Access Server rather than the resource. With the Keycloak policy engine, the
`demo`/`demo` user has the `wallet.payer` role (can charge) and `guest`/`guest`
does not (denied **403** on `/wallet/charge`).

## Running

```bash
dotnet run --project samples/MockResourceServers/Wallet
```

The four-party flow needs an Access Server. The stub AS (no Docker) is included
in `make demo`; for the live Keycloak policy engine use `make demo-keycloak`.

## With AgentConsole

```bash
# Baseline (wallet.read) — any user
dotnet run --project samples/AgentConsole -- http://localhost:5003/wallet \
  --ap http://localhost:5301 --ps http://localhost:5100 --sub aauth:demo@ap.example

# Payment (wallet.charge) — demo can charge; guest is denied 403 by the AS
dotnet run --project samples/AgentConsole -- http://localhost:5003/wallet/charge \
  --ap http://localhost:5301 --ps http://localhost:5100 --sub aauth:demo@ap.example
```

See [Federated Access](../../../docs/workflows/federated-access.md) and the
[Mock Access Server README](../../MockAccessServers/Federated/README.md) for the policy
engine, and [Mock Resource Servers](../README.md) for the suite overview.
