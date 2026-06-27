# Mock Resource Servers

Five small ASP.NET Core resource servers that together demonstrate **every**
AAuth access mode and signing mode. They replace the former single `WhoAmI`
sample by splitting one mega-server into five focused, copy-paste-able templates,
each a short `Program.cs` (well-known + one verification pipeline + a couple of
endpoints).

> **Samples only — not part of the AAuth SDK.** These are illustrative wiring
> built on top of the SDK. Do not depend on their types or HTTP surface in
> production code.

## The "Aria" narrative

The servers model the backend an AI travel assistant ("Aria") would call on a
traveler's behalf — each protocol concept gets a real-feeling home:

| Server | Port | Access mode | What it protects | Endpoints → scope/role |
|--------|------|-------------|------------------|------------------------|
| [**Profile**](Profile/) | 5000 | Identity-Based | who the caller is (no Person Server) | `/pseudonymous` (`hwk`), `/identified` (`jwks_uri`), `/anchored` (`jkt-jwt`) — no scope |
| [**Calendar**](Calendar/) | 5001 | PS-Asserted (three-party) | the traveler's events | `/events` → `calendar.read`, `/events/write` → `calendar.write` (step-up), `/events/admin` → role `calendar.owner` (RBAC) |
| [**Trips**](Trips/) | 5002 | three-party + mission-aware | trip planning under a mission | `/trips` → `trips.read` (in-mission, silent), `/trips/book` → `trips.book` (out-of-mission, prompts) |
| [**Wallet**](Wallet/) | 5003 | Federated (four-party) | the bank, with its own Access Server | `/wallet` → `wallet.read`, `/wallet/charge` → `wallet.charge` (AS role `wallet.payer`) |
| [**Inbox**](Inbox/) | 5004 | Resource-Managed (two-party) | the traveler's inbox / trip confirmations | `/messages` → reactive (`202` + own consent → poll `/pending/{code}` → `AAuth-Access`), `/authorize` → proactive (`{scope}`) |

The narrative reads as a journey: *Aria identifies itself (Profile), imports your
trip confirmations from your **Inbox** (which manages its own consent — no Person
or Access Server), reads your **Calendar**, drafts a **Trip** under a mission you
approved, then asks the bank before charging your **Wallet** — and the bank's own
Access Server decides if you're allowed to pay.*

## Signing mode ↔ Profile path

The Profile server's three paths are three **signing modes** of one access mode
(identity). The path names describe what the resource *concludes* (the outcome);
the `scheme` values are the unchanged RFC 9421 `Signature-Key` identifiers.

| Profile path | `Signature-Key` scheme | What the resource learns | `signingMode` |
|--------------|------------------------|--------------------------|---------------|
| `/pseudonymous` | `hwk` | a key thumbprint only — caller is a pseudonym | `pseudonymous` |
| `/identified` | `jwks_uri` | a named, verifiable agent identity (via JWKS) | `agent-identity` |
| `/anchored` | `jkt-jwt` | an ephemeral key anchored to a durable enrollment key | `pseudonymous` |

> Per the spec, `jkt-jwt` yields **pseudonymous** access (the resource learns
> only the durable key's thumbprint, not a named identity). The `/anchored` path
> name describes the key *mechanism* (the naming-JWT refresh); the `signingMode`
> field reports the spec identity type.

## Response field convention

- **Profile** endpoints return `signingMode` + `scheme` (signing-mode demo).
- **Calendar / Trips / Wallet** endpoints return `accessMode` + `scheme`
  (access-mode demo: `three-party` / `four-party`).
- **Inbox** endpoints return `scope` + `messages` (resource-managed /
  `two-party`: the Inbox issues its own `AAuth-Access` token, so the payload
  reflects the granted scope rather than a federated mode).

Each payload's field names self-describe which concept it demonstrates. None of
these response bodies are spec-defined — the spec governs headers and tokens, not
demo JSON.

## Running

Run all five at once:

```bash
make resources
```

Or individually:

```bash
dotnet run --project samples/MockResourceServers/Profile    # :5000
dotnet run --project samples/MockResourceServers/Calendar   # :5001
dotnet run --project samples/MockResourceServers/Trips      # :5002
dotnet run --project samples/MockResourceServers/Wallet     # :5003
dotnet run --project samples/MockResourceServers/Inbox      # :5004
```

Each serves `/.well-known/aauth-resource.json` and `/.well-known/jwks.json`
without an AAuth signature, plus an unauthenticated `GET /` index listing its
flows. Override the issuer with `--AAuth:Issuer https://my-rs.example` (or the
`AAuth__Issuer` env var).

See the per-server READMEs for the exchange details, and the
[samples README](../README.md) for end-to-end AgentConsole invocations.
