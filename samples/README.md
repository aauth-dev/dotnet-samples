# Samples

Sample applications demonstrate AAuth flows end-to-end. The eight Aria
resource servers (Profile, Calendar, Trips, Wallet, Inbox, Bookings, Catalog, Documents) live under
[MockResourceServers/](MockResourceServers/); the two access servers (Federated,
R3) live under [MockAccessServers/](MockAccessServers/).

| Sample | Port | Description |
|--------|------|-------------|
| [Profile](MockResourceServers/Profile/) | 5000 | JWT identity access plus explicitly generic HWK, direct JWKS and naming-JWT demonstrations |
| [Calendar](MockResourceServers/Calendar/) | 5001 | PS-Asserted (three-party) resource server — `/events` (`calendar.read`), `/events/write` (`calendar.write`), `/events/admin` (role `calendar.owner`) |
| [Trips](MockResourceServers/Trips/) | 5002 | Mission-aware resource server — `/trips` (`trips.read`), `/trips/book` (`trips.book`) |
| [Wallet](MockResourceServers/Wallet/) | 5003 | Federated (four-party) resource server — `/wallet` (`wallet.read`), `/wallet/charge` (`wallet.charge`) |
| [Inbox](MockResourceServers/Inbox/) | 5004 | Resource-Managed (two-party) resource server — manages authorization itself via its own consent page; issues an opaque `AAuth-Access` token (`GET /messages`, `POST /authorize`) |
| [Bookings](MockResourceServers/Bookings/) | 5005 | Rich Resource Requests (R3, four-party) resource server — dining & experiences reservations via the **OpenAPI** vocabulary; `searchAvailability`/`holdReservation` → `r3_granted`, `confirmReservation` → `r3_per_call` (per-call proposal) |
| [Catalog](MockResourceServers/Catalog/README.md) | 5006 | Travel catalog reads through one merged OpenAPI definition with renamed colliding operation IDs |
| [Documents](MockResourceServers/Documents/README.md) | 5007 | Resource release permission before PS consent, with account-bound signed download |
| [Concierge](Concierge/) | 5200 | Intermediate service — call chaining with nested `act` delegation |
| [MissionAgent](MissionAgent/) | — | CLI agent — drives the optional, orthogonal **agent governance** layer: proposes a mission, asks per-action permission, records audit, and relays interactions through a PS (§Agent Governance) |
| [MockPersonServer](MockPersonServer/) | 5100 | Reference Person Server — verifies exchanges, mints auth tokens, federates to an Access Server. **Sample only — not part of the AAuth SDK.** |
| [MockAgentProvider](MockAgentProvider/) | 5301 | Reference Agent Provider — issues agent tokens, hosts JWKS. **Sample only — not part of the AAuth SDK.** |
| [MockAccessServer](MockAccessServers/Federated/) | 5500 | Reference Access Server (Federated) — the fourth party in federated access; evaluates policy (stub or Keycloak) and mints `aa-auth+jwt` (`dwk=aauth-access.json`). **Sample only — not part of the AAuth SDK.** |
| [R3 Access Server](MockAccessServers/R3/) | 5501 | Dedicated Access Server for Rich Resource Requests — fetches/hash-verifies R3 documents, splits granted vs per-call by policy, mints R3 auth tokens (guards Bookings). **Sample only — not part of the AAuth SDK.** |
| [GuidedTour](GuidedTour/) | 5400 | Blazor walk-through — visualises every AAuth flow step by step, including the four-party federated flow |
| [SampleApp](SampleApp/) | 5240 | Golden example — one page per signing mode (hwk, jwks_uri, jkt-jwt, jwt, call chain, federated four-party) plus the resource-managed Inbox |
| [AgentConsole](AgentConsole/) | — | CLI agent — signs requests, handles challenges, exchanges with a PS |
| [EventAgent](EventAgent/README.md) | None | Single-shot Events CLI; the shared EventSupport client also powers both apps' `/events` pages |
| [LiveWhoAmITest](LiveWhoAmITest/) | 5199 | Live interop test against `whoami.aauth.dev` + `person.hello.coop` — exercises all 3 protocol modes over a public tunnel |

## Quick Start

Both primary apps expose `/wallet-protocol` (AS clarification, chaining an AS-issued grant,
federated revocation), `/catalog-gateway`, `/documents` and `/events`. See the
[Wallet guide](../docs/workflows/wallet-protocol.md),
[Document Release guide](../docs/workflows/document-release.md),
[Catalog guide](../docs/workflows/catalog-gateway.md) and
[Events guide](../docs/workflows/events.md) for exact steps and rejection/recovery
paths. CapabilitySupport and EventSupport share code between the two apps; they
are libraries, not additional servers.

### Network Admission

The SDK defaults to HTTPS, exact lowercase server identifiers, and public
destination addresses. These samples explicitly use the loopback origin list in
[SampleEgress.cs](SampleEgress.cs), shared through
[Directory.Build.props](Directory.Build.props). Changing a sample to another
local port requires adding that exact origin to the policy. Neither the host
environment nor a test process name enables a network exception. HTTPS private
destinations remain blocked.

`SampleEgress.Policy` in SampleApp and GuidedTour snippets is that explicit
configuration, not an SDK global. `SampleHttpClient` uses the SDK's pinned
transport; capture handlers in GuidedTour wrap the same transport. The sample
request deadline is 45 seconds to accommodate 30-second long polls, and each
response is limited to 1 MiB. Production defaults use a 10-second request deadline.

For a standalone local caller, configure only the origins it needs:

```csharp
var policy = AAuth.Discovery.AAuthEgressPolicy.ForDevelopmentLoopback(
  "http://localhost:5100", "http://localhost:5400");
var metadata = new AAuth.Discovery.MetadataClient(policy: policy);
var document = await metadata.FetchAsync(
  metadata.GetUrl("http://localhost:5100", "aauth-person.json"));
using var client = new AAuthClientBuilder(key)
  .WithEgressPolicy(policy)
  .UseJwt(agentToken)
  .Build();
```

Injected clients require `AAuthHttpTransport.AttachPolicy` and an explicit
transport contract. `EnforcesEgressPolicy` is a caller obligation to enforce
DNS/address admission and connection pinning and disable proxies and redirects;
attaching it cannot repair an opaque handler. `InProcessOnly` is for fixtures
that perform no network I/O or forwarding. Cross-origin JWKS links require
an explicit source/target origin pair in `AAuthEgressPolicy`.

Browser interaction destinations are admitted before the SDK invokes a callback.
The SDK cannot pin a separate browser's connections; browser and deployment
network controls remain responsible for subsequent navigation.

### Start the Stack

Browser demo consent is disabled unless `AAuth__EnableIsolatedDemoConsent=true`.
The `demo`, `demo-mission`, `demo-keycloak`, `ps-consent` and `resources` make
targets and the Playwright fixture explicitly enable it. Direct `dotnet run`
does not. The demo sign-in button selects a simulated single-user identity; it
does not authenticate a person and is not suitable for Internet deployment.
No password or other host credential is embedded by this consent feature.

Run an enabled demo only on loopback listeners under your OS account in an
isolated development environment. Do not publish its ports, tunnel it, or put
a public reverse proxy in front of it. The browser helper checks both the
actual peer address and Host for loopback; those checks do not establish OS
user identity and cannot protect a host deliberately forwarding public traffic
as localhost. The samples also contain unsigned demo administration endpoints.
Use OS permissions, firewall rules and private port-forwarding controls to
restrict access. Keycloak mode never enables the stub approval endpoints.

Production hosts must authenticate browser users and configure
`BrowserConsentSessions` with `authorizePerson`. The callback must bind the
pending request to the authenticated person using the host's enrollment/account
mapping. The helper binds a decision to a stable subject, issuer and
authentication type from one authenticated identity, not `Identity.Name`.
It denies missing or ambiguous identity and missing authorization policy.
An external-login callback must complete and validate its identity-provider
flow and authorize the person before mutating pending state; the browser state
check alone is not identity-provider authentication.

The interaction code is a separate, generated Crockford correlation value,
not the signed pending URL identifier. Each new consent round gets a new code
and invalidates earlier decision sessions. Opening the URL does not approve it;
approval/denial requires the session-bound CSRF form and the host's person
authorization. Unknown GET parameters cannot invalidate another request.
Protected code attempts can name their own decision session; five failures
terminate only that authenticated scope. Unscoped guesses are throttled by
address and browser budget, not assigned to an arbitrary victim.

In-memory pending records expire and retain an additional one-hour diagnostic
window. After eviction or restart, well-formed missing pending identifiers
return 410, without asserting that they previously existed. Malformed paths
remain unknown; browser codes return `invalid_code` after their retained
context is gone, and `expired` while the expired context remains available.
These stores do not provide crash durability or distributed abuse controls.

The fastest way to run all samples together:

```bash
make demo
```

The `demo`, `demo-mission` and `demo-keycloak` targets keep persistent draft-10
sample keys, enrollment records and databases under
`$XDG_DATA_HOME/aauth-samples/v10/home` (or
`~/.local/share/aauth-samples/v10/home` when `XDG_DATA_HOME` is unset).
They set the services' `HOME` and `XDG_DATA_HOME` to that isolated location while
reusing your existing .NET and NuGet caches. Earlier `~/.aauth` keys are left
untouched; keys created before the required JWK `alg` member was introduced are
not silently accepted or overwritten. Restarts reuse the same demo state.
Set `DEMO_HOME` to an absolute directory to select another demo state location.

Run only one stack at a time: stop an existing demo with `Ctrl+C` before starting
another, since the services use fixed ports. Individual `dotnet run` commands
use your normal environment; supply the same `HOME` and `XDG_DATA_HOME` if they
need to share the demo's persisted state.

This starts Profile + Calendar + Trips + Wallet + Inbox + Bookings + Catalog + Documents + Concierge + MockPersonServer + MockAgentProvider + Federated AS (stub) + R3 AS + GuidedTour + SampleApp in parallel, prints their URLs, and tears them down on `Ctrl+C`. Then open the **GuidedTour** at <http://localhost:5400> and click **Run all**, or the **SampleApp** at <http://localhost:5240>.

For the **four-party (federated)** flow with an Access Server, `make demo` already
includes a stub Access Server (no Docker). For the live Keycloak policy engine,
use the Keycloak variant:

```bash
make demo-keycloak   # both UIs + real Keycloak policy engine (Docker)
```

The Keycloak target boots the Access Server with the Keycloak policy engine; log
in as `demo`/`demo` (has the `wallet.payer` role) or `guest`/`guest` (read-only). See
[Federated Access](../docs/workflows/federated-access.md) and the
[Mock Access Server README](MockAccessServers/Federated/README.md).

For the optional **agent governance** layer — an agent operating under a
human-approved mission, with the PS as the contextual policy point — use the
mission stack (§Agent Governance is orthogonal to the access modes above):

```bash
make demo-mission     # AP + PS + Trips for the MissionAgent CLI
make agent-mission    # drive it from another terminal
```

See the [MissionAgent README](MissionAgent/README.md).

## Running Individually

### Profile (Identity-Based Resource Server)

```bash
dotnet run --project samples/MockResourceServers/Profile
```

Profile deliberately enables generic Signature Keys alongside agent-JWT identity:

| Path | Mode | Verification / Policy |
|------|------|-----------------------|
| `/pseudonymous` | Pseudonymous | HTTP signature only — resource sees key thumbprint (`jkt`) |
| `/anchored` | Pseudonymous (key delegation) | Signature only — agent known by durable key thumbprint via naming JWT |
| `/identified` | Verified identity | Agent JWT issuer/key verification, or explicitly generic direct `jwks` discovery |

### Calendar (PS-Asserted Resource Server)

```bash
dotnet run --project samples/MockResourceServers/Calendar
```

| Path | Mode | Verification / Policy |
|------|------|-----------------------|
| `/events` | Three-party JWT | Full issuer verification + `aud` + PoP, scope `calendar.read` |
| `/events/write` | Three-party (step-up) | Elevated scope `calendar.write` |
| `/events/admin` | Three-party (RBAC) | Role `calendar.owner` from the auth token's `roles` claim |

### Trips (Mission-Aware Resource Server)

```bash
dotnet run --project samples/MockResourceServers/Trips
```

| Path | Mode | Verification / Policy |
|------|------|-----------------------|
| `/trips` | Three-party (mission-aware) | Scope `trips.read` — in-mission, granted silently |
| `/trips/book` | Three-party (mission-aware) | Scope `trips.book` — out-of-mission, prompts for approval |

### Wallet (Federated Resource Server)

```bash
dotnet run --project samples/MockResourceServers/Wallet
```

| Path | Mode | Verification / Policy |
|------|------|-----------------------|
| `/wallet` | Four-party | Scope `wallet.read` — verified against the Access Server |
| `/wallet/charge` | Four-party (step-up) | Scope `wallet.charge` — requires the AS `wallet.payer` role |

### Inbox (Resource-Managed Resource Server)

```bash
dotnet run --project samples/MockResourceServers/Inbox
```

| Path | Mode | Verification / Policy |
|------|------|-----------------------|
| `/messages` | Resource-managed (reactive) | Verified agent JWT and HTTP proof; first call returns `202` for Inbox consent, then requires the key/account-bound opaque `AAuth-Access` credential |
| `/authorize` | Resource-managed (proactive) | Signed `POST { "scope" }` — same consent path (§Authorization Endpoint Request) |

The Inbox manages authorization **itself** (two-party, no PS/AS) and issues an
opaque `AAuth-Access` token bound to the agent's signature. See
[MockResourceServers/Inbox/README.md](MockResourceServers/Inbox/README.md).

All paths serve `/.well-known/aauth-resource.json` and `/.well-known/jwks.json` without requiring a signature.

Override the issuer: `--AAuth:Issuer https://my-rs.example` (or env var `AAuth__Issuer`).

Browse discovery:

```bash
curl http://localhost:5001/.well-known/aauth-resource.json
curl http://localhost:5001/.well-known/jwks.json
```

### AgentConsole

When the target URL has no path, AgentConsole maps explicitly chosen generic
schemes to Profile: `hwk` to `/pseudonymous`, `jkt-jwt` to `/anchored`, and `jwks`
to `/identified`. The default `jwt` uses Calendar `/events`; resource-managed
uses Inbox `/messages`. JWT does not require a PS, so pass an explicit Profile
`/identified` URL for agent-identity-only access. See
[AgentConsole](AgentConsole/README.md) for setup and endpoint choices.

**Generic pseudonymous HWK signing** (explicit; the CLI default is JWT):

```bash
dotnet run --project samples/AgentConsole -- http://localhost:5000/pseudonymous --ap http://localhost:5301 --signing-mode hwk
```

**Pseudonymous with key delegation (JKT-JWT):**

```bash
dotnet run --project samples/AgentConsole -- http://localhost:5000 \
  --ap http://localhost:5301 --signing-mode jkt-jwt
```

**Generic direct JWKS identity:**

```bash
dotnet run --project samples/AgentConsole -- http://localhost:5000 \
  --ap http://localhost:5301 --signing-mode jwks
```

**Three-party flow** (agent advertises a PS; resource challenges; agent exchanges — grant consent first):

```bash
dotnet run --project samples/AgentConsole -- http://localhost:5001 \
  --ap http://localhost:5301 --ps http://localhost:5100
```

**Three-party with elevated scope (`/events/write`)** — grant consent for scope `calendar.write`:

```bash
dotnet run --project samples/AgentConsole -- http://localhost:5001/events/write \
  --ap http://localhost:5301 --ps http://localhost:5100 --signing-mode jwt
```

**Three-party with RBAC (`/events/admin`)** — the PS asserts roles `calendar.owner` and groups `demo-users`:

```bash
dotnet run --project samples/AgentConsole -- http://localhost:5001/events/admin \
  --ap http://localhost:5301 --ps http://localhost:5100 --signing-mode jwt
```

**Four-party with payment (`/wallet/charge`)** — the Access Server requires the `wallet.payer` role (log in as `demo`):

```bash
dotnet run --project samples/AgentConsole -- http://localhost:5003/wallet/charge \
  --ap http://localhost:5301 --ps http://localhost:5100 --signing-mode jwt
```

> **Note:** `make demo` starts MockPersonServer with `RequireConsent=true`, so three-party flows (`jwt`, `jkt-jwt`) will print an interaction URL for user approval:
>
> ```
> [interaction] User approval required: http://localhost:5100/interaction?code=...
> ```
>
> Open that URL in a browser and click **Approve**, or pre-approve programmatically:
>
> ```bash
> curl -X POST http://localhost:5100/admin/consent \
>   -H "Content-Type: application/json" \
>   -d '{"agent":"aauth:demo@ap.example","resource":"http://localhost:5001","scope":"calendar.read"}'
> ```
>
> To skip consent entirely, start MockPersonServer separately without the flag: `dotnet run --project samples/MockPersonServer`

| Flag | Default | Purpose |
|------|---------|---------|
| `--ap <url>` | _(required)_ | Agent Provider URL (enrol + refresh endpoints) |
| `--sub <id>` | `aauth:demo@ap.example` | Agent subject identifier |
| `--ps <url>` | _(none)_ | Person Server URL — enables three-party flow |
| `--signing-mode <mode>` | `jwt` | JWT for AAuth; explicit `hwk`, `jwks`, `jkt-jwt` for generic demonstrations |
| `--prefer-wait <seconds>` | _(none)_ | Long-poll hint for deferred PS responses |
| `--upstream-token <jwt>` | _(none)_ | Upstream auth token for call-chaining scenarios |

### MockPersonServer

```bash
dotnet run --project samples/MockPersonServer
```

Verifies the RFC 9421 signature on the exchange request, parses the `resource_token`, and mints an `aa-auth+jwt` bound to the agent's confirmation key. See [MockPersonServer/README.md](MockPersonServer/README.md) for consent mode and admin endpoints.

### MockAgentProvider

```bash
dotnet run --project samples/MockAgentProvider
```

Implements AP enrollment and JWKS hosting. See [MockAgentProvider/README.md](MockAgentProvider/README.md) for details.

### GuidedTour

```bash
dotnet run --project samples/GuidedTour
```

Requires the resource servers (Profile, Calendar, Trips, Wallet, Inbox), MockPersonServer, Concierge, and MockAgentProvider already running (or use `make demo`). See [GuidedTour/README.md](GuidedTour/README.md) for mode configuration.

### SampleApp

```bash
dotnet run --project samples/SampleApp
```

Simple Blazor app showing each signing mode as a separate page. Open <http://localhost:5240>. Requires the resource servers (Profile, Calendar, Trips, Wallet, Inbox), MockPersonServer, and Concierge running. MockAgentProvider is needed only for the JWKS-URI enrollment page.

### LiveWhoAmITest

```bash
dotnet run --project samples/LiveWhoAmITest
```

Live interop test that runs against the public reference servers (`whoami.aauth.dev` and `person.hello.coop`) instead of the local mocks. It generates an agent key, starts a local metadata + JWKS endpoint on port 5199, exposes it via a `cloudflared` quick tunnel, and exercises all three protocol modes:

- **Mode 1** — unsigned request returns `401` + `Accept-Signature`.
- **Mode 2** — `aa-agent+jwt` returns the agent identity (no scope) or a `401` + `AAuth-Requirement` resource token (scoped).
- **Mode 3** — full three-party flow: agent token → resource token → PS exchange → auth token → identity claims.

Requires `cloudflared` on the `PATH` (preinstalled in the dev container) and outbound network access. Mode 3 may prompt for user consent at `person.hello.coop`; the agent prints the interaction URL to approve in a browser.

## Make Targets

```bash
make help            # list available targets
make build           # dotnet build AAuth.slnx
make restore         # restore NuGet packages
make test            # run all tests (SDK + conformance)
make test-unit       # SDK unit + integration tests only
make test-conformance # spec conformance tests only
make demo            # start the full stack (resource servers + Concierge + PS + AP + AS + both UIs)
make resources       # only the five Aria resource servers (Profile :5000, Calendar :5001, Trips :5002, Wallet :5003, Inbox :5004)
make ps              # MockPersonServer (port 5100)
make ps-consent      # MockPersonServer with RequireConsent=true
make ap              # MockAgentProvider (port 5301)
make tour            # GuidedTour (port 5400; expects other services running)
make sampleapp       # SampleApp (port 5240; expects other services running)
make agent           # AgentConsole against the Profile server (override URL=…)
make live            # LiveWhoAmITest against whoami.aauth.dev (needs cloudflared + network)
make clean           # dotnet clean + remove bin/ obj/
```
