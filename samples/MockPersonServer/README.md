# Mock Person Server

A minimal AAuth Person Server for end-to-end demos and integration tests.

> **Sample only — not part of the AAuth SDK.** This project illustrates how a Person Server can be built on top of the SDK; it is not a supported runtime component.

## What it does

- Serves PS discovery metadata at `/.well-known/aauth-person.json` (with `token_endpoint`).
- Serves its signing JWKS at `/.well-known/jwks.json`.
- Maps the token endpoint, the deferred-poll endpoint, and PS metadata in one
  call — [`app.MapAAuthPersonServer(...)`](../../docs/server/token-issuance.md#one-call-person-server-mapaauthpersonserver).
  The SDK owns the protocol (RFC 9421 signature verification, `resource_token`
  verification, the three-/four-party mint, PS→AS federation, and the mission
  three-gate + the normative `requirement=clarification` round-trip); this sample
  supplies only the **decisions** through DI seams:
  - `IIdentityClaimsAsserter` (`SampleIdentityClaimsAsserter`) — the directed
    identity, plus the non-mission `ConsentStore` gate.
  - `IMissionTokenConsent` (`ScriptMissionTokenConsent`) — the out-of-scope
    mission decision (grant / deny / clarify / hold), driven by the scripted
    `MissionConsentScript` (a stand-in for a live consent screen, or an LLM).
  - `IPersonPendingStore` (`ConsentBridgePersonPendingStore`) — bridges the demo
    `ConsentStore` into the SDK's id-keyed pending model.
- On `POST /token`, the mapper validates the signature, reads `resource_token`,
  and returns an `aa-auth+jwt` bound to the agent's confirmation key.
- When started with `RequireConsent=true`, the exchange defers instead:
  `POST /token` returns `202 Accepted` with `Location: /pending/{id}`, a
  `Retry-After`, and `AAuth-Requirement: requirement=interaction; url; code`. The
  agent then polls the signed `GET /pending/{id}` until the user decides:
  - **Approve** (`POST /interaction/approve`, or `POST /admin/consent` from a
    script) → next poll returns `200` with the `auth_token`.
  - **Deny** (`POST /interaction/deny`) → next poll returns `403` with
    `{"error":"denied"}`.
  - No action → the agent's polling budget eventually expires.
- `GET /interaction` renders a tiny built-in consent page used by the
  `GuidedTour` "Open consent page" button.

The mapper **verifies** the posted `resource_token` using the SDK helper
`TokenVerifier.VerifyResourceTokenAsync` (JWKS discovery against the issuing
resource per §Resource Token Verification): `typ`/`dwk`/signature, `exp`/`iat`,
`aud`, `agent`, and `agent_jkt`. Forged or expired tokens are rejected with
`invalid_resource_token` / `expired_resource_token`. The consent screen and the
issued auth token derive only from the verified token.

## Three-party vs four-party

The PS decides which role to play from the resource token's `aud` claim:

- **Three-party (collapsed PS+AS)** — `aud` is this PS. The PS *is* the
  authorization server: it applies its own policy (consent gate) and mints the
  auth token itself (`iss` = PS, `dwk` = `aauth-person.json`). This is the
  default flow exercised above.
- **Four-party (federated)** — `aud` is an *Access Server* the resource
  delegated authorization to. The PS does not mint the token; it verifies the
  resource token's agent binding, then forwards a **signed PS→AS request** via
  the SDK's `AccessServerClient` (`jwks_uri` scheme, the PS's key resolved from
  `{issuer}/.well-known/jwks.json`) and returns the **AS-issued** token
  (`iss` = AS, `dwk` = `aauth-access.json`). The AS owns policy, so the PS
  consent gate is skipped on this path.

The PS only federates to Access Servers listed in
`MockPersonServer:TrustedAccessServers`; any other `aud` is rejected with
`untrusted_access_server` (403).

> **One call, pluggable decisions.** Both branches above — the three-party
> collapsed mint and the four-party federation routing — are packaged by
> [`MapAAuthPersonServer`](../../docs/server/token-issuance.md#one-call-person-server-mapaauthpersonserver).
> This sample adopts that helper and injects its policy through the
> `IIdentityClaimsAsserter` / `IMissionTokenConsent` / `IPersonPendingStore`
> seams, while keeping its own browser consent + mission screens (the SDK leaves
> *how the PS authenticates the approving party* out of scope).

## Agent governance (missions)

Beyond minting tokens, this PS doubles as the **contextual policy point** for
the optional, orthogonal agent-governance layer (§Agent Governance). Governance
is wired with a single call — `builder.Services.AddAAuthGovernance()` — which
registers an in-memory mission store and log; the sample then supplies the
policy and user-channel seams (`IPermissionDecider`, `IAuditSink`,
`IInteractionRelay`, and `IMissionTokenConsent` for the out-of-scope token gate)
plus a deterministic consent script that stands in for a real user-consent screen.

It serves the four governance endpoints from the protocol exchange diagram:

| Endpoint | Spec | Purpose |
|---|---|---|
| `POST /mission` | §Mission Creation | The agent proposes a mission in natural language; the PS stores the approval bytes verbatim, computes `s256`, and returns the `AAuth-Mission` header (`approver`, `s256`). |
| `POST /permission` | §Permission Endpoint | The agent asks whether an action is allowed. Pre-approved tools on the active mission short-circuit to *granted*; everything else runs the three-gate decision (in-scope / prior consent / prompt the user). |
| `POST /audit` | §Audit Endpoint | The agent reports an action it took; the PS appends it to the mission log (fire-and-forget). |
| `POST /mission-interaction` | §Interaction Endpoint | The agent relays a question, payment, or completion proposal to the user through the PS. |

The **mission token gate** (silent in-scope grant, prior-consent, the
out-of-scope decision, and the clarification chat) is owned by
`MapAAuthPersonServer` and resolves under the unified `/pending/{id}` poll; the
`IMissionTokenConsent` seam supplies the decision. The governance endpoints'
own deferred prompts (`POST /permission`, mission creation) resolve via
`POST /permission-pending/{id}` and `POST /mission-create-pending/{id}`.

A **mission-aware resource** copies the mission object (`approver`, `s256`) from
the `AAuth-Mission` header into the resource token it issues (§Resource Token
Verification, Terminology: *mission-aware resource*); the PS then has full
mission context when it evaluates each downstream hop. Try it end-to-end with
the [MissionAgent](../MissionAgent/README.md) CLI (`make demo-mission`).

## Run

```bash
dotnet run --project samples/MockPersonServer
# → http://localhost:5100
```

Pair it with `samples/MockResourceServers/Calendar` (configured with `AAuth:Issuer=http://localhost:5001`)
and exercise the three-party flow with `samples/AgentConsole`:

```bash
# Terminal 1
ASPNETCORE_URLS=http://localhost:5100 \
  dotnet run --project samples/MockPersonServer

# Terminal 2
ASPNETCORE_URLS=http://localhost:5001 \
  dotnet run --project samples/MockResourceServers/Calendar

# Terminal 3
dotnet run --project samples/AgentConsole -- \
  http://localhost:5001 --ap http://localhost:5301 --ps http://localhost:5100
```

## Configuration

| Key | Default | Purpose |
|---|---|---|
| `AAuth:Issuer` | `http://localhost:5100` | PS issuer URL — must match what agents put in their agent token's `ps` claim |
| `AAuth:SignatureWindow` | `60` | RFC 9421 `created` freshness window, in seconds |
| `MockPersonServer:RequireConsent` | `false` | When `true`, `POST /token` returns `202 + Location` and the user must approve or deny via `/interaction/{approve,deny}` before the poll resolves. `make demo` sets this to `true`. |
| `MockPersonServer:TrustedAccessServers` | `["http://localhost:5500"]` | Access Servers this PS will federate to in the four-party flow (resource token `aud` ≠ PS). Any other `aud` is rejected with `untrusted_access_server`. |
