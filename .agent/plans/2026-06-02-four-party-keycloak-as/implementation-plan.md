# Implementation Plan: Four-Party (Federated) AAuth Example with Keycloak

Status: **in progress** — Phase 1 complete; Phase 2 next.

Created: 2026-06-02

Related research: [research.md](research.md)

## Confirmed decisions (2026-06-02)

- **Resource sample**: extend `samples/WhoAmI` with a new **isolated** federated
  branch (e.g. `/federated`), matching how WhoAmI already isolates `/hwk`,
  `/jwt`, `/jwt/admin`. No new resource project.
- **Scenario / scopes**: reuse the existing `whoami` / `whoami:admin` scopes.
- **PS↔AS trust (v1)**: **pre-established / claims-only** — the AS trusts the
  configured PS (like WhoAmI's `TrustedPersonServers`); per-request consent
  bubble-up is still demonstrated via a policy-driven `202`. Dynamic
  interaction-based account binding is deferred.
- **Runtime**: docker-outside-of-docker is available; AS policy backend is
  config-selected (`AccessServer__PolicyProvider=stub|keycloak`, default `stub`).

## Summary

Build an end-to-end four-party (federated) AAuth example where Keycloak backs
the Access Server (AS) role via a thin .NET AAuth↔Keycloak adapter. Each phase
below is a placeholder; expand scope, files, and decisions before implementing.
Each phase ends with a Definition of Done.

## Phase 1 — Pure-SDK Mock AS (no Keycloak) baseline

Goal: prove the four-party wire flow with a minimal SDK-only Access Server
before introducing Keycloak. Closes gaps G4 (partial), G5.

- _To populate: new `samples/MockAccessServer` serving
  `/.well-known/aauth-access.json` + JWKS, AAuth `/token` that verifies PS sig,
  verifies resource token (aud=AS), mints `aa-auth+jwt` (dwk=aauth-access.json)._
- _To populate: WhoAmI gains an isolated `/federated` branch that emits a
  resource token with `aud` = AS URL and verifies an AS-issued auth token._

Implementation Decisions:

- New `samples/MockAccessServer` project (port 5500) hosts the AS: serves
  `/.well-known/aauth-access.json` + `/.well-known/jwks.json`, and `POST /token`
  verifying the PS signature, verifying the resource token (`aud`=AS), and
  minting `aa-auth+jwt` (`dwk=aauth-access.json`). Policy is a hardcoded allow
  stub in this phase (the `IAccessPolicy` seam arrives in Phase 4).
- WhoAmI adds an isolated `/federated` verification + challenge branch (mirrors
  `/jwt`), with the challenge's resource-token `aud` set to the AS URL.
- Pre-established trust: AS trusts the configured PS issuer; resource trusts the
  AS issuer for `dwk=aauth-access.json` auth tokens.

Definition of Done:

- [x] Mock AS serves valid `aauth-access.json` + JWKS.
- [x] Resource issues a resource token with `aud` = AS URL.
- [x] AS verifies PS request and mints a spec-valid `aa-auth+jwt`.
- [x] A manual PS→AS `POST /token` returns `200` with a verifiable auth token.

Delivered:

- `samples/MockAccessServer/` (port 5500): `Program.cs`, `appsettings.json`,
  `Properties/launchSettings.json`, `README.md`; added to `AAuth.slnx`.
  Serves `/.well-known/aauth-access.json` + JWKS via
  `MapAAuthAccessServerWellKnown`; `POST /token` verifies the PS `jwks_uri`
  signature (with trusted-PS host pinning), verifies the body's `agent_token`
  (`VerifyWithJwksAsync`) and `resource_token` (`VerifyResourceTokenAsync`,
  `aud`=AS), and mints `aa-auth+jwt` with `Dwk = AuthTokenBuilder.AccessDwk`.
  Policy is a hardcoded allow stub.
- `samples/WhoAmI/Program.cs`: isolated `/federated` branch — `FederatedVerification()`
  (trusts the AS issuer for the auth token) + `ChallengeForFederated()`
  (resource-token `aud` = AS via `ChallengeOptions.PersonServerAudience`); new
  `/federated` endpoint + index entry. Config: `AAuth:AccessServer` (default
  `http://localhost:5500`).
- `tests/AAuth.Tests/Integration/MockAccessServerTests.cs`: 4 passing tests
  (metadata, mint bound to agent key with `dwk=aauth-access.json`, reject
  resource token with wrong `aud`, reject untrusted PS host). Hand-signs the
  PS→AS request with `AAuthClientBuilder.UseJwksUri`.
- Full suite green: 350 passed.

SDK note: no new public SDK API was needed — the Mock AS uses existing
`MapAAuthAccessServerWellKnown`, `TokenVerifier.VerifyWithJwksAsync` /
`VerifyResourceTokenAsync`, `AuthTokenBuilder` (with `AccessDwk`), and the
verification middleware already accepts `dwk=aauth-access.json` and
`ChallengeOptions.PersonServerAudience`.

## Phase 2 — PS→AS federation client in the SDK

Goal: SDK support for the signed PS-to-AS token request and the deferred loop.
Closes gaps G2, G6.

- _To populate: new `AccessServerClient` (build `{resource_token, agent_token,
  upstream_token?}`, sign via `jwks_uri`, handle `200/202/402`)._
- _To populate: PS-side Auth Token Delivery verification (7 checks)._

Implementation Decisions:

- _TBD._

Definition of Done:

- [ ] `AccessServerClient` performs a signed PS→AS token request.
- [ ] Handles `200` (auth token) and `202 requirement=claims`.
- [ ] PS verifies the AS auth token (iss/aud/agent/cnf/act/scope) before return.
- [ ] Unit tests in `tests/AAuth.Tests` cover the client.

## Phase 3 — MockPersonServer federation branch

Goal: `MockPersonServer` branches to federation when `resource_token.aud != self`.
Closes gaps G1, G3, G7 (pre-established trust).

- _To populate: discover AS, call `AccessServerClient`, return auth token._
- _To populate: respond to `requirement=claims` with directed `sub` + claims._

Implementation Decisions:

- _TBD._

Definition of Done:

- [ ] PS detects four-party (`aud != self`) and federates to the AS.
- [ ] PS still supports three-party (`aud == self`) unchanged.
- [ ] PS-AS collapse variant documented/demonstrated.

## Phase 4 — Keycloak as the policy engine (adapter)

Goal: replace the Mock AS policy stub with a real Keycloak decision via the
uma-ticket grant. Closes gap G4 (full).

- _To populate: Keycloak dev container + realm/client/resource/scope/policy import._
- _To populate: adapter maps `(resource iss, scope)` → `RESOURCE#SCOPE`, pushes
  PS claims via `claim_token`, calls `response_mode=decision`._
- _To populate: **config-selected policy backend** so the AS uses the stub by
  default and Keycloak when opted in (mirrors the existing
  `MockPersonServer__RequireConsent` env pattern). Toggle:
  `AccessServer__PolicyProvider=stub|keycloak` (default `stub`); optional
  graceful fallback to stub when `keycloak` is selected but unreachable._

Implementation Decisions:

- AS selection is **config-driven**, not a build-time choice: the same AS adapter
  binary runs either policy backend behind `IAccessPolicy` (S3). Default `stub`
  keeps `make e2e` / CI pure-.NET (no Docker); `make demo-federated` sets
  `keycloak` and boots Keycloak via docker-outside-of-docker.

Definition of Done:

- [ ] Keycloak realm import provisions resources, scopes, and policies.
- [ ] Adapter obtains a decision from Keycloak and gates auth-token issuance.
- [ ] Denied policy → spec-compliant `403`; granted → `200 aa-auth+jwt`.

## Phase 5 — Consent bubble-up from the AS (deferred interaction)

Goal: when a Keycloak policy needs a human, the AS returns `202
requirement=interaction`, the PS relays it, and the agent surfaces the consent
URL — reusing the existing call-chain interaction pattern. Closes gap G3/G7
(dynamic trust).

Reference implementation to mirror:
[samples/SampleApp/Components/Pages/CallChain.razor](../../samples/SampleApp/Components/Pages/CallChain.razor)
(two callbacks: `WithChallengeHandling.OnInteractionRequired` for the PS-exchange
`202`, `WithInteractionHandling.OnInteractionRequired` for the re-emitted/chained
`202`; both funnel to a shared `SurfaceInteraction`, then poll the pending URL).

- _To populate: AS adapter emits `202 + AAuth-Requirement: requirement=
  interaction; url=…; code=…` + `Location` pending URL when Keycloak signals a
  user decision is required; AS exposes a pending/poll endpoint._
- _To populate: PS relays/re-emits the AS `202` to the agent (same shape as the
  Orchestrator's chained `202`)._
- _To populate: map Keycloak "needs user" verdict → AAuth interaction (login/
  consent in Keycloak, or a stub approval endpoint for the demo)._

Implementation Decisions:

- _TBD._

Definition of Done:

- [ ] AS returns a spec-valid `202 requirement=interaction` with pending URL.
- [ ] PS relays the interaction; agent surfaces the consent URL and polls.
- [ ] Approve → `200 aa-auth+jwt`; deny → spec-compliant terminal error.

## Phase 6 — GuidedTour: four-party swimlanes

Goal: a Guided Tour run that visualizes all four parties, one swimlane each.

- _To populate: add `Actor.AccessServer` to
  [samples/GuidedTour/StepRecord.cs](../../samples/GuidedTour/StepRecord.cs)
  (today `Actor` has Agent/Resource/PersonServer/AgentProvider/Orchestrator)._
- _To populate: `StepRecord`s for resource token (`aud`=AS), agent→PS exchange,
  PS→AS federation, Keycloak decision (sub-step), AS-minted `aa-auth+jwt`, and
  the final agent→resource call; include the optional `202` consent detour._
- _To populate: wire a four-party tour option in `TourSession`/`TourOptions`._

Implementation Decisions:

- _TBD._

Definition of Done:

- [ ] Tour renders four distinct swimlanes (Agent, Resource, PS, Access Server).
- [ ] Each step shows request/response, signature base, and decoded tokens.
- [ ] The AS-issued auth token shows `dwk=aauth-access.json` and `cnf.jwk`.

## Phase 7 — SampleApp: four-party flow entry with consent bubble-up

Goal: a new SampleApp page for the four-party flow demonstrating consent
bubble-up, modeled on the call-chain page.

- _To populate: new `Components/Pages/Federated.razor` (nav entry + agent code
  panel) reusing the two-callback consent surface from `CallChain.razor`._
- _To populate: Playwright specs for the pre-granted (direct `200`) and deferred
  (`202` → approve popup → `200`) paths, mirroring `call-chain-deferred.spec.ts`._

Implementation Decisions:

- _TBD._

Definition of Done:

- [ ] SampleApp has a four-party page reachable from the nav.
- [ ] Pre-granted path completes with a direct `200` + `aa-auth+jwt`.
- [ ] Deferred path surfaces the AS consent URL and completes after approval.
- [ ] Playwright specs cover both paths.

## Phase 8 — End-to-end wiring & orchestration

Goal: a single command runs the full four-party demo. Closes gap G8.

- _To populate: `Makefile`/orchestrator target, README, port assignments for
  the AS adapter + federated resource + Keycloak container._
- _To populate: federated variants for **both** demo flavors, mirroring the
  existing `demo` (GuidedTour) / `demo-sample` (SampleApp) split:_
  - _`make demo-federated` \u2014 GuidedTour four-party + real Keycloak._
  - _`make demo-federated-sample` \u2014 SampleApp four-party + real Keycloak._
  - _`make demo-federated-stub` / `make demo-federated-sample-stub` \u2014 the same
    two flavors with the pure-.NET stub policy (no Docker)._
- _To populate: each target boots WhoAmI/MockResource + PS + AP + AS adapter +
  (Keycloak) + the relevant app, and sets `AccessServer__PolicyProvider`
  accordingly (mirrors how `demo`/`demo-sample` set
  `MockPersonServer__RequireConsent=true`)._

Implementation Decisions:

- _TBD._

Definition of Done:

- [ ] `make demo-federated` (GuidedTour) and `make demo-federated-sample`
      (SampleApp) each start Keycloak + AS adapter + resource + PS + agent.
- [ ] Matching `*-stub` targets run the same two flavors with no Docker.
- [ ] Agent completes a federated call end-to-end (Keycloak grant path).

## Phase 9 — End-to-end test through the full four-party flow

Goal: automated e2e coverage of the complete four-party flow, exercised through
the demos in the existing Playwright harness.

Reference harness:
[tests/e2e/playwright.config.ts](../../tests/e2e/playwright.config.ts)
(`webServer` array boots every backend + both apps; `guided-tour` and
`sample-app` projects). Consent is reset before every test by the auto-fixture
in [tests/e2e/helpers/fixtures.ts](../../tests/e2e/helpers/fixtures.ts); reuse
the helpers in [tests/e2e/helpers/consent.ts](../../tests/e2e/helpers/consent.ts)
and [tests/e2e/helpers/agents.ts](../../tests/e2e/helpers/agents.ts).

- _To populate: add Keycloak + AS adapter + federated resource to the
  `webServer` array (gate Keycloak readiness on `uma2-configuration`); add new
  URLs/agents to the helpers._
  [samples/SampleApp/playwright-tests/call-chain-deferred.spec.ts](../../samples/SampleApp/playwright-tests/call-chain-deferred.spec.ts)):
  pre-granted direct `200`, deferred `202`→approve→`200`, and a Keycloak deny
  path._
- _To populate: GuidedTour spec (mirror
  [samples/GuidedTour/playwright-tests/call-chain.spec.ts](../../samples/GuidedTour/playwright-tests/call-chain.spec.ts))
Implementation Decisions:

- **Default e2e uses the stub policy backend** (`AccessServer__PolicyProvider=
  stub`) so the suite boots entirely via `dotnet run` `webServer` entries — no
  Docker dependency in CI. A **separate opt-in spec/project** exercises the real
  Keycloak path when a daemon is available (docker-outside-of-docker), skipped
  otherwise.

Definition of Done:

- [ ] Playwright `webServer` boots Keycloak + AS adapter + federated resource.
- [ ] New GuidedTour spec (`samples/GuidedTour/playwright-tests/federated.spec.ts`)
      asserts the four swimlanes and the AS-issued auth token.
- [ ] New SampleApp spec(s) (`samples/SampleApp/playwright-tests/federated.spec.ts`,
      and `federated-deferred.spec.ts` for the consent path) cover grant,
      deferred-consent, and deny paths.
- [ ] Suite is green locally and in CI (`reuseExistingServer` honored).

## Phase 10 — Documentation

Goal: document the four-party flow, the Keycloak-backed AS, and the new demos.

- _To populate: expand
  [docs/workflows/federated-access.md](../../docs/workflows/federated-access.md)
  beyond the agent-only view — add the AS server-side code, the Keycloak
  decision hop, the `dwk=aauth-access.json` auth token, and the consent
  bubble-up sequence._
- _To populate: new doc (or section) for the AAuth↔Keycloak AS adapter — realm/
  client/resource/scope/policy setup, claim mapping, `uma-ticket` decision call._
- _To populate: README entries for the new samples (Mock/Adapter AS, federated
  resource) under [samples/README.md](../../samples/README.md); GuidedTour and
  SampleApp READMEs note the four-party flow._
- _To populate: cross-link from [docs/README.md](../../docs/README.md) and
  [docs/concepts.md](../../docs/concepts.md) (Access Server participant)._

Implementation Decisions:

- _TBD._

Definition of Done:

- [ ] `federated-access.md` covers AS server code, Keycloak, and consent bubble-up.
- [ ] Keycloak AS adapter setup is documented (realm/policy + claim mapping).
- [ ] Sample READMEs and the docs index reference the four-party demos.
- [ ] Mermaid diagrams render and in-repo links resolve.

## Phase 11 — SDK API investigation & design (consultation required)

Goal: after the demos prove the flow end-to-end, step back and harden the
**SDK public surface** so four-party is a first-class scenario for Client /
Resource / PS / AS authors — not bespoke sample glue. This phase is
investigation + design first; **no API is added or changed without explicit
sign-off from the user** (gate below).

> Note: individual APIs may be introduced in whichever earlier phase first needs
> them (tracked in the [research.md](research.md) "SDK API findings" table).
> This phase is where the **overall** public surface is revisited, reconciled,
> and ratified as a coherent whole.

Inputs: the friction discovered while building Phases 1–10, plus the current
surface ([AAuthClientBuilder.cs](../../src/AAuth/HttpSig/AAuthClientBuilder.cs),
[TokenExchangeClient.cs](../../src/AAuth/Agent/TokenExchangeClient.cs),
[AAuthApplicationBuilderExtensions.cs](../../src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs),
[WellKnownEndpoints.cs](../../src/AAuth/Server/WellKnownEndpoints.cs),
[AuthTokenBuilder.cs](../../src/AAuth/Tokens/AuthTokenBuilder.cs)).

Candidate improvements to evaluate (not commitments):

- **PS→AS federation client** — a public `AccessServerClient` (mirroring
  `TokenExchangeClient`) that builds the signed `{resource_token, agent_token,
  upstream_token?}` request, signs with the `jwks_uri` scheme, and follows the
  `200/202/402` loop. Candidate `WithChallengeHandling` option so the PS
  federates automatically when `resource_token.aud != self`.
- **AS server hosting helper** — a `MapAAuthAccessServer` / `UseAAuthAccessServer`
  extension (sibling to `MapAAuthResource`/`UseAAuthIntermediary`) that wires the
  AS token endpoint, PS-signature verification, resource-token verification, and
  `AuthTokenBuilder` minting.
- **Pluggable policy decision abstraction** — an `IAccessPolicy` /
  `AccessDecision` seam so the AS delegates allow/deny/needs-interaction to a
  provider (Keycloak adapter, in-memory stub, custom). Keeps Keycloak out of the
  core package.
- **Auth Token Delivery verification helper** — a reusable verifier for the
  PS-side 7-check validation of the AS response (today scattered across
  `TokenVerifier`).
- **Deferred/interaction ergonomics** — review whether the two-callback consent
  pattern (`WithChallengeHandling` + `WithInteractionHandling`) should be unified
  or documented as the canonical four-party shape.
- **Resource-side audience helper** — confirm `ChallengeOptions` explicit
  audience is the right ergonomics for "delegate to AS"; consider a named option.

Implementation Decisions:

- _To be filled during the consultation gate below._

### Consultation gate (required before any code)

1. Produce a short design note: proposed new public types/methods, signatures,
   namespaces, and backward-compat impact (additive vs breaking).
2. Present options/trade-offs to the user and **get explicit approval**.
3. Only then implement, with unit tests and updated docs.

Definition of Done:

- [ ] Design note enumerating proposed API additions/changes is written.
- [ ] User has reviewed and signed off on the design (recorded here).
- [ ] Approved APIs implemented with unit tests in `tests/AAuth.Tests`.
- [ ] Samples refactored to consume the new public surface (no bespoke glue).
- [ ] Public API surface / docs updated to match.

## Out of scope (for now)

| Item | Reason |
|---|---|
| Keycloak Java SPI / native `aa-auth+jwt` protocol mapper | High effort; adapter pattern keeps AAuth crypto in .NET. |
| `402` payment / billing flows | Not needed for the core demo. |
| Call chaining (`upstream_token`) in the four-party demo | Orthogonal; already covered elsewhere. |
| Production hardening (TLS, key rotation, HA Keycloak) | Demo runs on loopback HTTP. |
