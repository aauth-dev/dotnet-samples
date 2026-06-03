# Implementation Plan: Four-Party (Federated) AAuth Example with Keycloak

Status: **in progress** — Phases 1–4 complete (Phase 4 absorbs Phase 5);
Phase 6 complete (GuidedTour four-party swimlanes + arrow rendering + demo
parity). Phase 7 (SampleApp) next.

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
  upstream_token?}`, sign via `jwks_uri`, handle `200/202`)._
- _To populate: PS-side Auth Token Delivery verification (7 checks)._

Implementation Decisions (confirmed 2026-06-02):

- **Namespace**: `AccessServerClient` lives in `AAuth.Tokens`, co-located with
  its PS-side collaborators `AuthTokenResponseValidator` and
  `UpstreamTokenValidator` (this is PS-side federation code, not agent-side like
  `TokenExchangeClient`, nor inbound ASP.NET middleware like `AAuth.Server`).
- **Surface**: `AccessServerClient(HttpClient signedClient, MetadataClient,
  AuthTokenResponseValidator)` + `AccessServerRequest` (ResourceToken,
  AgentToken, UpstreamToken?, expected iss/aud/agent/jkt, OnInteractionRequired?,
  PollerOptions?). Mirrors `TokenExchangeClient` (SSRF same-origin pinning,
  https-or-loopback enforcement, `AAuthDiagnostics` activities).
- **Delivery verification**: reuse the existing
  `AuthTokenResponseValidator.ValidateAsync` (already implements all 7 delivery
  steps: sig/iss/aud/agent/cnf/act/scope-narrowing). No new verifier API.
- **`202` deferred loop**: reuse the existing `DeferredPoller` /
  `OnInteractionRequired` callback (same as `TokenExchangeClient`).
- **`402` Payment Required**: surface a typed `AAuthPaymentRequiredException`
  carrying `Location` + `WWW-Authenticate`; settlement is **out of scope**
  (spec excludes it). Minimum spec-aligned recognition, no x402/MPP import.
- **`requirement=claims`**: handled in **Phase 11** (now implemented). It is a
  conditionally-MUST, distinct active-push mechanism (not a poll). When an
  `OnClaimsRequired` callback is configured the client resolves + POSTs the
  directed `sub` + claims to the `Location` and resumes the loop; when no handler
  is configured it still surfaces a clear terminal error (`NotSupportedException`,
  "claims required but no handler configured"). The Phase 11 addition was purely
  additive.

Definition of Done:

- [x] `AccessServerClient` performs a signed PS→AS token request.
- [x] Handles `200` (auth token) and the `202` deferred poll loop.
- [x] Recognizes `402` and surfaces `AAuthPaymentRequiredException`.
- [x] PS verifies the AS auth token (iss/aud/agent/cnf/act/scope) before return
      via `AuthTokenResponseValidator`.
- [x] An unhandled `requirement=claims` surfaces a clear terminal error.
- [x] Unit tests in `tests/AAuth.Tests` cover the client.

Delivered:

- `src/AAuth/Tokens/AccessServerClient.cs` (namespace `AAuth.Tokens`): signed
  PS→AS federation client. Discovers `aauth-access.json` `token_endpoint`
  (https-or-loopback + same-origin SSRF guard), POSTs signed
  `{resource_token, agent_token, upstream_token?}` (`Prefer: wait` honored),
  handles `200`, the `202` deferred poll loop (reuses `DeferredPoller` +
  `OnInteractionRequired`), `402` → `AAuthPaymentRequiredException`, and
  `202 requirement=claims` → claims push when `OnClaimsRequired` is set, else
  `NotSupportedException` (handler implemented in Phase 11).
  Runs the 7-step §Auth Token Delivery via `AuthTokenResponseValidator` and
  throws `TokenVerificationException` on failure.
- `src/AAuth/Tokens/AccessServerRequest.cs`: `required` request payload +
  delivery-verification context + deferred-consent options.
- `src/AAuth/Errors/AAuthPaymentRequiredException.cs`: typed `402` carrying
  `Location` + `WWW-Authenticate`; settlement out of scope.
- `tests/AAuth.Tests/AccessServerClientTests.cs`: 6 unit tests (stub AS) —
  success path, upstream-token passthrough, `402`, `requirement=claims`,
  audience-mismatch delivery failure, structured token-endpoint error.
- Full suite green: 356 passed (was 350).

SDK note: new public surface (`AccessServerClient`, `AccessServerRequest`,
`AAuthPaymentRequiredException`) — additive only. Reuses existing
`AuthTokenResponseValidator` (7-step delivery) and `DeferredPoller`. Overall
surface still ratified under the Phase 12 consultation gate.

## Phase 3 — MockPersonServer federation branch

Goal: `MockPersonServer` branches to federation when `resource_token.aud != self`.
Closes gaps G1, G3, G7 (pre-established trust).

- _To populate: discover AS, call `AccessServerClient`, return auth token._
- `requirement=claims` response (directed `sub` + claims): implemented in
  **Phase 11** via the `OnClaimsRequired` callback + `demoUserClaims` (see that
  phase's Delivered section).

Implementation Decisions:

- **Routing key**: the PS peeks the (unverified) `resource_token.aud` to decide
  three-party vs four-party — `aud == PsIssuer` → mint directly (collapsed
  PS+AS, unchanged); `aud != PsIssuer` → federate. The token is fully verified
  on whichever branch is taken, so the unverified peek is routing-only.
- **Trust**: `MockPersonServer:TrustedAccessServers` (default
  `["http://localhost:5500"]`) gates which `aud` values the PS will federate to;
  any other `aud` → `403 untrusted_access_server`. Mirrors WhoAmI's
  `TrustedPersonServers` pattern (pre-established trust, v1).
- **Federation transport**: `AccessServerClient` registered as a singleton built
  from the DI `MetadataClient`/`JwksClient` + `AuthTokenResponseValidator`; its
  signed PS→AS client uses `AAuthClientBuilder(psKey).UseJwksUri(...)` over a
  named `"aauth-federation"` `HttpClient` so tests can route the transport
  in-process.
- **Four-party path delegates policy to the AS**: the PS skips its own consent
  gate and its `UpstreamTokenValidator` on the federated path (the AS owns
  policy and validates the `act` chain). Consent bubble-up from the AS is
  Phase 5; `requirement=claims` active push is Phase 11.
- **Pre-forward check**: the PS still verifies the resource token's agent
  binding (`agent`/`agent_jkt`, signature, `aud`=AS) before relaying it, and
  reads `iss` (resource URL) + `scope` to drive the `AccessServerRequest`.
- **No new public SDK API** — Phase 3 is sample-only; it consumes the Phase 2
  `AccessServerClient`.

Definition of Done:

- [x] PS detects four-party (`aud != self`) and federates to the AS.
- [x] PS still supports three-party (`aud == self`) unchanged.
- [x] PS-AS collapse variant documented/demonstrated.

Delivered:

- `samples/MockPersonServer/Program.cs`: four-party branch in `POST /token` —
  peeks `resource_token.aud` (`PeekJwtAudience`), gates on
  `MockPersonServer:TrustedAccessServers` (`403 untrusted_access_server`),
  verifies the resource token's agent binding (`aud`=AS), then federates via the
  DI-registered `AccessServerClient` (signed `jwks_uri` client over the named
  `"aauth-federation"` `HttpClient`) and returns the AS-issued token. Relays
  `AAuthTokenExchangeException` (AS error code/status), `402` →
  `payment_required`, and a failed delivery verification → `502
  invalid_auth_token`. Three-party (`aud == PsIssuer`) path unchanged.
- `samples/MockPersonServer/README.md`: new "Three-party vs four-party" section
  + `TrustedAccessServers` config row.
- `tests/AAuth.Tests/Integration/MockPersonServerFederationTests.cs`: 3 passing
  tests (federates to AS and returns the AS-minted token; rejects untrusted AS
  with `403`; three-party direct mint still works) using an in-process
  `FederatedStub` that serves both the resource and AS discovery and mints the
  AS auth token.
- Full suite green: 359 passed (was 356).

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

### Confirmed decisions (2026-06-02, user answered)

- **Scope**: full Phase 4 — `IAccessPolicy` seam + `StubAccessPolicy` +
  `KeycloakAccessPolicy` + Keycloak realm import. Docker only for the demo
  target, not CI.
- **Phase 5 is ABSORBED into Phase 4**: the user chose the full interactive
  Keycloak login + consent now. The AS emits `202 requirement=interaction`, the
  PS relays it, and the agent surfaces the consent URL and polls. (Phase 5's
  former DoD is folded in below; the standalone Phase 5 section is retired.)
- **Decision mechanism**: interactive Keycloak user session (OIDC
  authorization-code login + consent), then the `uma-ticket` grant with the
  user's subject token and `response_mode=decision`. PS-asserted claims are
  still pushed via `claim_token` for ABAC augmentation.
- **Demo policy**: `whoami` granted to any verified agent once a Keycloak user
  has authenticated; `whoami:admin` granted only when the PS asserts an admin
  role/group claim (mirrors WhoAmI `/jwt` vs `/jwt/admin`).
- **Testing**: unit-test `KeycloakAccessPolicy` and the AS interactive flow
  against a **stub Keycloak `HttpMessageHandler`** (fake uma-ticket + token +
  authorization endpoints; the OIDC callback is driven directly with a fake
  code). Default `stub` keeps `make e2e`/CI pure-.NET (no Docker).
- **Unreachable fallback**: **fail closed** — if `PolicyProvider=keycloak` and
  Keycloak is unreachable, return a `5xx`/deny. No silent fallback to the allow
  stub.

### Delivery sub-steps (each independently committable)

- **A** (docker-free): `IAccessPolicy`/`AccessDecision` seam in
  `MockAccessServer`; refactor the allow-stub into `StubAccessPolicy`;
  `AccessServer:PolicyProvider=stub|keycloak` selection (default `stub`);
  fail-closed wiring. Unit tests against the stub.
- **B**: `KeycloakAccessPolicy` — OIDC login/consent + `uma-ticket`
  `response_mode=decision`; returns `AccessDecision.NeedsInteraction(url)` when
  no user session yet. AS interactive endpoints (login-start redirect, OIDC
  callback, pending/poll) + `202 requirement=interaction` emission. Unit tests
  against a stub Keycloak handler.
- **C**: `MockPersonServer` four-party branch relays the AS `202` to the agent
  (passes `OnInteractionRequired`/pending-poll through `AccessServerClient`).
- **D**: Keycloak realm import JSON (realm, confidential client w/ Authorization
  Services + `whoami` resource + scopes + policies + a demo admin user),
  `make demo-federated` boots Keycloak, `appsettings` for the keycloak provider,
  docs.

Definition of Done:

- [x] Keycloak realm import provisions resources, scopes, and policies (+ a demo
      user for the interactive login).
- [x] `IAccessPolicy` seam selects `stub` (default) or `keycloak` via config;
      `keycloak` unreachable → fail closed (no silent stub fallback).
- [x] Adapter obtains a decision from Keycloak (after interactive login) and
      gates auth-token issuance.
- [x] AS returns a spec-valid `202 requirement=interaction` with a pending URL
      when a user decision is required; the PS relays it; the agent surfaces the
      consent URL and polls.
- [x] Granted → `200 aa-auth+jwt`; denied → spec-compliant `403`.

## Phase 5 — (absorbed into Phase 4)

Consent bubble-up from the AS (the former Phase 5) was **merged into Phase 4**
per the 2026-06-02 decision to do the full interactive Keycloak login/consent in
one phase. See Phase 4's "Delivery sub-steps" (B and C) and DoD. The reference
pattern still applies:
[samples/SampleApp/Components/Pages/CallChain.razor](../../samples/SampleApp/Components/Pages/CallChain.razor)
(two `OnInteractionRequired` callbacks funnelling to a shared
`SurfaceInteraction`, then poll the pending URL).

## Phase 6 — GuidedTour: four-party swimlanes

Goal: a Guided Tour run that visualizes all four parties, one swimlane each.

- _To populate: add `Actor.AccessServer` to
  [samples/GuidedTour/StepRecord.cs](../../samples/GuidedTour/StepRecord.cs)
  (today `Actor` has Agent/Resource/PersonServer/AgentProvider/Orchestrator)._
- _To populate: `StepRecord`s for resource token (`aud`=AS), agent→PS exchange,
  PS→AS federation, Keycloak decision (sub-step), AS-minted `aa-auth+jwt`, and
  the final agent→resource call; include the optional `202` consent detour._
- _To populate: wire a four-party tour option in `TourSession`/`TourOptions`._

Implementation Decisions (2026-06-02):

- The federated tour runs against the **stub** AS policy provider (no Keycloak)
  so the four-swimlane walkthrough is fully non-interactive and reproducible.
  The interactive Keycloak login/consent path is exercised separately by the
  SampleApp (Phase 7) and `make demo-federated` (Phase 8). The DoD (four
  swimlanes; decoded AS-minted auth token showing `dwk=aauth-access.json` +
  `cnf.jwk`) is satisfied without a live Keycloak.
- New `TourMode.Federated` + `Actor.AccessServer` (the S8 sample type). The mode
  is selectable only when `GuidedTour:AccessServerUrl` is configured
  (`HasAccessServer`), mirroring how `HasOrchestrator` gates `CallChain`.
- The tour targets `{WhoAmIUrl}/federated`; it is modeled on the **Autonomous**
  (6-step direct-grant) path plus an Access Server hop rendered as **sub-steps**
  inside the PS exchange (exactly how `CallChain` renders the Orchestrator's
  internal hops). 7 steps total.
- Reuses `StepFetchPersonMetadataAsync`; dedicated `StepFederated*` methods cover
  the rest. 4-lane diagram: Agent / Resource / Person Server / Access Server.
- No new public SDK API — sample-only, consuming Phases 1–4.

Definition of Done:

- [x] Tour renders four distinct swimlanes (Agent, Resource, PS, Access Server).
- [x] Each step shows request/response, signature base, and decoded tokens.
- [x] The AS-issued auth token shows `dwk=aauth-access.json` and `cnf.jwk`.

Delivered:

- `samples/GuidedTour/StepRecord.cs`: `Actor.AccessServer` (S8); `SubStep`
  visual-only arrow record (`Label, From, To, IsResponse`); `StepRecord` gained
  `SubSteps` and `SubStepsLabel` (names the component the inner steps run inside,
  e.g. "inside person server" for federation vs the default "inside orchestrator"
  for call-chaining).
- `samples/GuidedTour/TourSession.cs`: `TourMode.Federated`, `IsFederatedMode`/
  `HasAccessServer`, and the `StepFederated*` methods (resource token `aud`=AS,
  PS exchange with the AS hop rendered as sub-steps labeled "inside person
  server", AS-minted `aa-auth+jwt`, replay, inspect). Parse-challenge steps
  modeled as `Agent→Agent` self-steps so the 401 response is not immediately
  followed by a second right-to-left arrow.
- `samples/GuidedTour/Components/SequenceDiagram.razor`: arrow rendering rewritten
  into three ordered rows per step — **request** (solid arrow) → **sub-steps box**
  (component-internal hops) → **response** (dotted arrow, rendered *after* the box
  so a parent reply follows its component's internal work). Response direction is
  the reverse of the request; the box label is driven by `SubStepsLabel` via a
  `--substeps-label` CSS variable.
- `samples/GuidedTour/Components/Pages/Tour.razor`: `FederatedLanes` (Agent /
  Resource / Person Server / Access Server) with the Access Server on its own
  `as` lane class; banner shows the Access Server URL via `hl-as`.
- `samples/GuidedTour/wwwroot/app.css`: dotted response arrows + labels (main and
  sub-step), arrowhead vertical centering, full-height swimlanes
  (`.seq { min-height: 100% }`), the dynamic `--substeps-label` box title, a new
  `--danger` red, and `.lanes .as` / `.hl-as` so the **Access Server lane renders
  red** (distinct from Resource green and Person Server orange).
- `Makefile`: `demo-federated` now boots the Orchestrator and runs MockPersonServer
  with `MockPersonServer__RequireConsent=true` so the deferred-consent button has a
  live interaction URL under the four-party demo (previously dead — the PS minted a
  `200` directly without an interaction URL). Brings `demo-federated` to parity with
  `demo`.

Findings (UI / demo correctness, recorded for Phase 7 reuse):

- A remote step's response must render **after** any component sub-steps box, not
  before — the parent reply logically follows the component's internal work.
- Inner sub-step responses (e.g. AS→PS) are on different lanes than the outer reply
  (PS→Agent), so they are **not** duplicates and must not suppress the outer
  response row. An earlier "suppress outer response when sub-steps end in a
  response" heuristic was wrong and was removed.
- "Two consecutive right-to-left arrows with no request between" is the duplicate
  smell to avoid; modeling pure client-side work (parse challenge) as an
  `Agent→Agent` self-step prevents it.
- Responses are dotted, requests solid; status text is the response row's centered
  label. Dotted arrowheads need a small upward nudge (`top:-6px`) to center on the
  border-drawn line.
- `make demo-federated` must launch the **same backends** as `make demo` plus the
  AS/Keycloak — a missing backend (Orchestrator) or a missing env flag
  (`RequireConsent=true`) silently breaks a flow (call-chain / deferred consent)
  only under the federated target. Phase 7/8 targets must mirror the full backend
  set, not just add the AS.

## Phase 7 — SampleApp: four-party flow entry with consent bubble-up

Goal: a new SampleApp page for the four-party flow demonstrating consent
bubble-up, modeled on the call-chain page.

- _To populate: new `Components/Pages/Federated.razor` (nav entry + agent code
  panel) reusing the two-callback consent surface from `CallChain.razor`._
- _To populate: Playwright specs for the pre-granted (direct `200`) and deferred
  (`202` → approve popup → `200`) paths, mirroring `call-chain-deferred.spec.ts`._

Implementation Decisions (2026-06-02):

- **Page shape**: new `samples/SampleApp/Components/Pages/Federated.razor`
  (`@page "/federated"`, `@rendermode InteractiveServer`), modeled on
  [Deferred.razor](../../samples/SampleApp/Components/Pages/Deferred.razor) for
  the single-surface consent UX rather than the two-hop `CallChain.razor` — the
  four-party flow surfaces **one** consent (the AS/Keycloak login+consent),
  relayed by the PS, not two chained hops. The agent code panel and a server-side
  panel explain the four parties (Agent / Resource / PS / AS) and the
  `aud=Access Server` tell.
- **Target endpoint**: the agent calls `{Resource}/federated` (WhoAmI's isolated
  federated branch from Phase 1), whose `401` resource token carries
  `aud = Access Server`. The agent is **identical** to the three-party deferred
  agent — federation is transparent to it; only the PS behaves differently. This
  is the key teaching point of the page.
- **Consent surface**: a single `WithChallengeHandling(opts =>
  opts.OnInteractionRequired = i => Surface(i.BuildUserUrl()))` callback. When the
  AS (Keycloak) needs an interactive user session it returns `202
  requirement=interaction`; the PS relays it back through the agent's PS exchange,
  so it arrives on the **challenge** pipeline (the same path as three-party
  deferred), not the chained `WithInteractionHandling` path. No second callback is
  required for the non-chained four-party case. (Mirrors the GuidedTour federated
  flow, which renders this as the AS hop inside the PS exchange box.)
- **Keycloak interactive path (the "same sitch" as `make demo-federated`)**: when
  the AS runs with `AccessServer__PolicyProvider=keycloak`, the surfaced
  `interaction` URL is the AS's login-start endpoint, which **302-redirects the
  user's browser to Keycloak** for OIDC login + consent (demo users `demo/demo`
  with the admin role, `guest/guest` without). After the user authenticates, the
  AS records the decision and the agent's background poll resolves to `200 +
  aa-auth+jwt`. The SampleApp page therefore behaves identically whether the AS is
  stub (auto-`200`, no consent panel) or Keycloak (consent panel → open URL →
  Keycloak login → completes) — exactly like the GuidedTour federated mode under
  `make demo-federated`. The page itself is policy-agnostic; only the demo target
  selects the backend (Phase 8 `demo-federated-sample`).
- **Config**: add `AAuth:AccessServer` (`http://localhost:5500`) to
  [SampleApp/appsettings.json](../../samples/SampleApp/appsettings.json) for the
  banner/explainer only; the agent never calls the AS directly. The page is shown
  in the nav unconditionally (like the other pages) but its run depends on the AS
  being up (the demo target wires it).
- **Pre-granted vs deferred**: with the **stub** AS policy the call returns a
  direct `200` (no consent surface). With **Keycloak** policy (or
  `MockPersonServer__RequireConsent`-style gating) the first run surfaces the
  consent URL, then completes after approval. The page handles both by simply not
  showing the approval panel when no `202` arrives — same control flow as
  Deferred.razor.
- **Nav**: add a "Federated (Four-Party)" `NavLink` to
  [SampleApp/Components/Layout/NavMenu.razor](../../samples/SampleApp/Components/Layout)
  next to the Call Chain entry.
- **Findings carried from Phase 6**: the demo target that runs this page must boot
  the **full** backend set (Resource + PS-with-consent + AP + AS + Keycloak), not
  just add the AS — a missing backend or env flag silently breaks the flow under
  the federated target only (Phase 8 owns the `make demo-federated-sample` target).
- **No new public SDK API** — sample-only; consumes Phases 1–4. Any agent-side
  ergonomic gap discovered here is logged in research "SDK API findings" for the
  Phase 12 gate.

Definition of Done:

- [x] SampleApp has a four-party page reachable from the nav.
- [x] Pre-granted path completes with a direct `200` + `aa-auth+jwt` (exercised by the `MockAccessServerTests` direct-allow integration tests; the SampleApp page itself runs the stub with `RequireConsent=true`, so the interactive path is the default UX).
- [x] Deferred path surfaces the AS consent URL and completes after approval.
- [x] Playwright specs cover both paths (`federated.spec.ts` approve + `federated-deferred.spec.ts` Keycloak).

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

- **`demo-federated-sample` mirrors `demo-federated` exactly, swapping GuidedTour
  for SampleApp.** It boots the identical backend set and env wiring that already
  works for the GuidedTour federated demo: Keycloak (Docker import-realm, waited on
  `openid-configuration`) + WhoAmI + Orchestrator + MockPersonServer
  (`MockPersonServer__RequireConsent=true`) + MockAgentProvider + MockAccessServer
  (`AccessServer__PolicyProvider=keycloak` + the five `AccessServer__Keycloak__*`
  vars) + **SampleApp** (instead of GuidedTour). Same `trap`/`docker rm -f
  aauth-keycloak`/`kill 0` cleanup, same build-once-then-`--no-build` launch. The
  SampleApp's `/federated` page surfaces the AS→Keycloak interaction URL just as
  the GuidedTour federated mode does — this is the "same sitch" the SampleApp
  needs to work with Keycloak.
- **`demo-federated-sample-stub` mirrors a (new) `demo-federated-stub`** but with
  SampleApp: no Docker, no Keycloak; runs the AS with
  `AccessServer__PolicyProvider=stub` (auto-`200`, no consent panel) so the
  four-party flow is reproducible without a daemon. Backend set is otherwise the
  same (WhoAmI + Orchestrator + PS-with-consent + AP + AS-stub + app).
- **Shared make variables**: reuse the existing `KEYCLOAK_URL/IMAGE/REALM`,
  `AS_URL`, `SAMPLE_PROJECT`, and the `AccessServer__Keycloak__*` block already
  defined for `access-server`/`demo-federated`. Factor the Keycloak boot/wait and
  the AS env block so `demo-federated` and `demo-federated-sample` do not drift
  (a single missing var silently breaks consent — see Phase 6 findings).
- **Banners**: each target prints its app URL, the Keycloak login users
  (`demo/demo` admin, `guest/guest` non-admin), and the AS policy provider in
  effect, matching the existing `demo-federated` banner.
- The non-federated `demo`/`demo-sample` targets are unchanged.

Definition of Done:

- [x] `make demo-keycloak` starts Keycloak + AS adapter + resource + PS + agent
      + **both** UIs, and the SampleApp `/federated` page completes the
      interactive Keycloak consent. (The per-app `demo-federated`/`-sample`
      split was consolidated into a single `demo` / `demo-keycloak` pair.)
- [x] `make demo` runs the same flavor with the pure-.NET stub AS, no Docker.
- [x] Agent completes a federated call end-to-end via `make agent-federated`
      (Keycloak grant path).

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

- [x] Playwright `webServer` boots the AS adapter + federated resource. Per the
      Phase 9 decision the default backend is the **stub** AS (no Docker in CI);
      the real Keycloak path is opt-in via `KEYCLOAK_E2E=1` +
      `AccessServer__PolicyProvider=keycloak` (the `federated-deferred.spec.ts`
      project), skipped otherwise.
- [x] New GuidedTour spec (`samples/GuidedTour/playwright-tests/federated.spec.ts`)
      asserts the four swimlanes and the AS-issued auth token (approve + deny).
- [x] New SampleApp spec(s) (`samples/SampleApp/playwright-tests/federated.spec.ts`,
      and `federated-deferred.spec.ts` for the Keycloak consent path) cover the
      grant/deferred-consent path. The **deny** path is covered by the GuidedTour
      `federated.spec.ts` deny test (the SampleApp federated spec asserts approve
      only).
- [x] Suite is green locally and in CI (`reuseExistingServer` honored): 25
      passed, 1 skipped (Keycloak-gated).

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

- [x] `federated-access.md` covers AS server code, Keycloak, and consent bubble-up.
- [x] Keycloak AS adapter setup is documented in the Mock Access Server README
      (realm/client/resource/scope/policy + claim mapping).
- [x] Sample READMEs and the docs index reference the four-party demos.
- [x] Mermaid diagrams render and in-repo links resolve.

## Phase 11 — Identity claims push (requirement=claims, full spec)

Goal: implement the spec's `requirement=claims` flow properly, now that the
other pieces are in place — the PS federation client (Phase 2), the
`MockPersonServer` federation branch (Phase 3) that holds the user's identity
claims, and a Keycloak-backed AS (Phase 4) whose ABAC policy can actually
*request* directed identity claims. Deferred from Phase 2 to keep that phase
bare-minimum and because this path is untestable end-to-end until an AS issues
a claims requirement.

Spec basis: a server **MUST** use `requirement=claims` (returned as `202` with
`AAuth-Requirement: requirement=claims` + a `Location` URL) when it needs
identity claims; the recipient **MUST** provide the requested claims by POSTing
a directed `sub` + claims to the `Location` URL. This is an active push, **not**
the deferred poll loop used for `interaction`.

- _To populate: extend `AccessServerClient` with an `OnClaimsRequired` callback
  (additive) that resolves the requested claims and POSTs the directed `sub` +
  claims to the `Location`, then continues the loop._
- _To populate: `MockPersonServer` supplies directed claims for its bound user._
- _To populate: Keycloak AS adapter emits `202 requirement=claims` when policy
  evaluation needs attributes the AS does not yet hold._

Delivered:

- SDK (additive, non-breaking — see Phase 11 finding below):
  - `src/AAuth/Headers/AAuthClaimsRequirement.cs` (new) — typed projection of a
    `requirement=claims` response; `FromResponse` reads `required_claims` from
    the body (preferred) or a `claims` header parameter (fallback).
  - `AccessServerRequest.OnClaimsRequired`
    (`Func<AAuthClaimsRequirement, CancellationToken, Task<JsonObject>>?`). When
    `null` and the AS asks for claims, the call still throws
    `NotSupportedException` (prior behaviour preserved).
  - `AccessServerClient.FederateAsync` — new `requirement=claims` branch: reads
    the claim names, invokes the callback, POSTs the returned directed `sub` +
    claims (signed via the PS HTTP-Sig client) to the `Location` (origin-pinned
    via `ResolveSameOriginLocation` to stop a tampered Location exfiltrating the
    directed `sub`), then resumes the poll loop to the `200` auth token. A
    `403 access_denied` after the push surfaces `AAuthInteractionDeniedException`;
    a null result or a missing `sub` surfaces `InvalidOperationException`. The
    202 handling is a **bounded composition loop** (added by the SPEC-review D1
    fix) so `interaction`/`payment` → `claims` chained on one `Location` are all
    handled, via the new `DeferredPollerOptions.StopWhenAccepted` predicate.
  - `AuthTokenBuilder.AdditionalClaims` (additive, mirrors
    `AgentTokenBuilder`) so an AS can assert the pushed identity claims.
- `MockAccessServer`: `AccessDecisionKind.NeedsClaims` +
  `AccessDecision.NeedsClaims(requiredClaims)`; `StubAccessPolicy` takes
  configured `AccessServer:RequireClaims` (default empty = no behaviour change)
  and returns `NeedsClaims` until every named claim is present;
  `AccessPendingStore` carries `RequiredClaims`/`SuppliedSubject`/`SuppliedClaims`;
  `POST /pending/{id}` claims-push endpoint merges + re-evaluates + mints with the
  directed `sub` and echoed claims; `GET /pending/{id}` mints likewise.
- `MockPersonServer`: `demoUserClaims` (`email`/`tenant`/`name`) + an
  `OnClaimsRequired` callback returning `sub` + the held claims for the principal.
- Tests: `AccessServerClientTests` +2 (claims push round trip; missing-`sub`
  guard); the no-handler case renamed to
  `..._WhenNoHandler`. `StubAccessServer` handles the `POST /pending/` push.
  368 unit tests pass (was 366); full solution builds clean.

Implementation Decisions:

- The callback is **additive and non-breaking**: a new optional property whose
  absence preserves the previous `NotSupportedException`. Treated as authorized
  by Phase 11 (distinct from the Phase 12 public-API gate), but flagged for
  review (nothing committed).
- The directed `sub` is enforced SDK-side (spec MUST) to fail fast on a PS bug.
- The claims `Location` is origin-pinned to the AS — the push carries a directed
  identifier and must not be divertible to another host.
- The demo claims requirement is driven by `AccessServer:RequireClaims` on the
  **stub** policy so the round trip is testable without Docker; default-off so
  the existing federated e2e stays green.

Findings (for review):

- **Public SDK surface changed** (additive): `AAuthClaimsRequirement` (new
  type), `AccessServerRequest.OnClaimsRequired`, `AuthTokenBuilder.AdditionalClaims`,
  and `DeferredPollerOptions.StopWhenAccepted` (new optional predicate, added by
  the SPEC-review fix below). All optional/non-breaking, but new public API —
  confirm on return.
- **Keycloak AS does not yet emit `requirement=claims`.** Only the stub policy
  drives the push (via `AccessServer:RequireClaims`). Wiring Keycloak's
  Authorization Services to request directed attributes it lacks is non-trivial
  and was left out to keep the change scoped and testable; the SDK + PS + stub
  AS exercise the full spec round trip. Recommend a follow-up for the Keycloak
  adapter. (Reviewer confirmed this is NOT a spec violation — the spec mandates
  the protocol shape *if* an AS asks for claims, not that every AS must.)
- Not yet live-e2e'd through the browser flow; covered by unit tests. The
  existing federated Playwright specs remain green (default `RequireClaims` off).

SPEC reviewer pass (against `aauth-spec/draft-hardt-oauth-aauth-protocol.md`,
pinned commit c090879):

- All MUST/SHOULD clauses of §Claims Required verified PASS for the standalone
  claims-first flow, with strong security hardening confirmed (HTTP-signed push,
  origin-pinned directed-`sub` Location, AS-side PS-signature verification,
  `sub` enforced on both ends).
- **D1 (MAJOR) — FIXED.** The reviewer found the SDK only dispatched the claims
  push when `requirement=claims` was the *immediate* `/token` reply, not when it
  arose **mid-poll** after an `interaction`/`payment` step — violating the spec's
  composition guarantee (§Trust Establishment: "these mechanisms may compose …
  Each step uses the same `Location` URL for polling"). Fixed by: (a) adding
  `DeferredPollerOptions.StopWhenAccepted` so a poll can return early when the
  `AAuth-Requirement` escalates; (b) restructuring `AccessServerClient`'s 202
  handling into a bounded composition loop that re-dispatches each requirement
  on the same `Location`; (c) new test
  `FederateAsync_ComposesInteractionThenClaims_OnSameLocation`. 369 tests pass.
- **D2 / D3 (MINOR, demo-scoped — NOT spec violations, left as-is):** the mock
  AS does not bind a pending entry to the originating PS (any validly-signed
  caller that learns a pending id could push — `AccessPendingStore` already flags
  this as a production gap), and a hypothetical *multi-round* AS claims request
  would leave `GET /pending` falling through to the interaction branch. Neither
  is reachable from the stub policy; both are noted production-hardening items.

Definition of Done:

- [x] AS returns a spec-valid `202 requirement=claims` with a `Location` URL
      (stub policy via `AccessServer:RequireClaims`; Keycloak adapter is a noted
      follow-up).
- [x] `AccessServerClient` resolves and POSTs directed `sub` + claims, then
      continues to a `200 aa-auth+jwt`.
- [x] `MockPersonServer` provides the requested claims for its bound user.
- [x] Unit/e2e tests cover the claims-push round trip (unit; e2e is a follow-up).

## Phase 12 — SDK API investigation & design (consultation required)

Goal: after the demos prove the flow end-to-end, step back and harden the
**SDK public surface** so four-party is a first-class scenario for Client /
Resource / PS / AS authors — not bespoke sample glue. This phase is
investigation + design first; **no API is added or changed without explicit
sign-off from the user** (gate below).

> Note: individual APIs may be introduced in whichever earlier phase first needs
> them (tracked in the [research.md](research.md) "SDK API findings" table).
> This phase is where the **overall** public surface is revisited, reconciled,
> and ratified as a coherent whole.

Inputs: the friction discovered while building Phases 1–11, plus the current
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

- Design note written: [phase-12-api-design.md](phase-12-api-design.md).
  **DESIGN ONLY — no public SDK API added/changed under this phase; awaiting
  user sign-off.** It reconciles S1–S10: what already shipped additively in
  Phases 1–11 (`AccessServerClient`, `AuthTokenResponseValidator`,
  `AAuthClaimsRequirement`, `OnClaimsRequired`, `AuthTokenBuilder.AdditionalClaims`),
  what is still sample-only and recommended for promotion (`IAccessPolicy`/
  `AccessDecision` → S3, `MapAAuthAccessServer` → S2), and what to defer/close
  (S5 defer, S7 close — no change).

### Consultation gate (required before any code)

1. Produce a short design note: proposed new public types/methods, signatures,
   namespaces, and backward-compat impact (additive vs breaking).
2. Present options/trade-offs to the user and **get explicit approval**.
3. Only then implement, with unit tests and updated docs.

Definition of Done:

- [x] Design note enumerating proposed API additions/changes is written
      ([phase-12-api-design.md](phase-12-api-design.md)).
- [x] User has reviewed and signed off on the design (recorded here). Approved
      full scope **R1–R3 + S2 + S3 + Keycloak Option B** with backward-compat
      **waived**.
- [x] Approved APIs implemented with unit tests in `tests/AAuth.Tests`
      (`AAuthClaimsResponse`, typed `OnClaimsRequired`, `AuthTokenBuilder.Tenant`,
      core `IAccessPolicy`/`AccessDecision`, `IAccessPendingStore` +
      `InMemoryAccessPendingStore`, `MapAAuthAccessServer`). 369/369 pass.
- [x] Samples refactored to consume the new public surface (MockAccessServer
      now wires `MapAAuthAccessServer`; deleted its sample `IAccessPolicy.cs` +
      `AccessPendingStore.cs`; keeps only `StubAccessPolicy` +
      `KeycloakAccessPolicy` + `/interaction` endpoints).
- [x] Public API surface / docs updated to match
      ([federated-access.md](../../docs/workflows/federated-access.md),
      [MockAccessServer README](../../samples/MockAccessServer/README.md),
      design note Section 0).

### Delivered findings

- The §Claims Required push surface was reshaped clean (no back-compat): claim
  names live **only** in the body `required_claims` (header `claims` fallback
  removed); `OnClaimsRequired` returns a typed `AAuthClaimsResponse` whose
  `Subject` (directed `sub`) is a compile-time `required`; `tenant` is promoted
  to a named §Auth Token claim via `AuthTokenBuilder.Tenant` (the host helper
  separates it from the open claim remainder when minting).
- `MapAAuthAccessServer` owns the whole token-endpoint pipeline including the
  composition loop (interaction→claims on the same `Location`) and `GET|POST
  /pending/{id}`; the verdict is the only thing delegated to `IAccessPolicy`.
- Keycloak Option B (UMA `need_info` → `NeedsClaims`, re-decide on PS push) is
  implemented in the sample adapter but is **not CI-testable** without a
  claim-gathering realm; Option A (`AccessServer:RequireClaims` via the stub)
  is the dependency-free, CI-covered path.

### SPEC review (Phase 12) — findings + fixes

A read-only conformance reviewer checked the changes against §Claims Required,
§Auth Token, §Trust Establishment, §AS Token Endpoint, and §Access Server
Metadata. Verdict: **conformant — no CRITICAL/MUST violations.** All six targets
PASS (header-vs-body claim placement, mandatory directed `sub`, first-class
`tenant`, `dwk`/`exp`/`sub` minting, same-Location composition, 200/202/402,
required metadata, origin-pinned signed pushes). Findings actioned:

- **F2 (MAJOR, security)** — *fixed.* The pending poll/push endpoints did not
  re-enforce the trusted-PS pin (only `/token` did) and entries were not bound
  to the originating PS. Added `AccessPendingEntry.OriginPersonServerHost`
  (captured at park time) and an `AuthorizePsCaller` guard on `GET|POST
  /pending/{id}` that re-checks the `jwks_uri` scheme + trusted set and binds to
  the originating PS host (403 otherwise). Regression tests:
  `ClaimsPush_FromTrustedPersonServer_MintsAuthToken` (happy path) +
  `ClaimsPush_FromUntrustedPersonServer_IsRejected` (371 tests total).
- **F4 (MINOR)** — *fixed.* `NeedsPayment` now fails fast (500) rather than
  emitting an empty `402` `Location` if `PaymentUrl` is blank.
- **F1 (MINOR, doc)** — *fixed.* `ExtractClaimsRequirementAsync` XML summary no
  longer mentions the removed header `claims` fallback.
- **F3 (MINOR/WARN)** — *left as documented.* A `claims→interaction` escalation
  is polled silently rather than surfaced to `OnInteractionRequired`. The spec's
  canonical order ends in claims, so this is a low-risk edge; not fixed.

## Out of scope (for now)

| Item | Reason |
|---|---|
| Keycloak Java SPI / native `aa-auth+jwt` protocol mapper | High effort; adapter pattern keeps AAuth crypto in .NET. |
| `402` payment / billing flows | Not needed for the core demo. |
| Call chaining (`upstream_token`) in the four-party demo | Orthogonal; already covered elsewhere. |
| Production hardening (TLS, key rotation, HA Keycloak) | Demo runs on loopback HTTP. |
