# Server-Side API Surface — Implementation Plan

Phased plan to introduce a high-level, spec-grounded server API surface for the
AAuth .NET SDK: a complete DI registration, declarative per-route protection, a
decoupled opt-in interaction module, and role-mapper adoption for the PS/AS
samples.

- **Research:** [research.md](research.md)
- **Log:** [implementation-log.md](implementation-log.md)
- **Created:** 2026-06-27

## Guiding principles

- **Spec conformance is paramount; backwards compatibility is not a goal.** This
  is a spec-accurate alpha SDK. Do a single coordinated cutover — replace the
  diverged helpers and migrate every consumer in the same change set. No
  dual-format shims, no old+new side-by-side. Deliberate exceptions are logged as
  `PROCEEDED`/`RESOLVED` entries in [implementation-log.md](implementation-log.md).
- **Reuse, don't rewrite.** The spike proved the new surface is a thin
  metadata-driven orchestrator over the existing `AAuthVerificationMiddleware`,
  `AAuthChallengeMiddleware`, `IOpaqueTokenStore`, and `MapAAuthPersonServer` — keep
  those engines; change only how consumers wire them.
- **Opt-in, not embedded.** Interaction, replay detection, resource-managed
  access, and mission-awareness are flags/calls a server turns on; a plain
  payload endpoint carries none of them.
- **Layered surface, 80/20.** Three layers: (1) interfaces + primitives,
  (2) options-driven middleware, (3) one-call DI + map convenience. The
  high-level surface must read like intent for ~80% of cases; the other ~20% is
  composed from the fine-grained primitives. **Invariant:** every high-level
  call must be expressible as the fine-grained calls beneath it, and every
  default must be replaceable via DI. If a convenience method can do something
  you cannot reassemble from primitives, that is a bug.
- **Configurability ceiling (no god-object).** The high-level surface carries the
  common shape plus a *named, closed* set of axes — per-route **access mode**
  (signature-only / auth-token / resource-managed), **scope**, **role**,
  **mission-aware**; resource-level **trusted issuers**, **keys/issuer/identifier**,
  **discovery**. Variation beyond that set falls through to the primitives; it does
  **not** become another option. High-level calls default the boilerplate from DI
  and ask only for the per-route *delta*.
- **No string indirection, no manual HTTP wiring (consumer invariants).** The SDK
  never introduces a string *key* to connect two call sites — if two places must
  agree, they share a typed handle, not a magic string (this kills the
  `AddAAuthScopePolicy("AAuth.Scope.…")` → `RequireAuthorization("AAuth.Scope.…")`
  pattern; protocol values like headers/schemes/claims/modes stay typed
  constants). And consumers register **zero** `HttpClient`/`IHttpClientFactory`
  plumbing: discovery clients, named handlers, and handler lifetime are owned
  inside the SDK's `Add*` calls. A consumer-defined scope/role *value* may appear
  once (it is protocol data, not indirection).

## Chosen options (from the decision interview)

| Area | Choice |
|---|---|
| Endpoint style | Per-endpoint `.RequireAAuth(scope:…, role:…)` (research 4.2-A) |
| Interaction | Full opt-in module: codegen + pending store + poll + approve hook (4.3-A) |
| Role mappers | Do now — migrate PS sample onto its mapper, add seams for real gaps (4.4-A) |
| DI | Extend `AddAAuthResource` to parity + fold in discovery (4.1-A+C) |
| Cutover | Clean cutover, no back-compat shims |

---

## Phase 0 — Decision gate

Resolve the research open questions before code. Each ruling is recorded in
[implementation-log.md](implementation-log.md); prefer a default ruling over
blocking.

**Definition of Done**

- [ ] Every open question (Q1–Q5 interview choices; G1–G6 research gaps) has a
      recorded ruling in `implementation-log.md`.
- [ ] G3 ruling: `UseAAuth` defaults resource signing key / issuer / identifier
      from the DI-registered `AAuthResourceMetadataOptions`; the only per-call
      config is *trust* (`TrustedAuthTokenIssuers`). Metadata is owned by the
      extended `AAuthResourceOptions`.
- [ ] G5 ruling: the interaction module is built on a small park/poll primitive
      but RS opaque-token issuance stays distinct from PS auth-token minting; a
      full PS-governance unification is **out of scope** this round.

---

## Phase 1 — DI parity + discovery hygiene (decision 1)

Make `AddAAuthResource` the registration the samples actually use. Low risk,
isolated; unblocks adoption for later phases.

**Files**

- [AAuthResourceOptions.cs](../../../src/AAuth/DependencyInjection/AAuthResourceOptions.cs)
  — add `SignatureWindow`, `AccessMode`, `AuthorizationEndpoint`, and an optional
  discovery-client hook (named `IHttpClientFactory` clients for socket hygiene).
- [AAuthResourceServiceCollectionExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthResourceServiceCollectionExtensions.cs)
  — register `MetadataClient`/`JwksClient` as **overridable singletons**
  (factory-backed when the hook is set); store the complete
  `AAuthResourceMetadataOptions`.
- [AAuthApplicationBuilderExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs)
  — `MapAAuthWellKnown` publishes the new metadata fields.

**Definition of Done**

- [x] `AddAAuthResource` registers verifier, discovery clients, jti store, and
      complete metadata in one call.
- [x] `MapAAuthWellKnown` emits `access_mode` / `signature_window` /
      `authorization_endpoint`.
- [x] `MetadataClient`/`JwksClient` remain replaceable via
      `services.RemoveAll<…>()` + re-add (the integration-harness seam, G4) — a
      test asserts an override still wins.
- [ ] Consumers register **zero** `HttpClient`/named-client lines; the SDK owns
      the discovery clients and their handler lifetime (e.g. `SocketsHttpHandler`
      with `PooledConnectionLifetime`), and the discovery-client name strings no
      longer appear in any sample. _(SDK side done; sample cutover in Phase 3 —
      see log.)_
- [x] `dotnet build AAuth.slnx` green; existing integration tests pass.

---

## Phase 2 — Interaction module (decision 3)

Move resource-managed interaction generation/handling out of payload endpoints
into an opt-in SDK module. Directly answers the brief's "a payload endpoint
shouldn't embed interaction generation."

**Files (new + Inbox migration)**

- New `AAuthInteractionCode` — spec-conformant Crockford base32 generator
  (#interaction-code-format L2066): ≥ 40 bits, optional hyphens, case-insensitive
  fold (`I`/`L`→`1`, `O`→`0`), single-use, rate-limited validation. Replaces every
  hand-rolled `NewInteractionCode` (fixes the Inbox hex conformance bug, G2).
- New `IInteractionPendingStore` + `InMemoryInteractionPendingStore` (built on the
  shared park/poll primitive, G5).
- New `RequireAAuthInteraction(this HttpContext, scope)` helper — generates a
  code, parks the pending entry, emits `202 + requirement=interaction + Location`.
- New `MapAAuthInteractionPoll(pattern)` — serves `GET /pending/{code}` (202 while
  pending; on approval issues `AAuth-Access` via `IOpaqueTokenStore`).
- New `AddAAuthResourceManaged(…)` DI registration; an `Approve(code)` hook the
  resource's own consent page calls.
- Migrate [Inbox/Program.cs](../../../samples/MockResourceServers/Inbox/Program.cs):
  delete `NewInteractionCode`, `PendingStore`, `/pending/{code}`; the consent page
  stays (look-and-feel + the user auth the spec leaves to the resource, L2078).

**Definition of Done**

- [x] Inbox's `/messages` opts into interaction with one call; no codegen / pending
      store / poll endpoint remain in its `Program.cs`.
- [x] Generated codes are Crockford base32, ≥ 40 bits, single-use; rate-limiting
      the consent URL is deployment-level (logged).
- [x] `InboxFlowTests` (both reactive `/messages` and proactive `/authorize`
      entry points) pass.
- [x] Unit tests for the code generator (alphabet, entropy, fold, hyphen-strip,
      single-use, expiry).

---

## Phase 3 — Per-route protection (decision 2)

Highest blast radius — touches every resource server and middleware ordering. Do
after DI (Phase 1) is settled. Spike-validated (9/9 `CalendarFlowTests`).

**Refactor `MapAAuthResource` by splitting the concern (not by adding knobs).** A
resource is per-route heterogeneous, so the app-wide single-mode/single-scope
pipeline is the wrong model. Resource-level config moves to DI
(`AddAAuthResource`); per-route intent moves to the endpoint (`.RequireAAuth(...)`).
`MapAAuthResource` is **redefined** as the one-liner for a genuinely uniform
resource; the per-route surface is the real 80% path. Per-route calls carry only
the *delta* (scope/role/mode) — signing key, issuer, and identifier default from
the DI-registered `AAuthResourceMetadataOptions` (so no more `ChallengeForScope`
lambdas restating boilerplate).

**Files (new + 5-server migration)**

- New `AAuthEndpointRequirement` routing metadata (`Mode`, `Scope`, `Role`,
  `MissionAware`).
- New `RequireAAuth(scope?, role?, missionAware?)` / `RequireAAuthSignature(identified?)`
  endpoint extensions — attach metadata + an **inline** authorization policy
  (retires the `AddAAuthScopePolicy`/`AddAAuthRolePolicy` magic-string names, 3.3).
- New `UseAAuth(configure)` post-routing middleware — composes the existing
  verification + challenge per matched endpoint; defaults resource signing
  key/issuer/identifier from `AAuthResourceMetadataOptions` (G3); takes only trust
  config per call.
- **Fail-closed guard (the spike's footgun):** if an endpoint carries an
  `AAuthEndpointRequirement` but routing did not run (`GetEndpoint()` null at the
  middleware), fail closed rather than serve unverified — or ship a single ordered
  entry-point (`MapAAuthResource`-style) that wires `UseRouting → UseAAuth →
  UseAuthentication → UseAuthorization` so ordering can't be gotten wrong.
- Migrate Profile, Calendar, Trips, Wallet, Inbox to `UseAAuth` + per-route
  `.RequireAAuth(...)` / `.RequireAAuthSignature(...)`.

**Definition of Done**

- [x] Each server's middleware/policy block reduces to `UseAAuth` + per-route
      attributes; no `UseWhen`, factory lambdas, prefix exclusions, or named scope
      policies remain.
- [x] Identity-only (`RequireAAuthSignature`), 3-party (`scope`), role
      (`scope`+`role`), mission-aware (`missionAware`), and federated
      (trust = AS) endpoints all covered.
- [x] Fail-closed guard verified by a test (protected endpoint without
      `UseRouting` does not serve unverified).
- [x] `CalendarFlowTests`, `InboxFlowTests`, and Profile/Trips/Wallet integration
      tests green.

---

## Phase 4 — PS/AS role-mapper adoption + seams (decision 4)

`MapAAuthPersonServer` already covers 3-/4-party + mission + sub-agents (G6); the
work is migration, surfacing real seam gaps empirically. **Refactor license:** if
migration shows the `IIdentityClaimsAsserter` seam is too narrow, widen it (richer
context / decision hooks) so the sample *adopts* the mapper — do not let the
sample keep hand-rolling `/token`. The mapper is changeable, not sacred.

**Files**

- New `SampleIdentityClaimsAsserter` in MockPersonServer — moves consent / mission
  / federated-claims logic behind `IIdentityClaimsAsserter`.
- Migrate [MockPersonServer/Program.cs](../../../samples/MockPersonServer/Program.cs)
  onto `MapAAuthPersonServer`; delete the duplicated hand-rolled `/token`.
- Add `IIdentityClaimsAsserter`/mapper seams **only** for micro-gaps found during
  migration (candidates: `requireConsent` toggle, demo role/group derivation,
  federated `OnClaimsRequired` answering arbitrary claim names via `ProjectClaims`).
- Add a DI helper for the four-party federation client (`AddAAuthFederation(...)`
  or fold into a PS registration) so the PS's `AccessServerClient` + its signed
  `HttpClient` are no longer hand-wired in the sample (consumer invariant 2 on the
  PS side).
- Confirm MockAccessServer (already on `MapAAuthAccessServer`) needs no change.

**Definition of Done**

- [ ] MockPersonServer's hand-rolled `/token` is deleted; behavior comes from
      `MapAAuthPersonServer` + `SampleIdentityClaimsAsserter`. _(Deferred — logged
      issue for review; mapper proven by `PersonServerMapperTests`.)_
- [x] Any added seams are listed in `implementation-log.md` with the gap they close.
- [x] The PS federation client is registered via a DI helper — no manual
      `AddHttpClient`/`AccessServerClient` wiring remains in the sample.
- [x] `MockPersonServerTests`, `MockPersonServerFederationTests`, and the
      consent-path `CalendarFlowTests` pass.

---

## Phase 5 — Samples / snippets / docs sweep

Run after the code surface is frozen. Non-compiled surfaces drift silently, so
sweep them explicitly.

**Definition of Done**

- [x] [docs/server/*](../../../docs/server) (verification, challenge, token
      issuance, authorization policies), [reference/configuration.md](../../../docs/reference/configuration.md),
      [getting-started.md](../../../docs/getting-started.md), and resource-server
      READMEs reflect the new surface.
- [x] `CodeSnippets.cs` and any string-literal snippets compile against the new API.
- [x] e2e Playwright assertions and the root [README.md](../../../README.md) API
      map updated.

---

## Phase 6 — Internal review

A fresh subagent validates the work against the spec, [research.md](research.md),
and this plan with severity-graded findings.

**Definition of Done**

- [x] Subagent review recorded; HIGH/CRITICAL findings resolved or logged.
- [x] Full `dotnet build AAuth.slnx` + unit + conformance + integration suites green.

---

## Phase 7 — Faithful mission/clarification seam in the mapper, then migrate PS (Option A, approved)

Reverses the earlier "declined" framing. The real finding is a tier-3 conformance
gap, not a reason to hand-roll: `MapAAuthPersonServer` routes the out-of-scope
mission decision through `IIdentityClaimsAsserter` (identity-claims), which cannot
emit the normative `requirement=clarification` round-trip
([spec L989/L995](../../../aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md))
nor record the spec mission-log reasons (`OutOfScope`/`Clarification`, #mission-log).
The SDK already ships the right primitives (`IInteractionRelay` Question,
`IMissionLog`); the mapper just doesn't compose them for the token gate. The agent
half of clarification is already in the SDK — fixing the server-side asymmetry.

**Decision (owner-approved):** the SDK owns the **protocol** mechanics (the
`requirement=clarification` 202, the pending-URL `GET`/`POST`/`DELETE`
round-trip, mission-log entries with correct reasons, the three-gate structure);
a **consumer seam** owns **how** the out-of-scope decision + clarification is made
(LLM, human consent screen, scripted test). Spec basis: the PS "does not prescribe
how the decision is made" (L3226) — policy is the consumer's.

**Seam (new, `AAuth.Server.Governance`):** `IMissionTokenConsent.ReviewAsync(ctx)`
returning a rich outcome — `Grant` / `Deny(reason)` / `Clarify(question,timeout?,options?)`
/ `Defer` (hold for an out-of-band human verdict). `ctx` carries agent/resource/
scope/mission/prompt/capabilities + the clarification history. Default impl ships
the spec three-gate's interactive resolution; registered via `AddAAuthGovernance`.
Identity claims on `Grant` still come from `IIdentityClaimsAsserter` (governance
decision and identity stay separate seams).

**Mapper protocol (SDK-owned):** the unified `{PendingPathPrefix}/{id}` endpoint
gains `GET` (emit `requirement=clarification` while awaiting an answer; resolve via
`ReviewAsync` / external `MarkAllowed`/`MarkDenied`), `POST` (`clarification_response`
or updated `resource_token` → log `Clarification`, re-review), and `DELETE`
(withdraw → log `Clarification: cancelled`). Gate 2a in-scope stays silent
(`InScope`); gate 2b prior-consent stays silent (`PriorConsent`); gate 2c logs
`OutOfScope` on the resolved verdict.

**Migration scope:** replace MockPersonServer's hand-rolled `/token` + `/pending`
+ `/federated-pending` + `/mission-pending` (token clarification/decision) with
`MapAAuthPersonServer`, plus a sample `ScriptMissionTokenConsent` adapter over the
existing `MissionConsentScript`. **Keep** the governance endpoints (`/mission`,
`/permission`, `/audit`, `/mission-interaction`, `/permission-pending`) — they
already compose tier-2 seams cleanly — and `/admin/*` + `ConsentStore`.

**Definition of Done**

- [x] `IMissionTokenConsent` + default ship; `IInteractionRelay`/`IMissionLog`
      composition; unit-covered.
- [x] Mapper emits the normative `requirement=clarification` round-trip and logs
      `InScope`/`PriorConsent`/`OutOfScope`/`Clarification` per the spec; covered by
      new `PersonServerMapperTests` rows.
- [x] MockPersonServer `/token` + its three pending polls come from the mapper;
      `ScriptMissionTokenConsent` injects the scripted decision; governance
      endpoints + `/admin/*` + `ConsentStore` unchanged.
- [x] `MissionAgentFlowTests` (all 12 rows), `MockPersonServerTests`,
      `MockPersonServerFederationTests`, consent-path `CalendarFlowTests` pass.
- [x] Full build + AAuth.Tests + AAuth.Conformance green.

---

## Phase 8 — Re-run docs sweep + internal review (post-migration)

**Definition of Done**

- [x] Docs/READMEs/snippets referencing the PS hand-rolled `/token`/stores updated;
      the new `IMissionTokenConsent` seam documented in [docs/server](../../../docs/server)
      + the API map; invariant greps over `docs/` + `samples/` re-confirmed clean.
- [x] Fresh subagent review of the Phase 7 change; HIGH/CRITICAL resolved or logged.
- [x] Full build + both suites green.

---

## Phase 9 — Replay detection: key on the signature, not the carrier `jti` (spec conformance)

The Phase 3 migration moved the **Concierge** intermediary onto `AddAAuthResource`,
which turns on replay detection by default (`EnableReplayDetection = true` →
`InMemoryJtiStore`). That exposed a **pre-existing, latent SDK conformance bug**:
`AAuthVerificationMiddleware` records the **presented carrier token's `jti`** and
rejects duplicates, which makes a reusable **auth token single-use**. It only
surfaced at the Concierge because that is the one place an auth token is
legitimately **re-presented** — the deferred call-chain re-drives the chain on each
`GET /pending/{id}` poll, signing every poll with the same auth token. The OLD
Concierge hand-registered its services with **no** `IJtiStore`, so the latent bug
was invisible; the migration's default flipped it on and broke all three
`call-chain*` e2e specs (`invalid_jwt` on the second presentation).

**Spec basis — replay is on the signature, not the token** (§Freshness and Replay,
[L2376/L2378](../../../aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md)):

> The `created` parameter is the primary replay defense … a verifier MAY maintain
> a short-lived cache keyed by `(signing-key-thumbprint, created, @method,
> @authority, @path)` for the duration of the window, rejecting duplicate tuples.
> … This profile defines no nonce mechanism.

The auth token is a PoP-bound credential **presented on every request**; `jti` is
for **audit + revocation** ([L567/L2274](../../../aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md)),
not single-use. The fix lives in the SDK; the resource sample and the e2e specs
are already correct (reusing the token is what a real agent does).

**Change (SDK):** in the `AAuthVerificationMiddleware` replay block, build the
record key from the **verified per-request signature** itself
(`key-thumbprint | <Signature header value>`) and pass that to
`IJtiStore.TryRecordAsync` (allows legitimate reuse, still rejects an exact
in-window replay). The signature cryptographically binds the spec's tuple
`(key-thumbprint, created, @method, @authority, @path)` **plus** the covered
`signature-key` (the carrier), so it is a stronger realization of the example
tuple — distinct carriers/paths never collide. Keep the `IsRevokedAsync(jti)`
check on the **real carrier `jti`** — revocation is by `jti`. `IJtiStore` /
`InMemoryJtiStore` / the revocation endpoint are unchanged. `created` (parsed
from `Signature-Input`) only bounds the cache-entry expiry to the freshness
window.

**Implementation Decisions**

- Keyed on the full signature, not the literal spec tuple. The literal tuple
  `(key, created, method, authority, path)` omits the carrier, so under a fixed
  test clock it false-collides the challenge→retry hop (agent token then auth
  token, same key/created/path) and the “different jti both succeed” jkt-jwt case.
  The signature value subsumes the tuple and adds the carrier, eliminating those
  false positives while still rejecting a verbatim captured-signature replay.
- No new public API: the composite key is an internal string handed to the
  existing `IJtiStore`. `EnableReplayDetection` stays on by default for resources.

**Definition of Done**

- [x] Middleware records the verified signature, not the carrier `jti`; revocation
      still keyed on `jti`; temporary PS-mapper + Concierge diagnostics removed.
- [x] New conformance coverage (`ReplayDetectionMiddlewareTests`): same auth token
      reused across two signed requests is accepted; an exact captured-signature
      replay is rejected; revocation-by-`jti` still rejects.
- [x] Full build + AAuth.Tests (504) + AAuth.Conformance (563) green (no regressions).
- [x] All `call-chain*` e2e specs (guided-tour + sample-app) pass; full e2e green
      (44 passed / 1 skipped).

## Phase 10 — Docs sweep + internal review (replay fix)

**Definition of Done**

- [x] [replay-detection.md](../../../docs/server/replay-detection.md) rewritten to
      the signature-keyed model (auth tokens are reusable; `jti` is
      audit/revocation); [glossary.md](../../../docs/glossary.md),
      [docs/README.md](../../../docs/README.md) API map, and
      [token-issuance.md](../../../docs/server/token-issuance.md) cross-refs
      corrected; 5 stale “fresh `jti` dodges replay” comments in
      [MissionAgent](../../../samples/MissionAgent/Program.cs) +
      [GuidedTour](../../../samples/GuidedTour/TourSession.cs) corrected; invariant
      greps over `docs/` + `samples/` re-confirmed clean.
- [x] Fresh subagent review of the Phase 9 change against the spec — APPROVED, no
      CRITICAL/HIGH; the one MEDIUM (cross-link the lightweight `created` extract
      to the authoritative parser) applied.
- [x] Full build + both suites + e2e green.

---

## Out of scope

| Item | Why |
|---|---|
| Full PS-governance park/poll unification | G5 deferred; keep RS opaque-token issuance distinct from PS minting this round |
| Agent-side convenience APIs | Tracked separately ([2026-05-23-convenience-apis](../2026-05-23-convenience-apis)) |
| New access modes / payment (x402) | No spec change driving them here |
| Route-group DSL endpoint style | Not chosen (per-endpoint `RequireAAuth` selected) |
| Multi-resource (multi-vhost) hosting in one process | Design-noted below; **no current need** — process-per-origin is the supported topology |

---

## Design notes (deferred — no current need)

### Multiple `AAuthResourceOptions` / "two pipelines in one process"

Raised during review: do we have enough primitives for a consumer to run more
than one resource pipeline in one process, without re-introducing verbosity?

**Spec grounding.** A resource's identity *is* its origin/issuer URL; its public
`/.well-known/aauth-resource.json` carries one `issuer`, one key set, one advisory
`access_mode` — and `access_mode` is explicitly per-endpoint-overridable at runtime
([spec L190/L2598/L2600](../../../aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md#L2598)).
So there are two different "second pipeline" meanings:

1. **Same origin, varied enforcement per endpoint group** (e.g. tighter
   `ClockSkew` / different `TrustedAuthTokenIssuers` on `/admin`). This is **one
   resource** per the spec, and it is **already expressible with low verbosity** —
   the identity/trust/posture knobs are explicit options
   (`AAuthVerificationOptions.ResourceIdentifier` / `TrustedAuthTokenIssuers` /
   `RequireIssuerVerification` / `ClockSkew`; `UseAAuthChallenge(ChallengeOptions)`),
   composed under `UseWhen(...)` exactly as the mapper composes them. No new
   primitives needed.

2. **Two distinct origins (vhosts) in one process.** The only spec-meaningful
   "two identities," and today it forces a drop below the helpers. Most of what a
   second identity needs is already parameterized (resource id, trust, challenge
   key); the shared `AAuthVerifier`/resolver/discovery singletons are infra (not
   identity) and **should stay shared** — making them per-config would be the
   verbosity regression. The **one real gap** is the well-known surface:
   `MapAAuthResourceWellKnown` is fixed-path (two calls collide on
   `/.well-known/aauth-resource.json`) and the JWKS dedup is keyed by the *builder*
   (`ConditionalWeakTable<IEndpointRouteBuilder,…>` in
   [WellKnownEndpoints.cs](../../../src/AAuth/Server/Metadata/WellKnownEndpoints.cs)),
   so two origins' keysets silently merge.

**Design conclusion (when/if a need appears):** do **not** add `IOptions`/named
registration. Make two small, forward-compatible moves so `UseWhen(host)`
composition completes the picture: (a) make `MapAAuthResourceWellKnown`
host-scopable (usable inside a `MapWhen(host)` branch); (b) key the JWKS dedup by
*issuer* instead of by builder. Keep the infra singletons shared and identity/trust
as the explicit options they already are. Also worth noting: `AAuthResourceOptions`
fuses identity (1/origin) with verification tuning (N possible); if this is ever
revisited, the cleaner split is identity-metadata options vs enforcement options
rather than named instances of the fused object.

**Status:** deferred, no implementation. Process-per-origin remains the supported
topology; the `UseWhen` recipe is the escape hatch for the rare in-process case.
</content>
