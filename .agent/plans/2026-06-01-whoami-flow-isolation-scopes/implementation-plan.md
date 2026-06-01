# WhoAmI Flow Isolation + Scopes/Policy — Implementation Plan

ms.date: 2026-06-01

Companion research: [research.md](research.md). Golden rule: **spec compliance**
(`aauth-spec/draft-hardt-oauth-aauth-protocol.md`). Backward compatibility is
waived (alpha). Validate with the e2e suite as work proceeds. New findings →
`research.md` with a dated `> **Update**` callout. Design changes → ask maintainer.

## Phase 1: Research & decisions ✅

Captured in `research.md`: spec mapping, SDK gaps (G1–G7), target pipeline
layout, scope/role taxonomy, consumer blast radius.

### Definition of Done

- [x] Research doc created with spec section references per area
- [x] SDK gaps catalogued with fix/out-of-scope decisions
- [x] Target pipeline layout agreed (6 isolated groups + index)

---

## Phase 2: SDK enhancements (RBAC + scope correctness)

Spec basis: PS-asserted access asserts `roles`/`groups`; resource enforces.

Files:
- `src/AAuth/Tokens/AuthTokenBuilder.cs` — add `Roles`/`Groups` (`IReadOnlyList<string>?`)
  emitting `roles`/`groups` array claims (G2).
- `src/AAuth/Server/AAuthVerificationResult.cs` — add `Roles`/`Groups`
  (`IReadOnlySet<string>`) (G3).
- `src/AAuth/Server/AAuthVerificationMiddleware.cs` — populate `Roles`/`Groups`
  from verified auth token claims (G3).
- `src/AAuth/Server/AAuthAuthenticationHandler.cs` — emit `ClaimTypes.Role` per role
  + `aauth:group` per group; add `RoleClaimType`/`GroupClaimType` constants (G1).
- `src/AAuth/Server/AAuthScopeHandler.cs` — require `AAuthLevel.Authorized` before
  scope match (G4).
- `src/AAuth/DependencyInjection/AAuthResourceServiceCollectionExtensions.cs` — add
  `AddAAuthRolePolicy(name, role)` convenience (mirrors `AddAAuthScopePolicy`).

### Definition of Done

- [x] `AuthTokenBuilder` emits `roles`/`groups` when set; omits when null
- [x] `AAuthVerificationResult.Roles`/`Groups` populated for auth tokens
- [x] Auth handler emits `ClaimTypes.Role` + `aauth:group`
- [x] Scope handler requires Authorized level
- [x] `AddAAuthRolePolicy` registers a `RequireRole`-backed policy
- [x] `dotnet build` clean; existing unit/conformance tests pass

---

## Phase 3: WhoAmI refactor — isolated pipelines + scope/role demo

Files: `samples/WhoAmI/Program.cs` (+ split helpers if needed).

- Register `AddAAuthResource`, `AddAAuthAuthentication`, `AddAAuthAuthorization`,
  `AddAAuthScopePolicy("AAuth.Scope.whoami","whoami")`,
  `AddAAuthScopePolicy("AAuth.Scope.whoami:admin","whoami:admin")`,
  `AddAAuthRolePolicy("AAuth.Role.whoami-admin","whoami-admin")`.
- One `MapGroup` per mode, each with its own verification branch (replace the
  negative `UseWhen` match):
  - `/hwk`, `/jkt-jwt` — sig only, pseudonymous response (unchanged shape).
  - `/jwks-uri` — sig only, `RequireAuthorization("AAuth.Identified")`.
  - `/jwt` — `UseAAuthVerification` (full) + `UseAAuthChallenge` (scope `whoami`)
    + `UseAuthentication`/`UseAuthorization`; `RequireAuthorization("AAuth.Scope.whoami")`.
  - `/jwt/admin` — challenge scope `whoami:admin`; `RequireAuthorization("AAuth.Scope.whoami:admin")`.
  - `/jwt/roles` — `RequireAuthorization("AAuth.Role.whoami-admin")`.
- `/` — plain index JSON listing flows (no auth).
- Responses surface verified claims from `ctx.User` / `AAuthVerificationResult`
  (scopes, roles where relevant).

### Definition of Done

- [x] No negative path-matching; each flow in its own group
- [x] `/jwt`, `/jwt/admin`, `/jwt/roles` enforce scope/role policies
- [x] Challenge middleware requests the correct per-endpoint scope
- [x] WhoAmI builds and runs; `/` returns flow index

---

## Phase 4: MockPersonServer — requested-scope echo + roles

Files: `samples/MockPersonServer/Program.cs`.

- Parse `scope` from the resource token and issue the auth token with that scope
  (G5), instead of hardcoding `whoami`. Fallback to `whoami` if absent.
- Track consent per `(agent, resource, scope)` (already keyed by scope; thread
  the parsed scope through `pending.Add` and `IssueAuthToken`).
- Issue `roles: ["whoami-admin"]` (+ optional `groups`) for the demo agent so
  `/jwt/roles` works end-to-end.
- Publish `whoami:admin` in `ScopeDescriptions`.

### Definition of Done

- [x] PS issues the scope requested in the resource token
- [x] PS issues `roles` for the demo agent
- [x] `scopes_supported`/`scope_descriptions` include `whoami:admin`
- [x] PS builds and runs

---

## Phase 5: Update tests (integration + conformance + e2e)

Files: `tests/AAuth.Tests/Integration/WhoAmIFlowTests.cs`,
`tests/AAuth.Conformance/HttpSignatures/AuthorizationIntegrationTests.cs` (if
affected), `tests/e2e/**`, `samples/*/playwright-tests/**`.

- Point three-party assertions at `/jwt`; add `/jwt/admin` (scope) and
  `/jwt/roles` (role) coverage.
- Keep 401 `AAuth-Requirement` resource-token shape assertions.

### Definition of Done

- [x] Integration tests updated and green
- [x] New scope + role flows covered
- [x] `dotnet test` passes for unit + conformance + integration

---

## Phase 6: Validate end-to-end

- Run the e2e Playwright suite (`tests/e2e`) against the refactored stack.

### Definition of Done

- [x] e2e suite passes (or failures triaged to consumer updates in Phase 7)
- [x] AgentConsole permutations validated (all 6 modes 200; see research Update)

---

## Phase 7: Docs + sample code snippets (subagents)

Use a **separate subagent for each sample** and **one subagent for all docs**.

- Subagent A — `samples/GuidedTour`: update WhoAmI targeting, `CodeSnippets.cs`,
  README, playwright specs for new paths/scope-role flows.
- Subagent B — `samples/SampleApp`: update Blazor pages calling WhoAmI (`/`→`/jwt`),
  playwright specs, README.
- Subagent C — `samples/AgentConsole` + `samples/WhoAmI` README + `samples/README.md`:
  jwt path → `/jwt`; document the new flows.
- Subagent D — all `docs/**`: `server/authorization-policies.md`,
  `server/challenge-middleware.md`, `server/verification-middleware.md`,
  `reference/dependency-injection.md`, `signing-modes/*`, workflows — reflect
  isolated pipelines + scope/role policies + `AddAAuthRolePolicy`.

### Definition of Done

- [x] Each sample updated by its subagent; all samples build
- [x] Docs updated by docs subagent; code snippets compile/match SDK
- [x] No stale references to the old root `/` three-party path

---

## Phase 8: Self-review + surface feedback

- Run a self-reviewer subagent (Implementation Validator) over the diff for spec
  compliance, correctness, and consistency.
- **Present findings to the maintainer before fixing anything.**

### Definition of Done

- [x] Reviewer findings collected with severity grades
- [x] Findings presented to maintainer
- [x] Fixes applied only after maintainer direction

---

## Phase 9: Honor PS namespacing of asserted claims (G8)

Spec basis: "the resource namespaces those claims by the asserting PS — the same
`sub` value from a different PS is a different subject … matches a user record on
`(iss, sub)`." Namespacing key = the auth-token `iss`. See research §"Claim
namespacing by the asserting PS (G8 investigation)". **Backward compatibility is
waived** — namespacing is mandatory and issuer trust is fail-closed.

### Implementation Decisions (confirmed 2026-06-01)

- [x] **Namespacing mandatory.** `(iss, sub)` is the canonical user identity;
  `Claim.Issuer = iss` set on every PS-asserted identity claim; no flat
  un-namespaced `sub`/`role` retained.
- [x] **Enforcement = Option A, fail-closed.** `AllowedIssuers` is required; a
  token whose `iss` is not trusted is **rejected at verification**. Empty/unset =
  **reject all PS-asserted tokens** (safe default). No "trust any" branch.

> **Implementation note (2026-06-01):** the existing
> `AAuthVerificationOptions.TrustedAuthTokenIssuers` property is **reused** as
> the fail-closed allow-list (no new `AllowedIssuers` property). Its prior
> permissive semantics (null = trust any) were flipped to fail-closed
> (null/empty = reject all PS-asserted tokens).
- [x] **Keep `RequireRole` value-only.** The fail-closed allowlist provides the
  isolation; Option B (issuer-aware policy overload) is **not** built now.
- [x] **User-key surfacing:** composite `aauth:sub_iss` (`{iss}|{sub}`) claim +
  `Claim.Issuer` provenance.

Files:
- `src/AAuth/Server/AAuthAuthenticationHandler.cs` — set `Claim.Issuer = result.Issuer`
  on `NameIdentifier`/`Role`/`aauth:group`/`email`/`tenant`; add a composite
  `aauth:sub_iss` (`{iss}|{sub}`) claim + constant.
- `src/AAuth/Server/AAuthVerificationOptions.cs` — add `AllowedIssuers`
  (`IReadOnlySet<string>?`); semantics: null/empty = reject all PS-asserted
  (issuer-verified) tokens.
- `src/AAuth/Server/AAuthVerificationMiddleware.cs` — when an auth token's `iss`
  is not in `AllowedIssuers`, reject with 401 (issuer not trusted); surface the
  decision on `AAuthVerificationResult`. Signature-only flows (`hwk`/`jkt-jwt`/
  `jwks_uri`) are unaffected (no `iss` assertion to namespace).
- `samples/WhoAmI/Program.cs` — set `AllowedIssuers` to the demo MockPersonServer
  on the `/jwt*` branches; surface namespaced identity (`(iss, sub)`) in responses.
- All other 3-party consumers/tests that verify PS-asserted tokens — add the
  one-line trusted-PS config (in scope; compat waived).
- `docs/server/authorization-policies.md` + `verification-middleware.md` — document
  mandatory namespacing + fail-closed `AllowedIssuers`.

Tests:
- `tests/AAuth.Tests/Server/AAuthAuthenticationHandlerTests.cs` — identity claims
  carry `Claim.Issuer == iss`; `aauth:sub_iss` present and well-formed.
- `tests/AAuth.Tests/Integration/WhoAmIFlowTests.cs` — a token from a
  non-allowlisted issuer is **rejected (401)**; the allowlisted issuer succeeds;
  empty allowlist rejects all PS-asserted tokens.

### Definition of Done

- [x] Identity claims carry asserting-PS provenance (`Claim.Issuer`) + `(iss, sub)` surfaced
- [x] `AllowedIssuers` is fail-closed; untrusted/absent `iss` → 401
- [x] WhoAmI demo trusts only its MockPersonServer and shows namespaced identity
- [x] All 3-party consumers/tests updated to declare their trusted PS
- [x] Build clean; unit + conformance + e2e green

---

## Phase 10: PS-side resource-token verification (G9)

Spec basis: §"Resource Token Verification" — the recipient MUST verify the
`resource_token` (`typ`/`dwk`/signature via `{iss}/.well-known/aauth-resource.json`,
`exp`/`iat`, `aud`, `agent`, `agent_jkt`, optional `mission.approver`) before
acting on it. The mock PS currently trusts an unsigned payload (G9). See research
§"PS-side resource-token verification (G9 investigation)".

### Implementation Decisions (confirmed 2026-06-01)

- [x] **Add an SDK convenience** `TokenVerifier.VerifyResourceTokenAsync(...)`
  (symmetric to `VerifyAuthTokenWithJwksAsync`) that does JWKS discovery + spec
  steps 1–7; reusable by any SDK-based PS. Then wire it into the mock PS.
- [x] **Fail-closed:** verification failure → reject `POST /token` with the spec
  error (`invalid_resource_token` / `expired_resource_token`), 400/401 per
  §"Error Response Format". The consent screen + issued auth token derive only
  from a verified token.
- [x] **`mission` (step 7) optional** for the mock PS (no AAuth-Mission in the
  demo), but the SDK helper supports it.

Files:
- `src/AAuth/Tokens/TokenVerifier.cs` — add
  `VerifyResourceTokenAsync(jwt, expectedAudience, expectedAgentId, expectedAgentJkt, jwks, metadata, expectedApprover?, ct)`:
  resolve issuer JWKS from `{iss}/.well-known/aauth-resource.json`, call existing
  `Verify` for steps 1–4 (`typ=aa-resource+jwt`, `dwk=aauth-resource.json`,
  `aud`), then enforce `agent`/`agent_jkt`/`mission.approver` (steps 5–7); return
  the verified scope/mission.
- `samples/MockPersonServer/Program.cs` — replace the manual base64 decode in the
  `/token` handler with `VerifyResourceTokenAsync` (pass the PS's own issuer as
  `aud`, the HTTP-sig `agent`/`agent_jkt` from the verified request); map failures
  to the spec error response. Keep the verified `iss`→`aud` and `scope` flow.
- `docs/server/verification-middleware.md` (or a PS-focused doc) — document the
  resource-token verification helper and the 7 checks.

Tests:
- `tests/AAuth.Tests/Tokens/TokenVerifierTests.cs` — valid resource token passes;
  wrong `typ`/`dwk`, bad signature, expired, wrong `aud`, wrong `agent`/`agent_jkt`
  each rejected with the right error.
- `tests/AAuth.Tests/Integration/` (PS three-party) — a tampered/forged
  resource token is rejected at `POST /token`; the genuine flow still succeeds.

### Definition of Done

- [x] `VerifyResourceTokenAsync` enforces spec steps 1–7 with JWKS discovery
- [x] Mock PS rejects unverifiable resource tokens with the spec error codes
- [x] Consent screen + issued auth token derive only from a verified token
- [x] Unit coverage for each failure mode; three-party integration still green
- [x] Build clean; unit + conformance + e2e green

---

## Phase 11: Final validation sweep + authN/authZ wiring docs

Final phase. Validate that every doc, sample snippet, and console permutation
still holds after Phases 2–10, and add new authentication/authorization (authN/
authZ) guidance covering both ASP.NET Core hosting styles. Run as **parallel
subagents**; collect findings and **present to the maintainer before applying
non-trivial fixes** (consistent with Phase 8).

### 11a — Markdown validation (one subagent per user-facing markdown file)

Spawn a **separate subagent per markdown file** below; each verifies the file's
claims against the post-change codebase (paths, API names, scope/role/`iss`
namespacing behaviour, `/jwt` vs old `/` path, `AddAAuthRolePolicy`,
`AllowedIssuers`, resource-token verification) and reports stale spots with exact
fixes. **Scope = user-facing docs/READMEs only.** Exclude `.agent/plans/**`
(historical records) and `aauth-spec/**` (upstream spec — read-only reference).

- Root: `README.md`
- `docs/README.md`, `docs/concepts.md`, `docs/getting-started.md`
- `docs/advanced/*.md` (error-handling, key-management, missions, observability,
  platform-attestation, interaction-chaining)
- `docs/reference/*.md` (configuration, dependency-injection)
- `docs/server/*.md` (authorization-policies, challenge-middleware,
  multi-scheme-verification, replay-detection, resource-metadata, token-issuance,
  verification-middleware)
- `docs/signing-modes/*.md` (overview, agent-token-jwt, agent-identity-jwks-uri,
  key-rotation-jkt-jwt, pseudonymous-hwk)
- `docs/workflows/*.md` (bootstrap-enrollment, call-chaining, deferred-consent,
  federated-access, identity-based-access, ps-asserted-access,
  resource-managed-access)
- Sample/test READMEs: `samples/README.md`, `samples/{WhoAmI,MockPersonServer,
  Orchestrator,AgentConsole,GuidedTour,MockAgentProvider}/README.md`,
  `tests/e2e/README.md`, `tests/AAuth.Conformance/README.md`

### 11b — Sample code-snippet validation (subagent)

One subagent verifies the **interactive code snippets** in `samples/GuidedTour`
(`CodeSnippets.cs` + any snippet content rendered by the tour) and
`samples/SampleApp` (Blazor component snippets) still compile against and match
the current SDK surface (DI calls, scope/role policies, `/jwt*` paths, namespaced
identity). Report mismatches with exact corrections.

### 11c — Console permutation check (subagent or direct run)

Re-run all six `samples/AgentConsole` permutations (`hwk`, `jkt-jwt`, `jwks_uri`,
`jwt`, `jwt/admin`, `jwt/roles`) end-to-end against the running stack and confirm
each returns the expected result. Account for the known disk-cached-enrollment
quirk (clear `~/.local/share/aauth-agent-console/` so the console re-enrolls
against the running AP — see research Update). Report any genuine regression.

### 11d — New authN/authZ wiring docs

Add documentation elaborating the authentication (authN) and authorization
(authZ) details and how to wire AAuth up in **both** ASP.NET Core hosting styles:

- **Minimal APIs** — `MapGroup` + `RequireAuthorization("policy")` + the
  verification/challenge middleware ordering (as WhoAmI does).
- **Classic / MVC controllers** — `[Authorize(Policy = ...)]` / `[Authorize(Roles = ...)]`
  on controllers/actions, with the same `AddAAuthAuthentication`/
  `AddAAuthAuthorization`/`AddAAuthScopePolicy`/`AddAAuthRolePolicy` registration.

Cover: the authN pipeline (`AAuthAuthenticationHandler`, level mapping
Pseudonymous/Identified/Authorized, claim mapping incl. `Claim.Issuer = iss`
namespacing), the authZ pipeline (scope handler requires Authorized; role policy;
`(iss, sub)` principal key), and middleware ordering for each style. Suggested
home: a new `docs/server/authn-authz.md` (cross-linked from
`authorization-policies.md`, `verification-middleware.md`, and `docs/README.md`).

Files:
- New `docs/server/authn-authz.md` (+ index/cross-link updates).
- Fixes to any markdown/snippets flagged in 11a/11b (after maintainer sign-off).

### Definition of Done

- [x] One subagent per listed markdown file; findings collected with exact fixes
- [x] GuidedTour + SampleApp snippets verified against the current SDK
- [x] All six AgentConsole permutations confirmed (genuine regressions triaged)
- [x] `docs/server/authn-authz.md` added covering minimal-API **and** classic-MVC wiring
- [x] Findings presented to maintainer; approved fixes applied; docs links updated
- [x] Build clean; unit + conformance + e2e green

---

## Out of Scope

| Item | Reason |
|---|---|
| G6 multi-scope AllOf/AnyOf requirements | Single scope per endpoint suffices; spec scope is a set but demo needs one each |
| G7 step-up re-challenge on insufficient-scope token | Spec MAY; request-time scoping is compliant |
| Redeploying `whoami.aauth.dev` live instance | Infra/ops, outside repo |
| Federated (four-party) AS pipeline in WhoAmI | WhoAmI is PS-asserted; AS demo lives elsewhere |
