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

## Out of Scope

| Item | Reason |
|---|---|
| G6 multi-scope AllOf/AnyOf requirements | Single scope per endpoint suffices; spec scope is a set but demo needs one each |
| G7 step-up re-challenge on insufficient-scope token | Spec MAY; request-time scoping is compliant |
| Redeploying `whoami.aauth.dev` live instance | Infra/ops, outside repo |
| Federated (four-party) AS pipeline in WhoAmI | WhoAmI is PS-asserted; AS demo lives elsewhere |
