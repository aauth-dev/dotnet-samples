# WhoAmI Flow Isolation + Scopes/Policy — Research

ms.date: 2026-06-01

Research-only document. No task lists here (see `implementation-plan.md`).

## Goal

Refactor `samples/WhoAmI` so each AAuth resource access mode is an **independent,
self-contained pipeline**, and add a first-class demonstration of **scope- and
role-based authorization** using the ASP.NET Core authn/authz integration that
already ships in the SDK. Spec compliance is the golden rule; backward
compatibility with existing paths/response shapes is explicitly waived (alpha).

## Spec grounding (every design choice maps to a spec section)

All references are to `aauth-spec/draft-hardt-oauth-aauth-protocol.md` unless noted.

| Design area | Spec section | Key requirement |
|---|---|---|
| Four access modes are distinct | `## Resource Access Modes` | Identity-based, Resource-managed (2P), PS-asserted (3P), Federated (4P) are separate modes, each adding parties. Justifies one isolated pipeline per mode. |
| Signing vs. access mode orthogonality | `docs/signing-modes/overview.md` "Valid Combinations per Access Mode" | Identity-based ⇒ `hwk`/`jwks_uri`; PS-asserted ⇒ `jwt` only; key rotation ⇒ `jkt-jwt`. Drives which signing mode each pipeline verifies. |
| Identity-based access | `### Identity-Based Access {#overview-identity-access}` | Resource verifies signature, applies its own policy, no tokens beyond agent token. ⇒ `/hwk`, `/jwks-uri` pipelines. |
| PS-asserted access | `### PS-Asserted Access (Three-Party)` | Resource issues resource token (`aud=PS`), PS asserts identity + **consent for the requested scope**, resource applies policy on resulting claims. ⇒ `/jwt*` pipelines. |
| Resource token `scope` is REQUIRED | `## Authorization Endpoint Request` (line ~603) | "`scope` (REQUIRED): space-separated scope values the agent is requesting." ⇒ each scoped endpoint must request its own scope in the resource token. |
| PS asserts `sub`/`email`/`tenant`/`groups`/`roles` | `### PS-Asserted Access` + `## What AAuth Provides` (OIDC vocab) | Auth token carries identity claims incl. `roles`/`groups`. ⇒ SDK should map these for RBAC. |
| Step-up authorization | `## Auth Token Required {#requirement-auth-token}` | "A resource MAY return `requirement=auth-token` with a new resource token to a request that already includes an auth token … step-up authorization at any time." Step-up is a MAY; request-time scoping is sufficient and compliant. |
| Resource is enforcement point | `## Policy Evaluation Points` | Resource "decides what is required … and enforces the resulting auth token at access." ⇒ scope/role policy enforcement belongs in the resource. |
| Scopes reuse OIDC vocabulary | `## Relationship to Existing Standards` | AAuth reuses OIDC scope values + identity claims; aligns with ASP.NET claims model. |

## Current state (as-is)

`samples/WhoAmI/Program.cs` is one app multiplexing four paths via `UseWhen`:

- `/hwk` — pseudonymous (`hwk`), signature only, `RequireIssuerVerification=false`.
- `/jkt-jwt` — pseudonymous + key delegation (`jkt-jwt`), signature only.
- `/jwks-uri` — agent identity (`jwks_uri`), signature only.
- `/` — three-party (`jwt`), full issuer + `aud` + PoP + `act`; challenge minted
  manually in `ChallengeWithResourceToken` (does **not** use `UseAAuthChallenge`).

Problems:
1. Root pipeline uses a fragile **negative** path match (`!StartsWith(...) && ...`).
2. All handlers hand-roll `ctx.GetAAuthVerification()` / `GetAAuthTokenType()`;
   the ASP.NET authn/authz layer is unused.
3. Only one scope (`whoami`) exists and it is **never enforced** — no
   scope/policy demonstration anywhere in the sample set.

## SDK capability inventory (what already exists)

- `src/AAuth/Server/AAuthScopeRequirement.cs` — single-scope requirement.
- `src/AAuth/Server/AAuthScopeHandler.cs` — succeeds if `result.Scopes.Contains(scope)`.
- `src/AAuth/Server/AAuthAuthenticationHandler.cs` — maps `AAuthVerificationResult`
  → `ClaimsPrincipal`. Emits `aauth:scope` (one per scope), `aauth:level`, etc.
- `src/AAuth/DependencyInjection/AAuthResourceServiceCollectionExtensions.cs` —
  `AddAAuthAuthentication`, `AddAAuthAuthorization` (level policies
  `AAuth.Authenticated`/`Identified`/`Authorized`), `AddAAuthScopePolicy`.
- `tests/AAuth.Conformance/HttpSignatures/AuthorizationIntegrationTests.cs` — the
  only existing demonstration of `RequireAuthorization(...)` with scope policies.

## SDK gaps identified

| # | Gap | Spec basis | Decision |
|---|---|---|---|
| G1 | No role/group claim mapping; `[Authorize(Roles=…)]` / `RequireRole()` impossible. Handler never emits `ClaimTypes.Role`. | PS asserts `roles`/`groups`. | **Fix** — map `roles`→`ClaimTypes.Role`, `groups`→`aauth:group`. |
| G2 | `AuthTokenBuilder` cannot emit `roles`/`groups`. | Auth token identity claims. | **Fix** — add `Roles`/`Groups` init props. |
| G3 | `AAuthVerificationResult` has no `Roles`/`Groups`; middleware does not surface them. | Same. | **Fix** — add props + populate from verified auth token. |
| G4 | Scope handler ignores level; a non-Authorized token with a stray scope claim could pass. | Scopes only meaningful on auth tokens (Authorized). | **Fix** — require `AAuthLevel.Authorized`. |
| G5 | MockPersonServer hardcodes issued `scope=whoami`, ignoring the resource token's requested scope. | Resource token `scope` REQUIRED; PS confirms consent "for the requested scope". | **Fix** — echo requested scope from resource token. |
| G6 | Multi-scope (AllOf/AnyOf) requirement semantics absent. | Scope is a space-separated set. | **Out of scope** — single scope per endpoint suffices for the demo. |
| G7 | Step-up re-challenge on insufficient-scope auth token not implemented in scope handler. | Step-up is a MAY. | **Out of scope** — request-time scoping is compliant; note as future. |

## Scope/role taxonomy for the demo

- `whoami` — baseline three-party identity (existing).
- `whoami:admin` — elevated; demonstrates a second scope + policy gate.
- Role `whoami-admin` — demonstrates `RequireRole` / `[Authorize(Roles=…)]`-style RBAC.

The MockPersonServer issues `roles: ["whoami-admin"]` for the demo agent so the
role-gated endpoint can be exercised end-to-end.

## Target pipeline layout (every flow independent)

Each mode gets its own `MapGroup` with a dedicated verification branch:

| Group | Mode (spec) | Signing | Verification | Authz |
|---|---|---|---|---|
| `/hwk` | Identity-based (pseudonymous) | `hwk` | sig only | none (pseudonymous) |
| `/jkt-jwt` | Identity-based + key delegation | `jkt-jwt` | sig only | none |
| `/jwks-uri` | Agent identity | `jwks_uri` | sig only | `AAuth.Identified` |
| `/jwt` | PS-asserted (3P) baseline | `jwt` | full + challenge (`whoami`) | `AAuth.Scope.whoami` |
| `/jwt/admin` | PS-asserted (3P) elevated | `jwt` | full + challenge (`whoami:admin`) | `AAuth.Scope.whoami:admin` |
| `/jwt/roles` | PS-asserted (3P) RBAC | `jwt` | full + challenge (`whoami`) | `AAuth.Role.whoami-admin` |

`/` becomes a small index listing the available flows (no auth).

## Consumers / blast radius

| Consumer | Coupling | Action |
|---|---|---|
| `samples/AgentConsole/Program.cs` | maps `jwt→/`, others→`/hwk` etc. | Update jwt path → `/jwt`. |
| `samples/GuidedTour` | `WhoAmIUrl`, per-mode targeting, code snippets | Subagent: update targeting + snippets. |
| `samples/SampleApp` | Blazor pages call WhoAmI; playwright specs | Subagent: update jwt call to `/jwt`; assertions. |
| `tests/AAuth.Tests/Integration/WhoAmIFlowTests.cs` | asserts JSON keys, `/`, 401 shape | Update to `/jwt`, new scope/role assertions. |
| `tests/e2e/**` | port 5000, specs | Update specs as needed; validate. |
| `Makefile`, `LiveWhoAmITest`, `whoami.aauth.dev` | orchestration + live instance | Makefile targets unchanged (port same); note live redeploy out of scope. |

## Open questions

- None blocking. Step-up re-challenge (G7) and multi-scope (G6) deferred; raise
  with maintainer only if a future phase needs them.

> **Update 2026-06-01 (console validation):** All six AgentConsole permutations
> pass on the branch — `hwk`, `jkt-jwt`, `jwks_uri` (200, signature-only/identity)
> and the three-party `jwt`, `jwt/admin`, `jwt/roles` (200 with `scope:["whoami"]`,
> `access:"admin"` + `scope:["whoami:admin"]`, and `access:"rbac"` + roles/groups).
> Earlier 400/500 results were a **pre-existing demo quirk**, not a regression:
> `MockAgentProvider` keeps enrollments in memory while `AgentConsole` caches its
> enrollment on disk (`~/.local/share/aauth-agent-console/<sub>.json`). After the
> AP restarts it forgets the enrollment, so the signed `/refresh` (jwt/jkt-jwt) and
> the AP-hosted `/agents/<sub>/jwks.json` (jwks_uri) return 4xx for the stale agent.
> `hwk` is unaffected because it performs no refresh. Clearing the cache so the
> console re-enrolls against the running AP makes every mode succeed. `MockAgentProvider`
> is unmodified by this branch (`git diff --name-only origin/main` excludes it), so
> the quirk is independent of the flow-isolation refactor. Possible future hardening
> (out of scope, needs maintainer sign-off): have `AgentConsole` auto-re-enroll on a
> 400 `invalid_grant` from `/refresh`.
