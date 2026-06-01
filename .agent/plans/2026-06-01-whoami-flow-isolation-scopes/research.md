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
| G8 | PS-asserted identity claims (`sub`/`email`/`tenant`/`roles`/`groups`) are mapped to flat ASP.NET claims with no link to the asserting `iss`. `RequireRole`/`IsInRole` match value-only, so identical role/sub values from different PSes collide. | Resource MUST namespace asserted claims by the asserting PS; `(iss, sub)` identifies the user. | **Fix (new Phase 9)** — honor namespacing; design below. |
| G9 | The PS does not verify the resource token: `MockPersonServer` base64-decodes the payload and trusts `iss`/`scope` from an unsigned blob; the SDK has no resource-token-side verifier (only auth-token `VerifyAuthTokenWithJwksAsync`). | Spec §Resource Token Verification: the recipient MUST verify `typ`/`dwk`/signature (via `{iss}/.well-known/aauth-resource.json` JWKS), `exp`/`iat`, `aud`, `agent`, `agent_jkt`, and `mission.approver`. | **Fix (new Phase 10)** — add SDK `VerifyResourceTokenAsync`; use it in the mock PS; design below. |

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

## Claim namespacing by the asserting PS (G8 investigation, 2026-06-01)

### Spec model (normative)

- `## What AAuth Provides` (line 162) and the PS-asserted overview (line 298):
  > "Any agent's PS can assert identity claims to any resource without bilateral
  > setup; **the resource namespaces those claims by the asserting PS** — the same
  > `sub` value from a different PS is a different subject. … the resource …
  > creates or matches a user record based on whether it has seen this `(iss, sub)`
  > before."
- Auth token claims (`### Auth Token`, line ~1568): `iss` is "the URL of the
  server that issued the auth token — an AS (four-party) or a PS asserting identity
  (three-party)." Identity claims subject to namespacing: `sub`, `email`,
  `tenant`, `groups`, `roles` (the latter two from `## Scopes`, line 1783, via
  RFC 9068 / SCIM).
- **Namespacing key = the auth-token `iss`.** Two different PSes asserting the
  same literal `roles:["admin"]` or `sub:"u1"` are asserting about **different**
  principals; the resource must not conflate them.

### Current SDK behaviour (un-namespaced)

- `AAuthAuthenticationHandler` mints `sub`→`ClaimTypes.NameIdentifier`,
  `roles`→`ClaimTypes.Role`, `groups`→`aauth:group`, and `iss`→`aauth:issuer`
  as **separate, flat** claims, all with the default identity issuer
  (`"LOCAL AUTHORITY"`). Nothing ties an identity claim to the `iss` that
  asserted it.
- `RequireRole` / `ClaimsPrincipal.IsInRole` match the **value only** and ignore
  `Claim.Issuer`. So a `whoami-admin` role from PS-A and from PS-B satisfy the
  same policy — a cross-PS collision the spec explicitly forbids.
- `AAuthVerificationOptions` has no trusted-issuer allowlist for the **inbound**
  auth token (only `UpstreamTokenValidator` has `trustedIssuers`, and only for
  the call-chaining upstream token). Any auth token whose `iss` JWKS verifies is
  accepted, regardless of which PS it is.

### Design options to honor namespacing in the ASP.NET claims model

1. **Provenance — set `Claim.Issuer = result.Issuer`** on each PS-asserted
   identity claim (`sub`, `email`, `tenant`, `roles`, `groups`) when minting them.
   Idiomatic .NET; records *which* PS asserted each claim. Cheap, non-breaking.
   **Necessary but not sufficient** — `RequireRole`/`IsInRole` still ignore issuer.
2. **User key — surface `(iss, sub)`** explicitly (e.g. a composite
   `aauth:sub_iss` claim and/or set `NameIdentifier.Issuer = iss`) so resources
   match user records on the tuple, exactly as the spec says. Demo response shows
   the namespaced identity.
3. **Enforcement isolation (the real decision):**
   - **Option A — trusted-issuer allowlist on verification.** Add
     `AllowedIssuers` (a.k.a. trusted PSes) to `AAuthVerificationOptions`; reject
     (or strip identity claims from) auth tokens whose `iss` is not allowlisted.
     With a single trusted PS, collisions are impossible because foreign-PS
     claims never enter. Default empty = trust any verified issuer (preserves
     current sample behaviour). Simplest, strongest, matches "the resource
     decides which PS it trusts."
   - **Option B — issuer-aware policies.** `AddAAuthRolePolicy(name, role, issuer)`
     overload backed by a custom requirement that checks both the role value and
     that it was asserted by a specific `iss` (via `Claim.Issuer`). More granular;
     more code; needed only when one resource trusts multiple PSes with
     overlapping role vocabularies.
   - **Option C — value-namespacing** (`{iss}#role`). Rejected: breaks
     `RequireRole("role")` ergonomics and the "works out of the box" property.

### Recommendation

> **Update 2026-06-01 (backward compatibility waived — fail-closed design):**
> Backward compatibility is **not** a requirement for this plan (alpha; "Spec is
> king"). That removes the soft edges and makes the spec's namespacing the **only**
> behaviour:
>
> - **Layers 1 + 2 are mandatory, not additive.** The user identity *is*
>   `(iss, sub)`. `Claim.Issuer = iss` is set on every PS-asserted identity claim
>   unconditionally, and `aauth:sub_iss` is the canonical principal key the demo
>   matches on. No flat un-namespaced `sub`/`role` kept "for compatibility."
> - **Option A is always on and fail-closed.** `AllowedIssuers` is required; an
>   auth token whose `iss` is not in the trusted set is **rejected at
>   verification** (not merely stripped). Empty/unset = **reject all PS-asserted
>   tokens** — the safe default and the spec's own framing ("the resource decides
>   which PS it trusts"). This eliminates cross-PS collisions *by construction*
>   rather than by documentation.
> - **Keep `RequireRole` value-only ergonomics.** Because the fail-closed
>   allowlist guarantees only trusted-PS claims ever reach the principal, value-only
>   `RequireRole` is safe again. **Option B** (issuer-aware policy) remains an
>   optional add-on for the niche case of one resource trusting multiple PSes with
>   overlapping role vocabularies — not built now.
> - **Cost (in scope):** every 3-party flow + `WhoAmIFlowTests` + any sample that
>   verifies a PS-asserted token must now declare its trusted PS (a one-line
>   `AllowedIssuers` config each). Acceptable under the waived-compat rule.
>
> Net: less code (no "trust any" branch), stronger isolation, fully spec-aligned.

## PS-side resource-token verification (G9 investigation, 2026-06-01)

### Spec model (normative)

Spec §"Resource Token Verification"
(`aauth-spec/draft-hardt-oauth-aauth-protocol.md`) lists the 7 checks the
recipient (PS in three-party; AS in four-party) MUST run on the
`resource_token` before acting on it:

1. Decode header; `typ == aa-resource+jwt` (and reject `alg: none`).
2. `dwk == aauth-resource.json`; discover JWKS at `{iss}/.well-known/aauth-resource.json`,
   locate `kid`, verify the JWT signature.
3. `exp` in the future; `iat` not in the future.
4. `aud` matches the recipient's own identifier (the PS).
5. `agent` matches the requesting agent's identifier (from the HTTP-sig context).
6. `agent_jkt` matches the JWK Thumbprint of the key that signed the request to `/token`.
7. If `mission` present, `mission.approver` matches this PS.

### Current behaviour (un-verified)

`samples/MockPersonServer/Program.cs` splits the compact JWT and
`JsonNode.Parse`s the payload, then trusts `iss` (→ auth-token `aud`) and
`scope` directly — no signature check, no `typ`/`dwk` check, no
`agent`/`agent_jkt` binding. The file comment already flags this as a demo
shortcut. A forged resource token can therefore smuggle any `aud`/`scope`
(only the absolute-http(s) `iss` shape is validated today). The displayed
consent scope (G5 work) is thus shown from an **unverified** token.

### SDK building blocks that already exist

- `TokenVerifier.Verify(jwt, issuerKey, expectedType, expectedDwk, expectedAudience)`
  covers steps 1–4 (alg/none rejection, `typ`, `dwk`, signature, `exp`/`iat`,
  `aud`, `iss` shape) once the issuer key is resolved.
- `MetadataClient` + `JwksClient.ResolveKeyAsync(jwksUri, kid)` perform the
  step-2 discovery (the same path `VerifyAuthTokenWithJwksAsync` uses for auth
  tokens, and `UpstreamTokenValidator` uses for call chaining).
- There is **no** resource-token counterpart to `VerifyAuthTokenWithJwksAsync`,
  so every PS reimplements discovery + steps 5–7 by hand (the mock PS skips
  them entirely).

### Recommendation

Add a symmetric SDK convenience `TokenVerifier.VerifyResourceTokenAsync(...)`
that takes the compact `resource_token`, the recipient's own identifier
(expected `aud`), the requesting `agent` id, the request signing-key thumbprint
(`agent_jkt`), and a `JwksClient`/`MetadataClient`; it resolves the resource's
JWKS from `{iss}/.well-known/aauth-resource.json`, calls the existing `Verify`
for steps 1–4, then enforces steps 5–7 and returns the parsed scope/mission.
Wire the mock PS `/token` handler to call it and reject with the spec error
codes (`invalid_resource_token` / `expired_resource_token`) on failure, so the
consent screen and issued auth token derive from a **verified** token. `mission`
verification (step 7) is optional for the mock PS (no AAuth-Mission in the demo)
but the SDK helper should support it for completeness.

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

> **Update 2026-06-01 (self-review + maintainer-directed fixes):** The Implementation
> Validator returned **no CRITICAL/HIGH findings — sound to merge**. It confirmed the
> scope bypass is closed (`Level == Authorized` gate), the role policy is correct,
> pipeline isolation is sound, claim names are consistent end-to-end, and the
> identity-fallback removal is a net security improvement. Three MEDIUM follow-ups were
> raised and, per maintainer direction, **applied on the branch**:
>
> - **M1 — unconditional role assertion.** The mock PS asserted `whoami-admin`/`demo-users`
>   on *every* auth token, so any agent satisfied `/jwt/roles` and role DENIAL was never
>   exercised. Fixed: `MockPersonServer` now asserts roles/groups only for recognized
>   admin demo agents (`IsAdminAgent` ⇒ id starts with `aauth:demo@`). A production PS
>   would resolve directory membership instead.
> - **M2 — missing negative tests.** Added `AAuthScopeHandlerTests` (Authorized+scope ⇒
>   succeed; Authorized+wrong-scope ⇒ fail; Identified/Pseudonymous+stray-scope ⇒ fail;
>   no result ⇒ fail) and `WhoAmIFlowTests.RoleFlow_Returns403_WhenAgentLacksRole`
>   (guest agent `aauth:guest@ap.test` completes the exchange but gets a 403 at
>   `/jwt/roles`).
> - **M3 — role/challenge dependency.** Documented (in `samples/WhoAmI/Program.cs` and
>   `docs/server/authorization-policies.md`) that `/jwt/roles` challenges only for the
>   `whoami` scope; if a spec-compliant PS withholds the role the result is an
>   unrecoverable 403, since insufficient-role step-up (G7) is out of scope.
>
> LOW findings (L1 role/scope decoupling — intentional; L2 brittle demo URL construction;
> L3 `aauth:group` emitted but unconsumed) were accepted as informational and left as-is.
> After the fixes: unit 333 + conformance 345 pass; e2e 20/20 pass.
