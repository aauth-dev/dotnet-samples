# Phase 12 — SDK public-surface design note (four-party)

> **Status: DELIVERED (2026-06-xx).** The user approved the full Phase 12 scope
> (R1–R3 + S2 + S3 + Keycloak Option B) with backward-compat **waived**. All
> items below marked as proposals are now implemented; the tables are retained
> as the as-built record. See the "Delivered" summary directly below.

## 0. Delivered (as-built)

- **R1** — `OnClaimsRequired` now returns a typed
  `AAuthClaimsResponse { required Subject; Claims }`
  (`src/AAuth/Headers/AAuthClaimsResponse.cs`); `AccessServerClient` validates a
  non-blank `Subject` and pushes `ToJson()`.
- **R2** — `AAuthClaimsRequirement.FromResponse` reads **only** the body
  `required_claims`; the header `claims` fallback and `ClaimsParameter` const are
  removed; absence → `FormatException`.
- **R3** — `AuthTokenBuilder.Tenant` added (named §Auth Token `tenant` claim),
  emitted after `sub`; `AdditionalClaims` kept for the open remainder.
- **S3** — `IAccessPolicy` / `IInteractiveAccessPolicy` / `AccessPolicyRequest` /
  `AccessDecision` / `AccessDecisionKind` promoted to `AAuth.Server`
  (`src/AAuth/Server/IAccessPolicy.cs`). `Allow` carries `subject`/`tenant`/
  `additionalClaims`.
- **S2** — `IAccessPendingStore` + `InMemoryAccessPendingStore` and the host
  helper `MapAAuthAccessServer(AAuthAccessServerOptions)` shipped in
  `src/AAuth/Server/` (`IAccessPendingStore.cs`, `AAuthAccessServerEndpoints.cs`).
  The helper owns signature/token verification, the §Claims Required composition,
  `GET|POST /pending/{id}`, and minting. MockAccessServer was refactored onto it
  (deleted its sample `IAccessPolicy.cs` + `AccessPendingStore.cs`; kept only
  `StubAccessPolicy` + `KeycloakAccessPolicy` + the `/interaction` endpoints).
- **Keycloak Option B** — `KeycloakAccessPolicy` maps UMA `need_info` →
  `NeedsClaims`, parks the ticket + user token by interaction id, and re-decides
  on the PS push. Not CI-testable (needs a claim-gathering realm); Option A
  (config `AccessServer:RequireClaims` via the stub) remains the dependency-free
  path.
- Docs/snippets updated in lockstep: `docs/workflows/federated-access.md`,
  `samples/MockAccessServer/README.md`, and the `AccessServerClientTests`.
- Validation: full solution builds clean; **369/369** unit tests pass; the
  refactored AS metadata + JWKS verified at runtime via the host helper.

## 1. What already shipped in the SDK (Phases 1–11)

| Surface | Location | Notes |
|---|---|---|
| `AccessServerClient` (S1) | `src/AAuth/Tokens/AccessServerClient.cs` | Signed PS→AS token request + `200/202/402` loop + claims push. Public. |
| `AccessServerRequest` (S1) | `src/AAuth/Tokens/AccessServerRequest.cs` | Parameter object; now carries `OnInteractionRequired` + `OnClaimsRequired`. Public. |
| `AuthTokenResponseValidator` (S4) | `src/AAuth/Tokens/` | Reusable PS-side Auth Token Delivery checks. Public. |
| `MapAAuthAccessServerWellKnown` (part of S2) | `src/AAuth/Server/` | AS metadata + JWKS publishing. Public. |
| `AAuthClaimsRequirement` (S10) | `src/AAuth/Headers/AAuthClaimsRequirement.cs` | Typed `requirement=claims` projection. Public, additive. |
| `AuthTokenBuilder.AdditionalClaims` (S10) | `src/AAuth/Tokens/AuthTokenBuilder.cs` | AS asserts pushed identity claims. Public, additive. |
| `DeferredPollerOptions.StopWhenAccepted` (S10) | `src/AAuth/Agent/DeferredPoller.cs` | Optional predicate to return early from a poll when the `AAuth-Requirement` escalates mid-poll (composition). Added by the SPEC-review D1 fix. Public, additive. |

## 2. Still sample-only glue (candidates to promote)

| ID | Today | Recommendation |
|---|---|---|
| **S2** `MapAAuthAccessServer` full host helper | The MockAccessServer hand-wires the `/token` endpoint: PS-signature pinning, agent-token verify, resource-token verify, policy dispatch, pending store, mint. Only the well-known half is in the SDK. | **Promote, additive.** A `MapAAuthAccessServer(options)` that wires verify→policy→mint, delegating the decision to `IAccessPolicy`, would remove ~250 lines of sample glue and make AS authoring first-class. Medium effort; needs the `IAccessPolicy` seam (S3) in core first. |
| **S3** `IAccessPolicy` / `AccessDecision` | Lives in `samples/MockAccessServer/Policy/`. Now has four decision kinds (Allow/Deny/NeedsInteraction/**NeedsClaims**). | **Promote, additive**, as the policy seam for S2. The `NeedsClaims(requiredClaims)` kind added in Phase 11 is the model for the core abstraction. Keep Keycloak adapter in the sample. |
| **S5** PS auto-federation toggle | The MockPersonServer manually peeks `aud`, branches three- vs four-party, and runs `FederateAsync` in a background task with a pending store. | **Evaluate.** A `WithChallengeHandling` option ("federate when `resource_token.aud != self`") would hide the branch, but the background-task + pending-store relay is genuinely PS-specific. Lower priority; document the pattern first. |
| **S7** Resource "delegate to AS" audience | Resource sets the resource-token `aud` to the AS via existing `ChallengeOptions`. | **No new API needed** — confirmed the explicit-audience option already covers it. Close as "investigate → resolved". |

## 3. Phase 11 claims surface (S10) — recommendations

Spec basis. §Auth Token requires the PS to return a directed `sub` (**MUST**)
plus an open-ended set of requested identity claims. §Claims Required puts the
claim **names** in the response body's `required_claims` — the `AAuth-Requirement`
header carries no claim names. §Auth Token defines `tenant` as a first-class
optional claim with `(iss, tenant, sub)` semantics, not a generic extension.
Backward-compat is **not** required (per user direction), so take the cleanest
spec-faithful shape and update all snippets in lockstep.

**R1 — `OnClaimsRequired` return type: adopt a typed `AAuthClaimsResponse`.**
Today it returns a raw `JsonObject` and the mandatory `sub` is enforced at
runtime (`InvalidOperationException`). The spec makes `sub` a MUST, so encode it
as a required property and let the compiler enforce it:

```csharp
public sealed record AAuthClaimsResponse
{
    // The directed user identifier (spec MUST). Pairwise per resource.
    public required string Subject { get; init; }

    // The requested identity claims (open set; unknown names omitted).
    public IReadOnlyDictionary<string, JsonNode?> Claims { get; init; }
        = new Dictionary<string, JsonNode?>();
}
```

`OnClaimsRequired` becomes
`Func<AAuthClaimsRequirement, CancellationToken, Task<AAuthClaimsResponse>>?`.
Breaking, but the `sub` MUST is now structural rather than a runtime trap.

**R2 — `AAuthClaimsRequirement.FromResponse`: drop the header `claims` fallback.**
The spec puts claim names only in the body's `required_claims`; there is no
`claims` parameter on the requirement header. Read `required_claims` from the
body and treat its absence as a malformed AS response (`FormatException`). This
removes a non-spec code path.

**R3 — `AuthTokenBuilder`: add a first-class `Tenant`, keep `AdditionalClaims`.**
`tenant` is a named spec claim; the demo currently smuggles it through
`AdditionalClaims`. Add a named `Tenant` property (projected to the `tenant`
claim) and keep `AdditionalClaims` for the genuinely open-ended remainder.
Low risk; aligns the builder with §Auth Token.

## 4. Backward-compat summary

- Everything shipped in Phases 1–11 is **additive** (new types, new optional
  properties). No existing signature changed.
- The only behavioural change: `AccessServerClient` previously threw
  `NotSupportedException` for **every** `requirement=claims`; it now throws only
  when `OnClaimsRequired` is unset (same exception, narrower trigger).

## 5. Recommendation / proposed order (pending sign-off)

Spec-grounded rationale for promotion: the AS token-endpoint mechanics are
identical for every AS author (verify PS signature → verify agent token →
verify resource token with `aud`=AS → run the deferred-requirement loop → mint
`dwk=aauth-access.json`, `exp`≤1h, `act`). Only the verdict is deployment
specific. That is the textbook seam for an SDK helper + a policy interface.

1. **S3 → core, spec-complete decision model.** Move `IAccessPolicy` +
   `AccessDecision` into the SDK. Model the full deferred-requirement set the
   spec defines for the AS token endpoint, via factory methods + a kind enum
   (extensible):
   - `Allow` — carries the directed `sub`, optional `tenant`, and extra claims
     to mint.
   - `Deny(reason)` → `403 access_denied`.
   - `NeedsInteraction(url, code?)` → `202 requirement=interaction`.
   - `NeedsClaims(requiredClaims)` → `202 requirement=claims`.
   - `NeedsPayment(...)` → `402` (shape only; settlement out of scope).
   - `requirement=clarification` / `requirement=approval` — not modeled now;
     the enum + factories leave room to add them additively later.
2. **S2 → core `MapAAuthAccessServer`.** A host helper that owns the entire
   spec-defined token-endpoint mechanics — PS-signature pinning, agent-token
   verify, resource-token verify, the pending store, `GET /pending/{id}` poll,
   `POST /pending/{id}` claims push, composition across requirements, and
   minting — delegating only the verdict to `IAccessPolicy`. Ship an
   `IAccessPendingStore` + `InMemoryAccessPendingStore` (mirrors the existing
   `IJtiStore`/`InMemoryJtiStore`). Refactor MockAccessServer to consume it;
   keep only `StubAccessPolicy` + `KeycloakAccessPolicy` as sample policy.
3. **S10 shapes** — adopt R1–R3 (Section 3).
4. **Defer S5** (PS auto-federation toggle — the background relay is genuinely
   PS-specific; document the pattern first). **Close S7** (no new API).
5. **Keycloak `requirement=claims`** — see Section 6.

When implemented, all affected docs and code snippets are updated in lockstep:
`docs/workflows/federated-access.md`, `samples/README.md`, the GuidedTour
README, this note's tables, and every `OnClaimsRequired` / `AdditionalClaims` /
`IAccessPolicy` example.

## 6. Keycloak `requirement=claims` emission — proposal

Problem. `KeycloakAccessPolicy` pushes PS claims into Keycloak's `claim_token`
and reads a permit/deny verdict, so it never returns `NeedsClaims`; only
`StubAccessPolicy` exercises the push. The spec says the AS "cannot know what
claims it needs until it has processed the resource token" — so the
needed-claims signal should come from the policy engine, not from SDK glue.

**Option B (recommended, spec-faithful): map Keycloak UMA claim-gathering onto
`requirement=claims`.** Keycloak's UMA 2.0 grant already implements this exact
handshake. When a policy needs attributes it does not hold, the token endpoint
responds `403` with `error=need_info`, a `required_claims` array (claim name +
metadata), and a fresh `ticket`. The adapter maps that to
`AccessDecision.NeedsClaims(names)`; on the PS push, it re-submits the
`uma-ticket` grant with the pushed values in the `claim_token` plus the returned
`ticket`, then reads permit/deny. Keycloak becomes the genuine, dynamic source
of the requirement after it sees the resource token — the closest match to the
spec. Requires a claim-based Keycloak policy configured to gather the attribute
(a realm-import addition).

**Option A (fallback, minimal): config-declared required claims.** Configure the
adapter with `(resource|scope) → required claim names`. On first evaluation, if
`request.Claims` lacks them, return `NeedsClaims(missing)`; once pushed, feed
them into the `claim_token` so a Keycloak ABAC policy (e.g. `tenant ==
"demo-tenant"`) actually consumes them. No claim-gathering realm config needed;
mirrors the stub but proves Keycloak consuming pushed claims.

Recommendation: implement **Option B** as the primary path (spec-aligned dynamic
discovery, end-to-end against a real policy engine) and keep **Option A** as a
documented config-only fallback where the claim-gathering realm config is
absent. Either way the SDK and PS sides are unchanged — the claims-push round
trip already works; this is purely the Keycloak **sample** adapter emitting the
requirement.

**No code will be written for Sections 3, 5, or 6 until the user approves.**

> **Update:** the user approved; Sections 3, 5 (S5 deferred / S7 closed), and 6
> (Option B) are delivered as recorded in Section 0.
