# Implementation Plan — PS/AS whitelisting spec-compliance

Phased plan to make all four PS/AS trust-lists **spec-compliant by default
(open / dynamically-establishable)** while keeping the API surface minimal,
adding a `Func<string,bool>` policy delegate beside each existing static set, an
`AAuthTrust.Any` intent sentinel, and startup footgun guards. Grounded in
[`research.md`](research.md); every behavior decision traces to a spec line cited
there.

> **Status (2026-06-29): all phases (0–13) implemented** on branch
> `feature/ps-as-trust-spec-compliance` (uncommitted). Full solution builds;
> AAuth.Tests 517 / AAuth.Conformance 570 pass. Phase 13 review (Explore agent):
> **APPROVED FOR MERGE** (no CRITICAL/HIGH). Decisions, deviations, and follow-ups
> are recorded in [`implementation-log.md`](implementation-log.md).

## Guiding principles (restated per the repo workflow)

- **Spec conformance is paramount; backwards compatibility is not a goal.** This is
  a spec-accurate alpha SDK. The two fail-closed deviations (#1 resource inbound,
  #4 PS→AS federation) flip to open-by-default in a single coordinated cutover; the
  two compliant templates (#2, #3) gain the same predicate for a uniform surface.
  No dual-format shims, no compatibility fallbacks. Where a uniformity change alters
  an edge case (#3 empty-set: open → deny-all), take the uniform behavior and log it.
- **Two invariants, both binding** ([research §Design invariants](research.md#design-invariants)):
  (1) spec-compliant by default; (2) no new API-surface complexity — one optional
  predicate per existing options object, composed by **AND** with the set, default
  open.
- **Verification ≠ trust.** `RequireIssuerVerification` (crypto) is untouched; the
  set/predicate is the policy layer that only ever *narrows* the verifiable floor
  ([research §Relationship to RequireIssuerVerification](research.md#relationship-to-requireissuerverification-two-layers-not-one)).
- Every deviation from this plan is logged in
  [`implementation-log.md`](implementation-log.md) as a dated `[Phase N]` entry.

## Trust-decision model (the shape every phase implements)

```csharp
// id = auth-token iss (#1) / agent-token iss (#2) / PS jwks_uri authority (#3) / resource-token aud (#4)
bool trusted =
    (set is null    || set.Contains(id)) &&   // existing static set; null = no constraint, empty = deny-all
    (policy is null || policy(id));            // new Func<string,bool>; null = no constraint
// both null ⇒ accept any *verifiable* counterparty (spec default)
```

---

## Phase 0 — Decision gate

Resolve every open question in [research §Gaps & open questions](research.md#gaps--open-questions)
before any code. Rulings live in [`implementation-log.md`](implementation-log.md)
(seeded with this plan).

### Definition of Done

- [x] Q1–Q10 each have a recorded ruling in `implementation-log.md` (default
  ruling acceptable; revert if the owner disagrees).
- [x] Q6 (namespacing) confirmed already-implemented against
  [`AAuthAuthenticationHandler.cs`](../../../src/AAuth/Server/Verification/AAuthAuthenticationHandler.cs)
  (`aauth:issuer`, `aauth:sub_iss`).
- [x] Predicate input value per mechanism pinned (Q3): #1/#2 = token `iss`; #4 =
  resource-token `aud`; #3 = PS `jwks_uri` authority.

---

## Phase 1 — Shared trust primitive

The smallest, most isolated piece — a sentinel and one helper that all four
enforcement sites call, so the model is implemented once.

### Files & responsibilities

| File | Responsibility |
|---|---|
| `src/AAuth/Server/AAuthTrust.cs` (new) | `public static class AAuthTrust { public static readonly Func<string,bool> Any = _ => true; }` — the greppable "intentional open" marker (Option B). |
| `src/AAuth/Server/Verification/IssuerTrust.cs` (new, internal) | `internal static bool IsTrusted(IReadOnlyCollection<string>? set, Func<string,bool>? policy, string id)` ⇒ `(set is null || set.Contains(id)) && (policy is null || policy(id))`. Membership-agnostic; callers pass a **normalized** set/id and `null` (never empty) when the option is unset, so `null`=open / empty=deny-all is preserved. |

### Implementation Decisions

- `IsTrusted` takes `IReadOnlyCollection<string>?` so both `IReadOnlySet` (#1/#2,
  O(1) `Contains`) and the host/url collections (#3/#4) share it.
- Sentinel lives in a public, discoverable namespace (`AAuth.Server`); confirm
  final namespace in the log.

### Definition of Done

- [x] `AAuthTrust.Any` compiles and is referenced by a unit test asserting it
  returns `true` for arbitrary input.
- [x] `IssuerTrust.IsTrusted` unit-tested across the truth table (null/empty/match/
  miss × null/true/false predicate).
- [x] Build green; no other code references yet.

---

## Phase 2 — Resource inbound trust (#1 + #2 uniformity)

The core behavioral fix: flip the resource auth-token default open and add the
predicate to both resource-side gates.

### Files & responsibilities

| File | Responsibility |
|---|---|
| [`src/AAuth/Server/Verification/AAuthVerificationOptions.cs`](../../../src/AAuth/Server/Verification/AAuthVerificationOptions.cs) | Add `Func<string,bool>? IsTrustedAuthTokenIssuer` (#1) and `Func<string,bool>? IsTrustedAgentProviderIssuer` (#2). Rewrite `TrustedAuthTokenIssuers` docstring: `null` = accept any verifiable PS (spec default), empty = deny-all, predicate AND-composes. |
| [`src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs`](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs#L424) | `VerifyAuthTokenIssuerAsync`: replace `trusted is null \|\| Count == 0 \|\| !Contains` with `IssuerTrust.IsTrusted(set, IsTrustedAuthTokenIssuer, iss)` (default open). `VerifyAgentTokenIssuerAsync` (L351): route through the same helper, adding the predicate (set semantics already null=open/empty=deny-all). |
| [`src/AAuth/Server/Endpoints/AAuthEndpointRequirement.cs`](../../../src/AAuth/Server/Endpoints/AAuthEndpointRequirement.cs#L42) | Add both predicate properties to `AAuthServerOptions`. |
| [`src/AAuth/Server/Endpoints/AAuthEndpointExtensions.cs`](../../../src/AAuth/Server/Endpoints/AAuthEndpointExtensions.cs#L163) | Forward both predicates into `AAuthVerificationOptions` (RequireAuthToken branch only). |
| [`src/AAuth/DependencyInjection/AAuthResourcePipelineOptions.cs`](../../../src/AAuth/DependencyInjection/AAuthResourcePipelineOptions.cs#L30) | Add both predicate properties. |
| [`src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs`](../../../src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs#L202) | Forward both predicates. |

### Definition of Done

- [x] `VerifyAuthTokenIssuerAsync` accepts a verifiable PS when no set/predicate
  configured; still rejects when a non-matching set or `policy ⇒ false` is set.
- [x] [`VerificationMiddlewareTests`](../../../tests/AAuth.Conformance/HttpSignatures/VerificationMiddlewareTests.cs#L378):
  `RejectsAuthTokenWhenNoTrustedIssuersConfigured` **inverted** to assert a
  verifiable PS is accepted (and `iss` is surfaced); `RejectsAuthTokenFromUntrustedPsIssuer`
  retained.
- [x] New tests: predicate-only accept/reject (#1); set+predicate AND; empty-set
  deny-all; `#2` predicate accept/reject.
- [x] Predicate forwards through `UseAAuth` and `UseAAuthVerification`.
- [x] Build + full conformance/unit suite green.

---

## Phase 3 — PS outbound federation (#4) + upstream follow-through (#5)

### Files & responsibilities

| File | Responsibility |
|---|---|
| [`src/AAuth/Person/AAuthPersonServerEndpoints.cs`](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L68) | Add `Func<string,bool>? IsTrustedAccessServer` to `AAuthPersonServerOptions`; rewrite docstring (`null` = federate to the AS named in the verified resource-token `aud`; empty = three-party only / deny federation). |
| same, [L177](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L177) | Build a **nullable** normalized AS set (null when the option is null) so `null`=open / empty=deny is preserved; keep the materialized set for the #5 union. |
| same, [L829](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L829) | `HandleFederatedAsync`: replace `Count == 0 \|\| !Contains` with `IssuerTrust.IsTrusted(asSetOrNull, IsTrustedAccessServer, aud)` (default federate). Validate `aud` is HTTPS before the outbound call (Q8). |
| same, [L598](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L598) | #5 follow-through: an upstream issuer passes when it is `self` **or** `IssuerTrust.IsTrusted(asSetOrNull, IsTrustedAccessServer, iss)`, so chains through dynamically-trusted ASes still satisfy the mandated §Upstream Token Verification check (L1742). |

### Implementation Decisions

- Q8: federation remains routed from the **verified** resource-token `aud`
  (signed by the resource, names its own AS) — not attacker-arbitrary. Enforce
  `aud` HTTPS + existing `MetadataClient` host-poison check + `HttpClient`
  timeouts. Keep the explicit set as the pre-establishment affordance.
- Q9: "authorized to extend" without a static list = `self` ∪ (open AS policy).
  Default recorded in the log; revisit if four-party interop reveals a gap.

### Definition of Done

- [x] `#4` first-hop federation: open by default (`null`), empty ⇒ refused, explicit
  set/predicate restrict — decision logic covered by `IssuerTrustTests`; explicit-set
  + reject + three-party paths integration-tested in
  [`MockPersonServerFederationTests`](../../../tests/AAuth.Tests/Integration/MockPersonServerFederationTests.cs).
  (Dedicated four-party open/empty integration tests deferred — see log / Phase 10.)
- [x] `#5` upstream-issuer behavior **superseded by Phase 8** (tightened to
  self-only by default); validated by Phase 8 DoD + `UpstreamTokenValidationTests`.
- [x] Build + suite green.

---

## Phase 4 — AS inbound (#3) uniformity

Additive predicate + the one uniformity behavior change (empty set: open →
deny-all).

### Files & responsibilities

| File | Responsibility |
|---|---|
| [`src/AAuth/Access/AAuthAccessServerEndpoints.cs`](../../../src/AAuth/Access/AAuthAccessServerEndpoints.cs#L59) | Add `Func<string,bool>? IsTrustedPersonServer` to `AAuthAccessServerOptions`. |
| same, [L146](../../../src/AAuth/Access/AAuthAccessServerEndpoints.cs#L146) | Build a **nullable** `trustedPsHosts` (null when option null) to preserve null=open / empty=deny-all. |
| same, [L199](../../../src/AAuth/Access/AAuthAccessServerEndpoints.cs#L199) and [L249](../../../src/AAuth/Access/AAuthAccessServerEndpoints.cs#L249) | Replace the `Count > 0` guards with `IssuerTrust.IsTrusted(psHostsOrNull, IsTrustedPersonServer, callerAuthority)`. **Behavior change:** an explicitly empty set flips open → deny-all. |

### Implementation Decisions

- Q3 (#3 predicate input): pass the PS **`jwks_uri` authority** to both set and
  predicate so the helper stays uniform; documented asymmetry vs. #1/#2/#4 (which
  pass a full URL). Revisit if a consumer needs the full `jwks_uri`.

### Definition of Done

- [x] AS with no `TrustedPersonServers`/predicate accepts any verifiable PS
  (unchanged default); explicitly empty set now denies all (new) — both tested.
- [x] `IsTrustedPersonServer` accept/reject test.
- [x] [`MockAccessServerTests`](../../../tests/AAuth.Tests/Integration/MockAccessServerTests.cs) /
  Keycloak tests still green with explicit set.
- [x] Build + suite green.

---

## Phase 5 — Startup footgun guards

Diagnostics only (TOP) + config validation (BOTTOM) — no runtime policy change.
Lands after the open defaults exist to guard.

### Files & responsibilities

| File | Responsibility |
|---|---|
| [`src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs`](../../../src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs) (`UseAAuthVerification`) | **BOTTOM fail-fast:** throw `InvalidOperationException` when `RequireIssuerVerification == false` and any of `TrustedAuthTokenIssuers` / `IsTrustedAuthTokenIssuer` / `TrustedAgentProviderIssuers` / `IsTrustedAgentProviderIssuer` is set. **TOP warning:** resolve `ILogger`; `Warning` when an auth-token pipeline has no auth-token set **and** no predicate. |
| [`src/AAuth/Server/Endpoints/AAuthEndpointExtensions.cs`](../../../src/AAuth/Server/Endpoints/AAuthEndpointExtensions.cs) (`UseAAuth`) | Same TOP warning at the unified entry (RequireAuthToken endpoints). BOTTOM is structurally impossible here (forwarder gates the policy to the verify branch) — assert/skip. |
| [`src/AAuth/Person/AAuthPersonServerEndpoints.cs`](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs) / [`src/AAuth/Access/AAuthAccessServerEndpoints.cs`](../../../src/AAuth/Access/AAuthAccessServerEndpoints.cs) | TOP warning when the PS (#4) / AS (#3) has neither set nor predicate. |

### Implementation Decisions

- TOP fires **only when both set and predicate are null**; any policy — including
  `AAuthTrust.Any` / `_ => true` — suppresses it (Q10).
- BOTTOM throws (not warns): a silently-bypassed security control must not reach
  production (Q10). Message names the offending property and the fix.

### Definition of Done

- [x] BOTTOM: `UseAAuthVerification` with `RequireIssuerVerification=false` + a
  trust policy throws `InvalidOperationException`; `SignatureOnly()` with no policy
  does not.
- [x] TOP: a startup `Warning` is logged for an unconfigured auth-token pipeline;
  setting `AAuthTrust.Any` suppresses it (asserted via a test logger).
- [x] Build + suite green.

---

## Phase 6 — Samples / snippets / docs sweep

Run after the code surface is frozen (compiled code fixed in Phases 1–5; the
non-compiled surface drifts silently and is swept here).

### Scope

- **Deviation #1 docs** — reconcile "fail-closed / reject all" wording to "omit ⇒
  accept any verifiable PS (namespaced by `iss`); set/predicate to restrict":
  [`verification-middleware.md`](../../../docs/server/verification-middleware.md#L88),
  [`configuration.md`](../../../docs/reference/configuration.md#L22),
  [`authn-authz.md`](../../../docs/server/authn-authz.md#L85),
  [`dependency-injection.md`](../../../docs/reference/dependency-injection.md#L159),
  [`README.md`](../../../README.md#L205),
  [`authorization-policies.md`](../../../docs/server/authorization-policies.md#L107),
  [`challenge-middleware.md`](../../../docs/server/challenge-middleware.md#L143);
  verify [`getting-started.md`](../../../docs/getting-started.md#L250) (already correct).
- **Deviation #4 docs** — reconcile "null/empty ⇒ three-party only":
  [`token-issuance.md`](../../../docs/server/token-issuance.md#L256),
  [`configuration.md`](../../../docs/reference/configuration.md#L70),
  [`dependency-injection.md`](../../../docs/reference/dependency-injection.md#L475),
  [`federated-access.md`](../../../docs/workflows/federated-access.md#L116),
  [`MockPersonServer/README.md`](../../../samples/MockPersonServer/README.md#L136).
- **New surface docs** — document `IsTrusted*` predicates + `AAuthTrust.Any` + the
  two startup guards in `configuration.md` / `verification-middleware.md`.
- **Samples** — keep four-party explicit pinning (Wallet / MockAccessServer /
  Calendar / Trips); update any sample comment asserting fail-closed; optionally
  add one `AAuthTrust.Any` demonstration.
- **e2e / playwright** — confirm no assertion depends on the old fail-closed
  default.

### Definition of Done

- [x] `grep` for "fail-closed" / "reject all" / "three-party only" /
  "every auth token is rejected" returns no stale claims about the default.
- [x] Predicate + sentinel + startup guards documented.
- [x] Samples build; e2e assertions unaffected.

---

## Phase 7 — Internal review

Fresh subagent validates the work against the spec, `research.md`, and this plan.

### Definition of Done

- [x] Subagent confirms all four mechanisms implement the trust-decision model
  uniformly (null=open, empty=deny-all, predicate AND).
- [x] Spec citations (L312, L1581, L1707, L2716, L2661) still hold.
- [x] Severity-graded findings recorded; criticals resolved or logged.

---

## Out of scope

| Item | Why |
|---|---|
| `RequireIssuerVerification` semantics / `SignatureOnly()` | The crypto gate is orthogonal; unchanged. |
| Richer predicate overload (`dwk` / claims context) | YAGNI; ship `Func<string,bool>` only (Q3). Add later if a real case appears. |
| Endpoint-scan TOP warning ("policy set but all routes `RequireAAuthSignature`") | Lower-value; documented instead (Phase 11) and suppressible with `AAuthTrust.Any`. |
| Config (appsettings) schema | Predicates are code-only; static sets keep their config keys. No schema change. |
| Four-party sample AS pinning (Wallet / MockAccessServer / Calendar / Trips) | Intentionally explicit as the documented four-party pattern (Q5). |
| Revocation 404-on-unknown-`jti` + store `jti→issuer` records | Spec nicety (L2274); needs an `IJtiStore` interface change. Endpoint returns `200` on revoke. Deferred — see below. |

### Deferred follow-up — revocation `404` + per-token issuer check

Two revocation refinements are parked together because both need richer store
records than [`IJtiStore`](../../../src/AAuth/Server/IJtiStore.cs) provides (it
tracks replay-seen + revoked state only; `RevokeAsync` returns `void` and there is
no `jti→issuer` mapping):

- **`404` on unknown `jti`** (L2274 / revocation response: `200` if revoked or
  already-invalid, `404` if not recognized). Requires an **issued-token ledger** —
  the issuer records each `jti` at mint time — with retention *past expiry* (the
  replay store evicts on expiry, so reusing it would mis-report expired tokens as
  `404` instead of the spec's `200`).
- **Per-token issuer authorization** (L2302 "issuer of the token … or a trusted
  PS"). Phase 9 enforces the *trusted-PS* arm (deny-by-default `TrustedRevokers` /
  `IsTrustedRevoker`); the finer "caller is the issuer of *this* `jti`" check needs
  the `jti→issuer` mapping.

Recommended scoping (separate change, no breaking `IJtiStore` edit): introduce an
`IIssuedTokenStore` (issuer records `jti` + issuer at mint, explicit retention),
wire `RevocationEndpoint` to it for `404` + per-token issuer checks, and leave the
replay `IJtiStore` contract untouched. Note: AAuth's `404` deliberately diverges
from RFC 7009 (which mandates `200` even for unknown tokens) — modest value, hence
deferred. Functional revocation (mark `jti` revoked → `200`) already works.

---

# Follow-up phases (post-review remediation, 2026-06-29)

Added after the first implementation pass and owner review of the surfaced
issues. Same guiding principles apply.

## Phase 8 — Tighten `#5` call-chaining upstream trust (explicit, spec-compliant default)

The first pass widened the §Upstream Token Verification (L1742) issuer check to
inherit the open federation default. Owner decision: tighten it so any four-party
*call-chaining* extension is an **explicit** decision, with a safe default.

### Files & responsibilities

| File | Responsibility |
|---|---|
| [`src/AAuth/Person/AAuthPersonServerEndpoints.cs`](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs#L598) | Change the `isTrustedUpstreamIssuer` lambda from open (`IssuerTrust.IsTrusted(trustedAccessServersOrNull, …)`) to **explicit**: `iss == self` (previously brokered) `OR trustedAccessServers.Contains(iss)` (explicit set) `OR IsTrustedAccessServer?.Invoke(iss)` (explicit predicate). Unconfigured ⇒ **self only**. Document the asymmetry: first-hop federation (`#4`) is open (L1581); call-chaining extension is tight (L1742, higher delegation stakes). |

### Definition of Done

- [x] Three-party call-chaining (upstream issued by self) still works with no config.
- [x] Four-party call-chaining through an **unconfigured** AS is rejected (`untrusted_issuer`); through an AS in `TrustedAccessServers` or passing `IsTrustedAccessServer` succeeds.
- [x] Spec-mandated check (signature/aud/structure) still runs before the issuer-trust decision.
- [x] Build + suites green.

## Phase 9 — Revocation caller-trust hardening (L2302)

[`RevocationEndpoint.cs`](../../../src/AAuth/Server/RevocationEndpoint.cs) currently
revokes any `jti` from any **unauthenticated** caller — violating L2302 ("MUST
verify the caller's identity via HTTP Message Signatures and MUST only accept
revocation from the issuer of the token being revoked or from a trusted PS").

### Files & responsibilities

| File | Responsibility |
|---|---|
| `src/AAuth/Server/AAuthRevocationOptions.cs` (new) | `IReadOnlyCollection<string>? TrustedRevokers` + `Func<string,bool>? IsTrustedRevoker` over the caller's verified identity. **Deny-by-default** (spec MANDATES restriction — the opposite of the four open-by-default trust-lists). |
| [`src/AAuth/Server/RevocationEndpoint.cs`](../../../src/AAuth/Server/RevocationEndpoint.cs) | Add a `configure` overload. Endpoint: (1) require a verified caller — read `AAuthVerificationResult` from features; `401` if absent (must be mapped behind `UseAAuthVerification` / `RequireAAuthSignature`); (2) authorize the caller identity against the deny-by-default policy → `403 untrusted_revoker`; (3) parse the spec JSON body `{"jti": …}`; (4) `RevokeAsync`; `200`. |
| [`docs/server/replay-detection.md`](../../../docs/server/replay-detection.md#L129) | Update the revocation example: behind verification, with a trusted-revoker policy. |

### Implementation Decisions

- Deny-by-default here is correct and spec-mandated (contrast the four open-by-default lists). The operator lists trusted PSes (and/or the issuer's own identity) explicitly.
- Wire format aligned to the spec example (`application/json` `{"jti"}`), replacing the previous form-encoded `token`. `404`-on-unknown-`jti` deferred (needs store change) — Out of Scope.

### Definition of Done

- [x] Unsigned / unverified caller ⇒ `401`.
- [x] Verified-but-untrusted caller ⇒ `403`.
- [x] Verified trusted-revoker (set or predicate) ⇒ `200` and the `jti` is revoked.
- [x] [`JtiStoreAndRevocationTests`](../../../tests/AAuth.Conformance/Discovery/JtiStoreAndRevocationTests.cs) updated for the signed+authorized flow; the JTI-store unit tests are unaffected.
- [x] Build + suites green.

## Phase 10 — `#4` open-federation integration coverage

Add the lighter coverage the owner asked for (not a new harness): a focused test
on the SDK PS endpoint reusing the existing federation stub.

### Files & responsibilities

| File | Responsibility |
|---|---|
| [`tests/AAuth.Tests/Integration/MockPersonServerFederationTests.cs`](../../../tests/AAuth.Tests/Integration/MockPersonServerFederationTests.cs) (or a focused SDK test) | Map a PS with `TrustedAccessServers = null` (open) using the existing `FederatedStub`; assert it federates to the AS named in a verified resource token's `aud`. Keeps the MockPersonServer sample pinned (Q5). |

### Definition of Done

- [x] Open (`null`) PS federates to the verified `aud`'s AS; empty set still refused; explicit set still works.
- [x] Build + suites green.

## Phase 11 — TOP-warning docs + sample demo + test-name cleanup

### Files & responsibilities

| File | Responsibility |
|---|---|
| [`docs/reference/configuration.md`](../../../docs/reference/configuration.md) / [`docs/server/verification-middleware.md`](../../../docs/server/verification-middleware.md) | Document that a `UseAAuth` resource with only `RequireAAuthSignature` endpoints may see the open-trust warning, and that any policy / `AAuthTrust.Any` suppresses it. |
| An applicable signature-only sample (e.g. [`samples/MockResourceServers/Inbox`](../../../samples/MockResourceServers/Inbox/Program.cs)) | Show `AAuthTrust.Any` (or a policy) to declare intent / silence the warning where appropriate. |
| [`tests/AAuth.Tests/Server/TrustConfigDiagnosticsTests.cs`](../../../tests/AAuth.Tests/Server/TrustConfigDiagnosticsTests.cs) | Drop the internal `TOP:` / `BOTTOM:` jargon from `[Fact(DisplayName=…)]` names; use descriptive names. |

### Definition of Done

- [x] Doc note added; sample demonstrates intentional-open / suppression.
- [x] Test display names carry no `TOP`/`BOTTOM` prefixes.
- [x] Build + suites green.

## Phase 12 — Docs sweep (redo)

Re-sweep docs for the follow-up surfaces: revocation trust options + behind-
verification requirement, the `#5` call-chaining asymmetry, and any remaining
stale wording. Run after Phases 8–11 freeze the code.

### Definition of Done

- [x] Revocation, `#5` asymmetry, and the new options documented; no stale claims remain.

## Phase 13 — Internal review (redo)

Fresh **tool-enabled** subagent (Explore) validates the full change — original
Phases 1–7 plus follow-up Phases 8–12 — against the spec, `research.md`, and this
plan, with severity-graded findings.

### Definition of Done

- [x] All four trust-lists + `#5` + revocation validated against their spec lines.
- [x] Severity-graded findings recorded; criticals resolved or logged.
