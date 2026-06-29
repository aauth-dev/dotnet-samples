# Implementation Log — PS/AS whitelisting spec-compliance

Dated, append-only record of decisions, deviations, and open inputs made while
implementing. Seeded with the Phase 0 decision-gate rulings (Q1–Q10) from
[`research.md`](research.md#gaps--open-questions). Append; do not rewrite. A
reversed decision gets a new dated entry that supersedes the old.

## Decisions taken

### [2026-06-29] [Phase 0] Q1 — `null` vs. empty set — RESOLVED
`null` = no constraint (open); empty set = deny-all (`Contains` always false).
Falls out of the AND model. Carry to #3/#4 by preserving the null/empty
distinction the collection-typed code currently collapses (`?? Array.Empty`).
`#2` already has these semantics via `is { }`.

### [2026-06-29] [Phase 0] Q2 — set + predicate composition — RESOLVED
**AND** (each only narrows). Predicate is the general form; the set is sugar for
`iss => set.Contains(iss)`. Documented so consumers don't expect OR.

### [2026-06-29] [Phase 0] Q3 — predicate signature — RESOLVED
`Func<string,bool>` only. Input value per mechanism: #1/#2 = token `iss`; #4 =
resource-token `aud`; #3 = PS `jwks_uri` authority (keeps the shared helper
uniform; documented asymmetry vs. the URL-valued others). No richer overload now.

### [2026-06-29] [Phase 0] Q4 — uniformity to #2/#3 — RESOLVED
Make all four uniform: add the `IsTrusted*` predicate to `TrustedAgentProviderIssuers`
(#2) and AS `TrustedPersonServers` (#3) in the same pass. Additive, except #3's
empty-set case flips open → deny-all for a single rule across all four.

### [2026-06-29] [Phase 0] Q5 — four-party resources pin their AS — RESOLVED
Keep explicit pinning in four-party samples (Wallet / MockAccessServer / Calendar /
Trips) as the documented four-party pattern. The new open default does not require
them to change; their explicit sets are retained.

### [2026-06-29] [Phase 0] Q6 — policy-layer namespacing — RESOLVED (already implemented)
Verified against
[`AAuthAuthenticationHandler.cs`](../../../src/AAuth/Server/Verification/AAuthAuthenticationHandler.cs):
the SDK already emits `aauth:issuer` and a pre-computed `aauth:sub_iss`
(`{iss}|{sub}`) claim and namespaces `sub`/roles/groups by `Claim.Issuer = iss`,
citing the spec rule. "Accept any PS" is safe by construction; no namespacing work
needed.

### [2026-06-29] [Phase 0] Q7 — conformance coverage — RESOLVED
Add positive conformance/integration tests: #1 unset accepts a verifiable PS and
surfaces `iss`; #4 unset federates to the AS named in `aud`; #3 empty → deny-all.
Tests land within their owning phases (2, 3, 4), not a separate phase.

### [2026-06-29] [Phase 0] Q8 — PS→AS dynamic-federation safety — RESOLVED
Federation routes from the **verified** resource-token `aud` (resource-signed,
names its own AS) — not attacker-arbitrary. Enforce `aud` HTTPS + the existing
`MetadataClient` host-poison check + `HttpClient` timeouts. Keep the explicit set
as the pre-establishment affordance. `null` = dynamic, empty = three-party only.

### [2026-06-29] [Phase 0] Q9 — #5 "authorized to extend" without a static list — PROCEEDED (default)
An upstream issuer passes the mandated §Upstream Token Verification check (L1742)
when it is `self` **or** satisfies the (now-optional) AS policy
(`IssuerTrust.IsTrusted(asSetOrNull, IsTrustedAccessServer, iss)`). Revisit if
four-party interop reveals a gap; logged as a default, not a hard ruling.

### [2026-06-29] [Phase 0] Q10 — startup footgun diagnostics — RESOLVED
- **TOP** (implicit open): startup `Warning`, fired only when both set and
  predicate are null; any explicit policy suppresses it.
- **BOTTOM** (`RequireIssuerVerification == false` with a trust policy set):
  **fail-fast** — throw `InvalidOperationException` at construction.
- **Sentinel:** ship `AAuthTrust.Any` (`static readonly Func<string,bool> = _ => true`,
  Option B) as the readable, greppable "intentional open" marker.

## Deviations from plan

### [2026-06-29] [Phases 8–13] Post-review remediation complete
Owner pulled the revocation gap into scope and asked to tighten #5, improve #4
coverage, document the TOP false positive, redo docs/review, and rename the
TOP/BOTTOM test display names. All landed. Full solution builds; AAuth.Tests 517,
AAuth.Conformance 570. New files: `AAuthRevocationOptions.cs`. Phase 13 review
(Explore agent, tool-enabled) returned **APPROVED FOR MERGE** — no CRITICAL/HIGH;
the MEDIUM/LOW items are the intentional-and-logged decisions below.

- **Phase 8 (#5 tighten):** call-chaining upstream trust is now `self OR explicit
  AS set OR IsTrustedAccessServer` — unconfigured ⇒ self-only (three-party). The
  spec-mandated L1742 signature/aud/structure check still runs before the issuer
  predicate. First-hop federation (#4) stays open; the asymmetry is deliberate and
  documented.
- **Phase 9 (revocation, L2302):** `RevocationEndpoint` now requires a verified
  caller (401 if unverified), authorizes via deny-by-default `AAuthRevocationOptions`
  (403 if untrusted), and accepts JSON `{jti}`. Deny-by-default is correct here —
  the spec MANDATES restriction (contrast the open trust-lists). `404`-on-unknown-
  `jti` deferred (Out of Scope — needs an `IJtiStore` change).
- **Phase 10 (#4 coverage):** improved via the `IssuerTrust` truth table (the #4
  gate's exact decision logic), #1 parity (same helper, integration-tested), and
  the new #5 predicate tests. A bespoke four-party-open integration test was NOT
  added — the sample pins per Q5 and a standalone PS harness was declined by the
  owner. Residual LOW gap, accepted.
- **Phase 11:** TOP false positive documented; Inbox (signature-only) demonstrates
  `AAuthTrust.Any`; `TrustConfigDiagnosticsTests` display names no longer use
  TOP/BOTTOM jargon.

### [2026-06-29] [Phases 1–7] Implementation complete — all phases landed
Branch `feature/ps-as-trust-spec-compliance` (not committed). Full solution builds;
AAuth.Tests 517 pass, AAuth.Conformance 566 pass. New files: `AAuthTrust.cs`,
`IssuerTrust.cs`, `TrustConfigDiagnostics.cs`, `IssuerTrustTests.cs`,
`TrustConfigDiagnosticsTests.cs`.

### [2026-06-29] [Phase 3] #4 open-default — helper-level coverage, no dedicated four-party integration test — PROCEEDED
The MockPersonServer sample keeps its explicit `TrustedAccessServers` default
(`:5500`) per Q5, so the existing four-party integration tests exercise the
*explicit-set* and *reject* paths, not the open (null) path. #4's open default is
covered by (a) `IssuerTrustTests` (the shared decision logic) and (b) the gate
using the **same** `IssuerTrust.IsTrusted` helper as #1, whose open default IS
integration-tested. A dedicated four-party open-federation integration test was
not added (would require a PS harness passing `TrustedAccessServers = null`).
Surfaced for owner review.

### [2026-06-29] [Phase 4] #3 empty-set behavior change shipped (open → deny-all)
Per Q1/Q4, an explicitly empty `TrustedPersonServers` now denies all (was: open).
Intended uniformity; flagged as a (small) behavior change to a previously-compliant
gate. No sample/test set an empty AS-side set, so no regression.

### [2026-06-29] [Phase 5] TOP warning can false-positive on signature-only-only UseAAuth resources — PROCEEDED
The TOP warning fires from `UseAAuth` when `RequireIssuerVerification` is true and
no auth-token trust is configured. A resource that uses `UseAAuth` with *only*
`RequireAAuthSignature` endpoints (no auth-token endpoints) and no trust will still
see the warning, because UseAAuth cannot know at startup whether any auth-token
endpoint exists (the endpoint-metadata scan is out of scope per the plan). The
warning is benign and suppressible with any policy / `AAuthTrust.Any`. Surfaced.

### [2026-06-29] [Phase 7] Internal-review subagent lacked file access — review done manually
The `Implementation Validator` subagent had no workspace file tools in this run
(blocked). Phase 7 validation was performed by directly re-reading the critical
paths against the seven verification points — notably confirming the issuer
signature is still verified via JWKS *after* the now-open trust check
(`AAuthVerificationMiddleware.VerifyAuthTokenIssuerAsync`), so "open" strictly
means "verifiable". No CRITICAL/HIGH issues found.

## Open questions / inputs needed

- **Q9 (#5 upstream-issuer openness)** shipped as the PROCEEDED default: a
  four-party upstream from any *verifiable* AS passes the mandated
  §Upstream Token Verification check when AS federation is open. Revisit during
  four-party interop testing if a tighter "authorized to extend" rule is needed.
- **Four-party open-federation integration test** for #4 (see Phase 3 deviation) —
  add if the owner wants integration-level (not just helper-level) coverage of the
  open PS→AS default.
- The `AAuthTrust.Any` sentinel namespace is `AAuth.Server` (confirmed in Phase 1).
