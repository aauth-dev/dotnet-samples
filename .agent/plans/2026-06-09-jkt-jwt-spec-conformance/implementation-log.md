# Implementation Log — Decisions, Deviations & Open Questions

> Living log for the `jkt-jwt` draft-04 conformance work. Maintained by the
> implementing agent while the owner reviews at the end. See
> [implementation-plan.md](implementation-plan.md) and [research.md](research.md)
> for the agreed design.

## How to read this

- **Decisions taken** — choices made to keep moving, with rationale. Revert if you disagree.
- **Deviations from plan** — where reality differed from the plan/research.
- **Open questions / inputs needed** — things wanting an owner ruling.

Each entry: `[YYYY-MM-DD] [Phase N] <title>` with status
`PROCEEDED (default X)` / `BLOCKED` / `RESOLVED`.

---

## Decisions taken

### [2026-06-09] [Grounding] AAuth spec is the authoritative layer — and it delegates `jkt-jwt` to signature-key-04
- **Owner principle:** "We are building the AAuth SDK, so the AAuth spec is a
  layer that supersedes any other spec."
- **Verified there is no conflict to resolve.** Both AAuth-layer documents
  *normatively delegate* the `jkt-jwt` wire format to the signature-key draft, so
  conforming to draft-04 §3.4 **is** being AAuth-spec-accurate:
  - Protocol spec (normative): "builds on the HTTP Signature Keys specification
    `[@!I-D.hardt-httpbis-signature-key]`" for "how signing keys are bound to
    JWTs and discovered" (lines 105, 158, 160).
  - Bootstrap draft (informational): refresh "chains the new ephemeral key to the
    durable key via the `jkt-jwt` scheme `[@!I-D.hardt-httpbis-signature-key]`"
    (line 149); §Two-Key Refresh example is `sig=jkt-jwt;jwt="eyJhbGc..."` — **no
    `jkt` param** (line ~300); the AP "verifies the durable-key signature on the
    naming JWT, looks up the enrollment by the durable key's thumbprint" (line
    289). This is precisely Phase 4 Option A.
- **Implication for any future conflict:** if an AAuth document ever stated a
  `jkt-jwt` shape that contradicted signature-key-04, the AAuth document would
  win. Today they do not — they point *to* it. The Phase 4 AP-side enrolment
  cross-check is the one AAuth-layer requirement layered on top of the §3.4
  verification, and the plan already includes it.

### [2026-06-09] [Phase 0] Spec-accurate, no back-compat — all gates resolved
- **Owner principle:** "Back-compat is not needed — this repo is a spec-accurate
  alpha SDK. Do whatever is needed to be spec-accurate."
- **Resolved:** (A) AP-refresh leg conforms to draft-04 §3.4 self-anchoring (not
  switched to the `jwt` scheme); `jkt-s256+jwt` only (SHA-256); rename
  `AAuthTokenType.NamingJwt`→`JktS256Jwt` and `TokenTypes.NamingJwt`
  (`"naming+jwt"`)→`TokenTypes.JktS256Jwt` (`"jkt-s256+jwt"`) with **no** alias;
  single coordinated cutover.

### [2026-06-09] [Phase 1] Keep `jti` as an additive naming-JWT claim
- **Decision:** §3.4 lists `iss`/`iat`/`exp`/`cnf` as REQUIRED and says `sub` is
  not used; it is silent on `jti`. JWTs permit additional claims, so retaining
  `jti` is spec-compatible. Kept because the verification middleware uses it for
  naming-JWT replay detection (existing `NamingJwtValidationTests`).
- **Input needed?** If you prefer a strictly minimal §3.4 payload, say so and I
  will drop `jti` and the associated replay test.

### [2026-06-09] [Phase 1] `alg` from the durable key instance, not the static const
- **Decision:** Use `durableKey.Algorithm` (EdDSA *or* ES256) for the naming-JWT
  header `alg`, replacing the previous static `AAuthKey.Algorithm` (`"EdDSA"`).
  §3.4 requires `alg` to be the durable key's actual signature algorithm.

### [2026-06-09] [Phase 8] Final review — §3.4 conformance confirmed
- **Line-by-line §3.4 check** of `ResolveJktJwtAsync` (steps 1–11) passed:
  typ check → header `jwk` → RFC 7638 thumbprint → expected `urn:jkt:sha-256:`
  iss → ordinal string-equality compare → signature verify against the header
  `jwk` → return `cnf.jwk`. Signature is verified **before** `cnf.jwk` is
  returned; the old insecure null-metadata fallback is gone. Verification binds
  to the key's own crypto type (`durableKey.Verify`), so the attacker-controlled
  header `alg` cannot cause algorithm confusion (§6.3 honoured).
- **Residue sweep:** the only remaining `naming+jwt` / `;jkt="` hits are the two
  intentional negative-test vectors (wrong-typ and stray-jkt rejection). Zero in
  `src/`, `samples/`, `docs/` production paths.
- **Verification matrix green:** build 0/0; unit 389/0; conformance 485/0;
  SampleApp e2e 16 passed; GuidedTour identity e2e 4 passed (incl. JktJwt);
  AgentConsole live 200 OK with §3.4 wire format.
- **Note:** the Implementation Validator subagent could not run (no file-read
  tools in this session) — the conformance check above was performed directly.

---

## Deviations from plan

### [2026-06-09] [Phase 3] `jkt-jwt` removed from the external issuer-verification machinery
- **Decision:** The middleware previously grouped `jkt-jwt` with `jwt` for
  external issuer verification and the `IssuerVerified` flag. With self-anchoring
  (draft-04 §3.4) `jkt-jwt` carries no external issuer — it is pseudonymous TOFU
  (§6.3). So `jkt-jwt` is now treated like `hwk`: excluded from the metadata/JWKS
  issuer block, reports `IssuerVerified=false`, and is not a carrier for upstream
  auth tokens. This also removes a latent `InvalidOperationException` that fired
  when `RequireIssuerVerification=true` met a `jkt-jwt` request with no
  `MetadataClient` registered.
- **Plan delta:** Phase 3 listed only "don't pass naming JWTs through unverified."
  This broader middleware cleanup follows directly from the self-anchored model
  and the spec-accuracy principle. Flagged for review.

### [2026-06-09] [Phase 3] Removed the dead `MetadataClient` resolver dependency
- **Decision:** `DefaultSignatureKeyResolver`'s `metadataClient` constructor
  parameter and field are gone — self-anchored `jkt-jwt` needs no metadata/JWKS
  lookup, and no other scheme used it. Updated callers in
  `AAuthResourceServiceCollectionExtensions` and `AAuthApplicationBuilderExtensions`.
  `jwks_uri` still uses `JwksClient`.
- **Plan delta:** Phase 3 said "drop metadata/JWKS discovery for jkt-jwt"; removing
  the now-unused ctor parameter is the clean-dead-code corollary. Public ctor
  signature changed (acceptable: spec-accurate alpha SDK, no back-compat).

### [2026-06-09] [Phase 7] SampleApp jkt-jwt e2e flakes in isolation (pre-existing) — HARDENED
- **Observation:** `jkt-jwt.spec.ts` failed when run **alone**
  (`-g "jkt-jwt enrols"`) at the enrolment step — Blazor's first-click-drop on a
  freshly-connected circuit. The `jkt-jwt` and `jwks-uri` specs used a plain
  `.click()` for "Enrol", unlike the call-chain/mission specs which use
  `clickAndConfirm`.
- **Evidence it was not my change:** the failure was *before* any jkt-jwt code
  runs (enrolment is untouched), and the **full** sample-app suite passed
  (16 passed / 1 skipped). The SDK round-trip is independently verified green via
  AgentConsole (200 OK, see below).
- **Resolved (2026-06-09):** hardened both specs to wrap the enrol click in
  `clickAndConfirm` (retries a dropped cold-circuit click until `.alert-info`
  appears), matching the existing pattern used by the call-chain/mission specs.
  Both now pass **in isolation** and together: `jkt-jwt enrols` ✓ (5.1s),
  `jwks-uri enrols` ✓ (warm-circuit run 475ms — enrol button correctly skipped).

### [2026-06-09] [Phase 7] Live SDK verification (AgentConsole)
- `AgentConsole --signing-mode jkt-jwt → Profile /anchored` returns **200 OK**.
  Decoded wire: `sig=jkt-jwt;jwt="…"` (single param); naming-JWT
  `typ=jkt-s256+jwt`, durable `jwk` in header,
  `iss=urn:jkt:sha-256:<durable-thumbprint>`; the resource reports `jkt` = the
  durable thumbprint. Confirms self-anchored §3.4 verification works with no
  MetadataClient registered (the path that previously hit the insecure fallback).

---

## Open questions / inputs needed

### [2026-06-09] [Research] AP-refresh vs `jwt`-scheme overlap — RESOLVED by the spec author
- **Question:** §3.4's `jkt-jwt` is built around self-anchored device identity;
  the AAuth refresh case (AP already knows the durable key) seemed to overlap with
  the `jwt` scheme. Which is canonical for refresh?
- **Spec author's answer (Dick Hardt, 2026-06-09):** *"It all depends on the
  environment. I added jkt-jwt when I was implementing bootstrapping a mobile app
  where there is an enclave to store the key, but not practical to use for signing
  everything. On first use, the AP drives a platform attestation in addition to
  the jkt-jwt — and then the jkt-jwt is all that is needed for future agent
  tokens."*
- **Resolution:** `jkt-jwt` IS the intended scheme for the two-key refresh leg —
  it was purpose-built for the enclave-backed case we use it in. It is not
  redundant with `jwt`: the enclave can't sign every request, so it delegates to a
  fast ephemeral key, and scheme choice is environment-driven (enclave → jkt-jwt;
  single durable key → hwk; issuer-discoverable → jwt). At the AP the durable key
  is **not** trusted by pure TOFU — trust is established by the **platform
  attestation at enrollment** and then carried forward by the durable-key
  signature on each naming JWT (no re-attestation per refresh). This is exactly
  Phase 4 Option A: the AP runs the §3.4 self-anchored verification, then
  cross-checks the durable key against the enrolment record the attestation
  established (`MockAgentProvider`). No code change required — the choice is
  confirmed correct.
