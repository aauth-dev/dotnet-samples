# Implementation Plan — `jkt-jwt` conformance with HTTP Signature Keys draft-04

Companion to [`research.md`](research.md). Brings the SDK's `jkt-jwt` Signature-Key
scheme into conformance with `draft-hardt-httpbis-signature-key-04` §3.4, closes
the resource-side verification security gap, and updates samples, docs, and tests.

> Status: **not started.** Phase 0 is a decision gate — do not write code until
> the maintainer resolves the AP-refresh design question.

## Summary of the change

| Aspect | From (current) | To (draft-04 §3.4) |
|---|---|---|
| Header params | `sig=jkt-jwt;jkt="…";jwt="…"` | `sig=jkt-jwt;jwt="…"` |
| Naming-JWT `typ` | `naming+jwt` | `jkt-s256+jwt` |
| Naming-JWT header `jwk` | absent (`kid` only) | durable public key (REQUIRED) |
| Naming-JWT `iss` | AP issuer HTTPS URL | `urn:jkt:sha-256:<durable-thumbprint>` |
| `cnf.jwk` | ephemeral key | ephemeral key (unchanged) |
| Resource verification | metadata→jwks_uri→kid; **unverified fallback** | self-anchored TOFU: thumbprint(header jwk)==iss, verify sig with header jwk, then trust cnf.jwk |

## Phase 0 — Decision gate (no code)

Resolve the AP-refresh design question from research §"Gaps & open questions":
for the **agent↔AP refresh leg**, either (A) conform `jkt-jwt` to draft-04 §3.4
self-anchoring, or (B) switch that leg to the `jwt` scheme and reserve `jkt-jwt`
for resource self-anchoring. The **resource leg is fixed**: draft-04 §3.4.

Record the decision in this phase's Implementation Decisions before any code.

### Implementation Decisions (Phase 0)

- [ ] AP-refresh leg scheme: **(A) conform to §3.4** _or_ **(B) switch to `jwt`** — _pending maintainer_.
- [ ] Hash agility: implement `jkt-s256+jwt` only (SHA-256) for now; defer `jkt-s512+jwt`. _Proposed._
- [ ] `AAuthTokenType.NamingJwt`: keep as public enum member mapped to `jkt-s256+jwt`, or rename. _Pending._
- [ ] Back-compat: no dual-format acceptance window (internal demo only) — single coordinated cutover. _Proposed._

### Definition of Done

- [ ] AP-refresh design choice (A or B) recorded above with rationale.
- [ ] Hash-agility, enum, and back-compat decisions recorded.

## Phase 1 — Naming-JWT construction (draft-04 §3.4)

Rewrite naming-JWT minting to the canonical shape.

| File | Change |
|---|---|
| `src/AAuth/Agent/NamingJwtBuilder.cs` | header `typ`=`jkt-s256+jwt`, `alg`, **`jwk`=durable public key**; payload `iss`=`urn:jkt:sha-256:<durable-thumbprint>`, `iat`, `exp`, `jti`, `cnf.jwk`=ephemeral; drop `kid`. |
| `src/AAuth/AAuthConstants.cs` | add `TokenTypes.JktS256Jwt = "jkt-s256+jwt"`; keep/retire `NamingJwt` per Phase 0. Add `UrnJktPrefix = "urn:jkt:sha-256:"` helper. |
| `src/AAuth/AAuthTokenType.cs` | map `jkt-s256+jwt` ↔ enum per Phase 0 decision. |
| `src/AAuth/Crypto/*` | ensure an RFC 7638 thumbprint→`urn:jkt:sha-256:` formatter exists (reuse `ComputeJwkThumbprint`). |

### Definition of Done

- [ ] Naming JWT emits `typ=jkt-s256+jwt`, durable `jwk` in header, `iss=urn:jkt:sha-256:<thumbprint>`, `cnf.jwk`=ephemeral.
- [ ] Unit test: minted JWT round-trips and `thumbprint(header.jwk) == iss` suffix.
- [ ] Solution builds with 0 warnings.

## Phase 2 — Wire format (header emit + parse)

| File | Change |
|---|---|
| `src/AAuth/HttpSig/SignatureKeyHeader.cs` | `FormatJktJwt(string jwt)` → `sig=jkt-jwt;jwt="{jwt}"`; **drop the `jkt` param**. |
| `src/AAuth/HttpSig/JktJwtSignatureKeyProvider.cs` | stop computing/emitting the ephemeral `jkt`; provider supplies only the naming JWT. |
| `src/AAuth/HttpSig/SignatureKeyParser.cs` | `ParseJktJwtScheme`: require **only `jwt`**; reject a stray `jkt`; parse header `jwk`, `iss`, `cnf.jwk`. |

### Definition of Done

- [ ] Emitted header is `sig=jkt-jwt;jwt="…"` (no `jkt`).
- [ ] Parser accepts the new shape and rejects a `jkt` param.
- [ ] Unit tests updated for both emit and parse.

## Phase 3 — Resource verification: self-anchored TOFU (security fix)

Implement draft-04 §3.4 steps 4–11 and **remove the unverified fallback**.

| File | Change |
|---|---|
| `src/AAuth/HttpSig/DefaultSignatureKeyResolver.cs` | `ResolveJktJwtAsync`: (1) read header `jwk`; (2) compute RFC 7638 thumbprint; (3) build expected `urn:jkt:sha-256:<thumbprint>`; (4) **string-compare to `iss`**; (5) **verify the naming-JWT signature with the header `jwk`**; (6) only then return `cnf.jwk`. **Delete the `_metadataClient is null` → return ephemeral fallback.** Drop metadata/JWKS discovery for `jkt-jwt` (self-anchored needs neither). |
| `src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs` | ensure `jkt-s256+jwt` naming JWTs are not silently passed through unverified; `exp`/`jti` still enforced; document that key resolution now self-anchors. |

### Definition of Done

- [ ] `iss` mismatch with `thumbprint(header.jwk)` → rejected.
- [ ] Tampered naming-JWT signature → rejected.
- [ ] Forged naming JWT with attacker `iss` + attacker ephemeral key → **rejected** (the old gap).
- [ ] No code path returns `cnf.jwk` without verifying the naming-JWT signature.
- [ ] Conformance test reproducing the old forgery is added and passes (now 401).

## Phase 4 — AP-refresh path

Apply the Phase 0 decision to the agent↔AP refresh leg.

| File | Change |
|---|---|
| `src/AAuth/Agent/AgentProviderClient.cs` (and AP refresh handler) | option (A): verify the §3.4 self-anchored naming JWT, still cross-check the durable thumbprint against the enrollment record; option (B): switch refresh signing to `jwt` scheme. |
| `samples/MockAgentProvider/**` | match the chosen refresh verification. |

### Definition of Done

- [ ] Refresh leg conforms to the Phase 0 decision (A or B).
- [ ] AP still binds the durable key to the enrollment record (no downgrade).
- [ ] Integration test: refresh succeeds end-to-end; tampered refresh rejected.

## Phase 5 — Samples

| File | Change |
|---|---|
| `samples/MockResourceServers/Profile/Program.cs` | `/anchored` keeps `jkt-jwt`; resolver no longer needs `MetadataClient`/`JwksClient` for it (self-anchored). Verify DI yields a resolver that performs §3.4 verification. |
| `samples/MockResourceServers/Profile/README.md` | update `/anchored` description + sample header to `sig=jkt-jwt;jwt="…"`. |
| `samples/AgentConsole/**`, `samples/GuidedTour/**` | confirm `jkt-jwt → /anchored` flows still work with the new wire shape; update any captured/expected headers. |

### Definition of Done

- [ ] Profile `/anchored` accepts a valid §3.4 token and rejects a forged one.
- [ ] AgentConsole `jkt-jwt → /anchored` succeeds.
- [ ] No sample emits or asserts the legacy `jkt` param.

## Phase 6 — Docs

| File | Change |
|---|---|
| `docs/signing-modes/key-rotation-jkt-jwt.md` | rewrite to draft-04 §3.4: `typ=jkt-s256+jwt`, durable `jwk` in header, `iss=urn:jkt:sha-256:…`, self-anchored TOFU verification; header example without `jkt`. |
| `docs/signing-modes/overview.md` | update the two comparison-table `jkt-jwt` rows from `sig=jkt-jwt;jkt="…";jwt="…"` to `sig=jkt-jwt;jwt="…"`. |
| `docs/server/multi-scheme-verification.md`, `docs/server/verification-middleware.md` | describe self-anchored `jkt-jwt` verification; remove any AP-discovery framing for the resource path. |
| `docs/glossary.md` | ensure `jkt-jwt` / `urn:jkt` entries match §3.4. |

### Definition of Done

- [ ] No doc shows the legacy `jkt` param or `typ=naming+jwt`.
- [ ] `jkt-jwt` verification is described as self-anchored TOFU.
- [ ] Cross-links to `draft-hardt-httpbis-signature-key-04` §3.4 present.

## Phase 7 — Tests & verification

| File | Change |
|---|---|
| `tests/AAuth.Conformance/HttpSignatures/SignatureKeySchemesTests.cs` | assert `sig=jkt-jwt;jwt="…"`; remove `jkt`-param assertion; add a "stray `jkt` rejected" case. |
| `tests/AAuth.Conformance/HttpSignatures/NamingJwtValidationTests.cs` | rebuild vectors with `typ=jkt-s256+jwt`, header `jwk`, `urn:jkt` iss; add: valid, expired, tampered-sig, `iss`/thumbprint mismatch, **forgery (attacker iss)**. |
| `tests/AAuth.Tests/AAuthTokenTypeTests.cs` | update `naming+jwt` ↔ enum per Phase 0. |
| `tests/AAuth.Tests/AAuthConstantsTests.cs` | add `jkt-s256+jwt`; scheme name `jkt-jwt` unchanged. |
| e2e | GuidedTour identity flow w/ `jkt-jwt`; SampleApp `/anchored` (`jkt-jwt.spec.ts`); AgentConsole `jkt-jwt → /anchored`. |

### Verification matrix

| Layer | Command |
|---|---|
| Unit | `dotnet test tests/AAuth.Tests` |
| Conformance | `dotnet test tests/AAuth.Conformance` |
| Integration | refresh + `/anchored` happy-path and forgery |
| e2e | GuidedTour + SampleApp Playwright specs |
| Build | `dotnet build AAuth.slnx` (0 warnings) |

### Definition of Done

- [ ] All unit + conformance tests pass.
- [ ] Forgery vector returns 401 at a resource.
- [ ] e2e for GuidedTour, SampleApp `/anchored`, AgentConsole pass.
- [ ] Full solution builds clean.

## Out of scope

| Item | Reason |
|---|---|
| `jkt-s512+jwt` (SHA-512) | SHA-256 sufficient for current keys; add later if needed. |
| `x509` scheme changes | Not part of this gap. |
| Dual-format (legacy `jkt`) acceptance window | Internal demo only; coordinated cutover instead. |
| Spec PR upstream resolving the AP-refresh/`jwt` overlap | Tracked as an open question, not code in this repo. |
