# Implementation Plan — `jkt-jwt` conformance with HTTP Signature Keys draft-04

Companion to [`research.md`](research.md). Brings the SDK's `jkt-jwt` Signature-Key
scheme into conformance with `draft-hardt-httpbis-signature-key-04` §3.4, closes
the resource-side verification security gap, and updates samples, docs, and tests.

Decisions and deviations are recorded in
[`implementation-log.md`](implementation-log.md) for end-of-run review.

> Status: **Phase 0 resolved** (2026-06-09). Guiding principle from the owner:
> *"Back-compat is not needed — this repo is a spec-accurate alpha SDK. Do
> whatever is needed to be spec-accurate."* All open design questions are
> resolved in favour of strict draft-04 conformance; see Phase 0.

## Guiding principle (applies to every phase)

- **Spec accuracy over compatibility.** Match `draft-hardt-httpbis-signature-key-04`
  §3.4 exactly. No dual-format acceptance, no deprecation shims, no legacy
  aliases. One coordinated cutover — the SDK signs *and* verifies, so it stays
  internally consistent.
- **Delete dead code.** Remove now-unused parameters/fields rather than leaving
  them (e.g. the ephemeral `jkt`, the AP-URL `iss`/`apIssuer`).
- **Stable pseudonym = durable key.** Per §7.1 the identity a resource reports
  for `jkt-jwt` is the **durable** key's thumbprint (from the naming-JWT header
  `jwk` / `iss`), not the rotating ephemeral key.

## Summary of the change

| Aspect | From (current) | To (draft-04 §3.4) |
|---|---|---|
| Header params | `sig=jkt-jwt;jkt="…";jwt="…"` | `sig=jkt-jwt;jwt="…"` |
| Naming-JWT `typ` | `naming+jwt` | `jkt-s256+jwt` |
| Naming-JWT header `alg` | static `"EdDSA"` const | `durableKey.Algorithm` (EdDSA **or** ES256) |
| Naming-JWT header `jwk` | absent (`kid` only) | durable public key (REQUIRED) |
| Naming-JWT header `kid` | durable thumbprint | removed (identity is the `jwk` thumbprint) |
| Naming-JWT `iss` | AP issuer HTTPS URL | `urn:jkt:sha-256:<durable-thumbprint>` |
| Naming-JWT `cnf.jwk` | ephemeral key | ephemeral key (unchanged) |
| Naming-JWT `jti` | present | retained (additive; powers naming-JWT replay detection — §3.4 permits extra claims) |
| Reported identity (`Jkt`) | **ephemeral** thumbprint (rotates) | **durable** thumbprint (stable pseudonym, §7.1) |
| Resource verification | metadata→jwks_uri→kid; **unverified fallback** | self-anchored TOFU: `thumbprint(header jwk)==iss`, verify naming-JWT sig with header `jwk`, then trust `cnf.jwk` |
| AP-refresh verification | lookup by `kid`; verify sig vs enrolled key | self-anchored §3.4 first, then cross-check header `jwk` == enrolled durable key |

## Phase 0 — Decision gate (RESOLVED 2026-06-09)

The owner's guiding principle ("spec-accurate alpha SDK, no back-compat")
resolves every open question in favour of strict draft-04 conformance.

### Implementation Decisions (Phase 0)

- [x] **AP-refresh leg scheme: (A) conform to draft-04 §3.4 self-anchoring.**
  `jkt-jwt` means exactly one thing everywhere — the §3.4 self-issued delegation
  JWT (durable `jwk` in header, `iss=urn:jkt:sha-256:<thumbprint>`). The AP runs
  the §3.4 verification, then additionally cross-checks the header `jwk` against
  its enrolment record (the AP-specific trust binding layered *on top of* the
  spec verification, not instead of it). Rejected option (B) (switch refresh to
  the `jwt` scheme) because it would leave two different wire shapes and muddy
  the demo.
- [x] **Hash agility: implement `jkt-s256+jwt` (SHA-256) only.** §3.4: "MUST
  support `jkt-s256+jwt`"; `jkt-s512+jwt` is MAY. SDK keys use SHA-256 RFC 7638
  thumbprints (`ComputeJwkThumbprint`), so SHA-256 is the natural fit.
  `jkt-s512+jwt` stays out of scope.
- [x] **Rename `AAuthTokenType.NamingJwt` → `JktS256Jwt`; constant
  `TokenTypes.NamingJwt = "naming+jwt"` → `TokenTypes.JktS256Jwt = "jkt-s256+jwt"`.**
  No alias kept (no back-compat). Add `urn:jkt:sha-256:` prefix constant.
- [x] **No back-compat.** Single coordinated cutover; no dual-format parsing.

### Definition of Done

- [x] AP-refresh design choice (A) recorded with rationale.
- [x] Hash-agility, enum-rename, and back-compat decisions recorded.

## Phase 1 — Naming-JWT construction (draft-04 §3.4)

Rewrite naming-JWT minting to the canonical self-issued shape.

### Files

| File | Change |
|---|---|
| [`src/AAuth/Agent/NamingJwtBuilder.cs`](../../../src/AAuth/Agent/NamingJwtBuilder.cs) | New signature `Build(IAAuthKey durableKey, IAAuthKey ephemeralKey)`. Header: `alg`=`durableKey.Algorithm` (instance prop, not the static const), `typ`=`AAuthConstants.TokenTypes.JktS256Jwt`, `jwk`=`durableKey.ToPublicJwk()`; **drop `kid`**. Payload: `iss`=`AAuthConstants.JktThumbprintUrnPrefix + durableKey.ComputeJwkThumbprint()`, `iat`, `exp` (keep 5-min), `jti` (keep), `cnf.jwk`=`ephemeralKey.ToPublicJwk()`. **Drop the `issuer`/`kid` params.** Update the class doc-comment to cite §3.4 (not "bootstrap § Two-Key Refresh"). |
| [`src/AAuth/AAuthConstants.cs`](../../../src/AAuth/AAuthConstants.cs) | In `TokenTypes`, replace `NamingJwt = "naming+jwt"` with `JktS256Jwt = "jkt-s256+jwt"`. Add `public const string JktThumbprintUrnPrefix = "urn:jkt:sha-256:";` (with an XML-doc citing §3.4 Table 1). |
| [`src/AAuth/AAuthTokenType.cs`](../../../src/AAuth/AAuthTokenType.cs) | Rename enum member `NamingJwt` → `JktS256Jwt`; update `ToHeaderValue` and `ParseTokenType` to map `JktS256Jwt` ↔ `"jkt-s256+jwt"`. |

> No new crypto helper needed: `IAAuthKey.ComputeJwkThumbprint()` already returns
> the base64url SHA-256 RFC 7638 thumbprint, and `ToPublicJwk()` already emits the
> canonical public JWK. The `iss` URN is `prefix + thumbprint`.

### Definition of Done

- [x] Naming JWT emits `typ=jkt-s256+jwt`, `alg`=durable key alg, header `jwk`=durable public key, `iss=urn:jkt:sha-256:<thumbprint>`, `cnf.jwk`=ephemeral; no `kid`.
- [x] Unit test: minted JWT's `thumbprint(header.jwk)` equals the `iss` suffix, and the durable key verifies the JWT signature.
- [x] Solution builds with 0 warnings.

## Phase 2 — Wire format (header emit + parse)

### Files

| File | Change |
|---|---|
| [`src/AAuth/HttpSig/SignatureKeyHeader.cs`](../../../src/AAuth/HttpSig/SignatureKeyHeader.cs) | Change `FormatJktJwt(string jkt, string jwt)` → `FormatJktJwt(string jwt)` returning `sig=jkt-jwt;jwt="{jwt}"`. Apply the same RFC 8941 sf-string control-char/quote/backslash validation that `FormatJwt` uses. Update the XML-doc. |
| [`src/AAuth/HttpSig/JktJwtSignatureKeyProvider.cs`](../../../src/AAuth/HttpSig/JktJwtSignatureKeyProvider.cs) | Drop the `_ephemeralKey` field and the `ephemeralKey` constructor param (now unused — the HTTP signing key is held by `AAuthSigningHandler`, not the provider). `GetSignatureKeyHeader()` becomes `return SignatureKeyHeader.FormatJktJwt(_namingJwtFactory());`. Update the class doc-comment (no more `jkt="…"`). |
| [`src/AAuth/HttpSig/SignatureKeyParser.cs`](../../../src/AAuth/HttpSig/SignatureKeyParser.cs) | `ParseJktJwtScheme`: require **only** `jwt`; if a `jkt` param is present, reject (`AAuthVerificationException` — it signals the retired non-conformant format). Parse the header `jwk` into a durable key (`KeyFactory.FromJwk`), set `Jkt` = **durable** thumbprint (stable pseudonym), set `ConfirmationKey` = `cnf.jwk` ephemeral. Keep `Header`/`Payload`/`Jwt`. |

### Call-site ripple (this phase)

- `new JktJwtSignatureKeyProvider(ephemeralKey, () => namingJwt)` → `new JktJwtSignatureKeyProvider(() => namingJwt)` in:
  [`src/AAuth/Agent/AgentProviderClient.cs`](../../../src/AAuth/Agent/AgentProviderClient.cs) (≈L208),
  [`samples/AgentConsole/Program.cs`](../../../samples/AgentConsole/Program.cs) (≈L204, via `UseJktJwt`),
  [`tests/AAuth.Conformance/HttpSignatures/NamingJwtValidationTests.cs`](../../../tests/AAuth.Conformance/HttpSignatures/NamingJwtValidationTests.cs).
- [`src/AAuth/AAuthClientBuilder.cs`](../../../src/AAuth/AAuthClientBuilder.cs) `UseJktJwt` (≈L192) constructs the provider — update to the 1-arg ctor.

### Definition of Done

- [x] Emitted header is `sig=jkt-jwt;jwt="…"` (no `jkt`).
- [x] Parser accepts the new shape, rejects a stray `jkt` param, and exposes the durable thumbprint as `Jkt`.
- [x] Unit/conformance tests updated for both emit and parse.

## Phase 3 — Resource verification: self-anchored TOFU (security fix)

Implement draft-04 §3.4 steps 1–11 and **remove the unverified fallback**. This
is the security-critical phase.

### Files

| File | Change |
|---|---|
| [`src/AAuth/HttpSig/DefaultSignatureKeyResolver.cs`](../../../src/AAuth/HttpSig/DefaultSignatureKeyResolver.cs) | Rewrite `ResolveJktJwtAsync` to §3.4: (2) check `typ == jkt-s256+jwt` (reject otherwise); (4) extract header `jwk` → durable key; (5) compute its SHA-256 thumbprint; (6) build `urn:jkt:sha-256:<thumbprint>`; (7) **string-equality compare to payload `iss`**, reject mismatch; (8) **verify the naming-JWT signature with the header `jwk`**, reject failure; (10) extract `cnf.jwk` ephemeral; (11) return ephemeral as `PublicKey`. **Delete** the `_metadataClient is null` → `return info.ConfirmationKey` fallback and the entire metadata→`jwks_uri`→`kid` discovery block (self-anchored needs none of it). The `_jwksClient`/`_metadataClient` fields remain only for the `jwks_uri` scheme; update the ctor doc-comments so they no longer claim `jkt-jwt` needs them. Make `ResolveJktJwtAsync` synchronous-friendly (no `await`) but keep the `Task` signature for the dispatcher. |
| [`src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs`](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs) | Keep the naming-JWT `exp` check (≈L165). For the reported pseudonym (≈L258 `Jkt = ...`), use the **durable** thumbprint for `jkt-jwt`: `parsedInfo.Scheme == JktJwt ? parsedInfo.Jkt : (parsedInfo.ConfirmationKey?.ComputeJwkThumbprint() ?? parsedInfo.Jkt)`. Confirm `DetermineLevel` maps `jkt-jwt` → pseudonymous. Update the "Other token types … not verified at this layer" comment (≈L206) to note that `jkt-s256+jwt` self-anchoring is performed during key resolution. |

> **Trust model note.** §3.4 is self-anchored TOFU: *any* party can mint a valid
> `jkt-jwt` for *their own* durable key (a distinct pseudonym). The security
> property is that an attacker **cannot impersonate another agent's pseudonym** —
> claiming a victim's `iss` fails the `thumbprint(header jwk)==iss` check, and
> supplying the victim's `jwk` fails the signature check (no private key). The
> old fallback returned `cnf.jwk` without either check; that is the gap being
> closed.

### Definition of Done

- [x] `iss` not equal to `thumbprint(header.jwk)` → 401 (forgery via spoofed pseudonym).
- [x] Tampered naming-JWT signature → 401.
- [x] No code path returns `cnf.jwk` without verifying the naming-JWT signature.
- [x] A self-consistent attacker token (own durable+ephemeral keys) is accepted but yields the attacker's *own* durable thumbprint (distinct pseudonym) — documents the TOFU model.
- [x] Resource reports the **durable** thumbprint as the agent identity.

## Phase 4 — AP-refresh path (Option A — §3.4 self-anchored)

The AP runs the §3.4 verification, then cross-checks the header `jwk` against its
enrolment record.

### Files

| File | Change |
|---|---|
| [`src/AAuth/Agent/AgentProviderClient.cs`](../../../src/AAuth/Agent/AgentProviderClient.cs) | `RefreshTwoKeyAsync(refreshEndpoint, localKeyHandle, apIssuer, ct)` → drop `apIssuer` (no longer used — `iss` is now the durable thumbprint URN). Call `NamingJwtBuilder.Build(durableKey, ephemeralKey)` and the 1-arg `JktJwtSignatureKeyProvider`. |
| [`src/AAuth/Agent/AgentProviderTokenRefresher.cs`](../../../src/AAuth/Agent/AgentProviderTokenRefresher.cs) | Remove the `apIssuer` requirement/field for `RefreshMode.TwoKey` (≈L66, L86, L119); `WithRefreshMode(RefreshMode.TwoKey)` no longer takes an issuer. |
| [`src/AAuth/EnrolledBuilder.cs`](../../../src/AAuth/EnrolledBuilder.cs) | Drop the `apIssuer` param/doc (≈L67) tied to TwoKey refresh. |
| [`samples/MockAgentProvider/Program.cs`](../../../samples/MockAgentProvider/Program.cs) | Rewrite the refresh-endpoint `jkt-jwt` verification (≈L180–226): (1) check `typ==jkt-s256+jwt`; (2) extract header `jwk`, compute thumbprint, verify `iss==urn:jkt:sha-256:<thumbprint>`; (3) verify the naming-JWT signature with the header `jwk`; (4) look up the enrolment by that **durable thumbprint** (replacing the `kid`-based lookup); (5) cross-check the enrolled record's public key equals the header `jwk`; (6) validate `exp`; (7) use `cnf.jwk` as the ephemeral HTTP-sig key. |

### Definition of Done

- [x] Refresh naming JWT is §3.4-conformant (durable `jwk` header, `urn:jkt` iss, no `kid`).
- [x] AP verifies self-anchoring **and** binds the durable `jwk` to its enrolment record (no downgrade).
- [x] `apIssuer` is gone from the two-key refresh API surface.
- [x] Integration/e2e: two-key refresh succeeds end-to-end; tampered naming JWT rejected.

## Phase 5 — Samples

### Files

| File | Change |
|---|---|
| [`samples/MockResourceServers/Profile/Program.cs`](../../../samples/MockResourceServers/Profile/Program.cs) | `/anchored` keeps `jkt-jwt`. The `DefaultSignatureKeyResolver(JwksClient)` DI (≈L50) stays (JWKS is still needed for the `/identified` `jwks_uri` path); the `jkt-jwt` path now self-anchors and ignores those clients. Confirm `/anchored` accepts a valid §3.4 token. Update the header comment block (≈L21) if it shows the old wire shape. |
| [`samples/MockResourceServers/Profile/README.md`](../../../samples/MockResourceServers/Profile/README.md) | Update the `/anchored` description + any sample header to `sig=jkt-jwt;jwt="…"`; describe self-anchored verification + durable-thumbprint identity. |
| [`samples/AgentConsole/Program.cs`](../../../samples/AgentConsole/Program.cs) | `jkt-jwt` case (≈L191–211): `NamingJwtBuilder.Build(key, twoKeyResult.EphemeralKey)` (drop issuer+kid args); `RefreshTwoKeyAsync(refreshEndpoint, localKeyHandle)` (drop apUrl); `WithRefreshMode(RefreshMode.TwoKey)` (drop apUrl); 1-arg provider via `UseJktJwt`. |
| [`samples/GuidedTour/**`](../../../samples/GuidedTour) | Find where the `JktJwt` signing mode mints the naming JWT / reports identity (`CodeSnippets.cs`, `TourSession.cs`, `Tour.razor`). Update to the new `Build`/refresh API and ensure the displayed identity is the durable thumbprint. Update the `sig=jkt-jwt` narrative copy if it shows a `jkt` param. |

### Definition of Done

- [x] Profile `/anchored` accepts a valid §3.4 token; a spoofed-`iss` token is rejected.
- [x] AgentConsole `--signing-mode jkt-jwt → /anchored` succeeds against Profile :5000.
- [x] GuidedTour Key-Rotation flow runs and shows the durable thumbprint.
- [x] No sample emits or asserts the legacy `jkt` param.

## Phase 6 — Docs

### Files

| File | Change |
|---|---|
| [`docs/signing-modes/key-rotation-jkt-jwt.md`](../../../docs/signing-modes/key-rotation-jkt-jwt.md) | Rewrite to draft-04 §3.4: `typ=jkt-s256+jwt`, durable `jwk` in header, `iss=urn:jkt:sha-256:…`, self-anchored TOFU verification steps, header example without `jkt`, durable-thumbprint identity. |
| [`docs/signing-modes/overview.md`](../../../docs/signing-modes/overview.md) | Change the two comparison-table `jkt-jwt` rows from `sig=jkt-jwt;jkt="…";jwt="…"` to `sig=jkt-jwt;jwt="…"` (self-correcting the earlier doc edit). |
| [`docs/server/multi-scheme-verification.md`](../../../docs/server/multi-scheme-verification.md), [`docs/server/verification-middleware.md`](../../../docs/server/verification-middleware.md) | Describe self-anchored `jkt-jwt` verification; remove any AP/metadata-discovery framing for the resource path. |
| [`docs/glossary.md`](../../../docs/glossary.md) | Ensure `jkt-jwt` / `urn:jkt` / naming-JWT entries match §3.4. |
| [`docs/advanced/key-management.md`](../../../docs/advanced/key-management.md), [`docs/getting-started.md`](../../../docs/getting-started.md) | Sweep for any `jkt="…"`/`naming+jwt`/AP-iss descriptions and align. |

### Definition of Done

- [x] No doc shows the legacy `jkt` param or `typ=naming+jwt`.
- [x] `jkt-jwt` verification is described as self-anchored TOFU with durable-thumbprint identity.
- [x] Cross-links to `draft-hardt-httpbis-signature-key-04` §3.4 present.

## Phase 7 — Tests & verification

### Files

| File | Change |
|---|---|
| [`tests/AAuth.Conformance/HttpSignatures/SignatureKeySchemesTests.cs`](../../../tests/AAuth.Conformance/HttpSignatures/SignatureKeySchemesTests.cs) | `FormatJktJwt` test (≈L39–43): assert `sig=jkt-jwt;jwt="…"`; drop the `jkt` assertion. `ParseAny` test (≈L93–109): build a real §3.4 naming JWT (durable `jwk` header, `urn:jkt` iss) and assert scheme + durable `Jkt`. Add a "stray `jkt` param rejected" case. |
| [`tests/AAuth.Conformance/HttpSignatures/NamingJwtValidationTests.cs`](../../../tests/AAuth.Conformance/HttpSignatures/NamingJwtValidationTests.cs) | Rewrite `BuildNamingJwt` (≈L121) to §3.4 (typ `jkt-s256+jwt`, header `jwk`=durable, `iss=urn:jkt:sha-256:<thumbprint>`, `cnf`=ephemeral, keep `jti`). Keep valid/expired/skew/replay. Add: **spoofed-iss → 401**, **tampered-signature → 401**, **wrong-typ → 401**. |
| [`tests/AAuth.Tests/AAuthTokenTypeTests.cs`](../../../tests/AAuth.Tests/AAuthTokenTypeTests.cs) | `naming+jwt`↔`NamingJwt` (L12, L32) → `jkt-s256+jwt`↔`JktS256Jwt`. |
| [`tests/AAuth.Tests/AAuthConstantsTests.cs`](../../../tests/AAuth.Tests/AAuthConstantsTests.cs) | Scheme `jkt-jwt` unchanged (L68). Add `JktS256Jwt == "jkt-s256+jwt"` and `JktThumbprintUrnPrefix` assertions; remove any `naming+jwt` assertion. |
| [`samples/GuidedTour/playwright-tests/identity.spec.ts`](../../../samples/GuidedTour/playwright-tests/identity.spec.ts) | `JktJwt` case (≈L34): ensure the asserted `jkt` is the **durable** thumbprint; adjust if the displayed value changes. |
| SampleApp e2e | Add/confirm a `jkt-jwt` → `/anchored` Playwright assertion (the `JktJwt.razor`/`anchored` page). |

### Verification matrix

| Layer | Command |
|---|---|
| Unit | `dotnet test tests/AAuth.Tests/AAuth.Tests.csproj` |
| Conformance | `dotnet test tests/AAuth.Conformance/AAuth.Conformance.csproj` |
| Build | `dotnet build AAuth.slnx` (0 warnings) |
| e2e (GuidedTour) | `make` target / Playwright identity spec |
| e2e (SampleApp) | Playwright `/anchored` spec |

### Definition of Done

- [x] All unit + conformance tests pass.
- [x] Spoofed-`iss` and tampered-signature vectors return 401.
- [x] e2e for GuidedTour Key-Rotation and SampleApp `/anchored` pass.
- [x] Full solution builds clean (0 warnings).

## Phase 8 — Final review

A consolidated review pass before handing back to the owner (mirrors the prior
plan's closing review).

### Approach

- Re-read `draft-hardt-httpbis-signature-key-04` §3.4 and check the implementation
  line-by-line against verification steps 1–11 (a subagent may be dispatched for
  an independent conformance check).
- `grep` the whole repo for residue of the old format: `naming+jwt`,
  `jkt="`, `sig=jkt-jwt;jkt`, AP-URL `iss` in naming JWTs, `apIssuer` on the
  two-key path. Expect zero hits outside historical plan/log notes.
- Re-run the full verification matrix (build + unit + conformance + e2e).
- Walk the [`implementation-log.md`](implementation-log.md) Decisions / Deviations
  / Open-questions entries and confirm each is either resolved or flagged for the
  owner.

### Definition of Done

- [x] Line-by-line §3.4 conformance confirmed (steps 1–11).
- [x] Zero residual old-format hits in `src/`, `samples/`, `tests/`, `docs/`.
- [x] Full verification matrix green.
- [x] `implementation-log.md` reviewed; open questions surfaced to the owner.

## Out of scope

| Item | Reason |
|---|---|
| `jkt-s512+jwt` (SHA-512) | §3.4 makes it MAY; SDK keys use SHA-256 thumbprints. |
| `x509` scheme changes | Not part of this gap. |
| Dual-format / legacy `jkt` acceptance | Spec-accurate alpha SDK — no back-compat (owner decision, Phase 0). |
| Spec PR upstream resolving the AP-refresh/`jwt` overlap | Tracked as a research open question, not code in this repo. |
