# Research — `jkt-jwt` signing scheme vs. HTTP Signature Keys draft-04

> Research-only. No task lists or step-by-step instructions. The phased work
> lives in the companion `implementation-plan.md`.

## Goal

Determine whether the SDK's `jkt-jwt` Signature-Key scheme is conformant with its
authoritative definition, why it diverges, and what the spec actually requires —
so the implementation plan can fix it correctly (not just cosmetically).

Trigger: while saving the canonical spec
[`aauth-spec/draft-hardt-httpbis-signature-key-04.txt`](../../../aauth-spec/draft-hardt-httpbis-signature-key-04.txt)
(downloaded 2026-06-09) we noticed our `jkt-jwt` wire format and verification do
not match §3.4 of that draft. An independent spec-grounded subagent review
confirmed the divergences and surfaced a **live security gap** in the
resource-facing path.

## Authoritative sources

| Source | Role | Notes |
|---|---|---|
| `aauth-spec/draft-hardt-httpbis-signature-key-04.txt` §3.4 | **Canonical** definition of the `jkt-jwt` scheme (wire format + 11-step verification) | The AAuth protocol spec defers entirely to this for scheme formats. |
| `aauth-spec/draft-hardt-oauth-aauth-protocol.md` §http-message-signatures-profile (≈L2074–2078) | Sanctions `jkt-jwt` as a **pseudonym** scheme for general (resource-facing) access; defers wire format to the signature-key draft via `[@!I-D.hardt-httpbis-signature-key]` (normative, **unversioned/latest**). | "For `pseudonym`: the agent uses `scheme=hwk` … or `scheme=jkt-jwt`." |
| `aauth-spec/draft-hardt-aauth-bootstrap.md` §Two-Key Refresh (≈L274–310) | **Informational** — describes `jkt-jwt` used **only at the AP refresh endpoint**, where the AP already holds the durable key from enrollment. | Its own example is `sig=jkt-jwt;jwt="…"` — **no `jkt` parameter** — and it still requires the AP to verify the durable-key signature on the naming JWT. |

## What `jkt-jwt` is, per draft-04 §3.4

A device with a hardware-backed **durable/enclave** key delegates HTTP-signing to
a fast **ephemeral** key via a self-issued "naming" JWT. The scheme is
**self-anchored, Trust-On-First-Use (TOFU)** pseudonymous identity.

Canonical wire format and verification:

| Element | draft-04 §3.4 requirement |
|---|---|
| `Signature-Key` params | **`jwt` only**: `sig=jkt-jwt;jwt="<naming-jws>"` (example L519). No `jkt` parameter exists in the scheme. |
| Naming-JWT header `typ` | `jkt-s256+jwt` (SHA-256) or `jkt-s512+jwt` (SHA-512) (L456). |
| Naming-JWT header `alg` | signature algorithm of the durable key (L460). |
| Naming-JWT header `jwk` | **REQUIRED** — the durable/enclave **public key** that signed the JWT (L462). |
| Naming-JWT payload `iss` | `urn:jkt:<alg>:<thumbprint>` — the **durable key's** JWK thumbprint URI (RFC 7638) (L466). |
| Naming-JWT payload `iat`/`exp` | required (L478–481). |
| Naming-JWT payload `cnf.jwk` | the **ephemeral** public key delegated for signing (L482). |
| Naming-JWT payload `sub` | "not used" (L484). |
| Verification (L559–575) | (1) parse JWT; (2) check `typ`; (3) derive hash alg + `iss` prefix from `typ`; (4) extract header `jwk`; (5) compute its RFC 7638 thumbprint; (6) build expected `iss`; (7) **compare to `iss` by string equality**; (8) **verify the JWT signature using the header `jwk`**; (9) validate `exp`/`iat`; (10) extract `cnf.jwk`; (11) verify the HTTP signature with the ephemeral key. |
| Security note (§6.3, L1311–1318) | "any party can create a jkt-jwt — the scheme provides pseudonymous identity, not verified identity"; the verifier **MUST always compute the expected `iss` from the header `jwk` … never trust the `iss` value alone." |

`jkt-jwt` was **added in signature-key draft-03** (Appendix A.2, L1763); draft-01
shipped only `hwk`, `jwks_uri`, `x509`, `jwt` (A.4, L1786).

## What our SDK actually implements

A **different** scheme wearing the `jkt-jwt` name: an **AP-URL-issuer** naming-JWT
delegation whose trust model is the `jwt`/`jwks_uri` *issuer-discovery* model, not
TOFU self-anchoring.

| Element | Our code | File |
|---|---|---|
| `Signature-Key` params | adds a non-spec `jkt` param: `sig=jkt-jwt;jkt="…";jwt="…"` | [`SignatureKeyHeader.FormatJktJwt`](../../../src/AAuth/HttpSig/SignatureKeyHeader.cs) |
| `jkt` value | the **ephemeral** key thumbprint (rotates every refresh) | [`JktJwtSignatureKeyProvider`](../../../src/AAuth/HttpSig/JktJwtSignatureKeyProvider.cs) |
| Naming-JWT `typ` | `naming+jwt` | [`AAuthConstants.TokenTypes.NamingJwt`](../../../src/AAuth/AAuthConstants.cs), [`NamingJwtBuilder`](../../../src/AAuth/Agent/NamingJwtBuilder.cs) |
| Naming-JWT header `jwk` | **absent** — only `kid` = durable thumbprint | [`NamingJwtBuilder.Build`](../../../src/AAuth/Agent/NamingJwtBuilder.cs) |
| Naming-JWT `iss` | the **AP issuer HTTPS URL** | [`NamingJwtBuilder.Build`](../../../src/AAuth/Agent/NamingJwtBuilder.cs) |
| `cnf.jwk` | ephemeral key ✓ (the one element that matches) | — |
| Parser | **requires** both `jkt` and `jwt` params | [`SignatureKeyParser.ParseJktJwtScheme`](../../../src/AAuth/HttpSig/SignatureKeyParser.cs) |
| Resolver (verify) | resolves the durable key via `iss` → `/.well-known/aauth-agent.json` → `jwks_uri` → `kid`, then verifies the naming-JWT signature | [`DefaultSignatureKeyResolver.ResolveJktJwtAsync`](../../../src/AAuth/HttpSig/DefaultSignatureKeyResolver.cs) |

### The live security gap (confirmed)

`DefaultSignatureKeyResolver.ResolveJktJwtAsync` has a **graceful fallback**: when
`_metadataClient` (or `_jwksClient`) is null it `return info.ConfirmationKey;`
**without verifying the naming-JWT signature** — the durable→ephemeral delegation
is never cryptographically checked. The only check left is structural
(`jkt` param == `cnf.jwk` thumbprint), which an attacker fully controls.

The Profile sample **hits this fallback at runtime**: it registers
`new DefaultSignatureKeyResolver(JwksClient)` — passing the JWKS client but **not**
the `MetadataClient` — so `_metadataClient is null`
([`samples/MockResourceServers/Profile/Program.cs`](../../../samples/MockResourceServers/Profile/Program.cs), DI ≈L50). The `/anchored`
endpoint runs `SignatureOnly()` (`RequireIssuerVerification=false`), and the
middleware's issuer-verification block only handles `typ`=agent/auth-token —
`naming+jwt` falls through "Other token types … are not verified at this layer"
([`AAuthVerificationMiddleware`](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs) ≈L181–211). Net effect: **a resource accepts any
naming JWT with any `iss` and the attacker's own ephemeral key**, subject only to
`exp` and the self-referential thumbprint check. This is precisely the failure
§6.3 warns against ("never trust the `iss` value alone").

## Why the divergence exists (root cause)

The SDK was modeled on the **bootstrap draft's informal AP-refresh description**
(and/or a pre-04 understanding), then reused unchanged at resources:

- The constant is literally `naming+jwt` and `NamingJwtBuilder`'s doc-comments use
  bootstrap terminology ("naming JWT", durable→ephemeral), not draft-04's
  `jkt-s256+jwt` / `urn:jkt`.
- `iss`=AP-URL + metadata/`jwks_uri` discovery is the *AP-knows-the-key* model the
  bootstrap draft describes — not draft-04's self-anchored thumbprint.
- `jkt-jwt` only entered the signature-key draft at **-03**; the canonical
  `typ`/`iss`/header-`jwk` wire format is newer than the bootstrap-style
  delegation the SDK encodes. The extra `jkt` param appears **borrowed from the
  `hwk` scheme** (which legitimately uses `jkt`), i.e. assembled by analogy rather
  than from §3.4.

## Does the AAuth spec set justify it?

Partly — and this is the crux:

1. **AP-refresh use is a defensible profile.** The bootstrap draft (informational)
   has the AP "look up the enrollment by the durable key's thumbprint" and
   "verif[y] the durable-key signature on the naming JWT." Because the AP already
   holds the durable key, omitting the header `jwk` and the `urn:jkt` `iss` is
   reasonable for that **agent↔AP** leg. **But even the bootstrap example uses no
   `jkt` param** and still mandates signature verification — so our extra `jkt`
   param is non-conformant even there, and the AP path is only safe *because* the
   AP verifies the signature against its enrollment record.

2. **Resource use must follow draft-04.** The protocol spec sanctions `jkt-jwt`
   for general pseudonymous **resource** access (L2074–2078) and **defers the wire
   format to the signature-key draft**. Therefore the resource-facing `/anchored`
   path SHOULD use draft-04 §3.4's format and 11-step self-anchored verification —
   which it does not — and the unverified fallback is a security bug regardless of
   format.

## Verdict (synthesised)

**A mix, with a security gap:**

- **Resource-facing `jkt-jwt` (Profile `/anchored`)** — genuine **conformance bug
  + security gap**. Must adopt draft-04 §3.4 wire format and self-anchored
  verification; the unverified fallback must be removed.
- **AP-refresh `jkt-jwt` (agent↔AP)** — a *legitimate AAuth profile* the bootstrap
  draft sanctions, but should still (a) drop the non-spec `jkt` param to match both
  the draft-04 and bootstrap wire shape, and (b) keep verifying the naming-JWT
  signature (it already does when clients are registered). Both ends are ours, so
  external-interop risk is low.

## Spec ambiguity worth recording

draft-04's `jkt-jwt` is built around *self-anchored device identity* (header `jwk`
present, `iss`=thumbprint URN). It does **not** cleanly fit the AAuth refresh case
where the AP already knows the durable key and wants `iss` to mean "this AP."
Strictly, the AP-refresh leg is arguably better served by the `jwt` scheme
(issuer-discoverable `cnf.jwk` delegation), reserving `jkt-jwt` for the genuinely
self-anchored resource case. The drafts do not resolve this overlap — which is
plausibly how the divergence arose. This is an **open question for the maintainers**
(see implementation-plan Phase 0 decision gate).

## Impact surface (for planning)

SDK (authoritative wire format + verification):
- `src/AAuth/HttpSig/SignatureKeyHeader.cs` (`FormatJktJwt`)
- `src/AAuth/HttpSig/JktJwtSignatureKeyProvider.cs`
- `src/AAuth/HttpSig/SignatureKeyParser.cs` (`ParseJktJwtScheme`)
- `src/AAuth/HttpSig/DefaultSignatureKeyResolver.cs` (`ResolveJktJwtAsync` + the fallback)
- `src/AAuth/Agent/NamingJwtBuilder.cs`
- `src/AAuth/AAuthConstants.cs` (`TokenTypes.NamingJwt`), `src/AAuth/AAuthTokenType.cs`
- `src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs` (naming-JWT handling)
- `src/AAuth/Agent/AgentProviderClient.cs` (refresh path that mints the naming JWT)

Samples:
- `samples/MockResourceServers/Profile/Program.cs` + `README.md` (`/anchored` DI + pipeline)
- `samples/MockAgentProvider/**` (AP refresh verification, if it re-verifies)
- `samples/AgentConsole/**`, `samples/GuidedTour/**` (jkt-jwt mode flows)

Docs:
- `docs/signing-modes/key-rotation-jkt-jwt.md`, `docs/signing-modes/overview.md`
- `docs/server/multi-scheme-verification.md`, `docs/server/verification-middleware.md`

Tests (assert the **current** shape — will need updating):
- `tests/AAuth.Conformance/HttpSignatures/SignatureKeySchemesTests.cs` (asserts `sig=jkt-jwt;jkt="…";jwt="…"`)
- `tests/AAuth.Conformance/HttpSignatures/NamingJwtValidationTests.cs` (exp/replay; needs new `typ`/`iss`/header-`jwk` + signature vectors)
- `tests/AAuth.Tests/AAuthTokenTypeTests.cs` (`naming+jwt` ↔ `NamingJwt`)
- `tests/AAuth.Tests/AAuthConstantsTests.cs` (scheme name `jkt-jwt` — unchanged)
- e2e: GuidedTour identity flow with `jkt-jwt`; SampleApp `/anchored`; AgentConsole `jkt-jwt → /anchored`

## Gaps & open questions

1. **Design decision (Phase 0 gate):** for the **AP-refresh leg**, conform `jkt-jwt`
   to draft-04 §3.4 (self-anchored, header `jwk`, `urn:jkt` iss), **or** switch that
   leg to the `jwt` scheme and reserve `jkt-jwt` for resource self-anchoring? Both
   are spec-defensible; the maintainers must choose. The resource leg is
   non-negotiable: it must be draft-04 §3.4.
2. **Backward compatibility:** the SDK signs *and* verifies, so a coordinated change
   keeps the SDK self-consistent. Is any deployed token/cache or external party
   relying on the current `jkt`-param shape? (Believed no — internal demo only.)
3. **`typ` rename:** does `AAuthTokenType.NamingJwt` need to stay as a public
   alias, or can it map to `jkt-s256+jwt`? Affects `AAuthTokenTypeTests`.
4. **Hash agility:** draft-04 defines `jkt-s256+jwt` and `jkt-s512+jwt`. SDK uses
   Ed25519/P-256; SHA-256 thumbprints suffice. Implement `jkt-s256+jwt` only?

## Sources

- `aauth-spec/draft-hardt-httpbis-signature-key-04.txt` (§3.4, §4.4.1, §6.3, §7.1, Appendix A) — canonical scheme.
- `aauth-spec/draft-hardt-oauth-aauth-protocol.md` (§http-message-signatures-profile; normative ref to the signature-key draft).
- `aauth-spec/draft-hardt-aauth-bootstrap.md` (§Two-Key Refresh — AP-refresh profile, informational).
- Independent spec-grounded review (Researcher subagent, 2026-06-09) — verdict (iii) mix + confirmed security gap.
- SDK + sample files enumerated under **Impact surface**.
