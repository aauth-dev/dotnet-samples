# Implementation Plan: End-to-End Signing Mode Support

> Created 2026-05-22. Closes GAPS §3.1 from
> [`../2026-05-20-aauth-sdk-gap-remediation/gaps.md`](../2026-05-20-aauth-sdk-gap-remediation/gaps.md).
> Branch: `feat/gap-remediation-plan-updates`

## Goal

Wire the remaining three Signature-Key schemes (`hwk`, `jwks_uri`, `jkt-jwt`)
through the signing handler and verification middleware so the SDK supports all
four AAuth signing modes end-to-end.

## Background

Parse/format primitives exist: `SignatureKeyHeader.Format*()` and
`SignatureKeyParser.ParseAny()` handle all four schemes. The gap is the
**pipeline** — producing signed requests and verifying them for non-`jwt`
schemes.

## Design decisions

### Signing: strategy pattern via `ISignatureKeyProvider`

Rather than bloating `AAuthSigningHandler` with multiple constructors/modes,
introduce a small strategy interface that produces the `Signature-Key` header
value. The handler calls the provider instead of hard-coding `FormatJwt`.

```csharp
public interface ISignatureKeyProvider
{
    string GetSignatureKeyHeader();
}
```

Built-in implementations:
- `JwtSignatureKeyProvider(Func<string> tokenFactory)` — existing behaviour.
- `HwkSignatureKeyProvider(IAAuthKey key)` — emits `FormatHwk(key.ComputeJwkThumbprint())`.
- `JwksUriSignatureKeyProvider(string uri, string kid)` — emits `FormatJwksUri(uri, kid)`.
- `JktJwtSignatureKeyProvider(IAAuthKey ephemeralKey, Func<string> namingJwtFactory)` —
  emits `FormatJktJwt(ephemeralKey.ComputeJwkThumbprint(), namingJwt)`.

### Verification: scheme-dispatch via `ISignatureKeyResolver`

The middleware currently does synchronous jwt-only parsing. Replace with an
async resolution step that dispatches on scheme:

```csharp
public interface ISignatureKeyResolver
{
    Task<SignatureKeyResolution> ResolveAsync(
        ParsedSignatureKeyInfo info, CancellationToken ct);
}
```

Where `SignatureKeyResolution` carries the resolved `IAAuthKey` and optional
parsed token info. The default implementation chains:
- `jwt` → extract `cnf.jwk` from inline JWT (existing path).
- `hwk` → delegate to `IKeyLookup` (DI service, application-supplied).
- `jwks_uri` → delegate to `JwksClient.ResolveKeyAsync`.
- `jkt-jwt` → verify naming JWT, confirm thumbprint match, return key.

### Verifier accepts `IAAuthKey`

`AAuthVerifier.Verify()` parameter changes from `AAuthKey publicKey` to
`IAAuthKey publicKey`. This is source-compatible (callers passing `AAuthKey`
still work since `AAuthKey : IAAuthKey`).

---

## Phase 1: Signing handler refactor + `hwk`/`jwks_uri`/`jkt-jwt` signing

### Deliverables

| Item | File(s) |
|------|---------|
| `ISignatureKeyProvider` interface | `src/AAuth/HttpSig/ISignatureKeyProvider.cs` |
| `JwtSignatureKeyProvider` | `src/AAuth/HttpSig/JwtSignatureKeyProvider.cs` |
| `HwkSignatureKeyProvider` | `src/AAuth/HttpSig/HwkSignatureKeyProvider.cs` |
| `JwksUriSignatureKeyProvider` | `src/AAuth/HttpSig/JwksUriSignatureKeyProvider.cs` |
| `JktJwtSignatureKeyProvider` | `src/AAuth/HttpSig/JktJwtSignatureKeyProvider.cs` |
| `AAuthSigningHandler` refactor | Accept `ISignatureKeyProvider`; keep existing ctor as convenience |
| Unit tests for each provider | `tests/AAuth.Tests/HttpSig/SignatureKeyProviderTests.cs` |
| Integration test: sign+verify round-trip per mode | `tests/AAuth.Tests/HttpSig/SigningModeRoundTripTests.cs` |

### Definition of Done

- [ ] `ISignatureKeyProvider` interface defined.
- [ ] All four provider implementations emit correct header format.
- [ ] `AAuthSigningHandler` accepts `ISignatureKeyProvider`; backward-compat ctor still works.
- [ ] Round-trip test for each mode (sign → extract header → parse → verify signature).
- [ ] `dotnet test` green.

---

## Phase 2: Verification middleware multi-scheme dispatch

### Deliverables

| Item | File(s) |
|------|---------|
| `ISignatureKeyResolver` interface | `src/AAuth/HttpSig/ISignatureKeyResolver.cs` |
| `DefaultSignatureKeyResolver` | `src/AAuth/HttpSig/DefaultSignatureKeyResolver.cs` |
| `IKeyLookup` interface | `src/AAuth/HttpSig/IKeyLookup.cs` |
| `AAuthVerifier` generalized | Accept `IAAuthKey` |
| `AAuthVerificationMiddleware` refactor | Use `ParseAny()` + resolver |
| Unit tests for resolver | `tests/AAuth.Tests/HttpSig/SignatureKeyResolverTests.cs` |
| Integration test: middleware verifies each scheme | `tests/AAuth.Tests/Integration/MultiSchemeVerificationTests.cs` |

### Design notes

- `IKeyLookup` is intentionally minimal: `Task<IAAuthKey?> FindByThumbprintAsync(string jkt, CancellationToken ct)`.
  Applications register their own implementation (AP enrollment store, etc.).
- For `jwks_uri`: resolver takes `JwksClient` from DI. URI must be `https`
  (or loopback for dev). Spec-mandated rate-limit is already in `JwksClient`.
- For `jkt-jwt`: resolver verifies the naming JWT signature using the key in
  its own `cnf.jwk`, then confirms `ephemeralThumbprint == jkt` parameter.
- `DefaultSignatureKeyResolver` requires `JwksClient` (always available from
  DI) and optional `IKeyLookup` (only needed if the server expects `hwk`
  requests). If `hwk` arrives and no `IKeyLookup` is registered, return
  `unknown_key` error.

### Definition of Done

- [ ] `ISignatureKeyResolver` interface defined.
- [ ] `IKeyLookup` interface defined.
- [ ] `DefaultSignatureKeyResolver` dispatches all 4 schemes.
- [ ] `AAuthVerifier.Verify()` accepts `IAAuthKey`.
- [ ] Middleware uses `ParseAny()` + async resolver flow.
- [ ] Unit tests for each scheme resolution path (including error cases).
- [ ] Integration tests verifying signed requests in all 4 modes through the middleware.
- [ ] Backward compat: existing `jwt`-only callers work without changes.
- [ ] `dotnet test` green.

---

## Phase 3: Conformance tests + GuidedTour demo

### Deliverables

| Item | File(s) |
|------|---------|
| Conformance tests per scheme | `tests/AAuth.Conformance/HttpSignatures/SigningModeTests.cs` |
| GuidedTour signing mode selector | `samples/GuidedTour/` (optional UI) |

### Definition of Done

- [ ] Conformance test: `hwk` sign → verify round-trip.
- [ ] Conformance test: `jwks_uri` sign → verify with JWKS fetch.
- [ ] Conformance test: `jkt-jwt` sign → verify with delegation chain.
- [ ] Conformance test: `jwt` sign → verify (existing, confirm still passes).
- [ ] `dotnet test` green (all 306+ tests pass).

---

## Signing Mode × Flow Matrix (spec-mandated)

Per the AAuth Protocol spec and the [Signing Mode Comparison](https://explorer.aauth.dev/signing/compare):

| Flow | Valid Signing Modes | Rationale |
|------|--------------------:|-----------|
| **Identity-based (no PS)** | `hwk`, `jwks_uri` | Resource applies own access control; no PS-issued token available |
| **PS-asserted (three-party)** | `jwt` only | Spec: "agent MUST present its agent token via Signature-Key using `scheme=jwt`" |
| **AS-federated (four-party)** | `jwks_uri` (PS→AS), `jwt` (agent→resource) | PS uses JWKS identity to AS; agent presents auth token via jwt |
| **Bootstrap refresh** | `jkt-jwt` | Two-key delegation: naming JWT from durable key delegates to ephemeral key |

**Key constraint:** `jwt` requires a Person Server (the token carries a `ps` claim and is PS-issued).
Identity-based access (no PS) cannot use `jwt` — only `hwk` or `jwks_uri`.

### What the resource learns per mode

| Mode | Scheme | Resource learns | Use case |
|------|--------|-----------------|----------|
| Anonymous | (none) | Nothing | Public endpoints, no access control |
| Pseudonymous | `sig=hwk` | Key thumbprint — identity unknown | Accountable access, rate-limiting by key |
| Agent Identity | `sig=jwks_uri` | Agent identifier + verifiable public key (via JWKS) | Access control by identity, replacing API keys |
| Agent Token | `sig=jwt` | Agent identity, PS URL, bound signing key, delegation chain | Full PS-AS authorization flows (requires PS) |

### Demo constraints

- **GuidedTour**: Signing mode selector shown **only** in Identity flow (`hwk` / `jwks_uri`).
  Three-party flows (Autonomous/Deferred) lock to `jwt` per spec — no selector shown.
  `jwt` is not an option in the Identity picker because it requires a PS.
- **AgentConsole**: Defaults to `hwk` without `--ps`, `jwt` with `--ps`. Rejects `jwt` without
  `--ps` and rejects non-`jwt` with `--ps`.
- **WhoAmI**: Handles `hwk`/`jwks_uri` for identity-based access (returns 200 with scheme-appropriate
  claims). For `jwt` with `aa-agent+jwt` containing a `ps` claim, issues challenge for three-party flow.

---

## Out of scope

| Item | Reason |
|------|--------|
| Multi-algorithm JwksClient (ES256 key resolution) | Tracked separately in GAPS §4; `JwksClient` currently skips non-Ed25519 |
| Anonymous mode middleware opt-out | Trivial — caller just doesn't register the middleware on those routes |
| Platform attestation | GAPS §7 — `IPlatformAttestor` seam already exists |
| ECDSA `jkt-jwt` naming JWT | Needs multi-alg JwksClient first |
