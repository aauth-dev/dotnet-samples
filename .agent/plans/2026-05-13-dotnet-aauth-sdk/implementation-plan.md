# Implementation Plan: .NET AAuth SDK & Demo

> Created 2026-05-18. Goal: minimal functional SDK + samples showcasing AAuth flows.
> Not production polish — enough to demonstrate the spec and let people build demos.

## Principles

- Single solution, single library project — no premature package splitting.
- Lean on existing NuGet packages (NSign, Microsoft.IdentityModel, StructuredFieldValues).
- Each phase produces a runnable artifact you can demo.
- **Every production type ships with tests.** No new public type, header parser, token builder, or HTTP handler lands without an accompanying xUnit test that exercises it. Tests live alongside the code they prove — no separate test phase. A phase is not Done until `dotnet test` passes.
- **README stays in sync with the code.** Every phase that adds or changes a runnable artifact (library, sample, CLI, server) updates the root `README.md` in the same PR. The README is the public-facing entry point — out-of-date layout tables, missing samples, or stale quickstarts make the repo feel abandoned. A phase is not Done until the README reflects its artifacts.

---

## Phase 1: Core Crypto + Agent Token + Signed Request

**Goal**: An agent console app that generates a key, creates an `aa-agent+jwt`, and makes a signed HTTP request.

### Phase 1 Implementation Decisions (recorded 2026-05-18)

Confirmed before starting implementation:

- **Target framework**: `net10.0` (matches dev container SDK 10.0.300). Native `System.Security.Cryptography.EdDSA` is **not** present on .NET 10 in this container (verified 2026-05-18 — the type does not resolve at runtime). All Ed25519 operations use BouncyCastle. Phase 1 initially pulled BouncyCastle in transitively via `NSign.BouncyCastle`; Phase 2 self-review (see §"Phase 2 self-review hardening" below) replaced the NSign packages with a direct `BouncyCastle.Cryptography` reference. See research §5.2 update.
- **NuGet versions pinned for Phase 1** (verified to restore on `net10.0` in this dev container, 2026-05-18). NSign rows have been **removed post-Phase-2 self-review** (see Phase 2 §self-review hardening) and BouncyCastle is now a direct dependency:
  - ~~`NSign.Client` 1.2.3~~ — removed in Phase 2 self-review.
  - ~~`NSign.BouncyCastle` 1.2.3~~ — removed in Phase 2 self-review.
  - `BouncyCastle.Cryptography` 2.6.2 — direct reference (post Phase 2 self-review); previously transitive via NSign.
  - `Microsoft.IdentityModel.Tokens` 8.18.0 — `JsonWebKey` serialization and built-in `ComputeJwkThumbprint()` (RFC 7638).
  - **Removed during PR review (2026-05-18):** `StructuredFieldValues` 0.7.7 was originally pinned for the `Signature-Key` header but the hand-rolled parser made it unused; dropped to keep the transitive closure minimal. Re-add when a future header genuinely needs full RFC 8941 coverage.
  - Tests: `xunit`, `xunit.runner.visualstudio`, `Microsoft.NET.Test.Sdk` (latest at pin time). Shared via `tests/Directory.Build.props`.
- **Agent JWT signing strategy**: hand-roll a minimal JWT writer (Base64Url header + payload + BouncyCastle `Ed25519Signer`) inside `AgentTokenBuilder`. Rationale:
  - `Microsoft.IdentityModel.Tokens` 8.18 still ships no built-in EdDSA `SignatureProvider`.
  - Native `System.Security.Cryptography.EdDSA` is unavailable on .NET 10 in this container.
  - Phase 1 only needs to *issue* one token type; the format is small and well-defined.
  - Avoids pulling in a third JWT stack (`ScottBrady.IdentityModel.Tokens` or `jose-jwt`) before Phase 2's verification path is designed.
  - Revisit when verification lands in Phase 2.
- **Key storage**: file-based JWK JSON under `~/.aauth/keys/` (no OS credential store integration in Phase 1).
- **Single library project**: all Phase 1 code ships in `src/AAuth/AAuth.csproj`. No sub-package splitting until the API stabilizes.
- **RFC 9421 signing strategy**: Phase 1 hand-rolls a minimal RFC 9421 signer that covers the fixed AAuth set (`@method`, `@authority`, `@path`, `signature-key`). NSign is referenced (so the dependency graph is settled) but its `DefaultMessageSigner` + DI plumbing is **not** wired up yet. Rationale: NSign's value lies mainly in server-side verification (ASP.NET Core middleware) and broader covered-component support; for a client emitting four well-defined components, ~50 lines of direct code is clearer than wiring `IOptions`, `ISigner`, and `MessageContext`. Phase 2 will revisit and likely switch to NSign for the verification side, at which point the signer can be migrated for symmetry.
- **Spec-traceable conformance tests**: a separate `tests/AAuth.Conformance/` xUnit project mirrors the AAuth spec's section structure. Tests use `[Fact(DisplayName = "§<section> — <clause>")]` so CI output reads like a conformance checklist, with xmldoc summaries quoting the exact spec sentences. Plain xUnit (not Reqnroll/Gherkin) — the spec's `MUST/SHOULD` clauses read naturally as test names without a DSL layer. Phase 1 covers only **issuer-side** clauses for `aa-agent+jwt`; receiver-side clauses ("MUST verify ...") land in Phase 2 alongside the verifier. See [tests/AAuth.Conformance/README.md](../../../tests/AAuth.Conformance/README.md) for the section→file map.
- **Self-review hardening (recorded 2026-05-18, post-PR-review)**: a third pass found two real correctness bugs the automated reviewer missed plus several smaller polish items. Fixed in Phase 1:
  - `AAuthKey.FromJwk` now derives the public key from `d` and rejects mismatched `x`/`d` JWKs (would otherwise silently produce tokens whose signatures don't verify against their own `cnf.jwk`).
  - `AAuthSigningHandler` signs `Uri.GetComponents(Path, UriEscaped)` instead of `AbsolutePath`, so paths with percent-encoded / non-ASCII characters verify against the on-the-wire form per RFC 9421 §2.2.7.
  - `ComputeJwkThumbprint` constructs the canonical JSON explicitly so future field reordering can't silently change thumbprints.
  - `SignatureKeyHeader.FormatJwt` rejects all C0 control chars (not just `"`/`\`) so the formatter is safe outside HttpClient.
  - `SignatureKeyHeader` parser only unescapes RFC 8941 §3.3.3 escapes (`\"`, `\\`); other `\X` sequences are rejected.
  - `AgentTokenBuilder` validates `Issuer` and `PersonServer` are absolute `https://` URLs at issue time.

### Phase 1 follow-ups deferred to Phase 2

Recorded 2026-05-18 from the self-review. These don't block Phase 1 DoD but should be addressed when the corresponding Phase 2 work lands:

- **Composable `Signature`/`Signature-Input` headers** (`AAuthSigningHandler`): the handler currently `Remove`s the full `Signature` / `Signature-Input` headers before adding its own. Once the Phase 2 inbound verifier exists and we may compose multiple signers (e.g. AAuth + a separate proof-of-possession layer), the handler should merge by RFC 9421 label rather than clobbering the entire header. Track under §2.1.
- **`KeyStore.Save` overwrite semantics**: `Save` silently truncates an existing key. Add a `bool overwrite = false` parameter (or `SaveNew` variant) when the API stabilizes — defer until Phase 2 surfaces real callers beyond `LoadOrCreate`. Track under §2.2 or a future credential-store refactor.
- **Receiver-side negative conformance cases**: the Phase 1 conformance suite is all positive structural assertions. The negative cases (`alg=none` rejected, missing `cnf` rejected, mismatched `cnf.jwk` rejected, expired token rejected) land with the verifier in §2.9.

### 1.1 Project scaffolding

| Action | Detail |
|---|---|
| Create `src/AAuth/AAuth.csproj` | Class library targeting `net10.0` |
| Create `samples/AgentConsole/AgentConsole.csproj` | Console app referencing `AAuth` |
| Create `tests/AAuth.Tests/AAuth.Tests.csproj` | xUnit test project |
| Create `AAuth.sln` | Solution file tying everything together |
| NuGet references (AAuth) | `NSign.Client`, `NSign.BouncyCastle`, `Microsoft.IdentityModel.JsonWebTokens`, `Microsoft.IdentityModel.Tokens`, `StructuredFieldValues`, `ScottBrady.IdentityModel.EdDsa` (or `jose-jwt`) |

### 1.2 Ed25519 key management (minimal)

| File | Responsibility |
|---|---|
| `src/AAuth/Crypto/AAuthKey.cs` | Generate Ed25519 key pair, export/import JWK, compute JWK thumbprint (RFC 7638) |
| `src/AAuth/Crypto/KeyStore.cs` | Save/load key from `~/.aauth/keys/` as JWK JSON file (simple file-based, no OS credential store yet) |

**Test**: Generate key → export public JWK → compute thumbprint → verify matches expected.

### 1.3 Agent token creation

| File | Responsibility |
|---|---|
| `src/AAuth/Tokens/AgentTokenBuilder.cs` | Build and sign `aa-agent+jwt` with claims: `iss`, `sub`, `cnf.jwk`, `iat`, `exp`, `jti`, `dwk` |

**Test**: Create token → decode → verify all claims present and signature valid.

### 1.4 HTTP signature (outbound)

| File | Responsibility |
|---|---|
| `src/AAuth/HttpSig/SignatureKeyHeader.cs` | Format `Signature-Key: sig=jwt;jwt="..."` header value |
| `src/AAuth/HttpSig/AAuthSigningHandler.cs` | `DelegatingHandler` wrapping NSign's signing handler. Adds `Signature-Key` header and configures covered components (`@method`, `@authority`, `@path`, `signature-key`) |

**Test**: Create handler → send request through `MockHttpMessageHandler` → verify `Signature`, `Signature-Input`, `Signature-Key` headers present and well-formed.

### 1.5 Agent console sample

| File | Responsibility |
|---|---|
| `samples/AgentConsole/Program.cs` | Generate/load key → create agent token → make signed `GET` to a URL (configurable) → print response + headers |

**Runnable demo**: `dotnet run --project samples/AgentConsole -- https://some-resource.example`

### Phase 1 Definition of Done

- [x] `dotnet build` succeeds for the whole solution
- [x] Every new type in `src/AAuth/` has at least one xUnit test in `tests/AAuth.Tests/`
- [x] `dotnet test` passes (key gen + JWK round-trip + thumbprint, agent token claims + signature, `Signature-Key` header formatting, signing handler header emission)
- [x] AgentConsole sends a properly signed request (verifiable by inspecting headers)
- [x] `README.md` updated with Phase 1 layout (`src/`, `samples/`, `tests/`) and a runnable AgentConsole quickstart

---

## Phase 2: Resource Server + Three-Party Challenge-Response

**Goal**: A WhoAmI resource server that verifies agent signatures, issues resource tokens, and verifies auth tokens. The agent auto-handles the 401 challenge.

### Phase 2 Implementation Decisions (recorded 2026-05-18)

Confirmed before starting implementation:

- **Inbound RFC 9421 verification is hand-rolled, informed by NSign's implementation.** Symmetric with Phase 1's outbound signer. NSign was originally referenced as a study reference and as a transitive source of BouncyCastle Ed25519; during Phase 2 self-review the `NSign.Client` + `NSign.BouncyCastle` packages were removed (no runtime usage emerged), and `BouncyCastle.Cryptography` is now a direct dependency of `src/AAuth/AAuth.csproj`. Rationale and impact:
  - AAuth covers a fixed, small set of components (`@method`, `@authority`, `@path`, `signature-key`). The verification base reconstruction mirrors the Phase 1 signer almost line-for-line.
  - Keeps the dependency graph minimal; no new `IOptions`/DI plumbing.
  - We read NSign's `SignatureInputParser`, `SignatureInputSpec`, and `MessageContext.GetSignatureBase` to ensure our parser handles the same edge cases (parameter ordering, quoted-string escapes, `created` parameter, structured-field framing).
  - **Impact**: AAuth owns header parsing and freshness checks. Acceptable while the covered-component set is fixed; if AAuth ever needs full RFC 9421 component coverage (`@query-param`, derived components, Content-Digest binding, etc.), revisit and re-introduce NSign.
  - Verification entry point is a plain ASP.NET middleware that consumes `HttpContext`; no NSign middleware in the pipeline.
- **EdDSA JWT verification is hand-rolled with BouncyCastle**, mirroring `AgentTokenBuilder`'s signing path. Rationale and impact:
  - Consistent with Phase 1's decision; avoids introducing `ScottBrady.IdentityModel.EdDsa` or a second JWT stack solely to verify three token types we already know the structure of.
  - `TokenVerifier` does Base64Url decode of header/payload/signature, validates `alg=EdDSA` and `typ`, runs BouncyCastle `Ed25519Signer.VerifySignature`, then deserializes claims with `System.Text.Json` and validates them explicitly (`iss`, `aud`, `exp`, `iat`, `cnf.jwk` binding, `agent_jkt`, `scope`).
  - **Impact**: AAuth ships its own claim-validation logic instead of leaning on `TokenValidationParameters`. Acceptable while the token shapes are spec-fixed and small. Reconsider if/when we need broader algorithm support (ES256, RS256) — at that point switching to `JsonWebTokenHandler` + an EdDSA provider becomes worthwhile.
- **Three-party integration test uses an in-process mock PS via `WebApplicationFactory`.** A second `WebApplicationFactory<TPersonServerStartup>` in `tests/AAuth.Tests/Integration/` issues `aa-auth+jwt` against a test key, lets the agent retry, and asserts WhoAmI returns `200`. This keeps Phase 2 self-contained — no Phase 3 dependency. **Follow-up**: once Phase 3 lands `samples/MockPersonServer/`, the integration test should be migrated to spin up the real mock binary (or its `WebApplicationFactory`) so the test exercises shipped sample code rather than a private duplicate. Tracked as a Phase 3 §3.1 follow-up.

### 2.1 HTTP signature verification (inbound)

| File | Responsibility |
|---|---|
| `src/AAuth/HttpSig/SignatureKeyParser.cs` | Parse `Signature-Key` header → extract JWT → decode `cnf.jwk` → provide public key to the AAuth verifier |
| `src/AAuth/HttpSig/AAuthVerifier.cs` | Hand-rolled RFC 9421 verifier (mirror of Phase 1 signer): parses `Signature-Input`, rebuilds signature base, checks `created` freshness window, verifies Ed25519 signature via BouncyCastle. Informed by NSign's parser but no runtime dependency on it. |
| `src/AAuth/HttpSig/AAuthVerificationMiddleware.cs` | ASP.NET middleware that runs the verifier, validates the embedded token type (`aa-agent+jwt` or `aa-auth+jwt`), and sets `HttpContext.Items` with parsed claims |

### 2.2 Token verification

| File | Responsibility |
|---|---|
| `src/AAuth/Tokens/TokenVerifier.cs` | Verify any AAuth JWT: fetch issuer metadata (`/.well-known/{dwk}`), fetch JWKS, validate signature, check `exp`/`aud`/`cnf` binding |
| `src/AAuth/Discovery/MetadataClient.cs` | Fetch + cache well-known metadata documents |
| `src/AAuth/Discovery/JwksClient.cs` | Fetch + cache JWKS with rate limiting (≥ 1 min between fetches) |

### 2.3 Resource token minting

| File | Responsibility |
|---|---|
| `src/AAuth/Tokens/ResourceTokenBuilder.cs` | Build and sign `aa-resource+jwt` with: `iss`, `dwk`, `aud` (= PS URL from agent token's `ps` claim), `agent`, `agent_jkt`, `scope`, `iat`, `exp` (5 min) |

### 2.4 Well-known endpoints

| File | Responsibility |
|---|---|
| `src/AAuth/Server/WellKnownEndpoints.cs` | Extension method: `app.MapAAuthResourceWellKnown(options)` → serves `/.well-known/aauth-resource.json` and `/.well-known/jwks.json` |

### 2.5 AAuth-Requirement response

| File | Responsibility |
|---|---|
| `src/AAuth/Headers/AAuthRequirementHeader.cs` | Build and parse `AAuth-Requirement: requirement=auth-token; resource-token="..."` with a hand-rolled parser sharing structure with `SignatureKeyHeader`. Inbound parsing is exposed on the same type via static `Parse`; no separate `AAuthRequirementParser.cs` is shipped. |

### 2.6 WhoAmI sample server

| File | Responsibility |
|---|---|
| `samples/WhoAmI/Program.cs` | Minimal API: `GET /` verifies signature, if agent-token → 401 + resource_token, if auth-token → 200 + claims JSON. Serves well-known endpoints. |
| `samples/WhoAmI/WhoAmI.csproj` | Web project referencing `AAuth` (which transitively brings in `BouncyCastle.Cryptography`). No direct NSign reference. |

**Test**: In-process `WebApplicationFactory` test: send signed request → get 401 + resource_token → verify resource_token is valid JWT with correct claims.

### 2.7 Token exchange (agent side)

| File | Responsibility |
|---|---|
| `src/AAuth/Agent/TokenExchangeClient.cs` | POST `resource_token` to PS `token_endpoint` (signed request), receive `auth_token` |

### 2.8 Challenge-response handler (agent side)

| File | Responsibility |
|---|---|
| `src/AAuth/Agent/ChallengeHandler.cs` | Detect `AAuth-Requirement` on 401, extract resource_token, call `TokenExchangeClient`, retry original request with auth_token in `Signature-Key` |

`AAuthRequirementHeader.Parse` (see §2.5) handles inbound parsing. `AAuthSigningHandler` itself remained unchanged in Phase 2 — challenge-response is composed at the `HttpClient` pipeline level by chaining `ChallengeHandler → AAuthSigningHandler` rather than entangling the two responsibilities in one handler.

### 2.9 Receiver-side conformance tests

Extend `tests/AAuth.Conformance/` with receiver-side clauses now that a verifier exists:

| File | Spec coverage |
|---|---|
| `AgentTokens/AgentTokenVerificationTests.cs` | protocol §Agent Token Verification (steps 1–6) |
| `HttpSignatures/SignatureKeyHeaderTests.cs` | draft-hardt-httpbis-signature-key |
| `HttpSignatures/CoveredComponentsTests.cs` | protocol §Resource Access (required components, `created` window) |
| `ResourceTokens/ResourceTokenStructureTests.cs` | protocol §Resource Tokens |
| `Discovery/WellKnownMetadataTests.cs` | protocol §Discovery (`/.well-known/aauth-resource.json`, JWKS) |

Update [tests/AAuth.Conformance/README.md](../../../tests/AAuth.Conformance/README.md) section→file map as each lands.

### Phase 2 Definition of Done

- [x] WhoAmI server starts, serves well-known, verifies signatures, issues resource tokens
- [x] AgentConsole → WhoAmI returns 401 + resource_token (identity-based access also works if PS claim absent)
- [x] Integration test: full three-party flow with mock PS returning auth_token
- [x] Agent retries with auth_token → WhoAmI returns 200 + claims
- [x] Receiver-side conformance tests land for agent-token verification, `Signature-Key` parsing, resource-token structure, and discovery endpoints
- [x] `README.md` updated with WhoAmI sample + three-party flow quickstart

### Phase 2 self-review hardening (recorded 2026-05-18, post-PR-review)

Follow-ups landed against PR #6 after the in-repo review (`.copilot-tracking/pr/review/dasithw-phase-2/`):

- **Loopback-aware HTTPS check.** Introduced `src/AAuth/AAuthUrl.cs` with `IsHttpsOrLoopback` and routed all token builders (`AgentTokenBuilder`, `ResourceTokenBuilder`, `AuthTokenBuilder`) plus `WellKnownEndpoints.Validate` through it. The sample's default `http://localhost:5000` issuer now flows through the three-party path without an env-var escape hatch; non-loopback `http://` is still rejected.
- **Asymmetric `created` freshness window.** `AAuthVerifier` now exposes `MaxFutureSkew` (default 5s) alongside `MaxAge`. The previous symmetric tolerance silently doubled the legitimate replay window into the future.
- **DI-aware `UseAAuthVerification`.** The middleware extension now passes through to `app.UseMiddleware<AAuthVerificationMiddleware>()` when no verifier is supplied, so a DI-registered `AAuthVerifier` (e.g. WhoAmI's `signature_window`-bound singleton) is honoured. Previously the extension always instantiated a fresh `new AAuthVerifier()`, shadowing DI.
- **`AAuthTokenHolder._token` made `volatile`.** Documents the release/acquire intent for cross-thread token rotation.
- **WhoAmI plumbs `signature_window` end-to-end.** `AAuthResourceMetadataOptions.SignatureWindow` (from config) now feeds both the published metadata and the verifier's `MaxAge`. `KeyId` and `Scope` literals are consolidated to `ResourceKid` / `ResourceScope` constants.
- **NSign removal.** `NSign.Client` and `NSign.BouncyCastle` were study-only references that never imported; both are dropped and replaced with a direct `BouncyCastle.Cryptography` 2.6.2 package reference on `src/AAuth/AAuth.csproj`. Phase 1 §"NuGet versions pinned" wording is now stale — see updated text in Phase 2 §Implementation Decisions above.
- **401 shape integration test.** Added `WhoAmIFlowTests.ThreePartyChallenge_Returns401WithResourceToken` which bypasses the agent's `ChallengeHandler` and inspects the raw 401 + `AAuth-Requirement` + decoded `resource_token` payload, guarding the spec-mandated shape independently of the happy-path retry.
- **Phase 3 follow-up TODO.** A `TODO(Phase 3 §3.1)` marker on `WhoAmIFlowTests.StartMockPsAsync` records the planned migration to the shared `samples/MockPersonServer/` binary.

#### Second-round PR review (2026-05-18, commit `ead54c1`)

- **`TokenExchangeClient` SSRF guard.** `ExchangeAsync` now requires the PS-advertised `token_endpoint` to pass `AAuthUrl.IsHttpsOrLoopback` **and** share an origin (scheme/host/port) with the configured `personServer` before the signed POST is dispatched. A malicious or compromised PS metadata document can no longer divert the exchange to an arbitrary host or downgrade it to plain http.
- **`TokenVerifier.VerifyWithJwksAsync` fail-fast ordering.** The cheap local invariants (`header.alg`, `header.typ`, `payload.dwk`) are now validated immediately after segment decode, **before** any `MetadataClient.FetchAsync` / `JwksClient.ResolveKeyAsync` call. Obviously-invalid tokens no longer cause outbound discovery traffic, removing a DoS-amplification / outbound-probe surface.

---

## Phase 3: End-to-End Demo with Person Server + Guided Tour

> Restructured 2026-05-19: the original Phase 2.5 "Guided Tour (Blazor Server)"
> idea was folded into Phase 3. The tour needs `MockPersonServer` to tell the
> full three-party story; shipping both together avoids a half-feature first
> drop and lets the tour subsume the planned `demo-run.sh` orchestrator.

**Goal**: A self-contained, runnable demo of all three AAuth resource access
flows (identity-based, PS-asserted autonomous, user-consent), exposed two ways:
a Blazor Server "follow the bouncing ball" guided tour for newcomers, and
xUnit integration tests for CI. Both consume the same `src/AAuth/` SDK that
`samples/AgentConsole/` already uses.

### Phase 3 Implementation Decisions (recorded 2026-05-19)

- **`MockPersonServer` ships first.** It is the prerequisite for the
  three-party leg of the Guided Tour, the integration tests, and the planned
  Phase 2 follow-up that migrates `WhoAmIFlowTests.StartMockPsAsync` to the
  shipped binary. Build order within the phase: §3.1 → §3.3 → §3.2 → §3.4.
- **§3.3 (Guided Tour) before §3.2 (DeferredPoller).** The Blazor tour was
  the user-facing trigger for opening Phase 3, and its three-party-autonomous
  spine does not need deferred polling. `DeferredPoller` + `AAuthInteraction`
  remain in this phase but ship alongside the user-consent integration test
  (§3.4) once the tour is up.
- **Guided Tour hosting: Blazor Server.** The SDK's `DelegatingHandler`
  pipeline, Ed25519 signing, and `HttpClient` plumbing all run server-side in
  .NET; the browser only renders state pushed over SignalR. WASM would
  require porting Ed25519 + RFC 9421 signing into the browser, out of scope.
- **Guided Tour points at running external processes** (`samples/WhoAmI`
  + `samples/MockPersonServer`) via configured URLs. It does not spawn them
  in-process. Keeps the tour focused on visualization.
- **Identity-based fallback.** If `MockPersonServerUrl` is not configured the
  tour collapses to the identity-based path (steps 1–4 below) and ends at
  step 4 with a 200. So the tour is still useful without MockPS running.
- **No new SDK code from the tour.** The tour consumes `src/AAuth/` as-is.
  If a missing observability hook is discovered (e.g. surfacing the RFC 9421
  signature base for display), the gap is filled in `src/AAuth/` with an
  accompanying xUnit test, not patched into the sample.
- **`demo-run.sh` is dropped.** The Blazor tour subsumes its purpose
  (orchestrate WhoAmI + MockPS + a client flow, with visible trace). An
  optional script may resurface later if non-interactive CLI orchestration
  is needed, but it is not part of Phase 3 DoD.

### Phase 3 progress log

- **2026-05-19 §3.1 complete.** `samples/MockPersonServer/` ships with
  `aauth-person.json` + `jwks.json` + signed `POST /token`. Five unit tests
  in `tests/AAuth.Tests/Integration/MockPersonServerTests.cs` cover metadata
  shape, JWKS shape, happy-path token issuance, rejection of an
  auth-token-as-carrier, and missing-resource_token. Added to `AAuth.slnx`.
- **2026-05-19 Phase 2 follow-up cleared.** The private in-process mock PS
  inside `WhoAmIFlowTests.StartMockPsAsync` has been replaced with
  `WebApplicationFactory<MockPersonServer.Entry>` against the shipped
  sample. The integration tests now exercise shipped sample code; ~80 lines
  of test-only duplication and the temporary `TODO(Phase 3 §3.1)` marker
  are gone.
- **2026-05-19 Cross-sample `Program` ambiguity resolved.** Both `WhoAmI`
  and `MockPersonServer` now expose namespaced `Entry` marker types
  (`WhoAmI.Entry`, `MockPersonServer.Entry`) instead of `public partial
  class Program;` so a single test assembly can reference both samples
  without a CS0433 collision on the implicit `Program` type emitted by
  top-level statements.
- **2026-05-19 SDK observability hook added.** `AAuthSigningHandler` now
  exposes `Action<HttpRequestMessage, string>? OnSignatureBase { get; init; }`
  invoked with the canonical RFC 9421 signature base immediately before
  signing. Used by the Guided Tour to display the bytes that were signed.
  Covered by `AAuthSigningHandlerTests.OnSignatureBase_IsInvokedWithBytesActuallySigned`
  which round-trips: verifier reconstructs the captured base, recovers the
  emitted signature, and confirms it validates.
- **2026-05-19 §3.3 complete.** `samples/GuidedTour/` Blazor Server app
  ships at `http://localhost:5400`. Three-pane UI: step list (left),
  three-actor swim-lane sequence diagram (center), payload inspector
  (right). Eight steps walk the three-party autonomous flow against
  running `samples/WhoAmI` + `samples/MockPersonServer` instances; the
  tour collapses to a four-step identity-based path if
  `GuidedTour:PersonServerUrl` is empty. Each step captures request line,
  request/response headers, request/response body, RFC 9421 signature
  base (for signed requests), and decoded JWT header+payload (for steps
  that mint or receive a token). Smoke-tested: `GET /` returns 200 with
  the expected page title. Repo `README.md` updated to list the sample.
- **2026-05-19 §3.2 + §3.4 + deferred-mode tour complete.**
  `src/AAuth/Headers/AAuthInteraction.cs` parses + formats the
  `requirement=interaction; url; code` projection of `AAuth-Requirement`
  and produces the user-facing `{url}?code={code}` link.
  `src/AAuth/Agent/DeferredPoller.cs` polls a `Location` URL honoring
  `Retry-After` (delta or HTTP-date) against a bounded total budget.
  `TokenExchangeClient` gained a deferred-aware overload that surfaces
  `AAuthInteraction` to a caller-supplied callback and drives the poller
  to a terminal `auth_token`; `ChallengeHandler` accepts the same
  callback so the agent pipeline composes end-to-end. Eleven new SDK
  unit tests cover the parser and the poller. MockPS gained a consent
  store, an `AAuth-Requirement: requirement=interaction` 202 response,
  a signed `GET /pending/{id}` that flips to 200 once consent is
  recorded, and unsigned `POST /admin/consent` + `POST /admin/revoke` +
  `GET /interaction` demo endpoints; three integration tests cover the
  202→200 flip and the pre-consented happy path. The §3.4
  `ThreePartyUserConsentFlow_WaitsForApproval` integration test drives
  the full agent pipeline against a `RequireConsent=true` PS, using the
  `onInteractionRequired` callback to invoke `/admin/consent` and then
  letting the poller deliver the auth token. GuidedTour gained a
  `TourMode` setting (default `Deferred`), an 11-step deferred flow that
  pauses at step 9 behind an "Approve as user" button, and a
  `PrepareConsentStateAsync` hook that resets the PS's consent store on
  every session start. `make demo` now launches MockPS with
  `RequireConsent=true` so the deferred path is exercised
  out-of-the-box; `make ps-consent` shortcut added. **164 tests pass**
  (47 conformance + 117 unit/integration); Phase 3 DoD met.
- **2026-05-19 Phase 3 UX polish (post-DoD).** Iterative pass on the
  GuidedTour to make the deferred path tangible:
  - **Per-step descriptions + actor badges.** `TourPlanStep(Number,
    Title, Description, From, To)` replaces the bare title list;
    `StepList.razor` renders a two-line entry with an
    "Agent → Person Server"-style badge under each title.
  - **Denial / timeout end-to-end.** MockPS keeps denied pending
    entries and returns `403 access_denied` (instead of dropping them
    to 404); `POST /interaction/deny` records the denial. New typed
    `AAuthInteractionDeniedException` / `AAuthInteractionTimeoutException`
    in `src/AAuth/Agent/`; `TokenExchangeClient` translates the 403 +
    `error=access_denied` body and `TimeoutException` from
    `DeferredPoller` into these. Two new integration tests
    (`Pending_Returns403AccessDenied_AfterDeny`,
    `ThreePartyUserConsentFlow_ThrowsAAuthInteractionDenied_WhenUserDenies`)
    cover the path. GuidedTour exposes a "Simulate deny" button beside
    the consent link.
  - **Live polling spinner.** `TourSession` runs step 10's
    `DeferredPoller.PollAsync` on a background `Task.Run` driven by a
    `CancellationTokenSource`; `DeferredPoller.OnPoll` callback
    increments `PollCount` and raises a new `event Action?
    StateChanged` that `Tour.razor` re-renders via
    `InvokeAsync(StateHasChanged)`. A `.polling` status card shows
    spinner + `GET /pending/{id}` + live poll count + elapsed time.
    `RunNextAsync` awaits the in-flight task to avoid double-polling.
  - **Mermaid-style `loop […]` notation in the sequence diagram.**
    `SequenceDiagram.razor` gained `LoopAroundStepNumber`,
    `CompletedLoopLabel`, `LoopCompletedKind`, `IsPolling`,
    `PollCount`, and `LoopGhostStep` parameters. While polling, a
    dashed accent-blue `.seq-loop.active` box surrounds a pulsing
    ghost row (`Agent → Person Server`) with a tab label
    `loop [polling pending URL] · N polls`. When step 10 resolves, the
    box turns solid and colour-codes by terminal state:
    `.seq-loop.completed.ok` (green ✓ resolved),
    `.seq-loop.completed.denied` (red ✖ denied),
    `.seq-loop.completed.timeout` (muted ⏱ timed out).
  - **168 tests pass** (47 conformance + 121 unit/integration).

### 3.1 MockPersonServer

Issues `aa-auth+jwt` against `resource_token` POSTs. Also serves the
PS-side well-known + JWKS used by `WhoAmI`'s resource-token `aud` and the
agent's discovery during exchange.

| File | Responsibility |
|---|---|
| `samples/MockPersonServer/Program.cs` | Minimal API. Serves `/.well-known/aauth-person.json` and `/.well-known/jwks.json`. `POST /token` accepts a signed request whose `Signature-Key` carries the agent token, validates the posted `resource_token`, and returns an `aa-auth+jwt` bound to the same agent key (`cnf.jwk` from the agent token). |
| `samples/MockPersonServer/MockPersonServer.csproj` | Web project. Net 10. References `src/AAuth/AAuth.csproj`. |
| `samples/MockPersonServer/appsettings.json` | Issuer URL, signing key id, default scope. |
| `samples/MockPersonServer/README.md` | Run instructions. |

**Phase 2 follow-up cleared in the same PR**: migrate
`tests/AAuth.Tests/Integration/WhoAmIFlowTests.StartMockPsAsync` from its
private in-process duplicate to the shipped sample (via
`WebApplicationFactory<MockPersonServer.Program>` or, if that introduces a
project-reference loop, a thin `IMockPersonServerHost` interface implemented
by the sample and consumed by the test).

### 3.2 Deferred polling (agent side)

Required for the user-consent integration test (§3.4) where PS returns 202
with interaction details.

| File | Responsibility |
|---|---|
| `src/AAuth/Agent/DeferredPoller.cs` | Poll `Location` URL on 202, respect `Retry-After`, return terminal response. Bounded total wait + cancellation token. |
| `src/AAuth/Headers/AAuthInteraction.cs` | Parse interaction requirements (`url`, `code`) from `AAuth-Requirement`. Sits beside `AAuthRequirementHeader` from Phase 2; the requirement header parser already exists, this only adds the interaction-specific projection. |

Add unit tests in `tests/AAuth.Tests/Agent/DeferredPollerTests.cs` and
`tests/AAuth.Tests/Headers/AAuthInteractionTests.cs`.

### 3.3 Guided Tour (Blazor Server)

A `samples/GuidedTour/` Blazor Server app that drives the same SDK pipeline
as `samples/AgentConsole/` but exposes each stage as a discrete UI step. The
user clicks "Next" (or "Send"), the app performs one hop of the protocol,
and the UI highlights the party that just acted in a sequence-diagram view
while showing the raw request/response payloads alongside human-readable
explanations.

#### 3.3.1 Project scaffolding

| Action | Detail |
|---|---|
| Create `samples/GuidedTour/GuidedTour.csproj` | Blazor Server, `net10.0`, references `src/AAuth/AAuth.csproj` |
| Create `samples/GuidedTour/Program.cs` | Standard Blazor Server bootstrap; register `TourSession` as scoped, `TourOptions` (URLs for WhoAmI + MockPS) from config |
| Add to `AAuth.slnx` | Slot under `samples/` |

#### 3.3.2 Tour orchestration service

| File | Responsibility |
|---|---|
| `samples/GuidedTour/Services/TourSession.cs` | Scoped service. Owns the agent key, agent token, `AAuthTokenHolder`, the configured `HttpClient` pipeline, and the ordered list of steps. Exposes `AdvanceAsync()` which runs the next protocol action and records what happened. |
| `samples/GuidedTour/Services/StepRecord.cs` | Record type capturing: step name, party acting, narrative blurb, request method + URL + headers + body, response status + headers + body, decoded JWT payloads (header + claims) for any tokens involved, raw signature base if applicable. |
| `samples/GuidedTour/Services/TourOptions.cs` | Configured URLs (`WhoAmIUrl`, `MockPersonServerUrl`), default agent metadata (`iss`, `sub`, `kid`). |
| `samples/GuidedTour/Services/CapturingSigningHandler.cs` | `DelegatingHandler` that wraps `AAuthSigningHandler` (or sits beside it) to capture the outbound request *after signing* and the inbound response, surfacing them to `TourSession` for display. Reads the signature base from a hook on the SDK (see §3.3.6). |

#### 3.3.3 Tour steps

Each step is a discrete `AdvanceAsync` call producing one `StepRecord`. The
exact list is finalized during implementation, but the planned spine is:

| # | Step | Party acting | Shows |
|---|---|---|---|
| 1 | Generate / load Ed25519 key | Agent (local) | Public JWK, JWK thumbprint |
| 2 | Build agent token | Agent (local) | JWT header, decoded claims (`iss`, `sub`, `cnf.jwk`, `iat`, `exp`, `dwk`, `ps`), encoded JWT |
| 3 | Discover resource well-known | Agent → WhoAmI | `GET /.well-known/aauth-resource.json`, response JSON |
| 4 | Send signed `GET /` | Agent → WhoAmI | Signature base, `Signature-Input`, `Signature`, `Signature-Key` headers, body |
| 5 | Receive 401 + `AAuth-Requirement` | WhoAmI → Agent | Status, `AAuth-Requirement` parsed parameters, decoded `resource_token` claims |
| 6 | Discover PS well-known | Agent → MockPS | `GET /.well-known/aauth-person.json`, JSON |
| 7 | Exchange resource_token at PS | Agent → MockPS | Signed `POST /token`, request body, decoded `auth_token` from response |
| 8 | Retry signed `GET /` with auth_token | Agent → WhoAmI | New `Signature-Key` carrying auth_token, 200 response, identity claims body |

Identity-based mode (`MockPersonServerUrl` not configured) collapses 5–7 and
ends at step 4 with a 200 response.

#### 3.3.4 UI components

| File | Responsibility |
|---|---|
| `samples/GuidedTour/Components/App.razor` | Root component, layout, SignalR-backed Blazor Server pipeline |
| `samples/GuidedTour/Components/Pages/Tour.razor` | The single page hosting the tour. Three panes: sequence diagram (left), step list + "Next" button (center), payload inspector (right). |
| `samples/GuidedTour/Components/SequenceDiagram.razor` | Renders Agent / WhoAmI / MockPS as lanes; draws arrows for each completed step; highlights the most recent hop. Pure SVG, no JS library required for v1. |
| `samples/GuidedTour/Components/PayloadInspector.razor` | Tabbed view: **Request** / **Response** / **Signature base** / **Decoded tokens**. Pretty-prints JSON; uses `<pre>` for raw bytes. |
| `samples/GuidedTour/Components/StepList.razor` | Ordered list of step names; the active step is highlighted; completed steps are clickable to re-inspect their `StepRecord`. |
| `samples/GuidedTour/Components/TokenView.razor` | Three-line view of any JWT: header, claims, signature; "encoded" toggle for the raw compact form. |

#### 3.3.5 Wiring & configuration

| File | Responsibility |
|---|---|
| `samples/GuidedTour/appsettings.json` | `Tour:WhoAmIUrl`, `Tour:MockPersonServerUrl`, `Tour:Agent:Issuer`, `Tour:Agent:Subject`, `Tour:Agent:KeyId` |
| `samples/GuidedTour/Properties/launchSettings.json` | Single profile on `http://localhost:5400` |
| `samples/GuidedTour/README.md` | One-screen quickstart: "in three terminals run WhoAmI, MockPS, GuidedTour, then open <http://localhost:5400>". |

#### 3.3.6 SDK hook (if needed)

The SDK currently does not expose the signature base string it computes. The
tour wants to display it. If inspection of `src/AAuth/HttpSig/` confirms the
base is built inside `AAuthSigningHandler` and not surfaced, add a minimal
hook (e.g. `Action<string>? OnSignatureBase { get; init; }` on the handler)
**with an accompanying xUnit test** in `tests/AAuth.Tests/HttpSig/`. No
behavioral change — purely additive observability.

#### 3.3.7 Tests

| File | Coverage |
|---|---|
| `tests/AAuth.Tests/GuidedTour/TourSessionTests.cs` | Unit-test `TourSession.AdvanceAsync` against an `HttpMessageHandler` mock for each step transition. Asserts `StepRecord` is populated with the expected headers / decoded tokens. |
| `tests/AAuth.Tests/HttpSig/AAuthSigningHandlerObservabilityTests.cs` | If §3.3.6 lands: assert the signature-base hook fires with the expected canonical string. |

No Blazor-component rendering tests in this phase — the value is in the
underlying session model. Add `bunit` later if regressions appear.

### 3.4 Integration tests (all three flows)

| Test | Flow |
|---|---|
| `IdentityBasedFlowTest` | Agent → Resource (no `ps` claim, resource trusts identity) → 200 |
| `ThreePartyAutonomousFlowTest` | Agent → Resource (401) → PS (auto) → Resource (200), using the shipped `MockPersonServer` sample |
| `ThreePartyUserConsentFlowTest` | Agent → Resource (401) → PS (202 + interaction) → poll → PS (200) → Resource (200), exercising `DeferredPoller` from §3.2 |

The three-party tests replace the private in-process mock PS used by
Phase 2's `WhoAmIFlowTests` with the shipped `samples/MockPersonServer/`
binary (or its `WebApplicationFactory`).

### Phase 3 Definition of Done

- [x] `samples/MockPersonServer/` builds, runs, issues `aa-auth+jwt`, and has unit tests for token issuance + well-known shape
- [x] `DeferredPoller` + `AAuthInteraction` parser ship with unit tests
- [x] `dotnet run --project samples/GuidedTour` serves the tour on `http://localhost:5400`
- [x] Against running `samples/WhoAmI` + `samples/MockPersonServer`, the tour walks the full three-party flow with payloads visible at every step
- [x] Without `MockPersonServer` configured, the tour walks the identity-based flow (steps 1–4) and ends at 200
- [x] All three integration tests in §3.4 pass against the shipped `MockPersonServer`
- [x] Phase 2's `WhoAmIFlowTests` private mock PS is removed in favour of the shipped binary
- [x] `README.md` (root) updates: lists the new `MockPersonServer` and `GuidedTour` samples, and a quickstart for running the full three-party demo

---

## Phase 4: CLI Tool + Key Bootstrap

**Goal**: A `dotnet aauth` global tool for key management and making authenticated requests.

### 4.1 CLI project

| File | Responsibility |
|---|---|
| `tools/AAuth.Cli/AAuth.Cli.csproj` | `dotnet tool` with `System.CommandLine` |
| `tools/AAuth.Cli/Program.cs` | Root command dispatcher |
| `tools/AAuth.Cli/Commands/GenerateCommand.cs` | `aauth generate [--algorithm ed25519|es256]` → creates key, saves to `~/.aauth/` |
| `tools/AAuth.Cli/Commands/PublicKeyCommand.cs` | `aauth public-key` → outputs JWK to stdout |
| `tools/AAuth.Cli/Commands/SignTokenCommand.cs` | `aauth sign-token --iss <url> --sub <id>` → outputs agent token JWT |
| `tools/AAuth.Cli/Commands/FetchCommand.cs` | `aauth fetch <url> [--scope ...]` → makes signed request, handles challenge, prints response |
| `tools/AAuth.Cli/Commands/ConfigCommand.cs` | `aauth config` → shows `~/.aauth/config.json` |

### 4.2 Config model

| File | Responsibility |
|---|---|
| `src/AAuth/Keys/AAuthConfig.cs` | Serialize/deserialize `~/.aauth/config.json` matching the TypeScript SDK format |

### Phase 4 Definition of Done

- [ ] `dotnet tool install` works
- [ ] `aauth generate` + `aauth sign-token` + `aauth fetch https://whoami-server/` works end-to-end
- [ ] Config file compatible with packages-js format
- [ ] `README.md` documents the `dotnet aauth` CLI commands with examples

---

## Phase 5: Full Multi-Agent Demo (aauth-full-demo port)

**Goal**: Multi-agent orchestration in .NET showing the same flows as the Python aauth-full-demo, reusing Agentgateway + AAuth Service + Person Server as Go binaries.

### 5.1 Backend API

| Project | Responsibility |
|---|---|
| `samples/FullDemo/BackendApi/` | ASP.NET Core Web API: starts optimization, calls agents via signed HTTP, polls progress |

### 5.2 Supply Chain Agent

| Project | Responsibility |
|---|---|
| `samples/FullDemo/SupplyChainAgent/` | ASP.NET Core service: receives signed requests, applies business logic, calls Market Analysis agent (signed) |

### 5.3 Market Analysis Agent

| Project | Responsibility |
|---|---|
| `samples/FullDemo/MarketAnalysisAgent/` | ASP.NET Core service: receives signed requests, returns market data |

### 5.4 Docker Compose / scripts

| File | Responsibility |
|---|---|
| `samples/FullDemo/docker-compose.yml` | Orchestrate: .NET services + Agentgateway + AAuth Service + Person Server |
| `samples/FullDemo/agentgateway/` | Config files (copied/adapted from aauth-full-demo) |

### 5.5 Integration tests

| Test | Coverage |
|---|---|
| `Mode1FlowTest` | Identity-based: agent → gateway → resource → 200 |
| `Mode3FlowTest` | PS-asserted: agent → gateway → 401 → PS → retry → 200 |
| `UserConsentFlowTest` | Agent → gateway → 401 → PS (interaction) → poll → 200 |
| `PolicyEnforcementTest` | CEL rule blocks unauthorized agent/scope |

### Phase 5 Definition of Done

- [ ] `docker compose up` brings up all components
- [ ] Can run through identity-based, PS-asserted, and user-consent flows
- [ ] Integration tests pass against running stack
- [ ] `README.md` describes the full-demo topology and `docker compose` quickstart

---

## Out of Scope (defer to later)

| Item | Reason |
|---|---|
| Hardware keys (YubiKey) | Nice-to-have, not needed for demo |
| R3 operations | Advanced feature, not core flow |
| Mission system | Governance layer, not core auth |
| MCP transports (stdio, OpenClaw) | Separate concern from auth flows |
| Production packaging (multi-NuGet) | Premature for demo-stage SDK |
| OS credential store integration | File-based keys sufficient for demos |
| Four-party federated flow | Three-party covers the key demo scenario |

---

## Dependency Graph

```
Phase 1 (Core + Agent)
    │
    ▼
Phase 2 (Resource Server + 3-Party)
    │
    ├──────────────────┐
    ▼                  ▼
Phase 3 (E2E Demo + Tour)   Phase 4 (CLI)
    │
    ▼
Phase 5 (Full Multi-Agent Demo)
```

Phases 3 and 4 are independent of each other — can be done in parallel or in either order. Phase 3 ships `MockPersonServer`, `DeferredPoller`, the Blazor Guided Tour, and the three-flow integration tests together; the tour and the integration tests both depend on `MockPersonServer` (§3.1).

---

## Estimated File Count per Phase

| Phase | New files | Cumulative |
|---|---|---|
| 1 | ~12 (lib + sample + tests + sln) | 12 |
| 2 | ~12 (server middleware + sample + tests) | 24 |
| 3 | ~20 (mock PS + deferred poller + Blazor tour + integration tests) | 44 |
| 4 | ~8 (CLI commands + config) | 52 |
| 5 | ~15 (3 services + docker + gateway config + tests) | 67 |

---

## Key Decisions Made

1. **Single `AAuth` library** — no package splitting until the API stabilizes.
2. **NSign for RFC 9421** — don't reimplement; wrap with AAuth specifics.
3. **Mock Person Server in .NET** — enables fully self-contained demo without Go binary dependency.
4. **File-based key storage** — simple, cross-platform, compatible with packages-js config format.
5. **Ed25519 only (initially)** — the spec MUST algorithm. Add ES256 in Phase 5 if needed.
6. **Go binaries for gateway/PS in full demo** — proven infrastructure; .NET port is out of scope.
