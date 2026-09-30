---
description: Fix designs for the draft-11 compliance audit findings, aligned with the SDK API surface consistency conventions.
---

# Research — draft-11 compliance remediation

Input: the audit in
[2026-09-30-v11-compliance-audit](../2026-09-30-v11-compliance-audit/research.md),
which has confirmed findings `SDK-nn`, `SMP-nn`, `DOC-nn` and MEDIUM/LOW source
IDs, and its
[remediation backlog](../2026-09-30-v11-compliance-audit/remediation-backlog.md).
Constraints come from the completed
[2026-09-29-sdk-api-surface-consistency](../2026-09-29-sdk-api-surface-consistency/implementation-plan.md)
initiative (83/83 DoD ticked). Baseline commit `30b8015`. Spec:
[aauth-spec/v11](../../../aauth-spec/v11/).

This file holds research only. Phases and tasks are in
[implementation-plan.md](implementation-plan.md), and rulings are in
[implementation-log.md](implementation-log.md).

## Method

1. Group the audit findings by **fix locality**, so one design touches one
   coherent set of files. The resulting design areas R01–R19 are listed below.
2. Dispatch one read-only design subagent per area. Each agent:
   - re-reads its findings, the spec lines and the current code;
   - proposes 2–3 candidate fixes and recommends one;
   - specifies the public API delta, wire effect, tests (positive plus
     negative controls), and sample/doc updates;
   - lists conflicts with the API-surface conventions and open questions.

   Output goes to `designs/Rnn-<slug>.md`.
3. Run an adversarial red-team pass: one agent per group of 4–5 designs. It
   attacks each recommended fix for spec non-conformance, security regressions,
   API-surface violations and cross-design conflicts. It writes
   `designs/RT-<n>.md`.
4. The orchestrator re-verifies the highest-stakes claims directly: every
   CRITICAL/HIGH fix, every public API removal, and every wire change. The
   rulings are collated below and the open questions are seeded in the log.

## Design constraints (from the API-surface initiative)

Every design MUST conform to these. Citations are to
[the API-surface plan](../2026-09-29-sdk-api-surface-consistency/implementation-plan.md)
("ASP") and [its log](../2026-09-29-sdk-api-surface-consistency/implementation-log.md)
("ASL").

- **C1 No compat.** Every change is a single cutover: no `[Obsolete]`, no
  dual overloads, no shims. Deliberate spec exceptions are logged (ASP L33-L40).
- **C2 Layered 80/20.** Primitives → options-driven middleware and handlers
  → one-call `Add*` + `Map*`/`Use*`. Every high-level call is expressible via
  primitives. Every default is replaceable via DI (ASP L41-L54).
- **C3 One options model.** `IOptions<T>` or named options, `TimeProvider`,
  sync shape validation at start, async failures at first use. Identity is
  read once at composition, with no hot reload (ASP L55-L61).
- **C4 R0 extensibility ladder.** Each decision point accepts data, a
  delegate or a DI service, normalized into one internal seam. Precedence:
  1. per-request or per-endpoint override;
  2. an explicit instance or delegate;
  3. DI keyed by instance name, then unkeyed (the SDK does the fallback);
  4. the default built from data.

  Seam contexts carry `IServiceProvider` (ASP L62-L82; ASL L45-L58). Seam
  defaults are keyed forwarding factories (ASL L1050-L1055).
- **C5 Identity once per role.** Issuer, key and kid are declared once, and
  everything else is derived from them. This includes the resource
  identifier used for `aud` checks (ASP L83-L85).
- **C6 SDK owns mechanics, consumers own policy.** Spec-mandated bookkeeping
  such as entitlement, revocation fan-out and single-use enforcement lives in
  the SDK. Consent, policy and account selection stay with the consumer
  (ASP L86-L88).
- **C7 No string indirection.** Protocol values are `const string` in
  `AAuthConstants` for open sets (ASL L128-L133).
- **C8 No consumer HTTP plumbing.** Samples register no `AddHttpClient()` and
  build no signed clients by hand (ASP L90-L91).
- **C9 Trust is async and context-rich.** Trust goes through
  `IAAuthTrustPolicy.IsTrustedAsync(AAuthTrustContext)`. Its default comes
  from `AAuthTrustOptions`: `null` means open with a warning, and
  `AAuthTrust.Any` is available. Per-endpoint override is
  `.RequireAAuth(trust:)` (ASL L120-L126).
- **C10 Single-use and held invocations.** `IAAuthSingleUseGate` claims,
  completes and returns results by `jti`, and `IAAuthHeldInvocationStore`
  holds pending entries. Both are serializable (ASL L99-L104).
- **C11 Revocation.** One cascade engine (`RevokeTokenAsync`, public
  `CascadeAsync`) serves inbound endpoints and app code (ASL L106-L111,
  L1030-L1036).
- **C12 Named role instances.** PS and AS roles support named instances. The
  resource role stays single-instance, with an eager options instance exposed
  as `IOptions<AAuthResourceOptions>` (ASL L92-L97, L1057-L1063). In-memory
  defaults warn outside Development.
- **C13 Gates.** Every phase runs the ASP verification gates (ASP L93-L109):
  - build;
  - four test projects;
  - the `ApiSurface --write` diff;
  - docs-inventory, snippet and link tests;
  - Playwright e2e;
  - Keycloak for high-blast-radius phases.

Prior deliberate decisions that an audit finding now contradicts are flagged
for re-ruling, not silently reversed:

- ASL L933-L939 (*signatures take a unique created per target*) is the
  origin of SDK-16.
- ASL L954-L959 (*scope step-up answers 403*) is related to A20-003 and to the
  missing step-up for auth tokens.

## Design area map

Audit IDs refer to the
[audit research](../2026-09-30-v11-compliance-audit/research.md). Severity is the
final audit grade.

| ID | Area | Findings | Primary code |
|---|---|---|---|
| R01 | Resource audience binding | SDK-01 (CRIT), A09-MED-001; DOC-03 | `DependencyInjection/AAuthApplicationBuilderExtensions.cs`, `Server/Verification/*` |
| R02 | Four-party trust and AS-issued tokens | SDK-02, A17-002; D09-01, D10-05 | `Server/Endpoints/AAuthEndpointExtensions.cs`, `Server/AAuthTrust*.cs`, `Tokens/AuthTokenResponseValidator.cs` |
| R03 | Authorization endpoint and access-mode gating | SDK-08, SDK-18, A07-001/A09-MED-002, A09-HIGH-003, A08-03, A03-HIGH-002; SMP-04, DOC-04 | `AAuthApplicationBuilderExtensions.MapAAuthAuthorizationEndpoint`, `Server/Challenge/*`, `Server/Verification/AAuthAccessMode.cs` |
| R04 | R3 single use, audit and entitlement | SDK-03, SDK-19, A23-003, A23-004, A22-MED-001; DOC-06 | `src/AAuth.R3/*`, `Server/HeldInvocations.cs` |
| R05 | Upstream provenance and interaction chaining | SDK-04, A18-003; SMP-03, DOC-05, D07-02 | `Tokens/UpstreamTokenValidator.cs`, `Person/*`, `Agent/AAuthInteractionExceptions.cs`, `Server/CallChaining/*` |
| R06 | Revocation ordering and pending dependencies | SDK-05, A20-002, A20-003 (+ ASL L954 step-up) | `Person/AAuthPersonServerEndpoints.cs` federation path, `Server/Revocation*`, `Server/Verification/*` |
| R07 | Federation (collapse, 402, dwk pinning) | A17-001, A17-003/A19-HIGH-005, S04-01; D06-02 | `Access/*`, `Person/AAuthPersonServerEndpoints.cs` |
| R08 | Clarification, `updated_request` and PS input validation | SDK-06, A12-02, A12-03, A12-04, A13-02, A13-03 | PS clarification paths, `Agent/ClarificationExchange.cs`, `Agent/DeferredExchange.cs` |
| R09 | Missions | SDK-14, A16-001, A16-003, A16-004; D04-002, D05-02, D08-05, D10-03 | `Server/Governance/IMission*`, PS pending paths |
| R10 | Agent–person binding and person-token defaults | SDK-07, A11-03, A11-04, A15-002; SMP-01 | `Person/AgentPersonBinding.cs`, `Person/IIdentityClaimsAsserter.cs`, `/person` handler |
| R11 | Deferred polling and error codes | SDK-11, SDK-12, SDK-13, A19-HIGH-003, A19-HIGH-004, A14-MED-004; S08-02, S08-03, S09-01, S05-002, D07-05 | `Agent/ChallengeHandler.cs`, `Agent/DeferredPoller.cs`, `Server/DeferredState.cs`, `Server/HeldInvocations.cs`, `Errors/*` |
| R12 | Governance endpoints | SDK-09, SDK-10, A15-004, A15-005; SMP-02, DOC-07, D05-01, D05-03 | `Server/Governance/*`, PS metadata, `AAuthGovernance*Extensions.cs` |
| R13 | HTTP-signature producer | SDK-16, A02-HIGH-002, A01-M01, A04-04 | `HttpSig/AAuthSigningHandler.cs`, `Discovery/ServerMetadata.cs`, `Server/InMemoryJtiStore.cs` |
| R14 | JWT and verification hygiene | SDK-17, A01-H01, A01-M02, A03-HIGH-001, A19-HIGH-001, A21-TLS-01 | `Tokens/TokenVerifier.cs`, `HttpSig/DefaultSignatureKeyResolver.cs`, `Server/Challenge/*`, `Discovery/AAuthHttpTransport.cs` |
| R15 | Agent client behaviour | SDK-15, A08-02/A13-01, A10-01, A06-02, A05-02/A06-03, A13-04/A07-004, A07-003, A07-005, A07-007 | `AAuthClientBuilder.cs`, `Agent/*` |
| R16 | Metadata and identifier validation | A04-01, A04-02, A04-05, A04-06, A07-002, A04-03 | `Identifiers/*`, `Server/Metadata/*`, `Discovery/*` |
| R17 | Events | A24-01, A24-02, A24-03; S06-01 | `src/AAuth.Events/*`, `samples/EventSupport/SqliteEventStore.cs` |
| R18 | Samples-only fixes | SMP-01, S07-01, S08-01, S03-02, S03-03, S04-01, S05-002, sample LOWs | `samples/*` |
| R19 | Docs rewrite inventory | DOC-01, DOC-02, D02-02, D01-01/D02-03/D10-06, remaining doc MEDIUMs | `docs/*`, READMEs, `aauth-spec/SPEC-VERSION.md` |

## Design template

```markdown
# Rnn — <area>

Findings: <ids>. Spec: <anchors + lines>. Files read: <list>.

## Problem restated (verified)
## Candidate fixes
| # | Approach | Pros | Cons | Spec fit | API-surface fit (C1–C13) |
## Recommendation
## Public API delta
<added / changed / removed members; ApiSurface impact>
## Wire effect
<status codes, headers, claims, bodies that change on the wire>
## Implementation sketch
<files and methods, ordered steps>
## Tests
<positive + negative controls; which project; the adversarial case from the audit>
## Samples and docs to update
## Dependencies and conflicts with other Rnn
## Open questions (with proposed default)
```

## Designs (collated)

Nineteen design agents produced [designs/R01–R19](designs/). Five red-team
agents reviewed them: RT-1 covered resource verification, RT-2 PS/AS/R3, RT-3
pending state and governance, RT-4 agent/signing/metadata/events, and RT-5
cross-design synthesis, samples and docs.

| Red-team verdict | Count |
|---|---|
| SOUND | 35 |
| SOUND-WITH-CHANGES | 23 |
| UNSOUND | 2 |

The two UNSOUND verdicts were R11 SDK-11 (the poll refactor dropped deferred
re-exchange) and R16 A04-05 (strict identifiers had no dev/e2e path). Both are
resolved by rulings below. Each red-team required change is folded into the
ruling it touches; the full rulings are Q1–Q32 in
[implementation-log.md](implementation-log.md).

### Orchestrator re-verification

These claims were checked directly against spec and code before the rulings
were recorded:

- **R01**
  - `AAuthOptionsResolver.Create` applies `IConfigureOptions` and
    `IPostConfigureOptions` before the per-pipeline delegate
    (`src/AAuth/AAuthOptionsResolver.cs:16-22`). Post-configuring
    `ResourceIdentifier` from `AddAAuthResource` is therefore overridable, as
    the design claims.
  - `UseAAuth` already sets the identifier
    (`src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs:225-231`).
- **R13 / Q1**
  - Spec: the replay cache is a verifier MAY, keyed on the tuple
    `(thumbprint, created, @method, @authority, @path)`, and the profile
    defines no nonce (#freshness-and-replay, L2270-L2272). `created` MUST be
    the current time (L2234).
  - The SDK verifier keys replays on thumbprint plus SHA-256 of the whole
    signature base (`src/AAuth/HttpSig/AAuthVerifier.cs:112`). That is looser
    than the tuple, because `content-digest` differs per body, but identical
    GETs, including ones differing only in query, still collide.
- **Q3**
  - Signature-Key §5.4.7 defines `invalid_key` as a key that "does not meet
    the server's trust requirements" (`draft-hardt-httpbis-signature-key-09.txt`
    L2044-L2048). An untrusted issuer is therefore a 401 `invalid_key`.
  - §5.3's 403 (L1936-L1944) is for denial after identity is accepted.
  - This overrides R03's `403 access_denied` and R11's `issuer_mismatch`.
- **R06 / Q8.** Step-up with a new resource token on a request that already
  carries an auth token is a resource MAY, and agents MUST handle it
  (#requirement-auth-token, L640).
- **R15 / Q18.** `EnrolledBuilder` already rejects `TwoKey`
  (`src/AAuth/EnrolledBuilder.cs:165-167`), so removing automatic two-key
  refresh from `AgentProviderTokenRefresher` leaves no supported path broken.

### Per-design summary

| ID | Recommended fix (headline) | Public API delta | Wire effect | Red-team outcome → ruling |
|---|---|---|---|---|
| R01 | Post-configure `AAuthVerificationOptions.ResourceIdentifier` from `AddAAuthResource.Issuer`. Delete the token-`aud` fallback. Auth/person JWTs fail closed without an identifier. | Semantics only | Cross-resource tokens → 401 `invalid_jwt`; missing identifier → 401 `invalid_request` | SOUND |
| R02 | `AAuthResourceOptions.AccessServer` declares four-party. It derives AS-only auth-token trust plus `dwk=aauth-access.json`. Three-party pins `aauth-person.json`. AS responses at the PS are pinned to access metadata. | Add `AccessServer`, `ExpectedAuthTokenDwk`, `AAuthTrustContext.TokenDwk` | PS-issued tokens rejected at four-party resources | SWC: pin the three-party dwk → Q4 |
| R03 | New `PersonTokenRequired` gate on the authorization endpoint. Typed request with an extension seam for R3 (no core→R3 dependency). `AgentTokenRequired` accepts only agent tokens. Helper rejects agent assertions. Content type → 400. | Access mode, request shape, extension seam, response helpers | `requirement=person-token` challenges; 400 | SOUND; trust-denial status overridden → Q3 |
| R04 | `R3Enforcement` returns an execute-once `SingleUse` handle over `IAAuthSingleUseGate`. Per-token expiring document entitlement for AS and PS. Authoritative operation validation before minting. Audit record gains `ps`/`sub`/`agent_jkt`. | `R3Enforcement` result, audit record, entitlements | Replays answered from the retained result | SWC: key = (iss, jti), shared with the 202 held path → Q6 |
| R05 | Provenance-aware inventory (`IJtiStore` extension). PS upstream step-4 primitive that fails closed. Call-chaining interaction module so intermediaries mint their own code and `Location`. | `IJtiStore` members, provenance record, chaining module; interaction-chaining exception reshaped | Missing provenance → `invalid_upstream_token` | SWC: retention and quotas, atomic writes → Q5 |
| R06 | Source guard: "check sources, then act" before every outbound presentation or mint. Pending revocation → `revoked` + detail. Revoked auth token adds `requirement=person-token`. Scope step-up → 401 auth-token. | Typed source dependencies (`SourceTokens` break) | Step-up 401 replaces 403 on `RequireAAuth(scope:)` | SWC: guarded outbound primitive → Q7, Q8 |
| R07 | Explicit PS-AS collapse declaration with internal AS policy evaluation and `dwk=aauth-access.json`. Payment-settler seam with a 402 loop. Enforce the claims `sub` rule. | Co-host builder, collapse policy, `IAAuthPaymentSettler`, payment decision shape | Collapse `dwk` changes; 402 `Location` polled | SWC: exact declaration fails closed; narrow settler plus billing cache → Q17 |
| R08 | One `ApplyUpdatedRequestAsync` recomputes bounds and sources from the replacement pair. Shared platform/device/capabilities validator. Central round counter. Agent `timeout` deadline. | Capability constants move to `AAuthConstants` | Malformed inputs → 400 | SWC: bounds may grow → Q11, Q12 |
| R09 | One mission status evaluator (state + `expires_at` + reason). Store keyed by `(PS, s256)`. `TerminateAsync(reason)` replaces `SetStateAsync`. Uniform `mission_not_found`. | `IMissionStore` break | `termination_reason` populated | SWC: equivalence contract tests → Q13 |
| R10 | `AAuthPersonKey` plus `IAgentPersonBindingStore` (atomic bind-or-verify). HMAC pairwise-`sub` deriver. First-issuance enrollment. Governance `ps` check. | New seam types; `IdentityAssertion.PersonKey` | Conflicting person → deny | SWC: atomic mint, key ring, `ps` scope → Q14, Q15 |
| R11 | Internal poll core shared by `DeferredPoller` and `ChallengeHandler`. Closed-table problem helpers. Unknown pending id → 410 `invalid_code`. No invented codes. | Error enums trimmed | Status/code corrections | **UNSOUND** (re-exchange) → Q9, Q10; untrusted → Q3 |
| R12 | `.WithGovernance()` declares paths once, and `MapAAuthPersonServer` auto-maps. Relay states limited to `Pending`/`Unavailable` (202/424). Strict JSON objects. Audit carries `parameters`/`result`. | Governance options renamed (`InteractionEndpointPath`) | 424/202 replace 200 | SWC: exclusive states, conflict guard, question with no channel → Q16 |
| R13 | Never future-date `created`; wait for the next free second. Fail closed on a body without Content-Type. Label consistency. Typed `additional_signature_components` seeds the first request. | Additive metadata members | No future `created` | SWC: throughput ruling → Q1; typed field wins → Q26 |
| R14 | Reject unsupported `crit`. Companion key-resolution seam. Zero `exp` skew. Remove `ChallengeOptions.AllowedSignatureKeySchemes`. Central `Signature-Error` writer. Pin TLS 1.2/1.3. | `ISignatureTokenVerifier` contract; option removed | Stricter JWT failures; correct 401 headers | SOUND → Q22–Q24 |
| R15 | Remove automatic two-key refresh. Pass `login_hint` through. Verify auth-token signature and `typ` by default. Five-minute carrier margin. 24 h producer cap. PS-first relay. Strict `AAuth-Access`. Capability union and SF serializer. | Remove the `TwoKey` refresher path; exchange verification options | `login_hint`; PS relay POSTs | SWC → Q18–Q21 |
| R16 | Shared `UrlKind` validator for producers and consumers. Strict `AgentId` structure. AP `event_endpoint`/`localhost_callback_allowed`. Fragments rejected. | Two AP metadata options | Invalid metadata rejected | **UNSOUND** (A04-05 dev path) → Q2; Events bridge → Q26 |
| R17 | Typed store outcome enum mapped to status by the SDK. Body components required only when a body is present. Optional subscription body. | Store contract break | 404 on exhaustion; bodyless delivery accepted | SOUND → Q27 |
| R18 | Sample-only fixes: SMP-01 exact identity, tour signing-mode labelling, same-origin pending, revocation surfaces, Keycloak `sub` filtering, Concierge pending shape, LOW prose and redaction. | None | Sample wire corrections | S09-02 gap assigned → Q30 |
| R19 | Doc change inventory; `getting-started.md` restructured to the draft-11 flow; pessimistic README/SPEC-VERSION correction first. | N/A | N/A | Claim-restoration ordering → Q28 |

### Cross-design constraints (from RT-5)

- Several designs edit the same files, so each group lands in one phase:
  - `AAuthPersonServerEndpoints.cs`: R05, R06, R07, R08, R09, R10, R12.
  - `ChallengeHandler.cs`: R11, R13, R14, R15, R16.
  - Verification middleware and composition: R01, R02, R03, R06, R14.
- One inventory model (Q5) serves provenance (R05), source dependencies
  (R06), bindings (R10) and retained results (R04/R11).
- Dependency order:
  1. R01 before R02 and R03.
  2. R14 verifier seam before R02, R15 and R17 consume it.
  3. R11 poll core before R04, R15 and the samples.
  4. R09 and R10 before R12, and R12 before R15's PS-first relay.
  5. R06 guard wraps R07's final federation send.
  6. R13's field together with R16's reserved-field validator.
- Samples (R18) and docs (R19) trail. The exceptions are the narrow SMP-01
  patch and the pessimistic conformance-claim correction, which land first.
