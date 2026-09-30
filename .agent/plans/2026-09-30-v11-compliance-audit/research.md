---
description: Adversarial draft-11 compliance audit of the SDK, then samples, then docs — method, area map and collated findings.
---

# Research — AAuth draft-11 compliance audit

Baseline commit: `30b8015e532c662c64b927fb0f85040d36afaeb7` (2026-09-30).
Spec baseline: vendored [`aauth-spec/v11/`](../../../aauth-spec/v11/) — the
protocol draft-11, Signature Keys draft-09, R3 and Events editor's copies at
the draft-11 tag. Bootstrap draft-02 is informational; Budgets is not
implemented (see [SPEC-VERSION.md](../../../aauth-spec/SPEC-VERSION.md)).

This is an **audit**, not a migration. The previous initiative
([2026-09-11-aauth-v11-spec-migration](../2026-09-11-aauth-v11-spec-migration/))
moved the SDK to draft-11 and kept a
[conformance ledger](../2026-09-11-aauth-v11-spec-migration/conformance-ledger.md).
This audit independently re-derives requirements from the spec text and tries
to *break* the implementation, rather than confirming the ledger.

## Method

1. Split the spec into small logical areas, each paired with the SDK files that
   implement it (tables below). Scope is kept small so one subagent can read the
   full spec slice and every listed file without exhausting its context.
2. Dispatch one **adversarial** read-only subagent per area. Each extracts every
   normative statement (MUST / MUST NOT / REQUIRED / SHALL / SHOULD / SHOULD
   NOT / MAY with behavioural effect) in its slice, maps it to code, and then
   actively tries to construct inputs or sequences the code accepts but the spec
   forbids (or rejects but the spec requires). Findings are written to
   `findings/<phase>/<ID>-<slug>.md` using the template below; the agent returns
   only a short summary.
3. Collate findings into the tables at the bottom of this file, de-duplicate
   cross-area findings, and **re-verify every CRITICAL/HIGH finding directly**
   against the spec line and current code before recording it as confirmed.
   Findings are marked `CONFIRMED`, `REPORTED` (not re-verified), or
   `REJECTED` (false positive, with reason).
4. Repeat for samples, then docs, using the SDK findings as input so that
   samples/docs that faithfully reflect an SDK defect are attributed to the SDK.

### Severity scale

| Severity | Meaning |
|---|---|
| CRITICAL | MUST/MUST NOT violation with a security impact an attacker can exploit (auth bypass, token confusion, replay, privilege escalation). |
| HIGH | MUST/MUST NOT violation or wire-format incompatibility with a conforming peer; no direct exploit. |
| MEDIUM | SHOULD violation, partial enforcement, or a spec-mandated check reachable only through a non-default path. |
| LOW | MAY-level divergence, naming/shape drift, missing defensive check with no known impact. |
| INFO | Observation, spec ambiguity, or a documented deliberate deviation. |

### Findings file template

```markdown
# <ID> — <Area>

Spec slice: <file> L<a>–L<b>. Files read: <list>.

## Findings

| ID | Sev | Spec (anchor, line) | Code (file:line) | Requirement | Observed | Adversarial scenario | Conf |
|---|---|---|---|---|---|---|---|

## Verified compliant

- <requirement> — <file:line> (one line each)

## Not assessed / out of slice

- <item> — <why / which area owns it>
```

### Adversarial agent brief (shared)

Every auditor receives: the spec slice (file + line range), the code files, the
severity scale, the template, the output path, and these rules —

- Read-only for the repository except the single findings file it owns. No
  `dotnet build`/`test` (parallel agents share `obj/`); static analysis only.
- Cite spec lines as `(#anchor, Lnnn)` verified against the vendored file, and
  code as `path:line`.
- Assume the implementation is wrong until proven right; for each requirement,
  try at least one hostile input (missing/duplicate/extra claim, wrong `typ`,
  wrong `aud`, expired/future `iat`, oversize value, wrong header casing,
  replay, cross-issuer confusion, downgrade, unexpected status code).
- Check both directions: producer (what the SDK emits) and consumer (what it
  accepts).
- A behaviour already logged as a deliberate deviation in the migration
  `implementation-log.md` or `SPEC-VERSION.md` is `INFO`, not a defect, unless
  the deviation itself contradicts a MUST.
- Stay inside the slice; list cross-area observations under *Not assessed*.

## Area map — Phase 1 (SDK)

Spec: `P` = [draft-hardt-oauth-aauth-protocol.md](../../../aauth-spec/v11/draft-hardt-oauth-aauth-protocol.md),
`SK` = [draft-hardt-httpbis-signature-key-09.txt](../../../aauth-spec/v11/draft-hardt-httpbis-signature-key-09.txt),
`R3` = [draft-hardt-aauth-r3.md](../../../aauth-spec/v11/draft-hardt-aauth-r3.md),
`EV` = [draft-hardt-aauth-events.md](../../../aauth-spec/v11/draft-hardt-aauth-events.md),
`BS` = [draft-hardt-aauth-bootstrap.md](../../../aauth-spec/v11/draft-hardt-aauth-bootstrap.md).
Code paths are relative to `src/AAuth/` unless prefixed.

| ID | Area | Spec slice | Primary code |
|---|---|---|---|
| A01 | Signature-Key header & schemes | SK §3–3.9 L345–L1371; SK §7.1 L2324–L2356 | `HttpSig/SignatureKey*`, `StructuredFields*`, `*SignatureKeyProvider`, `DefaultSignatureKeyResolver`, `ISignatureKeyResolver`, `NamingTokenVerifier`, `Crypto/KeyFactory`, `Crypto/JwkValidationException` |
| A02 | AAuth HTTP-sig profile: sign + verify + freshness | P #http-message-signatures-profile L2160–L2275 | `HttpSig/AAuthSigningHandler`, `AAuthSigningKeySetHandler`, `AAuthVerifier`, `AAuthHttpClientExtensions`, `Server/IJtiStore`, `Server/InMemoryJtiStore`, `Crypto/*` (alg selection) |
| A03 | Signature errors, Accept-Signature-*, scheme rejection | SK §4–5 L1487–L2159, SK §7.4 L2485–L2544; P #scheme-rejection L2256–L2267, #why-401-signature-failures L3524 | `Errors/SignatureError`, `Server/Verification/AAuthVerificationMiddleware` (error paths), `Server/Challenge/*` (headers), `Agent/ChallengeHandler` (client processing §4.9) |
| A04 | Identifiers, metadata, JWKS discovery | P "Agent Identifiers" L486–L507, #protocol-primitives L1940–L2159, #jwks-discovery L2276–L2289 | `Identifiers/*`, `Discovery/*` (except egress), `Server/Metadata/*`, `AAuthUrl` |
| A05 | Common JWT rules, agent token, JWT/media types | P #agent-tokens L508–L544, #aauth-tokens L2290–L2323, IANA L3021–L3109 | `Tokens/AgentTokenBuilder`, `Tokens/JwtWriter`, `Tokens/TokenVerifier` (common + agent), `Agent/NamingJwtBuilder`, `AAuthTokenType`, `AAuthConstants` |
| A06 | Agent provider, bootstrap, refresh | P #agent-provider L467–L485, #re-authorization L1289–L1306; BS (informational) | `Agent/AgentProviderClient`, `AgentProviderTokenRefresher`, `SelfIssuedTokenRefresher`, `TokenRefreshHandler`, `AAuthTokenCache`, `AAuthTokenHolder`, `IPlatformAttestor`, `Tokens/AgentIssuanceContext`, `*Builder.cs` at root |
| A07 | Requirement headers, interaction codes, capabilities, resource-managed | P #requirement-agent-token L560–L614, #requirement-responses L2324–L2477 | `Headers/*`, `Server/ResourceManaged/*`, `Agent/AAuthCapabilitiesHeader` |
| A08 | Person/auth token required, resource token, challenge verification | P #requirement-person-token L615–L664, #resource-token L725–L781, #why-presented-jti L3482 | `Tokens/ResourceTokenBuilder`, `Server/Challenge/*`, `Server/AAuthServerIdentity` |
| A09 | Access modes, authorization endpoint, resource verification pipeline | P #resource-access-modes L228–L431, #authorization-endpoint-request L665–L724, adoption L2769–L2828 | `Server/Verification/*`, `Server/AAuthTrust*`, `Server/Endpoints/*`, `Server/Authorization/*`, `Server/AAuthAuthorizationRequest`, `DependencyInjection/AAuthApplicationBuilderExtensions` |
| A10 | Auth token structure & verification | P #auth-tokens L1766–L1837 | `Tokens/AuthTokenBuilder`, `AuthTokenResponseValidator`, `AgentAuthTokenValidator`, `UpstreamTokenValidator`, `TokenVerifier` (auth), `Server/AuthTokenResponse` |
| A11 | Person token & person token endpoint | P #person-server L782–L923, L2872–L2926 | `Tokens/PersonTokenBuilder`, `Person/AAuthPersonServerEndpoints` (person-token), `Person/AgentPersonBinding`, `Person/IIdentityClaimsAsserter`, `TokenVerifier` (person) |
| A12 | PS auth token endpoint — server side | P #ps-token-endpoint L924–L1042, L2898–L2911 | `Person/AAuthPersonServerEndpoints` (auth-token), `IPersonPendingStore`, `PsApprovalGuard`, `PersonResourceInteraction`, `AgentAssertedContent`, `Server/BrowserConsentSessions` |
| A13 | Token exchange & interaction & clarification — agent side | P L924–L1126 (client duties) | `Agent/TokenExchange*`, `ChallengeHandler`, `InteractionHandler`, `ClarificationExchange`, `AAuthInteractionExceptions`, `IInteractionPresenter`, `AAuthCallbackHandlers`, `Errors/InteractionCallbackError`, `Headers/ClarificationRequirement` |
| A14 | Deferred responses & polling | P #deferred-auth-token L643–L664, #deferred-responses L2478–L2640 | `Agent/DeferredExchange`, `DeferredPoller`, `Server/DeferredState`, `Server/HeldInvocations`, `Errors/PollingError`, pending-store poll paths |
| A15 | Interaction / permission / audit endpoints | P #interaction-endpoint L1127–L1288 | `Agent/Governance/*` (non-mission), `Server/Governance/GovernanceEndpoints`, `IInteractionRelay`, `IPermissionDecider`, `IAuditSink`, defaults |
| A16 | Missions | P #missions L1307–L1568, L2969–L2972 | `Agent/Mission*`, `Agent/Governance/Mission*`, `Server/Governance/IMission*`, `MissionApprovalBuilder`, `InMemoryMission*`, `MissionPersonTokenExtensions`, `Tokens/MissionReference`, `Errors/AAuthMissionTerminatedException`, `DependencyInjection/AAuthGovernance*` |
| A17 | Access Server federation | P #access-server-federation L1569–L1765 | `Access/*`, `Headers/Claims*`, `DependencyInjection/AAuthAccessServer*` |
| A18 | Call chaining, interaction chaining, sub-agents | P #agent-delegation L1838–L1939, flows L3300–L3417 | `Server/CallChaining/*`, `Tokens/UpstreamTokenValidator`, `Person/PersonResourceInteraction`, sub-agent paths in person endpoints and `AgentTokenBuilder` |
| A19 | Errors, scopes, account binding | P #error-responses L2565–L2665 | `Errors/*`, `Server/AAuthProblemDetails`, `Tokens/AccountBinding`, scope handler |
| A20 | Revocation | P #token-revocation L2666–L2768, L3532 | `Server/Revocation*`, `Server/IOpaqueTokenStore`, `Server/Token{Key,Grant,Registration}`, `Errors/RevocationError` |
| A21 | Security & privacy considerations; secure defaults | P L2829–L2972 | `Discovery/AAuthEgressPolicy`, `AAuthHttpTransport`, `DependencyInjection/*` defaults, `AAuthOptionsValidator`, `AAuthSeams` |
| A22 | R3 — vocabularies, annotations, authorization endpoint extensions | R3 L128–L443 | `src/AAuth.R3/Model/*`, `R3AccessAnnotations`, `R3Metadata`, `R3Request` |
| A23 | R3 — document, processing, auth token extensions, enforcement, proposals | R3 L444–L755 | `src/AAuth.R3/R3Document*`, `R3AccessTokenEndpoint`, `R3Enforcement`, `R3Hash`, `R3AuthClaims`, `R3ClaimReader`, `R3Challenge`, `R3ProposalStore`, `R3Audit`, `R3FetchClient` |
| A24 | Events | EV L149–L612 | `src/AAuth.Events/*` |

## Area map — Phase 3 (samples)

Samples are audited for (a) protocol behaviour the sample itself implements
(mock servers enforce spec rules too), (b) misuse of the SDK that would be
non-conformant in production, and (c) comments/README claims that contradict
draft-11.

| ID | Scope |
|---|---|
| S01 | `samples/MockPersonServer/Program.cs` + README |
| S02 | `samples/MockPersonServer/*` (non-Program: consent, missions, asserter) |
| S03 | `samples/MockResourceServers/*` + README |
| S04 | `samples/MockAccessServers/*` + `samples/MockAgentProvider/*` + READMEs |
| S05 | Agents: `Concierge`, `MissionAgent`, `AgentConsole`, `SampleApp`, `EventAgent`, `LiveWhoAmITest` + READMEs |
| S06 | Support: `CapabilitySupport`, `ConsentSupport`, `EventSupport`, `SampleEgress.cs`, `FederatedWorkerScenario.cs`, `samples/README.md` |
| S07 | `samples/GuidedTour/TourSession.cs` L1–L1750 |
| S08 | `samples/GuidedTour/TourSession.cs` L1751–L3500 |
| S09 | `samples/GuidedTour/TourSession.cs` L3501–end + `TourSession.Capabilities.cs` |
| S10 | `samples/GuidedTour/` other files (`CodeSnippets.cs` string snippets, options, README) |

## Area map — Phase 4 (docs)

| ID | Scope |
|---|---|
| D01 | `docs/README.md`, `concepts.md`, `glossary.md`, `getting-started.md` |
| D02 | `docs/signing-modes/*`, `docs/advanced/key-management.md`, `platform-attestation.md` |
| D03 | `docs/server/` verification-middleware, multi-scheme-verification, challenge-middleware, replay-detection, resource-metadata |
| D04 | `docs/server/` authn-authz, authorization-policies, token-issuance |
| D05 | `docs/server/mission-governance.md`, `docs/advanced/missions.md`, `mission-governance-clients.md`, `docs/workflows/mission-governed-access.md` |
| D06 | `docs/workflows/` identity-based, resource-managed, ps-asserted, deferred-consent, federated-access |
| D07 | `docs/workflows/` call-chaining, rich-resource-requests, events, wallet-protocol, catalog-gateway, bootstrap-enrollment; `document-release.md`; `docs/advanced/interaction-chaining.md`, `clarification-chat.md` |
| D08 | `docs/advanced/error-handling.md`, `observability.md`, `docs/reference/configuration.md` |
| D09 | `docs/reference/dependency-injection.md` |
| D10 | Root `README.md`, `src/*/README.md`, `aauth-spec/SPEC-VERSION.md` claims |

## Collated findings

### Summary

44 adversarial read-only agents audited one area each (24 SDK, 10 samples,
10 docs); the orchestrator de-duplicated cross-area findings and re-verified
every CRITICAL/HIGH against the vendored draft-11 text and current code.

| Phase | CRITICAL | HIGH | MEDIUM | LOW | Rejected |
|---|---|---|---|---|---|
| SDK (`src/AAuth`, `AAuth.R3`, `AAuth.Events`) | 1 | 15 | 54 | 10 | 3 |
| Samples | 0 | 4 | 11 | 13 | 0 |
| Docs | 0 | 7 | 30 | 13 | 0 |

One finding is CRITICAL (SDK-01, upgraded in the Phase 6 review). The two raw
agent CRITICALs were conditional on a trusted-party compromise (SDK-04) or on a
host skipping a composition step (SDK-03, now MEDIUM; its docs instance DOC-06
stays HIGH). The top risks are:

1. **SDK-01 (CRITICAL)**: the documented low-level `UseAAuthVerification()` path never checks
   `aud`, so tokens for one resource are accepted at another (DOC-03 recommends it).
2. **SDK-02**: four-party resources still accept auth tokens from any PS, which
   bypasses their AS.
3. **DOC-06 / SDK-03**: the R3 docs show per-call enforcement without the
   single-use gate, so approvals copied from them are replayable.
4. **SDK-04 / SDK-05**: upstream-token provenance is not checked against PS
   records, and a person token revoked while pending can still be presented to
   an AS.
5. **SDK-19**: the R3 AS issuance audit record omits the mandated `ps`, `sub` and
   `agent_jkt`.
6. **SMP-01**: the demo PS grants admin roles to any `aauth:demo@*` agent id.
7. **DOC-01**: `getting-started.md` still teaches the draft-10 flow (no person
   token, no `presented_token`).

The remaining HIGHs are wire incompatibilities on default paths: polling status
codes and `Retry-After`, governance `interaction_endpoint` and `424`, mission
`expires_at` on pending paths, `updated_request` bounds, the authorization
endpoint's person-token requirement, future `created`, `crit`, and R3 on the
authorization endpoint.

**Assessed compliant (no confirmed HIGH):**

- Signature-Key scheme parsing and key validation (A01).
- HTTP-sig verification and scheme rejection on the default path (A02/A03).
- Identifiers and discovery (A04).
- Resource-token structure and agent-side challenge verification (A08).
- Auth-token structure and resource-side verification on `UseAAuth` (A10).
- Agent token exchange (A13).
- Error modelling (A19).
- Egress/SSRF defences (A21).
- Events token handling (A24).

Each findings file's *Verified compliant* section lists the individual
requirements that passed.

### SDK (Phase 2)

Raw agent output: 2 CRITICAL, 56 HIGH (incl. CRITICAL), 28 MEDIUM, 6 LOW, 9 INFO
across 24 files in [findings/sdk/](findings/sdk/). Every CRITICAL/HIGH was
re-verified by the orchestrator against spec text and code; most were regraded
under the severity scale (a MUST violation reachable only via non-default
configuration, or one that fails closed, is MEDIUM; a missing SHOULD is MEDIUM).
After de-duplication: **0 CRITICAL, 18 HIGH, 52 MEDIUM, 10 LOW**, 3 rejected
false positives, 9 INFO.

> **Update (2026-09-30, Phase 6 review):** SDK-01 upgraded to **CRITICAL**;
> SDK-03, SDK-07 and SDK-15 regraded **MEDIUM**; A23-002 upgraded to **HIGH** as
> SDK-19. Final SDK counts: **1 CRITICAL, 15 HIGH, 54 MEDIUM, 10 LOW**. The IDs
> are kept stable; the grade column below is authoritative. MEDIUM spot-check: 7 of 23 original MEDIUMs re-read against code (A06-02,
A09-MED-001, A09-MED-002, A11-03, A12-04, A13-05, A20-003) — all held; A13-05
regraded LOW and A20-003's summary corrected (SHOULD, not MUST).

#### CRITICAL / HIGH — confirmed (grades per the Phase 6 update)

| ID | Source | Spec | Code | Finding |
|---|---|---|---|---|
| SDK-01 (**CRITICAL**) | A09-MED-001, A10-02 | (#auth-token-verification, L1812) | `src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs:237`, `:247`; `src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs:39-48` | Public `UseAAuthVerification()` never sets `ResourceIdentifier` (even when `AddAAuthResource` configured `Issuer`), and the middleware then uses the token's own `aud` as the expected audience — the audience check is a tautology. An auth/person token minted for resource A is accepted at resource B by the same key holder. `UseAAuth`/`MapAAuthResource` set it correctly; `docs/server/multi-scheme-verification.md:44` shows the unsafe call. |
| SDK-02 | A09-HIGH-001 | (#overview-federated, L386-L431), (#trust-posture-in-ps-asserted-access, L2866) | `src/AAuth/Server/Endpoints/AAuthEndpointExtensions.cs:174-196`; `src/AAuth/Server/AAuthTrustPolicy.cs:67-89` | A four-party resource configured with `AccessServer` still trusts auth tokens from any verifiable issuer (unconfigured trust = open), including PS-issued `dwk=aauth-person.json` tokens, so the resource's AS policy is bypassable by any PS. The cited text contains no explicit MUST restricting issuers. The HIGH grade rests on the four-party model and the security impact. |
| SDK-03 (**MEDIUM**) | A23-001 | R3 (#per-call-flow, L676) | `src/AAuth.R3/R3Enforcement.cs:100-143`; `src/AAuth.R3/R3ProposalStore.cs:49` | `R3Enforcement` returns `Granted` on every replay of a per-call auth token; single use needs `IAAuthSingleUseGate.ExecuteOnceAsync` (`src/AAuth/Server/HeldInvocations.cs:70`), which only the Bookings sample composes and no doc mentions. |
| SDK-04 | A18-001 | (#upstream-token-verification, L1833, L1835) | `src/AAuth/Tokens/UpstreamTokenValidator.cs:128-133`; `src/AAuth/Person/AAuthPersonServerEndpoints.cs:243-247` | PS accepts AS-issued upstream auth tokens from any statically trusted AS without a record that it presented a person token to that AS for that `aud`/`sub`, and does not reject when it cannot identify the calling agent. |
| SDK-05 | A20-001 | (#revocation-cascade, L2752) | `src/AAuth/Person/AAuthPersonServerEndpoints.cs:1447-1455` | Four-party deferred path federates the stored `presented_token` to the AS before re-checking source revocation; a person token revoked while pending is still presented. |
| SDK-06 | A12-01 | (#ps-token-endpoint, L941), (#agent-response-to-clarification, L1117) | `src/AAuth/Person/AAuthPersonServerEndpoints.cs:734-750` | `updated_request` swaps in a replacement `presented_token` but keeps the original `AuthorizationExpiresAt`/`SourceTokens`, so the new token's `exp` and revocation do not bound the grant. |
| SDK-07 (**MEDIUM**) | A11-01 | (#agent-person-binding, L2914, L2916) | `src/AAuth/Person/AAuthPersonServerEndpoints.cs:526-548`; `src/AAuth/Person/AgentPersonBinding.cs:21` | PS mints whatever subject the asserter returns; binding record has no person and nothing prevents a second person claiming the same agent. Not documented as a host duty. |
| SDK-08 | A09-HIGH-002 | (#authorization-endpoint-request, L667) | `src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs:151-157` | `MapAAuthAuthorizationEndpoint` accepts any verified token (agent/auth) instead of requiring a person token, and answers absence with `401 invalid_request` rather than `requirement=person-token`. |
| SDK-09 | A15-003 | (#interaction-response-poll-authority, L1168), (#interaction-endpoint-errors, L1189) | `src/AAuth/Server/Governance/DefaultInteractionRelay.cs:21-26` | Default relay answers `interaction`/`payment` with `200 ok` instead of `424 interaction_unavailable`; the agent never falls back to directing the user. |
| SDK-10 | A15-001 | (#ps-metadata, L2065) | `src/AAuth/Person/AAuthPersonServerEndpoints.cs:195`; `src/AAuth/Server/Governance/AAuthGovernancePipelineOptions.cs:27` | PS metadata `interaction_endpoint` defaults to the browser consent path `/interaction`, while the governance relay is mapped at `/mission-interaction`. |
| SDK-11 | A14-HIGH-001 | (#deferred-responses, L2531), (#polling-error-codes, L2626) | `src/AAuth/Agent/ChallengeHandler.cs:211-302` | Deferred auth-token (`202 requirement=auth-token`) polling ignores `Retry-After` and treats `429 slow_down` as terminal. |
| SDK-12 | A14-HIGH-002 | (#polling-error-codes, L2625) | `src/AAuth/Server/DeferredState.cs:36-40` | `invalid_code` emitted as `400`; table requires terminal `410`. |
| SDK-13 | A14-HIGH-003 | (#polling-error-codes, L2623) | `src/AAuth/Server/HeldInvocations.cs:320-329` | Held-invocation timeout answers `410 expired` on first poll; spec is `408`, `410` only after a terminal response. |
| SDK-14 | A16-002 | (#mission-approval, L1425) | `src/AAuth/Person/AAuthPersonServerEndpoints.cs:1254-1259` | Pending/federated decision paths check only mission `State`, not `expires_at`. |
| SDK-15 (**MEDIUM**) | A06-01 | (#re-authorization, L1293) | `src/AAuth/AAuthClientBuilder.cs:722-727`, `:857`; `src/AAuth/Agent/AgentProviderTokenRefresher.cs:84-88` | Two-key refresh returns a token bound to a fresh ephemeral key that is never installed; requests keep signing with the durable key, so every conforming verifier rejects the proof. |
| SDK-16 | A02-HIGH-001 | (#signature-parameters, L2234) | `src/AAuth/HttpSig/AAuthSigningHandler.cs:67-82` | Signer deliberately emits future `created` values (last+1) for same-target requests within one second; MUST be current time; >60 req/s to one target trips `clock_skew`. |
| SDK-17 | A05-01 | (#common-verification, L2313) | `src/AAuth/Tokens/TokenVerifier.cs:629` | JWT `crit` header is never checked; RFC 7515 requires rejecting unknown critical extensions. |
| SDK-19 | A23-002 | R3 (#r3-processing, L548) | `src/AAuth.R3/R3Audit.cs:11-23`; `src/AAuth.R3/R3AccessTokenEndpoint.cs:88-97` | The R3 issuance audit record has no `ps`, `sub` or `agent_jkt`, and the AS never supplies them. The AS MUST record them. This is an unconditional MUST violation on the default path. |
| SDK-18 | A22-HIGH-001 | R3 (#authorization-endpoint-extensions, L386-L417) | `src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs:182-195`; `src/AAuth.R3/R3Request.cs:27` | Mapped authorization endpoint requires `scope` and drops `r3_operations`; the SDK's own R3 request body (no `scope`) gets `400`. |

#### MEDIUM

| Source | Area | Finding (short) |
|---|---|---|
| A01-H01 | Sig-Key | `jwt` without `iss`/`dwk` rejected even with a companion verifier (SK L1189). |
| A01-M01 | Sig-Key | Producer lets provider label differ from `Signature-Input` label. |
| A01-M02 | Sig-Key | Companion `jwt`/`self-jwt` expiry accepts 30 s skew. |
| A02-HIGH-002 | HTTP-sig | `content-type` not covered when a caller-built body has no Content-Type (SDK clients always set it). |
| A03-HIGH-001 | Sig errors | Challenge-layer scheme filter returns 401 without `Signature-Error`/`Accept-Signature-Scheme` (non-default config). |
| A03-HIGH-002 | Sig errors | Untrusted-issuer denial reported as `401 invalid_jwt`; SK §5.3 suggests 403 without signature headers. |
| A04-01 | Identifiers | Empty sub-agent discriminator / `+` in top-level local part accepted. |
| A04-02 | Metadata | Producer emits configured endpoint/URI fields without https/no-query/no-fragment validation. |
| A04-04 | Metadata | `additional_signature_components` not parsed; agent recovers only via `invalid_input` retry. |
| A04-05 | Identifiers | Dev egress policy admits `http://localhost:port` issuers. |
| A04-06 | Metadata | AP metadata lacks `event_endpoint`, `localhost_callback_allowed`. |
| A05-02 / A06-03 | Agent token | No upper bound on agent-token lifetime (SHOULD ≤ 24 h). |
| A06-02 | Refresh | Five-minute refresh margin applied only to agent tokens. |
| A07-001 / A09-MED-002 | Access modes | `AgentTokenRequired` passes person/auth tokens. |
| A07-002 | Headers | Interaction URL / endpoint validation rejects `?` but not `#`. |
| A07-003 | Headers | Malformed/multiple `AAuth-Access` ignored rather than rejecting the response. |
| A07-004 / A13-04 | Interaction | Agent does not relay interactions to PS `interaction_endpoint` first (SHOULD). |
| A07-005 | Capabilities | Mission-approval `capabilities` not unioned into `AAuth-Capabilities`. |
| A07-007 | Capabilities | `AAuth-Capabilities` parser not a strict SF List of Tokens. |
| A08-02 / A13-01 | Exchange | Resource-token `login_hint` not forwarded to the PS. |
| A08-03 | Resource token | `BuildResourceTokenAsync` helper accepts an agent-token assertion. |
| A10-01 | Auth token | Agent does not verify returned auth-token signature/`typ` (SHOULD). |
| A11-03 | Person token | Default asserter uses one fixed `sub` for all resources. |
| A11-04 | Person token | No first-issuance approval / metadata fetch for new resources in default path. |
| A12-02 | PS endpoint | `platform`/`device` not validated against registry/length/printable. |
| A12-03 | PS endpoint | Malformed `capabilities` silently treated as absent. |
| A12-04 | Clarification | Federated triage path bypasses the clarification round cap. |
| A13-02 | Clarification | `timeout` parsed but not enforced on agent side. |
| A14-MED-004 | Polling | `Retry-After: 0` / interval handling edge. |
| A15-002 | Governance | Governance endpoints do not check agent `ps` names this PS. |
| A15-004 | Governance | Non-object `parameters`/`result` silently dropped. |
| A15-005 | Governance | Default audit sink discards `parameters`/`result`. |
| A16-001 | Missions | Termination reason not stored. |
| A16-003 | Missions | Mission authorization ignores approving PS (shared store). |
| A16-004 | Missions | Nonexistent vs foreign mission distinguishable (timing/body). |
| A17-001 | Federation | PS-AS collapse unsupported (always three-party, `dwk` person). |
| A17-002 | Federation | PS does not pin `dwk=aauth-access.json` when verifying AS tokens. |
| A17-003 / A19-HIGH-005 | Federation | AS `402` payment flow treated as terminal. |
| A18-003 | Chaining | SDK guidance passes downstream interaction code through instead of intermediary's own. |
| A19-HIGH-001 | Errors | Some 401 problem bodies lack `Signature-Error`. |
| A19-HIGH-003 | Errors | Invented token-endpoint codes (`untrusted_person_server`, `policy_error`, …). |
| A19-HIGH-004 | Errors | Invented polling codes (`unknown_pending` 404, `request_withdrawn`, …). |
| A20-002 | Revocation | Pending request dependency revocation not surfaced as `revoked` in all paths. |
| A20-003 | Revocation | `401 revoked_jwt` for a revoked auth token omits the recommended `AAuth-Requirement: requirement=person-token` (SHOULD). |
| A21-TLS-01 | Security | TLS ≥ 1.2 not pinned (OS default). |
| A22-MED-001 | R3 | Ambiguous bare operation identifiers across merged definitions not rejected. |
| A23-003 | R3 | Designated AS may fetch any R3 document without per-token entitlement. |
| A23-004 | R3 | Operations not validated against authoritative definition before minting. |
| A24-01 | Events | Protected subscription requires a JSON body (optional per spec). |
| A24-02 | Events | Event delivery requires `content-digest` even with no payload. |
| A24-03 | Events | Exhausted `max_uses` answered `429` (tests pin it) instead of `404`. |

#### LOW

A04-03 (consumer https check on `tos_uri`/`logo_uri` etc.), A09-HIGH-003 / A19-HIGH-002
(`415` vs `400 invalid_request`), A13-03 (agent does not pre-validate
replacement pair; PS enforces), A13-05 (`device` ASCII-only), A07-006, A08-04,
A10-03, A16-005, A23-005, A23-006 — see findings files.

#### Rejected (false positives)

| Source | Reason |
|---|---|
| A08-01 | Agent resource-challenge verification (L775-L780) has no `aud` step; `aud` may be the AS. Agent checks `ps`, `iss`, `agent_jkt`, `sub`, `presented_jti`. |
| A11-02 | `ps` claim is informational (L523: "The PS of an issued authorization is the `iss` of the person token … not this claim"). Kept as INFO hardening. |
| A18-002 | `clock_skew` for a future-`iat` token carried as a request parameter is explicitly allowed (#common-verification, L2320). |

#### Areas with no confirmed HIGH

A01 Signature-Key schemes, A03 signature errors, A04 identifiers/discovery,
A06 agent provider/refresh (after Phase 6), A07 headers, A08 resource token,
A10 auth token, A11 person token (after Phase 6), A13 agent exchange, A17
federation, A19 errors, A21 security defaults, A24 Events.

### Samples (Phase 3)

Raw agent output across [findings/samples/](findings/samples/): 0 CRITICAL, 8 HIGH,
7 MEDIUM, 13 LOW, 13 INFO. All 8 HIGHs re-verified against code; 4 kept HIGH, 4
regraded MEDIUM (sample demo against trusted local servers, or a sample instance
of an SDK MEDIUM). Final: **0 CRITICAL, 4 HIGH, 11 MEDIUM, 13 LOW**.

#### HIGH — confirmed

| ID | Source | Spec | Code | Finding |
|---|---|---|---|---|
| SMP-01 | S02-01 | (#untrusted-input, L2844), (#agent-person-binding, L2916) | `samples/MockPersonServer/SampleIdentityClaimsAsserter.cs:45-54`; `samples/MockPersonServer/ConsentBridgePersonPendingStore.cs:56-60` | Demo admin roles/groups are granted to any agent whose id starts with `aauth:demo@` — any domain, any AP — so `aauth:demo@attacker.example` receives privileged claims. |
| SMP-02 | S01-01 | (#interaction-response-poll-authority, L1162-L1168), (#interaction-endpoint-errors, L1189) | `samples/MockPersonServer/Program.cs:503-518`; `samples/MockPersonServer/MissionGovernance.cs:217-223` | The sample's own `/mission-interaction` handler answers every `interaction`/`payment` with `200 {"status":"ok"}`, ignoring `Pending`/`Unavailable`; mirrors SDK-09 in hand-written code. |
| SMP-03 | S05-001 | (#interaction-chaining, L1886) | `samples/Concierge/Program.cs:213-224`; `samples/Concierge/PendingStore.cs:13-18`; `samples/SampleApp/Components/Pages/CallChain.razor:106-112` | Concierge (the intermediary) re-emits the downstream PS `url`/`code` instead of its own interaction code; the SampleApp UI encodes the pass-through. Wire-level instance of SDK A18-003. |
| SMP-04 | S03-01 | (#authorization-endpoint-request, L667) | `samples/MockResourceServers/Inbox/Program.cs:127-138` | Inbox publishes `/authorize` via `MapAAuthAuthorizationEndpoint(...).RequireAAuthSignature()` and grants on an agent signature alone — the public sample instance of SDK-08. |

#### MEDIUM

| Source | Finding (short) |
|---|---|
| S06-01 | `SqliteEventStore` returns `429` on exhausted `max_uses` (Events L437/L441 require `404`); independent of SDK A24-03. |
| S07-01 | Guided Tour offers `hwk`, `jwks_uri`, `jkt-jwt` as agent signing modes against the Profile resource; agents MUST NOT use `hwk`/`jwks_uri` for AAuth resource requests (#keying-material, L2179). SDK keeps these behind the explicit `RequireGenericSignature()` opt-in; the tour presents them as AAuth modes. |
| S08-01 | Tour accepts any absolute `Location` and sends signed polls (carrying agent/auth tokens) to it; spec requires same-origin pending URLs (L2516) and the SDK's `ValidatePendingLocation` is bypassed. |
| S08-02 | Tour polling ignores absent-`Retry-After` default and `429` back-off. |
| S08-03 | Tour copy/handling of `expired` (408) and `invalid_code` (410) statuses is wrong. |
| S09-01 | Capability polling clamps `Retry-After` to 5 s and treats `429` as terminal; clarification loop polls every 500 ms. |
| S09-02 | Tour omits `AAuth-Capabilities` on signed resource requests (SHOULD). |
| S03-02 | Resources that accept person tokens do not all publish a revocation endpoint (SHOULD). |
| S03-03 | Resource revocation acceptance does not cover all issuers whose tokens the resource accepts. |
| S04-01 | Federated AS requests `sub` in a `requirement=claims` round trip (AS MUST NOT). |
| S05-002 | Concierge pending body/status for unknown or consumed codes diverges (`410 invalid_code`, `"pending"`). |

LOW items (S01-02..04, S03-04/05, S04-03, S05-003..005, S06-02/03, S07-02,
S10-001) are stale prose, "four modes" wording, or logging hygiene — see files.
Inherited SDK defects are recorded as INFO in each file.

### Docs (Phase 4)

Raw agent output across [findings/docs/](findings/docs/): 0 CRITICAL, 20 HIGH,
19 MEDIUM, 12 LOW, 5 INFO. All 20 HIGHs re-read against the doc and code. Rule
applied: a doc that **teaches or recommends** a non-conformant or unsafe pattern
stays HIGH; a doc that overstates conformance the SDK does not yet meet (fixed
by fixing the SDK) is MEDIUM; an incomplete HTTP example is LOW. Final:
**0 CRITICAL, 7 HIGH, 30 MEDIUM, 13 LOW** (D01-03 merged into DOC-01).

#### HIGH — confirmed

| ID | Source | Doc | Finding |
|---|---|---|---|
| DOC-01 | D01-02, D01-03 | `docs/getting-started.md:160-223` | The main walkthrough teaches the **draft-10 flow**: resource reads `ps` from the agent token and issues a resource token directly; PS request body is only `{"resource_token": …}`; no person token, no `presented_token`, no `presented_jti` check; diagram shows `AAuth-Requirement: resource_token (aud=PS)`. Draft-11 requires a verified person/auth token before any resource token (L729-L745) and `presented_token` in every exchange (L936-L941). |
| DOC-02 | D02-01 | `docs/signing-modes/agent-identity-jwks-uri.md:18-50`, `:72` | Teaches agent→resource calls signed with `UseJwksUri`/`UseJwks` and a custom `dwk`; agents MUST use `jwt` and MUST NOT use `jwks_uri`/`hwk` for AAuth resource requests (#keying-material, L2179). |
| DOC-03 | D03-01 | `docs/server/multi-scheme-verification.md:36-44` | Recommends `AddAAuthResource(Issuer)` + bare `app.UseAAuthVerification()` — the SDK-01 path where `aud` is never checked. |
| DOC-04 | D06-01 | `docs/workflows/resource-managed-access.md:128-139` | Recommends `MapAAuthAuthorizationEndpoint(...).RequireAAuthSignature()` granting on any signature (SDK-08); spec requires a person token (L667). |
| DOC-05 | D07-01 | `docs/advanced/interaction-chaining.md:19`, `:94`, `:107-118`, `:234` | Tells intermediaries to forward the downstream PS `url`/`code`; spec requires the intermediary's own code and `Location` (L1886). |
| DOC-06 | D07-03 | `docs/workflows/rich-resource-requests.md:152-161` | R3 per-call enforcement example uses `R3Enforcement.Evaluate` with no single-use gate — approvals replayable (SDK-03, R3 L676). |
| DOC-07 | D09-02 | `docs/reference/dependency-injection.md:761-775` | PS governance example never maps `MapAAuthGovernance()` nor sets `InteractionEndpointPath`, so copied config advertises `mission_endpoint` with no handler and `interaction_endpoint=/interaction` (SDK-10). |

#### MEDIUM

| Source | Finding (short) |
|---|---|
| D01-01, D02-03, D10-06 | "Four modes" / stale "PS-Asserted" wording; Person identity mode and `requirement=person-token` missing from entry docs, signing-modes overview and README. |
| D01-04 | Auth token `sub` described as optional; it is REQUIRED (L1777-L1780). |
| D02-02 | Key-management and `key-rotation-jkt-jwt.md` present `jkt-jwt` as an agent→resource rotation scheme; draft-11 reserves `jkt-jwt` for the AP key-refresh ceremony (L2196). |
| D03-02 | `replay-detection.md:223-231` claims deferred delivery re-checks source revocation before federation (SDK-05 says it does not). |
| D03-03 | `challenge-middleware.md:39-40` says `AgentTokenRequired` requires an agent token; SDK passes person/auth tokens (A07-001). |
| D03-04 | `multi-scheme-verification.md:101-132` recommends issuer policy via resolver exceptions → `401 Signature-Error` instead of `403`. |
| D04-001 | Role-based authorization examples do not namespace roles by issuer in open-trust mode. |
| D04-002, D08-05, D10-03 | Docs claim mission `expires_at` is enforced on every path (SDK-14 says pending/federated paths do not). |
| D05-01 | `AddAAuthGovernance()` + `MapAAuthGovernance()` described as safe defaults; default relay answers `200` not `424` (SDK-09). |
| D05-02 | Mission termination guidance has no termination reason (A16-001). |
| D05-03 | Client doc omits resource-hosted interaction poll authority (L1164). |
| D06-02 | Claims PS-AS collapse "needs no code changes"; SDK has no collapse path (A17-001). |
| D06-04 | Deferred-consent docs show a 202 JSON payload with `interaction_url`/`pending_url`/`code` and `AAuth-Requirement: interaction`; not draft-11 wire shape. |
| D06-05 | Error table invents a resource-token `error` claim. |
| D07-02 | Call-chaining docs present `UpstreamTokenValidator` as the full upstream check; it covers steps 1-3 only (SDK-04). |
| D07-04 | R3 document shape given as `operations` + `display`; omits required `vocabulary`. |
| D07-05 | Sample pending endpoint uses invented `unknown_pending` 404 (A19-HIGH-004). |
| D08-01 | `error-handling.md:47-54` shows `SignatureError.Format` output without `error=`; actual output is `error=invalid_signature`. |
| D08-02 | Error-handling page omits revocation error codes. |
| D08-03 | `configuration.md` omits several options (`EgressPolicy`, `RequireBodyCoverage`, `ExpectedAccount`, metadata members). |
| D09-01, D10-05 | Resource DI docs and README present open auth-token trust as the "spec default" without the four-party caveat (SDK-02). |
| D10-01, D10-02, D10-04 | README / `SPEC-VERSION.md` claim revocation cascades, `202` auth-token delivery and R3 per-call as implemented to spec; SDK-05, SDK-11..13 and SDK-03 contradict. |
| D10-07 | Top-level docs do not state draft baseline / coverage consistently. |

LOW: D06-03 (federated `202 requirement=claims` example omits required
`Retry-After` / `Cache-Control: no-store`) plus 12 LOW items in the findings files
(links, wording, minor option naming). INFO: 5.

### Internal review (Phase 6)

A fresh `rubber-duck` reviewer re-checked SDK-01, 02, 03, 04, 05, 07, 15 and 16,
the three rejections, area coverage and counts. Outcomes are logged in
[implementation-log.md](implementation-log.md).

- **Accepted:**
  - SDK-01 upgraded to CRITICAL. It is an exploitable cross-resource bypass on a
    public, documented API.
  - A23-002 upgraded to HIGH (SDK-19). It is an unconditional MUST.
  - SDK-03 regraded MEDIUM. The SDK ships a `jti` single-use gate, so the defect
    is the uncomposed API plus the docs (DOC-06 stays HIGH).
  - SDK-07 regraded MEDIUM. Exploiting it needs a misbehaving host asserter.
    The remediation must key the binding on a stable internal person key, not
    the pairwise `sub`.
  - SDK-15 regraded MEDIUM. `TwoKey` needs explicit non-default composition, and
    `src/AAuth/EnrolledBuilder.cs:165-167` rejects it.
- **Accepted with note:** SDK-02 stays HIGH. The row now states that there is no
  explicit issuer-restriction MUST.
- **Confirmed unchanged:** SDK-04, SDK-05 and SDK-16 stay HIGH. All three
  rejections (A08-01, A11-02, A18-002) hold.
- **Coverage gap closed:** Signature-Key §7.2 Caching (L2357) and §7.3
  Scheme-Specific Risks (L2392) had no auditor. The reviewer spot-checked them:
  `src/AAuth/Discovery/DiscoveryCache.cs:24-35`, `:62-94` enforces capacity and
  a TTL floor, and `src/AAuth/HttpSig/SignatureKeyParser.cs:77-80` rejects `cnf`
  in `self-jwt`. Both are compliant. This is recorded as assessed (reviewer
  spot-check, not a full adversarial pass).
