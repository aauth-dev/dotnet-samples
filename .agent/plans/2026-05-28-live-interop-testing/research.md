# Live Interop Testing: Research Document

> Research-only. No implementation steps.
> Created 2026-05-28 as part of plan `2026-05-28-live-interop-testing`.
> Companion to [`implementation-plan.md`](./implementation-plan.md).

---

## 1. Live Servers Under Test

### 1.1 whoami.aauth.dev (Resource Server)

| Property | Value |
|---|---|
| Stack | Cloudflare Workers + Hono (TypeScript) |
| Key algorithm | Ed25519 |
| Signature-Key scheme | Only `jwt` accepted |
| Metadata | `https://whoami.aauth.dev/.well-known/aauth-access.json` |
| Source | [aauth-dev/whoami](https://github.com/nickhardware/whoami-aauth-dev) (inferred) |
| Behaviour on unsigned GET | 401 + `Accept-Signature` header |
| Behaviour on agent-token (scoped) | 401 + `AAuth-Requirement: requirement=auth-token, resource_token=<jwt>` |
| Behaviour on auth-token | 200 + identity claims JSON |
| Differences from local WhoAmI sample | No multi-path routing; no scope shortcut for unscoped; returns `Accept-Signature` |

### 1.2 person.hello.coop (Person Server)

| Property | Value |
|---|---|
| Metadata URL | `https://person.hello.coop/.well-known/aauth-person.json` |
| Token endpoint | `https://person.hello.coop/aauth/token` |
| Interaction endpoint | `https://person.hello.coop/auth` |
| JWKS URI | `https://issuer.hello.coop/.well-known/jwks.json` |
| Token exchange POST body (expected) | `{ resource_token, capabilities?, prompt?, provider_hint? }` |
| Deferred response | 202 + `Location` + `AAuth-Requirement: requirement=interaction, ...` |
| Error when no capabilities | `400 user_unreachable` with `"Agent has no interaction capability and user has no registered mobile devices"` |

### 1.3 web-agent.aauth.dev (Reference Agent)

| Property | Value |
|---|---|
| Role | Combined AP + agent server |
| Source | [nickhardware/web-agent-demo](https://github.com/nickhardware/web-agent-demo) (TypeScript) |
| Token exchange body | `{ resource_token, capabilities: ["interaction"], prompt: "consent", provider_hint: "email--" }` |
| Key | sends `capabilities: ["interaction"]` which is why PS returns 202 instead of 400 |

---

## 2. Protocol Flow Observations

### 2.1 Three Protocol Modes (as demonstrated)

```
Mode 1: GET (unsigned)
  → 401 + Accept-Signature: sig=("@method" "@authority" "@path" "signature-key");keyid="...";tag="aauth"

Mode 2a: GET + HTTP Signature + Signature-Key (agent_token, no scope)
  → 200 + { sub, ps } — agent identity echoed back, no PS involvement

Mode 2b: GET + HTTP Signature + Signature-Key (agent_token, with ?scope=email)
  → 401 + AAuth-Requirement: requirement=auth-token, resource_token=<compact-jwt>
  (Resource verified agent token via JWKS discovery at agent's issuer URL)

Mode 3: Full three-party exchange
  → Agent takes resource_token to PS token_endpoint (POST, signed)
  → PS returns 200 + { auth_token } (cached consent) OR
  → PS returns 202 + interaction requirement (first-time consent needed)
     → Agent polls Location URL while user approves
     → PS returns 200 + { auth_token }
  → Agent re-sends request with auth_token → 200 + claims
```

### 2.2 PS Token Exchange Body Requirements

The PS at `person.hello.coop` requires the following in the POST body:

| Field | Required | Description |
|---|---|---|
| `resource_token` | Yes | The compact JWT from the resource's `AAuth-Requirement` header |
| `capabilities` | Conditional | Array of strings; must include `"interaction"` if agent can handle redirects. Without it, PS returns `400 user_unreachable` if user has no push device |
| `prompt` | No | Hint to PS (e.g. `"consent"`) |
| `provider_hint` | No | Login provider hint (e.g. `"email--"`) |
| `upstream_token` | No | For call-chaining scenarios |

### 2.3 Agent JWKS Discovery

The resource server (whoami) discovers the agent's public key via:

1. Parses agent token JWT → extracts `iss` claim
2. Fetches `{iss}/.well-known/aauth-agent.json`
3. Reads `jwks_uri` from metadata
4. Fetches JWKS and finds key by `kid`
5. Verifies agent token signature

This requires the agent's issuer URL to be publicly reachable (hence cloudflared tunnel).

---

## 3. Gap Analysis (Spec References)

Each gap references the relevant AAuth spec section from `draft-hardt-oauth-aauth-protocol`.

### Gap A: Capabilities declaration at PS token endpoint

| Aspect | Detail |
|---|---|
| **Symptom** | PS returns `400 user_unreachable` |
| **Current fix** | Send `capabilities: ["interaction"]` in POST body when `onInteractionRequired` is non-null |
| **Spec §** | §AAuth-Capabilities Request Header (`#aauth-capabilities`, line 1756) |
| **Spec says** | "Agents SHOULD include the `AAuth-Capabilities` header on signed requests to **resources**. **The header is not used on requests to PS endpoints** — the PS learns the agent's capabilities through the mission approval flow." |
| **Spec token endpoint params §** | §Agent Token Request (`#ps-token-endpoint`, line 830): Lists `resource_token`, `upstream_token`, `justification`, `login_hint`, `tenant`, `domain_hint`, `platform`, `device`. Does NOT list `capabilities`. |
| **Spec error code** | §Token Endpoint Error Codes (line 2016): `interaction_required` (403) — "User interaction is needed but no interaction channel is available — the PS cannot reach the user and the agent does not have the `interaction` capability" |
| **PS actual behavior** | Returns `400 user_unreachable` (not in spec error table) when `capabilities` not in body |
| **Conclusion** | `capabilities` in the token exchange POST body is a **Hellō PS-specific extension**, not in the AAuth spec. The spec says capabilities are communicated via the `AAuth-Capabilities` HTTP header on requests to resources, and via mission approval for PSes. However, Hellō PS requires it in the body. |
| **TODO** | 1) Should SDK send `AAuth-Capabilities` header on POST to PS token_endpoint as well? 2) Or include `capabilities` in body as PS-specific? 3) Should be configurable? |

### Gap B: `prompt` / `provider_hint` in token exchange

| Aspect | Detail |
|---|---|
| **Symptom** | web-agent-demo sends these; our SDK doesn't |
| **Spec §** | §Agent Token Request (line 830) |
| **Spec says** | Token endpoint parameters are: `resource_token`, `upstream_token`, `justification`, `login_hint`, `tenant`, `domain_hint`, `platform`, `device`. No `prompt` or `provider_hint`. |
| **Conclusion** | `prompt` and `provider_hint` are **NOT in the AAuth spec**. They are Hellō PS-specific extensions. The spec provides `login_hint` for a similar purpose (hint about who to authorize, per OpenID Core §3.1.2.1). |
| **TODO** | 1) Support `login_hint` (spec-standard). 2) Support arbitrary extra body fields via extensibility hook for PS-specific params? |

### Gap C: `Accept-Signature` header parsing

| Aspect | Detail |
|---|---|
| **Symptom** | whoami returns `Accept-Signature` on unsigned 401; SDK ignores it |
| **Spec §** | §Covered Components (`#covered-components`, line 2087); §Incremental Adoption (line 2300); §Resource Metadata `additional_signature_components` (line 2281) |
| **Spec says** | Base covered components are `@method`, `@authority`, `@path`, `signature-key`. Resources MAY require additional via `additional_signature_components` in metadata. `Accept-Signature` is referenced as what resources return (per `I-D.hardt-httpbis-signature-key`) but the spec doesn't define agent behavior on receiving it. |
| **Accept-Signature definition** | Defined in the Signature-Key spec (`I-D.hardt-httpbis-signature-key`), not in the main AAuth protocol spec. It tells the agent what components to sign. |
| **Conclusion** | Agent SHOULD parse `Accept-Signature` to discover required components. The SDK's current defaults (`@method`, `@authority`, `@path`, `signature-key`) match what whoami expects, but a resource advertising different requirements would fail. |
| **TODO** | 1) Parse `Accept-Signature` on first 401 and adapt. 2) Also read `additional_signature_components` from resource metadata. 3) Priority: medium (works today against known resources). |

### Gap D: Interaction URL presentation

| Aspect | Detail |
|---|---|
| **Symptom** | SDK surfaces URL via callback; no built-in opener |
| **Spec §** | §User Interaction (line 893) |
| **Spec says** | "The agent constructs the user-facing URL as `{url}?code={code}` and directs the user using one of the methods defined in (#requirement-responses) (browser redirect, QR code, or display code)." Also: agent MAY append `callback` parameter. |
| **Conclusion** | Spec is intentionally vague about HOW the agent presents the URL. Library-level callback is correct. A convenience helper could auto-open browser for CLI scenarios. |
| **TODO** | Low priority. Consider a `DefaultInteractionPresenter` that calls `Process.Start` for desktop/CLI apps. |

### Gap E: PS error classification

| Aspect | Detail |
|---|---|
| **Symptom** | All PS errors thrown as `HttpRequestException`; `user_unreachable` info lost |
| **Spec §** | §Token Endpoint Error Response Format (`#error-response-format`, line 2000); §Token Endpoint Error Codes (line 2006); §Polling Error Codes (line 2024) |
| **Spec error codes** | `invalid_request` (400), `invalid_agent_token` (400), `expired_agent_token` (400), `invalid_resource_token` (400), `expired_resource_token` (400), `interaction_required` (403), `server_error` (500) |
| **Polling error codes** | `denied` (403), `abandoned` (403), `expired` (408), `invalid_code` (410), `slow_down` (429), `server_error` (500) |
| **PS actual** | Returns `user_unreachable` (not in spec) |
| **Conclusion** | SDK should parse JSON `error` + `error_description` and throw typed exceptions. Spec defines error codes that should be distinguishable. Hellō PS uses non-standard codes too. |
| **TODO** | 1) Parse JSON body on non-2xx before throwing. 2) `AAuthTokenExchangeException` with `ErrorCode` property. 3) Allow unknown error codes (PS-specific). |

### Gap F: Polling timeout configuration

| Aspect | Detail |
|---|---|
| **Symptom** | Default `MaxTotalWait=5min`; `PreferWaitSeconds=45` per the spec example |
| **Spec §** | §Deferred Responses (`#deferred-responses`, line 1906); spec example (line 857) shows `Prefer: wait=45` |
| **Spec says** | "The agent MUST respect `Retry-After` values. If a `Retry-After` header is not present, the default polling interval is 5 seconds." Spec does NOT define a max total polling budget. |
| **Spec polling errors** | `expired` (408) — "Timed out". The server decides when to expire. |
| **Conclusion** | The server controls timeout (via 408 `expired`). Client-side max budget is a safety net, not spec-mandated. 5 minutes is reasonable. The `Prefer: wait=45` is directly from the spec example. |
| **TODO** | Validated. Current defaults are fine. No change needed unless testing reveals issues. |

### Gap G: HttpClient.Timeout vs long-poll

| Aspect | Detail |
|---|---|
| **Symptom** | `TaskCanceledException` after 100s (HttpClient default) during a `Prefer: wait=45` long-poll |
| **Current fix** | Per-request CTS with `PreferWait+60s`; catch `TaskCanceledException` in `TokenExchangeClient` |
| **Spec §** | §Deferred Responses (line 1906) — `Prefer: wait=N` is standard |
| **Conclusion** | .NET implementation detail. The `HttpClient.Timeout` default (100s) conflicts with long-poll semantics. Fix is correct in principle but approach may change. |
| **TODO** | 1) Set `Timeout=InfiniteTimeSpan` on the exchange-specific HttpClient in the builder. 2) Remove per-request CTS workaround once root cause fixed. |

### Gap H: PS consent caching / `prompt` parameter

| Aspect | Detail |
|---|---|
| **Symptom** | 2nd run got auth_token immediately (200) without consent |
| **Spec §** | §Resource Token (line 784): "The PS SHOULD remember prior consent decisions within a mission so the user is not re-prompted when the agent resubmits a request for the same resource and scope." |
| **Spec says** | Consent caching is expected PS behavior (within a mission). No standard way to force re-consent. |
| **Reference behavior** | web-agent-demo sends `prompt: "consent"` (not in spec) to force the consent screen |
| **Conclusion** | Consent caching is per-spec. Forcing re-consent (`prompt: "consent"`) is a PS-specific extension. |
| **TODO** | Low priority. If needed, expose via the extensibility hook for PS-specific body fields (same as Gap B). |

### Gap I: `content-type` in covered components for POST

| Aspect | Detail |
|---|---|
| **Symptom** | SDK signs `@method`, `@authority`, `@path`, `signature-key` for all requests. web-agent-demo adds `content-type` for POST. |
| **Spec §** | §Covered Components (`#covered-components`, line 2087) |
| **Spec says** | "The signature MUST cover: `@method`, `@authority`, `@path`, `signature-key`." These are the REQUIRED components. `content-type` is NOT required. Resources MAY require additional via `additional_signature_components` metadata. |
| **Spec also says** | "Servers MAY require additional covered components (e.g., `content-digest` for request body integrity)." |
| **Conclusion** | SDK is spec-compliant. `content-type` is optional. web-agent-demo includes it as defense-in-depth but it's not required. |
| **TODO** | Low priority. Could auto-include `content-type` for body-bearing requests as best practice, but not a spec violation to omit. |

### Gap J: Exchange client HttpClient.Timeout

| Aspect | Detail |
|---|---|
| **Symptom** | Same root cause as Gap G — the exchange HttpClient has a 100s default timeout |
| **Spec §** | N/A — implementation detail |
| **Conclusion** | The builder should configure `Timeout = Timeout.InfiniteTimeSpan` on the signed HttpClient used for token exchange + polling, since those flows can legitimately take minutes. |
| **TODO** | Fix in builder. Related to Gap G — once this is fixed, the per-request CTS workaround in DeferredPoller can be simplified. |

---

## 4. Infrastructure Notes

### 4.1 cloudflared Quick Tunnel

- Binary: `/usr/local/bin/cloudflared` v2026.5.2
- No account required; generates random `*.trycloudflare.com` subdomain
- DNS propagation takes 3-15 seconds after tunnel starts
- Command: `cloudflared tunnel --url http://localhost:{port} --no-autoupdate`
- URL extracted from stderr via regex: `https://[a-z0-9\-]+\.trycloudflare\.com`

### 4.2 Dev Container Constraints

- No browser available inside container (headless)
- User must open interaction URLs on host machine
- `$BROWSER` variable available for host browser opening

---

## 5. Open Questions (Resolved)

| # | Question | Resolution |
|---|---|---|
| 1 | Are `prompt` and `provider_hint` standardized AAuth fields or Hellō-specific? | **`prompt` will be standard in -02** (OIDC values: `none`, `login`, `consent`, `select_account`). `provider_hint` stays Hellō-specific. |
| 2 | Does the PS accept capabilities beyond `"interaction"`? | **Spec defines:** `interaction`, `clarification`, `payment` (§AAuth-Capabilities, L1756). PS behavior unconfirmed for `clarification`/`payment`. |
| 3 | PS polling timeout - how long before expiring? | **Server-controlled.** Spec §Deferred Responses says server returns `expired` (408) when it decides. No client max mandated. |
| 4 | Does PS support `Prefer: wait=N` on initial POST or only polls? | **Both.** Spec example (L857) shows `Prefer: wait=45` on initial POST. Confirmed working with person.hello.coop. |
| 5 | What claims does whoami return for different scopes? | **Tested:** Returns `sub`, `iss` always. Scope-dependent claims not yet tested (whoami may not support scopes). |
| 6 | Is `capabilities` in POST body spec-standard or PS-specific? | **Will be standard in -02.** Spec lead confirmed body is the correct place. See §5b. |
| 7 | Is `user_unreachable` a valid error code? | **Yes, will be added in -02.** Distinct from `interaction_required`. See §5b. |

## 5a. Resolved: `capabilities` Header vs Body

> **Resolved 2026-05-30** - Spec lead confirmed our fix is correct. Will be standardized in -02.

Original discrepancy:

- **Spec -01** (§AAuth-Capabilities, L1776): "The header is not used on requests to PS endpoints - the PS learns the agent's capabilities through the mission approval flow."
- **Live PS** (person.hello.coop): Requires `capabilities: ["interaction"]` in the POST body.

**Resolution from spec lead:**

- `capabilities` belongs in the token request body, not headers.
- The `AAuth-Capabilities` header exclusion on PS endpoints (§12.1) stands - that header is for resource calls.
- Headers are only used where there's a conflict with a pre-existing API; for the PS token endpoint, body is correct.
- When a mission is active, the agent doesn't need to re-send `capabilities` (PS has them from approval flow) but MAY include them.
- **Spec -02 will list `capabilities` as a standard token endpoint parameter.**

**SDK action:** Current fix is correct. Promote from "partially fixed" to "confirmed correct".

## 5b. Spec Lead Response (2026-05-30)

Full clarification from spec lead on our three questions:

### `capabilities` in token endpoint body

- Will be added to §7.1.3 Agent Token Request as a standard OPTIONAL parameter.
- Array of strings from the capabilities registry (`interaction`, `clarification`, `payment`).
- Mission-less agents: MUST send if they need interaction. Mission agents: MAY send (PS already knows from approval).

### `user_unreachable` vs `interaction_required`

These are two **distinct** conditions:

| Error | Status | Type | Meaning |
|-------|--------|------|--------|
| `interaction_required` | 202 | Non-terminal | PS needs the agent to direct the user somewhere (URL + code). Polling continues. |
| `user_unreachable` | 400 | Terminal | PS has no channel to the user AND agent didn't declare `interaction`. Hard stop. |

- `user_unreachable` will be added to the spec error table in -02.
- Hellourrent behavior is correct.

### `prompt` parameter

- Will be added to §7.1.3 in -02 with OIDC values: `none`, `login`, `consent`, `select_account`.
- Consistent with spec already reusing OIDC vocabulary for `login_hint`, `tenant`, `domain_hint`.
- `provider_hint` stays Hellospecific (steers between consumer providers, doesn't generalize).

---

## 6. Web-Agent-Demo Parity Analysis

> **Update (2026-05-28):** Confirmed all modes work end-to-end. Added Mode 2a.
> PS caches consent — second run got auth_token immediately (200) without interaction.

### 6.1 Reference Agent Covered Components

| Request type | Components signed |
|---|---|
| GET (all modes) | `@method`, `@authority`, `@path`, `signature-key` |
| POST with body | `@method`, `@authority`, `@path`, `content-type`, `signature-key` |

**Gap I**: Our SDK always signs `@method`, `@authority`, `@path`, `signature-key` regardless of request type. The reference adds `content-type` for POST requests with body.

### 6.2 Reference Agent PS Token Exchange Body

```json
{
  "resource_token": "<compact-jwt>",
  "capabilities": ["interaction"],
  "prompt": "consent",
  "provider_hint": "email--"
}
```

Our SDK sends:
```json
{
  "resource_token": "<compact-jwt>",
  "capabilities": ["interaction"]
}
```

### 6.3 Reference Agent Long-Poll Configuration

- `POLL_WAIT_SECONDS = 45` (sent as `Prefer: wait=45` on GET to pending URL)
- No explicit max total wait — loops indefinitely on 202
- On network error: waits 5 seconds then retries

### 6.4 Reference Agent Signing Modes

| Flow | Signature scheme |
|---|---|
| Bootstrap POST | `sig=hwk` (bare key, no JWT) |
| Refresh POST | `sig=hwk` |
| Agent forget POST | `sig=hwk` |
| Whoami GET (agent_token) | `sig=jwt` (jwt=agent_token) |
| PS token exchange POST | `sig=jwt` (jwt=agent_token) |
| Poll GET | `sig=jwt` (jwt=agent_token) |
| Whoami GET (auth_token) | `sig=jwt` (jwt=auth_token) |

### 6.5 Confirmed Behaviors

- ✅ Unscoped GET with valid agent_token → 200 with `{ sub, ps }`
- ✅ Scoped GET → 401 + resource_token
- ✅ Capabilities: `["interaction"]` is required for the PS to return 202 instead of 400
- ✅ PS caches consent — subsequent requests get 200 immediately (no interaction)
- ✅ Poll uses `Prefer: wait=45` — PS holds connection open (long-poll semantics)
- ✅ On 200 from PS, response body is `{ auth_token: "<compact-jwt>" }`

---

## 7. Phase 5: Edge Case Validation (2026-05-30)

Audited each edge case against the implemented SDK and existing tests. Most
were already covered; findings below.

| # | Edge case | Status | Implementation / Test |
|---|---|---|---|
| 1 | Interaction timeout (user never approves) → timeout | ✅ Covered | `DeferredPoller.PollAsync` throws `TimeoutException` on `MaxTotalWait`; `TokenExchangeClient` wraps as `AAuthInteractionTimeoutException`. Tests: `DeferredPollerTests`, `InteractionHandlerTests.TimesOut_WhenPollKeepsReturning202`. |
| 2 | User explicitly denies → terminal | ✅ Covered | `TokenExchangeClient` maps `403 + access_denied` to `AAuthInteractionDeniedException`. Tests: `MockPersonServerConsentTests`, `WhoAmIFlowTests` deny path. |
| 3 | `user_unreachable` (400, terminal) | ✅ Fixed | Added explicit `TokenErrorCode.UserUnreachable` (wire `user_unreachable`); `AAuthTokenExchangeException.IsTerminalCode` returns terminal. Tests: `TokenErrorTests.UserUnreachable_IsTerminal`, `ChallengeHandlerTests.Exchange_NonSuccessWithErrorBody_ThrowsTyped` inline case. |
| 4 | Expired / revoked agent keys | ✅ Covered | `SignatureErrorCode.ExpiredJwt`; expiry validated in middleware (clock-skew aware). Tests: `TokenVerifierTests.Verify_RejectsExpiredToken`, `AAuthVerifierTests.Verify_RejectsExpiredCreated`. |
| 5 | Mismatched `kid` (unknown_key) | ✅ Covered | `JwksClient.ResolveKeyAsync` returns null for unknown kid (rate-limited refresh); resolver raises `unknown_key`. Tests: `JwksClientTests` unknown-kid + refresh cases. |
| 6 | Different scope values | ⚪ Out of scope | Scope is a resource-token / response concern (`ResourceTokenBuilder.Scope`, `AuthTokenResponseValidator`), not an agent-supplied token-endpoint param. Spec §7.1.3 token-endpoint params do not include `scope`; not added speculatively. Live scope behavior remains a manual LiveWhoAmITest concern. |

**New gap register entries:** none. Item 3 was already in scope under Gap E (upcoming-changes-02 item 2); it is now explicit rather than incidental. Item 6 confirmed out of scope.

## 8. Phase 6: Documentation Validation (2026-05-30)

Dispatched 6 parallel Explore subagents covering all Markdown, GuidedTour `CodeSnippets.cs`, SampleApp code, and `upcoming-changes-02.md`. Each finding was re-verified against source before applying. Stylistic `using`-omission complaints were rejected (consistent docs convention).

| File | Inaccuracy | Fix |
|---|---|---|
| `docs/README.md` | `TokenError`/`PollingError` type names wrong | `TokenErrorResponse`/`PollingErrorException`; added `AAuthTokenExchangeException` row |
| `docs/reference/configuration.md` | `MetadataCacheDuration`/`JwksCacheDuration` wrong; JWKS default wrong; ChallengeHandlingOptions table incomplete | Renamed to `*CacheTtl`, added `JwksMinRefreshInterval`, JWKS default 1h, completed options table |
| `docs/reference/dependency-injection.md` | Same `*CacheDuration` names + default | Renamed to `*CacheTtl`, JWKS default 1h |
| `docs/server/verification-middleware.md` | Error-code table incomplete; `expired` not a wire code | Listed all 8 `SignatureErrorCode` wire codes incl. `expired_jwt`, `invalid_input` |
| `docs/server/token-issuance.md` | Used `WWW-Authenticate: AAuth resource_token=...` | Use `context.ChallengeAAuth(resourceToken)` (sets `AAuth-Requirement`) |
| `docs/workflows/call-chaining.md` | `ExchangeAsync` skipped required `onInteractionRequired` positional param | Added `onInteractionRequired: null` |
| `samples/GuidedTour/CodeSnippets.cs` | `SelfSignAgentToken` missing `required` `KeyId` | Added `KeyId = "sample-key-1"` |

Confirmed accurate (no change): root `README.md`, `concepts.md`, `getting-started.md`, `docs/advanced/*`, remaining `docs/server/*` (incl. `resource-metadata.md` correctly omitting `additional_signature_components`), all `docs/signing-modes/*`, remaining `docs/workflows/*`, all sample READMEs, SampleApp code, and `upcoming-changes-02.md` (all 3 items implemented).

Validation: full solution builds clean (0 warnings/errors); 320 unit + 342 conformance tests pass.

## 9. PR #27 Review Findings (2026-05-31)

Two independent review passes against PR #27 (branch `feat/live-interop-testing`): (a) the GitHub automated reviewer (`copilot-pull-request-reviewer`, 4 inline comments) and (b) an internal PR Review subagent run spec-first then SDK. The internal pass corroborated all 4 external comments and surfaced additional findings. Each item below was verified against the spec (`aauth-spec/draft-hardt-oauth-aauth-protocol.md` §Covered Components L2098, §Verification L2111, `additional_signature_components` L2266-2281) and the SDK source.

### 9.1 Consolidated Findings Table

| ID | Severity | File / Location | Issue | Source | Status |
|---|---|---|---|---|---|
| H1 | High | `src/AAuth/Agent/TokenExchangeClient.cs` ~L88-96 | `ExchangeAsync` full overload inserts optional `capabilities`/`prompt` before `CancellationToken` — source + binary break; positional `cancellationToken` callers now bind to `capabilities` (compile error). All internal call sites already switched to named `cancellationToken:`. | External #3 + internal | Fixed (7.3) |
| H2 | High | `src/AAuth/HttpSig/AAuthSigningHandler.cs` ~L256-271 (`ResolveAdditionalComponents`) | Adaptive learn-and-retry throws `InvalidOperationException` when a required component has no header. SDK never computes `Content-Digest`, yet that is the spec's canonical additional component (L2098, L2266). Retry throws instead of satisfying a resource demanding `content-digest` on a body request. | Internal only (new) | Fixed (7.1) |
| M1 | Medium | `src/AAuth/Agent/ChallengeHandler.cs` ~L303 (`SeedAdditionalComponents`) | Unconditional `request.Options.Set(AdditionalComponentsKey, components)` clobbers any caller-set per-request components. `MergeComponents` (~L311) exists but is not consulted here. | External #2 + internal | Fixed (7.2) |
| M2 | Medium | `src/AAuth/Agent/ChallengeHandler.cs` ~L334 (`CloneAsync`) | Clone intentionally omits `HttpRequestMessage.Options`. Mitigated for AAuth's own key (re-applied on both retry paths) but loses any other request-scoped option (Polly context, telemetry, caller-set key). | External #1 + internal | Fixed (7.2) |
| M3 | Medium | `src/AAuth/Agent/DeferredPoller.cs` ~L119-122 | Inline comment asserts the HttpClient is always `Timeout.InfiniteTimeSpan`, but the class is `public` and constructible with any `HttpClient`. `MaxTotalWait` only gates between polls, so a default client (100s) with `PreferWaitSeconds > ~100` aborts an in-flight long-poll with an uncaught `TaskCanceledException`. | External #4 + internal | Fixed (7.4) |
| L1 | Low | `src/AAuth/Agent/ChallengeHandler.cs` ~L255-257 | `_learnedComponents` read-modify-write not atomic; concurrent 401s for one origin race (last-writer-wins). Benign — both produce supersets. Could use `AddOrUpdate`. | Internal only | Fixed (7.5) |
| L2 | Low | `src/AAuth/Errors/SignatureError.cs` ~L111-135 (`ParseRequiredInput`) | Naive `IndexOf("required_input")` could match a token like `x-required_input`. Fine for own output; word-boundary/`;`-split parse more robust vs third-party servers. | Internal only | Fixed (7.5) |
| L3 | Nit | `src/AAuth/Errors/AAuthTokenExchangeException.cs` ~L52-53 | `IsTerminalCode` marks `interaction_required` terminal; per `upcoming-changes-02.md` it is 202/non-terminal. Currently unreachable (only runs on `!IsSuccessStatusCode`; 202 is success). Worth a comment. | Internal only | Fixed (7.5) |
| L4 | Nit | `samples/LiveWhoAmITest/Program.cs` ~L78-93 | `tunnelProcess` (`IDisposable`) never disposed; `Kill()`/`StopAsync()` not in `finally` — leaks tunnel + Kestrel if an exception precedes cleanup. Per-mode `HttpResponseMessage`s not disposed. Demo-only. | Internal only | Fixed (7.5) |
| L5 | Nit | `.devcontainer/post-create.sh` ~L36 | Stray blank-line removal adjacent to cloudflared block; cosmetic. cloudflared install correctly uses `signed-by` keyring and is idempotent. | Internal only | Fixed (7.5) |

### 9.2 External Comment Accuracy Verdicts

All four GitHub-reviewer comments were accurate (no false positives), though two were narrower or softer than stated:

- **#1 (CloneAsync drops Options):** Valid but narrow. High-level paths (metadata `AdditionalSignatureComponents` dict + runtime `_learnedComponents` cache) survive because the cloned request is re-seeded; only a caller-set low-level `AdditionalComponentsKey` not also in dict/cache is genuinely lost. = M2.
- **#2 (SeedAdditionalComponents overwrites):** Valid. Same root cause as #1 — the public per-request option is not treated as an additive input. = M1.
- **#3 (ExchangeAsync ordering):** Valid, but the comment's "now binds to `capabilities`" implies a silent rebind; it is a *compile-time* break (`CancellationToken` not convertible to `IReadOnlyList<string>?`), not silent. Internal pass adds the binary-compat angle. = H1.
- **#4 (DeferredPoller comment):** Valid, doc-only at minimum; internal pass shows a real abort risk for external callers using a default client. = M3.

### 9.3 Confirmed Correct (both passes)

`capabilities`/`prompt` sent in the token request *body* (matches `upcoming-changes-02.md` L17-31; `AAuth-Capabilities` header stays resource-only); `"interaction"` capability inference from a wired callback (overridable); `user_unreachable` distinct terminal code (400/terminal per spec delta); `AdditionalComponentsKey` signing logic (RFC 9421 §2.1 ordering, base-component de-dup, `", "` multi-value join); issuer formatting (scheme+host, lowercased, no trailing slash, §Identifiers); non-JSON error-body fallback to `HttpRequestException`; no injected secrets.

### 9.4 Recommended Remediation Order

1. **H2** — spec-correctness gap (new): implement `Content-Digest` (RFC 9530) when required, or downgrade the hard throw to an actionable error naming the unmet component + origin and document the caller-pre-populate contract.
2. **M1 + M2** — one cohesive fix: treat per-request `AdditionalComponentsKey` as an additive merge input on both seed and clone (reuse `MergeComponents`); copy or deliberately reset `Options` on the clone with an accurate comment.
3. **M3** — reword the comment to a requirement and/or enforce a per-request linked CTS.
4. **H1** — add a back-compat overload or a `TokenExchangeRequest` options object (decision gated on whether the alpha SDK offers source-compat guarantees).
5. **L1-L5** — cleanup pass.

