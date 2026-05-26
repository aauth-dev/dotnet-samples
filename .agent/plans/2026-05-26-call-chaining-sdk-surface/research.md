# Call-Chaining SDK Surface — Research

## Problem Statement

The Orchestrator sample hand-rolls the entire call-chaining state machine:
type-switch on `ParsedSignatureKeyInfo`, manual `ResourceTokenBuilder` +
`AAuth-Requirement` formatting, manual 401-parse / `TokenExchangeClient` wiring /
second `AAuthClientBuilder().UseJwt(...)` retry. The SDK ships most of the pieces
but lacks a composable API layer that ties them together for intermediary
(resource-as-agent) scenarios.

PR #18 (`copilot/analyze-call-chaining`) attempted this simplification but raised
spec-compliance concerns. This research validates the correct approach against the
protocol specification.

## Source Documents

| Document | Location | Relevant Sections |
|----------|----------|-------------------|
| AAuth Protocol | `aauth-spec/draft-hardt-oauth-aauth-protocol.md` | §Call Chaining, §Upstream Token Verification, §Interaction Chaining, §Multi-Hop Resource Access, §Call Chaining Identity, §Auth Token Structure (`act` claim), §PS Token Endpoint |
| AAuth Bootstrap | `aauth-spec/draft-hardt-aauth-bootstrap.md` | Enrollment only (not chaining-related) |
| Four-Party Call Chaining flow | Appendix: Detailed Flows § Four-Party: Call Chaining | Full sequence diagram |

## Spec Analysis: §Call Chaining (normative)

### Routing Rules (MUST-level)

When a resource needs to access a downstream resource on behalf of the caller,
it determines where to send the downstream token request based on the upstream
auth token it received:

| Priority | Condition | Target |
|----------|-----------|--------|
| 1 | `mission.approver` present in upstream auth token | PS at `mission.approver` URL |
| 2 | No mission, `iss` is a PS (three-party upstream) | PS at `iss` |
| 3 | No mission, `iss` is an AS (four-party upstream) | AS at `iss` |

**Key insight:** The router does NOT need to distinguish PS from AS — the
`TokenExchangeClient` resolves the correct metadata document (`aauth-person.json`
or `aauth-access.json`) based on server discovery. Routes 2 and 3 collapse to
"use `iss`" at routing time.

**Security constraint:** If `mission.approver` is present but violates
https-or-loopback policy, the implementation MUST fail rather than silently
falling through to `iss`. This prevents a compromised upstream from re-routing a
chained request to a different governance authority.

### PS Token Endpoint Requirements for Call Chaining

The intermediary's exchange request MUST include:

| Parameter | Delivery Mechanism | Notes |
|-----------|-------------------|-------|
| `resource_token` | JSON body field | From the downstream resource's 401 challenge |
| `upstream_token` | JSON body field | The caller's auth token (already verified by inbound middleware) |
| agent identity | HTTP Message Signature (RFC 9421) | The intermediary signs with its OWN agent key; agent token presented via `Signature-Key: sig=jwt` |

**Critical:** The agent token is NOT a body field — it is proved via the HTTP
signature on the exchange request. The SDK already implements this correctly:
`TokenExchangeClient` uses a `_signedClient` that has an `AAuthSigningHandler`
pinned to the intermediary's agent key.

### Upstream Token Verification (PS-side, informational)

When the PS receives `upstream_token`:

1. Auth Token Verification on the upstream token.
2. Verify `iss` is a trusted AS.
3. Verify `aud` in upstream token matches the resource now acting as agent.
4. Construct nested `act` claim: wrap upstream `act` inside new `act` for intermediary.
5. Evaluate mission/governance policy.

**SDK implication:** The SDK does not implement PS-side logic. The SDK's
responsibility is to correctly send `upstream_token` — the PS builds the nested
`act`.

### Auth Token `act` Claim (§Auth Token Structure)

> "In call chaining, `act` nests to record the full delegation chain — each
> intermediary's identity is preserved as a nested `act` claim within the outer
> `act`."

**SDK implication:** The SDK does NOT synthesize `act` claims. The PS does.
The SDK reads `act` for verification only (max depth 10 in `TokenVerifier`).

### Call Chaining Identity (MUST)

> "The resource MUST publish agent metadata at `/.well-known/aauth-agent.json`
> so that downstream resources and ASes can verify its identity."

**SDK implication:** Cannot be enforced by library code. Must be documented as a
deployment requirement.

## Spec Analysis: §Interaction Chaining (normative)

> "When a resource acting as an agent receives a `202 Accepted` response with
> `AAuth-Requirement: requirement=interaction`, and the resource needs to
> propagate this interaction requirement to its caller, it MUST return a
> `202 Accepted` response to the original agent with its own
> `AAuth-Requirement` header containing `requirement=interaction` and its own
> interaction code."

**Implications for SDK:**

1. The intermediary must NOT simply throw on a 202 from the PS exchange.
2. It must be able to surface the interaction requirement back to the caller.
3. This requires request-level lifecycle management (pending URLs, polling).

**Design options:**

| Option | Pros | Cons |
|--------|------|------|
| A: `ChallengeHandler` propagates 202 as HTTP 202 to original caller | Fully automated, spec-compliant | Complex; requires the handler to know the HTTP context of the original request |
| B: `ExchangeForDownstreamAsync` accepts `onInteractionRequired` callback | Explicit; app decides propagation strategy | Not fully automated; app must wire 202 return |
| C: Hybrid — automatic propagation with opt-out | Best of both | Highest complexity |

**Recommended:** Option B (matches PR #18 approach) + document interaction
chaining as a separate advanced scenario. Automatic propagation (Option A) can
be a later phase.

## Spec Analysis: §Deferred Responses (applies to call chaining)

> "The following state machine applies to any AAuth endpoint that returns a
> `202 Accepted` response — including PS token endpoints, AS token endpoints,
> and resource endpoints during call chaining."

The existing `DeferredPoller` already implements this state machine with a 5s
default interval. The call-chaining exchange path MUST use the same poller
infrastructure.

## Spec Analysis: AAuth-Mission Header

The `AAuth-Mission` request header is emitted by agents on requests to resources.
It contains `approver` and `s256` fields.

**For an intermediary:**

- The upstream auth token may contain `mission.approver` and `mission.s256` — these
  inform routing decisions.
- The intermediary SHOULD forward `AAuth-Mission` on its downstream request when
  `mission.approver` is present in the upstream auth token — this preserves
  governance context through the full call chain.
- The SDK provides a `MissionForwardingHandler` that auto-emits the header when
  the upstream token carries mission context. The handler is opt-in via pipeline
  wiring (not silently injected).

> **Update (2026-05):** Earlier analysis stated "the SDK MUST NOT synthesize
> or strip `AAuth-Mission` automatically." Revised: the spec does not prohibit
> forwarding existing mission context. The SDK auto-forwards (does not
> synthesize new missions) when mission.approver is present. This is consistent
> with §Call Chaining routing which already keys on mission.approver.

## PR #18 Spec Compliance Assessment

### Items that are Spec-Correct

| Item | Verdict | Reasoning |
|------|---------|-----------|
| `CallChainingRouter.ResolveDownstreamServer` | ✅ PASS | Three routes correct; PS/AS differentiation deferred to metadata discovery |
| Token exchange plumbing (resource_token + upstream_token + agent sig) | ✅ PASS | `TokenExchangeClient` already handles all three components |
| `UpstreamAuthTokenFeature` exposure after verification | ✅ PASS | Middleware verifies first; feature is a convenience accessor |
| `UseAAuthIntermediary` composition | ✅ PASS | Just `UseAAuthVerification` + `UseAAuthChallenge` in correct order |
| AAuth-Mission left to application | ✅ PASS | Spec does not require SDK automation of mission header |
| Agent metadata not SDK-enforced | ✅ PASS | Deployment requirement; cannot be library-enforced |

### Items with Spec Concerns

| Item | Concern | Risk | Mitigation |
|------|---------|------|------------|
| Interaction chaining (202 propagation) | PR #18 adds `onInteractionRequired` callback but doesn't automate 202 propagation to original caller | Medium — intermediaries that hit deferred consent will fail without explicit handling | Document as advanced scenario; provide `onInteractionRequired` callback; add interaction-chaining sample later |
| `WithCallChaining` implicitly enables `WithChallengeHandling` | PR #18 auto-enables challenge when `upstreamTokenProvider` is set | Low — reasonable ergonomic choice; challenge is always needed for call chaining | Keep implicit enable; document the coupling |
| `personServer` becomes nullable on `ChallengeHandler` | PR #18 makes `personServer` nullable when `upstreamTokenProvider` is set | Low — spec routing supersedes static PS when upstream token is present | Add validation: at least one of personServer or upstreamTokenProvider required |
| No `Prefer: wait=N` on exchange request | SDK doesn't send `Prefer` header on PS exchange | Low — spec says "agent signals its willingness to wait using the Prefer header" but not MUST | Add `Prefer: wait=45` by default in future phase |

### Items Missing from PR #18 (Gaps)

| Gap | Spec Requirement | Priority |
|-----|-----------------|----------|
| `mission.approver` validation fail-fast | Invalid approver MUST error, not fall through to `iss` | P1 — security |
| Tests for routing edge cases | Malformed JWT, missing iss, invalid approver URL | P1 — correctness |
| Interaction chaining sample | Show 202 propagation in orchestrator scenario | P2 — completeness |
| `Prefer: wait=N` on exchange | Spec recommends signaling wait willingness | P3 — polish |

## Existing SDK Components to Reuse

| Component | Location | Role in Call Chaining |
|-----------|----------|---------------------|
| `TokenExchangeClient` | `src/AAuth/Agent/TokenExchangeClient.cs` | Sends resource_token + upstream_token to PS; signs with agent key |
| `ChallengeHandler` | `src/AAuth/Agent/ChallengeHandler.cs` | Intercepts 401 from downstream, triggers exchange, retries |
| `AAuthSigningHandler` | `src/AAuth/HttpSig/AAuthSigningHandler.cs` | Signs outbound requests with agent key |
| `AAuthClientBuilder` | `src/AAuth/HttpSig/AAuthClientBuilder.cs` | Fluent builder composing handler pipeline |
| `AAuthVerificationMiddleware` | `src/AAuth/Server/AAuthVerificationMiddleware.cs` | Verifies inbound signatures + JWT issuer |
| `AAuthChallengeMiddleware` | `src/AAuth/Server/AAuthChallengeMiddleware.cs` | Auto-issues 401 + resource token for agent tokens |
| `DeferredPoller` | `src/AAuth/Agent/DeferredPoller.cs` | 202 polling state machine (5s default) |
| `MetadataClient` | `src/AAuth/Discovery/MetadataClient.cs` | Discovers PS/AS metadata including token_endpoint |
| `AAuthUrl` | `src/AAuth/AAuthUrl.cs` | HTTPS-or-loopback URL validation |

## Configuration & Testability Concerns

Multiple SDK components instantiate dependencies with hardcoded defaults that are
not exposed through any public options surface:

| Component | Hidden Setting | Default | Impact |
|-----------|---------------|---------|--------|
| `TokenVerifier` | `MaxActDepth` | 10 | Cannot tune chain depth limit |
| `TokenVerifier` | `ClockSkew` | 30s | Cannot tune temporal tolerance |
| `AAuthVerifier` | `MaxFutureSkew` | 5s | Cannot tune NTP drift tolerance |
| `DeferredPoller` | `MinPollInterval` | 100ms | Cannot prevent tight-loop polling |
| `DeferredPoller` | `OnPoll` | null | No observability hook |
| All above + `JwksClient`, `MetadataClient`, `AAuthSigningHandler` | `Clock` | `() => UtcNow` | Cannot inject test clocks |

**Design principle:** Every behavioral parameter must be reachable from the
public entry point that constructs the component — either `AAuthVerificationOptions`
(server-side) or `AAuthClientBuilder` / `ChallengeHandlingOptions` (client-side).
Clock injection enables deterministic unit tests without `Thread.Sleep`.

## Open Questions

1. **Should `WithCallChaining` require explicit `WithChallengeHandling()` call?**
   PR #18 proposes implicit enable. The spec always requires a challenge for
   call chaining, so implicit is more ergonomic and prevents misconfiguration.
   **Recommendation:** Implicit enable (match PR #18).

2. **Should `CallChainingRouter` live in `AAuth.Server` or `AAuth.Agent`?**
   It's agent-side logic (the intermediary acting as agent decides where to send
   the exchange). However it reads claims from an inbound auth token (server
   context). **Recommendation:** Keep in `AAuth.Server` — it's used by
   intermediaries which are server-side code.

3. **Should the SDK auto-propagate 202/interaction back to the original caller?**
   This requires deep integration with ASP.NET Core's request pipeline (writing
   202 responses, managing pending URLs). **Recommendation:** Phase 1 provides
   the callback; Phase 2 (future) adds automatic propagation middleware.
