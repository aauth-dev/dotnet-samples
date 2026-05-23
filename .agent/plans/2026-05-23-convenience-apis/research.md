# Convenience APIs — Research

## Problem Statement

The AAuth SDK exposes powerful low-level types but requires extensive manual
wiring for common workflows. A user implementing the three-party PS-asserted
flow must construct ~6 objects and thread them together (~20 lines). The same
applies to resource-managed interaction flows and server-side verification
setup.

## Spec Compliance Audit

> **Update (2026-05-23):** Validated all phases against
> `draft-hardt-oauth-aauth-protocol` and `draft-hardt-aauth-bootstrap`.

### Existing SDK Violations

| Issue | Spec Requirement | Current SDK | Fix Required |
|-------|-----------------|-------------|--------------|
| Default poll interval | "If a `Retry-After` header is not present, the default polling interval is 5 seconds" (§Deferred Responses) | `DeferredPollerOptions.DefaultPollInterval = 1s` | Change to 5s |

### Phase Compliance Summary

| Phase | Verdict | Notes |
|-------|---------|-------|
| 1. WithChallengeHandling | COMPLIANT | PS discovery from `ps` claim is correct per §PS-Asserted Access. 401 + `requirement=auth-token` + resource token in header matches spec. |
| 2. WithInteractionHandling | PARTIALLY COMPLIANT | Must handle both `requirement=interaction` (user URL) AND `requirement=approval` (no URL, poll-only). Default poll interval must be 5s. |
| 3. AddAAuthAgent DI | COMPLIANT | No spec constraints on internal lifecycle. Multiple tokens per agent is correct. |
| 4. AddAAuthResource | COMPLIANT | `issuer` + `jwks_uri` are the only REQUIRED metadata fields. JTI replay detection is OPTIONAL. |
| 5. Bootstrap | PARTIALLY COMPLIANT | Enrollment endpoint is NOT in AP metadata (`aauth-agent.json` has no `enrol_endpoint` field). SDK must take explicit endpoint, not discover it. |
| 6. Discovery | COMPLIANT | `JwksClient` already implements rate-limit (1 fetch/min) and cache (1h default). Spec-compliant. |

### Spec-Mandated Behaviors for Convenience APIs

**Challenge flow (§PS-Asserted Access, §Requirement Responses):**
- Agent discovers PS from `ps` claim in agent token (§Agent Tokens: "The agent
  token MAY include a `ps` claim identifying its person server").
- Resource returns `401 Unauthorized` with `AAuth-Requirement:
  requirement=auth-token; resource-token="<jwt>"`.
- Agent POSTs resource token to PS's `token_endpoint` (discovered from
  `/.well-known/aauth-person.json`).
- Exchange request MUST be signed with the agent token (not the auth token).
- PS may return 202 + `requirement=interaction` for deferred consent.

**Interaction flow (§Requirement Responses, §Deferred Responses):**
- `202 Accepted` + `AAuth-Requirement: requirement=interaction; url="...";
  code="..."` + `Location: /pending/xxx`.
- Agent constructs user-facing URL as `{url}?code={code}`.
- Agent polls `Location` with signed GETs.
- Default poll interval: 5 seconds (MUST).
- On 429: increase interval by 5s (linear backoff per RFC 8628 §3.5).
- `Prefer: wait=N` MAY be included for long-poll.

**Approval flow (§Approval Pending):**
- `202 Accepted` + `AAuth-Requirement: requirement=approval` +
  `Location: /pending/xxx` + `Retry-After: N`.
- No user URL — server handles approval via push/email/admin.
- Agent polls `Location` same as interaction.
- Response MUST include both `Location` and `Retry-After`.

**AP Metadata (`/.well-known/aauth-agent.json`):**
- REQUIRED: `issuer`, `jwks_uri`.
- OPTIONAL: `client_name`, `logo_uri`, `logo_dark_uri`, `callback_endpoint`,
  `login_endpoint`, `localhost_callback_allowed`, `tos_uri`, `policy_uri`.
- NO `enrol_endpoint` field. Enrollment is "AP-internal" per bootstrap spec.

**Resource Metadata (`/.well-known/aauth-resource.json`):**
- REQUIRED: `issuer`, `jwks_uri`.

**Capabilities header:**
- Agent sends `AAuth-Capabilities: interaction` to indicate it can handle
  `requirement=interaction`. Resources use this to decide response type.

## Existing Convenience Surface

| Type | Pattern | Coverage |
|------|---------|----------|
| `AAuthClientBuilder` | Fluent builder → `HttpClient` | Identity-based (HWK, JWKS, JWT, JKT-JWT) only |
| `AAuthHttpClientExtensions` | `services.AddAAuthClient("name", opts)` | DI for identity-based signing only |
| `AAuthSigningHandler.CreateClient()` | Static factory | One-liner for simple cases |
| `WellKnownEndpoints.MapAAuthResourceWellKnown()` | Extension on `IEndpointRouteBuilder` | Server metadata endpoints |
| Token builders (`AgentTokenBuilder`, etc.) | Init-only properties + `.Build()` | Complete — no changes needed |

## Gaps

### Agent-Side (Client)

1. **Three-party challenge flow** — `ChallengeHandler`, `TokenExchangeClient`,
   `AAuthTokenHolder`, and a separate exchange `HttpClient` must all be wired
   manually. No builder or DI support.
2. **Resource-managed interaction flow** — no handler intercepts 202 +
   `interaction` requirement automatically.
3. **AP bootstrap** — `AgentProviderClient` requires manual `HttpClient` and
   `IKeyStore` construction. No shorthand for "enrol and give me a ready
   client."
4. **Token holder lifecycle** — `AAuthTokenHolder` is created manually; no
   integration with DI scoped lifetimes.

### Server-Side (Resource / PS / AS)

5. **Verification middleware setup** — requires manual `AAuthVerifier` +
   `DefaultSignatureKeyResolver` + `JwksClient` + optional `IJtiStore`
   construction before calling `app.UseMiddleware<...>()`.
6. **Discovery client registration** — `MetadataClient` and `JwksClient` are
   instantiated ad-hoc; no shared singleton registration.

## AAuth Protocol Workflows (from spec)

| Workflow | Parties | Agent signing mode | Challenge? | Key SDK types needed |
|----------|---------|-------------------|------------|----------------------|
| Identity-based | Agent + Resource | `hwk` or `jwks_uri` | No | `AAuthSigningHandler` |
| Resource-managed | Agent + Resource + User | Any | 202 + interaction | `AAuthSigningHandler` + interaction handler |
| PS-asserted (3-party) | Agent + Resource + PS | `jwt` | 401 + resource token | `AAuthSigningHandler` + `ChallengeHandler` + `TokenExchangeClient` |
| Federated (4-party) | Agent + Resource + PS + AS | `jwt` | 401 + resource token | Same as PS-asserted (transparent to agent) |
| Deferred consent | Agent + Resource + PS | `jwt` | 401 → 202 + interaction at PS | PS-asserted + interaction callback |
| Bootstrap / enrollment | Agent + AP | N/A | N/A | `AgentProviderClient` + `IKeyStore` |

## Design Principles

- **Progressive disclosure**: simple things simple, complex things possible.
  `AAuthClientBuilder` remains the entry point; advanced options are opt-in
  method calls.
- **DI-friendly but not DI-required**: builders work standalone; DI extensions
  call the same builders internally.
- **No breaking changes**: existing constructors and patterns remain. New APIs
  are additive.
- **Workflow-centric naming**: method names map to protocol concepts
  (`WithChallengeHandling`, `WithInteractionHandling`, `Bootstrap`).

## Dependencies

- `Microsoft.Extensions.DependencyInjection.Abstractions` — needed for
  `IServiceCollection` extensions. Already transitively available via
  `Microsoft.AspNetCore.App` FrameworkReference.
- `Microsoft.Extensions.Http` — needed for `IHttpClientFactory` integration.
  Already transitively available.

## Open Questions

- [ ] Should the builder own the `AAuthTokenHolder` internally, or expose it
  for external observation (e.g., logging token transitions)?
- [ ] For DI registration, should named clients share a single `MetadataClient`
  singleton or each get their own?
- [ ] Should `WithInteractionHandling` also handle `requirement=approval`
  (server-side approval, no user URL to present)? **Likely yes** — spec treats
  them as the same polling primitive with different UX.

## Resolved Questions

- [x] Should `WithChallengeHandling()` automatically extract the PS URL from
  the agent token's `ps` claim, or always require it explicitly?
  **Resolution:** Support both. No-arg version reads `ps` claim; overload
  accepts explicit URL. Spec confirms PS is in the `ps` claim (§Agent Tokens).
- [x] Does the spec define an AP enrollment endpoint in metadata?
  **Resolution:** No. `aauth-agent.json` has no `enrol_endpoint`. The bootstrap
  spec says enrollment is "AP-internal." SDK must take explicit endpoint URL.
- [x] What is the spec-mandated default poll interval?
  **Resolution:** 5 seconds (§Deferred Responses). Current SDK has 1s — must fix.
- [x] Does `JwksClient` already meet spec caching requirements?
  **Resolution:** Yes. Already implements 1 fetch/min rate limit (matches spec
  "no more than once per minute") and 1-hour default cache TTL.
