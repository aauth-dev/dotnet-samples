# Research — AAuth-Access opaque-token flow (resource-managed authorization)

Research-only document for a future initiative: adding the draft-08
**`AAuth-Access`** opaque-token flow (the `aauth-access-token` access mode) to the
.NET AAuth SDK. Spun off from the
[2026-06-25 draft-08 migration](../2026-06-25-aauth-v08-spec-migration/implementation-plan.md),
whose Phase 3 recorded that the SDK has **no** `Authorization: AAuth` /
`AAuth-Access` consumption or production path, so the draft-08 `token68`
validation had nothing to attach to (see that plan's Phase 3 deviation).

Spec source: [`aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md`](../../../aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md).
No implementation steps here — see [`implementation-plan.md`](implementation-plan.md).

## Research method

Read the draft-08 `AAuth-Access` sections directly and re-verified every line
citation against the vendored spec. Audited the current SDK signing/verification
and challenge surfaces with workspace search + file reads. All claims below were
verified against source (no subagent delegation); line numbers are precise to the
current vendor and the `{#anchor}` is the durable reference.

## Spec summary (verified)

### The `AAuth-Access` response header (`#aauth-access`, L738)

- A resource MAY hand the agent an **opaque** access token via the `AAuth-Access`
  response header after it authorizes the agent itself; the agent replays it on
  later requests as `Authorization: AAuth <token68>` (`#aauth-access`, L738–745).
- The token wraps the resource's internal authorization state (which MAY be an
  existing OAuth access token); it is opaque to the agent (L740).
- **Binding (MUST):** the agent MUST include `authorization` in the covered
  components of its HTTP Message Signature, binding the opaque token to the signed
  request — it is useless as a standalone bearer token without a valid AAuth
  signature (L753; restated in **AAuth-Access Security**, L2712–2714).
- **Rolling refresh:** a resource MAY return a new `AAuth-Access` on any response;
  the agent MUST switch to the new value on subsequent requests — no explicit
  refresh flow (L754).
- **`token68` grammar (MUST):** the `AAuth-Access` value, and the
  `Authorization: AAuth` credential, is a `token68` ([@!RFC9110] §11.2).
  Recipients MUST reject empty values, values with embedded whitespace or control
  characters, and messages carrying more than one credential (L756).

### Resource-managed authorization handshake (`#resource-managed-auth`, L758)

- The resource manages authorization itself. When it needs the user, it returns
  `202 Accepted` with `AAuth-Requirement: requirement=interaction; url=…; code=…`
  (L758–776), the agent drives the user through the resource's own consent/login
  flow and polls the `Location` per the deferred-response pattern, and on
  completion the resource returns `200 OK` and MAY include `AAuth-Access` (L776).
- A resource MAY also authorize on identity alone (no interaction) and still
  return `AAuth-Access` (L778).
- Advertised via resource metadata `access_mode = "aauth-access-token"` (L2642):
  the agent's call (or a hit on `authorization_endpoint`) triggers the `202`
  interaction, then the resource issues the opaque token.

### Fully-bound request shape (L743–751, example L2343–2348)

```http
GET /api/data HTTP/1.1
Host: resource.example
Authorization: AAuth wrapped-opaque-token-value
Signature-Input: sig=("@method" "@authority" "@path" \
    "authorization" "signature-key");created=1730217600
Signature: sig=:...:
Signature-Key: sig=jwt;jwt="eyJhbGc..."
```

`Signature-Key` still carries the auth token (four-party) or agent token whose
`cnf.jwk` is the signing key; `authorization` is an *additional* covered
component. Authorization still depends on the auth-token claims + resource
enforcement — the opaque token proves only that the resource previously
authorized this agent (L2343).

## Current SDK state (audited)

- ❌ **No production path.** No SDK code emits an `AAuth-Access` response header,
  and the resource verification/challenge pipeline
  ([Server/Verification/AAuthVerificationMiddleware.cs](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs),
  [Headers/AAuthRequirementHeader.cs](../../../src/AAuth/Headers/AAuthRequirementHeader.cs))
  has no opaque-token issuance.
- ❌ **No consumption path.** No SDK code reads `Authorization: AAuth`, and the
  agent signing handler
  ([HttpSig/AAuthSigningHandler.cs](../../../src/AAuth/HttpSig/AAuthSigningHandler.cs))
  does not store/replay an `AAuth-Access` value nor add `authorization` to the
  covered components.
- ✅ **Adjacent machinery exists.** The deferred-response poller
  ([Agent/DeferredPoller.cs](../../../src/AAuth/Agent/DeferredPoller.cs)) and the
  interaction projection ([Headers/Interaction.cs](../../../src/AAuth/Headers/Interaction.cs))
  already drive `202 + requirement=interaction → poll → 200`, which the
  resource-managed handshake reuses; only the trailing `AAuth-Access` capture +
  replay is missing.
- ✅ **`access_mode` is already modeled** on resource metadata
  ([Server/Metadata/WellKnownEndpoints.cs](../../../src/AAuth/Server/Metadata/WellKnownEndpoints.cs)
  `AccessMode`), including the `aauth-access-token` value.

## SDK touch-point inventory

Agent side:

- A `token68` parse/validate helper (reject empty / embedded whitespace / control
  chars; one credential only) — likely beside
  [Errors/](../../../src/AAuth/Errors/) or a new `Headers/AAuthAccessToken.cs`.
- Capture the `AAuth-Access` response header on every response, store the latest
  value per resource origin, and replay it as `Authorization: AAuth …` on the next
  request — a small per-origin store wired into the agent's `DelegatingHandler`
  chain near `AAuthSigningHandler`.
- Add `authorization` to the HTTP Message Signature covered components **when** an
  `AAuth-Access` token is present (the signer must cover the header it sends).

Resource side:

- Issue an `AAuth-Access` header (wrapping internal state) after the resource
  authorizes the agent (interaction-completed or identity-only), wired into the
  challenge/verification pipeline.
- On inbound requests, parse + `token68`-validate `Authorization: AAuth`, confirm
  `authorization` is in the covered components, unwrap the internal state, and
  surface it to the app.

## Gaps & open questions

- **OQ1 — Opaque-state wrapping seam.** The spec leaves the wrapped state's format
  to the resource. Does the SDK ship a default wrapper (e.g. an encrypted blob over
  app-supplied state) or only an `IAAuthAccessTokenStore`/codec seam the app
  implements? Default lean: a seam + a simple reference-token demo store.
- **OQ2 — Per-origin replay store ownership.** Where does the agent keep the latest
  `AAuth-Access` per resource origin — inside the signing handler, a sibling
  handler, or an injectable store? Default lean: a sibling `DelegatingHandler` with
  an injectable in-memory store, mirroring the existing handler composition.
- **OQ3 — `authorization` covered-component toggle.** Always add `authorization`
  when a token is present, or make it explicit per request? Default lean:
  automatic when the handler has a stored token for the target origin.
- **OQ4 — Rolling-refresh races.** Concurrent in-flight requests may each receive a
  new `AAuth-Access`; define a last-writer-wins update rule and whether to
  serialize. Default lean: last-writer-wins, documented, no serialization.
- **OQ5 — Interaction reuse.** Confirm the resource-managed `202 → poll → 200`
  reuses `DeferredPoller`/`Interaction` unchanged, with only the `AAuth-Access`
  capture added at the terminal `200`.

## Verification note

Line numbers above were read directly from
[`aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md`](../../../aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md)
on 2026-06-25. Re-verify against the vendored source before editing any file —
line numbers shift on re-vendor; the `{#anchor}` references are durable.
