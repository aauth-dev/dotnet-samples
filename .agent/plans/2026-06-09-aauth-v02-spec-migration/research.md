# Research — AAuth SDK migration to protocol draft-02

> Research-only. No task lists or step-by-step instructions. The phased work
> lives in the companion [`implementation-plan.md`](implementation-plan.md);
> decisions and deviations are logged in
> [`implementation-log.md`](implementation-log.md).

## Goal

Determine, at high fidelity, what must change across the SDK (`src/AAuth/`),
samples (`samples/`), docs (`docs/`), and tests (`tests/`) to bring this repo
into conformance with **AAuth protocol draft-02**, now vendored at
[`aauth-spec/v02/`](../../../aauth-spec/v02/). The current code targets
**draft-01** ([`aauth-spec/v01/`](../../../aauth-spec/v01/)).

Trigger: draft-02 was published to the IETF datatracker and vendored into the
repo (commit `feda56b`, 2026-06-09). The full delta is catalogued in
[`aauth-spec/CHANGELOG.md`](../../../aauth-spec/CHANGELOG.md). This research
turns that spec-level delta into a code-level migration scope.

## Method

Six independent read-only subagents each scoped one logical change set against
the v02 spec and the current SDK/samples/docs/tests. Their findings are collated
below. The three highest-stakes findings (the `user_unreachable` wire value, the
SDK's current value, and the missing metadata issuer check) were re-verified
directly against source after collation.

## Authoritative sources

| Source | Role |
|---|---|
| [`aauth-spec/v02/draft-hardt-oauth-aauth-protocol.md`](../../../aauth-spec/v02/draft-hardt-oauth-aauth-protocol.md) | Canonical draft-02 protocol. All line numbers below reference this file as vendored. |
| [`aauth-spec/v01/draft-hardt-oauth-aauth-protocol.md`](../../../aauth-spec/v01/draft-hardt-oauth-aauth-protocol.md) | draft-01 baseline the SDK currently targets. |
| [`aauth-spec/CHANGELOG.md`](../../../aauth-spec/CHANGELOG.md) | Curated v01→v02 delta with anchors and term counts. |
| [`aauth-spec/v01/upcoming-changes-02.md`](../../../aauth-spec/v01/upcoming-changes-02.md) | Pre-publication planning notes. **Diverges from published v02 on the `user_unreachable` status code** (proposed 400; published 403). |
| `.agent/plans/2026-06-06-mission-api-refactor/` | Prior work that shipped `prompt`/`capabilities` and the `UserUnreachable` enum *forward-looking*. |
| `.agent/plans/2026-06-09-jkt-jwt-spec-conformance/` | Just-completed `jkt-jwt` work that already satisfies draft-02's "agent token is the minimum credential" clarification. |

## Cross-cutting themes

Three themes shape the whole migration and the phase ordering in the plan:

1. **Some draft-02 work already shipped forward-looking — verify, don't rebuild.**
   The client-side `prompt` and `capabilities` token-endpoint parameters are
   already implemented and tested ([src/AAuth/Agent/TokenExchangeRequest.cs](../../../src/AAuth/Agent/TokenExchangeRequest.cs),
   [TokenExchangeClient.cs](../../../src/AAuth/Agent/TokenExchangeClient.cs)). The
   `jkt-jwt` minimum-credential clarification is fully satisfied by the
   2026-06-09 conformance work. These need confirmation + server-side wiring, not
   net-new build.

2. **Two pre-existing defects become conformance bugs under draft-02.**
   - **Wire mismatch (terminal error):** the SDK emits `user_unreachable` as HTTP
     **400** ([src/AAuth/Agent/DeferredExchange.cs](../../../src/AAuth/Agent/DeferredExchange.cs) L191),
     but published draft-02 (L2194) specifies **403**. The 400 came from the
     pre-publication planning note. Verified directly.
   - **Security gap (host-poisoned metadata):** draft-02 L2343–2351 makes it a
     normative MUST that a fetched metadata document's `issuer` matches the URL
     it was retrieved from. [src/AAuth/Discovery/MetadataClient.cs](../../../src/AAuth/Discovery/MetadataClient.cs)
     has a forward `BuildUrl(issuer, dwk)` helper but performs **no reverse
     verification** on fetch. Verified directly.

3. **Most "security/HTTP-sig" deltas are clarifications, not wire changes.**
   The mandated covered components, non-repudiation guidance, WWW-Authenticate
   independence, and Markdown-sanitization mandates are all either already
   satisfied in code or are docs/advisory. This keeps that change set cheap.

## Change set 1 — Sub-agents (net-new feature)

Spec: [`#sub-agents`](../../../aauth-spec/v02/draft-hardt-oauth-aauth-protocol.md) (§ ~L1728–1810), Delegation Chain Examples (~L1776), Resource Token Verification step 6 (~L839).

### Spec summary

- **`parent_agent`** — new agent-token claim naming the parent agent; its
  presence marks the token as a sub-agent's; registered in the JWT Claims
  registry. Agent Token Verification adds a step: if present, validate it is a
  valid agent identifier.
- **`subagent_token`** — new OPTIONAL body parameter on the **PS** and **AS**
  token endpoints. Carries the sub-agent's agent token when a parent requests
  authorization on the sub-agent's behalf. The signing agent (parent) MUST be
  named by `subagent_token.parent_agent`.
- **Single-level depth (two MUSTs):** a PS MUST reject a token request signed by
  an agent whose own token carries `parent_agent`; an AP MUST NOT issue a
  sub-agent token whose parent is itself a sub-agent.
- **`+` local-part delimiter:** sub-agent local-part is `parent + "+" +
  discriminator` (e.g. `aauth:planner.7f3c+search1@vendor.example`). Parties MUST
  NOT parse the local-part for decisions — `parent_agent` is authoritative.
- **`act` nesting** records the delegation chain. Verbatim shape (sub-agent only):

  ```json
  {
    "aud": "search.example", "sub": "user:alice",
    "agent": "aauth:planner.7f3c+search1@vendor.example",
    "act": {
      "sub": "aauth:planner.7f3c+search1@vendor.example",
      "act": { "sub": "aauth:planner.7f3c@vendor.example" }
    }
  }
  ```

- **Resource Token Verification step 6** (~L839): when a `subagent_token` is
  present, verify `agent_jkt` against the `subagent_token`'s `cnf.jwk` (the
  sub-agent's key) — because the **parent** signs the HTTP request, not the
  sub-agent.

### Current SDK state

- ✅ Already present: `+` is in the `AgentId` local-part charset
  ([src/AAuth/Identifiers/AgentId.cs](../../../src/AAuth/Identifiers/AgentId.cs)); the `act`
  chain builder/reader and nesting work
  ([ActChainBuilder.cs](../../../src/AAuth/Tokens/ActChainBuilder.cs),
  [ActChainReader.cs](../../../src/AAuth/Tokens/ActChainReader.cs),
  [AuthTokenBuilder.cs](../../../src/AAuth/Tokens/AuthTokenBuilder.cs) — supports arbitrary nesting depth).
- ❌ Missing: `parent_agent` on [AgentTokenBuilder.cs](../../../src/AAuth/Tokens/AgentTokenBuilder.cs)
  and its verification in [TokenVerifier.cs](../../../src/AAuth/Tokens/TokenVerifier.cs);
  `subagent_token` on the PS token endpoint ([AAuthPersonServerEndpoints.cs](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs)),
  the AS endpoint/client ([Access/](../../../src/AAuth/Access/)), and the agent-side request
  ([TokenExchangeClient.cs](../../../src/AAuth/Agent/TokenExchangeClient.cs)); the single-level
  depth checks; and the resource-token step-6 sub-agent key binding in `TokenVerifier`.

This is the **largest net-new change set**: token builders/verifier, PS and AS
endpoints + clients, agent-side request shape, plus `AgentId` validation for the
top-level-vs-sub-agent naming rule.

## Change set 2 — Drop-in adoption: `access_mode` + `requirement=agent-token`

Spec: Resource Metadata `access_mode` (~L2464), [`#requirement-agent-token`](../../../aauth-spec/v02/draft-hardt-oauth-aauth-protocol.md) (§Agent Token Required, ~L732), `jwks_uri` relaxation (~L2464), Drop-In/Consuming narrative (~L2481, ~L2490).

### Spec summary

- **`access_mode`** (OPTIONAL resource-metadata field): one of `agent-token`,
  `aauth-access-token`, `auth-token`; default `agent-token`. Advisory — runtime
  `AAuth-Requirement` stays authoritative. An agent MAY use it to skip resources
  it cannot satisfy (e.g. a PS-less agent skips `auth-token`).
- **`requirement=agent-token`** (401): asks specifically for an AAuth agent token
  (`typ: aa-agent+jwt`), no PS/AS involved. Header has no parameters. Distinct
  from `requirement=auth-token`. Added to the Requirement Value Registry.
- **`jwks_uri` relaxation:** REQUIRED only when the resource issues resource
  tokens or makes signed calls; an identity-only resource MAY omit it.

### Current SDK state

- ❌ `ResourceMetadata` ([src/AAuth/Discovery/ServerMetadata.cs](../../../src/AAuth/Discovery/ServerMetadata.cs))
  has no `AccessMode`; `JwksUri` is `required` (should be optional).
- ❌ [AAuthRequirementHeader.cs](../../../src/AAuth/Headers/AAuthRequirementHeader.cs) has
  `AuthTokenRequirement` but no `agent-token` constant/formatter.
- ❌ Server `AAuthAccessMode` enum (`src/AAuth/Server/Verification/AAuthAccessMode.cs`)
  has `IdentityOnly`/`RequireAuthToken` but no agent-token-required value; the
  challenge middleware has no branch to emit a bare `requirement=agent-token`.
- ❌ Agent-side `ChallengeHandler` only handles `auth-token`; no agent-token retry path.

## Change set 3 — Interaction handling + error codes

Spec: Token Endpoint Error Codes (~L2185), Interaction Endpoint Errors (~L1265), PS-first relay [`#interaction-relay`](../../../aauth-spec/v02/draft-hardt-oauth-aauth-protocol.md) (~L2022), `max_wait` (~L1187), Interaction Code Format (~L2004).

### Spec summary

- **`user_unreachable` = 403** (terminal; L2194). Was `interaction_required` in
  v01. **The SDK currently emits 400 — wire mismatch.**
- **`interaction_unavailable` = 424** (non-terminal; L1271) — PS declines to relay
  a specific interaction; agent falls back to directing the user itself.
- **PS-first relay (SHOULD):** agent relays to the PS interaction endpoint before
  directing the user; on 424 it falls back.
- **`max_wait`** (OPTIONAL interaction param) — bounds how long the PS holds a
  relay's deferred response; pairs with `status: "interacting"` polling.
- **Interaction code format (multiple MUSTs):** Crockford base32 alphabet
  (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`, omits I/L/O/U); ≥40 bits entropy (≥8
  symbols, CSPRNG); presentational hyphens stripped before compare;
  case-insensitive with glyph-folding (I/L→1, O→0); single-use; mandatory
  rate-limiting; expiry bound to the pending interaction.

### Current SDK state

- ❌ `user_unreachable` emitted at **400** ([DeferredExchange.cs](../../../src/AAuth/Agent/DeferredExchange.cs) L191); enum exists in [TokenError.cs](../../../src/AAuth/Errors/TokenError.cs) L32; docs ([error-handling.md](../../../docs/advanced/error-handling.md)) and a forward-looking test ([TokenErrorTests.cs](../../../tests/AAuth.Conformance/Errors/TokenErrorTests.cs)) cite 400.
- ❌ No `interaction_unavailable` (424) anywhere; [PollingError.cs](../../../src/AAuth/Errors/PollingError.cs) has no value and the relay contract ([IInteractionRelay.cs](../../../src/AAuth/Server/Governance/IInteractionRelay.cs)) cannot signal "unavailable".
- ❌ `InteractionRequest` ([src/AAuth/Agent/Governance/InteractionRequest.cs](../../../src/AAuth/Agent/Governance/InteractionRequest.cs)) lacks `max_wait`; `InteractionResult` lacks a `status` field for `"interacting"`.
- ❌ No Crockford base32 generation/validation exists anywhere — codes are passed through as opaque strings. This is a **security-relevant gap** (the code is the only secret guarding the interaction URL).
- ❌ `InteractionClient` ([src/AAuth/Agent/Governance/InteractionClient.cs](../../../src/AAuth/Agent/Governance/InteractionClient.cs)) throws on any non-2xx — no 424 fallback path.

## Change set 4 — PS token-endpoint params (`prompt`, `capabilities`)

Spec: Agent Token Request params (~L886 `prompt`, ~L889 `capabilities`).

### Spec summary

- **`prompt`** (OPTIONAL): space-delimited OIDC values `none`/`login`/`consent`/`select_account` (OpenID Core §3.1.2.1).
- **`capabilities`** (OPTIONAL array): the body equivalent of the
  `AAuth-Capabilities` header (which is not used on PS endpoints). Without a
  mission, this is how the PS learns capabilities; within a mission, if present
  it refreshes the values captured at approval.

### Current SDK state

- ✅ **Client side already done** (forward-looking): `TokenExchangeRequest.Prompt`
  and `.Capabilities` exist, are serialized into the POST body, and have six
  passing tests ([ChallengeHandlerTests.cs](../../../tests/AAuth.Tests/Agent/ChallengeHandlerTests.cs)); capability
  constants exist ([AAuthCapabilitiesHeader.cs](../../../src/AAuth/Agent/AAuthCapabilitiesHeader.cs)).
  Published v02 matches the shipped shape.
- ❌ **Server side missing:** the PS token endpoint
  ([AAuthPersonServerEndpoints.cs](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs)) never reads
  `prompt`/`capabilities` from the body; `IdentityAssertionRequest` has no field
  to carry them; no mission-refresh logic. Docs ([token-issuance.md](../../../docs/server/token-issuance.md)) don't cover PS handling.

## Change set 5 — Mission reference naming + metadata hardening

Spec: Terminology mission reference vs blob (~L210), metadata issuer host-binding (~L2343–2351), metadata `description` on all four docs (~L2363/2403/2427/2458).

### Spec summary

- **"Mission reference"** is now the named `{approver, s256}` concept, distinct
  from the full mission blob. **Wire shape unchanged** — terminology only.
- **Metadata issuer host-binding (NEW MUST):** a fetched metadata document's
  `issuer` MUST match the URL it came from (URL minus `/.well-known/{dwk}`);
  reject on mismatch. Prevents host-poisoned metadata.
- **Metadata `description`** (OPTIONAL Markdown) added to agent/person/access/
  resource metadata; implementations MUST sanitize before rendering.

### Current SDK state

- ✅ Mission claim model ([MissionClaim.cs](../../../src/AAuth/Tokens/MissionClaim.cs)) and
  `AAuth-Mission` header already use `{approver, s256}` correctly — no wire change.
- ❌ **Security gap:** [MetadataClient.cs](../../../src/AAuth/Discovery/MetadataClient.cs) `FetchAsync`
  does not verify issuer == fetch URL. Verified directly: only a forward
  `BuildUrl(issuer, dwk)` helper exists.
- ❌ No `Description` field on any metadata options class or on the
  `ServerMetadata`/`ResourceMetadata` read models; `WellKnownEndpoints` emits none.

## Change set 6 — HTTP Message Signatures + security clarifications

Spec: covered-components rationale (~L2275), Keying Material / minimum credential (~L2254), Non-Repudiation After Key Rotation (~L2617), WWW-Authenticate independence (~L1947), Untrusted Input (~L2560).

### Spec summary & state — mostly already satisfied

- ✅ **Covered components** `@method`/`@authority`/`@path`/`signature-key` are
  exactly what the SDK enforces ([AAuthSigningHandler.cs](../../../src/AAuth/HttpSig/AAuthSigningHandler.cs),
  [AAuthVerifier.cs](../../../src/AAuth/HttpSig/AAuthVerifier.cs)). Rationale is new prose only.
- ✅ **`jkt-jwt` minimum-credential restriction** already done by the 2026-06-09
  conformance work (restricted to AP refresh; treated like `hwk`).
- ✅ **WWW-Authenticate independence** already holds — the only WWW-Authenticate
  references read a 402 Payment challenge ([AAuthPaymentRequiredException.cs](../../../src/AAuth/Errors/AAuthPaymentRequiredException.cs));
  AAuth requirements are only ever emitted via `AAuth-Requirement`.
- 📝 **Docs-only:** signing-mode overview/hwk/jkt-jwt pages should state hwk and
  jkt-jwt are not full AAuth access modes; add non-repudiation guidance; surface
  the Markdown-sanitization mandate in verification-middleware docs.

## Gaps & open questions

These need an owner ruling before or during implementation. The plan's Phase 0
collects the blocking ones.

| # | Question | Why it matters |
|---|---|---|
| Q1 | Confirm `user_unreachable` → **403** (published v02) supersedes the 400 from `upcoming-changes-02.md`. | Wire fix; flips a shipped value and a test. Verified in spec; needs sign-off. |
| Q2 | Exception type for the metadata issuer-mismatch rejection — reuse `InvalidOperationException` or a new `MetadataVerificationException`? | Security fix; affects caller error handling. |
| Q3 | `AAuthAccessMode` enum: add an `AgentTokenRequired` value additively, or rename existing values to match spec wording? | Breaking-change surface vs clarity. |
| Q4 | Does the SDK own a Crockford base32 interaction-code generator/validator, or is that PS/resource responsibility? | Determines whether change set 3 ships a new security-critical utility. |
| Q5 | `interaction_unavailable` (424) surface — new exception parallel to polling errors, or an `Unavailable` outcome on the relay contract? | API-shape consistency. |
| Q6 | Should the SDK integrate a Markdown sanitizer for `description`/justification fields, or document that the UI layer sanitizes? | The spec MUST applies at render time; SDK is a library, not a renderer. |
| Q7 | `prompt`/`capabilities` validation: reject unknown values or pass through for forward-compat? Is `provider_hint` handled via an extensibility hook? | PS-side policy + extensibility. |
| Q8 | Sub-agent error taxonomy: codes for single-level-depth violation and `subagent_token.parent_agent` mismatch. | New failure modes need agreed error codes. |
| Q9 | Back-compat posture overall. The 2026-06-09 work established "spec-accurate alpha SDK, no back-compat." Confirm it carries to this migration (it informs every breaking choice below). | Governs whether renames/removals are acceptable. |

## Out-of-scope candidates (confirm in plan)

- R3 (Rich Resource Requests) draft-00 revisions (Per-Call Proposals, Operations
  Spanning Multiple Definitions) — tracked separately under the R3 plan; this
  migration covers the **protocol** draft-02 only.
- Bootstrap draft is byte-identical between v01 and v02 — no work.
- A full PS-side mission-refresh policy engine for `capabilities` (beyond reading
  the values) may exceed this migration's scope.
