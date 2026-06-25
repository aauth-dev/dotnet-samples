# Research — AAuth SDK migration to protocol draft-08

> Research-only. No task lists or step-by-step instructions. The phased work
> lives in the companion [`implementation-plan.md`](implementation-plan.md);
> decisions, deviations, and open-question rulings are logged in
> [`implementation-log.md`](implementation-log.md) for end-of-run review.

## Goal

Determine, at high fidelity, what must change across the SDK (`src/AAuth/`),
samples (`samples/`), docs (`docs/`), and tests (`tests/`) to bring this repo
into conformance with **AAuth protocol draft-08**, now vendored at
[`aauth-spec/v08/`](../../../aauth-spec/v08/). The current code targets
**draft-02** ([`aauth-spec/v02/`](../../../aauth-spec/v02/)).

Trigger: draft-08 was published to the IETF datatracker and vendored into the
repo (commit `dd2b852`, document date 2026-06-17, copied 2026-06-25). draft-08
is the cumulative result of six published drafts (03 → 08). The spec-level delta
is catalogued in [`aauth-spec/CHANGELOG.md`](../../../aauth-spec/CHANGELOG.md);
this research turns that delta into a code-level migration scope.

## Method

Seven independent read-only subagents each scoped one logical change set against
the draft-08 spec and the current SDK/samples/docs/tests. Their findings were
collated below, then the highest-stakes claims (the `act.agent` rename, `act`
becoming OPTIONAL, the `client_name`→`name` rename, the new Interaction Callback
Errors section, the auth-token verification split, and the PS "MUST require a
mission" rule) were **re-verified directly against `aauth-spec/v08/`** after
collation. Line numbers in this document reference the vendored draft-08 protocol
file unless noted; anchors in parentheses (e.g. `#delegation-chain`) are the
spec's own kramdown anchors and are stable across line shifts.

## Authoritative sources

| Source | Role |
|---|---|
| [`aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md`](../../../aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md) | Canonical draft-08 protocol. Line numbers below reference this file. |
| [`aauth-spec/v08/draft-hardt-httpbis-signature-key-05.txt`](../../../aauth-spec/v08/draft-hardt-httpbis-signature-key-05.txt) | HTTP Signature Keys draft-05 (referenced by the protocol). |
| [`aauth-spec/v08/interop-demo-profile.md`](../../../aauth-spec/v08/interop-demo-profile.md) | New non-normative interop demo profile (extracted in draft-06). |
| [`aauth-spec/v02/draft-hardt-oauth-aauth-protocol.md`](../../../aauth-spec/v02/draft-hardt-oauth-aauth-protocol.md) | draft-02 baseline the SDK currently targets. |
| [`aauth-spec/v02/draft-hardt-httpbis-signature-key-04.txt`](../../../aauth-spec/v02/draft-hardt-httpbis-signature-key-04.txt) | HTTP Signature Keys draft-04 baseline. |
| [`aauth-spec/CHANGELOG.md`](../../../aauth-spec/CHANGELOG.md) | Curated v02→v08 delta with anchors and the author's verbatim per-draft changelog. |
| `.agent/plans/2026-06-09-aauth-v02-spec-migration/` | Prior migration (draft-01 → draft-02). Establishes the no-back-compat posture and the act-chain/sub-agent seams this work builds on. |

## Cross-cutting themes

Four themes shape the whole migration and the phase ordering in the plan:

1. **The `act` rework is the spine of the migration.** `act.sub` → `act.agent`
   and `act` becoming OPTIONAL touch token construction, verification, the
   PS/AS upstream-token path, sub-agent issuance, every delegation example, and
   a wide band of tests and docs. Most other code changes are independent of it,
   but it has the largest blast radius, so it is sequenced as its own phase with
   a single coordinated cutover (the SDK signs *and* verifies, so no dual-format
   shim is needed).

2. **Call-chaining routing already conforms; only the PS mission gate is new.**
   [CallChainingRouter.cs](../../../src/AAuth/Server/CallChaining/CallChainingRouter.cs)
   already routes from `mission.approver` then `iss` and ignores the caller's
   `ps` claim (verified), and the `aud == iss` upstream binding is already
   enforced by [UpstreamTokenValidator.cs](../../../src/AAuth/Tokens/UpstreamTokenValidator.cs).
   The only net-new behavior is the draft-08 rule that a PS **MUST require a
   mission** to stay in the loop for four-party upstream chains (L1765).

3. **The draft-06 "clarity pass" is mostly tightening, not net-new wire.** Of its
   seven sub-items, several are already satisfied (JWKS same-`kid` refresh, the
   `Signature-Error` header, replay detection via the existing `jti` store), some
   are validation tightening (`scheme=jwt` restriction, mission `approver`/`s256`
   syntax, structured `cnf.jwk` ordering), and one is a new security guard (PS
   approval endpoint authentication). This keeps the cluster's code cost moderate
   despite its breadth.

4. **HTTP Signature Keys draft-05 needs essentially no code.** The schemes, the
   `Signature-Key`/`Signature-Error` wire formats, and the verification steps are
   byte-identical to draft-04; the new material is informational SSRF/egress
   guidance and a reference/author update. This is the cheapest change set.

---

## Change set 1 — Auth-token `act` semantics (`act.sub` → `act.agent`, `act` OPTIONAL)

Spec: `## Delegation Chain` (`#delegation-chain`, L1829–1838); Auth Token claims
(L1678 — `act` is OPTIONAL); verification steps (L1546, L1723, L1735); PS upstream
construction (L1744); sub-agent issuance (L1825); examples (L1840–1880); URI
scheme note (L2945); Document History (L2975, L2978).

### Spec summary (verified)

- **`act.sub` is replaced by `act.agent`** within each `act` node
  ([issue #47](https://github.com/dickhardt/AAuth/issues/47), Document History
  L2978). The spec uses `agent` (not RFC 8693's `sub`) to make explicit the value
  is an AAuth agent identifier (L1833).
- **`act` is now OPTIONAL** — **absent** when the agent obtained the auth token
  directly (no chaining, no sub-agent) (L1678, L1829, Document History L2975).
- **`act.agent` identifies the immediate upstream agent — the delegator, not the
  presenter.** The presenter's own identity stays in the top-level `agent` claim
  and is **not** repeated inside `act` (L1833–1838). Nesting (`act.act`) records
  the full upstream chain.
- Verification: "If `act` is present, verify `act.agent` ..." (L1723, L1735) —
  i.e. the verifier must tolerate its absence and check `agent` (not `sub`) when
  present.

Verbatim shape change:

```jsonc
// draft-02 (current): act ALWAYS present; self-referential; field is `sub`
{ "agent": "aauth:asst@agent.example",
  "act": { "sub": "aauth:asst@agent.example" } }

// draft-08: direct auth omits act entirely
{ "agent": "aauth:asst@agent.example" }

// draft-08: call chaining — act.agent is the UPSTREAM delegator, field is `agent`
{ "agent": "aauth:booking@booking.example",
  "act": { "agent": "aauth:asst@agent.example" } }
```

### Current SDK state

- ❌ [ActChainBuilder.cs](../../../src/AAuth/Tokens/ActChainBuilder.cs) writes
  `["sub"]` in `BuildNestedAct` and validates on `sub` in `ValidateChain`
  (verified — L33, L60).
- ❌ [ActChainReader.cs](../../../src/AAuth/Tokens/ActChainReader.cs) reads
  `act.sub` in `GetDelegationChain`, `GetImmediateActor`, `GetOriginalActor`.
- ❌ [AuthTokenBuilder.cs](../../../src/AAuth/Tokens/AuthTokenBuilder.cs) always
  emits `act = { sub: Agent }` (self-reference), even for direct authorization.
- ❌ [TokenVerifier.cs](../../../src/AAuth/Tokens/TokenVerifier.cs) and
  [UpstreamTokenValidator.cs](../../../src/AAuth/Tokens/UpstreamTokenValidator.cs)
  require `act` to be present and check `act.sub`.
- ❌ [AAuthVerificationMiddleware.cs](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs)
  and [AAuthVerificationResult.cs](../../../src/AAuth/Server/Verification/AAuthVerificationResult.cs)
  surface/verify `act.sub` semantics.

### Simulated fix

| File | Current | draft-08 |
|---|---|---|
| [ActChainBuilder.cs](../../../src/AAuth/Tokens/ActChainBuilder.cs) | `["sub"] = intermediaryAgentId`; validate on `sub` | `["agent"] = intermediaryAgentId`; validate on `agent` |
| [ActChainReader.cs](../../../src/AAuth/Tokens/ActChainReader.cs) | reads `current["sub"]`; throws if `act` null in some paths | reads `current["agent"]`; `act` null ⇒ empty chain / `null` actor |
| [AuthTokenBuilder.cs](../../../src/AAuth/Tokens/AuthTokenBuilder.cs) | always emit `act={sub:Agent}` + nest upstream | emit `act` **only** when delegated; node uses `agent`; omit for direct auth |
| [UpstreamTokenValidator.cs](../../../src/AAuth/Tokens/UpstreamTokenValidator.cs) | require `act`; check `act.sub` | `act` optional; when present check `act.agent` identifies upstream agent |
| [TokenVerifier.cs](../../../src/AAuth/Tokens/TokenVerifier.cs) | require `act`; `act.sub` checks | "if `act` present" guard; `act.agent` checks |
| [AAuthVerificationMiddleware.cs](../../../src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs) | requires `act`; verifies `act.sub == agent` | direct auth ⇒ `act` absent; delegated ⇒ `act.agent` is upstream |

### Tests / docs affected

- Conformance: `ActChainBuilderTests`, `ActChainReaderTests`,
  `AuthTokenStructureTests`, `AuthTokenVerificationTests`, `CallChainingTests`,
  `AuthTokenDeliveryTests`, and `AuthorizationIntegrationTests` all assert on
  `act.sub` / always-present `act`.
- E2E/Playwright: `samples/GuidedTour/playwright-tests/{autonomous,call-chain,sub-agent}.spec.ts`,
  `samples/SampleApp/playwright-tests/call-chain.spec.ts`, and `GuidedTour` display
  code read `act.sub`.
- Docs: [docs/workflows/call-chaining.md](../../../docs/workflows/call-chaining.md),
  [docs/server/verification-middleware.md](../../../docs/server/verification-middleware.md),
  [docs/glossary.md](../../../docs/glossary.md) describe `act.sub`.

---

## Change set 2 — Call chaining and routing

Spec: `# Agent Delegation` / `## Multi-Hop Resource Access` (`#multi-hop`);
upstream `aud == iss` binding (L1743); routing from `mission.approver`/`iss`
(L1757–1761); PS MUST require a mission for four-party chains (L1765).

### Spec summary (verified)

- **Upstream token `aud` MUST equal the `iss` of the intermediary's agent token**
  presented in the `Signature-Key` header (L1743).
- **Routing is derived from the upstream auth token** — `mission.approver` if a
  mission is present, otherwise `iss` — **not** the caller's `ps` claim
  (L1757–1761).
- **A PS MUST require a mission** to remain in the loop for four-party upstream
  chains; the mission puts `mission.approver` in the upstream auth token so every
  intermediary has a PS to route to regardless of PS-vs-AS issuance (L1765,
  verified).

### Current SDK state

- ✅ `aud == iss` is already enforced — [UpstreamTokenValidator.cs](../../../src/AAuth/Tokens/UpstreamTokenValidator.cs)
  verifies the upstream token against `expectedAudience` = the intermediary's
  `iss` (from its agent token).
- ✅ Routing already conforms — [CallChainingRouter.ResolveDownstreamServer](../../../src/AAuth/Server/CallChaining/CallChainingRouter.cs)
  routes `mission.approver` → `iss`, fails fast on a present-but-invalid
  approver, and never consults the caller's `ps` claim (verified by reading the
  file).
- ❌ The **four-party PS mission gate is not enforced**. The PS token endpoint
  ([AAuthPersonServerEndpoints.cs](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs))
  accepts an `upstream_token` without requiring a mission when the upstream `iss`
  is an AS.

### Simulated fix

- In the PS token endpoint, after validating the `upstream_token`, when the
  request carries no mission **and** the upstream `iss` resolves to an AS (not a
  PS), reject (reuse `invalid_request` with a distinct description). This needs a
  PS-vs-AS determination — candidates: probe `{iss}/.well-known/aauth-access.json`
  vs `aauth-person.json`, or a configured trusted-AS list. The `MetadataClient`
  already caches fetches, so a metadata probe is viable.
- No change to `CallChainingRouter` or `UpstreamTokenValidator` for the binding
  rules — already compliant.

### Tests affected

- Existing `UpstreamTokenValidationTests` and `CallChainingTests` routing tests
  stay green (behavior unchanged).
- New: four-party upstream + no mission ⇒ rejected; three-party upstream + no
  mission ⇒ allowed; explicit `aud == intermediary.iss` assertion.

---

## Change set 3 — Interactions (callback errors + interaction-code semantics)

Spec: new `### Interaction Callback Errors` (`#interaction-callback-errors`,
L971–987); interaction code as a correlation identifier (Interaction Code
Format section, ~L2078); Crockford base32 citation update (~L2071).

### Spec summary (verified)

- **New Interaction Callback Errors section (L971).** When an interaction cannot
  complete, the server redirects to the `callback` URL with an `error` query
  parameter: `{callback_url}?error={error_code}`. Error values: `access_denied`,
  `user_abandoned` (L982), `server_error`, `temporarily_unavailable`,
  `interaction_expired`.
- **PS callback-error → polling-error mapping (L987, verified):** `access_denied`
  → `denied`; `user_abandoned` → `abandoned`; `interaction_expired` → `expired`;
  `server_error` and `temporarily_unavailable` → `server_error`. Recipients of a
  callback with an `error` parameter MUST NOT treat the pending request as
  completable and MUST surface the error.
- **Interaction code is a correlation identifier, not an authorization credential
  (draft-08).** The code alone MUST NOT authorize the decision; the approve/deny
  decision is recorded over an authenticated channel at the PS. This is a framing
  change — the pure-function code rules (Crockford base32, entropy, hyphen/case
  handling) are unchanged.

### Current SDK state

- The interaction-code utility exists at
  [Headers/InteractionCode.cs](../../../src/AAuth/Headers/InteractionCode.cs)
  (Crockford base32 generation/validation) and the requirement header at
  [Headers/Interaction.cs](../../../src/AAuth/Headers/Interaction.cs).
- Polling errors live in [Errors/PollingError.cs](../../../src/AAuth/Errors/PollingError.cs).
  The agent polling path is [Agent/DeferredPoller.cs](../../../src/AAuth/Agent/DeferredPoller.cs)
  and [Agent/DeferredExchange.cs](../../../src/AAuth/Agent/DeferredExchange.cs).
- ❌ No parsing of a `?error=` callback redirect; no callback-error → polling-error
  mapping. The code is documented with draft-02 "only secret" framing.

### Simulated fix

- Add the five callback error constants and the callback→polling mapping (most
  naturally alongside [PollingError.cs](../../../src/AAuth/Errors/PollingError.cs)).
- Where the SDK consumes interaction callbacks, detect a redirect carrying
  `?error=`, map to the polling error, and surface it (do not treat as
  completable). Whether this lands in the agent poller, the PS resource-initiated
  flow, or both depends on which side owns the callback in the SDK — an open
  question below.
- Update the `InteractionCode` doc comment to the correlation-identifier framing
  (no behavioral change). Refresh the Crockford citation in docs.

### Tests affected

- New poller tests for each `?error=` value and the unknown-value default; new
  PS mapping tests; existing interaction/clarification tests must stay green.

---

## Change set 4 — Metadata documents

Spec: Metadata common-fields table and RFC 9728 divergence note (L2441–2453);
`documentation_uri` on agent/person/access/resource (L2449, L2469, L2485, L2503,
L2523, L2548, L2563, L2583, L2605); unprefixed `name` (L2453).

### Spec summary (verified)

- **`client_name` → `name`.** draft-02 used `client_name` for the agent and
  resource docs (v02 L2359/L2374/L2447/L2466); draft-08's divergence note
  mandates the unprefixed `name` across all four roles (L2453). PS and AS docs
  gain `name` as a new optional field.
- **New `documentation_uri` (OPTIONAL, `https`)** on all four metadata documents
  (agent L2485, person L2523, access L2563, resource L2605), plus the common
  fields `logo_dark_uri`, `tos_uri`, `policy_uri` formalized in the table.
- **Common-fields table + RFC 9728 divergence (L2441–2453)** — documentation:
  AAuth uses `issuer` (not `resource`) and unprefixed names. No wire change beyond
  the field renames/additions above.

### Current SDK state (verified)

- Client parse: [Discovery/ServerMetadata.cs](../../../src/AAuth/Discovery/ServerMetadata.cs)
  exposes `ClientName` and reads `client_name` (L96, L125); no `Name`,
  `DocumentationUri`, `LogoDarkUri`, `TosUri`, `PolicyUri`.
- Server options: [AAuthAgentMetadataOptions.cs](../../../src/AAuth/Server/Metadata/AAuthAgentMetadataOptions.cs)
  has `ClientName` and emits `client_name`; PS/AS options
  ([AAuthPersonServerMetadataOptions.cs](../../../src/AAuth/Server/Metadata/AAuthPersonServerMetadataOptions.cs),
  [AAuthAccessServerMetadataOptions.cs](../../../src/AAuth/Server/Metadata/AAuthAccessServerMetadataOptions.cs))
  have no `Name`/visual/doc fields. Builders live in
  [WellKnownEndpoints.cs](../../../src/AAuth/Server/Metadata/WellKnownEndpoints.cs).

### Simulated fix

- Rename `ClientName` → `Name` and emit `name` (agent + resource docs); add
  `Name` to PS/AS options. Per the no-back-compat posture, this is a clean rename,
  not a dual-emit.
- Add `DocumentationUri` (+ `LogoDarkUri`, `TosUri`, `PolicyUri`) parse (client)
  and conditional emit (server) across all four docs.
- Client `ResourceMetadata.FromJson` may read `name` with a `client_name`
  fallback to tolerate older resources during interop (decision deferred to the
  plan; default is spec-accurate `name` only).

### Tests affected

- Metadata round-trip / well-known endpoint tests asserting `client_name`; new
  assertions for `name` and `documentation_uri` emission/parse.

---

## Change set 5 — PS approval auth and implementation-clarity pass (draft-06)

Spec: Document History L2972 (verbatim cluster list, verified); sub-items below.
This is the broadest cluster (seven sub-items) but mostly tightening.

| # | Sub-item | Spec | Current SDK | Disposition |
|---|---|---|---|---|
| a | **PS Approval Endpoint Authentication** — PS MUST authenticate the approving party unless loopback-only | `#ps-approval-endpoint-auth` (L2724) | No auth guard on PS approval/consent | **New guard** (+ loopback exemption); pluggable auth handler |
| b | **Mission `approver`/`s256` syntax** — `approver` is a server-id (scheme+host, exact match); `s256` is unpadded base64url of 32-byte SHA-256 | Mission reference rules | Loose validation in [Agent/Mission.cs](../../../src/AAuth/Agent/Mission.cs) / [MissionHeaderHandler.cs](../../../src/AAuth/Agent/MissionHeaderHandler.cs) | **Validation tightening**, reuse [Identifiers/ServerId.cs](../../../src/AAuth/Identifiers/ServerId.cs) |
| c | **Agent keying material restricted to `scheme=jwt`** | Agent token usage (~L580) | [SignatureKeyParser.cs](../../../src/AAuth/HttpSig/SignatureKeyParser.cs) accepts any scheme; no agent-token scheme guard | **Add check**: agent token (dwk `aauth-agent.json`) MUST be `scheme=jwt` |
| d | **`AAuth-Requirement` / `AAuth-Access` / `AAuth-Capabilities` grammars** — ignore unknown params/values; `AAuth-Access` is `token68` (reject empty/whitespace/multiple) | Header grammar sections | [Headers/AAuthRequirementHeader.cs](../../../src/AAuth/Headers/AAuthRequirementHeader.cs), [Agent/AAuthCapabilitiesHeader.cs](../../../src/AAuth/Agent/AAuthCapabilitiesHeader.cs) parse but lack explicit token68/unknown-value rules | **Minor validation + forward-compat** |
| e | **JWKS same-`kid` refresh + egress admission** — refresh once on verification failure (silent re-keying); apply egress admission before fetch | JWKS discovery/caching | [Discovery/JwksClient.cs](../../../src/AAuth/Discovery/JwksClient.cs) already refreshes on unknown `kid` with a once-per-minute floor | **Mostly satisfied**; consider refresh-on-verify-failure; egress admission is deployment-level |
| f | **Auth-token verification split: JWT trust vs request-context binding, structured `cnf.jwk` ordering** | `#### JWT Trust Verification` (L1711), `#### Request-Context Binding` (L1718) | [TokenVerifier.cs](../../../src/AAuth/Tokens/TokenVerifier.cs) verifies in one pass; basic `cnf.jwk` check | **Restructure + structured `cnf.jwk` failure ordering**; folds in the `act.agent` change from set 1 |
| g | **Freshness and replay policy** — `created` window primary defense; OPTIONAL replay cache keyed by `(key-thumbprint, created, @method, @authority, @path)`; resources NOT required to cache resource tokens | Freshness/replay subsection | [HttpSig/AAuthVerifier.cs](../../../src/AAuth/HttpSig/AAuthVerifier.cs) enforces the `created` window; repo already has `jti` replay detection ([InMemoryJtiStore](../../../src/AAuth/Server/InMemoryJtiStore.cs)) | **Largely satisfied**; mostly docs + optional cache-key alignment |

### Structured `cnf.jwk` failure ordering (sub-item f, verified split)

draft-08 splits verification (L1709: "A valid JWT signature alone is not a
complete AAuth authorization check — both JWT trust and request-context binding
must pass"):

1. **JWT Trust (L1711):** `typ = aa-auth+jwt`; `dwk` ∈ {`aauth-access.json`,
   `aauth-person.json`} + JWKS discovery + signature; `exp`/`iat`; `iss` is HTTPS.
2. **Request-Context Binding (L1718):** `aud` = resource; `agent` = signing
   context; **`cnf.jwk` REQUIRED with ordered failures** — absent or missing
   `kty`/key-type members ⇒ "structurally incomplete" *before* decode; present
   but unparseable ⇒ "invalid key material"; else verify it matches the HTTP
   signing key; then "if `act` present" check `act.agent`; then `sub` or `scope`.

### Simulated fix

- (a) Add an approval-endpoint auth guard with a loopback exemption and a
  pluggable verifier; default-deny when externally reachable and unauthenticated.
- (b) Validate `approver` via `ServerId` and `s256` as unpadded base64url of 32
  bytes; reject otherwise.
- (c) After parsing an agent token's `Signature-Key`, require `scheme=jwt`.
- (d) Document/ignore unknown `AAuth-Requirement` params and unknown
  `AAuth-Capabilities` values; reject empty/whitespace/multi-credential
  `AAuth-Access` (`token68`).
- (e) Optionally add refresh-on-verify-failure to `JwksClient`; treat egress
  admission as deployment guidance (HttpClient transport, network policy).
- (f) Split `TokenVerifier` into trust + binding helpers with the ordered
  `cnf.jwk` checks; adopt `act.agent` (shared with change set 1).
- (g) Align/extend the existing replay machinery to the spec cache key if a
  resource opts in; otherwise docs-only.

### Tests affected

- New tests per sub-item (approval auth + loopback bypass; mission syntax;
  agent-token non-`jwt` scheme rejected; `AAuth-Access` token68; `cnf.jwk`
  structurally-incomplete vs invalid-key ordering; same-`kid` silent re-key).

---

## Change set 6 — HTTP Signature Keys draft-04 → draft-05

Spec: [`draft-hardt-httpbis-signature-key-05.txt`](../../../aauth-spec/v08/draft-hardt-httpbis-signature-key-05.txt)
vs draft-04. The Signature Keys spec now lives in its own repository
(<https://github.com/dickhardt/signature-key>) and is referenced as
`[@!I-D.hardt-httpbis-signature-key]`.

### Spec summary (subagent diff; low risk)

- Schemes (`hwk`, `jkt-jwt`, `jwks_uri`, `jwt`, `x509`), the `Signature-Key` and
  `Signature-Error` headers, and verification steps are **byte-identical** to
  draft-04.
- New material is informational: a jkt-jwt enclave-algorithm note; a once-per-
  minute JWKS fetch floor + silent re-keying guidance (§6.2); and an SSRF/egress
  admission checklist (§6.3 — HTTPS-only, size/timeout limits, redirect
  constraints, private/loopback/link-local rejection, DNS-rebinding pinning,
  cross-origin admission). A second author (T. Meunier, Cloudflare) is added.

### Current SDK state

- The `Signature-Error` header is already modeled at
  [Errors/SignatureError.cs](../../../src/AAuth/Errors/SignatureError.cs) and the
  schemes are implemented under [HttpSig/](../../../src/AAuth/HttpSig/).
- [Discovery/JwksClient.cs](../../../src/AAuth/Discovery/JwksClient.cs) already
  enforces a once-per-minute refresh floor (overlaps §6.2 and change set 5e).

### Simulated fix

- **No required code changes.** Update version citations (draft-04 → draft-05) in
  code comments/docs; optionally add a regression test for silent re-keying; add
  an SSRF/egress deployment checklist to the server docs. Egress admission is an
  infrastructure concern, not signature-verification logic.

---

## Change set 7 — Agent-delegation restructure, terminology, and interop demo profile

Spec: `# Agent Delegation` umbrella with `## Multi-Hop Resource Access`,
`## Sub-Agents`, and the consolidated `## Delegation Chain` (L1829); new
[`interop-demo-profile.md`](../../../aauth-spec/v08/interop-demo-profile.md).

### Spec summary

- draft-02's top-level `# Multi-Hop Resource Access` and `# Sub-Agents` are now
  subsections under `# Agent Delegation`; the draft-02 sub-agent subsections
  (Sub-Agent Identity, Single-Level Depth, Parent-Mediated Authorization,
  Delegation Chain Examples) collapse into a single `## Delegation Chain`. This is
  structural — anchors like `#sub-agents` and `#multi-hop` remain valid.
- The new interop demo profile lists five minimum live surfaces: S1 PS mission
  approval; S2 `AAuth-Mission` presentation + resource-token echo; S3
  resource-token issuance + issuer discovery; S4 auth-token issuance +
  presentation; S5 parent-mediated sub-agent handling.

### Current state

- Logic for all five surfaces exists across the SDK and samples (MissionAgent +
  Trips for S1/S2; resource servers for S3; three/four-party flows for S4;
  `AAuthPersonServerEndpoints` parent-mediated path for S5).
- **Gap:** no runnable end-to-end **sub-agent (S5)** sample drives a parent
  creating a sub-agent, the sub-agent calling a resource, and the parent
  exchanging via the PS. SDK code exists but is not exercised by a sample/e2e.
- Docs/samples carry old terminology (`act.sub`, top-level section references)
  that travels with change set 1 and the metadata rename.

### Simulated fix

- Terminology sweep in docs/samples (`act.sub` → `act.agent`; section-name
  references) — bundled with change sets 1 and 4.
- Decide whether to add an S5 sub-agent sample/e2e or accept the gap (deferred to
  the plan / Out of Scope).

---

## Gaps & open questions

| # | Question | Notes |
|---|---|---|
| Q1 | Confirm the no-back-compat posture for draft-08 (clean renames, single cutover). | Default: yes, per the 2026-06-09 migration precedent. Affects `act.sub`/`client_name` renames and metadata fallbacks. |
| Q2 | Should `ResourceMetadata` parse `name` with a `client_name` fallback for interop with older resources? | Default: spec-accurate `name` only; add fallback only if live interop needs it. |
| Q3 | How should the PS determine PS-vs-AS for the four-party mission gate? | Options: probe `aauth-access.json` vs `aauth-person.json`; configured trusted-AS list; metadata field heuristic. Metadata probe reuses the cached `MetadataClient`. |
| Q4 | Which side owns interaction `?error=` callback parsing — agent poller, PS resource-initiated flow, or both? | Drives where the callback→polling mapping lives. Needs an audit of the PS resource-initiated interaction implementation. |
| Q5 | Error code for the four-party "mission required" rejection. | Default: `invalid_request` with a distinct description (matches existing patterns). |
| Q6 | Is the existing `jti`/`created` replay machinery sufficient for the freshness/replay subsection, or is the spec's `(thumbprint, created, @method, @authority, @path)` cache key needed? | Likely docs-only; confirm against [InMemoryJtiStore](../../../src/AAuth/Server/InMemoryJtiStore.cs) and `AAuthVerifier`. |
| Q7 | Does the SDK need first-class egress-admission/SSRF hooks, or is it deployment-level (HttpClient + network policy)? | Default: deployment-level + docs; defer SDK hardening unless a concrete gap is found. |
| Q8 | Approval-endpoint authentication shape — built-in cookie/signed-request handler, or app-supplied delegate? | Default: app-supplied verifier with a loopback exemption built in. |
| Q9 | Add a runnable sub-agent (S5) interop sample, or defer? | Default: defer (Out of Scope) unless interop testing requires it. |

> Verification note: the spec line references in change sets 1–4 and the
> verification split (5f) and PS mission gate (set 2) were re-checked directly
> against [`aauth-spec/v08/`](../../../aauth-spec/v08/). The draft-04→draft-05
> byte-identical assessment (set 6) and the per-file line numbers inside the
> draft-06 cluster (set 5) come from the subagent reports and should be
> re-confirmed at implementation time before editing each file.
