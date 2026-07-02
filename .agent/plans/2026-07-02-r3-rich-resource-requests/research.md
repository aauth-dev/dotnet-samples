# R3 (Rich Resource Requests) — SDK & Samples Research

Research-only analysis of how to add AAuth **Rich Resource Requests (R3)** support
to the .NET SDK (`src/AAuth`) and the samples, including a new **Bookings** resource
server aligned with the "Aria" travel-assistant narrative. Consumability of the
public API is a first-class concern, grounded in the conventions shipped by
[.agent/plans/2026-06-27-server-api-surface](../2026-06-27-server-api-surface/implementation-plan.md).

- **Status:** Research only. No implementation steps, no checkboxes.
- **Date:** 2026-07-02
- **R3 spec:** [aauth-spec/v08/draft-hardt-aauth-r3.md](../../../aauth-spec/v08/draft-hardt-aauth-r3.md) (draft-00)
- **Base spec:** [aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md](../../../aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md) (draft-08)
- **SDK root:** [src/AAuth](../../../src/AAuth)

> **Supersedes [.agent/plans/2026-06-06-r3-rich-resource-requests](../2026-06-06-r3-rich-resource-requests/research.md).**
> That research predates the draft-08 migration and the 2026-06-27 server API
> surface. Its central prerequisite — an **RFC 8785 (JCS) canonical-JSON
> serializer** for `r3_s256` — is **incorrect** against the current (and,
> per the changelog, byte-identical draft-00) spec: content addressing hashes the
> **verbatim served bytes with no canonicalization step**
> ([r3 #content-addressing, L335](../../../aauth-spec/v08/draft-hardt-aauth-r3.md)).
> The old scope-tier open questions are also resolved here (the SDK now targets
> draft-08 and hosts AS/PS roles). Treat this document as the current R3 research.

---

## Problem statement

R3 adds **resource-declared, vocabulary-based authorization** on top of AAuth:
resources publish content-addressed **R3 documents** describing what a class of
access *means*, and tokens carry `r3_uri`, `r3_s256`, `r3_granted`, and
`r3_conditional` alongside (or instead of) opaque scope strings. The SDK has
**zero** R3 code today (`grep -ri "r3_uri\|r3_s256\|r3_operations\|r3_granted\|
r3_vocabularies" src/ samples/` → no matches, verified 2026-07-02). This document
maps the R3 spec model, the exact SDK extension points, the API-surface
conventions R3 must honor, eight validated design suggestions, and the Bookings
sample design — so an implementation plan can follow.

---

## Method

Three logical change sets were explored with read-only subagents and collated:

1. **SDK surface inventory** — the token builders, verification result, challenge
   path, metadata, authorization endpoint, AS/PS role seams, agent exchange, and
   signing handler that R3 plugs into.
2. **Samples & Aria narrative** — GuidedTour tour modes, SampleApp pages, the five
   resource servers, MockAccessServer/MockPersonServer/MockAgentProvider, ports,
   Makefile, e2e tests, and docs.
3. **Design validation** — two adversarial validator subagents scored each of the
   eight suggestions (S1–S8) and the access-mode decision against the spec and the
   code, returning per-suggestion verdicts and required corrections.

Per the planning workflow, the **highest-stakes claims were re-verified directly
against source** because subagent line numbers drift. Anchors are the durable
reference; line numbers are precise as of the draft-08 vendor (commit `dd2b852`).

**Re-verified directly (line-checked in this pass):**

- R3: `#resource-metadata-extensions` L83; `#authorization-endpoint-extensions`
  L234–L236; AS-only fetch MUST L297; "no canonicalization step" L335; PS/AS fetch
  split L388; resource enforcement matches L483–L484; `#per-call-proposals` L491;
  atomic audit L557.
- Base: three-party "resource applies its own access policy" L312; "at least one
  of `sub` or `scope` MUST be present" L1686 / verify step L1724; multi-hop "flight
  booking API that calls a payment processor" example L1771 / L3236.
- SDK: token-exchange body uses `resource_token` not an OAuth `grant_type`
  ([TokenExchangeClient.cs L83](../../../src/AAuth/Agent/TokenExchangeClient.cs));
  `Mission.ComputeS256` hashes verbatim bytes
  ([Mission.cs L125](../../../src/AAuth/Agent/Mission.cs)); `ResourceTokenBuilder`
  is a closed init-property set; `AuthTokenBuilder` has an `AdditionalClaims` bag
  plus a hard `sub|scope` guard; `MapAAuthAuthorizationEndpoint` parses only
  `{ "scope" }` ([AAuthApplicationBuilderExtensions.cs L123](../../../src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs)).

**Reported by subagents (not independently line-checked; anchors durable, lines
may drift):** the finer line numbers for `IAccessPolicy`, `AAuthEndpointExtensions`,
`AAuthChallengeMiddleware`, `TourOptions`/`TourSession`, and the `Makefile` targets.
These are cited below with that caveat.

---

## Part A — R3 spec model (verified)

### A.1 Core concepts

- **Vocabulary** (`urn:aauth:vocabulary:*`) names how operations are expressed for
  an interface type (MCP, OpenAPI, gRPC, GraphQL, AsyncAPI, WSDL, OData). Agents
  declare operations; resource and AS interpret them through the vocabulary
  (r3 L101–L103).
- **R3 document** — JSON the **resource** publishes, describing a class of access:
  `vocabulary`, `operations`, human-readable `display` (r3 `#r3-document`).
- **`r3_uri`** — where the AS fetches the document. **`r3_s256`** —
  `base64url(SHA-256(served-bytes))`, no padding. The document's identity is its
  **hash**, not its URI (r3 `#content-addressing` L331–L340).
- **Resource-declared, not client-declared** — the resource defines and signs the
  access semantics; the agent carries an opaque hash it cannot read (r3 §Design
  Rationale / Why Not RAR).

### A.2 Content addressing — **verbatim bytes, no canonicalization** (correction)

> "The resource's serialization **is** the document. **There is no
> canonicalization step** — verifiers hash the bytes received over the wire, not a
> normalized form." — [r3 L335](../../../aauth-spec/v08/draft-hardt-aauth-r3.md)

`r3_s256 = base64url(SHA-256(exact-served-bytes))`, no padding. Resources MUST
serialize the document **once** and serve those exact bytes verbatim on every
fetch; re-serialization (parse-and-re-stringify middleware, `Results.Json`, CDN
minification, key reordering) breaks the hash (r3 L335–L340). This is **byte-for-
byte identical** to how the SDK already computes the mission `s256`
([Mission.ComputeS256, Mission.cs L125](../../../src/AAuth/Agent/Mission.cs):
`SHA256.HashData(bytes)` → `Base64UrlEncoder.Encode`). **No RFC 8785 dependency
exists or is needed** — this is the single largest correction versus the 2026-06-06
plan.

### A.3 Where each claim/parameter lives (verified)

| Extension point | Spec | Shape |
|---|---|---|
| Resource metadata | r3 `#resource-metadata-extensions` L83 | OPTIONAL `r3_vocabularies` — object `{ vocab-URI → discovery endpoint }` in `aauth-resource.json` |
| **Authorization endpoint request** | r3 `#authorization-endpoint-extensions` **L234–L266** | OPTIONAL `r3_operations` `{ vocabulary, operations[] }` in the **resource's** `authorize` body — **not** the PS/AS token endpoint |
| Resource token | r3 §Resource Token Extensions L342–L360 | adds `r3_uri` + `r3_s256` (MUST include both when R3 present); coexists with `scope` |
| AS processing | r3 §AS Processing L396–L404 | fetch R3 (AS-signed), hash-verify or reject, **audit**, evaluate `operations`, mint claims |
| Auth token | r3 §Auth Token Extensions L419–L475 | adds `r3_uri`, `r3_s256`, `r3_granted` (REQUIRED for R3), `r3_conditional` (OPTIONAL) |
| Resource enforcement | r3 §Resource Enforcement L479–L485 | match → `r3_granted` (serve) / `r3_conditional` (challenge+proposal) / else reject |
| PS processing | r3 L388–L389 | PS fetches R3 only to render `display` for consent — **display-only** |

**Key directionality fact (correction):** `r3_operations` is a request parameter of
the **resource's** authorization endpoint (r3 L236: "it includes `r3_operations` in
the authorization endpoint request body"; example targets
`Host: calendar.example.com` L242). The PS/AS never receives `r3_operations`; it
learns the R3 context from the resource token's `r3_uri`/`r3_s256`, which it
**fetches itself** (r3 L395–L404). `scope` remains REQUIRED at the authorize
endpoint (base L620–L622); `r3_operations` is additive.

### A.4 Claim semantics — objects, not strings (correction)

`r3_operations`, `r3_granted`, `r3_conditional`, and an R3 document's `operations`
all use the **same** vocabulary-specific structure: an object
`{ "vocabulary": "...", "operations": [ ... ] }` where each operation is a small
object keyed by the vocabulary (MCP `{ "tool": "..." }`, OpenAPI
`{ "operationId": "..." }`, gRPC `{ "method": "pkg.Svc/M" }`, etc.) — r3 L261–L263,
L322 ("the same format used in the agent's `r3_operations` request and in the auth
token's `r3_granted` and `r3_conditional`"), L472–L475. They are **not** scope
strings, CSV, or arrays of strings. Both exploration subagents initially modelled
them as string lists; that is non-conformant and is corrected throughout Part D.

- **`r3_granted`** (REQUIRED for R3): operations the AS fully authorized — the
  resource serves them immediately, no round-trip.
- **`r3_conditional`** (OPTIONAL): operations authorized in principle but requiring
  per-call approval against the concrete parameters (r3 L476–L485).

### A.5 Per-call proposals — reuse the existing challenge, no new header (correction)

An `r3_conditional` operation is not authorized for any specific call. When the
agent invokes one (r3 `#per-call-proposals` L491–L539):

1. **Conditional challenge.** The resource builds a **per-call proposal** — a
   single-invocation R3 document that adds a `parameters` object (large/sensitive
   values as a `{ s256, excerpt?, media_type? }` digest) — persists it keyed by its
   `r3_s256`, and returns the **existing** `AAuth-Requirement=auth-token` with a
   resource token whose `r3_uri`/`r3_s256` reference the proposal (r3 L529; base
   `#requirement-auth-token` L780–L782). The token carries only the reference, not
   the parameters.
2. **Approval.** The AS fetches the proposal, evaluates `parameters`, and issues a
   per-call auth token echoing the proposal's `r3_uri`/`r3_s256` with the operation
   now in `r3_granted`.
3. **Enforced retry.** The agent retries; the resource recovers the proposal by
   `r3_s256` and **MUST verify** each presented parameter matches the approved
   proposal — for a digest, `base64url(SHA-256(presented)) == stored s256` — and
   reject on any mismatch (r3 L531). An approval to email one recipient cannot be
   replayed against another.

There is **no** `AAuth-Conditional-Access` header (a value both exploration
subagents invented); the flow reuses the standard `AAuth-Requirement` challenge and
the standard token-exchange path.

### A.6 Security invariants (verified)

- **AS-only R3-document fetch** (r3 L297, L541–L549): the resource MUST require a
  valid HTTP Message Signature from **its AS** on `r3_uri` requests and reject all
  others. This is the linchpin of agent opacity and is a critical, deployment-
  tested access control.
- **Hash-verify before use** (r3 L400–L403): the AS MUST verify `r3_s256` against
  the fetched bytes before using the document.
- **Atomic audit-with-issuance** (r3 L557): auth-token issuance and its audit-log
  entry MUST be written atomically (transactional or equivalent).
- **Operation validation** (r3 §Operation Validation): the resource MUST validate
  declared operations against its authoritative interface definition before issuing
  a resource token.
- **Grant enforcement** (r3 §Grant Enforcement L563–L565): `r3_granted` served;
  `r3_conditional` MUST trigger a challenge; non-matching calls rejected.

### A.7 Standard vocabularies

Seven registered under `urn:aauth:vocabulary:` — `mcp` (`tool`), `openapi`
(`operationId`), `grpc` (`method`), `graphql` (`operation`+`type`), `asyncapi`
(`operationId`+`action`), `wsdl` (`operation`+`service?`), `odata`
(`operation`+`methods?`). Third parties MAY define more (r3 §Standard Vocabularies,
L101–L232). **OpenAPI** is the natural fit for an ASP.NET resource; **MCP** fits an
agent that speaks the Model Context Protocol.

---

## Part B — Current SDK surface & R3 extension points (verified)

New R3 code belongs in a new **`src/AAuth/R3/`** folder (mirrors `Tokens/`,
`Server/`, `Access/`, `Person/`). The concrete seams:

| Concern | File / type | R3 touch |
|---|---|---|
| Resource token | [Tokens/ResourceTokenBuilder.cs](../../../src/AAuth/Tokens/ResourceTokenBuilder.cs) — closed init-prop set (`iss`/`dwk`/`aud`/`jti`/`agent`/`agent_jkt`/`scope`/`mission`) | add `R3Uri`, `R3S256` (both-or-neither) |
| Auth token | [Tokens/AuthTokenBuilder.cs](../../../src/AAuth/Tokens/AuthTokenBuilder.cs) — typed props + `AdditionalClaims` bag; hard `sub|scope` guard (L155–L159) | add `R3Uri`, `R3S256`, `R3Granted`, `R3Conditional` as typed props |
| Claim record precedent | [Tokens/MissionClaim.cs](../../../src/AAuth/Tokens/MissionClaim.cs) — `ToJsonObject()`/`FromPayload()` | mirror for `R3OperationSet` |
| Hashing | [Agent/Mission.cs L125](../../../src/AAuth/Agent/Mission.cs) `ComputeS256(ReadOnlySpan<byte>)` | reuse verbatim-bytes hash for R3 |
| Metadata | [Server/Metadata/WellKnownEndpoints.cs](../../../src/AAuth/Server/Metadata/WellKnownEndpoints.cs) — `AAuthResourceMetadataOptions` + `BuildResourceMetadata` (the `ScopeDescriptions` block is the map-emit precedent) | add `R3Vocabularies` |
| Authorize endpoint | [DependencyInjection/AAuthApplicationBuilderExtensions.cs L123](../../../src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs) `MapAAuthAuthorizationEndpoint`; [Server/AAuthAuthorizationRequest.cs](../../../src/AAuth/Server/AAuthAuthorizationRequest.cs) | parse `r3_operations`; carry it into the handler |
| Challenge | [Server/Challenge/AAuthChallengeMiddleware.cs](../../../src/AAuth/Server/Challenge/AAuthChallengeMiddleware.cs) + `ChallengeOptions` (static per-endpoint config) | **not** the vehicle for dynamic per-call proposals — see S5 |
| Dynamic challenge | `HttpContext.ChallengeAAuth(resourceToken)` ([Server/Verification/AAuthHttpContextExtensions.cs](../../../src/AAuth/Server/Verification/AAuthHttpContextExtensions.cs)) | mint the per-call proposal resource token here |
| Verification result | [Server/Verification/AAuthVerificationResult.cs](../../../src/AAuth/Server/Verification/AAuthVerificationResult.cs) (no `Mission` field today) | add `R3Uri`/`R3S256`/`R3Granted`/`R3Conditional` as new first-class fields, populated in `AAuthVerificationMiddleware` |
| Access server | [Access/IAccessPolicy.cs](../../../src/AAuth/Access/IAccessPolicy.cs) (`AccessPolicyRequest`, `AccessDecision.Allow` closed factory); [Access/AAuthAccessServerEndpoints.cs](../../../src/AAuth/Access/AAuthAccessServerEndpoints.cs) | add fetched `R3Document`+`R3Uri`+`R3S256` to the request; `R3Granted`/`R3Conditional` to the decision |
| Person server | [Person/IIdentityClaimsAsserter.cs](../../../src/AAuth/Person/IIdentityClaimsAsserter.cs) | expose R3 `display` on the request — **display-only**, no grant minting |
| Agent proactive authorize | *(no existing client — new surface)* | agent-side POST to a resource `authorization_endpoint` carrying `r3_operations` |
| Server-to-server signing | [HttpSig/AAuthSigningHandler.cs](../../../src/AAuth/HttpSig/AAuthSigningHandler.cs) + [HttpSig/JwksUriSignatureKeyProvider.cs](../../../src/AAuth/HttpSig/JwksUriSignatureKeyProvider.cs) | AS-signed R3 fetch reuses this (jwks_uri scheme) |
| Constants | [AAuthConstants.cs](../../../src/AAuth/AAuthConstants.cs) — `Headers`/`Schemes`/`AccessModes`/`TokenTypes`/`DwkFiles` | add a `Vocabularies` group + R3 claim-name constants |

Token `typ` values are `aa-resource+jwt` / `aa-auth+jwt` (draft-08 rename). R3
draft-00 examples show `resource+jwt` / `auth+jwt`; the R3 **claims** layer onto the
draft-08 `typ` values (the SDK targets the base protocol).

---

## Part C — API-surface conventions R3 must honor

R3 must extend, not fight, the server surface shipped in
[.agent/plans/2026-06-27-server-api-surface](../2026-06-27-server-api-surface/implementation-plan.md).
Load-bearing conventions:

- **One-call DI.** `AddAAuthResource(o => …)` registers verifier, discovery
  clients, jti store, and complete metadata. Consumers register **zero**
  `HttpClient`/named-client lines — the SDK owns discovery transport.
- **Declarative per-route protection.** `UseAAuth(o => o.TrustedAuthTokenIssuers = …)`
  (post-routing) + per-route `.RequireAAuth(scope:, role:, missionAware:)` /
  `.RequireAAuthSignature(identified:)` via `AAuthEndpointRequirement` metadata.
  Fail-closed if `UseRouting` did not run.
- **Opt-in modules.** Resource-managed interaction is a module you turn on
  (`AddAAuthResourceManaged` + `RequireAAuthInteraction` + `MapAAuthInteractionPoll`),
  not code embedded in a payload endpoint.
- **No string indirection.** Two call sites that must agree share a **typed handle**,
  never a magic string. Protocol values (headers/schemes/claims/vocab URIs) are
  typed constants; a scope/operation *value* may appear once as protocol data.
- **Layered 80/20, no god-object.** Every high-level call must be reassemblable from
  the primitives beneath it; the high-level surface carries a *named, closed* set of
  axes and defaults the rest from DI. Variation beyond that set falls through to the
  primitives.
- **Spec owns the wire; app owns policy + presentation.** The SDK owns code formats,
  headers, poll loops, token shapes, fetch/hash/verify/audit; the app owns the
  consent page look-and-feel and the policy decision.

**R3 implication:** the SDK owns R3 hashing, byte-verbatim serving, AS-signed fetch,
hash-verify, audit, and per-call-proposal binding. The sample owns only the
operation catalogue, the policy decision, and the consent copy.

---

## Part D — Design suggestions (validated)

Each suggestion carries the validator verdict and any required correction folded
in. These are a **design inventory**, not an ordered task list.

### S1 — R3 primitives (`src/AAuth/R3/`) — VALID (with caveats)

- **`R3OperationSet { string Vocabulary; IReadOnlyList<R3Operation> Operations }`** —
  one type reused for `r3_operations`, `r3_granted`, `r3_conditional`, and an R3
  document's `operations`, with `ToJsonObject()`/`FromJson()`. The spec makes this
  identity explicit (r3 L261–L263, L322, L472–L475). **VALID.**
- **`R3Operation`** — first-class MCP `{ tool }` and OpenAPI `{ operationId }`, with
  a `JsonObject` escape hatch for the other five vocabularies. Typed factories
  `R3Operation.Mcp(tool)` / `R3Operation.OpenApi(operationId)`. The escape hatch is
  acceptable (the spec does not require all seven be typed) **provided** it
  preserves each vocabulary's REQUIRED extra keys (`graphql.type`,
  `asyncapi.action`, `wsdl.service`, `odata.methods`) and snake_case names.
- **`R3Document { Version?, Vocabulary, Operations[], Display? }`** plus a per-call
  proposal variant adding `Parameters` (+ digest `{ s256, excerpt?, media_type? }`).
- **`R3Display { Summary, Implications?, DataAccessed?, Irreversible?, Detail? }`**
  (`detail` markdown is proposal-only; r3 L515–L524). **VALID.**
- **Hashing & storage.** Reuse the verbatim-bytes hash. **Correction:** do **not**
  name any helper `…Canonical…` (there is no canonicalization, r3 L335); a
  `SerializeOnce()`/persist-bytes model is correct. Provide **`IR3DocumentStore`**
  (`Store(doc) → (uri, s256)`; `TryGet(s256) → bytes`) with an in-memory default,
  and the r3_uri endpoint MUST write the persisted bytes **raw** (never
  `Results.Json`, which re-serializes and breaks the hash, r3 L335–L336).

### S2 — `r3_vocabularies` resource metadata — VALID

Add `R3Vocabularies` (`IReadOnlyDictionary<string,string>`) to
`AAuthResourceMetadataOptions`; emit it in `BuildResourceMetadata` exactly like the
existing `ScopeDescriptions` guarded-nested-object block; set it via
`AddAAuthResource(o => o.R3Vocabularies = …)`. Shape matches r3 L83–L112 exactly.
(SDK keeps the pre-existing `issuer` identity field; the R3 example's `resource`
field is draft-02 naming and out of scope.)

### S3 — Token claims — VALID (with caveats)

- `ResourceTokenBuilder` gains `R3Uri`, `R3S256` (validate both-or-neither; r3 L344
  "MUST include both").
- `AuthTokenBuilder` gains `R3Uri`, `R3S256`, `R3Granted` (`R3OperationSet`,
  REQUIRED for R3), `R3Conditional` (`R3OperationSet`, OPTIONAL) as **typed props**
  (mirrors the `MissionClaim` precedent), **not** the loose `AdditionalClaims` bag.
- `AAuthVerificationResult` gains the four R3 fields as **new first-class fields**
  (it has no `Mission` field today), populated in `AAuthVerificationMiddleware`.
- **Correction (keep the guard):** an R3 auth token **still requires `sub` OR
  `scope`**; `r3_granted` does **not** satisfy the base rule (base L1686, verify
  step L1724; enforced at `AuthTokenBuilder.cs` L155–L159). An R3 resource therefore
  still issues a `scope` (even a coarse one) alongside the R3 grant.

### S4 — Agent side — VALID **only after relocating `r3_operations`** (was INVALID as first drafted)

- **Correction (blocker):** `r3_operations` must be sent to the **resource's
  `authorization_endpoint`**, not the PS/AS token endpoint (r3 L234–L266). Put
  `R3Operations` on the authorize path — extend `AuthorizationEndpointBody` +
  `AAuthAuthorizationRequest` + `MapAAuthAuthorizationEndpoint` — and add a **new
  agent-side proactive authorize client** (none exists today; the agent only has
  reactive challenge handling). Do **not** add `R3Operations` to
  `TokenExchangeRequest` — the PS/AS learns R3 from the resource token it fetches.
- After exchange, the agent reads `r3_granted`/`r3_conditional` via a typed accessor
  on the parsed auth token.
- The conditional per-call round-trip reuses the **existing**
  `AAuth-Requirement=auth-token` challenge + token-exchange path (base L782; r3 L484,
  L529) — **no new agent header or handler**. `HttpContext.ChallengeAAuth` and the
  current challenge handling suffice on both ends.

### S5 — Resource-side enforcement — VALID (with two important caveats)

- **Read/match helpers.** `HttpContext` extensions: `GetAAuthR3Grant()` (typed
  granted/conditional from the verification result) and
  `MatchR3Operation(R3Operation) → { Granted, Conditional, None }`. The
  serve/challenge/reject algorithm matches r3 L479–L485 and L563–L565 exactly.
  **VALID.**
- **Correction 1 (dynamic challenge).** Per-call `r3_uri`/`r3_s256` are **dynamic**;
  `ChallengeOptions` is static per-endpoint config for the auto-challenge
  middleware. `RequireAAuthProposal(R3Document proposal, IR3DocumentStore)` should
  mint the resource token dynamically via `ResourceTokenBuilder` (+ the new R3 props
  from S3) and return through `HttpContext.ChallengeAAuth(resourceToken)` — **not**
  by extending `ChallengeOptions`.
- **Correction 2 (security — new code required).** The AS-only R3-fetch gate
  (r3 L297, L541–L549) is a MUST and is **not** provided by
  `.RequireAAuthSignature(identified:)`, which accepts **any** valid signer;
  moreover `AAuthVerificationResult.Issuer` is null for the jwks_uri scheme the AS
  uses. A **new issuer-pinned gate** is required that asserts the verified signer
  equals the resource's configured AS identity. Building blocks exist
  (`AAuthVerifier`, `JwksUriSignatureKeyProvider`, `SignatureOnly()`), but the pin
  is new surface — likely `.RequireAAuthSignature(pinnedIssuer: asUrl)` or a
  dedicated `MapAAuthR3Document(store, asIssuer)` helper.
- On retry, `VerifyR3Proposal(store, presentedParameters)` enforces the digest match
  (r3 L531) and rejects on mismatch.

### S6 — AS/PS-side R3 processing (SDK-owned) — VALID (AS) / corrected (PS)

- The **SDK** (not the sample) fetches `r3_uri` via an AS-signed GET
  (`AAuthSigningHandler` + jwks_uri provider), hash-verifies against `r3_s256`,
  caches by `s256`, and audits **before** invoking policy — a new
  **`IR3DocumentFetcher`** (default = signed fetch + verify + cache, no manual
  `HttpClient`). This placement matches the existing "crypto in the host, policy
  only decides" split ([IAccessPolicy.cs](../../../src/AAuth/Access/IAccessPolicy.cs),
  [MockAccessServer/Program.cs](../../../samples/MockAccessServer/Program.cs)) and
  the atomic-audit MUST (r3 L557). **VALID.**
- `AccessPolicyRequest` gains `R3Uri`, `R3S256`, and the fetched+verified
  `R3Document`; `AccessDecision.Allow` gains typed `R3Granted`/`R3Conditional`,
  minted into the auth token by `MapAAuthAccessServer`.
- **Correction (PS is display-only).** Only the **AS** populates
  `r3_granted`/`r3_conditional` (r3 L391, L404); base three-party puts policy on the
  resource and never has the PS emit grants (base L312). Exposing R3 `display` on
  `IdentityAssertionRequest` for consent is fine; **do not mint `r3_granted` from
  the PS.** Both PS and AS are auth-token issuers and both fetch R3, but grant
  population is an AS-only role.

### S7 — Bookings resource server sample — VALID (with a narrative reframe)

- New `samples/MockResourceServers/Bookings` on **port 5005** (free; Makefile
  L24–L35). Advertises an **OpenAPI** vocabulary (natural ASP.NET fit; MCP optional)
  via `r3_vocabularies`. Operations: `searchBookings` / `getBooking` (read →
  `r3_granted`), `createBooking` (→ `r3_granted`), and **`payBooking`** (or
  `cancelBooking`) as **`r3_conditional`** — irreversible and costly, so it exercises
  the per-call proposal flow end-to-end (r3 L491–L539: `parameters`, digest, AS
  re-eval, enforced retry). Serves AS-gated R3 document + proposal endpoints;
  enforces grants with the S5 helpers. Built with `AddAAuthResource` +
  `MapAAuthWellKnown` + `UseRouting`/`UseAAuth` + per-route helpers — the Wallet
  shape.
- **Correction (narrative collision).** Trips (:5002) already owns *trip* booking
  (`/trips/book`, `trips.book`, mission-aware). Reframe Bookings as a **distinct
  external reservations/payments provider** (hotel / restaurant / event ticket +
  an irreversible **payment**). The base spec itself uses "a flight booking API
  that calls a payment processor" as the multi-hop example (base L1771, L3236),
  which fits perfectly: **Trips = mission gating; Bookings = the R3 concept server**
  (vocabulary operations + conditional payment). Drop "trip" from Bookings copy.

### S8 — Integration surfaces — VALID (with caveats)

- **GuidedTour.** Add a `TourMode` (e.g. `RichRequests`) — enum in
  [TourOptions.cs](../../../samples/GuidedTour/TourOptions.cs); mappings are
  name-based switch expressions in
  [TourSession.cs](../../../samples/GuidedTour/TourSession.cs) (subagent-reported
  L151–L207). Insert **after `Federated`** (its four-party neighbour). Enum has no
  persisted int values, so insertion is safe; every `Mode is TourMode.X ? …` switch
  needs a matching arm plus URL/highlighter wiring.
- **SampleApp.** New `/bookings` page under
  [samples/SampleApp/Components/Pages](../../../samples/SampleApp) demonstrating the
  conditional per-call approval.
- **Makefile.** Add `BOOKINGS_PROJECT`/`BOOKINGS_URL` (5005) and wire `resources`
  and `demo`; add `BOOKINGS_AS_*` if a dedicated AS (see decision below);
  GuidedTour/SampleApp `appsettings` get `BOOKINGS_URL`.
- **Tests (caveat).** A four-party `BookingsFlowTests` needs a **third in-proc
  host** (the AS) via `MultiHostHandler` — closer to
  [MockPersonServerFederationTests](../../../tests/AAuth.Tests/Integration) /
  `MockAccessServerTests` than to the two-host `CalendarFlowTests`. Bookings and its
  AS must expose public `Entry` partials (like `Calendar.Entry`).
- **Docs.** New `docs/workflows/rich-resource-requests.md`, slotted **after**
  [docs/workflows/federated-access.md](../../../docs/workflows/federated-access.md),
  near [mission-governed-access.md](../../../docs/workflows/mission-governed-access.md).

---

## Part E — Access-mode decision for Bookings

**Recommendation: four-party (Bookings has its own AS), with a *dedicated* Bookings
AS rather than reusing MockAccessServer.** Both validators concur; firm.

- **Four-party is the spec-natural mode.** R3 grant population and per-call
  evaluation are AS-centric throughout (r3 L391, L404, L530). Three-party has no AS,
  and the base protocol puts policy on the **resource** in that mode (base L312) —
  so three-party R3 would force the PS to improvise the AS's grant-population role, a
  spec gap. The PS still fetches R3 for `display` consent in either mode (r3 L389).
- **A dedicated Bookings AS beats reusing MockAccessServer.** MockAccessServer is
  wallet-shaped (`DefaultScope=wallet.read`, admin-role derivation, Keycloak
  `ResourceName=wallet`) with a single registered `IAccessPolicy`
  ([MockAccessServer/Program.cs](../../../samples/MockAccessServer/Program.cs)). R3
  grants are **operation-based, not scope-based**, and would force a resource-routing
  branch inside one policy, coupling two teaching demos. Since either path needs new
  R3 code in the AS, reuse buys little. A dedicated AS (own R3 `IAccessPolicy`, no
  Keycloak coupling) keeps the one-server-per-concept suite clean.
- **Port:** open question (Q3) — `5501` (groups with the AS role at :5500) or
  `5006` (groups with the Bookings cluster). Reusing MockAccessServer remains a
  lighter fallback that piggybacks the AS already in `make demo`.

---

## Part F — Consolidated security invariants (implementation must test)

1. **Byte-verbatim serving** (r3 L331–L340): persist and serve exact bytes for both
   class R3 documents **and** per-call proposals; never re-serialize. Highest-
   frequency footgun with ASP.NET JSON helpers.
2. **AS-only R3-fetch, issuer-pinned** (r3 L297, L541–L549): new gate pinning the
   verified signer to the resource's specific AS (S5 correction 2).
3. **Hash-verify before use** (r3 L400–L403): reject on `r3_s256` mismatch.
4. **Atomic audit-with-issuance** (r3 L557).
5. **Per-call digest verification** (r3 L531): reject when presented parameters do
   not match the approved proposal.
6. **Operation validation** against the authoritative interface definition before
   issuing a resource token (r3 §Operation Validation).

---

## Part G — Risks & considerations

- **Draft status.** R3 is an Exploratory Draft (draft-00) with no other known
  implementations; APIs built now may need rework. Conformance vectors should record
  the draft revision.
- **New agent-side proactive authorize client** (S4) is genuinely new surface, not
  an extension of an existing type.
- **AS-only-fetch pin** (S5/F2) is security-critical and unbuilt; a weak
  implementation silently breaks agent opacity.
- **Vocabulary escape hatch** (S1) risks dropping REQUIRED per-vocabulary keys if
  modelled too loosely.
- **Test topology** shifts to three in-proc hosts for the four-party Bookings flow.

---

## Open questions

Resolve in an implementation plan's Phase 0 gate; defaults offered to stay
unblocked.

1. **Vocabulary coverage.** Type MCP + OpenAPI first-class with a generic escape
   hatch for the other five (**default**), or fully type all seven? Product/API
   preference, not a spec requirement.
2. **Bookings vocabulary.** OpenAPI (**default**, natural ASP.NET fit), MCP, or
   both advertised simultaneously (the spec allows multiple, r3 L112)?
3. **Bookings AS port.** `5501` (AS-role grouping, **default lean**) vs `5006`
   (Bookings cluster) — or reuse MockAccessServer as a lighter fallback?
4. **AS-only-fetch gate shape.** `.RequireAAuthSignature(pinnedIssuer:)` overload
   vs a dedicated `MapAAuthR3Document(store, asIssuer)` mapper (**default lean:
   dedicated mapper**, since it also owns byte-verbatim serving).
5. **Proposal store seam.** Reuse `IR3DocumentStore` for both class docs and per-call
   proposals (**default**), or a distinct `IR3ProposalStore`?
6. **GuidedTour placement.** New `RichRequests` mode after `Federated` (**default**)
   — confirm the exact ordering and whether it also demonstrates the deferred
   consent variant.

---

## Out of scope (unless decided otherwise)

| Item | Reason |
|---|---|
| RFC 8785 / JCS canonical JSON | **Not required** — R3 hashes verbatim bytes (r3 L335); the old plan's prerequisite is void |
| Vocabulary *discovery* parsing (fetch/parse MCP tool list, OpenAPI spec, `$metadata`, introspection) | Resource/agent discovery detail; a later R3 phase at most |
| Fully-typed models for all seven vocabularies | See Q1; escape hatch suffices for the demo |
| PS-side `r3_granted` minting | Out of spec — the PS is display-only (r3 L391, L404) |
| Reusing MockAccessServer for Bookings | Superseded by the dedicated-AS recommendation (Part E); retained only as a fallback |
| Mission ↔ R3 combined governance flow | The spec does not define the interplay; keep orthogonal in samples unless a design decision says otherwise |

---

## Appendix — source references

- R3 spec: [aauth-spec/v08/draft-hardt-aauth-r3.md](../../../aauth-spec/v08/draft-hardt-aauth-r3.md)
  (anchors + line-verified numbers cited inline).
- Base spec: [aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md](../../../aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md).
- Prior R3 research (superseded): [.agent/plans/2026-06-06-r3-rich-resource-requests/research.md](../2026-06-06-r3-rich-resource-requests/research.md).
- API-surface conventions: [.agent/plans/2026-06-27-server-api-surface](../2026-06-27-server-api-surface/implementation-plan.md).
- SDK seams: [src/AAuth/Tokens](../../../src/AAuth/Tokens), [src/AAuth/Server/Metadata/WellKnownEndpoints.cs](../../../src/AAuth/Server/Metadata/WellKnownEndpoints.cs), [src/AAuth/Access](../../../src/AAuth/Access), [src/AAuth/Person](../../../src/AAuth/Person), [src/AAuth/HttpSig/AAuthSigningHandler.cs](../../../src/AAuth/HttpSig/AAuthSigningHandler.cs).
- Samples: [samples/MockResourceServers](../../../samples/MockResourceServers), [samples/MockAccessServer](../../../samples/MockAccessServer), [samples/GuidedTour](../../../samples/GuidedTour), [samples/SampleApp](../../../samples/SampleApp), [Makefile](../../../Makefile).
