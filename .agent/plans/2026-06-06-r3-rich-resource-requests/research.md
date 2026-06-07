# R3 (Rich Resource Requests) — Research

## Problem Statement

The AAuth **Rich Resource Requests (R3)** extension
(`aauth-spec/draft-hardt-aauth-r3.md`) adds **resource-declared, vocabulary-based
authorization** to the AAuth Protocol: resources publish content-addressed **R3
documents** describing what a class of access *means*, and tokens carry `r3_uri`,
`r3_s256`, `r3_granted`, and `r3_conditional` claims instead of (or alongside)
opaque scopes. The AAuth .NET SDK (`src/AAuth/`) has **zero** R3 implementation.

This document captures the R3 spec model, the current (empty) SDK state, the
implementation surface, the prerequisites (notably RFC 8785 canonical JSON), the
interplay with missions, and the open design choices — so a future initiative can
plan R3 support. It contains **no** implementation steps; those live in
[implementation-plan.md](implementation-plan.md).

> This research was **extracted** from the mission-API initiative
> (`.agent/plans/2026-06-06-mission-api-refactor/`) on 2026-06-06, where R3 was
> originally folded in as Part E and then split out at the user's request.

## Source Documents

| Document | Location | Relevant Sections |
|----------|----------|-------------------|
| AAuth R3 (Rich Resource Requests) | `aauth-spec/draft-hardt-aauth-r3.md` | §Vocabularies; §Authorization Endpoint Extensions; §R3 Document; §Resource Token Extensions; §R3 Processing (MM/AS); §Auth Token Extensions; §Security Considerations; §IANA; §Design Rationale |
| AAuth Protocol (base) | `aauth-spec/draft-hardt-oauth-aauth-protocol.md` | §Authorization Endpoint; §Resource Token; §Auth Token; HTTP Message Signatures (AS-signed R3 fetch) |
| RFC 8785 (JCS) | external | JSON Canonicalization Scheme — required for `r3_s256` |

> **Draft status:** R3 is an **Exploratory Draft** (draft-hardt-aauth-r3-00, dated
> 2026-03-24). Its Implementation Status section states: *"There are currently no
> known implementations."* The spec may change materially before standardization,
> which is central to the in-scope-now vs. wait decision (see
> [Open Design Choices](#open-design-choices)).

---

## Part A — R3 Spec Model

### A.1 Core concepts (§R3 Document; §Vocabularies)

- **Vocabulary** (`urn:aauth:vocabulary:*`): names how operations are expressed for
  an interface type. The agent declares operations; the resource and AS interpret
  them through the vocabulary.
- **R3 Document**: a JSON object the **resource** publishes at a URI, describing a
  class of access — `vocabulary`, `operations`, and human-readable `display`. It is
  **content-addressed** by SHA-256 of its RFC 8785 canonical form.
- **`r3_uri`**: where the AS fetches the R3 document.
- **`r3_s256`**: `base64url(SHA-256(RFC8785(document)))`, no padding. The document's
  identity is its **hash**, not its URI — enabling infinite caching and permanent
  audit provenance.
- **Resource-declared, not client-declared** (§Design Rationale / Why Not RAR): the
  resource defines and **signs** the access semantics; the agent cannot reframe it.
  This opposite directionality from OAuth RAR is a deliberate security property.

### A.2 Standard vocabularies (§Vocabularies)

Seven registered vocabularies, each with a vocabulary-specific operation shape:

| Vocabulary URI | Interface | Operation entry |
|----------------|-----------|-----------------|
| `urn:aauth:vocabulary:mcp` | MCP server | `tool` (REQUIRED) |
| `urn:aauth:vocabulary:openapi` | HTTP/REST | `operationId` (REQUIRED) |
| `urn:aauth:vocabulary:grpc` | gRPC | `method` = `pkg.Service/Method` (REQUIRED) |
| `urn:aauth:vocabulary:graphql` | GraphQL | `operation` + `type` (query/mutation/subscription) |
| `urn:aauth:vocabulary:asyncapi` | Event-driven | `operationId` + `action` (send/receive) |
| `urn:aauth:vocabulary:wsdl` | SOAP/WSDL | `operation` + `service?` |
| `urn:aauth:vocabulary:odata` | OData | `operation` + `methods?` |

New values register under Specification Required (RFC 8126).

### A.3 R3 Document fields (§R3 Document / Fields)

- **`version`** (RECOMMENDED) — human-readable; identity is the hash, not this.
- **`vocabulary`** (REQUIRED) — must match one advertised in `r3_vocabularies`.
- **`operations`** (REQUIRED) — vocabulary-specific array; same shape used in the
  agent request and the auth token grants.
- **`display`** (RECOMMENDED) — consent-facing description of what *the resource*
  does:
  - `summary` (REQUIRED if `display` present)
  - `implications` (OPTIONAL) — side effects (emails sent, records modified, costs)
  - `data_accessed` (OPTIONAL) — what becomes visible
  - `irreversible` (OPTIONAL) — actions that cannot be undone

### A.4 Extension points (where R3 touches the protocol)

| Extension point | Spec § | Shape |
|-----------------|--------|-------|
| Resource metadata | §Vocabularies (intro) | OPTIONAL `r3_vocabularies` object (vocabulary URI → discovery endpoint) in `/.well-known/aauth-resource.json` |
| Authorization endpoint request | §Authorization Endpoint Extensions | OPTIONAL `r3_operations` `{vocabulary, operations[]}` in the authorize body |
| Resource token | §Resource Token Extensions | adds `r3_uri` + `r3_s256` (MUST include both when R3 present); coexists with `scope` — AS enforces both independently |
| AS processing | §R3 Processing / AS Processing | fetch R3 doc (AS-signed), hash-verify, audit `r3_uri`/`r3_s256`, evaluate `operations`, mint auth-token claims |
| Auth token | §Auth Token Extensions | adds `r3_uri`, `r3_s256`, `r3_granted` (REQUIRED), `r3_conditional` (OPTIONAL) |
| Resource enforcement | §Auth Token Extensions / Resource Enforcement | match call → `r3_granted` (serve) / `r3_conditional` (challenge w/ params) / else reject |
| MM processing | §R3 Processing / MM | fetch R3 doc to show `display` during consent |

### A.5 Token claim semantics (§Auth Token Extensions)

- **`r3_granted`** (REQUIRED): operations the AS fully authorized — the resource
  serves them immediately, no further round-trip.
- **`r3_conditional`** (OPTIONAL): operations authorized *in principle* but requiring
  per-call approval. The resource returns `AAuth-Requirement` with a resource token
  containing the **actual call parameters**; the AS evaluates those concrete params
  and issues a per-call auth token.
- Enforcement needs **no introspection or R3 fetch** at access time — the resource
  matches against the vocabulary it already understands.

### A.6 Content addressing & caching (§Content Addressing; §R3 Processing / Caching)

- The AS (and MM) cache R3 documents by `r3_s256`; a document that verifies against
  its hash never needs re-fetching.
- Old auth tokens keep referencing the previous hash even after the resource updates
  the document at the same URI — permanent audit provenance.
- The AS need not retain documents beyond token issuance; its audit log records
  `r3_uri` + `r3_s256`, sufficient for later re-verification.

### A.7 Security invariants (§Security Considerations)

- **AS-only R3-document fetch.** The resource MUST require a valid HTTP Message
  Signature from its AS on R3-document requests and reject all others. This is what
  makes agents carry a hash of a document they cannot read (agent opacity). Treat as
  a critical, deployment-tested access control.
- **Hash-verify before use.** The AS MUST verify `r3_s256` against the fetched
  document before using it.
- **Atomic audit-with-issuance.** Auth-token issuance and its audit-log entry MUST be
  written atomically (transactional or equivalent).
- **Operation validation.** The resource MUST validate declared operations against
  its authoritative interface definition before issuing a resource token.
- **Grant enforcement.** `r3_granted` served; `r3_conditional` MUST trigger
  `AAuth-Requirement`; non-matching calls rejected.

### A.8 IANA registrations (§IANA)

- JWT claims: `r3_uri`, `r3_s256`, `r3_granted`, `r3_conditional`.
- New "AAuth R3 Vocabulary Registry" seeded with the seven vocabularies above.

---

## Part B — Current SDK State (empty)

`grep` for `r3_uri|r3_s256|r3_vocabular|R3Document|vocabulary|RichResource` across
`src/**/*.cs` returns **no matches** (verified 2026-06-06). There is:

- **No** R3 model (`R3Document`, vocabulary/operation records).
- **No** `r3_vocabularies` metadata field on resource metadata.
- **No** `r3_operations` request parameter on the authorize/exchange request.
- **No** `r3_uri`/`r3_s256`/`r3_granted`/`r3_conditional` token claims.
- **No** RFC 8785 (JCS) canonical-JSON serializer — a hard prerequisite for
  `r3_s256`. The SDK's hashing today operates on verbatim bytes (e.g. mission
  `s256`), not canonicalized JSON.
- **No** AS or MM role implementation. R3's AS/MM processing (fetch, hash-verify,
  cache, claim population, consent display) has no host in the current SDK; only
  mock servers (`samples/MockAccessServer`) could demonstrate it.

---

## Part C — Implementation Surface (candidate inventory)

A full R3 implementation would touch the following areas. Sizing only — not a plan.

### C.1 Prerequisite primitive

- **RFC 8785 (JCS) canonical JSON** serializer + SHA-256 → base64url(no-pad) hasher.
  Independently unit-testable against the RFC's published test vectors. This is the
  riskiest standalone unit; everything else depends on a correct hash.

### C.2 Models

- `R3Document` (`version?`, `vocabulary`, `operations[]`, `display?`).
- Per-vocabulary operation records (MCP `tool`, OpenAPI `operationId`, gRPC
  `method`, GraphQL `operation`+`type`, AsyncAPI `operationId`+`action`, WSDL
  `operation`+`service?`, OData `operation`+`methods?`).
- `R3Operations` request `{vocabulary, operations[]}`.
- `R3Display` (`summary`, `implications?`, `data_accessed?`, `irreversible?`).
- `R3Grant`/`R3Conditional` claim types (vocabulary + operations).

### C.3 Agent side

- Send `r3_operations` on the authorize/exchange request body.
- Read `r3_granted`/`r3_conditional` from the auth token; expose to the caller.
- Handle `r3_conditional` per-call challenge round-trips (`AAuth-Requirement` with
  call parameters).

### C.4 Resource side

- Publish `r3_vocabularies` in `/.well-known/aauth-resource.json`.
- Map declared operations → an R3 document; emit `r3_uri` + `r3_s256` in the
  resource token (both, always together).
- Serve **AS-signature-gated** R3-document endpoints (reject non-AS callers).
- Enforce `r3_granted`/`r3_conditional` at access time without introspection.

### C.5 AS/MM side (mock-only in this SDK)

- AS: fetch R3 doc (AS-signed), hash-verify, cache by `r3_s256`, audit, evaluate
  `operations`, populate `r3_granted`/`r3_conditional` in the auth token, atomic
  audit-with-issuance.
- MM: fetch R3 doc, render `display` for consent.

### C.6 Samples & docs

- A resource sample (e.g. WhoAmI) publishing a vocabulary + R3 documents.
- `MockAccessServer` extended to act as the R3-fetching AS (and/or MM).
- A new R3 walkthrough doc + conformance vectors for hashing and token claims.

---

## Part D — R3 ↔ Mission Interplay

Both R3 `display`-based consent and mission governance live partly at the PS/MM:

- The **MM** fetches R3 `display` to obtain informed consent (§R3 Processing / MM).
- The **PS** governs missions (mission intent + log).

R3 does **not** specify how an `r3_operations` request interacts with a mission's
`approved_tools` or the permission flow. If R3 and missions are combined in a sample
or product flow, that interplay needs an explicit design decision (e.g. does an
R3-granted operation satisfy a mission permission check, or are they orthogonal?).
This is an open spec gap, not just an SDK gap.

---

## Part E — Risks & Considerations

- **Spec volatility.** Exploratory Draft, no known implementations — APIs built now
  may need rework. Conformance vectors should track the draft revision.
- **RFC 8785 correctness.** Canonicalization bugs silently break interop (different
  content hashed than peers compute). Must be vector-tested.
- **Role gap.** The SDK is agent+resource centric; R3's value concentrates in the
  AS/MM. Demonstrating R3 end-to-end requires mock AS/MM, raising the effort even
  for a "demo" scope.
- **Security-critical access control.** The AS-only R3-fetch restriction is the
  linchpin of agent opacity; a weak implementation silently breaks the core property
  and must be deployment-tested.

---

## Open Design Choices

These require user input **before** authoring `implementation-plan.md` for R3.

1. **Scope tier.** (a) Research-only (this doc is the deliverable), (b) mock-demo
   (WhoAmI publishes a vocabulary; MockAccessServer acts as AS/MM; agent sends
   `r3_operations`; enforcement demonstrated), or (c) full SDK implementation
   (models + RFC 8785 hasher + token claims + resource enforcement + AS/MM fetch).
2. **Vocabulary focus.** If building, which vocabulary(ies) first — MCP and/or
   OpenAPI are the most demonstrable with the existing samples.
3. **AS/MM hosting.** Use `MockAccessServer` as the R3-fetching AS (and MM), or
   stub these roles minimally?
4. **Mission interplay.** Keep R3 and missions orthogonal in samples, or design a
   combined flow (Part D)?
5. **Timing.** Proceed now, or hold until the R3 draft advances past Exploratory?

---

## Out of Scope (unless decided otherwise)

| Item | Reason |
|------|--------|
| Production AS/MM SDK roles | The SDK is agent+resource centric; AS/MM are external — mock only |
| Vocabulary discovery parsing (MCP tool list / OpenAPI / `$metadata` / introspection fetch) | Resource/agent discovery detail; likely a later phase even within R3 |
| Mission-API streamlining | Tracked separately in `.agent/plans/2026-06-06-mission-api-refactor/` |
