# R3 (Rich Resource Requests) — Implementation Plan

## Overview

Implement support for the AAuth **Rich Resource Requests (R3)** extension
(`aauth-spec/draft-hardt-aauth-r3.md`): vocabulary-based, resource-declared
authorization with content-addressed R3 documents and `r3_uri`/`r3_s256`/
`r3_granted`/`r3_conditional` token claims.

See [research.md](research.md) for the full spec model, the (empty) current SDK
state, the implementation surface, and the recorded design decisions. Every phase
below cites the governing R3 spec section.

> **Status: PENDING SCOPE DECISION.** R3 is an *Exploratory Draft* with no known
> implementations and concentrates value in the AS/MM roles the SDK does not host.
> The phases below assume the **mock-demo** scope tier; they are not active until
> the user confirms scope (research [Open Design Choices](research.md), Q1). This
> plan was extracted from the mission-API initiative on 2026-06-06.

## Context

- **Spec:** `aauth-spec/draft-hardt-aauth-r3.md` — §Vocabularies, §Authorization
  Endpoint Extensions, §R3 Document, §Resource Token Extensions, §R3 Processing,
  §Auth Token Extensions, §Security Considerations.
- **Base spec:** `aauth-spec/draft-hardt-oauth-aauth-protocol.md` (HTTP Message
  Signatures for AS-signed R3 fetch; resource/auth token structure).
- **Prerequisite:** RFC 8785 (JCS) canonical JSON.
- **Branch:** TBD (new branch recommended; do not mix with mission-API refactor).
- **Sequencing:** Phase 0 prerequisite (hasher) → Phase 1 models → Phase 2 agent →
  Phase 3 resource → Phase 4 mock AS/MM → Phase 5 samples → Phase 6 docs → review.

## Cross-Cutting Decisions

- **CC1 — Scope tier (PENDING).** Default assumption: **mock-demo** — WhoAmI
  publishes a vocabulary + R3 documents; `MockAccessServer` acts as the
  R3-fetching AS (and MM); the agent sends `r3_operations`; enforcement is
  demonstrated. Confirm before activating.
- **CC2 — Vocabulary focus (PENDING).** Default: **MCP + OpenAPI** first (most
  demonstrable with existing samples).
- **CC3 — Hash correctness is gating.** RFC 8785 must be vector-tested before any
  dependent phase (research Part E).
- **CC4 — Security invariants are test targets.** AS-only R3 fetch, hash-verify-
  before-use, atomic audit-with-issuance (research Part A.7).

---

## Phase 0 — RFC 8785 canonical JSON + R3 hash primitive

**Goal:** A correct, vector-tested JCS serializer and `r3_s256` hasher.

**Spec:** §Content Addressing (`base64url(SHA-256(RFC8785(document)))`, no padding);
RFC 8785.

### Files (illustrative)

| File | Action |
|------|--------|
| `src/AAuth/Crypto/JsonCanonicalizer.cs` | **New** — RFC 8785 serializer |
| `src/AAuth/R3/R3Hash.cs` | **New** — canonical JSON → SHA-256 → base64url(no-pad) |
| `tests/AAuth.Conformance/R3/JsonCanonicalizerTests.cs` | **New** — RFC 8785 vectors |
| `tests/AAuth.Conformance/R3/R3HashTests.cs` | **New** — spec example documents |

### Definition of Done

- [ ] JCS serializer passes RFC 8785 published test vectors.
- [ ] `r3_s256` matches hand-computed hashes for spec example documents.
- [ ] No dependent phase starts until this is green.

---

## Phase 1 — R3 models

**Goal:** Strongly-typed R3 document, operations, and claim types.

**Spec:** §R3 Document / Fields; §Vocabularies (per-vocabulary operation shape);
§Auth Token Extensions (`r3_granted`/`r3_conditional`).

### Files (illustrative)

| File | Action |
|------|--------|
| `src/AAuth/R3/R3Document.cs` | **New** — `version?`, `vocabulary`, `operations[]`, `display?` |
| `src/AAuth/R3/Vocabulary.cs` | **New** — vocabulary URIs + registry constants |
| `src/AAuth/R3/R3Operation.cs` | **New** — per-vocabulary operation records |
| `src/AAuth/R3/R3Display.cs` | **New** — `summary`/`implications?`/`data_accessed?`/`irreversible?` |
| `src/AAuth/R3/R3Operations.cs` | **New** — request `{vocabulary, operations[]}` |
| `tests/AAuth.Conformance/R3/R3ModelTests.cs` | **New** |

### Definition of Done

- [ ] Models round-trip JSON for all seven vocabularies (or the CC2-chosen subset).
- [ ] `display.summary` required when `display` present; validation enforced.

---

## Phase 2 — Agent-side R3

**Goal:** Send `r3_operations`; read `r3_granted`/`r3_conditional`; handle the
conditional per-call challenge.

**Spec:** §Authorization Endpoint Extensions (`r3_operations` request param);
§Auth Token Extensions (grant claims); §Resource Enforcement (conditional flow).

### Files (illustrative)

| File | Action |
|------|--------|
| `src/AAuth/Agent/TokenExchangeRequest.cs` | **Modify** — carry `R3Operations` |
| `src/AAuth/Tokens/*AuthToken*` | **Modify** — parse `r3_granted`/`r3_conditional` |
| `tests/AAuth.Conformance/R3/AgentR3RequestTests.cs` | **New** |

### Definition of Done

- [ ] Agent emits `r3_operations` in the authorize/exchange body.
- [ ] Auth-token grant claims surfaced to the caller.
- [ ] `r3_conditional` per-call challenge round-trip exercised.

---

## Phase 3 — Resource-side R3

**Goal:** Advertise vocabularies, emit `r3_uri`/`r3_s256`, serve AS-gated R3
documents, enforce grants.

**Spec:** §Vocabularies (`r3_vocabularies` metadata); §Resource Token Extensions
(both claims together); §R3 Document (AS-signed, HTTPS, agent-opaque); §Resource
Enforcement; §Security Considerations.

### Files (illustrative)

| File | Action |
|------|--------|
| Resource metadata options | **Modify** — `r3_vocabularies` |
| Resource token builder | **Modify** — `r3_uri` + `r3_s256` (both) |
| `src/AAuth/Server/R3/R3DocumentEndpoint.cs` | **New** — AS-signature-gated serve |
| `src/AAuth/Server/R3/R3Enforcement.cs` | **New** — match `r3_granted`/`r3_conditional` |
| `tests/AAuth.Conformance/R3/ResourceR3Tests.cs` | **New** |

### Definition of Done

- [ ] `r3_vocabularies` published in `/.well-known/aauth-resource.json`.
- [ ] Resource token includes both `r3_uri` and `r3_s256` when R3 applies.
- [ ] R3-document endpoint **rejects non-AS** callers (agent opacity) — tested.
- [ ] Enforcement serves `r3_granted`, challenges `r3_conditional`, rejects else.

---

## Phase 4 — Mock AS/MM R3 processing

**Goal:** Demonstrate the AS/MM half via mock servers (per CC1).

**Spec:** §R3 Processing (AS fetch + hash-verify + cache + claim population; MM
`display` consent); §Security Considerations (atomic audit-with-issuance).

### Files (illustrative)

| File | Action |
|------|--------|
| `samples/MockAccessServer/Program.cs` | **Modify** — AS: fetch (signed), hash-verify, cache by `r3_s256`, populate grants, audit atomically |
| `samples/MockPersonServer/` or MM stub | **Modify** — render `display` for consent |

### Definition of Done

- [ ] AS fetches R3 doc with a valid HTTP Message Signature; hash-verifies before use.
- [ ] AS populates `r3_granted`/(`r3_conditional`) in the auth token.
- [ ] MM surfaces `display` (`summary`/`implications`/…) at consent time.

---

## Phase 5 — Samples

**Goal:** End-to-end R3 demo with a real vocabulary.

### Files (illustrative)

| File | Action |
|------|--------|
| `samples/WhoAmI/Program.cs` | **Modify** — publish a vocabulary + R3 documents |
| Agent sample | **Modify** — request `r3_operations`; show granted/conditional |
| `tests/e2e/` | **New** — R3 Playwright/console spec |

### Definition of Done

- [ ] A full R3 flow runs against the mock stack for the CC2 vocabulary.
- [ ] Conditional-operation per-call approval demonstrated.

---

## Phase 6 — Docs & review

**Goal:** Document R3 support; multi-subagent review + gates.

### Files (illustrative)

| File | Action |
|------|--------|
| `docs/advanced/r3-rich-resource-requests.md` | **New** — full walkthrough |
| docs index / concepts | **Modify** — link R3 |

### Definition of Done

- [ ] R3 doc compiles against the surface; security invariants called out.
- [ ] Subagent findings adjudicated against spec text before changes.
- [ ] Build 0/0; unit + conformance + R3 e2e green; research updated with findings.

---

## Out of Scope

| Item | Reason |
|------|--------|
| Production AS/MM SDK roles | SDK is agent+resource centric; AS/MM are external — mock only |
| Vocabulary discovery parsing (tool list / OpenAPI / `$metadata` / introspection) | Discovery detail; later phase even within R3 |
| Mission-API streamlining | Separate initiative — `.agent/plans/2026-06-06-mission-api-refactor/` |
