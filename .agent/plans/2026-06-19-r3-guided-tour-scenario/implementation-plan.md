# R3 Guided Tour Scenario — Implementation Plan

## Overview

Add a **10th GuidedTour scenario** demonstrating AAuth **Rich Resource Requests
(R3)** end-to-end against **live mock servers**, on a **new four-party `Bookings`
resource server** (`:5004`, purpose-built for R3 and **not** mission-aware), using
the **MCP** vocabulary, including the **conditional / per-call proposal** arc, and
flagged **experimental**. The scenario is **Rich Trip Booking**:
`search_trip_options` + `hold_itinerary` granted, `book_trip` conditional.

> **R3 stays out of the core SDK (2026-06-23).** `src/AAuth` is **not** modified.
> R3 ships as a standalone, extraction-ready **`AAuth.R3` preview library**
> (`samples/AAuth.R3`, `IsPackable=false`) depending only on the public `AAuth`
> surface, consumed by the demo servers and GuidedTour. A later lift to
> `src/AAuth.R3` + packaging yields the `AAuth.R3` NuGet alongside `AAuth`.

The work is split into **two parts**, delivered in order:

- **Part 1 — R3 preview library.** Build the `AAuth.R3` library (types, hashing,
  R3 claim build/parse, R3 challenge, document endpoint, enforcement) against the
  public `AAuth` surface. Independently buildable and unit-tested; no GuidedTour
  dependency; **zero edits to `src/AAuth`**.
- **Part 2 — Demo.** Wire the new Bookings server + AS + PS to use `AAuth.R3`, then
  wire the GuidedTour 10th scenario, docs, and E2E on top of Part 1.

See [research.md](research.md) for the spec model, the v02 change (no
canonicalization), confirmed scope, file surface, and security invariants. The
full deep-dive spec model lives in the prior
[2026-06-06 research](../2026-06-06-r3-rich-resource-requests/research.md).

## Cross-Cutting Decisions

- **CC1 — Reality tier:** live mock servers (real HTTP, real tokens). Not
  in-process.
- **CC2 — Vocabulary:** MCP only (`urn:aauth:vocabulary:mcp`), op shape
  `{ "tool": "…" }`.
- **CC3 — Hash:** v02 verbatim bytes — `base64url(SHA-256(bytes-served))`, no
  padding. **No RFC 8785 / JCS.** Serialize once, persist exact bytes, serve
  verbatim.
- **CC4 — Resource + AS isolation:** a **new** **Bookings** server (`:5004`) —
  four-party, purpose-built for R3, **not** mission-aware (deliberately reuses
  nothing from the mission-bound Trips server). **Its AS is a dedicated
  MockAccessServer instance** (`:5501`, R3 mode) so the shared `:5500` AS used by
  Wallet / scenario 6 is **untouched**; Bookings' resource-token `aud` points at the
  `:5501` AS. **PS:** MockPersonServer (`:5100`). The PS routes to the AS purely by
  the resource token's `aud` (origin-pinned `token_endpoint` discovery — see CC12),
  so no PS federation-logic change is needed. It follows the Wallet's four-party
  shape (`aud` = AS; trusts AS-issued tokens) but is independent; Wallet/Trips are
  left intact.
- **CC5 — Security invariants are test targets:** trusted-fetcher R3 gate (**AS +
  PS**, agent opacity), hash-verify-before-use, per-call digest binding. The **SDK
  verifies HTTP Message Signatures and surfaces the caller; the resource owns the
  trusted AS/PS allowlist** (Decision 3).
- **CC6 — Experimental:** disclaimer banner in the tour blurb and docs.
- **CC7 — Consent rendering:** the **PS** fetches the R3 document and renders the
  `display` consent (R3-faithful), then federates to the AS for `operations` and
  grant minting (Decision 1 + four-party topology).
- **CC8 — Spec deviation (documented):** §Content Addressing literally mandates an
  AS-only fetch, but §R3 Processing requires the PS to fetch too. We follow the
  processing model (trusted AS + PS); recorded in research Part A.
- **CC9 — No core SDK changes (2026-06-23):** `src/AAuth` is frozen. R3 lives in the
  `AAuth.R3` preview library. For the **auth token**, the library reuses
  `AuthTokenBuilder.AdditionalClaims` to attach `r3_*` claims and the verifier's
  parsed payload to read them. Two SDK seams are **missing**, and the library fills
  both itself (no SDK edit): (a) `ResourceTokenBuilder` / the challenge middleware
  have no extra-claims hook, so the library emits its **own** R3 challenge +
  resource token, hand-signed via the public `IAAuthKey.Sign`; (b)
  `AccessPolicyRequest` does **not** surface the verified resource-token payload, so
  a plain `IAccessPolicy` cannot see `r3_uri`/`r3_s256` — the library therefore
  ships its **own** AS R3 token endpoint (Phase 1.6) that verifies the tokens, reads
  the R3 claims, fetches/hash-verifies the document, evaluates `operations`, and
  mints via `AuthTokenBuilder` (Finding 1, 2026-06-25). `IAccessPolicy`
  `additionalClaims` stays available but is not the R3 evaluation seam.
- **CC10 — Extraction-ready:** `AAuth.R3` depends only on the public `AAuth`
  surface; no reverse dependency from `src/AAuth`. Future extraction = move
  `samples/AAuth.R3` → `src/AAuth.R3`, flip `IsPackable`, ship `AAuth.R3` NuGet.
- **CC11 — R3 fetch signing scheme (2026-06-25):** the AS and PS authenticate R3
  document / proposal fetches with the **`jwks_uri`** `Signature-Key` scheme — the
  same scheme the AS token endpoint already requires of the PS. Bookings'
  trusted-fetcher allowlist matches the caller's parsed `JwksUri` **authority**
  against the configured AS and PS origins (Finding 4). **Wire note:** in this
  codebase the header is `Signature-Key: sig=jwks_uri;uri="…";kid="…"` — the
  parameter is **`uri`** ([SignatureKeyParser](../../../src/AAuth/HttpSig/SignatureKeyParser.cs)
  reads `uri`), **not** `jwks_uri="…"`. Code uses the parsed `JwksUri`/origin; do not
  copy the older feedback file's `jwks_uri="…"` header example.
- **CC12 — AS R3 endpoint routing (2026-06-26):** the PS discovers the AS
  `token_endpoint` from `{resource_token.aud}/.well-known/aauth-access.json` and
  **origin-pins** it ([AccessServerClient.FederateAsync](../../../src/AAuth/Access/AccessServerClient.cs)).
  R3 routing is therefore driven entirely by `aud`, with **no** PS change. Bookings
  names a **dedicated AS origin** (`:5501`) whose `/token` is owned by
  `R3AccessTokenEndpoint`; the shared `:5500` AS keeps `MapAAuthAccessServer`. We
  **reject** sharing one `/token` (feedback options 1/3): `MapAAuthAccessServer`
  owns that route as a mapped endpoint (no clean delegate / fall-through), and
  intercepting it would risk scenario 6 / Wallet. The dedicated instance only ever
  serves R3 traffic, so `R3AccessTokenEndpoint` fully owns its `/token` with no
  non-R3 fallback. The PS adds the new AS issuer to its trusted-federation set
  (config, not logic).

---

# Part 1 — R3 preview library (`AAuth.R3`, extraction-ready)

> New project `samples/AAuth.R3` (namespace `AAuth.R3`, `IsPackable=false`),
> referencing only the public `AAuth` SDK. **No edits to `src/AAuth`.** Tests live
> in a sibling `tests/AAuth.R3.Tests` (kept out of the SDK conformance gates).

## Phase 1.0 — Project scaffolding

**Goal:** Stand up the extraction-ready library + test project.

| File | Action |
|------|--------|
| `samples/AAuth.R3/AAuth.R3.csproj` | **New** — classlib, `IsPackable=false`, project-refs `src/AAuth` (package-ref after extraction) |
| `tests/AAuth.R3.Tests/AAuth.R3.Tests.csproj` | **New** — xUnit; references `AAuth.R3` |
| `AAuth.slnx` | **Modify** — add both projects |

### Definition of Done

- [x] `AAuth.R3` + `AAuth.R3.Tests` build 0/0; `src/AAuth` shows no diff.

## Phase 1.1 — R3 hash primitive

**Goal:** A correct, vector-tested verbatim-bytes `r3_s256` hasher.

**Spec:** v02 §Content Addressing (`base64url(SHA-256(bytes-served))`, no padding,
no canonicalization).

| File | Action |
|------|--------|
| `samples/AAuth.R3/R3Hash.cs` | **New** — bytes → SHA-256 → base64url(no-pad); reuse `AAuth` crypto helpers |
| `tests/AAuth.R3.Tests/R3HashTests.cs` | **New** — local fixtures: pinned exact payload bytes + pre-computed digest; positive match + negative byte/digest-mismatch case |

### Definition of Done

- [x] `r3_s256` matches a pre-computed digest over **pinned exact payload bytes**
      (local fixtures — the draft publishes JSON examples but no expected digests).
- [x] Hashing operates on exact bytes (round-trip through serialize→hash→serve is
      byte-identical); a byte-different-but-similar payload or a tampered digest is
      detected (negative test).

## Phase 1.2 — R3 models

**Goal:** Strongly-typed R3 document, MCP operation, and claim types.

**Spec:** v02 §R3 Document / Fields; §MCP Vocabulary; §Auth Token Extensions.

| File | Action |
|------|--------|
| `samples/AAuth.R3/Model/R3Document.cs` | **New** — `version?`, `vocabulary`, `operations[]`, `display?` |
| `samples/AAuth.R3/Model/McpOperation.cs` | **New** — `{ tool }` |
| `samples/AAuth.R3/Model/R3Operations.cs` | **New** — request `{ vocabulary, operations[] }` |
| `samples/AAuth.R3/Model/R3Display.cs` | **New** — `summary`, `implications?`, `data_accessed?`, `irreversible?`, `detail?` (proposal Markdown) |
| `samples/AAuth.R3/Model/R3Grant.cs` | **New** — `{ vocabulary, operations[] }` for granted/conditional |
| `samples/AAuth.R3/Model/R3ProposalDocument.cs` | **New** — per-call proposal: R3-doc fields + single-op `operations[]` + `parameters` (REQUIRED) + `display.detail?` (Finding 3) |
| `samples/AAuth.R3/Model/R3Parameter.cs` | **New** — a parameter value: inline JSON **or** a digest object `{ s256, excerpt?, media_type? }` |
| `samples/AAuth.R3/Model/Vocabulary.cs` | **New** — MCP URI constant |
| `tests/AAuth.R3.Tests/R3ModelTests.cs` | **New** |

### Implementation Decisions

- **Serialized bytes are the source of truth.** A resource serializes an R3 document
  **once**, then hashes, stores, and serves those exact bytes. Do not re-serialize on
  each fetch and hope it matches. This keeps `r3_s256` reproducible and aligns with v02's
  "serialize once, serve verbatim" rule; the model's serializer only needs to be
  deterministic enough to produce the canonical bytes at authoring time.

### Definition of Done

- [x] Models round-trip JSON for the MCP vocabulary, byte-stable for hashing.
- [x] `display.summary` required when `display` present; validation enforced.
- [x] `R3ProposalDocument` round-trips (`parameters` incl. digest objects,
      `display.detail`), serializes byte-stable, and enforces required `parameters`
      and a single conditional operation (Finding 3).

## Phase 1.3 — R3 token claims (no SDK edits)

**Goal:** Build and parse R3 claims for resource and auth tokens using existing SDK
extension points; supply a custom R3 challenge where the SDK has no hook.

**Spec:** v02 §Resource Token Extensions (both `r3_uri`+`r3_s256` together);
§Auth Token Extensions (`r3_granted` required, `r3_conditional` optional).

| File | Action |
|------|--------|
| `samples/AAuth.R3/R3AuthClaims.cs` | **New** — build the `r3_uri`/`r3_s256`/`r3_granted`/`r3_conditional` `JsonNode` set for `AuthTokenBuilder.AdditionalClaims` (consumed by the AS R3 endpoint, Phase 1.6) |
| `samples/AAuth.R3/R3Challenge.cs` | **New** — emit the 401 R3 challenge + resource token with `r3_uri`+`r3_s256` (custom writer; `ResourceTokenBuilder`/challenge middleware have no extra-claims hook) |
| `samples/AAuth.R3/R3ClaimReader.cs` | **New** — read R3 claims from a verified token payload (`JsonObject`) into typed values |
| `tests/AAuth.R3.Tests/TokenClaimTests.cs` | **New** — build + parse round-trip |

### Implementation Decisions

- **Use existing SDK hooks for the auth token.** `AuthTokenBuilder.AdditionalClaims`
  already accepts arbitrary JSON claims, so the AS R3 token endpoint (Phase 1.6)
  attaches R3 grants with **no** SDK change. (`IAccessPolicy` Allow `additionalClaims`
  exists too, but cannot drive R3: its request context omits the resource-token
  payload — Finding 1.)
- **Custom challenge for the resource token.** `ResourceTokenBuilder` and the
  challenge middleware expose no extra-claims hook, so the Bookings server uses
  `AAuth.R3`'s `R3Challenge` to emit its own 401 + resource token carrying
  `r3_uri`/`r3_s256`. Still no `src/AAuth` edit.
- **The custom resource token is hand-signed via the public key API.** `JwtWriter`
  is `internal`, so `R3Challenge` reproduces its ~6-line compact-JWS assembly
  (`base64url(header).base64url(payload)`, signed with the public
  `IAAuthKey.Sign`). It MUST stay byte-compatible with `TokenVerifier` (Finding 5).

### Definition of Done

- [x] Resource-token challenge emits both `r3_uri` and `r3_s256` when R3 applies;
      neither otherwise; never one without the other (validated).
- [x] Auth-token R3 claim set round-trips through `AdditionalClaims`; `r3_granted`
      (+ optional `r3_conditional`) parse back to typed values.
- [x] **Parity (Finding 5):** the hand-built R3 resource token passes
      `TokenVerifier.VerifyResourceTokenAsync` — header `typ = aa-resource+jwt`,
      `dwk = aauth-resource.json`, expected `aud`/`agent`/`agent_jkt`/`iat`/`exp`,
      signature verifies through the resource JWKS path — and both `r3_uri` and
      `r3_s256` survive verification; one-sided R3 claims rejected before minting.
- [x] `src/AAuth` shows no diff.

## Phase 1.4 — Resource metadata + R3 endpoint + enforcement

**Goal:** Advertise vocabularies, serve signature-verified R3 docs behind a
resource-owned trusted-fetcher policy, enforce grants.

**Spec:** v02 §Vocabularies (`r3_vocabularies`); §R3 Document (agent-opaque; trusted
AS + PS per §R3 Processing — see CC8); §Resource Enforcement; §Per-Call Proposals;
§Security Considerations.

| File | Action |
|------|--------|
| `samples/AAuth.R3/R3Metadata.cs` | **New** — compose `r3_vocabularies` into the resource's `/.well-known/aauth-resource.json` (Bookings emits it; SDK metadata options untouched) |
| `samples/AAuth.R3/R3DocumentEndpoint.cs` | **New** — **verify** the HTTP Message Signature (via the SDK verifier) and surface the caller; accept a resource-supplied trusted-fetcher predicate. Does **not** hard-code AS-only (Decision 3) |
| `samples/AAuth.R3/R3Enforcement.cs` | **New** — match call → `r3_granted` / `r3_conditional` / reject; build per-call proposal |
| `samples/AAuth.R3/R3ProposalStore.cs` | **New** — persist proposal bytes keyed by `r3_s256` (verbatim serve) |
| `samples/AAuth.R3/R3FetchClient.cs` | **New** — consumer side (AS + PS): sign the R3 / proposal fetch with the `jwks_uri` scheme (CC11), fetch, and **hash-verify** `r3_s256` against the bytes before returning them |
| `tests/AAuth.R3.Tests/ResourceR3Tests.cs` | **New** |

### Implementation Decisions

- **Trust is resource-owned (Decision 3).** The SDK endpoint helper validates the
  HTTP Message Signature and exposes the verified caller identity; it takes a
  caller-supplied predicate (e.g. "is this a trusted AS or PS?") rather than baking
  in AS-only. The trusted AS/PS allowlist lives in the resource app (Phase 2.1).
- **Fetcher set = trusted AS + PS (Decision 1, CC8).** Documented deviation from the
  literal §Content Addressing AS-only MUST; agents and untrusted callers are still
  rejected, preserving agent opacity.

### Definition of Done

- [x] `r3_vocabularies` published in resource metadata.
- [x] R3-document endpoint **verifies** the signature, surfaces the caller, and
      serves only to the resource-configured trusted **AS or PS**, rejecting agents
      and untrusted callers — tested all ways (AS sig → 200; PS sig → 200; agent →
      401/403; untrusted → 401/403).
- [x] Enforcement serves `r3_granted`, challenges `r3_conditional` with a per-call
      proposal, rejects unmatched.
- [x] Per-call retry **digest-matches** presented params against the stored
      proposal; mismatch rejected (negative test).

## Phase 1.5 — Agent-side R3 request (no SDK edits)

**Goal:** Send `r3_operations`; read grants; drive the conditional challenge — all
from the `AAuth.R3` library / demo, without modifying the SDK agent client.

**Spec:** v02 §Authorization Endpoint Extensions; §Resource Enforcement.

| File | Action |
|------|--------|
| `samples/AAuth.R3/R3Request.cs` | **New** — compose the `r3_operations` body for the resource `authorization_endpoint` (`POST /authorize`); demo crafts the request (no SDK agent change) |
| `samples/AAuth.R3/R3ClaimReader.cs` | **(from 1.3)** — expose `r3_granted`/`r3_conditional` to the caller |
| `tests/AAuth.R3.Tests/AgentR3RequestTests.cs` | **New** |

### Definition of Done

- [x] `r3_operations` carried in the resource `authorization_endpoint` request body
      (`POST /authorize`), with a 401-challenge fallback (no SDK agent change).
- [x] Grant claims surfaced to the caller; conditional per-call round-trip
      exercised end-to-end in-process.

## Phase 1.6 — AS-side R3 token endpoint (no SDK edits)

**Goal:** A self-contained AS token endpoint the MockAccessServer maps for the R3
flow. Needed because `AccessPolicyRequest` does **not** expose the resource-token
payload, so a plain `IAccessPolicy` cannot read `r3_uri`/`r3_s256` (Finding 1,
2026-06-25).

**Spec:** v02 §AS Processing (verify → fetch → hash-verify → evaluate `operations`
→ mint `r3_granted`/`r3_conditional` + audit).

| File | Action |
|------|--------|
| `samples/AAuth.R3/R3AccessTokenEndpoint.cs` | **New** — maps a self-contained AS surface (`/.well-known/aauth-access.json` with `token_endpoint` = `{as}/token`, JWKS, and `POST /token`); verify agent + resource tokens via the public `TokenVerifier`; read `r3_uri`/`r3_s256` (`R3ClaimReader`); fetch + hash-verify via `R3FetchClient`; evaluate `operations` → grants; mint the auth token via `AuthTokenBuilder` + `AdditionalClaims` (`R3AuthClaims`); audit `r3_uri`/`r3_s256` + per-call proposal evaluation |
| `tests/AAuth.R3.Tests/AccessEndpointR3Tests.cs` | **New** |

### Implementation Decisions

- **The R3 path bypasses `IAccessPolicy` for evaluation.** The SDK policy seam
  cannot read the resource-token payload, so the library owns the
  verify→fetch→evaluate→mint pipeline. The minted token still flows through
  `AuthTokenBuilder`, so it is verifier-identical to an SDK-minted auth token.
- **Extraction-ready.** `R3AccessTokenEndpoint` is a mappable helper (e.g. an
  endpoint-builder extension) so the MockAccessServer wires it in one line and a
  future real AS can reuse it unchanged.
- **Owns a dedicated AS origin, no non-R3 fallback (CC12).** Because the PS routes
  by the resource token's `aud` and origin-pins `token_endpoint`, this endpoint runs
  as Bookings' **own** AS instance (`:5501`) and never shares `/token` with the
  `:5500` AS. It therefore needs no non-R3 branch and cannot affect scenario 6 /
  Wallet.

### Definition of Done

- [x] Endpoint mints an auth token carrying `r3_uri`/`r3_s256`/`r3_granted`
      (+ optional `r3_conditional`) that passes `TokenVerifier`.
- [x] Rejects a resource token whose `r3_s256` does not match the fetched bytes.
- [x] Per-call proposal request mints a per-call token granting the conditional op.
- [x] `src/AAuth` shows no diff.

### Part 1 exit criteria

- [x] `AAuth.R3` builds 0 warnings / 0 errors; **`src/AAuth` shows no diff**.
- [x] All Phase 1.0–1.6 `AAuth.R3.Tests` green.
- [x] `AAuth.R3` depends only on the public `AAuth` surface; no reverse dependency
      from `src/AAuth`; no GuidedTour/live-server dependency in the library.

---

# Part 2 — Demo (live servers + GuidedTour)

> Depends on Part 1. Do not start until Part 1 exit criteria are met.

## Phase 2.1 — New Bookings resource speaks R3

**Goal:** A new four-party `Bookings` server (`:5004`, non-mission) advertises MCP,
maps requests to R3 docs, emits claims, serves signature-verified docs + proposals
behind its trusted AS/PS allowlist, and enforces grants. It follows the Wallet's
four-party shape (`aud` = AS) but reuses nothing from Trips/missions.

| File | Action |
|------|--------|
| `samples/MockResourceServers/Bookings/Bookings.csproj` | **New** — minimal ASP.NET Core resource project; references `AAuth` + `AAuth.R3` |
| `samples/MockResourceServers/Bookings/Program.cs` | **New** — four-party wiring (`aud` = AS; trusts AS-issued tokens); R3 logic via `AAuth.R3`: `r3_vocabularies` ⇒ `{ "urn:aauth:vocabulary:mcp": "{bookings}/mcp" }`; `authorization_endpoint` (`POST /authorize`) that accepts `r3_operations`, maps to a fixed R3 doc for `search_trip_options` / `hold_itinerary` / `book_trip`, persists exact bytes, and returns a resource token with `r3_uri`/`r3_s256`; the R3 document endpoint at **`/r3/{hash}`** gated by a resource-owned trusted **AS + PS** allowlist (parsed `JwksUri` authority match); operation endpoints; per-call proposal on `book_trip`; enforce grants |
| `samples/MockResourceServers/Bookings/appsettings.json` | **New** — issuer/port, trusted AS issuer, trusted AS **and** PS `jwks_uri` origins for the R3 fetch gate |
| `AAuth.slnx` | **Modify** — add the Bookings project |
| `samples/MockResourceServers/README.md` | **Modify** — add Bookings (`:5004`) to the server table + narrative |

### Implementation Decisions

- **Authorization endpoint is first-class (Finding 2).** Bookings publishes
  `authorization_endpoint` in `/.well-known/aauth-resource.json` and implements
  `POST /authorize` accepting `{ "r3_operations": … }`. It validates the MCP tool
  names, composes/selects the R3 document, persists the exact serialized bytes,
  computes `r3_s256`, and returns a resource token (`aud` = AS) carrying
  `r3_uri`/`r3_s256`. The 401-challenge path remains as a fallback.
- **Enforce by R3 claims, not legacy scope (Finding 6).** The scenario endpoints
  gate on `r3_granted`/`r3_conditional`, not on an ASP.NET scope policy:
  `search_trip_options` + `hold_itinerary` require a match in `r3_granted`;
  `book_trip` first matches `r3_conditional` → returns a per-call proposal → accepts
  the retry only when the per-call auth token grants `book_trip` **and** the
  presented parameters digest-match the stored proposal. Any `scope` claim kept for
  compatibility is not the gate.
- **Fetch gate keys on `jwks_uri` authority (Finding 4, CC11).** The R3 endpoint
  accepts a `jwks_uri`-signed request whose authority is the configured trusted AS
  or PS; agents and untrusted callers are rejected.
- **Concrete paths (2026-06-26).** The R3 document endpoint is **`/r3/{hash}`**
  (resolves Open Question 1). `r3_vocabularies` advertises the MCP discovery endpoint
  as **`{bookings}/mcp`** — a concrete metadata value per spec ("the MCP server
  URL"); it is **not** backed by a live MCP server and discovery parsing stays out of
  scope, but the metadata carries a real URL rather than a placeholder token.

### Definition of Done

- [ ] `GET /.well-known/aauth-resource.json` includes `r3_vocabularies`
      (`urn:aauth:vocabulary:mcp` ⇒ `{bookings}/mcp`) **and** `authorization_endpoint`.
- [ ] `POST /authorize` accepts `r3_operations`, persists exact R3 bytes, and returns
      a resource token carrying `r3_uri`/`r3_s256` (aud = AS).
- [ ] R3 endpoint at `/r3/{hash}` serves the trusted AS + PS (parsed `JwksUri`
      authority match), rejects agents/untrusted.
- [ ] Scenario endpoints gate on R3 claims (not scope); `book_trip` triggers a
      per-call proposal (`itinerary_id`, `destination`, `depart`/`return`,
      `total_usd`, `cancellation_policy`); granted ops (`search_trip_options`,
      `hold_itinerary`) served from the token.
- [ ] No mission handling on Bookings (no `AAuth-Mission`; `MissionAware = false`).

## Phase 2.2 — AS + PS R3 processing

**Goal:** The PS fetches R3, renders `display`, and federates to the AS; the AS
fetches/verifies R3, evaluates `operations`, and mints grants.

| File | Action |
|------|--------|
| `samples/MockAccessServer/Program.cs` | **Modify** — add an **R3 mode** (config-selected) that maps `AAuth.R3`'s `R3AccessTokenEndpoint` at `/token` **instead of** `MapAAuthAccessServer`; run as a **dedicated instance** (`:5501`) for Bookings. Verifies tokens, reads `r3_uri`/`r3_s256`, fetches + hash-verifies via `R3FetchClient`, evaluates `operations`, mints via `AuthTokenBuilder` + `AdditionalClaims`, audits; per-call proposal eval. **Not** plain `IAccessPolicy` (cannot see the resource-token payload — Finding 1). The default `:5500` instance is **unchanged** |
| `samples/MockAccessServer/appsettings.R3.json` (or env) | **New** — R3-mode config for the `:5501` instance (issuer/port, trusted PS, R3 fetch keys) |
| `samples/MockPersonServer/Program.cs` | **Modify (config)** — add the Bookings AS (`:5501`) issuer to the PS trusted-federation set; no federation-logic change (CC12) |
| `samples/MockPersonServer/Program.cs` + `ConsentStore.cs` | **Modify** — in the **federated branch** of the `/token` handler, **right after `VerifyResourceTokenAsync` yields the resource-token payload** (read `r3_uri`/`r3_s256` from it) and **before** building `fedRequest` / starting `FederateAsync` / relaying the `202` interaction: `jwks_uri`-signed R3 fetch via `AAuth.R3` `R3FetchClient`, hash-verify, render summary/implications/data_accessed/irreversible (and proposal `display.detail`) at consent, then federate to the AS |

### Implementation Decisions

- **PS R3 fetch/render placement is exact (2026-06-26).** In MockPersonServer's
  `/token` **federated branch**, the R3 fetch + `display` render MUST sit **between**
  (a) the point where `VerifyResourceTokenAsync` produces the resource-token payload
  — the only place `r3_uri`/`r3_s256` are readable — and (b) the point where the PS
  builds `fedRequest` and hands off to `AccessServerClient.FederateAsync` / returns
  the `202` interaction relay. Fetching any later (e.g. inside the
  `OnInteractionRequired` relay, or after the background federation resolves) renders
  consent **without** the R3 `display` — the exact bug this note exists to prevent.
  No `src/AAuth` edit: MockPersonServer owns `/token`, so the insertion is local to
  the sample (CC9).

### Definition of Done

- [ ] PS fetches R3 with a valid `jwks_uri` signature, hash-verifies, and renders the
      `display` fields at consent **in the federated branch right after
      `VerifyResourceTokenAsync`, before `FederateAsync` / the `202` interaction
      relay** (not later).
- [ ] AS R3 token endpoint fetches R3 with a valid signature, hash-verifies before
      use, and rejects a hash mismatch.
- [ ] AS auth token carries `r3_uri`/`r3_s256`/`r3_granted` (+ `r3_conditional`)
      and passes `TokenVerifier`.
- [ ] The Bookings AS runs on its **own origin** (`:5501`); the PS reaches it purely
      via the resource token's `aud`; the `:5500` AS and scenario 6 / Wallet are
      unaffected (CC12).

## Phase 2.3 — GuidedTour 10th scenario

**Goal:** A server-backed `RichRequest` flow (~9 steps) over the new four-party
Bookings server: discover Bookings metadata + MCP vocabulary → request
`r3_operations` (search, hold, book) → resource token (aud = AS,
`r3_uri`/`r3_s256`) → PS fetches R3 + renders `display` consent → PS federates to
the AS → AS grants search + hold, marks book conditional → granted 200
(`search_trip_options` / `hold_itinerary`) → conditional challenge on `book_trip`
→ per-call approval of the concrete itinerary → enforced digest-matched retry 200.

**Spec/UI pattern:** mirror the server-backed Federated/Autonomous flows
(`HttpClient` + `CapturingMessageHandler`), not the in-process Sub-Agents flow.

| File | Action |
|------|--------|
| `samples/GuidedTour/TourOptions.cs` | **Modify** — `TourMode.RichRequest` |
| `samples/GuidedTour/GuidedTour.csproj` | **Modify** — reference `AAuth.R3` |
| `samples/GuidedTour/TourSession.cs` | **Modify** — `IsRichRequestMode`, `TotalSteps`, `RichRequestPlan`, step methods, `RunNextAsync` dispatch |
| `samples/GuidedTour/Components/Pages/Tour.razor` | **Modify** — picker option `10 · Rich Trip Booking (R3) …` + experimental blurb |
| `samples/GuidedTour/CodeSnippets.cs` | **Modify** — `AAuth.R3` preview-library snippets per step (make clear `src/AAuth` is unchanged) |
| `samples/GuidedTour/appsettings.json` | **Modify** — Bookings/AS/PS URLs for the flow |

### Definition of Done

- [ ] Flow runs end-to-end against the live four-party stack to a final `200`.
- [ ] Steps show `r3_uri`/`r3_s256`, the PS-rendered `display`, the PS→AS
      federation, `r3_granted`/`r3_conditional`, and the digest-matched per-call
      `book_trip` retry.
- [ ] Blurb carries the experimental disclaimer.

## Phase 2.4 — Wiring, E2E, docs

**Goal:** One-command demo, E2E coverage, and documentation.

| File | Action |
|------|--------|
| `Makefile` | **Modify** — `demo-tour-r3` target (Bookings `:5004` + dedicated R3 AS `:5501` + PS `:5100` + GuidedTour); add Bookings to the run-all resource targets |
| `samples/GuidedTour/playwright-tests/rich-request.spec.ts` | **New** — drive the flow to 200; assert claims + conditional retry |
| `samples/GuidedTour/playwright-tests/picker.spec.ts` | **Modify** — option count 9 → 10 |
| `tests/e2e/helpers/` | **Modify** — `RichRequest` mode + any new URLs |
| `docs/workflows/rich-resource-requests.md` | **New** — full walkthrough, experimental note |
| `samples/GuidedTour/README.md` | **Modify** — add flow #10 to "What you'll see" |
| `docs/README.md` / concepts | **Modify** — link the R3 workflow |

### Definition of Done

- [ ] `make demo-tour-r3` brings up the stack and the flow completes.
- [ ] `rich-request.spec.ts` green; picker count assertion updated.
- [ ] Docs build; experimental status called out in blurb + workflow page.

### Part 2 exit criteria

- [ ] Full repo build 0/0; unit + conformance + R3 E2E green.
- [ ] Multi-subagent review adjudicated against v02 spec text before merge.
- [ ] research updated with any findings via dated `> **Update**` callout.

---

## Out of Scope

| Item | Reason |
|------|--------|
| Vocabularies other than MCP | Demo focuses on MCP |
| Vocabulary discovery parsing (MCP tool-list, OpenAPI `$metadata`) | Demo uses a fixed operation set |
| Mission + R3 combined flow | Orthogonal by decision (CC) |
| Production AS/PS SDK roles | SDK stays agent+resource centric; AS/PS remain mock |
| RFC 8785 / JCS canonical JSON | Removed by v02 — verbatim-bytes hashing |
| Any change to `src/AAuth` | R3 stays out of the core SDK (2026-06-23); lives in `AAuth.R3` + demo |
| Shipping `AAuth.R3` as a NuGet now | Preview library is `IsPackable=false`; extraction/packaging is future work |
| R3 on Calendar / converting Calendar to four-party | Superseded by a dedicated four-party server (Decision 2) |
| Reusing the Wallet for R3 | Superseded 2026-06-23 by a dedicated new `Bookings` server |
| Mission-aware R3 on Bookings | Kept simple by request; Bookings reuses nothing from Trips/missions |
| SDK-owned trusted-fetcher allowlist | Resource-owned by Decision 3; the `AAuth.R3` library only verifies signatures |
