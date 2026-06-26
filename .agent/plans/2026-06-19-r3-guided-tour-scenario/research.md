# R3 Guided Tour Scenario — Research

## Problem Statement

Add a **10th scenario to the GuidedTour interactive tutorial**
([samples/GuidedTour](../../../samples/GuidedTour)) demonstrating AAuth **Rich
Resource Requests (R3)** end-to-end against **live mock servers** — the closest-
to-reality tier. R3 replaces opaque scope strings with **vocabulary-based,
content-addressed authorization**: the resource publishes R3 documents, the agent
requests operations in a vocabulary it understands (MCP), the PS renders the
human-readable `display` for consent, the AS evaluates `operations` and mints
`r3_granted`/`r3_conditional` grants, and the resource enforces directly from the
auth token.

This document captures the spec model, the current (empty) SDK/sample state, the
concrete implementation surface for **this** scenario, and the confirmed scope
decisions. It contains **no** task lists; those live in
[implementation-plan.md](implementation-plan.md).

> **Update (2026-06-23) — R3 stays out of the core SDK.** Team decision: do **not**
> add R3 to `src/AAuth` for now. R3 is a separate, still-experimental draft while
> the core SDK is stabilizing. R3 is implemented in a **standalone,
> extraction-ready `AAuth.R3` preview library** (under `samples/`, depending only on
> the public `AAuth` surface) plus the demo servers; `src/AAuth` is left
> **unchanged**. The design keeps a clean seam so R3 can later be lifted into its
> own `AAuth.R3` NuGet package alongside `AAuth`. Where this doc previously said
> "add to `src/AAuth`", read "add to the `AAuth.R3` preview library."

> **Relationship to prior R3 research.** A broader, SDK-wide R3 research doc
> already exists at
> [.agent/plans/2026-06-06-r3-rich-resource-requests/research.md](../2026-06-06-r3-rich-resource-requests/research.md).
> That doc remains the authoritative deep-dive on the full spec model (all seven
> vocabularies, IANA registrations, the SDK inventory, mission interplay). **This
> doc does not duplicate it** — it records what changed since (v02 spec), the
> confirmed scope for the GuidedTour scenario, and the concrete file surface. Read
> the 2026-06-06 doc first for the full model.

## Source Documents

| Document | Location | Relevant Sections |
|----------|----------|-------------------|
| AAuth R3 (Rich Resource Requests) | [aauth-spec/v02/draft-hardt-aauth-r3.md](../../../aauth-spec/v02/draft-hardt-aauth-r3.md) | §Vocabularies; §Authorization Endpoint Extensions; §R3 Document; §Resource Token Extensions; §R3 Processing (PS/AS); §Auth Token Extensions; §Per-Call Proposals; §Security Considerations |
| AAuth Protocol (base) | [aauth-spec/v02/draft-hardt-oauth-aauth-protocol.md](../../../aauth-spec/v02/draft-hardt-oauth-aauth-protocol.md) | §Authorization Endpoint; §Resource Token; §Auth Token; HTTP Message Signatures (AS-signed R3 fetch) |
| Prior R3 research (full model) | [.agent/plans/2026-06-06-r3-rich-resource-requests/research.md](../2026-06-06-r3-rich-resource-requests/research.md) | Parts A–E, vocabulary table, security invariants |

> **Draft status.** R3 is an **Exploratory Draft** (`draft-hardt-aauth-r3`, v02).
> Its own status text notes there are no known implementations. The scenario and
> docs MUST flag this as experimental.

---

## Part A — What changed since the 2026-06-06 research (v02 spec)

The prior research was written against the pre-v02 spec. The v02 migration
(2026-06-09) changed one load-bearing detail and the spec path:

- **No canonicalization (the big one).** v02 §Content Addressing states: *"There
  is no canonicalization step — verifiers hash the bytes received over the wire,
  not a normalized form... Resources MUST serialize the R3 document once and serve
  those exact bytes verbatim."* So `r3_s256 = base64url(SHA-256(bytes-served))`,
  no padding. **RFC 8785 / JCS is no longer a prerequisite** — the prior plan's
  Phase 0 (a vector-tested JCS serializer) is obsolete. The hash is a thin reuse
  of the SDK's existing verbatim-bytes hashing (mission `s256` already works this
  way).
- **Persist-bytes requirement.** Because the hash is over served bytes, a resource
  that builds R3 documents (or per-call proposals) on the fly MUST persist the
  exact serialized bytes, keyed by `r3_uri`/`r3_s256`, and serve them verbatim on
  every fetch. Re-serialization (key reordering, minification) breaks the hash.
- **Spec path.** `aauth-spec/v02/draft-hardt-aauth-r3.md` (was
  `aauth-spec/draft-hardt-aauth-r3.md`).
- **PS, not "MM."** v02 uses **Person Server (PS)** as the consent role that
  fetches `display`; the AS evaluates `operations`. (The prior doc said "MM".)
- **Both PS and AS fetch the R3 document (the spec contradicts itself here).**
  §R3 Processing and the Terminology both state the document is *"Fetched by both
  the PS (for user consent using `display`) and the AS (for policy evaluation using
  `operations`)."* But §Content Addressing says the resource *"MUST reject requests
  that are not signed by the resource's AS."* Those cannot both hold. Per the
  2026-06-22 session (Decision 1) we resolve in favor of the processing model: the
  resource serves the R3 document to its **trusted AS *and* trusted PS**, rejecting
  agents and untrusted callers. This is a **deliberate, documented deviation** from
  the literal §Content Addressing "AS-only" MUST, flagged here so reviewers do not
  treat it as a bug. (R3 is an Exploratory Draft with no known implementations.)

## Part B — Confirmed scope for this scenario

> **Update (2026-06-22).** An implementation-readiness session reversed/clarified
> four items (see
> [session-feedback-2026-06-22.md](session-feedback-2026-06-22.md)):
> (1) the R3 fetch gate is **trusted AS + PS**, not AS-only (Decision 1);
> (2) the host resource is now the **Wallet four-party federated** deployment,
> superseding the earlier Calendar three-party choice (Decision 2) — scenario 10
> stays independent and scenario 6 is untouched;
> (3) the SDK only **verifies HTTP Message Signatures and surfaces the caller**
> while the **resource owns** the trusted-fetcher allowlist (Decision 3);
> (4) operations are **Wallet-flavored** and the **PS renders** the R3 `display`
> consent. The table and narrative below reflect these decisions.

> **Update (2026-06-23).** Resource choice revised again: instead of reusing the
> Wallet, scenario 10 gets its **own new four-party resource server, `Bookings`**
> (`:5004`), purpose-built for R3 and **not mission-aware** (it deliberately pulls
> in nothing from the mission-bound Trips server). It follows the same four-party
> shape as the Wallet (`aud` = AS; trusts AS-issued auth tokens) but is independent.
> The narrative is **Rich Trip Booking** — `search_trip_options` + `hold_itinerary`
> granted, `book_trip` conditional. This supersedes the 2026-06-22 "reuse Wallet"
> choice; everything else from that update still holds.

> **Update (2026-06-25) — implementation-readiness feedback resolved.** A review
> ([implementation-feedback-2026-06-25.md](implementation-feedback-2026-06-25.md))
> surfaced three load-bearing seams, all accepted after verifying against v02 spec
> text and the SDK:
> (1) **AS R3 input.** `AccessPolicyRequest` does not expose the verified
> resource-token payload, so a plain `IAccessPolicy` cannot read `r3_uri`/`r3_s256`.
> The `AAuth.R3` library therefore ships its **own** AS R3 token endpoint
> (`R3AccessTokenEndpoint`) that verifies tokens, reads the R3 claims,
> fetches/hash-verifies the document, evaluates `operations`, and mints via
> `AuthTokenBuilder` — still **no** `src/AAuth` edit (Finding 1).
> (2) **Resource authorization endpoint.** Bookings publishes `authorization_endpoint`
> and implements `POST /authorize` accepting `r3_operations`, so the tour faithfully
> shows the agent declaring operations (Finding 2).
> (3) **Per-call proposal model.** A first-class `R3ProposalDocument` (`parameters`
> incl. digest objects, `display.detail`) lands in the library (Finding 3).
> Medium items: AS + PS sign R3 fetches with the **`jwks_uri`** scheme and Bookings
> allowlists by that authority (Finding 4); the hand-signed R3 resource token gets a
> `TokenVerifier` parity test (Finding 5, feasible because the public
> `IAAuthKey.Sign` reproduces the internal `JwtWriter`); Bookings enforces by R3
> claims, not legacy scope (Finding 6).

> **Update (2026-06-26) — implementation review findings resolved.** Final
> spec/security review tightened three R3 invariants now captured by the
> implementation: (1) agent-facing responses stay opaque and do not include fetched
> R3 `display` or proposal documents; only the PS renders display after a signed,
> hash-verified fetch, (2) per-call proposal approval is bound by a proposal
> resource token carrying that proposal's `r3_uri`/`r3_s256`, not by caller-supplied
> proposal URI/hash fields, and (3) R3 fetch trust fails closed: PS allowlists are
> required, `jwks_uri` is checked against an explicit trusted-origin predicate before
> any JWKS fetch, and R3 document/proposal fetches are origin-bound to the verified
> resource issuer before outbound requests.

| Decision | Choice |
|----------|--------|
| Reality tier | **Live mock servers** — real HTTP, real tokens; not in-process |
| Vocabulary | **MCP** only (`urn:aauth:vocabulary:mcp`), operation shape `{ "tool": "…" }` |
| SDK | `src/AAuth` **unchanged**. R3 types + helpers live in a new extraction-ready **`AAuth.R3`** preview library (`samples/AAuth.R3`, `IsPackable=false`) that depends only on the public `AAuth` surface; the library verifies signatures, the resource owns trust (Decision 3). Future: split into `AAuth` + `AAuth.R3` NuGet packages (2026-06-23) |
| Resource | **Bookings** (`:5004`) — a **new** four-party R3 server, **not** mission-aware; follows the Wallet's four-party shape (`aud` = AS) but independent (Decision 2, rev. 2026-06-23) |
| AS host | **Dedicated MockAccessServer instance** (`:5501`, R3 mode) — maps `R3AccessTokenEndpoint` at `/token`; fetches/hash-verifies R3, evaluates `operations`, mints grants. The shared `:5500` AS (Wallet / scenario 6) is **untouched**; the PS routes to it purely by the resource token's `aud` (CC12 / 2026-06-26) |
| PS host | **MockPersonServer** (`:5100`) — **fetches R3, renders `display`** at consent, then federates to the AS |
| R3 fetch gate | **Trusted AS + PS** (resource-owned allowlist); agents and untrusted callers rejected — agent opacity (Decision 1) |
| Conditional arc | **Included** — `r3_conditional` + per-call proposal + digest-matched retry (the `book_trip` op) |
| Mission interplay | **Orthogonal** — standalone R3 flow, no mission combination |
| Experimental flag | **Yes** — disclaimer banner in the tour blurb + docs |

### Demonstrative narrative (Aria + Bookings, MCP) — Rich Trip Booking

Aria is planning a trip and requests three MCP operations from the **Bookings**
resource: `search_trip_options` and `hold_itinerary` (granted — read candidates,
place a temporary no-charge hold) and `book_trip` (conditional — purchasing a
concrete itinerary may charge the traveler and carry cancellation rules). The
resource token's `aud` is the AS (four-party). The **PS fetches the R3 document and
shows the human the `display`**: *"Search and temporarily hold travel options.
Booking a trip may charge your payment method and cancellation may be limited."* The
PS then federates to the AS, which fetches the same document, hash-verifies it,
grants search + hold, and marks `book_trip` conditional. The granted calls return
200 straight from the auth token. The `book_trip` call carries concrete parameters
(`itinerary_id`, `destination`, `depart`/`return`, `total_usd`,
`cancellation_policy`); the resource answers with a per-call proposal, the human
approves those exact details, and the Bookings server digest-matches the presented
parameters on retry before committing the purchase.

## Part C — Current state (empty)

- **SDK** (`src/AAuth`): no R3 anywhere, and it **stays that way** (2026-06-23
  decision). For the **auth token**, the existing extension points already suffice
  without editing the SDK: `AuthTokenBuilder.AdditionalClaims` carries
  `r3_uri`/`r3_s256`/`r3_granted`/`r3_conditional`, and the verifier surfaces the
  parsed payload for read-only access. **Two seams are missing** and the `AAuth.R3`
  library fills both itself: (a)
  [ResourceTokenBuilder.cs](../../../src/AAuth/Tokens/ResourceTokenBuilder.cs) and
  the challenge middleware have **no** extra-claims hook, so the Bookings server (via
  the library) emits its **own** R3 challenge + resource token, hand-signed through
  the public `IAAuthKey.Sign`; (b)
  [AccessPolicyRequest](../../../src/AAuth/Access/IAccessPolicy.cs) does **not**
  expose the verified resource-token payload, so a plain `IAccessPolicy` cannot see
  `r3_uri`/`r3_s256` — the library therefore ships its **own** AS R3 token endpoint
  (`R3AccessTokenEndpoint`) that the MockAccessServer maps. Both stay no-SDK-edit
  (Finding 1, 2026-06-25).
- **GuidedTour**: nine flows wired via `TourMode` in
  [TourOptions.cs](../../../samples/GuidedTour/TourOptions.cs); the engine
  [TourSession.cs](../../../samples/GuidedTour/TourSession.cs) dispatches per-step;
  picker in [Tour.razor](../../../samples/GuidedTour/Components/Pages/Tour.razor).
  Server-backed flows (Autonomous/Deferred/Mission/Federated) call live servers via
  `HttpClient` + `CapturingMessageHandler`; the in-process Sub-Agents flow calls
  SDK builders directly. This scenario is **server-backed**.
- **Mock servers**: scenario 10 adds a **new** four-party resource, **Bookings**
  (`samples/MockResourceServers/Bookings/`, `:5004`, to be created), that issues
  resource tokens whose `aud` is **a dedicated R3 AS instance** (`:5501`) and trusts
  AS-issued auth tokens — the same four-party shape as the Wallet but **not**
  mission-aware. That R3 AS is a second
  [MockAccessServer](../../../samples/MockAccessServer/Program.cs) instance run in
  **R3 mode** (it maps `AAuth.R3`'s `R3AccessTokenEndpoint` at `/token` instead of
  `MapAAuthAccessServer`); the existing `:5500` instance (which mints AS auth tokens
  via a pluggable `IAccessPolicy` for Wallet / scenario 6) is **unchanged**. The PS
  reaches the right AS purely via the resource token's `aud` (origin-pinned
  `token_endpoint` discovery — CC12), so
  [MockPersonServer/Program.cs](../../../samples/MockPersonServer/Program.cs) needs
  only the new AS issuer added to its trusted-federation set (config) plus R3 fetch
  via [ConsentStore.cs](../../../samples/MockPersonServer/ConsentStore.cs). None know
  R3 today; the existing servers (Wallet, Trips, AS, PS) are left intact.

## Part D — Implementation surface (sizing, not steps)

### R3 preview library (`AAuth.R3`) — Part 1

> New project `samples/AAuth.R3` (namespace `AAuth.R3`, `IsPackable=false`),
> depending only on the public `AAuth` surface. `src/AAuth` is **not** modified.
> Extraction-ready: a later move to `src/AAuth.R3` + `IsPackable=true` ships the
> `AAuth.R3` NuGet.

| Area | File(s) | Change |
|------|---------|--------|
| Models | new `samples/AAuth.R3/Model/` (`R3Document`, `R3Operations`, `McpOperation`, `R3Display`, `R3Grant`, `R3ProposalDocument`, `R3Parameter`, `Vocabulary`) | Strongly-typed R3 document, MCP operation, grant/conditional, and first-class per-call proposal (`parameters` incl. digest objects, `display.detail`) types |
| Hash | new `samples/AAuth.R3/R3Hash.cs` | `base64url(SHA-256(bytes))`, no padding, over verbatim serialized bytes |
| Resource metadata | new `samples/AAuth.R3/R3Metadata.cs` | Compose `r3_vocabularies` into the resource's `/.well-known/aauth-resource.json` (Bookings emits it; SDK metadata options untouched) |
| Resource token | new `samples/AAuth.R3/R3Challenge.cs` | Emit the 401 R3 challenge + a resource token carrying `r3_uri` + `r3_s256` (custom, because `ResourceTokenBuilder` has no extra-claims hook) |
| Auth token | new `samples/AAuth.R3/R3AuthClaims.cs` | Build the `r3_uri`/`r3_s256`/`r3_granted`/`r3_conditional` claim set for `AuthTokenBuilder.AdditionalClaims` (consumed by `R3AccessTokenEndpoint`; not the `IAccessPolicy` path — Finding 1) |
| Token read | new `samples/AAuth.R3/R3ClaimReader.cs` | Read R3 claims from a verified token payload (`JsonObject`) |
| R3 fetch (AS + PS) | new `samples/AAuth.R3/R3FetchClient.cs` | `jwks_uri`-signed fetch of an R3 doc / proposal + hash-verify `r3_s256` before use (consumer side) |
| AS token endpoint | new `samples/AAuth.R3/R3AccessTokenEndpoint.cs` | Verify tokens → read `r3_uri`/`r3_s256` → fetch + hash-verify → evaluate `operations` → mint via `AuthTokenBuilder` (the AS R3 seam `IAccessPolicy` cannot fill — Finding 1) |
| Agent request | new `samples/AAuth.R3/R3Request.cs` | Compose `r3_operations` for the resource `authorization_endpoint` (`POST /authorize`); no SDK agent change |
| R3 endpoint | new `samples/AAuth.R3/R3DocumentEndpoint.cs` | Verify the HTTP Message Signature (via the SDK verifier) and surface the caller; the resource supplies the trusted-fetcher predicate (AS + PS) (Decision 3) |
| Enforcement | new `samples/AAuth.R3/R3Enforcement.cs` | Match call → `r3_granted` (serve) / `r3_conditional` (challenge w/ proposal) / else reject |
| Tests | new `tests/AAuth.R3.Tests/` | Hash fixtures, model round-trip, claim build/parse, enforcement (separate from SDK conformance gates) |

### Demo (servers + GuidedTour) — Part 2

| Area | File(s) | Change |
|------|---------|--------|
| Bookings resource (new) | `samples/MockResourceServers/Bookings/Program.cs` | **New** four-party R3 server (`:5004`, non-mission): advertise `r3_vocabularies` (MCP); publish `authorization_endpoint` + `POST /authorize` accepting `r3_operations`; map `r3_operations` → R3 doc; emit `r3_uri`/`r3_s256` (aud = AS); serve the signature-verified R3 endpoint behind a resource-owned trusted **AS + PS** allowlist (`jwks_uri` authority); per-call proposal on `book_trip`; enforce grants/conditional by R3 claims (not scope) |
| Access Server | [MockAccessServer/Program.cs](../../../samples/MockAccessServer/Program.cs) | Map `AAuth.R3`'s `R3AccessTokenEndpoint` for the R3 flow: fetch (signed) + hash-verify R3 doc; evaluate `operations`; mint `r3_granted`/`r3_conditional`; per-call proposal evaluation (not plain `IAccessPolicy` — Finding 1) |
| Person Server | [MockPersonServer/Program.cs](../../../samples/MockPersonServer/Program.cs) + ConsentStore | Fetch (signed) + hash-verify R3 doc; render its `display` at consent; federate to the AS. **Placement:** in the `/token` federated branch, after `VerifyResourceTokenAsync` yields the payload and before `FederateAsync` / the `202` interaction relay |
| GuidedTour enum/flags | [TourOptions.cs](../../../samples/GuidedTour/TourOptions.cs) | `TourMode.RichRequest`; `IsRichRequestMode` |
| GuidedTour engine | [TourSession.cs](../../../samples/GuidedTour/TourSession.cs) | `TotalSteps`, `RichRequestPlan`, step methods, `RunNextAsync` dispatch |
| GuidedTour UI | [Tour.razor](../../../samples/GuidedTour/Components/Pages/Tour.razor) | Picker option #10 + experimental blurb |
| Code snippets | [CodeSnippets.cs](../../../samples/GuidedTour/CodeSnippets.cs) | `AAuth.R3` preview-library snippet per step (`src/AAuth` unchanged) |
| Wiring | [Makefile](../../../Makefile), GuidedTour `appsettings.json` | A `demo-tour-r3` target wiring Bookings + AS + PS |
| E2E | [samples/GuidedTour/playwright-tests/](../../../samples/GuidedTour/playwright-tests) + picker count 9→10 | New `rich-request.spec.ts` |
| Docs | [docs/workflows/](../../../docs/workflows), [GuidedTour/README.md](../../../samples/GuidedTour/README.md) | New R3 workflow page + README update, experimental note |

## Part E — Security invariants to demonstrate / test

From v02 §Security Considerations (the linchpins of agent opacity):

- **Trusted-fetcher gate (AS + PS), agent-opaque.** The Bookings R3 endpoint MUST
  verify a valid HTTP Message Signature and serve only to the resource's trusted AS
  or trusted PS, rejecting agents and all untrusted callers. The **`AAuth.R3` library
  verifies the signature (via the SDK verifier) and surfaces the caller; the resource
  owns the allowlist** (Decision 3).
  This is the enforced (not by-convention) basis of agent opacity — worth a tour
  step showing an agent fetch rejected vs. the AS/PS signed fetch succeeding.
  > **Note — deliberate spec deviation.** §Content Addressing literally says reject
  > anything *"not signed by the resource's AS"*, but §R3 Processing requires the PS
  > to fetch too. We follow the processing model (trusted AS + PS); see Part A.
- **Hash-verify before use.** The AS **and** the PS MUST each verify `r3_s256`
  against the bytes they fetch before using the document.
- **Per-call digest binding.** On the conditional retry, the resource MUST verify
  the presented parameters' digest matches the approved proposal — the approval
  cannot be replayed against different content.

## Open Questions

1. **R3 endpoint path on Bookings** — confirm a path (e.g. `/r3/{hash}`) and that
   both the AS and PS signing keys are discoverable to Bookings for the trusted-
   fetcher gate.
   > **Resolved (2026-06-26).** Path is **`/r3/{hash}`**. `r3_vocabularies`
   > advertises MCP discovery as **`{bookings}/mcp`** (concrete per spec; not a live
   > MCP server, discovery parsing out of scope). The `jwks_uri` wire parameter is
   > **`uri`** (`sig=jwks_uri;uri="…";kid="…"`); match on the parsed `JwksUri`
   > authority, not a `jwks_uri="…"` literal.
2. **Bookings ↔ AS/PS trust wiring for the R3 fetch.** Bookings is a brand-new
   four-party server, so it must be provisioned from the start to (a) trust the AS
   as the auth-token *issuer* and (b) recognize the AS **and** PS signing keys for
   the R3 *fetch* gate (config vs. discovery). No existing server wiring is
   disturbed.
   > **Resolved (2026-06-26, CC12).** Bookings names a **dedicated AS origin**
   > (`:5501`, a MockAccessServer in R3 mode) as its `aud`. The PS reaches it purely
   > by `aud` (origin-pinned `token_endpoint` discovery in
   > [AccessServerClient.FederateAsync](../../../src/AAuth/Access/AccessServerClient.cs)),
   > so no PS federation-logic change is needed — only the new AS issuer in the PS
   > trusted-federation set. The shared `:5500` AS keeps `MapAAuthAccessServer`;
   > scenario 6 / Wallet are unaffected.
3. **Step count** — target ~9 steps for the full granted+conditional arc; finalize
   once the server round-trips are wired (mirrors how Federated's count flexes).

## Out of Scope

| Item | Reason |
|------|--------|
| Vocabularies other than MCP | Demo focuses on MCP; OpenAPI/gRPC/etc. deferred |
| Vocabulary discovery parsing (MCP tool-list fetch, OpenAPI `$metadata`) | Discovery detail; the demo uses a fixed operation set |
| Mission + R3 combined flow | Orthogonal by decision; spec gap (prior research Part D) |
| Production AS/PS SDK roles | SDK stays agent+resource centric; AS/PS remain mock |
| Any change to `src/AAuth` | R3 stays out of the core SDK (2026-06-23); implemented in the `AAuth.R3` preview library + demo |
| R3 on Calendar / converting Calendar to four-party | Superseded by a dedicated four-party server (Decision 2) |
| Reusing the Wallet for R3 | Superseded 2026-06-23 by a dedicated new `Bookings` server |
| Mission-aware R3 on Bookings | Kept simple by request — Bookings reuses nothing from the mission-bound Trips server |
| SDK-owned trusted-fetcher allowlist | Resource-owned by Decision 3; the `AAuth.R3` library only verifies signatures |
