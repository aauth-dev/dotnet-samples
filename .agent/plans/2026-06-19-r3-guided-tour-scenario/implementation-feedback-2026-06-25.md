# R3 Guided Tour Scenario - Implementation Feedback (2026-06-25)

This file captures implementation-readiness feedback on the updated Rich Trip
Booking / `AAuth.R3` preview-library plan. It is written as actionable review
input for another agent to either implement directly or debate explicitly before
changing the plan.

The overall direction looks sound:

- Rich Trip Booking is a cleaner R3 demo domain than reusing Wallet or Calendar.
- Keeping R3 out of `src/AAuth` is a good boundary while R3 remains exploratory.
- An extraction-ready `samples/AAuth.R3` library is a reasonable bridge toward a
  future standalone `AAuth.R3` NuGet package.
- A new non-mission-aware `Bookings` four-party resource keeps the scenario
  isolated from existing Trips, Wallet, and mission flows.

The items below should be clarified before implementation starts.

## Finding 1 - AS R3 Processing Cannot Use Only `IAccessPolicy` Today

### Issue

The plan says `MockAccessServer` can use `AAuth.R3` through `IAccessPolicy`
`additionalClaims` to fetch/hash-verify R3 documents, evaluate operations, and
attach `r3_*` claims.

The output side is real: `AccessDecision.Allow(..., additionalClaims)` can pass
claims into `AuthTokenBuilder.AdditionalClaims`.

The input side is the problem: `AccessPolicyRequest` currently gives the policy
only:

- resource URL
- scope
- agent id
- identity claims
- optional interaction id

It does not expose the verified resource-token payload or the raw resource token.
Therefore an `IAccessPolicy` implementation cannot see `r3_uri` or `r3_s256`, so
it cannot fetch/hash-verify the R3 document or build `r3_granted` /
`r3_conditional` from the R3 document by itself.

### Why It Matters

If implementation assumes `IAccessPolicy` can evaluate R3, the AS work will stall
or accidentally reintroduce a `src/AAuth` change. This is the most important seam
to resolve while preserving the decision that `src/AAuth` remains untouched.

### Candidate Resolutions

1. **Preferred: add an `AAuth.R3`-owned AS token endpoint/wrapper for R3 flows.**
   The wrapper can manually verify the agent/resource tokens through the public
   `AAuth` APIs, read `r3_uri`/`r3_s256`, fetch/hash-verify R3, evaluate grants,
   and mint with `AuthTokenBuilder.AdditionalClaims`.

2. **Alternative: add a MockAccessServer-specific R3 token path.**
   This keeps `src/AAuth` untouched but is less extraction-ready than a reusable
   `AAuth.R3` AS helper.

3. **Rejected unless the no-SDK-change decision changes: extend `src/AAuth`
   `AccessPolicyRequest` to include the verified resource-token payload.**
   This would be clean for the core SDK but contradicts the current plan.

### Suggested Plan Update

Update Phase 2.2 to state whether `MockAccessServer` uses an `AAuth.R3` AS
endpoint/wrapper or a sample-specific R3 token path. Do not rely on plain
`IAccessPolicy` receiving R3 input unless the SDK is changed.

## Finding 2 - Bookings Resource Authorization Endpoint Should Be Explicit

### Issue

The plan says the GuidedTour sends `r3_operations`, but the Bookings resource
phase does not explicitly require a resource authorization endpoint.

In the R3 draft, `r3_operations` is sent to the resource authorization endpoint,
not to the PS or AS token endpoint. The resource maps requested operations to an
R3 document and returns a resource token carrying `r3_uri` and `r3_s256`.

### Why It Matters

A 401 challenge flow can still include R3 claims when `r3_operations` is absent,
but that skips the core demonstration: the agent declaring intended operations in
a vocabulary it understands.

### Suggested Plan Update

Add to Phase 2.1:

- Bookings publishes `authorization_endpoint` in `/.well-known/aauth-resource.json`.
- Bookings implements `POST /authorize` for the R3 scenario.
- `POST /authorize` accepts `{ "r3_operations": ... }`.
- Bookings validates the MCP tool names, chooses or composes the R3 document,
  persists exact bytes, computes `r3_s256`, and returns a resource token with
  `aud = AS`, `r3_uri`, and `r3_s256`.

This keeps the tour step `request r3_operations` faithful to the draft.

## Finding 3 - Per-Call Proposal Model Needs To Be First-Class

### Issue

Phase 1.2 lists the class R3 document fields only:

- `version?`
- `vocabulary`
- `operations[]`
- `display?`

Per-call proposals additionally require `parameters`, and proposal `display` may
include `detail`.

### Why It Matters

The plan later depends on `R3ProposalStore`, per-call proposal fetching, PS
rendering of proposal display, AS evaluation of proposal parameters, and digest
matching on retry. Without a first-class proposal model, those pieces will likely
be implemented ad hoc in the Bookings server instead of cleanly in `AAuth.R3`.

### Candidate Resolutions

1. Add `R3ProposalDocument` with:
   - `vocabulary`
   - single-operation `operations[]`
   - `parameters`
   - `display` including optional `detail`

2. Or make `R3Document` intentionally extensible and explicitly support
   proposal-only `parameters` plus `display.detail`.

### Suggested Plan Update

Add `R3ProposalDocument` or equivalent model coverage to Phase 1.2 and add tests
for proposal JSON round-trip, exact-byte serialization, and validation of
required `parameters`.

## Finding 4 - Signed R3 Fetch Identity Needs A Concrete Shape

### Issue

The plan says trusted AS and trusted PS can fetch R3 documents/proposals, and the
resource owns the allowlist. It does not yet say exactly how AS/PS identify
themselves on those signed fetches.

### Why It Matters

The trusted-fetcher predicate cannot be implemented or tested cleanly until the
caller identity shape is explicit.

### Candidate Resolution

Use `jwks_uri` signing for AS and PS R3 fetches:

- AS signs fetches with `Signature-Key: sig=jwks_uri; jwks_uri="{as}/.well-known/jwks.json"; kid="..."`.
- PS signs fetches with `Signature-Key: sig=jwks_uri; jwks_uri="{ps}/.well-known/jwks.json"; kid="..."`.
- Bookings allowlist matches those trusted AS/PS JWKS origins or issuer origins.

A `jwt` carrier could also work, but it would require deciding which AS/PS role
tokens are used. `jwks_uri` is simpler and matches existing PS-to-AS federation
patterns in the samples.

### Suggested Plan Update

Add a cross-cutting decision or Phase 2.1 implementation decision naming the R3
fetch signing scheme and the allowlist comparison key.

## Finding 5 - Custom Resource Token Writer Needs Parity Tests

### Issue

The plan correctly notes that `ResourceTokenBuilder` has no extra-claims hook and
`JwtWriter` is internal, so `AAuth.R3` must emit its own R3 resource token for the
custom challenge / authorization response.

### Why It Matters

A custom writer must remain compatible with the existing verifier and downstream
PS/AS token endpoints. It is easy to mint a token that looks right but fails
resource-token verification.

### Suggested Tests

Add tests proving the custom R3 resource token passes
`TokenVerifier.VerifyResourceTokenAsync` and preserves R3 claims in the verified
payload.

Minimum assertions:

- header `typ = aa-resource+jwt`
- payload `dwk = aauth-resource.json`
- expected `aud`, `agent`, `agent_jkt`, `iat`, `exp`
- signature verifies through the Bookings JWKS metadata path
- `r3_uri` and `r3_s256` are both present and parseable after verification
- invalid one-sided R3 claims are rejected before minting

### Suggested Plan Update

Add this parity requirement to Phase 1.3 Definition of Done.

## Finding 6 - Scope vs R3 Enforcement Should Be Explicit

### Issue

Bookings is new, so the plan can avoid the ambiguity that existed with Wallet's
scope-based endpoints. But it should still state whether Bookings uses scopes at
all for the R3 path.

### Why It Matters

R3 demonstrates operation-based authorization. If Bookings also requires legacy
scope policies on the same endpoints, implementation may mint valid R3 grants but
still fail ASP.NET authorization because no matching scope was present.

### Recommended Decision

For scenario 10, Bookings operation endpoints should be enforced by R3 claims,
not by legacy scope policies:

- `search_trip_options` and `hold_itinerary` require matching operations in
  `r3_granted`.
- `book_trip` first matches `r3_conditional`, returns a per-call proposal, then
  accepts the retry only when the per-call auth token grants `book_trip` and the
  presented parameters match the stored proposal.
- Any scope claim included for compatibility should not be the primary gate for
  the scenario endpoints.

### Suggested Plan Update

Add this as a Phase 2.1 implementation decision and test it explicitly.

## Finding 7 - Research Has A Stale Wallet Wiring Reference

### Issue

The implementation plan now correctly says `demo-tour-r3` wires Bookings + AS +
PS + GuidedTour. The research implementation-surface table still says the wiring
is Wallet + AS + PS.

### Why It Matters

This is small, but it can mislead an implementation agent that reads research
before the plan.

### Suggested Plan/Research Update

Update the research table row to Bookings + AS + PS. The historical 2026-06-22
Wallet decision can remain as superseded context, but current implementation
surface should consistently name Bookings.

## Finding 8 - GuidedTour Snippets Should Say `AAuth.R3`, Not SDK Snippets

### Issue

The plan still describes `CodeSnippets.cs` as "R3 SDK snippets per step" in some
places. With the new architecture, examples should show `AAuth.R3` preview-library
usage and make clear that `src/AAuth` remains unchanged.

### Why It Matters

The tour and docs should reinforce the package boundary instead of implying R3 is
part of the core SDK.

### Suggested Plan Update

Rename this wording to "AAuth.R3 snippets per step" or "R3 preview-library
snippets per step."

## Summary Recommendation

Before implementation, update the plan to resolve these three high-impact seams:

1. How MockAccessServer gets access to `r3_uri`/`r3_s256` without changing
   `src/AAuth`.
2. The exact Bookings `POST /authorize` flow that receives `r3_operations`.
3. The first-class per-call proposal model and enforcement flow.

After those are explicit, the rest of the plan is implementable with the stated
library boundary.