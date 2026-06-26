# R3 Guided Tour Scenario - Session Feedback (2026-06-22)

This file captures feedback and decisions discussed during the 2026-06-22
implementation-readiness session. It intentionally does not update
`research.md` or `implementation-plan.md`; those remain unchanged until the
open items below are resolved.

## Decision 1 - Trusted AS and PS R3 Fetch

R3 document and per-call proposal fetches should be allowed for both trusted
Access Servers and trusted Person Servers.

Implementation implication: the resource-side R3 document endpoint should not be
hard-coded as AS-only. It should enforce that callers are trusted R3 document
consumers, with trust generalized by role/configuration so the same mechanism can
authorize a resource's AS and trusted PSes while still rejecting agents and all
untrusted callers.

The endpoint still preserves the agent-opacity property: agents may carry
`r3_uri` and `r3_s256` in tokens, but they must not be able to fetch the R3
document or proposal body directly.

## Decision 2 - Reuse Scenario 6 Topology, Keep Scenario 10 Independent

Decision: reuse the topology of GuidedTour scenario 6, but build the R3 tour as
an independent scenario 10.

GuidedTour scenario 6 already uses the Wallet resource and MockAccessServer in
the four-party federated flow. Scenario 10 should reuse that deployment shape:
resource token audience is the AS, the PS federates to the AS, and the AS issues
the final auth token. The existing scenario 6 should remain its own Wallet
federation walkthrough.

Working notes:

- Wallet is already a four-party resource: it issues resource tokens whose
  audience is the Access Server, and it trusts AS-issued auth tokens.
- Reusing scenario 6's topology reduces topology changes compared with converting
  Calendar from its existing PS-asserted flow into a federated R3 flow.
- Scenario 10 stays separate in the picker and tour engine so the existing
  federated Wallet scenario remains intact.
- The remaining design choice is narrative/domain: whether scenario 10 uses
  Wallet-flavored R3 operations or keeps the Calendar/MCP operation story while
  borrowing the four-party topology pattern.

Outcome: implement R3 as a new scenario 10 that reuses the scenario 6
four-party topology pattern without modifying scenario 6's purpose.

## Decision 3 - SDK Verifies Signatures; Resource Owns R3 Fetch Trust Policy

Decision: the SDK does not need to enforce trusted AS/PS authorization for R3
document fetches. The SDK should validate HTTP Message Signatures and expose the
verified caller information. The resource server implementation is responsible
for checking that the verified caller is in its configured list of trusted R3
fetch parties, such as trusted ASes and trusted PSes.

This aligns with the spec because the normative requirement is on resource
behavior: the resource must reject unauthorized R3 document/proposal fetches. The
trust decision can live in the resource application as long as it is enforced
before returning protected R3 bytes.

Working notes:

- The problem is not that the SDK cannot verify HTTP Message Signatures. It can.
- Signature validation proves who signed the request; it does not by itself mean
  that the signer is allowed to fetch R3 material.
- Agent opacity still depends on the resource rejecting signed-but-untrusted
  callers, including valid agent signatures.
- The chosen shape must support trusted PS fetch as well as trusted AS fetch.
- A resource implementation can hard-code, configure, or discover trusted AS/PS
  parties, but that policy remains resource-owned rather than SDK-owned.

Outcome: SDK implements R3 primitives plus signature verification surfaces;
resource servers enforce their own trusted AS/PS allowlist before serving R3
documents or proposals.

## Discussion 4 - Hash Test Vectors

Status: clarified; no implementation blocker identified.

Question: Clarify the statement that the draft has example R3 documents but not
expected hash vectors.

Working notes:

- The draft shows JSON examples of R3 documents and per-call proposals, but it
  does not publish expected digest values for those examples.
- This is not a test blocker. Tests should store a pre-calculated digest, mock an
  HTTP payload that is meant to match that digest after hashing, and assert that
  the computed `r3_s256` matches.
- Because v02 hashing is over bytes served, whitespace, property order, line
  endings, and final newline all affect the hash. Tests must therefore pin exact
  payload bytes, not just object equality.
- A negative test should use a visually similar but byte-different payload, or a
  tampered digest, to prove that byte changes are detected.
- These are local project fixtures, not values copied from the draft text.

Outcome: use simple pre-calculated local hash fixtures over exact mocked HTTP
payload bytes; include a negative byte-mismatch or digest-mismatch case.