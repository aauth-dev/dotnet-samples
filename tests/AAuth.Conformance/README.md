# AAuth Conformance Test Suite

Spec-traceable tests that exercise this SDK against clauses in the AAuth
protocol specification.

## Spec version under test

See [`aauth-spec/SPEC-VERSION.md`](../../aauth-spec/SPEC-VERSION.md). At the time
of writing: commit `c090879ea2254d4af43a7253c7715f8d6530eb26`
(tag `draft-hardt-oauth-aauth-protocol-01`).

When the spec version bumps, run this suite first — failures here generally
indicate either a spec drift to absorb or a real conformance regression.

## Organization

Tests are grouped by spec section. Each test:

- Has a `[Fact(DisplayName = "<section-id> <requirement> <expectation>")]`
  so test output reads like a checklist of conformance clauses.
- Carries an xmldoc summary quoting the exact spec sentence(s) it enforces.
- Lives in a folder named after the spec area
  (`AgentTokens/`, `HttpSignatures/`, `ResourceTokens/`, `Discovery/`, ...).

## Scope today (Phase 2)

Issuer-side coverage for agent, resource, and (transitively, via the
verification tests) auth tokens; receiver-side coverage for agent tokens
and the AAuth HTTP signature profile; discovery endpoints (resource
metadata + JWKS).

## Section → file map

| Spec section | Test file | Status |
|---|---|---|
| protocol §Agent Token Structure | [AgentTokens/AgentTokenStructureTests.cs](AgentTokens/AgentTokenStructureTests.cs) | Phase 1 |
| protocol §Agent Token Verification | [AgentTokens/AgentTokenVerificationTests.cs](AgentTokens/AgentTokenVerificationTests.cs) | Phase 2 |
| signature-key §Header Format | [HttpSignatures/SignatureKeyHeaderTests.cs](HttpSignatures/SignatureKeyHeaderTests.cs) | Phase 2 |
| protocol §HTTP Signature Profile | [HttpSignatures/CoveredComponentsTests.cs](HttpSignatures/CoveredComponentsTests.cs) | Phase 2 |
| protocol §Resource Token Structure | [ResourceTokens/ResourceTokenStructureTests.cs](ResourceTokens/ResourceTokenStructureTests.cs) | Phase 2 |
| protocol §Discovery | [Discovery/WellKnownMetadataTests.cs](Discovery/WellKnownMetadataTests.cs) | Phase 2 |
