# AAuth Conformance Test Suite

Spec-traceable tests that exercise this SDK against clauses in the AAuth
protocol specification.

## Spec version under test

See [`aauth-spec/SPEC-VERSION.md`](../../aauth-spec/SPEC-VERSION.md). At the time
of writing: draft-11, commit `178e9e68b6578e4d6f7d0bf30f33b4c38833e3a1`
(tag `draft-hardt-oauth-aauth-protocol-11`).

When the spec version bumps, run this suite first — failures here generally
indicate either a spec drift to absorb or a real conformance regression.

## Organization

Tests are grouped by spec section. Each test:

- Has a `[Fact(DisplayName = "<section-id> <requirement> <expectation>")]`
  so test output reads like a checklist of conformance clauses.
- Carries an xmldoc summary quoting the exact spec sentence(s) it enforces.
- Lives in a folder named after the spec area
  (`AgentTokens/`, `HttpSignatures/`, `ResourceTokens/`, `Discovery/`, ...).

## Scope today

Coverage includes issuer and receiver behavior for agent, person, resource and
auth tokens; resource-managed `AAuth-Access`; four-party trust; deferred
polling; revocation cascades; missions; sub-agents; call chaining; HTTP
Signature-Key/JWT verification; and discovery endpoints. R3 and Events companion
coverage lives in their own unit projects.

## Section → file map

| Spec section | Test file | Status |
|---|---|---|
| protocol §Agent Token Structure | [AgentTokens/AgentTokenStructureTests.cs](AgentTokens/AgentTokenStructureTests.cs) | Covered |
| protocol §Agent Token Verification | [AgentTokens/AgentTokenVerificationTests.cs](AgentTokens/AgentTokenVerificationTests.cs) | Covered |
| signature-key §Header Format | [HttpSignatures/SignatureKeyHeaderTests.cs](HttpSignatures/SignatureKeyHeaderTests.cs) | Covered |
| protocol §HTTP Signature Profile | [HttpSignatures/CoveredComponentsTests.cs](HttpSignatures/CoveredComponentsTests.cs) | Covered |
| protocol §Resource Token Structure | [ResourceTokens/ResourceTokenStructureTests.cs](ResourceTokens/ResourceTokenStructureTests.cs) | Covered |
| protocol §Discovery | [Discovery/WellKnownMetadataTests.cs](Discovery/WellKnownMetadataTests.cs) | Covered |
