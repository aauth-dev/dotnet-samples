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

## Scope today (Phase 1)

Only **issuer-side** clauses for agent tokens. Receiver-side clauses
("MUST verify ...") land in Phase 2 alongside the token verifier and HTTP
signature verification middleware.

## Section → file map

| Spec section | Test file | Status |
|---|---|---|
| protocol §Agent Token Structure | [AgentTokens/AgentTokenStructureTests.cs](AgentTokens/AgentTokenStructureTests.cs) | Phase 1 |
| protocol §Agent Token Verification | _pending_ | Phase 2 |
| signature-key §Header Format | _pending_ | Phase 2 |
| protocol §Resource Tokens | _pending_ | Phase 2 |
| protocol §Discovery | _pending_ | Phase 2 |
