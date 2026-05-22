# AAuth .NET SDK Documentation

This is the documentation for the AAuth .NET SDK (`AAuth` NuGet package). It covers agent-side signing, server-side verification, all four signing modes, and all resource access workflows.

- [Interactive Protocol Explorer](https://explorer.aauth.dev/)
- [AAuth Protocol Specification](../aauth-spec/draft-hardt-oauth-aauth-protocol.md)

## Getting Started

- [Getting Started](getting-started.md) — Install, generate a key, make your first signed request
- [Protocol Concepts](concepts.md) — The four participants (Agent, Resource, Person Server, Access Server), three layers, and how the SDK maps to them

## Signing Modes

[Compare signing modes →](https://explorer.aauth.dev/signing/compare)

- [Overview](signing-modes/overview.md) — When to use each mode
- [Pseudonymous (hwk)](signing-modes/pseudonymous-hwk.md)
- [Agent Identity (jwks_uri)](signing-modes/agent-identity-jwks-uri.md)
- [Agent Token (jwt)](signing-modes/agent-token-jwt.md)
- [Key Rotation (jkt-jwt)](signing-modes/key-rotation-jkt-jwt.md)

## Workflows

[Compare access workflows →](https://explorer.aauth.dev/access/compare)

- [Identity-Based Access](workflows/identity-based-access.md)
- [Resource-Managed Access](workflows/resource-managed-access.md)
- [PS-Asserted Access](workflows/ps-asserted-access.md)
- [Federated Access](workflows/federated-access.md)
- [Bootstrap & Enrollment](workflows/bootstrap-enrollment.md)
- [Deferred Consent](workflows/deferred-consent.md)

## Server Implementation

- [Verification Middleware](server/verification-middleware.md)
- [Resource Metadata](server/resource-metadata.md)
- [Token Issuance](server/token-issuance.md)
- [Replay Detection](server/replay-detection.md)
- [Multi-Scheme Verification](server/multi-scheme-verification.md)

## Advanced Topics

- [Missions](advanced/missions.md)
- [Platform Attestation](advanced/platform-attestation.md)
- [Key Management](advanced/key-management.md)
- [Error Handling](advanced/error-handling.md)

## Reference

- [Configuration](reference/configuration.md)

## Samples

- [`GuidedTour`](../samples/GuidedTour/) — Interactive Blazor walkthrough of all flows
- [`AgentConsole`](../samples/AgentConsole/) — CLI agent demonstrating signing modes
- [`WhoAmI`](../samples/WhoAmI/) — Minimal resource server with verification middleware
