---
title: "AP Enrollment Key Naming — Implementation Plan"
description: Rename EnrolledKeyId to LocalKeyHandle, default to JWK thumbprint, and clarify docs/samples around AP↔agent identifier separation.
ms.date: 2026-05-27
---

## Goals

1. Stop conflating three distinct identifiers (JWK thumbprint, AP-internal JWT `kid`, local keystore handle).
2. Default the local keystore handle to the durable key's JWK thumbprint (spec-endorsed; § Identifier Strategies in `draft-hardt-aauth-bootstrap.md`).
3. Make XML docs, samples, and prose state clearly that the AP and agent **never share a keystore**, and that the AP identifies the agent at refresh time by signature/thumbprint, not by any string the agent sends.

Breaking renames are OK (alpha).

## Phase 1 — SDK changes

`src/AAuth/Agent/AgentProviderClient.cs`
* Rename `EnrollResult.EnrolledKeyId` → `LocalKeyHandle`. XML doc: "Agent-local handle for the durable private key in `IKeyStore`. Persist this in your config so the agent can re-load the key after restart. The AP does not see this value — at refresh time the AP identifies the agent from the HTTP signature (JWK thumbprint), not from this string."
* Add `EnrollResult.AgentTokenKid` (nullable `string`). XML doc: "AP-internal opaque identifier the AP returned in the enrollment response (typically the JWT `kid` of the issued agent token). Diagnostic only — the agent never sends this back."
* In `EnrolAsync`: drop the `$"{agentId}:{Guid.NewGuid():N}"` fabrication. Compute `localHandle = key.ComputeJwkThumbprint()`. Store the key under `localHandle`. Capture the AP's optional `body["key_id"]` into `AgentTokenKid`.
* Collapse the two `RefreshAsync` overloads into one: `RefreshAsync(string refreshEndpoint, string localKeyHandle, CancellationToken ct)`. Remove the misleading `currentAgentToken` parameter (unused — confirmed by reading `RefreshCoreAsync`).

`src/AAuth/Agent/AgentProviderTokenRefresher.cs`
* Rename ctor / builder / field parameters `enrolledKeyId` → `localKeyHandle`.
* Update XML docs to use the new "AP and agent never share a keystore" language.

## Phase 2 — Tests

`tests/AAuth.Tests/Agent/AgentProviderTokenRefresherTests.cs`
* Rename `Constructor_ThrowsOnEmptyEnrolledKeyId` → `Constructor_ThrowsOnEmptyLocalKeyHandle`.
* Update any other affected assertions/identifiers.

(Sweep for any other test files touching `EnrolledKeyId`.)

## Phase 3 — Samples

| File | Change |
|------|--------|
| `samples/AgentConsole/Program.cs` | `result.EnrolledKeyId` → `result.LocalKeyHandle` |
| `samples/SampleApp/EnrollmentService.cs` | property + field rename; update comments |
| `samples/SampleApp/Components/Pages/JwksUri.razor` | property usage + UI label |
| `samples/SampleApp/Components/Pages/Jwt.razor` | property usage |
| `samples/GuidedTour/CodeSnippets.cs` | property usage + comments |
| `samples/Orchestrator/Program.cs` | commented snippet only |

Leave `samples/MockAgentProvider/appsettings.json` (`AgentProvider:KeyId = ap-key-1`) alone — that is the AP's **own** signing-key id, a different concept.

## Phase 4 — Docs

Primary rewrite:
* `docs/workflows/bootstrap-enrollment.md`
  * Code snippets: `enrol.EnrolledKeyId` → `enrol.LocalKeyHandle`; `AAuth:KeyId` → `AAuth:LocalKeyHandle`.
  * "What Bootstrap Produces" — split the `key_id` bullet into "A local key handle (agent-chosen, defaults to the durable key's JWK thumbprint)" and "An optional AP-internal JWT `kid` carried inside the agent token (opaque to receivers)".
  * "Token Refresh" → "AP-Enrolled Agents" — call out that the AP identifies the agent from the signature alone; the handle is purely a local `IKeyStore` lookup.
  * "Key IDs: What Goes Where" — restructure into three rows for the three identifiers (JWK thumbprint / AP-internal JWT `kid` / local keystore handle) instead of two scenarios.
  * Update the mermaid "AP-Enrolled: Key ID Flow" diagram to relabel "Agent Provider assigns key_id" → "Agent Provider records public key by JWK thumbprint" and the local-store node to "stores private key under local handle (defaults to thumbprint)".

Touch-ups (rename string `EnrolledKeyId` and `AAuth:KeyId` → `AAuth:LocalKeyHandle`, with a one-line clarification where the doc mentions the AP):
* `docs/getting-started.md`
* `docs/reference/dependency-injection.md`
* `docs/signing-modes/agent-token-jwt.md`
* `docs/workflows/call-chaining.md`
* `docs/workflows/deferred-consent.md`
* `docs/workflows/federated-access.md`
* `docs/workflows/identity-based-access.md`
* `docs/workflows/ps-asserted-access.md`
* `docs/workflows/resource-managed-access.md`

Smaller insertion:
* `docs/concepts.md` — add a one-line note in the Agent Provider row that AP and agent share only public keying material; the agent's private key never leaves the agent's `IKeyStore`.

## Validation

* `dotnet build` and `dotnet test` from the repo root.
* Visual review of bootstrap-enrollment.md.
* `parallel_validation` before opening the PR.

## Commit / PR shape

Single PR (alpha repo, all changes are coupled):

1. SDK rename + thumbprint default + XML doc clarifications.
2. Test updates.
3. Sample updates.
4. Documentation updates.

PR title: "Rename EnrolledKeyId → LocalKeyHandle; clarify AP enrollment key identifiers"
