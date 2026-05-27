---
title: "AP Enrollment Key Naming — Research"
description: Spec alignment review of how the SDK names and uses the durable key identifier produced by Agent Provider enrollment, and how it flows into refresh.
ms.date: 2026-05-27
---

## Problem Statement

The current SDK surfaces a single `EnrolledKeyId` value out of `AgentProviderClient.EnrolAsync` and threads it through `AgentProviderTokenRefresher`, `IKeyStore`, and `appsettings.json`. The name implies "an identifier shared with the AP that the AP uses to recognize this agent at refresh," which is not what the spec says and is not what the code actually does. The conflation invites readers to assume the agent and the AP share a keystore. They do not.

## What the spec actually says

Source: `aauth-spec/draft-hardt-aauth-bootstrap.md` (the bootstrap draft is the authoritative reference for AP enrollment and refresh).

There are **three distinct identifiers** in play around enrollment / refresh; the spec keeps them disjoint:

| # | Identifier | Owner / origin | Where it travels | Purpose |
|---|------------|----------------|------------------|---------|
| A | **JWK thumbprint of the durable key** (RFC 7638) | Derived from the public key | Implicit on every signed request | The AP uses this to look up the enrollment record (§ "Refresh Patterns", lines 284, 305) |
| B | **JWT `kid` header** on the issued `aa-agent+jwt` | AP chooses (opaque string) | Inside the issued token | AP-internal; "Receivers treat the identifier as opaque" (§ "Agent Identifier Strategies", line 240). It is **not** an identifier the agent ever needs to send back to the AP. |
| C | **Local handle** for the durable private key inside the agent's `IKeyStore` | Agent chooses | Never leaves the agent process | Used by `IKeyStore.LoadAsync(handle)` at app startup |

Key quotes from the spec:

* §6 Single-Key Refresh: "APs ... sign the refresh request directly with the durable key under the `hwk` scheme. The AP verifies the signature, **looks up the enrollment by the key's thumbprint**, and issues a fresh agent token."
* §6 Two-Key Refresh: "The AP verifies the durable-key signature on the naming JWT, **looks up the enrollment by the durable key's thumbprint**, ..."
* §5 Identifier Strategies: "APs are free to choose any opaque scheme for the local part: ... a deterministic derivation from the durable key's thumbprint ... Receivers treat the identifier as opaque."

**Conclusion:** the spec permits — and explicitly endorses — deriving identifiers from the durable key's JWK thumbprint, and it treats any AP-returned string as opaque. The agent never needs to send back an enrollment identifier to refresh; the signature does the identification.

## What the SDK does today

`src/AAuth/Agent/AgentProviderClient.cs`:

```csharp
var key   = AAuthKey.Generate();
var keyId = $"{agentId}:{Guid.NewGuid():N}";          // (1) locally fabricated
...
var assignedKeyId = (string?)body["key_id"] ?? keyId; // (2) prefers AP's response
await _keyStore.StoreAsync(assignedKeyId, key, ct);   // (3) used as local handle
return new EnrollResult { ..., EnrolledKeyId = assignedKeyId, ... };
```

`AgentProviderTokenRefresher` then takes the same string back and does `keyStore.LoadAsync(enrolledKeyId)` (no value of that string is ever sent to the AP — confirmed in `RefreshCoreAsync`).

`samples/MockAgentProvider/Program.cs` confirms the AP-side behavior matches the spec: refresh ignores any client-supplied identifier and looks up the agent purely by JWK thumbprint (lines 192-196).

### Why this is confusing

1. **`EnrolledKeyId` name lies about ownership.** It sounds like an AP-issued identifier the AP also uses. In reality:
   - The AP-returned `key_id` is the JWT `kid` header (identifier **B**), which is opaque to everyone except the AP and is never required for refresh.
   - The value the agent persists is just a *local* handle for `IKeyStore` (identifier **C**).
2. **One name covers three jobs.** The SDK uses the same string for the JWT `kid`, the local keystore handle, and the human-readable config value. Conflating them suggests a shared keystore that does not exist.
3. **`{agentId}:{Guid.NewGuid():N}` fallback is misleading.** When the AP doesn't return `key_id`, the SDK fabricates a string that *looks* like an AP-assigned identifier. It is purely local.
4. **Docs reinforce the mismatch.** `docs/workflows/bootstrap-enrollment.md` table caption "AP-enrolled — Key ID value: `aauth:myapp@ap.example:c34078382e` — Who assigns it: Agent Provider" reads as if this string is meaningful to the AP at refresh. It is not.

## Is "use the JWK thumbprint" spec-compliant?

Yes. The spec is explicit (§5, line 240) that derivation from the durable key's thumbprint is one of the listed acceptable strategies, and that receivers treat identifiers as opaque. Using the thumbprint as the **local handle** is purely a client-side choice and the spec has nothing to say about it (it never leaves the agent). Using the thumbprint as the **JWT `kid`** the AP puts inside the issued token is an AP policy decision; our MockAP currently uses a `{agentId}:{guid}` form, which is fine — that's the AP's `kid` (identifier B), opaque to the agent.

## SDK design options for the local handle

| Option | Pros | Cons |
|--------|------|------|
| **Use the durable key's JWK thumbprint** (RFC 7638, base64url SHA-256) | Stable, collision-free, derivable any time from the key itself, matches the value the AP uses internally, no need to fabricate anything | A bit opaque if a human is reading their `appsettings.json` |
| Fabricate `{agentId}:{guid}` locally | Slightly more human-readable | Looks like an AP-assigned ID, but isn't; non-deterministic |
| Use the AP's response `key_id` verbatim | Matches what's printed in AP logs | Conflates two unrelated identifiers; breaks if the AP doesn't return one |

**Decision:** default the local handle to the durable key's JWK thumbprint. Drop the fabricated `{agentId}:{guid}` fallback. Allow callers to override the handle if they want a friendlier name. Expose any AP-returned `key_id` separately (as `AgentTokenKid`) for diagnostics — clearly labelled as AP-internal and opaque.

## Affected types and members

SDK (`src/AAuth/Agent/`):
* `EnrollResult.EnrolledKeyId` → `LocalKeyHandle`; add `AgentTokenKid` (nullable).
* `AgentProviderClient.EnrolAsync` — pick handle = `key.ComputeJwkThumbprint()`; record AP `key_id` separately.
* `AgentProviderClient.RefreshAsync(refreshEndpoint, currentAgentToken, enrolledKeyId, ct)` — `currentAgentToken` param is unused and misleading; collapse to a single `RefreshAsync(refreshEndpoint, localKeyHandle, ct)` overload.
* `AgentProviderTokenRefresher.Create(refreshEndpoint, enrolledKeyId)` — rename parameter to `localKeyHandle`; update XML docs.

Tests:
* `tests/AAuth.Tests/Agent/AgentProviderTokenRefresherTests.cs`

Samples (string `EnrolledKeyId` / config key `AAuth:KeyId`):
* `samples/AgentConsole/Program.cs`
* `samples/SampleApp/EnrollmentService.cs`
* `samples/SampleApp/Components/Pages/JwksUri.razor`
* `samples/SampleApp/Components/Pages/Jwt.razor`
* `samples/GuidedTour/CodeSnippets.cs`
* `samples/Orchestrator/Program.cs` (comment only)

(The `samples/MockAgentProvider/appsettings.json` `KeyId: ap-key-1` is the AP's **own** signing-key id — a different concept, unrelated to enrollment. Leave it alone.)

Docs:
* `docs/workflows/bootstrap-enrollment.md` (primary surface — rewrite Key IDs table and diagrams)
* `docs/getting-started.md`
* `docs/concepts.md` (one line clarifying AP↔agent share only public material)
* `docs/reference/dependency-injection.md`
* `docs/signing-modes/agent-token-jwt.md`
* `docs/workflows/call-chaining.md`
* `docs/workflows/deferred-consent.md`
* `docs/workflows/federated-access.md`
* `docs/workflows/identity-based-access.md`
* `docs/workflows/ps-asserted-access.md`
* `docs/workflows/resource-managed-access.md`
* Top-level `README.md` (sweep for enrollment snippets)

## Open questions resolved by the user

* **Rename to `LocalKeyHandle`** — confirmed.
* **Use JWK thumbprint as the default local handle** — confirmed spec-compliant; adopt.
* **Breaking changes acceptable** — yes (alpha); no `[Obsolete]` shim required.

## Out of scope

* Two-key (`jkt-jwt`) refresh: the SDK only implements single-key (`hwk`) refresh today; renaming is orthogonal to that work.
* AP-side identifier policy in the MockAgentProvider (it already does the correct thumbprint-based lookup at refresh).
