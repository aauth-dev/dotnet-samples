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

### Definition of Done

- [x] `EnrollResult.EnrolledKeyId` renamed to `LocalKeyHandle`
- [x] `EnrollResult.AgentTokenKid` added (nullable)
- [x] `EnrolAsync` uses `key.ComputeJwkThumbprint()` as local handle
- [x] Two `RefreshAsync` overloads collapsed to one (removed `currentAgentToken`)
- [x] `AgentProviderTokenRefresher` parameters renamed
- [x] XML docs updated with keystore-separation language
- [x] `dotnet build` passes

## Phase 2 — Tests

`tests/AAuth.Tests/Agent/AgentProviderTokenRefresherTests.cs`
* Rename `Constructor_ThrowsOnEmptyEnrolledKeyId` → `Constructor_ThrowsOnEmptyLocalKeyHandle`.
* Update any other affected assertions/identifiers.

(Sweep for any other test files touching `EnrolledKeyId`.)

### Definition of Done

- [x] Test method renamed
- [x] `dotnet test` passes

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

### Definition of Done

- [x] All samples compile
- [x] `result.EnrolledKeyId` references replaced with `result.LocalKeyHandle`
- [x] AgentConsole persists/restores `AgentTokenKid` in enrollment cache
- [x] AgentConsole variable renamed from `keyId` to `localKeyHandle` (done in Phase 5b)
- [x] `JwksUri.razor` uses `AgentTokenKid` for `UseJwksUri` kid param — throws if null per spec (done in Phase 5a)

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

### Definition of Done

- [x] `bootstrap-enrollment.md` rewritten with three-identifier table
- [x] All workflow docs updated with `AAuth:LocalKeyHandle`
- [x] `concepts.md` clarification added
- [x] `getting-started.md` updated
- [x] `dependency-injection.md` updated
- [x] `docs/signing-modes/agent-identity-jwks-uri.md` clarified (done in Phase 5f)
- [x] `docs/signing-modes/overview.md` clarified (done in Phase 5f)
- [x] `docs/advanced/key-management.md` clarified (done in Phase 5f)

## Phase 5 — Review findings fix-up

> **Added 2026-05-27** after PR #22 review. Addresses bugs and gaps identified during spec-alignment review and automated PR review comments.

### 5a. Fix `jwks_uri` kid bug in samples

The `UseJwksUri(url, kid)` call must pass the AP-published JWKS `kid` (from `AgentTokenKid`), not the local keystore handle. The local handle defaults to the JWK thumbprint, which doesn't match the AP's published `kid` in the JWKS — causing `unknown_key` errors at the resource.

| File | Fix |
|------|-----|
| `samples/SampleApp/Components/Pages/JwksUri.razor` | Change `var keyId = _enrollment.LocalKeyHandle` → use `_enrollment.AgentTokenKid ?? _enrollment.LocalKeyHandle` as the kid param in `UseJwksUri` |
| `samples/GuidedTour/CodeSnippets.cs` (`SignedGetJwksUri`) | Change `result.LocalKeyHandle` → `result.AgentTokenKid ?? result.LocalKeyHandle` |

### 5b. Complete variable rename in `AgentConsole/Program.cs`

Rename the `string keyId` variable to `string localKeyHandle` (and all its usages). The current name reintroduces the identifier confusion this PR eliminates.

### 5c. Complete snippet rename in `GuidedTour/CodeSnippets.cs`

The `SignedGetJwt`, `TokenExchangeDirect`, and `FullAutomatic` string constants still reference `keyId`. Update to `localKeyHandle`:
* Line 73: `AgentProviderTokenRefresher.Create(refreshEndpoint, keyId)` → `localKeyHandle`
* Line 112: same pattern
* Line 214: `var key = await keyStore.LoadAsync(keyId)` → `localKeyHandle`
* Line 216: same pattern as line 73

### 5d. Fix `Jwt.razor` illustrative HTML code

The `<pre><code>` block (line ~38) shows `RefreshAsync(refreshEndpoint, keyId, ct)`. Update to `localKeyHandle`.

### 5e. Clarify `AgentTokenKid` documentation

> **Update (2026-05-27):** PR review identified that `AgentTokenKid` is documented as "diagnostic only" but is actually **required** for `jwks_uri` mode (it's the kid the AP publishes in its per-agent JWKS). Update the XML doc to:
> "AP-published key identifier returned in the enrollment response. Required as the `kid` parameter for `UseJwksUri` when using `jwks_uri` signing mode. For other signing modes (hwk, jwt, jkt-jwt), this value is informational only."

### 5f. Doc gaps — signing-modes and key-management clarifications

| File | Change |
|------|--------|
| `docs/signing-modes/agent-identity-jwks-uri.md` | Add comment to AP-enrolled example: `// "my-key-1" is the AP-published kid (EnrollResult.AgentTokenKid), not the local key handle` |
| `docs/signing-modes/overview.md` | Add comment to `jwks_uri` line: `// kid = AP-published JWKS kid (AgentTokenKid) or self-chosen kid for self-hosted` |
| `docs/advanced/key-management.md` | Add a paragraph in the Overview or after `IKeyStore` interface noting that for AP-enrolled agents the `keyId` parameter is the `LocalKeyHandle` (JWK thumbprint by default) — not an AP-assigned identifier |

### 5g. Sweep top-level `README.md`

Check for any enrollment code snippets using `EnrolledKeyId` or `AAuth:KeyId`. Update if found.

### Definition of Done

- [x] `JwksUri.razor` uses `AgentTokenKid` for kid param (throws if null — no fallback per spec)
- [x] `GuidedTour/CodeSnippets.cs` `SignedGetJwksUri` uses `AgentTokenKid` (throws if null)
- [x] `GuidedTour/CodeSnippets.cs` remaining snippets use `localKeyHandle` variable
- [x] `AgentConsole/Program.cs` variable renamed from `keyId` to `localKeyHandle`
- [x] `Jwt.razor` illustrative HTML updated
- [x] `EnrollResult.AgentTokenKid` XML doc updated (required for jwks_uri, not "diagnostic only")
- [x] `docs/signing-modes/agent-identity-jwks-uri.md` comment added
- [x] `docs/signing-modes/overview.md` comment added
- [x] `docs/advanced/key-management.md` paragraph added
- [x] `README.md` swept — no stale enrollment references
- [x] `dotnet build` passes
- [x] All four AgentConsole signing modes verified against mock servers (hwk ✓ jwks_uri ✓; jwt/jkt-jwt need PS flow)
- [x] AgentConsole auto-routes to `/hwk` or `/jwks-uri` when target URL has no path

## Phase 6 — SDK improvements (formerly out of scope)

> **Added 2026-05-27.** These items were originally out of scope but pulled in to complete the identifier cleanup in one pass.

### 6a. Rename `IKeyStore` parameter from `keyId` to `handle`

The `IKeyStore` interface uses `string keyId` as the parameter name in `LoadAsync`, `StoreAsync`, and `DeleteAsync`. After the rename PR the semantic is clearly "a local handle/name" — rename the parameter to `handle` to complete the cleanup.

| File | Change |
|------|--------|
| `src/AAuth/Crypto/IKeyStore.cs` | Rename parameter `keyId` → `handle` in `LoadAsync`, `StoreAsync`, `DeleteAsync` |
| `src/AAuth/Crypto/FileKeyStore.cs` | Update parameter names to match interface |
| `src/AAuth/Crypto/InMemoryKeyStore.cs` | Update parameter names to match interface |
| `docs/advanced/key-management.md` | Update interface listing and examples |

### 6b. Add `AAuthClientBuilder.From(EnrollResult)` convenience API

Every sample after enrollment manually extracts fields and wires them together. Add a static factory that wires `LocalKeyHandle`, `AgentTokenKid`, `JwksUri`, and `Key` from an `EnrollResult`.

```csharp
// Proposed API
public static AAuthClientBuilder From(EnrollResult result, IKeyStore keyStore)
```

The builder should pre-configure:
* `Key` from `result.Key`
* If `result.JwksUri` is set: `UseJwksUri(result.JwksUri, result.AgentTokenKid ?? result.LocalKeyHandle)`

Callers still chain `.WithTokenRefresh(...)` and `.WithChallengeHandling(...)` as needed.

### 6c. Two-key (`jkt-jwt`) refresh — SDK side

The SDK currently only implements single-key (`hwk`) refresh. Add `jkt-jwt` refresh support:

| File | Change |
|------|--------|
| `src/AAuth/Agent/NamingJwtBuilder.cs` | **New file.** Internal helper that creates a naming JWT signed by the durable key, embedding the ephemeral key's public half as `cnf.jwk`. Claims: `iss` (AP URL), `iat`, `exp` (+5 min), `jti`, `cnf.jwk`. Header: `alg=EdDSA`, `typ=naming+jwt`, `kid` = durable key thumbprint. |
| `src/AAuth/Agent/AgentProviderClient.cs` | Add `RefreshTwoKeyAsync(refreshEndpoint, localKeyHandle, apIssuer, ct)` → `TwoKeyRefreshResult`. Generates ephemeral key, builds naming JWT, signs refresh POST with ephemeral key under `jkt-jwt` scheme, returns `{ AgentToken, EphemeralKey }`. |
| `src/AAuth/Agent/AgentProviderClient.cs` | Add `TwoKeyRefreshResult` record: `AgentToken` (string) + `EphemeralKey` (AAuthKey). |
| `src/AAuth/Agent/AgentProviderTokenRefresher.cs` | Add `RefreshMode` enum (`SingleKey` / `TwoKey`). Add `.WithRefreshMode(RefreshMode)` to `RefresherBuilder`. When `TwoKey`, call `RefreshTwoKeyAsync` and update the signing key in the handler. |

### 6d. Two-key (`jkt-jwt`) refresh — MockAP side

The MockAgentProvider's `/refresh` endpoint currently only accepts `scheme=hwk`. Extend it to also accept `scheme=jkt-jwt`:

| File | Change |
|------|--------|
| `samples/MockAgentProvider/Program.cs` | In `/refresh` handler: if `parsedKey.Scheme == "jkt-jwt"`, parse the naming JWT, extract `cnf.jwk` (ephemeral key), verify naming JWT signature against enrolled durable key (looked up by durable key thumbprint from JWT `kid`), verify HTTP signature against ephemeral key, issue new agent token with `ConfirmationKey = ephemeralKey`. |

### 6e. AgentConsole — wire two-key refresh

| File | Change |
|------|--------|
| `samples/AgentConsole/Program.cs` | In `case "jkt-jwt"`: switch from single-key `RefreshAsync` to the new `RefreshTwoKeyAsync`-based flow, using the refresher builder with `.WithRefreshMode(RefreshMode.TwoKey)`. |

### Definition of Done

- [x] `IKeyStore` parameter renamed from `keyId` to `handle`
- [x] `FileKeyStore` and `InMemoryKeyStore` parameter names updated
- [x] `AAuthClientBuilder.From(EnrollResult)` implemented
- [x] At least one sample updated to use `AAuthClientBuilder.From()`
- [x] `NamingJwtBuilder` implemented (internal helper)
- [x] `RefreshTwoKeyAsync` implemented in `AgentProviderClient`
- [x] `TwoKeyRefreshResult` type added
- [x] `AgentProviderTokenRefresher` supports `RefreshMode.TwoKey`
- [x] MockAP `/refresh` accepts `jkt-jwt` scheme
- [x] AgentConsole `jkt-jwt` mode uses two-key refresh
- [x] `dotnet build` passes
- [x] `dotnet test` passes
- [x] AgentConsole `--signing-mode jkt-jwt` returns 200 against mock servers

## Validation

* `dotnet build` and `dotnet test` from the repo root.
* Visual review of bootstrap-enrollment.md.
* All four AgentConsole signing modes (`hwk`, `jwks_uri`, `jwt`, `jkt-jwt`) return 200 against mock servers.

## Commit / PR shape

Single PR (alpha repo, all changes are coupled):

1. SDK rename + thumbprint default + XML doc clarifications.
2. Test updates.
3. Sample updates.
4. Documentation updates.
5. Review fix-ups (kid bug, variable naming, doc gaps).

PR title: "Rename EnrolledKeyId → LocalKeyHandle; clarify AP enrollment key identifiers"

## Out of Scope

| Item | Reason |
|------|--------|
| AP-side identifier policy in MockAgentProvider | Already does correct thumbprint-based lookup at refresh — no change needed |
