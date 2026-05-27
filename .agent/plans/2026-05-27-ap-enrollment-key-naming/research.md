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

> **Update (2026-05-27):** Two-key (`jkt-jwt`) refresh was pulled into scope as Phase 6c–6e. Resource-side jkt-jwt endpoint and sample routing were added as Phase 7.

* ~~Two-key (`jkt-jwt`) refresh: the SDK only implements single-key (`hwk`) refresh today; renaming is orthogonal to that work.~~ → **Done in Phase 6.**
* AP-side identifier policy in the MockAgentProvider (it already does the correct thumbprint-based lookup at refresh).

---

## Spec Reference Excerpts (for review validation)

### From `draft-hardt-aauth-bootstrap.md` — § Refresh Patterns

> Agent token lifetime is the AP's policy re-evaluation cadence — every refresh is the AP's chance to re-check device posture, attestation freshness, and account status before issuing a new token.

> **Single-Key Refresh:** APs that opt for the single-durable pattern sign the refresh request directly with the durable key under the `hwk` scheme. **The AP verifies the signature, looks up the enrollment by the key's thumbprint**, and issues a fresh agent token with a new `exp`. The same `cnf.jwk` is carried through; the agent's key is unchanged.

> **Two-Key Refresh:** The agent constructs a JWT signed by the **durable key**, naming the new ephemeral public key. [...] The AP verifies the durable-key signature on the naming JWT, **looks up the enrollment by the durable key's thumbprint**, verifies the HTTP signature against the ephemeral public key [...]

### From `draft-hardt-aauth-bootstrap.md` — § Agent Identifier Strategies

> APs are free to choose any opaque scheme for the local part: a random string assigned at enrollment, **a deterministic derivation from the durable key's thumbprint**, a sequential identifier, or a human-readable handle. When deriving from a thumbprint, use the durable key's thumbprint — the ephemeral key rotates on each refresh and is not a stable identifier. **Receivers treat the identifier as opaque.**

### From `draft-hardt-aauth-bootstrap.md` — § Self-Hosted Agents

> A self-hosted agent runs under a domain the user controls. [...] Self-hosted agents act as their own AP — they self-issue agent tokens signed by the JWKS-published key. There is no separate AP to refresh against, so the two-key pattern does not apply: the JWKS-published key serves both as the AP signing key (signing self-issued agent tokens) and as the key whose public part appears in `agent_token.cnf.jwk` (signing HTTP messages).

### From `draft-hardt-oauth-aauth-protocol.md` — § Agent Provider Metadata

> `jwks_uri` (REQUIRED): URL to the agent provider's JSON Web Key Set

### From `draft-hardt-aauth-bootstrap.md` — § Example Agent Token Claims

> JWT header: `{ "alg": "EdDSA", "typ": "aa-agent+jwt", "kid": "..." }`
>
> The `kid` in the JWT header is chosen by the AP. It is the AP's internal reference for key selection within its published JWKS. **Receivers use it to select the verification key from the AP's `jwks_uri`** — they do not interpret its content.

---

## Critical Review Findings (PR analysis)

> **Note:** PR #22 review comments from `copilot-pull-request-reviewer` independently flagged findings 1–4 below, confirming these are real issues rather than false positives.

### Finding 1: `jwks_uri` mode `kid` parameter inconsistency (BUG — flagged in PR review)

The `AgentConsole/Program.cs` correctly uses:
```csharp
builder.UseJwksUri(jwksUrl, agentTokenKid ?? keyId);
```

But `SampleApp/Components/Pages/JwksUri.razor` (line ~148) and `GuidedTour/CodeSnippets.cs` (line 63) pass:
```csharp
.UseJwksUri(jwksUri, result.LocalKeyHandle)   // GuidedTour
.UseJwksUri(jwksUri, keyId)                   // JwksUri.razor (keyId = _enrollment.LocalKeyHandle)
```

**Problem:** In `jwks_uri` mode the receiver fetches the JWKS and selects the key by `kid`. The AP publishes the JWK with whatever `kid` it chose (the value in `AgentTokenKid`). The `LocalKeyHandle` defaults to the JWK thumbprint — which may not match the AP's published `kid`. These samples will fail JWKS key lookup unless the AP happens to use the thumbprint as its `kid`.

**PR reviewer comment:** "UseJwksUri expects the kid of the key inside the JWKS, not the local keystore handle. With the existing MockAgentProvider, the per-agent JWKS publishes record.KeyId from the enrollment response as kid, while LocalKeyHandle now defaults to the JWK thumbprint, so this sample will emit a kid that the verifier cannot resolve."

**Fix needed:** `JwksUri.razor` and `GuidedTour/CodeSnippets.cs` should use `AgentTokenKid ?? LocalKeyHandle`, matching the AgentConsole pattern.

### Finding 2: `Jwt.razor` HTML code block still shows old `keyId` variable

The `<pre><code>` illustrative snippet in `Jwt.razor` (line ~38) shows:
```csharp
return await ap.RefreshAsync(refreshEndpoint, keyId, ct);
```

Should be `localKeyHandle` for consistency with the rename. This is display-only HTML (not compiled) but readers will copy-paste it.

### Finding 3: `GuidedTour/CodeSnippets.cs` — lines 73, 112, 214, 216 still use `keyId` (flagged in PR review)

The `SignedGetJwt`, `TokenExchangeDirect`, and `FullAutomatic` snippets still reference `keyId` in:
```csharp
AgentProviderTokenRefresher.Create(refreshEndpoint, keyId)
var key = await keyStore.LoadAsync(keyId);
```

These are illustrative string constants, but they should use `localKeyHandle` for consistency. The plan said to update CodeSnippets.cs but only partially addressed it.

**PR reviewer comment:** "This snippet is only partially renamed: it tells users to persist enrol.LocalKeyHandle, but the startup section below still loads keyId and passes keyId to AgentProviderTokenRefresher.Create. As written, users copying the example have no declared variable matching the persisted handle; update the startup snippet/comment to use localKeyHandle consistently."

### Finding 4: `AgentConsole/Program.cs` — variable still named `keyId` (flagged in PR review)

After the PR, `AgentConsole/Program.cs` still declares `string keyId` and assigns `result.LocalKeyHandle` to it. The variable name `keyId` reintroduces the confusion this PR is eliminating. Should be `localKeyHandle` or `keyHandle`.

**PR reviewer comment:** "keyId is also used as the kid for UseJwksUri later in this file, but LocalKeyHandle is only a local keystore handle and no longer necessarily matches the key id published in the AP's per-agent JWKS."

Note: The final commit (e7783fe) partially addressed this by using `agentTokenKid ?? keyId` for the `UseJwksUri` call, but the variable name itself is still confusing.

### Finding 5: `EnrollResult.AgentTokenKid` naming/documentation is misleading (flagged in PR review)

**PR reviewer comment:** "The in-repo MockAgentProvider does not use enrollment key_id as the issued agent token's JWT kid: the token header kid is the AP signing key id, while the response key_id is published as the per-agent JWKS key id. Documenting this value as an agent-token kid and diagnostic-only leaves AP-enrolled callers without a correctly named value to pass to UseJwksUri alongside JwksUri."

**Problem:** The `AgentTokenKid` property is described as "diagnostic only" but it's actually **required** for `jwks_uri` mode to work. The property should be named something like `JwksKid` or `ApPublishedKid` and documented as the key identifier needed for `UseJwksUri`. Calling it "diagnostic-only" invites callers to ignore it, causing the bug in Finding 1.

### Finding 6: Implementation plan lacks Definition of Done checklists (flagged in PR review)

**PR reviewer comment:** "This implementation plan defines phases but does not include Definition of Done checklists at the end of each phase. The repository planning workflow requires each phase in .agent/plans/*/implementation-plan.md to end with - [ ] / - [x] DoD checkboxes."

### Finding 7: `docs/signing-modes/agent-identity-jwks-uri.md` not updated

The plan lists this file's sibling `agent-token-jwt.md` in the touch-up list but **does not mention** `agent-identity-jwks-uri.md`. That file shows:
```csharp
.UseJwksUri("https://ap.example/agents/aauth:myapp@ap.example/jwks.json", "my-key-1")
```

This is fine as an illustrative example, but there's no clarifying comment explaining that `"my-key-1"` is the AP-published `kid` (`AgentTokenKid`), not the local key handle. Given the PR's goal of eliminating identifier confusion, this doc should add a one-line comment.

### Finding 8: `docs/advanced/key-management.md` not updated

This doc defines the `IKeyStore` interface and shows usage like:
```csharp
await keyStore.StoreAsync("my-agent-key", AAuthKey.Generate());
var key = await keyStore.LoadAsync("my-agent-key");
```

It has no mention of what the `keyId` parameter represents semantically in the enrollment flow. Given the PR's clarification goal, this doc should include a note that for AP-enrolled agents the `keyId` passed to `IKeyStore` is the `LocalKeyHandle` (JWK thumbprint by default) — not an AP-assigned identifier.

### Finding 9: `docs/signing-modes/overview.md` uses generic `kid` without explanation

Line 35 shows:
```csharp
"jwks_uri" => new AAuthClientBuilder(key).UseJwksUri(jwksUri, kid).Build(),
```

No clarification that `kid` here is the AP-published JWT `kid` (for AP-enrolled agents) or a developer-chosen `kid` (for self-hosted). After this PR, this is a source of the same confusion the PR aims to eliminate.

### Finding 10: No `appsettings.json` examples updated

The plan references `AAuth:KeyId` → `AAuth:LocalKeyHandle` config key change, but no actual `appsettings.json` files in the samples directory were updated. Quick check:

```
samples/AgentConsole/ — no appsettings.json (uses cache file — OK)
samples/SampleApp/appsettings.json — may contain AAuth section
```

### Finding 11: Research claims "collapse the two `RefreshAsync` overloads" but the implementation is clean

The research noted the `currentAgentToken` parameter was unused. The implementation correctly removed it and collapsed to one overload. This is **good** — spec-aligned because the spec says the request body is empty and identification is by signature alone.

---

## jkt-jwt Spec Classification and Resource Access Model

> **Update (2026-05-27):** Discovered during Phase 7 (WhoAmI endpoint + sample routing fixes) that the jkt-jwt signing mode was being incorrectly treated as three-party by the samples.

### Key Finding: jkt-jwt is pseudonymous, not three-party

Source: `aauth-spec/draft-hardt-oauth-aauth-protocol.md`, line 2076:

> "For pseudonym: the agent uses scheme=hwk (inline public key) or scheme=jkt-jwt (delegation from a hardware-backed key)."

**jkt-jwt and hwk belong to the same category**: pseudonymous keying material schemes. They are **2-party** at resource access time — the resource verifies the HTTP signature directly without contacting the AP.

| Scheme | Category | Parties at resource access | AP role |
|--------|----------|---------------------------|---------|
| `jwt` | Three-party | Agent ↔ AP ↔ Resource | AP issues agent token; resource verifies via AP JWKS |
| `jwks_uri` | Identity-based | Agent ↔ Resource (AP publishes JWKS) | AP publishes per-agent JWKS; resource fetches it |
| `hwk` | Pseudonymous | Agent ↔ Resource (2-party) | None at resource access time |
| `jkt-jwt` | Pseudonymous | Agent ↔ Resource (2-party) | None at resource access time |

### How jkt-jwt resource access works (2-party)

1. Agent generates an ephemeral key pair.
2. Agent signs a naming JWT with the durable key, embedding the ephemeral public key as `cnf.jwk`.
3. Agent signs the HTTP request with the ephemeral key.
4. Agent attaches `Signature-Key: sig=jkt-jwt;jkt="<ephemeral-thumbprint>";jwt="<naming-jwt>"` to the request.
5. Resource verifies the HTTP signature against the ephemeral key (extracted from `cnf.jwk` in the naming JWT). No AP contact needed.
6. Resource identifies the agent by the durable key's JWK thumbprint (from the naming JWT's `kid` header).

### How jkt-jwt differs from hwk

- **hwk**: single key signs HTTP requests; resource identifies agent by that key's thumbprint.
- **jkt-jwt**: two keys — durable key (long-lived, hardware-backed) delegates to ephemeral key (short-lived). Resource still identifies agent by the durable key's thumbprint, but the actual HTTP signature is made by the ephemeral key. This allows hardware keys that can't do per-request signing to delegate to a software ephemeral key.

### Where AP *is* involved for jkt-jwt

The AP is involved only during **enrollment and refresh** (bootstrap phase), not during resource access:
- **Enrollment**: Agent enrols its durable public key with the AP (same as all modes).
- **Two-key refresh**: Agent signs the refresh request with the ephemeral key under `jkt-jwt` scheme. AP verifies the naming JWT signature against the enrolled durable key, then issues a fresh agent token.

### Why this matters for WhoAmI routing

The original WhoAmI `GET /` endpoint used `AAuthVerificationMiddleware` which performs **issuer verification** — it contacts the AP to verify the agent token. This is correct for `jwt` mode (three-party) but wrong for `jkt-jwt`:
- jkt-jwt has no agent token at resource access time.
- The `Signature-Key` header contains `typ=naming+jwt` (not `aa-agent+jwt`), which the issuer-verifying middleware rejects.

**Solution**: Dedicated `/jkt-jwt` endpoint with `RequireIssuerVerification = false` — same pattern as the existing `/hwk` endpoint for pseudonymous access.

### AgentConsole `--ps` validation was wrong

The original code (prior to fix):
```csharp
if (personServer is null && signingMode is "jwt" or "jkt-jwt")
{
    Console.Error.WriteLine("Agent Token mode (jwt/jkt-jwt) requires a Person Server (--ps).");
}
```

This incorrectly grouped `jkt-jwt` with `jwt` as requiring a Person Server. Per the spec, jkt-jwt is pseudonymous — it doesn't need PS for resource access. The PS is only needed for three-party `jwt` mode where the AP delegates consent decisions to the Person Server.

**Fix**: Only `jwt` mode requires `--ps`. The `jkt-jwt` mode works without PS (same as `hwk`).

---

## SDK Improvement Opportunities (beyond this PR)

### 1. `UseJwksUri` should accept `AgentTokenKid` directly from `EnrollResult`

The pattern `UseJwksUri(result.JwksUri, result.AgentTokenKid ?? result.LocalKeyHandle)` is error-prone — every sample gets it wrong differently. A better API would be:

```csharp
// Proposed: accept EnrollResult directly
builder.UseJwksUri(result);
// Or: UseJwksUri with smart defaulting
builder.UseJwksUri(result.JwksUri, result.AgentTokenKid);
```

### 2. `IKeyStore` parameter name is `keyId` — should be `handle` or `name`

The `IKeyStore` interface uses `string keyId` as the parameter name. After this rename PR, the semantic is clearly "a local handle/name" — but the interface parameter still says `keyId`, which perpetuates the old confusion. Renaming the interface parameter to `handle` or `name` would complete the cleanup.

### 3. No convenience `EnrollResult.BuildClient()` method

Every sample after enrollment manually extracts fields and wires them together:
```csharp
var key = result.Key;
var keyId = result.LocalKeyHandle;
builder.UseJwksUri(result.JwksUri, result.AgentTokenKid ?? keyId);
```

A fluent `result.BuildClient()` or `AAuthClientBuilder.From(result)` would eliminate this boilerplate and prevent kid/handle confusion.

### 4. `AgentConsole` still names variable `keyId` (confusing)

After the PR, `AgentConsole/Program.cs` still declares `string keyId` and assigns `result.LocalKeyHandle` to it. The variable name `keyId` reintroduces the confusion this PR is eliminating. Should be `localKeyHandle` or `keyHandle`.

---

## Missing Items from the Plan (focused on docs and samples)

| # | Missing Item | Category | Impact | PR Review Flagged? |
|---|---|---|---|---|
| 1 | `samples/SampleApp/Components/Pages/JwksUri.razor` — `kid` parameter should use `AgentTokenKid ?? LocalKeyHandle` | Sample Bug | Runtime failure when AP `kid` ≠ thumbprint | Yes |
| 2 | `samples/GuidedTour/CodeSnippets.cs` — `SignedGetJwksUri` passes `result.LocalKeyHandle` as kid | Sample Bug | Same as above | Yes |
| 3 | `samples/GuidedTour/CodeSnippets.cs` — `SignedGetJwt`, `TokenExchangeDirect`, `FullAutomatic` still use `keyId` variable | Sample Inconsistency | Copy-paste confusion | Yes |
| 4 | `samples/SampleApp/Components/Pages/Jwt.razor` — HTML code block shows `keyId` in RefreshAsync | Doc Inconsistency | Reader confusion | — |
| 5 | `EnrollResult.AgentTokenKid` — documented as "diagnostic only" but required for `jwks_uri` mode | API Design Flaw | Callers ignore it, then `jwks_uri` breaks | Yes |
| 6 | `samples/AgentConsole/Program.cs` — variable still named `keyId` | Naming Inconsistency | Contradicts the PR's intent | Yes |
| 7 | Implementation plan missing DoD checklists per phase | Process Gap | Doesn't follow repo planning workflow | Yes |
| 8 | `docs/advanced/key-management.md` — no mention of the enrollment-handle semantic | Doc Gap | Missing context about what the `keyId` param is in enrollment context | — |
| 9 | `docs/signing-modes/agent-identity-jwks-uri.md` — no comment clarifying `kid` is AP-published | Doc Gap | Perpetuates kid/handle confusion for jwks_uri mode | — |
| 10 | `docs/signing-modes/overview.md` — `kid` variable in code block unexplained | Doc Gap | Same confusion | — |
| 11 | Top-level `README.md` — not swept for enrollment snippets (plan said to sweep) | Doc Gap | Possibly stale | — |
