# Upcoming Changes in draft-hardt-oauth-aauth-protocol-02

Confirmed by spec lead (2026-05-30). Tracked here until the -02 draft is published.

## Index

| # | Change | Extends | Status |
|---|--------|---------|--------|
| 1 | Add `capabilities` as standard token endpoint parameter | §7.1.3 Agent Token Request (L830) | Pending -02 |
| 2 | Add `user_unreachable` to error table as terminal error | §Error Responses (L2006) | Pending -02 |
| 3 | Add `prompt` as standard token endpoint parameter | §7.1.3 Agent Token Request (L830) | Pending -02 |

---

## 1. `capabilities` as token endpoint body parameter

**Extends:** §7.1.3 Agent Token Request (`#ps-token-endpoint`, line 830)

**Current spec:** Token endpoint params are `resource_token`, `upstream_token`, `justification`, `login_hint`, `tenant`, `domain_hint`, `platform`, `device`. The `AAuth-Capabilities` header (§AAuth-Capabilities, L1756) is explicitly excluded from PS endpoints.

**Change:** Add `capabilities` (OPTIONAL) to the token endpoint request body. Array of strings. Values from the AAuth Capabilities registry (`interaction`, `clarification`, `payment`).

**Clarification:**
- `capabilities` in the body is the correct mechanism for mission-less agents.
- When a mission is active, the PS already has capabilities from the approval flow - the agent doesn't need to resend them but MAY include them if they've changed.
- The `AAuth-Capabilities` header remains resource-only. No conflict - headers are used where there's a pre-existing API; body is the right place for the PS token endpoint.

**SDK impact:** Current fix (sending `capabilities` in POST body) is correct and will be spec-standard.

---

## 2. `user_unreachable` as terminal error

**Extends:** §Token Endpoint Error Codes (`#error-response-format`, line 2006)

**Current spec:** Error table has `interaction_required` (403) defined as "User interaction is needed but no interaction channel is available."

**Change:** Add `user_unreachable` as a distinct terminal error. Clarify the difference:

| Error | Status | Type | Meaning |
|-------|--------|------|---------|
| `interaction_required` | 202 | Non-terminal | PS needs the agent to direct the user somewhere (URL + code). Polling continues. |
| `user_unreachable` | 400 | Terminal | PS has no channel to the user AND the agent didn't declare `interaction` capability. No way to reach the user. |

**Clarification:** These are two distinct conditions, not aliases. `interaction_required` comes with a deferred response (202) and an interaction URL. `user_unreachable` is a hard stop - nothing can be done without the agent declaring capabilities.

**SDK impact:** Error classification (Gap E) should treat `user_unreachable` as a terminal, non-retryable error distinct from `interaction_required`.

---

## 3. `prompt` as token endpoint body parameter

**Extends:** §7.1.3 Agent Token Request (`#ps-token-endpoint`, line 830)

**Current spec:** No `prompt` parameter listed.

**Change:** Add `prompt` (OPTIONAL) to the token endpoint request body. Values follow OIDC (per OpenID Core §3.1.2.1):

| Value | Meaning |
|-------|---------|
| `none` | No UI. Return error if consent/login is needed. |
| `login` | Force re-authentication. |
| `consent` | Force consent screen even if prior consent exists. |
| `select_account` | Prompt user to select an account. |

**Not included:** `provider_hint` remains a Hellospecific extension. It steers between consumer providers (email, Google, etc.) and doesn't generalize.

**SDK impact:** Should support `prompt` as a first-class option on the token exchange builder. `provider_hint` can go through the extensibility hook for PS-specific params.
