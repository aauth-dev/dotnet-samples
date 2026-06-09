# AAuth Specification Changelog



High-fidelity record of what changed between the vendored AAuth specification
snapshots in this repository. Each snapshot is a self-contained folder; see
[`SPEC-VERSION.md`](SPEC-VERSION.md) for source commits and metadata.

Entries are grouped by snapshot folder, so every document in a release (protocol,
R3, bootstrap) is listed together and a change to R3 or bootstrap travels with the
protocol version it shipped in.

Section and line references point into the **draft-02** files under
[`v02/`](v02/) as vendored (commit `feda56b`). Anchors in parentheses (e.g.
`#sub-agents`) are the spec's own kramdown anchors and are stable across line
shifts.

| Snapshot | Protocol | Bootstrap | R3 | Source commit |
|---|---|---|---|---|
| [`v01/`](v01/) | draft-01 | draft-01 | draft-00 | `c090879` (2026-05-11) |
| [`v02/`](v02/) | draft-02 | draft-01 (unchanged) | draft-00 (revised) | `feda56b` (2026-06-09) |

## Contents

- [`v02/` — AAuth draft-02 snapshot](#v02--aauth-draft-02-snapshot)
  - [Protocol (draft-02)](#protocol-draft-02)
    - [1. Sub-agents (new)](#1-sub-agents-new)
    - [2. Drop-in adoption path (new)](#2-drop-in-adoption-path-new)
    - [3. Tighter interaction handling](#3-tighter-interaction-handling)
    - [4. PS token-endpoint parameters (new)](#4-ps-token-endpoint-parameters-new)
    - [5. Clarifications and hardening](#5-clarifications-and-hardening)
    - [6. Editorial](#6-editorial)
  - [R3 (draft-00, revised)](#r3-draft-00-revised)
  - [Bootstrap (draft-01, unchanged)](#bootstrap-draft-01-unchanged)
  - [Author's verbatim changelog (protocol)](#authors-verbatim-changelog-protocol)
- [`v01/` — AAuth draft-01 snapshot (baseline)](#v01--aauth-draft-01-snapshot-baseline)

---

## `v02/` — AAuth draft-02 snapshot

The release that bundles protocol **draft-02** with the revised R3 (**draft-00**)
and the unchanged bootstrap (**draft-01**). Everything in this folder is listed
together so an R3 or bootstrap change travels with the protocol version it shipped
in.

### Protocol (draft-02)

Published as IETF
[draft-hardt-oauth-aauth-protocol-02](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/02/).
Grouped below by theme. New wire identifiers and their first-introduction counts
(v01 → v02) are noted to make the surface area auditable.

#### 1. Sub-agents (new)

An orchestrating agent can spawn short-lived workers under a single user consent,
while each sub-agent stays individually identifiable for audit and revocation.

- New top-level section `# Sub-Agents` (`#sub-agents`, v02 line 1728) with
  subsections Sub-Agent Identity (1732), Single-Level Depth (1752),
  Parent-Mediated Authorization (1761), and Delegation Chain Examples
  (`#delegation-chain-examples`, 1776).
- New agent-token claim **`parent_agent`** (0 → 18 occurrences) — marks an agent
  as a sub-agent and names its parent; registered in the JWT Claims registry.
- New PS/AS token-endpoint body parameter **`subagent_token`** (0 → 13) — the
  parent obtains auth tokens on the sub-agent's behalf. A sub-agent MUST NOT call
  the PS directly.
- **Single-level depth** rule: a sub-agent MUST NOT have sub-agents of its own.
- **`+`** reserved as the sub-agent local-part delimiter
  (e.g. `aauth:planner.7f3c+search1@vendor.example`); parties rely on
  `parent_agent`, not local-part parsing, for protocol decisions.
- Auth-token `act` claim nests to record the full delegation chain (agent →
  parent → … ), shown in Delegation Chain Examples.

#### 2. Drop-in adoption path (new)

Identity-based access replaces API keys; resource-managed access wraps an
existing OAuth/consent flow. Discovery lets an agent go from hostname to a
working API call.

- New resource-metadata field **`access_mode`** (0 → 10): one of `agent-token`,
  `aauth-access-token`, or `auth-token`, letting an agent plan its first call
  without a speculative challenge. Advisory — runtime `AAuth-Requirement` remains
  authoritative.
- New section `## Drop-In Replacement for API Keys and OAuth`
  (`#drop-in-migration`, v02 line 2481).
- New walkthrough `### Consuming a Resource End to End` (`#consuming-a-resource`,
  2490).
- New section `## Agent Token Required` (`#requirement-agent-token`, 732) adding
  **`requirement=agent-token`** (401) (0 → 5) — distinct from
  `requirement=auth-token`; asks for the agent's own identity token with no PS/AS
  involved.
- `jwks_uri` relaxed in resource metadata: REQUIRED only when the resource issues
  resource tokens or makes signed calls (an identity-only resource MAY omit it).
- Bootstrapping guidance: resources SHOULD publish `access_mode` and an R3
  vocabulary.

#### 3. Tighter interaction handling

PS-relayed user interactions, clearer terminal vs. non-terminal errors, and a
fully specified interaction-code format.

- Terminal error renamed: `interaction_required` → **`user_unreachable`**
  (0 → 6). Published draft-02 error table lists it as **403**
  (`#token-endpoint-error-codes`, v02 line 2194).
  > Note: the earlier planning note [`v01/upcoming-changes-02.md`](v01/upcoming-changes-02.md)
  > §2 proposed status **400** for this error. The published draft uses **403**.
  > The SDK's forward-looking `TokenErrorCode.UserUnreachable` was modeled at 400
  > and should be reconciled to 403 during the draft-02 migration.
- New non-terminal error **`interaction_unavailable`** (424) (0 → 6) — the PS
  declining to relay a *specific* interaction; the agent falls back to directing
  the user itself. Defined in new section `### Interaction Endpoint Errors`
  (`#interaction-endpoint-errors`, 1265; table row at 1271).
- **PS-first interaction relay**: new `#### Relaying Through the Person Server`
  (`#interaction-relay`, 2022) — the agent SHOULD relay to the PS's interaction
  endpoint before directing the user itself.
- New interaction parameter **`max_wait`** (0 → 4) bounding how long the PS holds
  a relay's deferred response; clarified completion polling for resource-hosted
  interactions (`status: "interacting"`).
- New `#### Interaction Code Format` (`#interaction-code-format`, 2004):
  **Crockford base32** alphabet (0 → 8) omitting `I L O U`, **≥40 bits** of
  entropy, presentational hyphens stripped before **case-insensitive** compare,
  **single-use**, **mandatory rate-limiting**, and expiry bound to the pending
  interaction — documented as the brute-force defense in Interaction Code
  Misdirection.

#### 4. PS token-endpoint parameters (new)

- **`prompt`** (OPTIONAL) — OIDC values `none` / `login` / `consent` /
  `select_account`, per OpenID Core §3.1.2.1 (v02 line 886). (v01 had no `prompt`
  parameter.)
- **`capabilities`** (OPTIONAL) — array of capability values; the request-body
  equivalent of the `AAuth-Capabilities` header, which is not used on PS
  endpoints (v02 line 889). Without a mission, this is how the PS learns the
  agent's capabilities.

#### 5. Clarifications and hardening

- **Mission reference**: the `{approver, s256}` pair is now a named concept
  (0 → 6 "mission reference"), used consistently for the `mission` claim in
  resource and auth tokens — distinct from the full mission blob.
- **Metadata host-binding**: a fetched metadata document's `issuer` MUST match
  the URL it was retrieved from (prevents host-poisoned metadata).
- **Optional Markdown `description`** field added to every well-known metadata
  document (agent, person, access, resource).
- **Call chaining**: clarified the intermediary signs with its *own* key and that
  `upstream_token` is a body parameter (neither presented via `Signature-Key` nor
  used as the signing key).
- **HTTP Message Signatures**: added rationale for the mandated covered
  components (`@method`, `@authority`, `@path`, `signature-key`).
- **Security**: new `## Non-Repudiation and Audit After Key Rotation`
  (v02 line 2617); clarified the agent token is AAuth's minimum credential
  (identity Signature-Key schemes only — pseudonym `hwk`/`jkt-jwt` are not an
  AAuth access mode).
- **`WWW-Authenticate`**: AAuth never conveys its own requirements via
  `WWW-Authenticate`, leaving a resource's existing challenges available alongside
  `AAuth-Requirement`.

#### 6. Editorial

- Removed the empty "Clarification Flow" subsection.
- Renamed "Why Four Adoption Modes" → "Why Four Resource Access Modes".
- Diagrams use snake_case `agent_token` / `auth_token`.
- Resource-access challenge sections ordered weakest-to-strongest; distinct
  anchors added to appendix flow diagrams (`#flow-call-chaining`,
  `#flow-interaction-chaining`).

### R3 (draft-00, revised)

The R3 (Rich Resource Requests) draft kept its `-00` version value but its
content was revised between snapshots. Section-level changes (v01 → v02):

- New `## Operations Spanning Multiple Definitions`
  (`#operations-spanning-definitions`).
- New top-level section `# Per-Call Proposals` (`#per-call-proposals`) with
  subsections Proposal Document, Flow, and Large and Sensitive Payloads.
- Explicit anchors added to `# R3 Document` (`#r3-document`) and
  `## Content Addressing` (`#content-addressing`).

### Bootstrap (draft-01, unchanged)

Byte-identical between the `v01/` and `v02/` snapshots. Retained in both folders
so each is self-contained.

### Author's verbatim changelog (protocol)

Reproduced from the Document History section of
[`v02/draft-hardt-oauth-aauth-protocol.md`](v02/draft-hardt-oauth-aauth-protocol.md):

> **draft-hardt-oauth-aauth-protocol-02**
>
> - Added sub-agents: agent token `parent_agent` claim, single-level depth,
>   parent-mediated authorization with a `subagent_token` parameter, and the `+`
>   sub-agent local-part delimiter; registered `parent_agent` in the JWT Claims
>   registry.
> - Renamed the terminal `interaction_required` error to `user_unreachable`;
>   added `interaction_unavailable` (424) and PS-first interaction relay;
>   clarified completion polling for resource-hosted interactions; added the
>   `max_wait` interaction parameter.
> - Added `capabilities` and OIDC `prompt` request parameters to the PS token
>   endpoint.
> - Added `requirement=agent-token` (`401`); ordered the resource-access
>   challenge sections weakest-to-strongest.
> - Added an `access_mode` resource-metadata field, a "Drop-In Replacement for
>   API Keys and OAuth" section, and a "Consuming a Resource End to End"
>   walkthrough; relaxed `jwks_uri` to be required only when the resource issues
>   resource tokens or makes signed calls.
> - Added an OPTIONAL Markdown `description` field to each well-known metadata
>   document.
> - Metadata: require the returned `issuer` to match the URL it was fetched from.
> - Call chaining: clarified that the intermediary signs with its own key and
>   `upstream_token` is a body parameter.
> - Added rationale for the mandated covered components in the HTTP Message
>   Signatures profile.
> - Added a Security Consideration on non-repudiation after key rotation;
>   clarified that the agent token is AAuth's minimum credential (identity
>   Signature-Key schemes only; pseudonym `hwk`/`jkt-jwt` not an AAuth mode).
> - Bootstrapping: pointer to the AAuth Bootstrap document; resources SHOULD
>   publish `access_mode` and an R3 vocabulary.
> - Diagrams: use snake_case `agent_token` and `auth_token`.
> - Named the `{approver, s256}` pair the "mission reference" and used it
>   consistently for the `mission` claim in resource and auth tokens, distinct
>   from the full mission blob.
> - Stated that AAuth never conveys its own requirements via `WWW-Authenticate`,
>   leaving a resource's existing challenges available alongside
>   `AAuth-Requirement`.
> - Specified the interaction `code` format: Crockford base32 alphabet, ≥40 bits
>   of entropy, presentational hyphens stripped before case-insensitive
>   comparison, single use, mandatory rate-limiting, and expiry bound to the
>   pending interaction; documented the entropy/rate-limit rules as the
>   brute-force defense in Interaction Code Misdirection and made the four `code`
>   examples consistently hyphenated.
> - Editorial consistency pass: trimmed redundant mode walkthroughs, removed the
>   empty "Clarification Flow" subsection, and added distinct anchors to the
>   appendix flow diagrams.

---

## `v01/` — AAuth draft-01 snapshot (baseline)

The baseline the `v02/` entries are measured against: protocol **draft-01**,
bootstrap **draft-01**, R3 **draft-00**. Pinned to source commit `c090879`
(2026-05-11); see [`SPEC-VERSION.md`](SPEC-VERSION.md).

This folder also retains [`upcoming-changes-02.md`](v01/upcoming-changes-02.md) —
the planning notes that tracked the confirmed draft-02 deltas before the -02 draft
was published, now superseded by the `v02/` snapshot above.
