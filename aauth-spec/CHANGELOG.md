# AAuth Specification Changelog



High-fidelity record of what changed between the vendored AAuth specification
snapshots in this repository. Each snapshot is a self-contained folder; see
[`SPEC-VERSION.md`](SPEC-VERSION.md) for source commits and metadata.

Entries are grouped by snapshot folder, so every document in a release (protocol,
R3, bootstrap) is listed together and a change to R3 or bootstrap travels with the
protocol version it shipped in.

Section and line references in the **`v02/`** entry point into the draft-02 files
under [`v02/`](v02/) (commit `feda56b`); references in the **`v08/`** entry point
into the draft-08 files under [`v08/`](v08/) (commit `dd2b852`). Anchors in
parentheses (e.g. `#sub-agents`) are the spec's own kramdown anchors and are stable
across line shifts.

| Snapshot | Protocol | Bootstrap | R3 | Source commit |
|---|---|---|---|---|
| [`v01/`](v01/) | draft-01 | draft-01 | draft-00 | `c090879` (2026-05-11) |
| [`v02/`](v02/) | draft-02 | draft-01 (unchanged) | draft-00 (revised) | `feda56b` (2026-06-09) |
| [`v08/`](v08/) | draft-08 | draft-01 (unchanged) | draft-00 (unchanged) | `dd2b852` (2026-06-25) |

> **The SDK code targets `v02/` (draft-02).** The `v08/` snapshot was vendored
> 2026-06-25 as the latest upstream reference; migrating the SDK to draft-08 is
> tracked separately and has not started. See
> [`SPEC-VERSION.md`](SPEC-VERSION.md).

## Contents

- [`v08/` — AAuth draft-08 snapshot](#v08--aauth-draft-08-snapshot)
  - [Protocol (drafts 03–08)](#protocol-drafts-0308)
    - [1. Agent-delegation restructure](#1-agent-delegation-restructure)
    - [2. Auth-token `act` semantics (drafts 04–05)](#2-auth-token-act-semantics-drafts-0405)
    - [3. Call chaining and routing (draft-08)](#3-call-chaining-and-routing-draft-08)
    - [4. Interactions (drafts 03, 07–08)](#4-interactions-drafts-03-0708)
    - [5. Metadata (draft-03)](#5-metadata-draft-03)
    - [6. PS approval auth and implementation clarity (draft-06)](#6-ps-approval-auth-and-implementation-clarity-draft-06)
  - [R3 and Bootstrap (unchanged)](#r3-and-bootstrap-unchanged)
  - [Interoperability Demo Profile (new)](#interoperability-demo-profile-new)
  - [HTTP Signature Keys (draft-05)](#http-signature-keys-draft-05)
  - [Author's verbatim changelog (drafts 03–08)](#authors-verbatim-changelog-drafts-0308)
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

## `v08/` — AAuth draft-08 snapshot

The latest upstream snapshot, vendored 2026-06-25 for reference. It bundles
protocol **draft-08** with the unchanged R3 (**draft-00**) and bootstrap
(**draft-01**), adds the new informational **Interoperability Demo Profile**, and
bumps the HTTP Signature Keys draft to **draft-05**.

> **The SDK now targets draft-08** (migrated 2026-06-25). The entries below measure
> draft-08 against the prior **draft-02** baseline ([`v02/`](v02/)) — they double as
> the migration's change catalogue. The `AAuth-Access` opaque-token flow
> (resource-managed access) is implemented (see
> `.agent/plans/2026-06-25-aauth-access-token-flow/`).

### Protocol (drafts 03–08)

Published as IETF
[draft-hardt-oauth-aauth-protocol-08](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/08/)
(commit `dd2b852`, document date 2026-06-17). draft-08 is the cumulative result of
six published drafts (03 → 08). Grouped below by theme; the author's verbatim
per-draft changelog is reproduced at the end. Anchors in parentheses are the
spec's own kramdown anchors.

#### 1. Agent-delegation restructure

The multi-hop and sub-agent material was reorganized under a single umbrella, and
the sub-agent subsections were consolidated.

- New top-level section `# Agent Delegation` (`#agent-delegation`) now contains
  `## Multi-Hop Resource Access` (`#multi-hop`) and `## Sub-Agents`
  (`#sub-agents`), both previously top-level sections in draft-02.
- The draft-02 sub-agent subsections (Sub-Agent Identity, Single-Level Depth,
  Parent-Mediated Authorization, Delegation Chain Examples) collapsed into a
  single `## Delegation Chain` (`#delegation-chain`).
- New `## PS Approval Endpoint Authentication` (`#ps-approval-endpoint-auth`).

#### 2. Auth-token `act` semantics (drafts 04–05)

The delegation-chain claim was reworked so the `act` chain identifies agents, not
subjects, and is omitted when there is no delegation.

- `act.sub` replaced by **`act.agent`** within each `act` node
  ([issue #47](https://github.com/dickhardt/AAuth/issues/47)).
- `act` is now **OPTIONAL** — absent in direct authorization. `act.agent`
  identifies the immediate upstream agent (the delegator, not the presenter);
  nesting records the full chain. Verification steps, sub-agent issuance, PS
  upstream-token construction, and the delegation-chain examples were updated to
  match.

#### 3. Call chaining and routing (draft-08)

Call-chaining gained explicit token-binding and routing rules.

- Upstream token **`aud` MUST equal the `iss`** of the intermediary's agent token.
- PS-vs-AS routing is derived from the **upstream auth token**
  (`mission.approver` or `iss`), not the calling agent's `ps` claim.
- A PS **MUST require a mission** to remain in the loop for four-party upstream
  chains.

#### 4. Interactions (drafts 03, 07–08)

- New `## Interaction Callback Errors` (draft-07) defining the `?error=` redirect
  wire format — `access_denied`, `user_abandoned`, `server_error`,
  `temporarily_unavailable`, `interaction_expired` — and the PS mapping to polling
  errors. Resource-Initiated Interaction now references it and specifies PS
  behavior on error callbacks.
- **Interaction code** is now described as a **correlation identifier, not an
  authorization credential** (draft-08): the code alone MUST NOT authorize the
  decision.
- Crockford base32 citation updated to
  `[@?I-D.crockford-davis-base32-for-humans]` (draft-03).

#### 5. Metadata (draft-03)

- New **common-fields table** at the top of the Metadata Documents section
  covering all four well-known files; documented intentional RFC 9728 divergences
  (`issuer` not `resource`; unprefixed field names).
- New **`documentation_uri`** field on `aauth-agent.json`, `aauth-person.json`,
  and `aauth-access.json`.

#### 6. PS approval auth and implementation clarity (draft-06)

An implementation- and interop-driven clarity pass (feedback from Joshua Gay):

- Mission-reference dereference boundary and `approver` / `s256` syntax rules.
- Agent keying material restricted to **`scheme=jwt`**.
- `AAuth-Requirement` parameter shape and unknown-value behavior; `AAuth-Access`
  token grammar (`token68`); `AAuth-Capabilities` forward-compatibility.
- JWKS **same-`kid` refresh** and egress admission.
- Auth-token verification split into **JWT trust** vs. **request-context binding**
  with structured `cnf.jwk` failure ordering.
- New PS approval-endpoint authentication security consideration and a
  freshness/replay policy subsection.
- The Interoperability Demo Profile was **extracted** to a standalone
  non-normative document (see below).

### R3 and Bootstrap (unchanged)

Both are byte-identical to the [`v02/`](v02/) snapshot:

- **R3** stays at **draft-00** (`draft-hardt-aauth-r3.md`).
- **Bootstrap** stays at **draft-01** (`draft-hardt-aauth-bootstrap.md`) —
  byte-identical across `v01/`, `v02/`, and `v08/`.

### Interoperability Demo Profile (new)

`interop-demo-profile.md` is **new** in this snapshot — a non-normative document
extracted from the protocol spec in draft-06. It describes the minimum live
surfaces for an end-to-end interop demo: PS mission approval, `AAuth-Mission`
presentation and resource-token echo, resource-token issuance, auth-token issuance
and presentation, and parent-mediated sub-agent handling.

### HTTP Signature Keys (draft-05)

Bumped **draft-04 → draft-05** (`draft-hardt-httpbis-signature-key-05.txt`). The
Signature Keys spec is now maintained in its own repository
(<https://github.com/dickhardt/signature-key>); the protocol references its
editor's copy via `[@!I-D.hardt-httpbis-signature-key]`. draft-05 names a second
author (T. Meunier, Cloudflare) and a `Signature-Error` header for structured
error reporting.

### Author's verbatim changelog (drafts 03–08)

Reproduced from the Document History section of
[`v08/draft-hardt-oauth-aauth-protocol.md`](v08/draft-hardt-oauth-aauth-protocol.md):

> **draft-hardt-oauth-aauth-protocol-08**
>
> - Call chaining: upstream token `aud` MUST equal the `iss` of the intermediary's
>   agent token; routing to PS or AS is derived from the upstream auth token
>   (`mission.approver` or `iss`), not the calling agent's `ps` claim; PS MUST
>   require a mission to remain in the loop for four-party upstream chains.
> - Interaction code: added that the code is a correlation identifier, not an
>   authorization credential; the code alone MUST NOT authorize the decision.
>
> **draft-hardt-oauth-aauth-protocol-07**
>
> - Added `Interaction Callback Errors` section defining the `?error=` wire format
>   for callback redirects (`access_denied`, `user_abandoned`, `server_error`,
>   `temporarily_unavailable`, `interaction_expired`) and the PS mapping to polling
>   errors. Updated Resource-Initiated Interaction to reference the new section and
>   specify PS behavior on error callbacks. Added Joshua Gay to Acknowledgments.
>
> **draft-hardt-oauth-aauth-protocol-06**
>
> - Implementation and interoperability clarity driven by feedback from Joshua Gay
>   (sidecat): mission reference dereference boundary and `approver`/`s256` syntax
>   rules; agent keying material restricted to `scheme=jwt`; `AAuth-Requirement`
>   parameter shape and unknown-value behavior; `AAuth-Access` token grammar
>   (`token68`); `AAuth-Capabilities` forward-compatibility; JWKS same-`kid` refresh
>   and egress admission; auth token verification split into JWT trust and
>   request-context binding with structured `cnf.jwk` failure ordering; PS approval
>   endpoint authentication security consideration; freshness and replay policy
>   subsection. Interoperability demo profile extracted to a standalone
>   non-normative document.
>
> **draft-hardt-oauth-aauth-protocol-05**
>
> - Auth tokens: `act` is OPTIONAL, absent in direct authorization; `act.agent`
>   identifies the immediate upstream agent (the delegator), not the presenter;
>   nesting records the full chain. Updated verification steps, sub-agent issuance,
>   PS upstream token construction, and delegation chain examples accordingly.
>   Replaced the "sub-agent calls a chained resource" example with "sub-agent inside
>   a chain."
>
> **draft-hardt-oauth-aauth-protocol-04**
>
> - Auth tokens: replaced `act.sub` with `act.agent` within each `act` node; see
>   [issue #47](https://github.com/dickhardt/AAuth/issues/47).
>
> **draft-hardt-oauth-aauth-protocol-03**
>
> - Metadata: added a common-fields table at the top of the Metadata Documents
>   section covering all four well-known files; documented intentional RFC 9728
>   divergences (`issuer` not `resource`; unprefixed field names).
> - Metadata: added `documentation_uri` to `aauth-agent.json`, `aauth-person.json`,
>   and `aauth-access.json`.
> - Interaction code: updated Crockford base32 citation to
>   `[@?I-D.crockford-davis-base32-for-humans]`.

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
  > The SDK's forward-looking `TokenErrorCode.UserUnreachable` was modeled at 400;
  > it was reconciled to 403 in the draft-02 migration (Phase 1).
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
