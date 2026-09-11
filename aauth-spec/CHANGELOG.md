# AAuth Specification Changelog



High-fidelity record of what changed between the vendored AAuth specification
snapshots in this repository. Each snapshot is a self-contained folder; see
[`SPEC-VERSION.md`](SPEC-VERSION.md) for source commits and metadata.

Entries are grouped by snapshot folder, so every document in a release
(protocol, R3, bootstrap, and companion documents) is listed together and a
companion change travels with the protocol version it shipped in.

Section and line references in the **`v02/`** entry point into the draft-02 files
under [`v02/`](v02/) (commit `feda56b`); references in the **`v08/`** entry point
into the draft-08 files under [`v08/`](v08/) (commit `dd2b852`); references in the
**`v09/`** entry point into the draft-09 files under [`v09/`](v09/) (commit
`90089f8`); references in the **`v10/`** entry point into the draft-10 files under
[`v10/`](v10/) (commit `9dee49f`); references in the **`v11/` WIP** entry point
into [`v11/`](v11/) (commit `55ae44c`). Anchors in parentheses (e.g. `#sub-agents`)
are the spec's own kramdown anchors and are stable across line shifts.

| Snapshot | Protocol | Bootstrap | R3 | Interop profile | Events | Source commit |
|---|---|---|---|---|---|---|
| [`v01/`](v01/) | draft-01 | draft-01 | draft-00 | — | — | `c090879` (2026-05-11) |
| [`v02/`](v02/) | draft-02 | draft-01 (unchanged) | draft-00 (revised) | — | — | `feda56b` (2026-06-09) |
| [`v08/`](v08/) | draft-08 | draft-01 (unchanged) | draft-00 (unchanged) | new | — | `dd2b852` (2026-06-25) |
| [`v09/`](v09/) | draft-09 | draft-01 (unchanged) | draft-00 (revised) | unchanged | draft-00 (new) | `90089f8` (2026-07-05) |
| [`v10/`](v10/) | draft-10 | draft-02 (revised) | draft-01 (revised) | unchanged | draft-00 (revised) | `9dee49f` (2026-08-06) |
| [`v11/`](v11/) (WIP) | draft-11 working text | draft-02 (revised) | draft-02 working text | revised | draft-00 (unchanged) | `55ae44c` (2026-09-08) |

> [!WARNING]
> `v11/` is the latest vendored working reference, captured 2026-09-11, not a
> published draft-11 release. Draft-10 remains the latest published protocol
> revision and the SDK target. The WIP snapshot also adds the Budgets companion
> and separately pinned Signature Keys working source. No SDK migration is included.

> The SDK code targets `v10/` (draft-10) after the separately verified 2026-09-09
> migration. The snapshot was vendored 2026-09-08 and remains byte-unchanged.
> All four access modes and local four-party sub-agent scenarios are implemented;
> optional exclusions and incomplete external authorization interop remain explicit.
> See [SPEC-VERSION](SPEC-VERSION.md) and the
> [migration evidence](../.agent/plans/2026-09-08-aauth-v10-spec-migration/implementation-log.md).
> Historical per-snapshot entries below describe their original publication state.

## Contents

- [`v11/` - AAuth draft-11 WIP snapshot](#v11---aauth-draft-11-wip-snapshot)
  - [Protocol (WIP draft-11)](#protocol-wip-draft-11)
  - [Companion documents (WIP)](#companion-documents-wip)
  - [HTTP Signature Keys (published and working references)](#http-signature-keys-published-and-working-references)
  - [Known WIP inconsistencies](#known-wip-inconsistencies)
  - [Author's verbatim changelog (WIP draft-11)](#authors-verbatim-changelog-wip-draft-11)
- [`v10/` — AAuth draft-10 snapshot](#v10--aauth-draft-10-snapshot)
  - [Protocol (draft-10)](#protocol-draft-10)
    - [1. Fully specified algorithms and keys](#1-fully-specified-algorithms-and-keys)
    - [2. Signature verification and errors](#2-signature-verification-and-errors)
    - [3. Revocation identity and routing](#3-revocation-identity-and-routing)
    - [4. Directed subject handling](#4-directed-subject-handling)
    - [5. Account binding](#5-account-binding)
  - [R3 (draft-01)](#r3-draft-01)
  - [AAuth Events (revised draft-00)](#aauth-events-revised-draft-00)
  - [Bootstrap (draft-02)](#bootstrap-draft-02)
  - [Interoperability Demo Profile (unchanged)](#interoperability-demo-profile-unchanged)
  - [HTTP Signature Keys (draft-08)](#http-signature-keys-draft-08)
  - [Author's verbatim changelog (draft-10)](#authors-verbatim-changelog-draft-10)
- [`v09/` — AAuth draft-09 snapshot](#v09--aauth-draft-09-snapshot)
  - [Protocol (draft-09)](#protocol-draft-09)
    - [1. Clarification response discriminator](#1-clarification-response-discriminator)
    - [2. RFC 9457 error responses](#2-rfc-9457-error-responses)
    - [3. AAuth Events integration](#3-aauth-events-integration)
    - [4. Editorial and implementation-status changes](#4-editorial-and-implementation-status-changes)
  - [AAuth Events (new companion draft)](#aauth-events-new-companion-draft)
  - [R3 (revised)](#r3-revised)
  - [Bootstrap and Interoperability Demo Profile (unchanged)](#bootstrap-and-interoperability-demo-profile-unchanged)
  - [HTTP Signature Keys (draft-06)](#http-signature-keys-draft-06)
  - [Author's verbatim changelog (draft-09)](#authors-verbatim-changelog-draft-09)
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

## `v11/` - AAuth draft-11 WIP snapshot

Captured 2026-09-11 from the source of the
[editor's draft](https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html),
pinned at AAuth commit `55ae44cc3a07da29c4d6821c3800569ac77b9441` (2026-09-08).
There is no draft-11 release tag or IETF archive revision at capture time.
The SDK continues to target draft-10; this is documentation-only vendoring.

The following summary compares the working snapshot with `v10/`, not the SDK
implementation. Draft labels in companion history are not release claims.

### Protocol (WIP draft-11)

#### Person identity and token exchange

- Adds `aa-person+jwt`, a PS-issued, resource-audience identity token bound to the
  agent's key, and the `person_token_endpoint`. Person identity access becomes
  the fifth resource access mode (`#person-tokens`, `#person-token-endpoint`).
- Resources must verify a person token before the initial resource-token grant;
  `requirement=person-token` requests it. Person tokens cannot stand in for auth
  tokens where authorization is required.
- Renames PS/AS `token_endpoint` to `auth_token_endpoint`. The resource token's
  `presented_jti` names the person or auth token actually presented. The agent
  sends it as required `presented_token`; the PS forwards it to the AS, and both
  verify the binding and claim consistency (`#resource-token-verification`).
- Resource tokens carry `ps`, `sub`, and `presented_jti`, not an agent identifier.
  Auth tokens gain required `ps` and `sub` and lose `agent` and `act`. Chaining
  routes through the upstream auth token's `ps`; parent-mediated authorization
  now includes obtaining a person token for the sub-agent.
- Names the opaque resource-managed credential a session token and changes
  `access_mode=aauth-access-token` to `session-token` (`#aauth-access`).

#### Missions, consent, and supervision

- Replaces nested token `mission` objects with `mission_s256` and removes the
  agent-asserted `AAuth-Mission` header. Mission approval returns the exact blob
  bytes base64url-encoded, with `s256` alongside them (`#mission-approval`).
- Adds optional mission `expires_at` and `approved_resources`. A proposal can
  name resources and receive person tokens in the approval response.
  `capabilities` moves outside the immutable blob.
- Defines agent-owned update/completion requests at the mission URL, accepted
  updates in the mission log, and termination reasons outside the blob.
  Completion moves off the interaction endpoint. Non-owner control operations
  remain a companion concern (`#mission-update`, `#mission-management`).
- Requires equivalent not-found/non-owner responses and distinguishes
  resource-asserted consent content from agent assertions. Names supervision
  and the Supervisor without defining a new on-wire server role.

#### Revocation, expiry, and signatures

- Revocation bodies become `jti` plus `exp`; the issuer is derived from the
  verified server signature, while stored revocations remain keyed by `(iss, jti)`.
  A recorded revocation returns `200` even without a retained token record.
- Adds person/resource-token revocation, four-party cascading, bounded retention,
  and explicit revoked-token errors. Revocation endpoints become recommended
  for PSes, ASes, and resources accepting person tokens (`#token-revocation`).
- Verifiers judge token expiry without skew tolerance. Agents should refresh
  from the top of the token chain with a five-minute margin; issued auth tokens
  cannot outlive the presented token (`#refresh-margin`).
- Requires server-to-server `jwks_uri` signing with the metadata issuer as `id`.
  Requests with bodies to PS/AS endpoints must sign `content-type` and
  `content-digest`; delayed verification uses the signed `created` time.

#### Discovery, deferred responses, and errors

- Adds optional `accept_signature_algs`, an Access Mode Value Registry, and the
  `aauth-resource` metadata link relation (`#resource-metadata-link`).
- Allows `202` auth-token challenges that hold the invocation; completion and
  repeat presentation return a retained result (`#deferred-auth-token`).
- Defines `as_unreachable` (502), relaying AS terminal errors, `clock_skew`, and
  invalid/expired/revoked presented-token errors. Removes Third-Party Login and
  the `login_endpoint` metadata field.
- Adds a minimal-PS appendix and reorganizes the overview, PS endpoints, examples,
  metadata, and rationale. The full upstream history is reproduced below.

### Companion documents (WIP)

- R3's working draft-02 adds operation-level access and budget annotations,
  `per-call` access, single-use grants, idempotent completion, and approval to
  release an already computed result. `r3_conditional` becomes `r3_per_call`,
  document `version` is removed, and token examples follow protocol draft-11.
  The delta also includes working draft-01 additions absent from `v10/`:
  per-call proposals, hashing bytes as served rather than canonicalized JSON,
  and composing one R3 document across internal definitions.
- Bootstrap remains labelled draft-02 but adds multiple self-hosted agents per
  operator and acquisition guidance for hosted/self-hosted sub-agent tokens.
- The interop profile is revised around five surfaces: mission approval,
  person-token presentation, resource tokens, auth tokens, and sub-agents.
- Events is byte-identical to `v10/`; no Events protocol delta is introduced.
- [Budgets](v11/draft-hardt-aauth-budgets.md) is a new working companion,
  referenced by R3's budget annotations and accounting discussion. Its inclusion
  does not add SDK budget support.

### HTTP Signature Keys (published and working references)

The protocol's reference is unversioned. The snapshot includes both published
[draft-08](v11/draft-hardt-httpbis-signature-key-08.txt), freshly downloaded and
byte-identical to `v10/`, and the
[working Markdown source](v11/draft-hardt-httpbis-signature-key.md) from
`dickhardt/signature-key` commit
`10a7563beecb2a461d5b412549a69d49f97f500c` (2026-09-03).
Neither is represented as a new published revision or a fully aligned dependency.

### Known WIP inconsistencies

- The protocol uses `clock_skew` and `revoked_jwt`, but the pinned Signature Keys
  source and published draft-08 do not define them.
- The interop profile still describes PS lookup of the person token and omits
  the newly required `presented_token` in its exchange descriptions.
- The author's history includes superseded intermediate choices, such as
  suppressing distinct revocation errors and adding `mission_expired` before
  folding it into `mission_terminated`. The governing sections take precedence
  over isolated history bullets.
- No Supervision Protocol source is present at the pinned AAuth commit despite
  the protocol referring to that companion.

These upstream inconsistencies are preserved. No vendored source is edited, and
this capture makes no draft-11 conformance claim.

### Author's verbatim changelog (WIP draft-11)

Reproduced from the pinned
[protocol Document History](v11/draft-hardt-oauth-aauth-protocol.md#document-history).
This is the author's working history, including intermediate decisions later
superseded within the same draft.

```text
- draft-hardt-oauth-aauth-protocol-11
  - Added Expiry and the Refresh Margin under Re-authorization. A verifier judges `exp` against its own clock with no skew tolerance. `iat` stays REQUIRED and is not a validity check — a verifier MAY refuse an `iat` too far in the future, using the same 60-second window it allows on a signature's `created`, with the new error `clock_skew` (body, and `Signature-Error` for a header JWT or a future `created`) — distinct from `invalid_`/`expired_` because refreshing does not help while waiting does — and otherwise it is what neighbouring profiles expect, the issuance time audit reports, a clock-free check of the issuer's lifetime ceiling (`exp` minus `iat`), and an optional age bound a verifier may apply by its own policy. The agent absorbs skew instead: it SHOULD refresh a token with fewer than five minutes left and SHOULD NOT present one inside that margin, because a presented token is verified at several parties in sequence, expiry propagates downward through the chain, and five minutes is the resource token's maximum lifetime — a token with that much left when a resource token names it is still valid when the resource token is redeemed. Refresh runs from the agent token down. States when refresh is unnecessary (no further use) and when reactive renewal on `expired_jwt` is acceptable (an auth token presented only to the resource, for an idempotent request).
  - `presented_jti` names the token the request actually carried, and the agent passes that token to the PS as `presented_token`. On a step-up or per-call challenge the request carries an auth token, and Resource Token Structure had the resource supply the person token's `jti` from a record it cannot key: an auth token carries no reference to the person token or the resource token, and `(ps, sub, agent key)` does not identify one person token under concurrent missions. The resource now names the token it just verified, person or auth, and copies `ps`, `sub`, `mission_s256`, and `tenant` from it. The auth token request gains `presented_token`, REQUIRED, and the PS-to-AS request's `person_token` becomes `presented_token`, passed through, so the PS and the AS run one verification: signature against the issuer, `aud` the resource, `cnf.jwk` against `agent_jkt`, `jti` against `presented_jti`, claims against the resource token. Resource token verification no longer looks up retained person tokens; the retention MUST narrows to what revocation needs; `unknown_person_token` is removed and `invalid_presented_token` added; `expired_person_token` and `revoked_person_token` become `expired_presented_token` and `revoked_presented_token`. An auth token's `exp` is capped at the presented token's, whichever type. Addresses issue #152.
  - Defined what a party returns when a revoked token is presented, which nothing covered. A revoked token verifies, is unexpired, and has intact claims, so reporting it as malformed or expired is false and leaves the caller no reason not to present it again. Where the answer goes follows how the token was carried. A token in the `Signature-Key` header — agent, person, or auth — is refused with `401` and `Signature-Error: error=revoked_jwt`, newly defined in the HTTP Signature Keys specification; a resource refusing a revoked auth token SHOULD carry `requirement=auth-token` with a fresh resource token on the same response, so one message says why and how to recover. A token carried as a request parameter is not the credential that signed the request, so it is answered in the body as `revoked_<token>_token`, beside the `invalid_` and `expired_` codes that parameter already has: added `revoked_resource_token` and `revoked_presented_token`. A pending request already started against a withdrawn resource token terminates with the new polling code `revoked`, rather than `denied`, which says the user refused.
  - `revocation_endpoint` is RECOMMENDED for a PS, for an AS, and for a resource that accepts person tokens; a resource that accepts only agent tokens receives no revocations and need not publish one. It was OPTIONAL everywhere, which said nothing about what the absence costs: every cascade in Token Revocation lands on one of these endpoints, and a server without one honors a revoked token until its `exp`. Addresses issue #154.
  - Added resource tokens to Token Revocation. A resource issues them and can withdraw one, calling the revocation endpoint of the party named in `aud` and, in four-party, of the `ps` holding it. The window is five minutes but spans the wait for user interaction, which is when a resource is most likely to withdraw. Also stated what a party returns when a revoked token is presented — the existing challenge or error for each token type, with no distinct "revoked" error, since the recovery is the same and a distinct error would disclose that a revocation exists.
  - Removed Third-Party Login and the `login_endpoint` metadata field from agent providers and resources. The flow had the agent or resource mint a resource token with nothing presented and POST it to the PS, which a resource cannot do and an agent no longer can: a resource token copies `ps`, `sub`, and `presented_jti` from a verified person or auth token. Its `ps` parameter chose a PS the agent token already fixes. The use cases are agent-person binding at first interaction, the agent's own UI, or a call to the resource's authorization endpoint. Addresses issue #155.
  - Pinned how a server signs. Keying Material named the scheme for agents and said nothing about the PS, AS, AP, and resource requests the protocol also depends on — server-to-server signing appeared only in an example. A server signing in its own right MUST use `scheme=jwks_uri` with `id` equal to its metadata `issuer` and `dwk` the well-known name of that document, so the recipient resolves the caller to the `iss` of every token it mints. Revocation rests on that derivation: it names a token by `jti` alone and keys the entry under the verified caller. A resource acting as an agent in multi-hop signs as an agent, with `scheme=jwt`.
  - Reworked Token Revocation. The request is now `jti` and `exp`, both REQUIRED: `iss` is gone, because a caller revokes only its own tokens and the recipient takes the issuer from the verified signature, which keys the revocation and makes revoking another issuer's token unreachable rather than refused. `exp` is the revoked token's own expiration, and a recipient MAY discard the entry once `exp` plus its clock skew has passed; nothing previously bounded the entry, since the section had removed the token type that would have selected a maximum. Named the three revocable token types and where each is revoked — an agent token only at a PS, a person token and an auth token at the resource — which replaces the SHOULD that asked a resource accepting agent tokens to provide a revocation endpoint the agent provider has no way to find. Spelled out the four-party chain: a PS cannot revoke an AS-issued auth token, so it revokes the person token at the AS and the AS cascades to what it issued, which is why a PS and an AS retain what they issued until its `exp`. Replaced the `200`/`404` response rule with `200 OK` once the revocation is recorded, whether or not the recipient holds a record of the token, so a stateless verifier is not answering `404` to every revocation it honors, and defined `invalid_request` and `unsupported_iss`. Addresses issue #146.
  - Added the informative appendix A Minimal Person Server: how a PS serving one person composes from the four REQUIRED metadata fields, out-of-band consent completion, person token records, and the existing pending-request rules, with no new requirement. Readers sizing a self-hosted PS were inferring the full endpoint surface.
  - Named the Supervisor: the party the PS consults for a per-act decision, the Person by default, or a supervision server (SS) the PS delegates to under the AAuth Supervision Protocol, a companion specification. Added to Terminology and Roles; Policy Evaluation Points, Consent Presentation, and Why Missions Are Not a Policy Language name it where they previously described an anonymous decision-maker. Nothing on the wire changes.
  - Editorial pass with no normative change. Gone or merged: the Introduction's feature list and its negation, the Overview's three mission diagrams and its Bootstrapping section, the signature-header boilerplate on fourteen examples, the per-role repetition of the common metadata fields, two duplicate `202` examples and two of the three clarification-response examples, three Design Rationale entries that restated body text and five one-sentence entries now in an In Brief list, and six Security Considerations subsections that restated normative text stated elsewhere. The three `401` requirement challenges are now adjacent. Every MUST, SHOULD, and MAY survives in the section that governs it.
  - Moved the Person Token Endpoint into the Person Server chapter beside the auth token endpoint, leaving the token's structure, usage, and verification in Person Token with a pointer. Every other PS endpoint was already defined in that chapter, and a PS implementer had to find this one under the token. The chapter now opens with the full list of endpoints a PS serves and their requirement levels.
  - Pointed verifiers that first see a signed artifact after a delay at the signed `created` parameter: the token is checked for validity at `created`, the accepted skew is the verifier's policy, and a replay cache there MUST span that skew. The profile already mandated `created`; nobody reading from the queued-consumption angle was directed to it.
  - Stated that the server hosting an interaction URL MAY complete the interaction over a channel it controls, without the person visiting `url` or presenting `code`, and what happens to the code: consumed at completion, `invalid_code` on later presentation, the pending URL returns the terminal response. The single-use rule was keyed on arrival at the URL, which did not describe a phone tap or a chat approval.
  - Added `as_unreachable` (502) for a PS that cannot complete federation, and the rule that an AS's well-formed terminal error is relayed to the agent with the AS's `error` and status. Nothing normative covered the PS-to-agent leg of a failed federation; `invalid_resource_token` and `server_error` were both wrong for it. Found implementing federation in a PS against the reference AS.
  - The PS-to-AS token request gains the token named by the resource token's `presented_jti`, REQUIRED (now `presented_token`, see above). The AS verifies it against the resource token and caps the auth token it issues at its `exp`. This closes a rule the Resource and the AS could not satisfy: -11 required every token carrying `mission_s256` to expire no later than the mission's `expires_at`, and neither party holds the mission. A resource token's lifetime is now independent of the mission; the PS caps what it issues at `expires_at`, and the person token carries that bound to the AS. Added `expired_person_token` (now `expired_presented_token`). Agents are advised to refresh the person token at least five minutes before expiry and to re-obtain resource and auth tokens against it.
  - Warned resource implementers that policy keyed on the agent identifier is local to the two-party modes. The identifier reaches a resource in agent identity and resource-managed access and in no other mode, so an allowlist or per-agent label designed there is silently unenforceable once an endpoint moves to auth tokens; durable per-operation policy is `scope` or R3 operations. A deployment walked into exactly this and neither of its own review passes caught it.
  - Policy Evaluation Points points the PS's supervision policy at a companion specification on AAuth supervision, which will define how the policy is evaluated and by whom. This document defines only the artifacts that carry the outcome.
  - Distinguished supervision from governance. Governance remains the name of the layer (missions plus permission, audit, and interaction relay). Supervision is the per-act evaluation the PS performs against the mission's intent and prior log entries, and now has a Terminology entry; a dozen occurrences that used governance in that sense were changed. The agent-provider rationale's fleet-level sense is reworded as control and enforcement. Aligns with AAuth Budgets, which already uses supervision as a term of art, and gives a companion specification for a delegated supervisor a term to define against.
  - Stated the conformance floor in Person Server Metadata: the four REQUIRED fields are the whole of a conformant PS. Consent needs no metadata field, because the interaction URL travels in the `AAuth-Requirement` header; `interaction_endpoint` is the agent's channel to the person, not a consent surface. Readers sizing an implementation were inferring the full endpoint surface was required.
  - Restated the person-token-before-resource-token prerequisite where readers of the `401` path meet it. The three-party and four-party figures now show the person token leg and carry a step list; the Resource Token section opens with the prerequisite; a resource MUST NOT challenge with `requirement=auth-token` on a request that carried neither a person token nor an auth token. A deployment that read the draft carefully built both its flow and its wire trace without a person token, because the figures went straight from the authorization endpoint to a resource token.
  - Derived the resource token's audience from the verified person token in the places that still routed on the agent token's `ps` claim: both `aud` bullet lists and the authorization endpoint responses intro. Dropped the sentence saying the `401` path is reached with an agent token, which contradicted the rule that a resource MUST NOT issue a resource token without a verified person token. Renamed the token-request subsection Auth Token Request, for the token it returns.
  - Added Consent Presentation, naming the two kinds of content a consent surface carries and what the PS MUST do with them. Resource-asserted content is the resource's metadata (`name`, `description`, `logo_uri`, `scope_descriptions`), the claims of the resource token, and an R3 `display` section; agent-asserted content is `justification`, `platform`, `device`, and clarification responses. A PS MUST visually distinguish the two and attribute the agent's, and MUST NOT decide on agent-asserted content alone where resource-asserted content covering the same operation is available. Nothing previously required the distinction, so a person reading a consent screen could not tell which party asserted what, and the agent controlled one of the two.
  - Added the Security Considerations subsection Agent Control of the Consent Surface. Sanitizing the `justification` prevents script injection and nothing else; the agent can still describe the access as something other than what the resource says it is. The mitigation is attribution, not filtering.
  - Resolved the `justification` TODO. No section structure is defined for the value: the justification says why the agent wants the access, the resource says what the access does, and the person weighs the one against the other. The parameter now points at Consent Presentation and at clarification chat.
  - Three places still said a resource discovers the agent's PS from the `ps` claim in the agent token — the three-party access mode, the bootstrapping requirements, and the claim's own definition — which the Design Rationale already contradicted. The agent token's `ps` is the advance signal that the agent has a person server, which is what lets a resource decide to challenge for a person token. The PS of an issued authorization is the `iss` of the person token the resource verified, which the resource copies into the resource token's `ps`.
  - Corrected the JWT Claims Registrations table. `ps` was registered twice; the two rows are collapsed into one covering agent, resource, and auth tokens. `agent` is no longer a claim in any token and its row is removed — it survives only as a member of the mission blob, which is not a JWT. Added `presented_jti`, `account`, and `interaction`, none of which were registered.
  - Established the AAuth Access Mode Value Registry, seeded with `agent-token`, `person-token`, `session-token`, and `auth-token`. The `access_mode` field was described as a closed list of four, which left no room for the `per-call` value R3 defines; the registry is how the other extensible AAuth value spaces are already handled.
  - Pointed `access_mode` at R3 operation access annotations. Two places said a resource MAY apply different modes to different endpoints without naming a mechanism for saying which.
  - Added the person token (`aa-person+jwt`), issued by a PS to identify the person to one resource. Presented via `Signature-Key` in place of the agent token. A resource MUST verify one before issuing a resource token. Lifetime capped at 1 hour, as for auth tokens.
  - Added `person_token_endpoint`, REQUIRED in PS metadata, taking `resource`, `mission_s256`, `subagent_token`, and `upstream_token`.
  - Five resource access modes instead of four, sorted by what the resource ends up knowing and which party established it: agent identity, resource-managed, person identity, PS authorization, federated authorization. A resource MAY apply different modes to different endpoints.
  - A person token carries no authorization from the PS, but a resource MAY serve requests on identity alone, so holding one is effectively access at such a resource. The consent question at first issuance is whether the agent may act at the resource as the person.
  - Renamed the PS and AS metadata field `token_endpoint` to `auth_token_endpoint`; added `person-token` to `access_mode`.
  - Added `requirement=person-token`, and the `invalid_person_token` and `invalid_account` authorization endpoint errors.
  - Resource tokens carry `ps`, `sub`, and `presented_jti`, and no agent identifier. The PS verifies the named token, which the agent passes with its token request, and rejects any mismatch, which makes mission stripping detectable — comparing claims alone cannot, because concurrent missions mean several person tokens per agent and resource.
  - Auth tokens carry `ps` and a REQUIRED `sub`, and no agent identifier. `act` and the delegation chain are removed.
  - Replaced the `mission` object with the `mission_s256` claim in person, resource, and auth tokens; `approver` is dropped everywhere but the mission blob.
  - Removed the `AAuth-Mission` header and its registration. A mission reaches a resource only inside a PS-issued token, so it is no longer agent-asserted. The approval response carries the mission blob base64url-encoded, with `s256` alongside it, so the digest covers an unambiguous byte sequence and the agent can verify it as it would a JWT payload.
  - Mission blob gained `approved_resources` and MAY carry `expires_at`; the PS caps the person tokens and auth tokens it issues at it, and every PS decision path compares the current time to it. Added the `mission_expired` status.
  - Moved `capabilities` out of the mission blob to the approval response — it describes whether the PS can currently reach the person, which is not a term of the mission and should not perturb its digest.
  - A mission proposal MAY name the `resources` it expects to use; the approval response returns a person token for each.
  - Chain routing uses the auth token's `ps` claim. Removed the branch routing a downstream request to the upstream AS, which required the two resources to share an access server and was never stated as such.
  - `sub` MUST be unique within the issuer; `(iss, sub)` is the identifier and `tenant` is organizational context, not part of it. `sub` values from different issuers MUST NOT be matched.
  - Stated the extensibility posture: recipients ignore what they do not recognize, and no document carries a version or schema a recipient must understand.
  - Defined the mission endpoint's error responses, including that a PS MUST answer identically — status, body, headers, and timing — whether a mission does not exist or the agent does not own it. Without that the agent surface is an existence oracle for any party that has seen a `mission_s256` in an auth token. Adopted from `draft-mcguinness-mission-aauth-management`.
  - The mission endpoint is the owning agent's surface, with three operations of one shape: `POST {mission_endpoint}` proposes a mission, and `POST {mission_endpoint}/{mission_s256}` carries `action: update` or `action: completion`. The `action` discriminator is the one the pending route already uses.
  - Added mission update. An update records a change in the work, is appended to the mission log, and is digested so the sequence is verifiable. It does not change the blob, `mission_s256`, or any token carrying it; what it changes is the context the PS evaluates against, so the mission's meaning becomes the approved blob plus its accepted updates and an audit MUST read both.
  - Moved completion off the interaction endpoint. It is a lifecycle transition, not transport: creation and completion are the same shape — the agent proposes, the person decides, clarification is available, the response is deferred — and were split across two endpoints for no structural reason. The interaction endpoint keeps `interaction`, `payment`, and `question`, which are the things the agent genuinely cannot do itself.
  - Defined the termination reasons `completed`, `revoked`, `expired`, `superseded`, and `administrative` as an open set recorded outside the immutable blob, and folded `mission_expired` back into `mission_terminated` with an OPTIONAL `termination_reason` member. One error rather than one per reason, because the reason set is open.
  - `mission_control_endpoint` is the mission control plane: where parties other than the owning agent read and manage missions. Its authentication model and operations are left to a companion specification, because AAuth defines no administrative principal.
  - A request carrying a body to a PS or AS endpoint MUST additionally sign `content-digest` and `content-type`. Those requests decide what is authorized and only their tokens were self-protecting. Resources keep declaring what they need through `additional_signature_components`, since bodyless requests and streamed uploads make a blanket requirement wrong there.
  - Stated that the mission blob's member lists are a floor: a PS MAY add members, readers ignore what they do not recognize, and a blob with an extra member has a different identifier because it is a different mission.
  - Named the opaque credential a resource issues in resource-managed access the **session token**. It was the only credential in the protocol without a name. The `access_mode` value `aauth-access-token` becomes `session-token`.
  - Renamed the resource token claim `person_token_jti` to `presented_jti`. The old name asserted the credential presented was a person token, which is false on every step-up and per-call challenge, where it is an auth token. The value is the `jti` of the token whose verification established `ps` and `sub`: the person token, or on a step-up the auth token (see above). Addresses issues #95 and #152.
  - Stated the person token's assurance floor where the token is introduced: it asserts recognition and agency, guarantees continuity of `(iss, sub)`, and a resource MUST NOT treat it as evidence of identity proofing, legal identity, or any assurance level. Addresses issue #97.
  - Stated the retention obligation on person tokens: a PS MUST record the `jti`, `aud`, and `exp` of each person token it issues, and any access server it presented it to, until `exp` plus clock skew, for revocation. Resource token verification does not consult the record, since the agent presents the token itself (see above). Addresses issue #87.
  - Added the OPTIONAL common metadata field `accept_signature_algs`, the out-of-band twin of the `Accept-Signature-Alg` response header: exactly the set of fully-specified algorithms the server's verifier accepts, one list per server. Addresses issue #94.
  - A resource MAY deliver `requirement=auth-token` as a `202 Accepted` deferred response that holds the invocation; the agent completes at the pending URL with the auth token, and completion consumes the pending record. The `401` remains the baseline delivery; agents MUST support both. Addresses issue #92.

  - Added the `aauth-resource` link relation, as a `Link` header field or an HTML `link` element, so that a developer portal or an API served from a host other than the resource identifier can point an agent at the resource metadata document. The target is constrained to the well-known URL and the document is verified as any metadata document is, so the link is a pointer and not an authority; verifiers never use it. Registered with IANA; Link Relation Discovery added to Security Considerations. Requested by a developer-portal operator whose agents reach the portal before the resource.
  - Corrected four recitals that earlier -11 changes left behind: the mission blob's `expires_at` text no longer says a resource token may not outlive it; Updated Request and Non-Repudiation no longer name the removed `agent` claim; Resource Adoption Path step 3 routes on the verified person token rather than the agent token's `ps`.
```

---

## `v10/` — AAuth draft-10 snapshot

The latest upstream snapshot, vendored 2026-09-08 for reference. It bundles
protocol **draft-10** with R3 **draft-01**, Bootstrap **draft-02**, revised AAuth
Events **draft-00**, the unchanged Interoperability Demo Profile, and HTTP
Signature Keys **draft-08**.

> **The SDK continues to target draft-08.** Draft-09 and draft-10 migrations are
> separate implementation work.

### Protocol (draft-10)

Published as IETF
[draft-hardt-oauth-aauth-protocol-10](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/10/)
(commit `9dee49f`, source frontmatter date 2026-06-17, IETF publication date
2026-08-06). The author's verbatim draft-10 changelog is reproduced below.

#### 1. Fully specified algorithms and keys

The HTTP Message Signatures profile now requires algorithms to be explicit and
unambiguous (`#signature-algorithms`, `#keying-material`):

- Every conveyed or referenced key MUST carry a fully specified `alg`.
- `Ed25519` replaces the deprecated polymorphic `EdDSA`; `none`, symmetric
  algorithms, and algorithms prohibited by the JOSE registry MUST NOT be used.
- A verifier MUST reject a key whose `kty` or `crv` disagrees with `alg`.
- Every `cnf.jwk` and every AAuth server key selected from `jwks_uri` follows
  these rules. Unselected JWKS members do not need to use supported algorithms.
- The HTTP Signature `alg` parameter MUST NOT be sent and is ignored if present;
  the selected key determines the algorithm.

#### 2. Signature verification and errors

Verification and error behavior now align with HTTP Signature Keys draft-08
(`#verification`, `#authentication-errors`):

- Defined failures include `unsupported_scheme`, `unsupported_algorithm`,
  `invalid_key`, `issuer_missing`, and `issuer_mismatch` in addition to existing
  signature and JWT errors.
- Signature failures are authentication failures and always use `401`; the
  `Signature-Error` header is the machine-readable carrier.
- `unsupported_scheme` and `unsupported_algorithm` can advertise accepted values
  through `Accept-Signature-Scheme` and `Accept-Signature-Alg`.
- A `403` means authentication succeeded but authorization failed, so it MUST NOT
  carry `Signature-Error` or either `Accept-Signature-*` header.
- Metadata discovery explicitly rejects a missing or mismatched `issuer`.

The protocol also adds designated-expert instructions for its Requirement,
Capability, and Platform registries (`#designated-expert-instructions`).

#### 3. Revocation identity and routing

Token revocation is keyed by the pair `(iss, jti)`, because `jti` is unique only
within an issuer's namespace (`#token-revocation`):

- Revocation requests carry both `iss` and `jti`; recipients MUST store
  revocation state under the pair.
- A PS or AS revokes an auth token at the resource that received it.
- An AP revokes its agent token at the PS's `revocation_endpoint`; the PS denies
  later use and should revoke auth tokens issued or provided for that agent.
- Identity-based access cannot always receive that push, so exposure remains
  bounded by token lifetime when no resource revocation endpoint is reachable.

#### 4. Directed subject handling

Federation rules prevent directed person identifiers from crossing trust
boundaries as if they were globally meaningful:

- A downstream issuer MUST NOT copy `sub` from an upstream auth token.
- It MAY issue its own directed `sub` only after its own authenticated federation
  step maps the person into the downstream resource's namespace.
- Person identifiers MUST NOT appear in `act`; that chain identifies agents.

#### 5. Account binding

The new optional `account` parameter distinguishes multiple accounts that the
same person may hold at one resource (`#account-binding`):

- The authorization request names an account in the resource's own namespace.
- The resource echoes it into the resource token, and the PS or AS copies it into
  the auth token.
- The resource enforces the claim per account, and audit records retain the
  account covered by the authorization.
- The value selects an existing resource account; it is not an authentication
  hint and has no protocol-defined structure.

### R3 (draft-01)

R3 advances from draft-00 to draft-01 and incorporates the protocol changes:

- The R3 document gains optional `account`, copied from the authorization request
  and resource token. Its `display` should name the account in terms the person
  recognizes rather than exposing an opaque resource identifier.
- Operation identifiers are explicitly scoped to a vocabulary's advertised
  discovery endpoint.
- The new `urn:aauth:vocabulary:openapi-gateway` vocabulary qualifies operations
  with `(service, operationId)` for multi-service gateways.
- JWT examples use `Ed25519`, include `alg` in `cnf.jwk`, and correct token types
  to `aa-resource+jwt` and `aa-auth+jwt`.
- The R3 Vocabulary Registry gains designated-expert instructions.

### AAuth Events (revised draft-00)

Events remains draft-00 but changes resource-to-AP delivery to match the
Signature Keys model:

- Event tokens now use `scheme=self-jwt`: the resource issues the JWT and signs
  the HTTP request with the same discoverable JWKS key, so the token has no
  `cnf` claim.
- Subscribe-token examples use fully specified `Ed25519` and carry `alg` in
  `cnf.jwk`.
- The draft adds open-network and `self-jwt` design rationale and points its
  protocol-family references at the Datatracker document pages.

### Bootstrap (draft-02)

Bootstrap advances from draft-01 to draft-02. Its token examples replace
`EdDSA` with `Ed25519`, add `alg` to `cnf.jwk`, and reference the protocol through
its Datatracker document page. The enrollment guidance is otherwise unchanged.

### Interoperability Demo Profile (unchanged)

`interop-demo-profile.md` is byte-identical to `v09/`.

### HTTP Signature Keys (draft-08)

Bumped **draft-06 → draft-08**
([published 2026-08-05](https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key/08/)).
Draft-07 was editorial only. Draft-08 is not backward compatible with draft-07
and includes these implementation-relevant changes:

- Algorithms now come from required, fully specified JWK `alg` values. `EdDSA`,
  `none`, symmetric algorithms, and key/algorithm mismatches are forbidden.
- `Accept-Signature-Scheme` and `Accept-Signature-Alg` replace the `sigkey`
  parameter; `supported_algorithms` is removed from `Signature-Error`.
- Covering `signature-key` is now mandatory for signers and verifiers; `exp` is
  mandatory for `jwt` and `self-jwt`; malformed JWT rejection and cache limits
  become mandatory.
- The new `jwks` scheme directly fetches a JWKS URL that serves as both identity
  and key location. Discovery adds `issuer_missing` and `issuer_mismatch` errors.
- Optional assertion caching adds the `cached` scheme,
  `Signature-Key-Cache`, and `cache_miss`, with bounded verifier state.
- Unknown schemes and unsupported algorithms have defined negotiation and error
  behavior, and selected JWKS keys are validated independently of other members.

### Author's verbatim changelog (draft-10)

Reproduced from the Document History section of
[`v10/draft-hardt-oauth-aauth-protocol.md`](v10/draft-hardt-oauth-aauth-protocol.md):

> **draft-hardt-oauth-aauth-protocol-10**
>
> - Adopted the fully-specified `Ed25519` of [@!RFC9864] in place of the `EdDSA`
>   it deprecates. `alg` is REQUIRED and MUST be fully specified; `EdDSA`, `none`,
>   and symmetric algorithms MUST NOT be used; a verifier MUST reject a key whose
>   `kty` or `crv` disagrees with its `alg`. Addresses issue #57.
> - A `cnf` JWK MUST carry a fully-specified `alg`, as MUST every key at an AAuth
>   server's `jwks_uri`. A verifier MUST select the key matching `kid` without
>   requiring the other JWKS members to be usable.
> - Aligned verification and error mapping with
>   [@!I-D.hardt-httpbis-signature-key]: added `unsupported_scheme`,
>   `unsupported_algorithm`, `invalid_key`, `issuer_missing`, and
>   `issuer_mismatch`; pinned signature failures to `401`; a `403` MUST NOT carry
>   `Signature-Error` or either `Accept-Signature-*` header; the `alg` signature
>   parameter MUST NOT be used.
> - Revocation identifies a token by `(iss, jti)`, and recipients key revocation
>   state by that pair. An agent provider revokes an agent token at the PS's
>   `revocation_endpoint`. Addresses issues #59 and #60.
> - A downstream issuer MUST NOT copy a directed `sub` from an upstream token,
>   MAY emit one only from its own authenticated federation step, and MUST NOT
>   place a person identifier in `act`. Addresses issue #41.
> - Added the OPTIONAL `account` parameter on the authorization endpoint request,
>   echoed in the resource token and copied into the auth token, binding an
>   authorization to one of several accounts a resource may hold for the same
>   person. Addresses issue #52.

## `v09/` — AAuth draft-09 snapshot

The latest upstream snapshot, vendored 2026-07-19 for reference. It bundles
protocol **draft-09** with a revised R3 (**draft-00**), the unchanged bootstrap
(**draft-01**) and Interoperability Demo Profile, the new AAuth Events companion
(**draft-00**), and HTTP Signature Keys **draft-06**.

> **The SDK continues to target draft-08.** This snapshot is the immutable input
> to the separate draft-09 migration.

### Protocol (draft-09)

Published as IETF
[draft-hardt-oauth-aauth-protocol-09](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/09/)
(commit `90089f8`, source frontmatter date 2026-06-17, IETF publication date
2026-07-04). The author's verbatim draft-09 changelog is reproduced below.

#### 1. Clarification response discriminator

Clarification-chat POSTs to a pending URL are now explicitly typed
(`#clarification-chat`):

- The body MUST include `action=clarification_response` when answering the
  user's question, or `action=updated_request` when replacing the resource
  request.
- A server MUST reject a missing or unrecognized `action` with
  `400 Bad Request`.
- Both wire examples now carry the discriminator, removing the draft-08
  inference from whether `clarification_response` or `resource_token` happened
  to be present.

#### 2. RFC 9457 error responses

The token-endpoint-specific JSON format became a common AAuth problem-details
format (`#error-responses`, `#error-response-format`):

- Error bodies use RFC 9457 `application/problem+json`.
- The AAuth `error` code remains REQUIRED as an extension member; the standard
  `detail` member replaces `error_description`.
- Standard RFC 9457 members MAY be present, but receivers MUST use `error`, not
  `type`, to determine AAuth behavior.
- Authorization, interaction, mission-status, token-endpoint, and polling
  errors now reference or demonstrate the common format. Authentication failures
  continue to use the HTTP Signature Keys `Signature-Error` header.

#### 3. AAuth Events integration

The protocol now introduces its Events companion at the core integration points:

- The protocol overview names asynchronous event delivery through the AP, and
  the AP role gains event-router behavior.
- Agent metadata (`#metadata-documents`) gains optional `event_endpoint`, which
  is required when an AP supports AAuth Events.
- IANA considerations register the companion's `aa-subscribe+jwt` and
  `aa-event+jwt` token types.

#### 4. Editorial and implementation-status changes

- Hand-maintained source references for HTTP Signature Keys and Bootstrap were
  removed in favor of the references resolved by the publication toolchain; the
  citations remain.
- The acknowledgments add Lukas Friman and Sanjay Dalal.

### AAuth Events (new companion draft)

`draft-hardt-aauth-events.md` is a new standards-track companion source at
draft-00 (source date 2026-06-24). It defines AP metadata, subscribe tokens,
public and protected registration, event tokens, resource-to-AP delivery,
AP-to-agent routing, and AsyncAPI discovery. It is included because both the
protocol and revised R3 reference it.

At copy time the Events source was present at the pinned protocol tag but had no
dedicated Git tag or published Datatracker revision. The snapshot therefore pins
the exact companion source from protocol tag
`draft-hardt-oauth-aauth-protocol-09` rather than a moving branch.

### R3 (revised)

R3 remains draft-00 but its AsyncAPI vocabulary changed:

- `action` is now OPTIONAL rather than REQUIRED; when present it is `send` or
  `receive`, and event subscriptions use `receive`.
- A granted AsyncAPI subscription operation now hands off registration and
  delivery to AAuth Events using a subscription ticket URL and subscribe token.

### Bootstrap and Interoperability Demo Profile (unchanged)

- `draft-hardt-aauth-bootstrap.md` remains draft-01 and is byte-identical to
  `v08/`.
- `interop-demo-profile.md` is byte-identical to `v08/`.

### HTTP Signature Keys (draft-06)

Bumped **draft-05 → draft-06**
([published 2026-07-02](https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key/06/)).
Draft-06 adds the `self-jwt` scheme: a self-issued JWT whose issuer and signer
are the same party, using the issuer's discovered JWKS key for both the JWT and
HTTP signature and carrying no `cnf` claim.

The protocol draft-09 publication resolves its Signature Keys reference to
draft-06. This snapshot intentionally vendors that revision rather than the
newer draft-07.

### Author's verbatim changelog (draft-09)

Reproduced from the Document History section of
[`v09/draft-hardt-oauth-aauth-protocol.md`](v09/draft-hardt-oauth-aauth-protocol.md):

> **draft-hardt-oauth-aauth-protocol-09**
>
> - Clarification chat: added a required `action` discriminator
>   (`clarification_response` / `updated_request`) to the agent's POST responses
>   on the pending URL, so the response type is explicit rather than inferred
>   from key presence.
> - Error responses: adopted RFC 9457 problem details — error bodies use
>   `Content-Type: application/problem+json` with the AAuth error code as a
>   required `error` extension member; `error_description` replaced by the RFC
>   9457 `detail` member; added token endpoint and polling error examples.

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
