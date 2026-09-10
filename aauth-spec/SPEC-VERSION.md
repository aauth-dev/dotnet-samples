# AAuth Specification Version

These spec files were copied from the [AAuth](https://github.com/dickhardt/AAuth)
repository for reference while building the .NET samples. They are grouped by the
AAuth protocol draft version under [`v01/`](v01/), [`v02/`](v02/),
[`v08/`](v08/), [`v09/`](v09/), and [`v10/`](v10/). Each folder is a
self-contained snapshot, so each carries its own copy of the HTTP Signature Keys
draft at the version that snapshot's protocol references.

The GitHub repository is the working source we vendor from. The canonical,
permanent home is the **IETF Datatracker**, which retains every published revision
(and its `.txt` / `.html` renderings) even if the GitHub repo is moved or
deprecated. Use it as the source of record and fallback:

- Datatracker document — <https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/>
- Per-revision text (example) — <https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-09.txt>

The vendored `.md` files are the upstream kramdown source; if the GitHub repo is
unavailable, the Datatracker `.txt`/`.html` renderings are the authoritative
substitute.

The SDK now targets **draft-10** ([`v10/`](v10/)), following the separately
verified migration on 2026-09-09. This includes all four access modes, the
resource-managed opaque credential, accounts, AS clarification, issuer-qualified
revocation, and real four-party parent/worker scenarios in both primary apps.
Signature Keys draft-08, R3 draft-01 and revised Events draft-00 are included;
Bootstrap draft-02 remains informational. No snapshot bytes changed during migration.

`v10/` remains the latest vendored upstream reference. Earlier snapshots are
historical, not compatibility fallbacks. X.509/cached carriers and third-party
login hosting are unsupported; platform/native transports and production
persistence/policy are deployment responsibilities. External whoami identity
access passed, but scoped access returned `person-token`; external authorization
and the full external mission/sub-agent profile remain unverified. See the
[migration log](../.agent/plans/2026-09-08-aauth-v10-spec-migration/implementation-log.md)
and [conformance ledger](../.agent/plans/2026-09-08-aauth-v10-spec-migration/conformance-ledger.md)
for executed gates and explicit limitations. Historical snapshot entries below
retain their original context.

For a high-fidelity record of what changed between snapshots, see
[`CHANGELOG.md`](CHANGELOG.md).

## `v01/` — protocol draft-01

| Field | Value |
|---|---|
| Source repository | <https://github.com/dickhardt/AAuth> |
| Commit | `c090879ea2254d4af43a7253c7715f8d6530eb26` |
| Commit date | 2026-05-11 |
| Tagged version | `draft-hardt-oauth-aauth-protocol-01` / `draft-hardt-aauth-bootstrap-01` |
| Copied on | 2026-05-13 |

- `draft-hardt-oauth-aauth-protocol.md` — Main AAuth protocol specification (draft-01)
- `draft-hardt-aauth-bootstrap.md` — Agent bootstrap guidance (draft-01, informational)
- `draft-hardt-aauth-r3.md` — Rich Resource Requests (R3) specification (draft-00)
- `draft-hardt-httpbis-signature-key-04.txt` — HTTP Signature Keys: the `Signature-Key`
  header and its schemes (`hwk`, `jkt-jwt`, `jwks_uri`, `jwt`, `x509`). Referenced
  by the protocol spec as `[@!I-D.hardt-httpbis-signature-key]`. Downloaded
  2026-06-09 from <https://www.ietf.org/archive/id/draft-hardt-httpbis-signature-key-04.txt>
  (Internet-Draft, 9 April 2026 revision).
- `upcoming-changes-02.md` — Notes tracking the confirmed draft-02 deltas while the
  -02 draft was still pending. Superseded by `v02/` now that draft-02 is published;
  retained for the migration trail.

## `v02/` — protocol draft-02

| Field | Value |
|---|---|
| Source repository | <https://github.com/dickhardt/AAuth> |
| Commit | `feda56b04ef9d631abab71bdbb6bbb80b007872f` |
| Commit date | 2026-06-09 |
| Tagged version | `draft-hardt-oauth-aauth-protocol-02` |
| IETF draft | <https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/02/> |
| Copied on | 2026-06-09 |

- `draft-hardt-oauth-aauth-protocol.md` — Main AAuth protocol specification (draft-02)
- `draft-hardt-aauth-bootstrap.md` — Agent bootstrap guidance (draft-01, unchanged from `v01/`)
- `draft-hardt-aauth-r3.md` — Rich Resource Requests (R3) specification (draft-00, revised)
- `draft-hardt-httpbis-signature-key-04.txt` — HTTP Signature Keys (Internet-Draft, draft-04;
  duplicated from `v01/`, referenced by the protocol spec as `[@!I-D.hardt-httpbis-signature-key]`).

### Notable draft-02 changes

- Sub-agents: agent token `parent_agent` claim, single-level depth, parent-mediated
  authorization with a `subagent_token` parameter, and the `+` sub-agent local-part delimiter.
- Renamed the terminal `interaction_required` error to `user_unreachable`; added
  `interaction_unavailable` (424) and PS-first interaction relay; added the `max_wait`
  interaction parameter.
- Added `capabilities` and OIDC `prompt` request parameters to the PS token endpoint.
- Added `requirement=agent-token` (401) and an `access_mode` resource-metadata field.
- Added an OPTIONAL Markdown `description` field to each well-known metadata document.
- Named the `{approver, s256}` pair the "mission reference" and used it consistently.

## `v08/` — protocol draft-08

> This is the version the SDK targets (migrated 2026-06-25). See the intro and
> [`CHANGELOG.md`](CHANGELOG.md) for the draft-02 → draft-08 delta.

| Field | Value |
|---|---|
| Source repository | <https://github.com/dickhardt/AAuth> |
| Commit | `dd2b8524eb8a6beb1a6cd922f285cc8bd0464cd8` |
| Commit date | 2026-06-25 |
| Tagged version | `draft-hardt-oauth-aauth-protocol-08` |
| Document date | 2026-06-17 |
| IETF draft | <https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/08/> |
| Copied on | 2026-06-25 |

- `draft-hardt-oauth-aauth-protocol.md` — Main AAuth protocol specification (draft-08)
- `draft-hardt-aauth-bootstrap.md` — Agent bootstrap guidance (draft-01, byte-identical
  to `v01/` and `v02/`)
- `draft-hardt-aauth-r3.md` — Rich Resource Requests (R3) specification (draft-00,
  byte-identical to `v02/`)
- `interop-demo-profile.md` — Interoperability Demo Profile (informational; **new** in
  this snapshot — extracted from the protocol spec in draft-06). Describes the minimum
  live surfaces for an end-to-end interop demo.
- `draft-hardt-httpbis-signature-key-05.txt` — HTTP Signature Keys (Internet-Draft,
  draft-05; bumped from draft-04 in `v01/`/`v02/`). The Signature Keys spec now lives in
  its own repository (<https://github.com/dickhardt/signature-key>); the protocol
  references it as `[@!I-D.hardt-httpbis-signature-key]`. Downloaded 2026-06-25 from
  <https://www.ietf.org/archive/id/draft-hardt-httpbis-signature-key-05.txt>
  (Internet-Draft, 17 June 2026 revision).

### Notable changes since draft-02

draft-08 bundles six published protocol drafts (03 → 08). The headline deltas:

- **Structural reorg**: `Multi-Hop Resource Access` and `Sub-Agents` are now
  subsections of a new top-level `# Agent Delegation` section; the sub-agent
  subsections collapsed into a single `## Delegation Chain`.
- **Auth-token `act` semantics** (drafts 04–05): `act` is now OPTIONAL (absent in
  direct authorization); `act.sub` replaced by `act.agent` identifying the immediate
  upstream agent (the delegator, not the presenter); nesting records the full chain.
- **Call-chaining binding** (draft-08): upstream token `aud` MUST equal the `iss` of
  the intermediary's agent token; PS/AS routing is derived from the upstream auth token
  (`mission.approver` or `iss`), not the caller's `ps` claim.
- **Interaction code** clarified as a correlation identifier, not an authorization
  credential (the code alone MUST NOT authorize the decision).
- **New `## Interaction Callback Errors`** (draft-07) defining the `?error=` redirect
  wire format and PS-to-polling error mapping.
- **Metadata** (draft-03): common-fields table across all four well-known docs,
  documented RFC 9728 divergences, and a `documentation_uri` field on the agent,
  person, and access metadata documents.
- **New `## PS Approval Endpoint Authentication`** section and an implementation-clarity
  pass (draft-06): `AAuth-Requirement`/`AAuth-Access`/`AAuth-Capabilities` grammar,
  JWKS same-`kid` refresh, and structured `cnf.jwk` verification ordering.

## `v09/` — protocol draft-09

> This is the latest upstream reference. The SDK continues to target draft-08
> until the separate draft-09 migration is complete.

| Field | Value |
|---|---|
| Source repository | <https://github.com/dickhardt/AAuth> |
| Commit | `90089f80eaccccbd22e32e06946e2aa08f7d67fe` |
| Commit date | 2026-07-05 |
| Tagged version | `draft-hardt-oauth-aauth-protocol-09` |
| Source document date | 2026-06-17 |
| IETF publication date | 2026-07-04 |
| IETF draft | <https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/09/> |
| Copied on | 2026-07-19 |

- `draft-hardt-oauth-aauth-protocol.md` — Main AAuth protocol specification
  (draft-09).
- `draft-hardt-aauth-bootstrap.md` — Agent bootstrap guidance (draft-01,
  byte-identical to `v08/`).
- `draft-hardt-aauth-r3.md` — Rich Resource Requests (R3) specification
  (draft-00, revised to integrate AAuth Events subscriptions).
- `interop-demo-profile.md` — Interoperability Demo Profile (informational,
  byte-identical to `v08/`).
- `draft-hardt-aauth-events.md` — AAuth Events companion specification
  (draft-00, **new** in this snapshot). It is present at the pinned protocol tag
  but did not yet have its own published tag or Datatracker revision when copied.
- `draft-hardt-httpbis-signature-key-06.txt` — HTTP Signature Keys
  (Internet-Draft, draft-06; bumped from draft-05 in `v08/`). The published
  protocol draft-09 resolves its reference to draft-06, so this snapshot keeps
  that historical dependency even though a newer revision now exists. Downloaded
  2026-07-19 from
  <https://www.ietf.org/archive/id/draft-hardt-httpbis-signature-key-06.txt>
  (Internet-Draft, 2 July 2026 revision).

### Notable changes since draft-08

- Clarification-chat POST bodies now require an `action` discriminator with
  `clarification_response` or `updated_request`; missing or unknown values are
  rejected with `400 Bad Request`.
- AAuth JSON errors now use RFC 9457 problem details with
  `Content-Type: application/problem+json`; `error` remains the required AAuth
  extension member and `detail` replaces `error_description`.
- The protocol adds AAuth Events integration: APs can publish an
  `event_endpoint`, act as event routers, and recognize the new
  `aa-subscribe+jwt` and `aa-event+jwt` token types.
- The new AAuth Events draft defines subscription registration and signed event
  delivery through an Agent Provider. R3's AsyncAPI vocabulary now links granted
  subscription operations to that protocol and makes its `action` field optional.
- HTTP Signature Keys advances from draft-05 to draft-06, adding the `self-jwt`
  scheme for self-issued JWTs.

## `v10/` — protocol draft-10

> This is the latest upstream reference. The SDK continues to target draft-08;
> draft-09 and draft-10 migrations remain separate implementation work.

| Field | Value |
|---|---|
| Source repository | <https://github.com/dickhardt/AAuth> |
| Commit | `9dee49fbf49074d1460d0a7c0670bf355aef5e1e` |
| Commit date | 2026-08-06 |
| Tagged version | `draft-hardt-oauth-aauth-protocol-10` |
| Source document date | 2026-06-17 |
| IETF publication date | 2026-08-06 |
| IETF draft | <https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/10/> |
| Copied on | 2026-09-08 |

- `draft-hardt-oauth-aauth-protocol.md` — Main AAuth protocol specification
  (draft-10).
- `draft-hardt-aauth-bootstrap.md` — Agent bootstrap guidance (draft-02,
  revised with fully specified algorithm examples and a Datatracker protocol
  reference).
- `draft-hardt-aauth-r3.md` — Rich Resource Requests specification (draft-01,
  revised with account binding, operation-identifier scoping, and the OpenAPI
  Gateway vocabulary).
- `interop-demo-profile.md` — Interoperability Demo Profile (informational,
  byte-identical to `v09/`).
- `draft-hardt-aauth-events.md` — AAuth Events companion specification
  (draft-00, revised to use the HTTP Signature Keys `self-jwt` scheme for event
  delivery and fully specified algorithms).
- `draft-hardt-httpbis-signature-key-08.txt` — HTTP Signature Keys
  (Internet-Draft, draft-08; bumped from draft-06 in `v09/`; draft-07 was
  editorial only). Downloaded 2026-09-08 from
  <https://www.ietf.org/archive/id/draft-hardt-httpbis-signature-key-08.txt>
  (Internet-Draft, 5 August 2026 revision).

### Notable changes since draft-09

- AAuth keys now require fully specified `alg` identifiers. `Ed25519` replaces
  deprecated `EdDSA`; `none`, symmetric algorithms, and key/algorithm mismatches
  are rejected.
- Signature verification aligns with HTTP Signature Keys draft-08, including
  defined scheme, algorithm, key, and issuer errors; signature failures use
  `401`, while a `403` must not carry signature error or negotiation headers.
- Revocation identifies tokens by `(iss, jti)`, including agent-token revocation
  by an AP through the PS's revocation endpoint.
- Downstream issuers cannot copy directed `sub` values from upstream tokens or
  place person identifiers in `act`.
- The authorization request gains optional `account` binding, propagated through
  resource and auth tokens. R3 carries the same value and adds display guidance.
- R3 adds operation-identifier scoping and an OpenAPI Gateway vocabulary. Events
  switches resource-to-AP delivery to `self-jwt`; Bootstrap advances to draft-02.
- HTTP Signature Keys draft-08 adds `jwks`, assertion caching, fully specified
  algorithm rules, stricter covered-component and expiry requirements, and new
  negotiation and error handling.
