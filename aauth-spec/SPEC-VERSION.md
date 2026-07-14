# AAuth Specification Version

These spec files were copied from the [AAuth](https://github.com/dickhardt/AAuth)
repository for reference while building the .NET samples. They are grouped by the
AAuth protocol draft version under [`v01/`](v01/), [`v02/`](v02/), and
[`v08/`](v08/), and [`v09/`](v09/). Each folder is a self-contained snapshot, so
each carries its own copy of the HTTP Signature Keys draft at the version that
snapshot's protocol references.

The GitHub repository is the working source we vendor from. The canonical,
permanent home is the **IETF Datatracker**, which retains every published revision
(and its `.txt` / `.html` renderings) even if the GitHub repo is moved or
deprecated. Use it as the source of record and fallback:

- Datatracker document — <https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/>
- Per-revision text (example) — <https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-08.txt>

The vendored `.md` files are the upstream kramdown source; if the GitHub repo is
unavailable, the Datatracker `.txt`/`.html` renderings are the authoritative
substitute.

The SDK code now targets **draft-08** ([`v08/`](v08/)) — migrated from draft-02 in
the 2026-06-25 migration (see `.agent/plans/2026-06-25-aauth-v08-spec-migration/`).
All four resource access modes are implemented, including the `AAuth-Access`
opaque-token flow (resource-managed, two-party access), added under
`.agent/plans/2026-06-25-aauth-access-token-flow/`. The runnable four-party
sub-agent (S5) interop demo is deferred, though the parent-mediated code path
is implemented and conformance-tested.

`v08/` remains the version the SDK conforms to. The latest upstream reference is
draft-09 ([`v09/`](v09/)), vendored 2026-07-14; it includes the newly added AAuth
Events draft. The earlier draft-02 ([`v02/`](v02/)) and draft-01
([`v01/`](v01/)) snapshots are retained for reference.

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

> This is the latest upstream reference snapshot. The SDK still targets draft-08;
> vendoring draft-09 does not migrate SDK behavior.

| Field | Value |
|---|---|
| Source repository | <https://github.com/dickhardt/AAuth> |
| Commit | `90089f80eaccccbd22e32e06946e2aa08f7d67fe` |
| Commit date | 2026-07-05 |
| Tagged version | `draft-hardt-oauth-aauth-protocol-09` |
| Protocol document date | 2026-06-17 |
| AAuth Events document date | 2026-06-24 |
| IETF draft | <https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/09/> |
| Copied on | 2026-07-14 |

- `draft-hardt-oauth-aauth-protocol.md` — Main AAuth protocol specification
  (draft-09)
- `draft-hardt-aauth-bootstrap.md` — Agent bootstrap guidance (draft-01,
  byte-identical to `v08/`)
- `draft-hardt-aauth-r3.md` — Rich Resource Requests (R3) specification (draft-00,
  revised from `v08/` to connect its AsyncAPI vocabulary to AAuth Events)
- `draft-hardt-aauth-events.md` — AAuth Events specification (draft-00; **new** in
  this snapshot). The tagged editor's copy is pinned by the snapshot commit; no
  IETF Datatracker revision had been published as of the copied-on date.
- `interop-demo-profile.md` — Interoperability Demo Profile (informational,
  byte-identical to `v08/`)
- `draft-hardt-httpbis-signature-key-06.txt` — HTTP Signature Keys
  (Internet-Draft, draft-06; bumped from draft-05 in `v08/`). Downloaded
  2026-07-14 from
  <https://www.ietf.org/archive/id/draft-hardt-httpbis-signature-key-06.txt>
  (Internet-Draft, 2 July 2026 revision). The published protocol draft-09 cites
  this revision.

### Notable changes since draft-08

- **AAuth Events draft-00** adds AP-routed asynchronous events, subscribe and
  event tokens, public and protected subscription registration, and AsyncAPI/R3
  discovery.
- **Protocol integration for Events** adds the AP `event_endpoint` metadata field,
  describes the AP's event-router role, and references the `aa-subscribe+jwt` and
  `aa-event+jwt` types.
- **Clarification responses** now require an explicit `action` discriminator with
  `clarification_response` or `updated_request`.
- **Error responses** now use RFC 9457 problem details with
  `Content-Type: application/problem+json`, the AAuth `error` extension member,
  and `detail` instead of `error_description`.
- **R3 AsyncAPI vocabulary** now links granted event operations to the AAuth
  Events subscription-ticket and subscribe-token flow.
- **HTTP Signature Keys draft-06** adds the `self-jwt` scheme for a self-issued
  JWT whose discovered signing key also verifies the HTTP message signature.
