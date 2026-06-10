# AAuth Specification Version

These spec files were copied from the [AAuth](https://github.com/dickhardt/AAuth)
repository for reference while building the .NET samples. They are grouped by the
AAuth protocol draft version under [`v01/`](v01/) and [`v02/`](v02/). Each folder is
a self-contained snapshot, so shared documents (the HTTP Signature Keys draft) are
duplicated into both.

The SDK targets **draft-02** ([`v02/`](v02/)) — migrated from draft-01 in the
2026-06-09 migration (see `.agent/plans/2026-06-09-aauth-v02-spec-migration/`).
The draft-01 snapshot ([`v01/`](v01/)) is retained for reference. One item is
deferred: four-party AS federation of sub-agents (the three-party parent-mediated
path is complete).

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
