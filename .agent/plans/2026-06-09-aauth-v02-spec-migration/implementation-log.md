# Implementation Log — Decisions, Deviations & Open Questions

> Living log for the AAuth protocol **draft-02** migration. Maintained by the
> implementing agent while the owner reviews at the end. See
> [implementation-plan.md](implementation-plan.md) and [research.md](research.md)
> for the agreed design.

## How to read this

- **Decisions taken** — choices made to keep moving, with rationale. Revert if you disagree.
- **Deviations from plan** — where reality differed from the plan/research.
- **Open questions / inputs needed** — things wanting an owner ruling.

Each entry: `[YYYY-MM-DD] [Phase N] <title>` with status
`PROCEEDED (default X)` / `BLOCKED` / `RESOLVED`.

---

## Decisions taken

### [2026-06-09] [Grounding] Published draft-02 is the authoritative target
- **Source of truth:** [`aauth-spec/v02/draft-hardt-oauth-aauth-protocol.md`](../../../aauth-spec/v02/draft-hardt-oauth-aauth-protocol.md)
  (commit `feda56b`), with the v01→v02 delta catalogued in
  [`aauth-spec/CHANGELOG.md`](../../../aauth-spec/CHANGELOG.md).
- **Precedence rule:** where the pre-publication planning note
  [`upcoming-changes-02.md`](../../../aauth-spec/v01/upcoming-changes-02.md)
  disagrees with the published draft, the **published draft wins**. The one known
  conflict is the `user_unreachable` status code (note proposed 400; published
  draft-02 specifies 403 at L2194 — verified directly).

### [2026-06-09] [Grounding] No-back-compat posture carried from the jkt-jwt work
- **Owner principle (prior work):** *"this repo is a spec-accurate alpha SDK; do
  whatever is needed to be spec-accurate."* Applied here pending explicit
  confirmation (Phase 0 / Q9): breaking renames and removals are acceptable when
  they buy spec accuracy; no dual-format shims.

---

## Deviations from plan

_None yet — research only. Entries land as phases execute._

---

## Open questions / inputs needed

> Mirrors `research.md` Gaps & Open Questions and Phase 0. Status starts as
> `BLOCKED` (awaiting owner) and flips to `RESOLVED` with the ruling recorded.

### [2026-06-09] [Phase 0] Q1 — `user_unreachable` status code — BLOCKED
- Published draft-02 (L2194) specifies **403**; the SDK currently emits **400**
  ([DeferredExchange.cs](../../../src/AAuth/Agent/DeferredExchange.cs) L191), inherited
  from the planning note. Plan assumes 403. Confirm.

### [2026-06-09] [Phase 0] Q2 — Metadata issuer-mismatch exception type — BLOCKED
- New `MetadataVerificationException` vs reuse `InvalidOperationException` for the
  host-binding rejection in `MetadataClient.FetchAsync`.

### [2026-06-09] [Phase 0] Q3 — `AAuthAccessMode` additive vs rename — BLOCKED
- Add an `AgentTokenRequired` value additively, or rename existing
  `IdentityOnly`/`RequireAuthToken` to match spec wording (breaking).

### [2026-06-09] [Phase 0] Q4 — Interaction-code generator ownership — BLOCKED
- Does the SDK ship a Crockford base32 generator/validator (security-critical),
  or is generation PS/resource-only with SDK validation helpers?

### [2026-06-09] [Phase 0] Q5 — `interaction_unavailable` (424) surface — BLOCKED
- New exception parallel to polling errors, or an `Unavailable` outcome on the
  `IInteractionRelay` contract.

### [2026-06-09] [Phase 0] Q6 — Markdown sanitization ownership — BLOCKED
- SDK-integrated sanitizer for `description`/justification fields vs documented
  UI-layer responsibility. SDK is a library, not a renderer.

### [2026-06-09] [Phase 0] Q7 — `prompt`/`capabilities` strictness + `provider_hint` — BLOCKED
- Reject unknown values or pass through for forward-compat; whether
  mission-scoped `capabilities` override or merge approval-time values; whether
  `provider_hint` rides an extensibility hook.

### [2026-06-09] [Phase 0] Q8 — Sub-agent error taxonomy — BLOCKED
- Error codes for single-level-depth violation and `subagent_token.parent_agent`
  mismatch.

### [2026-06-09] [Phase 0] Q9 — No-back-compat posture — BLOCKED
- Confirm the spec-accurate-alpha / no-back-compat posture governs this migration
  (it informs every breaking choice in the plan).
