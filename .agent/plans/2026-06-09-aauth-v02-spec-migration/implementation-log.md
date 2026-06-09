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

### [2026-06-09] [Phase 0] Decision gate closed — all Q1–Q9 ruled
- All nine open questions resolved (see the section below, each flipped to
  `RESOLVED`). Rulings are grounded in direct code reads of the affected seams
  (`AAuthTokenExchangeException`, `AAuthAccessMode`, `IInteractionRelay`,
  `TokenExchangeRequest`, `Interaction`/`GovernanceEndpoints`) rather than the
  subagent summaries alone. Two rulings refine the research framing:
  - **Q3:** the server challenge enum (`AAuthAccessMode`) and the wire metadata
    `access_mode` field are *distinct concepts*. Keep the enum (add one value);
    model the wire field separately. The research's "rename the enum to match
    spec" conflated the two.
  - **Q4:** there is no interaction-code generator in the SDK today, but the SDK
    *does* emit server-side 202 interaction challenges, so it owns the generator
    + validator (the code is the only secret guarding the interaction URL).

---

## Deviations from plan

### [2026-06-09] [Phase 1] Latent test bugs exposed by the new metadata issuer check — RESOLVED
- The host-binding check (Phase 1b) surfaced pre-existing test bugs where mock
  metadata declared an `issuer` that did not match the origin it was served from
  — invisible before because nothing verified it. Fixed the fixtures, not the
  check:
  - `tests/AAuth.Tests/Integration/MissionAgentFlowTests.cs` built resource
    tokens with `iss = https://trips.test` while `ResourceStub` served metadata
    declaring `issuer: https://calendar.test` and signed with the stub's key.
    PS-side resource-token verification fetches the resource metadata, so the
    mismatch now (correctly) fails as `invalid_resource_token`. Aligned the const
    to `ResourceStub.Url` (7 rows fixed).
  - `tests/AAuth.Conformance/Observability/ActivityDiagnosticsTests.cs` served PS
    metadata with **no `issuer`** at all (3 spans). Added the matching issuer
    (`http://localhost:9999/9998/9997`) — what a real PS emits.
- **Why fixtures, not the check:** the check is spec-mandated (§Metadata
  Documents) and the fixtures were internally inconsistent; production behavior
  is correct. This is exactly the host-poisoning class the MUST exists to prevent.

### [2026-06-09] [Phase 1] Metadata issuer comparison is authority-based — PROCEEDED
- The spec says compare the document `issuer` to "the URL minus the
  `/.well-known/{dwk}` suffix." Since AAuth server identifiers are scheme + host
  only (§Server Identifiers — no port/path/query), the expected issuer is the
  fetch URL's authority (`Uri.GetLeftPart(UriPartial.Authority)`), which is also
  exactly what `MetadataClient.BuildUrl` uses in the forward direction. Ordinal
  comparison; a missing/blank/non-string `issuer` is rejected too (cannot verify
  ⇒ MUST reject). Revert to a literal suffix-strip if a non-root-hosted
  well-known ever appears (it should not under RFC 8615).

---

## Open questions / inputs needed

> Mirrors `research.md` Gaps & Open Questions and Phase 0. All resolved
> 2026-06-09 as `PROCEEDED (default X)` — revert any you disagree with.

### [2026-06-09] [Phase 0] Q1 — `user_unreachable` status code — RESOLVED
- **Ruling: 403.** Published draft-02 (L2194) specifies **403**; verified
  directly. Supersedes the planning note's 400. Phase 1a changes
  [DeferredExchange.cs](../../../src/AAuth/Agent/DeferredExchange.cs) L191 and the docs/tests
  that cite 400.

### [2026-06-09] [Phase 0] Q2 — Metadata issuer-mismatch exception type — RESOLVED
- **Ruling: new typed `AAuthMetadataException`.** Matches the existing
  `AAuth*Exception` family (`AAuthTokenExchangeException`,
  `AAuthMissionTerminatedException`, `AAuthPaymentRequiredException`) so callers
  can branch on a security-relevant rejection instead of catching a generic
  `InvalidOperationException`. Carries the document URL, the claimed `issuer`,
  and the expected issuer.

### [2026-06-09] [Phase 0] Q3 — `AAuthAccessMode` additive vs rename — RESOLVED
- **Ruling: additive + decouple.** Keep `IdentityOnly`/`RequireAuthToken` (an
  internal server *challenge* concept — renaming is churn with no spec-accuracy
  gain) and **add** `AgentTokenRequired` for the `requirement=agent-token` 401.
  Model the wire metadata `access_mode` field **separately** as string constants
  (`agent-token` / `aauth-access-token` / `auth-token`) on the metadata models —
  it is an advisory wire declaration, distinct from the challenge enum.

### [2026-06-09] [Phase 0] Q4 — Interaction-code generator ownership — RESOLVED
- **Ruling: SDK owns a Crockford base32 generator + validator.** The SDK
  implements server roles that emit 202 interaction challenges, and the code is
  the only secret guarding the interaction URL, so a correct centralized utility
  belongs here (new `InteractionCode` type: generate ≥40-bit CSPRNG codes;
  validate with hyphen-strip, glyph-fold I/L→1 O→0, single-use + rate-limit
  hooks). Server-side emission uses it; the agent keeps reading codes as opaque
  via [Interaction.cs](../../../src/AAuth/Headers/Interaction.cs).

### [2026-06-09] [Phase 0] Q5 — `interaction_unavailable` (424) surface — RESOLVED
- **Ruling: structured outcome, not an exception.** 424 is non-terminal and
  falling back to directing the user is the *normal* path, so an exception is the
  wrong shape. Add an `Unavailable` outcome to `InteractionRelayResult` (PS side)
  and surface 424 on the agent `InteractionClient` as a non-throwing result the
  caller acts on. Consistent with the existing record-based relay result.

### [2026-06-09] [Phase 0] Q6 — Markdown sanitization ownership — RESOLVED
- **Ruling: documented UI responsibility; no SDK sanitizer dependency.** The SDK
  is a library and never renders; the spec MUST is "before rendering to users."
  Continue the existing pattern (the `Mission`/`ClarificationRequirement` doc
  comments already say consumers MUST sanitize) for the new `description` fields.
  Docs surface the requirement at the render boundary.

### [2026-06-09] [Phase 0] Q7 — `prompt`/`capabilities` strictness + `provider_hint` — RESOLVED
- **Ruling: tolerant pass-through; refresh = replace; bag for extensions.**
  (a) Do not reject unknown `prompt`/`capability` values at the SDK boundary
  (forward-compat; matches "recipients MUST ignore unrecognized capability
  values"). (b) Within a mission, supplied `capabilities` **replace** the
  approval-time values for that request ("refreshes them for this request").
  (c) Add `AdditionalParameters` (`string`→`JsonNode`) to `TokenExchangeRequest`
  so PS-specific params like `provider_hint` ride an extensibility hook rather
  than becoming first-class fields.

### [2026-06-09] [Phase 0] Q8 — Sub-agent error taxonomy — RESOLVED
- **Ruling: reuse `invalid_request`.** The spec defines no new codes for these,
  and the principle is to fit the existing taxonomy. Both the single-level-depth
  violation (a sub-agent signing a direct request) and a `subagent_token`
  `parent_agent` mismatch are disallowed/malformed requests → `invalid_request`
  with distinct `error_description` text. A `subagent_token` that is itself
  malformed/expired still uses `invalid_agent_token` / `expired_agent_token`.

### [2026-06-09] [Phase 0] Q9 — No-back-compat posture — RESOLVED
- **Ruling: confirmed.** Spec-accurate alpha SDK; breaking renames/removals are
  acceptable for spec accuracy; single coordinated cutover; no dual-format shims.
  Carries from the 2026-06-09 jkt-jwt work.
