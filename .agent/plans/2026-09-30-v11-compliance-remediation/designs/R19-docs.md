# R19 — Docs rewrite inventory

Findings: DOC-01, DOC-02, DOC-03, DOC-04, DOC-05, DOC-06, DOC-07, D01-01, D01-04, D02-02, D02-03, D03-02, D03-03, D03-04, D04-001, D04-002, D05-01, D05-02, D05-03, D06-02, D06-03, D06-04, D06-05, D07-02, D07-04, D07-05, D08-01, D08-02, D08-03, D08-05, D09-01, D10-01, D10-02, D10-03, D10-04, D10-05, D10-06, D10-07, LOW sweep. Spec: #requirement-person-token L615, #person-token-endpoint L801, #resource-token L725-L760, #ps-token-endpoint L924-L968, #auth-token-structure L1768-L1790, #keying-material L2179/L2196, #verification L2254, #revocation-cascade L2752, #polling-error-codes L2621-L2628. Files read: audit docs section in `.agent/plans/2026-09-30-v11-compliance-audit/research.md`, every file under `.agent/plans/2026-09-30-v11-compliance-audit/findings/docs/`, `docs/getting-started.md`, `docs/signing-modes/agent-identity-jwks-uri.md`, `README.md`, `aauth-spec/SPEC-VERSION.md`, `tests/AAuth.Tests/Api/DocumentationInventory.cs`, `DocumentationLinkTests.cs`, and `SnippetCompilationTests.cs`.

## Problem restated (verified)

- The primary doc defect is not API design; it is stale or unsafe prose. `docs/getting-started.md:160-223` still teaches a draft-10 three-party flow: an agent token reaches the resource, the resource reads `ps` from that token, the PS request is only `{"resource_token": ...}`, and no `presented_token`/`presented_jti` pair is verified. Draft-11 requires an initial `requirement=person-token` path (#requirement-person-token L615), a PS person-token endpoint (#person-token-endpoint L801), resource tokens copied from a verified person/auth token (#resource-token L725-L760), and auth-token requests containing both `resource_token` and `presented_token` (#ps-token-endpoint L924-L968).
- `docs/signing-modes/agent-identity-jwks-uri.md:18-50` and `:72`, plus the jkt-jwt rotation pages, present generic Signature-Key schemes as AAuth agent-to-resource credentials. Draft-11 AAuth resource requests use `sig=jwt`; `jwks_uri`/`jwks` are server/generic Signature-Key schemes, and `jkt-jwt` is reserved for AP key refresh (#keying-material L2179/L2196).
- Several docs are wrong independently of SDK fixes: access-mode tables still say “four modes” or “PS-Asserted”; `getting-started.md:232-238` marks auth-token `sub` optional even though it is required (#auth-token-structure L1768-L1790); role examples ignore issuer context; deferred examples use non-parseable `AAuth-Requirement` shorthand; error/config docs omit current machine-readable codes and options.
- A second class of docs should not be redesigned in R19 because they describe SDK defects owned by other remediation areas. They should be inventoried as “update after Rnn lands” with exact file:line so the docs sweep can align with the code cutover rather than documenting temporary bugs as guidance.
- The doc gates are active. `DocumentationInventory.Files()` inventories `README.md`, `docs/**`, `src/**/*.md`, and sample snippets; `SnippetCompilationTests.Documentation_CompilationProbe` compiles Markdown C# fences; `Documentation_FrozenSurface` requires `.agent/plans/2026-09-11-aauth-v11-spec-migration/docs-surface-map.md` to be regenerated with `AAUTH_UPDATE_DOCS_INVENTORY=1`; `DocumentationLinkTests` checks local links/anchors in active docs plus `aauth-spec/SPEC-VERSION.md` and `CHANGELOG.md`.

## Candidate fixes

| # | Approach | Pros | Cons | Spec fit | API-surface fit (C1–C13) |
|---|---|---|---|---|---|
| 1 | Patch individual paragraphs only where the audit named a line. | Smallest diff and low risk. | Keeps the entry docs fragmented; misses repeated stale terms; cannot explain draft-11 flow coherently. | Partial: fixes isolated lines but not the mental model. | Weak C13: repeated fences/inventory churn likely. |
| 2 | Rewrite the entry walkthrough and signing-mode pages first, then perform a doc-inventory sweep table by finding ID, with SDK-dependent rows deferred to their Rnn. | Gives readers one draft-11 flow; avoids redesigning code-owned gaps; aligns docs and gates in one pass. | Requires coordinated updates to README, docs-surface inventory, and snippet tests. | Strong: spec citations map directly to the walkthrough steps. | Strong C1/C13: single cutover, no compat language, gates explicit. |
| 3 | Defer all docs until every SDK remediation area lands. | Avoids temporary wording. | Leaves high-risk copy/paste guidance in place; DOC-01/DOC-02 are docs-only enough to fix now. | Poor: known non-conformant docs remain published. | Poor C13: docs gate debt accumulates. |

## Recommendation

Adopt candidate 2. First rewrite `getting-started.md` and signing-mode/key-management prose so the public path teaches draft-11 only. Then run a structured docs sweep using the table below: rows with `N/A` can be fixed immediately; rows with `Rnn` must wait for that remediation branch to land and should be changed to the final conformant behavior, not to an interim workaround.

Adversarial check: a conforming peer will reject every stale wire shape named here (`AAuth-Requirement: interaction`, `{"resource_token": ...}` without `presented_token`, bare `Signature-Error: invalid_signature`, `jwks_uri` AAuth agent credentials). The rewrite must therefore remove copyable invalid snippets, not merely add warnings below them.

## Public API delta

N/A for docs. ApiSurface should not change because R19 only rewrites Markdown/prose and snippet text.

## Wire effect

N/A for docs. The rewritten docs describe wire changes owned by draft-11 and other Rnn areas, but R19 itself must not change runtime behavior.

## Implementation sketch

1. Rewrite `docs/getting-started.md` “Three-Party Flow Deep Dive” into a draft-11 PS authorization walkthrough:
   1. Agent sends first request with `aa-agent+jwt`; resource cannot identify a person and returns `401` with `AAuth-Requirement: requirement=person-token` (#requirement-person-token L615).
   2. Agent calls the PS `person_token_endpoint`, signing with the agent token and requesting `resource`, optional mission/context values (#person-token-endpoint L801).
   3. Agent retries the resource with `aa-person+jwt`; resource verifies it, then issues an `aa-resource+jwt` whose `ps`, `sub`, and `presented_jti` are copied from the person token and whose `aud` is PS or AS according to the access posture (#resource-token L725-L760).
   4. Agent posts to the PS auth-token endpoint with `resource_token` **and** `presented_token` equal to the person token named by `presented_jti`; include a JSON fence showing both parameters (#ps-token-endpoint L924-L968).
   5. PS/AS issues `aa-auth+jwt`; document required `aud`, `ps`, `sub`, `cnf`, bounded `exp`, and optional `scope`/identity claims (#auth-token-structure L1768-L1790).
   6. Agent retries with `aa-auth+jwt`; resource verifies signature, `aud`, `cnf`, trust, scope, revocation, and issuer-aware claim policy.
2. Replace “four modes” tables in README, docs overview, signing-mode overview, and package README with five rows: agent identity, resource-managed/session-token, person identity/person-token, PS authorization/auth-token, and AS-federated authorization/auth-token. Use draft-11 names; do not keep stale “PS-Asserted” except as a historical alias in one note if needed.
3. Rewrite `agent-identity-jwks-uri.md` as a generic Signature-Key/server-to-server page or move it under a non-AAuth-agent section. State that AAuth agent resource requests use `jwt`; remove resource-call examples that use `.UseJwksUri(...)` or `.UseJwks(...)` as agent credentials.
4. Rewrite jkt-jwt key-rotation docs to say AP key refresh may use `jkt-jwt`, but resource-facing AAuth requests continue with returned `jwt` tokens and old auth tokens require re-authorization when the bound key changes.
5. Apply immediate `N/A` rows in the inventory. For SDK-dependent rows, add or keep a local TODO only in the implementation plan/log of the owning Rnn, not in published docs, until the owning fix lands.
6. After every Markdown/snippet edit, regenerate the docs inventory and update links/frozen hashes. Keep all new C# fences either exact-compilable, an `DocumentationApiExcerpts` excerpt, or an `ExternalTemplate` already recognized by `SnippetCompilationTests`.

### Doc change inventory

| Doc file | Lines | Change | Depends on Rnn | Gate impact |
|---|---:|---|---|---|
| `docs/getting-started.md` | 140-147, 160-223, 232-238 | Replace four-mode table and draft-10 PS authorization sequence with the draft-11 person-token → resource-token → `presented_token` auth-token flow; make auth-token `sub` required. | N/A | Markdown/C# fences must compile; frozen docs inventory hash changes. |
| `docs/signing-modes/agent-identity-jwks-uri.md` | 18-50, 72 | Stop teaching `jwks_uri`/`jwks` as AAuth agent-to-resource signing; scope page to generic/server Signature-Key or remove examples. | N/A | C# fences likely change; inventory hash and link anchors must update. |
| `docs/advanced/key-management.md` | 180-184, 222 | Recast `jkt-jwt` as AP key-refresh only; explain resource-facing JWT re-authorization after key change. | N/A | C# fences and frozen inventory. |
| `docs/signing-modes/key-rotation-jkt-jwt.md` | 16, 50, 79 | Rename/rewrite from resource-visible rotation to AP refresh ceremony; remove any claim that old auth tokens remain valid. | N/A | Link anchors may change; link test and inventory. |
| `docs/README.md` | 3-5 | Update entry summary from four modes to draft-11 five modes and terms. | N/A | Link/inventory only. |
| `docs/concepts.md` | 42-47 | Add person identity/person-token mode; replace stale PS-Asserted terminology. | N/A | Link/inventory only. |
| `README.md` | 14, 35-42 | Point spec link at `aauth-spec/v11/...`; list five access modes including person identity. | N/A | Link test covers v11 path; README is in docs inventory. |
| `src/AAuth/README.md` | 37-44 | Update package README access-mode table to five modes and draft-11 names. | N/A | Inventory includes `src/**/*.md`; snippet/link checks. |
| `docs/signing-modes/overview.md` | 113-126 | Add person-token mode row and replace stale PS-Asserted wording. | N/A | Existing targeted snippet tests read this file; inventory hash. |
| `docs/signing-modes/agent-token-jwt.md` | 13 | Replace stale “PS-asserted” term with “PS authorization” and distinguish person-token. | N/A | Link/inventory only. |
| `docs/server/challenge-middleware.md` | 39-40 | Avoid claiming `AgentTokenRequired` excludes person/auth tokens unless R03 changes code; either document exact final carrier semantics after R03 or use a neutral challenge description. | R03 if code semantics change; otherwise N/A wording fix | Link/inventory only. |
| `docs/server/multi-scheme-verification.md` | 101-132 | Replace resolver-exception issuer policy with post-verification trust/authorization policy guidance that yields 403. | N/A | C# fence may change; snippet compile and inventory. |
| `docs/server/authorization-policies.md` | 74-87, 103-109 | Change role examples to issuer-aware policies; warn `RequireRole`/role helpers match role value only unless namespaced. | N/A | C# fences compile; targeted docs tests may need assertions. |
| `docs/server/authn-authz.md` | 221-230, 234-236 | Mirror issuer-aware role guidance and warnings for framework policies. | N/A | C# fences compile; inventory. |
| `docs/workflows/deferred-consent.md` | 5, 17 | Replace JSON `interaction_url`/`pending_url` mental model with `Location`, `Retry-After`, `Cache-Control: no-store`, and structured `AAuth-Requirement`. | N/A | HTTP fences are frozen inventory; link anchors unchanged. |
| `docs/workflows/resource-managed-access.md` | 34, 202 | Use `AAuth-Requirement: requirement=interaction; url=...; code=...` and `Location`; remove shorthand `interaction`. | N/A | HTTP fence inventory; link test. |
| `docs/workflows/ps-asserted-access.md` | 199-204 | Remove invented resource-token `error` claim; describe problem+json or `Signature-Error` paths. | N/A | Link/inventory only. |
| `docs/workflows/rich-resource-requests.md` | 67 | Add required R3 `vocabulary` to the document shape. | N/A | Link/inventory; any JSON fence frozen hash. |
| `docs/advanced/error-handling.md` | 47-54, add revocation section | Fix `Signature-Error` examples to `error=...`; add revocation errors including `unsupported_iss`, `rate_limited` with `Retry-After`, `revocation_unsupported`, `revocation_unavailable`. | N/A | HTTP fences/hash; consider targeted assertion. |
| `docs/reference/configuration.md` | 35-46, 215-219, 229-239, 283-287 | Add omitted options/constructor parameters: `EgressPolicy`, `RequireBodyCoverage`, `ExpectedAccount`, metadata members, metadata cache/transport knobs, resolver dependencies. | N/A | `ConfigurationReferenceTests` and `DocumentationApiExcerpts` table checks. |
| `README.md`; `src/AAuth.Events/README.md`; `tests/AAuth.Conformance/README.md` | 14; 5; 7-10 | Normalize draft baseline/coverage claims to draft-11 and current vendored companion drafts. | N/A | Link tests; README inventory; source Markdown inventory. |
| `docs/workflows/federated-access.md` | 242-249 | LOW: add required `Retry-After` and `Cache-Control: no-store` to `202 requirement=claims` example. | N/A | HTTP fence frozen hash. |
| `docs/getting-started.md` | 459-480 | LOW: declare/reuse `keyStore` consistently in advanced AP fences. | N/A | C# snippet compile. |
| `docs/signing-modes/overview.md`; `agent-token-jwt.md`; `agent-identity-jwks-uri.md`; `key-rotation-jkt-jwt.md`; `pseudonymous-hwk.md` | 75-87; 88-94; 58-65; 57-64; 34-41 | LOW: add `using AAuth.HttpSig;` or fully qualify manual signature provider snippets. | N/A | C# snippet compile. |
| `docs/advanced/key-management.md` | 104-111 | LOW: change persisted key filenames to `*.jwk.json`. | N/A | Link/inventory only. |
| `docs/server/resource-metadata.md` | 30-77 | LOW: add `AccessMode`/`access_mode`, `AdditionalMetadata`, description/logo/docs/TOS/policy fields. | N/A | Targeted snippet/config tests and inventory. |
| `docs/server/multi-scheme-verification.md` | 33-59, 73 | LOW: fix “four/six schemes” inconsistency and Signature-Key draft-09 citation. | N/A | Link/inventory only. |
| `docs/server/token-issuance.md` | 343-344 | LOW: fix missing `federated-access.md` anchor. | N/A | `DocumentationLinkTests`. |
| `docs/server/mission-governance.md` | 121-126 | LOW: replace invented `invalid_carrier_token` with actual/spec error language. | N/A | HTTP fence/hash. |
| `docs/workflows/resource-managed-access.md` | 13-15 | LOW: include person tokens as valid `jwt` resource-request carriers. | N/A | Link/inventory only. |
| `docs/workflows/federated-access.md` | 86-93, 120-130 | LOW: add `using AAuth.Crypto;` for `AAuthSigningKeySet`. | N/A | C# snippet compile. |
| `docs/workflows/bootstrap-enrollment.md` | 207 | LOW: update `jkt-jwt` citation from Signature Keys draft-08 to draft-09. | N/A | Link/inventory only. |
| `docs/reference/configuration.md` | 334, 350 | LOW: distinguish nullable option initializer from effective builder default for `TokenRefreshThreshold` and `EgressPolicy`. | N/A | Configuration reference tests. |
| `docs/advanced/observability.md` | 48-50 | LOW: attribute `AAuth.DeferredPoll` spans to `DeferredExchange` / `AccessServerClient`, not `TokenExchangeClient`. | N/A | Link/inventory only. |

### SDK-dependent doc rows: update after Rnn lands

| Doc file | Lines | Change after owner lands | Depends on Rnn | Gate impact |
|---|---:|---|---|---|
| `docs/server/multi-scheme-verification.md` | 36-44 | Replace unsafe low-level `UseAAuthVerification()`/audience guidance with the R01 audience-bound API. | R01 | C# fence compile; inventory. |
| `docs/workflows/resource-managed-access.md` | 128-139 | Show authorization endpoint requiring a person token, not any signature. | R03 | C# fence compile; inventory. |
| `docs/advanced/interaction-chaining.md` | 19, 94, 107-118, 234 | Show intermediary-owned `202`, code, and `Location`; do not forward downstream code/url. | R05 | C# fence/HTTP fence inventory. |
| `docs/workflows/call-chaining.md` | 324, 371, 381 | Describe full upstream validation including PS records and revoked/unknown caller bindings. | R05 | C# fence compile; inventory. |
| `docs/workflows/rich-resource-requests.md` | 152-161 | Compose R3 approval with the single-use gate and retained result semantics. | R04 | C# fence compile; inventory. |
| `src/AAuth.R3/README.md` | 24, 63-66 | Claim per-call enforcement only after R04 closes replay semantics. | R04 | Source README inventory. |
| `docs/reference/dependency-injection.md` | 761-775 | Include `MapAAuthGovernance()` and correct `InteractionEndpointPath` in PS governance setup. | R12 | C# fence compile; inventory. |
| `docs/server/mission-governance.md` | 23-25, 34, 58-65, 83-93 | Describe safe governance defaults and `424 interaction_unavailable` behavior after R12. | R12 | C#/HTTP fences; inventory. |
| `docs/advanced/mission-governance-clients.md` | 144-169 | Clarify resource-hosted interaction poll authority once R12 client semantics are fixed. | R12 | C# fence compile; inventory. |
| `docs/server/replay-detection.md` | 223-231 | Restore/adjust deferred revocation guarantee after R06 source checks land. | R06 | Link/inventory only. |
| `README.md`; `aauth-spec/SPEC-VERSION.md` | 301-304; 22-27 | Re-check `{jti, exp}` revocation “with cascades” claim after R06. Until then mark limitation. | R06 | README inventory; SPEC-VERSION link test. |
| `docs/server/token-issuance.md` | 165-168 | Claim pending/federated mission expiry ceilings only after R09 enforces them. | R09 | C#/prose inventory. |
| `docs/server/mission-governance.md` | 315-326 | Include termination reason storage/API after R09. | R09 | C# fence compile if example changes. |
| `docs/advanced/error-handling.md` | 336-340 | Claim expired mission errors only after every path enforces `expires_at`. | R09 | HTTP/prose inventory. |
| `README.md`; `aauth-spec/SPEC-VERSION.md` | 301-303; 22-26 | Re-check mission “updates and expiry” implemented claim after R09. | R09 | README inventory; SPEC-VERSION link test. |
| `docs/workflows/federated-access.md` | 231-233 | Describe PS-AS collapse behavior only after R07 implements the structural four-party branch. | R07 | C# fence/inventory. |
| `docs/reference/dependency-injection.md` | 265-270 | Add four-party trust caveat / AS policy default after R02 final trust behavior. | R02 | Link/inventory. |
| `README.md` | 222 | Replace “any verifiable PS is spec default” with three-party-only caveat after R02. | R02 | README inventory. |
| `docs/advanced/interaction-chaining.md` | 129-135 | Replace `unknown_pending` with final polling error/status after R11. | R11 | HTTP fence/hash. |
| `README.md`; `aauth-spec/SPEC-VERSION.md` | 301-304; 22-27 | Re-check `202` auth-token delivery claim after R11 polling/status fixes. | R11 | README inventory; SPEC-VERSION link test. |

## Tests

- `tests/AAuth.Tests/Api/SnippetCompilationTests.Documentation_CompilationProbe`: every rewritten C# fence in `README.md`, `docs/**`, `src/**/*.md`, and sample snippets must compile or be classified as an existing external template/API excerpt. Negative control: a new `getting-started.md` C# fence that references an undeclared variable (like current `keyStore`) must fail.
- `SnippetCompilationTests.Documentation_FrozenSurface`: after doc edits, run with `AAUTH_UPDATE_DOCS_INVENTORY=1` to refresh `.agent/plans/2026-09-11-aauth-v11-spec-migration/docs-surface-map.md`; then run normally to prove the inventory is current. Negative control: editing any inventoried Markdown without regenerating the map must fail as stale.
- `tests/AAuth.Tests/Api/DocumentationLinkTests.ActiveMarkdown_LocalLinksAndAnchorsResolve`: all new/renamed anchors and spec links must resolve, including `aauth-spec/SPEC-VERSION.md`. Negative control: the current bad `federated-access.md#access-server-side-code` link should fail until fixed.
- Extend `SnippetCompilationTests` with doc-specific assertions: no `docs/getting-started.md` fence/body may contain `{"resource_token": "<resource-token>"}` without `presented_token`; no active doc may show `AAuth-Requirement: interaction` without `requirement=`; no active doc may show bare `Signature-Error: invalid_signature`.
- `tests/AAuth.Tests/Api/ConfigurationReferenceTests` and `DocumentationApiExcerpts.ValidateTables`: update expected row counts/excerpts when `configuration.md` adds omitted options.

No build/test execution is part of this design brief; the implementation phase should run the smallest docs gate set above, then the normal AAuth.Tests gate if targeted assertions change.

## Samples and docs to update

All rows in the inventory above are docs or README surfaces. No runtime samples should be changed for R19 unless a doc fence is sourced from `samples/**`; if so, change the source snippet first so the rendered doc and browser/demo evidence stay aligned.

The two inventory files/gates to update are:

- `.agent/plans/2026-09-11-aauth-v11-spec-migration/docs-surface-map.md` via `AAUTH_UPDATE_DOCS_INVENTORY=1` after any README/docs/src/sample Markdown or snippet change.
- `aauth-spec/SPEC-VERSION.md` draft-11 paragraph (currently lines 22-27) plus root `README.md` conformance paragraph (currently lines 301-304) after R06/R09/R11/R04 land; these are not in the snippet inventory except README, but `DocumentationLinkTests` covers `SPEC-VERSION.md`.

## Dependencies and conflicts with other Rnn

- R19 can immediately fix DOC-01, DOC-02, D02-02, D01-01/D02-03/D10-06, D01-04, D03-04, D04-001, D06-03, D06-04, D06-05, D07-04, D08-01, D08-02, D08-03, D10-07, and the LOW sweep.
- Do not redesign docs that exist only because code is non-conformant: DOC-03 → R01; DOC-04 → R03; DOC-05/D07-02 → R05; DOC-06/D10-04 → R04; DOC-07/D05-01/D05-03 → R12; D03-02/D10-01 → R06; D04-002/D05-02/D08-05/D10-03 → R09; D06-02 → R07; D09-01/D10-05 → R02; D07-05/D10-02 → R11.
- Potential conflict: changing README/SPEC-VERSION conformance claims before owner Rnn fixes land may make later Rnn docs look like regressions. Default: mark current limitations honestly now, then restore positive claims only after the owning tests pass.

## Open questions (with proposed default)

1. Should `agent-identity-jwks-uri.md` be deleted or retained as a generic Signature-Key page? Default: retain but retitle/scope it to non-AAuth-agent examples so inbound links keep working.
2. Should README/SPEC-VERSION claims be pessimistically corrected before R06/R09/R11/R04 land? Default: yes; published docs should not claim unimplemented conformance, and owner Rnn can restore the claim when verified.
