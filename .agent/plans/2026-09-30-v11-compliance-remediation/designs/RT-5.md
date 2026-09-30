# RT-5 — Cross-design synthesis, samples, docs

## File contention matrix

The matrix is based on the design `Implementation sketch` sections and their explicit samples/docs update lists (R01 L49-L57; R02 L64-L74; R03 L62-L72; R04 L55-L82; R05 L46-L58; R06 L48-L59; R07 L52-L64; R08 L69-L83; R09 L50-L83; R10 L79-L102; R11 L57-L86; R12 L169-L209; R13 L56-L71; R14 L54-L65; R15 L74-L119; R16 L69-L80; R17 L43-L51; R18 L53-L138; R19 L35-L113).

| Source file / surface | Designs | Contention / implementation risk | Recommended handling |
|---|---|---|---|
| `src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs`, `AAuthEndpointExtensions.cs`, high-level `UseAAuth` / `MapAAuthResource` | R01, R02, R03, R14 | R01 derives resource audience; R02 derives AS issuer/dwk defaults; R03 adds person-token authorization route semantics; R14 removes challenge-layer scheme filtering and centralizes signature failures. | One verification/challenge phase. Apply R01 first, then R02/R03/R14 together so high-level composition has one final option merge and one final 401/403 writer. |
| `src/AAuth/Server/Verification/AAuthVerificationMiddleware.cs`, `AAuthVerificationOptions`, trust context | R01, R02, R06, R14 | Audience, auth-token dwk, revoked auth-token challenge, and signature-failure writer all change the same middleware failure paths. | Avoid independent PRs. Shared acceptance tests should cover wrong audience, wrong `dwk`, revoked auth token, unsupported scheme, and 403 trust denial. |
| `src/AAuth/Server/Challenge/AAuthChallengeMiddleware.cs`, requirement header helpers | R03, R06, R10, R14 | R03 makes authorization endpoint require person tokens; R06 changes scope step-up to 401 auth-token challenge; R10 adds pairwise person binding data copied into tokens; R14 owns signature failure helper boundaries. | Implement after R01 and with R14 helper available; keep requirement challenges distinct from `Signature-Error`. |
| `src/AAuth/Person/AAuthPersonServerEndpoints.cs` and PS pending paths | R05, R06, R07, R08, R09, R10, R12 | Highest contention: upstream provenance, source-revocation guard, collapse/payment federation, updated_request replacement, mission evaluator, person binding/enrollment, governance auto-mapping. | Single PS-core mega-phase or tightly ordered stack: R06/R05 source model, then R10/R09 identity+missions, then R12 governance, then R07 federation/payment, then R08 replacement edge cases. |
| `src/AAuth/Agent/ChallengeHandler.cs`, `DeferredPoller.cs`, `DeferredExchange.cs`, `AAuthClientBuilder.cs`, `TokenExchangeClient` | R11, R13, R14, R15, R16 | Polling core, metadata-seeded signing components, default auth-token verification, TLS/JWKS transport, strict URL validation, capabilities all meet in automatic challenge handling. | R11 poller/error core before R15; R13/R16 metadata shape before R15; R14 token verifier before R15 signature verification. |
| `src/AAuth/Server/Revocation*`, `IJtiStore` / `InMemoryJtiStore`, `TokenRegistration`, source dependency models | R04, R05, R06, R10, R13 | R04 needs retained-result single-use; R05 wants provenance in token inventory; R06 wants source registrations for pending revocation; R10 needs binding revocation; R13 touches replay/JTI store semantics. | Define one inventory record model with provenance and source dependencies; do not add parallel stores for each design. |
| `src/AAuth/Server/HeldInvocations.cs`, `IAAuthSingleUseGate`, deferred retained result | R04, R11 | R04 explicitly reuses `HeldInvocationResult` and single-use semantics; R11 owns deferred polling/status cleanup. | R11 first, then R04 uses the final retained-result API. |
| `src/AAuth/Server/Governance/*`, `IMissionStore`, `MissionLogEntry`, governance metadata | R09, R10, R12, R15 | R09 changes mission identity/state API; R10 changes authorization to include expected PS; R12 maps governance and interaction relay; R15 relays PS-first interactions. | R09 + R10 before R12; R12 before R15 as required by R15's dependency on final `interaction_endpoint` and 424 semantics. |
| `src/AAuth/Tokens/TokenVerifier.cs`, `HttpSig/DefaultSignatureKeyResolver.cs`, companion verifier interfaces | R02, R14, R15, R17 | R02 adds expected auth-token `dwk`; R14 changes JOSE `crit`, skew, companion verifier; R15 verifies PS auth-token responses; R17 updates Events verifiers after interface break. | R14 owns verifier seam; R02/R15/R17 consume it in the same cutover window. |
| `src/AAuth/Discovery/ServerMetadata.cs`, metadata options, `AAuthEgressPolicy` | R13, R16, R17, R19 | R13 adds `additional_signature_components`; R16 validates all metadata URL fields and adds AP events metadata; R17 owns event delivery semantics; R19 docs configuration table follows. | R13 field and R16 reserved-field validation must land together: typed metadata fields win over `AdditionalMetadata`. |
| `src/AAuth.R3/*` and R3 docs/readmes | R03, R04, R19 | R03 adds R3 authorization-extension parsing; R04 owns R3 single-use, entitlement, operation validation; R19 documents after R04. | R03 parser seam first, R04 enforcement second, R19 docs last. |
| `src/AAuth.Events/*`, `samples/EventSupport/SqliteEventStore.cs`, Events README | R14, R16, R17, R19 | R14 breaks verifier interface; R16 adds AP `event_endpoint`; R17 changes store outcome and no-body signing; R19 updates README/baseline. | R14/R16 before R17, R19 after. |
| `samples/MockPersonServer/Program.cs`, `MissionGovernance.cs`, asserter/pending store | R06, R08, R09, R10, R11, R12, R18 | Sample PS sits on every PS-core change plus R18 admin/prose fixes. | Do not edit piecemeal; sample pass after PS-core designs, with R18 allowed only to remove prefix grants safely if it lands early. |
| `samples/GuidedTour/TourSession.cs`, `TourSession.Capabilities.cs`, UI/snippets | R03, R05, R08, R11, R13, R15, R17, R18 | Tour manually implements authorization, call-chain, polling, signing components, capabilities, events, and sample wording. | R11 poller semantics and R15 capabilities must precede R18 GuidedTour pass; otherwise the sample will encode stale mechanics twice. |
| `samples/Concierge/Program.cs` / `PendingStore.cs` | R05, R11, R15, R16, R18 | R05 owns intermediary code ownership; R11 owns polling codes; R18 owns pending body/status; R15/R16 affect agent behavior and URL parsing. | Implement R05/R11 first; R18 only finalizes sample wire/prose. |
| `samples/MockResourceServers/*` | R01, R03, R04, R11, R15, R18 | Audience binding, auth endpoint removal, R3 enforcement, polling errors, agent-client changes, and revocation surfaces overlap in Bookings/Catalog/Documents/Inbox/Profile. | Group resource sample changes in R18 after R01/R03/R04/R11/R15. |
| `samples/MockAccessServers/Federated/*` | R07, R10, R11, R16, R18 | Collapse/payment/claims filtering, person binding, polling codes, metadata URL validation, and sample Keycloak filtering share code. | R07/R10/R16 first, R18 final filtering/prose. |
| Public docs and README inventory (`docs/**`, `README.md`, `src/**/README.md`, `aauth-spec/SPEC-VERSION.md`) | R01-R17 via owned lines, R19 as collator | R19 intentionally collides with almost every design. | Treat R19 as a trailing inventory pass; only immediate docs-only safety fixes should happen earlier, and final conformance claims wait for owning tests. |

## Contradictions

| Area | Contradictory or unstable decision | Proposed ruling |
|---|---|---|
| Sample admin binding vs SDK person binding | R10 says SMP-01 needs SDK `AgentIssuer` and fixes sample prefix trust in its cutover (R10 L21-L78, L144-L158). R18 says no SDK API delta and fixes sample prefix trust now with exact subject/key until R10 exposes issuer (R18 L35-L52, L139-L146). | Split ownership: R18 may remove prefix privilege now using exact subject + key; R10 later upgrades the same sample to issuer + subject + key. Do not let R10 block the high-risk sample fix, but do not invent issuer plumbing in R18. |
| Capability constants/header parser | R08 removes `AAuthCapabilitiesHeader.Capabilities` and moves open-set constants to `AAuthConstants` (R08 L52-L68). R15 changes `AAuthCapabilitiesHeader.Format/Parse`, removes the `auth-token` default, and validates outbound capabilities (R15 L53-L73). | One combined capabilities cutover. R08 owns constant home and validation helper; R15 owns agent behavior/defaults using that helper. No aliases. |
| Payment API and payment error taxonomy | R07 removes `AccessDecision.NeedsPayment(string)` / `PaymentUrl` for spec-shaped payment challenges (R07 L33-L44). R11 maps malformed policy/payment states into registered error outcomes (R11 L23-L56), and R12 maps unsupported governance interaction/payment to 424 (R12 L71-L168). | R07 owns payment API shape and 402 loop. R11 supplies shared problem helpers only; R12's 424 is governance relay, not AS payment `Location` semantics. |
| Challenge-layer scheme gates vs endpoint requirements | R14 removes `ChallengeOptions.AllowedSignatureKeySchemes`; verification middleware is the single scheme gate (R14 L22-L53). R03 adds `AAuthAccessMode.PersonTokenRequired` route behavior that returns `AAuth-Requirement`, not `Signature-Error` (R03 L26-L61). | Keep both by layer: unsupported cryptographic scheme is R14 `Signature-Error`; missing/wrong valid token type at authorization endpoints is R03 `AAuth-Requirement: requirement=person-token`. |
| Audience vs issuer/dwk trust | R01 says `ResourceIdentifier = null` rejects auth/person JWTs and derives audience from `AddAAuthResource` (R01 L23-L48). R02 adds four-party `AccessServer`, issuer defaults, and `ExpectedAuthTokenDwk` (R02 L23-L63). | R01 first. R02 must not use `AccessMode` as topology and must not weaken R01 audience binding; accepted token requires both correct `aud` and correct issuer/dwk trust. |
| Token inventory ownership | R05 wants provenance-aware `IJtiStore`; R06 wants typed source dependencies; R10 wants binding revocation to update inventory; R04/R13 touch single-use/replay stores (R05 L21-L45; R06 L20-L47; R10 L55-L78; R04 L31-L54; R13 L31-L55). | Design one inventory abstraction with token key, provenance, source dependencies, revocation status, and retained-result integration. Avoid duplicate provenance/source stores. |
| Metadata extension fields | R13 adds typed `additional_signature_components` metadata (R13 L39-L55). R16 forbids bypassing typed metadata validation through `AdditionalMetadata` and must include future URL-like fields (R16 L23-L68, L112-L120). | Typed fields always win; R16 reserved-field validator must know R13's field and reject shadowing. |
| Event sample coverage | Audit S06-01 is a sample finding, but R18 delegates S06-01 to R17 and only handles S06-02/S06-03 prose (R18 L139-L145). | Accept delegation, but the implementation plan must explicitly list S06-01 under R17 sample updates so the Phase 3 sample finding is not lost. |
| Docs conformance claims | R19 says immediate pessimistic README/SPEC-VERSION corrections are allowed before R06/R09/R11/R04 land, then restored later (R19 L133-L143). Owner designs might otherwise update positive claims in their own branches. | R19 owns all public conformance claim wording. Owner Rnn may update local docs snippets only when code lands; final claims restored by R19 after gates pass. |

## Proposed phase ordering

1. **Foundation / low-blast isolated fixes.** R13 HTTP-signature producer and typed metadata field; R16 strict identifiers/metadata URL helper; R17 Events after R13/R16 verifier/metadata implications. These are mostly isolated from PS token issuance and reduce later sample/doc ambiguity.
2. **Verification and challenge core.** R01 audience binding first, then R02 four-party trust/dwk, R14 JWT/signature-failure helper, and R03 authorization endpoint/person-token gating. This groups the shared verification files and preserves the required R01-before-R02 dependency.
3. **Deferred, inventory, revocation, R3.** R11 polling/error core first; R06 source guard and scope step-up; R05 provenance/call-chaining on the same inventory model; R04 R3 single-use/entitlement after R11 retained-result semantics. This gives samples one final polling/error contract.
4. **PS identity, mission, governance, federation.** R10 person binding/enrollment, R09 mission evaluator/store, R12 governance endpoints, then R07 federation collapse/payment. R12 must precede R15's PS-first interaction relay; R07 should see final source guard and trust defaults.
5. **Agent client behavior.** R15 after R11/R12/R13/R14/R16 and after mission capability decisions from R09. This prevents a second poller, second interaction relay, or duplicate capability validator.
6. **Samples.** R18 after all owner code designs it names: R03, R05, R07, R10, R11, R12, R15, R17. If necessary, land the SMP-01 prefix removal early as a narrow security sample patch, then let R10/R18 reconcile issuer fields later.
7. **Docs.** R19 final sweep last. Immediate docs-only rows may be corrected earlier to stop publishing unsafe copy/paste guidance, but `update after Rnn lands` rows and README/SPEC-VERSION conformance claims should be finalized only after the owner phase and docs gates.

## Samples/docs coverage

### Samples (Phase 3)

| Audit finding | Covered by | Coverage status |
|---|---|---|
| SMP-01 prefix admin grants | R18 now; R10 later issuer-aware binding | Covered, but split ownership must be explicit (R18 L35-L52; R10 L21-L78). |
| SMP-02 Mock PS governance relay 200 | R12 | Covered by governance relay 424/202 design; R18 correctly excludes SDK/governance redesign. |
| SMP-03 Concierge pass-through interaction code | R05, with R18 pending body cleanup | Covered if R05 updates Concierge/SampleApp or R18's sample pass includes R05-owned sample lines. |
| SMP-04 Inbox `/authorize` on agent signature | R03 | Covered; R18 must not keep Inbox authorization example after R03. |
| S06-01 `SqliteEventStore` exhausted max_uses | R17 | Covered outside R18; add explicit implementation-plan row because R18's header omits it. |
| S07-01 generic signing modes taught as AAuth | R18 | Covered. |
| S08-01 cross-origin pending `Location` in Tour | R18 | Covered. |
| S08-02, S08-03, S09-01 polling/backoff/status errors in Tour | R11, then R18 UI/sample pass | Covered by R18 dependency note, but only if R11's shared poller is actually consumed by Tour or R18 mirrors it. |
| S09-02 missing `AAuth-Capabilities` on signed Tour requests | R15/R18 | **Gap:** R18 does not name S09-02 in findings or dependencies. Add an explicit R15-owned or R18-owned row so this Phase 3 MEDIUM is not dropped. |
| S03-02, S03-03 resource revocation surfaces | R18 | Covered. |
| S04-01 Federated AS requests `sub` | R18 with optional R07 constants/helper | Covered. |
| S05-002 Concierge pending shape/errors | R18 with R11 constants/status helpers | Covered. |
| LOW sweep S01-02..S10-001 | R18 | Covered for all named lows in R18 header; inherited SDK INFOs stay with owner Rnn. |

### Docs (Phase 4)

R19 covers every HIGH doc finding: DOC-01 and DOC-02 are immediate R19 rewrites; DOC-03 maps to R01; DOC-04 to R03; DOC-05/D07-02 to R05; DOC-06/D10-04 to R04; DOC-07/D05-01/D05-03 to R12 (R19 L35-L113, L133-L143). Medium/low group mappings are also real designs: revocation claims to R06, mission expiry/reasons to R09, federation collapse to R07, polling/status to R11, four-party trust to R02, stale access-mode terminology and `jkt-jwt` docs to immediate R19/R15, and configuration/resource metadata omissions to R16/R13. I found no dangling `update after Rnn lands` reference to a nonexistent design. The main docs risk is timing: R19's pessimistic README/SPEC-VERSION correction should land before public docs claim conformance, but the positive restoration must wait for R04/R06/R09/R11 owner tests.

## Consolidated open questions

1. **Four-party trust merge:** do not implicitly merge declared AS into explicit `Trust.AuthTokenIssuers.Allowed`; warn/throw if AS absent (R02 L113-L116).
2. **Mixed PS+AS auth-token acceptance:** low-level opt-out is `ExpectedAuthTokenDwk = null`; high-level AS resources stay fail-closed (R02 L117-L120).
3. **DWK pinning data shape:** start with `AAuthTrustContext.TokenDwk` plus `ExpectedAuthTokenDwk`; add data maps only if needed (R02 L121-L123).
4. **Low-level `AAuthServerOptions.AccessServer`:** keep as primitive override; document high-level `AAuthResourceOptions.AccessServer` (R02 L124-L126).
5. **Missing-token requirement option:** no new public option unless implementation cannot preserve malformed-token `Signature-Error` (R03 L98-L101).
6. **Inbox `/authorize`:** remove from two-party resource-managed sample (R03 L102-L103).
7. **Trust-denial 403 code:** use `access_denied` with optional detail (R03 L104-L106).
8. **Provenance store:** extend `IJtiStore` rather than adding a parallel store (R05 L87-L90).
9. **AS trust with provenance:** static trust may further restrict, but provenance is mandatory (R05 L91-L93).
10. **PS-issued auth-token provenance:** record provenance for every PS-issued auth token at mint time (R05 L94-L96).
11. **In-memory provenance loss:** fail closed with `invalid_upstream_token` (R05 L97-L99).
12. **Chained-interaction store:** store operation name + JSON state, not delegates (R05 L100-L102).
13. **Proactive revocation callbacks:** no public callback; rely on lazy poll/pre-outbound guards (R06 L87-L90).
14. **Scope step-up in named policies:** only `.RequireAAuth(scope:)`/`UseAAuth` step up; lower-level policies remain 403 (R06 L91-L94).
15. **Role/claim step-up:** no; only scope maps to auth-token step-up (R06 L95-L97).
16. **`SourceTokens` API break:** accept typed source-registration break under C1 (R06 L98-L100).
17. **Printable `device`:** valid Unicode scalars, reject control/format/surrogate/private-use/unassigned, count runes (R08 L116-L119).
18. **`capabilities: []`:** distinguish present empty from omission (R08 L120-L122).
19. **Non-positive clarification timeout:** reject as malformed; if lenient, treat already expired (R08 L123-L125).
20. **Capabilities constant aliases:** no aliases; move to `AAuthConstants` (R08 L126-L127).
21. **Opaque person key:** `readonly record struct AAuthPersonKey(string Value)` with non-empty validation (R10 L152-L154).
22. **First metadata fetch failure:** `400 invalid_request` and no token (R10 L155-L157).
23. **Unset pairwise subject secret:** ephemeral only in Development/test with warning; production requires configured secret/custom deriver (R10 L158-L161).
24. **`NeedsConsent` without `PersonKey`:** allowed only until pending approval; no mint without key (R10 L162-L164).
25. **Untrusted Signature-Key error:** `issuer_mismatch` (R11 L117-L119).
26. **Unknown pending ID:** `410 invalid_code` (R11 L120-L122).
27. **Unregistered token error constants:** remove from token-endpoint enum; introduce endpoint-specific types only if proven (R11 L123-L125).
28. **`.WithGovernance()` auto-add deferred store:** no; return 424 without store (R12 L286-L291).
29. **Keep `MapAAuthGovernance()`:** yes, as primitive/advanced API with `InteractionEndpointPath` terminology (R12 L292-L296).
30. **JSON `null` for governance `parameters`/`result`:** reject as present non-object (R12 L297-L299).
31. **Same-target signature wait timeout:** no new public timeout; honor cancellation token (R13 L112-L115).
32. **Signature labels:** do not hard-code to `sig` in this remediation; validate consistency (R13 L116-L118).
33. **`signature_window`:** do not use to future-date producer `created` (R13 L119-L121).
34. **JOSE `crit`:** accept none until an extension is actually implemented (R14 L96-L99).
35. **Companion issuer-key resolution with `iss`+`dwk`:** no; standard metadata first (R14 L100-L103).
36. **Companion missing key error:** `UnknownKey` when identity known; otherwise `InvalidJwt` (R14 L104-L107).
37. **Signature-failure helper visibility:** keep internal for now (R14 L108-L110).
38. **TLS pinning tests:** real TLS 1.1 when possible, otherwise focused handler assertion + docs tests (R14 L111-L113).
39. **Automatic two-key refresh:** do not reintroduce; future atomic credential provider needed (R15 L152-L154).
40. **Malformed `AAuth-Access` exception:** use `HttpRequestException` unless shared protocol exception appears (R15 L155-L157).
41. **Relaying PS-returned interactions:** yes only after R12 proves no loop; otherwise limit to resource-response interactions (R15 L158-L160).
42. **Strict identifiers and localhost:** do not allow `https://localhost` server identifiers (R16 L120-L122).
43. **Informational URLs:** consumers should apply egress/private-address admission; producers require shape unless policy supplied (R16 L123-L125).
44. **Emit `localhost_callback_allowed=false`:** omit false, emit only true (R16 L126-L127).
45. **Multiple event endpoints:** fail metadata mapping unless explicit `EventEndpoint` is set (R16 L128-L130).
46. **`ServerMetadata.FromJson` validation:** add defense-in-depth shape validation; issuer/JWKS checks stay in `MetadataClient` (R16 L131-L133).
47. **Duplicate event delivery:** store returns `Duplicate` with previous remaining uses; endpoint maps to same 202 shape (R17 L83-L85).
48. **Event store invalid-token states:** token validation belongs before store; store uses `Forbidden` for persisted binding conflicts (R17 L86-L89).
49. **Body-bearing `Content-Length: 0`:** treat as no body unless content type/transfer encoding indicates body (R17 L90-L92).
50. **GuidedTour generic Signature-Key lesson:** keep, but only as clearly separated non-AAuth primitive lesson (R18 L148-L150).
51. **Demo admin seed:** seed current local demo subject + key thumbprint; require issuer too after R10 (R18 L151-L153).
52. **Redaction bypass:** redacted by default; explicit local-only GuidedTour setting only (R18 L153-L153).
53. **`agent-identity-jwks-uri.md`:** retain but retitle/scope as generic Signature-Key, not AAuth-agent guidance (R19 L139-L141).
54. **README/SPEC-VERSION pessimistic correction:** yes; restore positive claims only after owner designs pass (R19 L142-L143).
