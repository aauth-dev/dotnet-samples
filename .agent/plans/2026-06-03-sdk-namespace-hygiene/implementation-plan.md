---
title: "SDK Namespace Hygiene — Implementation Plan"
description: Phased plan to improve AAuth SDK namespace layout and public type naming
ms.date: 2026-06-03
---

This plan addresses the four issues in [research.md](research.md). Phasing is
**non-breaking first**: Phase 1 ships the high-value DI ergonomics win on its
own; Phases 2–5 are the breaking renames/moves.

> **Policy (2026-06-03):** SDK is in **alpha** — clean breaks are acceptable.
> **No** `[Obsolete]` shims or type-forwarders. Apply renames/moves directly and
> update all in-repo callers (`src/`, `samples/`, `tests/`, `docs/`) in the same
> change. Phases are sequenced for review clarity only; there is no version gate
> blocking the breaking phases.

## Phase 1: Move DI/Builder Extensions to Conventional Namespaces

Surface the registration API with no extra `using`. This is the only
non-breaking phase (for callers relying on implicit usings) and delivers the
biggest day-one ergonomics gain.

### Files

| Action | Path | Change |
|--------|------|--------|
| Edit | `src/AAuth/DependencyInjection/AAuthResourceServiceCollectionExtensions.cs` | `namespace` → `Microsoft.Extensions.DependencyInjection` |
| Edit | `src/AAuth/DependencyInjection/AAuthAgentServiceCollectionExtensions.cs` | `namespace` → `Microsoft.Extensions.DependencyInjection` |
| Edit | `src/AAuth/DependencyInjection/AAuthDiscoveryServiceCollectionExtensions.cs` | `namespace` → `Microsoft.Extensions.DependencyInjection` |
| Edit | `src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs` | `namespace` → `Microsoft.AspNetCore.Builder` |
| Edit | option records (`AAuthResourceOptions`, `AAuthAgentOptions`, `AAuthDiscoveryOptions`, `AAuthResourcePipelineOptions`) | `namespace` → `AAuth` root |
| Edit | extension `.cs` files | add `using AAuth;` for the relocated options where needed |
| Edit | in-repo callers | drop now-redundant `using AAuth.DependencyInjection;`; add `using AAuth;` only where an options type is named |

### Implementation notes

- Keep the class names unchanged — only the `namespace` declaration moves.
- The extension methods reference their options types; once options live in
  `AAuth`, add `using AAuth;` inside the extension files.
- Verify the four-party `AAuthAccessServerOptions` (in `AAuth.Server`) is **not**
  in scope here — it is a host-options type, not a DI-extension options record.
- Update in-repo consumers found in research (tests under
  `tests/AAuth.Tests/DependencyInjection/`, `tests/AAuth.Conformance/`).

### Implementation Decisions

- Options records land in the `AAuth` root (resolved 2026-06-03) — keeps the
  registration call reachable with a single `using AAuth;` for the named options
  type, no `AAuth.Configuration` namespace.

### Definition of Done

- [x] DI extension methods compile under `Microsoft.Extensions.DependencyInjection`
- [x] App-builder extensions compile under `Microsoft.AspNetCore.Builder`
- [x] Option records relocated and referenced correctly
- [x] A minimal `Program.cs` can call `services.AddAAuthResource(...)` with **no**
      `using AAuth.DependencyInjection;`
- [x] In-repo callers updated; redundant usings removed
- [x] `dotnet build AAuth.slnx -v q` clean
- [x] `dotnet test tests/AAuth.Tests` and `tests/AAuth.Conformance` green
- [ ] Docs (`docs/reference/dependency-injection.md`, getting-started) updated to
      drop the extra `using` _(folded into the single Phase 6 doc sweep)_

---

## Phase 2: Resolve `AAuth` Type-Name Stutter

Drop the redundant `AAuth` prefix where it adds no disambiguation; keep it where
collision/brand identity matters (see research buckets).

### Candidate renames (confirm final list in Implementation Decisions)

| From | To | Namespace |
|------|----|-----------|
| `AAuthMission` | `Mission` | `AAuth.Agent` |
| `AAuthAgentId` | `AgentId` | `AAuth.Identifiers` |
| `AAuthServerId` | `ServerId` | `AAuth.Identifiers` |
| `AAuthInteraction` | `Interaction` | `AAuth.Headers` |
| `AAuthVerificationResult` | _kept (see decision)_ | `AAuth.Server` |
| `AAuthClaimsRequirement` | `ClaimsRequirement` | `AAuth.Headers` |
| `AAuthClaimsResponse` | `ClaimsResponse` | `AAuth.Headers` |

### Keep (do not rename)

`AAuthKey`, `IAAuthKey`, `AAuthVerifier`, `AAuthClientBuilder`, `AAuthConstants`,
`AAuthDiagnostics`, `AAuthLevel`, `AAuthAccessMode`, `AAuthUrl`.

### Implementation notes

- Use the language-server rename so all references update atomically.
- Clean break: do **not** add `[Obsolete]` aliases (alpha policy).
- Sweep docs and samples for the old names.

### Implementation Decisions

- Compat-shim policy: **clean break, no shims** (alpha) — resolved 2026-06-03.
- Final rename list: the candidate table above is adopted as-is (resolved
  2026-06-03).
- **Deviation (2026-06-03):** `AAuthVerificationResult` is **kept** (not renamed
  to `VerificationResult`). A distinct public `VerificationResult` already exists
  in `AAuth.Server` (the middleware's raw `HttpContext.Items` result), so the
  `AAuth` prefix provides real disambiguation here. Consolidating the two result
  types is a behavior change and out of scope for a names-only phase.

### Definition of Done

- [x] Agreed renames applied via language-server rename
- [x] No remaining references to old names in `src/`, `samples/`, `tests/` _(docs
      swept in Phase 6)_
- [x] `dotnet build AAuth.slnx -v q` clean; full test suite green
- [ ] E2E (`tests/e2e`, sample `playwright-tests`) green _(run once at the
      consolidated validation before Phase 7)_

---

## Phase 3: Consolidate the Access-Server Feature Namespace

Co-locate the four-party federated types so the feature lives in one namespace.

### Files

| Action | Path | Change |
|--------|------|--------|
| Edit | `src/AAuth/Tokens/AccessServerClient.cs` | `namespace` → `AAuth.Access` |
| Edit | `src/AAuth/Tokens/AccessServerRequest.cs` | `namespace` → `AAuth.Access` |
| Edit | `src/AAuth/Server/IAccessPolicy.cs` (+ `AccessDecision`) | `namespace` → `AAuth.Access` |
| Edit | `src/AAuth/Server/IAccessPendingStore.cs` (+ `AccessPendingEntry`, `InMemoryAccessPendingStore`) | `namespace` → `AAuth.Access` |
| Edit | `src/AAuth/Server/AAuthAccessServerEndpoints.cs` (+ `AAuthAccessServerOptions`) | `namespace` → `AAuth.Access` |
| Optional | move files into a new `src/AAuth/Access/` folder to match namespace | folder reorg |

### Implementation notes

- Confirm namespace name with research Open Question 3 (`AAuth.Access` vs
  `AAuth.Federation`).
- Update `using` sites in `samples/MockAccessServer`, `samples/MockPersonServer`,
  and the federation tests.
- Decide whether to physically move files into an `Access/` folder (cleaner) or
  only change the `namespace` declaration (smaller diff).

### Implementation Decisions

- Namespace name: `AAuth.Access` (resolved 2026-06-03).
- Folder reorg: yes — move the files into `src/AAuth/Access/` so the folder
  mirrors the namespace (resolved 2026-06-03).

### Definition of Done

- [x] All four-party types share one namespace
- [x] Sample servers + federation tests updated and building
- [ ] `make demo` and `make demo-keycloak` start cleanly _(consolidated validation)_
- [ ] Federated e2e (`npx playwright test --grep "Federated"`) green _(consolidated validation)_

---

## Phase 4: Surface Client Builders in a First-Class Namespace

Move the headline builders out of `AAuth.HttpSig`.

### Files

| Action | Path | Change |
|--------|------|--------|
| Edit | `src/AAuth/HttpSig/AAuthClientBuilder.cs` | `namespace` → chosen target |
| Edit | `src/AAuth/HttpSig/SelfIssuingBuilder.cs` | `namespace` → chosen target |
| Edit | `src/AAuth/HttpSig/EnrolledBuilder.cs` | `namespace` → chosen target |
| Edit | `src/AAuth/HttpSig/BootstrapBuilder.cs` | `namespace` → chosen target |
| Optional | move files to a matching folder | folder reorg |

### Implementation notes

- Choose target per research Issue 4: **Option A** (root `AAuth`) for max "one
  using", or **Option B** (`AAuth.Client`) for client/transport separation.
- Leave signing internals (`AAuthSigningHandler`, `ISignatureKeyProvider`,
  `SignatureKeyParser`, resolvers) in `AAuth.HttpSig`.
- Update `using AAuth.HttpSig;` consumer sites that only needed the builders.

### Implementation Decisions

- Option A — builders land in the root `AAuth` namespace (resolved 2026-06-03)
  for the maximum "one `using`" ergonomics; signing internals stay in
  `AAuth.HttpSig`.

### Definition of Done

- [x] Builders relocated; signing internals remain in `AAuth.HttpSig`
- [x] Consumers reach `AAuthClientBuilder` via root `AAuth` (Option A) or
      `AAuth.Client` (Option B)
- [x] `dotnet build AAuth.slnx -v q` clean; full suite green (e2e consolidated)
- [ ] Quick-start docs show the simplified `using` _(Phase 6 doc sweep)_

---

## Phase 5: Split `AAuth.Server` into Concern-Based Sub-Namespaces

After Phase 3 extracts the four-party federation types into `AAuth.Access`, the
~20 remaining `AAuth.Server` types cluster cleanly by concern. Split them into
sub-namespaces so the (currently 25-file) `Server/` folder is navigable and each
namespace declares its purpose. This is low-risk because Phase 1 routes the
common path through `services.AddAAuthResource(...)` / `app.UseAAuth...()` in the
Microsoft namespaces — most apps never import `AAuth.Server.*` directly.

### Proposed grouping

| Target namespace | Types | Theme |
|---|---|---|
| `AAuth.Server.Verification` | `AAuthVerificationMiddleware`, `AAuthVerificationOptions`, `AAuthVerificationResult`, `AAuthAuthenticationHandler`, `AAuthHttpContextExtensions`, `AAuthLevel`, `AAuthAccessMode` | Inbound request verification + the ASP.NET auth handler and `HttpContext` accessors |
| `AAuth.Server.Challenge` | `AAuthChallengeMiddleware`, `ChallengeOptions` | Emitting `401`/`WWW-Authenticate` challenges |
| `AAuth.Server.Authorization` | `AAuthScopeRequirement`, `AAuthScopeHandler` | ASP.NET Core scope authorization |
| `AAuth.Server.Metadata` | `WellKnownEndpoints`, `AAuthResourceMetadataOptions`, `AAuthAgentMetadataOptions`, `AAuthPersonServerMetadataOptions` | `.well-known/*` discovery documents |
| `AAuth.Server.CallChaining` | `CallChainingRouter`, `CallChainingHandler`, `CallChainingOptions`, `UpstreamAuthTokenFeature` | Multi-hop `act` delegation |
| `AAuth.Server` (unchanged) | `IJtiStore`, `InMemoryJtiStore`, `IOpaqueTokenStore`, `RevocationEndpoint` | Replay/JTI + opaque-token persistence and revocation — left at the root to avoid over-fragmenting |

### Implementation notes

- Sequence **after** Phase 3 so the `AAuth.Access` types are already gone from
  `Server/` and do not need re-touching.
- Mirror each namespace with a folder: `src/AAuth/Server/Verification/`,
  `.../Challenge/`, `.../Authorization/`, `.../Metadata/`, `.../CallChaining/`.
- Update the DI extension files (now in `Microsoft.Extensions.DependencyInjection`)
  to add the new `using AAuth.Server.*;` imports they need.
- Update in-repo callers that import `AAuth.Server` directly (sample servers,
  conformance/integration tests) to the specific sub-namespaces.

### Implementation Decisions

- Adopt the five-group split above (resolved 2026-06-03).
- Keep the stores group (`IJtiStore`, `InMemoryJtiStore`, `IOpaqueTokenStore`,
  `RevocationEndpoint`) at the `AAuth.Server` root — no dedicated
  `AAuth.Server.Stores` (resolved 2026-06-03).
- `AAuthResourceMetadataOptions` is declared inside `WellKnownEndpoints.cs`, so
  it moves to `AAuth.Server.Metadata` with that file (no separate file).
- `AAuthAccessServerMetadataOptions` was also folded into
  `AAuth.Server.Metadata` (it is a `.well-known` metadata type); the grouping
  table above omitted it but it belongs with the other metadata options.

### Definition of Done

- [x] `Server/` types relocated to the agreed sub-namespaces and matching folders
- [x] DI extensions and in-repo callers updated with the new imports
- [x] No half-split namespace (every moved type and its references consistent)
- [x] `dotnet build AAuth.slnx -v q` clean; full unit + conformance suites green
- [ ] `make demo` / `make demo-keycloak` start; e2e green _(consolidated run before Phase 7)_

---

## Phase 6: Propagate Renames to Samples, Docs, and Embedded Snippets

Phases 1–5 update `src/` and the directly-referenced callers, but the SDK's
*teaching surface* also embeds the public type/namespace names as **literal
text** that the compiler never checks: documentation prose, Markdown code
fences, and the C# snippets rendered inside the GuidedTour and SampleApp UIs.
These must be swept by hand so the visible API matches the shipped API.

### Surfaces to sweep

| Surface | Where | Why it is not caught by build |
|---|---|---|
| Sample app source | `samples/**/*.cs`, `samples/**/*.razor` | Builds, but `using` lines and type names need updating to the new namespaces (e.g. `samples/SampleApp/Program.cs` imports `AAuth.DependencyInjection`, `AAuth.Server`) |
| GuidedTour step snippets | `samples/GuidedTour/CodeSnippets.cs`, `StepRecord.CodeSnippet` | C# rendered as **strings** in `PayloadInspector.razor`; not compiled |
| GuidedTour highlighter token list | `samples/GuidedTour/Components/PayloadInspector.razor` (the `AAuthKey|AgentTokenBuilder|AAuthClientBuilder|...` regex) | Highlight keyword list references type names literally |
| GuidedTour / SampleApp prose | `Tour.razor`, `Home.razor`, other `Components/Pages/*.razor` | Inline `<code>` spans and explanatory copy |
| Markdown docs | `docs/**/*.md`, `README.md`, `src/AAuth/README.md`, `samples/**/README.md` | Code fences + prose reference namespaces/types as text |
| Plan/research embedded examples | this folder + sibling plans, only if they show now-renamed public API in a "current usage" context | Keep historical decisions intact; update only illustrative current-API snippets |

### Implementation notes

- Run this phase **after** each breaking phase lands, or once after Phases 2–5,
  to avoid sweeping the same files twice. Prefer a single sweep after Phase 5.
- For each renamed/moved symbol, grep the whole repo (including `*.razor`,
  `*.md`, `*.cs` string literals) for the **old** name and update every hit.
- Update the GuidedTour highlighter regex token list in `PayloadInspector.razor`
  so renamed types still colorize.
- Re-run the GuidedTour and SampleApp so the embedded snippets render and the
  flows still execute (snippets are illustrative but must match what the running
  sample actually does).
- Do **not** rewrite historical plan decisions; only fix illustrative
  current-API snippets per the plan-workflow rules.

### Definition of Done

- [ ] No occurrence of any old namespace/type name remains in `samples/`,
      `docs/`, `README.md`, `src/AAuth/README.md` (grep clean for each renamed symbol)
- [ ] `samples/GuidedTour/CodeSnippets.cs` and any `StepRecord.CodeSnippet`
      strings show the new namespaces/types
- [ ] GuidedTour highlighter regex updated for renamed types
- [ ] `Tour.razor` / `Home.razor` inline `<code>` references updated
- [ ] `dotnet build AAuth.slnx -v q` clean (samples included)
- [ ] `make demo` and `make demo-keycloak` start; GuidedTour (:5400) and
      SampleApp (:5240) render the updated snippets
- [ ] Sample `playwright-tests` and `tests/e2e` green

---

## Phase 7: Internal Reviewer-Agent Verification (No-Regression + Spec Alignment)

A final independent pass: dispatch an **internal reviewer agent** to confirm the
refactor changed *only* names/namespaces — not behavior — and that all
user-visible terminology aligns **100%** with the protocol specifications in
[aauth-spec/](../../aauth-spec/).

### Reviewer scope

| Check | Source of truth | Pass criterion |
|---|---|---|
| No functional regression | Phases 1–6 diffs | Every change is a namespace move, type rename, `using` update, or literal-text edit. **Zero** logic/control-flow/signature-shape changes beyond the rename |
| Public-surface consistency | `src/AAuth/**` | New names are internally consistent (no half-renamed members, no orphaned old names) |
| Spec terminology alignment | `aauth-spec/draft-hardt-oauth-aauth-protocol.md`, `draft-hardt-aauth-bootstrap.md`, `draft-hardt-aauth-r3.md`, `SPEC-VERSION.md` | Every user-visible term (type names, namespace stems, doc prose, GuidedTour/SampleApp copy) matches the spec's canonical vocabulary — e.g. "Access Server", "Person Server", "Agent Provider", "auth token", "resource token", "agent token", `sig=jwt`, `dwk`, `cnf.jwk`, federated/deferred wording |
| Docs/snippets match running behavior | `samples/`, `docs/` | Embedded snippets reflect the actual SDK calls the samples make post-rename |

### How to run

- Dispatch the **Implementation Validator** agent (and/or a spec-terminology
  reviewer) with: the plan + research docs, the full diff of Phases 1–6, and the
  `aauth-spec/` directory as the terminology source of truth.
- Ask for **severity-graded findings**: Critical (behavior changed / spec
  mismatch on a normative term), Major (inconsistent or half-applied rename),
  Minor (stylistic/doc nit).
- Triage findings: fix Critical/Major before closing; capture Minor as follow-ups
  or fix inline.

### Definition of Done

- [ ] Reviewer agent run completed with findings recorded
- [ ] Zero Critical findings (no behavior regression; no normative-term mismatch)
- [ ] Zero unresolved Major findings (renames fully and consistently applied)
- [ ] Spec terminology verified 100% aligned across types, docs, and sample copy
- [ ] Full build + unit + conformance + e2e suites green
- [ ] Findings summary appended to this plan (or a linked review note)

---

## Out of Scope

| Item | Reason |
|------|--------|
| Renaming `IAAuthKey`/`AAuthKey` | Brand identity + BCL `Key` collision risk; intentionally kept |
| Assembly/package split (multiple NuGet packages) | Larger architectural decision; not a namespace concern |
| Renaming the root `AAuth` assembly/namespace | Out of question; it is the product brand |
