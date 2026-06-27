# Research — AAuth-Access opaque-token flow (resource-managed authorization)

Research-only document for a future initiative: adding the draft-08
**`AAuth-Access`** opaque-token flow (the `aauth-access-token` access mode) to the
.NET AAuth SDK. Spun off from the
[2026-06-25 draft-08 migration](../2026-06-25-aauth-v08-spec-migration/implementation-plan.md),
whose Phase 3 recorded that the SDK has **no** `Authorization: AAuth` /
`AAuth-Access` consumption or production path, so the draft-08 `token68`
validation had nothing to attach to (see that plan's Phase 3 deviation).

Spec source: [`aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md`](../../../aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md).
No implementation steps here — see [`implementation-plan.md`](implementation-plan.md).

> **Update (2026-06-27):** Continued the research to scope the *implementation*
> shape — SDK surface, demo wiring, flow placement, and docs. Two corrections to
> the original audit emerged and are flagged with `> **Update**` callouts below:
> (1) the agent signer **already** auto-covers `authorization` when the header is
> present, so the binding MUST is satisfied at signing time; and (2) the
> resource-side opaque-token seam (`IOpaqueTokenStore` + `InMemoryOpaqueTokenStore`
> + `OpaqueTokenInfo`) **already exists** but is wired to nothing. The flow is
> therefore *non-functional end to end* despite several building blocks being
> present. New sections cover the four implementation questions and a
> [pre-existing inconsistencies](#pre-existing-inconsistencies-to-fix) list.

## Research method

Read the draft-08 `AAuth-Access` sections directly and re-verified every line
citation against the vendored spec. Audited the current SDK signing/verification
and challenge surfaces with workspace search + file reads. All claims below were
verified against source (no subagent delegation); line numbers are precise to the
current vendor and the `{#anchor}` is the durable reference.

## Spec summary (verified)

### The `AAuth-Access` response header (`#aauth-access`, L738)

- A resource MAY hand the agent an **opaque** access token via the `AAuth-Access`
  response header after it authorizes the agent itself; the agent replays it on
  later requests as `Authorization: AAuth <token68>` (`#aauth-access`, L738–745).
- The token wraps the resource's internal authorization state (which MAY be an
  existing OAuth access token); it is opaque to the agent (L740).
- **Binding (MUST):** the agent MUST include `authorization` in the covered
  components of its HTTP Message Signature, binding the opaque token to the signed
  request — it is useless as a standalone bearer token without a valid AAuth
  signature (L753; restated in **AAuth-Access Security**, L2712–2714).
- **Rolling refresh:** a resource MAY return a new `AAuth-Access` on any response;
  the agent MUST switch to the new value on subsequent requests — no explicit
  refresh flow (L754).
- **`token68` grammar (MUST):** the `AAuth-Access` value, and the
  `Authorization: AAuth` credential, is a `token68` ([@!RFC9110] §11.2).
  Recipients MUST reject empty values, values with embedded whitespace or control
  characters, and messages carrying more than one credential (L756).

### Resource-managed authorization handshake (`#resource-managed-auth`, L758)

- The resource manages authorization itself. When it needs the user, it returns
  `202 Accepted` with `AAuth-Requirement: requirement=interaction; url=…; code=…`
  (L758–776), the agent drives the user through the resource's own consent/login
  flow and polls the `Location` per the deferred-response pattern, and on
  completion the resource returns `200 OK` and MAY include `AAuth-Access` (L776).
- A resource MAY also authorize on identity alone (no interaction) and still
  return `AAuth-Access` (L778).
- Advertised via resource metadata `access_mode = "aauth-access-token"` (L2642):
  the agent's call (or a hit on `authorization_endpoint`) triggers the `202`
  interaction, then the resource issues the opaque token.

### Fully-bound request shape (L743–751, example L2346)

```http
GET /api/data HTTP/1.1
Host: resource.example
Authorization: AAuth wrapped-opaque-token-value
Signature-Input: sig=("@method" "@authority" "@path" \
    "authorization" "signature-key");created=1730217600
Signature: sig=:...:
Signature-Key: sig=jwt;jwt="eyJhbGc..."
```

`Signature-Key` still carries the auth token (four-party) or agent token whose
`cnf.jwk` is the signing key; `authorization` is an *additional* covered
component. Authorization still depends on the auth-token claims + resource
enforcement — the opaque token proves only that the resource previously
authorized this agent (L2343). The example above is simplified; the canonical
spec example (L2346) also covers `aauth-mission`, i.e.
`("@method" "@authority" "@path" "authorization" "aauth-mission" "signature-key")`.

## Current SDK state (audited)

> **Update (2026-06-27):** Re-audited against `src/AAuth`. Two ❌ items below were
> overstated and are corrected inline; the resource-managed *seam* exists but is
> inert. Net: building blocks are scattered across the code but **nothing wires
> them into a working two-party flow**.

- ⚠️ **No production path, but the store seam already exists.** No SDK code emits
  an `AAuth-Access` response header and no middleware reads `Authorization: AAuth`.
  *However*, the opaque-token seam ships already:
  [`Server/IOpaqueTokenStore.cs`](../../../src/AAuth/Server/IOpaqueTokenStore.cs)
  defines `IOpaqueTokenStore` (`IssueAsync`/`ValidateAsync`/`RevokeAsync`),
  `OpaqueTokenInfo` (binds `AgentJkt`, `Scope`, `Expiration`, `Subject`), and an
  `InMemoryOpaqueTokenStore` — doc-commented "§1.1, 2-party flow." It is
  referenced **only** by
  [`tests/AAuth.Conformance/ResourceTokens/OpaqueTokenStoreTests.cs`](../../../tests/AAuth.Conformance/ResourceTokens/OpaqueTokenStoreTests.cs)
  and docs; no `MapAAuth*`, middleware, or DI extension consumes it. Registering
  it is a no-op (see
  [pre-existing inconsistencies](#pre-existing-inconsistencies-to-fix)).
- ⚠️ **Partial consumption path.** No SDK code captures/replays `AAuth-Access`.
  *But* the agent signer
  ([HttpSig/AAuthSigningHandler.cs](../../../src/AAuth/HttpSig/AAuthSigningHandler.cs))
  **already adds `authorization` to the covered components whenever
  `request.Headers.Authorization is not null`** (L217–221 append to the signature
  base; L280–284 list it in `@signature-params`) — the binding MUST (L753, L2716)
  is satisfied at signing time. What is missing is the layer that *sets*
  `Authorization: AAuth <token68>` from a captured `AAuth-Access` value and
  stores the latest per resource origin.
- ✅ **Resource metadata already models the advertisement.**
  [`Server/Metadata/WellKnownEndpoints.cs`](../../../src/AAuth/Server/Metadata/WellKnownEndpoints.cs)
  emits and validates `access_mode` (`AAuthResourceMetadataOptions.AccessMode`,
  validated against `AAuthConstants.AccessModes` incl. `aauth-access-token`,
  L374–380) and `authorization_endpoint` (`AuthorizationEndpoint`, L170–172). The
  `access_mode` constant lives at
  [`AAuthConstants.AccessModes.AAuthAccessToken`](../../../src/AAuth/AAuthConstants.cs)
  (= `"aauth-access-token"`, L60).
- ✅ **Agent DI options already expose the resource-interaction callback.**
  [`AAuthAgentOptions`](../../../src/AAuth/DependencyInjection/AAuthAgentOptions.cs)
  has `OnResourceInteraction` / `OnApprovalPending` / `PollingTimeout`, and
  [`AddAAuthAgent`](../../../src/AAuth/DependencyInjection/AAuthAgentServiceCollectionExtensions.cs)
  wires them through `WithInteractionHandling`.
- ✅ **Adjacent machinery exists.** The interaction handler
  ([Agent/InteractionHandler.cs](../../../src/AAuth/Agent/InteractionHandler.cs))
  and projection ([Headers/Interaction.cs](../../../src/AAuth/Headers/Interaction.cs))
  already drive `202 + requirement=interaction → poll Location → terminal 200`,
  which the resource-managed handshake reuses; only the trailing `AAuth-Access`
  capture + replay is missing. **Gap:** `InteractionHandler.SendAsync` returns the
  terminal `200` but never inspects it for `AAuth-Access`.
- ❌ **No `AAuth-Access` header constant.**
  [`AAuthConstants.Headers`](../../../src/AAuth/AAuthConstants.cs) (L7–28) has
  `Signature`, `Signature-Input`, `Signature-Key`, `AAuth-Error`,
  `AAuth-Requirement`, `AAuth-Mission`, `AAuth-Capabilities` — but no
  `AAuth-Access`. The `Authorization: AAuth` credential scheme is also unmodeled.
- ❌ **No `token68` validator.** Nothing rejects empty / embedded-whitespace /
  control-char values or "more than one credential" (the L756 MUST).
- ❌ **Verification challenge enum has no resource-managed value.**
  [`Server/Verification/AAuthAccessMode.cs`](../../../src/AAuth/Server/Verification/AAuthAccessMode.cs)
  models `IdentityOnly`, `RequireAuthToken`, `AgentTokenRequired` only — there is
  no "resource-managed / issue opaque token" decision. (Note this server-side
  enum is deliberately distinct from the advisory `AAuthConstants.AccessModes`
  metadata strings.)

## SDK touch-point inventory

> **Update (2026-06-27):** Trimmed the agent-side list — the covered-component
> work is already done by the signer (above). See
> [SDK surface to introduce](#sdk-surface-to-introduce) for the consolidated,
> implementation-ready surface.

Agent side:

- A `token68` parse/validate helper (reject empty / embedded whitespace / control
  chars; one credential only) — new `Headers/AAuthAccessHeader.cs` plus an
  `AAuthConstants.Headers.AAuthAccess` constant.
- Capture the `AAuth-Access` response header on every response (including the
  terminal `200` from the interaction poll), store the latest value per resource
  origin, and replay it as `Authorization: AAuth …` on the next request — a small
  per-origin store wired into a `DelegatingHandler` positioned **outer** of
  `AAuthSigningHandler` so the header is present when the signer covers it.
- ~~Add `authorization` to the covered components when a token is present~~ —
  **already handled by the signer** (L217–221, L280–284). The new handler only
  needs to *set* the header; signing picks it up automatically.

Resource side:

- Issue an `AAuth-Access` header (wrapping internal state via `IOpaqueTokenStore`)
  after the resource authorizes the agent (interaction-completed or
  identity-only), wired into the challenge/verification pipeline.
- On inbound requests, parse + `token68`-validate `Authorization: AAuth`, confirm
  `authorization` is in the covered components, `ValidateAsync` it against the
  store, and surface the resulting `OpaqueTokenInfo` to the app.

## SDK surface to introduce

The consolidated, implementation-ready surface — split by side. Items marked
**new** are net-new types; **extend** modifies an existing type; **wire** connects
something that already exists but is inert.

### Agent side

| Kind | Type / member | Responsibility | Spec |
|---|---|---|---|
| **new** | `AAuthConstants.Headers.AAuthAccess = "AAuth-Access"` | Header-name constant (the one missing entry in the `Headers` table) | `#aauth-access`, L738 |
| **new** | `Headers/AAuthAccessHeader.cs` — `Parse`/`TryParse`/`Validate` | `token68` grammar: reject empty, embedded whitespace, control chars, and >1 credential; shared by capture (response) and replay (`Authorization`) | L756 |
| **new** | `IAAuthAccessStore` + `InMemoryAAuthAccessStore` | Per-resource-origin latest-token store (key = scheme+host+port). **Distinct** from the server-side `IOpaqueTokenStore` — agent holds the opaque blob, resource mints it | rolling refresh L754; L2716 |
| **new** | `Agent/AAuthAccessHandler.cs` (`DelegatingHandler`) | Outer of `AAuthSigningHandler`: before send, if the store has a token for the origin, set `Authorization: AAuth <token68>` (signer then auto-covers it); after receive, capture any `AAuth-Access` and update the store (rolling refresh) | L743–754; binding via signer L217–221 |
| **extend** | `AAuthClientBuilder.WithResourceManagedAccess(IAAuthAccessStore? store = null)` | Fluent opt-in that inserts `AAuthAccessHandler` into `BuildHandler()` immediately outside the signer and *inside* `InteractionHandler`, so the terminal `200`'s `AAuth-Access` is captured | `#resource-managed-auth`, L758 |
| **extend** | `InteractionHandler` | On the terminal (non-202) poll response, allow the access handler to observe it (it already returns the `200`; the access handler sits outside and will see it) — confirm ordering, no behavior change needed | L776 |
| **extend** | `AAuthAgentOptions` + `AddAAuthAgent` | Add `EnableResourceManagedAccess` (+ optional `AAuthAccessStore`); when set, call `WithResourceManagedAccess`. `OnResourceInteraction`/`PollingTimeout` already exist and are reused verbatim | L2642 |

### Resource side

| Kind | Type / member | Responsibility | Spec |
|---|---|---|---|
| **wire** | `IOpaqueTokenStore` / `InMemoryOpaqueTokenStore` / `OpaqueTokenInfo` | Already shipped — make the pipeline actually call `IssueAsync`/`ValidateAsync` | `#aauth-access`, L740 |
| **new** | `AAuthAccessMode.ResourceManaged` enum value | A fourth access decision: when no valid `Authorization: AAuth`, return `202 + requirement=interaction`; on completion / identity-only, issue an `AAuth-Access` | `#resource-managed-auth`, L758, L778 |
| **new** | `Server/Verification` (or `Server/Challenge`) consumption | Parse + `token68`-validate inbound `Authorization: AAuth`, **assert `authorization` is in the signed covered components** (reject if absent — the binding MUST), `ValidateAsync` against the store, attach `OpaqueTokenInfo` to `HttpContext` | L753, L2716 |
| **new** | `Server/AAuthHttpContextExtensions` — `IssueAAuthAccess(info)` / `TryGetAAuthAccess(out info)` | App-facing seam to mint/rotate a token onto the response and read the resolved info | L740, L754 |
| **extend** | `AAuthResourceOptions` / `AAuthResourcePipelineOptions` | Opt-in flag (`EnableResourceManagedAccess`) that registers the consumption middleware + `IOpaqueTokenStore` default | metadata L2608 |
| **new** | `MapAAuthAuthorizationEndpoint(...)` helper | **In scope** (owner ruling — demo both spec entry points). Accepts a signed `POST` with `{"scope": …}` (L620), reads the agent token from `Signature-Key`, and runs the same resource-managed decision logic as the reactive path (`202` / issue). `AuthorizationEndpoint` metadata already emits | L605, L620, L2642 |

### Why a separate agent store from `IOpaqueTokenStore`

The flow has **two** parties that each hold the same opaque token string, but for
opposite reasons. They need **two different store types**. The names are similar
(`IOpaqueTokenStore` vs the proposed `IAAuthAccessStore`), so this section spells
out the split to avoid wiring the wrong one.

**The resource mints and understands the token.** Its store,
[`IOpaqueTokenStore`](../../../src/AAuth/Server/IOpaqueTokenStore.cs), is the
mint/validate seam: `IssueAsync` wraps the resource's internal authorization
state into an `OpaqueTokenInfo` that carries **resource-only** meaning, the agent
key thumbprint the token is bound to (`AgentJkt`), the granted `Scope`, the
`Expiration`, and the `Subject`. Only the resource can interpret these. The token
string itself is just a lookup key into that state.

**The agent stores and replays the token but never understands it.** To the agent
the value is **opaque** (spec L740). It never decodes it, never sees `AgentJkt` /
`Scope` / `Expiration`. It only answers one question: *"what is the latest
`AAuth-Access` string I was handed for this resource origin?"* so it can put that
string back into the next `Authorization: AAuth …` request. That is all the
proposed agent-side `IAAuthAccessStore` does: map *resource origin
(scheme+host+port) → latest opaque string*.

| | Resource: `IOpaqueTokenStore` (ships) | Agent: `IAAuthAccessStore` (new) |
|---|---|---|
| Role | Mint + validate the token | Store + replay the token |
| Understands the value? | Yes, it owns `OpaqueTokenInfo` | No, treats it as an opaque blob |
| Keyed by | Token string → `OpaqueTokenInfo` | Resource origin → latest token string |
| Operations | `IssueAsync` / `ValidateAsync` / `RevokeAsync` | get / set latest per origin |
| Lives in | `src/AAuth/Server/` | `src/AAuth/Agent/` (alongside the handler) |

**Why not reuse one type for both.** If the agent reused `IOpaqueTokenStore`, it
would drag resource-side concepts (key-thumbprint binding, scope, expiry
semantics) into a place that has no business knowing or setting them, a leaky
abstraction. Keeping a thin, separate `IAAuthAccessStore` keeps each side's
responsibility honest: the resource owns *what the token means*; the agent owns
*which token to send next*.

**End-to-end data flow** (one round trip plus a rolling refresh):

1. Resource authorizes the agent, calls `IOpaqueTokenStore.IssueAsync(info)`, and
   sends the returned string back as `AAuth-Access: <token68>`.
2. Agent's `AAuthAccessHandler` captures that string and saves it in
   `IAAuthAccessStore` under the resource's origin.
3. Next request, the handler reads the string back and sets
   `Authorization: AAuth <token68>`; the signer covers it automatically.
4. Resource reads the header, calls `IOpaqueTokenStore.ValidateAsync(string)` to
   recover the `OpaqueTokenInfo`, and authorizes.
5. If the resource returns a **new** `AAuth-Access` on any response (rolling
   refresh, L754), step 2 overwrites the stored string; the agent never compares
   or merges, it just keeps the latest.

## Demo resource server: new vs reuse

**Recommendation: introduce a fifth Aria resource server, not reuse an existing
one.** Rationale grounded in the current sample design and the spec:

- The samples follow a strict **one-server-per-access-mode** invariant
  ([samples/README.md](../../../samples/README.md)): Profile :5000 = Identity-Based,
  Calendar :5001 = PS-Asserted, Trips :5002 = mission-aware, Wallet :5003 =
  Federated. Resource-managed (two-party) is the **only** access mode of the four
  (#overview-resource-managed, L279) with no server. Bolting it onto e.g. Profile
  would break that invariant and muddy the narrative.
- Resource-managed is wired *fundamentally differently*: **no PS, no AS**, the
  resource owns its **own consent/login page** and mints **opaque tokens** — it
  "drops in where you use OAuth" (L2624). None of the existing four servers have a
  consent surface of their own (they delegate to the PS), so there is nothing to
  reuse.
- Narrative fit: a service Aria connects to via *the resource's own* OAuth/login,
  then receives an opaque access token. Proposed **Aria Inbox** (email) on
  **:5004** — or Photos/Docs if a non-PII domain is preferred. Endpoints:
  - `GET /messages` — first call returns `202 + AAuth-Requirement:
    requirement=interaction; url=…; code=…` pointing at Inbox's **own** consent
    page (L758); after the user approves and the agent polls `Location`, the
    terminal `200` carries `AAuth-Access: <token68>` (L776).
  - subsequent `GET /messages` calls send `Authorization: AAuth <token>` (signed,
    `authorization` covered) and get `200` directly; a `/messages/rotate`-style
    response demonstrates **rolling refresh** by returning a fresh `AAuth-Access`
    (L754).
  - publishes `access_mode: "aauth-access-token"` and an
    `authorization_endpoint` in its `aauth-resource.json` (L2608, L2642), and
    demonstrates both the reactive `202` and the proactive `POST` entry points
    (L605).
- Port choice `:5004` continues the `500x` resource-server block; PS/AP/AS
  (`5100`/`5301`/`5500`) stay uninvolved, reinforcing "two-party."

## Flow placement in GuidedTour & SampleApp

The spec orders the four access modes **Identity-Based → Resource-Managed →
PS-Asserted → Federated** (overview L279; adoption narrative L2620–2626; the root
[README.md](../../../README.md) Access Modes table already lists Resource-Managed
**second**, L34). Place the new demo in that slot everywhere:

- **GuidedTour** `TourMode` enum
  ([samples/GuidedTour/TourOptions.cs](../../../samples/GuidedTour/TourOptions.cs)):
  insert `ResourceManaged` **between `Identity` and `Autonomous`**. Add a
  `ResourceManaged` step script (reuses the `202 → poll → 200` visuals, adds an
  `AAuth-Access` capture + `Authorization: AAuth` replay row). Add an `InboxUrl`
  (`http://localhost:5004`) option. The flow needs **no** `PersonServerUrl`
  (two-party), unlike Autonomous/Deferred.
- **SampleApp**
  ([samples/SampleApp/Components/Pages](../../../samples/SampleApp/Components/Pages)):
  add an `/inbox` page **between `/identified` and `/calendar`** in nav order,
  mirroring the README's mode order.
- **AgentConsole**: add a path/mode mapping (e.g. a `--signing-mode hwk` call to
  `:5004/messages` that handles the `202` + replays the token), since
  resource-managed is signing-mode-agnostic ("Any" in the README table).
- **e2e**: new `resource-managed.spec.ts` under
  `samples/GuidedTour/playwright-tests/`; add the mode to the `phase8-visual.spec.ts`
  server/mode matrix (`{ mode: ResourceManaged, server: 'Inbox', url: ':5004' }`).

## Docs & samples to update

| Doc / file | Change | Why |
|---|---|---|
| [README.md](../../../README.md) (root) | Add GuidedTour/SampleApp demo links to the **Resource-Managed** row (L34, currently links only the workflow guide); flip the "one protocol surface not yet implemented" sentence (L287) once landed; bump the sample count if a server is added | Today it is listed as a first-class mode with **no runnable demo** |
| [samples/README.md](../../../samples/README.md) | "four Aria resource servers" → five; add the **Inbox** table row + a "Running Individually" subsection; update `make demo` description | Sample inventory + run instructions |
| [docs/workflows/resource-managed-access.md](../../../docs/workflows/resource-managed-access.md) | Replace **aspirational** snippets with the real implemented API (the server-side `IOpaqueTokenStore` snippet currently implies a working wire-up that does not exist); add a live-demo reference | Largest accuracy gap (see inconsistencies) |
| [docs/concepts.md](../../../docs/concepts.md) (L38) | Update the Resource-Managed SDK-surface line beyond just `IOpaqueTokenStore` (add the agent handler + access-mode) | Currently implies the store alone delivers the mode |
| [docs/README.md](../../../docs/README.md) (API map, L210; workflows list) | Add the new agent/resource types to the API map | API map completeness |
| [docs/reference/dependency-injection.md](../../../docs/reference/dependency-injection.md) | Document the new `AddAAuthAgent` flag + resource opt-in + the wired `IOpaqueTokenStore` | DI reference |
| [docs/getting-started.md](../../../docs/getting-started.md) | If it enumerates the modes, add resource-managed | Consistency |
| GuidedTour / SampleApp READMEs | Mention the new flow/page | Per-sample docs |
| [Makefile](../../../Makefile) | Boot the Inbox server in `make demo` (and any `make demo-*` that lists resource servers) | Demo stack |
| [aauth-spec/SPEC-VERSION.md](../../../aauth-spec/SPEC-VERSION.md) | Drop/adjust the "not yet implemented" note for `AAuth-Access` once landed | Spec-status accuracy |

## Pre-existing inconsistencies to fix

Found while auditing; these exist **independent of** the new implementation and
should be corrected (some only become correct once the flow lands):

1. **`docs/workflows/resource-managed-access.md` documents a flow that does not
   run.** Its *Server-Side* snippet registers `IOpaqueTokenStore` as though that
   enables the mode, but **no middleware consumes the store** — the resource never
   emits `AAuth-Access` and never reads `Authorization: AAuth`. The agent snippet
   shows receiving a token that the SDK never captures. The doc compiles but the
   end-to-end behaviour is absent. *(Fix: rewrite against the real API once wired;
   until then it overstates capability.)*
2. **`docs/concepts.md` (L38) and `docs/README.md` (L210)** present
   `IOpaqueTokenStore` as *the* SDK surface for resource-managed, implying it is
   functional. It is an isolated, test-only seam.
3. **Root `README.md` is internally inconsistent.** The Access Modes table (L34)
   lists **Resource-Managed** as a peer of the other three modes (each of which has
   a GuidedTour/SampleApp demo column), yet L287 states the `AAuth-Access` flow is
   "the one protocol surface not yet implemented." A reader gets "supported" and
   "not implemented" from the same document.
4. **Missing `AAuth-Access` header constant.** Every other AAuth header has a
   constant in `AAuthConstants.Headers`; `AAuth-Access` does not, so any future
   code would hard-code the string. *(Fix: add the constant regardless.)*
5. **`OpaqueTokenInfo` carries no rolling-refresh / rotation affordance.** The
   store mints opaque strings but there is no notion of replacing the current token
   on a later response (L754). The agent-side store must own that; the resource
   store may also want a "supersede" helper. *(Design note, not a bug.)*
6. **Research line-cite drift (this doc).** The original recorded the bound-request
   example at "L2343–2348"; in the current vendor it is at **L2346**, and the
   example now also covers **`aauth-mission`** (covered set
   `("@method" "@authority" "@path" "authorization" "aauth-mission"
   "signature-key")`). The simplified example in the Spec-summary above omits
   `aauth-mission` for clarity, which is fine, but the line cite is updated here.

## Gaps & open questions

> **Update (2026-06-27):** OQ1 and OQ3 are now largely resolved by existing code
> (the store seam ships; the signer auto-covers `authorization`). Restated below
> with their resolutions; OQ2/OQ4/OQ5 stand.

- **OQ1 — Opaque-state wrapping seam.** *Resolved:* the SDK already ships the seam
  + demo store (`IOpaqueTokenStore` / `InMemoryOpaqueTokenStore` /
  `OpaqueTokenInfo`). The spec leaves the wrapped format to the resource, so no
  default encryption is mandated. Remaining work is **wiring**, not designing the
  seam. The agent needs its own thin `IAAuthAccessStore` (see
  [SDK surface](#sdk-surface-to-introduce)).
- **OQ2 — Per-origin replay store ownership.** Where does the agent keep the latest
  `AAuth-Access` per resource origin — inside the signing handler, a sibling
  handler, or an injectable store? Default lean: a sibling `DelegatingHandler`
  (`AAuthAccessHandler`) **outer** of the signer, with an injectable in-memory
  store, mirroring the existing handler composition.
- **OQ3 — `authorization` covered-component toggle.** *Resolved:* the signer
  already covers `authorization` automatically whenever the header is present
  (`AAuthSigningHandler` L217–221, L280–284). So the toggle is implicit: the
  access handler sets the header; covering is automatic. No per-request flag
  needed.
- **OQ4 — Rolling-refresh races.** Concurrent in-flight requests may each receive a
  new `AAuth-Access`; define a last-writer-wins update rule and whether to
  serialize. Default lean: last-writer-wins, documented, no serialization.
- **OQ5 — Interaction reuse.** Confirm the resource-managed `202 → poll → 200`
  reuses `InteractionHandler`/`Interaction` unchanged, with only the `AAuth-Access`
  capture added by the outer access handler at the terminal `200`. (Note the
  original wrote `DeferredPoller`; the reused poll loop is in `InteractionHandler`.)
- **OQ6 — `authorization_endpoint` in v1?** *Resolved (in scope, owner ruling):*
  the samples must demonstrate **both** spec entry points (L605), so the build adds
  a `MapAAuthAuthorizationEndpoint` helper (signed `POST` per L620) and the Inbox
  demo exercises the reactive `202` *and* the proactive `POST`. Reverses the
  earlier "out of scope" lean.

## Verification note

Line numbers were read directly from
[`aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md`](../../../aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md):
the original spec summary on 2026-06-25, and the 2026-06-27 additions
(`#aauth-access` L738; `#resource-managed-auth` L758; bound example L2346;
`access_mode` onboarding L2642; `authorization_endpoint` metadata L2608;
**AAuth-Access Security** L2712–2716; overview L279). SDK line cites
(`AAuthSigningHandler` L217–221/L280–284, etc.) reflect the current `src/AAuth`.
Re-verify against source before editing any file — line numbers shift on
re-vendor; the `{#anchor}` and symbol references are durable.
