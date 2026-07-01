# Server-Side API Surface — Research

Research-only analysis of the server-side API surface of the AAuth .NET SDK
(`src/AAuth`) — Resource Servers (RS), Person Servers (PS), and Access Servers
(AS) — measuring the verbosity of consumer setup and grounding a set of
higher-level API options (DI helpers, endpoint builders, fluent methods, and a
decoupled interaction module) in both the spec and the current code.

- **Status:** Research only. No implementation steps, no checkboxes.
- **Date:** 2026-06-27
- **Spec:** [aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md](../../../aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md)
- **SDK root:** [src/AAuth](../../../src/AAuth)

## Method

Three logical change sets were explored in parallel and collated:

1. **Spec grounding** of the three server roles and their obligations.
2. **SDK surface inventory** of the server-side DI, middleware, endpoint
   mappers, options, and seams.
3. **Sample verbosity** measured across all five resource servers plus the PS
   and AS samples.

Per the planning workflow, the highest-stakes claims were re-verified directly
against source. **Spec line numbers reported by a subagent were systematically
wrong (off by 200–700 lines); every spec citation below was re-read and
corrected against the vendored source.** Anchors are the durable reference;
line numbers are precise as of this re-vendor. SDK signatures were read
directly from the files cited.

---

## Part 1 — Spec grounding: what each server role owes

### 1.1 Roles and access modes

The spec defines four resource access modes, additive in parties and capability
(#resource-access-modes table, L217–L228). The "(two-party)" label is shorthand
for resource-managed access, where the resource runs an authorization flow
rather than deciding on identity alone (L219).

| Mode | Parties | Server role(s) involved | Spec |
|---|---|---|---|
| Identity-based | Agent + Resource | RS verifies signature, applies own policy | #overview-identity-access L274 |
| Resource-managed (two-party) | Agent + Resource | RS runs its own consent/OAuth; opaque `AAuth-Access` | #overview-resource-managed L279 |
| PS-asserted (three-party) | Agent + Resource + PS | RS issues resource token (`aud`=PS); PS asserts identity/consent | #fig-ps-asserted L339 |
| Federated (four-party) | Agent + Resource + PS + AS | RS issues resource token (`aud`=AS); PS federates to AS; AS mints | #resource-access-modes L223 |

Missions are an **orthogonal, OPTIONAL** governance layer; any agent with a `ps`
claim can use PS governance regardless of which access mode a resource uses
(#agent-adoption-path L2624; mission-aware resource tokens embed the mission
reference, #resource-token-structure L795).

### 1.2 Resource Server obligations

- **Metadata `/.well-known/aauth-resource.json`** (#resource-metadata L2570;
  the `issuer`/`jwks_uri` common fields are also defined in a shared metadata
  table at L2443). REQUIRED: `issuer` (L2598); `jwks_uri` (REQUIRED only when the
  resource issues resource tokens or makes signed calls — a pure identity-verifier
  MAY omit it, L2599). OPTIONAL: `access_mode` (`agent-token` | `aauth-access-token`
  | `auth-token`, default `agent-token`, **advisory** — runtime `AAuth-Requirement`
  stays authoritative and a resource MAY mix modes per endpoint, L2600);
  `authorization_endpoint` (L2608); `scope_descriptions` (L2610);
  `signature_window` (seconds, default 60, L2611); `additional_signature_components`
  (L2612); plus `name`/`description`/`logo_uri`/`tos_uri`/`policy_uri`/
  `revocation_endpoint`/`login_endpoint`.
- **Request signature verification.** Covered components MUST include `@method`,
  `@authority`, `@path`, `signature-key`; `created` MUST be within the signature
  window (default 60 s); replay caches are OPTIONAL (#resource-token-structure
  freshness and the covered-component mandate live in the Signature-Key profile,
  cross-referenced from L789, L2621).
- **Challenge / requirement responses** (#requirement-responses L2003;
  Requirement Values table L2025):
  - `requirement=agent-token` → `401`, no params (identity-only RS that wants the
    AAuth agent token specifically, #requirement-agent-token L725).
  - `requirement=auth-token` → `401`, MUST carry a `resource-token` JWT
    (#requirement-auth-token L780). MAY re-challenge a request that already
    carries an auth token (step-up, L789).
  - `requirement=interaction` → `202` + `Location` + `Retry-After` +
    `url`/`code` (#interaction-required L2042; resource-managed variant
    #resource-managed-auth L758).
  - Only the AS may issue `requirement=claims` (Requirement Values table, the
    `claims` row is RS=blank PS=blank AS=Y, L2036).
- **Resource token structure** (#resource-token-structure L795): `typ:
  aa-resource+jwt`; payload `iss`/`dwk=aauth-resource.json`/`aud`/`jti`/`agent`/
  `agent_jkt`/`iat`/`exp`/`scope`; OPTIONAL `mission` (when mission-aware) and
  `interaction` (when the RS runs its own user-facing flow first). `aud` = PS URL
  (three-party) or AS URL (four-party) (L613–L616, L795). SHOULD live ≤ 5 minutes
  (L820).
- **Resource-managed `AAuth-Access`** (#aauth-access L738): opaque `token68`
  response header; agent replays it as `Authorization: AAuth <token68>` and MUST
  cover `authorization` in the signature (L752). Rolling refresh: a new header on
  any response replaces the token (L754). Recipients MUST reject empty / embedded
  whitespace / >1 credential (L756; security at #aauth-access-security L2712).

### 1.3 Interaction / deferred-consent handling (the decoupling target)

This is the surface the user wants decoupled from payload endpoints. The spec
treats interaction generation and the poll loop as a **self-contained protocol
module**, separable from the data the endpoint serves:

- **Interaction code is a correlation identifier, NOT a credential** — the code
  alone MUST NOT authorize the decision; the approve/deny decision is recorded on
  an authenticated channel separate from the code (#interaction-code-format,
  "Correlation only", L2078).
- **Code format is fully specified and uniform**: Crockford base32 alphabet,
  ≥ 40 bits entropy (≥ 8 symbols) from a CSPRNG, optional presentational hyphens,
  case-insensitive with `I`/`L`→`1` `O`→`0` folding, single-use, rate-limited,
  expiring no later than the pending request (#interaction-code-format L2066–L2098).
  None of this is endpoint-specific — it is identical for every resource, PS, and
  AS.
- **Poll loop is uniform**: `202` + `Location` (same origin) + `Retry-After`
  (REQUIRED) + `Cache-Control: no-store`; agent switches to GET and polls;
  default interval 5 s; `429`→ +5 s linear backoff (#deferred-responses L2148;
  state machine L2206). `requirement=approval` is the same poll loop with no user
  URL (#approval-pending L2133).
- **Ownership split**: the server owns the consent/interaction page **and** the
  poll endpoint, but these are distinct concerns from serving the protected
  payload. A resource MAY also relay through the PS's `interaction_endpoint`
  before directing the user itself (#interaction-relay L2086).

**Implication for the SDK:** code generation, pending tracking, the `202`
emission, and the poll/terminal response are a reusable unit. A payload endpoint
("serve my messages") should *opt in* to that unit, not re-implement it inline.
The current SDK has the low-level primitives (`InteractionRequiredAAuth`,
`IssueAAuthAccessAsync`, `IOpaqueTokenStore`) but no orchestration unit — see
Part 3.

### 1.4 Person Server obligations

- **Metadata `/.well-known/aauth-person.json`** (#ps-metadata L2492). REQUIRED:
  `issuer` (L2518), `token_endpoint` (L2526), `jwks_uri` (L2533). OPTIONAL:
  `mission_endpoint`/`permission_endpoint`/`audit_endpoint`/`interaction_endpoint`/
  `mission_control_endpoint`/`revocation_endpoint`; RECOMMENDED `scopes_supported`,
  `claims_supported` (L2530–L2536).
- **Token endpoint** (#ps-token-endpoint L855): signed POST presenting the agent
  token via `Signature-Key sig=jwt`. Body REQUIRED `resource_token`; OPTIONAL
  `upstream_token` (call chaining), `subagent_token`, `justification`, `prompt`,
  `platform`, `device`, `capabilities`. Routes on the resource token's `aud`:
  `aud`=PS → three-party mint; `aud`=AS → federate (#ps-as-federation). Sub-agent
  single-level-depth rule applies. Returns `200 {auth_token, expires_in}` or
  `202` interaction.
- **Governance endpoints** (mission creation, permission, audit, interaction):
  request/response shapes per #mission-endpoint, #permission-endpoint,
  #audit-endpoint, #interaction-endpoint; all enforce the `mission_terminated`
  rule.

### 1.5 Access Server obligations

- **Metadata `/.well-known/aauth-access.json`** (#access-server-metadata L2537).
  REQUIRED: `issuer` (L2558), `token_endpoint` (L2566), `jwks_uri` (L2568).
- **Token endpoint** (#as-token-endpoint L1471): PS→AS signed POST (PS signs with
  `jwks_uri` scheme); body `resource_token` + `agent_token` REQUIRED,
  `subagent_token`/`upstream_token` OPTIONAL. Decisions: `200` mint (auth token
  marked `dwk=aauth-access.json`), `202 requirement=claims` (#requirement-claims
  L1553, AS-only), `202 requirement=interaction`, `402 Payment Required`.

---

## Part 2 — Current SDK server-side surface

The SDK already ships a substantial server surface. The problem is **shape and
adoption**, not absence. Inventory:

### 2.1 DI registration extensions ([src/AAuth/DependencyInjection](../../../src/AAuth/DependencyInjection))

| Method | Registers | Notes |
|---|---|---|
| `AddAAuthResource(Action<AAuthResourceOptions>)` | `AAuthVerifier`, `JwksClient` (via `new HttpClient()`), `ISignatureKeyResolver`, `IJtiStore`, `IOpaqueTokenStore` (opt), `AAuthResourceMetadataOptions` | **Bypassed by every sample** — see Part 3.1 |
| `AddAAuthAuthentication()` | the `AAuth` auth scheme | thin wrapper over `AddScheme` |
| `AddAAuthAuthorization()` | `AAuthScopeHandler` + `AAuth.Authenticated`/`Identified`/`Authorized` policies | |
| `AddAAuthScopePolicy(name, scope)` / `AddAAuthRolePolicy(name, role)` | one named policy each | **name is a magic string** repeated at the call site of `RequireAuthorization` |
| `AddAAuthDiscovery(Action<AAuthDiscoveryOptions>?)` | shared `MetadataClient` + `JwksClient` singletons | **unused by samples** |
| `AddAAuthGovernance()` | mission store/log + decider/audit/relay seams (all `TryAdd`) | PS-side |
| `AddAAuthInteractionRelay(delegate)` / `AddAAuthDeferredConsent()` | PS user-channel + deferred-consent store | PS-side |

### 2.2 Middleware / endpoint extensions ([AAuthApplicationBuilderExtensions.cs](../../../src/AAuth/DependencyInjection/AAuthApplicationBuilderExtensions.cs))

- `UseAAuthVerification(AAuthVerificationOptions?)` — signature + optional issuer
  verification middleware.
- `UseAAuthChallenge(ChallengeOptions)` — emits the `401 requirement=auth-token`
  challenge with a freshly signed resource token.
- `UseAAuthIntermediary(verify, challenge)` — convenience pair for call-chaining
  resources.
- `MapAAuthWellKnown()` — DI-driven metadata (reads `AAuthResourceMetadataOptions`).
- `MapAAuthAuthorizationEndpoint(pattern, handler)` — proactive
  `authorization_endpoint`; validates JSON content type / body and hands the
  verified request + scope to the handler.
- `MapAAuthResource(Action<AAuthResourcePipelineOptions>?)` — **one-call pipeline**:
  well-known + verification + challenge. **Single access mode, single default
  scope for the whole app** (see Part 3.2).

### 2.3 Role-specific one-call mappers

- `MapAAuthAccessServer(AAuthAccessServerOptions)` ([Access/AAuthAccessServerEndpoints.cs](../../../src/AAuth/Access/AAuthAccessServerEndpoints.cs))
  — well-known + verification + `POST /token` + `/pending`. Delegates the
  allow/deny/defer decision to `IAccessPolicy`. **The AS sample uses this.**
- `MapAAuthPersonServer(AAuthPersonServerOptions)` ([Person/AAuthPersonServerEndpoints.cs](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs))
  — well-known + verification + `POST /token` + `/pending`, three-/four-party +
  mission gate + sub-agents. Delegates to `IIdentityClaimsAsserter`. **The PS
  sample does NOT use this** — it hand-rolls `/token` (Part 3.3).
- `MapAAuthGovernance(Action<AAuthGovernancePipelineOptions>?)` — mission /
  permission / audit / interaction + deferred-consent poll.

### 2.4 Building blocks

- Verification: `AAuthVerificationMiddleware`, `AAuthVerificationOptions`
  (`.SignatureOnly()` factory; `RequireIssuerVerification`,
  `TrustedAuthTokenIssuers`, `TrustedAgentProviderIssuers`, `ResourceIdentifier`,
  `MaxActDepth`, `ClockSkew`, `MaxFutureSkew`, `Clock`), `AAuthVerificationResult`
  (Features), `AAuthAccessMode` enum (`IdentityOnly`/`RequireAuthToken`/
  `AgentTokenRequired`/`ResourceManaged`), `AAuthAuthenticationHandler`,
  `AAuthLevel`.
- Challenge: `AAuthChallengeMiddleware`, `ChallengeOptions` (`AccessMode`,
  `ResourceSigningKey`, `ResourceKeyId`, `ResourceIdentifier`,
  `PersonServerAudience`, `DefaultScopes`, `AllowedSignatureKeySchemes`,
  `MissionAware`).
- `HttpContext` helpers ([AAuthHttpContextExtensions.cs](../../../src/AAuth/Server/Verification/AAuthHttpContextExtensions.cs)):
  `GetAAuthVerification`, `GetAAuthParsedKey`, `GetAAuthTokenType`,
  `ChallengeAAuth`, `SetAAuthError`, and the resource-managed trio
  `ResolveAAuthAccessAsync` / `IssueAAuthAccessAsync` / `InteractionRequiredAAuth`.
- Metadata: `WellKnownEndpoints.MapAAuth{Resource,Agent,PersonServer,AccessServer}WellKnown`
  + the four `*MetadataOptions` classes. **`AAuthResourceMetadataOptions` carries
  `SignatureWindow`, `AccessMode`, `AuthorizationEndpoint`** — which the DI
  `AAuthResourceOptions` does not expose (Part 3.1).
- Stores/seams: `IOpaqueTokenStore`/`InMemory`, `IJtiStore`/`InMemory`,
  `IAccessPolicy`/`IAccessPendingStore`, `IIdentityClaimsAsserter`/
  `IPersonPendingStore`, governance `IMission*`/`IPermissionDecider`/`IAuditSink`/
  `IInteractionRelay`/`IDeferredConsentStore`.

---

## Part 3 — Verbosity analysis (grounded in the samples)

The five resource servers under [samples/MockResourceServers](../../../samples/MockResourceServers)
cover all four access modes. Each `Program.cs` repeats the same scaffolding. The
table shows what is identical vs. what actually varies.

| Server | Mode | Verification | Challenge | Hand-rolled extras |
|---|---|---|---|---|
| [Profile](../../../samples/MockResourceServers/Profile/Program.cs) | identity | `SignatureOnly()` ×3 paths | none | — |
| [Calendar](../../../samples/MockResourceServers/Calendar/Program.cs) | 3-party | `FullVerification()` | `ChallengeForScope(scope)` ×3 | scope+role policies |
| [Trips](../../../samples/MockResourceServers/Trips/Program.cs) | mission | `FullVerification()` | `ChallengeForMission(scope)` (`MissionAware=true`) ×2 | — |
| [Wallet](../../../samples/MockResourceServers/Wallet/Program.cs) | federated | `FederatedVerification()` (trust = AS) | `ChallengeForFederated(scope)` (`PersonServerAudience`=AS) ×2 | — |
| [Inbox](../../../samples/MockResourceServers/Inbox/Program.cs) | resource-managed | `SignatureOnly()` | none | **interaction codegen + PendingStore + /consent + /pending + /consent/approve** |

### 3.1 DI verbosity — the high-level helper exists but is unused

Every resource server hand-registers the same six-or-seven services instead of
calling `AddAAuthResource`:

```csharp
builder.Services.AddSingleton(resourceKey);
builder.Services.AddSingleton(new AAuthVerifier { MaxAge = TimeSpan.FromSeconds(signatureWindowSeconds) });
builder.Services.AddSingleton<IJtiStore, InMemoryJtiStore>();
builder.Services.AddSingleton<MetadataClient>(sp => new MetadataClient(sp.GetRequiredService<IHttpClientFactory>().CreateClient("aauth-metadata")));
builder.Services.AddSingleton<JwksClient>(sp => new JwksClient(sp.GetRequiredService<IHttpClientFactory>().CreateClient("aauth-jwks")));
builder.Services.AddSingleton<ISignatureKeyResolver>(sp => new DefaultSignatureKeyResolver(sp.GetRequiredService<JwksClient>()));
builder.Services.AddHttpClient("aauth-metadata");
builder.Services.AddHttpClient("aauth-jwks");
```

This is **identical across all five resource servers plus the PS and AS samples**
(≈ 8–10 lines each). Why is `AddAAuthResource` bypassed? Three concrete gaps:

1. **`HttpClient` hygiene.** `AddAAuthResource` builds its `JwksClient` from
   `new HttpClient()`; the samples deliberately route discovery through named
   `IHttpClientFactory` clients (`aauth-metadata`, `aauth-jwks`) so the e2e
   harness can redirect them in-process. The helper offers no hook for this.
2. **Metadata field coverage.** Samples need `SignatureWindow`, `AccessMode`, and
   `AuthorizationEndpoint` in the published document; `AAuthResourceOptions` (the
   DI options) exposes none of these, so samples call
   `MapAAuthResourceWellKnown(new AAuthResourceMetadataOptions { … })` directly
   and skip the DI-stored metadata entirely.
3. **No middleware story.** `AddAAuthResource` registers services but the samples
   still need per-path verification/challenge, which the helper does not address
   — so once they are hand-wiring middleware anyway, hand-wiring DI is a small
   marginal cost and keeps everything in one visible block.

Net: the **DI helper and the actual consumer path have diverged**; the helper is
dead code in practice.

### 3.2 Middleware / path mapping — the one-call helper is too coarse

`MapAAuthResource` collapses well-known + verification + challenge into one call,
but `AAuthResourcePipelineOptions` carries a **single** `AccessMode` and a
**single** `DefaultScopes` for the whole application. Real resources gate
different paths with different scopes (`/events` read vs `/events/write` write vs
`/events/admin` role). So every multi-scope server drops back to raw middleware:

```csharp
app.UseWhen(ctx => ctx.Request.Path.StartsWithSegments("/events/write"),
    branch => { branch.UseAAuthVerification(FullVerification());
                branch.UseAAuthChallenge(ChallengeForScope(ScopeWrite)); });
app.UseWhen(ctx => ctx.Request.Path.StartsWithSegments("/events/admin"),
    branch => { branch.UseAAuthVerification(FullVerification());
                branch.UseAAuthChallenge(ChallengeForScope(ScopeRead)); });
app.UseWhen(ctx => ctx.Request.Path.StartsWithSegments("/events")
        && !ctx.Request.Path.StartsWithSegments("/events/write")
        && !ctx.Request.Path.StartsWithSegments("/events/admin"),
    branch => { branch.UseAAuthVerification(FullVerification());
                branch.UseAAuthChallenge(ChallengeForScope(ScopeRead)); });
```

Pain points, each repeated in Calendar/Trips/Wallet:

- A `FullVerification()` / `ChallengeForX()` **local factory lambda** is declared
  per server purely to avoid copy-pasting the options object.
- **Prefix disambiguation is manual and error-prone** — the general `/events`
  branch must hand-exclude `/events/write` and `/events/admin`, and the comment
  in every file warns that more-specific routes must be declared first.
- **Verification is re-registered per branch** even though it is identical for
  every path on the server.
- The challenge differs from the verification only by `scope` (Calendar/Trips) or
  by an `aud`/trust swap (Wallet) or a `MissionAware` flag (Trips) — i.e. **the
  variation is a tiny, declarative delta** that today requires a full
  `UseWhen` + two `Use*` calls.

### 3.3 Authorization-policy ceremony

Scope/role gating is a three-touch dance with a magic string:

```csharp
builder.Services.AddAAuthScopePolicy("AAuth.Scope.calendar.read", ScopeRead);   // 1. register name↔scope
…
app.MapGet("/events", …).RequireAuthorization("AAuth.Scope.calendar.read");      // 2. reference the name
```

The policy name (`"AAuth.Scope.calendar.read"`) is an opaque string that must be
kept in sync between registration and use, and it duplicates the scope value it
gates. There is no `.RequireAAuthScope("calendar.read")` endpoint extension that
would register-and-apply in one place.

### 3.4 Interaction generation embedded in a payload endpoint (Inbox)

This is the clearest instance of the coupling the user flagged. The Inbox is a
resource that **serves email payloads**, but its `Program.cs` also contains the
entire interaction subsystem inline:

- `NewInteractionCode()` — hand-rolled 8-byte hex code generator. **Note: this is
  hex, not the spec's Crockford base32 (#interaction-code-format L2070); a shared
  SDK generator would also fix this latent conformance gap.**
- a bespoke `PendingStore` class (+ `PendingConsent` with a `volatile bool`) to
  track in-flight consent.
- a `RequireConsent(ctx, scope)` helper that ties code generation + pending
  tracking + `ctx.InteractionRequiredAAuth(...)` together.
- `GET /pending/{code}` — the poll endpoint (202-or-issue logic).
- `GET /consent`, `POST /consent/approve` — the consent page (≈ 40 lines of
  inline HTML) and its form handler.

The payload itself is three lines (`/messages` returns `sampleMessages`). The
remaining ≈ 120 lines are interaction plumbing that is **identical in shape for
any resource-managed resource** and is exactly the spec's self-contained
interaction module (Part 1.3). The SDK gives the primitives
(`InteractionRequiredAAuth`, `IssueAAuthAccessAsync`, `IOpaqueTokenStore`) but no
orchestration, so each resource re-implements the loop — and can drift from the
spec (the hex code above).

### 3.5 PS sample bypasses its own one-call mapper

`MapAAuthPersonServer` exists, but [MockPersonServer/Program.cs](../../../samples/MockPersonServer/Program.cs)
hand-rolls `POST /token` and wires ≈ 15 services directly. The likely cause: the
mapper delegates the decision to a single `IIdentityClaimsAsserter`, but the
sample needs custom mission/consent/federation behavior threaded through several
stores, and the mapper exposes no seam for that composition. This signals that
the **role mappers are rigid**: usable for the happy path, abandoned the moment a
server needs to interleave custom logic — the same rigidity that makes
`MapAAuthResource` unusable for multi-scope resources (3.2).

---

## Part 4 — Design options for a cleaner high-level surface

Four problem areas, each with options and tradeoffs. They compose; a likely
recommendation picks one per area. **Spec conformance is paramount and backward
compatibility is not a goal** (per the repo's planning principles), so these may
replace the diverged helpers rather than wrap them.

### 4.1 DI — one honest "register the common types" call

**Goal:** a single call that registers everything a resource needs, that the
samples would actually use, closing the three gaps in 3.1.

- **Option A — extend `AddAAuthResource` to parity and adopt it.** Add
  `SignatureWindow`, `AccessMode`, `AuthorizationEndpoint`, and an
  `Action<IHttpClientBuilder>?`/named-client hook to `AAuthResourceOptions`; have
  it register the discovery clients through `IHttpClientFactory`; make
  `MapAAuthResource`/`MapAAuthWellKnown` read the DI-stored metadata. Then
  migrate all samples onto it. *Pro:* no new concept; deletes ≈ 10 lines/server.
  *Con:* `AAuthResourceOptions` grows a metadata sub-object (it currently
  half-owns metadata).
- **Option B — split into `AddAAuthResourceCore()` + builder.** A parameterless
  (or minimal) core registration returning an `IAAuthResourceBuilder` with
  `.WithDiscoveryHttpClient(name)`, `.WithMetadata(...)`, `.WithReplayDetection(false)`,
  `.WithResourceManagedAccess()`. *Pro:* progressive disclosure; mirrors
  `AddAuthentication().AddScheme(...)`. *Con:* one more type.
- **Option C — fold discovery into the resource registration.** Have the resource
  registration call `AddAAuthDiscovery` internally (idempotent via `TryAdd`) so
  consumers never wire `MetadataClient`/`JwksClient`. Combine with A or B.

**Lean:** A + C (extend to parity, pull discovery in, adopt in samples). Lowest
concept count, directly kills the dead-helper divergence.

### 4.2 Endpoint mapping — declarative per-route protection

**Goal:** express "this route needs an auth token with scope X" without a
`UseWhen` + two `Use*` calls and manual prefix exclusion.

- **Option A — endpoint metadata + a single global filter.** Add fluent endpoint
  extensions that attach AAuth metadata to a route, and register **one**
  verification/challenge filter that reads that metadata per matched endpoint:

  ```csharp
  app.MapGet("/events", handler).RequireAAuth(scope: "calendar.read");
  app.MapGet("/events/write", handler).RequireAAuth(scope: "calendar.write");
  app.MapGet("/events/admin", handler).RequireAAuth(scope: "calendar.read", role: "calendar.owner");
  app.MapGet("/pseudonymous", handler).RequireAAuthSignature();          // identity-only
  ```

  Routing already does longest-prefix matching, so this **eliminates the manual
  `/events/write` exclusions** entirely. *Pro:* idiomatic Minimal-API; verification
  registered once; the per-route delta is exactly the declarative scope/role.
  *Con:* challenge-on-`401` historically lives in middleware (runs before
  routing); moving it to an endpoint filter/`IAuthorizationMiddlewareResultHandler`
  needs care so the resource token is still minted on the challenge path.
- **Option B — a route-group/builder DSL.** A
  `app.MapAAuthResourceGroup(resource => { resource.MapScoped("/events", "calendar.read", handler); … })`
  that owns verification once and emits per-route challenge config. *Pro:* one
  obvious home for resource config; *Con:* a parallel mapping vocabulary to learn.
- **Option C — per-route options on `MapAAuthResource`.** Extend the pipeline
  options with a route→(mode, scope, role, missionAware) map. *Pro:* smallest
  change; *Con:* config-as-data is clunky for handlers and re-introduces
  ordering/prefix concerns.

**Lean:** A (endpoint metadata + global filter), with `RequireAAuth(...)` /
`RequireAAuthSignature()` and `RequireAAuthScope/Role` sugar that also removes the
named-policy ceremony of 3.3. Verify the challenge-minting can run as a filter
before settling.

### 4.3 Interaction — a decoupled, opt-in module

**Goal:** a payload endpoint opts into resource-managed interaction without
embedding code generation, pending tracking, the consent page wiring, or the poll
endpoint (3.4), and gets a spec-correct code generator for free (1.3).

- **Option A — `IInteractionFlow` service + `MapAAuthInteraction`.** Register an
  interaction service (`AddAAuthResourceManaged(...)`) that owns:
  - a spec-conformant Crockford-base32 code generator (≥ 40 bits, single-use,
    rate-limited, expiry) — replaces every hand-rolled `NewInteractionCode`;
  - an `IInteractionPendingStore` (default in-memory) for parked consents;
  - `MapAAuthInteractionPoll(pattern)` to emit the `GET /pending/{code}` loop
    (202 / issue `AAuth-Access` on approval) from the store automatically;
  - a hook for the resource's own consent page to call
    `interaction.Approve(code)` (the SDK owns the protocol; the app owns only the
    page's look-and-feel and the user authentication the spec leaves out, L2078).

  A payload endpoint then reads:

  ```csharp
  app.MapGet("/messages", async ctx =>
      await ctx.ResolveAAuthAccessAsync(store) is { } info
          ? Results.Ok(new { info.Scope, messages })
          : await ctx.RequireAAuthInteraction("inbox.read"));   // SDK: code + park + 202
  ```

  with no `PendingStore`, no `/pending`, no `NewInteractionCode` in the resource.
  *Pro:* directly answers "serve-a-payload endpoints shouldn't embed interaction
  generation"; centralizes the conformance-sensitive code format; opt-in.
  *Con:* the SDK must own a poll endpoint and a pending store (new surface).
- **Option B — keep primitives, add only the code generator + a poll-endpoint
  mapper.** Smaller: ship `AAuthInteractionCode.Generate()` and
  `MapAAuthInteractionPoll`, leave parking to the app. *Pro:* minimal; fixes the
  conformance gap and the most-repeated endpoint. *Con:* the app still wires the
  store and the `RequireConsent` glue.
- **Option C — unify with PS deferred-consent.** The PS side already has
  `IDeferredConsentStore` + a `/governance-pending` poll
  (`AddAAuthDeferredConsent`, `MapAAuthGovernance`). Generalize that parked-poll
  machinery so RS resource-managed and PS governance share one pending/poll
  engine. *Pro:* one mental model and one tested implementation for "park → 202 →
  poll → resolve" across all three roles; *Con:* larger refactor; must keep the
  RS opaque-token issuance vs PS auth-token mint distinct.

**Lean:** A for the resource-managed RS surface, designed so its pending/poll
core (C) can be the same engine the PS governance mapper already uses — i.e.
build A on a shared park/poll primitive.

### 4.4 Role mappers — add composition seams

**Goal:** make `MapAAuthPersonServer` (and the AS/governance mappers) usable for
real servers that interleave custom logic (3.5), so they are not abandoned.

- **Option A — richer delegate seams.** Where the mapper today takes a single
  asserter, accept per-decision hooks (pre/post mint, mission-gate override,
  federation router) so a server customizes one step without forking the whole
  `/token` handler.
- **Option B — expose the handler as composable middleware/endpoint filters** so a
  server can wrap or short-circuit specific stages.
- **Option C — document the mappers as "reference happy path" and keep the
  building blocks first-class** for servers that need full control (status quo,
  but make it explicit). *Pro:* honest; *Con:* leaves the PS sample verbose.

**Lean:** A — the asserter/policy seams already prove the pattern; extend them to
the mission/federation steps the PS sample needed.

### 4.5 Cross-cutting design principles

- **Layered surface, 80/20.** Three layers: (1) interfaces + primitives,
  (2) options-driven middleware, (3) one-call DI + map convenience. The
  high-level surface reads like intent for ~80% of cases (`AddAAuthResource(...)`
  + `RequireAAuth(...)`); the other ~20% composes the primitives
  (`UseAAuthVerification`, `ChallengeOptions`, `IOpaqueTokenStore`), which stay
  public. **Invariant:** every high-level call must be expressible as the
  fine-grained calls beneath it, and every default must be replaceable via DI.
- **Configurability ceiling.** The high-level surface carries the common shape
  plus a *named, closed* set of axes — per-route access mode / scope / role /
  mission-aware; resource-level trusted issuers / keys / issuer / discovery.
  Variation beyond that falls through to the primitives rather than becoming
  another option, and high-level calls default boilerplate from DI so each call
  carries only the per-route delta. The fix for `MapAAuthResource` is to *split*
  resource-level config (DI) from per-route intent (endpoint), not to grow its
  options.
- **Opt-in, not embedded:** interaction, replay detection, resource-managed
  access, mission-awareness are all flags/calls a server turns on — a plain
  payload endpoint carries none of them.
- **Spec-owned vs app-owned split:** the SDK owns the wire (code format, headers,
  poll loop, token shapes); the app owns only policy and presentation (the consent
  page's HTML, the user authentication the spec defers, L2078).
- **One park/poll engine:** RS resource-managed, PS governance deferred-consent,
  and AS pending decisions are the same `202 + Location + poll` primitive
  (#deferred-responses L2148) — converging them reduces surface and drift.

---

## Part 5 — Gaps and open questions

> **Update (2026-06): simulated fix run.** A spike validated the riskiest
> decision (per-route protection) against the real multi-scope three-party flow,
> and code-tracing corrected two open questions. The spike (a new
> `AAuthEndpointExtensions` + a Calendar migration) was reverted after
> validation; findings below. Build stayed green; all **9 `CalendarFlowTests`
> passed** against the migrated server.
>
> - **G1 — RESOLVED (viable).** A single post-routing middleware reading
>   `endpoint.Metadata.GetMetadata<AAuthEndpointRequirement>()` ran verification
>   **and** minted the `401 requirement=auth-token` challenge correctly — the
>   standard `UseRouting → UseAAuth → UseAuthentication → UseAuthorization`
>   ordering that `UseAuthorization` itself uses. It composes the **existing**
>   `AAuthVerificationMiddleware` + `AAuthChallengeMiddleware` per endpoint (no
>   rewrite). `.RequireAAuth(scope:, role:)` replaced 3 `UseWhen` branches, 2
>   factory lambdas, 3 `AddAAuthScopePolicy` registrations, and the magic-string
>   `.RequireAuthorization("AAuth.Scope.…")` — Calendar's middleware/policy block
>   went from ≈ 45 lines to ≈ 10, and the manual `/events/write` prefix
>   exclusions vanished (routing's longest-match handles them).
>   - **New footgun (plan must address):** if a consumer forgets explicit
>     `app.UseRouting()`, `GetEndpoint()` is null for every request and the
>     middleware silently passes protected endpoints through **unverified**. The
>     plan must fail-closed (or ship a single ordered entry-point so ordering
>     can't be gotten wrong).
> - **G2 — RESOLVED (safe).** No test asserts the Inbox hex code format; the
>   only `tests/` match was an unrelated `token68` string. Swapping to a shared
>   Crockford-base32 generator is a free conformance fix.
> - **G4 — CORRECTED.** The integration harness does **not** override the named
>   `aauth-metadata`/`aauth-jwks` clients — it does
>   `services.RemoveAll<MetadataClient>(); services.RemoveAll<JwksClient>();` then
>   re-registers those **singletons** wrapping a `MultiHostHandler`
>   ([CalendarFlowTests.cs](../../../tests/AAuth.Tests/Integration/CalendarFlowTests.cs#L59-L99)).
>   So the DI helper only needs to keep `MetadataClient`/`JwksClient` as
>   overridable singletons — which `AddAAuthResource` already does via
>   `TryAddSingleton`. The named clients are connection hygiene, not the test
>   seam. 4.1 is lower-risk than stated.
> - **G6 — CORRECTED.** `MapAAuthPersonServer` already covers three-party,
>   four-party federation (same background-`Task.Run` relay shape), the mission
>   three-gate, and sub-agents — delegating identity/consent to
>   `IIdentityClaimsAsserter`. MockPersonServer's hand-rolled `/token` largely
>   **duplicates** it. So "do role mappers now" is mostly a **migration**:
>   move the sample's consent/mission/claims logic into a
>   `SampleIdentityClaimsAsserter` and adopt the mapper, adding seams only for
>   micro-gaps surfaced during migration (candidates: the `requireConsent`
>   toggle, demo role/group derivation, federated `OnClaimsRequired` answering
>   arbitrary claim names via `ProjectClaims`).

- **G3 — `AAuthResourceOptions` vs `AAuthResourceMetadataOptions` ownership.**
  Two overlapping metadata models exist. Should DI options own metadata fully
  (4.1-A) or delegate to a metadata sub-object? Affects whether `MapAAuthWellKnown`
  can replace the direct `MapAAuthResourceWellKnown` calls. The spike also showed
  `UseAAuth` wants the resource signing key + issuer + identifier — these should
  default from the DI-registered metadata so the only per-call config is *trust*
  (`TrustedAuthTokenIssuers`). This ties decisions 1 and 2 together.
- **G5 — Park/poll unification scope.** How much of the PS `IDeferredConsentStore`
  + `/governance-pending` engine can be generalized to RS resource-managed
  without conflating opaque-token issuance (RS) with auth-token minting (PS)?

---

## Appendix — Source references

- Spec: [aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md](../../../aauth-spec/v08/draft-hardt-oauth-aauth-protocol.md)
  (anchors and verified line numbers cited inline).
- Prior convenience-API work:
  [.agent/plans/2026-05-23-convenience-apis/research.md](../2026-05-23-convenience-apis/research.md)
  (agent-side focus; server-side gaps 5–6 there overlap with Part 3.1 here).
- DI: [src/AAuth/DependencyInjection](../../../src/AAuth/DependencyInjection).
- Role mappers: [Access/AAuthAccessServerEndpoints.cs](../../../src/AAuth/Access/AAuthAccessServerEndpoints.cs),
  [Person/AAuthPersonServerEndpoints.cs](../../../src/AAuth/Person/AAuthPersonServerEndpoints.cs).
- Samples: [samples/MockResourceServers](../../../samples/MockResourceServers),
  [samples/MockPersonServer/Program.cs](../../../samples/MockPersonServer/Program.cs),
  [samples/MockAccessServer/Program.cs](../../../samples/MockAccessServer/Program.cs).
</content>
</invoke>
