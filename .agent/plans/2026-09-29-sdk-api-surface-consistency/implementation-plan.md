# SDK API Surface Consistency — Implementation Plan

Research: [research.md](research.md). Rulings:
[implementation-log.md](implementation-log.md).

## Goal

Make the server-facing and client-facing SDK APIs follow one consistent set of
.NET hosting conventions:

- how components are constructed;
- how configuration flows in (`IOptions<T>`, `IConfiguration`);
- how callbacks and seams are supplied (DI interfaces);
- how identity is declared once per role.

After this work:

- a host app configures an agent, resource, PS, or AS with one `Add*` call
  (optionally bound from configuration) and one `Map*`/`Use*` call;
- every default is replaceable through DI;
- every high-level call remains expressible through primitives such as the
  builder, typed clients, and engines.

## Guiding principles

- **Spec conformance is paramount; backwards compatibility is not a goal.**
  - This is a spec-accurate alpha SDK.
  - Every change is a single coordinated cutover: breaking renames,
    removals, and signature changes are expected.
  - There are no `[Obsolete]` bridges, dual overloads kept for old callers,
    or compatibility shims.
  - Wire behaviour stays at draft-11. Any deliberate exception is logged in
    `implementation-log.md`.
- **Layered 80/20 (carried from 2026-06-27-server-api-surface).**
  Primitives → options-driven handlers or middleware → one-call DI plus
  `Map*`. Every high-level call is expressible via primitives, and every
  default is replaceable via DI. This now applies to the **client side too**.
- **One options model.**
  - `IOptions<T>` / named options, with settable properties.
  - `TimeProvider` for time.
  - Validation at start.
  - Options carry bindable scalars and policy knobs.
  - Keys, stores, and callbacks are DI services, never option properties.
- **Identity once per role.** An issuer, signing key, and kid are declared in
  one registration. Everything else (metadata, revocation, federation, signed
  outbound clients) derives from it.
- **SDK owns mechanics, consumers own policy.** Bookkeeping the spec requires
  (entitlement, revocation fan-out, single-use enforcement) moves into the SDK.
  Consumers keep decisions such as consent, policy, and account selection.
- **No string indirection.** Protocol values are typed.
- **No consumer HTTP plumbing.** Samples register no `AddHttpClient()` and
  build no signed clients by hand.

## Verification gates (every phase)

```bash
dotnet build AAuth.slnx -c Release -v q -nologo 2>&1 | grep -E ' error |warn'   # expect nothing
for p in AAuth.Tests AAuth.Conformance AAuth.R3.Tests AAuth.Events.Tests; do
  dotnet test tests/$p -c Release --no-build; done
dotnet run --project tools/ApiSurface -c Release -- . --write                  # review the diff
AAUTH_UPDATE_DOCS_INVENTORY=1 dotnet test tests/AAuth.Tests -c Release --no-build \
  --filter FullyQualifiedName~Documentation_FrozenSurface
dotnet test tests/AAuth.Tests -c Release --no-build \
  --filter "FullyQualifiedName~SnippetCompilationTests|FullyQualifiedName~DocumentationLinkTests"
npm --prefix tests/e2e run typecheck
cd tests/e2e && CI=1 NODE_PATH=./node_modules npx playwright test --reporter=line --retries=0
```

Phases 3, 5, 9, and 11 also run the Keycloak profile (see the
[v11 migration plan](../2026-09-11-aauth-v11-spec-migration/implementation-plan.md)).

## Phase 0 — Decision gate and baseline

Resolve Q1–Q18 from [research.md](research.md#gaps-and-open-questions).

### Definition of Done

- [ ] Every question Q1–Q18 has a `RESOLVED` or `PROCEEDED (default X)`
      ruling in `implementation-log.md`.
- [ ] Q16 sequencing is confirmed. If the dashboard lands first, this branch is
      rebased onto it and the research line citations for MockPersonServer and
      SampleApp are re-derived.
- [ ] Baseline gates are green on the starting commit; test counts are
      recorded in the log.
- [ ] An `ApiSurface` snapshot of the starting commit is recorded for the final
      diff review.

## Phase 1 — Typed constants, labels, dead code (F-S7, F-S8, F-S9)

Cheap and isolated.

- Add `MissionTerminationReason` (per Q18) with the five spec values
  (#mission-management, L1522-L1526).
  - Change `GovernanceEndpoints.MissionTerminated`, the PS call sites, and
    `AAuthMissionTerminatedException.TerminationReason` to use it.
  - Round-trip unknown values: the set is open (L1567).
- Fix the agent-token code labels in `TokenError.cs` (L15, L19) and
  `docs/advanced/error-handling.md` (L111-L112). They should say "kept
  pending AAuth #199 interim ruling", not "removed".
- Delete the dead `AddHttpClient()` calls (Concierge L43, SampleApp L20).
- MockPersonServer well-known: use `MapAAuthPersonServerWellKnown` if the
  resource-metadata call is unintended; otherwise log why.

### Definition of Done

- [ ] `MissionTerminationReason` exists and is used server-side and
      client-side. No string literal `"expired"`/`"revoked"`/... remains at
      a termination call site (grep evidence in the log).
- [ ] Tests: `MissionTerminationReasonTests` (known values, unknown value
      round-trip, JSON serialization); existing mission-status tests updated.
- [ ] #199 labels are corrected in code comments and docs.
- [ ] Dead `AddHttpClient()` calls are removed.
- [ ] The PS well-known ruling is logged; the code is changed if applicable.
- [ ] Gates pass.

## Phase 2 — Shared options foundations (F-X2, F-X3, F-X4; Q1, Q13, Q14)

These are building blocks the later phases depend on. They cause no
behaviour change.

- Replace every `Func<DateTimeOffset> Clock` with `TimeProvider`:
  - `TokenVerifier`
  - `AAuthVerifier`
  - `AAuthVerificationOptions`
  - `AAuthResourceOptions`
  - `R3Challenge`
- Introduce `AAuthTrustOptions`, holding trusted auth-token issuers, person
  servers, agent-provider issuers, and access servers, each as a set plus a
  predicate.
  - Remove the duplicated members from `AAuthServerOptions`,
    `AAuthVerificationOptions`, `AAuthResourcePipelineOptions`, and the PS/AS
    options.
  - These types consume the shared `AAuthTrustOptions` instance.
- Normalize option types to settable properties, as `IOptions<T>` configure
  delegates require.
- Add an internal `AAuthOptionsValidator<T>` pattern (`IValidateOptions<T>`)
  and a `ValidateOnStart` convention.

### Definition of Done

- [ ] `grep -rn 'Func<DateTimeOffset>' src` returns nothing; tests use
      `FakeTimeProvider`.
- [ ] `AAuthTrustOptions` is the single trust declaration. Grep evidence
      shows no other public `Trusted*` members.
- [ ] Every public options type uses `{ get; set; }`.
- [ ] Tests: `AAuthTrustOptionsTests` (set vs predicate precedence,
      empty-means-deny semantics preserved), plus clock-injection tests for
      each migrated type.
- [ ] Gates pass; `ApiSurface` diff reviewed.

## Phase 3 — Server role registration (F-S1, F-S2, F-S9; Q2, Q3, Q9)

This is the highest-blast-radius server change.

- **Resource role.** `AddAAuthResource` moves to named `IOptions`.
  - Add an `(IConfiguration)` overload for section `AAuth:Resource`.
  - Resolve the signing key from DI, keyed by role (per Q3).
  - Register `TokenVerifier` with the role's egress policy and
    `TimeProvider`.
- **Person Server role.** Add `AddAAuthPersonServer(...)` returning an
  `AAuthPersonServerBuilder`.
  - It holds issuer, key, and kid once.
  - It `TryAdd`s these defaults:
    - `InMemoryPersonPendingStore`
    - `DefaultIdentityClaimsAsserter`
    - `TokenVerifier`
    - the mission stores (from `AddAAuthGovernance`)
    - the token inventory
  - `.WithFederation()` replaces `AddAAuthFederation(key, issuer, kid)`.
  - `.WithGovernance()` folds in `AddAAuthGovernance`.
- **Access Server role.** Add `AddAAuthAccessServer(...)`.
  - It `TryAdd`s `InMemoryAccessPendingStore` and requires an `IAccessPolicy`
    registration. That requirement is validated at start with a clear error.
- Parameterless `MapAAuthPersonServer()` / `MapAAuthAccessServer()` read
  options from DI.
  - Metadata endpoint URLs (mission, permission, audit, interaction) derive
    from issuer plus route paths.
  - Consumers stop hand-building them.
- Expose the role identity as a DI service (`IAAuthServerIdentity`: issuer,
  kid, key). Samples use it instead of restating `psIssuer`, e.g. for
  `IssueMissionPersonTokensAsync`, `StoredMission`, and `Interaction.Format`
  call sites.
- Migrate MockPersonServer, the MockAccessServers, and the MockResourceServers
  in this phase to keep the build green.

### Definition of Done

- [ ] `AddAAuthPersonServer` and `AddAAuthAccessServer` exist and bind from
      `AAuth:PersonServer` and `AAuth:AccessServer`. `ValidateOnStart` fails
      fast on a missing issuer, a missing key, or (AS only) a missing
      `IAccessPolicy`.
- [ ] `MapAAuthPersonServer()` / `MapAAuthAccessServer()` take no options
      instance.
- [ ] `AddAAuthFederation` is deleted; federation is enabled through the PS
      builder.
- [ ] Tests:
  - [ ] `PersonServerRegistrationTests`: defaults resolved, each seam
        replaceable, validation failures.
  - [ ] `AccessServerRegistrationTests`: missing-policy error, pending-store
        default.
  - [ ] `ResourceRegistrationTests`: `TokenVerifier` registered with the role
        egress policy.
  - [ ] Configuration binding tests for each role section.
- [ ] Sample PS/AS/resource `Program.cs` files contain no
      `AddSingleton<IPersonPendingStore|IIdentityClaimsAsserter|IAccessPendingStore>`
      unless they are overriding a default (each override commented), and no
      `new TokenVerifier`.
- [ ] Grep evidence: `psIssuer`/`asIssuer` appear only where configuration is
      read.
- [ ] Gates pass, including the Keycloak profile.

## Phase 4 — Server feature seams (F-S3, F-S4, F-S5; Q10, Q12)

- Add `IAAuthHeldInvocationStore` and `IAAuthSingleUseGrantStore`.
  - The current classes become the in-memory defaults.
  - `AddAAuthHeldInvocations(o => ...)` registers them with path prefix and
    lifetime as options.
  - `MapAAuthHeldInvocations()` becomes parameterless.
- R3:
  - The approval path entitles automatically (per Q12). `R3ProposalStore.Entitle`
    becomes internal, and Bookings drops L304 and L560.
  - `MapR3AccessTokenEndpoint()` reads `R3AccessTokenEndpointOptions` from
    `IOptions`.
  - `MapR3Document` keeps its per-route `getBytes`, but its reader policy
    resolves from DI by default.
- Events: `AddAAuthEvents(o => ...)` registers `EventsProtocol` and the
  stores. `MapAAuthEventEndpoint(path)` and
  `MapAAuthSubscriptionEndpoint(path, o => ...)` resolve those from DI.
- `MapAAuthRevocationEndpoint(path)` resolves `IJtiStore` from DI.
- `UseAAuthChallenge()` and `UseAAuthVerification()` resolve their options
  from DI.

### Definition of Done

- [ ] No public `Map*`/`Use*` takes a store, protocol, verifier, or options
      **instance**. Per-route lambdas and route patterns are allowed.
      `ApiSurface` diff is attached to the log.
- [ ] Tests:
  - [ ] `HeldInvocationStoreTests`: a custom store is used; the single-use
        guarantee holds under concurrency.
  - [ ] `R3AutoEntitlementTests`: approval entitles; denial does not; a
        second PS is not entitled.
  - [ ] Events DI tests.
  - [ ] A revocation-endpoint DI test.
- [ ] Bookings has no `new AAuthSingleUseGrants()`, no `Entitle(` call, and no
      `IsEntitledPersonServer` wiring beyond an optional policy override.
- [ ] Gates pass.

## Phase 5 — Revocation initiation (F-S6; Q11)

- Add `IAAuthRevocationService`, registered by each role and signed with
  `IAAuthServerIdentity`.
  - `RevokeAtAsync(Uri endpoint, string jti, DateTimeOffset exp)`.
  - PS cascades:
    - `RevokePersonTokenAsync(jti)`: resource `aud` plus every AS it was
      presented to, and the SHOULD for upstream-derived tokens
      (#revocation-cascade, L2752).
    - `RevokeMissionAsync(s256)`: L2754.
    - Agent-token cascade by `sub`: L2755.
- `MapAAuthIssuerRevocation` is deleted. Role registration maps the issuer
  revocation endpoint from its identity.
- `RevocationClient` becomes the primitive under the service. The public
  constructor stays for primitive users.

### Definition of Done

- [ ] Samples construct no `new RevocationClient(` or hand-built PS-signed
      client. Grep evidence covers MockPersonServer, GuidedTour, and
      CapabilitySupport.
- [ ] Tests:
  - [ ] `PersonTokenRevocationCascadeTests`: fan-out to `aud` and to every
        recorded AS; an upstream-derived token is revoked.
  - [ ] `MissionRevocationCascadeTests`.
  - [ ] `AgentTokenRevocationCascadeTests`.
  - [ ] A test that the endpoint is signed with the role identity.
- [ ] The conformance ledger rows for L2752, L2754, and L2755 point at the new
      tests.
- [ ] Gates pass, including the Keycloak profile.

## Phase 6 — Client options and configuration (F-C1, F-C6; Q1, Q2, Q3, Q6)

This is the highest-blast-radius client change.

- `AddAAuthAgent(name)` returns an `AAuthAgentBuilder` (wrapping
  `IHttpClientBuilder`) backed by named `IOptions<AAuthAgentOptions>`.
  - It has an `(IConfiguration)` overload for `AAuth:Agents:<name>`.
  - It is lazy: the handler chain is composed from `IServiceProvider` at first
    resolve.
- Reach **full parity** with `AAuthClientBuilder`:
  - identity source (agent token, refresher, self-issued, JWKS URI, jkt-jwt,
    enrolled key store);
  - person server, mission, call chaining, capabilities, prompt;
  - poll tuning, resource-managed access, development loopback.
- Parity is enforced mechanically, not by review (see the DoD).
- Keys come from DI (keyed `IAAuthKey` by agent name, or an `IKeyStore` plus
  handle binding). `AgentProviderTokenRefresher` and `AgentProviderClient`
  are provisioned by `.WithAgentProvider(...)` from configuration
  (`AgentProvider`, `KeyHandle`).
- `AddAAuthClient` adopts the same options conventions.
- `AddAAuthGovernanceClient` folds into `AddAAuthAgent(name).WithGovernance()`.
- The DI path composes `AAuthClientBuilder`, so the builder remains the
  primitive.

### Definition of Done

- [ ] `AAuthAgentOptions` contains only bindable scalars and policy knobs,
      with no `IAAuthKey`, lambda, or store properties.
- [ ] Parity test `AgentBuilderParityTests`: reflection lists the public
      `AAuthClientBuilder` configuration methods, and each one maps to an
      `AAuthAgentBuilder` method or option, or to an explicit, justified
      exclusion list.
- [ ] Binding tests cover every scalar in `AAuth:Agents:<name>`.
      `ValidateOnStart` fails on a missing identity source or on conflicting
      sources.
- [ ] Missions, clarification, and call chaining each have one DI-path
      end-to-end unit test against the in-process mock servers.
- [ ] `AddAAuthGovernanceClient` is deleted.
- [ ] Gates pass.

## Phase 7 — Client callbacks as DI seams (F-C4; Q4, Q5)

- Add these interfaces:
  - `IAAuthInteractionHandler.OnInteractionRequiredAsync(Interaction, CancellationToken)`.
    It covers PS- and resource-initiated interaction, with
    `Interaction.Source` as the discriminator.
  - `IAAuthClarificationHandler`.
  - `IAAuthApprovalObserver` (approval pending, poll observed).
- Resolution order per agent: a keyed service by agent name, then an unkeyed
  service, then none, in which case the capability is not declared.
  Capabilities are derived from which handlers are present, not set by hand.
- Builder lambda overloads adapt to the same interfaces. The
  `Func<string, string, CancellationToken, Task>` shape is deleted.
- Remove the callback properties from `ChallengeHandlingOptions`,
  `InteractionHandlingOptions`, and `GovernanceOptions`.

### Definition of Done

- [ ] No public options type exposes a `Func<>`/`Action<>` callback, except
      `OnSignatureBase` as a debug hook (logged if kept).
- [ ] Tests:
  - [ ] `InteractionHandlerResolutionTests`: keyed beats unkeyed; absence
        removes the `interaction` capability.
  - [ ] Clarification handler round limit.
  - [ ] PS-initiated and resource-initiated interaction reach the same
        handler.
- [ ] Concierge's chaining behaviour (throwing
      `AAuthInteractionChainedException`) is expressed as a registered
      handler.
- [ ] Gates pass.

## Phase 8 — Typed clients, token cache, lifetime (F-C3, F-C5, F-C7; Q7, Q8)

- Add an `IAAuthTokenCache` seam with an in-memory default that is a
  singleton per agent name. `AAuthClientBuilder.WithTokenCache(...)` accepts
  it, so builder-built clients can share caches.
- `AddAAuthAgent(name)` also registers keyed typed clients:
  - `TokenExchangeClient`
  - `MissionClient`, `PermissionClient`, `AuditClient`, `InteractionClient`
    (the person server comes from options)
  - `AAuthGovernanceClient`
  - `RevocationClient`
  All share the agent's signed pipeline and the DI `MetadataClient`/`JwksClient`.
- Timeouts:
  - Reproduce F-C7.
  - Set `HttpClient.Timeout` on agent clients so that long polls are governed
    by `PollingTimeout`.
  - Document the relationship between `PollingTimeout`, `RequestTimeout`, and
    `HttpClient.Timeout`.
- Document client lifetime (build once, reuse; disposal ownership) in
  `docs/reference/dependency-injection.md` and the builder XML docs.

### Definition of Done

- [ ] `TokenCacheSharingTests`: two builds sharing a cache perform one token
      exchange. The DI path reuses the cache across resolves.
- [ ] Keyed typed-client resolution tests for each client.
- [ ] Timeout test: a 3-minute deferred poll behind a DI agent client
      completes (with `FakeTimeProvider` or a shortened equivalent).
- [ ] Walkthrough code (`DocumentDemoSession.cs` L47, `WalletScenarioCode.cs`
      L18) uses the keyed typed clients or the agent client, not hand-built
      `TokenExchangeClient`s.
- [ ] Gates pass.

## Phase 9 — Sample migration (compiled code; F-C2; Q15)

- Move the host apps to the high-level path:
  - SampleApp: `AddAAuthAgent` bound from `AAuth:Agents:*`; pages inject
    clients instead of building per click.
  - Concierge: one registered downstream agent, with call chaining per request
    via the options API.
  - MissionAgent and AgentConsole: generic host plus DI.
  - EventSupport.
- Teaching surfaces:
  - GuidedTour and CapabilitySupport code panes show the DI path by default.
  - Signing-mode pages keep the builder where it is the lesson, each with a
    comment explaining why.
- Remove per-request `using var client = ... .Build()` from request and page
  handlers.

### Definition of Done

- [ ] Grep evidence:
  - no `AAuthClientBuilder` in SampleApp pages except signing-mode lessons
    (each listed in the log);
  - no `.Build()` inside request handlers;
  - no `Configuration["AAuth:...` reads that duplicate a bound section.
- [ ] `make demo` works end-to-end (closes the convenience-apis Phase 7 box).
- [ ] Full Playwright suite green with `--retries=0`; Keycloak profile green.

## Phase 10 — Samples, snippets and docs sweep

Run once the code surface is frozen.

Sweep the non-compiled surfaces:

- `docs/**`, especially `reference/configuration.md`,
  `reference/dependency-injection.md`, `getting-started.md`, the `workflows/*`
  `AddAAuthAgent` examples, and `server/*`;
- READMEs;
- GuidedTour `CodeSnippets.cs` string snippets;
- walkthrough code panes;
- e2e assertions on displayed code.

Add a configuration reference: every section and key, with type, default, and
validation.

### Definition of Done

- [ ] Case- and separator-insensitive sweep for every deleted or renamed
      symbol. The results table is in the log; the grep counts are stable
      (not truncated).
- [ ] `docs/reference/configuration.md` documents every bound key and matches
      the options types (a test enumerates option properties against the doc).
- [ ] Snippet, link, and docs-inventory gates pass.
- [ ] `ApiSurface --write` diff reviewed against the Phase 0 snapshot. Every
      removal is intentional and listed.

## Phase 11 — Independent internal review

A fresh subagent reviews the work against research.md, this plan, P1–P6, and
the spec rows cited for Phases 1 and 5. Findings are severity-graded
(P0–P3). Every citation is re-derived.

### Definition of Done

- [ ] Review report recorded in the log.
- [ ] All P0/P1 findings fixed or ruled.
- [ ] A final gate run is green, including the Keycloak profile and full
      Playwright `--retries=0`.

## Out of scope

| Item | Reason |
|---|---|
| Agent Provider server endpoints (`MapAAuthAgentProvider*`, F-S10) | New role surface; separate initiative (Q17) |
| Persistent store implementations (EF Core, Redis) for new seams | Seams only; in-memory defaults ship |
| Multi-resource / multi-vhost hosting | Deferred by 2026-06-27-server-api-surface |
| Budgets draft (`draft-hardt-aauth-budgets`) | Not implemented; separate initiative |
| AAuth #199 agent-token error-code outcome | Upstream decision; only labels are fixed here |
| Wire or protocol changes | Draft-11 behaviour is frozen for this initiative |
| PS consent dashboard | Owned by 2026-09-28-ps-consent-dashboard (Q16) |
| MVC `AddAAuthScopePolicy`/`AddAAuthRolePolicy` string policy names | Retired from samples by server-api-surface Phase 4. Kept as the documented MVC `[Authorize]` fallback (docs/server/authorization-policies.md) |
