# SDK API Surface Consistency — Implementation Plan

Research: [research.md](research.md). Rulings:
[implementation-log.md](implementation-log.md).

## Goal

Make the server-facing and client-facing SDK APIs follow one consistent set of
.NET hosting conventions:

- how components are constructed;
- how configuration flows in (`IOptions<T>`, `IConfiguration`);
- how decisions, callbacks, and seams are supplied (data, delegates, or DI
  services, normalized into one seam each);
- how identity is declared once per role instance.

> **Update (2026-09):** revised after an adversarial review round (one
> subagent per question cluster plus a red-team synthesis pass). See
> [research.md](research.md#adversarial-review-2026-09-29) and the
> implementation log. Rulings that changed: Q3, Q4, Q12, Q14, Q18. Q19 is
> new (signing abstraction), and so is Phase 3. Later phases are renumbered.

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
- **Samples are not the design target.** Real hosts need:
  - multi-tenant and runtime-created agents;
  - dynamic and async trust;
  - KMS/HSM keys and key rotation;
  - scale-out;
  - background jobs with no `HttpContext`;
  - console apps without DI;
  - tests.

  Every seam must serve these, not just the demo wiring.
- **One options model.**
  - `IOptions<T>` / named options, with settable properties.
  - `TimeProvider` for time.
  - Sync shape validation at start. Async concerns such as key loading fail
    at first use with a clear error.
  - Identity-bearing options are read once at composition. There is no hot
    reload of identity.
- **Extensibility ladder (R0).** Every decision point accepts three
  equivalent forms, normalized into **one internal seam interface**:
  1. data: sets or scalars, config-bindable;
  2. a delegate (sync or async) on options or the builder;
  3. a DI service implementing the interface.

  Rules:
  - Options MAY hold delegates and instances; configuration binding ignores
    them.
  - Precedence:
    1. per-request override (client: `HttpRequestMessage.Options`) or
       per-endpoint override (server: endpoint metadata);
    2. an explicit instance or delegate on the builder or options;
    3. a DI service: keyed by instance name, then unkeyed. The SDK performs
       this fallback itself, because keyed DI does not fall back on its own;
    4. the default built from data.
  - Seam contexts carry an `IServiceProvider`: request services when there
    is a request, otherwise a created scope. Scoped dependencies therefore
    work in background jobs too.
  - Docs show three or four canonical patterns per seam, not every
    combination.
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

Phases 3, 4, 6, 10, and 12 also run the Keycloak profile (see the
[v11 migration plan](../2026-09-11-aauth-v11-spec-migration/implementation-plan.md)).

## Phase 0 — Decision gate and baseline

Resolve Q1–Q19 from [research.md](research.md#gaps-and-open-questions).

### Definition of Done

- [x] Every question Q1–Q19 has a `RESOLVED` or `PROCEEDED (default X)`
      ruling in `implementation-log.md`.
- [x] Q16 sequencing is confirmed: the dashboard lands first (owner,
      2026-09-29). This branch is rebased onto it, and the research line
      citations for MockPersonServer, SampleApp, and GuidedTour are
      re-derived. The dashboard's services are added to the Phase 4 and
      Phase 10 inventories.
- [x] Baseline gates are green on the starting commit; test counts are
      recorded in the log.
- [x] An `ApiSurface` snapshot of the starting commit is recorded for the final
      diff review.

## Phase 1 — Typed constants, labels, dead code (F-S7, F-S8, F-S9)

Cheap and isolated.

- Add `AAuthConstants.MissionTerminationReasons` `const string` values for
  the five spec values (#mission-management, L1522-L1526), per Q18.
  - This matches the SDK's open-set convention, e.g.
    `AAuthConstants.AccessModes` (AAuthConstants.cs L59).
  - `TerminationReason` stays `string?`, so unknown values round-trip
    (L1567).
  - Every SDK and sample call site uses the constants.
- Fix the agent-token code labels in `TokenError.cs` (L15, L19) and
  `docs/advanced/error-handling.md` (L111-L112). They should say "kept
  pending AAuth #199 interim ruling", not "removed".
- Delete the dead `AddHttpClient()` calls (Concierge L43, SampleApp L20).
- MockPersonServer well-known: use `MapAAuthPersonServerWellKnown` if the
  resource-metadata call is unintended; otherwise log why.

### Definition of Done

- [x] `MissionTerminationReasons` constants exist and are used at every
      termination call site. No string literal `"expired"`/`"revoked"`/...
      remains (grep evidence in the log).
- [x] Tests: the constants match the spec table, and an unknown reason
      round-trips through `AAuthMissionTerminatedException`.
- [x] #199 labels are corrected in code comments and docs.
- [x] Dead `AddHttpClient()` calls are removed.
- [x] The PS well-known ruling is logged; the code is changed if applicable.
- [x] Gates pass.

## Phase 2 — Shared options foundations (F-X2, F-X3, F-X4; Q1, Q13, Q14)

These are building blocks the later phases depend on. They cause no
behaviour change.

- Replace every `Func<DateTimeOffset> Clock` with `TimeProvider`:
  - `TokenVerifier`
  - `AAuthVerifier`
  - `AAuthVerificationOptions`
  - `AAuthResourceOptions`
  - `R3Challenge`
- **Trust seam (Q14).**
  - Add `IAAuthTrustPolicy` with `ValueTask<bool> IsTrustedAsync(AAuthTrustContext, CancellationToken)`.
  - `AAuthTrustContext` carries:
    - the issuer;
    - `AAuthTrustedParty` (AuthTokenIssuer, PersonServer, AgentProvider,
      AccessServer);
    - the token type;
    - `HttpContext?`;
    - `IServiceProvider`.
  - The default implementation is built from `AAuthTrustOptions`: sets plus
    sync or async predicates per party. It preserves today's semantics:
    - AND composition;
    - `null` = open with the startup warning;
    - `AAuthTrust.Any` = explicit open.
  - Remove the duplicated members from `AAuthServerOptions`,
    `AAuthVerificationOptions`, `AAuthResourcePipelineOptions`, and the PS/AS
    options. Each role instance configures trust once.
  - Per-endpoint override: `.RequireAAuth(trust: ...)` metadata.
- **Seam resolver (R0).** Add an internal helper that applies the R0
  precedence (keyed by instance name → unkeyed → default) for every seam.
  Later phases use it.
- Normalize option types to settable properties, as `IOptions<T>` configure
  delegates require.
- Add an internal `AAuthOptionsValidator<T>` pattern (`IValidateOptions<T>`)
  and a `ValidateOnStart` convention.

### Definition of Done

- [x] `grep -rn 'Func<DateTimeOffset>' src` returns nothing; tests use
      `FakeTimeProvider`.
- [x] `AAuthTrustOptions` / `IAAuthTrustPolicy` is the single trust
      declaration. Grep evidence shows no other public `Trusted*` members.
- [x] Every public options type uses `{ get; set; }`.
- [x] Tests:
  - [x] `AAuthTrustPolicyTests`:
    - set AND predicate;
    - `null` open with the warning;
    - an empty set denies;
    - an async predicate;
    - a DI policy with a scoped dependency, both inside a request and from a
      background scope;
    - a per-endpoint override beats the role policy.
  - [x] `SeamResolverTests`: explicit beats keyed, keyed beats unkeyed,
        unkeyed beats default.
  - [x] Clock-injection tests for each migrated type.
- [x] Gates pass; `ApiSurface` diff reviewed.

## Phase 3 — Signing abstraction (F-X5; Q19)

The prerequisite for KMS/HSM keys and rotation. Every role uses it.

- Split `IAAuthKey` into:
  - a public-key identity (public JWK, thumbprint, algorithm);
  - `IAAuthSigner` with `ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte>, CancellationToken)`.
- `ToPrivateJwk` moves to an exportable-key subtype, which only
  `FileKeyStore` needs (FileKeyStore.cs L62). Local keys complete
  synchronously.
- Make the five sync signing sites async:
  - `JwtWriter` L25
  - `AgentTokenBuilder` L211
  - `AAuthSigningHandler` L258 (already inside an async path)
  - `R3Challenge` L137
  - `EventsTokens` L24

  Token builders' `Build()` becomes `BuildAsync()`.
- Add `AAuthSigningKeySet`: kid → signer, plus the active kid. It serves
  rotation (publish several, sign with one) and replaces the
  `SigningKeys` dictionaries.
- Options reference keys by `KeyHandle`, resolved through the registered
  `IKeyStore` (Q2), or accept a signer or key-set instance directly.

### Definition of Done

- [x] `grep -rn '\.Sign(' src` returns only the local-key implementation.
- [x] Tests:
  - [x] `RemoteSignerTests`: a fake async non-exportable signer mints
        agent, person, auth, and resource tokens and signs HTTP requests.
  - [x] `SigningKeySetTests`: JWKS publishes all kids; tokens are signed with
        the active kid; rotation takes effect without a restart.
- [x] Gates pass, including the Keycloak profile.

## Phase 4 — Server role registration (F-S1, F-S2, F-S9; Q2, Q3, Q9)

This is the highest-blast-radius server change.

- **Resource role.** `AddAAuthResource` moves to named `IOptions`.
  - Add an `(IConfiguration)` overload for section `AAuth:Resource`.
  - Keys come from the Phase 3 key set or `KeyHandle`.
  - Register `TokenVerifier` with the role's egress policy and
    `TimeProvider`.
- **Person Server role.** Add `AddAAuthPersonServer(name?)` returning an
  `AAuthPersonServerBuilder`. Like `AuthenticationBuilder`, it exposes
  `Services` and `Name`.
  - It holds issuer and key set once per named instance. Several named
    instances, and co-hosted PS + AS + resource roles, are supported.
  - It `TryAdd`s these defaults:
    - `InMemoryPersonPendingStore`
    - `DefaultIdentityClaimsAsserter`
    - `TokenVerifier`
    - the mission stores (from `AddAAuthGovernance`)
    - the token inventory
  - `.Use*<T>()` / `.Use*(instance)` builder helpers replace each default.
  - Any in-memory default in use outside Development logs a startup
    **warning**.
  - `.WithFederation()` replaces `AddAAuthFederation(key, issuer, kid)`.
  - `.WithGovernance()` folds in `AddAAuthGovernance`.
  - `.WithTrust(...)` configures trust per R0.
- **Access Server role.** Add `AddAAuthAccessServer(name?)`.
  - It `TryAdd`s `InMemoryAccessPendingStore` and requires an `IAccessPolicy`
    registration. That requirement is validated at start with a clear error.
- `MapAAuthPersonServer(name?)` / `MapAAuthAccessServer(name?)` read options
  from DI.
  - Metadata endpoint URLs (mission, permission, audit, interaction) derive
    from issuer plus route paths.
  - Consumers stop hand-building them.
- Expose the role identity as a keyed DI service (`IAAuthServerIdentity`:
  issuer and key set; signs through `IAAuthSigner`, never a raw key). Samples
  use it instead of restating `psIssuer`, e.g. for
  `IssueMissionPersonTokensAsync`, `StoredMission`, and `Interaction.Format`
  call sites.
- Migrate MockPersonServer, the MockAccessServers, and the MockResourceServers
  in this phase to keep the build green.
- **Consent dashboard seams (landed 2026-09-29; see the dashboard plan's
  Phase 7 log).** Fold them into the PS builder:
  - MockPersonServer `Program.cs` hand-registers `ConsentRegistry`,
    `PersonConsentDecisions` and `ConsentDashboardSessions`, and maps
    `MapConsentDashboard()`.
  - The bridge store and `MissionPendingStore` call `registry.Register`
    themselves. An SDK pending-store observer should replace that.
  - `BrowserInteraction.Consume()` is public only for the sample decision
    service. An SDK out-of-band decision API (#user-interaction, v11 L1011)
    should own it.
  - The four-party `Pending202` re-advertises a fresh PS interaction code
    after an Access Server clarification, although nothing is asked of the
    person. Decide whether it should return a bare `202`.

### Definition of Done

- [x] `AddAAuthPersonServer` and `AddAAuthAccessServer` exist and bind from
      `AAuth:PersonServer` and `AAuth:AccessServer`. `ValidateOnStart` fails
      fast on a missing issuer, a missing key, or (AS only) a missing
      `IAccessPolicy`.
- [x] `MapAAuthPersonServer(name?)` / `MapAAuthAccessServer(name?)` take no
      options instance.
- [x] `AddAAuthFederation` is deleted; federation is enabled through the PS
      builder.
- [x] Tests:
  - [x] `PersonServerRegistrationTests`:
    - defaults resolved;
    - each seam replaceable through the builder helper and through DI;
    - validation failures;
    - the in-memory warning appears outside Development.
  - [x] `CoHostedRolesTests`: PS + AS + resource in one host, with two named
        PS instances.
  - [x] `AccessServerRegistrationTests`: missing-policy error, pending-store
        default.
  - [x] `ResourceRegistrationTests`: `TokenVerifier` registered with the role
        egress policy.
  - [x] Configuration binding tests for each role section.
- [x] Sample PS/AS/resource `Program.cs` files contain no
      `AddSingleton<IPersonPendingStore|IIdentityClaimsAsserter|IAccessPendingStore>`
      unless they are overriding a default (each override commented), and no
      `new TokenVerifier`.
- [x] Grep evidence: `psIssuer`/`asIssuer` appear only where configuration is
      read.
- [x] Gates pass, including the Keycloak profile.

## Phase 5 — Server feature seams (F-S3, F-S4, F-S5; Q10, Q12)

- **Held invocations (Q10).** Split the seams by what can be persisted:
  - `IAAuthSingleUseGate`: `TryClaimAsync` / `CompleteAsync` /
    `GetResultAsync` by `jti`, with a serializable `HeldInvocationResult`.
  - `IAAuthHeldInvocationStore`: pending entries, serializable.
  - The execute delegate stays an in-process per-endpoint registration and
    is never stored.
  - Per-route pending lifetime via endpoint metadata.
  - `AddAAuthHeldInvocations(o => ...)` registers in-memory defaults, with
    the non-Development warning. `MapAAuthHeldInvocations()` becomes
    parameterless.
- **R3 (Q12, corrected).**
  - Entitlement follows the spec rule (r3 #r3-document-access-restriction,
    L725-L730): the readers are the AS in `aud` and the PS in `ps` of a
    resource token carrying that `r3_uri`.
  - Every SDK path that mints such a token (`R3Challenge`, the per-call
    proposal path) records both through `IR3DocumentEntitlements`, which
    has an in-memory default.
  - `EntitleAsync` stays public on the seam for hosts that mint resource
    tokens themselves.
  - `IsEntitledPersonServer` remains as an additional custom predicate, per
    R0.
  - Bookings drops L304 and L560.
  - `MapR3AccessTokenEndpoint()` reads `R3AccessTokenEndpointOptions` from
    `IOptions`.
  - `MapR3Document` keeps its per-route `getBytes`, but its reader policy
    resolves from DI by default.
- **Events.** `AddAAuthEvents(o => ...)` registers `EventsProtocol` and the
  stores. `MapAAuthEventEndpoint(path)` and
  `MapAAuthSubscriptionEndpoint(path, o => ...)` resolve those from DI.
- `MapAAuthRevocationEndpoint(path)` resolves `IJtiStore` from DI.
- `UseAAuthChallenge()` and `UseAAuthVerification()` resolve their options
  from DI.

### Definition of Done

- [x] No public `Map*`/`Use*` takes a store, protocol, verifier, or options
      **instance**. Per-route lambdas and route patterns are allowed.
      `ApiSurface` diff is attached to the log.
- [x] Tests:
  - [x] `SingleUseGateTests`:
    - a custom gate is used;
    - single use holds under concurrency;
    - a fake shared-store gate stays single-use across two app instances
      (scale-out simulation).
  - [x] `R3AutoEntitlementTests`:
    - minting entitles both `aud` and `ps`;
    - a third signer is rejected;
    - a host-minted token entitles through `EntitleAsync`.
  - [x] Events DI tests.
  - [x] A revocation-endpoint DI test.
- [x] Bookings has no `new AAuthSingleUseGrants()`, no `Entitle(` call, and no
      `IsEntitledPersonServer` wiring beyond an optional policy override.
- [x] Gates pass.

## Phase 6 — Revocation service (F-S6; Q11)

- Extract the private cascade engine in `RevocationEndpoint.cs`
  (`CascadeAsync`, ~L228) into a public `IAAuthRevocationService`.
  - It is registered per role instance and signs through
    `IAAuthServerIdentity`.
  - Inbound endpoints **and** app code (admin UI, background jobs, webhooks)
    use the same engine.
  - It returns a structured per-recipient result; it neither throws nor
    returns a bare boolean.
  - Calls are idempotent per `(iss, jti)`.
  - `RevokeAtAsync(Uri endpoint, string jti, DateTimeOffset exp)`.
  - PS cascades:
    - `RevokePersonTokenAsync(jti)`: resource `aud` plus every AS it was
      presented to, and the SHOULD for upstream-derived tokens
      (#revocation-cascade, L2752).
    - `RevokeMissionAsync(s256)`: L2754.
    - `RevokeAgentAsync(iss, sub)`: L2755.
- **Records gap check first.**
  - Compare the inventory with the spec Records paragraph (L2758):
    - agent `(iss, jti)` + `sub` index;
    - person-token upstream `(iss, jti)`;
    - AS `presented_jti`.
  - Today `TokenGrant` is `(TokenKey, Resource, ExpiresAt)` (TokenGrant.cs
    L5).
  - Extend `TokenGrant`/`IJtiStore` for anything missing, and log the
    result.
- `MapAAuthIssuerRevocation` is deleted. Role registration maps the issuer
  revocation endpoint from its identity.
- `RevocationClient` remains the public primitive under the service.

### Definition of Done

- [x] Samples construct no `new RevocationClient(` or hand-built PS-signed
      client. Grep evidence covers MockPersonServer, GuidedTour, and
      CapabilitySupport.
- [x] Tests:
  - [x] `PersonTokenRevocationCascadeTests`: fan-out to `aud` and to every
        recorded AS; an upstream-derived token is revoked.
  - [x] `MissionRevocationCascadeTests`.
  - [x] `AgentTokenRevocationCascadeTests`, by `sub`, across two agent tokens.
  - [x] `BackgroundRevocationTests`: invoked with no `HttpContext`.
  - [x] A test that the endpoint is signed with the role identity.
- [x] The conformance ledger rows for L2752, L2754, and L2755 point at the new
      tests.
- [x] Gates pass, including the Keycloak profile.

## Phase 7 — Client registration, factory, configuration (F-C1, F-C6; Q1, Q2, Q3, Q6)

This is the highest-blast-radius client change.

- `AddAAuthAgent(name)` returns an `AAuthAgentBuilder`.
  - It exposes `Services`, `Name`, and the underlying `IHttpClientBuilder`.
  - It is backed by named `IOptions<AAuthAgentOptions>`.
  - It has an `(IConfigurationSection)` overload for `AAuth:Agents:<name>`.
  - It is lazy: the handler chain is composed from `IServiceProvider` at first
    resolve.
- Add `IAAuthAgentFactory` for agents unknown at startup: per tenant, per
  user, or a per-request intermediary.
  - `Get(name)` returns a registered agent.
  - `Create(AAuthAgentDescriptor | Action<AAuthClientBuilder>)` builds an
    ad-hoc agent.
  - The returned `AAuthAgent` exposes `HttpClient` plus the typed clients
    (Phase 9).
  - Ownership and disposal: the factory owns registered agents; the caller
    owns ad-hoc ones.
- Reach **full parity** with `AAuthClientBuilder`:
  - identity source (agent token, refresher, self-issued, JWKS URI, jkt-jwt,
    enrolled key store);
  - person server, mission, call chaining, capabilities, prompt;
  - poll tuning, resource-managed access, development loopback.
- Parity is enforced mechanically, not by review (see the DoD).
- Delegates and instances (call-chaining source, token refresher, trust
  predicates) are allowed on options and builder per R0.
- Keys:
  - `KeyHandle` binds from configuration and resolves through `IKeyStore`.
  - Alternatively, a signer or key-set instance is set directly.
- `AgentProviderTokenRefresher` and `AgentProviderClient` are provisioned by
  `.WithAgentProvider(...)` from configuration (`AgentProvider`,
  `KeyHandle`).
- `AddAAuthClient` adopts the same options conventions.
- `AddAAuthGovernanceClient` folds into `AddAAuthAgent(name).WithGovernance()`.
- The DI path composes `AAuthClientBuilder`, so the builder remains the
  primitive.

### Definition of Done

- [x] Every configuration-bindable concept on `AAuthAgentOptions` binds from
      `AAuth:Agents:<name>`. Delegate and instance members are documented as
      code-only.
- [x] Parity test `AgentBuilderParityTests`: reflection lists the public
      `AAuthClientBuilder` configuration methods, and each one maps to an
      `AAuthAgentBuilder` method or option, or to an explicit, justified
      exclusion list.
- [x] Binding tests cover every scalar in `AAuth:Agents:<name>`.
      `ValidateOnStart` fails on a missing identity source or on conflicting
      sources.
- [x] Missions, clarification, and call chaining each have one DI-path
      end-to-end unit test against the in-process mock servers.
- [x] `AgentFactoryTests`:
  - two runtime-created tenant agents with different keys and person
    servers stay isolated;
  - a per-request intermediary agent chains its own upstream token;
  - disposal ownership.
- [x] A console test without Generic Host uses the builder only.
- [x] `AddAAuthGovernanceClient` is deleted.
- [x] Gates pass.

## Phase 8 — Client callbacks (F-C4; Q4, Q5)

- Add these interfaces:
  - `IAAuthInteractionHandler.OnInteractionRequiredAsync(Interaction, CancellationToken)`.
    It covers PS- and resource-initiated interaction.
    `Interaction(Url, Code)` gains `Source` (PersonServer | Resource).
  - `IAAuthClarificationHandler`.
  - `IAAuthDeferredObserver` (approval pending, poll observed).
- Delegate properties stay on options and builder and adapt to the same
  interfaces (R0). Console apps and tests keep one-line lambdas.
- Per-request override: typed `HttpRequestOptionsKey<IAAuthInteractionHandler>`
  (and similar keys for the other handlers) on `HttpRequestMessage.Options`.
  One singleton pipeline can then route a callback to the current user's
  session.
- Resolution follows R0: per-request, then explicit, then keyed by agent
  name, then unkeyed, then none.
- Capabilities keep today's rule (ChallengeHandlingOptions.cs L70-L76): `null`
  means inferred from which handlers resolve; an explicit list (possibly
  empty) overrides.
- The `Func<string, string, CancellationToken, Task>` shape is deleted.
  `ChallengeHandlingOptions`, `InteractionHandlingOptions`, and
  `GovernanceOptions` share one callback set instead of three copies.

### Definition of Done

- [ ] Tests:
  - [ ] `InteractionHandlerResolutionTests`:
    - per-request beats explicit, explicit beats keyed, keyed beats unkeyed;
    - with no handler, the `interaction` capability is not declared.
  - [ ] Per-user routing: two concurrent requests through one agent reach
        two different handlers.
  - [ ] Clarification handler round limit.
  - [ ] PS-initiated and resource-initiated interaction reach the same
        handler, with the correct `Source`.
- [ ] Concierge's chaining behaviour (throwing
      `AAuthInteractionChainedException`, capabilities empty) is expressed as
      a registered handler plus an explicit empty capability list.
- [ ] Gates pass.

## Phase 9 — Typed clients, token cache, lifetime (F-C3, F-C5, F-C7; Q7, Q8)

- Add an `IAAuthTokenCache` seam: multi-entry and thread-safe.
  - Its key is exactly the tuple `AAuthTokenHolder.SelectForRequest` guards
    today (AAuthTokenHolder.cs L50-L73): agent token, upstream, mission
    `s256`, audience, account, cnf thumbprint.
  - Expired entries are ignored.
  - Exchanges are single-flight per key.
  - It replaces the single-value holder. That removes the thrash when
    alternating resources and the per-`Build()` cache loss.
  - The in-memory default is per agent. `AAuthClientBuilder.WithTokenCache(...)`
    lets builder-built clients share a cache.
- `AddAAuthAgent(name)` also registers keyed typed clients:
  - `TokenExchangeClient`
  - `MissionClient`, `PermissionClient`, `AuditClient`, `InteractionClient`
    (the person server comes from options)
  - `AAuthGovernanceClient`
  - `RevocationClient`
  All share the agent's signed pipeline and the DI `MetadataClient`/`JwksClient`.
- Factory-created agents expose the same clients on `AAuthAgent`.
- Timeouts:
  - Reproduce F-C7.
  - Set `HttpClient.Timeout` on agent clients so that long polls are governed
    by `PollingTimeout`.
  - Document the relationship between `PollingTimeout`, `RequestTimeout`, and
    `HttpClient.Timeout`.
- Document client lifetime (build once, reuse; disposal ownership) in
  `docs/reference/dependency-injection.md` and the builder XML docs.

### Definition of Done

- [ ] `TokenCacheSharingTests`:
  - two builds sharing a cache perform one token exchange;
  - alternating two resources performs two exchanges, not one per call;
  - concurrent first requests trigger one exchange (single-flight);
  - a different upstream token or mission never reuses an entry.
- [ ] The DI path reuses the cache across resolves.
- [ ] Keyed typed-client resolution tests for each client.
- [ ] Timeout test: a 3-minute deferred poll behind a DI agent client
      completes (with `FakeTimeProvider` or a shortened equivalent).
- [ ] Walkthrough code (`DocumentDemoSession.cs` L47, `WalletScenarioCode.cs`
      L18) uses the keyed typed clients or the agent client, not hand-built
      `TokenExchangeClient`s.
- [ ] Gates pass.

## Phase 10 — Sample migration (compiled code; F-C2; Q15)

- Move the host apps to the high-level path:
  - SampleApp: `AddAAuthAgent` bound from `AAuth:Agents:*`; pages inject
    clients instead of building per click.
  - Concierge: one registered downstream agent. Call chaining is per request,
    through a per-request override or the agent factory.
  - MissionAgent and AgentConsole: generic host plus DI.
  - EventSupport.
- Teaching surfaces:
  - GuidedTour and CapabilitySupport code panes show the DI path by default.
  - Signing-mode pages keep the builder where it is the lesson, each with a
    comment explaining why.
- Remove per-request `using var client = ... .Build()` from request and page
  handlers.
- Consent dashboard call sites that restate the PS identity:
  - `PersonServerConsent.DashboardUrl(ps)` in ConsentSupport;
  - MissionAgent and AgentConsole build `{ps}/dashboard?code=` inline;
  - GuidedTour `TourSession.PersonServer`.

  Each should read the PS from the agent registration once Phase 7 exists.

### Definition of Done

- [ ] Grep evidence:
  - no `AAuthClientBuilder` in SampleApp pages except signing-mode lessons
    (each listed in the log);
  - no `.Build()` inside request handlers;
  - no `Configuration["AAuth:...` reads that duplicate a bound section.
- [ ] `make demo` works end-to-end (closes the convenience-apis Phase 7 box).
- [ ] Full Playwright suite green with `--retries=0`; Keycloak profile green.

## Phase 11 — Samples, snippets and docs sweep

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
validation. For each seam, document three or four canonical extensibility
patterns (data, delegate, DI service, per-request/per-endpoint override),
including a multi-tenant example and a KMS signer example.

### Definition of Done

- [ ] Case- and separator-insensitive sweep for every deleted or renamed
      symbol. The results table is in the log; the grep counts are stable
      (not truncated).
- [ ] `docs/reference/configuration.md` documents every bound key and matches
      the options types (a test enumerates option properties against the doc).
- [ ] Snippet, link, and docs-inventory gates pass.
- [ ] `ApiSurface --write` diff reviewed against the Phase 0 snapshot. Every
      removal is intentional and listed.

## Phase 12 — Independent internal review

A fresh subagent reviews the work against research.md, this plan, P1–P6, R0,
and the spec rows cited for Phases 1, 5, and 6. Findings are severity-graded
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
| Persistent store implementations (EF Core, Redis) for new seams | Seams only; in-memory defaults ship with a non-Development warning |
| Per-request issuer resolution (one PS instance serving many issuers by host header) | Named role instances cover multi-tenant hosting; a per-request issuer resolver is a separate initiative |
| Hot reload of identity (issuer, keys) via `IOptionsMonitor` | Rotation goes through `AAuthSigningKeySet` (Phase 3); identity options are read once |
| Multi-resource / multi-vhost hosting | Deferred by 2026-06-27-server-api-surface |
| Budgets draft (`draft-hardt-aauth-budgets`) | Not implemented; separate initiative |
| AAuth #199 agent-token error-code outcome | Upstream decision; only labels are fixed here |
| Wire or protocol changes | Draft-11 behaviour is frozen for this initiative |
| PS consent dashboard | Owned by 2026-09-28-ps-consent-dashboard (Q16) |
| MVC `AddAAuthScopePolicy`/`AddAAuthRolePolicy` string policy names | Retired from samples by server-api-surface Phase 4. Kept as the documented MVC `[Authorize]` fallback (docs/server/authorization-policies.md) |
